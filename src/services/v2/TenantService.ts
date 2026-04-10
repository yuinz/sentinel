import { V2PolicyConfig } from '../../types/v2';
import { redisClient } from '../../utils/cache';
import { supabase } from '../../config/supabase';
import logger from '../../utils/logger';

export class TenantService {
    /**
     * Resolves the Policy for a given API Key.
     * Enforces architecture rule #4: Database lookups are forbidden on the fast path.
     * Uses L2 (Redis) for <2ms resolution, falls back to L3 (Supabase) on cold starts.
     */
    static async getPolicy(apiKey: string): Promise<V2PolicyConfig> {
        if (!apiKey) return this.getDefaultPolicy();

        const cacheKey = `v2:policy:${apiKey}`;

        // 1. FAST PATH: Check Redis (L2 Cache)
        if (redisClient) {
            try {
                const cached = await redisClient.get(cacheKey);
                if (cached) return JSON.parse(cached) as V2PolicyConfig;
            } catch (err) {
                logger.error('[TenantService] Redis cache read failed', err);
            }
        }

        // 2. COLD START PATH: Fallback to Supabase (L3)
        // This only happens once every 5 minutes per tenant on Vercel Edge.
        try {
            const { data, error } = await supabase
                .from('tenant_policies') // You will create this table in Supabase
                .select('mode, allowed_asns, blocked_asns')
                .eq('api_key', apiKey)
                .single();

            if (error || !data) {
                return this.getDefaultPolicy();
            }

            const policy: V2PolicyConfig = {
                mode: (data.mode as any) || 'BALANCED',
                allowed_asns: data.allowed_asns || [],
                blocked_asns: data.blocked_asns || []
            };

            // 3. SYNCHRONIZE REDIS to protect the Fast Path for the next 10,000 requests
            if (redisClient) {
                await redisClient.setex(cacheKey, 300, JSON.stringify(policy)); // 5 minute TTL
            }

            return policy;
        } catch (err) {
            logger.error('[TenantService] Supabase fallback failed', err);
            return this.getDefaultPolicy();
        }
    }

    private static getDefaultPolicy(): V2PolicyConfig {
        return { mode: 'BALANCED' };
    }
}
