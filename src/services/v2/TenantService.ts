import { V2PolicyConfig } from '../../types/v2';
import { redisClient } from '../../utils/cache';
import { supabase } from '../../config/supabase';
import logger from '../../utils/logger';

export class TenantService {
    /**
     * Resolves the Policy for a given API Key.
     * Architecture rule: DB lookups are forbidden on the fast path.
     * Uses Redis (L2) for <2ms resolution, falls back to Supabase (L3) on cold starts.
     */
    static async getPolicy(apiKey: string): Promise<V2PolicyConfig> {
        if (!apiKey) return this.getDefaultPolicy();

        const cacheKey = `v2:policy:v2:${apiKey}`;

        // 1. FAST PATH: Check Redis (L2 Cache)
        if (redisClient) {
            try {
                const cached = await redisClient.get(cacheKey);
                if (cached) return JSON.parse(cached) as V2PolicyConfig;
            } catch (err) {
                logger.error('[TenantService] Redis cache read failed', err);
            }
        }

        // 2. COLD START PATH: Resolve user_id from api_access, then fetch policy from user_policies.
        // Runs only on cache miss (once per 5 minutes per tenant).
        try {
            // Step A: resolve the owner of this API key
            const { data: keyRow, error: keyError } = await supabase
                .from('api_access')
                .select('user_id')
                .eq('api_key', apiKey)
                .single();

            if (keyError || !keyRow?.user_id) {
                return this.getDefaultPolicy();
            }

            // Step B: fetch the user's saved global policy
            const { data, error } = await supabase
                .from('user_policies')
                .select('mode, block_proxies, block_datacenters, force_bwt, difficulty_level, allowed_asns, blocked_asns')
                .eq('user_id', keyRow.user_id)
                .maybeSingle();

            if (error || !data) {
                return this.getDefaultPolicy();
            }

            const policy: V2PolicyConfig = {
                mode: (data.mode as any) || 'BALANCED',
                block_proxies: data.block_proxies ?? true,
                block_datacenters: data.block_datacenters ?? false,
                force_bwt: data.force_bwt ?? true,
                difficulty_level: data.difficulty_level ?? 3,
                allowed_asns: data.allowed_asns || [],
                blocked_asns: data.blocked_asns || []
            };

            // 3. Warm Redis so next 5 min of requests hit the fast path
            if (redisClient) {
                await redisClient.setex(cacheKey, 300, JSON.stringify(policy));
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
