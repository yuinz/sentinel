"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TenantService = void 0;
const cache_1 = require("../../utils/cache");
const supabase_1 = require("../../config/supabase");
const logger_1 = __importDefault(require("../../utils/logger"));
class TenantService {
    /**
     * Resolves the Policy for a given API Key.
     * Enforces architecture rule #4: Database lookups are forbidden on the fast path.
     * Uses L2 (Redis) for <2ms resolution, falls back to L3 (Supabase) on cold starts.
     */
    static async getPolicy(apiKey) {
        if (!apiKey)
            return this.getDefaultPolicy();
        const cacheKey = `v2:policy:${apiKey}`;
        // 1. FAST PATH: Check Redis (L2 Cache)
        if (cache_1.redisClient) {
            try {
                const cached = await cache_1.redisClient.get(cacheKey);
                if (cached)
                    return JSON.parse(cached);
            }
            catch (err) {
                logger_1.default.error('[TenantService] Redis cache read failed', err);
            }
        }
        // 2. COLD START PATH: Fallback to Supabase (L3)
        // This only happens once every 5 minutes per tenant on Vercel Edge.
        try {
            const { data, error } = await supabase_1.supabase
                .from('tenant_policies') // You will create this table in Supabase
                .select('mode, allowed_asns, blocked_asns')
                .eq('api_key', apiKey)
                .single();
            if (error || !data) {
                return this.getDefaultPolicy();
            }
            const policy = {
                mode: data.mode || 'BALANCED',
                allowed_asns: data.allowed_asns || [],
                blocked_asns: data.blocked_asns || []
            };
            // 3. SYNCHRONIZE REDIS to protect the Fast Path for the next 10,000 requests
            if (cache_1.redisClient) {
                await cache_1.redisClient.setex(cacheKey, 300, JSON.stringify(policy)); // 5 minute TTL
            }
            return policy;
        }
        catch (err) {
            logger_1.default.error('[TenantService] Supabase fallback failed', err);
            return this.getDefaultPolicy();
        }
    }
    static getDefaultPolicy() {
        return { mode: 'BALANCED' };
    }
}
exports.TenantService = TenantService;
