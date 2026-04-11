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
     * Architecture rule: DB lookups are forbidden on the fast path.
     * Uses Redis (L2) for <2ms resolution, falls back to Supabase (L3) on cold starts.
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
        // 2. COLD START PATH: Resolve user_id from api_access, then fetch policy from user_policies.
        // Runs only on cache miss (once per 5 minutes per tenant).
        try {
            // Step A: resolve the owner of this API key
            const { data: keyRow, error: keyError } = await supabase_1.supabase
                .from('api_access')
                .select('user_id')
                .eq('api_key', apiKey)
                .single();
            if (keyError || !keyRow?.user_id) {
                return this.getDefaultPolicy();
            }
            // Step B: fetch the user's saved global policy
            const { data, error } = await supabase_1.supabase
                .from('user_policies')
                .select('mode, block_proxies, block_datacenters, force_bwt, difficulty_level, allowed_asns, blocked_asns')
                .eq('user_id', keyRow.user_id)
                .maybeSingle();
            if (error || !data) {
                return this.getDefaultPolicy();
            }
            const policy = {
                mode: data.mode || 'BALANCED',
                block_proxies: data.block_proxies ?? true,
                block_datacenters: data.block_datacenters ?? false,
                force_bwt: data.force_bwt ?? true,
                difficulty_level: data.difficulty_level ?? 3,
                allowed_asns: data.allowed_asns || [],
                blocked_asns: data.blocked_asns || []
            };
            // 3. Warm Redis so next 5 min of requests hit the fast path
            if (cache_1.redisClient) {
                await cache_1.redisClient.setex(cacheKey, 300, JSON.stringify(policy));
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
