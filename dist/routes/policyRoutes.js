"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const supabase_1 = require("../config/supabase");
const cache_1 = require("../utils/cache");
const router = (0, express_1.Router)();
// Middleware to verify Supabase JWT
const ensureSupabaseAuth = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No authorization token provided' });
    }
    const token = authHeader.split(' ')[1];
    const { data: { user }, error } = await supabase_1.supabase.auth.getUser(token);
    if (error || !user) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
};
// GET — return saved policy for this user
router.get('/global', ensureSupabaseAuth, async (req, res) => {
    const user = req.user;
    try {
        const { data } = await supabase_1.supabase
            .from('user_policies')
            .select('mode, difficulty_level, block_proxies, block_datacenters, force_bwt')
            .eq('user_id', user.id)
            .maybeSingle();
        return res.json(data || null);
    }
    catch {
        return res.json(null);
    }
});
// POST — upsert policy for this user (one row per user, no FK dependency)
router.post('/global', ensureSupabaseAuth, async (req, res) => {
    const user = req.user;
    const { mode, difficulty, block_proxies, block_dc, force_bwt } = req.body;
    try {
        const payload = {
            user_id: user.id,
            mode: mode || 'BALANCED',
            difficulty_level: difficulty || 3,
            block_proxies: block_proxies !== undefined ? block_proxies : true,
            block_datacenters: block_dc !== undefined ? block_dc : false,
            force_bwt: force_bwt !== undefined ? force_bwt : true,
            updated_at: new Date().toISOString()
        };
        const { error } = await supabase_1.supabase
            .from('user_policies')
            .upsert(payload, { onConflict: 'user_id' });
        if (error) {
            console.error('[Policy] Upsert failed:', error);
            return res.status(500).json({ error: 'Failed to save policy', detail: error.message });
        }
        // Flush Redis cache for all API keys belonging to this user
        if (cache_1.redisClient) {
            const { data: keys } = await supabase_1.supabase
                .from('api_access')
                .select('api_key')
                .eq('user_id', user.id);
            if (keys) {
                for (const k of keys) {
                    cache_1.redisClient.del(`v2:policy:v2:${k.api_key}`);
                }
            }
        }
        return res.json({ success: true });
    }
    catch (err) {
        return res.status(500).json({ error: 'Database synchronization failed' });
    }
});
exports.default = router;
