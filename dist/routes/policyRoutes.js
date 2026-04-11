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
// GET — read current saved policy for this user (first key wins as global defaults)
router.get('/global', ensureSupabaseAuth, async (req, res) => {
    const user = req.user;
    try {
        const { data, error } = await supabase_1.supabase
            .from('tenant_policies')
            .select('mode, difficulty_level, block_proxies, block_datacenters, force_bwt')
            .eq('user_id', user.id)
            .limit(1)
            .single();
        if (error || !data)
            return res.json(null);
        return res.json(data);
    }
    catch {
        return res.json(null);
    }
});
router.post('/global', ensureSupabaseAuth, async (req, res) => {
    const user = req.user;
    const { mode, difficulty, block_proxies, block_dc, force_bwt } = req.body;
    try {
        // 1. Get all API keys belonging to this user
        const { data: keys, error: keyError } = await supabase_1.supabase
            .from('api_access')
            .select('api_key')
            .eq('user_id', user.id);
        if (keyError || !keys) {
            return res.status(500).json({ error: 'Failed to access keys' });
        }
        if (keys.length === 0) {
            return res.status(404).json({ error: 'No active vectors found to apply policies to' });
        }
        // 2. Upsert policy across all keys
        for (const k of keys) {
            const payload = {
                api_key: k.api_key,
                user_id: user.id,
                mode: mode || 'BALANCED',
                difficulty_level: difficulty || 3,
                block_proxies: block_proxies !== undefined ? block_proxies : true,
                block_datacenters: block_dc !== undefined ? block_dc : false,
                force_bwt: force_bwt !== undefined ? force_bwt : true,
                updated_at: new Date().toISOString()
            };
            const { error: upsertError } = await supabase_1.supabase
                .from('tenant_policies')
                .upsert(payload, { onConflict: 'api_key' });
            if (upsertError) {
                console.error('Failed applying policy to', k.api_key, upsertError);
            }
            // 3. Nuke Redis Cache to force Edge reload
            if (cache_1.redisClient) {
                cache_1.redisClient.del(`v2:policy:${k.api_key}`);
            }
        }
        res.json({ success: true, message: 'Global Policy Synchronized to Edge' });
    }
    catch (err) {
        res.status(500).json({ error: 'Database Synchronization failed' });
    }
});
exports.default = router;
