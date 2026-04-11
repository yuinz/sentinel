import { Router, Request, Response } from 'express';
import { supabase } from '../config/supabase';
import { redisClient } from '../utils/cache';

const router = Router();

// Middleware to verify Supabase JWT
const ensureSupabaseAuth = async (req: Request, res: Response, next: any) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No authorization token provided' });
    }

    const token = authHeader.split(' ')[1];
    const { data: { user }, error } = await supabase.auth.getUser(token);

    if (error || !user) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }

    (req as any).user = user;
    next();
};

// GET — return saved policy for this user
router.get('/global', ensureSupabaseAuth, async (req: any, res) => {
    const user = req.user;
    try {
        const { data } = await supabase
            .from('user_policies')
            .select('mode, difficulty_level, vpn_action, datacenter_action, exempt_server_requests, block_proxies, block_datacenters, force_bwt')
            .eq('user_id', user.id)
            .maybeSingle();

        if (data) {
            // Apply migration fallback so the UI always gets the new schema shape
            data.vpn_action = data.vpn_action || (data.block_proxies ? 'block' : 'allow');
            data.datacenter_action = data.datacenter_action || (data.block_datacenters ? 'block' : 'allow');
            data.exempt_server_requests = data.exempt_server_requests ?? false;
        }

        return res.json(data || null);
    } catch {
        return res.json(null);
    }
});

// POST — upsert policy for this user (one row per user, no FK dependency)
router.post('/global', ensureSupabaseAuth, async (req: any, res) => {
    const user = req.user;
    const { mode, difficulty, vpn_action, datacenter_action, exempt_server_requests, block_proxies, block_dc, force_bwt } = req.body;

    try {
        const payload = {
            user_id: user.id,
            mode: mode || 'BALANCED',
            difficulty_level: difficulty || 3,
            vpn_action: vpn_action || (block_proxies !== undefined ? (block_proxies ? 'block' : 'allow') : 'allow'),
            datacenter_action: datacenter_action || (block_dc !== undefined ? (block_dc ? 'block' : 'allow') : 'allow'),
            exempt_server_requests: exempt_server_requests || false,
            force_bwt: force_bwt !== undefined ? force_bwt : true,
            updated_at: new Date().toISOString()
        };

        const { error } = await supabase
            .from('user_policies')
            .upsert(payload, { onConflict: 'user_id' });

        if (error) {
            console.error('[Policy] Upsert failed:', error);
            return res.status(500).json({ error: 'Failed to save policy', detail: error.message });
        }

        // Flush Redis cache for all API keys belonging to this user
        if (redisClient) {
            const { data: keys } = await supabase
                .from('api_access')
                .select('api_key')
                .eq('user_id', user.id);

            if (keys) {
                for (const k of keys) {
                    redisClient.del(`v2:policy:v2:${k.api_key}`);
                }
            }
        }

        return res.json({ success: true });
    } catch (err) {
        return res.status(500).json({ error: 'Database synchronization failed' });
    }
});

export default router;
