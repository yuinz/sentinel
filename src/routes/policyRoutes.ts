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

router.post('/global', ensureSupabaseAuth, async (req: any, res) => {
    const user = req.user;
    const { mode, difficulty, block_proxies, block_dc, force_bwt } = req.body;

    try {
        // 1. Get all API keys belonging to this user
        const { data: keys, error: keyError } = await supabase
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

            const { error: upsertError } = await supabase
                .from('tenant_policies')
                .upsert(payload, { onConflict: 'api_key' });

            if (upsertError) {
                console.error('Failed applying policy to', k.api_key, upsertError);
            }

            // 3. Nuke Redis Cache to force Edge reload
            if (redisClient) {
                redisClient.del(`v2:policy:${k.api_key}`);
            }
        }

        res.json({ success: true, message: 'Global Policy Synchronized to Edge' });
    } catch (err) {
        res.status(500).json({ error: 'Database Synchronization failed' });
    }
});

export default router;
