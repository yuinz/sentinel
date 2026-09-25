import { Router, Request, Response } from 'express';
import { supabase } from '../config/supabase';
import { DossierService } from '../services/dossierService';
import logger from '../utils/logger';

const router = Router();

async function ensureSupabaseAuth(req: Request, res: Response, next: any) {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No authorization token provided' });
    }
    const token = authHeader.slice(7);
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
    (req as any).user = user;
    next();
}

/**
 * GET /api/intel/dossier?ip=1.2.3.4
 * Optional observed_* query params from the feed row.
 */
router.get('/dossier', ensureSupabaseAuth, async (req: any, res: Response) => {
    const ip = String(req.query.ip || '').trim();
    if (!ip || ip.length < 3 || ip.length > 64) {
        return res.status(400).json({ error: 'Valid ip query required' });
    }

    const observed = {
        verdict: req.query.verdict ? String(req.query.verdict) : undefined,
        score: req.query.score !== undefined && req.query.score !== '' ? Number(req.query.score) : undefined,
        reason: req.query.reason ? String(req.query.reason) : undefined,
        latency_ms: req.query.latency !== undefined && req.query.latency !== '' ? Number(req.query.latency) : undefined,
        profile: req.query.profile ? String(req.query.profile) : undefined,
        bwt_verified: req.query.bwt !== undefined
            ? (req.query.bwt === '1' || req.query.bwt === 'true')
            : undefined,
        time: req.query.time ? String(req.query.time) : undefined
    };

    try {
        const dossier = await DossierService.build(req.user.id, ip, observed);
        return res.json({ status: 'ok', dossier });
    } catch (err: any) {
        logger.error('[Dossier] build failed', err);
        return res.status(500).json({ error: 'Dossier enrichment failed' });
    }
});

export default router;
