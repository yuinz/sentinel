"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const supabase_1 = require("../config/supabase");
const dossierService_1 = require("../services/dossierService");
const logger_1 = __importDefault(require("../utils/logger"));
const router = (0, express_1.Router)();
async function ensureSupabaseAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No authorization token provided' });
    }
    const token = authHeader.slice(7);
    const { data: { user }, error } = await supabase_1.supabase.auth.getUser(token);
    if (error || !user) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
}
/**
 * GET /api/intel/dossier?ip=1.2.3.4
 * Optional observed_* query params from the feed row.
 */
router.get('/dossier', ensureSupabaseAuth, async (req, res) => {
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
        const dossier = await dossierService_1.DossierService.build(req.user.id, ip, observed);
        return res.json({ status: 'ok', dossier });
    }
    catch (err) {
        logger_1.default.error('[Dossier] build failed', err);
        return res.status(500).json({ error: 'Dossier enrichment failed' });
    }
});
exports.default = router;
