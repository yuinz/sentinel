"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.flushCache = exports.getVisitorStats = exports.verifyChallenge = exports.issueChallenge = exports.preCheck = exports.getHealth = exports.checkTarget = void 0;
const supabase_1 = require("../config/supabase");
const intelService_1 = require("../services/intelService");
const zod_1 = require("zod");
const axios_1 = __importDefault(require("axios"));
const crypto_1 = __importDefault(require("crypto"));
const logger_1 = __importDefault(require("../utils/logger"));
const cache_1 = require("../utils/cache");
const checkSchema = zod_1.z.object({
    target: zod_1.z.string().min(3).max(255),
    privacy_mode: zod_1.z.enum(['strict', 'full']).optional().default('full'),
    profile: zod_1.z.enum(['api', 'signup', 'payments', 'crypto']).optional().default('api')
});
const checkTarget = async (req, res) => {
    try {
        const validation = checkSchema.safeParse(req.body);
        if (!validation.success) {
            return res.status(400).json({ error: 'Invalid target format.', details: validation.error.format() });
        }
        const { target, privacy_mode, profile } = validation.data;
        const mode = req.query.mode;
        const bwtNonce = req.headers['x-bwt-nonce'];
        const trustToken = req.headers['x-sentinel-trust'];
        const bypassHeader = req.headers['x-sentinel-bypass'] === 'true';
        // 0. Developer Invisibility Layer
        if (bypassHeader && (target === '127.0.0.1' || target === 'localhost')) {
            logger_1.default.info(`Developer Bypass Triggered for ${target}`);
            return res.json({ status: 'success', allow: true, risk: 'none', reason: 'development_bypass' });
        }
        // 1. Cache Layer Check
        const cacheKey = `${target}:${privacy_mode}:${profile}:${trustToken || 'no-token'}`;
        const cachedResult = cache_1.intelCache.get(cacheKey);
        if (cachedResult) {
            cache_1.cacheStats.hits++;
        }
        else {
            cache_1.cacheStats.misses++;
        }
        const result = cachedResult ? cachedResult : await intelService_1.IntelService.analyze(target, privacy_mode, profile, trustToken, req.user?.tier);
        // 2. Persist to Cache if new
        if (!cachedResult) {
            cache_1.intelCache.set(cacheKey, result);
        }
        const isBwtValid = bwtNonce ? intelService_1.IntelService.verifyBehavioralWork(target, bwtNonce) : false;
        // 3. Telemetry Logic: Record the event for Analytics
        try {
            // We fire and forget this to keep response times <50ms
            supabase_1.supabase.from('telemetry').insert({
                api_access_id: req.apiRecordId,
                target: target,
                verdict: result.verdict,
                profile: profile,
                latency_ms: result.latency_ms,
                reason: result.verdict_reasons?.[0] || 'reputation_verified',
                confidence: result.confidence,
                bwt_verified: isBwtValid || !!trustToken,
                created_at: new Date().toISOString()
            }).then(({ error }) => {
                if (error)
                    logger_1.default.error('Telemetry Log Error:', error);
            });
        }
        catch (e) {
            logger_1.default.error('Telemetry recording failed');
        }
        // 4. Mode Selection (Standard vs Trust Decision)
        if (mode === 'decision') {
            const hasPassedChallenge = isBwtValid || !!trustToken;
            const allow = result.verdict !== 'UNTRUSTED' || hasPassedChallenge;
            return res.json({
                allow: allow,
                action: allow ? 'allow' : 'block',
                http_status: allow ? 200 : 403,
                risk: result.verdict.toLowerCase(),
                reason: result.verdict_reasons?.[0] || (allow ? 'reputation_verified' : 'untrusted_infrastructure'),
                confidence: result.confidence / 100,
                remediation: result.remediation
            });
        }
        logger_1.default.info(`Synthesis Complete: ${target} [Cache: ${cachedResult ? 'HIT' : 'MISS'}] [Mode: ${privacy_mode}]`);
        return res.json({
            status: 'success',
            trust_intel: {
                ...result,
                bwt_verified: isBwtValid,
                meta: {
                    usage_remaining: (req.user?.max_usage || 0) - (req.user?.usage_count || 0),
                    request_id: crypto_1.default.randomUUID(),
                    cached: !!cachedResult,
                    cache_reason: cachedResult ? 'asn_match' : 'fresh_resolution'
                }
            }
        });
    }
    catch (err) {
        logger_1.default.error('Controller error', err);
        return res.status(500).json({ error: err.message || 'Internal server error.' });
    }
};
exports.checkTarget = checkTarget;
const getHealth = async (req, res) => {
    const uptimeInSeconds = process.uptime();
    // Check External Intel Tethers (Lightweight)
    let intelStatus = 'OFFLINE';
    try {
        const intelCheck = await axios_1.default.get('https://internetdb.shodan.io/8.8.8.8', { timeout: 1500 });
        if (intelCheck.status === 200)
            intelStatus = 'ONLINE';
    }
    catch (e) {
        intelStatus = 'RATE_LIMITED_OR_OFFLINE';
    }
    const totalRequests = cache_1.cacheStats.hits + cache_1.cacheStats.misses;
    const hitRatio = totalRequests > 0 ? (cache_1.cacheStats.hits / totalRequests) : 0;
    return res.json({
        status: 'HEALTHY',
        vitals: {
            service: 'Sentinel-Engine',
            version: '1.2.0-ALPHA',
            uptime: `${Math.floor(uptimeInSeconds / 3600)}h ${Math.floor((uptimeInSeconds % 3600) / 60)}m`,
            asn_matrix_loaded: true,
            intel_tether_status: intelStatus
        },
        stats: {
            cache_hits: cache_1.cacheStats.hits,
            cache_misses: cache_1.cacheStats.misses,
            hit_ratio: `${(hitRatio * 100).toFixed(2)}%`,
            total_scans_serviced: totalRequests
        },
        timestamp: new Date().toISOString()
    });
};
exports.getHealth = getHealth;
const preCheck = async (req, res) => {
    // 1. Disable Caching (Ensure fresh high-authority assessment)
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    // 2. Resolve IP (With Mocking support ONLY in non-prod lab testing)
    const isProd = process.env.NODE_ENV === 'production';
    const mockIp = !isProd ? req.headers['x-sentinel-mock-ip'] : null;
    let target = mockIp ||
        req.ip ||
        req.headers['x-forwarded-for'] ||
        '127.0.0.1';
    if (target.startsWith('::1'))
        target = '127.0.0.1';
    if (target.startsWith('::ffff:'))
        target = target.substring(7);
    logger_1.default.info(`Pre-check request from: ${target} ${req.headers['x-sentinel-mock-ip'] ? '[MOCKED]' : ''}`);
    // Run high-authority analysis with forced enrichment
    const result = await intelService_1.IntelService.analyze(target, 'full', 'api', undefined, 'PRO', true);
    return res.json({
        required: result.verdict !== 'TRUSTED',
        verdict: result.verdict,
        score: result.trust_score,
        target: target
    });
};
exports.preCheck = preCheck;
const issueChallenge = async (req, res) => {
    const { target, context, duration } = req.body;
    if (!target)
        return res.status(400).json({ error: 'Target IP required.' });
    const challenge = await intelService_1.IntelService.issueBehavioralWork(target, context || 'general', duration);
    return res.json(challenge);
};
exports.issueChallenge = issueChallenge;
const verifyChallenge = async (req, res) => {
    const { target, nonce } = req.body;
    if (!target || !nonce)
        return res.status(400).json({ error: 'Target and Nonce required.' });
    const isValid = intelService_1.IntelService.verifyBehavioralWork(target, nonce);
    if (!isValid) {
        return res.status(403).json({ success: false, error: 'Trust verification failed.' });
    }
    const trustToken = intelService_1.IntelService.generateTrustToken(target);
    return res.json({
        success: true,
        trust_token: trustToken,
        confidence: 1.0,
        expires_in: 1800
    });
};
exports.verifyChallenge = verifyChallenge;
const getVisitorStats = async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const { data, error } = await supabase_1.supabase
            .from('site_visits')
            .select('country, created_at, ip')
            .gte('created_at', today.toISOString());
        if (error)
            throw error;
        const stats = (data || []).reduce((acc, visit) => {
            const country = visit.country || 'Unknown';
            acc.countries[country] = (acc.countries[country] || 0) + 1;
            acc.total++;
            return acc;
        }, { total: 0, countries: {} });
        return res.json({
            success: true,
            date: today.toDateString(),
            ...stats,
            raw_count: data?.length || 0
        });
    }
    catch (err) {
        logger_1.default.error('Failed to fetch visitor stats:', err);
        return res.status(500).json({ error: 'Intelligence retrieval failed.' });
    }
};
exports.getVisitorStats = getVisitorStats;
const flushCache = async (req, res) => {
    try {
        cache_1.intelCache.clear();
        cache_1.velocityCache.clear();
        cache_1.cacheStats.hits = 0;
        cache_1.cacheStats.misses = 0;
        logger_1.default.info('System Cache Flush Triggered');
        return res.json({ success: true, message: 'All telemetry and velocity caches purged.' });
    }
    catch (err) {
        return res.status(500).json({ error: 'Cache purge failed.' });
    }
};
exports.flushCache = flushCache;
