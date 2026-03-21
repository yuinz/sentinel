import { Request, Response, RequestHandler } from 'express';
import { supabase } from '../config/supabase';
import { AuthRequest } from '../middleware/auth';
import { IntelService } from '../services/intelService';
import { z as zod } from 'zod';
import axios from 'axios';
import crypto from 'crypto';
import logger from '../utils/logger';
import { BroadcastService } from '../services/broadcastService';
import { intelCache, cacheStats, velocityCache } from '../utils/cache';

const checkSchema = zod.object({
    target: zod.string().min(3).max(255),
    privacy_mode: zod.enum(['strict', 'full']).optional().default('full'),
    profile: zod.enum(['api', 'signup', 'payments', 'crypto']).optional().default('api')
});

export const checkTarget = async (req: AuthRequest, res: Response) => {
    try {
        const validation = checkSchema.safeParse(req.body);
        if (!validation.success) {
            return res.status(400).json({ error: 'Invalid target format.', details: validation.error.format() });
        }

        const { target, privacy_mode, profile } = validation.data;
        const mode = req.query.mode as string;
        const bwtNonce = req.headers['x-bwt-nonce'] as string;
        const trustToken = req.headers['x-sentinel-trust'] as string;
        const bypassHeader = req.headers['x-sentinel-bypass'] === 'true';
        const userAgent = (req.headers['user-agent'] as string) || 'unknown';

        // 0. Developer Invisibility Layer
        if (bypassHeader && (target === '127.0.0.1' || target === 'localhost')) {
            logger.info(`Developer Bypass Triggered for ${target}`);
            return res.json({ status: 'success', allow: true, risk: 'none', reason: 'development_bypass' });
        }

        // 1. Cache Layer Check
        const cacheKey = `${target}:${privacy_mode}:${profile}:${trustToken || 'no-token'}`;
        const cachedResult = intelCache.get(cacheKey);
        if (cachedResult) {
            cacheStats.hits++;
        } else {
            cacheStats.misses++;
        }

        const result = cachedResult ? cachedResult : await IntelService.analyze(target, privacy_mode, profile, trustToken, req.user?.tier);

        // 2. Persist to Cache if new
        if (!cachedResult) {
            intelCache.set(cacheKey, result);
        }

        const isBwtValid = bwtNonce ? IntelService.verifyBehavioralWork(target, bwtNonce, userAgent) : false;

        // 3. Telemetry Logic: Record the event for Analytics
        const isBotMonitor = userAgent.toLowerCase().includes('uptimerobot');

        if (!isBotMonitor) {
            try {
                // We fire and forget this to keep response times <50ms
                const telemetryPayload = {
                    api_access_id: (req as any).apiRecordId,
                    target: target,
                    verdict: result.verdict,
                    trust_score: result.trust_score,
                    profile: profile,
                    latency_ms: result.latency_ms,
                    reason: result.verdict_reasons?.[0] || (result.verdict === 'UNTRUSTED' ? 'untrusted_infrastructure' : 'reputation_verified'),
                    confidence: result.confidence / 100,
                    bwt_verified: isBwtValid || !!trustToken,
                    created_at: new Date().toISOString()
                };

                supabase.from('telemetry').insert(telemetryPayload).then(({ error }) => {
                    if (error) {
                        logger.error('Telemetry Log Error:', error);
                    }
                });
            } catch (e) {
                logger.error('Telemetry recording failed', e);
            }

            // 3.5 Global Propagation: Broadcast UNTRUSTED signals to the Edge
            if (result.verdict === 'UNTRUSTED') {
                BroadcastService.broadcast({
                    ip: target,
                    verdict: 'UNTRUSTED',
                    reason: result.verdict_reasons?.[0] || 'untrusted_infrastructure',
                    profile: profile
                }).catch(e => logger.error('Global Broadcast failed', e));
            }
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
                latency_ms: result.latency_ms,
                remediation: result.remediation
            });
        }

        logger.info(`Synthesis Complete: ${target} [Cache: ${cachedResult ? 'HIT' : 'MISS'}] [Mode: ${privacy_mode}]`);

        return res.json({
            status: 'success',
            trust_intel: {
                ...result,
                bwt_verified: isBwtValid,
                meta: {
                    usage_remaining: (req.user?.max_usage || 0) - (req.user?.usage_count || 0),
                    request_id: crypto.randomUUID(),
                    cached: !!cachedResult,
                    cache_reason: cachedResult ? 'asn_match' : 'fresh_resolution'
                }
            }
        });

    } catch (err: any) {
        logger.error('Controller error', err);
        return res.status(500).json({ error: err.message || 'Internal server error.' });
    }
};

export const getHealth = async (req: AuthRequest, res: Response) => {
    const uptimeInSeconds = process.uptime();

    // Check External Intel Tethers (Lightweight)
    let intelStatus = 'OFFLINE';
    try {
        const intelCheck = await axios.get('https://internetdb.shodan.io/8.8.8.8', { timeout: 1500 });
        if (intelCheck.status === 200) intelStatus = 'ONLINE';
    } catch (e) {
        intelStatus = 'RATE_LIMITED_OR_OFFLINE';
    }

    const totalRequests = cacheStats.hits + cacheStats.misses;
    const hitRatio = totalRequests > 0 ? (cacheStats.hits / totalRequests) : 0;

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
            cache_hits: cacheStats.hits,
            cache_misses: cacheStats.misses,
            hit_ratio: `${(hitRatio * 100).toFixed(2)}%`,
            total_scans_serviced: totalRequests
        },
        timestamp: new Date().toISOString()
    });
};

export const preCheck: RequestHandler = async (req: Request, res: Response) => {
    // 1. Disable Caching (Ensure fresh high-authority assessment)
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    // 2. Resolve IP (With Mocking support ONLY in non-prod lab testing)
    const isProd = process.env.NODE_ENV === 'production';
    const mockIp = !isProd ? (req.headers['x-sentinel-mock-ip'] as string) : null;

    let target = mockIp ||
        req.ip ||
        (req.headers['x-forwarded-for'] as string) ||
        '127.0.0.1';

    if (target.startsWith('::1')) target = '127.0.0.1';
    if (target.startsWith('::ffff:')) target = target.substring(7);

    logger.info(`Pre-check request from: ${target} ${req.headers['x-sentinel-mock-ip'] ? '[MOCKED]' : ''}`);

    // Run high-authority analysis with forced enrichment
    const result = await IntelService.analyze(target, 'full', 'api', undefined, 'PRO', true);

    return res.json({
        required: result.verdict !== 'TRUSTED',
        verdict: result.verdict,
        score: result.trust_score,
        target: target
    });
};

export const issueChallenge = async (req: AuthRequest, res: Response) => {
    const { target, context, duration } = req.body;
    if (!target) return res.status(400).json({ error: 'Target IP required.' });

    const userAgent = (req.headers['user-agent'] as string) || 'unknown';
    const challenge = await IntelService.issueBehavioralWork(target, context || 'general', duration, userAgent);
    return res.json(challenge);
};

export const verifyChallenge = async (req: AuthRequest, res: Response) => {
    const { target, nonce } = req.body;
    if (!target || !nonce) return res.status(400).json({ error: 'Target and Nonce required.' });

    const userAgent = (req.headers['user-agent'] as string) || 'unknown';
    const isValid = IntelService.verifyBehavioralWork(target, nonce, userAgent);
    if (!isValid) {
        return res.status(403).json({ success: false, error: 'Trust verification failed.' });
    }

    const trustToken = IntelService.generateTrustToken(target);
    return res.json({
        success: true,
        trust_token: trustToken,
        confidence: 1.0,
        expires_in: 1800
    });
};

export const getVisitorStats = async (req: Request, res: Response) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const { data, error } = await supabase
            .from('site_visits')
            .select('country, created_at, ip')
            .gte('created_at', today.toISOString());

        if (error) throw error;

        const stats = (data || []).reduce((acc: any, visit: any) => {
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
    } catch (err: any) {
        logger.error('Failed to fetch visitor stats:', err);
        return res.status(500).json({ error: 'Intelligence retrieval failed.' });
    }
};
export const flushCache = async (req: Request, res: Response) => {
    try {
        intelCache.clear();
        velocityCache.clear();
        cacheStats.hits = 0;
        cacheStats.misses = 0;

        logger.info('System Cache Flush Triggered');
        return res.json({ success: true, message: 'All telemetry and velocity caches purged.' });
    } catch (err: any) {
        return res.status(500).json({ error: 'Cache purge failed.' });
    }
};
