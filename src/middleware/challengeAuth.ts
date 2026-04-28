/**
 * challengeAuth.ts
 *
 * Soft-authentication middleware for the public BWT challenge endpoints.
 *
 * Design contract:
 *   - Valid sl_ key found in api_access  → lenient rate limit (120 req/min), keyed by tenant DB record ID
 *   - Key present but NOT in DB          → strict rate limit (10 req/min), keyed by IP  [demo key path]
 *   - No Authorization header at all     → strict rate limit (10 req/min), keyed by IP
 *   - DB error during lookup             → fail OPEN with strict rate limit — the widget NEVER goes down
 *
 * This intentionally does NOT deduct from usage_count (quota).
 * Challenge endpoints are pre-auth infrastructure, not billable API evaluations.
 *
 * V1 /check, V2 /evaluate, and all other routes are completely untouched.
 */

import { Request, Response, NextFunction } from 'express';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import { supabase } from '../config/supabase';
import logger from '../utils/logger';

// ─── Rate Limiters ─────────────────────────────────────────────────────────────

/**
 * Strict limiter: for anonymous callers, demo-key callers, or unknown keys.
 * 10 challenges per minute per IP. Kills bot farming while keeping human
 * widget users (who won't hit the widget 10x/min) completely unaffected.
 *
 * ipKeyGenerator is required by express-rate-limit v7+ to correctly normalise
 * IPv6 addresses — without it the library throws ERR_ERL_KEY_GEN_IPV6 on boot.
 */
const strictLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => {
        const rawIp =
            (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim()
            || req.ip
            || 'unknown';
        return ipKeyGenerator(rawIp);
    },
    handler: (_req: Request, res: Response) => {
        logger.warn('[ChallengeAuth] Rate limit exceeded (unauthenticated/unknown key)');
        res.status(429).json({
            error: 'Too many challenge requests. Provide a valid API key for higher limits.',
            code: 'CHALLENGE_RATE_LIMITED'
        });
    }
});

/**
 * Lenient limiter: for verified tenant keys.
 * 120 challenges per minute, keyed by the tenant's DB record ID — not IP.
 * This correctly handles tenants behind CDNs or shared egress IPs.
 *
 * Falls back through ipKeyGenerator so IPv6 normalisation is always applied
 * when we do need the IP as the key.
 */
const tenantLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 120,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => {
        const tenantId = (req as any).__challengeTenantId?.toString();
        if (tenantId) return tenantId;
        const rawIp =
            (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim()
            || req.ip
            || 'unknown';
        return ipKeyGenerator(rawIp);
    },
    handler: (_req: Request, res: Response) => {
        logger.warn('[ChallengeAuth] Tenant challenge rate limit exceeded');
        res.status(429).json({
            error: 'Challenge rate limit exceeded. Please slow down.',
            code: 'TENANT_CHALLENGE_RATE_LIMITED'
        });
    }
});

// ─── Middleware ────────────────────────────────────────────────────────────────

export const challengeAuthMiddleware = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    // 1. Extract key from Authorization header (Bearer) or x-api-key header
    const authHeader = req.headers['authorization'];
    const rawKeyHeader = req.headers['x-api-key'] as string | undefined;

    let apiKey: string | null = null;

    if (authHeader && authHeader.startsWith('Bearer ')) {
        apiKey = authHeader.slice(7).trim() || null;
    } else if (rawKeyHeader) {
        apiKey = rawKeyHeader.trim() || null;
    }

    // 2. No key → apply strict rate limit, then let the request through
    if (!apiKey) {
        logger.debug('[ChallengeAuth] No API key — applying strict rate limit');
        strictLimiter(req, res, next);
        return;
    }

    // 3. Key present → check against api_access
    try {
        const { data, error } = await supabase
            .from('api_access')
            .select('id')
            .eq('api_key', apiKey)
            .maybeSingle(); // maybeSingle returns null (not error) on no rows found

        if (error) {
            // DB query error (network blip, etc.) — fail OPEN, strict rate limit
            logger.error('[ChallengeAuth] DB lookup error, failing open:', error.message);
            strictLimiter(req, res, next);
            return;
        }

        if (!data) {
            // Key not found — could be demo key (sk_test_...) or a stale/invalid key.
            // Apply strict rate limit but do NOT hard-block (demo key must still work).
            logger.debug(`[ChallengeAuth] Unknown key: ${apiKey.substring(0, 8)}... — applying strict rate limit`);
            strictLimiter(req, res, next);
            return;
        }

        // 4. Valid key — tag the request with tenant ID for the rate limiter keygen,
        //    then apply the lenient tenant limiter
        (req as any).__challengeTenantId = data.id;
        logger.debug(`[ChallengeAuth] Valid key — tenant ${data.id} — applying lenient rate limit`);
        tenantLimiter(req, res, next);
        return;

    } catch (err: any) {
        // Unexpected exception — fail OPEN so the widget never goes down
        logger.error('[ChallengeAuth] Unexpected exception, failing open:', err?.message || err);
        strictLimiter(req, res, next);
        return;
    }
};
