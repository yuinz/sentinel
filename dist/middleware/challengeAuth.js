"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.challengeAuthMiddleware = void 0;
const express_rate_limit_1 = __importStar(require("express-rate-limit"));
const supabase_1 = require("../config/supabase");
const logger_1 = __importDefault(require("../utils/logger"));
// ─── Rate Limiters ─────────────────────────────────────────────────────────────
/**
 * Strict limiter: for anonymous callers, demo-key callers, or unknown keys.
 * 10 challenges per minute per IP. Kills bot farming while keeping human
 * widget users (who won't hit the widget 10x/min) completely unaffected.
 *
 * ipKeyGenerator is required by express-rate-limit v7+ to correctly normalise
 * IPv6 addresses — without it the library throws ERR_ERL_KEY_GEN_IPV6 on boot.
 */
const strictLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        const rawIp = req.headers['x-forwarded-for']?.split(',')[0].trim()
            || req.ip
            || 'unknown';
        return (0, express_rate_limit_1.ipKeyGenerator)(rawIp);
    },
    handler: (_req, res) => {
        logger_1.default.warn('[ChallengeAuth] Rate limit exceeded (unauthenticated/unknown key)');
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
const tenantLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60 * 1000,
    limit: 120,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        const tenantId = req.__challengeTenantId?.toString();
        if (tenantId)
            return tenantId;
        const rawIp = req.headers['x-forwarded-for']?.split(',')[0].trim()
            || req.ip
            || 'unknown';
        return (0, express_rate_limit_1.ipKeyGenerator)(rawIp);
    },
    handler: (_req, res) => {
        logger_1.default.warn('[ChallengeAuth] Tenant challenge rate limit exceeded');
        res.status(429).json({
            error: 'Challenge rate limit exceeded. Please slow down.',
            code: 'TENANT_CHALLENGE_RATE_LIMITED'
        });
    }
});
// ─── Middleware ────────────────────────────────────────────────────────────────
const challengeAuthMiddleware = async (req, res, next) => {
    // 1. Extract key from Authorization header (Bearer) or x-api-key header
    const authHeader = req.headers['authorization'];
    const rawKeyHeader = req.headers['x-api-key'];
    let apiKey = null;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        apiKey = authHeader.slice(7).trim() || null;
    }
    else if (rawKeyHeader) {
        apiKey = rawKeyHeader.trim() || null;
    }
    // 2. No key → apply strict rate limit, then let the request through
    if (!apiKey) {
        logger_1.default.debug('[ChallengeAuth] No API key — applying strict rate limit');
        strictLimiter(req, res, next);
        return;
    }
    // 3. Key present → check against api_access
    try {
        const { data, error } = await supabase_1.supabase
            .from('api_access')
            .select('id')
            .eq('api_key', apiKey)
            .maybeSingle(); // maybeSingle returns null (not error) on no rows found
        if (error) {
            // DB query error (network blip, etc.) — fail OPEN, strict rate limit
            logger_1.default.error('[ChallengeAuth] DB lookup error, failing open:', error.message);
            strictLimiter(req, res, next);
            return;
        }
        if (!data) {
            // Key not found — could be demo key (sk_test_...) or a stale/invalid key.
            // Apply strict rate limit but do NOT hard-block (demo key must still work).
            logger_1.default.debug(`[ChallengeAuth] Unknown key: ${apiKey.substring(0, 8)}... — applying strict rate limit`);
            strictLimiter(req, res, next);
            return;
        }
        // 4. Valid key — tag the request with tenant ID for the rate limiter keygen,
        //    then apply the lenient tenant limiter
        req.__challengeTenantId = data.id;
        logger_1.default.debug(`[ChallengeAuth] Valid key — tenant ${data.id} — applying lenient rate limit`);
        tenantLimiter(req, res, next);
        return;
    }
    catch (err) {
        // Unexpected exception — fail OPEN so the widget never goes down
        logger_1.default.error('[ChallengeAuth] Unexpected exception, failing open:', err?.message || err);
        strictLimiter(req, res, next);
        return;
    }
};
exports.challengeAuthMiddleware = challengeAuthMiddleware;
