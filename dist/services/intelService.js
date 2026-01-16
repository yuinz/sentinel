"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.IntelService = exports.SENTINEL_PROFILES = void 0;
const axios_1 = __importDefault(require("axios"));
const crypto_1 = __importDefault(require("crypto"));
const logger_1 = __importDefault(require("../utils/logger"));
const cache_1 = require("../utils/cache");
const HIGH_RISK_ASNS = [
    212238, 9009, 14061, 20473, 16509, 14618, 63949, 15169, 396982,
    24940, 21341, 16276, 13335, 54113, 20940, 204915, 47583, 53667,
    8100, 13213, 46475, 60068, 199218, 203020, 201839, 398324,
    398705, 398722, 211298, 213412, 216341, 30823, 214497, 215208,
    215240, 198953, 200593, 42969, 215778, 49217, 20052, 11878,
    46562, 204957, 216419, 51167, 12876, 16276, 35816, 50673
];
exports.SENTINEL_PROFILES = {
    api: { threshold: 60 },
    signup: { threshold: 75 },
    payments: { threshold: 85 },
    crypto: { threshold: 90 }
};
class IntelService {
    /**
     * The Real Product: Decision Latency.
     * Rendering a trust decision in <50ms by prioritizing in-memory signals.
     */
    static async analyze(target, privacyMode = 'full', profileName = 'api', trustToken) {
        const start = Date.now();
        const profile = exports.SENTINEL_PROFILES[profileName];
        const signals = [];
        // 1. Private/Internal IP Bypass (Instant)
        if (this.isPrivateIp(target)) {
            return this.finalize(target, 100, 'TRUSTED', [{ id: 'NET-LOCAL', label: 'Local Network', weight: 0, status: 'positive' }], start);
        }
        // 2. Trust Token Verification (Local HMAC - <2ms)
        let trustBonus = 0;
        if (trustToken && this.verifyTrustToken(target, trustToken)) {
            trustBonus = 35;
            signals.push({ id: 'NET-RECOVERY', label: 'Verified Intent Proof', weight: 35, status: 'positive', confidence: 1.0 });
        }
        // 3. FAST PATH: Local ASN Matrix & Velocity (<5ms)
        const asnRisk = this.checkLocalAsnMatrix(target);
        const velocity = cache_1.velocityCache.get(target) || [];
        const isHighVelocity = velocity.length > 5;
        // Update velocity sync
        velocity.push(Date.now());
        cache_1.velocityCache.set(target, velocity.slice(-10));
        let currentRisk = asnRisk.risk + (isHighVelocity ? 20 : 0);
        if (asnRisk.risk > 0)
            signals.push({ id: 'ASN-MATRIX', label: 'High-Risk Network Match', weight: asnRisk.risk, status: 'negative' });
        if (isHighVelocity)
            signals.push({ id: 'NET-VELOCITY', label: 'Request Velocity Spike', weight: 20, status: 'negative' });
        // 4. COLD ENRICHMENT: Triggered Async
        // We do NOT await external I/O here. We return the best decision we can 
        // using fast signals, and let the background worker populate the deep intel for the next check.
        this.enrichInBackground(target, privacyMode, profileName);
        const finalScore = Math.max(0, 100 - currentRisk + trustBonus);
        const verdict = finalScore >= (profile.threshold + 15) ? 'TRUSTED' : finalScore >= profile.threshold ? 'UNSTABLE' : 'UNTRUSTED';
        return this.finalize(target, finalScore, verdict, signals, start, {
            remediation: finalScore < profile.threshold + 15 ? {
                type: 'challenge',
                optional: finalScore >= profile.threshold,
                recommended: true,
                behavioral_duration: finalScore < profile.threshold ? 4.0 : 2.0
            } : undefined
        });
    }
    static finalize(target, score, verdict, signals, start, extra = {}) {
        return {
            target,
            trust_score: score,
            confidence: 0.9,
            verdict,
            geo: { infrastructure: 'analyzing...' },
            signals,
            latency_ms: Date.now() - start,
            ...extra
        };
    }
    static async enrichInBackground(target, privacyMode, profileName) {
        // Heavy I/O moved to separate thread/execution context
        try {
            const cacheKey = `deep:${target}`;
            if (cache_1.intelCache.get(cacheKey))
                return; // Already enriched
            const res = await axios_1.default.get(`https://ipwho.is/${target}`, { timeout: 2000 });
            if (res.data && res.data.success) {
                cache_1.intelCache.set(cacheKey, res.data, { ttl: 3600 }); // Cache deep intel for 1 hour
                logger_1.default.info(`Cold Enrichment Resolved: ${target}`);
            }
        }
        catch (e) {
            // Background resolution failed - system stays fast regardless
        }
    }
    static checkLocalAsnMatrix(target) {
        // Logic for fast local range check would go here
        return { risk: 0 };
    }
    static isPrivateIp(ip) {
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4)
            return false;
        return parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168) || parts[0] === 127;
    }
    static verifyTrustToken(target, token) {
        try {
            const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
            const decoded = Buffer.from(token, 'base64').toString();
            const [t, ts, sig] = decoded.split(':');
            return t === target && (Math.floor(Date.now() / 1000) - parseInt(ts)) < 1800 && sig === crypto_1.default.createHmac('sha256', salt).update(`${t}:${ts}`).digest('hex').substring(0, 16);
        }
        catch {
            return false;
        }
    }
    static async issueBehavioralWork(target, context, duration) {
        const difficulty = 4;
        const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
        const signature = crypto_1.default.createHash('sha256').update(target + salt + difficulty).digest('hex').substring(0, 8);
        return {
            challenge_id: `ch_${crypto_1.default.randomBytes(4).toString('hex')}`,
            type: 'BWT',
            difficulty,
            nonce_prefix: `${signature}${difficulty}`,
            behavioral_duration: duration || 2.0,
            instruction: `Intent Proof: Click and hold for ${duration || 2.0}s.`
        };
    }
    static verifyBehavioralWork(target, nonce) {
        try {
            const difficulty = parseInt(nonce.substring(8, 9), 10);
            const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
            const signature = crypto_1.default.createHash('sha256').update(target + salt + difficulty).digest('hex').substring(0, 8);
            return crypto_1.default.createHash('sha256').update(`${signature}${difficulty}${nonce}`).digest('hex').startsWith("0".repeat(difficulty));
        }
        catch {
            return false;
        }
    }
    static generateTrustToken(target) {
        const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
        const ts = Math.floor(Date.now() / 1000);
        const sig = crypto_1.default.createHmac('sha256', salt).update(`${target}:${ts}`).digest('hex').substring(0, 16);
        return Buffer.from(`${target}:${ts}:${sig}`).toString('base64');
    }
}
exports.IntelService = IntelService;
