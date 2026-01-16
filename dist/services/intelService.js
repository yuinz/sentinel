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
    static async analyze(target, privacyMode = 'full', profileName = 'api', trustToken, tier = 'FREE', forceEnrich = false) {
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
        // 4. COLD ENRICHMENT: Triggered Async (PRO Only)
        if (tier === 'PRO') {
            // Check if we already have this IP's DNA in cache
            const cacheKey = `deep:${target}`;
            const deepIntel = cache_1.intelCache.get(cacheKey);
            if (deepIntel && deepIntel.asn) {
                const asnNumber = deepIntel.asn.asn;
                const isHighRisk = HIGH_RISK_ASNS.includes(asnNumber);
                if (isHighRisk) {
                    currentRisk += 80; // Massive penalty for Data Centers/VPNs
                    signals.push({
                        id: 'ASN-REPUTATION',
                        label: `High-Risk Infrastructure (${deepIntel.asn.name || 'Hosting'})`,
                        weight: 80,
                        status: 'negative',
                        confidence: 0.95
                    });
                }
                else {
                    signals.push({ id: 'ASN-REPUTATION', label: 'Residential/Consumer Network', weight: 0, status: 'positive' });
                }
            }
            else {
                if (forceEnrich) {
                    const freshIntel = await this.performSyncEnrich(target);
                    if (freshIntel && freshIntel.asn) {
                        const isHighRisk = HIGH_RISK_ASNS.includes(freshIntel.asn.asn);
                        if (isHighRisk) {
                            currentRisk += 80;
                            signals.push({ id: 'ASN-REPUTATION', label: `High-Risk Infrastructure (${freshIntel.asn.name})`, weight: 80, status: 'negative' });
                        }
                    }
                }
                else {
                    // If not in cache, trigger background enrichment for next time
                    this.enrichInBackground(target, privacyMode, profileName);
                    signals.push({ id: 'SYS-PENDING', label: 'Background Forensic Gathering', weight: 0, status: 'neutral' });
                }
            }
        }
        else {
            signals.push({ id: 'SYS-FREE', label: 'Limited Signals (Free Tier)', weight: 0, status: 'neutral' });
        }
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
    static async performSyncEnrich(target) {
        try {
            const res = await axios_1.default.get(`https://ipwho.is/${target}`, { timeout: 1500 });
            if (res.data && res.data.success) {
                const cacheKey = `deep:${target}`;
                cache_1.intelCache.set(cacheKey, res.data, { ttl: 3600 });
                return res.data;
            }
        }
        catch {
            return null;
        }
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
        // Instant forensic check against known hosting ranges
        for (const range of this.DATACENTER_RANGES) {
            if (this.ipInRow(target, range)) {
                return { risk: 85 }; // Critical Risk: Data-Center Origin
            }
        }
        return { risk: 0 };
    }
    static ipInRow(ip, cipher) {
        try {
            const [range, bits] = cipher.split('/');
            const mask = ~((1 << (32 - parseInt(bits))) - 1) >>> 0;
            const ipDots = ip.split('.').map(Number);
            const rangeDots = range.split('.').map(Number);
            const ipInt = ((ipDots[0] << 24) | (ipDots[1] << 16) | (ipDots[2] << 8) | ipDots[3]) >>> 0;
            const rangeInt = ((rangeDots[0] << 24) | (rangeDots[1] << 16) | (rangeDots[2] << 8) | rangeDots[3]) >>> 0;
            return (ipInt & mask) === (rangeInt & mask);
        }
        catch {
            return false;
        }
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
        const prefix = `${signature}${difficulty}`;
        logger_1.default.info(`[PoW Issue] Target: ${target}, Prefix: ${prefix}`);
        return {
            challenge_id: `ch_${crypto_1.default.randomBytes(4).toString('hex')}`,
            type: 'BWT',
            difficulty,
            nonce_prefix: prefix,
            behavioral_duration: duration || 2.0,
            instruction: `Intent Proof: Click and hold for ${duration || 2.0}s.`
        };
    }
    static verifyBehavioralWork(target, nonce) {
        try {
            const difficulty = parseInt(nonce.substring(8, 9), 10);
            const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
            const signature = crypto_1.default.createHash('sha256').update(target + salt + difficulty).digest('hex').substring(0, 8);
            logger_1.default.info(`[PoW Verify] Target: ${target}, Difficulty: ${difficulty}`);
            logger_1.default.info(`[PoW Verify] Nonce: ${nonce}`);
            logger_1.default.info(`[PoW Verify] Expected Signature Prefix: ${signature}`);
            if (!nonce.startsWith(`${signature}${difficulty}`)) {
                logger_1.default.warn(`[PoW Verify] Signature Mismatch! Nonce doesn't start with ${signature}${difficulty}`);
                return false;
            }
            const hash = crypto_1.default.createHash('sha256').update(nonce).digest('hex');
            const isValid = hash.startsWith("0".repeat(difficulty));
            logger_1.default.info(`[PoW Verify] Computed Hash: ${hash}`);
            logger_1.default.info(`[PoW Verify] Is Valid: ${isValid}`);
            return isValid;
        }
        catch (err) {
            logger_1.default.error(`[PoW Verify] Error during verification: ${err}`);
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
// Comprehensive High-Risk Matrix (Hosting, VPN, Tor, Proxy)
// In Pro Tier, this list is updated via the Sentinel Global C2 every 6 hours.
IntelService.DATACENTER_RANGES = [
    // Amazon Web Services (AWS)
    '3.0.0.0/8', '13.0.0.0/8', '18.0.0.0/8', '34.192.0.0/10', '35.160.0.0/12',
    '44.0.0.0/8', '52.0.0.0/10', '54.0.0.0/8',
    // Microsoft Azure
    '13.64.0.0/11', '20.33.0.0/16', '23.96.0.0/12', '40.64.0.0/10',
    '51.103.0.0/16', '52.136.0.0/13',
    // Google Cloud (GCP)
    '34.64.0.0/10', '35.184.0.0/13', '104.154.0.0/15',
    // DigitalOcean
    '104.248.0.0/13', '138.197.0.0/16', '159.203.0.0/16', '165.22.0.0/16',
    // Akamai / Linode / Cloudflare
    '45.33.0.0/16', '104.16.0.0/12', '162.158.0.0/15', '172.64.0.0/13',
    // Vultr / Hetzner / OVH
    '45.32.0.0/16', '108.61.0.0/16', '95.216.0.0/15', '116.202.0.0/15',
    '51.254.0.0/15', '54.36.0.0/15', '188.165.0.0/16',
    // Common VPN Vectors (M247, Datacamp, Choopa)
    '185.204.0.0/22', '193.108.0.0/22', '185.228.0.0/16', '193.36.0.0/16',
    '89.187.0.0/16', '45.155.0.0/16', '82.102.0.0/16', '84.239.0.0/16',
    '185.151.0.0/16', '212.102.0.0/18',
    // Specialized Anonymizers
    '185.220.101.0/24', // Tor Exit Node Cluster
    '103.208.220.0/22', // Proxy Traffic
    '176.10.99.0/24' // Known VPN Exit
];
