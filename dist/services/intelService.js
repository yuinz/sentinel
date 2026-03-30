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
const configService_1 = require("./configService");
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
    static async analyze(rawTarget, privacyMode = 'full', profileName = 'api', trustToken, tier = 'FREE', forceEnrich = false, requestPath) {
        const target = this.normalizeTarget(rawTarget);
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
        // 3. FAST PATH: Local/Distributed Velocity (<5ms)
        const asnRisk = this.checkLocalAsnMatrix(target);
        // Track Velocity via Distributed SharedCache
        const velocityCount = await cache_1.SharedCache.recordVelocity(target);
        const isHighVelocity = velocityCount > 5;
        let currentRisk = asnRisk.risk + (isHighVelocity ? 20 : 0);
        if (asnRisk.risk > 0)
            signals.push({ id: 'ASN-MATRIX', label: 'High-Risk Network Match', weight: asnRisk.risk, status: 'negative' });
        if (isHighVelocity)
            signals.push({ id: 'NET-VELOCITY', label: 'Request Velocity Spike', weight: 20, status: 'negative' });
        // Sequence Entropy Check (if path is provided)
        if (requestPath && tier === 'PRO') {
            const sequence = await cache_1.SharedCache.recordSequence(target, requestPath);
            if (sequence.length >= 3) {
                // Heuristic: Are they moving through paths impossibly fast?
                const recent = sequence.slice(-3);
                const timeDiff = recent[2].time - recent[0].time; // time to hit 3 endpoints
                const isRapidSequence = timeDiff < 400 && new Set(recent.map(s => s.path)).size >= 2;
                if (isRapidSequence) {
                    currentRisk += 30;
                    signals.push({ id: 'SEQ-ENTROPY', label: 'Robotic Path Traversal', weight: 30, status: 'negative' });
                }
                else {
                    signals.push({ id: 'SEQ-HUMAN', label: 'Organic Site Traversal', weight: 0, status: 'positive' });
                }
            }
        }
        // 4. COLD ENRICHMENT: Triggered Async (PRO Only)
        if (tier === 'PRO') {
            // Check if we already have this IP's DNA in cache
            const cacheKey = `deep:${target}`;
            const deepIntel = cache_1.intelCache.get(cacheKey);
            if (deepIntel && deepIntel.asn) {
                const asnNumber = deepIntel.asn.asn;
                const verifiedBots = configService_1.ConfigService.getVerifiedBotAsns();
                const verifiedBotName = verifiedBots[asnNumber];
                const isHighRisk = configService_1.ConfigService.getHighRiskAsns().includes(asnNumber);
                if (verifiedBotName) {
                    currentRisk = 0; // Reset risk
                    trustBonus += 50; // Heavy boost for verified bots
                    signals.push({
                        id: 'ASN-VERIFIED',
                        label: verifiedBotName,
                        weight: 50,
                        status: 'positive',
                        confidence: 0.99
                    });
                }
                else if (isHighRisk) {
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
                    signals.push({ id: 'ASN-REPUTATION', label: `Network Domain (${deepIntel.asn.name || 'ISP'})`, weight: 0, status: 'positive' });
                }
            }
            else {
                if (forceEnrich) {
                    const freshIntel = await this.performSyncEnrich(target);
                    if (freshIntel && freshIntel.asn) {
                        const asnNumber = freshIntel.asn.asn;
                        const verifiedBots = configService_1.ConfigService.getVerifiedBotAsns();
                        const verifiedBotName = verifiedBots[asnNumber];
                        const isHighRisk = configService_1.ConfigService.getHighRiskAsns().includes(asnNumber);
                        if (verifiedBotName) {
                            currentRisk = 0;
                            trustBonus += 50;
                            signals.push({ id: 'ASN-VERIFIED', label: verifiedBotName, weight: 50, status: 'positive' });
                        }
                        else if (isHighRisk) {
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
        // 4. RISKSIGNAL TRUSTCARD ENRICHMENT (Available for FREE and PRO)
        const trustCardCacheKey = `trustcard:${target}`;
        let cachedTrustCard = cache_1.intelCache.get(trustCardCacheKey);
        // 🔥 INLINE REAL-TIME FETCH ON CACHE MISS (Max 500ms SLA)
        if (!cachedTrustCard) {
            try {
                // Race the API call against a hard 500ms timeout
                cachedTrustCard = await Promise.race([
                    this.fetchTrustCard(target),
                    new Promise((resolve) => setTimeout(() => resolve(undefined), 500))
                ]);
                if (cachedTrustCard) {
                    cache_1.intelCache.set(trustCardCacheKey, cachedTrustCard, { ttl: 2 * 60 * 60 * 1000 });
                }
            }
            catch (e) {
                // Fallback gracefully
            }
        }
        let fullTrustCardData = undefined;
        if (cachedTrustCard) {
            fullTrustCardData = cachedTrustCard;
            // Base score bonus/penalty
            const bonus = cachedTrustCard.trust_score > 80 ? 15 : (cachedTrustCard.trust_score < 60 ? -20 : 0);
            if (bonus !== 0) {
                currentRisk -= bonus;
                signals.push({
                    id: 'RS-TRUSTCARD',
                    label: `RiskSignal ${cachedTrustCard.verdict} Card`,
                    weight: Math.abs(bonus),
                    status: bonus > 0 ? 'positive' : 'negative'
                });
            }
            // Integrate Active Telemetry Flags
            if (cachedTrustCard.telemetry_flags && Array.isArray(cachedTrustCard.telemetry_flags)) {
                cachedTrustCard.telemetry_flags.forEach(flag => {
                    // Extract a clean ID for the flag
                    const cleanFlag = flag.replace(/[^A-Za-z0-9]/g, '').substring(0, 12).toUpperCase();
                    signals.push({
                        id: `RS-FLAG-${cleanFlag}`,
                        label: `RiskSignal Flag: ${flag}`,
                        weight: 5, // Standard penalty weight per active risk flag
                        status: 'negative'
                    });
                    currentRisk += 5;
                });
            }
            // System-Level Penalties
            if (cachedTrustCard.network?.node_type?.toLowerCase().includes('vpn')) {
                signals.push({ id: 'RS-NODE-VPN', label: 'VPN/Proxy Infrastructure Detected', weight: 30, status: 'negative' });
                currentRisk += 30;
            }
            // High Fraud Probability Alert
            if (cachedTrustCard.metrics && cachedTrustCard.metrics.fraud_percent > 70) {
                signals.push({ id: 'RS-HIGH-FRAUD', label: `High Fraud Probability (${cachedTrustCard.metrics.fraud_percent}%)`, weight: 20, status: 'negative' });
                currentRisk += 20;
            }
        }
        else {
            // Hard timeout reached - API too slow or unreachable
            signals.push({ id: 'RS-TIMEOUT', label: 'RiskSignal Enforcement Bypassed (Latency)', weight: 0, status: 'neutral' });
        }
        const finalScore = Math.max(0, 100 - currentRisk + trustBonus);
        const verdict = finalScore >= (profile.threshold + 15) ? 'TRUSTED' : finalScore >= profile.threshold ? 'UNSTABLE' : 'UNTRUSTED';
        return this.finalize(target, finalScore, verdict, signals, start, {
            risk_signal_card: fullTrustCardData,
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
        const ranges = configService_1.ConfigService.getDatacenterRanges();
        // Instant forensic check against known hosting ranges
        for (const range of ranges) {
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
    static async issueBehavioralWork(rawTarget, context, duration, userAgent = 'unknown') {
        const target = this.normalizeTarget(rawTarget);
        const difficulty = 4;
        const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
        const fp = crypto_1.default.createHash('md5').update(userAgent).digest('hex').substring(0, 8);
        const signature = crypto_1.default.createHash('sha256').update(target + salt + difficulty + fp).digest('hex').substring(0, 8);
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
    static verifyBehavioralWork(rawTarget, nonce, userAgent = 'unknown') {
        const target = this.normalizeTarget(rawTarget);
        try {
            const difficulty = parseInt(nonce.substring(8, 9), 10);
            const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
            const fp = crypto_1.default.createHash('md5').update(userAgent).digest('hex').substring(0, 8);
            const signature = crypto_1.default.createHash('sha256').update(target + salt + difficulty + fp).digest('hex').substring(0, 8);
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
    static generateTrustToken(rawTarget) {
        const target = this.normalizeTarget(rawTarget);
        const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
        const ts = Math.floor(Date.now() / 1000);
        const sig = crypto_1.default.createHmac('sha256', salt).update(`${target}:${ts}`).digest('hex').substring(0, 16);
        return Buffer.from(`${target}:${ts}:${sig}`).toString('base64');
    }
    static async fetchTrustCard(target) {
        try {
            const apiURL = process.env.RISKSIGNAL_API_URL || 'https://ahwkraeuotptvwvutbng.supabase.co/functions/v1/trust-api';
            const apiKey = process.env.RISKSIGNAL_API_KEY;
            if (!apiKey)
                return undefined;
            const res = await axios_1.default.post(apiURL, { target }, {
                headers: { 'x-api-key': apiKey, 'Content-Type': 'application/json' },
                timeout: 500 // Fail aggressively to respect engine SLA
            });
            if (res.data && res.data.status === 'success') {
                logger_1.default.info(`[Sentinel] TrustCard Sync Success: ${target}`);
                return res.data.trust_card;
            }
        }
        catch (e) {
            // Fallback - Timeout handled upstream
            return undefined;
        }
        return undefined;
    }
    /**
     * Patch IPv6 Loophole: Collapse IPv6 addresses into their /64 subnet
     */
    static normalizeTarget(ip) {
        if (!ip.includes(':'))
            return ip; // Return IPv4 as is
        const blocks = ip.split(':');
        if (blocks.length >= 4) {
            return blocks.slice(0, 4).join(':') + '::/64';
        }
        return ip;
    }
}
exports.IntelService = IntelService;
