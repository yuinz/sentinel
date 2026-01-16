"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.IntelService = exports.SENTINEL_PROFILES = void 0;
const axios_1 = __importDefault(require("axios"));
const promises_1 = __importDefault(require("dns/promises"));
const crypto_1 = __importDefault(require("crypto"));
const logger_1 = __importDefault(require("../utils/logger"));
const cache_1 = require("../utils/cache");
// Array of ASNs known for hosting VPN infrastructure, bulletproof hosting, or high-risk traffic
const HIGH_RISK_ASNS = [
    212238, 9009, 14061, 20473, 16509, 14618, 63949, 15169, 396982,
    24940, 21341, 16276, 13335, 54113, 20940, 204915, 47583, 53667,
    8100, 13213, 46475, 60068, 199218, 203020, 201839, 398324,
    398705, 398722, 211298, 213412, 216341, 30823, 214497, 215208,
    215240, 198953, 200593, 42969, 215778, 49217, 20052, 11878,
    46562, 204957, 216419, 51167, 12876, 16276, 35816, 50673 // Added OVH, Hetzner, and misc hosting
];
// Array of Gold-Standard Mobile Carriers (High Trust for legitimacy)
const TRUSTED_CARRIER_ASNS = [
    7018, 21928, 6167, 22394, 36873, 9498, 1273, 55836, 9808,
    5511, 29465, 31761, 3320, 8133, 45528, 45180, 28573, 12322
];
// Opinionated Security Profiles
exports.SENTINEL_PROFILES = {
    api: { threshold: 60, challenge_intensity: 'medium' },
    signup: { threshold: 75, challenge_intensity: 'high' },
    payments: { threshold: 85, challenge_intensity: 'extreme' },
    crypto: { threshold: 90, challenge_intensity: 'extreme' }
};
class IntelService {
    static isPrivateIp(ip) {
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4)
            return false;
        return (parts[0] === 10 ||
            (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
            (parts[0] === 192 && parts[1] === 168) ||
            parts[0] === 127);
    }
    static async analyze(target, privacyMode = 'full', profileName = 'api', trustToken) {
        const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);
        const signals = [];
        const profile = exports.SENTINEL_PROFILES[profileName];
        // 1. Trust Recovery Token Check
        let trustBonus = 0;
        if (trustToken && this.verifyTrustToken(target, trustToken)) {
            trustBonus = 35; // Significant bonus for passing a challenge
            signals.push({ id: 'NET-RECOVERY', label: 'Trust Verification Passed', weight: 35, status: 'positive', confidence: 1.0 });
        }
        // 0. Trusted Local/Bypass Check
        if (isIp && this.isPrivateIp(target)) {
            return {
                target,
                trust_score: 100,
                confidence: 1.0,
                verdict: 'TRUSTED',
                geo: { infrastructure: 'local-network' },
                signals: [{ id: 'NET-LOCAL', label: 'Internal/Private Network', weight: 0, status: 'positive', confidence: 1.0 }]
            };
        }
        let riskASN = 0; // Max 50
        let riskInfra = 0; // Max 30
        let riskBehavior = 0; // Max 20
        try {
            // 1. Geo & External Intel Enrichment
            const [geoRes, intelRes] = await Promise.all([
                axios_1.default.get(`https://ipwho.is/${target}`, { timeout: 3000 }),
                isIp ? axios_1.default.get(`https://internetdb.shodan.io/${target}`).catch(() => ({ data: { ports: [] } })) : Promise.resolve({ data: { ports: [] } })
            ]);
            const geoData = geoRes.data;
            const intelData = intelRes.data;
            const isExplicitProxy = geoData.security?.proxy || false;
            const isExplicitVpn = geoData.security?.vpn || false;
            const isTor = geoData.security?.tor || false;
            const infraType = geoData.connection?.type; // 'hosting', 'isp', 'business'
            const asnNumber = geoData.connection?.asn;
            const org = geoData.connection?.org || '';
            const openPorts = intelData.ports || [];
            // --- CATEGORY 1: ASN & ANONYMITY (MAX 50) ---
            if (isExplicitProxy || isExplicitVpn || isTor) {
                riskASN += 50; // Instant max for verified anonymizers
                signals.push({ id: 'NET-ANON', label: 'Verified Anonymizer (VPN/Proxy)', weight: 50, status: 'negative', confidence: 0.95 });
            }
            const isHighRiskASN = HIGH_RISK_ASNS.includes(asnNumber);
            const isTrustedCarrier = TRUSTED_CARRIER_ASNS.includes(asnNumber);
            const orgLower = org.toLowerCase();
            if (!isTor && (isHighRiskASN || orgLower.includes('vpn') || orgLower.includes('m247'))) {
                riskASN = Math.min(50, riskASN + 45);
                signals.push({ id: 'ASN-RISK', label: 'Cloud/VPN Governance Network', weight: 45, status: 'negative', confidence: 0.88 });
            }
            // --- CATEGORY 2: INFRASTRUCTURE CONTEXT (MAX 30) ---
            if (infraType === 'hosting') {
                riskInfra = 30;
                signals.push({ id: 'NET-DATACENTER', label: 'Cloud/DC Infrastructure', weight: 30, status: 'neutral', confidence: 0.90 });
            }
            if (isTrustedCarrier) {
                signals.push({ id: 'NET-MOBILE', label: 'Verified Mobile Carrier', weight: 20, status: 'positive', confidence: 0.95 });
            }
            if (infraType === 'isp') {
                signals.push({ id: 'NET-RES', label: 'Residential/ISP Allocation', weight: 15, status: 'positive', confidence: 0.85 });
            }
            // --- CATEGORY 3: BEHAVIOR & PORTS (MAX 20) ---
            const miningPorts = [3333, 4444, 14444, 24444, 3334];
            const hasMiningPorts = openPorts.some((p) => miningPorts.includes(p));
            if (hasMiningPorts) {
                riskBehavior += 10;
                signals.push({ id: 'NET-ABUSE-NODE', label: 'Active Cryptomining Activity', weight: 10, status: 'negative', confidence: 0.62 });
            }
            // Behavioral Velocity Tracking (Entropy/Abuse)
            if (isIp) {
                const now = Date.now();
                const history = cache_1.velocityCache.get(target) || [];
                const recentHistory = history.filter(ts => now - ts < 60000); // last 1 minute
                recentHistory.push(now);
                cache_1.velocityCache.set(target, recentHistory);
                if (recentHistory.length > 5) {
                    riskBehavior += 15;
                    signals.push({ id: 'NET-VELOCITY', label: 'High-Frequency Scan Patterns', weight: 15, status: 'negative', confidence: 0.85 });
                }
            }
            riskBehavior = Math.min(20, riskBehavior);
            // --- DNS Check (Contextual Risk - Infra Category) ---
            if (!isIp) {
                try {
                    const records = await promises_1.default.resolve(target);
                    if (records.length > 0) {
                        signals.push({ id: 'DNS-RES', label: 'Authoritative DNS Resolved', weight: 15, status: 'positive', confidence: 1.0 });
                    }
                }
                catch (dnsErr) {
                    riskInfra = Math.min(30, riskInfra + 20);
                    signals.push({ id: 'DNS-FAIL', label: 'DNS Resolution Failed', weight: 20, status: 'negative', confidence: 0.80 });
                }
            }
            // Calibration & Clamped Risk Calculation
            const baseRisk = riskASN + riskInfra + riskBehavior;
            const totalRisk = Math.max(0, baseRisk - trustBonus);
            const trustScore = Math.max(0, 100 - totalRisk);
            const verdictReasons = signals
                .filter(s => s.status === 'negative')
                .map(s => s.id);
            const result = {
                target,
                trust_score: trustScore,
                confidence: 95,
                verdict: trustScore >= (profile.threshold + 15) ? 'TRUSTED' : trustScore >= profile.threshold ? 'UNSTABLE' : 'UNTRUSTED',
                verdict_reasons: verdictReasons,
                privacy_mode: privacyMode,
                geo: {
                    city: privacyMode === 'full' ? geoData.city : undefined,
                    country: geoData.country,
                    asn: geoData.connection ? {
                        org: geoData.connection.org,
                        number: geoData.connection.asn
                    } : undefined,
                    infrastructure: infraType
                },
                signals
            };
            // F. Remediation Recommendation (Decoupled)
            const baseThreshold = profile.threshold;
            if (trustScore < baseThreshold + 15) {
                // Determine Hold Duration based on Risk (2.0s - 4.0s)
                let holdDuration = 2.0;
                if (riskASN >= 45 || infraType === 'hosting')
                    holdDuration = 3.0;
                if (trustScore < baseThreshold)
                    holdDuration = 4.0; // Highly Unstable/Untrusted
                result.remediation = {
                    type: 'challenge',
                    optional: trustScore >= baseThreshold,
                    recommended: trustScore < baseThreshold + 10,
                    behavioral_duration: holdDuration
                };
            }
            return result;
        }
        catch (err) {
            logger_1.default.error(`Intel analysis failed for ${target}`, err);
            throw new Error('Intelligence engine synthesis failed.');
        }
    }
    static generateTrustToken(target) {
        const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
        const timestamp = Math.floor(Date.now() / 1000);
        // Token valid for 30 minutes
        const payload = `${target}:${timestamp}`;
        const signature = crypto_1.default.createHmac('sha256', salt).update(payload).digest('hex').substring(0, 16);
        return Buffer.from(`${payload}:${signature}`).toString('base64');
    }
    static verifyTrustToken(target, token) {
        try {
            const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
            const decoded = Buffer.from(token, 'base64').toString();
            const [t, ts, sig] = decoded.split(':');
            if (t !== target)
                return false;
            const timestamp = parseInt(ts, 10);
            const now = Math.floor(Date.now() / 1000);
            if (now - timestamp > 1800)
                return false; // 30 min expiry
            const expectedSig = crypto_1.default.createHmac('sha256', salt).update(`${t}:${ts}`).digest('hex').substring(0, 16);
            return sig === expectedSig;
        }
        catch (e) {
            return false;
        }
    }
    static async issueBehavioralWork(target, context, duration) {
        // Behavioral Work Token (BWT) - Based on effort/intent metrics
        const difficulty = 4; // Default
        const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
        const signature = crypto_1.default.createHash('sha256').update(target + salt + difficulty).digest('hex').substring(0, 8);
        const noncePrefix = `${signature}${difficulty}`;
        return {
            challenge_id: `ch_${crypto_1.default.randomBytes(4).toString('hex')}`,
            type: 'BWT',
            difficulty,
            nonce_prefix: noncePrefix,
            behavioral_duration: duration || 2.0,
            expires_in: 120,
            instruction: `Click and hold for ${duration || 2.0}s to satisfy Intent Proof while nonce is computed.`
        };
    }
    static verifyBehavioralWork(target, nonce) {
        if (!nonce)
            return false;
        const difficultyChar = nonce.substring(8, 9);
        const difficulty = parseInt(difficultyChar, 10);
        if (isNaN(difficulty))
            return false;
        const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
        const signature = crypto_1.default.createHash('sha256').update(target + salt + difficulty).digest('hex').substring(0, 8);
        const noncePrefix = `${signature}${difficulty}`;
        const hash = crypto_1.default.createHash('sha256').update(noncePrefix + nonce).digest('hex');
        return hash.startsWith("0".repeat(difficulty));
    }
}
exports.IntelService = IntelService;
