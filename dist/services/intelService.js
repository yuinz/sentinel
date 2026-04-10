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
    static async analyze(rawTarget, privacyMode = 'full', profileName = 'api', trustToken, tier = 'FREE', forceEnrich = false, requestPath, userAgent) {
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
        // 🔥 INLINE REAL-TIME FETCH ON CACHE MISS (Max 2500ms SLA)
        if (!cachedTrustCard) {
            try {
                // Race the API call against a hard 2500ms timeout
                cachedTrustCard = await Promise.race([
                    this.fetchTrustCard(target),
                    new Promise((resolve) => setTimeout(() => resolve(undefined), 2500))
                ]);
                // The fetchTrustCard method now internally saves to cache on success.
                // We just use the awaited result here if it arrived in time.
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
        // 5. Automation Check
        if (userAgent) {
            const botKeywords = /headless|puppeteer|selenium|playwright|bot|crawl|spider|axios|python-requests|curl|wget/i;
            if (botKeywords.test(userAgent)) {
                currentRisk += 35;
                signals.push({ id: 'META-BOT', label: 'Automation Signature Detected', weight: 35, status: 'negative' });
            }
        }
        let finalScore = Math.max(0, 100 - currentRisk + trustBonus);
        let verdict = finalScore >= (profile.threshold + 15) ? 'TRUSTED' : finalScore >= profile.threshold ? 'UNSTABLE' : 'UNTRUSTED';
        const verdictReasons = [];
        // 🔥 THE BRAIN OVERRIDE: If the upstream Multi-Provider Brain says UNTRUSTED, we OBEY.
        if (fullTrustCardData && (fullTrustCardData.verdict === 'UNTRUSTED' || fullTrustCardData.network?.node_type === 'VPN' || fullTrustCardData.network?.node_type === 'Proxy')) {
            verdict = 'UNTRUSTED';
            finalScore = Math.min(finalScore, 5); // Force the score to near zero for infrastructure
            verdictReasons.push(fullTrustCardData.network?.node_type === 'VPN' ? 'vpn_detected' : 'untrusted_infrastructure');
        }
        return this.finalize(target, finalScore, verdict, signals, start, {
            risk_signal_card: fullTrustCardData,
            verdict_reasons: verdictReasons,
            remediation: verdict !== 'TRUSTED' ? {
                type: 'challenge',
                optional: verdict === 'UNSTABLE',
                recommended: true,
                behavioral_duration: verdict === 'UNTRUSTED' ? 4.0 : 2.0
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
        const difficulty = 3; // Lowered to 3 for browser speed — still cryptographically painful for bots
        const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
        // Signature is ONLY based on target + salt, NOT user-agent (removes browser variance)
        const signature = crypto_1.default.createHash('sha256').update(target + salt).digest('hex').substring(0, 12);
        const nonce_prefix = `${signature}`;
        logger_1.default.info(`[PoW Issue] Target: ${target}, Prefix: ${nonce_prefix}, Difficulty: ${difficulty}`);
        return {
            challenge_id: `ch_${crypto_1.default.randomBytes(4).toString('hex')}`,
            type: 'BWT',
            difficulty,
            nonce_prefix,
            behavioral_duration: duration || 2.0,
            instruction: `Intent Proof: Click and hold for ${duration || 2.0}s.`
        };
    }
    static verifyBehavioralWork(rawTarget, submitted_nonce, userAgent = 'unknown') {
        const target = this.normalizeTarget(rawTarget);
        try {
            const difficulty = 3;
            const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
            const signature = crypto_1.default.createHash('sha256').update(target + salt).digest('hex').substring(0, 12);
            const expected_prefix = signature;
            logger_1.default.info(`[PoW Verify] Target: ${target}, Expected Prefix: ${expected_prefix}`);
            logger_1.default.info(`[PoW Verify] Submitted Nonce: ${submitted_nonce}`);
            // The browser submits the raw nonce NUMBER it found.
            // We reconstruct the full string the browser hashed: nonce_prefix + nonce_number
            const full_string = expected_prefix + submitted_nonce;
            const hash = crypto_1.default.createHash('sha256').update(full_string).digest('hex');
            logger_1.default.info(`[PoW Verify] Computed Hash (${expected_prefix}+${submitted_nonce}): ${hash}`);
            const isValid = hash.startsWith('0'.repeat(difficulty));
            logger_1.default.info(`[PoW Verify] Is Valid: ${isValid}`);
            return isValid;
        }
        catch (err) {
            logger_1.default.error(`[PoW Verify] Error: ${err}`);
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
        // ── LOCAL INTELLIGENCE CONSTANTS ─────────────────────────────────────
        const HIGH_RISK_ASNS = new Set([
            9009, 212238, 14061, 20473, 16509, 14618, 63949, 24940, 16276, 54113,
            60068, 51167, 200651, 46484, 14576, 36352, 9318, 30823, 21341, 14061,
            20473, 16509, 14618, 13335, 16276, 24940, 212238, 60068, 396982
        ]);
        const HIGH_RISK_TERMS = [
            'm247', 'datacamp', 'digitalocean', 'hetzner', 'vultr', 'linode', 'ovh',
            'vpn', 'proxy', 'datacenter', 'hosting', 'cloud', 'server', 'dedicated',
            'hosthatch', 'leaseweb', 'packethost', 'quadranet', 'ovh-hosting', 'virtuozzo',
            'contabo', 'torguard', 'expressvpn', 'nordvpn', 'surfshark', 'mullvad', 'pnet'
        ];
        const normalizeIpApiIs = (d) => {
            if (!d?.ip)
                return null;
            const asnNum = parseInt(String(d.asn?.asn ?? 0));
            const org = (d.asn?.org ?? '').toLowerCase();
            const isp = (d.asn?.isp ?? '').toLowerCase();
            const isVpn = !!(d.is_vpn || d.is_tor || d.is_proxy);
            const isDC = !!(d.is_datacenter);
            const asnHit = HIGH_RISK_ASNS.has(asnNum);
            const termHit = HIGH_RISK_TERMS.some(t => org.includes(t) || isp.includes(t));
            const hostile = isVpn || isDC || asnHit || termHit;
            return {
                target,
                verdict: hostile ? 'UNTRUSTED' : 'TRUSTED',
                trust_score: hostile ? 5 : 90,
                network: {
                    provider: d.asn?.org ?? 'Unknown',
                    asn: String(d.asn?.asn ?? 'UNKNOWN'),
                    system: d.asn?.isp ?? 'Unknown',
                    protocol: 'IPv4',
                    node_type: isVpn ? 'VPN' : (isDC || asnHit ? 'Infrastructure' : 'Residential'),
                    zone: d.location?.countryCode ?? 'XX'
                },
                geo: { location: d.location?.country ?? 'Unknown', city: d.location?.city ?? 'Unknown' },
                intelligence_signals: [
                    ...(isVpn ? [{ id: 'LOCAL-VPN', label: 'VPN/Proxy Detected', weight: 30, status: 'negative' }] : []),
                    ...(asnHit ? [{ id: 'LOCAL-ASN', label: `High-Risk ASN (AS${asnNum})`, weight: 25, status: 'negative' }] : []),
                    ...(termHit ? [{ id: 'LOCAL-ORG', label: 'Infrastructure Org Match', weight: 20, status: 'negative' }] : []),
                ],
                telemetry_flags: hostile ? ['LOCAL_INFRA_MATCH'] : []
            };
        };
        // ── STEP 1: DIRECT PROVIDER CALL (ipapi.is) ──────────────────────────
        try {
            const r = await axios_1.default.get(`https://api.ipapi.is/?q=${target}`, { timeout: 2000 });
            const card = normalizeIpApiIs(r.data);
            if (card) {
                const trustCardCacheKey = `trustcard:${target}`;
                cache_1.intelCache.set(trustCardCacheKey, card, { ttl: 2 * 60 * 60 * 1000 });
                // ── STEP 2: FIRE-AND-FORGET Vercel enrichment overlay ─────────
                const apiURL = process.env.RISKSIGNAL_API_URL || `https://app.risksignal.name.ng/api/scan`;
                const apiKey = process.env.RISKSIGNAL_API_KEY;
                if (apiKey) {
                    axios_1.default.get(`${apiURL}?ip=${target}&legacy=true`, {
                        headers: { 'x-api-key': apiKey },
                        timeout: 3000
                    }).then(res => {
                        if (res.data?.status === 'success' && res.data?.trust_card) {
                            cache_1.intelCache.set(trustCardCacheKey, res.data.trust_card, { ttl: 2 * 60 * 60 * 1000 });
                            logger_1.default.info(`[Sentinel] Brain enrichment overlay applied for ${target}`);
                        }
                    }).catch(() => { });
                }
                return card;
            }
        }
        catch (e) {
            logger_1.default.warn(`[Sentinel] Direct provider call failed: ${e.message}`);
        }
        // ── STEP 3: FALLBACK — ip-api.com ────────────────────────────────────
        try {
            const r = await axios_1.default.get(`http://ip-api.com/json/${target}?fields=status,proxy,hosting,isp,org,as,countryCode,country,city`, { timeout: 2000 });
            if (r.data?.status === 'success') {
                const asnNum = parseInt(String(r.data.as ?? '').split(' ')[0].replace('AS', '') || '0');
                const org = (r.data.org ?? '').toLowerCase();
                const isp = (r.data.isp ?? '').toLowerCase();
                const isVpn = !!(r.data.proxy);
                const isDC = !!(r.data.hosting);
                const asnHit = HIGH_RISK_ASNS.has(asnNum);
                const termHit = HIGH_RISK_TERMS.some(t => org.includes(t) || isp.includes(t));
                const hostile = isVpn || isDC || asnHit || termHit;
                const card = {
                    target,
                    verdict: hostile ? 'UNTRUSTED' : 'TRUSTED',
                    trust_score: hostile ? 5 : 88,
                    network: {
                        provider: r.data.org ?? 'Unknown',
                        asn: String(asnNum),
                        system: r.data.isp ?? 'Unknown',
                        protocol: 'IPv4',
                        node_type: isVpn ? 'VPN' : (isDC || asnHit ? 'Infrastructure' : 'Residential'),
                        zone: r.data.countryCode ?? 'XX'
                    },
                    geo: { location: r.data.country ?? 'Unknown', city: r.data.city ?? 'Unknown' },
                    telemetry_flags: hostile ? ['FALLBACK_INFRA_MATCH'] : []
                };
                const trustCardCacheKey = `trustcard:${target}`;
                cache_1.intelCache.set(trustCardCacheKey, card, { ttl: 2 * 60 * 60 * 1000 });
                return card;
            }
        }
        catch (e) {
            logger_1.default.warn(`[Sentinel] Fallback provider failed: ${e.message}`);
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
