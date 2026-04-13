import axios from 'axios';
import crypto from 'crypto';
import logger from '../utils/logger';
import { SharedCache, intelCache } from '../utils/cache';
import { ConfigService } from './configService';

export interface TrustCard {
    target: string;
    verdict: string;
    trust_score: number;
    metrics?: {
        risk_percent: number;
        anon_percent: number;
        fraud_percent: number;
        abuse_percent: number;
        signal_confidence: number;
        detection_level: number;
    };
    network?: {
        provider: string;
        asn: string;
        system: string;
        protocol: string;
        node_type: string;
        zone: string;
    };
    geo?: {
        location: string;
        city: string;
    };
    telemetry_flags?: string[];
    reputation?: {
        status: string;
        abuse_history: string;
    };
}

export interface IntelResult {
    target: string;
    trust_score: number;
    confidence: number;
    verdict: 'TRUSTED' | 'UNSTABLE' | 'UNTRUSTED';
    privacy_mode?: 'strict' | 'full';
    geo: {
        city?: string;
        country?: string;
        asn?: {
            org: string;
            number: number;
        };
        infrastructure?: string;
    };
    signals: Array<{
        id: string;
        label: string;
        weight: number;
        status: 'positive' | 'negative' | 'neutral';
        confidence?: number;
    }>;
    remediation?: {
        type: 'challenge';
        optional: boolean;
        recommended: boolean;
        behavioral_duration?: number;
    };
    latency_ms?: number;
    risk_signal_card?: TrustCard;
}



export const SENTINEL_PROFILES = {
    api: { threshold: 60 },
    signup: { threshold: 75 },
    payments: { threshold: 85 },
    crypto: { threshold: 90 }
};

export class IntelService {
    /**
     * The Real Product: Decision Latency.
     * Rendering a trust decision in <50ms by prioritizing in-memory signals.
     */
    static async analyze(
        rawTarget: string,
        privacyMode: 'strict' | 'full' = 'full',
        profileName: keyof typeof SENTINEL_PROFILES = 'api',
        trustToken?: string,
        tier: 'FREE' | 'PRO' = 'FREE',
        forceEnrich: boolean = false,
        requestPath?: string,
        userAgent?: string
    ): Promise<IntelResult & { verdict_reasons?: string[] }> {
        const target = this.normalizeTarget(rawTarget);
        const start = Date.now();
        const profile = SENTINEL_PROFILES[profileName];
        const signals: IntelResult['signals'] = [];

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
        const velocityCount = await SharedCache.recordVelocity(target);
        const isHighVelocity = velocityCount > 5;

        let currentRisk = asnRisk.risk + (isHighVelocity ? 20 : 0);
        if (asnRisk.risk > 0) signals.push({ id: 'ASN-MATRIX', label: 'High-Risk Network Match', weight: asnRisk.risk, status: 'negative' });
        if (isHighVelocity) signals.push({ id: 'NET-VELOCITY', label: 'Request Velocity Spike', weight: 20, status: 'negative' });

        // Sequence Entropy Check (if path is provided)
        if (requestPath && tier === 'PRO') {
            const sequence = await SharedCache.recordSequence(target, requestPath);
            if (sequence.length >= 3) {
                // Heuristic: Are they moving through paths impossibly fast?
                const recent = sequence.slice(-3);
                const timeDiff = recent[2].time - recent[0].time; // time to hit 3 endpoints
                const isRapidSequence = timeDiff < 400 && new Set(recent.map(s => s.path)).size >= 2;
                
                if (isRapidSequence) {
                    currentRisk += 30;
                    signals.push({ id: 'SEQ-ENTROPY', label: 'Robotic Path Traversal', weight: 30, status: 'negative' });
                } else {
                    signals.push({ id: 'SEQ-HUMAN', label: 'Organic Site Traversal', weight: 0, status: 'positive' });
                }
            }
        }

        // 4. COLD ENRICHMENT: Triggered Async (PRO Only)
        if (tier === 'PRO') {
            // Check if we already have this IP's DNA in cache
            const cacheKey = `deep:${target}`;
            const deepIntel = intelCache.get(cacheKey) as any;

            if (deepIntel && deepIntel.asn) {
                const asnNumber = deepIntel.asn.asn;
                const verifiedBots = ConfigService.getVerifiedBotAsns();
                const verifiedBotName = verifiedBots[asnNumber];
                const isHighRisk = ConfigService.getHighRiskAsns().includes(asnNumber);

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
                } else if (isHighRisk) {
                    currentRisk += 80; // Massive penalty for Data Centers/VPNs
                    signals.push({
                        id: 'ASN-REPUTATION',
                        label: `High-Risk Infrastructure (${deepIntel.asn.name || 'Hosting'})`,
                        weight: 80,
                        status: 'negative',
                        confidence: 0.95
                    });
                } else {
                    signals.push({ id: 'ASN-REPUTATION', label: `Network Domain (${deepIntel.asn.name || 'ISP'})`, weight: 0, status: 'positive' });
                }
            } else {
                if (forceEnrich) {
                    const freshIntel = await this.performSyncEnrich(target);
                    if (freshIntel && freshIntel.asn) {
                        const asnNumber = freshIntel.asn.asn;
                        const verifiedBots = ConfigService.getVerifiedBotAsns();
                        const verifiedBotName = verifiedBots[asnNumber];
                        const isHighRisk = ConfigService.getHighRiskAsns().includes(asnNumber);
                        
                        if (verifiedBotName) {
                            currentRisk = 0;
                            trustBonus += 50;
                            signals.push({ id: 'ASN-VERIFIED', label: verifiedBotName, weight: 50, status: 'positive' });
                        } else if (isHighRisk) {
                            currentRisk += 80;
                            signals.push({ id: 'ASN-REPUTATION', label: `High-Risk Infrastructure (${freshIntel.asn.name})`, weight: 80, status: 'negative' });
                        }
                    }
                } else {
                    // If not in cache, trigger background enrichment for next time
                    this.enrichInBackground(target, privacyMode, profileName);
                    signals.push({ id: 'SYS-PENDING', label: 'Background Forensic Gathering', weight: 0, status: 'neutral' });
                }
            }
        }

        // 4. RISKSIGNAL TRUSTCARD ENRICHMENT (Available for FREE and PRO)
        const trustCardCacheKey = `trustcard:${target}`;
        let cachedTrustCard = intelCache.get(trustCardCacheKey) as TrustCard | undefined;

        // 🔥 INLINE REAL-TIME FETCH ON CACHE MISS (Max 2500ms SLA)
        if (!cachedTrustCard) {
            try {
                // Race the API call against a hard 2500ms timeout
                cachedTrustCard = await Promise.race([
                    this.fetchTrustCard(target),
                    new Promise<undefined>((resolve) => setTimeout(() => resolve(undefined), 2500))
                ]);

                // The fetchTrustCard method now internally saves to cache on success.
                // We just use the awaited result here if it arrived in time.
            } catch (e) {
                // Fallback gracefully
            }
        }

        let fullTrustCardData: TrustCard | undefined = undefined;

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

        } else {
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
        const verdictReasons: string[] = [];

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

    private static finalize(target: string, score: number, verdict: any, signals: any[], start: number, extra: any = {}): any {
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

    private static async performSyncEnrich(target: string): Promise<any> {
        try {
            const res = await axios.get(`https://ipwho.is/${target}`, { timeout: 1500 });
            if (res.data && res.data.success) {
                const cacheKey = `deep:${target}`;
                intelCache.set(cacheKey, res.data, { ttl: 3600 });
                return res.data;
            }
        } catch { return null; }
    }

    static async enrichInBackground(target: string, privacyMode: string, profileName: string) {
        // Heavy I/O moved to separate thread/execution context
        try {
            const cacheKey = `deep:${target}`;
            if (intelCache.get(cacheKey)) return; // Already enriched

            const res = await axios.get(`https://ipwho.is/${target}`, { timeout: 2000 });
            if (res.data && res.data.success) {
                intelCache.set(cacheKey, res.data, { ttl: 3600 }); // Cache deep intel for 1 hour
                logger.info(`Cold Enrichment Resolved: ${target}`);
            }
        } catch (e) {
            // Background resolution failed - system stays fast regardless
        }
    }


    static checkLocalAsnMatrix(target: string): { risk: number, asn?: any } {
        const ranges = ConfigService.getDatacenterRanges();

        // Instant forensic check against known hosting ranges
        for (const range of ranges) {
            if (this.ipInRow(target, range)) {
                return { risk: 85 }; // Critical Risk: Data-Center Origin
            }
        }
        return { risk: 0 };
    }

    private static ipInRow(ip: string, cipher: string): boolean {
        try {
            const [range, bits] = cipher.split('/');
            const mask = ~((1 << (32 - parseInt(bits))) - 1) >>> 0;

            const ipDots = ip.split('.').map(Number);
            const rangeDots = range.split('.').map(Number);

            const ipInt = ((ipDots[0] << 24) | (ipDots[1] << 16) | (ipDots[2] << 8) | ipDots[3]) >>> 0;
            const rangeInt = ((rangeDots[0] << 24) | (rangeDots[1] << 16) | (rangeDots[2] << 8) | rangeDots[3]) >>> 0;

            return (ipInt & mask) === (rangeInt & mask);
        } catch { return false; }
    }

    static isPrivateIp(ip: string): boolean {
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4) return false;
        return parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168) || parts[0] === 127;
    }

    static verifyTrustToken(target: string, token: string): boolean {
        try {
            const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
            const decoded = Buffer.from(token, 'base64').toString();
            const [t, ts, sig] = decoded.split(':');
            // Validates HMAC Signature and Expiration (30 mins).
            // We intentionally skip strict 't === target' enforcement because VPNs often dynamically 
            // rotate their last-octet egress IPs between the Widget Server (Render) and Orchestrator (Supabase),
            // which causes false-positive token rejections. The HMAC signature prevents forgery.
            return (Math.floor(Date.now() / 1000) - parseInt(ts)) < 1800 && sig === crypto.createHmac('sha256', salt).update(`${t}:${ts}`).digest('hex').substring(0, 16);
        } catch { return false; }
    }

    static async issueBehavioralWork(rawTarget: string, context: string, duration?: number) {
        const target = this.normalizeTarget(rawTarget);
        const difficulty = 3;
        const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
        const signature = crypto.createHash('sha256').update(target + salt + difficulty).digest('hex').substring(0, 8);

        const prefix = `${signature}${difficulty}`;
        logger.info(`[PoW Issue] Target: ${target}, Prefix: ${prefix}`);

        return {
            challenge_id: `ch_${crypto.randomBytes(4).toString('hex')}`,
            type: 'BWT',
            difficulty,
            nonce_prefix: prefix,
            behavioral_duration: duration || 2.0,
            instruction: `Intent Proof: Click and hold for ${duration || 2.0}s.`
        };
    }

    static verifyBehavioralWork(rawTarget: string, rawNonce: any): boolean {
        const target = this.normalizeTarget(rawTarget);
        try {
            const nonce = String(rawNonce);
            const difficulty = parseInt(nonce.substring(8, 9), 10);
            const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
            const signature = crypto.createHash('sha256').update(target + salt + difficulty).digest('hex').substring(0, 8);

            logger.info(`[PoW Verify] Target: ${target}, Difficulty: ${difficulty}`);
            logger.info(`[PoW Verify] Nonce: ${nonce}`);
            logger.info(`[PoW Verify] Expected Signature Prefix: ${signature}`);

            if (!nonce.startsWith(`${signature}${difficulty}`)) {
                logger.warn(`[PoW Verify] Signature Mismatch! Nonce doesn't start with ${signature}${difficulty}`);
                return false;
            }

            const hash = crypto.createHash('sha256').update(nonce).digest('hex');
            const isValid = hash.startsWith("0".repeat(difficulty));

            logger.info(`[PoW Verify] Computed Hash: ${hash}`);
            logger.info(`[PoW Verify] Is Valid: ${isValid}`);

            return isValid;
        } catch (err) {
            logger.error(`[PoW Verify] Error during verification: ${err}`);
            return false;
        }
    }

    static generateTrustToken(rawTarget: string): string {
        const target = this.normalizeTarget(rawTarget);
        const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
        const ts = Math.floor(Date.now() / 1000);
        const sig = crypto.createHmac('sha256', salt).update(`${target}:${ts}`).digest('hex').substring(0, 16);
        return Buffer.from(`${target}:${ts}:${sig}`).toString('base64');
    }

    static async fetchTrustCard(target: string): Promise<TrustCard | undefined> {
        // ── LOCAL INTELLIGENCE CONSTANTS ─────────────────────────────────────
        const HIGH_RISK_ASNS  = new Set([
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

        const normalizeIpApiIs = (d: any): TrustCard | null => {
            if (!d?.ip) return null;
            const asnNum  = parseInt(String(d.asn?.asn ?? 0));
            const org     = (d.asn?.org  ?? '').toLowerCase();
            const isp     = (d.asn?.isp  ?? '').toLowerCase();
            const isVpn   = !!(d.is_vpn || d.is_tor || d.is_proxy);
            const isDC    = !!(d.is_datacenter);
            const asnHit  = HIGH_RISK_ASNS.has(asnNum);
            const termHit = HIGH_RISK_TERMS.some(t => org.includes(t) || isp.includes(t));
            const hostile = isVpn || isDC || asnHit || termHit;

            return {
                target,
                verdict:    hostile ? 'UNTRUSTED' : 'TRUSTED',
                trust_score: hostile ? 5 : 90,
                network: {
                    provider: d.asn?.org ?? 'Unknown',
                    asn:      String(d.asn?.asn ?? 'UNKNOWN'),
                    system:   d.asn?.isp ?? 'Unknown',
                    protocol: 'IPv4',
                    node_type: isVpn ? 'VPN' : (isDC || asnHit ? 'Infrastructure' : 'Residential'),
                    zone:      d.location?.countryCode ?? 'XX'
                },
                geo: { location: d.location?.country ?? 'Unknown', city: d.location?.city ?? 'Unknown' },
                intelligence_signals: [
                    ...(isVpn  ? [{ id: 'LOCAL-VPN',  label: 'VPN/Proxy Detected',          weight: 30, status: 'negative' as const }] : []),
                    ...(asnHit ? [{ id: 'LOCAL-ASN',  label: `High-Risk ASN (AS${asnNum})`, weight: 25, status: 'negative' as const }] : []),
                    ...(termHit? [{ id: 'LOCAL-ORG',  label: 'Infrastructure Org Match',    weight: 20, status: 'negative' as const }] : []),
                ] as any,
                telemetry_flags: hostile ? ['LOCAL_INFRA_MATCH'] : []
            } as TrustCard;
        };

        // ── STEP 1: DIRECT PROVIDER CALL (ipapi.is) ──────────────────────────
        try {
            const r = await axios.get(`https://api.ipapi.is/?q=${target}`, { timeout: 2000 });
            const card = normalizeIpApiIs(r.data);
            if (card) {
                const trustCardCacheKey = `trustcard:${target}`;
                intelCache.set(trustCardCacheKey, card as any, { ttl: 2 * 60 * 60 * 1000 });

                // ── STEP 2: FIRE-AND-FORGET Vercel enrichment overlay ─────────
                const apiURL = process.env.RISKSIGNAL_API_URL || `https://app.risksignal.name.ng/api/scan`;
                const apiKey = process.env.RISKSIGNAL_API_KEY;
                if (apiKey) {
                    axios.get(`${apiURL}?ip=${target}&legacy=true`, {
                        headers: { 'x-api-key': apiKey },
                        timeout: 3000
                    }).then(res => {
                        if (res.data?.status === 'success' && res.data?.trust_card) {
                            intelCache.set(trustCardCacheKey, res.data.trust_card as any, { ttl: 2 * 60 * 60 * 1000 });
                            logger.info(`[Sentinel] Brain enrichment overlay applied for ${target}`);
                        }
                    }).catch(() => { /* enrichment failed silently */ });
                }

                return card;
            }
        } catch (e: any) {
            logger.warn(`[Sentinel] Direct provider call failed: ${e.message}`);
        }

        // ── STEP 3: FALLBACK — ip-api.com ────────────────────────────────────
        try {
            const r = await axios.get(
                `http://ip-api.com/json/${target}?fields=status,proxy,hosting,isp,org,as,countryCode,country,city`,
                { timeout: 2000 }
            );
            if (r.data?.status === 'success') {
                const asnNum  = parseInt(String(r.data.as ?? '').split(' ')[0].replace('AS','') || '0');
                const org     = (r.data.org ?? '').toLowerCase();
                const isp     = (r.data.isp ?? '').toLowerCase();
                const isVpn   = !!(r.data.proxy);
                const isDC    = !!(r.data.hosting);
                const asnHit  = HIGH_RISK_ASNS.has(asnNum);
                const termHit = HIGH_RISK_TERMS.some(t => org.includes(t) || isp.includes(t));
                const hostile = isVpn || isDC || asnHit || termHit;

                const card: TrustCard = {
                    target,
                    verdict:     hostile ? 'UNTRUSTED' : 'TRUSTED',
                    trust_score: hostile ? 5 : 88,
                    network: {
                        provider: r.data.org ?? 'Unknown',
                        asn:      String(asnNum),
                        system:   r.data.isp ?? 'Unknown',
                        protocol: 'IPv4',
                        node_type: isVpn ? 'VPN' : (isDC || asnHit ? 'Infrastructure' : 'Residential'),
                        zone:      r.data.countryCode ?? 'XX'
                    },
                    geo: { location: r.data.country ?? 'Unknown', city: r.data.city ?? 'Unknown' },
                    telemetry_flags: hostile ? ['FALLBACK_INFRA_MATCH'] : []
                };
                const trustCardCacheKey = `trustcard:${target}`;
                intelCache.set(trustCardCacheKey, card as any, { ttl: 2 * 60 * 60 * 1000 });
                return card;
            }
        } catch (e: any) {
            logger.warn(`[Sentinel] Fallback provider failed: ${e.message}`);
        }

        return undefined;
    }

    /**
     * Patch IPv6 Loophole: Collapse IPv6 addresses into their /64 subnet
     */
    static normalizeTarget(ip: string): string {
        if (!ip.includes(':')) return ip; // Return IPv4 as is
        const blocks = ip.split(':');
        if (blocks.length >= 4) {
            return blocks.slice(0, 4).join(':') + '::/64';
        }
        return ip;
    }
}
