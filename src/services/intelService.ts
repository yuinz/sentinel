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
        requestPath?: string
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

        let finalScore = Math.max(0, 100 - currentRisk + trustBonus);
        let verdict = finalScore >= (profile.threshold + 15) ? 'TRUSTED' : finalScore >= profile.threshold ? 'UNSTABLE' : 'UNTRUSTED';
        const verdictReasons: string[] = [];

        // 🔥 THE BRAIN OVERRIDE: If the upstream Multi-Provider Brain says UNTRUSTED, we OBEY.
        if (fullTrustCardData && fullTrustCardData.verdict === 'UNTRUSTED') {
            verdict = 'UNTRUSTED';
            finalScore = Math.min(finalScore, 30); // Force the score down to reflect the risk
            verdictReasons.push('untrusted_infrastructure');
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
            return t === target && (Math.floor(Date.now() / 1000) - parseInt(ts)) < 1800 && sig === crypto.createHmac('sha256', salt).update(`${t}:${ts}`).digest('hex').substring(0, 16);
        } catch { return false; }
    }

    static async issueBehavioralWork(rawTarget: string, context: string, duration?: number, userAgent: string = 'unknown') {
        const target = this.normalizeTarget(rawTarget);
        const difficulty = 4;
        const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
        const fp = crypto.createHash('md5').update(userAgent).digest('hex').substring(0, 8);
        const signature = crypto.createHash('sha256').update(target + salt + difficulty + fp).digest('hex').substring(0, 8);

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

    static verifyBehavioralWork(rawTarget: string, nonce: string, userAgent: string = 'unknown'): boolean {
        const target = this.normalizeTarget(rawTarget);
        try {
            const difficulty = parseInt(nonce.substring(8, 9), 10);
            const salt = process.env.POW_SECRET || 'sentinel-secure-powder';
            const fp = crypto.createHash('md5').update(userAgent).digest('hex').substring(0, 8);
            const signature = crypto.createHash('sha256').update(target + salt + difficulty + fp).digest('hex').substring(0, 8);

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
        try {
            // Target the Vercel Gatherer with ?legacy=true so it returns the formatted Trust Card
            const apiURL = process.env.RISKSIGNAL_API_URL || `https://app.risksignal.name.ng/api/scan`;
            const apiKey = process.env.RISKSIGNAL_API_KEY;

            if (!apiKey) return undefined;

            // Vercel /api/scan is a GET endpoint
            const res = await axios.get(`${apiURL}?ip=${target}&legacy=true`, {
                headers: { 'x-api-key': apiKey },
                timeout: 2500 // Aligned with SLA race timeout
            });

            if (res.data && res.data.status === 'success' && res.data.trust_card) {
                logger.info(`[Sentinel] Multi-Provider Sync Success: ${target}`);
                
                const trustCardCacheKey = `trustcard:${target}`;
                intelCache.set(trustCardCacheKey, res.data.trust_card as any, { ttl: 2 * 60 * 60 * 1000 }); // Cache for 2 hours
                
                return res.data.trust_card;
            }
        } catch (e: any) {
            logger.warn(`[Sentinel] Upstream Cluster Timeout: ${e.message}`);
            return undefined;
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
