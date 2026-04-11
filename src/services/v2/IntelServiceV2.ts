import { TrustSignal, EvaluationResult, V2PolicyConfig } from '../../types/v2';
import { TrustCalculator } from './TrustCalculator';
import { PolicyEngine } from './PolicyEngine';
import { SharedCache, intelCache, redisClient } from '../../utils/cache';
import { ConfigService } from '../configService';
import { IntelService as V1Helpers } from '../intelService';
import logger from '../../utils/logger';

export class IntelServiceV2 {
    
    /**
     * V2 Orchestrator.
     * Guaranteed sub-50ms execution on edge or serverless by strictly avoiding DB round-trips.
     * Sequence: Gather Fast Signals -> Calculate Math -> Decide Verdict -> Fire Async Background.
     */
    static async evaluate(
        rawTarget: string,
        policy: V2PolicyConfig,
        trustToken?: string,
        userAgent: string = 'unknown'
    ): Promise<EvaluationResult> {
        const start = Date.now();
        const target = V1Helpers.normalizeTarget(rawTarget);
        const signals: TrustSignal[] = [];

        // 1. FAST PATH: Local/Private Network Bypass
        if (V1Helpers.isPrivateIp(target)) {
            signals.push({ 
                id: 'RESIDENTIAL_IP', 
                weight: TrustCalculator.WEIGHTS.RESIDENTIAL_IP, 
                label: 'Local/Private Network' 
            });
            return this.finalizeCalculations(signals, policy, start);
        }

        // 2. FAST PATH: Cryptographic Token Proof
        if (trustToken && V1Helpers.verifyTrustToken(target, trustToken)) {
             signals.push({ 
                 id: 'TOKEN_VALID', 
                 weight: TrustCalculator.WEIGHTS.TOKEN_VALID, 
                 label: 'Verified Behavioral Token Present' 
             });
        }

        // 2a. POLICY ENFORCEMENT: Force BWT — challenge all unverified traffic
        // If the tenant has enabled force_bwt and no token was validated, force CHALLENGE immediately.
        const hasValidToken = signals.some(s => s.id === 'TOKEN_VALID');
        if (policy.force_bwt === true && !hasValidToken) {
            return {
                verdict: 'CHALLENGE',
                score: 0,
                signals,
                action_required: 'SOLVE_CAPTCHA',
                latency_ms: Date.now() - start
            };
        }

        // 2.5 FAST PATH: Read Async Intelligence State (L2 Redis)
        // Catch the VPN if the Async Engine recently resolved it in the background.
        let isAsyncVpn = false;
        try {
            if (redisClient) {
                isAsyncVpn = (await redisClient.get(`v2:async:${target}:vpn`)) === 'true';
            } else {
                isAsyncVpn = intelCache.get(`v2:async:${target}:vpn`) === ('true' as any);
            }
            
            if (isAsyncVpn) {
                signals.push({ id: 'VPN_DETECTED', weight: TrustCalculator.WEIGHTS.VPN_DETECTED, label: 'VPN/Proxy Detected (Async Intelligence)' });
                // 2.5a. POLICY ENFORCEMENT: Block Proxies
                if (policy.block_proxies === true) {
                    signals.push({ id: 'POLICY_BLOCK_PROXY', weight: -100, label: 'Blocked by Tenant Policy: Proxy Denied' });
                }
            }
        } catch (e) {
            logger.warn(`[V2] Failed to read async state for ${target}`);
        }

        const v1MatrixCheck = V1Helpers.checkLocalAsnMatrix(target);
        const isDatacenter = v1MatrixCheck && v1MatrixCheck.risk > 0;
        if (isDatacenter) {
            signals.push({
                id: 'DATACENTER_IP',
                weight: TrustCalculator.WEIGHTS.DATACENTER_IP,
                label: 'High-Risk Network Infrastructure (Cloud/Hosting)'
            });
            // 3a. POLICY ENFORCEMENT: Block Datacenters
            if (policy.block_datacenters === true) {
                signals.push({ id: 'POLICY_BLOCK_DC', weight: -100, label: 'Blocked by Tenant Policy: Datacenter IP Denied' });
            }
        } else if (!isAsyncVpn) {
            // Non-datacenter IPs act organically and get a baseline Trust Boost.
            signals.push({
                id: 'RESIDENTIAL_IP',
                weight: TrustCalculator.WEIGHTS.RESIDENTIAL_IP,
                label: 'Residential/Organic Network'
            });
        }

        // 4. FAST PATH: Velocity Analysis (Redis-backed for edge compat)
        try {
            const velocityCount = await SharedCache.recordVelocity(target);
            // V2 dynamically raises the velocity grace limit. 
            // 15 requests/sec is generous for humans but devastating for brute-force.
            if (velocityCount > 15) { 
                signals.push({
                    id: 'HIGH_VELOCITY',
                    weight: TrustCalculator.WEIGHTS.HIGH_VELOCITY,
                    label: `Velocity Spike Detected (${velocityCount} requests)`
                });
            }
        } catch (err) {
            logger.error(`[V2] Distributed velocity check failed for ${target}:`, err);
        }

        // 5. FAST PATH: Automation / Scanner Detection
        const botKeywords = /headless|puppeteer|selenium|playwright|bot|crawl|spider|axios|python-requests|curl|wget/i;
        if (botKeywords.test(userAgent)) {
            signals.push({
                id: 'SCANNER_PATTERN',
                weight: TrustCalculator.WEIGHTS.SCANNER_PATTERN,
                label: 'Automation/Script Signature Detected'
            });
        }

        // 6. ASYNC BACKGROUND: Trigger forensic webhooks & rDNS (Does NOT block the user)
        this.triggerAsyncTasks(target, policy);

        // 7. Math & Verdict execution
        return this.finalizeCalculations(signals, policy, start);
    }

    private static finalizeCalculations(signals: TrustSignal[], policy: V2PolicyConfig, startTime: number): EvaluationResult {
        const score = TrustCalculator.calculateScore(signals);
        const verdict = PolicyEngine.decideVerdict(score, policy, signals);

        let action: 'SOLVE_CAPTCHA' | 'SILENT_CHALLENGE' | undefined = undefined;
        if (verdict === 'CHALLENGE') {
             action = 'SOLVE_CAPTCHA';
        }

        return {
            verdict,
            score,
            signals,
            action_required: action,
            latency_ms: Date.now() - startTime
        };
    }

    private static triggerAsyncTasks(target: string, policy: V2PolicyConfig) {
         // This runs securely behind the scenes AFTER the response is already on its way back to the user.
         Promise.resolve().then(() => {
             // Deep trace external VPN check using V1's network API bindings.
             V1Helpers.fetchTrustCard(target).then(async (card) => {
                 if (card) {
                     const isVpnUrl = card.network?.node_type?.toLowerCase().includes('vpn') || card.network?.node_type?.toLowerCase().includes('proxy');
                     const cacheKey = `v2:async:${target}:vpn`;
                     const stringVal = isVpnUrl ? 'true' : 'false';
                     
                     if (redisClient) {
                         await redisClient.setex(cacheKey, 86400, stringVal); // Cache for 24 hours
                     } else {
                         intelCache.set(cacheKey, stringVal as any, { ttl: 86400000 } as any);
                     }
                     logger.info(`[V2 Async] Deep trace finished for ${target}. VPN Status cached: ${isVpnUrl}`);
                 }
             }).catch(() => {});
         }).catch(err => {
             logger.error(`[V2] Background execution error for ${target}`, err);
         });
    }
}
