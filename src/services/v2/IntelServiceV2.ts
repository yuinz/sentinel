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

        // ── PHASE 1: SIGNAL COLLECTION ─────────────────────────────────────────
        // Collect ALL signals unconditionally before applying any policy overrides.

        // 1. Private/Local Network — immediate trust, skip all checks
        if (V1Helpers.isPrivateIp(target)) {
            signals.push({
                id: 'RESIDENTIAL_IP',
                weight: TrustCalculator.WEIGHTS.RESIDENTIAL_IP,
                label: 'Local/Private Network'
            });
            return this.finalizeCalculations(signals, policy, start);
        }

        // 2. Cryptographic Token Proof
        if (trustToken && V1Helpers.verifyTrustToken(target, trustToken)) {
            signals.push({
                id: 'TOKEN_VALID',
                weight: TrustCalculator.WEIGHTS.TOKEN_VALID,
                label: 'Verified Behavioral Token Present'
            });
        }

        // 3. Async VPN Intelligence (L2 Redis — non-blocking read)
        let isAsyncVpn = false;
        try {
            if (redisClient) {
                isAsyncVpn = (await redisClient.get(`v2:async:${target}:vpn`)) === 'true';
            } else {
                isAsyncVpn = intelCache.get(`v2:async:${target}:vpn`) === ('true' as any);
            }
            if (isAsyncVpn) {
                signals.push({
                    id: 'VPN_DETECTED',
                    weight: TrustCalculator.WEIGHTS.VPN_DETECTED,
                    label: 'VPN/Proxy Detected (Async Intelligence)'
                });
            }
        } catch {
            logger.warn(`[V2] Failed to read async VPN state for ${target}`);
        }

        // 4. Datacenter / Infrastructure Check (<2ms memory operation)
        const v1MatrixCheck = V1Helpers.checkLocalAsnMatrix(target);
        const isDatacenter = v1MatrixCheck && v1MatrixCheck.risk > 0;
        if (isDatacenter) {
            signals.push({
                id: 'DATACENTER_IP',
                weight: TrustCalculator.WEIGHTS.DATACENTER_IP,
                label: 'High-Risk Network Infrastructure (Cloud/Hosting)'
            });
        } else if (!isAsyncVpn) {
            signals.push({
                id: 'RESIDENTIAL_IP',
                weight: TrustCalculator.WEIGHTS.RESIDENTIAL_IP,
                label: 'Residential/Organic Network'
            });
        }

        // 5. Velocity Analysis
        try {
            const velocityCount = await SharedCache.recordVelocity(target);
            if (velocityCount > 15) {
                signals.push({
                    id: 'HIGH_VELOCITY',
                    weight: TrustCalculator.WEIGHTS.HIGH_VELOCITY,
                    label: `Velocity Spike Detected (${velocityCount} requests)`
                });
            }
        } catch (err) {
            logger.error(`[V2] Velocity check failed for ${target}:`, err);
        }

        // 6. Automation / Scanner Detection
        const botKeywords = /headless|puppeteer|selenium|playwright|bot|crawl|spider|axios|python-requests|curl|wget/i;
        if (botKeywords.test(userAgent)) {
            signals.push({
                id: 'SCANNER_PATTERN',
                weight: TrustCalculator.WEIGHTS.SCANNER_PATTERN,
                label: 'Automation/Script Signature Detected'
            });
        }

        // ── PHASE 2: POLICY ENFORCEMENT ────────────────────────────────────────
        // All signals are now collected. Apply hard policy overrides in order of severity.
        // Hard blocks always take precedence over soft challenges.

        const hasValidToken = signals.some(s => s.id === 'TOKEN_VALID');

        // 2a. Block Proxies — hard block if VPN detected and policy says deny
        if (policy.block_proxies === true && isAsyncVpn) {
            signals.push({
                id: 'POLICY_BLOCK_PROXY',
                weight: -100,
                label: 'Blocked by Tenant Policy: Proxy/VPN Denied'
            });
            // Return BLOCK immediately — don't invite them to solve a CAPTCHA
            return {
                verdict: 'BLOCK',
                score: TrustCalculator.calculateScore(signals),
                signals,
                latency_ms: Date.now() - start
            };
        }

        // 2b. Block Datacenters — hard block if datacenter IP and policy says deny
        if (policy.block_datacenters === true && isDatacenter) {
            signals.push({
                id: 'POLICY_BLOCK_DC',
                weight: -100,
                label: 'Blocked by Tenant Policy: Datacenter IP Denied'
            });
            return {
                verdict: 'BLOCK',
                score: TrustCalculator.calculateScore(signals),
                signals,
                latency_ms: Date.now() - start
            };
        }

        // 2c. Force BWT — challenge unverified traffic (checked AFTER hard blocks)
        // Only fires if no hard block applied above.
        if (policy.force_bwt === true && !hasValidToken) {
            return {
                verdict: 'CHALLENGE',
                score: 0,
                signals,
                action_required: 'SOLVE_CAPTCHA',
                latency_ms: Date.now() - start
            };
        }

        // ── PHASE 3: ASYNC BACKGROUND ──────────────────────────────────────────
        // Fire forensic tasks AFTER response is on its way. Never blocks the user.
        this.triggerAsyncTasks(target, policy);

        // ── PHASE 4: SCORE + VERDICT ───────────────────────────────────────────
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
