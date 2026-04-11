"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.IntelServiceV2 = void 0;
const TrustCalculator_1 = require("./TrustCalculator");
const PolicyEngine_1 = require("./PolicyEngine");
const cache_1 = require("../../utils/cache");
const intelService_1 = require("../intelService");
const logger_1 = __importDefault(require("../../utils/logger"));
class IntelServiceV2 {
    /**
     * V2 Orchestrator.
     * Guaranteed sub-50ms execution on edge or serverless by strictly avoiding DB round-trips.
     * Sequence: Gather Fast Signals -> Calculate Math -> Decide Verdict -> Fire Async Background.
     */
    static async evaluate(rawTarget, policy, trustToken, userAgent = 'unknown') {
        const start = Date.now();
        const target = intelService_1.IntelService.normalizeTarget(rawTarget);
        const signals = [];
        // ── PHASE 1: SIGNAL COLLECTION ─────────────────────────────────────────
        // Collect ALL signals unconditionally before applying any policy overrides.
        // 1. Private/Local Network — immediate trust, skip all checks
        if (intelService_1.IntelService.isPrivateIp(target)) {
            signals.push({
                id: 'RESIDENTIAL_IP',
                weight: TrustCalculator_1.TrustCalculator.WEIGHTS.RESIDENTIAL_IP,
                label: 'Local/Private Network'
            });
            return this.finalizeCalculations(signals, policy, start);
        }
        // 2. Cryptographic Token Proof
        if (trustToken && intelService_1.IntelService.verifyTrustToken(target, trustToken)) {
            signals.push({
                id: 'TOKEN_VALID',
                weight: TrustCalculator_1.TrustCalculator.WEIGHTS.TOKEN_VALID,
                label: 'Verified Behavioral Token Present'
            });
        }
        // 3. Async VPN Intelligence (L2 Redis — non-blocking read)
        let isAsyncVpn = false;
        try {
            if (cache_1.redisClient) {
                isAsyncVpn = (await cache_1.redisClient.get(`v2:async:${target}:vpn`)) === 'true';
            }
            else {
                isAsyncVpn = cache_1.intelCache.get(`v2:async:${target}:vpn`) === 'true';
            }
            if (isAsyncVpn) {
                signals.push({
                    id: 'VPN_DETECTED',
                    weight: TrustCalculator_1.TrustCalculator.WEIGHTS.VPN_DETECTED,
                    label: 'VPN/Proxy Detected (Async Intelligence)'
                });
            }
        }
        catch {
            logger_1.default.warn(`[V2] Failed to read async VPN state for ${target}`);
        }
        // 4. Datacenter / Infrastructure Check (<2ms memory operation)
        const v1MatrixCheck = intelService_1.IntelService.checkLocalAsnMatrix(target);
        const isDatacenter = v1MatrixCheck && v1MatrixCheck.risk > 0;
        if (isDatacenter) {
            signals.push({
                id: 'DATACENTER_IP',
                weight: TrustCalculator_1.TrustCalculator.WEIGHTS.DATACENTER_IP,
                label: 'High-Risk Network Infrastructure (Cloud/Hosting)'
            });
        }
        else if (!isAsyncVpn) {
            signals.push({
                id: 'RESIDENTIAL_IP',
                weight: TrustCalculator_1.TrustCalculator.WEIGHTS.RESIDENTIAL_IP,
                label: 'Residential/Organic Network'
            });
        }
        // 5. Velocity Analysis
        try {
            const velocityCount = await cache_1.SharedCache.recordVelocity(target);
            if (velocityCount > 15) {
                signals.push({
                    id: 'HIGH_VELOCITY',
                    weight: TrustCalculator_1.TrustCalculator.WEIGHTS.HIGH_VELOCITY,
                    label: `Velocity Spike Detected (${velocityCount} requests)`
                });
            }
        }
        catch (err) {
            logger_1.default.error(`[V2] Velocity check failed for ${target}:`, err);
        }
        // 6. Automation / Scanner Detection
        const botKeywords = /headless|puppeteer|selenium|playwright|bot|crawl|spider|axios|python-requests|curl|wget/i;
        if (botKeywords.test(userAgent)) {
            signals.push({
                id: 'SCANNER_PATTERN',
                weight: TrustCalculator_1.TrustCalculator.WEIGHTS.SCANNER_PATTERN,
                label: 'Automation/Script Signature Detected'
            });
        }
        // ── PHASE 2: POLICY ENFORCEMENT ────────────────────────────────────────
        // All signals are now collected. Apply hard policy overrides in order of severity.
        // Hard blocks always take precedence over soft challenges.
        const hasValidToken = signals.some(s => s.id === 'TOKEN_VALID');
        // 2a. VPN / Proxy Enforcement
        if (isAsyncVpn) {
            const action = policy.vpn_action || 'allow';
            if (action === 'block') {
                signals.push({
                    id: 'POLICY_BLOCK_PROXY',
                    weight: -100,
                    label: 'Blocked by Tenant Policy: Proxy/VPN Denied'
                });
                return {
                    verdict: 'BLOCK',
                    score: TrustCalculator_1.TrustCalculator.calculateScore(signals),
                    signals,
                    latency_ms: Date.now() - start
                };
            }
            else if (action === 'challenge') {
                signals.push({
                    id: 'POLICY_CHALLENGE_PROXY',
                    weight: -40,
                    label: 'Challenged by Tenant Policy: Proxy/VPN Detected'
                });
            }
        }
        // 2b. Datacenter / Cloud Infrastructure Enforcement
        if (isDatacenter) {
            const action = policy.datacenter_action || 'allow';
            if (action === 'block') {
                signals.push({
                    id: 'POLICY_BLOCK_DC',
                    weight: -100,
                    label: 'Blocked by Tenant Policy: Datacenter IP Denied'
                });
                return {
                    verdict: 'BLOCK',
                    score: TrustCalculator_1.TrustCalculator.calculateScore(signals),
                    signals,
                    latency_ms: Date.now() - start
                };
            }
            else if (action === 'challenge') {
                signals.push({
                    id: 'POLICY_CHALLENGE_DC',
                    weight: -40,
                    label: 'Challenged by Tenant Policy: Datacenter IP Detected'
                });
            }
        }
        // 2c. Force BWT — challenge unverified traffic
        // Check if server bypass applies (e.g. non-browser automated client)
        const isServerClient = !(/mozilla|chrome|safari|applewebkit/i.test(userAgent)) || botKeywords.test(userAgent);
        const exemptBwt = policy.exempt_server_requests === true && isServerClient;
        if (policy.force_bwt === true && !hasValidToken && !exemptBwt) {
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
    static finalizeCalculations(signals, policy, startTime) {
        const score = TrustCalculator_1.TrustCalculator.calculateScore(signals);
        const verdict = PolicyEngine_1.PolicyEngine.decideVerdict(score, policy, signals);
        let action = undefined;
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
    static triggerAsyncTasks(target, policy) {
        // This runs securely behind the scenes AFTER the response is already on its way back to the user.
        Promise.resolve().then(() => {
            // Deep trace external VPN check using V1's network API bindings.
            intelService_1.IntelService.fetchTrustCard(target).then(async (card) => {
                if (card) {
                    const isVpnUrl = card.network?.node_type?.toLowerCase().includes('vpn') || card.network?.node_type?.toLowerCase().includes('proxy');
                    const cacheKey = `v2:async:${target}:vpn`;
                    const stringVal = isVpnUrl ? 'true' : 'false';
                    if (cache_1.redisClient) {
                        await cache_1.redisClient.setex(cacheKey, 86400, stringVal); // Cache for 24 hours
                    }
                    else {
                        cache_1.intelCache.set(cacheKey, stringVal, { ttl: 86400000 });
                    }
                    logger_1.default.info(`[V2 Async] Deep trace finished for ${target}. VPN Status cached: ${isVpnUrl}`);
                }
            }).catch(() => { });
        }).catch(err => {
            logger_1.default.error(`[V2] Background execution error for ${target}`, err);
        });
    }
}
exports.IntelServiceV2 = IntelServiceV2;
