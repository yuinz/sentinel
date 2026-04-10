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
        // 1. FAST PATH: Local/Private Network Bypass
        if (intelService_1.IntelService.isPrivateIp(target)) {
            signals.push({
                id: 'RESIDENTIAL_IP',
                weight: TrustCalculator_1.TrustCalculator.WEIGHTS.RESIDENTIAL_IP,
                label: 'Local/Private Network'
            });
            return this.finalizeCalculations(signals, policy, start);
        }
        // 2. FAST PATH: Cryptographic Token Proof
        // Directly solves the "VPN Infinite Challenge" bug. We securely verify the PoW token.
        if (trustToken && intelService_1.IntelService.verifyTrustToken(target, trustToken)) {
            signals.push({
                id: 'TOKEN_VALID',
                weight: TrustCalculator_1.TrustCalculator.WEIGHTS.TOKEN_VALID,
                label: 'Verified Behavioral Token Present'
            });
        }
        // 2.5 FAST PATH: Read Async Intelligence State (L2 Redis)
        // Catch the VPN if the Async Engine recently resolved it in the background.
        let isAsyncVpn = false;
        try {
            if (cache_1.redisClient) {
                isAsyncVpn = (await cache_1.redisClient.get(`v2:async:${target}:vpn`)) === 'true';
            }
            else {
                isAsyncVpn = cache_1.intelCache.get(`v2:async:${target}:vpn`) === 'true';
            }
            if (isAsyncVpn) {
                signals.push({ id: 'VPN_DETECTED', weight: TrustCalculator_1.TrustCalculator.WEIGHTS.VPN_DETECTED, label: 'VPN/Proxy Detected (Async Intelligence)' });
            }
        }
        catch (e) {
            logger_1.default.warn(`[V2] Failed to read async state for ${target}`);
        }
        // 3. FAST PATH: Datacenter Check (<2ms memory operation)
        // We reuse V1's matrix checker to identify AWS/Cloud infrastructure without applying V1's penalties.
        const v1MatrixCheck = intelService_1.IntelService.checkLocalAsnMatrix(target);
        if (v1MatrixCheck && v1MatrixCheck.risk > 0) {
            signals.push({
                id: 'DATACENTER_IP',
                weight: TrustCalculator_1.TrustCalculator.WEIGHTS.DATACENTER_IP,
                label: 'High-Risk Network Infrastructure (Cloud/Hosting)'
            });
        }
        else if (!isAsyncVpn) {
            // Non-datacenter IPs act organically and get a baseline Trust Boost.
            signals.push({
                id: 'RESIDENTIAL_IP',
                weight: TrustCalculator_1.TrustCalculator.WEIGHTS.RESIDENTIAL_IP,
                label: 'Residential/Organic Network'
            });
        }
        // 4. FAST PATH: Velocity Analysis (Redis-backed for edge compat)
        try {
            const velocityCount = await cache_1.SharedCache.recordVelocity(target);
            // V2 dynamically raises the velocity grace limit. 
            // 15 requests/sec is generous for humans but devastating for brute-force.
            if (velocityCount > 15) {
                signals.push({
                    id: 'HIGH_VELOCITY',
                    weight: TrustCalculator_1.TrustCalculator.WEIGHTS.HIGH_VELOCITY,
                    label: `Velocity Spike Detected (${velocityCount} requests)`
                });
            }
        }
        catch (err) {
            logger_1.default.error(`[V2] Distributed velocity check failed for ${target}:`, err);
        }
        // 5. FAST PATH: Automation / Scanner Detection
        const botKeywords = /headless|puppeteer|selenium|playwright|bot|crawl|spider|axios|python-requests|curl|wget/i;
        if (botKeywords.test(userAgent)) {
            signals.push({
                id: 'SCANNER_PATTERN',
                weight: TrustCalculator_1.TrustCalculator.WEIGHTS.SCANNER_PATTERN,
                label: 'Automation/Script Signature Detected'
            });
        }
        // 6. ASYNC BACKGROUND: Trigger forensic webhooks & rDNS (Does NOT block the user)
        this.triggerAsyncTasks(target, policy);
        // 7. Math & Verdict execution
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
