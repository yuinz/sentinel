"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.evaluateV2 = void 0;
const IntelServiceV2_1 = require("../../services/v2/IntelServiceV2");
const TenantService_1 = require("../../services/v2/TenantService");
const telemetryService_1 = require("../../services/telemetryService");
const broadcastService_1 = require("../../services/broadcastService");
const logger_1 = __importDefault(require("../../utils/logger"));
const zod_1 = require("zod");
const v2CheckSchema = zod_1.z.object({
    target: zod_1.z.string().min(3).max(255),
    path: zod_1.z.string().optional()
});
const evaluateV2 = async (req, res) => {
    try {
        // 1. Strict Validation
        const validation = v2CheckSchema.safeParse(req.body);
        if (!validation.success) {
            return res.status(400).json({ status: 'error', error: 'Invalid target format.' });
        }
        let target = validation.data.target;
        if (target === 'detect') {
            target = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip || '127.0.0.1';
            if (target.startsWith('::ffff:'))
                target = target.substring(7);
        }
        const requestPath = validation.data.path || 'v2_api';
        const trustToken = req.headers['x-sentinel-trust'];
        const userAgent = req.headers['user-agent'] || 'unknown';
        // 2. Multi-Tenant Lookup
        // The widget/sdk sends `Authorization: Bearer ds_xyz...`
        const rawAuth = req.headers.authorization;
        const apiKey = rawAuth?.startsWith('Bearer ')
            ? rawAuth.substring(7)
            : (req.headers['x-api-key'] || '');
        // 3. Resolve the strictly typed Policy Configuration
        const policy = await TenantService_1.TenantService.getPolicy(apiKey);
        // 4. Engage pure V2 Architecture
        const evaluation = await IntelServiceV2_1.IntelServiceV2.evaluate(target, policy, trustToken, userAgent);
        // 5. Fire Telemetry Sync (Analytics Bridge)
        const isBotMonitor = userAgent.toLowerCase().includes('uptimerobot');
        if (!isBotMonitor) {
            try {
                // Determine highest impact signal for the reason string
                const topSignal = evaluation.signals.length > 0
                    ? evaluation.signals.reduce((prev, current) => (prev.weight < current.weight) ? prev : current).id
                    : (evaluation.verdict === 'ALLOW' ? 'reputation_verified' : 'untrusted_infrastructure');
                telemetryService_1.TelemetryService.log({
                    api_access_id: req.apiRecordId, // Added silently by authMiddleware!
                    target: target,
                    verdict: evaluation.verdict === 'ALLOW' ? 'TRUSTED' : (evaluation.verdict === 'BLOCK' ? 'UNTRUSTED' : 'CHALLENGE'),
                    trust_score: evaluation.score,
                    profile: 'v2_global', // Default profile context for V2 globally mapped rules
                    latency_ms: evaluation.latency_ms,
                    reason: `[${requestPath}] ${topSignal}`,
                    confidence: Math.min(Math.abs(evaluation.score), 100) / 100, // Normalized confidence mapping
                    bwt_verified: evaluation.signals.some(s => s.id === 'TOKEN_VALID'),
                    created_at: new Date().toISOString()
                });
            }
            catch (e) {
                logger_1.default.error('[V2] Telemetry recording failed', e);
            }
            // 6. Global Edge Broadcast (V2 -> V1 Edge sync)
            if (evaluation.verdict === 'BLOCK') {
                broadcastService_1.BroadcastService.broadcast({
                    ip: target,
                    verdict: 'UNTRUSTED',
                    reason: 'v2_policy_violation',
                    profile: 'v2_global'
                }).catch(e => logger_1.default.error('[V2] Global Broadcast failed', e));
            }
        }
        // 7. Respond perfectly cleanly
        return res.json({
            status: 'success',
            tenant: {
                api_key: apiKey ? 'VALID' : 'MISSING',
                policy_engaged: policy.mode
            },
            decision: evaluation
        });
    }
    catch (err) {
        logger_1.default.error('[V2] Controller failure', err);
        return res.status(500).json({ status: 'error', error: 'V2 Engine failure.' });
    }
};
exports.evaluateV2 = evaluateV2;
