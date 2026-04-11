import { Request, Response } from 'express';
import { AuthRequest } from '../../middleware/auth';
import { IntelServiceV2 } from '../../services/v2/IntelServiceV2';
import { TenantService } from '../../services/v2/TenantService';
import { TelemetryService } from '../../services/telemetryService';
import { BroadcastService } from '../../services/broadcastService';
import logger from '../../utils/logger';
import { z as zod } from 'zod';

const v2CheckSchema = zod.object({
    target: zod.string().min(3).max(255),
    path: zod.string().optional()
});

export const evaluateV2 = async (req: Request, res: Response) => {
    try {
        // 1. Strict Validation
        const validation = v2CheckSchema.safeParse(req.body);
        if (!validation.success) {
             return res.status(400).json({ status: 'error', error: 'Invalid target format.' });
        }
        let target = validation.data.target;
        if (target === 'detect') {
            target = (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() || req.ip || '127.0.0.1';
            if (target.startsWith('::ffff:')) target = target.substring(7);
        }
        
        const requestPath = validation.data.path || 'v2_api';
        const trustToken = req.headers['x-sentinel-trust'] as string;
        const userAgent = (req.headers['user-agent'] as string) || 'unknown';

        // 2. Multi-Tenant Lookup
        // The widget/sdk sends `Authorization: Bearer ds_xyz...`
        const rawAuth = req.headers.authorization;
        const apiKey = rawAuth?.startsWith('Bearer ') 
            ? rawAuth.substring(7) 
            : (req.headers['x-api-key'] as string || '');

        // 3. Resolve the strictly typed Policy Configuration
        const policy = await TenantService.getPolicy(apiKey);

        // 4. Engage pure V2 Architecture
        const evaluation = await IntelServiceV2.evaluate(
            target,
            policy,
            trustToken,
            userAgent
        );

        // 5. Fire Telemetry Sync (Analytics Bridge)
        const isBotMonitor = userAgent.toLowerCase().includes('uptimerobot');
        if (!isBotMonitor) {
            try {
                // Determine highest impact signal for the reason string
                const topSignal = evaluation.signals.length > 0 
                  ? evaluation.signals.reduce((prev, current) => (prev.weight < current.weight) ? prev : current).id 
                  : (evaluation.verdict === 'ALLOW' ? 'reputation_verified' : 'untrusted_infrastructure');

                TelemetryService.log({
                    api_access_id: (req as any).apiRecordId, // Added silently by authMiddleware!
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
            } catch (e) {
                logger.error('[V2] Telemetry recording failed', e);
            }

            // 6. Global Edge Broadcast (V2 -> V1 Edge sync)
            if (evaluation.verdict === 'BLOCK') {
                BroadcastService.broadcast({
                    ip: target,
                    verdict: 'UNTRUSTED',
                    reason: 'v2_policy_violation',
                    profile: 'v2_global'
                }).catch(e => logger.error('[V2] Global Broadcast failed', e));
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

    } catch (err: any) {
        logger.error('[V2] Controller failure', err);
        return res.status(500).json({ status: 'error', error: 'V2 Engine failure.' });
    }
};
