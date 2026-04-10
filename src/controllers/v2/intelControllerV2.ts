import { Request, Response } from 'express';
import { IntelServiceV2 } from '../../services/v2/IntelServiceV2';
import { TenantService } from '../../services/v2/TenantService';
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

        const { target } = validation.data;
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

        // 5. Respond perfectly cleanly
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
