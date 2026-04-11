import { Router } from 'express';
import { evaluateV2 } from '../controllers/v2/intelControllerV2';
import { authMiddleware, quotaMiddleware } from '../middleware/auth';

const router = Router();

// V2 Engine (Multi-Tenant B2B Endpoint)
// Mounted logically at /v2 in the main express app.
// Middlewares enforce valid API key presence and deduct from billable usage quotas.
router.post('/evaluate', authMiddleware as any, quotaMiddleware as any, evaluateV2 as any);

export default router;
