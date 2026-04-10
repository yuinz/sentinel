import { Router } from 'express';
import { evaluateV2 } from '../controllers/v2/intelControllerV2';

const router = Router();

// V2 Engine (Multi-Tenant B2B Endpoint)
// Mounted logically at /v2 in the main express app.
router.post('/evaluate', evaluateV2 as any);

export default router;
