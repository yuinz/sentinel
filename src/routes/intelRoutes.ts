import { Router } from 'express';
import { checkTarget, getHealth, issueChallenge, verifyChallenge, preCheck, getVisitorStats, flushCache } from '../controllers/intelController';
import { authMiddleware, quotaMiddleware } from '../middleware/auth';
import { challengeAuthMiddleware } from '../middleware/challengeAuth';

const router = Router();

// Public Pre-check (Used for Conditional Captcha)
router.get('/precheck', preCheck);

// v1 Check Endpoint (Increments Quota)
router.post('/check', authMiddleware as any, quotaMiddleware as any, checkTarget);

// Decoupled Challenge System (Soft Auth + Rate Limited)
router.post('/challenge/issue', challengeAuthMiddleware as any, issueChallenge);
router.post('/challenge/verify', challengeAuthMiddleware as any, verifyChallenge);

// Secret Intelligence Stats
router.get('/intel/secret-stats', getVisitorStats);

// SOC Health Vitals
router.get('/health', authMiddleware as any, getHealth);

// System Maintenance
router.post('/cache/flush', authMiddleware as any, flushCache);

export default router;
