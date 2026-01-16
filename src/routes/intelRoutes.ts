import { Router } from 'express';
import { checkTarget, getHealth, issueChallenge, verifyChallenge, preCheck } from '../controllers/intelController';
import { authMiddleware, quotaMiddleware } from '../middleware/auth';

const router = Router();

// Public Pre-check (Used for Conditional Captcha)
router.get('/precheck', preCheck);

// v1 Check Endpoint (Increments Quota)
router.post('/check', authMiddleware as any, quotaMiddleware as any, checkTarget);

// Decoupled Challenge System (Free Auth)
router.post('/challenge/issue', authMiddleware as any, issueChallenge);
router.post('/challenge/verify', authMiddleware as any, verifyChallenge);

// SOC Health Vitals
router.get('/health', authMiddleware as any, getHealth);

export default router;
