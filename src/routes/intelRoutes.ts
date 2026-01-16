import { Router } from 'express';
import { checkTarget, getHealth, issueChallenge, verifyChallenge, preCheck, getVisitorStats } from '../controllers/intelController';
import { authMiddleware, quotaMiddleware } from '../middleware/auth';

const router = Router();

// Public Pre-check (Used for Conditional Captcha)
router.get('/precheck', preCheck);

// v1 Check Endpoint (Increments Quota)
router.post('/check', authMiddleware as any, quotaMiddleware as any, checkTarget);

// Decoupled Challenge System (Public - No Auth Required)
router.post('/challenge/issue', issueChallenge);
router.post('/challenge/verify', verifyChallenge);

// Secret Intelligence Stats
router.get('/intel/secret-stats', getVisitorStats);

// SOC Health Vitals
router.get('/health', authMiddleware as any, getHealth);

export default router;
