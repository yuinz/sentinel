"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const intelController_1 = require("../controllers/intelController");
const auth_1 = require("../middleware/auth");
const challengeAuth_1 = require("../middleware/challengeAuth");
const router = (0, express_1.Router)();
// Public Pre-check (Used for Conditional Captcha)
router.get('/precheck', intelController_1.preCheck);
// v1 Check Endpoint (Increments Quota)
router.post('/check', auth_1.authMiddleware, auth_1.quotaMiddleware, intelController_1.checkTarget);
// Decoupled Challenge System (Soft Auth + Rate Limited)
router.post('/challenge/issue', challengeAuth_1.challengeAuthMiddleware, intelController_1.issueChallenge);
router.post('/challenge/verify', challengeAuth_1.challengeAuthMiddleware, intelController_1.verifyChallenge);
// Secret Intelligence Stats
router.get('/intel/secret-stats', intelController_1.getVisitorStats);
// SOC Health Vitals
router.get('/health', auth_1.authMiddleware, intelController_1.getHealth);
// System Maintenance
router.post('/cache/flush', auth_1.authMiddleware, intelController_1.flushCache);
exports.default = router;
