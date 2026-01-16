"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const intelController_1 = require("../controllers/intelController");
const auth_1 = require("../middleware/auth");
const router = (0, express_1.Router)();
// Public Pre-check (Used for Conditional Captcha)
router.get('/precheck', intelController_1.preCheck);
// v1 Check Endpoint (Increments Quota)
router.post('/check', auth_1.authMiddleware, auth_1.quotaMiddleware, intelController_1.checkTarget);
// Decoupled Challenge System (Free Auth)
router.post('/challenge/issue', auth_1.authMiddleware, intelController_1.issueChallenge);
router.post('/challenge/verify', auth_1.authMiddleware, intelController_1.verifyChallenge);
// SOC Health Vitals
router.get('/health', auth_1.authMiddleware, intelController_1.getHealth);
exports.default = router;
