"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const intelControllerV2_1 = require("../controllers/v2/intelControllerV2");
const auth_1 = require("../middleware/auth");
const router = (0, express_1.Router)();
// V2 Engine (Multi-Tenant B2B Endpoint)
// Mounted logically at /v2 in the main express app.
// Middlewares enforce valid API key presence and deduct from billable usage quotas.
router.post('/evaluate', auth_1.authMiddleware, auth_1.quotaMiddleware, intelControllerV2_1.evaluateV2);
exports.default = router;
