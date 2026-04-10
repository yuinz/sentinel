"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const intelControllerV2_1 = require("../controllers/v2/intelControllerV2");
const router = (0, express_1.Router)();
// V2 Engine (Multi-Tenant B2B Endpoint)
// Mounted logically at /v2 in the main express app.
router.post('/evaluate', intelControllerV2_1.evaluateV2);
exports.default = router;
