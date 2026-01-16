"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.quotaMiddleware = exports.authMiddleware = void 0;
const supabase_1 = require("../config/supabase");
const logger_1 = __importDefault(require("../utils/logger"));
const authMiddleware = async (req, res, next) => {
    let apiKey = req.headers['x-api-key'];
    const authHeader = req.headers['authorization'];
    // Support Bearer Token (Site Keys)
    if (!apiKey && authHeader && authHeader.startsWith('Bearer ')) {
        apiKey = authHeader.split(' ')[1];
    }
    if (!apiKey) {
        return res.status(401).json({ error: 'Missing security credentials.' });
    }
    try {
        const { data: authData, error: authError } = await supabase_1.supabase
            .from('api_access')
            .select('*')
            .eq('api_key', apiKey)
            .single();
        if (authError || !authData) {
            logger_1.default.warn(`Invalid access attempt: ${apiKey.substring(0, 8)}...`);
            return res.status(403).json({ error: 'Invalid security key.' });
        }
        req.user = {
            id: authData.id,
            email: authData.email,
            usage_count: authData.usage_count,
            max_usage: authData.max_usage,
            tier: authData.tier || 'FREE'
        };
        // Cache the raw record ID for the quota middleware
        req.apiRecordId = authData.id;
        next();
    }
    catch (err) {
        logger_1.default.error('Auth middleware exception', err);
        return res.status(500).json({ error: 'Internal server error during authentication.' });
    }
};
exports.authMiddleware = authMiddleware;
// Middleware to gated usage for analysis endpoints
const quotaMiddleware = async (req, res, next) => {
    if (!req.user || !req.apiRecordId) {
        return res.status(401).json({ error: 'Authentication required for this operation.' });
    }
    if (req.user.usage_count >= req.user.max_usage) {
        return res.status(402).json({ error: 'Quota exceeded. Contact support for higher limits.' });
    }
    try {
        await supabase_1.supabase
            .from('api_access')
            .update({ usage_count: req.user.usage_count + 1 })
            .eq('id', req.apiRecordId);
        next();
    }
    catch (err) {
        logger_1.default.error('Quota update failed', err);
        next(); // Still proceed
    }
};
exports.quotaMiddleware = quotaMiddleware;
