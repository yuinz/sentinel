"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const supabase_1 = require("../config/supabase");
const crypto_1 = __importDefault(require("crypto"));
const router = (0, express_1.Router)();
// Middleware to verify Supabase JWT
const ensureSupabaseAuth = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No authorization token provided' });
    }
    const token = authHeader.split(' ')[1];
    const { data: { user }, error } = await supabase_1.supabase.auth.getUser(token);
    if (error || !user) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
};
// API Key Management Routes
router.get('/keys', ensureSupabaseAuth, async (req, res) => {
    const user = req.user;
    const { data, error } = await supabase_1.supabase
        .from('api_access')
        .select('*')
        .eq('user_id', user.id);
    if (error) {
        return res.status(500).json({ error: 'Failed to fetch API keys' });
    }
    res.json(data || []);
});
router.post('/keys/generate', ensureSupabaseAuth, async (req, res) => {
    const user = req.user;
    const newKey = `sk_live_${crypto_1.default.randomBytes(24).toString('hex')}`;
    const { data, error } = await supabase_1.supabase
        .from('api_access')
        .insert({
        user_id: user.id,
        email: user.email,
        api_key: newKey,
        usage_count: 0,
        max_usage: 500
    })
        .select()
        .single();
    if (error) {
        console.error('Key generation error:', error);
        return res.status(500).json({ error: 'Failed to generate API key' });
    }
    res.json({ success: true, key: data });
});
exports.default = router;
