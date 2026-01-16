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
    // Check existing key count for free tier limit
    const { data: existingKeys, error: countError } = await supabase_1.supabase
        .from('api_access')
        .select('id')
        .eq('user_id', user.id);
    if (countError) {
        console.error('Key count error:', countError);
        return res.status(500).json({ error: 'Failed to check existing keys' });
    }
    // Free tier: max 5 API keys
    if (existingKeys && existingKeys.length >= 5) {
        return res.status(403).json({
            error: 'Free tier limit reached',
            message: 'You have reached the maximum of 5 API keys for free accounts. Upgrade to Premium for unlimited vectors.',
            limit: 5,
            current: existingKeys.length
        });
    }
    const newKey = `sl_${crypto_1.default.randomBytes(24).toString('hex')}`;
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
router.get('/analytics', ensureSupabaseAuth, async (req, res) => {
    const user = req.user;
    try {
        // 1. Get all API keys for this user to filter telemetry
        const { data: keys } = await supabase_1.supabase
            .from('api_access')
            .select('id')
            .eq('user_id', user.id);
        if (!keys || keys.length === 0) {
            return res.json({ labels: [], values: [], risk_distribution: { stable: 0, unstable: 0, untrusted: 0 } });
        }
        const keyIds = keys.map(k => k.id);
        // 2. Fetch last 7 days of telemetry
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
        const { data: logs, error: logsError } = await supabase_1.supabase
            .from('telemetry')
            .select('verdict, created_at, target, latency_ms')
            .in('api_access_id', keyIds)
            .order('created_at', { ascending: false })
            .gte('created_at', sevenDaysAgo.toISOString());
        if (logsError)
            throw logsError;
        // 3. Process Risk Distribution
        const dist = { stable: 0, unstable: 0, untrusted: 0 };
        logs.forEach(l => {
            const v = l.verdict.toLowerCase();
            if (v === 'trusted')
                dist.stable++;
            else if (v === 'unstable')
                dist.unstable++;
            else if (v === 'untrusted')
                dist.untrusted++;
        });
        // 4. Process Daily Usage (Last 7 Days)
        const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        const dailyData = {};
        // Initialize last 7 days with 0
        for (let i = 6; i >= 0; i--) {
            const d = new Date();
            d.setDate(d.getDate() - i);
            dailyData[days[d.getDay()]] = 0;
        }
        logs.forEach(l => {
            const date = new Date(l.created_at);
            const dayLabel = days[date.getDay()];
            if (dailyData[dayLabel] !== undefined) {
                dailyData[dayLabel]++;
            }
        });
        res.json({
            labels: Object.keys(dailyData),
            values: Object.values(dailyData),
            risk_distribution: dist,
            total_signals: logs.length,
            recent_logs: logs.slice(0, 10).map(l => ({
                target: l.target,
                verdict: l.verdict,
                latency: l.latency_ms,
                time: l.created_at
            }))
        });
    }
    catch (err) {
        console.error('Analytics Fetch Error:', err);
        res.status(500).json({ error: 'Failed to generate real-time analytics' });
    }
});
exports.default = router;
