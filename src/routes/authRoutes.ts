import { Router, Request, Response } from 'express';
import { supabase } from '../config/supabase';
import crypto from 'crypto';

const router = Router();

// Middleware to verify Supabase JWT
const ensureSupabaseAuth = async (req: Request, res: Response, next: any) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No authorization token provided' });
    }

    const token = authHeader.split(' ')[1];
    const { data: { user }, error } = await supabase.auth.getUser(token);

    if (error || !user) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }

    (req as any).user = user;
    next();
};

// API Key Management Routes
router.get('/keys', ensureSupabaseAuth, async (req: any, res) => {
    const user = req.user;

    const { data, error } = await supabase
        .from('api_access')
        .select('*')
        .eq('user_id', user.id);

    if (error) {
        return res.status(500).json({ error: 'Failed to fetch API keys' });
    }

    res.json(data || []);
});

router.post('/keys/generate', ensureSupabaseAuth, async (req: any, res) => {
    const user = req.user;

    // Check existing key count and tier
    // We try to select 'tier', but if it fails (e.g. column missing), we default to 'FREE'
    let userTier = 'FREE';
    let keysCount = 0;

    const { data: existingKeys, error: countError } = await supabase
        .from('api_access')
        .select('id, tier')
        .eq('user_id', user.id);

    if (countError) {
        // If selecting tier failed, it might be because the column doesn't exist yet.
        // We try again without tier to at least get the count for limits.
        const { data: fallbackKeys, error: fallbackError } = await supabase
            .from('api_access')
            .select('id')
            .eq('user_id', user.id);

        if (fallbackError) {
            console.error('Key count fallback error:', fallbackError);
            return res.status(500).json({ error: 'Failed to check existing keys' });
        }
        keysCount = fallbackKeys?.length || 0;
    } else {
        userTier = existingKeys?.[0]?.tier || 'FREE';
        keysCount = existingKeys?.length || 0;
    }

    // Free tier: max 5 API keys
    if (userTier === 'FREE' && keysCount >= 5) {
        return res.status(403).json({
            error: 'Free tier limit reached',
            message: 'You have reached the maximum of 5 API keys for free accounts. Upgrade to Premium for unlimited vectors.',
            limit: 5,
            current: keysCount
        });
    }

    const newKey = `sl_${crypto.randomBytes(24).toString('hex')}`;

    // Set usage limit based on tier
    const maxUsage = userTier === 'PRO' ? 500000 : 500;

    const payload: any = {
        user_id: user.id,
        email: user.email,
        api_key: newKey,
        usage_count: 0,
        max_usage: maxUsage
    };

    // Only add tier to payload if we successfully retrieved it earlier (or at least didn't fail finding it)
    if (!countError) {
        payload.tier = userTier;
    }

    const { data, error } = await supabase
        .from('api_access')
        .insert(payload)
        .select()
        .single();

    if (error) {
        console.error('Key generation error:', error);
        return res.status(500).json({ error: 'Failed to generate API key. (Tip: Ensure api_access table has a tier TEXT column)' });
    }

    res.json({ success: true, key: data });
});

router.get('/analytics', ensureSupabaseAuth, async (req: any, res) => {
    const user = req.user;

    try {
        // 1. Get all API keys for this user to filter telemetry and get all-time usage count
        const { data: keys } = await supabase
            .from('api_access')
            .select('id, usage_count')
            .eq('user_id', user.id);

        if (!keys || keys.length === 0) {
            return res.json({
                labels: [],
                values: [],
                risk_distribution: { stable: 0, unstable: 0, untrusted: 0 },
                total_signals: 0,
                outcomes: { blocked: 0, reduction: "0.0%", saved: "0", challenges: 0 },
                p95: 0
            });
        }

        const keyIds = keys.map(k => k.id);
        const allTimeSignals = keys.reduce((acc, k: any) => acc + (k.usage_count || 0), 0);

        // 2a. Fetch all-time blocked entries for persistent outcomes
        const { count: allTimeBlocked, error: blockedError } = await supabase
            .from('telemetry')
            .select('*', { count: 'exact', head: true })
            .in('api_access_id', keyIds)
            .in('verdict', ['UNTRUSTED', 'untrusted', 'UNSTABLE', 'unstable']);

        if (blockedError) console.error('Blocked count error:', blockedError);

        // 2b. Fetch last 7 days of telemetry for charting/logs
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

        const { data: logs, error: logsError } = await supabase
            .from('telemetry')
            .select('verdict, created_at, target, latency_ms, profile, reason, confidence, trust_score')
            .in('api_access_id', keyIds)
            .order('created_at', { ascending: false })
            .gte('created_at', sevenDaysAgo.toISOString());

        if (logsError) throw logsError;

        // 3. Process Risk Distribution
        const dist = { stable: 0, unstable: 0, untrusted: 0 };
        logs.forEach(l => {
            const v = l.verdict.toLowerCase();
            if (v === 'trusted') dist.stable++;
            else if (v === 'unstable') dist.unstable++;
            else if (v === 'untrusted') dist.untrusted++;
        });

        // 4. Process Daily Usage (Last 7 Days)
        const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        const dailyData: Record<string, number> = {};

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

        // 5. Calculate Outcomes (Persistent / All-Time)
        const persistentBlocked = allTimeBlocked || 0;

        // Mitigation Rate based on all-time activity (capped for realism if desired, but here pure)
        const mitigationRate = allTimeSignals > 0 ? ((persistentBlocked / allTimeSignals) * 100).toFixed(1) : "0.0";

        // Infra Saved: $0.013 per blocked request
        const savedRaw = persistentBlocked * 0.013;
        const infraSaved = savedRaw > 0 && savedRaw < 1 ? savedRaw.toFixed(2) : (savedRaw > 0 ? savedRaw.toFixed(0) : "0");

        // Real-time p95 calculation
        const validLatencies = logs.map(l => l.latency_ms).filter(l => (l || 0) > 0).sort((a, b) => a - b);
        const p95 = validLatencies.length > 0 ? validLatencies[Math.floor(validLatencies.length * 0.95)] : 21;

        res.json({
            labels: Object.keys(dailyData),
            values: Object.values(dailyData),
            risk_distribution: dist,
            total_signals: allTimeSignals, // Persistent
            p95: p95,
            outcomes: {
                blocked: persistentBlocked,
                reduction: mitigationRate + "%",
                challenges: 0,
                saved: infraSaved
            },
            recent_logs: logs.slice(0, 15).map(l => ({
                target: l.target,
                verdict: l.verdict,
                latency: l.latency_ms,
                time: l.created_at,
                profile: (l as any).profile || 'api',
                reason: (l as any).reason || 'reputation_verified',
                confidence: (l as any).confidence || 0.9,
                trust_score: (l as any).trust_score
            }))
        });

    } catch (err) {
        console.error('Analytics Fetch Error:', err);
        res.status(500).json({ error: 'Failed to generate real-time analytics' });
    }
});

export default router;
