import { Request, Response, NextFunction } from 'express';
import { supabase } from '../config/supabase';
import axios from 'axios';
import logger from '../utils/logger';

// simple in-memory cache to avoid redundant IP-to-Country lookups in the same session
const countryCache: Record<string, string> = {};

export const visitorTracker = async (req: Request, res: Response, next: NextFunction) => {
    const userAgent = req.get('User-Agent') || 'unknown';

    // 1. Skip UptimeRobot and other health monitors to keep DB clean
    if (userAgent.toLowerCase().includes('uptimerobot')) {
        return next();
    }

    // Only track HTML page requests or root
    const isPage = req.accepts('html') && !req.path.includes('.') || req.path === '/' || req.path.endsWith('.html');

    if (!isPage) {
        return next();
    }

    const ip = (req.headers['x-forwarded-for'] as string) || req.ip || '127.0.0.1';
    const cleanIp = ip.includes(',') ? ip.split(',')[0].trim() : ip;

    // Fire and forget tracking
    trackVisit(cleanIp, userAgent).catch(err => {
        logger.error('Visitor tracking failed:', err);
    });

    next();
};

async function trackVisit(ip: string, userAgent: string) {
    if (ip === '127.0.0.1' || ip === '::1') return;

    let country = countryCache[ip] || 'Unknown';

    if (country === 'Unknown') {
        try {
            const response = await axios.get(`https://ipwho.is/${ip}`, { timeout: 2000 });
            if (response.data && response.data.success) {
                country = response.data.country || 'Unknown';
                countryCache[ip] = country;
            }
        } catch (e) {
            // Ignore lookup errors
        }
    }

    await supabase.from('site_visits').insert({
        ip,
        country,
        user_agent: userAgent,
        created_at: new Date().toISOString()
    });
}
