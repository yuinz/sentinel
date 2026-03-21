"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.visitorTracker = void 0;
const axios_1 = __importDefault(require("axios"));
const logger_1 = __importDefault(require("../utils/logger"));
const telemetryService_1 = require("../services/telemetryService");
// simple in-memory cache to avoid redundant IP-to-Country lookups in the same session
const countryCache = {};
const visitorTracker = async (req, res, next) => {
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
    const ip = req.headers['x-forwarded-for'] || req.ip || '127.0.0.1';
    const cleanIp = ip.includes(',') ? ip.split(',')[0].trim() : ip;
    // Fire and forget tracking
    trackVisit(cleanIp, userAgent, req.path).catch(err => {
        logger_1.default.error('Visitor tracking failed:', err);
    });
    next();
};
exports.visitorTracker = visitorTracker;
async function trackVisit(ip, userAgent, path) {
    if (ip === '127.0.0.1' || ip === '::1')
        return;
    let country = countryCache[ip] || 'Unknown';
    if (country === 'Unknown') {
        try {
            const response = await axios_1.default.get(`https://ipwho.is/${ip}`, { timeout: 2000 });
            if (response.data && response.data.success) {
                country = response.data.country || 'Unknown';
                countryCache[ip] = country;
            }
        }
        catch (e) {
            // Ignore lookup errors
        }
    }
    telemetryService_1.TelemetryService.logVisit({
        ip,
        country,
        user_agent: `[${path}] ${userAgent}`,
        created_at: new Date().toISOString()
    });
}
