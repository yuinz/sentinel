"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const supabase_1 = require("../config/supabase");
const logger_1 = __importDefault(require("../utils/logger"));
const cache_1 = require("../utils/cache");
/**
 * Sentinel Live Signal Tailing Utility
 * Mimics the 'sentinel tail' experience from the architecture spec.
 */
async function tailSignals() {
    console.clear();
    console.log('\x1b[36m%s\x1b[0m', '🚀 Sentinel Node ACTIVE | Monitoring Global Threat Signals...');
    if (cache_1.redisClient) {
        console.log('\x1b[35m%s\x1b[0m', '⚡ Distributed Velocity Engine: ONLINE (Redis Sync Active)');
    }
    else {
        console.log('\x1b[33m%s\x1b[0m', '⚠️ Distributed Velocity Engine: OFFLINE (Using Local LRU Cache)');
    }
    console.log('\x1b[90m%s\x1b[0m', '-------------------------------------------------------------');
    // Currently polling since standard anon keys may have limited realtime perms
    // In production, this would use Supabase Realtime Channels.
    setInterval(async () => {
        try {
            const { data, error } = await supabase_1.supabase
                .from('telemetry')
                .select('*')
                .order('created_at', { ascending: false })
                .limit(5);
            if (error)
                throw error;
            if (data && data.length > 0) {
                data.reverse().forEach((log) => {
                    const time = new Date(log.created_at).toLocaleTimeString();
                    const color = log.verdict === 'UNTRUSTED' ? '\x1b[31m' : (log.verdict === 'UNSTABLE' ? '\x1b[33m' : '\x1b[32m');
                    const reset = '\x1b[0m';
                    console.log(`[${time}] ${log.target.padEnd(15)} | ${color}${log.verdict.padEnd(10)}${reset} | Score: ${log.trust_score.toString().padEnd(3)} | Reason: ${log.reason}`);
                });
            }
        }
        catch (e) {
            logger_1.default.error('[CLI] Tail error:', e.message);
        }
    }, 3000);
}
tailSignals();
