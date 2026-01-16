import { LRUCache } from 'lru-cache';
import { IntelResult } from '../services/intelService';

const options = {
    // Keeping up to 5000 scans in memory for ultra-fast lookup
    max: 5000,

    // 20 minute TTL (Time to Live) as requested: 20 * 60 * 1000 ms
    ttl: 20 * 60 * 1000,

    // Clean up expired items periodically
    allowStale: false,
    updateAgeOnGet: false,
};

export const intelCache = new LRUCache<string, IntelResult & { security_challenge?: any; verdict_reasons?: string[] }>(options);

// Tracking for SOC health metrics
export const cacheStats = {
    hits: 0,
    misses: 0
};

// Velocity tracking for behavioral detection (IP -> timestamp[])
export const velocityCache = new LRUCache<string, number[]>({
    max: 10000,
    ttl: 60 * 60 * 1000 // 1 hour tracking
});
