"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.velocityCache = exports.cacheStats = exports.intelCache = void 0;
const lru_cache_1 = require("lru-cache");
const options = {
    // Keeping up to 5000 scans in memory for ultra-fast lookup
    max: 5000,
    // 20 minute TTL (Time to Live) as requested: 20 * 60 * 1000 ms
    ttl: 20 * 60 * 1000,
    // Clean up expired items periodically
    allowStale: false,
    updateAgeOnGet: false,
};
exports.intelCache = new lru_cache_1.LRUCache(options);
// Tracking for SOC health metrics
exports.cacheStats = {
    hits: 0,
    misses: 0
};
// Velocity tracking for behavioral detection (IP -> timestamp[])
exports.velocityCache = new lru_cache_1.LRUCache({
    max: 10000,
    ttl: 60 * 60 * 1000 // 1 hour tracking
});
