"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SharedCache = exports.redisClient = exports.sequenceCache = exports.velocityCache = exports.cacheStats = exports.intelCache = void 0;
const lru_cache_1 = require("lru-cache");
const ioredis_1 = __importDefault(require("ioredis"));
const logger_1 = __importDefault(require("../utils/logger"));
const options = {
    max: 5000,
    ttl: 20 * 60 * 1000,
    allowStale: false,
    updateAgeOnGet: false,
};
exports.intelCache = new lru_cache_1.LRUCache(options);
exports.cacheStats = {
    hits: 0,
    misses: 0
};
exports.velocityCache = new lru_cache_1.LRUCache({
    max: 10000,
    ttl: 60 * 60 * 1000 // 1 hour tracking
});
// For Sequence Entropy
exports.sequenceCache = new lru_cache_1.LRUCache({
    max: 10000,
    ttl: 5 * 60 * 1000 // 5 minutes tracking for paths
});
exports.redisClient = process.env.REDIS_URL ? new ioredis_1.default(process.env.REDIS_URL, {
    maxRetriesPerRequest: 3,
    retryStrategy: (times) => Math.min(times * 50, 2000)
}) : null;
if (exports.redisClient) {
    exports.redisClient.on('error', (err) => logger_1.default.error('Redis Error:', err));
    exports.redisClient.on('connect', () => logger_1.default.info('Distributed Velocity Engine (Redis) CONNECTED.'));
}
class SharedCache {
    /**
     * Push a timestamp to a velocity array and return the count.
     */
    static async recordVelocity(target) {
        const now = Date.now();
        if (exports.redisClient) {
            const key = `sentinel:vel:${target}`;
            const multi = exports.redisClient.multi();
            multi.lpush(key, now);
            multi.ltrim(key, 0, 9); // Keep last 10
            multi.expire(key, 3600); // 1 hour
            const results = await multi.exec();
            // result of lpush is the length
            if (results && results[0] && results[0][1]) {
                return results[0][1];
            }
            return 1;
        }
        else {
            const velocity = exports.velocityCache.get(target) || [];
            velocity.push(now);
            exports.velocityCache.set(target, velocity.slice(-10));
            return velocity.length;
        }
    }
    /**
     * Record a path traversal and return the sequence.
     */
    static async recordSequence(target, path) {
        const now = Date.now();
        const entry = { path, time: now };
        if (exports.redisClient) {
            const key = `sentinel:seq:${target}`;
            const seqStr = await exports.redisClient.get(key) || '[]';
            const seq = JSON.parse(seqStr);
            seq.push(entry);
            const trimmed = seq.slice(-5); // Keep last 5
            await exports.redisClient.setex(key, 300, JSON.stringify(trimmed));
            return trimmed;
        }
        else {
            const seq = exports.sequenceCache.get(target) || [];
            seq.push(entry);
            const trimmed = seq.slice(-5);
            exports.sequenceCache.set(target, trimmed);
            return trimmed;
        }
    }
}
exports.SharedCache = SharedCache;
