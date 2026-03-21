import { LRUCache } from 'lru-cache';
import { IntelResult } from '../services/intelService';
import Redis from 'ioredis';
import logger from '../utils/logger';

const options = {
    max: 5000,
    ttl: 20 * 60 * 1000,
    allowStale: false,
    updateAgeOnGet: false,
};

export const intelCache = new LRUCache<string, IntelResult & { security_challenge?: any; verdict_reasons?: string[] }>(options);

export const cacheStats = {
    hits: 0,
    misses: 0
};

export const velocityCache = new LRUCache<string, number[]>({
    max: 10000,
    ttl: 60 * 60 * 1000 // 1 hour tracking
});

// For Sequence Entropy
export const sequenceCache = new LRUCache<string, { path: string, time: number }[]>({
    max: 10000,
    ttl: 5 * 60 * 1000 // 5 minutes tracking for paths
});

export const redisClient = process.env.REDIS_URL ? new Redis(process.env.REDIS_URL, {
    maxRetriesPerRequest: 3,
    retryStrategy: (times) => Math.min(times * 50, 2000)
}) : null;

if (redisClient) {
    redisClient.on('error', (err) => logger.error('Redis Error:', err));
    redisClient.on('connect', () => logger.info('Distributed Velocity Engine (Redis) CONNECTED.'));
}

export class SharedCache {
    /**
     * Push a timestamp to a velocity array and return the count.
     */
    static async recordVelocity(target: string): Promise<number> {
        const now = Date.now();
        if (redisClient) {
            const key = `sentinel:vel:${target}`;
            const multi = redisClient.multi();
            multi.lpush(key, now);
            multi.ltrim(key, 0, 9); // Keep last 10
            multi.expire(key, 3600); // 1 hour
            const results = await multi.exec();
            // result of lpush is the length
            if (results && results[0] && results[0][1]) {
                return results[0][1] as number;
            }
            return 1;
        } else {
            const velocity = velocityCache.get(target) || [];
            velocity.push(now);
            velocityCache.set(target, velocity.slice(-10));
            return velocity.length;
        }
    }

    /**
     * Record a path traversal and return the sequence.
     */
    static async recordSequence(target: string, path: string): Promise<{ path: string, time: number }[]> {
        const now = Date.now();
        const entry = { path, time: now };
        
        if (redisClient) {
            const key = `sentinel:seq:${target}`;
            const seqStr = await redisClient.get(key) || '[]';
            const seq = JSON.parse(seqStr) as { path: string, time: number }[];
            seq.push(entry);
            const trimmed = seq.slice(-5); // Keep last 5
            await redisClient.setex(key, 300, JSON.stringify(trimmed));
            return trimmed;
        } else {
            const seq = sequenceCache.get(target) || [];
            seq.push(entry);
            const trimmed = seq.slice(-5);
            sequenceCache.set(target, trimmed);
            return trimmed;
        }
    }
}
