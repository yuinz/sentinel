import axios from 'axios';
import logger from '../utils/logger';

export interface BroadcastPayload {
    ip: string;
    verdict: 'TRUSTED' | 'UNSTABLE' | 'UNTRUSTED';
    reason?: string;
    profile?: string;
    ttl?: number;
}

/**
 * Sentinel Broadcast Service
 * This service is responsible for pushing block verdicts to the Global Edge (Cloudflare/Vercel)
 * and triggering webhooks for persistent threat propagation.
 */
export class BroadcastService {
    private static readonly CF_AUTH_EMAIL = process.env.CLOUDFLARE_EMAIL;
    private static readonly CF_AUTH_KEY = process.env.CLOUDFLARE_API_KEY;
    private static readonly CF_ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID;
    private static readonly CF_KV_NAMESPACE = process.env.CLOUDFLARE_KV_ID;

    private static readonly WEBHOOK_URL = process.env.SENTINEL_WEBHOOK_URL;

    /**
     * Broadcast a verdict to the global network.
     * This is fire-and-forget to keep engine response times < 50ms.
     */
    static async broadcast(payload: BroadcastPayload) {
        // Only broadcast UNTRUSTED signals to avoid global noise
        if (payload.verdict !== 'UNTRUSTED') return;

        logger.info(`[Broadcast] Propagating threat signal for ${payload.ip} [Reason: ${payload.reason || 'none'}]`);

        // 1. Trigger Internal Webhook
        if (this.WEBHOOK_URL) {
            axios.post(this.WEBHOOK_URL, {
                event: 'THREAT_DETECTED',
                ...payload,
                timestamp: new Date().toISOString()
            }).catch(e => logger.error('[Broadcast] Local Webhook failed', e));
        }

        // 2. Sync to Cloudflare KV (sub-2ms rejection at CDN edge)
        if (this.CF_AUTH_KEY && this.CF_ACCOUNT_ID && this.CF_KV_NAMESPACE) {
            this.syncToCloudflare(payload.ip, 'BLOCK', payload.ttl || 3600);
        }

        // 3. Sync to Global Registry (Optional dashboard update)
        // ... (Future: supabase push logic or specialized audit log)
    }

    /**
     * Propagate block to Cloudflare Key-Value store
     */
    private static async syncToCloudflare(ip: string, action: 'BLOCK' | 'ALLOW', ttl: number) {
        const url = `https://api.cloudflare.com/client/v4/accounts/${this.CF_ACCOUNT_ID}/storage/kv/namespaces/${this.CF_KV_NAMESPACE}/values/sentinel:verdict:${ip}`;
        
        try {
            await axios.put(url, action, {
                headers: {
                    'X-Auth-Email': this.CF_AUTH_EMAIL || '',
                    'X-Auth-Key': this.CF_AUTH_KEY,
                    'Content-Type': 'text/plain'
                },
                params: {
                    expiration_ttl: ttl
                }
            });
            logger.info(`[Broadcast] Edge Shield Sync Success: ${ip} -> ${action}`);
        } catch (e: any) {
            logger.error(`[Broadcast] Edge Shield Sync Failed for ${ip}`, e.message);
        }
    }
}
