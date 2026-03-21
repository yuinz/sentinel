import { supabase } from '../config/supabase';
import logger from '../utils/logger';

/**
 * Render Free Tier Optimizer:
 * Instead of firing individual HTTP requests to Supabase per API scan
 * which exhausts sockets and RAM on 512MB dynos, this queues logs
 * and fires them in bulk every 5s or 50 records.
 */
export class TelemetryService {
    private static telemetryBatch: any[] = [];
    private static visitorBatch: any[] = [];
    private static BATCH_SIZE_LIMIT = 50;
    private static FLUSH_INTERVAL_MS = 5000;
    private static timer: NodeJS.Timeout | null = null;

    static log(payload: any) {
        this.telemetryBatch.push(payload);
        this.checkFlush();
    }

    static logVisit(payload: any) {
        this.visitorBatch.push(payload);
        this.checkFlush();
    }

    private static checkFlush() {
        if (this.telemetryBatch.length >= this.BATCH_SIZE_LIMIT || this.visitorBatch.length >= this.BATCH_SIZE_LIMIT) {
            this.flush();
        } else if (!this.timer) {
            this.timer = setTimeout(() => this.flush(), this.FLUSH_INTERVAL_MS);
        }
    }

    private static async flush() {
        const telemetryPayload = [...this.telemetryBatch];
        const visitorPayload = [...this.visitorBatch];
        
        this.telemetryBatch = [];
        this.visitorBatch = [];
        
        if (this.timer) {
            clearTimeout(this.timer);
            this.timer = null;
        }

        try {
            if (telemetryPayload.length > 0) {
                const { error } = await supabase.from('telemetry').insert(telemetryPayload);
                if (error) logger.error('[TelemetryService] Batch telemetry insert error:', error);
            }
            if (visitorPayload.length > 0) {
                const { error } = await supabase.from('site_visits').insert(visitorPayload);
                if (error) logger.error('[TelemetryService] Batch visits insert error:', error);
            }
        } catch (e: any) {
            logger.error('[TelemetryService] Exception during flush:', e.message);
        }
    }
}
