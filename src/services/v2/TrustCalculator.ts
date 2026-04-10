import { TrustSignal } from '../../types/v2';

export class TrustCalculator {
    /**
     * Calculates the final trust score based on provided signals.
     * Employs pure mathematics - no side effects, no database calls.
     * Score range is strictly clamped between -100 and +100.
     */
    static calculateScore(signals: TrustSignal[]): number {
        let score = 0;
        
        for (const signal of signals) {
            score += signal.weight;
        }

        // Clamp between -100 and +100
        return Math.max(-100, Math.min(100, score));
    }

    /**
     * Single source of truth for standard signal weights.
     * Centralizing this prevents "magic numbers" scattered across the codebase.
     */
    static readonly WEIGHTS = {
        TOKEN_VALID: 30,
        VERIFIED_BOT: 50,
        RESIDENTIAL_IP: 10,
        VPN_DETECTED: -10,
        DATACENTER_IP: -20,
        HIGH_VELOCITY: -30,
        SCANNER_PATTERN: -60
    } as const;
}
