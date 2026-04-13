import { V2PolicyConfig, Verdict, TrustSignal } from '../../types/v2';

export class PolicyEngine {
    /**
     * Determines the final verdict based purely on the calculated score,
     * mapped against the tenant's exact policy mode.
     * KISS Rule Enforced: No complex nested "if/else" logic here.
     *
     * Signal weights (source of truth in TrustCalculator.ts):
     *   RESIDENTIAL_IP:  +10
     *   TOKEN_VALID:     +30
     *   VPN_DETECTED:    -10
     *   DATACENTER_IP:   -20
     *   HIGH_VELOCITY:   -30
     *   SCANNER_PATTERN: -60
     */
    static decideVerdict(score: number, policy: V2PolicyConfig, signals: TrustSignal[]): Verdict {
        
        // 1. Execute Tenant DSL Rules (Overrides math entirely)
        const dslOverride = this.evaluateRules(policy.rules || [], signals);
        if (dslOverride) return dslOverride;

        // 2. Fallback to Mathematical Score Thresholds
        switch (policy.mode) {
            case 'PASSIVE':
                // Near-permissive. Only hard blocks for explicitly malicious IPs.
                // Clean residential (+10)  → ALLOW
                // VPN (-10)               → CHALLENGE
                // High velocity (-30)      → CHALLENGE
                // Scanner (-60)           → BLOCK
                if (score >= 10) return 'ALLOW';
                if (score >= -40) return 'CHALLENGE';
                return 'BLOCK';

            case 'STRICT':
                // Strict enforcement. Residential + Token (40) required to ALLOW.
                // VPN alone (-10)         → CHALLENGE (let them try to verify)
                // Datacenter alone (-20)  → BLOCK
                // VPN + Token (20)        → CHALLENGE (token alone not enough in STRICT)
                if (score >= 38) return 'ALLOW';
                if (score >= -10) return 'CHALLENGE';
                return 'BLOCK';

            case 'DRACONIAN':
                // Maximum lockdown. Only residential + token passes (score 40 ≥ 38).
                // VPN + token (20)        → BLOCK
                // Residential alone (10)  → BLOCK (token mandatory)
                if (score >= 38) return 'ALLOW';
                if (score >= 25) return 'CHALLENGE';
                return 'BLOCK';

            case 'HUMAN_ONLY':
                // Absolute Zero-Trust: score doesn't matter, signals do.
                // Must NOT be an automated script or velocity abuser
                if (signals.some(s => s.id === 'SCANNER_PATTERN' || s.id === 'HIGH_VELOCITY')) {
                    return 'BLOCK';
                }
                // Must be residential AND have a valid token
                const hasResidential = signals.some(s => s.id === 'RESIDENTIAL_IP');
                const hasToken = signals.some(s => s.id === 'TOKEN_VALID');
                if (hasResidential && hasToken) return 'ALLOW';
                if (hasToken) return 'CHALLENGE'; // Token present but bad network
                return 'BLOCK'; // No token, no entry

            case 'BALANCED':
            default:
                // Standard balanced policy aligned with actual signal weights.
                // Clean residential (+10) → ALLOW  (no token needed for clean traffic)
                // VPN (-10)              → CHALLENGE
                // Datacenter (-20)       → CHALLENGE
                // High velocity (-30)    → BLOCK
                // Scanner (-60)          → BLOCK
                if (score >= 10) return 'ALLOW';
                if (score >= -20) return 'CHALLENGE';
                return 'BLOCK';
        }
    }

    /**
     * Parses and evaluates a domain-specific language (DSL) for custom rules.
     * Example syntax: "IF signal == 'VERIFIED_BOT' THEN ALLOW"
     */
    private static evaluateRules(rules: string[], signals: TrustSignal[]): Verdict | null {
        for (const rule of rules) {
            const match = rule.match(/IF\s+signal\s*==\s*['"]([A-Z_]+)['"]\s+THEN\s+(ALLOW|CHALLENGE|BLOCK)/i);
            if (match) {
                const targetSignal = match[1];
                const action = match[2].toUpperCase() as Verdict;
                if (signals.some(s => s.id === targetSignal)) {
                    return action;
                }
            }
        }
        return null;
    }
}
