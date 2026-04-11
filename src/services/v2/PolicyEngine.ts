import { V2PolicyConfig, Verdict, TrustSignal } from '../../types/v2';

export class PolicyEngine {
    /**
     * Determines the final verdict based purely on the calculated score,
     * mapped against the tenant's exact policy mode.
     * KISS Rule Enforced: No complex nested "if/else" logic here.
     */
    static decideVerdict(score: number, policy: V2PolicyConfig, signals: TrustSignal[]): Verdict {
        
        // 1. Execute Tenant DSL Rules (Overrides math entirely)
        const dslOverride = this.evaluateRules(policy.rules || [], signals);
        if (dslOverride) return dslOverride;

        // 2. Fallback to Mathematical Score Thresholds
        // Max achievable score for a verified browser user: RESIDENTIAL_IP(+10) + TOKEN_VALID(+30) = 40
        // All ALLOW thresholds are calibrated against this ceiling.
        switch (policy.mode) {
            case 'PASSIVE':
                // Near-permissive. Only hard blocks for explicitly malicious IPs.
                if (score >= 10) return 'ALLOW';
                if (score >= -40) return 'CHALLENGE';
                return 'BLOCK';

            case 'STRICT':
                // Requires residential IP + valid token to pass (score 40 ≥ 38).
                // VPN + token (score 20) gets CHALLENGE. Datacenter alone (score -20) gets BLOCK.
                if (score >= 38) return 'ALLOW';
                if (score >= 5) return 'CHALLENGE';
                return 'BLOCK';

            case 'DRACONIAN':
                // Maximum lockdown. Only residential + verified token passes (score 40 ≥ 38).
                // VPN + token (score 20) gets BLOCK. Residential without token (score 10) gets BLOCK.
                // Anything with both RESIDENTIAL_IP and TOKEN_VALID clears the threshold.
                if (score >= 38) return 'ALLOW';
                if (score >= 25) return 'CHALLENGE';
                return 'BLOCK';

            case 'HUMAN_ONLY':
                // Absolute Zero-Trust: score doesn't matter, signals do.
                // 1. Must NOT be an automated script or velocity abuser
                if (signals.some(s => s.id === 'SCANNER_PATTERN' || s.id === 'HIGH_VELOCITY')) {
                    return 'BLOCK';
                }
                // 2. Must be a residential IP and must have a valid token
                const hasResidential = signals.some(s => s.id === 'RESIDENTIAL_IP');
                const hasToken = signals.some(s => s.id === 'TOKEN_VALID');
                
                if (hasResidential && hasToken) return 'ALLOW';
                if (hasToken) return 'CHALLENGE'; // Has token but bad network (e.g., VPN)
                return 'BLOCK'; // No token, no entry

            case 'BALANCED':
            default:
                // Standard. Residential IP (+10) + Token (+30) = 40 → ALLOW.
                if (score >= 30) return 'ALLOW';
                if (score >= 0) return 'CHALLENGE';
                return 'BLOCK';
        }
    }

    /**
     * Parses and evaluates a domain-specific language (DSL) for custom rules.
     * Example syntax: "IF signal == 'VERIFIED_BOT' THEN ALLOW"
     */
    private static evaluateRules(rules: string[], signals: TrustSignal[]): Verdict | null {
        for (const rule of rules) {
            // Very fast Regex evaluation for the DSL syntax
            const match = rule.match(/IF\s+signal\s*==\s*['"]([A-Z_]+)['"]\s+THEN\s+(ALLOW|CHALLENGE|BLOCK)/i);
            if (match) {
                const targetSignal = match[1];
                const action = match[2].toUpperCase() as Verdict;
                
                // If the user's traffic contains the signal mentioned in the rule, obey the rule immediately.
                if (signals.some(s => s.id === targetSignal)) {
                    return action;
                }
            }
        }
        return null;
    }
}
