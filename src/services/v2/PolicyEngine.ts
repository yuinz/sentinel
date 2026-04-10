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
        switch (policy.mode) {
            case 'AGGRESSIVE':
                // Strict: Requires a very high score to pass smoothly.
                if (score >= 50) return 'ALLOW';
                if (score >= 10) return 'CHALLENGE';
                return 'BLOCK'; // < 10 is blocked directly
                
            case 'RELAXED':
                // Forgiving: Allows almost anything unless clearly malevolent.
                if (score >= 10) return 'ALLOW';
                if (score >= -40) return 'CHALLENGE';
                return 'BLOCK'; // Only block explicitly terrible IPs (<-40)
                
            case 'BALANCED':
            default:
                // Standard default profile. 
                // A normal IP starts at 0 (Challenge). With a normal residential IP (+10) and Token (+30) -> 40 (ALLOW).
                if (score >= 30) return 'ALLOW';
                if (score >= 0) return 'CHALLENGE'; // 0 to 29
                return 'BLOCK'; // < 0
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
