"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolicyEngine = void 0;
class PolicyEngine {
    /**
     * Determines the final verdict based purely on the calculated score,
     * mapped against the tenant's exact policy mode.
     * KISS Rule Enforced: No complex nested "if/else" logic here.
     */
    static decideVerdict(score, policy, signals) {
        // 1. Execute Tenant DSL Rules (Overrides math entirely)
        const dslOverride = this.evaluateRules(policy.rules || [], signals);
        if (dslOverride)
            return dslOverride;
        // 2. Fallback to Mathematical Score Thresholds
        switch (policy.mode) {
            case 'PASSIVE':
                // Monitor only — very forgiving, almost nothing gets blocked
                if (score >= 10)
                    return 'ALLOW';
                if (score >= -40)
                    return 'CHALLENGE';
                return 'BLOCK';
            case 'STRICT':
                // Stricter than BALANCED — requires clear trust signals to pass
                if (score >= 50)
                    return 'ALLOW';
                if (score >= 10)
                    return 'CHALLENGE';
                return 'BLOCK';
            case 'DRACONIAN':
                // Maximum lockdown — only explicitly verified traffic passes
                if (score >= 70)
                    return 'ALLOW';
                if (score >= 30)
                    return 'CHALLENGE';
                return 'BLOCK';
            case 'BALANCED':
            default:
                // Standard default. Residential IP (+10) + Token (+30) = 40 → ALLOW
                if (score >= 30)
                    return 'ALLOW';
                if (score >= 0)
                    return 'CHALLENGE';
                return 'BLOCK';
        }
    }
    /**
     * Parses and evaluates a domain-specific language (DSL) for custom rules.
     * Example syntax: "IF signal == 'VERIFIED_BOT' THEN ALLOW"
     */
    static evaluateRules(rules, signals) {
        for (const rule of rules) {
            // Very fast Regex evaluation for the DSL syntax
            const match = rule.match(/IF\s+signal\s*==\s*['"]([A-Z_]+)['"]\s+THEN\s+(ALLOW|CHALLENGE|BLOCK)/i);
            if (match) {
                const targetSignal = match[1];
                const action = match[2].toUpperCase();
                // If the user's traffic contains the signal mentioned in the rule, obey the rule immediately.
                if (signals.some(s => s.id === targetSignal)) {
                    return action;
                }
            }
        }
        return null;
    }
}
exports.PolicyEngine = PolicyEngine;
