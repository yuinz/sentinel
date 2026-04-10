# Custom Rule Engine (DSL)

Sentinel V2 completely shifts power from the Engine to the **Tenant**. 
Instead of hardcoding what is a "good bot" or a "bad proxy", Tenants upload standard **DSL (Domain Specific Language)** rules to their Supabase configuration, and V2 mathematically executes them.

## Syntax Format
All rules are evaluated via Regex in standard English format:
`IF signal == '[SIGNAL_ID]' THEN [VERDICT]`

### Example 1: E-Commerce Store (SEO Prioritized)
A public website wants to block scripts, but implicitly trust Googlebot.
```json
{
  "mode": "BALANCED",
  "rules": [
    "IF signal == 'VERIFIED_BOT' THEN ALLOW"
  ]
}
```

### Example 2: Private Banking API (Zero-Trust)
A private banking app wants absolutely zero bots tracing its system. 
```json
{
  "mode": "AGGRESSIVE",
  "rules": [
    "IF signal == 'VERIFIED_BOT' THEN BLOCK",
    "IF signal == 'DATACENTER_IP' THEN BLOCK"
  ]
}
```

## Available Signals
- `DATACENTER_IP`
- `RESIDENTIAL_IP`
- `VPN_DETECTED`
- `VERIFIED_BOT`
- `SCANNER_PATTERN`
- `TOKEN_VALID`
