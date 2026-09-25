# Global Master Policies

Sentinel V2 applies **one policy per account** to every API key under that tenant on `POST /v2/evaluate`.

Configure it in the dashboard: **Sentinel V2 Global Master Policies** → `GET` / `POST /api/policy/global`.

There is **no dashboard DSL editor** today. Custom `rules` strings, ASN allow/block lists, and country lists are not shipped. The engine may retain a parser for future use; it is not a live product surface.

---

## Controls (what ships)

| Control | Field | Effect |
|---------|-------|--------|
| Engine mode | `mode` | Score thresholds: `PASSIVE`, `BALANCED`, `STRICT`, `DRACONIAN`, `HUMAN_ONLY` |
| VPN / Proxy | `vpn_action` | `allow` (score only), `challenge`, or `block` when VPN is detected |
| Datacenter IPs | `datacenter_action` | Same for hosting/cloud ranges |
| Force BWT | `force_bwt` | Challenge browsers without a trust token **before** mode math |
| Exempt server clients | `exempt_server_requests` | Skips Force BWT only (not VPN/DC or mode) |
| PoW difficulty | `difficulty_level` | `1`–`5` for `/v1/challenge/issue` when a valid tenant key is present |

### Evaluation order

1. Private IP → mode math only  
2. Collect signals (token, VPN cache, ASN matrix, velocity, verified bot / scanner)  
3. **Verified bot** → skip VPN/DC hard blocks and Force BWT; mode still applies  
4. Valid trust token → skip infrastructure hard blocks; mode still applies  
5. VPN / datacenter hard actions  
6. Force BWT (if enabled)  
7. Score + mode thresholds  

---

## Modes (thresholds)

Signal weights (sum, clamped ±100):

| Signal | Weight |
|--------|--------|
| `TOKEN_VALID` | +30 |
| `VERIFIED_BOT` | +50 |
| `RESIDENTIAL_IP` | +10 |
| `VPN_DETECTED` | −10 |
| `DATACENTER_IP` | −20 |
| `HIGH_VELOCITY` | −30 |
| `SCANNER_PATTERN` | −60 |

| Mode | ALLOW | CHALLENGE | else |
|------|-------|-----------|------|
| `PASSIVE` | score ≥ −20 | score ≥ −40 | `BLOCK` |
| `BALANCED` | score ≥ 10 | score ≥ −20 | `BLOCK` |
| `STRICT` | score ≥ 38 | score ≥ −10 | `BLOCK` |
| `DRACONIAN` | score ≥ 38 | score ≥ 25 | `BLOCK` |
| `HUMAN_ONLY` | residential + token, or `VERIFIED_BOT` | token only | `BLOCK` (scanner/velocity → `BLOCK`) |

---

## Example policy payload

What the dashboard saves today:

```json
{
  "mode": "BALANCED",
  "difficulty": 3,
  "vpn_action": "challenge",
  "datacenter_action": "block",
  "force_bwt": true,
  "exempt_server_requests": false
}
```

---

## Verified bots

V2 recognizes known-good crawler User-Agents (Googlebot, Bingbot, Applebot, and similar) and emits `VERIFIED_BOT` (+50). Those requests are not tagged as `SCANNER_PATTERN`, and they skip Force BWT / VPN / DC hard blocks. Mode thresholds still apply (`HUMAN_ONLY` explicitly allows `VERIFIED_BOT`).

---

## Roadmap (not available yet)

- Custom DSL rule strings in the dashboard  
- Per-tenant ASN / country allow and block lists  

Until those ship, do not document them as live features.
