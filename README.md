# Sentinel

**API trust decisions for bots, proxies, and automated abuse.**

Sentinel scores a client IP (and optional trust token), then returns a verdict your app or edge can enforce: allow, challenge, or block. It is designed for signup, auth, payments, scraping surfaces, and agentic traffic — not for browser page CAPTCHAs.

**Production:** `https://sentinel.risksignal.name.ng`  
**Package:** [`api-turnstile`](https://www.npmjs.com/package/api-turnstile) (V1-oriented adapter; V2 adaptation still pending)

---

## Contents

1. [How it works](#how-it-works)
2. [Verdicts](#verdicts)
3. [Signals & scoring (V2)](#signals--scoring-v2)
4. [API surface](#api-surface)
5. [Global Master Policies (V2)](#global-master-policies-v2)
6. [Behavioral Work Tokens (BWT)](#behavioral-work-tokens-bwt)
7. [Authentication & quotas](#authentication--quotas)
8. [Integration patterns](#integration-patterns)
9. [Architecture](#architecture)
10. [Local development](#local-development)
11. [Environment variables](#environment-variables)
12. [Database](#database)
13. [Known gaps (accurate status)](#known-gaps-accurate-status)
14. [Docs & dashboard](#docs--dashboard)

---

## How it works

```
Client / Edge / SDK
        │
        ├─ GET  /v1/precheck              public risk probe
        ├─ POST /v1/check                 V1 evaluate (enrichment-heavy)
        ├─ POST /v2/evaluate              V2 evaluate (cache-first + tenant policy)
        └─ POST /v1/challenge/issue|verify   BWT → x-sentinel-trust
                │
         Express (this repo)
                │
    ┌───────────┼────────────┐
    ▼           ▼            ▼
 Supabase    Redis/LRU    External intel
 (keys,      (velocity,   (async / sync
  policies,   policy)      TrustCard)
  telemetry)
```

**Design rules**

- Decisions prefer memory (ASN matrix, velocity, cached VPN flags). Database is for keys, policies, and telemetry — not the hot path when Redis is warm.
- Fail-open at your edge: if Sentinel is unreachable, do not lock out legitimate users.
- V1 and V2 run in parallel. Existing `/v1/check` consumers are unchanged by V2.

---

## Verdicts

### V2 (`POST /v2/evaluate`)

| Verdict | Meaning | Typical action |
|---------|---------|----------------|
| `ALLOW` | Pass policy and score thresholds | Forward request |
| `CHALLENGE` | Ambiguous or policy requires proof | Serve widget / BWT, retry with `x-sentinel-trust` |
| `BLOCK` | Hard deny | `403` / drop at edge |

### V1 (`POST /v1/check`, `GET /v1/precheck`)

| Verdict | Meaning |
|---------|---------|
| `TRUSTED` | Clean enough for the requested profile |
| `UNSTABLE` | Ambiguous — challenge recommended |
| `UNTRUSTED` | High-risk infrastructure / signals |

V2 telemetry maps: `ALLOW` → `TRUSTED`, `CHALLENGE` → `CHALLENGE`, `BLOCK` → `UNTRUSTED`.

---

## Signals & scoring (V2)

Score is the sum of signal weights, clamped to `[-100, +100]`.

| Signal | Weight | Source |
|--------|--------|--------|
| `TOKEN_VALID` | +30 | Valid `x-sentinel-trust` HMAC |
| `RESIDENTIAL_IP` | +10 | Not flagged as datacenter (or private IP) |
| `VPN_DETECTED` | −10 | Async-cached VPN flag |
| `DATACENTER_IP` | −20 | In-memory ASN / hosting matrix |
| `HIGH_VELOCITY` | −30 | Velocity &gt; 15 in shared cache |
| `SCANNER_PATTERN` | −60 | Automation-like `User-Agent` |

`VERIFIED_BOT` (+50) is emitted on V2 for known-good crawler User-Agents (and cached ASN + crawler UA). Those requests skip Force BWT and VPN/DC hard blocks; mode still applies (`HUMAN_ONLY` allows them).

Mode thresholds (after hard policy steps) live in `PolicyEngine`:

| Mode | ALLOW if | CHALLENGE if | else |
|------|----------|--------------|------|
| `PASSIVE` | score ≥ −20 | score ≥ −40 | `BLOCK` |
| `BALANCED` (default) | score ≥ 10 | score ≥ −20 | `BLOCK` |
| `STRICT` | score ≥ 38 | score ≥ −10 | `BLOCK` |
| `DRACONIAN` | score ≥ 38 | score ≥ 25 | `BLOCK` |
| `HUMAN_ONLY` | residential **and** token | token only | `BLOCK` (also blocks scanner/velocity) |

---

## API surface

Base URL: `https://sentinel.risksignal.name.ng`  
**Paths are `/v1/...` and `/v2/...` — not `/api/v1/...`.**

### `GET /health`

Service liveness.

### `GET /v1/precheck`

Public. No API key. For “do I need a widget?” before an action.

- Forward client IP via `x-forwarded-for` (or use `?mock_ip=` in development).
- Response includes `required`, `verdict`, `score`, `target`.

### `POST /v1/check`

Authenticated + quota. Body: `{ "target": "<ip>", "profile": "api|signup|payments|crypto", ... }`.  
Supports decision-shaped responses and full trust intel depending on query/mode.

### `POST /v2/evaluate`

Authenticated + quota. Body:

```json
{
  "target": "203.0.113.10",
  "path": "/optional/route-label"
}
```

Optional header: `x-sentinel-trust: <token>`

Response shape:

```json
{
  "status": "success",
  "tenant": {
    "api_key": "VALID",
    "policy_engaged": "BALANCED"
  },
  "decision": {
    "verdict": "CHALLENGE",
    "score": -10,
    "signals": [],
    "latency_ms": 12,
    "action_required": "SOLVE_CAPTCHA"
  }
}
```

Use `target: "detect"` to take the IP from `x-forwarded-for` / connection.

### `POST /v1/challenge/issue` · `POST /v1/challenge/verify`

Soft-authenticated (widget-friendly). Issue a PoW challenge; verify solution; receive a trust token (`expires_in: 1800`).

### Dashboard / account (JWT)

| Method | Path | Purpose |
|--------|------|---------|
| GET/POST | `/api/keys`, `/api/keys/generate` | API keys |
| GET | `/api/analytics` | Usage / telemetry rollup |
| GET/POST | `/api/policy/global` | Global Master Policies |

### Payments

`POST /v1/pay/webhook` — NowPayments IPN.

---

## Global Master Policies (V2)

Configured in the dashboard under **Sentinel V2 Global Master Policies**, persisted in Supabase `user_policies` (one row per user), applied to **all** of that user’s API keys via `TenantService.getPolicy`.

### Evaluation order (authoritative)

On each `/v2/evaluate`:

1. Private / local IP → residential signal → mode math only (no VPN/DC/`force_bwt` hard steps).
2. Collect signals (token, cached VPN, ASN matrix, velocity, UA).
3. If token valid → infrastructure hard blocks are skipped; mode math still runs (with a large bypass weight).
4. Else apply **VPN action** / **datacenter action** (`block` returns immediately; `challenge` adds signals).
5. Else if **Force BWT** and no token (and not exempt server client) → immediate `CHALLENGE` (**mode is not consulted**).
6. Else score + **Engine mode** thresholds.

### Controls — contract vs reality

| Control | Dashboard | Persisted | Applied on evaluate | Exact meaning |
|---------|-----------|-----------|---------------------|---------------|
| Engine mode | Yes | `mode` | Yes* | Score thresholds above. \*Skipped when Force BWT returns early. |
| VPN / Proxy traffic | Yes | `vpn_action` | Yes | `allow` = no hard override (score still applies); `challenge` / `block` = hard policy. |
| Datacenter IPs | Yes | `datacenter_action` | Yes | Same as VPN. |
| Force BWT | Yes | `force_bwt` | Yes | Require trust token for non-exempt clients before mode math. |
| Exempt server API clients | Yes | `exempt_server_requests` | Yes | Only skips Force BWT; does **not** skip VPN/DC blocks or mode. |
| Cryptographic Demand (PoW scale) | Yes | `difficulty_level` | Yes | Used by `/v1/challenge/issue` when a valid tenant API key is present (clamped 1–5). |

### Label honesty (product contract)

These are the meanings operators should rely on — and what the product must match:

| UI label | Correct behavior |
|----------|------------------|
| PASSIVE — Monitor telemetry only | Soft thresholds; still challenges/blocks extreme scores (velocity/scanner). Not “never enforce.” |
| BALANCED | Clean residential can `ALLOW` without a token unless Force BWT is on. |
| STRICT / DRACONIAN | High bar; token usually required for `ALLOW`. |
| HUMANS ONLY | Residential + token for `ALLOW`; scanner/velocity → `BLOCK`. |
| VPN/DC “Allow (Auto-Score)” | No hard override; signal weights can still produce `CHALLENGE` under BALANCED. |
| Force BWT | Token required for browsers; when on, mode rarely matters until after a solve. |

### Defaults

| Source | Default |
|--------|---------|
| Schema / dashboard checkbox | `force_bwt = true` (UI default checked) |
| `TenantService.getDefaultPolicy()` | `{ mode: 'BALANCED', force_bwt: true, vpn_action/datacenter_action: 'allow', difficulty_level: 3, exempt_server_requests: false }` |
| Phase-2 `vpn_action` / `datacenter_action` columns | `'allow'` |
| Legacy `block_proxies` | `true` (used only if action columns are null) |

If no `user_policies` row exists, or policy load fails, evaluate uses the default above — not the dashboard checkbox defaults.

### Cache

Resolved policies are cached in Redis under `v2:policy:v2:<api_key>` (TTL 300s). Saving `/api/policy/global` deletes those keys for the user’s API keys when Redis is configured.

---

## Behavioral Work Tokens (BWT)

1. `POST /v1/challenge/issue` → nonce prefix + difficulty.
2. Widget (`/widget.js` from the Sentinel origin) solves SHA-256 PoW (user holds to demonstrate intent).
3. `POST /v1/challenge/verify` → base64 trust token.
4. Client retries protected calls with `x-sentinel-trust: <token>`.

Token format: `base64(ip : unix_ts : hmac_sha256(ip:ts, POW_SECRET)[0:16])`, TTL 30 minutes.

**Notes**

- Verification checks HMAC + expiry. Strict IP equality is intentionally relaxed (VPN egress rotation).
- Tokens are not tenant-scoped today (platform-wide human proof). Treat as intentional unless product policy changes.
- Load the widget from the Sentinel CDN/origin so it resolves the correct API base.

---

## Authentication & quotas

| Surface | Auth | Quota |
|---------|------|-------|
| `/v1/check`, `/v2/evaluate` | Bearer / `x-api-key` → `api_access` | Yes (`usage_count` / `max_usage`) |
| `/v1/challenge/*` | Soft auth + rate limits | No hard quota deduction |
| `/v1/precheck` | None | Public |
| `/api/policy/*`, `/api/keys/*` | Supabase Auth JWT | N/A |

Keys are created in the dashboard (`sl_…`). FREE vs PRO tiers differ in key count and `max_usage`.

---

## Integration patterns

### Edge (V2)

Call `/v2/evaluate` with your billing API key. Enforce `BLOCK` / `CHALLENGE` / `ALLOW`. Fail open on timeout.

### Origin gateway (precheck)

Use `/v1/precheck` when you only need a public risk probe (e.g. before showing a widget). Do not use site keys against `/v2/evaluate`.

### Node middleware

```bash
npm install api-turnstile
```

See the npm package for V1 middleware. V2 adaptation is still outstanding (`api-turnstile` TODO).

### Widget

```html
<div id="sentinel-widget" data-sitekey="sl_your_site_key"></div>
<script src="https://sentinel.risksignal.name.ng/widget.js" async defer></script>
```

Listen for `sentinelSuccess` on `document` for `event.detail.trust_token`.

---

## Architecture

| Layer | Implementation |
|-------|----------------|
| Runtime | Node.js, TypeScript → CommonJS |
| HTTP | Express 5 (`src/index.ts`) |
| Validation | Zod |
| DB | Supabase Postgres |
| Cache | `lru-cache` + optional Redis (`REDIS_URL`) |
| Logging | Winston + Morgan |
| Docs | VitePress → `/docs` |
| Marketing / dashboard | `landing-page/` static |

**Important modules**

| Path | Role |
|------|------|
| `src/services/intelService.ts` | V1 engine, PoW, trust tokens, TrustCard |
| `src/services/v2/IntelServiceV2.ts` | V2 orchestrator |
| `src/services/v2/PolicyEngine.ts` | Mode thresholds (+ optional future DSL parser) |
| `src/services/v2/TenantService.ts` | Policy resolve (Redis → Supabase) |
| `src/routes/policyRoutes.ts` | Global Master Policies API |
| `src/middleware/auth.ts` | API key + quota |
| `src/middleware/challengeAuth.ts` | Challenge soft auth |

---

## Local development

```bash
cp .env.example .env
# Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (required)

npm install
npm run dev          # nodemon src/index.ts  (default :3001)
npm run build && npm start

npm run docs:dev     # VitePress
npm run docs:build   # required for /docs via Express
npm run tail         # poll telemetry
```

Apply `V2_SCHEMA.sql` (and Phase-2 alters) in Supabase before using Global Master Policies.

---

## Environment variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `SUPABASE_URL` | Yes | Database / Auth |
| `SUPABASE_SERVICE_ROLE_KEY` | Yes | Server-side Supabase |
| `PORT` | No | Default `3001` |
| `NODE_ENV` | No | `development` / `production` |
| `POW_SECRET` | Recommended in prod | HMAC / PoW salt (dev fallback exists) |
| `REDIS_URL` | Recommended | Policy + velocity + async VPN cache |
| `RISKSIGNAL_API_KEY` / `RISKSIGNAL_API_URL` | No | Optional intel |
| `SENTINEL_C2_URL` | No | Threat matrix sync |
| `CLOUDFLARE_*` / `SENTINEL_WEBHOOK_URL` | No | Edge broadcast on hard blocks |
| `NOWPAYMENTS_IPN_SECRET` | No | Payment webhook |

---

## Database

### `api_access`

Billing API keys, `usage_count`, `max_usage`, `tier`, `user_id`.

### `user_policies`

One row per `user_id`. Columns used in production today:

- `mode`, `difficulty_level`, `force_bwt`
- `vpn_action`, `datacenter_action`, `exempt_server_requests`
- Legacy: `block_proxies`, `block_datacenters` (fallback only)

### `telemetry`

Batched decision logs for the dashboard.

### `site_visits`

Landing-page visit metrics.

---

## Known gaps (accurate status)

| ID | Gap | Status |
|----|-----|--------|
| **P0** | `TenantService` selected non-existent `allowed_asns` / `blocked_asns` → silent `BALANCED` fallback | **Fixed** — select only live columns; Redis cache key `v2:policy:v3:` |
| **P1** | PoW difficulty slider unused | **Fixed** — challenge issue loads tenant `difficulty_level` (1–5) |
| **P1** | Default policy omitted `force_bwt` | **Fixed** — defaults match schema/UI |
| **P2** | Mode / VPN labels overclaimed | **Fixed** — dashboard copy matches engine order |
| **P2** | Force BWT precedes mode | By design — documented in UI + README |
| **P2** | DSL `rules`, country lists, ASN allow/block | **Not shipped** — docs/landing no longer claim them as live; parser retained for later |
| **P2** | V2 `VERIFIED_BOT` | **Fixed** — crawler UA allowlist; skips scanner / Force BWT / VPN·DC hard blocks |
| **P3** | Docs `v1-vs-v2.md` `/api/...` paths | **Fixed** |
| **P3** | `api-turnstile` still V1-shaped | Open |
| — | Automated tests | `npm test` is a stub |

**Bar for Global Master Policies:** every control does what its label says; no dead saves; no silent fallbacks that contradict the dashboard.

---

## Docs & dashboard

| Surface | Location |
|---------|----------|
| Product site + dashboard | `landing-page/` → `/` |
| VitePress docs | `docs/` → `/docs` after `npm run docs:build` |
| Decision narrative | `engineflow.md` |
| Schema bootstrap | `V2_SCHEMA.sql` |

---

## License

Copyright © 2026 Sentinel Security. All rights reserved.
