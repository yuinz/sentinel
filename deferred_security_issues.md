# Sentinel Engine — Deferred Security Issues

> [!CAUTION]
> These issues are **live in production** right now. They cannot be patched without a staged migration because fixing them naively would break every existing V1 integration and widget embed globally.

---

## Issue 1: Trust Tokens Are Not Tenant-Scoped

### Root Cause
[generateTrustToken](file:///c:/Users/shiver/Desktop/f/sentinel-engine/src/services/intelService.ts#L433-L439) creates tokens in the format:

```
base64( ip : timestamp : hmac(ip:timestamp, POW_SECRET) )
```

The token contains **no tenant API key or user_id**. This means a token issued for IP `1.2.3.4` is valid across every tenant on the platform.

### Blast Radius
- A bot operator can solve a single BWT challenge against the **public** `/v1/challenge/issue` endpoint, receive a valid Trust Token, and then replay that token against **any** tenant's protected endpoint.
- The V2 engine's [TOKEN_VALID signal](file:///c:/Users/shiver/Desktop/f/sentinel-engine/src/services/v2/IntelServiceV2.ts#L40-L46) grants `+30` trust weight when this token passes `verifyTrustToken()`. That's enough to flip a CHALLENGE into an ALLOW on BALANCED mode.

### Safe Migration Plan

**Phase 1 — Issue new format (no breaking change):**
Modify `generateTrustToken()` to include the tenant's API key hash in the payload:
```
base64( ip : apiKeyHash : timestamp : hmac(ip:apiKeyHash:timestamp, POW_SECRET) )
```
Modify `verifyTrustToken()` to accept **both** old and new format tokens.

**Phase 2 — Deprecation window (30 days):**
Log a warning whenever an old-format token is accepted. Monitor telemetry for volume.

**Phase 3 — Hard cutover:**
Reject old-format tokens. All clients will have refreshed by this point via normal SDK behavior.

### Files to Modify
| File | Function | Change |
|---|---|---|
| [intelService.ts](file:///c:/Users/shiver/Desktop/f/sentinel-engine/src/services/intelService.ts#L433) | `generateTrustToken()` | Add apiKey hash to payload |
| [intelService.ts](file:///c:/Users/shiver/Desktop/f/sentinel-engine/src/services/intelService.ts) | `verifyTrustToken()` | Accept both formats during migration |
| [intelController.ts](file:///c:/Users/shiver/Desktop/f/sentinel-engine/src/controllers/intelController.ts#L222-L241) | `verifyChallenge()` | Pass apiKey context to token generator |
| [IntelServiceV2.ts](file:///c:/Users/shiver/Desktop/f/sentinel-engine/src/services/v2/IntelServiceV2.ts#L40) | `evaluate()` | Pass tenant key to `verifyTrustToken()` |

---

## Issue 2: Challenge Endpoints Have No Auth or Quota

### Root Cause
[intelRoutes.ts](file:///c:/Users/shiver/Desktop/f/sentinel-engine/src/routes/intelRoutes.ts#L13-L15):
```typescript
// Decoupled Challenge System (Public - No Auth Required)
router.post('/challenge/issue', issueChallenge);
router.post('/challenge/verify', verifyChallenge);
```

These routes are intentionally public because `widget.js` calls them directly from the browser. The widget sends `Authorization: Bearer <siteKey>` but the controller **ignores it** — it doesn't validate the key against `api_access`.

### Blast Radius
- **CPU drain:** Any bot can spam `/challenge/issue` to force the server to generate nonce prefixes and difficulty calculations endlessly. No rate limit. No quota deduction.
- **Token farming:** Combined with Issue 1, a bot can farm unlimited cross-tenant tokens at zero cost.
- **Invisible billing leak:** Legitimate widget usage on tenant sites consumes server resources but is never counted against any tenant's `usage_count`.

### Safe Migration Plan

> [!WARNING]
> Do NOT simply add `authMiddleware` to these routes. The `widget.js` sends the siteKey as a Bearer token, but `authMiddleware` does a full `api_access` lookup. If the demo key `sk_test_demo123456789` isn't in the database, the landing page widget will instantly break.

**Phase 1 — Soft auth (no breaking change):**
Create a new lightweight middleware `challengeAuthMiddleware` that:
1. Reads the `Authorization: Bearer` header
2. Validates the key exists in `api_access` (same as `authMiddleware`)
3. **But does NOT call `next()` with a 401 if the key is missing** — instead, applies a stricter rate limit (e.g. 5 req/min per IP for unauthenticated callers)
4. If key IS valid, deducts from the tenant's quota

**Phase 2 — Add IP-level rate limiting:**
Use `express-rate-limit` on `/challenge/*` with a hard cap of 10 requests per minute per source IP. This kills bot farming without breaking any legitimate widget integration.

**Phase 3 — Require auth (breaking change, major version):**
Once all widget embeds are confirmed to pass valid siteKeys, enforce hard 401 on missing/invalid keys.

### Files to Modify
| File | Change |
|---|---|
| [intelRoutes.ts](file:///c:/Users/shiver/Desktop/f/sentinel-engine/src/routes/intelRoutes.ts#L13-L15) | Add rate-limit + soft auth middleware |
| New file: `src/middleware/challengeAuth.ts` | Lightweight auth that rate-limits instead of blocking |
| `package.json` | Add `express-rate-limit` dependency |

---

## What Was Fixed Today

| Issue | File | Change | Risk |
|---|---|---|---|
| `sentinel.js` verify() required manual IP | [sentinel.js](file:///c:/Users/shiver/Desktop/f/sentinel-engine/landing-page/sentinel.js#L60) | Default `targetIp` to `'detect'` | ✅ Zero — backward compatible, existing calls with explicit IP still work |
| Dead `this.target = 'client-ip'` in widget | [widget.js](file:///c:/Users/shiver/Desktop/f/sentinel-engine/landing-page/widget.js#L9) | Removed unused property | ✅ Zero — property was never read by any code path |
| Docs showed `USER_IP` variable | [introduction.md](file:///c:/Users/shiver/Desktop/f/sentinel-engine/docs/introduction.md) | Updated to `window.Sentinel.verify()` (no args) | ✅ Zero — documentation only |
