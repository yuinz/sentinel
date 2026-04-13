# The Deterministic Trust Layer

Sentinel Engine is a high-velocity decision engine that renders sub-50ms trust decisions for your API traffic. It replaces user-hostile CAPTCHAs with infrastructure forensics and cryptographic Proof-of-Work — blocking automated attacks without ever interrupting a legitimate user.

> **Cloudflare Turnstile is for browsers. Sentinel is for APIs.**

::: info Outcome-Based Security
We measure success in blocked automation and reduced fraud, not traffic volume. Sentinel protects your bottom line by reducing infrastructure costs and preventing revenue loss from ghost traffic.
:::

---

## Core Architecture

Sentinel operates on a **Zero-Friction, Zero-Trust** philosophy using three distinct layers of defense:

### 1. Fast-Path Matrix (< 50ms)
Incoming requests are instantly checked against an in-memory matrix of known-bad hosting providers, proxy networks, and datacenter IP blocks. The majority of primitive bot traffic is blocked here without any external database lookup.

### 2. Behavioral Work Tokens (BWT)
When an IP is flagged as "Unstable" (ambiguous signals), Sentinel issues a cryptographic challenge. Legitimate clients solve it via the Sentinel Widget while their browser computes a SHA-256 Proof-of-Work in the background. Primitive scripts fail to produce a valid solution.

### 3. Infrastructure Forensics
For high-sensitivity endpoints, Sentinel performs real-time analysis: headless browser detection (Puppeteer, Playwright), VPN/Tor masking, automated runtime signatures, and request velocity anomalies.

---

## Verdict Reference

Every Sentinel response contains a `verdict` field. Here is what each value means and what action to take:

| Verdict | Meaning | Your Action |
|---------|---------|-------------|
| `TRUSTED` | Clean residential IP, no risk signals. | Allow the request. |
| `UNSTABLE` | Ambiguous signals (shared ISP, high velocity). | Serve the widget challenge. |
| `UNTRUSTED` | VPN, datacenter, known-bad infrastructure. | Hard block (403) or serve the widget depending on your policy. |

---

## The Verification Lifecycle

When your API decides a challenge is required, the flow is always the same three steps:

**1. Challenge Issuance** — Your backend calls `/v1/challenge/issue` (authenticated with your site key) to obtain a cryptographic nonce tied to the user's IP.

**2. Intent Demonstration** — The Sentinel Widget renders in the user's browser. The user clicks and holds for 2–4 seconds while the browser computes the SHA-256 Proof-of-Work.

**3. Token Issuance** — Your backend calls `/v1/challenge/verify`. If the nonce is valid, Sentinel returns a `trust_token`. Pass this as `x-sentinel-trust` on the retried request. The backend checks it and allows through.

---

## Public Pre-check Endpoint

Before rendering any widget, you should check whether a challenge is actually needed. Use the **public pre-check endpoint** — it requires no auth and is specifically designed for this purpose.

```
GET /v1/precheck
```

Forward the real client IP via `x-forwarded-for`. The response tells you whether to show the widget or proceed immediately:

```json
{
  "required": true,
  "verdict": "UNTRUSTED",
  "score": 5,
  "target": "104.21.0.1",
  "trace_id": "a1b2c3d4"
}
```

- `required: false` → clean IP, proceed with your action immediately.
- `required: true` → show the widget before allowing the action.

::: tip Testing
You can mock any IP for local development using the query parameter:
`GET /v1/precheck?mock_ip=104.21.0.1`
:::

---

## Frontend Integration

### Option A: The Visual Widget (Recommended)

Load the widget script **directly from the Sentinel CDN** — this is critical. The widget resolves its API base URL from its own `src`, so self-hosting it will break all challenge requests.

```html
<!-- 1. Place the container where you want the widget to appear -->
<div id="sentinel-widget" data-sitekey="sl_your_site_key_here"></div>

<!-- 2. Load the script from the Sentinel CDN (not self-hosted) -->
<script src="https://sentinel.risksignal.name.ng/widget.js" async defer></script>
```

::: warning Key format
Site keys always start with `sl_`. Do **not** use your billing API key (which starts with `sl_` but is longer) as the site key — they are different credentials. Get your site key from the Sentinel Dashboard.
:::

When the user completes the hold, the widget fires a `sentinelSuccess` event on `document`. Listen for it to get the trust token:

```javascript
document.addEventListener('sentinelSuccess', (event) => {
  const trustToken = event.detail.trust_token;

  // Retry your API call with the token attached
  await fetch('/api/your-endpoint', {
    method: 'POST',
    headers: {
      'x-sentinel-trust': trustToken,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ /* your payload */ }),
  });
});
```

If the widget is inside a `<form>`, the token is also automatically injected as a hidden `<input name="sentinel-token">` field — no extra code needed for traditional form submissions.

### SPA Integration Pattern (React / Vue / Svelte)

The most robust pattern for modern frameworks is the "Optimistic Action" approach. You assume the user's IP is trusted, attempt the secure action, and only unhide the widget if your backend issues a `401 Challenge Required`.

**1. Include the hidden widget container in your UI:**
```html
<div id="sentinel-widget-container" style="display: none;">
  <div id="sentinel-widget" data-sitekey="sl_your_site_key_here"></div>
</div>
```

**2. Implement the try/catch logic:**
```javascript
async function doAction(payload, token = null) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['x-sentinel-trust'] = token;

  const res = await fetch('/api/your-endpoint', {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  });

  // 1. The backend evaluates the IP. If it's unstable and lacks a token, it returns 401.
  if (res.status === 401) {
    const data = await res.json();
    if (data.action_required === 'solve_bwt') {
      
      // 2. Unhide the widget container to force the user to verify
      document.getElementById('sentinel-widget-container').style.display = 'block';
      
      // 3. Wait for the user to hold the button
      document.addEventListener('sentinelSuccess', async (event) => {
        // Hide the widget again
        document.getElementById('sentinel-widget-container').style.display = 'none';
        
        // Retry the exact same action, this time attaching the cryptographically verified token
        await doAction(payload, event.detail.trust_token);
      }, { once: true });
      
      return;
    }
  }

  // Handle success...
}
```

---

## Backend Integration

### Supabase Edge Functions (Deno)

Call `/v1/precheck` and forward the real client IP. Do **not** call `/v2/evaluate` for gateway enforcement — that endpoint requires a billing API key and will return 403 for site keys, silently passing all traffic through.

```typescript
async function sentinelGate(req: Request): Promise<Response | null> {
  const ip =
    req.headers.get('cf-connecting-ip') ||
    (req.headers.get('x-forwarded-for') || '').split(',')[0].trim() ||
    '127.0.0.1';

  const trustToken = req.headers.get('x-sentinel-trust');

  // If caller already has a valid trust token, let them through immediately.
  if (trustToken) return null;

  const res = await fetch('https://sentinel.risksignal.name.ng/v1/precheck', {
    method: 'GET',
    headers: { 'x-forwarded-for': ip },
  });

  if (!res.ok) return null; // Fail open — never block on Sentinel downtime

  const trust = await res.json();

  if (trust.required) {
    if (trust.verdict === 'UNTRUSTED') {
      return new Response(
        JSON.stringify({ error: 'Infrastructure Denied.' }),
        { status: 403, headers: { 'Content-Type': 'application/json' } }
      );
    }
    // UNSTABLE — issue a challenge
    return new Response(
      JSON.stringify({ action_required: 'solve_bwt', error: 'Challenge Required' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  return null; // Trusted — let the request proceed
}

// Usage in your serve handler:
serve(async (req) => {
  const block = await sentinelGate(req);
  if (block) return block;

  // ... your actual handler logic
});
```

### Node.js / Express

Use the `api-turnstile` npm package. Install it and import it as follows:

```bash
npm install api-turnstile
```

```javascript
import { sentinel } from 'api-turnstile';
import express from 'express';

const app = express();

app.use('/api', sentinel({
  apiKey: process.env.SENTINEL_API_KEY, // your sl_... API key
  onBlock: (req, res) => {
    res.status(403).json({ error: 'Infrastructure blocked' });
  },
  onChallenge: (req, res) => {
    res.status(401).json({ action_required: 'solve_bwt', error: 'Challenge Required' });
  },
}));
```

The middleware automatically reads `x-sentinel-trust` from incoming headers and bypasses the challenge flow if a valid token is present.

### Cloudflare Workers / Vercel Edge

For edge deployments where you need sub-10ms performance and zero dependencies, you can natively verify traffic using the V2 Evaluate endpoint. The engine evaluates both the IP and the Token sequentially, rendering a verdict instantly.

```javascript
export default {
  async fetch(request, env, ctx) {
    const ip =
      request.headers.get('cf-connecting-ip') ||
      request.headers.get('x-forwarded-for') ||
      '0.0.0.0';

    const trustToken = request.headers.get('x-sentinel-trust');

    // 1. Send the metadata AND the Token directly to the V2 Engine
    try {
      const edgeQuery = await fetch('https://sentinel.risksignal.name.ng/v2/evaluate', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${env.SENTINEL_API_KEY}`,
            'Content-Type': 'application/json',
            ...(trustToken ? { 'x-sentinel-trust': trustToken } : {})
        },
        body: JSON.stringify({ target: ip })
      });

      if (edgeQuery.ok) {
        const { decision } = await edgeQuery.json();
        
        // 2. Enforce the verdict natively at the edge
        if (decision.verdict === 'BLOCK') {
            return new Response('Infrastructure Denied', { status: 403 });
        }
        if (decision.verdict === 'CHALLENGE') {
            return new Response(JSON.stringify({ action_required: 'solve_bwt' }), { 
                status: 401, 
                headers: { 'Content-Type': 'application/json' } 
            });
        }
      }
    } catch(e) {
      // Sentinel timeout — gracefully fallback to origin
    }

    // 3. Trusted or allowed via valid cryptographic token — pass to your origin
    return fetch(request);
  },
};
```

This guarantees that user tokens are crypto-verified natively by the Sentinel V2 API, preventing any client-side spoofing, without needing to import any V1 legacy libraries.

::: tip Fail-Open Design
Every integration above follows the **fail-open** principle: if Sentinel is unreachable (timeout, network error), the gate returns `null` / proceeds normally. This ensures your service stays online even if Sentinel has an outage. Never block legitimate traffic because of a dependency failure.
:::

---

## Trust Token Reference

A trust token is a **base64-encoded HMAC string** issued by `/v1/challenge/verify` after a successful widget solve. It is:

- **IP-bound** — tied to the exact IP that solved the challenge.
- **Time-limited** — expires 30 minutes after issuance (`expires_in: 1800`).
- **Header-delivered** — send it as `x-sentinel-trust: <token>` on subsequent requests.

Pass it through as-is. You do not need to decode or validate it on your end — Sentinel's backend verifies the HMAC on every evaluation.
