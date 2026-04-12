# The Deterministic Trust Layer

Sentinel Engine represents a paradigm shift in threat protection. It balances ruthless security against automated vectors alongside an entirely frictionless experience for legitimate human users.

Cloudflare Turnstile is for browsers. **Sentinel is for APIs.**

Sentinel is a high-velocity decision engine engineered to render sub-50ms trust decisions for your API traffic at the network edge. It replaces user-hostile CAPTCHAs with infrastructure forensics and cryptographic Proof-of-Work, blocking automated attacks without ever interrupting a legitimate user.

::: info Outcome-Based Security
We measure success in blocked automation and reduced fraud, not just traffic volume. Sentinel is built to protect your bottom line by reducing infrastructure costs and preventing revenue loss from ghost traffic.
:::

## Core Architecture

Sentinel operates on a Zero-Friction, Zero-Trust philosophy using three distinct layers of defense:

### 1. Fast-Path Matrix (< 50ms latency)
Incoming API requests are instantly vetted against a globally distributed in-memory matrix of over 100 known-bad hosting providers, proxy networks, and datacenter IP blocks. This handles the majority of primitive bot traffic instantly, returning a `BLOCK` verdict without external database lookups.

### 2. Behavioral Work Tokens (BWT)
When an IP is identified as "Unstable" (suspicious signals found or ambiguous infrastructure), Sentinel issues a cryptographic challenge. Legitimate clients solve this in milliseconds via the background SDK engine, while primitive scripts and automated tools fail to generate a valid solution. We do not use visual puzzle grids.

### 3. Infrastructure Forensics
For high-sensitivity endpoints, Sentinel performs real-time forensic signatures on the requested environment. We detect headless browsers (Puppeteer, Playwright), automated runtimes, and masking attempts (VPN/Tor) with high confidence.

---

## Agentic Security & AI Governance

::: warning 2026 META // AI AGENT PROTECTION
The web is no longer just for humans. AI Agents (AutoGPT, ChatGPT Browse, Perplexity) consume your resources without buying subscriptions. Sentinel is the first engine built specifically to govern the **Agentic Web**.
:::

Traditional "Human-only" filters are too binary. Sentinel allows you to configure your tenant policy to categorize traffic into three tiers:
- **Verified Human**: Full unconditional access to high-compute resources.
- **Verified Agent**: Allowed via configuration for limited access (text-only endpoints, API interfaces).
- **Malicious Bot**: Hard rejection via structural IP intelligence.

---

## The Verification Lifecycle

Implementing Sentinel's behavioral gate on the frontend follows a deterministic three-stage lifecycle.

### Phase 1: Challenge Issuance
Your API returns a `CHALLENGE` verdict. The client frontend requests a new cryptographic challenge from the Sentinel infrastructure, unique to the user's IP and session.

### Phase 2: Intent Demonstration
The user demonstrates "Proof of Intent" (via the Sentinel SDK Widget) while their browser computes a complex SHA-256 solution in the background.

### Phase 3: Verification & Token
The client submits the solved nonce. If valid, Sentinel issues a **Trust Token**. This token serves as a cryptographic "passport" that bypasses the engine on subsequent requests.

---

## Frontend Integration 

When your API returns a `CHALLENGE` verdict, your frontend must resolve it. We provide two distinct ways to handle this depending on your UX requirements.

### Option A: The Visual Widget (Recommended)
Instead of forcing users to identify crosswalks, Sentinel provides a beautiful, interactive "Click and hold to verify" overlay. Place the empty container where you want the widget to render, and load the script.

> **For SPAs (React, Vue, Vite):** Keep your primary submit button visible initially. If your API returns a `401 CHALLENGE` or `403 FORBIDDEN` due to a Trust mismatch, hide your submit button and render the `<div id="sentinel-widget">` dynamically in its place. Once the user solves it, listen for the `sentinelSuccess` event and automatically retry your API call.

```html
<!-- 1. The container -->
<div id="sentinel-widget" data-sitekey="sz_live_your_key_here"></div>

<!-- 2. The script -->
<script src="https://sentinel.risksignal.name.ng/widget.js" async defer></script>
```
When the user holds the button, the widget silently solves the cryptographic BWT and injects a hidden `<input name="sentinel-token">` field into your parent form automatically.

### Modern SPAs (React, Vue)

If you are not using a traditional `<form>` submission, you can capture the token programmatically by listening to the global `sentinelSuccess` event fired by the Document object:

```javascript
document.addEventListener('sentinelSuccess', (e) => {
    // The Trust Token JWT is delivered directly in the event payload
    const trustToken = e.detail.trust_token;
    
    // Pass this token in the headers of your API calls
    // Headers: { 'x-sentinel-trust': trustToken }
});
```

---

### Option B: Zero-UI Headless SDK

If you are protecting background REST operations or multi-step API flows, you can solve the challenge entirely invisibly using our background SDK.

```html
<script src="https://sentinel.risksignal.name.ng/sentinel.js"></script>
```

Catch the 401/403 failure in your fetch interceptor and let the SDK handle the rest:

```javascript
// Initialize the Headless SDK with your tenant key
window.Sentinel.init('sl_live_your_key_here');

const res = await fetch('/api/checkout', { method: 'POST' });

if (res.status === 401) {
    // 1. Solve the BWT in the background (IP auto-detected by the backend)
    const verification = await window.Sentinel.verify();
    
    if (verification.success) {
        // 2. Retry the original request!
        const headers = window.Sentinel.getAuthHeaders();
        const retryRes = await fetch('/api/checkout', { 
            method: 'POST', 
            headers: { ...headers } // Auto-injects 'x-sentinel-trust'
        });
    }
}
```

---

## Global Framework Integration

Sentinel provides first-class support for standard Node.js applications, as well as zero-latency Edge computing runtimes. The Engine naturally delegates validation to the API key associated with your Tenant Dashboard.

### 1. Node.js / Express Middleware

For traditional servers, use the `api-turnstile` package. It automatically intercepts requests, validates Trust Tokens, and restricts access based on your dashboard rules.

```bash
npm install api-turnstile
```

```javascript
import { sentinel } from 'api-turnstile';
import express from 'express';

const app = express();

app.use(sentinel({
  apiKey: process.env.SENTINEL_TENANT_KEY,
  protect: ['/api/auth/*', '/v1/payments'],
  verifyToken: true, // Auto-validates x-sentinel-trust headers from the frontend widget
  onBlock: (req, res, decision) => {
    // Optionally override default 403 response
    return res.status(403).json({ error: "Infrastructure blocked" });
  }
}));
```

### 2. Edge Adapters (Cloudflare Workers / Vercel Edge)

For high-traffic applications, Sentinel offers a specialized **Edge Adapter** that moves enforcement natively to the CDN layer. This delegates decision latency to under 5ms using KV caches.

```bash
npm install sentinel-sdk
```

```javascript
import { SentinelEdge } from 'sentinel-sdk';

export default {
  async fetch(request, env, ctx) {
    const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for');
    const token = request.headers.get('x-sentinel-trust');

    const trust = await SentinelEdge.evaluate(ip, {
      apiKey: env.SENTINEL_TENANT_KEY,
      trustToken: token,
      userAgent: request.headers.get('user-agent'),
      cache: env.SENTINEL_KV // Cloudflare KV for sub-5ms caching
    });

    if (trust.verdict === 'BLOCK') {
      return new Response('Infrastructure Denied', { status: 403 });
    }
    
    if (trust.verdict === 'CHALLENGE') {
      return new Response(JSON.stringify({ action_required: 'solve_bwt' }), { status: 401 });
    }

    // ALLOWED -> Pass to Origin
    return await fetch(request);
  }
};
```

By connecting your `api_key` to the Engine, your routing logic automatically enforces all security rules engineered in your Sentinel Dashboard (VPN Drop, Datacenter Blocks, Human Only execution, etc).
