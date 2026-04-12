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

## Frontend Interaction SDK

When your API routes return a `CHALLENGE` verdict, your frontend must seamlessly invoke the Sentinel JS SDK to resolve it.

::: info Zero-UI Cryptography
Unlike CAPTCHAs, the Sentinel SDK operates entirely in the background. It silently fetches the challenge, computes the Proof-of-Work locally using WebCrypto, and generates a verified Trust Token.
:::

### 1. Installation
Include the Sentinel client script on your page.

```html
<!-- Add to your head or before body close -->
<script src="https://sentinel.risksignal.name.ng/sentinel.js"></script>
```

### 2. Handling Verification
If your API returns a 401 or 403 due to an unresolved challenge, invoke the engine to automatically clear the restriction before retrying.

```javascript
// 1. API Call gets Challenged/Blocked
const res = await fetch('/api/checkout', { method: 'POST' });

if (res.status === 401) {
    // 2. Automatically solve the Behavioral Work Token (BWT)
    const verification = await window.Sentinel.verify(USER_IP);
    
    if (verification.success) {
        // 3. Retry the request! SDK auto-saves Trust Token to localStorage
        const headers = window.Sentinel.getAuthHeaders();
        const retryRes = await fetch('/api/checkout', { 
            method: 'POST', 
            headers: { ...headers } // Injects x-sentinel-trust natively
        });
    }
}
```

---

## Global Framework Integration

Sentinel provides first-class support for Edge computing and Node.js frameworks. The V2 Engine delegates border control directly to the tenant's API key.

### Configuration

Drop this into any Express or Next.js edge middleware.

```javascript
import { SentinelEdge } from 'sentinel-sdk';

export async function middleware(req) {
  const ip = req.headers.get('x-forwarded-for') || req.ip;
  const token = req.headers.get('x-sentinel-trust');

  const trust = await SentinelEdge.evaluate(ip, {
    apiKey: process.env.SENTINEL_TENANT_KEY,
    trustToken: token,
    userAgent: req.headers.get('user-agent')
  });

  // Strict enforcement
  if (trust.verdict === 'BLOCK') {
    return new Response(JSON.stringify({ error: 'Infrastructure blocked' }), { status: 403 });
  }

  if (trust.verdict === 'CHALLENGE') {
    return new Response(JSON.stringify({ action_required: 'solve_bwt' }), { status: 401 });
  }

  // ALLOWED -> Proceed
}
```

By connecting your API key to the Engine, your routing logic perfectly inherits all rules engineered in your Sentinel Dashboard (VPN actions, Datacenter restrictions, and Human Only modes).
