# Sentinel V2 | The Deterministic Trust Layer for APIs
**todo: update api-turnstile to adapt to v2**

<div align="center">
  <img src="https://sentinel.risksignal.name.ng/sentinel-logo.png" alt="Sentinel Logo" width="120" />
  <h3>"Your APIs are being abused. You just don't see it yet."</h3>
  <p><b>Block 92% of automated attacks in <50ms without CAPTCHAs.</b></p>
  <p>
    <a href="https://sentinel.risksignal.name.ng"><img src="https://img.shields.io/badge/status-online-green?style=flat-square" alt="Status" /></a>
    <a href="https://www.npmjs.com/package/api-turnstile"><img src="https://img.shields.io/npm/v/api-turnstile?color=orange&style=flat-square" alt="npm package" /></a>
  </p>
</div>

---

**Sentinel V2** is a high-velocity, deterministic trust engine designed to secure modern APIs. It replaces probabilistic bot guessing and user-hostile CAPTCHAs with **Intent Cryptography** and deep infrastructure forensics, blocking 92% of automated threats in under 50ms while letting humans pass silently.

## 🚫 Problems Sentinel Stops
- **Signup & Auth Flooding**: Prevent fake account creation and form abuse.
- **Credential Stuffing**: Stop automated login attempts at the front door.
- **API Scraping**: Protect proprietary data from unauthorized crawlers.
- **AI Agent Governance**: Identify and throttle LLM agents vs. legitimate users.

## 💸 The Ghost Traffic Tax
Every bot request costs you money in AWS cycles, database queries, and bandwidth. Sentinel eliminates the "Ghost Traffic Tax" by identifying non-human infrastructure (AWS/Hetzner/DigitalOcean) in under 5ms and rejecting it at the edge.

## ⚡ Core Architecture
Sentinel builds a "Global Shield" using a decoupled intelligence model.

1.  **Fast-Path Decision Engine (<50ms)**: Real-time evaluation against structural ASN topology, carrier-level provenance, and behavioral entropy.
2.  **Intent Cryptography (BWT)**: A SHA-256 challenge mapped directly to physical DOM events, proving human intent through computational complexity.
3.  **V2 Policy DSL**: Run granular, dashboard-configurable security rules natively at the edge using our minimal, regex-compiled Domain Specific Language.
4.  **Global Edge Propagation**: Local signals are broadcast horizontally to every edge node globally in <2ms via a Redis-distributed backbone.

[Read the Decision & Propagation Flow (engineflow.md) →](./engineflow.md)

### 🌍 Edge-First Deployment
Sentinel can be deployed as an **Edge Guard** to kill bots before they ever reach your origin.
```typescript
// Cloudflare Worker Example
import { sentinelEdge } from 'api-turnstile';

const shield = sentinelEdge({ 
  apiKey: env.KEY, 
  cache: env.KV, 
  profile: 'agentic' 
});
```

---

## 🚀 Integration

### 1. The Official Client (`api-turnstile`)
The easiest way to consume Sentinel is via our official Node.js/Edge adapter.

```bash
npm install api-turnstile
```

```javascript
import { sentinel } from 'api-turnstile';

app.use(sentinel({
  apiKey: 'sz_...',
  protect: ['/auth/*', '/payments'],
  profile: 'strict'  // api | signup | payments | crypto
}));
```

[View the api-turnstile documentation →](https://www.npmjs.com/package/api-turnstile)

### 2. Direct API Access
For non-Node environments (Python, Go, PHP), query the Decision Gate directly.

**Endpoint**: `POST https://sentinel.risksignal.name.ng/v1/check`

**Request**:
```json
{
  "target": "1.2.3.4",
  "profile": "signup",
  "privacy_mode": "full"
}
```

**Response (Decision Mode)**:
```json
{
  "allow": false,
  "action": "block",
  "risk": "untrusted",
  "reason": "hosting_provider_detected",
  "confidence": 0.99,
  "latency_ms": 12
}
```

---

## 🛡️ Security Profiles

Custom-tuned logic for different parts of your application.

| Profile | Use Case | Tolerance | Key Signals |
| :--- | :--- | :--- | :--- |
| **`api`** | General API routes | High | Rate Limiting, Basic Rep Check |
| **`signup`** | Registration Forms | Medium | Disposable Email, VPN Check, ASN |
| **`payments`** | Checkout / Cards | Strict | Geo-Mismatch, Velocity, Residential Proxy |
| **`crypto`** | Web3 / Faucets | Zero-Trust | Wallet Cluster Analysis, Tor Nodes |

---

## 🧠 Advanced Features

### Behavioral Challenge API
Decoupled endpoints for building custom "Click-to-Verify" flows without the Sentinel Widget.

*   `POST /v1/challenge/issue`: Request a difficulty algorithm and salt.
*   `POST /v1/challenge/verify`: Submit the solved nonce for a `trust_token`.

### Intelligence & Telemetry
*   **Real-time Streaming**: Watch decisions occur live via the CLI (`sentinel tail`).
*   **Visitor Stats**: `GET /v1/intel/secret-stats` provides a breakdown of traffic origin by country.

### Developer Tools
*   **Mocking**: Send `x-sentinel-mock-ip: 1.2.3.4` in development to test responses.
*   **Bypass**: Use `x-sentinel-bypass: true` (localhost only) to skip checks during testing.

---

## 📊 Dashboard & Analytics

Manage your security posture via the [Sentinel Dashboard](https://sentinel.risksignal.name.ng).

*   **Live Metrics**: See total signals, blocked threats, and capital saved.
*   **API Keys**: Provision and revoke access keys.
*   **Usage Quotas**: Track your monthly decision volume.

---

## 🌍 Ecosystem Status

| Component | Status | Version |
| :--- | :--- | :--- |
| **Decision Engine (V2)** | 🟢 Online | v2.0.0-PROD |
| **Telemetry System** | 🟢 Online | Stable |
| **Edge Network** | 🟢 Online | Global (Redis Matrix) |
| **SDK Adapter** | 🟢 Online | v1.0.1 |

---

## License

Copyright © 2026 Sentinel Security. All rights reserved.
Generated by Antigravity.
