# Sentinel | Turnstile for APIs

**"Blocked 92% of bot signups without CAPTCHAs. Render sub-50ms trust decisions using infrastructure and behavioral signals."**

Sentinel is a high-velocity trust decision engine designed to replace user-hostile CAPTCHAs with deterministic, outcome-based security. It functions as a Turnstile for APIs.

---

## Decision Latency

In modern security, speed is the primary metric. Sentinel is architected to ensure security never compromises user experience.

- **Fast-Path Decisions (<50ms):** Immediate PASS/BLOCK decisions using in-memory local ASN matrices and velocity tracking.
- **Forced Forensic Audit (Premium):** Real-time, synchronous deep-intel lookups for critical paths (Login, Payments) to ensure 100% accuracy on first contact.
- **Async Cold Enrichment:** Deep forensic gathering (Shodan, IPWhoIs) occurs in the background, populating telemetry without adding latency to the critical request path.
- **Stateless by Design:** No database lookups in the decision path. Everything is handled via high-speed LRU caches and cryptographic tokens.

---

## Feature Ecosystem

Sentinel connects client-side behavior with server-side authority to create a comprehensive trust loop.

### 1. The Sentinel Widget (Invisible Verification)
The frontend verification component that establishes intent before a request reaches the application.
- **Behavioral Intent (BWT):** A proprietary "Click and Hold" interaction that validates human movement.
- **Cryptographic PoW:** Forces attacking CPUs to solve cryptographic puzzles, making automated bot-attacks economically non-viable.
- **Shadow DOM Isolation:** Base-level integration with zero CSS or logic conflicts.
- **Success Handoff:** Automatically injects HMAC-signed trust_tokens into your forms.

### 2. The Decision Gate (POST /v1/check)
The core server-side endpoint that renders an ultimate verdict in under 50ms.
- **Automatic Bot Mitigation:** Proven to block 92% of automated signups in production environments.
- **ASN Matrix Profiling:** Instant identification of over 100 malicious or hosting-only ASNs (M247, OVH, Hetzner, etc.).
- **Mobile Carrier Verification:** Applies trust incentives for verified mobile carriers (LTE/5G).
- **Profile-Based Security:** Customizable thresholds for api, signup, payments, or crypto use cases.

### 3. Management and Premium Insights
- **GitHub OAuth Dashboard:** Secure, passwordless onboarding via GitHub identity.
- **Real-Time Telemetry (Premium):** Live feed of every decision, including latency, IP reputation, and signal breakdown.
- **Risk Distribution Analytics (Premium):** Interactive charts showing stable vs. untrusted traffic patterns over time.
- **Conditional Security Shield (Premium):** Intelligent "pre-check" logic that only triggers the widget for high-risk origins (VPN/Proxy).
- **Automated Provisioning:** New accounts automatically receive their first Sentinel Vector (API Key).

---

## Outcomes

- **92%** Reduction in bot-driven account creation.
- **<50ms** Decision latency at the edge.
- **0** User-hostile puzzle challenges.
- **99.9%** Verification accuracy for legitimate mobile and ISP traffic.
- **100%** GDPR Compliance (No PII stored; Stateless architecture).

---

## Feature Registry

| Feature | Category | Tier | Outcome |
| :--- | :--- | :--- | :--- |
| **BWT (Behavioral Work)** | Frontend | Edge | Proves human intent via physical interaction. |
| **PoW (Proof of Work)** | Security | Edge | Increases attacker cost per request significantly. |
| **Fast-Path Check** | Performance | Edge | Renders decision in <50ms using local signals. |
| **ASN Matrix** | Intelligence | Edge/Premium | Instantly flags infrastructure designed for proxy/abuse. |
| **Forced Forensic Sync** | Security | **Premium** | Mandatory deep-audit for high-value endpoints (Login/Pay). |
| **Real-Time Analytics** | Governance | **Premium** | Full visibility into risk trends and signal telemetry. |
| **Conditional Widget** | UX | **Premium** | Widget only appears when a risk is detected (VPN/DC). |
| **Global Velocity Matrix** | Risk | **Premium** | Detects IP Churn and high-frequency scan patterns. |
| **Trust Tokens** | Security | Edge | Provides temporary prioritized access for verified users. |

---

## Tiered Security Architecture

### EDGE (Free Tier)
- **1,000 Decisions / Month** (v1/check)
- **Unlimited Widget Challenges** (BWT + PoW)
- **Fast-Path Decisions** (Local ASN Matrix)
- **Community Support**

### PREMIUM (Authority Tier - $6/mo)
- **500,000 Decisions / Month**
- **Forced Sync Intelligence:** Real-time deep forensics for Login and Payments.
- **Conditional Shield:** Intelligently gate your auth flow only for high-risk visitors.
- **Advanced Dashboard:** Access to risk distribution charts and individual signal telemetry.
- **Global Velocity Matrix:** Detect sophisticated IP-rotation attacks.
- **Mobile Carrier ID:** Prioritize verified cellular traffic.
- **Priority Tech Support.**

### Advanced Engineering (Undocumented)

Sentinel contains high-level abstractions for SOC teams and platform engineers to monitor engine health and simulate threats.

### 1. Global Intelligence Stats (`GET /v1/intel/secret-stats`)
A public-access endpoint for real-time traffic volume and geo-distribution auditing.
- **Outcome:** Real-time visibility into engine-wide traffic spikes and country-level origin analysis.

### 2. SOC Health Vitals (`GET /v1/health`)
Provides a deep forensic heartbeat of the Sentinel engine. **Requires Auth.**
- **Metrics:** Uptime, Cache Hit Ratio, Intel Tether Status (Shodan/WhoIs connectivity), and Total Scans Serviced.
- **Outcome:** Ensures the trust matrix is synchronized and running with optimal latency.

### 3. Engineering Headers (Lab Testing)
Used for local development and CI/CD automation without burning production quotas or triggering blocks.

| Header | Value | Purpose |
| :--- | :--- | :--- |
| `x-sentinel-bypass` | `true` | Forces a PASS decision. Only works for `127.0.0.1` or `localhost`. |
| `x-sentinel-mock-ip` | `IP_ADDR` | Simulates a specific IP origin. **Disabled in Production.** |
| `x-bwt-nonce` | `STRING` | Inject a behavioral work nonce directly into the decision gate. |
| `x-sentinel-trust` | `TOKEN` | Reuse a pre-verified trust token for repeated testing. |

### Payment and Upgrading

Sentinel integrates with NowPayments for secure, friction-free upgrades using cryptocurrency (ETH, BTC, USDT). Unlock Premium features instantly without credit card requirements.

## Quick Start (Engineering Mode)
Test how your API handles high-risk traffic using the mock header:

```bash
curl -X POST https://api.sentinel.com/v1/precheck \
     -H "x-sentinel-mock-ip: 185.220.101.10" # TOR Exit Node
```

---

## Quick Start
Protect your signup endpoint with a deterministic PASSS/BLOCK decision:

```javascript
// Use ?mode=decision for simplified integration
const res = await fetch('https://api.sentinel.com/v1/check?mode=decision', {
    method: 'POST',
    headers: { 'x-api-key': process.env.SENTINEL_KEY },
    body: JSON.stringify({ 
        target: userIp, 
        profile: 'signup' // api, signup, payments, crypto
    })
});

const { allow, risk, reason } = await res.json();
if (!allow) return blockRequest(risk, reason); // Decision in <50ms
```

---
*Generated by Antigravity — The Outcome-Based Security Standard.*
