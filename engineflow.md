# Sentinel Decision & Propagation Flow

This document outlines how Sentinel observes threats and propagates decisions globally, maintaining sub-50ms latency while ensuring comprehensive security.

## 1. The Observation: How Sentinel "Sees" a Threat
Sentinel uses a multi-layered approach to identify bad actors without relying on slow database lookups during the critical path.

*   **Layer 1: Static Infrastructure Forensics (ASN Matrix)**
    *   Sentinel maintains an in-memory matrix of known datacenter ranges (AWS, DigitalOcean, GCP, etc.).
    *   **Latency**: < 1ms.
    *   **Outcome**: Instant identification of proxy/bot infrastructure.

*   **Layer 2: Local Velocity Tracking (Short-Term Memory)**
    *   Uses a high-speed in-memory LRU cache to track request frequency per IP.
    *   **Outcome**: Detects high-velocity spikes and brute-force attempts in real-time.

*   **Layer 3: Behavioral Analysis (Cryptographic Proof-of-Work)**
    *   Issues "Behavioral Work Tokens" (BWT) to suspicious IPs.
    *   **Outcome**: Forces automated tools to solve expensive cryptographic puzzles, while humans pass through invisibly.

## 2. Decision Storage & Telemetry
While decisions are made in RAM, they are persisted asynchronously for auditing and global intelligence.

*   **Asynchronous Commit**: After a decision is rendered to the client, the result is sent to the `telemetry` table in Supabase.
*   **No Blocking**: The decision endpoint NEVER waits for the database. This is why Sentinel remains the fastest decision engine in its class.

## 3. Propagation: From Local Block to Global Shield
To move toward **Edge Enforcement**, Sentinel follows a "Broadcast" pattern:

1.  **Detection**: An IP is repeatedly flagged as UNTRUSTED across the network.
2.  **Broadcast**: The Sentinel Engine emits a high-priority signal (via Webhooks or Supabase Edge Functions).
3.  **Edge Sync**: This "Confirmed Bad" list is pushed to Global Key-Value stores (Cloudflare KV, Vercel Edge Config).
4.  **Enforcement**: Edge Adapters read from this local KV store. Future requests from that IP are blocked at the CDN level (latency: ~2ms), never reaching the user's origin server.

## 4. Key Architectural Patterns
*   **RAM for Speed**: All active decisions happens in memory.
*   **DB for Records**: Supabase stores the "history" and "telemetry" for dashboarding.
*   **KV for Global Sync**: Edge caches store the "verdict" for sub-2ms rejection at the internet's edge.
