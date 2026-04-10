# Welcome to Sentinel Engine

Sentinel Engine represents a paradigm shift in threat protection. It balances ruthless security against automated vectors alongside an entirely frictionless experience for legitimate human users.

## The Architecture
Our engine is deliberately split into two modules to satisfy different threat models:

1. **V1 (The Shield):** A synchronous, brutal firewall. Ideal for monolithic platforms where Zero-Trust is paramount and VPNs/Proxies must be heavily restricted immediately.
2. **V2 (The B2B Policy Engine):** A hyper-fast (\<5ms) edge evaluator. It delegates border control to the **Tenant**. Bots, proxies, and networks are mathematically scored and optionally allowed, challenged, or blocked based on Custom DSL Rules configured by your clients.

## The Secret Weapon
Sentinel doesn't use picture captchas. We use a **Behavioral Work Token (BWT)**.
Instead of making users click crosswalks, we present a beautiful overlay instructing them to "Click and hold to verify". While holding, their browser computes complex SHA256 hashes. It burns bot CPU and verifies human micro-interactions simultaneously.
