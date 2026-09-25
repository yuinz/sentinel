# V1 vs V2 Comparison

If you are a current API consumer utilizing `/v1/check`, you are entirely unaffected by the V2 release. Both architectures run in harmony.

### V1: The Dictator
*   **Routing:** `POST /v1/check`
*   **Execution Setup:** Makes synchronous external API requests across the internet to verify ASN statuses.
*   **Pros:** Heavy-handed block algorithms guarantee a clean application immediately.
*   **Cons:** Higher latency (approx 500ms - 2000ms), and false positives for corporate users on NordVPN, AWS WorkSpaces, or iCloud Private Relay.

### V2: The Executor
*   **Routing:** `POST /v2/evaluate`
*   **Execution Setup:** Relies exclusively on static memory (<5ms), Mathematics (-100 to +100 Scale), and Async Background Resolvers. 
*   **Pros:** Near 0ms latency. BWT for ambiguous humans. Per-tenant Global Master Policies (mode, VPN/DC actions, Force BWT).
*   **Cons:** Bot traffic metadata populates asynchronously on the second request. Custom DSL rule strings are not shipped yet.
