# V1 vs V2 Comparison

If you are a current API consumer utilizing `/v1/check`, you are entirely unaffected by the V2 release. Both architectures run in harmony.

### V1: The Dictator
*   **Routing:** `/api/v1/check`
*   **Execution Setup:** Makes synchronous external API requests across the internet to verify ASN statuses.
*   **Pros:** Heavy-handed block algorithms guarantee a clean application immediately.
*   **Cons:** Higher latency (approx 500ms - 2000ms), and false positives for corporate users on NordVPN, AWS WorkSpaces, or iCloud Private Relay.

### V2: The Executor
*   **Routing:** `/api/v2/evaluate`
*   **Execution Setup:** Relies exclusively on static memory (<5ms), Mathematics (-100 to +100 Scale), and Async Background Resolvers. 
*   **Pros:** Near 0ms latency. Zero false-positives for human users on infrastructure endpoints thanks to the BWT. Custom DSL overrides.
*   **Cons:** Bot traffic metadata populates asynchronously on the second request.
