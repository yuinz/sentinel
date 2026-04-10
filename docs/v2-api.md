# V2 API Reference

The Sentinel V2 API is a deterministic, multi-tenant evaluation endpoint. It does not perform active synchronous background profiling, guaranteeing `<10ms` response times.

## 1. Trust Evaluation Endpoint

Evaluate an incoming IP address against your specific tenant's DSL policies and the internal behavioral hash map.

**Endpoint:** `POST /v2/evaluate`  
**Headers:** 
- `Authorization: Bearer <YOUR_API_KEY>`
- `Content-Type: application/json`
- `x-sentinel-trust: <JWT>` (Optional. Required to bypass a block after a challenge is successfully solved.)

### Request Body
```json
{
  "target": "105.113.18.224"
}
```

### JSON Response Schema

**Success Example (Human Evaluator):**
```json
{
    "status": "success",
    "tenant": {
        "api_key": "VALID",
        "policy_engaged": "BALANCED"
    },
    "decision": {
        "verdict": "ALLOW",
        "score": 85,
        "signals": [
            {
                "id": "RESIDENTIAL_IP",
                "weight": 10,
                "label": "Residential/Organic Network"
            }
        ],
        "latency_ms": 4
    }
}
```

**Challenge Example (Bot Suspicion):**
```json
{
    "status": "success",
    "tenant": {
        "api_key": "VALID",
        "policy_engaged": "BALANCED"
    },
    "decision": {
        "verdict": "CHALLENGE",
        "score": -20,
        "signals": [
            {
                "id": "SCANNER_PATTERN",
                "weight": -50,
                "label": "Fast Enumeration Detected"
            }
        ],
        "action_required": "SOLVE_CAPTCHA",
        "latency_ms": 5
    }
}
```

## 2. Verdict Definitions

| Verdict | Meaning | Required Action |
|---------|---------|-----------------|
| `ALLOW` | The request is structurally and behaviorally human. | Forward the request. |
| `BLOCK` | The request aggressively triggered a critical threat parameter. | Deny request with a 403 or 401. |
| `CHALLENGE` | The request hit an ambiguous score threshold. | Serve the `SOLVE_CAPTCHA` Silent Widget, then re-evaluate. |

## 3. Asynchronous Data

V2 prioritizes speed over synchronized data fetching. If an IP lacks Deep Forensic Data (ASN/Carrier) during the first request, the Engine triggers a parallel cold cache retrieval. Subsequent requests from that IP within 24 hours will include the deeply analyzed data.
