# Where Sentinel applies

Sentinel returns a verdict. It does not sit in front of a website by itself. Your app, edge worker, or game server enforces that verdict. A URL that never calls Sentinel is unchanged.

Put the check on the routes that matter — signup, login, checkout, or every HTTP request — and leave the rest of the site alone.

---

## Precheck and evaluate

These are different calls. Use one for a hint, the other for the decision you enforce.

| | `GET /v1/precheck` | `POST /v2/evaluate` |
|---|---|---|
| Caller | Browser or edge. No API key. | Your server, with the billing key. Each call counts against quota. |
| Engine | V1. It may wait on a live IP lookup. | V2. Memory and cache, then the saved policy. |
| Mode, VPN, datacenter, Force BWT | Not used. | Used. |
| Trust token | Ignored. | `x-sentinel-trust` is checked. A valid token passes Force BWT. |
| Answer | `TRUSTED`, `UNSTABLE`, or `UNTRUSTED`, plus `required`. | `ALLOW`, `CHALLENGE`, or `BLOCK`. |
| What you do | `required: false` — continue. `required: true` — show the widget. | `ALLOW` forwards the request. `CHALLENGE` shows the widget, then retry with the token. `BLOCK` rejects it. |

A site key will not authenticate `/v2/evaluate`. Keep the billing key on the server. The widget in the browser uses the site key only for `/v1/challenge/issue` and `/v1/challenge/verify`.

---

## The saved mode after a challenge

The widget does not choose a mode. `/v2/evaluate` loads the Global Master Policy for that API key on every call.

Force BWT is on by default. The first evaluate, with no `x-sentinel-trust` header, returns `CHALLENGE` before Passive, Balanced, Strict, Draconian, or Humans only is consulted. That is true for a clean residential IP.

The visitor then uses the hold widget or the click widget. Either one solves the same proof and returns a trust token. The widget does not send the mode.

Your server retries `/v2/evaluate` with `x-sentinel-trust`. Force BWT steps aside, and the saved mode runs.

After a valid token, Passive, Balanced, Strict, and Draconian return `ALLOW`. Humans only still requires a residential IP together with the token, and it still blocks a scanner signature or a velocity spike.

With Force BWT off, the saved mode decides the first call. A clean IP on Balanced can be `ALLOW` with no widget. Show the widget only when that mode returns `CHALLENGE`.

---

## A datacenter block and the rest of the site

`datacenter_action: block` applies only to requests that call `/v2/evaluate` with that policy. A blog, a marketing page, or any other URL that does not call Sentinel is not filtered. Crawlers can still fetch those pages.

On the protected route, two details matter.

**Known crawlers.** Googlebot, Bingbot, and the other listed crawlers are `VERIFIED_BOT` when their User-Agent is the one Sentinel sees. A verified bot skips the datacenter hard block and Force BWT. The mode still runs. This works only if the evaluate call forwards the crawler's User-Agent. If your server calls Sentinel with its own User-Agent, a Google datacenter IP is treated like any other datacenter and a hard block rejects it on that route.

**Edge broadcast.** A `BLOCK` can be written to Cloudflare KV as `sentinel:verdict:<ip>` for about one hour, and only when `CLOUDFLARE_API_KEY`, the account id, and the KV namespace are set. That write does nothing to the rest of the site unless an edge worker on the zone reads the same key and blocks the IP. With no such worker, other pages stay unaffected.

---

## Same engine, different gate

The decision engine is one. The gate is wherever you enforce the verdict.

| Gate | Placement | What it covers |
|---|---|---|
| Route shield | Your API calls `/v2/evaluate` on signup, login, or checkout. | Those routes only. |
| Site gate | A Cloudflare Worker or reverse proxy calls evaluate for every HTTP request and drops `BLOCK` before the origin. | HTTP through that worker. Not packets, SSH, or UDP. |
| Game or other server | The server calls evaluate and closes the session on `BLOCK`. | The calls that server chooses to check. |

A site gate is an application check on HTTP. It is not a network firewall.
