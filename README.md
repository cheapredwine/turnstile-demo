# Turnstile remoteip_leniency Demo

> ⚠️ **NOT OFFICIAL CLOUDFLARE.** Not affiliated with or endorsed by Cloudflare, Inc.
> NO WARRANTIES, EXPRESS OR IMPLIED. Effectively untested demo code — read everything
> and dry-run before you run. You assume all risk. See [DISCLAIMER.md](./DISCLAIMER.md).

Cloudflare Worker demonstrating the undocumented `remoteip_leniency` parameter in Turnstile's siteverify API, using **staged enforcement** to classify IP mismatches.

**Live Demo (both hostnames serve the same worker):**
- https://turnstile-demo.jsherron.com — custom domain on the `jsherron.com` zone, **behind Cloudflare Access** and fronted by the **Cloudflare Precursor interstitial** for session-less visitors
- https://turnstile-demo.jsherron-test-account.workers.dev — workers.dev URL, behind Cloudflare Access

## What This Does

Demonstrates Turnstile's undocumented `remoteip_leniency` parameter + a **staged fallback cascade** that determines the exact IP mismatch level.

**Enforcement levels:**
- `off` — no IP enforcement (token validated on all other criteria only)
- `strict` — exact IP match required (any mismatch = reject)
- `relaxed` — same ASN/subnet required (rejects different ASN, different subnet IPv4 /24 or IPv6 /64)

**Problem:** when `strict`/`relaxed` blocks a token, the error code is `invalid-input-response` — the same code as expired/reused/malformed tokens. You can't tell an IP mismatch from another failure, or a strict-level mismatch from a relaxed-level one.

**Solution — staged enforcement:** the configured `REMOTEIP_LENIENCY` is the **starting level**; on an IP-policy failure (`invalid-input-response`) the same token is retried at the next looser level:

1. Call at the starting level → success means no IP mismatch (stop)
2. Fallback to the next looser level → success means the earlier level(s) would have blocked
3. All levels failed → token invalid for other reasons (expired/reused/malformed)

The cascade length depends on the starting level: `strict` → `strict, relaxed, off` (3 calls max), `relaxed` → `relaxed, off` (2 calls max), `off` → single call.

**Key insight:** failed IP checks don't consume the token (the IP check happens before the token store); the first successful call consumes it. Only `invalid-input-response` failures trigger fallback — other errors (e.g. `timeout-or-duplicate`) stop the cascade immediately.

> **Production guidance:** you normally need only **two calls** — your enforcement level, then `off` as the diagnostic. The intermediate `relaxed` call only adds classification granularity (same-subnet vs cross-ASN). Note `remoteip_leniency` is **undocumented** and may change or disappear without notice.

## Quick Start

```bash
npm install
npm test           # Run 44 tests
npm run check      # wrangler types --check + tsc --noEmit
npm run lint       # oxlint
npm run format     # oxfmt
npm run dev        # Local dev server (copy .dev.vars.example to .dev.vars first)
npm run deploy     # Deploy to Workers (wrangler deploy)
```

## Configuration

**wrangler.jsonc:**
```jsonc
"routes": [{ "pattern": "turnstile-demo.jsherron.com", "custom_domain": true }],
"workers_dev": true,
"vars": {
  "TURNSTILE_SITE_KEY": "0x4AAAAAAEX-IyAE9Fs2oLZ0",  // Public key
  "REMOTEIP_LENIENCY": "strict",                     // Starting enforcement level
  "TURNSTILE_HOSTNAMES": "turnstile-demo.jsherron-test-account.workers.dev, turnstile-demo.jsherron.com, jsherron.com, localhost, 127.0.0.1"
}
```

Also configured: `nodejs_compat` flag, `[observability]` with `head_sampling_rate: 1`, compatibility date tracking the pinned workerd.

**Secret (via wrangler):**
```bash
wrangler secret put TURNSTILE_SECRET
```

Local dev secret: copy `.dev.vars.example` to `.dev.vars` (gitignored).

## Project Structure

```
src/index.ts               # Worker, siteverify integration, staged enforcement, canonical gate
tests/turnstile.test.ts    # 44 tests covering all modes, fallbacks, and gates
wrangler.jsonc             # Worker config
```

## Endpoints

**GET /** — project overview + Precursor explainer + starting level (footer shows colo + Ray ID)
**GET /form** — Turnstile widget (managed mode) with selectors for starting level, IP-mismatch simulation, and mismatch action
**POST /form** — validates the token via staged enforcement, returns an HTML result page

## How It Works

1. Widget at `/form` (managed mode, `data-action="form"`); the form posts `cf-turnstile-response` plus the selected options
2. Worker calls siteverify starting at the selected `remoteip_leniency` level
3. If a call fails with `invalid-input-response` → retry the same token at the next looser level
4. **Canonical gate on the successful result:** the token's `action` must equal the widget's `data-action` (`form`), and if `TURNSTILE_HOSTNAMES` is set, siteverify's `hostname` must be in the allowlist — otherwise the request fails closed (401)
5. Response pages show:
   - **Success** — passed at the starting level + gate, no IP mismatch
   - **IP Mismatch Detected** — a later, looser level passed; the page classifies the mismatch level (strict-only vs relaxed-level) and applies the selected action (allow+flag → 200, hard block → 401)
   - **Verification Failed** — all levels failed, or the gate rejected the token (expired/reused/malformed/action/hostname)
6. Query params are allowlist-validated server-side (`strict|relaxed|off`, `none|subnet|asn`, `allow|block`); invalid values fall back to defaults — nothing user-supplied is echoed unescaped

**IP mismatch simulation:** `mismatch=subnet` sends the client IP with the last IPv4 octet incremented (same-subnet test; unsupported for IPv6 visitors — the real IP is sent and the page says so); `mismatch=asn` sends `8.8.8.8` (different-ASN test).

## Widget Domain Config

Widget works on these domains (configured via wrangler CLI):
```bash
wrangler turnstile widget update 0x4AAAAAAEX-IyAE9Fs2oLZ0 --mode managed \
  --domain localhost \
  --domain 127.0.0.1 \
  --domain jsherron.com \
  --domain "turnstile-demo.jsherron-test-account.workers.dev" \
  --domain "turnstile-demo.jsherron.com"
```
(PUT semantics — pass the complete list.)

## Cloudflare Precursor on This Demo

This demo runs on the `jsherron.com` zone so **Precursor** (client-side, session-based bot
detection that supersedes JavaScript Detections) is live in front of it:

- **Custom domain:** `turnstile-demo.jsherron.com` (attached via `routes` in `wrangler.jsonc`;
  `workers_dev: true` keeps the workers.dev URL alongside it)
- **Zone config** (zone `jsherron.com`, Security → Settings → Precursor):
  - Sitewide default `min-friction` (Show Interstitial **Off**) — untouched zone-wide
  - One **enforcement rule** scoped to `http.host eq "turnstile-demo.jsherron.com"` with
    `max-security` (interstitial required for visitors without a verified Precursor session)
  - Detection **Status** (Off/Monitor/Arm): confirm in the dashboard — the legacy API shape
    doesn't expose it; Monitor is the intended safe state
- **What a visitor sees:** Access login (both hostnames) → Precursor interstitial (first
  session-less visit to the custom domain) → the demo. Session verified → subsequent visits
  go straight through.
- **Where to observe:** Security → Analytics → Traffic → Bot analysis shows Precursor
  detections once it runs on the zone.
- **Rollback:** see `~/.opencode/plan/turnstile-precursor.md` — zone rule first, then widget
  whitelist, then worker config/deploy.

## Testing Different Starting Levels

Edit `wrangler.jsonc`:
```jsonc
"REMOTEIP_LENIENCY": "relaxed"  // or "off"
```

Then redeploy:
```bash
npm run deploy
```

Or use the level selector on `/form` (query param, no redeploy needed).

## Implementation Details

**siteverify call (src/index.ts, `verifyTurnstileToken`):**
```typescript
formData.append('remoteip_leniency', leniencyMode ?? env.REMOTEIP_LENIENCY ?? 'strict');
// remoteip is omitted entirely when the client IP is unknown
```

The call is hardened per the canonical pattern: token length ≤ 2048 enforced upstream, 10s `AbortSignal.timeout`, `response.ok` + payload shape validation, fail-closed on any transport/HTTP/payload error (synthetic `internal-error` code, logged as structured JSON without tokens), widget `data-action="form"` validated against siteverify's `action`, and optional `TURNSTILE_HOSTNAMES` hostname allowlist enforcement.

**Test coverage (44 tests):** parameter passing, all three levels, env default, missing IP, non-2xx/non-JSON fail-closed, oversized tokens, non-IP errors stopping the cascade, missing `error-codes`, starting-level semantics (strict/relaxed/off), full fallback cascades, allow/block actions, action/hostname gate checks, IPv4 subnet + ASN + IPv6 simulation, HTML escaping (XSS regressions), hostile query-param sanitization, and worker routing (404s).

## Troubleshooting

**Widget shows "unable to connect":** domain not whitelisted. Add it via `wrangler turnstile widget update`.

**Token validation fails:** check `wrangler secret list` shows `TURNSTILE_SECRET`.

**Typecheck fails:** run `npm install`, then `npm run check`.

## Resources

- [Turnstile Docs](https://developers.cloudflare.com/turnstile/)
- [Workers Docs](https://developers.cloudflare.com/workers/)
- [siteverify API](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)
