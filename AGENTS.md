# AGENTS.md - Turnstile remoteip_leniency Demo

## Project Overview

Cloudflare Worker demonstrating the undocumented `remoteip_leniency` parameter in the Turnstile siteverify API, using **staged enforcement** (starting level + fallback cascade) to classify IP mismatches — served from both a custom domain on the `jsherron.com` zone (with live Cloudflare **Precursor** in front) and the Access-gated workers.dev URL.

**Live:**
- https://turnstile-demo.jsherron.com (custom domain; Access-gated; Precursor interstitial for session-less visitors)
- https://turnstile-demo.jsherron-test-account.workers.dev (Access-gated)

## Architecture

```
GET /          → Project overview + Precursor explainer + starting level
GET /form      → Turnstile widget (managed mode) + option selectors
POST /form     → Token validation via staged enforcement
```

## Key Files

**src/index.ts** (913 lines)
- `verifyTurnstileToken()` — siteverify call with `remoteip_leniency`; hardened (10s timeout, `response.ok` check, payload shape validation, fail-closed on transport/HTTP errors, `remoteip` omitted when client IP unknown)
- `handleTurnstileVerification()` — allowlist-validates mode/mismatch/action params, token length ≤ 2048, runs the staged cascade, applies the canonical gate, renders result pages (all dynamic values HTML-escaped)
- Canonical gate on the successful result — `action` must equal the widget's `data-action` (`form`); hostname must be in `TURNSTILE_HOSTNAMES` allowlist when set (fail closed → 401)
- `simulateIpMismatch()` — subnet (last octet +1, IPv4 only) and ASN (8.8.8.8) simulation; IPv6 visitors get their real IP unchanged plus an explanatory note
- Structured `console.error` JSON logging on siteverify transport failures and handler errors (no tokens/secrets logged)
- Provenance footer on all pages: "Served by Cloudflare · colo · Ray ID" (`request.cf.colo` / `CF-Ray`) + links to Precursor docs and the Precursor Trace simulation
- Index page carries a full Precursor explainer: how it works (injected script, continuous loop, `cf_clearance` session state in Arm mode), Off/Monitor/Arm modes table, the Interstitial + Interstitial Rules model, and JSD supersession
- Four result pages: success (passed at starting level + gate), IP mismatch (fallback passed; classify + allow/block), hard failure (all levels failed or gate rejected)

**tests/turnstile.test.ts** (540 lines)
- 44 tests: siteverify formatting, all levels, env default, fail-closed paths, staged fallback cascades, actions, canonical gate (action/hostname), IP simulation, XSS regressions, routing
- Mocked fetch (`vi.stubGlobal`), no real API calls

**wrangler.jsonc**
- Site key: `0x4AAAAAAEX-IyAE9Fs2oLZ0` (managed widget)
- Custom domain route: `turnstile-demo.jsherron.com` (`custom_domain: true`) + `workers_dev: true`
- `REMOTEIP_LENIENCY` env var = starting enforcement level (strict/relaxed/off)
- `TURNSTILE_HOSTNAMES` var = siteverify hostname allowlist (5 entries mirroring the widget whitelist)
- Secret: `TURNSTILE_SECRET` via wrangler secrets; local dev via `.dev.vars` (see `.dev.vars.example`)
- `nodejs_compat` flag, `[observability] enabled` with `head_sampling_rate: 1`, compatibility_date 2026-10-01

**Zone integration (jsherron.com, zone id [removed])**
- Precursor config via `PUT /zones/{zone_id}/precursor` (legacy shape — the portal tool
  wrapper cannot send the `Cloudflare-Version: 1.0` header, so `mode`/`rules`/`show_interstitial`
  are rejected; use legacy `default_mode` ∈ off|min-friction|max-security and
  `enforcement_rules[{expression, mode, description?, enabled?}]`)
- Current zone state: sitewide `min-friction` (interstitial off) + one enforcement rule
  `http.host eq "turnstile-demo.jsherron.com"` → `max-security` (id `084dfe0da3d646c5a1bdf7b870b25db8`)
- Detection **Status** (Off/Monitor/Arm) is v1.0-only — confirm/set it in the dashboard
  (Security → Settings → Precursor); Monitor is the intended safe state
- Rollback: `~/.opencode/plan/turnstile-precursor.md` (zone rule → widget whitelist →
  worker config/deploy → git revert)

## Commands

```bash
npm install
npm test              # 44 tests, all pass
npm run check         # wrangler types --check && tsc --noEmit (must be clean before committing)
npm run lint          # oxlint
npm run format        # oxfmt
npm run types         # Regenerate worker-configuration.d.ts after wrangler.jsonc changes
npm run deploy        # Deploy via wrangler deploy
wrangler deployments list --name turnstile-demo
```

## Widget Configuration

**Managed widget** requires domain whitelist. Current domains:
```bash
wrangler turnstile widget list
# Shows: 127.0.0.1, jsherron.com, localhost, turnstile-demo.jsherron-test-account.workers.dev
```

**Add domain:**
```bash
wrangler turnstile widget update 0x4AAAAAAEX-IyAE9Fs2oLZ0 \
  --domain domain1.com --domain domain2.com --domain "*.workers.dev"
```

**Get widget secret:**
```bash
# Requires API token with challenge-widgets.write scope
curl "https://api.cloudflare.com/client/v4/accounts/{account_id}/challenges/widgets/{sitekey}/secrets" \
  -H "Authorization: Bearer $TOKEN"
```

## Staged Enforcement Semantics

`REMOTEIP_LENIENCY` (and the `/form?mode=` selector) sets the **starting level**; the cascade falls back through looser levels only on `invalid-input-response` (the IP-policy error):

| Start level | Sequence | Max calls |
|-------------|----------|-----------|
| strict | strict → relaxed → off | 3 |
| relaxed | relaxed → off | 2 |
| off | off | 1 |

**Decision matrix (strict start):**

| strict | relaxed | off | Meaning | Calls |
|--------|---------|-----|---------|-------|
| ✅ pass | - | - | Exact IP match | 1 |
| ❌ fail | ✅ pass | - | Same ASN/subnet, different exact IP | 2 |
| ❌ fail | ❌ fail | ✅ pass | Different ASN or subnet | 3 |
| ❌ fail | ❌ fail | ❌ fail | Token invalid (expired/reused/malformed) | 3 |

(relaxed start skips the strict column; off start is a single call.)

**Critical:**
- Failed IP checks **don't consume the token** (IP check happens before token store)
- First successful call consumes the token
- Only `invalid-input-response` triggers fallback — non-IP errors (e.g. `timeout-or-duplicate`) stop the cascade immediately
- Transport/HTTP/payload errors fail closed with a synthetic `internal-error` code
- Production guidance: two calls (enforcement level + `off` diagnostic) are sufficient; the middle `relaxed` call only adds classification granularity

**Query param validation (server-side allowlists):**
- `mode` ∈ strict|relaxed|off (invalid → env default or strict)
- `mismatch` ∈ none|subnet|asn (invalid → none)
- `action` ∈ allow|block (invalid → allow)

**Canonical siteverify gate (on the successful call):**
- `result.action` must equal `"form"` (widget embeds `data-action="form"`) — else `action-not-allowed` → 401
- If `TURNSTILE_HOSTNAMES` is set, `result.hostname` must be in the allowlist — else `hostname-not-allowed` → 401
- Gate failures always reject regardless of the allow/block selection (fail closed)

Hostile values are never echoed — invalid params fall back to defaults (XSS regression tests cover this).

## Response Types

1. **Success** (200) — passed at the starting level, 1 call
2. **IP Mismatch Detected** (200 allow+flag / 401 hard block) — fallback passed at a looser level; page classifies strict-only vs relaxed-level mismatch
3. **Hard Failure** (401) — all levels failed; token invalid for non-IP reasons

## Test Structure

1. `verifyTurnstileToken` — API call formatting, overrides, env default, missing IP, fail-closed on non-2xx/non-JSON
2. `handleTurnstileVerification` — validation (400s), non-IP errors, internal-error synthesis, missing `error-codes`
3. Starting enforcement level — strict/relaxed/off starts, all fallback paths
4. Actions — allow+flag vs hard block
5. IP simulation — subnet (IPv4), ASN, none, IPv6 unchanged, missing IP header
6. Canonical gate — action mismatch/missing, hostname allowlist enforced/not enforced
7. Output hygiene — escaped token reflection, challenge_ts/hostname display
8. Worker routes — GET /, GET /form (site key, defaults), hostile-param sanitization, POST end-to-end, 404s

---

**Status:** production-ready demo, 44/44 tests passing, typecheck + lint clean
**Last Updated:** 2026-10-28
**Account:** JSherron Test Account ([removed])
**Zone:** jsherron.com ([removed]) — Precursor live per plan rollback doc
