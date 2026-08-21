# AGENTS.md - Turnstile remoteip_leniency Demo

## Project Overview

Cloudflare Worker demonstrating undocumented `remoteip_leniency` parameter in Turnstile siteverify API.

**Live:** https://turnstile-demo.jsherron-test-account.workers.dev

## Architecture

```
GET /          → Project overview + config
GET /form      → Turnstile widget (managed mode)
POST /form     → Token validation with remoteip_leniency
```

## Key Files

**src/index.ts** (218 lines)
- `verifyTurnstileToken()` - Adds remoteip_leniency to siteverify FormData
- `handleTurnstileVerification()` - Processes POST with cf-turnstile-response
- Three HTML responses: index, form, success/error with UTF-8 charset

**tests/turnstile.test.ts** (379 lines)
- 19 tests: parameter passing, all modes, defaults, errors
- Mocked fetch, no real API calls

**wrangler.toml**
- Site key: `0x4AAAAAAEX-IyAE9Fs2oLZ0` (managed widget)
- REMOTEIP_LENIENCY env var (strict/relaxed/off)
- Secret: `TURNSTILE_SECRET` via wrangler secrets

## Commands

```bash
npm install
npm test              # 19 tests, all pass
npm run deploy        # Deploy to Workers
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

## Change remoteip_leniency Mode

Edit `wrangler.toml`:
```toml
REMOTEIP_LENIENCY = "relaxed"  # or "off"
```

Deploy:
```bash
npm run deploy
```

## Troubleshooting

**Widget shows "unable to connect"**
- Domain not whitelisted in widget config
- Add via `wrangler turnstile widget update`

**Tests fail**
- Run `npm install`
- Check `npx tsc --noEmit`

**Token validation fails**
- Check secret exists: `wrangler secret list`
- Verify correct account/worker

**Deployment fails**
- Update wrangler: `npm install -g wrangler@latest`
- Check auth: `wrangler whoami`

**Emoji rendering as garbage in terminal**
- Not a bug - terminal charset issue
- Browser renders UTF-8 correctly
- Response has proper `Content-Type: text/html; charset=utf-8`

## Implementation Details

**Double-Call Pattern (src/index.ts:37-50):**
```typescript
const verificationResult = await verifyTurnstileToken(token, clientIp, env, mode);

// If first call failed with invalid-input-response, retry with 'off'
if (!verificationResult.success && mode !== 'off' && 
    verificationResult["error-codes"].includes("invalid-input-response")) {
  const secondCallResult = await verifyTurnstileToken(token, clientIp, env, 'off');
  if (secondCallResult.success) {
    ipMismatchDetected = true; // First failed on IP, second succeeded
  }
}
```

**Response types:**
1. **Success** (200) - First call passed, no double-call needed
2. **IP Mismatch Detected** (200) - First failed, second passed → flag but allow
3. **Hard Failure** (401) - Both calls failed → token invalid (expired/reused/etc)

**Important:**
- Tokens consumed only on successful validation
- Failed strict + successful off = safe, demonstrates IP mismatch
- Default mode is `off` (not `strict` as previously thought)
- `relaxed` checks ASN + subnet, not just exact IP

**Test structure:**
1. verifyTurnstileToken - API call formatting
2. handleTurnstileVerification - Request handling + double-call
3. remoteip_leniency Parameter - All three modes
4. Edge cases - Defaults, missing values, errors

---

**Status:** Production ready, 19/19 tests passing  
**Last Updated:** 2026-08-21  
**Account:** JSherron Test Account ([removed])