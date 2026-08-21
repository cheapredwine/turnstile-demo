# Turnstile remoteip_leniency Demo

Cloudflare Worker demonstrating the undocumented `remoteip_leniency` parameter in Turnstile's siteverify API.

**Live Demo:** https://turnstile-demo.jsherron-test-account.workers.dev

## What This Does

Demonstrates Turnstile's undocumented `remoteip_leniency` parameter + double-call workaround for detecting IP mismatches.

**Modes:**
- `off` (default) - No IP enforcement
- `strict` - Exact IP match required (any mismatch = reject)
- `relaxed` - Same ASN/subnet required (rejects different ASN, different subnet IPv4 /24 or IPv6 /64)

**Problem:** When `strict`/`relaxed` blocks a token, error code is `invalid-input-response` (same as expired/reused tokens). No way to distinguish IP mismatch from other failures.

**Solution:** Double-call pattern:
1. Call with `strict` (or `relaxed`)
2. If failed → retry same token with `off`
3. If retry succeeds → IP mismatch detected (flag/allow)
4. If retry fails → token invalid for other reason (reject)

## Quick Start

```bash
npm install
npm test           # Run 19 tests
npm run deploy     # Deploy to Workers
```

## Configuration

**wrangler.toml:**
```toml
TURNSTILE_SITE_KEY = "0x4AAAAAAEX-IyAE9Fs2oLZ0"  # Public key
REMOTEIP_LENIENCY = "strict"                      # Test mode
```

**Secret (via wrangler):**
```bash
wrangler secret put TURNSTILE_SECRET
```

## Project Structure

```
src/index.ts              # Worker + siteverify integration
tests/turnstile.test.ts   # 19 tests covering all modes
wrangler.toml             # Worker config
```

## How It Works

1. Widget at `/form` (managed mode, 3 selectable modes + IP mismatch simulator)
2. Form POST submits cf-turnstile-response token
3. Worker calls siteverify with selected `remoteip_leniency`
4. If first call fails with `invalid-input-response` → retry with `off` (double-call pattern)
5. Response shows:
   - Success (first call passed)
   - IP Mismatch Detected (first failed, second passed)
   - Hard Failure (both failed - token expired/reused/malformed)

### Run Tests in Watch Mode
```bash
npm run test:watch
```

### Test Coverage

The test suite validates:

1. **Parameter Passing**: Verifies `remoteip_leniency` is correctly passed to Turnstile API
2. **All Three Modes**: Tests "strict", "relaxed", and "off" modes
## Endpoints

**GET /** - Project overview + config info  
**GET /form** - Turnstile widget  
**POST /form** - Validates token, returns HTML with result

## Widget Domain Config

Widget works on these domains (configured via wrangler CLI):
```bash
wrangler turnstile widget update 0x4AAAAAAEX-IyAE9Fs2oLZ0 \
  --domain localhost \
  --domain 127.0.0.1 \
  --domain jsherron.com \
  --domain "turnstile-demo.jsherron-test-account.workers.dev"
```

## Testing Different Modes

Edit `wrangler.toml`:
```toml
REMOTEIP_LENIENCY = "relaxed"  # or "off"
```

Then redeploy:
```bash
npm run deploy
```

## Implementation Details

**siteverify call (src/index.ts:64):**
```typescript
formData.append('remoteip_leniency', leniency);
```

**Test coverage:** 19 tests verify:
- Parameter is sent correctly
- All three modes work
- Defaults to "strict"
- Handles errors properly

## Troubleshooting

**Widget shows "unable to connect":** Domain not whitelisted. Add it via `wrangler turnstile widget update`.

**Token validation fails:** Check `wrangler secret list` shows `TURNSTILE_SECRET`.

**Tests fail:** Run `npm install` then `npm test`.

## Resources

- [Turnstile Docs](https://developers.cloudflare.com/turnstile/)
- [Workers Docs](https://developers.cloudflare.com/workers/)
- [siteverify API](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)