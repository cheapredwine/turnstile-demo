# Turnstile remoteip_leniency Demo

Cloudflare Worker demonstrating the undocumented `remoteip_leniency` parameter in Turnstile's siteverify API.

**Live Demo:** https://turnstile-demo.jsherron-test-account.workers.dev

## What This Does

Tests Turnstile's undocumented `remoteip_leniency` parameter with three modes:
- `strict` - Enforce exact IP match (default)
- `relaxed` - Allow IP variations 
- `off` - Disable IP validation

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

1. Widget rendered at `/form` with managed Turnstile
2. Form submits cf-turnstile-response token
3. Worker calls siteverify API with `remoteip_leniency` parameter
4. Response shows verification result + mode used

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