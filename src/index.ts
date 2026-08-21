// Turnstile Demo Worker with remoteip_leniency parameter

interface TurnstileVerifyResponse {
  success: boolean;
  "error-codes": string[];
  challenge_ts?: string;
  hostname?: string;
  "remoteip_leniency"?: string;
  ip_comparison_metadata?: {
    matched?: boolean;
    original_ip?: string;
    verification_ip?: string;
    comparison_method?: string;
    [key: string]: any;
  };
}

interface Env {
  TURNSTILE_SECRET: string;
  TURNSTILE_SITE_KEY: string;
  REMOTEIP_LENIENCY?: 'strict' | 'relaxed' | 'off';
  TURNSTILE_CACHE?: KVNamespace;
}

export async function handleTurnstileVerification(
  request: Request, 
  env: Env, 
  modeOverride?: 'strict' | 'relaxed' | 'off' | null
): Promise<Response> {
  try {
    const formData = await request.formData();
    const token = formData.get('cf-turnstile-response') as string;
    const clientIp = request.headers.get('CF-Connecting-IP') || '0.0.0.0';

    if (!token) {
      return new Response('No Turnstile token provided', { status: 400 });
    }

    const verificationResult = await verifyTurnstileToken(token, clientIp, env, modeOverride || undefined);

    if (!verificationResult.success) {
      const errorHtml = `
<!DOCTYPE html>
<html>
<head>
  <title>Verification Failed</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
    .error { border: 2px solid #dc3545; padding: 20px; border-radius: 8px; background: #f8d7da; }
    h2 { color: #dc3545; }
    .errors { background: #fff; padding: 10px; margin: 15px 0; border-radius: 4px; }
    a { display: inline-block; margin-top: 20px; color: #0056b3; }
  </style>
</head>
<body>
  <div class="error">
    <h2>❌ Verification Failed</h2>
    <div class="errors">
      <strong>Error codes:</strong> ${verificationResult["error-codes"].join(", ")}
    </div>
    <a href="/form">← Try again</a>
  </div>
</body>
</html>`;
      return new Response(errorHtml, {
        status: 401,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    const successHtml = `
<!DOCTYPE html>
<html>
<head>
  <title>Verification Success</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
    .success { border: 2px solid #28a745; padding: 20px; border-radius: 8px; background: #d4edda; }
    .result { background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 4px; font-family: monospace; }
    h2 { color: #28a745; }
    .label { font-weight: bold; }
    a { display: inline-block; margin-top: 20px; color: #0056b3; }
  </style>
</head>
<body>
  <div class="success">
    <h2>✅ Turnstile Verification Successful</h2>
    <div class="result">
      <div><span class="label">Mode Used:</span> ${modeOverride || env.REMOTEIP_LENIENCY || 'strict'}</div>
      <div><span class="label">Client IP:</span> ${clientIp}</div>
      <div><span class="label">Challenge TS:</span> ${verificationResult.challenge_ts || 'N/A'}</div>
      <div><span class="label">Hostname:</span> ${verificationResult.hostname || 'N/A'}</div>
      ${verificationResult.ip_comparison_metadata ? `<div><span class="label">IP Comparison:</span> ${JSON.stringify(verificationResult.ip_comparison_metadata)}</div>` : ''}
    </div>
    <details>
      <summary style="cursor: pointer; color: #0056b3;">Full API Response</summary>
      <pre style="background: #fff; padding: 10px; overflow-x: auto;">${JSON.stringify(verificationResult, null, 2)}</pre>
    </details>
    <a href="/form">← Try again</a>
  </div>
</body>
</html>`;
    return new Response(successHtml, {
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  } catch (error) {
    return new Response(`Error: ${error instanceof Error ? error.message : String(error)}`, { status: 500 });
  }
}

export async function verifyTurnstileToken(
  token: string,
  clientIp: string,
  env: Env,
  leniencyMode?: 'strict' | 'relaxed' | 'off'
): Promise<TurnstileVerifyResponse> {
  const formData = new FormData();
  formData.append('secret', env.TURNSTILE_SECRET);
  formData.append('response', token);
  formData.append('remoteip', clientIp);

  // Use environment variable if specified, otherwise default to strict
  const leniency = leniencyMode || env.REMOTEIP_LENIENCY || 'strict';
  formData.append('remoteip_leniency', leniency);

  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    body: formData,
    method: 'POST'
  });

  return response.json();
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/' && request.method === 'GET') {
      const leniencyMode = env.REMOTEIP_LENIENCY || 'strict';
      const indexHtml = `
<!DOCTYPE html>
<html>
<head>
  <title>Turnstile remoteip_leniency Demo</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; line-height: 1.6; }
    .container { border: 1px solid #ddd; padding: 30px; border-radius: 8px; }
    h1 { color: #0056b3; margin-bottom: 10px; }
    h2 { color: #333; margin-top: 30px; border-bottom: 2px solid #0056b3; padding-bottom: 5px; }
    h3 { color: #555; margin-top: 25px; }
    .info { background: #f0f8ff; padding: 15px; margin: 20px 0; border-left: 4px solid #0056b3; }
    .btn { display: inline-block; background: #0056b3; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin-top: 20px; }
    .btn:hover { background: #004494; }
    code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; color: #c7254e; }
    pre { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 4px; overflow-x: auto; line-height: 1.4; }
    pre strong { color: #f92672; }
    ul { margin: 15px 0; }
    li { margin: 10px 0; }
    em { color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Turnstile remoteip_leniency Demo</h1>
    <div class="info">
      <strong>Current Configuration:</strong> remoteip_leniency = "${leniencyMode}"
    </div>
    <h2>What is remoteip_leniency?</h2>
    <p>An <strong>undocumented parameter</strong> for Turnstile's <code>/siteverify</code> API that controls how strictly the user's IP address is validated during token verification.</p>
    
    <h3>Why It Matters</h3>
    <p>When a user solves a Turnstile challenge, the token is tied to their IP address. If their IP changes between solving the challenge and your server validating it (due to mobile network handoffs, VPN switches, or proxy rotation), validation may fail.</p>

    <h3>The Three Modes</h3>
    <ul>
      <li><code>strict</code> - Requires <strong>exact IP match</strong>. Use for high-security scenarios where you need certainty that the same device/network verified the token.</li>
      <li><code>relaxed</code> - Allows <strong>IP variations within reason</strong> (same /24 subnet, ASN changes, mobile carrier transitions). Best for mobile apps and users on dynamic IPs.</li>
      <li><code>off</code> - <strong>Disables IP validation entirely</strong>. Only verifies the token itself. Use cautiously—reduces bot detection effectiveness.</li>
    </ul>

    <h3>How to Use It</h3>
    <p>Add the parameter when calling Turnstile's siteverify endpoint:</p>
    <pre>const formData = new FormData();
formData.append('secret', env.TURNSTILE_SECRET);
formData.append('response', token);
formData.append('remoteip', clientIp);
<strong>formData.append('remoteip_leniency', 'relaxed');</strong>

const result = await fetch(
  'https://challenges.cloudflare.com/turnstile/v0/siteverify',
  { method: 'POST', body: formData }
);</pre>

    <p><em>Note: This parameter is not in official docs but works in production. Current mode for this demo: <code>${leniencyMode}</code></em></p>

    <a href="/form" class="btn">Try the Demo →</a>
  </div>
</body>
</html>`;
      return new Response(indexHtml, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (url.pathname === '/form' && request.method === 'GET') {
      const mode = url.searchParams.get('mode') || env.REMOTEIP_LENIENCY || 'strict';
      const formHtml = `
<!DOCTYPE html>
<html>
<head>
  <title>Turnstile Demo - remoteip_leniency: ${mode}</title>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>
    body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
    .container { border: 1px solid #ddd; padding: 20px; border-radius: 8px; }
    input[type="submit"] { background: #0056b3; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
    input[type="submit"]:hover { background: #004494; }
    .cf-turnstile { margin: 20px 0; }
    .info { background: #f0f8ff; padding: 10px; margin-bottom: 20px; border-left: 4px solid #0056b3; }
    .mode-toggle { margin: 15px 0; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px; }
    .mode-toggle label { margin-right: 15px; cursor: pointer; }
    .mode-toggle input[type="radio"] { margin-right: 5px; }
  </style>
</head>
<body>
  <div class="container">
    <h2>Turnstile remoteip_leniency Demo</h2>
    <div class="info">
      <strong>Current Mode:</strong> ${mode}<br>
      <strong>Purpose:</strong> Test undocumented remoteip_leniency parameter in siteverify API
    </div>
    
    <div class="mode-toggle">
      <strong>Select Mode:</strong><br><br>
      <label><input type="radio" name="mode" value="strict" ${mode === 'strict' ? 'checked' : ''} onchange="location.href='/form?mode=strict'"> strict</label>
      <label><input type="radio" name="mode" value="relaxed" ${mode === 'relaxed' ? 'checked' : ''} onchange="location.href='/form?mode=relaxed'"> relaxed</label>
      <label><input type="radio" name="mode" value="off" ${mode === 'off' ? 'checked' : ''} onchange="location.href='/form?mode=off'"> off</label>
    </div>

    <p>Complete the challenge and submit to verify with remoteip_leniency="${mode}"</p>
    <form method="POST" action="/form?mode=${mode}">
      <div class="cf-turnstile" data-sitekey="${env.TURNSTILE_SITE_KEY}"></div>
      <br>
      <input type="submit" value="Verify Token">
    </form>
  </div>
</body>
</html>
      `;

      return new Response(formHtml, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (request.method === 'POST') {
      const mode = url.searchParams.get('mode') as 'strict' | 'relaxed' | 'off' | null;
      return handleTurnstileVerification(request, env, mode);
    }

    return new Response('Method not allowed', { status: 405 });
  }
};