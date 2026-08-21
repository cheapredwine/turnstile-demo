// Turnstile Demo Worker with remoteip_leniency parameter

interface TurnstileVerifyResponse {
  success: boolean;
  "error-codes": string[];
  challenge_ts?: string;
  hostname?: string;
  "remoteip_leniency"?: string;
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
  modeOverride?: 'strict' | 'relaxed' | 'off' | null,
  mismatchIp?: boolean
): Promise<Response> {
  try {
    const formData = await request.formData();
    const token = formData.get('cf-turnstile-response') as string;
    const realClientIp = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
    // Use fake IP (TEST-NET-1 from RFC 5737) to simulate mismatch
    const clientIp = mismatchIp ? '192.0.2.1' : realClientIp;

    if (!token) {
      return new Response('No Turnstile token provided', { status: 400 });
    }

    const mode = modeOverride || env.REMOTEIP_LENIENCY || 'strict';
    
    // First call with specified mode
    const verificationResult = await verifyTurnstileToken(token, clientIp, env, mode);
    let ipMismatchDetected = false;
    let secondCallResult = null;

    // Double-call workaround: if first call failed and mode wasn't 'off', retry with 'off'
    if (!verificationResult.success && mode !== 'off' && 
        verificationResult["error-codes"].includes("invalid-input-response")) {
      secondCallResult = await verifyTurnstileToken(token, clientIp, env, 'off');
      if (secondCallResult.success) {
        // First call failed on IP enforcement, second succeeded without it
        ipMismatchDetected = true;
      }
    }

    // Handle IP mismatch detection (double-call succeeded on retry with 'off')
    if (ipMismatchDetected && secondCallResult) {
      const warningHtml = `
<!DOCTYPE html>
<html>
<head>
  <title>IP Mismatch Detected</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 700px; margin: 50px auto; padding: 20px; }
    .warning { border: 2px solid #ffc107; padding: 20px; border-radius: 8px; background: #fff3cd; }
    h2 { color: #856404; }
    .result { background: #fff; padding: 15px; margin: 15px 0; border-radius: 4px; font-family: monospace; font-size: 14px; }
    .label { font-weight: bold; color: #856404; }
    .doubleCall { background: #f8f9fa; padding: 15px; margin: 15px 0; border-left: 4px solid #ffc107; }
    a { display: inline-block; margin-top: 20px; color: #0056b3; }
  </style>
</head>
<body>
  <div class="warning">
    <h2>⚠️ IP Mismatch Detected (Double-Call Pattern)</h2>
    
    <div class="doubleCall">
      <strong>What happened:</strong><br>
      1. First call with <code>${mode}</code> → failed (IP mismatch)<br>
      2. Retry with <code>off</code> → succeeded (token valid, IP enforcement was the issue)
    </div>

    <div class="result">
      <div><span class="label">First Call Mode:</span> ${mode}</div>
      <div><span class="label">First Call Result:</span> FAILED (invalid-input-response)</div>
      <div><span class="label">Second Call Mode:</span> off</div>
      <div><span class="label">Second Call Result:</span> SUCCESS ✓</div>
      <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid #ddd;">
        <span class="label">Real Client IP:</span> ${realClientIp}<br>
        <span class="label">IP Sent to Verify:</span> ${clientIp}${mismatchIp ? ' (MISMATCHED)' : ''}<br>
        <span class="label">Token:</span> Valid, but IP didn't match ${mode} policy
      </div>
    </div>

    <p><strong>Decision point:</strong> Token is valid but IP changed. You can:</p>
    <ul>
      <li><strong>Allow + Flag:</strong> Let user through but log for review (this demo allows)</li>
      <li><strong>Hard Block:</strong> Reject as suspicious (attacker knows they're detected)</li>
    </ul>

    <details>
      <summary style="cursor: pointer;">Second Call Full Response</summary>
      <pre style="background: #fff; padding: 10px; margin-top: 10px;">${JSON.stringify(secondCallResult, null, 2)}</pre>
    </details>
    
    <a href="/form">← Try again</a>
  </div>
</body>
</html>`;
      return new Response(warningHtml, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

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
    .doubleCall { background: #f8f9fa; padding: 10px; margin: 15px 0; border-left: 4px solid #dc3545; font-size: 14px; }
    a { display: inline-block; margin-top: 20px; color: #0056b3; }
  </style>
</head>
<body>
  <div class="error">
    <h2>❌ Verification Failed</h2>
    <div class="errors">
      <strong>Error codes:</strong> ${verificationResult["error-codes"].join(", ")}<br><br>
      <strong>Mode Used:</strong> ${mode}<br>
      <strong>Real Client IP:</strong> ${realClientIp}<br>
      <strong>IP Sent to Verify:</strong> ${clientIp}${mismatchIp ? ' (MISMATCHED)' : ''}
    </div>
    
    ${secondCallResult ? `
    <div class="doubleCall">
      <strong>Double-Call Pattern Result:</strong><br>
      • First call with <code>${mode}</code> → failed<br>
      • Second call with <code>off</code> → also failed<br>
      • <strong>Conclusion:</strong> Token invalid for reasons other than IP (expired, reused, malformed, etc.)
    </div>
    <details>
      <summary style="cursor: pointer;">Second Call Response</summary>
      <pre style="background: #fff; padding: 10px; margin-top: 10px;">${JSON.stringify(secondCallResult, null, 2)}</pre>
    </details>
    ` : ''}

    <details style="margin-top: 15px;">
      <summary style="cursor: pointer; color: #dc3545;">First Call Response</summary>
      <pre style="background: #fff; padding: 10px; margin-top: 10px; overflow-x: auto;">${JSON.stringify(verificationResult, null, 2)}</pre>
    </details>
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
      <div><span class="label">Mode Used:</span> ${mode} (first call only, no double-call needed)</div>
      <div><span class="label">Real Client IP:</span> ${realClientIp}</div>
      <div><span class="label">IP Sent to Verify:</span> ${clientIp}${mismatchIp ? ' (MISMATCHED)' : ''}</div>
      <div><span class="label">Challenge TS:</span> ${verificationResult.challenge_ts || 'N/A'}</div>
      <div><span class="label">Hostname:</span> ${verificationResult.hostname || 'N/A'}</div>
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
    <p>An <strong>undocumented parameter</strong> for Turnstile's <code>/siteverify</code> API that controls IP address validation strictness.</p>
    
    <h3>The Three Modes</h3>
    <ul>
      <li><code>off</code> (default) - <strong>No IP enforcement.</strong> Token validated on all other criteria only.</li>
      <li><code>strict</code> - <strong>Exact IP match required.</strong> Rejects if remote IP ≠ token solve IP. Any mismatch = rejection.</li>
      <li><code>relaxed</code> - <strong>Same ASN/subnet required.</strong> Rejects if different ASN, different subnet (IPv4 /24, IPv6 /64), or invalid IP. Allows same-ASN changes, IPv4↔IPv6 cross-family (same ASN), private/loopback IPs.</li>
    </ul>

    <h3>The Problem: No IP Mismatch Signal</h3>
    <p>When <code>strict</code> or <code>relaxed</code> blocks a token due to IP mismatch, the response is:</p>
    <pre>{ "success": false, "error-codes": ["invalid-input-response"] }</pre>
    <p>This is the <strong>same error code</strong> as expired tokens, reused tokens, malformed tokens. <strong>You can't tell if it was an IP mismatch or something else.</strong></p>

    <h3>The Double-Call Workaround</h3>
    <p>Detect IP mismatches by calling siteverify twice:</p>
    <pre>1. Call with remoteip_leniency: "strict" (or "relaxed")
   → If success: true → allow (IP matched)
   → If success: false:

2. Retry SAME token with remoteip_leniency: "off"
   → If success: true → IP mismatch detected! (flag/allow)
   → If success: false → token invalid for other reason (reject)</pre>
    <p><strong>Note:</strong> Tokens are consumed only on successful validation, so a failed strict call + successful off call works. This demo implements the double-call pattern.</p>

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
      const mismatchIp = url.searchParams.get('mismatch') === 'true';
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
    .warning { background: #fff3cd; padding: 10px; margin-bottom: 20px; border-left: 4px solid #ffc107; }
    .mode-toggle { margin: 15px 0; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px; }
    .mode-toggle label { margin-right: 15px; cursor: pointer; }
    .mode-toggle input[type="radio"] { margin-right: 5px; }
    .test-toggle { margin: 15px 0; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px; }
    .test-toggle input[type="checkbox"] { margin-right: 5px; }
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
      <label><input type="radio" name="mode" value="strict" ${mode === 'strict' ? 'checked' : ''} onchange="updateMode('strict')"> strict</label>
      <label><input type="radio" name="mode" value="relaxed" ${mode === 'relaxed' ? 'checked' : ''} onchange="updateMode('relaxed')"> relaxed</label>
      <label><input type="radio" name="mode" value="off" ${mode === 'off' ? 'checked' : ''} onchange="updateMode('off')"> off</label>
    </div>

    <div class="test-toggle">
      <label>
        <input type="checkbox" id="mismatch" ${mismatchIp ? 'checked' : ''} onchange="updateMismatch()">
        <strong>Simulate IP Mismatch</strong> (send wrong IP to demonstrate failure)
      </label>
    </div>

    ${mismatchIp ? '<div class="warning"><strong>⚠️ IP Mismatch Mode:</strong> Will send 192.0.2.1 instead of your real IP to trigger validation failure. Use this to see how each mode handles mismatches.</div>' : ''}

    <p>Complete the challenge and submit to verify with remoteip_leniency="${mode}"</p>
    <form method="POST" action="/form?mode=${mode}${mismatchIp ? '&mismatch=true' : ''}">
      <div class="cf-turnstile" data-sitekey="${env.TURNSTILE_SITE_KEY}"></div>
      <br>
      <input type="submit" value="Verify Token">
    </form>
  </div>
  <script>
    function updateMode(mode) {
      const mismatch = document.getElementById('mismatch').checked;
      location.href = '/form?mode=' + mode + (mismatch ? '&mismatch=true' : '');
    }
    function updateMismatch() {
      const mismatch = document.getElementById('mismatch').checked;
      const mode = document.querySelector('input[name="mode"]:checked').value;
      location.href = '/form?mode=' + mode + (mismatch ? '&mismatch=true' : '');
    }
  </script>
</body>
</html>
      `;

      return new Response(formHtml, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (request.method === 'POST') {
      const mode = url.searchParams.get('mode') as 'strict' | 'relaxed' | 'off' | null;
      const mismatchIp = url.searchParams.get('mismatch') === 'true';
      return handleTurnstileVerification(request, env, mode, mismatchIp);
    }

    return new Response('Method not allowed', { status: 405 });
  }
};