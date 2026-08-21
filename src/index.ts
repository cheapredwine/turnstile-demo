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
  mismatchIp?: boolean,
  action?: string
): Promise<Response> {
  try {
    const formData = await request.formData();
    const token = formData.get('cf-turnstile-response') as string;
    const realClientIp = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
    // Use fake IP (Google DNS - definitely different ASN) to simulate mismatch
    // 192.0.2.1 is TEST-NET-1 which relaxed mode may treat as private/special
    const clientIp = mismatchIp ? '8.8.8.8' : realClientIp;

    if (!token) {
      return new Response('No Turnstile token provided', { status: 400 });
    }

    const mode = modeOverride || env.REMOTEIP_LENIENCY || 'strict';
    
    // First call with specified mode
    const startTime1 = Date.now();
    const verificationResult = await verifyTurnstileToken(token, clientIp, env, mode);
    const duration1 = Date.now() - startTime1;
    
    let ipMismatchDetected = false;
    let secondCallResult = null;
    let duration2 = 0;

    // Double-call workaround: if first call failed and mode wasn't 'off', retry with 'off'
    if (!verificationResult.success && mode !== 'off' && 
        verificationResult["error-codes"].includes("invalid-input-response")) {
      const startTime2 = Date.now();
      secondCallResult = await verifyTurnstileToken(token, clientIp, env, 'off');
      duration2 = Date.now() - startTime2;
      
      if (secondCallResult.success) {
        // First call failed on IP enforcement, second succeeded without it
        ipMismatchDetected = true;
      }
    }

    // Handle IP mismatch detection (double-call succeeded on retry with 'off')
    if (ipMismatchDetected && secondCallResult) {
      const shouldBlock = action === 'block';
      const warningHtml = `
<!DOCTYPE html>
<html>
<head>
  <title>IP Mismatch Detected</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; line-height: 1.6; }
    .warning { border: 2px solid #ffc107; padding: 20px; border-radius: 8px; background: #fff3cd; }
    h2 { color: #856404; }
    h3 { color: #666; margin-top: 25px; }
    .timeline { margin: 20px 0; }
    .call { background: #fff; border-left: 4px solid #dc3545; padding: 15px; margin: 15px 0; border-radius: 4px; }
    .call.success { border-left-color: #28a745; }
    .call-header { font-weight: bold; font-size: 16px; margin-bottom: 10px; }
    .call-detail { font-family: monospace; font-size: 13px; margin: 5px 0; }
    .label { font-weight: bold; color: #555; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }
    .badge.fail { background: #dc3545; color: white; }
    .badge.success { background: #28a745; color: white; }
    .request { background: #f8f9fa; padding: 10px; margin: 10px 0; border-radius: 4px; font-family: monospace; font-size: 12px; }
    .conclusion { background: #f8f9fa; padding: 15px; margin: 20px 0; border-left: 4px solid #ffc107; }
    details { margin: 15px 0; }
    summary { cursor: pointer; color: #856404; font-weight: bold; }
    pre { background: #2d2d2d; color: #f8f8f2; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 12px; }
    a { display: inline-block; margin-top: 20px; color: #0056b3; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="warning">
    <h2>⚠️ IP Mismatch Detected</h2>
    <p>The double-call pattern successfully identified an IP mismatch. Here's what happened:</p>

    <h3>Call Timeline</h3>
    <div class="timeline">
      <div class="call">
        <div class="call-header">
          📞 Call #1: siteverify with remoteip_leniency="${mode}"
          <span class="badge fail">FAILED</span>
          <span style="color: #999; font-size: 12px; font-weight: normal;">(${duration1}ms)</span>
        </div>
        <div class="request">
          POST https://challenges.cloudflare.com/turnstile/v0/siteverify<br>
          secret: [REDACTED]<br>
          response: ${token.substring(0, 40)}...<br>
          remoteip: ${clientIp}<br>
          <strong>remoteip_leniency: ${mode}</strong>
        </div>
        <div class="call-detail">
          <span class="label">Result:</span> success: false<br>
          <span class="label">Error:</span> ["invalid-input-response"]<br>
          <span class="label">Reason:</span> IP mismatch (real IP: ${realClientIp}, sent: ${clientIp})
        </div>
      </div>

      <div class="call success">
        <div class="call-header">
          📞 Call #2: Retry with remoteip_leniency="off"
          <span class="badge success">SUCCESS</span>
          <span style="color: #999; font-size: 12px; font-weight: normal;">(${duration2}ms)</span>
        </div>
        <div class="request">
          POST https://challenges.cloudflare.com/turnstile/v0/siteverify<br>
          secret: [REDACTED]<br>
          response: ${token.substring(0, 40)}... <em>(same token)</em><br>
          remoteip: ${clientIp}<br>
          <strong>remoteip_leniency: off</strong>
        </div>
        <div class="call-detail">
          <span class="label">Result:</span> success: true ✓<br>
          <span class="label">Challenge TS:</span> ${secondCallResult.challenge_ts || 'N/A'}<br>
          <span class="label">Hostname:</span> ${secondCallResult.hostname || 'N/A'}
        </div>
      </div>
    </div>

    <div class="conclusion">
      <strong>🔍 Conclusion:</strong><br>
      • First call failed due to <strong>IP enforcement</strong> (mode: ${mode})<br>
      • Second call succeeded when IP checking was disabled<br>
      • Token is valid, but IP changed between solve and verification<br>
      • <strong>This is the IP mismatch pattern</strong> — you detected it using the double-call workaround
    </div>

    <h3>Action Taken: ${shouldBlock ? '🚫 Hard Block' : '✅ Allow + Flag'}</h3>
    ${shouldBlock ? `
    <div style="background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin: 15px 0;">
      <strong>Request BLOCKED</strong><br>
      • IP mismatch detected → rejecting request (HTTP 401)<br>
      • User sees immediate failure<br>
      • ⚠️ <strong>Attacker knows they were detected</strong><br>
      • Use case: High-security scenarios where false positives are acceptable
    </div>
    ` : `
    <div style="background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin: 15px 0;">
      <strong>Request ALLOWED + FLAGGED</strong><br>
      • IP mismatch detected but allowing request (HTTP 200)<br>
      • Session/account flagged for review<br>
      • ✓ <strong>Attacker doesn't know they're being tracked</strong> (shadow ban)<br>
      • Use case: Gather intel, avoid false positive friction
    </div>
    `}

    <p><strong>Other options you could implement:</strong></p>
    <ul>
      <li><strong>Step-Up Auth:</strong> Require MFA, email code, or CAPTCHA</li>
      <li><strong>Rate Limit:</strong> Increase friction without blocking</li>
      <li><strong>Conditional Block:</strong> Block based on risk score, user history, etc.</li>
    </ul>

    <details>
      <summary>View Full API Responses</summary>
      <h4>First Call Response:</h4>
      <pre>${JSON.stringify(verificationResult, null, 2)}</pre>
      <h4>Second Call Response:</h4>
      <pre>${JSON.stringify(secondCallResult, null, 2)}</pre>
    </details>
    
    <a href="/form">← Try again</a>
  </div>
</body>
</html>`;
      return new Response(warningHtml, {
        status: shouldBlock ? 401 : 200,
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
    body { font-family: Arial, sans-serif; max-width: 700px; margin: 50px auto; padding: 20px; }
    .success { border: 2px solid #28a745; padding: 20px; border-radius: 8px; background: #d4edda; }
    .result { background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 4px; font-family: monospace; font-size: 14px; }
    .info { background: #e7f5ff; padding: 12px; margin: 15px 0; border-left: 4px solid #0066cc; font-size: 14px; }
    h2 { color: #28a745; }
    .label { font-weight: bold; }
    a { display: inline-block; margin-top: 20px; color: #0056b3; }
  </style>
</head>
<body>
  <div class="success">
    <h2>✅ Turnstile Verification Successful</h2>
    
    <div class="info">
      <strong>Single Call Success</strong><br>
      First call with <code>remoteip_leniency="${mode}"</code> succeeded immediately.<br>
      No double-call needed — IP matched the ${mode} policy (or mode is "off").
    </div>

    <div class="result">
      <div><span class="label">Mode Used:</span> ${mode}</div>
      <div><span class="label">Duration:</span> ${duration1}ms</div>
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

    <h3>Implementation Example: Double-Call Pattern</h3>
    <p>This demo implements the recommended pattern for detecting IP mismatches:</p>
    <pre>// Step 1: First call with strict/relaxed
const result1 = await verifyTurnstile(token, visitorIP, "strict");

if (result1.success) {
  return { allow: true, ipMismatch: false };
}

// Step 2: If failed, check if it was IP mismatch
if (result1["error-codes"].includes("invalid-input-response")) {
  // Retry same token with enforcement OFF
  const result2 = await verifyTurnstile(token, visitorIP, "off");
  
  if (result2.success) {
    // First failed on IP, second succeeded without enforcement
    return { 
      allow: true,  // or false - your choice
      ipMismatch: true,
      flagForReview: true 
    };
  }
}

// Both calls failed - token invalid for other reason
return { allow: false, error: result1["error-codes"] };</pre>

    <p><strong>Why it works:</strong> Tokens are consumed only on successful validation. A failed strict call followed by a successful off call proves the failure was IP-related, not token expiry/reuse/etc.</p>

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
      const action = url.searchParams.get('action') || 'allow';
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

    <div class="test-toggle">
      <strong>Action on IP Mismatch Detection:</strong><br><br>
      <label><input type="radio" name="action" value="allow" ${action === 'allow' ? 'checked' : ''} onchange="updateAction()"> Allow + Flag (shadow ban - attacker doesn't know)</label><br>
      <label><input type="radio" name="action" value="block" ${action === 'block' ? 'checked' : ''} onchange="updateAction()"> Hard Block (reject - attacker knows immediately)</label>
    </div>

    ${mismatchIp ? '<div class="warning"><strong>⚠️ IP Mismatch Mode:</strong> Will send 8.8.8.8 (Google DNS, different ASN) instead of your real IP to trigger validation failure. Works with both strict and relaxed modes.</div>' : ''}

    <div class="info" style="background: #e7f3ff; border-left-color: #0066cc; font-size: 14px;">
      <strong>What happens when you submit:</strong><br>
      ${mode !== 'off' ? `
        1️⃣ First call: siteverify with <code>remoteip_leniency="${mode}"</code><br>
        2️⃣ If first call fails with <code>invalid-input-response</code> → automatic retry with <code>remoteip_leniency="off"</code><br>
        3️⃣ If retry succeeds → <strong>IP mismatch detected!</strong> (you'll see the double-call timeline)<br>
        4️⃣ If retry also fails → token invalid for other reason (expired/reused/malformed)
      ` : `
        • Single call: siteverify with <code>remoteip_leniency="off"</code><br>
        • No double-call needed (IP enforcement already disabled)
      `}
    </div>

    <p>Complete the challenge and submit:</p>
    <form method="POST" action="/form?mode=${mode}${mismatchIp ? '&mismatch=true' : ''}${action ? '&action=' + action : ''}">
      <div class="cf-turnstile" data-sitekey="${env.TURNSTILE_SITE_KEY}"></div>
      <br>
      <input type="submit" value="Verify Token">
    </form>
  </div>
  <script>
    function buildUrl() {
      const mode = document.querySelector('input[name="mode"]:checked').value;
      const mismatch = document.getElementById('mismatch').checked;
      const action = document.querySelector('input[name="action"]:checked').value;
      return '/form?mode=' + mode + (mismatch ? '&mismatch=true' : '') + '&action=' + action;
    }
    function updateMode(mode) {
      location.href = buildUrl();
    }
    function updateMismatch() {
      location.href = buildUrl();
    }
    function updateAction() {
      location.href = buildUrl();
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
      const action = url.searchParams.get('action') || 'allow';
      return handleTurnstileVerification(request, env, mode, mismatchIp, action);
    }

    return new Response('Method not allowed', { status: 405 });
  }
};