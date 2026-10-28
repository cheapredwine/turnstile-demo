// Turnstile Demo Worker: remoteip_leniency with staged enforcement
//
// The siteverify `remoteip_leniency` parameter is undocumented. This demo treats the
// selected/env-configured mode as the STARTING enforcement level and falls back through
// progressively looser levels (strict → relaxed → off) when a call fails specifically on
// IP grounds ("invalid-input-response"). Failed IP checks do not consume the token; the
// first successful call does. This makes the failure classification observable:
//   - passed at the starting level  → no IP mismatch
//   - passed at a later level       → mismatch detected (earlier levels would have blocked)
//   - all levels failed             → token invalid for other reasons (expired/reused/etc.)

export type LeniencyMode = "strict" | "relaxed" | "off";
type MismatchMode = "none" | "subnet" | "asn";
type MismatchAction = "allow" | "block";

const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const SITEVERIFY_TIMEOUT_MS = 10_000;
const MAX_TOKEN_LENGTH = 2048;
const ASN_MISMATCH_IP = "8.8.8.8";
/** Canonical siteverify gate: the widget embeds data-action="form"; tokens must carry it. */
const EXPECTED_ACTION = "form";

// Result pages are static HTML (no external scripts) — lock them down hard.
const STATIC_PAGE_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'";
// The form page loads the Turnstile script + widget iframe and uses inline styles/scripts.
const FORM_PAGE_CSP =
  "default-src 'self'; " +
  "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; " +
  "style-src 'self' 'unsafe-inline'; " +
  "frame-src https://challenges.cloudflare.com; " +
  "connect-src 'self' https://challenges.cloudflare.com; " +
  "base-uri 'self'; form-action 'self'";

interface TurnstileVerifyResponse {
  success: boolean;
  "error-codes": string[];
  challenge_ts?: string;
  hostname?: string;
  action?: string;
  remoteip_leniency?: string;
}

export interface Env {
  TURNSTILE_SECRET: string;
  TURNSTILE_SITE_KEY: string;
  REMOTEIP_LENIENCY?: LeniencyMode;
  /** Optional comma-separated hostname allowlist checked against siteverify's `hostname`. Unset = no enforcement. */
  TURNSTILE_HOSTNAMES?: string;
}

interface CallRecord {
  level: LeniencyMode;
  result: TurnstileVerifyResponse;
  durationMs: number;
}

function isLeniencyMode(value: unknown): value is LeniencyMode {
  return value === "strict" || value === "relaxed" || value === "off";
}

function isMismatchMode(value: unknown): value is MismatchMode {
  return value === "none" || value === "subnet" || value === "asn";
}

function isMismatchAction(value: unknown): value is MismatchAction {
  return value === "allow" || value === "block";
}

/** Canonical siteverify check: the token's action must match the widget's data-action. */
function isActionAllowed(result: TurnstileVerifyResponse): boolean {
  return result.action === EXPECTED_ACTION;
}

/** Comma-separated TURNSTILE_HOSTNAMES → allowlist set; null when unset (no enforcement). */
function expectedHostnames(env: Env): Set<string> | null {
  const raw = env.TURNSTILE_HOSTNAMES;
  if (!raw) return null;
  const list = raw
    .split(",")
    .map((hostname) => hostname.trim().toLowerCase())
    .filter(Boolean);
  return list.length > 0 ? new Set(list) : null;
}

/** Optional hostname allowlist enforcement (no-op when TURNSTILE_HOSTNAMES is unset). */
function isHostnameAllowed(result: TurnstileVerifyResponse, env: Env): boolean {
  const allowed = expectedHostnames(env);
  if (!allowed) return true;
  return result.hostname !== undefined && allowed.has(result.hostname.toLowerCase());
}

/** Enforcement levels to try, in order, starting at the configured level. */
function enforcementSequence(start: LeniencyMode): LeniencyMode[] {
  switch (start) {
    case "strict":
      return ["strict", "relaxed", "off"];
    case "relaxed":
      return ["relaxed", "off"];
    case "off":
      return ["off"];
  }
}

const HTML_ENTITIES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => HTML_ENTITIES[ch]);
}

function isTurnstileVerifyResponse(value: unknown): value is TurnstileVerifyResponse {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.success === "boolean" &&
    (record["error-codes"] === undefined || Array.isArray(record["error-codes"]))
  );
}

export async function verifyTurnstileToken(
  token: string,
  clientIp: string | null,
  env: Env,
  leniencyMode?: LeniencyMode,
): Promise<TurnstileVerifyResponse> {
  const formData = new FormData();
  formData.append("secret", env.TURNSTILE_SECRET);
  formData.append("response", token);
  formData.append("remoteip_leniency", leniencyMode ?? env.REMOTEIP_LENIENCY ?? "strict");
  // remoteip is optional; omit it entirely when we don't know the client IP.
  if (clientIp) formData.append("remoteip", clientIp);

  const response = await fetch(SITEVERIFY_URL, {
    body: formData,
    method: "POST",
    signal: AbortSignal.timeout(SITEVERIFY_TIMEOUT_MS),
  });

  if (!response.ok) {
    throw new Error(`siteverify returned HTTP ${response.status}`);
  }

  const payload: unknown = await response.json();
  if (!isTurnstileVerifyResponse(payload)) {
    throw new Error("siteverify returned an unexpected payload");
  }

  return { ...payload, "error-codes": payload["error-codes"] ?? [] };
}

/**
 * Simulates an IP mismatch between the real client IP and the IP sent to siteverify.
 * IPv6 visitors are not supported by the same-subnet simulation; the real IP is sent
 * unchanged and the mismatch description says so.
 */
function simulateIpMismatch(
  realClientIp: string,
  mismatchMode: MismatchMode,
): { sentIp: string | null; mismatchDescription: string } {
  if (mismatchMode === "none") {
    return { sentIp: realClientIp || null, mismatchDescription: "" };
  }
  if (!realClientIp) {
    return { sentIp: null, mismatchDescription: "no client IP available — no remoteip sent" };
  }
  if (mismatchMode === "asn") {
    return { sentIp: ASN_MISMATCH_IP, mismatchDescription: "DIFFERENT ASN" };
  }
  if (realClientIp.includes(":")) {
    return {
      sentIp: realClientIp,
      mismatchDescription: "IPv6 — same-subnet simulation unsupported, real IP sent",
    };
  }
  const parts = realClientIp.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d+$/.test(part))) {
    return { sentIp: realClientIp, mismatchDescription: "" };
  }
  const lastOctet = Number.parseInt(parts[3], 10);
  const newOctet = lastOctet >= 255 ? 1 : lastOctet + 1;
  return {
    sentIp: `${parts[0]}.${parts[1]}.${parts[2]}.${newOctet}`,
    mismatchDescription: "SAME SUBNET",
  };
}

function textResponse(status: number, body: string): Response {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    },
  });
}

function htmlResponse(status: number, body: string, csp: string): Response {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy": csp,
    },
  });
}

function ipLabel(ip: string | null): string {
  return ip ? escapeHtml(ip) : "(not sent)";
}

function errorCodes(result: TurnstileVerifyResponse): string[] {
  return result["error-codes"] ?? [];
}

function renderCallTimeline(calls: CallRecord[], token: string, sentIp: string | null): string {
  return calls
    .map((call, index) => {
      const badge = call.result.success ? "success" : "fail";
      const label = call.result.success ? "PASSED ✓" : "FAILED ✗";
      const detail = call.result.success
        ? `<span class="label">Note:</span> token consumed at this level ✓`
        : `<span class="label">Error:</span> [${errorCodes(call.result)
            .map(escapeHtml)
            .join(", ")}]<br>
            <span class="label">Note:</span> token NOT consumed (IP check failed before token store)`;
      return `
      <div class="call ${badge}">
        <div class="call-header">
          📞 Call #${index + 1}: siteverify with remoteip_leniency="${call.level}"
          <span class="badge ${badge}">${label}</span>
          <span class="muted">(${call.durationMs}ms)</span>
        </div>
        <div class="request">
          POST ${SITEVERIFY_URL}<br>
          secret: [REDACTED]<br>
          response: ${escapeHtml(token.slice(0, 40))}${token.length > 40 ? "…" : ""}<br>
          remoteip: ${ipLabel(sentIp)}<br>
          <strong>remoteip_leniency: ${call.level}</strong>
        </div>
        <div class="call-detail">${detail}</div>
      </div>`;
    })
    .join("\n");
}

function renderResponseDetails(calls: CallRecord[]): string {
  const blocks = calls
    .map(
      (call, index) =>
        `<h4>Call #${index + 1} (${call.level}) Response:</h4>
         <pre>${escapeHtml(JSON.stringify(call.result, null, 2))}</pre>`,
    )
    .join("\n");
  return `
    <details>
      <summary>View Full API Responses</summary>
      ${blocks}
    </details>`;
}

function mismatchClassification(calls: CallRecord[]): string {
  const passed = calls.find((call) => call.result.success);
  if (passed?.level === "relaxed") {
    return `
      • <strong>Strict-only mismatch</strong> (call passed at relaxed)<br>
      • IP mismatch level: same ASN + same subnet, different exact IP
        (or IPv4↔IPv6 cross-family on the same ASN, or a private/loopback IP)<br>
      • Would be blocked by: strict only<br>
      • Would pass: relaxed and off`;
  }
  return `
      • <strong>Relaxed-level mismatch</strong> (call passed at off)<br>
      • IP mismatch level: different ASN, or same ASN + different subnet (IPv4 /24, IPv6 /64)<br>
      • Would be blocked by: strict and relaxed<br>
      • Would pass: off only`;
}

interface PageContext {
  token: string;
  sentIp: string | null;
  realClientIp: string;
  mismatchDescription: string;
}

function renderSuccessPage(calls: CallRecord[], ctx: PageContext): string {
  const first = calls[0];
  return `
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
    .muted { color: #6c757d; font-size: 12px; font-weight: normal; }
    .call { background: #fff; border-left: 4px solid #28a745; padding: 15px; margin: 15px 0; border-radius: 4px; }
    .call-header { font-weight: bold; font-size: 16px; margin-bottom: 10px; }
    .call-detail { font-family: monospace; font-size: 13px; margin: 5px 0; }
    .request { background: #f8f9fa; padding: 10px; margin: 10px 0; border-radius: 4px; font-family: monospace; font-size: 12px; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }
    .badge.success { background: #28a745; color: white; }
    pre { background: #2d2d2d; color: #f8f8f2; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 12px; }
    summary { cursor: pointer; color: #0056b3; font-weight: bold; }
    a { display: inline-block; margin-top: 20px; color: #0056b3; }
  </style>
</head>
<body>
  <div class="success">
    <h2>✅ Turnstile Verification Successful</h2>

    <div class="info">
      <strong>No IP mismatch.</strong><br>
      The first call passed at <code>remoteip_leniency="${first.level}"</code> — the IP matched the
      starting enforcement level, so no fallback was needed (${calls.length} call${calls.length === 1 ? "" : "s"} made).
    </div>

    <div class="result">
      <div><span class="label">Staged Result:</span> passed at ${first.level} (stopped at call #1)</div>
      <div><span class="label">Duration:</span> ${first.durationMs}ms</div>
      <div><span class="label">Real Client IP:</span> ${ctx.realClientIp ? escapeHtml(ctx.realClientIp) : "unknown"}</div>
      <div><span class="label">IP Sent to Verify:</span> ${ipLabel(ctx.sentIp)}${ctx.mismatchDescription ? ` (${escapeHtml(ctx.mismatchDescription)})` : ""}</div>
      <div><span class="label">Challenge TS:</span> ${escapeHtml(first.result.challenge_ts || "N/A")}</div>
      <div><span class="label">Hostname:</span> ${escapeHtml(first.result.hostname || "N/A")}</div>
    </div>

    ${renderCallTimeline(calls, ctx.token, ctx.sentIp)}
    ${renderResponseDetails(calls)}
    <a href="/form">← Try again</a>
  </div>
</body>
</html>`;
}

function renderMismatchPage(calls: CallRecord[], ctx: PageContext, action: MismatchAction): string {
  const shouldBlock = action === "block";
  const passedLevel = calls.find((call) => call.result.success)?.level ?? "off";
  return `
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
    .muted { color: #6c757d; font-size: 12px; font-weight: normal; }
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
    <h2>⚠️ IP Mismatch Detected (Staged Enforcement)</h2>
    <p>The starting level blocked the token on IP grounds, but a looser level accepted it.
       Here's the full call timeline:</p>

    <h3>Call Timeline</h3>
    <div class="timeline">
      ${renderCallTimeline(calls, ctx.token, ctx.sentIp)}
    </div>

    <div class="conclusion">
      <strong>🔍 Conclusion:</strong><br>
      ${mismatchClassification(calls)}<br>
      • Real IP: ${ctx.realClientIp ? escapeHtml(ctx.realClientIp) : "unknown"}<br>
      • Sent IP: ${ipLabel(ctx.sentIp)}${ctx.mismatchDescription ? ` (${escapeHtml(ctx.mismatchDescription)})` : ""}<br>
      • Token consumed at: <code>remoteip_leniency="${passedLevel}"</code>
    </div>

    <h3>Action Taken: ${shouldBlock ? "🚫 Hard Block" : "✅ Allow + Flag"}</h3>
    ${
      shouldBlock
        ? `
    <div style="background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin: 15px 0;">
      <strong>Request BLOCKED</strong><br>
      • IP mismatch detected → rejecting request (HTTP 401)<br>
      • ⚠️ <strong>Attacker knows they were detected</strong><br>
      • Use case: high-security scenarios where false positives are acceptable
    </div>
    `
        : `
    <div style="background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin: 15px 0;">
      <strong>Request ALLOWED + FLAGGED</strong><br>
      • IP mismatch detected but allowing request (HTTP 200)<br>
      • Session/account flagged for review<br>
      • ✓ <strong>Attacker doesn't know they're being tracked</strong> (shadow ban)<br>
      • Use case: gather intel, avoid false-positive friction
    </div>
    `
    }

    <p><strong>Other options you could implement:</strong></p>
    <ul>
      <li><strong>Step-Up Auth:</strong> require MFA, email code, or another challenge</li>
      <li><strong>Rate Limit:</strong> increase friction without blocking</li>
      <li><strong>Conditional Block:</strong> decide on risk score, user history, etc.</li>
    </ul>

    ${renderResponseDetails(calls)}
    <a href="/form">← Try again</a>
  </div>
</body>
</html>`;
}

function renderFailurePage(
  calls: CallRecord[],
  ctx: PageContext,
  syntheticCodes: string[] = [],
): string {
  const last = calls[calls.length - 1];
  const lastResult = last.result;
  const displayedCodes = [...errorCodes(lastResult), ...syntheticCodes];
  const stagedSummary =
    calls.length > 1
      ? `
    <div class="staged">
      <strong>Staged Enforcement Result:</strong><br>
      ${calls
        .map(
          (call, index) =>
            `• Call #${index + 1} (${call.level}) → failed: [${errorCodes(call.result)
              .map(escapeHtml)
              .join(", ")}]`,
        )
        .join("<br>")}<br>
      • <strong>Conclusion:</strong> token invalid for reasons other than IP
        (expired, reused, malformed, rule-blocked, etc.)
    </div>`
      : "";
  const gateSummary = syntheticCodes.length
    ? `
    <div class="staged">
      <strong>Validation Gate:</strong><br>
      • siteverify succeeded, but the canonical validation gate rejected the token:<br>
      • ${syntheticCodes
        .map((code) => `<code>${escapeHtml(code)}</code>`)
        .join(
          ", ",
        )} — action must be <code>${EXPECTED_ACTION}</code>${syntheticCodes.includes("hostname-not-allowed") ? " and the hostname must be in the TURNSTILE_HOSTNAMES allowlist" : ""}<br>
      • Request rejected (fail closed, HTTP 401)
    </div>`
    : "";
  return `
<!DOCTYPE html>
<html>
<head>
  <title>Verification Failed</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 700px; margin: 50px auto; padding: 20px; }
    .error { border: 2px solid #dc3545; padding: 20px; border-radius: 8px; background: #f8d7da; }
    h2 { color: #dc3545; }
    .errors { background: #fff; padding: 10px; margin: 15px 0; border-radius: 4px; }
    .staged { background: #f8f9fa; padding: 10px; margin: 15px 0; border-left: 4px solid #dc3545; font-size: 14px; }
    pre { background: #fff; padding: 10px; margin-top: 10px; overflow-x: auto; }
    details { margin-top: 15px; }
    summary { cursor: pointer; color: #dc3545; }
    a { display: inline-block; margin-top: 20px; color: #0056b3; }
  </style>
</head>
<body>
  <div class="error">
    <h2>❌ Verification Failed</h2>
    <div class="errors">
      <strong>Error codes:</strong> ${displayedCodes.map(escapeHtml).join(", ")}<br><br>
      <strong>Real Client IP:</strong> ${ctx.realClientIp ? escapeHtml(ctx.realClientIp) : "unknown"}<br>
      <strong>IP Sent to Verify:</strong> ${ipLabel(ctx.sentIp)}${ctx.mismatchDescription ? ` (${escapeHtml(ctx.mismatchDescription)})` : ""}
    </div>
    ${stagedSummary}
    ${gateSummary}
    ${renderResponseDetails(calls)}
    <a href="/form">← Try again</a>
  </div>
</body>
</html>`;
}

export async function handleTurnstileVerification(
  request: Request,
  env: Env,
  modeOverride?: string | null,
  mismatchOverride?: string | null,
  actionOverride?: string | null,
): Promise<Response> {
  try {
    const formData = await request.formData();
    const tokenField = formData.get("cf-turnstile-response");
    const token = typeof tokenField === "string" ? tokenField : "";

    if (!token) {
      return textResponse(400, "No Turnstile token provided");
    }
    if (token.length > MAX_TOKEN_LENGTH) {
      return textResponse(400, "Turnstile token too long");
    }

    const realClientIp = request.headers.get("CF-Connecting-IP") ?? "";
    const mismatchMode = isMismatchMode(mismatchOverride) ? mismatchOverride : "none";
    const action = isMismatchAction(actionOverride) ? actionOverride : "allow";
    const { sentIp, mismatchDescription } = simulateIpMismatch(realClientIp, mismatchMode);

    const startLevel = isLeniencyMode(modeOverride)
      ? modeOverride
      : (env.REMOTEIP_LENIENCY ?? "strict");

    const calls: CallRecord[] = [];
    for (const level of enforcementSequence(startLevel)) {
      const startedAt = Date.now();
      let result: TurnstileVerifyResponse;
      try {
        result = await verifyTurnstileToken(token, sentIp, env, level);
      } catch (error) {
        // Transport/HTTP/payload failure — fail closed with a synthetic error code.
        // Structured log for Workers Logs; never log tokens or secrets.
        console.error(
          JSON.stringify({
            event: "siteverify_call_failed",
            level,
            message: error instanceof Error ? error.message : String(error),
          }),
        );
        result = { success: false, "error-codes": ["internal-error"] };
      }
      calls.push({ level, result, durationMs: Date.now() - startedAt });
      if (result.success) break;
      // Only keep falling back when the failure looks like an IP-policy block.
      if (!errorCodes(result).includes("invalid-input-response")) break;
    }

    const ctx: PageContext = { token, sentIp, realClientIp, mismatchDescription };
    const first = calls[0];
    const passed = calls.find((call) => call.result.success);

    // Canonical siteverify gate on the successful result: expected action + optional hostname allowlist.
    let gateCode: string | null = null;
    if (passed) {
      if (!isActionAllowed(passed.result)) gateCode = "action-not-allowed";
      else if (!isHostnameAllowed(passed.result, env)) gateCode = "hostname-not-allowed";
    }

    if (first.result.success && !gateCode) {
      return htmlResponse(200, renderSuccessPage(calls, ctx), STATIC_PAGE_CSP);
    }
    if (passed && !gateCode) {
      return htmlResponse(
        action === "block" ? 401 : 200,
        renderMismatchPage(calls, ctx, action),
        STATIC_PAGE_CSP,
      );
    }
    return htmlResponse(
      401,
      renderFailurePage(calls, ctx, gateCode ? [gateCode] : []),
      STATIC_PAGE_CSP,
    );
  } catch (error) {
    // Malformed form body or unexpected error — fail closed without leaking internals.
    console.error(
      JSON.stringify({
        event: "handler_error",
        message: error instanceof Error ? error.message : String(error),
      }),
    );
    return textResponse(500, "Internal error");
  }
}

const BASE_STYLES = `
    body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; line-height: 1.6; }
    .container { border: 1px solid #ddd; padding: 30px; border-radius: 8px; }
    h1 { color: #0056b3; margin-bottom: 10px; }
    h2 { color: #333; margin-top: 30px; border-bottom: 2px solid #0056b3; padding-bottom: 5px; }
    h3 { color: #555; margin-top: 25px; }
    .info { background: #f0f8ff; padding: 15px; margin: 20px 0; border-left: 4px solid #0066cc; }
    .btn { display: inline-block; background: #0056b3; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin-top: 20px; }
    .btn:hover { background: #004494; }
    code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; color: #c7254e; }
    pre { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 4px; overflow-x: auto; line-height: 1.4; }
    pre strong { color: #f92672; }
    ul { margin: 15px 0; }
    li { margin: 10px 0; }
    table { border-collapse: collapse; margin: 15px 0; }
    th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; font-size: 14px; }
    th { background: #f0f8ff; }
    em { color: #666; }
`;

function renderIndexPage(startLevel: LeniencyMode): string {
  return `
<!DOCTYPE html>
<html>
<head>
  <title>Turnstile remoteip_leniency Demo</title>
  <style>${BASE_STYLES}</style>
</head>
<body>
  <div class="container">
    <h1>Turnstile remoteip_leniency Demo</h1>
    <div class="info">
      <strong>Current Configuration:</strong> starting enforcement level = "${startLevel}"
    </div>
    <h2>What is remoteip_leniency?</h2>
    <p>An <strong>undocumented parameter</strong> for Turnstile's <code>/siteverify</code> API that controls IP address validation strictness.</p>

    <h3>The Three Modes</h3>
    <ul>
      <li><code>off</code> — <strong>No IP enforcement.</strong> Token validated on all other criteria only.</li>
      <li><code>strict</code> — <strong>Exact IP match required.</strong> Rejects if the verifying IP ≠ token solve IP.</li>
      <li><code>relaxed</code> — <strong>Same ASN/subnet required.</strong> Rejects on different ASN, different subnet (IPv4 /24, IPv6 /64), or invalid IP. Allows same-ASN changes, IPv4↔IPv6 cross-family (same ASN), private/loopback IPs.</li>
    </ul>

    <h3>The Problem: No IP Mismatch Signal</h3>
    <p>When <code>strict</code> or <code>relaxed</code> blocks a token due to IP mismatch, the response is:</p>
    <pre>{ "success": false, "error-codes": ["invalid-input-response"] }</pre>
    <p>This is the <strong>same error code</strong> as expired, reused, or malformed tokens. <strong>You can't tell IP mismatch from other failures.</strong></p>

    <h3>The Workaround: Staged Enforcement</h3>
    <p>Call siteverify with progressively looser IP enforcement using the <em>same</em> token. Tokens are consumed
       only on successful validation, and failed IP checks don't consume them — so where the cascade stops tells you
       exactly which levels would have blocked:</p>
    <pre>1. Start at your chosen enforcement level (e.g. strict)
   → success: true  → allow (IP matched at that level)
   → success: false with "invalid-input-response":

2. Retry the SAME token at the next looser level (relaxed → off)
   → success: true  → IP mismatch detected! The earlier level(s) would have blocked.
   → success: false → token invalid for another reason (reject)</pre>
    <p><strong>Production guidance:</strong> you normally only need <strong>two calls</strong> — your enforcement
       level, then <code>off</code> as the diagnostic. The intermediate <code>relaxed</code> call only adds
       classification granularity (same-subnet vs cross-ASN), which is this demo's purpose.</p>

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

    <h3>Decision Matrix (starting at strict)</h3>
    <table>
      <tr><th>Call #1 (strict)</th><th>Call #2 (relaxed)</th><th>Call #3 (off)</th><th>Meaning</th><th>Calls</th></tr>
      <tr><td>✅ pass</td><td>—</td><td>—</td><td>Exact IP match</td><td>1</td></tr>
      <tr><td>❌ fail</td><td>✅ pass</td><td>—</td><td>Same ASN + subnet, different IP</td><td>2</td></tr>
      <tr><td>❌ fail</td><td>❌ fail</td><td>✅ pass</td><td>Different ASN or subnet</td><td>3</td></tr>
      <tr><td>❌ fail</td><td>❌ fail</td><td>❌ fail</td><td>Token invalid (expired/reused/…)</td><td>3</td></tr>
    </table>
    <p><em>Starting at relaxed skips call #1 (relaxed → off); starting at off makes a single call.</em></p>

    <h3>Key Behaviors</h3>
    <ul>
      <li>Failed IP checks <strong>don't consume the token</strong> (IP check happens before the token store).</li>
      <li>The first successful call consumes the token.</li>
      <li>Only <code>invalid-input-response</code> failures trigger fallback — non-IP errors stop the cascade.</li>
      <li>⚠️ <code>remoteip_leniency</code> is <strong>undocumented</strong> and may change or disappear without notice.</li>
    </ul>

    <a href="/form" class="btn">Try the Demo →</a>
  </div>
</body>
</html>`;
}

function renderFormPage(
  siteKey: string,
  mode: LeniencyMode,
  mismatch: MismatchMode,
  action: MismatchAction,
): string {
  const subnetNote =
    mismatch === "subnet"
      ? `<div class="warning">
          <strong>⚠️ Same Subnet Mismatch Mode</strong><br>
          We'll send (last octet + 1) to siteverify instead of your real IP. Expected: the cascade stops
          one level earlier if the IPs share the same ASN. IPv6 visitors: same-subnet simulation is
          unsupported — your real IP is sent unchanged.
        </div>`
      : "";
  const asnNote =
    mismatch === "asn"
      ? `<div class="warning" style="background: #ffe4e1;">
          <strong>⚠️ Different ASN Mismatch Mode</strong><br>
          Sending 8.8.8.8 (Google, ASN 15169) instead of your real IP. Expected: strict and relaxed both
          fail, off passes.
        </div>`
      : "";
  return `
<!DOCTYPE html>
<html>
<head>
  <title>Turnstile Demo — starting level: ${mode}</title>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>
    ${BASE_STYLES}
    input[type="submit"] { background: #0056b3; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
    input[type="submit"]:hover { background: #004494; }
    .cf-turnstile { margin: 20px 0; }
    .warning { background: #fff3cd; padding: 10px; margin-bottom: 20px; border-left: 4px solid #ffc107; }
    .toggle { margin: 15px 0; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px; }
    .toggle label { margin-right: 15px; cursor: pointer; display: inline-block; margin-top: 5px; }
    .toggle input[type="radio"] { margin-right: 5px; }
  </style>
</head>
<body>
  <div class="container">
    <h2>Turnstile remoteip_leniency Demo</h2>
    <div class="info">
      <strong>Starting enforcement level:</strong> ${mode}<br>
      <strong>Purpose:</strong> test the undocumented remoteip_leniency parameter and observe staged fallback
    </div>

    <div class="toggle">
      <strong>Starting Enforcement Level</strong> (first siteverify call; falls back to looser levels on IP failure):<br><br>
      <label><input type="radio" name="mode" value="strict" ${mode === "strict" ? "checked" : ""} onchange="updateMode('strict')"> strict → relaxed → off (3 calls max)</label><br>
      <label><input type="radio" name="mode" value="relaxed" ${mode === "relaxed" ? "checked" : ""} onchange="updateMode('relaxed')"> relaxed → off (2 calls max)</label><br>
      <label><input type="radio" name="mode" value="off" ${mode === "off" ? "checked" : ""} onchange="updateMode('off')"> off only (1 call, no IP check)</label>
    </div>

    <div class="toggle">
      <strong>IP Mismatch Simulation:</strong><br><br>
      <label><input type="radio" name="mismatch" value="none" ${mismatch === "none" ? "checked" : ""} onchange="updateMismatch()"> No mismatch (send real IP)</label><br>
      <label><input type="radio" name="mismatch" value="subnet" ${mismatch === "subnet" ? "checked" : ""} onchange="updateMismatch()"> Same subnet (your IP + 1)</label><br>
      <label><input type="radio" name="mismatch" value="asn" ${mismatch === "asn" ? "checked" : ""} onchange="updateMismatch()"> Different ASN (8.8.8.8)</label>
    </div>

    <div class="toggle">
      <strong>Action on IP Mismatch Detection:</strong><br><br>
      <label><input type="radio" name="action" value="allow" ${action === "allow" ? "checked" : ""} onchange="updateAction()"> Allow + Flag (shadow ban — attacker doesn't know)</label><br>
      <label><input type="radio" name="action" value="block" ${action === "block" ? "checked" : ""} onchange="updateAction()"> Hard Block (reject — attacker knows immediately)</label>
    </div>

    ${subnetNote}
    ${asnNote}

    <div class="info" style="font-size: 14px;">
      <strong>What happens when you submit:</strong><br>
      Call #1 uses the selected level. If it fails with <code>invalid-input-response</code> (the IP-policy
      error), the same token is retried at the next looser level. The cascade stops at the first success —
      the page shows which levels would have blocked.
    </div>

    <p>Complete the challenge and submit:</p>
    <form method="POST" action="/form?mode=${mode}&mismatch=${mismatch}&action=${action}">
      <div class="cf-turnstile" data-sitekey="${escapeHtml(siteKey)}" data-action="${EXPECTED_ACTION}"></div>
      <br>
      <input type="submit" value="Verify Token">
    </form>
  </div>
  <script>
    function buildUrl() {
      const mode = document.querySelector('input[name="mode"]:checked').value;
      const mismatch = document.querySelector('input[name="mismatch"]:checked').value;
      const action = document.querySelector('input[name="action"]:checked').value;
      return '/form?mode=' + encodeURIComponent(mode) + '&mismatch=' + encodeURIComponent(mismatch) + '&action=' + encodeURIComponent(action);
    }
    function updateMode() { location.href = buildUrl(); }
    function updateMismatch() { location.href = buildUrl(); }
    function updateAction() { location.href = buildUrl(); }
  </script>
</body>
</html>`;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;

    if (pathname === "/" && (request.method === "GET" || request.method === "HEAD")) {
      const startLevel = isLeniencyMode(env.REMOTEIP_LENIENCY) ? env.REMOTEIP_LENIENCY : "strict";
      return htmlResponse(200, renderIndexPage(startLevel), STATIC_PAGE_CSP);
    }

    if (pathname === "/form") {
      if (request.method === "GET" || request.method === "HEAD") {
        const defaultLevel = isLeniencyMode(env.REMOTEIP_LENIENCY)
          ? env.REMOTEIP_LENIENCY
          : "strict";
        const requested = url.searchParams.get("mode");
        const mismatchParam = url.searchParams.get("mismatch");
        const actionParam = url.searchParams.get("action");
        const mode = isLeniencyMode(requested) ? requested : defaultLevel;
        const mismatch = isMismatchMode(mismatchParam) ? mismatchParam : "none";
        const action = isMismatchAction(actionParam) ? actionParam : "allow";
        return htmlResponse(
          200,
          renderFormPage(env.TURNSTILE_SITE_KEY, mode, mismatch, action),
          FORM_PAGE_CSP,
        );
      }
      if (request.method === "POST") {
        return handleTurnstileVerification(
          request,
          env,
          url.searchParams.get("mode"),
          url.searchParams.get("mismatch"),
          url.searchParams.get("action"),
        );
      }
      return textResponse(405, "Method not allowed");
    }

    return textResponse(404, "Not found");
  },
};
