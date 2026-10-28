// Turnstile siteverify tests: remoteip_leniency staged enforcement (starting level + fallback cascade)

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker, {
  handleTurnstileVerification,
  verifyTurnstileToken,
  type Env,
  type LeniencyMode,
} from "../src/index";

const baseEnv: Env = {
  TURNSTILE_SECRET: "test-secret-key",
  TURNSTILE_SITE_KEY: "test-site-key",
};

const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

let mockFetch: ReturnType<typeof vi.fn>;

beforeEach(() => {
  mockFetch = vi.fn();
  vi.stubGlobal("fetch", mockFetch);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function queueSiteverify(body: unknown): void {
  mockFetch.mockResolvedValueOnce(new Response(JSON.stringify(body), { status: 200 }));
}

function postForm(token: string | null, options: { ip?: string; query?: string } = {}): Request {
  const body = new FormData();
  if (token !== null) body.append("cf-turnstile-response", token);
  const headers: Record<string, string> = options.ip ? { "CF-Connecting-IP": options.ip } : {};
  return new Request(`http://localhost/form${options.query ?? "?mode=strict"}`, {
    method: "POST",
    headers,
    body,
  });
}

const firstFormData = (): FormData => mockFetch.mock.calls[0][1].body as FormData;

const ok = (extra: Record<string, unknown> = {}) => ({
  success: true,
  "error-codes": [],
  action: "form",
  ...extra,
});
const ipFail = () => ({ success: false, "error-codes": ["invalid-input-response"] });

describe("verifyTurnstileToken", () => {
  it("sends secret, token, remoteip, and default remoteip_leniency to siteverify", async () => {
    queueSiteverify(ok());

    const result = await verifyTurnstileToken("tok", "192.168.1.1", baseEnv);

    expect(mockFetch.mock.calls[0][0]).toBe(SITEVERIFY_URL);
    expect(mockFetch).toHaveBeenCalledWith(
      SITEVERIFY_URL,
      expect.objectContaining({ method: "POST" }),
    );
    const form = firstFormData();
    expect(form.get("secret")).toBe(baseEnv.TURNSTILE_SECRET);
    expect(form.get("response")).toBe("tok");
    expect(form.get("remoteip")).toBe("192.168.1.1");
    expect(form.get("remoteip_leniency")).toBe("strict");
    expect(result.success).toBe(true);
  });

  it.each<LeniencyMode>(["strict", "relaxed", "off"])(
    "honors explicit leniency override: %s",
    async (mode) => {
      queueSiteverify(ok());

      await verifyTurnstileToken("tok", "192.168.1.1", baseEnv, mode);

      expect(firstFormData().get("remoteip_leniency")).toBe(mode);
    },
  );

  it("falls back to env.REMOTEIP_LENIENCY when no override is given", async () => {
    queueSiteverify(ok());

    await verifyTurnstileToken("tok", "192.168.1.1", { ...baseEnv, REMOTEIP_LENIENCY: "off" });

    expect(firstFormData().get("remoteip_leniency")).toBe("off");
  });

  it("omits remoteip when the client IP is unavailable", async () => {
    for (const missingIp of [null, ""]) {
      mockFetch.mockClear();
      queueSiteverify(ok());

      await verifyTurnstileToken("tok", missingIp, baseEnv);

      expect(firstFormData().get("remoteip")).toBeNull();
    }
  });

  it("fails closed (throws) on non-2xx siteverify responses", async () => {
    mockFetch.mockResolvedValueOnce(new Response("upstream exploded", { status: 503 }));

    await expect(verifyTurnstileToken("tok", "192.168.1.1", baseEnv)).rejects.toThrow(/503/);
  });

  it("fails closed on a non-JSON siteverify payload", async () => {
    mockFetch.mockResolvedValueOnce(new Response("<html>not json</html>", { status: 200 }));

    await expect(verifyTurnstileToken("tok", "192.168.1.1", baseEnv)).rejects.toThrow();
  });
});

describe("handleTurnstileVerification — input validation", () => {
  it("returns 400 when no token is provided", async () => {
    const response = await handleTurnstileVerification(postForm(null), baseEnv);

    expect(response.status).toBe(400);
    expect(await response.text()).toContain("No Turnstile token provided");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("returns 400 for oversized tokens (> 2048 chars)", async () => {
    const response = await handleTurnstileVerification(postForm("a".repeat(2049)), baseEnv);

    expect(response.status).toBe(400);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("does not retry when the failure is not IP-related", async () => {
    queueSiteverify({ success: false, "error-codes": ["timeout-or-duplicate"] });

    const response = await handleTurnstileVerification(postForm("tok"), baseEnv);

    expect(response.status).toBe(401);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(await response.text()).toContain("timeout-or-duplicate");
  });

  it("fails closed with a synthetic internal-error when siteverify throws", async () => {
    mockFetch.mockRejectedValueOnce(new Error("connection reset"));

    const response = await handleTurnstileVerification(postForm("tok"), baseEnv);

    expect(response.status).toBe(401);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(await response.text()).toContain("internal-error");
  });

  it("returns 401 when every enforcement level fails", async () => {
    queueSiteverify(ipFail());
    queueSiteverify(ipFail());
    queueSiteverify(ipFail());

    const response = await handleTurnstileVerification(postForm("tok"), baseEnv);

    expect(response.status).toBe(401);
    expect(mockFetch).toHaveBeenCalledTimes(3);
    expect(await response.text()).toContain("Verification Failed");
  });

  it("returns 401 without throwing when error-codes is missing from the response", async () => {
    queueSiteverify({ success: false });

    const response = await handleTurnstileVerification(postForm("tok"), baseEnv);

    expect(response.status).toBe(401);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});

describe("handleTurnstileVerification — starting enforcement level", () => {
  it("starts at strict by default and stops after one successful call", async () => {
    queueSiteverify(ok());

    const response = await handleTurnstileVerification(postForm("tok"), baseEnv);

    expect(response.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(firstFormData().get("remoteip_leniency")).toBe("strict");
    expect(await response.text()).toContain("Verification Successful");
  });

  it("starts at relaxed when overridden and passes on the first call", async () => {
    queueSiteverify(ok());

    const response = await handleTurnstileVerification(postForm("tok"), baseEnv, "relaxed");

    expect(response.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(firstFormData().get("remoteip_leniency")).toBe("relaxed");
  });

  it("starts at off when overridden and makes a single call", async () => {
    queueSiteverify(ok());

    const response = await handleTurnstileVerification(postForm("tok"), baseEnv, "off");

    expect(response.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(firstFormData().get("remoteip_leniency")).toBe("off");
  });

  it("uses env.REMOTEIP_LENIENCY as the starting level when no override is given", async () => {
    queueSiteverify(ok());

    await handleTurnstileVerification(postForm("tok"), {
      ...baseEnv,
      REMOTEIP_LENIENCY: "relaxed",
    });

    expect(firstFormData().get("remoteip_leniency")).toBe("relaxed");
  });

  it("falls back to relaxed when strict fails on IP grounds (2 calls)", async () => {
    queueSiteverify(ipFail());
    queueSiteverify(ok());

    const response = await handleTurnstileVerification(postForm("tok"), baseEnv, "strict");

    expect(response.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(mockFetch.mock.calls[1][1].body.get("remoteip_leniency")).toBe("relaxed");
    expect(await response.text()).toContain("IP Mismatch Detected");
  });

  it("falls back to off when strict and relaxed both fail on IP grounds (3 calls)", async () => {
    queueSiteverify(ipFail());
    queueSiteverify(ipFail());
    queueSiteverify(ok());

    const response = await handleTurnstileVerification(postForm("tok"), baseEnv, "strict");

    expect(response.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledTimes(3);
    expect(mockFetch.mock.calls[2][1].body.get("remoteip_leniency")).toBe("off");
    expect(await response.text()).toContain("IP Mismatch Detected");
  });

  it("falls back to off when relaxed (as start level) fails on IP grounds (2 calls)", async () => {
    queueSiteverify(ipFail());
    queueSiteverify(ok());

    const response = await handleTurnstileVerification(postForm("tok"), baseEnv, "relaxed");

    expect(response.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(mockFetch.mock.calls[1][1].body.get("remoteip_leniency")).toBe("off");
    expect(await response.text()).toContain("IP Mismatch Detected");
  });

  it("returns 401 when a relaxed start fails and off also fails (2 calls)", async () => {
    queueSiteverify(ipFail());
    queueSiteverify(ipFail());

    const response = await handleTurnstileVerification(postForm("tok"), baseEnv, "relaxed");

    expect(response.status).toBe(401);
    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(await response.text()).toContain("Verification Failed");
  });

  it("makes a single call for an off start and returns 401 when it fails", async () => {
    queueSiteverify(ipFail());

    const response = await handleTurnstileVerification(postForm("tok"), baseEnv, "off");

    expect(response.status).toBe(401);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});

describe("handleTurnstileVerification — action on detected mismatch", () => {
  it("hard-blocks (401) when action=block", async () => {
    queueSiteverify(ipFail());
    queueSiteverify(ok());

    const response = await handleTurnstileVerification(
      postForm("tok"),
      baseEnv,
      "strict",
      "none",
      "block",
    );

    expect(response.status).toBe(401);
    expect(await response.text()).toContain("Request BLOCKED");
  });

  it("allows + flags (200) when action=allow", async () => {
    queueSiteverify(ipFail());
    queueSiteverify(ok());

    const response = await handleTurnstileVerification(
      postForm("tok"),
      baseEnv,
      "strict",
      "none",
      "allow",
    );

    expect(response.status).toBe(200);
    expect(await response.text()).toContain("Request ALLOWED + FLAGGED");
  });
});

describe("handleTurnstileVerification — IP mismatch simulation", () => {
  it("increments the last octet for same-subnet simulation", async () => {
    queueSiteverify(ok());

    await handleTurnstileVerification(
      postForm("tok", { ip: "192.168.1.5" }),
      baseEnv,
      "strict",
      "subnet",
    );

    expect(firstFormData().get("remoteip")).toBe("192.168.1.6");
  });

  it("substitutes 8.8.8.8 for different-ASN simulation", async () => {
    queueSiteverify(ok());

    await handleTurnstileVerification(
      postForm("tok", { ip: "192.168.1.5" }),
      baseEnv,
      "strict",
      "asn",
    );

    expect(firstFormData().get("remoteip")).toBe("8.8.8.8");
  });

  it("sends the real IP for no-mismatch simulation", async () => {
    queueSiteverify(ok());

    await handleTurnstileVerification(
      postForm("tok", { ip: "192.168.1.5" }),
      baseEnv,
      "strict",
      "none",
    );

    expect(firstFormData().get("remoteip")).toBe("192.168.1.5");
  });

  it("leaves IPv6 addresses unchanged for same-subnet simulation and flags it", async () => {
    queueSiteverify(ok());

    const response = await handleTurnstileVerification(
      postForm("tok", { ip: "2001:db8::1" }),
      baseEnv,
      "strict",
      "subnet",
    );

    expect(firstFormData().get("remoteip")).toBe("2001:db8::1");
    expect(await response.text()).toContain("IPv6");
  });

  it("omits remoteip when the CF-Connecting-IP header is absent", async () => {
    queueSiteverify(ok());

    await handleTurnstileVerification(postForm("tok"), baseEnv);

    expect(firstFormData().get("remoteip")).toBeNull();
  });
});

describe("handleTurnstileVerification — output hygiene", () => {
  it("escapes user-controlled token text reflected into result pages (XSS regression)", async () => {
    queueSiteverify(ok());

    const response = await handleTurnstileVerification(
      postForm("<script>alert(1)</script>"),
      baseEnv,
    );

    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).toContain("&lt;script&gt;");
    expect(text).not.toContain("<script>");
  });

  it("shows challenge_ts and hostname from the siteverify response", async () => {
    queueSiteverify(ok({ challenge_ts: "2026-01-01T00:00:00Z", hostname: "example.com" }));

    const response = await handleTurnstileVerification(postForm("tok"), baseEnv);

    const text = await response.text();
    expect(text).toContain("2026-01-01T00:00:00Z");
    expect(text).toContain("example.com");
  });
});

describe("handleTurnstileVerification — canonical siteverify gate", () => {
  it("rejects tokens whose action does not match the widget data-action", async () => {
    queueSiteverify(ok({ action: "some-other-action" }));

    const response = await handleTurnstileVerification(postForm("tok"), baseEnv);

    expect(response.status).toBe(401);
    expect(await response.text()).toContain("action-not-allowed");
  });

  it("rejects tokens with a missing action", async () => {
    queueSiteverify(ok({ action: undefined }));

    const response = await handleTurnstileVerification(postForm("tok"), baseEnv);

    expect(response.status).toBe(401);
    expect(await response.text()).toContain("action-not-allowed");
  });

  it("rejects hostnames outside the TURNSTILE_HOSTNAMES allowlist", async () => {
    queueSiteverify(ok({ hostname: "evil.example" }));

    const response = await handleTurnstileVerification(postForm("tok"), {
      ...baseEnv,
      TURNSTILE_HOSTNAMES: "example.com",
    });

    expect(response.status).toBe(401);
    expect(await response.text()).toContain("hostname-not-allowed");
  });

  it("allows hostnames inside the TURNSTILE_HOSTNAMES allowlist", async () => {
    queueSiteverify(ok({ hostname: "example.com" }));

    const response = await handleTurnstileVerification(postForm("tok"), {
      ...baseEnv,
      TURNSTILE_HOSTNAMES: "example.com",
    });

    expect(response.status).toBe(200);
    expect(await response.text()).toContain("Verification Successful");
  });

  it("does not enforce hostnames when TURNSTILE_HOSTNAMES is unset", async () => {
    queueSiteverify(ok({ hostname: "anything.example" }));

    const response = await handleTurnstileVerification(postForm("tok"), baseEnv);

    expect(response.status).toBe(200);
    expect(await response.text()).toContain("Verification Successful");
  });
});

describe("worker routes", () => {
  it("serves the overview page at GET /", async () => {
    const response = await worker.fetch(new Request("http://localhost/"), baseEnv);

    expect(response.status).toBe(200);
    expect(await response.text()).toContain("remoteip_leniency");
  });

  it("serves the widget page at GET /form with the configured site key", async () => {
    const response = await worker.fetch(new Request("http://localhost/form"), baseEnv);

    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).toContain("cf-turnstile");
    expect(text).toContain(baseEnv.TURNSTILE_SITE_KEY);
  });

  it("defaults the starting level on GET /form to the env config", async () => {
    const response = await worker.fetch(new Request("http://localhost/form"), {
      ...baseEnv,
      REMOTEIP_LENIENCY: "relaxed",
    });

    const text = await response.text();
    expect(text).toContain("relaxed");
  });

  it("sanitizes hostile query params on GET /form (XSS regression)", async () => {
    const response = await worker.fetch(
      new Request(
        'http://localhost/form?mode="><svg onload=alert(1)>&mismatch="><script>alert(2)</script>&action="><script>alert(3)</script>',
      ),
      baseEnv,
    );

    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).not.toContain("<svg");
    expect(text).not.toContain("<script>alert");
    expect(text).not.toContain("onload=");
    // hostile values fall back to the default start level instead of being echoed
    expect(text).toContain("strict");
  });

  it("sanitizes a hostile mode param on POST /form (XSS regression)", async () => {
    queueSiteverify(ok());

    const response = await worker.fetch(
      new Request('http://localhost/form?mode="><script>alert(1)</script>', {
        method: "POST",
        headers: { "CF-Connecting-IP": "1.2.3.4" },
        body: new URLSearchParams({ "cf-turnstile-response": "tok" }),
      }),
      baseEnv,
    );

    expect(response.status).toBe(200);
    expect(firstFormData().get("remoteip_leniency")).toBe("strict");
    expect(await response.text()).not.toContain("<script>");
  });

  it("handles POST /form end to end through the worker fetch handler", async () => {
    queueSiteverify(ipFail());
    queueSiteverify(ok());

    const response = await worker.fetch(
      new Request("http://localhost/form?mode=strict", {
        method: "POST",
        headers: { "CF-Connecting-IP": "1.2.3.4" },
        body: new URLSearchParams({ "cf-turnstile-response": "tok" }),
      }),
      baseEnv,
    );

    expect(response.status).toBe(200);
    expect(await response.text()).toContain("IP Mismatch Detected");
  });

  it("returns 404 for unknown paths", async () => {
    const get = await worker.fetch(new Request("http://localhost/nope"), baseEnv);
    expect(get.status).toBe(404);

    const post = await worker.fetch(
      new Request("http://localhost/nope", { method: "POST", body: "x" }),
      baseEnv,
    );
    expect(post.status).toBe(404);
  });
});
