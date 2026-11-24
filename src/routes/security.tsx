import { Hono, type Context } from "hono";
import type { SecurityAuth } from "../security/auth";
import type { SecurityRuntime } from "../security/runtime";
import {
  alertChannels,
  criterionIds,
  lockdownModes,
  type AlertChannel,
  type CriterionId,
  type LockdownMode,
  type RuntimeOverrides,
} from "../security/types";
import { SecurityNavDot } from "../templates/app";
import {
  SecurityLogin,
  SecurityPanel,
  type SecurityFlash,
} from "../templates/security";
import { deriveSecurityDot, renderPage } from "./pages";

const MAX_FORM_BYTES = 16 * 1024;
const MAX_FORM_FIELDS = 64;
const LOGIN_MAX_FAILURES = 5;
const LOGIN_WINDOW_MS = 5 * 60 * 1_000;
const LOGIN_TRACKER_MAX_PEERS = 512;

const MODE_SET = new Set<string>(lockdownModes);
const CRITERION_SET = new Set<string>(criterionIds);
const CHANNEL_SET = new Set<string>(alertChannels);
const CSRF_FIELD_NAMES = new Set(["csrf", "_csrf", "csrfToken"]);

export interface SecurityRouterOptions {
  runtime: SecurityRuntime;
  auth: SecurityAuth;
  peer: (request: Request) => string | null | undefined;
  publicOrigin?: string;
}

type ParsedFormResult =
  | { ok: true; fields: Map<string, string> }
  | { ok: false; status: 400 | 413 | 415; message: string };

function normalizeOrigin(raw: string | undefined): string | null {
  if (!raw) return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return parsed.origin;
  } catch {
    return null;
  }
}

function isSameBrowserOrigin(
  request: Request,
  configuredPublicOrigin?: string,
): boolean {
  const allowed = new Set<string>();
  const reqOrigin = normalizeOrigin(request.url);
  if (reqOrigin) allowed.add(reqOrigin);
  const pubOrigin = normalizeOrigin(configuredPublicOrigin);
  if (pubOrigin) allowed.add(pubOrigin);
  if (allowed.size === 0) return false;

  const originHeader = request.headers.get("origin");
  if (originHeader !== null) {
    const trimmed = originHeader.trim();
    if (!trimmed || trimmed.toLowerCase() === "null") return false;
    try {
      const parsed = new URL(trimmed);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
      return parsed.origin === trimmed && allowed.has(parsed.origin);
    } catch {
      return false;
    }
  }

  const refererHeader = request.headers.get("referer");
  if (refererHeader !== null) {
    const parsed = normalizeOrigin(refererHeader);
    return parsed !== null && allowed.has(parsed);
  }

  return false;
}

function isFormUrlEncoded(contentType: string | null): boolean {
  if (!contentType) return false;
  const mime = contentType.split(";")[0]?.trim().toLowerCase();
  return mime === "application/x-www-form-urlencoded";
}

async function readBoundedText(
  request: Request,
  maxBytes: number,
): Promise<{ ok: true; text: string } | { ok: false; status: 400 | 413; message: string }> {
  const clHeader = request.headers.get("content-length");
  if (clHeader !== null) {
    const parsedLen = Number(clHeader);
    if (Number.isFinite(parsedLen) && parsedLen > maxBytes) {
      return { ok: false, status: 413, message: "Request body exceeds size limit." };
    }
  }

  const body = request.body;
  if (!body) {
    return { ok: true, text: "" };
  }

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        return { ok: false, status: 413, message: "Request body exceeds size limit." };
      }
      chunks.push(value);
    }
  } catch {
    return { ok: false, status: 400, message: "Unable to read request body." };
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(merged);
    return { ok: true, text };
  } catch {
    return { ok: false, status: 400, message: "Invalid UTF-8 form body." };
  }
}

async function parseUrlEncodedForm(request: Request): Promise<ParsedFormResult> {
  if (!isFormUrlEncoded(request.headers.get("content-type"))) {
    return {
      ok: false,
      status: 415,
      message: "Expected application/x-www-form-urlencoded body.",
    };
  }

  const read = await readBoundedText(request, MAX_FORM_BYTES);
  if (!read.ok) {
    return read;
  }

  const params = new URLSearchParams(read.text);
  const fields = new Map<string, string>();
  let count = 0;
  for (const [key, value] of params.entries()) {
    count += 1;
    if (count > MAX_FORM_FIELDS) {
      return { ok: false, status: 400, message: "Too many form fields." };
    }
    if (fields.has(key)) {
      return { ok: false, status: 400, message: "Duplicate form field rejected." };
    }
    fields.set(key, value);
  }

  return { ok: true, fields };
}

function extractSubmittedCsrf(
  fields: Map<string, string>,
  request: Request,
): string | undefined {
  for (const name of CSRF_FIELD_NAMES) {
    const val = fields.get(name);
    if (val !== undefined) return val;
  }
  return request.headers.get("x-csrf-token") ?? undefined;
}

function parsePositiveInt(raw: string | undefined): number | null {
  if (raw === undefined || !/^[1-9]\d*$/.test(raw)) return null;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 1) return null;
  return parsed;
}

function parseBooleanChoice(raw: string): boolean | null {
  const normalized = raw.trim().toLowerCase();
  if (normalized === "on" || normalized === "true" || normalized === "1") return true;
  if (normalized === "off" || normalized === "false" || normalized === "0") return false;
  return null;
}

export function createSecurityRouter(options: SecurityRouterOptions): Hono {
  const { runtime, auth, peer, publicOrigin } = options;
  const app = new Hono();
  const loginFailures = new Map<string, { count: number; resetAt: number }>();

  const nowMs = (): number => (typeof auth.now === "function" ? auth.now() : Date.now());

  const normalizePeerKey = (rawPeer: string | null | undefined): string => {
    const trimmed = typeof rawPeer === "string" ? rawPeer.trim() : "";
    return trimmed.length > 0 ? trimmed : "unknown";
  };

  const getActiveLoginFailure = (
    key: string,
    now: number,
  ): { count: number; resetAt: number } | undefined => {
    const entry = loginFailures.get(key);
    if (!entry) return undefined;
    if (now >= entry.resetAt) {
      loginFailures.delete(key);
      return undefined;
    }
    return entry;
  };

  const recordLoginFailure = (key: string, now: number): void => {
    const existing = getActiveLoginFailure(key, now);
    if (existing) {
      loginFailures.delete(key);
      loginFailures.set(key, { count: existing.count + 1, resetAt: existing.resetAt });
      return;
    }

    if (loginFailures.size >= LOGIN_TRACKER_MAX_PEERS) {
      for (const [k, entry] of loginFailures) {
        if (now >= entry.resetAt) {
          loginFailures.delete(k);
        }
      }
      while (loginFailures.size >= LOGIN_TRACKER_MAX_PEERS) {
        const oldestKey = loginFailures.keys().next().value;
        if (oldestKey === undefined) break;
        loginFailures.delete(oldestKey);
      }
    }

    loginFailures.set(key, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
  };

  const renderFragment = (
    c: Context,
    status: 200 | 400 | 404 | 409,
    flash?: SecurityFlash,
  ) => {
    c.header("Cache-Control", "no-store");
    const peerIp = peer(c.req.raw);
    const csrf = auth.csrfToken(c.req.raw, peerIp);
    if (csrf?.cookie) {
      c.header("Set-Cookie", csrf.cookie, { append: true });
    }
    const view = runtime.view();
    return c.html(
      <>
        <SecurityPanel view={view} csrfToken={csrf?.token} flash={flash} serverNow={nowMs()} />
        <SecurityNavDot state={deriveSecurityDot(view)} oob />
      </>,
      status,
    );
  };

  const respondSuccess = (c: Context, message: string) => {
    c.header("Cache-Control", "no-store");
    if (c.req.header("HX-Request")) {
      return renderFragment(c, 200, { kind: "success", message });
    }
    return c.redirect("/security", 303);
  };

  const respondError = (
    c: Context,
    status: 400 | 403 | 404 | 409 | 413 | 415,
    message: string,
    opts: { authenticated?: boolean } = {},
  ) => {
    c.header("Cache-Control", "no-store");
    if (
      opts.authenticated === true &&
      c.req.header("HX-Request") &&
      (status === 400 || status === 404 || status === 409)
    ) {
      return renderFragment(c, status, { kind: "error", message });
    }
    return c.text(message, status);
  };

  const guardMutation = async (
    c: Context,
  ): Promise<
    { ok: true; fields: Map<string, string> } | { ok: false; response: Response | Promise<Response> }
  > => {
    c.header("Cache-Control", "no-store");

    const peerIp = peer(c.req.raw);
    if (!auth.authorizeRead(c.req.raw, peerIp)) {
      return {
        ok: false,
        response: respondError(c, 403, "Forbidden: authorization required.", {
          authenticated: false,
        }),
      };
    }

    const parsed = await parseUrlEncodedForm(c.req.raw);
    if (!parsed.ok) {
      return {
        ok: false,
        response: respondError(c, parsed.status, parsed.message, { authenticated: false }),
      };
    }

    const csrf = extractSubmittedCsrf(parsed.fields, c.req.raw);
    if (!auth.authorizeMutation(c.req.raw, peerIp, csrf)) {
      return {
        ok: false,
        response: respondError(c, 403, "Forbidden: authorization or CSRF check failed.", {
          authenticated: false,
        }),
      };
    }

    return { ok: true, fields: parsed.fields };
  };

  // -------------------------------------------------------------------------
  // Login routes
  // -------------------------------------------------------------------------

  app.get("/security/login", (c) => {
    c.header("Cache-Control", "no-store");
    if (!auth.tokenConfigured) {
      return c.redirect("/security", 303);
    }
    if (auth.authorizeRead(c.req.raw, peer(c.req.raw))) {
      return c.redirect("/security", 303);
    }
    return renderPage(c, () => <SecurityLogin />, "Security Login", {
      securityDot: { active: false },
    });
  });

  app.post("/security/login", async (c) => {
    c.header("Cache-Control", "no-store");
    if (!auth.tokenConfigured) {
      return c.redirect("/security", 303);
    }

    const key = normalizePeerKey(peer(c.req.raw));
    const now = nowMs();
    const activeFailure = getActiveLoginFailure(key, now);
    if (activeFailure && activeFailure.count >= LOGIN_MAX_FAILURES) {
      const retryAfterSec = Math.max(1, Math.ceil((activeFailure.resetAt - now) / 1_000));
      c.header("Retry-After", String(retryAfterSec));
      return c.text("Too many failed login attempts. Try again later.", 429);
    }

    // Reserve an attempt slot synchronously before yielding to async body parsing
    // so concurrent login bursts cannot bypass LOGIN_MAX_FAILURES.
    recordLoginFailure(key, now);

    const parsed = await parseUrlEncodedForm(c.req.raw);
    if (!parsed.ok) {
      return c.text(parsed.message, parsed.status);
    }

    if (!isSameBrowserOrigin(c.req.raw, publicOrigin)) {
      return c.text("Forbidden origin.", 403);
    }

    const token = parsed.fields.get("token") ?? "";
    const result = auth.login(c.req.raw, token);
    if (!result.ok || !result.cookie) {
      return renderPage(
        c,
        () => <SecurityLogin error="Invalid access token." />,
        "Security Login",
        { securityDot: { active: false }, status: 401 },
      );
    }

    loginFailures.delete(key);
    c.header("Set-Cookie", result.cookie);
    return c.redirect("/security", 303);
  });

  // -------------------------------------------------------------------------
  // Read routes
  // -------------------------------------------------------------------------

  app.get("/security", (c) => {
    c.header("Cache-Control", "no-store");
    const peerIp = peer(c.req.raw);
    if (!auth.authorizeRead(c.req.raw, peerIp)) {
      if (c.req.header("HX-Request") === "true") {
        c.header("HX-Redirect", "/security/login");
        return c.text("", 200);
      }
      return c.redirect("/security/login", 303);
    }

    const csrf = auth.csrfToken(c.req.raw, peerIp);
    if (csrf?.cookie) {
      c.header("Set-Cookie", csrf.cookie, { append: true });
    }
    const view = runtime.view();
    const serverNow = nowMs();
    return renderPage(
      c,
      () => <SecurityPanel view={view} csrfToken={csrf?.token} serverNow={serverNow} />,
      "Security",
      { securityDot: deriveSecurityDot(view) },
    );
  });

  app.get("/security/fragment", (c) => {
    c.header("Cache-Control", "no-store");
    const peerIp = peer(c.req.raw);
    if (!auth.authorizeRead(c.req.raw, peerIp)) {
      return c.text("Unauthorized", 401);
    }
    return renderFragment(c, 200);
  });

  app.get("/api/security/status", (c) => {
    c.header("Cache-Control", "no-store");
    const peerIp = peer(c.req.raw);
    if (!auth.authorizeRead(c.req.raw, peerIp)) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    return c.json(runtime.view(), 200);
  });

  // -------------------------------------------------------------------------
  // Mutation routes (all routed through guardMutation)
  // -------------------------------------------------------------------------

  app.post("/security/scan", async (c) => {
    const guarded = await guardMutation(c);
    if (!guarded.ok) return guarded.response;

    void runtime.requestScan("manual").catch(() => {});
    return respondSuccess(c, "Security scan queued.");
  });

  app.post("/security/mode", async (c) => {
    const guarded = await guardMutation(c);
    if (!guarded.ok) return guarded.response;

    for (const key of guarded.fields.keys()) {
      if (!CSRF_FIELD_NAMES.has(key) && key !== "mode") {
        return respondError(c, 400, "Unexpected form field.", { authenticated: true });
      }
    }

    const mode = guarded.fields.get("mode");
    if (!mode || !MODE_SET.has(mode)) {
      return respondError(c, 400, "Invalid lockdown mode.", { authenticated: true });
    }

    try {
      runtime.updateSettings({ mode: mode as LockdownMode });
    } catch {
      return respondError(c, 400, "Unable to update lockdown mode.", { authenticated: true });
    }
    return respondSuccess(c, `Lockdown mode updated to ${mode}.`);
  });

  app.post("/security/settings", async (c) => {
    const guarded = await guardMutation(c);
    if (!guarded.ok) return guarded.response;

    const overrides: RuntimeOverrides = {};
    const criteriaUpdates: Partial<Record<CriterionId, boolean>> = {};
    let hasCriteria = false;
    let hasAnyField = false;

    for (const [key, value] of guarded.fields.entries()) {
      if (CSRF_FIELD_NAMES.has(key)) continue;

      if (key === "scanIntervalMinutes") {
        const minutes = parsePositiveInt(value);
        if (minutes === null || minutes < 1 || minutes > 1440) {
          return respondError(
            c,
            400,
            "Scan interval must be an integer between 1 and 1440 minutes.",
            { authenticated: true },
          );
        }
        overrides.scanIntervalMinutes = minutes;
        hasAnyField = true;
        continue;
      }

      if (key.startsWith("criteria.")) {
        const criterionId = key.slice("criteria.".length);
        if (!CRITERION_SET.has(criterionId)) {
          return respondError(c, 400, "Unknown security criterion.", { authenticated: true });
        }
        const parsedBool = parseBooleanChoice(value);
        if (parsedBool === null) {
          return respondError(c, 400, "Invalid criterion toggle value.", { authenticated: true });
        }
        criteriaUpdates[criterionId as CriterionId] = parsedBool;
        hasCriteria = true;
        hasAnyField = true;
        continue;
      }

      return respondError(c, 400, "Unknown settings field.", { authenticated: true });
    }

    if (!hasAnyField) {
      return respondError(c, 400, "No settings fields submitted.", { authenticated: true });
    }
    if (hasCriteria) {
      overrides.criteria = criteriaUpdates;
    }

    try {
      runtime.updateSettings(overrides);
    } catch {
      return respondError(c, 400, "Invalid security settings.", { authenticated: true });
    }
    return respondSuccess(c, "Security settings saved.");
  });

  app.post("/security/proposals/:id/approve", async (c) => {
    const guarded = await guardMutation(c);
    if (!guarded.ok) return guarded.response;

    const revision = parsePositiveInt(guarded.fields.get("revision"));
    if (revision === null) {
      return respondError(c, 400, "A positive integer proposal revision is required.", {
        authenticated: true,
      });
    }

    const id = c.req.param("id");
    let approved: boolean;
    try {
      approved = await runtime.approve(id, revision);
    } catch {
      return respondError(c, 409, "Unable to approve containment proposal.", {
        authenticated: true,
      });
    }
    if (!approved) {
      return respondError(
        c,
        409,
        "Proposal is stale, already settled, or ineligible in the current mode.",
        { authenticated: true },
      );
    }
    return respondSuccess(c, "Containment proposal approved.");
  });

  app.post("/security/proposals/:id/reject", async (c) => {
    const guarded = await guardMutation(c);
    if (!guarded.ok) return guarded.response;

    const revision = parsePositiveInt(guarded.fields.get("revision"));
    if (revision === null) {
      return respondError(c, 400, "A positive integer proposal revision is required.", {
        authenticated: true,
      });
    }

    const id = c.req.param("id");
    let rejected: boolean;
    try {
      rejected = runtime.reject(id, revision);
    } catch {
      return respondError(c, 409, "Unable to reject containment proposal.", {
        authenticated: true,
      });
    }
    if (!rejected) {
      return respondError(c, 409, "Proposal is stale or already settled.", {
        authenticated: true,
      });
    }
    return respondSuccess(c, "Containment proposal rejected.");
  });

  app.post("/security/actions/:id/unlock", async (c) => {
    const guarded = await guardMutation(c);
    if (!guarded.ok) return guarded.response;

    const id = c.req.param("id");
    let unlocked: boolean;
    try {
      unlocked = await runtime.unlock(id);
    } catch {
      return respondError(c, 409, "Containment action rollback failed.", {
        authenticated: true,
      });
    }
    if (!unlocked) {
      return respondError(c, 409, "Containment action could not be rolled back.", {
        authenticated: true,
      });
    }
    return respondSuccess(c, "Containment action rolled back.");
  });

  app.post("/security/test-alert", async (c) => {
    const guarded = await guardMutation(c);
    if (!guarded.ok) return guarded.response;

    for (const key of guarded.fields.keys()) {
      if (!CSRF_FIELD_NAMES.has(key) && key !== "channel") {
        return respondError(c, 400, "Unexpected form field.", { authenticated: true });
      }
    }

    const channelRaw = guarded.fields.get("channel");
    let channel: AlertChannel | undefined;
    if (channelRaw !== undefined && channelRaw !== "") {
      if (!CHANNEL_SET.has(channelRaw)) {
        return respondError(c, 400, "Alert channel is not eligible.", { authenticated: true });
      }
      channel = channelRaw as AlertChannel;
    }

    try {
      runtime.sendTestAlert(channel);
    } catch {
      return respondError(c, 400, "Selected alert channel is not ready for delivery.", {
        authenticated: true,
      });
    }
    return respondSuccess(
      c,
      channel ? `Test alert queued for ${channel}.` : "Test alert queued.",
    );
  });

  app.post("/security/alerts/:id/dismiss", async (c) => {
    const guarded = await guardMutation(c);
    if (!guarded.ok) return guarded.response;

    const id = c.req.param("id");
    let dismissed: boolean;
    try {
      dismissed = runtime.dismissAlert(id);
    } catch {
      return respondError(c, 409, "Unable to dismiss security alert.", {
        authenticated: true,
      });
    }
    if (!dismissed) {
      return respondError(c, 404, "Alert not found or already dismissed.", {
        authenticated: true,
      });
    }
    return respondSuccess(c, "Security alert dismissed.");
  });

  return app;
}
