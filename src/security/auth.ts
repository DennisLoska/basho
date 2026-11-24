import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Clock } from "./types";

const SESSION_COOKIE_NAME = "basho_session";
const LOCAL_CSRF_COOKIE_NAME = "basho_local_csrf";

const DEFAULT_SESSION_TTL_MS = 12 * 60 * 60 * 1_000;
const DEFAULT_LOCAL_CSRF_TTL_MS = 2 * 60 * 60 * 1_000;

const PROXY_FORWARDING_HEADERS = [
  "x-forwarded-for",
  "forwarded",
  "x-real-ip",
  "x-forwarded-host",
  "x-forwarded-proto",
] as const;

const TOKEN_PART_PATTERN = /^[A-Za-z0-9_-]{8,128}$/;

export interface SecurityAuthOptions {
  token?: string;
  clock?: Clock;
  publicOrigin?: string;
  sessionTtlMs?: number;
  localCsrfTtlMs?: number;
}

export interface LoginResult {
  ok: boolean;
  cookie?: string;
}

export interface CsrfIssue {
  token: string;
  cookie?: string;
}

export interface SecurityAuth {
  readonly tokenConfigured: boolean;
  now(): number;
  authorizeRead(request: Request, peer: string | null | undefined): boolean;
  authorizeMutation(
    request: Request,
    peer: string | null | undefined,
    csrf?: string,
  ): boolean;
  login(request: Request, suppliedToken: string): LoginResult;
  csrfToken(request: Request, peer: string | null | undefined): CsrfIssue | null;
  sessionExpiresAt(request: Request, peer: string | null | undefined): number | null;
}

function sha256Digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

function constantTimeEqual(a: string, b: string): boolean {
  return timingSafeEqual(sha256Digest(a), sha256Digest(b));
}

function normalizeConfiguredOrigin(raw: string | undefined): {
  origin: string;
  isHttps: boolean;
} | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (trimmed === "") return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    return {
      origin: parsed.origin,
      isHttps: parsed.protocol === "https:",
    };
  } catch {
    return null;
  }
}

function parseRequestOrigin(url: string): { origin: string; isHttps: boolean } | null {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    return {
      origin: parsed.origin,
      isHttps: parsed.protocol === "https:",
    };
  } catch {
    return null;
  }
}

function isLoopbackIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  for (let i = 0; i < 4; i += 1) {
    const part = parts[i]!;
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return false;
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return false;
    if (i === 0 && octet !== 127) return false;
  }
  return true;
}

export function isDirectLoopbackPeer(peer: string | null | undefined): boolean {
  if (typeof peer !== "string" || peer.length === 0) {
    return false;
  }
  if (peer !== peer.trim() || /[\s,]/.test(peer)) {
    return false;
  }
  const normalized = peer.toLowerCase();
  if (normalized === "::1" || normalized === "0:0:0:0:0:0:0:1") {
    return true;
  }
  if (isLoopbackIpv4(normalized)) {
    return true;
  }
  if (normalized.startsWith("::ffff:")) {
    const mapped = normalized.slice("::ffff:".length);
    if (isLoopbackIpv4(mapped)) {
      return true;
    }
  }
  return false;
}

function isLoopbackOrigin(origin: string): boolean {
  try {
    const parsed = new URL(origin);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return false;
    }
    const host = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (host === "localhost" || host === "::1") {
      return true;
    }
    return isLoopbackIpv4(host);
  } catch {
    return false;
  }
}

function hasProxyForwardingHeaders(request: Request): boolean {
  for (const header of PROXY_FORWARDING_HEADERS) {
    if (request.headers.has(header)) {
      return true;
    }
  }
  return false;
}

function parseCookies(headerValue: string | null): Map<string, string> {
  const cookies = new Map<string, string>();
  if (!headerValue) return cookies;
  for (const segment of headerValue.split(";")) {
    const eqIndex = segment.indexOf("=");
    if (eqIndex <= 0) continue;
    const name = segment.slice(0, eqIndex).trim();
    const value = segment.slice(eqIndex + 1).trim();
    if (name && value) {
      cookies.set(name, value);
    }
  }
  return cookies;
}

function parseExactOriginHeader(raw: string): string | null {
  const trimmed = raw.trim();
  if (trimmed === "" || trimmed.toLowerCase() === "null") {
    return null;
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    if (parsed.origin !== trimmed) {
      return null;
    }
    return parsed.origin;
  } catch {
    return null;
  }
}

function parseRefererOrigin(raw: string): string | null {
  const trimmed = raw.trim();
  if (trimmed === "") return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    return parsed.origin;
  } catch {
    return null;
  }
}

function formatSetCookie(
  name: string,
  value: string,
  maxAgeSeconds: number,
  secure: boolean,
): string {
  const attrs = [
    `${name}=${value}`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
  ];
  if (secure) {
    attrs.push("Secure");
  }
  return attrs.join("; ");
}

interface ParsedBinding {
  id: string;
  exp: number;
}

export function createSecurityAuth(options: SecurityAuthOptions = {}): SecurityAuth {
  const clock: Clock = options.clock ?? { now: () => Date.now() };
  const configuredToken =
    typeof options.token === "string" && options.token.length > 0 ? options.token : undefined;
  const configuredPublic = normalizeConfiguredOrigin(options.publicOrigin);
  const sessionTtlMs =
    typeof options.sessionTtlMs === "number" &&
    Number.isFinite(options.sessionTtlMs) &&
    options.sessionTtlMs > 0
      ? options.sessionTtlMs
      : DEFAULT_SESSION_TTL_MS;
  const localCsrfTtlMs =
    typeof options.localCsrfTtlMs === "number" &&
    Number.isFinite(options.localCsrfTtlMs) &&
    options.localCsrfTtlMs > 0
      ? options.localCsrfTtlMs
      : DEFAULT_LOCAL_CSRF_TTL_MS;

  const signingKey = randomBytes(32);

  const sign = (payload: string): string =>
    createHmac("sha256", signingKey).update(payload, "utf8").digest("base64url");

  const issueBinding = (kind: "session" | "local", ttlMs: number): {
    binding: ParsedBinding;
    value: string;
  } => {
    const id = randomBytes(16).toString("base64url");
    const exp = clock.now() + ttlMs;
    const sig = sign(`${kind}:${id}:${exp}`);
    return {
      binding: { id, exp },
      value: `${id}.${exp}.${sig}`,
    };
  };

  const verifyBinding = (
    kind: "session" | "local",
    raw: string | undefined,
  ): ParsedBinding | null => {
    if (typeof raw !== "string" || raw.length === 0) return null;
    const parts = raw.split(".");
    if (parts.length !== 3) return null;
    const [id, expText, sig] = parts;
    if (!id || !expText || !sig) return null;
    if (!TOKEN_PART_PATTERN.test(id) || !TOKEN_PART_PATTERN.test(sig)) return null;
    if (!/^\d+$/.test(expText)) return null;
    const exp = Number(expText);
    if (!Number.isSafeInteger(exp) || clock.now() >= exp) return null;

    const expectedSig = sign(`${kind}:${id}:${exp}`);
    if (!constantTimeEqual(sig, expectedSig)) {
      return null;
    }
    return { id, exp };
  };

  const issueCsrf = (kind: "session" | "local", binding: ParsedBinding): string => {
    const nonce = randomBytes(16).toString("base64url");
    const exp = Math.min(binding.exp, clock.now() + localCsrfTtlMs);
    const sig = sign(`csrf:${kind}:${binding.id}:${nonce}:${exp}`);
    return `${nonce}.${exp}.${sig}`;
  };

  const verifyCsrf = (
    kind: "session" | "local",
    binding: ParsedBinding,
    rawCsrf: string | undefined,
  ): boolean => {
    if (typeof rawCsrf !== "string" || rawCsrf.length === 0) return false;
    const parts = rawCsrf.split(".");
    if (parts.length !== 3) return false;
    const [nonce, expText, sig] = parts;
    if (!nonce || !expText || !sig) return false;
    if (!TOKEN_PART_PATTERN.test(nonce) || !TOKEN_PART_PATTERN.test(sig)) return false;
    if (!/^\d+$/.test(expText)) return false;
    const exp = Number(expText);
    if (!Number.isSafeInteger(exp) || clock.now() >= exp || exp > binding.exp) {
      return false;
    }
    const expectedSig = sign(`csrf:${kind}:${binding.id}:${nonce}:${exp}`);
    return constantTimeEqual(sig, expectedSig);
  };

  const allowedOriginsFor = (request: Request): Set<string> => {
    const allowed = new Set<string>();
    const reqOrigin = parseRequestOrigin(request.url);
    if (reqOrigin) {
      allowed.add(reqOrigin.origin);
    }
    if (configuredPublic) {
      allowed.add(configuredPublic.origin);
    }
    return allowed;
  };

  const shouldSetSecureCookie = (request: Request): boolean => {
    const reqOrigin = parseRequestOrigin(request.url);
    if (reqOrigin?.isHttps) {
      return true;
    }
    if (configuredPublic?.isHttps) {
      const matchedOrigin = resolveBrowserOrigin(request);
      if (matchedOrigin === configuredPublic.origin) {
        return true;
      }
    }
    return false;
  };

  /**
   * Resolves and verifies the request's browser origin.
   * Checks `Origin` when present (without falling back to `Referer`),
   * otherwise falls back to `Referer` origin.
   */
  const resolveBrowserOrigin = (request: Request): string | null => {
    const allowed = allowedOriginsFor(request);
    if (allowed.size === 0) return null;

    const originHeader = request.headers.get("origin");
    if (originHeader !== null) {
      const parsed = parseExactOriginHeader(originHeader);
      return parsed !== null && allowed.has(parsed) ? parsed : null;
    }

    const refererHeader = request.headers.get("referer");
    if (refererHeader !== null) {
      const parsed = parseRefererOrigin(refererHeader);
      return parsed !== null && allowed.has(parsed) ? parsed : null;
    }

    return null;
  };

  const parseBearerAuth = (
    request: Request,
  ): { present: boolean; valid: boolean } => {
    const authHeader = request.headers.get("authorization");
    if (authHeader === null) {
      return { present: false, valid: false };
    }
    if (!configuredToken) {
      return { present: true, valid: false };
    }
    const match = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
    if (!match?.[1]) {
      return { present: true, valid: false };
    }
    return {
      present: true,
      valid: constantTimeEqual(match[1], configuredToken),
    };
  };

  const readValidSession = (request: Request): ParsedBinding | null => {
    if (!configuredToken) return null;
    const cookies = parseCookies(request.headers.get("cookie"));
    return verifyBinding("session", cookies.get(SESSION_COOKIE_NAME));
  };

  const readValidLocalBinding = (request: Request): ParsedBinding | null => {
    const cookies = parseCookies(request.headers.get("cookie"));
    return verifyBinding("local", cookies.get(LOCAL_CSRF_COOKIE_NAME));
  };

  return {
    get tokenConfigured(): boolean {
      return configuredToken !== undefined;
    },

    now(): number {
      return clock.now();
    },

    authorizeRead(request: Request, _peer: string | null | undefined): boolean {
      if (!configuredToken) {
        return true;
      }

      const bearer = parseBearerAuth(request);
      if (bearer.present) {
        return bearer.valid;
      }

      return readValidSession(request) !== null;
    },

    authorizeMutation(
      request: Request,
      peer: string | null | undefined,
      csrf?: string,
    ): boolean {
      const suppliedCsrf =
        csrf !== undefined ? csrf : (request.headers.get("x-csrf-token") ?? undefined);

      if (configuredToken) {
        const bearer = parseBearerAuth(request);
        if (bearer.present) {
          if (!bearer.valid) {
            return false;
          }
          const allowed = allowedOriginsFor(request);
          const originHeader = request.headers.get("origin");
          if (originHeader !== null) {
            const parsed = parseExactOriginHeader(originHeader);
            return parsed !== null && allowed.has(parsed);
          }
          const refererHeader = request.headers.get("referer");
          if (refererHeader !== null) {
            const parsed = parseRefererOrigin(refererHeader);
            return parsed !== null && allowed.has(parsed);
          }
          return true;
        }

        const session = readValidSession(request);
        if (!session) {
          return false;
        }
        const matchedOrigin = resolveBrowserOrigin(request);
        if (!matchedOrigin) {
          return false;
        }
        return verifyCsrf("session", session, suppliedCsrf);
      }

      // Tokenless mode: allow mutations only for direct loopback peers without
      // proxy forwarding headers, on a loopback origin, with a valid local CSRF binding.
      if (!isDirectLoopbackPeer(peer) || hasProxyForwardingHeaders(request)) {
        return false;
      }
      const matchedOrigin = resolveBrowserOrigin(request);
      if (!matchedOrigin || !isLoopbackOrigin(matchedOrigin)) {
        return false;
      }
      const localBinding = readValidLocalBinding(request);
      if (!localBinding) {
        return false;
      }
      return verifyCsrf("local", localBinding, suppliedCsrf);
    },

    login(request: Request, suppliedToken: string): LoginResult {
      if (!configuredToken || typeof suppliedToken !== "string" || suppliedToken.length === 0) {
        return { ok: false };
      }

      const matchedOrigin = resolveBrowserOrigin(request);
      if (!matchedOrigin) {
        return { ok: false };
      }

      if (!constantTimeEqual(suppliedToken, configuredToken)) {
        return { ok: false };
      }

      const issued = issueBinding("session", sessionTtlMs);
      const cookie = formatSetCookie(
        SESSION_COOKIE_NAME,
        issued.value,
        sessionTtlMs / 1_000,
        shouldSetSecureCookie(request),
      );
      return { ok: true, cookie };
    },

    csrfToken(request: Request, peer: string | null | undefined): CsrfIssue | null {
      if (configuredToken) {
        const session = readValidSession(request);
        if (!session) {
          return null;
        }
        return { token: issueCsrf("session", session) };
      }

      if (!isDirectLoopbackPeer(peer) || hasProxyForwardingHeaders(request)) {
        return null;
      }

      const existing = readValidLocalBinding(request);
      if (existing) {
        return { token: issueCsrf("local", existing) };
      }

      const issued = issueBinding("local", localCsrfTtlMs);
      const cookie = formatSetCookie(
        LOCAL_CSRF_COOKIE_NAME,
        issued.value,
        localCsrfTtlMs / 1_000,
        shouldSetSecureCookie(request),
      );
      return {
        token: issueCsrf("local", issued.binding),
        cookie,
      };
    },

    sessionExpiresAt(request: Request, _peer: string | null | undefined): number | null {
      if (!configuredToken) {
        return null;
      }
      const bearer = parseBearerAuth(request);
      if (bearer.present) {
        return null;
      }
      const session = readValidSession(request);
      return session ? session.exp : null;
    },
  };
}
