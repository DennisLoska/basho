import { expect, test } from "bun:test";
import { createApp, createServeOptions } from "../../src/main";
import { createDemoSecurityRuntime } from "../../src/security/demo";
import { createSecurityAuth } from "../../src/security/auth";

const LOCAL_ORIGIN = "http://localhost";
const LOOPBACK = "127.0.0.1";
const REMOTE_PEER = "198.51.100.42";
const TOKEN = "secret-fixture";

type RequestApp = { request(input: string, init?: RequestInit): Promise<Response> };
type DemoRuntime = ReturnType<typeof createDemoSecurityRuntime>;
type Auth = ReturnType<typeof createSecurityAuth>;
type CsrfField = { name: string; value: string };

// ---------------------------------------------------------------------------
// Request / response helpers
// ---------------------------------------------------------------------------

function setCookieHeaders(response: Response): string[] {
  const headers = response.headers as Headers & { getSetCookie?: () => string[] };
  if (typeof headers.getSetCookie === "function") {
    const list = headers.getSetCookie();
    if (list.length > 0) return list;
  }
  const raw = response.headers.get("set-cookie");
  return raw ? [raw] : [];
}

function cookieHeader(response: Response): string {
  return setCookieHeaders(response)
    .map((value) => value.split(";")[0]?.trim() ?? "")
    .filter((value) => value.length > 0)
    .join("; ");
}

function attribute(tag: string, name: string): string | null {
  const match = new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`, "i").exec(tag);
  return match?.[1] ?? null;
}

function extractCsrf(html: string): CsrfField | null {
  for (const tag of html.match(/<input\b[^>]*>/gi) ?? []) {
    const name = attribute(tag, "name");
    if (!name || !/^(?:_?csrf|csrfToken)$/i.test(name)) continue;
    const value = attribute(tag, "value");
    if (value) return { name, value };
  }
  return null;
}

function navTag(html: string, path: string): string | null {
  for (const tag of html.match(/<a\b[^>]*>/gi) ?? []) {
    if (tag.includes(`data-nav-path="${path}"`)) return tag;
  }
  return null;
}

function isActiveNav(tag: string | null): boolean {
  return tag !== null && /\bactive\b/.test(tag);
}

interface MutationOptions {
  cookie?: string | null;
  origin?: string | null;
  csrf?: CsrfField | null;
  contentType?: string;
  htmx?: boolean;
  headers?: Record<string, string>;
}

function mutation(
  body: Record<string, string> | string,
  options: MutationOptions = {},
): RequestInit {
  const csrf = options.csrf ?? null;
  const encoded =
    typeof body === "string"
      ? body
      : new URLSearchParams({
          ...body,
          ...(csrf ? { [csrf.name]: csrf.value } : {}),
        }).toString();
  const origin = options.origin === undefined ? LOCAL_ORIGIN : options.origin;
  const headers: Record<string, string> = {
    "content-type": options.contentType ?? "application/x-www-form-urlencoded",
    ...(options.cookie ? { cookie: options.cookie } : {}),
    ...(origin === null ? {} : { origin }),
    ...(options.htmx ? { "HX-Request": "true" } : {}),
    ...(options.headers ?? {}),
  };
  return { method: "POST", headers, body: encoded };
}

type StreamReader = {
  read(): Promise<{ done: boolean; value?: Uint8Array }>;
};

async function readText(
  reader: StreamReader,
  timeoutMs = 1_000,
): Promise<string | null> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), timeoutMs);
  });
  const read = reader
    .read()
    .then(({ done, value }) => (done ? "" : new TextDecoder().decode(value)))
    .catch(() => "");
  const result = await Promise.race([read, timeout]);
  if (timer !== undefined) clearTimeout(timer);
  return result;
}

async function closesWithin(
  reader: StreamReader,
  timeoutMs: number,
): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<boolean>((resolve) => {
    timer = setTimeout(() => resolve(false), timeoutMs);
  });
  const drained = (async () => {
    try {
      while (true) {
        const { done } = await reader.read();
        if (done) return true;
      }
    } catch {
      return true;
    }
  })();
  const result = await Promise.race([drained, timeout]);
  if (timer !== undefined) clearTimeout(timer);
  return result === true;
}

async function expectStatus(response: Response, allowed: readonly number[]): Promise<void> {
  if (!allowed.includes(response.status)) {
    const text = await response.text();
    throw new Error(
      `Expected status ${allowed.join("/")} but received ${response.status}: ${text.slice(0, 200)}`,
    );
  }
}

interface DemoContext {
  app: RequestApp;
  runtime: DemoRuntime;
  auth: Auth;
}

async function withDemoApp(
  run: (context: DemoContext) => Promise<void>,
  config: {
    token?: string;
    clock?: { now: () => number };
    peer?: string;
    auth?: Auth;
  } = {},
): Promise<void> {
  const runtime = createDemoSecurityRuntime();
  const auth =
    config.auth ??
    createSecurityAuth({
      ...(config.token ? { token: config.token } : {}),
      ...(config.clock ? { clock: config.clock } : {}),
    });
  const app = createApp({
    runtime,
    peer: () => config.peer ?? LOOPBACK,
    demo: true,
    auth,
  });
  try {
    await run({ app, runtime, auth });
  } finally {
    await runtime.stop();
  }
}

async function localSession(
  app: RequestApp,
): Promise<{ cookie: string; csrf: CsrfField }> {
  const page = await app.request(`${LOCAL_ORIGIN}/security`);
  expect(page.status).toBe(200);
  const html = await page.text();
  const csrf = extractCsrf(html);
  expect(csrf).not.toBeNull();
  const cookie = cookieHeader(page);
  expect(cookie.length).toBeGreaterThan(0);
  return { cookie, csrf: csrf as CsrfField };
}

// ---------------------------------------------------------------------------
// Required verbatim Step 1 tests from the plan
// ---------------------------------------------------------------------------

test("Security uses the existing shell and HTMX partial convention", async () => {
  const runtime = createDemoSecurityRuntime();
  const app = createApp({
    runtime, peer: () => "127.0.0.1", demo: true,
    auth: createSecurityAuth({ clock: { now: () => Date.now() } }),
  });
  try {
    const full = await (await app.request("http://localhost/security")).text();
    expect(full).toContain("grid-cols-3");
    expect(full).toContain("lab-node-01");
    expect(full).toContain("data-security-stream");
    const partial = await (await app.request("http://localhost/security", {
      headers: { "HX-Request": "true" },
    })).text();
    expect(partial).toContain('hx-swap-oob="innerHTML"');
    expect(partial).not.toContain('id="bottom-nav"');
    expect((await app.request("http://localhost/security/mode", {
      method: "POST", body: new URLSearchParams({ mode: "monitor" }),
    })).status).toBe(403);
  } finally { await runtime.stop(); }
});

test("Security SSE publishes readiness and removes its subscription on cancellation", async () => {
  const runtime = createDemoSecurityRuntime();
  let subscriptions = 0;
  const subscribe = runtime.subscribe.bind(runtime);
  runtime.subscribe = (listener) => {
    subscriptions++;
    const unsubscribe = subscribe(listener);
    return () => { subscriptions--; unsubscribe(); };
  };
  const app = createApp({
    runtime, peer: () => "127.0.0.1", demo: true,
    auth: createSecurityAuth({ clock: { now: () => Date.now() } }),
  });
  try {
    const response = await app.request("http://localhost/sse/security");
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    expect(response.headers.has("access-control-allow-origin")).toBe(false);
    const reader = response.body!.getReader();
    expect(new TextDecoder().decode((await reader.read()).value)).toContain("event: security");
    await reader.cancel();
    expect(subscriptions).toBe(0);
  } finally { await runtime.stop(); }
});

// ---------------------------------------------------------------------------
// Navigation, existing tabs, and demo isolation
// ---------------------------------------------------------------------------

test("Resources and Services keep the three-tab shell with an active tab", async () => {
  await withDemoApp(async ({ app }) => {
    const resources = await app.request(`${LOCAL_ORIGIN}/`);
    expect(resources.status).toBe(200);
    expect(resources.headers.get("cache-control")).toContain("no-store");
    const resourcesHtml = await resources.text();
    expect(resourcesHtml).toContain("grid-cols-3");
    expect(resourcesHtml).toContain('href="/security"');
    expect(navTag(resourcesHtml, "/security")).not.toBeNull();
    expect(isActiveNav(navTag(resourcesHtml, "/"))).toBe(true);
    expect(isActiveNav(navTag(resourcesHtml, "/services"))).toBe(false);

    const services = await app.request(`${LOCAL_ORIGIN}/services`);
    expect(services.status).toBe(200);
    const servicesHtml = await services.text();
    expect(servicesHtml).toContain("grid-cols-3");
    expect(isActiveNav(navTag(servicesHtml, "/services"))).toBe(true);
    expect(isActiveNav(navTag(servicesHtml, "/"))).toBe(false);
    expect(navTag(servicesHtml, "/security")).not.toBeNull();
  });
});

test("demo mode serves fixture Services without probing the host", async () => {
  await withDemoApp(async ({ app }) => {
    const response = await app.request(`${LOCAL_ORIGIN}/services`);
    const html = await response.text();
    expect(html).toContain("192.0.2.12");
    expect(html).toContain("ComfyUI");
    expect(html).toContain("Synthetic image workflow service");
    expect(html).not.toContain("198.51.100.42");
  });
});

test("demo mode streams fixture system stats over SSE", async () => {
  await withDemoApp(async ({ app }) => {
    const response = await app.request(`${LOCAL_ORIGIN}/sse/system-stats`);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    const reader = response.body!.getReader();
    try {
      const chunk = await readText(reader, 2_000);
      expect(chunk).not.toBeNull();
      const payload = (chunk ?? "").split("data: ")[1] ?? "";
      const stats = JSON.parse(payload);
      expect(stats.type).toBe("system");
      expect(stats.cpu.count).toBe(8);
      expect(stats.ram.total).toBe(32);
      expect(stats.gpu.memoryTotal).toBe(16384);
    } finally {
      await reader.cancel();
    }
  });
});

test("Security HTMX partial returns the panel plus out-of-band header and dot", async () => {
  await withDemoApp(async ({ app }) => {
    const response = await app.request(`${LOCAL_ORIGIN}/security`, {
      headers: { "HX-Request": "true" },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("no-store");
    const html = await response.text();
    expect(html).toContain("lab-node-01");
    expect(html).toContain('id="header-title"');
    expect(html).toContain('hx-swap-oob="innerHTML"');
    expect((html.match(/hx-swap-oob/g) ?? []).length).toBeGreaterThanOrEqual(2);
    expect(html).not.toContain('id="bottom-nav"');
  });
});

test("fragment and status API are uncached and never wildcard-CORS", async () => {
  await withDemoApp(async ({ app }) => {
    const fragment = await app.request(`${LOCAL_ORIGIN}/security/fragment`);
    expect(fragment.status).toBe(200);
    expect(fragment.headers.get("cache-control")).toContain("no-store");
    expect(fragment.headers.get("access-control-allow-origin")).toBeNull();
    const fragmentHtml = await fragment.text();
    expect(fragmentHtml).toContain("demo-proposal-pending-1");
    expect(fragmentHtml).not.toContain('id="bottom-nav"');

    const status = await app.request(`${LOCAL_ORIGIN}/api/security/status`);
    expect(status.status).toBe(200);
    expect(status.headers.get("content-type")).toContain("application/json");
    expect(status.headers.get("cache-control")).toContain("no-store");
    expect(status.headers.get("access-control-allow-origin")).toBeNull();
    const body = await status.text();
    expect(body).toContain("lab-node-01");
    expect(body).not.toMatch(/api[_-]?key|authorization|bearer/i);
  });
});

// ---------------------------------------------------------------------------
// UI content and escaping
// ---------------------------------------------------------------------------

test("Security renders the KPIs, controls, containment, exposure, audit, and activity", async () => {
  await withDemoApp(async ({ app, runtime }) => {
    const response = await app.request(`${LOCAL_ORIGIN}/security`);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("no-store");
    const html = await response.text();
    const lower = html.toLowerCase();

    for (const kpi of ["posture", "exposure", "updates", "alerts 24h"]) {
      expect(lower).toContain(kpi);
    }
    expect(lower).toContain("breach");
    expect(lower).toContain("scan now");
    expect(lower).toContain("test alert");
    expect(lower).toContain("ready");
    expect(lower).toMatch(/next (scan|run)/);
    expect(html).toContain('name="mode"');
    expect(html).toContain('value="auto-lockdown"');
    expect(html).toContain("firewall_ufw");
    expect(lower).toContain("protected");
    expect(lower).toContain("helper");
    expect(html).toMatch(/role="status"|aria-live/);
    expect(html).toContain("sticky");
    expect(html).toContain("demo-alert-breach-1");
    expect(html).toContain("/security/alerts/demo-alert-breach-1/dismiss");

    expect(html).toContain("demo-proposal-pending-1");
    expect(html).toContain('name="revision"');
    expect(html).toContain("/security/proposals/demo-proposal-pending-1/approve");
    expect(html).toContain("/security/proposals/demo-proposal-pending-1/reject");
    expect(html).toMatch(/\bev:[a-z0-9-]+/i);
    expect(html).toMatch(/evidence/i);

    const action = runtime.view().actions.find((entry) => entry.state === "active");
    expect(action).toBeDefined();
    expect(html).toContain(`/security/actions/${action?.id}/unlock`);

    expect(lower).toContain("reachability");
    expect(html).toMatch(/type="search"|name="search"|name="q"/);
    expect(html).toContain("firewall");
    expect(html).toContain("<svg");
    expect(html).toMatch(/24h/i);
    expect(html).toContain("<details");
    expect(lower).toContain("investigation trail");
    expect(lower).toContain("hide noise");
    expect(lower).toContain("benign multicast");
    expect(html).toContain("data-security-stream");
    expect(html).toContain('hx-history="false"');
    expect(html).toContain("2 UFW-OPEN");
    expect(html).toContain("3 LAN-bound");
    expect(html).toContain(`data-next-scan-at="${runtime.view().nextScanAt}"`);
  });
});

test("Security escapes hostile fixture text instead of rendering markup", async () => {
  await withDemoApp(async ({ app, runtime }) => {
    const script = "<script>alert(1)</script>";
    const image = '"><img src=x onerror=alert(1)>';
    const baseView = runtime.view.bind(runtime);
    runtime.view = () => {
      const view = baseView();
      const alert = view.alerts[0];
      const event = view.events[0];
      return {
        ...view,
        hostLabel: script,
        alerts: alert ? [{ ...alert, summary: `${script} ${image}` }, ...view.alerts.slice(1)] : view.alerts,
        events: event ? [{ ...event, summary: `${image} ${script}` }, ...view.events.slice(1)] : view.events,
      };
    };

    const response = await app.request(`${LOCAL_ORIGIN}/security`);
    expect(response.status).toBe(200);
    const html = await response.text();
    expect(html).not.toContain(script);
    expect(html).not.toContain("<img src=x onerror=alert(1)>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("&lt;img");
    expect(html).toContain("&quot;");
  });
});

// ---------------------------------------------------------------------------
// Auth, login, CSRF, origin, content type, size, duplicate fields
// ---------------------------------------------------------------------------

test("token auth redirects anonymous page reads and rejects anonymous API and SSE", async () => {
  await withDemoApp(
    async ({ app, runtime }) => {
      const page = await app.request(`${LOCAL_ORIGIN}/security`);
      await expectStatus(page, [302, 303]);
      expect(page.headers.get("location") ?? "").toContain("/security/login");
      expect(page.headers.get("cache-control")).toContain("no-store");

      const htmxPage = await app.request(`${LOCAL_ORIGIN}/security`, {
        headers: { "HX-Request": "true" },
      });
      await expectStatus(htmxPage, [200, 204]);
      expect(htmxPage.headers.get("hx-redirect")).toBe("/security/login");
      expect(htmxPage.headers.get("location")).toBeNull();
      expect(htmxPage.headers.get("cache-control")).toContain("no-store");
      const htmxBody = await htmxPage.text();
      expect(htmxBody).not.toContain('id="security-panel"');
      expect(htmxBody).not.toContain("lab-node-01");

      const api = await app.request(`${LOCAL_ORIGIN}/api/security/status`);
      await expectStatus(api, [401, 403]);
      expect(api.headers.get("cache-control")).toContain("no-store");
      expect(api.headers.get("access-control-allow-origin")).toBeNull();

      let subscriptions = 0;
      const subscribe = runtime.subscribe.bind(runtime);
      runtime.subscribe = (listener) => {
        subscriptions++;
        const unsubscribe = subscribe(listener);
        return () => {
          subscriptions--;
          unsubscribe();
        };
      };
      const sse = await app.request(`${LOCAL_ORIGIN}/sse/security`);
      await expectStatus(sse, [401, 403]);
      expect(sse.headers.get("cache-control")).toContain("no-store");
      expect(subscriptions).toBe(0);
    },
    { token: TOKEN },
  );
});

test("login page renders and login rejects wrong origin and wrong token", async () => {
  await withDemoApp(
    async ({ app }) => {
      const page = await app.request(`${LOCAL_ORIGIN}/security/login`);
      expect(page.status).toBe(200);
      expect(page.headers.get("cache-control")).toContain("no-store");
      const html = await page.text();
      expect(html).toContain('name="token"');
      expect(html.toLowerCase()).toContain("password");
      expect(html).toContain('hx-history="false"');

      const badOrigin = await app.request(
        `${LOCAL_ORIGIN}/security/login`,
        mutation({ token: TOKEN }, { origin: "http://evil.example" }),
      );
      await expectStatus(badOrigin, [403]);

      const badToken = await app.request(
        `${LOCAL_ORIGIN}/security/login`,
        mutation({ token: "wrong-token" }),
      );
      await expectStatus(badToken, [401, 403]);
      expect(badToken.headers.get("cache-control")).toContain("no-store");
      expect(cookieHeader(badToken)).not.toContain("basho_session=");
    },
    { token: TOKEN },
  );
});

test("login issues an HttpOnly session accepted by page, API, SSE, and mutations", async () => {
  await withDemoApp(
    async ({ app, runtime }) => {
      const login = await app.request(
        `${LOCAL_ORIGIN}/security/login`,
        mutation({ token: TOKEN }),
      );
      expect(login.status).toBe(303);
      expect(login.headers.get("location") ?? "").toContain("/security");
      expect(login.headers.get("cache-control")).toContain("no-store");
      const setCookies = setCookieHeaders(login);
      const session = setCookies.find((value) => value.includes("basho_session=")) ?? "";
      expect(session).toContain("HttpOnly");
      expect(session).toContain("SameSite=Lax");
      expect(session).toContain("Path=/");
      const cookie = cookieHeader(login);
      expect(cookie).toContain("basho_session=");

      const page = await app.request(`${LOCAL_ORIGIN}/security`, { headers: { cookie } });
      expect(page.status).toBe(200);
      const html = await page.text();
      const csrf = extractCsrf(html);
      expect(csrf).not.toBeNull();

      const api = await app.request(`${LOCAL_ORIGIN}/api/security/status`, {
        headers: { cookie },
      });
      expect(api.status).toBe(200);

      const sse = await app.request(`${LOCAL_ORIGIN}/sse/security`, { headers: { cookie } });
      expect(sse.status).toBe(200);
      expect(sse.headers.get("content-type")).toContain("text/event-stream");
      const reader = sse.body!.getReader();
      expect((await readText(reader)) ?? "").toContain("event: security");
      await reader.cancel();

      const mutate = await app.request(
        `${LOCAL_ORIGIN}/security/mode`,
        mutation({ mode: "auto-lockdown" }, { cookie, csrf }),
      );
      expect(mutate.status).toBe(303);
      expect(runtime.view().settings.mode).toBe("auto-lockdown");
    },
    { token: TOKEN },
  );
});

test("bearer clients read and mutate without CSRF but cannot smuggle a foreign origin", async () => {
  await withDemoApp(
    async ({ app, runtime }) => {
      const authHeader = { authorization: `Bearer ${TOKEN}` };

      const api = await app.request(`${LOCAL_ORIGIN}/api/security/status`, {
        headers: authHeader,
      });
      expect(api.status).toBe(200);

      const originless = await app.request(
        `${LOCAL_ORIGIN}/security/mode`,
        mutation({ mode: "monitor" }, { origin: null, headers: authHeader }),
      );
      expect(originless.status).toBe(303);
      expect(runtime.view().settings.mode).toBe("monitor");

      const conflicting = await app.request(
        `${LOCAL_ORIGIN}/security/mode`,
        mutation({ mode: "approve" }, { origin: "http://evil.example", headers: authHeader }),
      );
      await expectStatus(conflicting, [403]);
      expect(runtime.view().settings.mode).toBe("monitor");

      const sameOrigin = await app.request(
        `${LOCAL_ORIGIN}/security/mode`,
        mutation({ mode: "approve" }, { headers: authHeader }),
      );
      expect(sameOrigin.status).toBe(303);
      expect(runtime.view().settings.mode).toBe("approve");
    },
    { token: TOKEN },
  );
});

test("local rendered form supplies the cookie and CSRF token used by mutations", async () => {
  await withDemoApp(async ({ app, runtime }) => {
    const { cookie, csrf } = await localSession(app);

    const response = await app.request(
      `${LOCAL_ORIGIN}/security/mode`,
      mutation({ mode: "auto-lockdown" }, { cookie, csrf }),
    );
    expect(response.status).toBe(303);
    expect(runtime.view().settings.mode).toBe("auto-lockdown");
  });
});

test("local mutations reject missing CSRF, foreign origin, and remote peers", async () => {
  const runtime = createDemoSecurityRuntime();
  const auth = createSecurityAuth({ clock: { now: () => Date.now() } });
  const localApp = createApp({ runtime, peer: () => LOOPBACK, demo: true, auth });
  const remoteApp = createApp({ runtime, peer: () => REMOTE_PEER, demo: true, auth });
  try {
    const page = await localApp.request(`${LOCAL_ORIGIN}/security`);
    const csrf = extractCsrf(await page.text());
    expect(csrf).not.toBeNull();
    const cookie = cookieHeader(page);
    expect(cookie.length).toBeGreaterThan(0);

    const missingCsrf = await localApp.request(
      `${LOCAL_ORIGIN}/security/mode`,
      mutation({ mode: "approve" }, { cookie, csrf: null }),
    );
    await expectStatus(missingCsrf, [403]);

    const foreignOrigin = await localApp.request(
      `${LOCAL_ORIGIN}/security/mode`,
      mutation({ mode: "approve" }, { cookie, csrf, origin: "http://evil.example" }),
    );
    await expectStatus(foreignOrigin, [403]);

    const remote = await remoteApp.request(
      `${LOCAL_ORIGIN}/security/mode`,
      mutation({ mode: "approve" }, { cookie, csrf }),
    );
    await expectStatus(remote, [403]);
    expect(runtime.view().settings.mode).toBe("approve");
  } finally {
    await runtime.stop();
  }
});

test("mutations reject malformed content type, oversized bodies, and duplicate fields", async () => {
  await withDemoApp(async ({ app, runtime }) => {
    const { cookie, csrf } = await localSession(app);

    const json = await app.request(
      `${LOCAL_ORIGIN}/security/mode`,
      mutation(JSON.stringify({ mode: "monitor" }), {
        contentType: "application/json",
        cookie,
      }),
    );
    await expectStatus(json, [400, 415]);

    const oversized = await app.request(
      `${LOCAL_ORIGIN}/security/mode`,
      mutation(`mode=monitor&${csrf.name}=${csrf.value}&pad=${"x".repeat(70 * 1024)}`, {
        cookie,
      }),
    );
    await expectStatus(oversized, [400, 413]);

    const duplicate = await app.request(
      `${LOCAL_ORIGIN}/security/mode`,
      mutation(`mode=monitor&mode=approve&${csrf.name}=${csrf.value}`, { cookie }),
    );
    expect(duplicate.status).toBe(400);

    const empty = await app.request(
      `${LOCAL_ORIGIN}/security/mode`,
      mutation("", { cookie }),
    );
    await expectStatus(empty, [400, 403]);
    expect(runtime.view().settings.mode).toBe("approve");
  });
});

// ---------------------------------------------------------------------------
// Mutation routes
// ---------------------------------------------------------------------------

test("scan queues on form and HTMX requests and mode rejects unknown values", async () => {
  await withDemoApp(async ({ app, runtime }) => {
    const { cookie, csrf } = await localSession(app);

    const htmxScan = await app.request(
      `${LOCAL_ORIGIN}/security/scan`,
      mutation({}, { cookie, csrf, htmx: true }),
    );
    expect(htmxScan.status).toBe(200);

    const formScan = await app.request(
      `${LOCAL_ORIGIN}/security/scan`,
      mutation({}, { cookie, csrf }),
    );
    expect(formScan.status).toBe(303);

    const validMode = await app.request(
      `${LOCAL_ORIGIN}/security/mode`,
      mutation({ mode: "monitor" }, { cookie, csrf }),
    );
    expect(validMode.status).toBe(303);
    expect(runtime.view().settings.mode).toBe("monitor");

    const invalidMode = await app.request(
      `${LOCAL_ORIGIN}/security/mode`,
      mutation({ mode: "bogus-mode" }, { cookie, csrf }),
    );
    expect(invalidMode.status).toBe(400);
    expect(runtime.view().settings.mode).toBe("monitor");
  });
});

test("settings updates the interval and criteria and rejects invalid fields", async () => {
  await withDemoApp(async ({ app, runtime }) => {
    const { cookie, csrf } = await localSession(app);

    const interval = await app.request(
      `${LOCAL_ORIGIN}/security/settings`,
      mutation({ scanIntervalMinutes: "15" }, { cookie, csrf }),
    );
    expect(interval.status).toBe(303);
    expect(runtime.view().settings.scanIntervalMinutes).toBe(15);

    for (const invalid of ["0", "-4", "1441", "abc"]) {
      const response = await app.request(
        `${LOCAL_ORIGIN}/security/settings`,
        mutation({ scanIntervalMinutes: invalid }, { cookie, csrf }),
      );
      expect(response.status).toBe(400);
    }

    const criteria = await app.request(
      `${LOCAL_ORIGIN}/security/settings`,
      mutation({ "criteria.firewall_ufw": "off" }, { cookie, csrf }),
    );
    expect(criteria.status).toBe(303);
    expect(runtime.view().settings.criteria.firewall_ufw).toBe(false);

    const unknown = await app.request(
      `${LOCAL_ORIGIN}/security/settings`,
      mutation({ "criteria.not_a_real_criterion": "on" }, { cookie, csrf }),
    );
    expect(unknown.status).toBe(400);
  });
});

test("proposal approval requires a positive revision and conflicts when stale", async () => {
  await withDemoApp(async ({ app, runtime }) => {
    const { cookie, csrf } = await localSession(app);
    const pending = runtime
      .view()
      .proposals.find((proposal) => proposal.status === "pending" && proposal.revision === 1);
    expect(pending).toBeDefined();
    const id = pending?.id as string;

    for (const revision of ["0", "-1", "abc"]) {
      const malformed = await app.request(
        `${LOCAL_ORIGIN}/security/proposals/${id}/approve`,
        mutation({ revision }, { cookie, csrf }),
      );
      expect(malformed.status).toBe(400);
    }

    const approved = await app.request(
      `${LOCAL_ORIGIN}/security/proposals/${id}/approve`,
      mutation({ revision: "1" }, { cookie, csrf }),
    );
    expect(approved.status).toBe(303);
    const after = runtime.view();
    expect(after.proposals.find((proposal) => proposal.id === id)?.status).not.toBe("pending");
    expect(after.actions.some((action) => action.proposalId === id)).toBe(true);

    const stale = await app.request(
      `${LOCAL_ORIGIN}/security/proposals/${id}/approve`,
      mutation({ revision: "1" }, { cookie, csrf }),
    );
    expect(stale.status).toBe(409);

    const unknown = await app.request(
      `${LOCAL_ORIGIN}/security/proposals/does-not-exist/approve`,
      mutation({ revision: "1" }, { cookie, csrf }),
    );
    expect(unknown.status).toBe(409);
  });
});

test("proposal rejection transitions the proposal and rejects unknown revisions", async () => {
  await withDemoApp(async ({ app, runtime }) => {
    const { cookie, csrf } = await localSession(app);
    const pending = runtime
      .view()
      .proposals.find((proposal) => proposal.status === "pending" && proposal.revision === 1);
    expect(pending).toBeDefined();
    const id = pending?.id as string;

    const missingRevision = await app.request(
      `${LOCAL_ORIGIN}/security/proposals/${id}/reject`,
      mutation({}, { cookie, csrf }),
    );
    expect(missingRevision.status).toBe(400);

    const rejected = await app.request(
      `${LOCAL_ORIGIN}/security/proposals/${id}/reject`,
      mutation({ revision: "1" }, { cookie, csrf }),
    );
    expect(rejected.status).toBe(303);
    expect(runtime.view().proposals.find((proposal) => proposal.id === id)?.status).toBe(
      "rejected",
    );

    const stale = await app.request(
      `${LOCAL_ORIGIN}/security/proposals/${id}/reject`,
      mutation({ revision: "1" }, { cookie, csrf }),
    );
    expect(stale.status).toBe(409);
  });
});

test("unlock rolls back idempotently and dismiss removes the alert", async () => {
  await withDemoApp(async ({ app, runtime }) => {
    const { cookie, csrf } = await localSession(app);
    const action = runtime.view().actions.find((entry) => entry.state === "active");
    expect(action).toBeDefined();
    const actionId = action?.id as string;

    const htmxUnlock = await app.request(
      `${LOCAL_ORIGIN}/security/actions/${actionId}/unlock`,
      mutation({}, { cookie, csrf, htmx: true }),
    );
    expect(htmxUnlock.status).toBe(200);
    expect(runtime.view().actions.find((entry) => entry.id === actionId)?.state).toBe(
      "rolled_back",
    );

    const formUnlock = await app.request(
      `${LOCAL_ORIGIN}/security/actions/${actionId}/unlock`,
      mutation({}, { cookie, csrf }),
    );
    expect(formUnlock.status).toBe(303);
    expect(runtime.view().actions.find((entry) => entry.id === actionId)?.state).toBe(
      "rolled_back",
    );

    const alert = runtime.view().alerts[0];
    expect(alert).toBeDefined();
    const alertId = alert?.id as string;

    const dismissed = await app.request(
      `${LOCAL_ORIGIN}/security/alerts/${alertId}/dismiss`,
      mutation({}, { cookie, csrf }),
    );
    expect(dismissed.status).toBe(303);
    expect(runtime.view().alerts.some((entry) => entry.id === alertId)).toBe(false);
  });
});

test("test alert queues an eligible channel and rejects an ineligible one", async () => {
  await withDemoApp(async ({ app }) => {
    const { cookie, csrf } = await localSession(app);

    const delivered = await app.request(
      `${LOCAL_ORIGIN}/security/test-alert`,
      mutation({ channel: "in-app" }, { cookie, csrf }),
    );
    expect(delivered.status).toBe(303);
    const deliveredText = await delivered.text();
    expect(deliveredText).not.toContain(TOKEN);

    const ineligible = await app.request(
      `${LOCAL_ORIGIN}/security/test-alert`,
      mutation({ channel: "pager" }, { cookie, csrf }),
    );
    expect(ineligible.status).toBe(400);
    const ineligibleText = await ineligible.text();
    expect(ineligibleText).not.toContain(TOKEN);
  });
});

// ---------------------------------------------------------------------------
// SSE live updates and lifecycle
// ---------------------------------------------------------------------------

test("SSE publishes runtime updates to an open security client", async () => {
  await withDemoApp(async ({ app, runtime }) => {
    const response = await app.request(`${LOCAL_ORIGIN}/sse/security`);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
    const reader = response.body!.getReader();
    try {
      expect((await readText(reader, 2_000)) ?? "").toContain("event: security");

      runtime.updateSettings({ scanIntervalMinutes: 45 });
      const update = await readText(reader, 2_000);
      expect(update ?? "").toContain("event: security");
      expect(update ?? "").toContain('"kind":"settings"');
    } finally {
      await reader.cancel();
    }
  });
});

test("SSE closes and unsubscribes when the authenticated session expires", async () => {
  let now = 1_800_000_000_000;
  const clock = { now: () => now };
  const auth = createSecurityAuth({ token: TOKEN, clock, sessionTtlMs: 5 * 60 * 1_000 });

  await withDemoApp(
    async ({ app, runtime }) => {
      const login = await app.request(
        `${LOCAL_ORIGIN}/security/login`,
        mutation({ token: TOKEN }),
      );
      expect(login.status).toBe(303);
      const cookie = cookieHeader(login);
      expect(cookie).toContain("basho_session=");

      let subscriptions = 0;
      const subscribe = runtime.subscribe.bind(runtime);
      runtime.subscribe = (listener) => {
        subscriptions++;
        const unsubscribe = subscribe(listener);
        return () => {
          subscriptions--;
          unsubscribe();
        };
      };

      const response = await app.request(`${LOCAL_ORIGIN}/sse/security`, {
        headers: { cookie },
      });
      expect(response.status).toBe(200);
      const reader = response.body!.getReader();
      try {
        expect((await readText(reader, 2_000)) ?? "").toContain("event: security");
        expect(subscriptions).toBe(1);

        now += 10 * 60 * 1_000;
        runtime.updateSettings({ scanIntervalMinutes: 30 });

        const closed = await closesWithin(reader, 2_000);
        expect(closed).toBe(true);
        expect(subscriptions).toBe(0);
      } finally {
        await reader.cancel();
      }
    },
    { auth },
  );
});

// ---------------------------------------------------------------------------
// Security hardening regression tests (Stage 1 & Stage 2 review findings)
// ---------------------------------------------------------------------------

test("token-mode anonymous HTMX mutations with malformed bodies never leak SecurityPanel", async () => {
  await withDemoApp(
    async ({ app }) => {
      const duplicate = await app.request(
        `${LOCAL_ORIGIN}/security/scan`,
        mutation("a=1&a=2", { htmx: true }),
      );
      await expectStatus(duplicate, [401, 403]);
      expect(duplicate.headers.get("cache-control")).toContain("no-store");
      const duplicateBody = await duplicate.text();
      expect(duplicateBody).not.toContain('id="security-panel"');
      expect(duplicateBody).not.toContain("lab-node-01");
      expect(duplicateBody).not.toContain("demo-alert-breach-1");

      const manyFields = Array.from({ length: 66 }, (_, i) => `f${i}=1`).join("&");
      const tooMany = await app.request(
        `${LOCAL_ORIGIN}/security/scan`,
        mutation(manyFields, { htmx: true }),
      );
      await expectStatus(tooMany, [401, 403]);
      expect(tooMany.headers.get("cache-control")).toContain("no-store");
      const tooManyBody = await tooMany.text();
      expect(tooManyBody).not.toContain('id="security-panel"');
      expect(tooManyBody).not.toContain("lab-node-01");
      expect(tooManyBody).not.toContain("demo-alert-breach-1");

      const invalidUtf8 = await app.request(`${LOCAL_ORIGIN}/security/scan`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          origin: LOCAL_ORIGIN,
          "HX-Request": "true",
        },
        body: new Uint8Array([0xff, 0xfe, 0xfd]),
      });
      await expectStatus(invalidUtf8, [401, 403]);
      expect(invalidUtf8.headers.get("cache-control")).toContain("no-store");
      const invalidUtf8Body = await invalidUtf8.text();
      expect(invalidUtf8Body).not.toContain('id="security-panel"');
      expect(invalidUtf8Body).not.toContain("lab-node-01");
      expect(invalidUtf8Body).not.toContain("demo-alert-breach-1");
    },
    { token: TOKEN },
  );
});

test("dismissAlert returns 404 for unknown or already-dismissed alerts and catches runtime throws", async () => {
  await withDemoApp(async ({ app, runtime }) => {
    const { cookie, csrf } = await localSession(app);

    const unknown = await app.request(
      `${LOCAL_ORIGIN}/security/alerts/does-not-exist/dismiss`,
      mutation({}, { cookie, csrf }),
    );
    expect(unknown.status).toBe(404);

    const unknownHtmx = await app.request(
      `${LOCAL_ORIGIN}/security/alerts/does-not-exist/dismiss`,
      mutation({}, { cookie, csrf, htmx: true }),
    );
    expect(unknownHtmx.status).toBe(404);
    expect(await unknownHtmx.text()).toContain('id="security-panel"');

    const alertId = runtime.view().alerts[0]?.id as string;
    const first = await app.request(
      `${LOCAL_ORIGIN}/security/alerts/${alertId}/dismiss`,
      mutation({}, { cookie, csrf }),
    );
    expect(first.status).toBe(303);

    const second = await app.request(
      `${LOCAL_ORIGIN}/security/alerts/${alertId}/dismiss`,
      mutation({}, { cookie, csrf }),
    );
    expect(second.status).toBe(404);

    // Runtime throwing internal errors must return sanitized 409, never 500 or secret text
    const leakedSecret = "internal-helper-secret-9911";
    runtime.approve = async () => {
      throw new Error(leakedSecret);
    };
    runtime.reject = () => {
      throw new Error(leakedSecret);
    };
    runtime.unlock = async () => {
      throw new Error(leakedSecret);
    };
    runtime.dismissAlert = () => {
      throw new Error(leakedSecret);
    };

    const approveErr = await app.request(
      `${LOCAL_ORIGIN}/security/proposals/p1/approve`,
      mutation({ revision: "1" }, { cookie, csrf }),
    );
    expect(approveErr.status).toBe(409);
    expect(await approveErr.text()).not.toContain(leakedSecret);

    const rejectErr = await app.request(
      `${LOCAL_ORIGIN}/security/proposals/p1/reject`,
      mutation({ revision: "1" }, { cookie, csrf }),
    );
    expect(rejectErr.status).toBe(409);
    expect(await rejectErr.text()).not.toContain(leakedSecret);

    const unlockErr = await app.request(
      `${LOCAL_ORIGIN}/security/actions/a1/unlock`,
      mutation({}, { cookie, csrf }),
    );
    expect(unlockErr.status).toBe(409);
    expect(await unlockErr.text()).not.toContain(leakedSecret);

    const dismissErr = await app.request(
      `${LOCAL_ORIGIN}/security/alerts/al1/dismiss`,
      mutation({}, { cookie, csrf }),
    );
    expect(dismissErr.status).toBe(409);
    expect(await dismissErr.text()).not.toContain(leakedSecret);
  });
});

test("POST /security/login rate-limits repeated failed attempts per peer and resets on success or window expiry", async () => {
  let now = 1_800_000_000_000;
  let currentPeer = "198.51.100.10";
  const clock = { now: () => now };
  const runtime = createDemoSecurityRuntime();
  const auth = createSecurityAuth({ token: TOKEN, clock });
  const app = createApp({
    runtime,
    auth,
    demo: true,
    peer: () => currentPeer,
  });

  try {
    for (let i = 0; i < 5; i++) {
      const fail = await app.request(
        `${LOCAL_ORIGIN}/security/login`,
        mutation({ token: "wrong-token" }),
      );
      expect(fail.status).toBe(401);
      expect(fail.headers.get("cache-control")).toContain("no-store");
    }

    const blocked = await app.request(
      `${LOCAL_ORIGIN}/security/login`,
      mutation({ token: "wrong-token" }),
    );
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("cache-control")).toContain("no-store");
    const retryAfter = Number(blocked.headers.get("retry-after"));
    expect(Number.isFinite(retryAfter) && retryAfter > 0).toBe(true);

    // Different peer is unaffected and successful login resets its own counter
    currentPeer = "198.51.100.11";
    const otherFail = await app.request(
      `${LOCAL_ORIGIN}/security/login`,
      mutation({ token: "wrong-token" }),
    );
    expect(otherFail.status).toBe(401);
    const otherOk = await app.request(
      `${LOCAL_ORIGIN}/security/login`,
      mutation({ token: TOKEN }),
    );
    expect(otherOk.status).toBe(303);

    // After the 5-minute window expires, original peer can authenticate again
    currentPeer = "198.51.100.10";
    now += 5 * 60 * 1_000 + 1_000;
    const recovered = await app.request(
      `${LOCAL_ORIGIN}/security/login`,
      mutation({ token: TOKEN }),
    );
    expect(recovered.status).toBe(303);
  } finally {
    await runtime.stop();
  }
});

test("SSE closes proactively on session expiry timer without waiting for keep-alive or runtime updates", async () => {
  const auth = createSecurityAuth({ token: TOKEN, sessionTtlMs: 80 });

  await withDemoApp(
    async ({ app, runtime }) => {
      const login = await app.request(
        `${LOCAL_ORIGIN}/security/login`,
        mutation({ token: TOKEN }),
      );
      expect(login.status).toBe(303);
      const cookie = cookieHeader(login);

      let subscriptions = 0;
      const subscribe = runtime.subscribe.bind(runtime);
      runtime.subscribe = (listener) => {
        subscriptions++;
        const unsubscribe = subscribe(listener);
        return () => {
          subscriptions--;
          unsubscribe();
        };
      };

      const response = await app.request(`${LOCAL_ORIGIN}/sse/security`, {
        headers: { cookie },
      });
      expect(response.status).toBe(200);
      const reader = response.body!.getReader();
      try {
        expect((await readText(reader, 1_000)) ?? "").toContain("event: security");
        expect(subscriptions).toBe(1);

        // No runtime update emitted — timer alone must close the stream promptly
        const closed = await closesWithin(reader, 1_500);
        expect(closed).toBe(true);
        expect(subscriptions).toBe(0);
      } finally {
        await reader.cancel();
      }
    },
    { auth },
  );
});

test("static/handlers.js supports 400/409 swaps, live countdown, flash/dirty preservation, and SSE backoff", async () => {
  const source = await Bun.file("static/handlers.js").text();
  // Ensure handlers.js parses cleanly as valid JavaScript
  expect(() => new Function(source)).not.toThrow();

  // Verify htmx:beforeSwap enables swapping 400/404/409 #security-panel fragments
  expect(source).toContain("detail.shouldSwap = true");
  expect(source).toContain("detail.isError = false");
  expect(source).toContain('id="security-panel"');

  // Verify live next-scan countdown interval + clock skew sync + cleanup
  expect(source).toContain("data-next-scan-at");
  expect(source).toContain("data-server-now");
  expect(source).toContain("stopSecurityCountdown");

  // Verify flash preservation, dirty control tracking, and bounded reconnect backoff
  expect(source).toContain("SECURITY_FLASH_TTL_MS");
  expect(source).toContain("#security-mode-select");
  expect(source).toContain("#scan-interval-input");
  expect(source).toContain('[name^="criteria."]');
  expect(source).toContain("#security-test-channel");
  expect(source).toContain("scheduleSecurityReconnect");
  expect(source).toContain("SECURITY_RECONNECT_MAX_MS");
});

test("POST /security/login enforces rate limit across concurrent requests from one peer", async () => {
  const now = 1_800_000_000_000;
  const runtime = createDemoSecurityRuntime();
  const auth = createSecurityAuth({ token: TOKEN, clock: { now: () => now } });
  const app = createApp({
    runtime,
    auth,
    demo: true,
    peer: () => "198.51.100.77",
  });

  try {
    const totalRequests = 12;
    const responses = await Promise.all(
      Array.from({ length: totalRequests }, () =>
        app.request(`${LOCAL_ORIGIN}/security/login`, mutation({ token: "wrong-token" })),
      ),
    );

    const unauthorized = responses.filter((res) => res.status === 401);
    const rateLimited = responses.filter((res) => res.status === 429);

    expect(unauthorized.length).toBeLessThanOrEqual(5);
    expect(unauthorized.length).toBeGreaterThanOrEqual(1);
    expect(unauthorized.length + rateLimited.length).toBe(totalRequests);
    expect(rateLimited.length).toBeGreaterThanOrEqual(totalRequests - 5);

    for (const res of rateLimited) {
      expect(res.headers.get("cache-control")).toContain("no-store");
      const retryAfter = Number(res.headers.get("retry-after"));
      expect(Number.isFinite(retryAfter) && retryAfter > 0).toBe(true);
    }
  } finally {
    await runtime.stop();
  }
});

test("SecurityPanel renders data-server-now from runtime view and handlers.js syncs countdown against clock skew", async () => {
  const serverClock = 1_800_000_000_000;
  await withDemoApp(
    async ({ app, runtime }) => {
      const demoView = runtime.view();
      expect(typeof demoView.serverNow).toBe("number");
      expect(demoView.nextScanAt).not.toBeNull();
      expect(demoView.nextScanAt!).toBeGreaterThan(demoView.serverNow);

      const pageHtml = await (await app.request(`${LOCAL_ORIGIN}/security`)).text();
      expect(pageHtml).toContain(`data-server-now="${demoView.serverNow}"`);
      expect(pageHtml).not.toContain("Next scan: due now");

      const fragHtml = await (await app.request(`${LOCAL_ORIGIN}/security/fragment`)).text();
      expect(fragHtml).toContain(`data-server-now="${demoView.serverNow}"`);
      expect(fragHtml).not.toContain("Next scan: due now");
    },
    { clock: { now: () => serverClock } },
  );

  // Execute static/handlers.js in an isolated harness where browser Date.now() is skewed by 2 hours
  const source = await Bun.file("static/handlers.js").text();
  let browserNow = serverClock - 2 * 60 * 60 * 1_000;
  let intervalCallback: (() => void) | null = null;
  const docListeners = new Map<string, Array<(evt: unknown) => void>>();

  const makeCountdownEl = (nextScanAt: number, serverNow: number) => {
    const attrs: Record<string, string> = {
      "data-next-scan-at": String(nextScanAt),
      "data-server-now": String(serverNow),
      "data-scan-running": "false",
    };
    return {
      textContent: "",
      getAttribute: (name: string) => (name in attrs ? attrs[name] : null),
    };
  };

  let countdownEl = makeCountdownEl(serverClock + 90_000, serverClock);
  const makePanel = () => ({
    id: "security-panel",
    getAttribute: (name: string) => (name === "data-security-stream" ? "/sse/security" : null),
    querySelector: (sel: string) => (sel === "[data-next-scan-at]" ? countdownEl : null),
    querySelectorAll: () => [],
    contains: () => false,
  });
  let panel = makePanel();

  const fakeDoc = {
    readyState: "complete",
    activeElement: null,
    documentElement: {
      getAttribute: () => "opencode",
      setAttribute: () => {},
    },
    getElementById: (id: string) => (id === "security-panel" ? panel : null),
    querySelector: (sel: string) => (sel === "[data-security-stream]" ? panel : null),
    querySelectorAll: () => [],
    addEventListener: (name: string, fn: (evt: unknown) => void) => {
      const list = docListeners.get(name) ?? [];
      list.push(fn);
      docListeners.set(name, list);
    },
  };
  const fakeWin = {
    location: { pathname: "/security", hostname: "localhost" },
    addEventListener: () => {},
  };
  const fakeDate = { now: () => browserNow };
  const fakeSetInterval = (fn: () => void) => {
    intervalCallback = fn;
    return 1;
  };
  const fakeClearInterval = () => {
    intervalCallback = null;
  };

  const run = new Function(
    "window",
    "document",
    "Date",
    "setInterval",
    "clearInterval",
    "EventSource",
    source,
  );
  run(
    fakeWin,
    fakeDoc,
    fakeDate,
    fakeSetInterval,
    fakeClearInterval,
    function FakeEventSource() {
      throw new Error("no-sse-in-unit-test");
    },
  );

  // Initial render: 90s remaining despite 2h browser clock skew
  expect(countdownEl.textContent).toBe("Next scan: 1m 30s");

  // Advance browser clock by 10s -> countdown ticks down to 1m 20s (offset stays fixed)
  browserNow += 10_000;
  expect(intervalCallback).not.toBeNull();
  intervalCallback!();
  expect(countdownEl.textContent).toBe("Next scan: 1m 20s");

  // Simulate panel swap with a fresh serverNow + nextScanAt and a different skew
  const swappedServerNow = serverClock + 30_000;
  browserNow += 5_000; // client jumped differently than server
  countdownEl = makeCountdownEl(swappedServerNow + 45_000, swappedServerNow);
  panel = makePanel();
  for (const fn of docListeners.get("htmx:afterSwap") ?? []) {
    fn({ detail: { target: panel, elt: panel } });
  }
  expect(countdownEl.textContent).toBe("Next scan: 45s");

  // Tick 5s after swap -> 40s
  browserNow += 5_000;
  intervalCallback!();
  expect(countdownEl.textContent).toBe("Next scan: 40s");
});

// ---------------------------------------------------------------------------
// Council Round 1 Cluster B regression tests (F03, F04, F08, F25)
// ---------------------------------------------------------------------------

test("F03: UPDATES KPI tile reads live PostureCollector package_updates facts (criterion + kernelUpdateCount)", async () => {
  await withDemoApp(async ({ app, runtime }) => {
    const baseView = runtime.view.bind(runtime);
    runtime.view = () => {
      const view = baseView();
      const scan = view.latestScan!;
      return {
        ...view,
        latestScan: {
          ...scan,
          snapshot: {
            ...scan.snapshot,
            evidence: scan.snapshot.evidence.map((ev) =>
              ev.kind === "criterion" && ev.facts.criterionId === "package_updates"
                ? {
                    id: ev.id,
                    kind: "criterion",
                    facts: {
                      criterion: "package_updates",
                      pendingCount: 4,
                      kernelUpdateCount: 1,
                      daysSinceLastUpgrade: 3,
                      advisoryCount: 0,
                      highAdvisoryCount: 0,
                    },
                  }
                : ev,
            ),
          },
        },
      };
    };

    const html = await (await app.request(`${LOCAL_ORIGIN}/security`)).text();
    expect(html).toContain("4 PENDING");
    expect(html).toContain("KERNEL PENDING");
  });
});

test("F04: server options set idleTimeout above SSE keep-alive and disable timeout on /sse/* requests", async () => {
  await withDemoApp(async ({ app }) => {
    const options = createServeOptions({
      port: 6969,
      hostname: "127.0.0.1",
      app: app as Parameters<typeof createServeOptions>[0]["app"],
    });
    expect(options.idleTimeout).toBeGreaterThan(15);
    expect(options.idleTimeout).toBe(60);

    const calls: Array<{ url: string; seconds: number }> = [];
    const mockServer = {
      timeout(req: Request, seconds: number) {
        calls.push({ url: req.url, seconds });
      },
    };

    const pageReq = new Request(`${LOCAL_ORIGIN}/security`);
    const pageRes = await options.fetch(pageReq, mockServer);
    expect(pageRes.status).toBe(200);
    expect(calls.length).toBe(0);

    const sseReq = new Request(`${LOCAL_ORIGIN}/sse/security`);
    const sseRes = await options.fetch(sseReq, mockServer);
    expect(sseRes.status).toBe(200);
    expect(calls).toEqual([{ url: `${LOCAL_ORIGIN}/sse/security`, seconds: 0 }]);
    await sseRes.body?.cancel();
  });
});

test("F08: live SecurityPanel computes nextScan, proposal expiry, and lease remaining from view.serverNow", async () => {
  await withDemoApp(async ({ app, runtime }) => {
    const baseView = runtime.view.bind(runtime);
    const base = baseView();
    const scanFinishedAt = base.latestScan!.finishedAt;
    // Advance live serverNow 20 minutes past the last stored scan/event/action timestamp
    const advancedNow = scanFinishedAt + 20 * 60_000;

    runtime.view = () => {
      const view = baseView();
      return {
        ...view,
        serverNow: advancedNow,
        nextScanAt: advancedNow + 12 * 60_000, // 12m 0s from serverNow (would be 32m from scanFinishedAt)
        proposals: view.proposals.map((p) =>
          p.status === "pending"
            ? { ...p, expiresAt: advancedNow + 7 * 60_000 } // 7m 0s from serverNow (27m from scanFinishedAt)
            : p,
        ),
        actions: view.actions.map((a) =>
          a.state === "active"
            ? { ...a, expiresAt: advancedNow + 3 * 60_000 } // 3m 0s from serverNow (23m from scanFinishedAt)
            : a,
        ),
      };
    };

    const html = await (await app.request(`${LOCAL_ORIGIN}/security`)).text();
    expect(html).toContain(`data-server-now="${advancedNow}"`);
    expect(html).toContain("Next scan: 12m 0s");
    expect(html).toContain("expires 7m 0s");
    expect(html).toContain("Remaining: 3m 0s");
  });
});

test("F25: cross-origin POST /security/login returns 403 without burning peer rate-limit quota", async () => {
  await withDemoApp(
    async ({ app }) => {
      for (let i = 0; i < 10; i++) {
        const res = await app.request(
          `${LOCAL_ORIGIN}/security/login`,
          mutation({ token: "wrong-token" }, { origin: "http://evil.example" }),
        );
        expect(res.status).toBe(403);
        expect(res.headers.get("cache-control")).toContain("no-store");
      }

      // Same-origin valid login from the exact same peer IP must still succeed (303, NOT 429)
      const valid = await app.request(
        `${LOCAL_ORIGIN}/security/login`,
        mutation({ token: TOKEN }),
      );
      expect(valid.status).toBe(303);
      expect(valid.headers.get("location")).toBe("/security");
    },
    { token: TOKEN, peer: "198.51.100.88" },
  );
});
