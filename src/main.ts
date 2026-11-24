import { Hono } from "hono";
import { serveStatic } from "hono/bun";
import type { SystemStats } from "./monitors/system";
import { createPagesRouter, deriveSecurityDot } from "./routes/pages";
import { createSecurityRouter } from "./routes/security";
import { createSseRouter } from "./routes/sse";
import { createSecurityAuth, type SecurityAuth } from "./security/auth";
import { loadSecurityConfig } from "./security/config";
import { createDemoSecurityRuntime } from "./security/demo";
import {
  createLiveSecurityRuntime,
  type SecurityRuntime,
} from "./security/runtime";
import { loadServices, type ServiceEntry } from "./services/registry";

export interface CreateAppOptions {
  runtime: SecurityRuntime;
  auth: SecurityAuth;
  peer?: (request: Request) => string | null | undefined;
  demo?: boolean;
  shutdownSignal?: AbortSignal;
  publicOrigin?: string;
  getServices?: () => Promise<ServiceEntry[]> | ServiceEntry[];
  getSystemStats?: () => Promise<SystemStats> | SystemStats;
}

export interface BashoApp {
  fetch: Hono["fetch"];
  request(input: Request | string | URL, init?: RequestInit): Promise<Response>;
}

export function createApp(options: CreateAppOptions): BashoApp {
  const resolvePeer = options.peer ?? (() => undefined);
  const app = new Hono();

  app.use("/static/*", serveStatic({ root: "./" }));

  app.route(
    "/",
    createPagesRouter({
      demo: options.demo,
      getServices: options.getServices,
      getSecurityDot: (c) =>
        options.auth.authorizeRead(c.req.raw, resolvePeer(c.req.raw))
          ? deriveSecurityDot(options.runtime.view())
          : { active: false },
    }),
  );

  app.route(
    "/",
    createSecurityRouter({
      runtime: options.runtime,
      auth: options.auth,
      peer: resolvePeer,
      publicOrigin: options.publicOrigin,
    }),
  );

  app.route(
    "/sse",
    createSseRouter({
      runtime: options.runtime,
      auth: options.auth,
      peer: resolvePeer,
      demo: options.demo,
      getSystemStats: options.getSystemStats,
      shutdownSignal: options.shutdownSignal,
    }),
  );

  app.notFound((c) => c.text("Not found", 404));

  return {
    fetch: app.fetch,
    request: (input, init) => Promise.resolve(app.request(input, init)),
  };
}

async function startServer(): Promise<void> {
  const { settings, secrets } = loadSecurityConfig();
  const demo = settings.process.demo;

  if (!demo) {
    await loadServices();
  }

  const runtime = demo
    ? createDemoSecurityRuntime()
    : createLiveSecurityRuntime({ settings, secrets });

  const auth = createSecurityAuth({
    token: secrets.authToken,
    publicOrigin: settings.notifications.publicOrigin,
  });

  const shutdownController = new AbortController();
  let server: ReturnType<typeof Bun.serve> | null = null;

  const app = createApp({
    runtime,
    auth,
    demo,
    publicOrigin: settings.notifications.publicOrigin,
    shutdownSignal: shutdownController.signal,
    peer: (request) => server?.requestIP(request)?.address ?? null,
  });

  try {
    server = Bun.serve({
      port: settings.process.port,
      hostname: settings.process.host,
      fetch: app.fetch,
    });
  } catch (error) {
    await runtime.stop().catch(() => {});
    throw error;
  }

  runtime.start();

  const modeLabel = demo ? " [DEMO SECURITY]" : "";
  console.log(
    `⚡ Basho running on http://${settings.process.host}:${settings.process.port}${modeLabel}`,
  );

  let shuttingDown = false;
  const shutdown = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    try {
      server?.stop();
    } catch {}
    shutdownController.abort();
    await runtime.stop().catch(() => {});
    process.exit(0);
  };

  process.on("SIGINT", () => {
    void shutdown();
  });
  process.on("SIGTERM", () => {
    void shutdown();
  });
}

if (import.meta.main) {
  await startServer();
}
