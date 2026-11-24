import { Hono } from "hono";
import { getStats, type SystemStats } from "../monitors/system";
import type { SecurityAuth } from "../security/auth";
import { getDemoSystemStats } from "../security/demo";
import type { SecurityRuntime, SecurityUpdate } from "../security/runtime";

const encoder = new TextEncoder();
const KEEP_ALIVE_MS = 15_000;
const SYSTEM_STATS_INTERVAL_MS = 2_000;

export interface SseRouterOptions {
  runtime?: SecurityRuntime;
  auth?: SecurityAuth;
  peer?: (request: Request) => string | null | undefined;
  demo?: boolean;
  getSystemStats?: () => Promise<SystemStats> | SystemStats;
  shutdownSignal?: AbortSignal;
}

const encodeSecurityUpdate = (update: SecurityUpdate): Uint8Array =>
  encoder.encode(`event: security\ndata: ${JSON.stringify(update)}\n\n`);

export function createSseRouter(options: SseRouterOptions = {}): Hono {
  const app = new Hono();
  const resolveStats =
    options.getSystemStats ?? (options.demo ? getDemoSystemStats : getStats);

  app.get("/system-stats", (c) => {
    let cleanupRef: (() => void) | null = null;

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        let closed = false;
        let cpuInterval: ReturnType<typeof setInterval> | null = null;
        let keepAliveInterval: ReturnType<typeof setInterval> | null = null;

        const onAbort = () => {
          cleanup();
        };

        const cleanup = () => {
          if (closed) return;
          closed = true;
          if (cpuInterval !== null) {
            clearInterval(cpuInterval);
            cpuInterval = null;
          }
          if (keepAliveInterval !== null) {
            clearInterval(keepAliveInterval);
            keepAliveInterval = null;
          }
          c.req.raw.signal.removeEventListener("abort", onAbort);
          options.shutdownSignal?.removeEventListener("abort", onAbort);
          try {
            controller.close();
          } catch {}
        };
        cleanupRef = cleanup;

        if (c.req.raw.signal.aborted || options.shutdownSignal?.aborted) {
          cleanup();
          return;
        }

        const send = (data: string) => {
          if (closed) return;
          try {
            controller.enqueue(encoder.encode(`data: ${data}\n\n`));
          } catch {
            cleanup();
          }
        };

        const pushStats = async () => {
          if (closed) return;
          try {
            const stats = await resolveStats();
            if (closed) return;
            send(JSON.stringify({ type: "system", ...stats }));
          } catch {
            // Keep SSE connection alive across transient monitor errors.
          }
        };

        void pushStats();

        cpuInterval = setInterval(() => {
          void pushStats();
        }, SYSTEM_STATS_INTERVAL_MS);

        keepAliveInterval = setInterval(() => {
          if (closed) return;
          try {
            controller.enqueue(encoder.encode(": keep-alive\n\n"));
          } catch {
            cleanup();
          }
        }, KEEP_ALIVE_MS);

        c.req.raw.signal.addEventListener("abort", onAbort, { once: true });
        options.shutdownSignal?.addEventListener("abort", onAbort, { once: true });
      },
      cancel() {
        cleanupRef?.();
      },
    });

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
        "X-Accel-Buffering": "no",
        "Access-Control-Allow-Origin": "*",
      },
    });
  });

  app.get("/security", (c) => {
    const runtime = options.runtime;
    const auth = options.auth;
    const peer = options.peer;

    if (!runtime || !auth || !peer) {
      return new Response("Security runtime unavailable", {
        status: 404,
        headers: { "Cache-Control": "no-store" },
      });
    }

    const request = c.req.raw;
    const peerIp = peer(request);

    if (!auth.authorizeRead(request, peerIp)) {
      return new Response("Unauthorized", {
        status: 401,
        headers: { "Cache-Control": "no-store" },
      });
    }

    if (options.shutdownSignal?.aborted) {
      return new Response("Service shutting down", {
        status: 503,
        headers: { "Cache-Control": "no-store" },
      });
    }

    let cleanupRef: (() => void) | null = null;

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        let closed = false;
        let unsubscribe: (() => void) | null = null;
        let keepAliveInterval: ReturnType<typeof setInterval> | null = null;

        const onAbort = () => {
          cleanup();
        };

        const cleanup = () => {
          if (closed) return;
          closed = true;
          if (keepAliveInterval !== null) {
            clearInterval(keepAliveInterval);
            keepAliveInterval = null;
          }
          if (unsubscribe !== null) {
            const unsub = unsubscribe;
            unsubscribe = null;
            try {
              unsub();
            } catch {}
          }
          request.signal.removeEventListener("abort", onAbort);
          options.shutdownSignal?.removeEventListener("abort", onAbort);
          try {
            controller.close();
          } catch {}
        };
        cleanupRef = cleanup;

        const ensureAuthorized = (): boolean => {
          if (closed) return false;
          if (!auth.authorizeRead(request, peerIp)) {
            cleanup();
            return false;
          }
          return true;
        };

        if (request.signal.aborted || options.shutdownSignal?.aborted) {
          cleanup();
          return;
        }

        unsubscribe = runtime.subscribe((update) => {
          if (!ensureAuthorized()) return;
          try {
            controller.enqueue(encodeSecurityUpdate(update));
          } catch {
            cleanup();
          }
        });

        try {
          controller.enqueue(encodeSecurityUpdate({ kind: "status" }));
        } catch {
          cleanup();
          return;
        }

        keepAliveInterval = setInterval(() => {
          if (!ensureAuthorized()) return;
          try {
            controller.enqueue(encoder.encode(": keep-alive\n\n"));
          } catch {
            cleanup();
          }
        }, KEEP_ALIVE_MS);

        if (
          typeof keepAliveInterval === "object" &&
          keepAliveInterval !== null &&
          "unref" in keepAliveInterval
        ) {
          (keepAliveInterval as { unref?: () => void }).unref?.();
        }

        request.signal.addEventListener("abort", onAbort, { once: true });
        options.shutdownSignal?.addEventListener("abort", onAbort, { once: true });
      },
      cancel() {
        cleanupRef?.();
      },
    });

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-store",
        Connection: "keep-alive",
        "X-Accel-Buffering": "no",
      },
    });
  });

  return app;
}

export default createSseRouter();
