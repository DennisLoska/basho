import { Hono } from "hono";
import { SystemMonitor } from "../monitors/system";

const encoder = new TextEncoder();
const app = new Hono();

app.get("/system-stats", (c) => {
  const stream = new ReadableStream({
    async start(controller) {
      let closed = false;
      let cpuInterval: Timer;
      let keepAliveInterval: Timer;

      const send = (data: string) => {
        if (closed) return;
        controller.enqueue(encoder.encode(`data: ${data}\n\n`));
      };

      cpuInterval = setInterval(async () => {
        const stats = await SystemMonitor.getStats();
        send(JSON.stringify({ type: "system", ...stats }));
      }, 2000);

      keepAliveInterval = setInterval(() => {
        if (closed) return;
        controller.enqueue(encoder.encode(": keep-alive\n\n"));
      }, 15000);

      c.req.raw.signal.addEventListener("abort", () => {
        closed = true;
        clearInterval(cpuInterval);
        clearInterval(keepAliveInterval);
      });
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

export default app;
