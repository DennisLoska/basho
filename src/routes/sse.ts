import { Hono } from "hono";
import { getStats } from "../monitors/system";

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
        try {
          controller.enqueue(encoder.encode(`data: ${data}\n\n`));
        } catch {}
      };

      const pushStats = async () => {
        if (closed) return;
        const stats = await getStats();
        send(JSON.stringify({ type: "system", ...stats }));
      };

      pushStats();

      cpuInterval = setInterval(pushStats, 2000);

      keepAliveInterval = setInterval(() => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(": keep-alive\n\n"));
        } catch {}
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
