import { Hono } from "hono";
import { serveStatic } from "hono/bun";
import pages from "./routes/pages";
import sse from "./routes/sse";
import { ServiceRegistry } from "./services/registry";

await ServiceRegistry.load();

const app = new Hono();

app.use("/static/*", serveStatic({ root: "./" }));

app.route("/", pages);
app.route("/sse", sse);

app.notFound((c) => c.text("Not found", 404));

Bun.serve({
  port: 6969,
  hostname: "0.0.0.0",
  fetch: app.fetch,
});

console.log("⚡ Basho running on http://0.0.0.0:6969");
