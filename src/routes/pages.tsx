import { Hono, Context } from "hono";
import { Layout } from "../templates/layout";
import { App } from "../templates/app";
import { Dashboard } from "../templates/dashboard";
import { Services } from "../templates/services";
import { ServiceRegistry } from "../services/registry";
import { ServiceScanner } from "../services/scanner";

const PAGE_TITLES: Record<string, string> = {
  dashboard: "Dashboard",
  services: "Services",
};

const app = new Hono();

function renderPage(c: Context, Page: () => any, page = "") {
  const title = PAGE_TITLES[page] || "Basho";

  if (c.req.header("HX-Request")) {
    return c.html(
      <>
        <Page />
        <h1 id="header-title" hx-swap-oob="innerHTML">
          {title}
        </h1>
      </>,
    );
  }
  return c.html(
    <Layout>
      <App page={page}>
        <Page />
      </App>
    </Layout>,
  );
}

app.get("/", (c) => renderPage(c, Dashboard, "dashboard"));

app.get("/services", async (c) => {
  const staticServices = ServiceRegistry.getAll();
  const scanned = await ServiceScanner.scan();

  const knownUrls = new Set(staticServices.map((s) => s.url));
  const uniqueScanned = scanned.filter((s) => !knownUrls.has(s.url));

  const services = [...staticServices, ...uniqueScanned];

  return renderPage(
    c,
    () => <Services services={services} />,
    "services",
  );
});

export default app;
