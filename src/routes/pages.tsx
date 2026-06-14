import { Hono, Context } from "hono";
import { Layout } from "../templates/layout";
import { App } from "../templates/app";
import { Dashboard } from "../templates/dashboard";
import { Services } from "../templates/services";
import { getAllServices } from "../services/registry";
import { scan } from "../services/scanner";

const app = new Hono();

function renderPage(c: Context, Page: () => any, title = "Basho") {
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
      <App title={title}>
        <Page />
      </App>
    </Layout>,
  );
}

app.get("/", (c) => renderPage(c, Dashboard, "Resources"));

app.get("/services", async (c) => {
  const staticServices = getAllServices();
  const scanned = await scan();

  const knownUrls = new Set(staticServices.map((s) => s.url));
  const uniqueScanned = scanned.filter((s) => !knownUrls.has(s.url));

  const services = [...staticServices, ...uniqueScanned];

  return renderPage(
    c,
    () => <Services services={services} />,
    "Services",
  );
});

export default app;
