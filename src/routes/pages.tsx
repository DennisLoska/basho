import { Hono, Context } from "hono";
import { Layout } from "../templates/layout";
import { App } from "../templates/app";
import { Dashboard } from "../templates/dashboard";
import { Services } from "../templates/services";
import { ServiceRegistry } from "../services/registry";

const app = new Hono();

function renderPage(c: Context, Page: () => any, page?: string) {
  if (c.req.header("HX-Request")) {
    return c.html(<Page />);
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

app.get("/services", (c) => {
  const services = ServiceRegistry.getAll();
  return renderPage(
    c,
    () => <Services services={services} />,
    "services",
  );
});

export default app;
