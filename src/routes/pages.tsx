import { Hono, type Context } from "hono";
import type { Child } from "hono/jsx";
import { Layout } from "../templates/layout";
import { App, SecurityNavDot, type SecurityDotState } from "../templates/app";
import { Dashboard } from "../templates/dashboard";
import { Services } from "../templates/services";
import { getAllServices, type ServiceEntry } from "../services/registry";
import { scan } from "../services/scanner";
import { getDemoServices } from "../security/demo";
import type { SecurityView } from "../security/runtime";

export interface RenderPageOptions {
  securityDot?: SecurityDotState | boolean;
  status?: number;
}

export interface PagesRouterOptions {
  demo?: boolean;
  getServices?: () => Promise<ServiceEntry[]> | ServiceEntry[];
  getSecurityDot?: (c: Context) => SecurityDotState | boolean;
}

export function deriveSecurityDot(view: SecurityView | null): SecurityDotState {
  if (!view) {
    return { active: false, count: 0 };
  }
  const activeAlerts = view.alerts.length;
  const pendingProposals = view.proposals.filter((p) => p.status === "pending").length;
  const count = activeAlerts + pendingProposals;
  if (count === 0) {
    return { active: false, count: 0 };
  }

  let severity: SecurityDotState["severity"] = "info";
  if (
    view.alerts.some((a) => a.severity === "breach") ||
    view.latestScan?.verdict?.kind === "breach"
  ) {
    severity = "breach";
  } else if (view.alerts.some((a) => a.severity === "critical")) {
    severity = "critical";
  } else if (pendingProposals > 0 || view.alerts.some((a) => a.severity === "warning")) {
    severity = "warning";
  }

  return { active: true, severity, count };
}

export function renderPage(
  c: Context,
  Page: () => Child,
  title = "Basho",
  options: RenderPageOptions = {},
) {
  c.header("Cache-Control", "no-store");
  const status = (options.status ?? 200) as 200;

  if (c.req.header("HX-Request")) {
    return c.html(
      <>
        {Page()}
        <h1 id="header-title" hx-swap-oob="innerHTML">
          {title}
        </h1>
        <SecurityNavDot state={options.securityDot} oob />
      </>,
      status,
    );
  }

  return c.html(
    <Layout>
      <App title={title} securityDot={options.securityDot}>
        {Page()}
      </App>
    </Layout>,
    status,
  );
}

async function resolveDefaultServices(): Promise<ServiceEntry[]> {
  const staticServices = getAllServices();
  const scanned = await scan();

  const knownUrls = new Set(staticServices.map((s) => s.url));
  const uniqueScanned = scanned.filter((s) => !knownUrls.has(s.url));

  return [...staticServices, ...uniqueScanned];
}

export function createPagesRouter(options: PagesRouterOptions = {}): Hono {
  const app = new Hono();

  app.get("/", (c) =>
    renderPage(c, Dashboard, "Resources", {
      securityDot: options.getSecurityDot?.(c),
    }),
  );

  app.get("/services", async (c) => {
    const services = options.getServices
      ? await options.getServices()
      : options.demo
        ? getDemoServices()
        : await resolveDefaultServices();

    return renderPage(c, () => <Services services={services} />, "Services", {
      securityDot: options.getSecurityDot?.(c),
    });
  });

  return app;
}

export default createPagesRouter();
