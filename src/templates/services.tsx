import type { ServiceEntry } from "../services/registry";
import { html, raw } from "hono/html";

function extractPort(url: string): string | null {
  const m = url.match(/:(\d+)/);
  return m ? `:${m[1]}` : null;
}

export const Services = ({ services }: { services: ServiceEntry[] }) => (
  <div class="space-y-4">
    {/* Mobile-Friendly Services Control & Filter Bar */}
    <div class="oc-panel p-3 sm:p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
      <div class="flex items-center justify-between sm:justify-start gap-3">
        <div class="flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-base-content/75">
          <span class="text-primary font-bold">//</span>
          <span>Endpoints</span>
          <span class="px-1.5 py-0.5 rounded bg-base-300 text-base-content font-semibold tabular-nums">
            {services.length}
          </span>
        </div>

        <div class="flex items-center gap-2 font-mono text-[11px] text-base-content/60">
          <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-success/10 border border-success/30 text-success tabular-nums">
            <span class="w-1.5 h-1.5 rounded-full bg-success" />
            <span id="services-online-count">0</span> online
          </span>
        </div>
      </div>

      <div class="flex items-center gap-2">
        <div class="relative flex-1 sm:w-64">
          <input
            id="services-filter"
            type="search"
            placeholder="Filter name or :port..."
            oninput="window.filterServices && window.filterServices(this.value)"
            class="w-full h-9 pl-8 pr-3 rounded bg-base-100 border border-base-300 focus:border-primary focus:outline-none font-mono text-xs text-base-content placeholder:text-base-content/35"
          />
          <svg
            xmlns="http://www.w3.org/2000/svg"
            class="h-3.5 w-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-base-content/40 pointer-events-none"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
        </div>

        <button
          type="button"
          hx-get="/services"
          hx-target="#content"
          hx-swap="innerHTML"
          class="inline-flex items-center gap-1.5 h-9 px-3 rounded bg-base-300/70 hover:bg-base-300 border border-base-300 font-mono text-xs font-medium text-base-content/85 hover:text-primary transition-colors cursor-pointer shrink-0 touch-manipulation"
          title="Rescan local ports"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            class="h-3.5 w-3.5"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width={2}
              d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
            />
          </svg>
          <span>Scan</span>
        </button>
      </div>
    </div>

    {services.length === 0 && (
      <div class="oc-panel p-8 sm:p-12 text-center">
        <div class="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-base-300/60 border border-base-300 text-2xl mb-3">
          🔌
        </div>
        <p class="font-mono text-sm sm:text-base font-semibold text-base-content">
          No active services discovered
        </p>
        <p class="font-mono text-xs text-base-content/55 mt-1.5">
          Edit <code class="text-primary">config/services.json</code> or start a
          local server on ports 1–9999
        </p>
      </div>
    )}

    <div
      id="services-grid"
      class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4"
    >
      {services.map((svc) => {
        const safeId = svc.name.replace(/\s+/g, "-");
        const portBadge = extractPort(svc.url);
        return (
          <a
            href={svc.url}
            target="_blank"
            rel="noopener noreferrer"
            data-service-card="true"
            data-service-url={svc.url}
            data-service-search={`${svc.name} ${svc.description} ${svc.url}`.toLowerCase()}
            class="oc-panel oc-panel-interactive p-4 flex flex-col justify-between gap-3 group no-underline touch-manipulation"
          >
            <div class="flex items-start justify-between gap-3">
              <div class="flex items-center gap-3 min-w-0">
                <div class="w-10 h-10 rounded-md bg-base-300/60 border border-base-300 flex items-center justify-center text-xl shrink-0 group-hover:border-primary/40 transition-colors">
                  {svc.icon || "🔌"}
                </div>
                <div class="min-w-0">
                  <div class="flex items-center gap-2">
                    <h3 class="font-mono text-sm sm:text-base font-bold text-base-content group-hover:text-primary transition-colors truncate">
                      {svc.name}
                    </h3>
                  </div>
                  <p class="text-xs text-base-content/55 truncate mt-0.5">
                    {svc.description}
                  </p>
                </div>
              </div>

              <div class="flex items-center gap-1.5 shrink-0 pt-0.5">
                <span
                  class="w-2.5 h-2.5 rounded-full bg-neutral ring-2 ring-base-200 transition-colors"
                  id={"status-" + safeId}
                  title="Checking..."
                />
              </div>
            </div>

            <div class="flex items-center justify-between gap-2 pt-2.5 border-t border-base-300/60 font-mono text-[11px]">
              <div class="flex items-center gap-1.5 min-w-0">
                {portBadge && (
                  <span class="px-1.5 py-0.5 rounded bg-base-300/80 text-primary font-semibold tabular-nums">
                    {portBadge}
                  </span>
                )}
                <span
                  id={"status-label-" + safeId}
                  class="text-base-content/45 uppercase tracking-wider text-[10px]"
                >
                  checking
                </span>
              </div>

              <span class="inline-flex items-center gap-1 text-base-content/45 group-hover:text-primary transition-colors">
                <span>open</span>
                <span class="group-hover:translate-x-0.5 transition-transform">
                  ↗
                </span>
              </span>
            </div>
          </a>
        );
      })}
    </div>

    {html`
      <script>
        (function() {
          var svcs = ${raw(JSON.stringify(services))};
          function run() {
            if (window.checkServices) window.checkServices(svcs);
            else setTimeout(run, 10);
          }
          run();
        })();
      </script>
    `}
  </div>
);
