import type { ServiceEntry } from "../services/registry";
import { html, raw } from "hono/html";

export const Services = ({ services }: { services: ServiceEntry[] }) => (
  <div class="space-y-4">
    <h2 class="text-2xl font-bold mb-4">Services</h2>
    {services.length === 0 && (
      <div class="card bg-base-200/60 backdrop-blur-sm border border-base-300/50 shadow-xl">
        <div class="card-body text-center text-base-content/60 py-12">
          <p class="text-lg">No services configured</p>
          <p class="text-sm mt-2">
            Edit config/services.json to add your local services
          </p>
        </div>
      </div>
    )}
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {services.map((svc) => (
        <div
          class="card bg-base-200/60 backdrop-blur-sm border border-base-300/50 shadow-xl hover:shadow-2xl transition-shadow cursor-pointer"
          onclick={"window.open('" + svc.url + "', '_blank')"}
        >
          <div class="card-body pt-3">
            <div
              class="w-3 h-3 rounded-full bg-neutral absolute top-3 right-3 ring-2 ring-base-100"
              id={"status-" + svc.name.replace(/\s+/g, "-")}
              title="Checking..."
            />
            <div class="flex items-center gap-3">
              <span class="text-2xl">{svc.icon || "🔌"}</span>
              <div class="flex-1 min-w-0">
                <h3 class="card-title text-lg truncate">{svc.name}</h3>
                <p class="text-sm text-base-content/60 truncate">{svc.description}</p>
              </div>
            </div>
            <div class="card-actions justify-end mt-2">
              <span class="text-sm text-base-content/40">Click to open →</span>
            </div>
          </div>
        </div>
      ))}
    </div>
    {html`
      <script>
        (function() {
          var svcs = ${raw(JSON.stringify(services))};
          function run() { if (window.checkServices) window.checkServices(svcs); else setTimeout(run, 10); }
          run();
        })();
      </script>
    `}
  </div>
);
