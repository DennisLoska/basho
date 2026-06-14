import type { ServiceEntry } from "../services/registry";
import { html } from "hono/html";

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
          class="card bg-base-200/60 backdrop-blur-sm border border-base-300/50 shadow-xl hover:shadow-2xl transition-shadow cursor-pointer relative"
          onclick={"window.open('" + svc.url + "', '_blank')"}
        >
          <div
            class="w-3.5 h-3.5 rounded-full absolute top-3 right-3"
            id={"status-" + svc.name.replace(/\s+/g, "-")}
            title="Checking..."
          />
          <div class="card-body">
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
      <div
        id="services-data"
        data-services="${Buffer.from(JSON.stringify(services)).toString("base64")}"
      ></div>
      <script>
        setTimeout(function() {
          var el = document.getElementById('services-data');
          if (el) {
            var raw = el.getAttribute('data-services');
            var json = atob(raw);
            var svcs = JSON.parse(json);
            window.checkServices(svcs);
          }
        }, 100);
      </script>
    `}
  </div>
);
