import type { ServiceEntry } from "../services/registry";

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
        <div class="card bg-base-200/60 backdrop-blur-sm border border-base-300/50 shadow-xl hover:shadow-2xl transition-shadow">
          <div class="card-body">
            <div class="flex items-center gap-3">
              <span class="text-2xl">{svc.icon || "🔌"}</span>
              <div class="flex-1">
                <h3 class="card-title text-lg">{svc.name}</h3>
                <p class="text-sm text-base-content/60">{svc.description}</p>
              </div>
              <div
                class="w-3 h-3 rounded-full"
                id={"status-" + svc.name.replace(/\s+/g, "-")}
                title="Checking..."
              />
            </div>
            <div class="card-actions justify-end mt-2">
              <a
                href={svc.url}
                target="_blank"
                rel="noopener noreferrer"
                class="btn btn-ghost btn-sm"
              >
                Open →
              </a>
            </div>
          </div>
        </div>
      ))}
    </div>
    <script data-services={JSON.stringify(services)}>{`
      setTimeout(function() {
        var el = document.currentScript || document.querySelector('script[data-services]');
        if (el) {
          var svcs = JSON.parse(el.getAttribute('data-services'));
          window.checkServices(svcs);
        }
      }, 100);
    `}</script>
  </div>
);
