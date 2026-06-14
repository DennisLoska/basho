export const Dashboard = () => (
  <div
    hx-ext="sse"
    sse-connect="/sse/system-stats"
    sse-swap="message"
    class="space-y-6"
  >
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      <div class="card bg-base-200/60 backdrop-blur-sm border border-base-300/50 shadow-xl">
        <div class="card-body">
          <div class="flex items-center gap-2 mb-2">
            <div class="w-3 h-3 rounded-full bg-accent animate-pulse" />
            <h2 class="card-title text-lg">CPU</h2>
            <span class="text-xs text-base-content/40 ml-auto" id="cpu-count" />
          </div>
          <div id="cpu-cores" class="space-y-2">
            <div class="text-4xl font-bold text-accent" id="cpu-average">
              0%
            </div>
            <div class="text-sm text-base-content/60">Average</div>
            <div id="cpu-core-bars" class="space-y-1 mt-3" />
          </div>
        </div>
      </div>

      <div class="card bg-base-200/60 backdrop-blur-sm border border-base-300/50 shadow-xl">
        <div class="card-body">
          <div class="flex items-center gap-2 mb-2">
            <div class="w-3 h-3 rounded-full bg-primary animate-pulse" />
            <h2 class="card-title text-lg">RAM</h2>
          </div>
          <div id="ram-info">
            <div class="text-4xl font-bold text-primary" id="ram-percent">
              0%
            </div>
            <div class="text-sm text-base-content/60 mt-1">
              <span id="ram-used">0.0</span> GB /{" "}
              <span id="ram-total">0.0</span> GB
            </div>
            <div class="text-xs text-base-content/40 mt-0.5">
              Cache: <span id="ram-cached">0.0</span> GB
            </div>
            <div class="h-3 bg-base-300 rounded-full mt-2 overflow-hidden">
              <div
                id="ram-bar"
                class="h-full bg-primary rounded-full transition-all duration-500"
                style="width: 0%"
              />
            </div>
          </div>
        </div>
      </div>

      <div class="card bg-base-200/60 backdrop-blur-sm border border-base-300/50 shadow-xl">
        <div class="card-body">
          <div class="flex items-center gap-2 mb-2">
            <div class="w-3 h-3 rounded-full bg-secondary animate-pulse" />
            <h2 class="card-title text-lg">GPU</h2>
          </div>
          <div id="gpu-info">
            <div class="text-4xl font-bold text-secondary" id="gpu-util">
              N/A
            </div>
            <div class="text-sm text-base-content/60 mt-1">
              <span id="gpu-temp">--</span>°C &middot; Util
            </div>
            <div class="text-sm text-base-content/60">
              VRAM: <span id="gpu-vram-used">0</span> /{" "}
              <span id="gpu-vram-total">0</span> MB
            </div>
            <div class="h-3 bg-base-300 rounded-full mt-3 overflow-hidden">
              <div
                id="gpu-bar"
                class="h-full bg-secondary rounded-full transition-all duration-500"
                style="width: 0%"
              />
            </div>
            <div class="text-xs text-base-content/40 mt-0.5">
              VRAM usage
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
);
