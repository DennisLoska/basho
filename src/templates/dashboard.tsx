function ChartSVG(id: string, colorVar: string, gradientId: string) {
  return (
    <svg class="w-full h-24" id={`${id}-chart`} viewBox="0 0 137 45" preserveAspectRatio="none">
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color={colorVar} stop-opacity="0.3" />
          <stop offset="100%" stop-color={colorVar} stop-opacity="0.02" />
        </linearGradient>
      </defs>
      <line x1="14" y1="3" x2="14" y2="40" stroke="var(--color-base-content)" stroke-opacity="0.12" stroke-width="1" />
      <line x1="14" y1="21.5" x2="135" y2="21.5" stroke="var(--color-base-content)" stroke-opacity="0.08" stroke-width="0.5" stroke-dasharray="2,2" />
      <line x1="14" y1="40" x2="135" y2="40" stroke="var(--color-base-content)" stroke-opacity="0.12" stroke-width="0.5" />
      <text id={`${id}-yl-0`} x="12" y="6" text-anchor="end" fill="var(--color-base-content)" fill-opacity="0.25" font-size="3.5" font-family="monospace">100</text>
      <text id={`${id}-yl-1`} x="12" y="24.5" text-anchor="end" fill="var(--color-base-content)" fill-opacity="0.25" font-size="3.5" font-family="monospace">50</text>
      <text id={`${id}-yl-2`} x="12" y="43" text-anchor="end" fill="var(--color-base-content)" fill-opacity="0.25" font-size="3.5" font-family="monospace">0</text>
      <path id={`${id}-chart-fill`} fill={`url(#${gradientId})`} d="" />
      <path id={`${id}-chart-line`} fill="none" stroke={colorVar} stroke-width="1.5" d="" />
    </svg>
  );
}

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
          <div id="cpu-info">
            <div class="text-4xl font-bold text-accent" id="cpu-average">0%</div>
            <div class="text-sm text-base-content/60 mt-1">Average</div>
            <div class="h-3 bg-base-300 rounded-full mt-2 overflow-hidden">
              <div id="cpu-bar" class="h-full bg-accent rounded-full transition-all duration-500" style="width: 0%" />
            </div>
          </div>
          <div class="mt-auto pt-3">{ChartSVG("cpu", "var(--color-accent)", "cpu-fill")}</div>
        </div>
      </div>

      <div class="card bg-base-200/60 backdrop-blur-sm border border-base-300/50 shadow-xl">
        <div class="card-body">
          <div class="flex items-center gap-2 mb-2">
            <div class="w-3 h-3 rounded-full bg-primary animate-pulse" />
            <h2 class="card-title text-lg">RAM</h2>
          </div>
          <div id="ram-info">
            <div class="text-4xl font-bold text-primary" id="ram-percent">0%</div>
            <div class="text-sm text-base-content/60 mt-1">
              <span id="ram-used">0.0</span> GB / <span id="ram-total">0.0</span> GB &middot; Cache: <span id="ram-cached">0.0</span> GB
            </div>
            <div class="h-3 bg-base-300 rounded-full mt-2 overflow-hidden">
              <div id="ram-bar" class="h-full bg-primary rounded-full transition-all duration-500" style="width: 0%" />
            </div>
          </div>
          <div class="mt-auto pt-3">{ChartSVG("ram", "var(--color-primary)", "ram-fill")}</div>
        </div>
      </div>

      <div class="card bg-base-200/60 backdrop-blur-sm border border-base-300/50 shadow-xl">
        <div class="card-body">
          <div class="flex items-center gap-2 mb-2">
            <div class="w-3 h-3 rounded-full bg-secondary animate-pulse" />
            <h2 class="card-title text-lg">GPU</h2>
          </div>
          <div id="gpu-info">
            <div class="text-4xl font-bold text-secondary" id="gpu-util">N/A</div>
            <div class="text-sm text-base-content/60 mt-1">
              <span id="gpu-temp">--</span>°C &middot; Util &middot; VRAM: <span id="gpu-vram-used">0</span> / <span id="gpu-vram-total">0</span> MB
              <span id="gpu-fan" class="hidden">&middot; Fan: <span id="gpu-fan-speed">--</span>%</span>
            </div>
            <div class="h-3 bg-base-300 rounded-full mt-2 overflow-hidden">
              <div id="gpu-bar" class="h-full bg-secondary rounded-full transition-all duration-500" style="width: 0%" />
            </div>
            <div class="text-xs text-base-content/40 mt-0.5">VRAM usage</div>
          </div>
          <div class="mt-auto pt-3">{ChartSVG("gpu", "var(--color-secondary)", "gpu-fill")}</div>
        </div>
      </div>
    </div>
  </div>
);
