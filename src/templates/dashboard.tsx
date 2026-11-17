function ChartSVG(id: string, colorVar: string, gradientId: string) {
  return (
    <svg
      class="w-full h-32 sm:h-40 block"
      id={`${id}-chart`}
      viewBox="0 0 137 45"
      preserveAspectRatio="none"
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color={colorVar} stop-opacity="0.32" />
          <stop offset="100%" stop-color={colorVar} stop-opacity="0.0" />
        </linearGradient>
      </defs>
      <line
        x1="16"
        y1="3"
        x2="135"
        y2="3"
        stroke="var(--color-base-content)"
        stroke-opacity="0.08"
        stroke-width="0.4"
        stroke-dasharray="1.5,1.5"
      />
      <line
        x1="16"
        y1="3"
        x2="16"
        y2="40"
        stroke="var(--color-base-content)"
        stroke-opacity="0.18"
        stroke-width="0.6"
      />
      <line
        x1="16"
        y1="21.5"
        x2="135"
        y2="21.5"
        stroke="var(--color-base-content)"
        stroke-opacity="0.12"
        stroke-width="0.4"
        stroke-dasharray="1.5,1.5"
      />
      <line
        x1="16"
        y1="40"
        x2="135"
        y2="40"
        stroke="var(--color-base-content)"
        stroke-opacity="0.18"
        stroke-width="0.6"
      />
      <text
        id={`${id}-yl-0`}
        x="14"
        y="6"
        text-anchor="end"
        fill="var(--color-base-content)"
        fill-opacity="0.5"
        font-size="3.4"
        font-family="monospace"
      >
        100
      </text>
      <text
        id={`${id}-yl-1`}
        x="14"
        y="22.8"
        text-anchor="end"
        fill="var(--color-base-content)"
        fill-opacity="0.5"
        font-size="3.4"
        font-family="monospace"
      >
        50
      </text>
      <text
        id={`${id}-yl-2`}
        x="14"
        y="40.5"
        text-anchor="end"
        fill="var(--color-base-content)"
        fill-opacity="0.5"
        font-size="3.4"
        font-family="monospace"
      >
        0
      </text>
      <path id={`${id}-chart-fill`} fill={`url(#${gradientId})`} d="" />
      <path
        id={`${id}-chart-line`}
        fill="none"
        stroke={colorVar}
        stroke-width="1.4"
        stroke-linecap="round"
        stroke-linejoin="round"
        d=""
      />
    </svg>
  );
}

export const Dashboard = () => (
  <div
    hx-ext="sse"
    sse-connect="/sse/system-stats"
    sse-swap="message"
    class="space-y-4 sm:space-y-6"
  >
    {/* Mobile-First Quick Telemetry Overview Strip */}
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 sm:gap-3">
      <a
        href="#card-cpu"
        class="oc-panel oc-panel-interactive px-3 py-2.5 flex items-center justify-between gap-2"
      >
        <div class="min-w-0">
          <div class="flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-base-content/55">
            <span class="w-1.5 h-1.5 rounded-full bg-accent" />
            CPU
          </div>
          <div
            id="quick-cpu"
            class="font-mono tabular-nums text-lg sm:text-xl font-bold text-accent mt-0.5"
          >
            0%
          </div>
        </div>
        <span class="text-[10px] font-mono text-base-content/40 uppercase">
          load
        </span>
      </a>

      <a
        href="#card-ram"
        class="oc-panel oc-panel-interactive px-3 py-2.5 flex items-center justify-between gap-2"
      >
        <div class="min-w-0">
          <div class="flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-base-content/55">
            <span class="w-1.5 h-1.5 rounded-full bg-primary" />
            MEM
          </div>
          <div
            id="quick-ram"
            class="font-mono tabular-nums text-lg sm:text-xl font-bold text-primary mt-0.5"
          >
            0%
          </div>
        </div>
        <span
          id="quick-ram-sub"
          class="text-[10px] font-mono tabular-nums text-base-content/40"
        >
          0.0G
        </span>
      </a>

      <a
        href="#card-gpu"
        class="oc-panel oc-panel-interactive px-3 py-2.5 flex items-center justify-between gap-2"
      >
        <div class="min-w-0">
          <div class="flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-base-content/55">
            <span class="w-1.5 h-1.5 rounded-full bg-secondary" />
            GPU
          </div>
          <div
            id="quick-gpu"
            class="font-mono tabular-nums text-lg sm:text-xl font-bold text-secondary mt-0.5"
          >
            N/A
          </div>
        </div>
        <span
          id="quick-gpu-sub"
          class="text-[10px] font-mono tabular-nums text-base-content/40"
        >
          --°C
        </span>
      </a>

      <a
        href="#disks-section"
        class="oc-panel oc-panel-interactive px-3 py-2.5 flex items-center justify-between gap-2"
      >
        <div class="min-w-0">
          <div class="flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-base-content/55">
            <span class="w-1.5 h-1.5 rounded-full bg-info" />
            I/O
          </div>
          <div
            id="quick-io"
            class="font-mono tabular-nums text-lg sm:text-xl font-bold text-info mt-0.5"
          >
            0
          </div>
        </div>
        <span class="text-[10px] font-mono text-base-content/40">ops/s</span>
      </a>
    </div>

    {/* Compute & Memory Telemetry Cards */}
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5 sm:gap-4">
      {/* CPU Card */}
      <section
        id="card-cpu"
        class="oc-panel p-4 sm:p-5 flex flex-col justify-between scroll-mt-16"
      >
        <div>
          <div class="flex items-center justify-between gap-2 pb-3 border-b border-base-300/80">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full bg-accent animate-pulse" />
              <h2 class="font-mono text-xs sm:text-sm font-bold uppercase tracking-wider text-base-content">
                CPU // Compute
              </h2>
            </div>
            <span
              class="font-mono text-[11px] px-2 py-0.5 rounded bg-base-300/70 text-base-content/70"
              id="cpu-count"
            >
              -- logical
            </span>
          </div>

          <div id="cpu-info" class="mt-3">
            <div class="flex items-baseline justify-between gap-2">
              <div
                class="text-3xl sm:text-4xl font-mono tabular-nums font-bold text-accent tracking-tight"
                id="cpu-average"
              >
                0%
              </div>
              <div class="text-xs font-mono text-base-content/50 uppercase">
                avg utilization
              </div>
            </div>

            <div class="h-2 bg-base-300 rounded-sm mt-2.5 overflow-hidden">
              <div
                id="cpu-bar"
                class="h-full bg-accent transition-all duration-500"
                style="width: 0%"
              />
            </div>

            {/* Per-core miniature load matrix */}
            <div
              id="cpu-cores-grid"
              class="grid grid-cols-8 sm:grid-cols-16 gap-1 mt-2.5 empty:hidden"
            />
          </div>
        </div>

        <div class="mt-4 pt-3 border-t border-base-300/50">
          {ChartSVG("cpu", "var(--color-accent)", "cpu-fill")}
        </div>
      </section>

      {/* RAM Card */}
      <section
        id="card-ram"
        class="oc-panel p-4 sm:p-5 flex flex-col justify-between scroll-mt-16"
      >
        <div>
          <div class="flex items-center justify-between gap-2 pb-3 border-b border-base-300/80">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full bg-primary animate-pulse" />
              <h2 class="font-mono text-xs sm:text-sm font-bold uppercase tracking-wider text-base-content">
                RAM // Memory
              </h2>
            </div>
            <span class="font-mono text-[11px] px-2 py-0.5 rounded bg-base-300/70 text-base-content/70">
              Cache: <span id="ram-cached">0.0</span> GB
            </span>
          </div>

          <div id="ram-info" class="mt-3">
            <div class="flex items-baseline justify-between gap-2 flex-wrap">
              <div
                class="text-3xl sm:text-4xl font-mono tabular-nums font-bold text-primary tracking-tight"
                id="ram-percent"
              >
                0%
              </div>
              <div class="text-xs sm:text-sm font-mono tabular-nums text-base-content/70">
                <span id="ram-used" class="text-base-content font-semibold">
                  0.0
                </span>{" "}
                / <span id="ram-total">0.0</span> GB
              </div>
            </div>

            <div class="h-2 bg-base-300 rounded-sm mt-2.5 overflow-hidden">
              <div
                id="ram-bar"
                class="h-full bg-primary transition-all duration-500"
                style="width: 0%"
              />
            </div>
          </div>
        </div>

        <div class="mt-4 pt-3 border-t border-base-300/50">
          {ChartSVG("ram", "var(--color-primary)", "ram-fill")}
        </div>
      </section>

      {/* GPU Card */}
      <section
        id="card-gpu"
        class="oc-panel p-4 sm:p-5 flex flex-col justify-between md:col-span-2 lg:col-span-1 scroll-mt-16"
      >
        <div>
          <div class="flex items-center justify-between gap-2 pb-3 border-b border-base-300/80">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full bg-secondary animate-pulse" />
              <h2 class="font-mono text-xs sm:text-sm font-bold uppercase tracking-wider text-base-content">
                GPU // Accelerator
              </h2>
            </div>
            <div class="flex items-center gap-1.5 font-mono text-[11px]">
              <span class="px-2 py-0.5 rounded bg-base-300/70 text-base-content/80 tabular-nums">
                <span id="gpu-temp">--</span>°C
              </span>
              <span
                id="gpu-fan"
                class="hidden px-2 py-0.5 rounded bg-base-300/70 text-base-content/70 tabular-nums"
              >
                Fan <span id="gpu-fan-speed">--</span>%
              </span>
            </div>
          </div>

          <div id="gpu-info" class="mt-3">
            <div class="flex items-baseline justify-between gap-2 flex-wrap">
              <div
                class="text-3xl sm:text-4xl font-mono tabular-nums font-bold text-secondary tracking-tight"
                id="gpu-util"
              >
                N/A
              </div>
              <div class="text-xs sm:text-sm font-mono tabular-nums text-base-content/70">
                VRAM:{" "}
                <span id="gpu-vram-used" class="text-base-content font-semibold">
                  0
                </span>{" "}
                / <span id="gpu-vram-total">0</span> MB
              </div>
            </div>

            <div class="h-2 bg-base-300 rounded-sm mt-2.5 overflow-hidden">
              <div
                id="gpu-bar"
                class="h-full bg-secondary transition-all duration-500"
                style="width: 0%"
              />
            </div>
            <div class="flex items-center justify-between text-[11px] font-mono text-base-content/45 mt-1">
              <span>VRAM allocation</span>
              <span id="gpu-vram-pct">0%</span>
            </div>
          </div>
        </div>

        <div class="mt-4 pt-3 border-t border-base-300/50">
          {ChartSVG("gpu", "var(--color-secondary)", "gpu-fill")}
        </div>
      </section>
    </div>

    {/* Storage & Disks Section */}
    <div id="disks-section" class="space-y-3 scroll-mt-16">
      <div class="flex items-center justify-between gap-2 px-1">
        <div class="flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-base-content/60">
          <span class="text-info font-bold">//</span>
          <span>Storage Volumes &amp; Block I/O</span>
        </div>
        <div class="font-mono text-[11px] tabular-nums text-base-content/55">
          R: <span id="disk-read-iops" class="text-base-content/85">0</span>/s
          &middot; W:{" "}
          <span id="disk-write-iops" class="text-base-content/85">0</span>/s
        </div>
      </div>

      <div
        id="disks-container"
        class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5 sm:gap-4"
      />
    </div>
  </div>
);
