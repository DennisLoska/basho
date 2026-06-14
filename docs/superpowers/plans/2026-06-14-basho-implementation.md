# Basho Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Execute this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Build running system monitor dashboard on port 6969

**Architecture:** Hono server with JSX templates (DaisyUI + Tailwind v4), SSE stream for real-time system stats. HTMX for client-side navigation and partial page updates.

**Tech Stack:** Bun, Hono, DaisyUI 5, Tailwind CSS v4, HTMX + SSE extension

---

### Task 1: Project scaffold & dependencies

**Files:**
- Create: `package.json`
- Modify: `tsconfig.json`
- Create: `src/main.ts`

- [ ] **Step 1: Write package.json**

```json
{
  "name": "basho",
  "module": "src/main.ts",
  "type": "module",
  "private": true,
  "scripts": {
    "dev": "bun --hot src/main.ts",
    "build:css": "npx @tailwindcss/cli -i src/templates/app.css -o static/style.css",
    "start": "bun src/main.ts"
  },
  "devDependencies": {
    "@types/bun": "latest"
  },
  "peerDependencies": {
    "typescript": "^5"
  },
  "dependencies": {
    "@tailwindcss/cli": "^4.2.2",
    "daisyui": "^5.0.0",
    "hono": "^4.12.9",
    "tailwindcss": "^4.2.2"
  }
}
```

- [ ] **Step 2: Write minimal main.ts**

```typescript
import { Hono } from "hono";
import { serveStatic } from "hono/bun";

const app = new Hono();

app.use("/static/*", serveStatic({ root: "./" }));

app.get("/", (c) => c.text("Basho starting up..."));

Bun.serve({
  port: 6969,
  hostname: "0.0.0.0",
  fetch: app.fetch,
});

console.log("Basho running on http://0.0.0.0:6969");
```

- [ ] **Step 3: Install dependencies**

Run: `bun install` in project root
Expected: packages installed successfully

- [ ] **Step 4: Verify server starts**

Run: `bun src/main.ts` (Ctrl+C after confirming it prints message)
Expected: "Basho running on http://0.0.0.0:6969"

---

### Task 2: Templates — layout, app shell, CSS

**Files:**
- Create: `src/templates/app.css`
- Create: `src/templates/layout.tsx`
- Create: `src/templates/app.tsx`
- Create: `static/` directory placeholder

- [ ] **Step 1: Write app.css**

```css
@import "tailwindcss";
@plugin "daisyui" {
  themes: light --default, dark --prefersdark, dracula, bumblebee, cupcake;
}

.scrollbar-hide {
  -ms-overflow-style: none;
  scrollbar-width: none;
}

.scrollbar-hide::-webkit-scrollbar {
  display: none;
}

.htmx-request .htmx-indicator,
button.htmx-request .htmx-indicator {
  display: inline-block;
}
```

- [ ] **Step 2: Write layout.tsx**

```typescript
import { Child } from "hono/jsx";

export const Layout = ({ children }: { children: Child }) => (
  <html lang="en" data-theme="dracula">
    <head>
      <meta charset="UTF-8" />
      <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0, viewport-fit=cover"
      />
      <title>Basho</title>
      <link href="/static/style.css" rel="stylesheet" />
      <script src="/static/htmx.min.js"></script>
      <script src="/static/htmx-ext-sse.min.js"></script>
      <script defer src="/static/handlers.js"></script>
    </head>
    <body>{children}</body>
  </html>
);
```

- [ ] **Step 3: Write app.tsx**

```typescript
import { Child } from "hono/jsx";

interface AppProps {
  children: Child;
  page?: string;
}

export const App = ({ children, page }: AppProps) => (
  <>
    <div className="drawer lg:drawer-open min-h-screen bg-base-100">
      <input id="main-drawer" type="checkbox" className="drawer-toggle" />
      <div className="drawer-content flex flex-col">
        <header className="navbar bg-base-200/80 backdrop-blur-sm px-4 shadow-sm z-10">
          <div className="flex-none">
            <label htmlFor="main-drawer" className="btn btn-ghost btn-circle btn-sm">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" /></svg>
            </label>
          </div>
          <div className="flex-1">
            <h1 className="text-xl font-bold">
              {page === "dashboard" && "Dashboard"}
              {page === "services" && "Services"}
              {!page && "Basho"}
            </h1>
          </div>
          <div className="flex-none">
            <button id="theme-toggle" className="btn btn-ghost btn-circle btn-sm" onclick="toggleTheme()">
              <svg id="theme-icon-sun" xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" /></svg>
              <svg id="theme-icon-moon" xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 hidden" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" /></svg>
            </button>
          </div>
        </header>
        <main className="flex-1 p-4">
          <div id="content" className="min-h-[400px]">
            {children}
          </div>
        </main>
      </div>
      <aside className="drawer-side z-20">
        <label htmlFor="main-drawer" className="drawer-overlay"></label>
        <div className="bg-base-200 border-r border-base-300 flex flex-col items-start min-h-full w-64">
          <a
            href="/"
            hx-get="/"
            hx-target="#content"
            hx-swap="innerHTML"
            hx-push-url="true"
            className="flex items-center gap-3 p-4 w-full hover:bg-base-300 transition-colors"
          >
            <span className="text-2xl">⚡</span>
            <span className="text-xl font-bold text-primary">Basho</span>
          </a>
          <ul className="menu menu-md w-full grow px-2 py-4">
            <li>
              <a
                hx-get="/"
                hx-target="#content"
                hx-swap="innerHTML"
                hx-push-url="true"
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z" /></svg>
                Dashboard
              </a>
            </li>
            <li>
              <a
                hx-get="/services"
                hx-target="#content"
                hx-swap="innerHTML"
                hx-push-url="true"
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" /></svg>
                Services
              </a>
            </li>
          </ul>
        </div>
      </aside>
    </div>
  </>
);
```

- [ ] **Step 4: Create static dir placeholder**

Run: `mkdir -p static && touch static/.gitkeep`

- [ ] **Step 5: Build CSS**

Run: `npx @tailwindcss/cli -i src/templates/app.css -o static/style.css`
Expected: style.css generated in static/

---

### Task 3: Theme handler & static assets

**Files:**
- Create: `static/handlers.js`
- Create: `config/services.json`

- [ ] **Step 1: Write handlers.js**

```javascript
(function() {
  const html = document.documentElement;
  const sunIcon = document.getElementById('theme-icon-sun');
  const moonIcon = document.getElementById('theme-icon-moon');

  const savedTheme = sessionStorage.getItem('basho-theme');
  if (savedTheme) {
    html.setAttribute('data-theme', savedTheme);
    updateIcons(savedTheme);
  }

  window.toggleTheme = function() {
    const current = html.getAttribute('data-theme');
    const next = current === 'dracula' ? 'bumblebee' : 'dracula';
    html.setAttribute('data-theme', next);
    sessionStorage.setItem('basho-theme', next);
    updateIcons(next);
  };

  function updateIcons(theme) {
    if (theme === 'dracula') {
      sunIcon.classList.remove('hidden');
      moonIcon.classList.add('hidden');
    } else {
      sunIcon.classList.add('hidden');
      moonIcon.classList.remove('hidden');
    }
  }
})();
```

- [ ] **Step 2: Write services config**

```json
[
  {
    "name": "Silicon Seeds",
    "url": "http://localhost:3000",
    "description": "AI media generation platform",
    "icon": "🧬"
  }
]
```

---

### Task 4: System monitor

**Files:**
- Create: `src/monitors/system.ts`

- [ ] **Step 1: Write system monitor**

```typescript
interface CpuCore {
  user: number;
  nice: number;
  sys: number;
  idle: number;
}

interface GpuInfo {
  utilization: number;
  memoryUsed: number;
  memoryTotal: number;
  temperature: number;
}

interface SystemStats {
  cpu: { cores: { usage: number; }[]; average: number; };
  ram: { used: number; total: number; percent: number; };
  gpu: GpuInfo | null;
}

export namespace SystemMonitor {
  let prevCpus: CpuCore[] | null = null;

  function getCpuTimes(): CpuCore[] {
    return require("os").cpus().map((c: any) => ({
      user: c.times.user,
      nice: c.times.nice,
      sys: c.times.sys,
      idle: c.times.idle,
    }));
  }

  function calcCpuUsage(current: CpuCore[], previous: CpuCore[]): { usage: number }[] {
    return current.map((c, i) => {
      const p = previous[i]!;
      const totalDiff = (c.user + c.nice + c.sys + c.idle) - (p.user + p.nice + p.sys + p.idle);
      const idleDiff = c.idle - p.idle;
      return { usage: totalDiff > 0 ? Math.round(((totalDiff - idleDiff) / totalDiff) * 100) : 0 };
    });
  }

  function getRamInfo() {
    const os = require("os");
    const total = os.totalmem();
    const free = os.freemem();
    const used = total - free;
    return {
      used: Math.round(used / 1024 / 1024 / 1024 * 10) / 10,
      total: Math.round(total / 1024 / 1024 / 1024 * 10) / 10,
      percent: Math.round((used / total) * 100),
    };
  }

  async function getGpuInfo(): Promise<GpuInfo | null> {
    try {
      const proc = Bun.spawnSync(["nvidia-smi", "--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu", "--format=csv,noheader,nounits"]);
      if (proc.exitCode !== 0) return null;
      const parts = proc.stdout.toString().trim().split(",").map(s => parseFloat(s.trim()));
      if (parts.length >= 4) {
        return {
          utilization: parts[0]!,
          memoryUsed: parts[1]!,
          memoryTotal: parts[2]!,
          temperature: parts[3]!,
        };
      }
      return null;
    } catch {
      return null;
    }
  }

  export async function getStats(): Promise<SystemStats> {
    const currentCpus = getCpuTimes();
    let cores: { usage: number }[] = [];
    if (prevCpus) {
      cores = calcCpuUsage(currentCpus, prevCpus);
    }
    prevCpus = currentCpus;

    const ram = getRamInfo();
    const gpu = await getGpuInfo();
    const average = cores.length > 0
      ? Math.round(cores.reduce((s, c) => s + c.usage, 0) / cores.length)
      : 0;

    return { cpu: { cores, average }, ram, gpu };
  }
}
```

---

### Task 5: SSE endpoint

**Files:**
- Create: `src/routes/sse.ts`

- [ ] **Step 1: Write SSE route**

```typescript
import { Hono } from "hono";
import { SystemMonitor } from "../monitors/system";

const encoder = new TextEncoder();
const app = new Hono();

app.get("/system-stats", (c) => {
  const stream = new ReadableStream({
    async start(controller) {
      let closed = false;
      let cpuInterval: Timer;
      let gpuInterval: Timer;

      const send = (data: string) => {
        if (closed) return;
        controller.enqueue(encoder.encode(`data: ${data}\n\n`));
      };

      cpuInterval = setInterval(async () => {
        const stats = await SystemMonitor.getStats();
        send(JSON.stringify({
          type: "system",
          cpu: stats.cpu,
          ram: stats.ram,
          gpu: stats.gpu,
        }));
      }, 2000);

      const keepAlive = setInterval(() => {
        if (closed) return;
        controller.enqueue(encoder.encode(": keep-alive\n\n"));
      }, 15000);

      c.req.raw.signal.addEventListener("abort", () => {
        closed = true;
        clearInterval(cpuInterval);
        clearInterval(gpuInterval);
        clearInterval(keepAlive);
      });
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
      "Access-Control-Allow-Origin": "*",
    },
  });
});

export default app;
```

---

### Task 6: Dashboard template

**Files:**
- Create: `src/templates/dashboard.tsx`

- [ ] **Step 1: Write dashboard template**

```typescript
export const Dashboard = () => (
  <div
    hx-ext="sse"
    sse-connect="/sse/system-stats"
    sse-swap="message"
    class="space-y-6"
  >
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {/* CPU Card */}
      <div class="card bg-base-200/60 backdrop-blur-sm border border-base-300/50 shadow-xl">
        <div class="card-body">
          <div class="flex items-center gap-2 mb-2">
            <div class="w-3 h-3 rounded-full bg-accent animate-pulse"></div>
            <h2 class="card-title text-lg">CPU</h2>
          </div>
          <div id="cpu-cores" class="space-y-2">
            <div class="text-4xl font-bold text-accent" id="cpu-average">0%</div>
            <div class="text-sm text-base-content/60">Average</div>
            <div class="space-y-1 mt-3">
              {Array.from({ length: 4 }, (_, i) => (
                <div key={i} class="flex items-center gap-2">
                  <span class="text-xs w-4 text-base-content/60">C{i}</span>
                  <div class="flex-1 h-2 bg-base-300 rounded-full overflow-hidden">
                    <div
                      id={`cpu-core-${i}`}
                      class="h-full bg-accent rounded-full transition-all duration-500"
                      style="width: 0%"
                    ></div>
                  </div>
                  <span class="text-xs w-8 text-right" id={`cpu-core-label-${i}`}>0%</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* RAM Card */}
      <div class="card bg-base-200/60 backdrop-blur-sm border border-base-300/50 shadow-xl">
        <div class="card-body">
          <div class="flex items-center gap-2 mb-2">
            <div class="w-3 h-3 rounded-full bg-primary animate-pulse"></div>
            <h2 class="card-title text-lg">RAM</h2>
          </div>
          <div id="ram-info">
            <div class="text-4xl font-bold text-primary" id="ram-percent">0%</div>
            <div class="text-sm text-base-content/60 mt-1">
              <span id="ram-used">0.0</span> GB / <span id="ram-total">0.0</span> GB
            </div>
            <div class="h-3 bg-base-300 rounded-full mt-3 overflow-hidden">
              <div
                id="ram-bar"
                class="h-full bg-primary rounded-full transition-all duration-500"
                style="width: 0%"
              ></div>
            </div>
          </div>
        </div>
      </div>

      {/* GPU Card */}
      <div class="card bg-base-200/60 backdrop-blur-sm border border-base-300/50 shadow-xl">
        <div class="card-body">
          <div class="flex items-center gap-2 mb-2">
            <div class="w-3 h-3 rounded-full bg-secondary animate-pulse"></div>
            <h2 class="card-title text-lg">GPU</h2>
          </div>
          <div id="gpu-info">
            <div class="text-4xl font-bold text-secondary" id="gpu-util">0%</div>
            <div class="text-sm text-base-content/60 mt-1">
              <span id="gpu-temp">--</span>°C
            </div>
            <div class="text-sm text-base-content/60">
              VRAM: <span id="gpu-vram-used">0</span> / <span id="gpu-vram-total">0</span> MB
            </div>
            <div class="h-3 bg-base-300 rounded-full mt-3 overflow-hidden">
              <div
                id="gpu-bar"
                class="h-full bg-secondary rounded-full transition-all duration-500"
                style="width: 0%"
              ></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    {/* Handle SSE messages */}
    <script>{`
      document.body.addEventListener('htmx:sseBeforeMessage', function(evt) {
        const detail = evt.detail;
        try {
          const data = JSON.parse(detail.data);
          if (data.type === 'system') {
            // CPU
            const avg = document.getElementById('cpu-average');
            if (avg) avg.textContent = data.cpu.average + '%';
            data.cpu.cores.forEach(function(core, i) {
              const bar = document.getElementById('cpu-core-' + i);
              const label = document.getElementById('cpu-core-label-' + i);
              if (bar) bar.style.width = core.usage + '%';
              if (label) label.textContent = core.usage + '%';
            });
            // RAM
            const rp = document.getElementById('ram-percent');
            const ru = document.getElementById('ram-used');
            const rt = document.getElementById('ram-total');
            const rb = document.getElementById('ram-bar');
            if (rp) rp.textContent = data.ram.percent + '%';
            if (ru) ru.textContent = data.ram.used;
            if (rt) rt.textContent = data.ram.total;
            if (rb) rb.style.width = data.ram.percent + '%';
            // GPU
            if (data.gpu) {
              const gu = document.getElementById('gpu-util');
              const gt = document.getElementById('gpu-temp');
              const gvu = document.getElementById('gpu-vram-used');
              const gvt = document.getElementById('gpu-vram-total');
              const gb = document.getElementById('gpu-bar');
              if (gu) gu.textContent = data.gpu.utilization + '%';
              if (gt) gt.textContent = data.gpu.temperature;
              if (gvu) gvu.textContent = data.gpu.memoryUsed;
              if (gvt) gvt.textContent = data.gpu.memoryTotal;
              if (gb) gb.style.width = data.gpu.utilization + '%';
            }
          }
        } catch(e) {}
      });
    `}</script>
  </div>
);
```

---

### Task 7: Services template & registry

**Files:**
- Create: `src/templates/services.tsx`
- Create: `src/services/registry.ts`

- [ ] **Step 1: Write services registry**

```typescript
export interface ServiceEntry {
  name: string;
  url: string;
  description: string;
  icon?: string;
}

export namespace ServiceRegistry {
  let services: ServiceEntry[] = [];

  export function load() {
    try {
      const config = require("../../config/services.json");
      services = config;
    } catch {
      services = [];
    }
  }

  export function getAll(): ServiceEntry[] {
    return services;
  }
}
```

- [ ] **Step 2: Write services template**

```typescript
import { ServiceEntry } from "../services/registry";

export const Services = ({ services }: { services: ServiceEntry[] }) => (
  <div class="space-y-4">
    <h2 class="text-2xl font-bold mb-4">Services</h2>
    {services.length === 0 && (
      <div class="card bg-base-200/60 backdrop-blur-sm border border-base-300/50 shadow-xl">
        <div class="card-body text-center text-base-content/60 py-12">
          <p class="text-lg">No services configured</p>
          <p class="text-sm mt-2">Edit config/services.json to add your local services</p>
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
              ></div>
            </div>
            <div class="card-actions justify-end mt-2">
              <a
                href={svc.url}
                target="_blank"
                rel="noopener noreferrer"
                class="btn btn-ghost btn-sm"
              >Open →</a>
            </div>
          </div>
        </div>
      ))}
    </div>
    <script>{`
      (function() {
        const services = ` + JSON.stringify(services) + `;
        services.forEach(function(svc) {
          const id = 'status-' + svc.name.replace(/\\s+/g, '-');
          const dot = document.getElementById(id);
          if (!dot) return;
          fetch(svc.url, { mode: 'no-cors' })
            .then(function() {
              dot.className = 'w-3 h-3 rounded-full bg-success';
              dot.title = 'Online';
            })
            .catch(function() {
              dot.className = 'w-3 h-3 rounded-full bg-error';
              dot.title = 'Offline';
            });
        });
      })();
    `}</script>
  </div>
);
```

---

### Task 8: Routes — pages & fragments

**Files:**
- Create: `src/routes/pages.tsx`
- Create: `src/routes/fragments.tsx`

- [ ] **Step 1: Write pages routes**

```typescript
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
    </Layout>
  );
}

app.get("/", (c) => renderPage(c, Dashboard, "dashboard"));
app.get("/services", (c) => {
  const services = ServiceRegistry.getAll();
  return renderPage(c, () => <Services services={services} />, "services");
});

export default app;
```

- [ ] **Step 2: Write fragments routes**

```typescript
import { Hono } from "hono";

const app = new Hono();

app.get("/dashboard", (c) => {
  const { Dashboard } = require("../templates/dashboard");
  return c.html(<Dashboard />);
});

export default app;
```

---

### Task 9: Wire up main.ts

**Files:**
- Modify: `src/main.ts`

- [ ] **Step 1: Write final main.ts**

```typescript
import { Hono } from "hono";
import { serveStatic } from "hono/bun";
import pages from "./routes/pages";
import sse from "./routes/sse";
import { ServiceRegistry } from "./services/registry";

// Load services config
ServiceRegistry.load();

const app = new Hono();

// Static files
app.use("/static/*", serveStatic({ root: "./" }));

// Routes
app.route("/", pages);
app.route("/sse", sse);

app.notFound((c) => c.text("Not found", 404));

// Start server
Bun.serve({
  port: 6969,
  hostname: "0.0.0.0",
  fetch: app.fetch,
});

console.log("⚡ Basho running on http://0.0.0.0:6969");
```

---

### Task 10: Download HTMX static assets

**Files:**
- Create: `static/htmx.min.js`
- Create: `static/htmx-ext-sse.min.js`

- [ ] **Step 1: Download HTMX**

Run: `curl -sL https://unpkg.com/htmx.org@2.0.0/dist/htmx.min.js -o static/htmx.min.js`
Expected: File downloaded

- [ ] **Step 2: Download SSE extension**

Run: `curl -sL https://unpkg.com/htmx-ext-sse@2.0.0/dist/sse.js -o static/htmx-ext-sse.min.js`
Expected: File downloaded

---

### Task 11: Build CSS & verify

- [ ] **Step 1: Build CSS**

Run: `npx @tailwindcss/cli -i src/templates/app.css -o static/style.css`
Expected: style.css generated

- [ ] **Step 2: Start server**

Run: `bun src/main.ts`
Expected: "Basho running on http://0.0.0.0:6969"

- [ ] **Step 3: Test endpoint**

Run: `curl -s http://localhost:6969/ | head -5`
Expected: HTML response with data-theme

- [ ] **Step 4: Test SSE**

Run: `timeout 3 curl -sN http://localhost:6969/sse/system-stats`
Expected: SSE data stream with JSON stats
