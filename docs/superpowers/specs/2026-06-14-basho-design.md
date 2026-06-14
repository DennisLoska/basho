# Basho — System Monitor Dashboard

## Stack
- **Runtime:** Bun
- **Backend:** Hono (JSX rendering)
- **Frontend:** DaisyUI 5 + Tailwind CSS v4 + HTMX + SSE
- **Build:** `@tailwindcss/cli` for CSS

## Architecture

```
basho/
├── src/
│   ├── main.ts              # Entry: Bun.serve({port:6969, hostname:"0.0.0.0"})
│   ├── routes/
│   │   ├── pages.tsx         # Full-page renders
│   │   ├── fragments.tsx     # HTMX fragment endpoints
│   │   └── sse.ts            # SSE endpoint for real-time stats
│   ├── templates/
│   │   ├── layout.tsx        # HTML shell (html, head, scripts)
│   │   ├── app.tsx           # App shell (drawer, sidebar, navbar)
│   │   ├── dashboard.tsx     # System resource gauges (CPU/RAM/GPU)
│   │   ├── services.tsx      # Services listing page
│   │   └── app.css           # Tailwind + DaisyUI import
│   ├── monitors/
│   │   └── system.ts         # CPU, RAM, GPU stats via os + nvidia-smi
│   └── services/
│       └── registry.ts       # Static service definitions
├── static/                   # Static assets (htmx, htmx-ext-sse, style.css, handlers.js)
├── package.json
└── tsconfig.json
```

## Routes

| Path | Method | Description |
|------|--------|-------------|
| `/` | GET | Dashboard (full page or HTMX fragment) |
| `/services` | GET | Services listing page |
| `/sse/system-stats` | GET | SSE stream for CPU/RAM/GPU |

## Theme

- DaisyUI `data-theme` attribute on `<html>`
- Toggle button writes to `sessionStorage` on click
- On page load, JS checks `sessionStorage` for theme, applies before render
- Default: dark theme ("dracula"), light toggle ("bumblebee")

## SSE System Stats

- **CPU:** `os.cpus()` — per-core usage percentage, calculated from idle/total ticks
- **RAM:** `os.totalmem()`, `os.freemem()` — used/total in GB
- **GPU:** Spawn `nvidia-smi --query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu --format=csv,noheader,nounits` every 5s
- Push interval: CPU/RAM every 2s, GPU every 5s
- Format: JSON `{ cpu: [...cores], ram: { used, total, percent }, gpu: { ... } }`

## Services

- Static JSON config: `config/services.json`
- Each entry: `{ name, url, description, icon? }`
- Page shows cards with status indicator (green/red based on fetch health check)
- HTMX polls each service `/health` or root every 30s

## Look & Feel

- Dark glass-morphism cards with backdrop blur
- Animated gradient bars for CPU/RAM usage
- Neon accent colors per metric type
- Mobile-first responsive grid
- DaisyUI drawer sidebar with navigation
