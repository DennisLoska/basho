# basho

Local-first server dashboard for monitoring system resources and discovering local web services.

## Stack

| Layer | Technology |
|-------|------------|
| Runtime | [Bun](https://bun.sh) |
| Framework | [Hono](https://hono.dev) |
| Frontend | [HTMX](https://htmx.org) + Server-Sent Events |
| Styling | [Tailwind CSS v4](https://tailwindcss.com) + [DaisyUI 5](https://daisyui.com) |
| Templates | Hono JSX |
| Monitoring | [systeminformation](https://systeminformation.io) + nvidia-smi |
| Bundler | Bun (native) |

## Setup

### Prerequisites

- [Bun](https://bun.sh) >= 1.2

### Installation

```bash
git clone <repo-url> basho
cd basho
bun install
```

### Configuration

Edit `config/services.json` to define static service entries:

```json
[
  {
    "name": "My App",
    "url": "http://localhost:3000",
    "description": "Description of my app",
    "icon": "🚀"
  }
]
```

Service scanning is automatic — any service listening on localhost:1-9999 is auto-discovered.

### Building CSS

The project uses Tailwind CSS v4 with DaisyUI. The CSS must be built before running:

```bash
./build-css.sh
```

Or use the npm script:

```bash
bun run build:css
```

This compiles `src/templates/app.css` → `static/style.css`.

### Running

```bash
# Development (hot reload)
bun run dev

# Production
bun run start
```

The server starts at **http://0.0.0.0:6969**.

### Environment

- Port: `6969` (hardcoded)
- Host: `0.0.0.0` (all interfaces)
- GPU monitoring: NVIDIA GPU via nvidia-smi (fallback after systeminformation)
- Service scan: TCP probes to ports 1-9999 on localhost

## Features

- **Resource Monitor** — Real-time CPU, RAM, and GPU utilization with live charts
- **Service Discovery** — Automatic scanning of localhost services (TCP 1-9999)
- **Live Updates** — SSE-based push every 2s (CPU/RAM) with chart history
- **Theme Toggle** — Dracula (dark) / Bumblebee (light) with session persistence
- **Collapsible Sidebar** — Mobile-friendly responsive layout

## Architecture

```
src/
  main.ts          — Entry point, Hono app bootstrap
  monitors/
    system.ts      — CPU, RAM, GPU stats collection
  routes/
    pages.tsx      — Page route handlers
    sse.ts         — SSE endpoint for live stats
  services/
    registry.ts    — Static service config loader
    scanner.ts     — Local TCP port scanner
  templates/
    app.css        — Tailwind CSS source with DaisyUI
    app.tsx        — Main app layout (sidebar, header)
    dashboard.tsx  — Resource monitor dashboard
    layout.tsx     — HTML document wrapper
    services.tsx   — Service discovery page
config/
  services.json    — Static service definitions
static/
  style.css        — Built CSS (generated)
  handlers.js      — HTMX SSE handlers, chart rendering, theme
```
