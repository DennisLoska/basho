import type { ServiceEntry } from "./registry";

const PORT_NAMES: Record<number, string> = {
  80: "HTTP Server",
  443: "HTTPS Server",
  1080: "Proxy Server",
  1234: "LM Studio",
  1880: "Node-RED",
  3000: "Web Dev Server",
  3001: "Web Dev Server",
  4000: "Web Server",
  4200: "Angular Dev Server",
  4321: "Web Server",
  5000: "Flask Server",
  5173: "Vite Dev Server",
  5555: "Web Server",
  6006: "TensorBoard",
  6347: "Stable Audio",
  6666: "Web Server",
  6868: "Web Server",
  6969: "Basho",
  7000: "Odysseus Server",
  7474: "Neo4j Browser",
  8000: "Python Dev Server",
  8006: "Diffusion Server",
  8080: "HTTP Alternative",
  8091: "Ntfy Service",
  8100: "ChromaDB",
  8188: "ComfyUI",
  8443: "HTTPS Alternative",
  8675: "AI Toolkit UI",
  8787: "Dashboard Monitor",
  8888: "Jupyter Server",
  9000: "Web Server",
  9090: "Prometheus",
  11434: "Ollama",
};

const CONCURRENCY = 200;
const TCP_TIMEOUT = 150;

interface OpenPort {
  host: string;
  port: number;
}

let cachedResult: ServiceEntry[] | null = null;
let lastScan = 0;
const SCAN_TTL = 30_000;

function guessName(port: number, title?: string): string {
  if (title) return title;
  return PORT_NAMES[port] ?? `Service on :${port}`;
}

function guessIcon(port: number): string {
  if (port === 443 || port === 8443) return "🔒";
  if (port >= 3000 && port < 4000) return "⚛️";
  if (port === 8080) return "🌐";
  if (port === 6969) return "⚡";
  if (port === 8888) return "📓";
  if (port === 7000) return "⚓";
  if (port === 11434) return "🦙";
  if (port === 8188) return "🎨";
  if (port === 8675) return "🤖";
  return "🔌";
}

function hostLabel(host: string): string {
  if (host === "127.0.0.1") return "127.0.0.1";
  if (host === "0.0.0.0") return "0.0.0.0";
  return "localhost";
}

async function probeTCP(host: string, port: number): Promise<boolean> {
  try {
    const result = await Promise.race([
      Bun.connect({
        hostname: host,
        port,
        socket: {
          data() {},
          open(socket) { try { socket.end(); } catch {} },
        },
      }).then(() => true as const),
      new Promise<false>((resolve) =>
        setTimeout(() => resolve(false), TCP_TIMEOUT),
      ),
    ]);
    return result;
  } catch {
    return false;
  }
}

async function fetchTitle(host: string, port: number): Promise<string | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 300);
    const res = await fetch(`http://${host}:${port}`, { signal: controller.signal });
    clearTimeout(timeout);
    const text = await res.clone().text();
    const m = text.match(/<title[^>]*>([^<]+)<\/title>/i);
    return m ? m[1]!.trim() : null;
  } catch {
    return null;
  }
}

async function scanHost(host: string, ports: number[]): Promise<OpenPort[]> {
  const open: OpenPort[] = [];
  const n = ports.length;
  for (let i = 0; i < n; i += CONCURRENCY) {
    const end = Math.min(i + CONCURRENCY, n);
    const batch: Promise<OpenPort | null>[] = [];
    for (let j = i; j < end; j++) {
      const port = ports[j]!;
      batch.push(probeTCP(host, port).then((ok) => (ok ? { host, port } : null)));
    }
    const results = await Promise.allSettled(batch);
    for (const r of results) {
      if (r.status === "fulfilled" && r.value) open.push(r.value);
    }
  }
  return open;
}

async function fetchAllTitles(
  openPorts: { host: string; port: number }[],
): Promise<(string | null)[]> {
  const titles: (string | null)[] = new Array(openPorts.length);
  const n = openPorts.length;
  for (let i = 0; i < n; i += CONCURRENCY) {
    const end = Math.min(i + CONCURRENCY, n);
    const batch: Promise<[number, string | null]>[] = [];
    for (let j = i; j < end; j++) {
      const { host, port } = openPorts[j]!;
      batch.push(fetchTitle(host, port).then((t) => [j, t]));
    }
    const results = await Promise.allSettled(batch);
    for (const r of results) {
      if (r.status === "fulfilled") {
        const [idx, title] = r.value;
        titles[idx] = title;
      }
    }
  }
  return titles;
}

export async function scan(): Promise<ServiceEntry[]> {
  const now = Date.now();
  if (cachedResult && now - lastScan < SCAN_TTL) {
    return cachedResult;
  }

  const allPorts = Array.from({ length: 9999 }, (_, i) => i + 1);
  const openPorts = await scanHost("localhost", allPorts);
  const entries: ServiceEntry[] = [];

  const titles = await fetchAllTitles(openPorts);
  for (let i = 0; i < openPorts.length; i++) {
    const { host, port } = openPorts[i]!;
    const title = titles[i];
    entries.push({
      name: guessName(port, title ?? undefined),
      url: `http://localhost:${port}`,
      description: `${hostLabel(host)} port ${port}${title ? ` — ${title}` : ""}`,
      icon: guessIcon(port),
    });
  }

  cachedResult = entries;
  lastScan = now;
  return entries;
}
