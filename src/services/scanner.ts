import type { ServiceEntry } from "./registry";

const COMMON_PORTS = [
  80, 443, 3000, 3001, 4321, 5000, 5173, 6969, 7000, 8000, 8080, 8443, 9000,
];

const PORT_NAMES: Record<number, string> = {
  80: "HTTP Server",
  443: "HTTPS Server",
  3000: "Web Dev Server",
  3001: "Web Dev Server",
  4321: "Web Server",
  5000: "Web Server",
  5173: "Vite Dev Server",
  6969: "Basho",
  7000: "Web Server",
  8000: "Web Server",
  8080: "HTTP Alternative",
  8443: "HTTPS Alternative",
  9000: "Web Server",
};

interface ScanResult {
  port: number;
  name: string;
  url: string;
  ok: boolean;
  title?: string;
}

export namespace ServiceScanner {
  function guessName(port: number, body?: string): string {
    if (PORT_NAMES[port]) return PORT_NAMES[port]!;
    return `Service on :${port}`;
  }

  function guessIcon(port: number): string {
    if (port === 443 || port === 8443) return "🔒";
    if (port === 3000 || port === 5173) return "⚛️";
    if (port === 8080) return "🌐";
    if (port === 6969) return "⚡";
    return "🔌";
  }

  export async function scan(): Promise<ServiceEntry[]> {
    const results: ServiceEntry[] = [];

    const scanPort = async (port: number): Promise<ScanResult | null> => {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 800);

        const res = await fetch(`http://localhost:${port}`, {
          signal: controller.signal,
        });
        clearTimeout(timeout);

        let body = "";
        try {
          body = await res.clone().text();
        } catch {}

        const title = body
          ? extractTitle(body) || guessName(port)
          : guessName(port);

        return {
          port,
          name: title,
          url: `http://localhost:${port}`,
          ok: true,
          title,
        };
      } catch {
        return null;
      }
    };

    const scanResults = await Promise.allSettled(
      COMMON_PORTS.map((p) => scanPort(p)),
    );

    for (const result of scanResults) {
      if (result.status === "fulfilled" && result.value) {
        const svc = result.value;
        results.push({
          name: svc.name,
          url: svc.url,
          description: `Port ${svc.port}`,
          icon: guessIcon(svc.port),
        });
      }
    }

    return results;
  }

  function extractTitle(html: string): string | null {
    const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    return match ? match[1]!.trim() : null;
  }
}
