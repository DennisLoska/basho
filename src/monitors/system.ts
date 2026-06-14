import si from "systeminformation";

export interface GpuInfo {
  utilization: number;
  memoryUsed: number;
  memoryTotal: number;
  temperature: number;
  fanSpeed: number | null;
}

export interface SystemStats {
  cpu: { cores: { usage: number }[]; average: number; count: number };
  ram: { used: number; total: number; percent: number; cached: number };
  gpu: GpuInfo | null;
}

async function getCpuStats() {
  const load = await si.currentLoad();
  return {
    cores: load.cpus.map((c) => ({ usage: Math.round(c.load) })),
    average: Math.round(load.currentLoad),
    count: load.cpus.length,
  };
}

async function getRamStats() {
  const mem = await si.mem();
  const used = mem.total - mem.available;
  return {
    used: Math.round((used / 1024 / 1024 / 1024) * 10) / 10,
    total: Math.round((mem.total / 1024 / 1024 / 1024) * 10) / 10,
    percent: Math.round((used / mem.total) * 100),
    cached: Math.round(((mem.cached + mem.buffers) / 1024 / 1024 / 1024) * 10) / 10,
  };
}

async function getGpuStats(): Promise<GpuInfo | null> {
  try {
    const graphics = await si.graphics();
    const ctrl = graphics.controllers[0];
    if (!ctrl) return null;
    const mu = ctrl.memoryUsed ?? 0;
    const mt = ctrl.memoryTotal ?? 1;
    return {
      utilization: ctrl.utilizationGpu ?? Math.round((mu / mt) * 100),
      memoryUsed: mu,
      memoryTotal: ctrl.memoryTotal ?? 0,
      temperature: ctrl.temperatureGpu ?? 0,
      fanSpeed: ctrl.fanSpeed ?? null,
    };
  } catch {
    try {
      const proc = Bun.spawnSync([
        "nvidia-smi",
        "--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu,fan.speed",
        "--format=csv,noheader,nounits",
      ]);
      if (proc.exitCode !== 0) return null;
      const parts = proc.stdout.toString().trim().split(",").map((s) => parseFloat(s.trim()));
      if (parts.length >= 4) {
        return {
          utilization: parts[0]!,
          memoryUsed: parts[1]!,
          memoryTotal: parts[2]!,
          temperature: parts[3]!,
          fanSpeed: parts[4] ?? null,
        };
      }
      return null;
    } catch {
      return null;
    }
  }
}

export async function getStats(): Promise<SystemStats> {
  const [cpu, ram, gpu] = await Promise.all([
    getCpuStats(),
    getRamStats(),
    getGpuStats(),
  ]);
  return { cpu, ram, gpu };
}
