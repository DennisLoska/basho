import { cpus, totalmem, freemem } from "os";

interface CpuTimes {
  user: number;
  nice: number;
  sys: number;
  idle: number;
}

export interface GpuInfo {
  utilization: number;
  memoryUsed: number;
  memoryTotal: number;
  temperature: number;
}

export interface SystemStats {
  cpu: { cores: { usage: number }[]; average: number };
  ram: { used: number; total: number; percent: number };
  gpu: GpuInfo | null;
}

export namespace SystemMonitor {
  let prevCpus: CpuTimes[] | null = null;

  function getCpuTimes(): CpuTimes[] {
    return cpus().map((c) => ({
      user: c.times.user,
      nice: c.times.nice,
      sys: c.times.sys,
      idle: c.times.idle,
    }));
  }

  function calcCpuUsage(current: CpuTimes[], previous: CpuTimes[]): { usage: number }[] {
    return current.map((c, i) => {
      const p = previous[i]!;
      const totalDiff =
        c.user + c.nice + c.sys + c.idle - (p.user + p.nice + p.sys + p.idle);
      const idleDiff = c.idle - p.idle;
      return {
        usage:
          totalDiff > 0
            ? Math.round(((totalDiff - idleDiff) / totalDiff) * 100)
            : 0,
      };
    });
  }

  function getRamInfo() {
    const total = totalmem();
    const free = freemem();
    const used = total - free;
    return {
      used: Math.round((used / 1024 / 1024 / 1024) * 10) / 10,
      total: Math.round((total / 1024 / 1024 / 1024) * 10) / 10,
      percent: Math.round((used / total) * 100),
    };
  }

  async function getGpuInfo(): Promise<GpuInfo | null> {
    try {
      const proc = Bun.spawnSync([
        "nvidia-smi",
        "--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu",
        "--format=csv,noheader,nounits",
      ]);
      if (proc.exitCode !== 0) return null;
      const parts = proc.stdout
        .toString()
        .trim()
        .split(",")
        .map((s) => parseFloat(s.trim()));
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
    const average =
      cores.length > 0
        ? Math.round(cores.reduce((s, c) => s + c.usage, 0) / cores.length)
        : 0;

    return { cpu: { cores, average }, ram, gpu };
  }
}
