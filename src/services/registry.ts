export interface ServiceEntry {
  name: string;
  url: string;
  description: string;
  icon?: string;
}

export namespace ServiceRegistry {
  let services: ServiceEntry[] = [];

  export async function load() {
    try {
      const { join } = require("path");
      const configPath = join(import.meta.dir, "../../config/services.json");
      const file = Bun.file(configPath);
      services = JSON.parse(await file.text()) as ServiceEntry[];
    } catch {
      services = [];
    }
  }

  export function getAll(): ServiceEntry[] {
    return services;
  }
}
