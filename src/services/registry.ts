export interface ServiceEntry {
  name: string;
  url: string;
  description: string;
  icon?: string;
}

let services: ServiceEntry[] = [];

export async function loadServices() {
  try {
    const configPath = import.meta.dir + "/../../config/services.json";
    const file = Bun.file(configPath);
    services = JSON.parse(await file.text()) as ServiceEntry[];
  } catch {
    services = [];
  }
}

export function getAllServices(): ServiceEntry[] {
  return services;
}
