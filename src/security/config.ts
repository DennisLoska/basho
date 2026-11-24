import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  aiProviderKinds,
  alertChannels,
  criterionIds,
  lockdownModes,
} from "./types";
import type {
  AiProviderKind,
  AlertChannel,
  CriterionId,
  EnrolledWorkload,
  LockdownMode,
  ProcessSettings,
  RuntimeOverrides,
  SecuritySecrets,
  SecuritySettings,
} from "./types";
import { isValidSystemdUnitName } from "./runner";

const DEFAULT_CONFIG_PATH = resolve(import.meta.dir, "../../config/security.json");

const CRITERION_SET = new Set<string>(criterionIds);
const MODE_SET = new Set<string>(lockdownModes);
const AI_PROVIDER_SET = new Set<string>(aiProviderKinds);
const CHANNEL_SET = new Set<string>(alertChannels);
const OVERRIDE_KEYS = new Set(["mode", "scanIntervalMinutes", "criteria"]);

export interface LoadSecurityConfigInput {
  env?: Record<string, string | undefined>;
  overrides?: RuntimeOverrides;
  fileConfig?: unknown;
  configPath?: string;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function defaultCriteria(): Record<CriterionId, boolean> {
  return Object.fromEntries(
    criterionIds.map((id) => [id, true]),
  ) as Record<CriterionId, boolean>;
}

function validateMode(value: unknown): LockdownMode {
  if (typeof value !== "string" || !MODE_SET.has(value)) {
    throw new Error(`Invalid lockdown mode: ${String(value)}`);
  }
  return value as LockdownMode;
}

function validateAiProvider(value: unknown, label: string): AiProviderKind {
  if (typeof value !== "string" || !AI_PROVIDER_SET.has(value)) {
    throw new Error(
      `Invalid ${label}: expected one of ${aiProviderKinds.join(", ")}`,
    );
  }
  return value as AiProviderKind;
}

function validateIntRange(value: unknown, min: number, max: number, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    throw new Error(`Invalid ${label}: expected integer between ${min} and ${max}`);
  }
  return value;
}

function validateConfidence(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error("Invalid ai.confidenceThreshold: expected number between 0 and 1");
  }
  return value;
}

function validatePort(value: unknown, label: string): number {
  return validateIntRange(value, 1, 65535, label);
}

function parseIpv4(host: string): [number, number, number, number] | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const nums: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    nums.push(n);
  }
  return nums as [number, number, number, number];
}

function isPrivateOrLocalIpv4(octets: [number, number, number, number]): boolean {
  const [a, b] = octets;
  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 10) return true; // 10.0.0.0/8 RFC1918
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 RFC1918
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 RFC1918
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 Tailscale/CGNAT
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local
  return false;
}

export function isLocalOrPrivateHost(rawHostname: string): boolean {
  const host = rawHostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host) return false;
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".ts.net") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".lan") ||
    host.endsWith(".home.arpa")
  ) {
    return true;
  }

  const ipv4 = parseIpv4(host);
  if (ipv4) return isPrivateOrLocalIpv4(ipv4);

  if (host.includes(":")) {
    if (host === "::1") return true;
    if (host.startsWith("fc") || host.startsWith("fd")) return true; // fc00::/7 (includes Tailscale fd7a:115c:a1e0::/48)
    if (host.startsWith("fe8") || host.startsWith("fe9") || host.startsWith("fea") || host.startsWith("feb")) {
      return true; // fe80::/10 link-local
    }
    const mapped = host.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped?.[1]) {
      const mappedV4 = parseIpv4(mapped[1]);
      if (mappedV4) return isPrivateOrLocalIpv4(mappedV4);
    }
    const mappedHex = host.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (mappedHex?.[1] && mappedHex[2]) {
      const hi = parseInt(mappedHex[1], 16);
      const lo = parseInt(mappedHex[2], 16);
      return isPrivateOrLocalIpv4([(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff]);
    }
    return false;
  }

  // Single-label local hostname (e.g., "flux" or "ntfy" on a private LAN/Tailnet)
  return !host.includes(".");
}

function validateUrl(
  value: unknown,
  label: string,
  options: { bareOrigin?: boolean } = {},
): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`Invalid ${label}: expected non-empty URL string`);
  }
  const raw = value.trim();
  if (raw.includes("#")) {
    throw new Error(`Invalid ${label}: URL fragments are not permitted`);
  }
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`Invalid ${label}: malformed URL`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error(`Invalid ${label}: protocol must be http or https`);
  }
  if (parsed.username !== "" || parsed.password !== "") {
    throw new Error(`Invalid ${label}: embedded URL credentials are not permitted`);
  }
  if (parsed.hash !== "") {
    throw new Error(`Invalid ${label}: URL fragments are not permitted`);
  }
  if (parsed.protocol === "http:" && !isLocalOrPrivateHost(parsed.hostname)) {
    throw new Error(`Invalid ${label}: http is only permitted for local, private, or Tailscale endpoints`);
  }
  if (options.bareOrigin) {
    if (parsed.search !== "" || raw.includes("?")) {
      throw new Error(`Invalid ${label}: must be a bare origin without query parameters`);
    }
    if (!/^https?:\/\//i.test(raw)) {
      throw new Error(`Invalid ${label}: must be a bare origin`);
    }
    const afterScheme = raw.slice(raw.indexOf("://") + 3);
    if (afterScheme.includes("\\") || afterScheme.includes("@")) {
      throw new Error(`Invalid ${label}: must be a bare origin without a path`);
    }
    const slashIdx = afterScheme.indexOf("/");
    if (
      parsed.pathname !== "/" ||
      (slashIdx !== -1 && slashIdx !== afterScheme.length - 1)
    ) {
      throw new Error(`Invalid ${label}: must be a bare origin without a path`);
    }
    return parsed.origin;
  }
  return raw;
}

function mergeCriteria(
  base: Record<CriterionId, boolean>,
  patch: unknown,
  label: string,
): Record<CriterionId, boolean> {
  if (patch === undefined) return { ...base };
  if (!isPlainObject(patch)) {
    throw new Error(`Invalid ${label}: expected object`);
  }
  const next = { ...base };
  for (const [key, value] of Object.entries(patch)) {
    if (!CRITERION_SET.has(key)) {
      throw new Error(`Invalid ${label}: unknown criterion "${key}"`);
    }
    if (typeof value !== "boolean") {
      throw new Error(`Invalid ${label}.${key}: expected boolean`);
    }
    next[key as CriterionId] = value;
  }
  return next;
}

function validateExpectedPorts(value: unknown): number[] {
  if (!Array.isArray(value)) {
    throw new Error("Invalid expectedPorts: expected array");
  }
  return value.map((port, idx) => validatePort(port, `expectedPorts[${idx}]`));
}

function validateWorkloads(value: unknown): EnrolledWorkload[] {
  if (!Array.isArray(value)) {
    throw new Error("Invalid workloads: expected array");
  }
  const seenIds = new Set<string>();
  const seenUnits = new Set<string>();
  return value.map((item, idx) => {
    if (!isPlainObject(item)) {
      throw new Error(`Invalid workloads[${idx}]: expected object`);
    }
    if (typeof item.id !== "string" || item.id.trim() === "") {
      throw new Error(`Invalid workloads[${idx}].id: expected non-empty string`);
    }
    const id = item.id.trim();
    if (seenIds.has(id)) {
      throw new Error(`Invalid workloads[${idx}].id: duplicate workload id "${id}"`);
    }
    seenIds.add(id);
    if (typeof item.unit !== "string" || !isValidSystemdUnitName(item.unit)) {
      throw new Error(`Invalid workloads[${idx}].unit: invalid systemd unit name`);
    }
    const unit = item.unit.trim();
    if (seenUnits.has(unit)) {
      throw new Error(`Invalid workloads[${idx}].unit: duplicate workload unit "${unit}"`);
    }
    seenUnits.add(unit);
    const workload: EnrolledWorkload = {
      id,
      unit,
    };
    if (item.name !== undefined) {
      if (typeof item.name !== "string" || item.name.trim() === "") {
        throw new Error(`Invalid workloads[${idx}].name: expected non-empty string`);
      }
      workload.name = item.name.trim();
    }
    if (item.ports !== undefined) {
      if (!Array.isArray(item.ports)) {
        throw new Error(`Invalid workloads[${idx}].ports: expected array`);
      }
      workload.ports = item.ports.map((p, pIdx) =>
        validatePort(p, `workloads[${idx}].ports[${pIdx}]`),
      );
    }
    return workload;
  });
}

function validateChannels(value: unknown): AlertChannel[] {
  if (!Array.isArray(value)) {
    throw new Error("Invalid notifications.channels: expected array");
  }
  const seen = new Set<AlertChannel>();
  const out: AlertChannel[] = [];
  for (const ch of value) {
    if (typeof ch !== "string" || !CHANNEL_SET.has(ch)) {
      throw new Error(`Invalid notifications channel: ${String(ch)}`);
    }
    const channel = ch as AlertChannel;
    if (!seen.has(channel)) {
      seen.add(channel);
      out.push(channel);
    }
  }
  return out;
}

function parsePortEnv(raw: string | undefined, fallback: number): number {
  if (raw === undefined || raw === "") return fallback;
  if (!/^\d+$/.test(raw)) {
    throw new Error(`Invalid BASHO_PORT: ${raw}`);
  }
  const parsed = Number(raw);
  return validatePort(parsed, "BASHO_PORT");
}

function parseBooleanEnv(raw: string | undefined, fallback: boolean, name: string): boolean {
  if (raw === undefined || raw === "") return fallback;
  const normalized = raw.trim().toLowerCase();
  if (normalized === "1" || normalized === "true") return true;
  if (normalized === "0" || normalized === "false") return false;
  throw new Error(`Invalid ${name}: expected 1, 0, true, or false`);
}

function parseProcessSettings(env: Record<string, string | undefined>): ProcessSettings {
  const hostRaw = env.BASHO_HOST;
  const host = hostRaw !== undefined && hostRaw !== "" ? hostRaw.trim() : "0.0.0.0";
  if (host === "" || /\s/.test(host)) {
    throw new Error("Invalid BASHO_HOST: must be a non-empty host without whitespace");
  }

  const port = parsePortEnv(env.BASHO_PORT, 6969);

  const dbRaw = env.BASHO_SECURITY_DB;
  const securityDbPath =
    dbRaw !== undefined && dbRaw !== "" ? dbRaw.trim() : "data/basho-security.db";
  if (securityDbPath === "") {
    throw new Error("Invalid BASHO_SECURITY_DB: must be non-empty");
  }

  const demo = parseBooleanEnv(env.BASHO_DEMO_SECURITY, false, "BASHO_DEMO_SECURITY");

  return { host, port, securityDbPath, demo };
}

function extractSecrets(env: Record<string, string | undefined>): SecuritySecrets {
  const readSecret = (key: string): string | undefined => {
    const val = env[key];
    return val !== undefined && val !== "" ? val : undefined;
  };
  const opencodeServerPassword = readSecret("OPENCODE_SERVER_PASSWORD");
  return {
    aiKey: readSecret("OPENCODE_API_KEY"),
    ...(opencodeServerPassword !== undefined ? { opencodeServerPassword } : {}),
    authToken: readSecret("BASHO_AUTH_TOKEN"),
    ntfyToken: readSecret("BASHO_NTFY_TOKEN"),
    discordWebhook: readSecret("BASHO_DISCORD_WEBHOOK"),
    telegramBotToken: readSecret("BASHO_TELEGRAM_BOT_TOKEN"),
    telegramChatId: readSecret("BASHO_TELEGRAM_CHAT_ID"),
  };
}

export function redactSecrets(text: string, secrets: SecuritySecrets): string {
  if (!text) return text;
  let result = text;

  const secretValues = new Set<string>();
  const rawSecrets = [
    secrets.aiKey,
    secrets.opencodeServerPassword,
    secrets.authToken,
    secrets.ntfyToken,
    secrets.discordWebhook,
    secrets.telegramBotToken,
  ];

  for (const raw of rawSecrets) {
    if (typeof raw !== "string" || raw.length === 0) continue;
    secretValues.add(raw);
    try {
      const encoded = encodeURIComponent(raw);
      if (encoded !== raw) {
        secretValues.add(encoded);
      }
    } catch {
      // Ignore malformed URI encoding edge cases.
    }
  }

  if (
    typeof secrets.opencodeServerPassword === "string" &&
    secrets.opencodeServerPassword.length > 0
  ) {
    const basicBlob = Buffer.from(
      `opencode:${secrets.opencodeServerPassword}`,
      "utf8",
    ).toString("base64");
    secretValues.add(`Basic ${basicBlob}`);
    secretValues.add(basicBlob);
  }

  const orderedSecrets = [...secretValues].sort((a, b) => b.length - a.length);
  for (const secret of orderedSecrets) {
    result = result.split(secret).join("[redacted]");
  }

  result = result.replace(/\bBasic\s+[A-Za-z0-9+/=]+/gi, "[redacted]");
  result = result.replace(/\bBearer\s+[^\s"',;]+/gi, "[redacted]");

  return result;
}

function readRawFileConfig(input: LoadSecurityConfigInput): Record<string, unknown> {
  if (input.fileConfig !== undefined) {
    if (!isPlainObject(input.fileConfig)) {
      throw new Error("Invalid fileConfig: expected object");
    }
    return input.fileConfig;
  }
  const path = input.configPath ?? DEFAULT_CONFIG_PATH;
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!isPlainObject(parsed)) {
    throw new Error(`Invalid config file at ${path}: expected JSON object`);
  }
  return parsed;
}

function validateOverrides(overrides: RuntimeOverrides | undefined): RuntimeOverrides {
  if (overrides === undefined) return {};
  if (!isPlainObject(overrides)) {
    throw new Error("Invalid overrides: expected object");
  }
  for (const key of Object.keys(overrides)) {
    if (!OVERRIDE_KEYS.has(key)) {
      throw new Error(`Invalid override field: "${key}"`);
    }
  }
  return overrides;
}

function withDefault<T>(value: unknown, fallback: T): unknown {
  return value === undefined ? fallback : value;
}

export function loadSecurityConfig(
  input: LoadSecurityConfigInput = {},
): { settings: SecuritySettings; secrets: SecuritySecrets } {
  const env = input.env ?? process.env;
  const file = readRawFileConfig(input);
  const overrides = validateOverrides(input.overrides);

  const fileAi = file.ai === undefined ? {} : file.ai;
  if (!isPlainObject(fileAi)) {
    throw new Error("Invalid ai configuration: expected object");
  }
  const fileNotifications = file.notifications === undefined ? {} : file.notifications;
  if (!isPlainObject(fileNotifications)) {
    throw new Error("Invalid notifications configuration: expected object");
  }
  const fileLockdown = file.lockdown === undefined ? {} : file.lockdown;
  if (!isPlainObject(fileLockdown)) {
    throw new Error("Invalid lockdown configuration: expected object");
  }

  const fileMode = file.mode !== undefined ? validateMode(file.mode) : undefined;
  const overrideMode = overrides.mode !== undefined ? validateMode(overrides.mode) : undefined;
  const mode = overrideMode ?? fileMode ?? "approve";

  const fileScanInterval =
    file.scanIntervalMinutes !== undefined
      ? validateIntRange(file.scanIntervalMinutes, 1, 1440, "scanIntervalMinutes")
      : undefined;
  const overrideScanInterval =
    overrides.scanIntervalMinutes !== undefined
      ? validateIntRange(overrides.scanIntervalMinutes, 1, 1440, "scanIntervalMinutes")
      : undefined;
  const scanIntervalMinutes = overrideScanInterval ?? fileScanInterval ?? 60;

  let criteria = defaultCriteria();
  criteria = mergeCriteria(criteria, file.criteria, "criteria");
  criteria = mergeCriteria(criteria, overrides.criteria, "overrides.criteria");

  const expectedPorts = validateExpectedPorts(withDefault(file.expectedPorts, [22, 6969]));
  const workloads = validateWorkloads(withDefault(file.workloads, []));

  const fileProvider =
    fileAi.provider !== undefined
      ? validateAiProvider(fileAi.provider, "ai.provider")
      : undefined;
  const envProvider = env.BASHO_AI_PROVIDER;
  const hasApiKey =
    typeof env.OPENCODE_API_KEY === "string" && env.OPENCODE_API_KEY.trim() !== "";
  const provider: AiProviderKind =
    envProvider !== undefined && envProvider !== ""
      ? validateAiProvider(envProvider.trim(), "BASHO_AI_PROVIDER")
      : (fileProvider ?? (hasApiKey ? "openai-compatible" : "opencode-harness"));

  const fileServerUrl =
    fileAi.serverUrl !== undefined
      ? validateUrl(fileAi.serverUrl, "ai.serverUrl")
      : undefined;
  const envServerUrl = env.OPENCODE_SERVER_URL;
  const serverUrl =
    envServerUrl !== undefined && envServerUrl !== ""
      ? validateUrl(envServerUrl, "OPENCODE_SERVER_URL")
      : fileServerUrl;

  const fileBaseURL =
    fileAi.baseURL !== undefined ? validateUrl(fileAi.baseURL, "ai.baseURL") : undefined;
  const envBaseURL = env.OPENCODE_BASE_URL;
  const baseURL =
    envBaseURL !== undefined && envBaseURL !== ""
      ? validateUrl(envBaseURL, "ai.baseURL")
      : (fileBaseURL ?? "https://opencode.ai/zen/go/v1");

  const model = withDefault(fileAi.model, "opencode-go/deepseek-v4.1-flash");
  if (typeof model !== "string" || model.trim() === "") {
    throw new Error("Invalid ai.model: expected non-empty string");
  }

  const sessionHeader = withDefault(fileAi.sessionHeader, true);
  if (typeof sessionHeader !== "boolean") {
    throw new Error("Invalid ai.sessionHeader: expected boolean");
  }

  const confidenceThreshold = validateConfidence(withDefault(fileAi.confidenceThreshold, 0.85));
  const triageCooldownMinutes = validateIntRange(
    withDefault(fileAi.triageCooldownMinutes, 10),
    0,
    1440,
    "ai.triageCooldownMinutes",
  );

  const channels = validateChannels(withDefault(fileNotifications.channels, ["in-app"]));
  const cooldownMinutes = validateIntRange(
    withDefault(fileNotifications.cooldownMinutes, 15),
    0,
    1440,
    "notifications.cooldownMinutes",
  );
  const ntfyUrl =
    fileNotifications.ntfyUrl !== undefined
      ? validateUrl(fileNotifications.ntfyUrl, "notifications.ntfyUrl")
      : undefined;
  const publicOrigin =
    fileNotifications.publicOrigin !== undefined
      ? validateUrl(fileNotifications.publicOrigin, "notifications.publicOrigin", {
          bareOrigin: true,
        })
      : undefined;

  const proposalMinutes = validateIntRange(
    withDefault(fileLockdown.proposalMinutes, 30),
    1,
    1440,
    "lockdown.proposalMinutes",
  );
  const leaseSeconds = validateIntRange(
    withDefault(fileLockdown.leaseSeconds, 600),
    30,
    1800,
    "lockdown.leaseSeconds",
  );
  const helperEnabled = withDefault(fileLockdown.helperEnabled, false);
  if (typeof helperEnabled !== "boolean") {
    throw new Error("Invalid lockdown.helperEnabled: expected boolean");
  }

  const processSettings = parseProcessSettings(env);
  const secrets = extractSecrets(env);

  const settings: SecuritySettings = {
    mode,
    scanIntervalMinutes,
    criteria,
    expectedPorts,
    workloads,
    ai: {
      provider,
      ...(serverUrl !== undefined ? { serverUrl } : {}),
      baseURL,
      model: model.trim(),
      sessionHeader,
      confidenceThreshold,
      triageCooldownMinutes,
    },
    notifications: {
      channels,
      cooldownMinutes,
      ...(ntfyUrl !== undefined ? { ntfyUrl } : {}),
      ...(publicOrigin !== undefined ? { publicOrigin } : {}),
    },
    lockdown: {
      proposalMinutes,
      leaseSeconds,
      helperEnabled,
    },
    process: processSettings,
  };

  return { settings, secrets };
}
