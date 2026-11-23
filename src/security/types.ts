export const criterionIds = [
  "firewall_ufw",
  "network_exposure",
  "ssh_hardening",
  "package_updates",
  "disk_and_boot",
  "kernel_sysctl",
  "systemd_health",
  "process_and_timers",
] as const;

export type CriterionId = (typeof criterionIds)[number];
export type Category = "auth" | "firewall" | "network" | "units" | "packages";
export type Severity = "info" | "warning" | "critical" | "breach";

export const lockdownModes = ["monitor", "approve", "auto-lockdown"] as const;
export type LockdownMode = (typeof lockdownModes)[number];

export const alertChannels = [
  "in-app",
  "desktop",
  "ntfy",
  "discord",
  "telegram",
] as const;
export type AlertChannel = (typeof alertChannels)[number];

export type Coverage = "complete" | "partial" | "unavailable";
export type Facts = Readonly<Record<string, string | number | boolean | null>>;

export interface Clock {
  now(): number;
}

export type HttpFetcher = (url: string, init: RequestInit) => Promise<Response>;

export interface Evidence {
  readonly id: string;
  readonly kind: "criterion" | "listener" | "event" | "process" | "unit";
  readonly facts: Facts;
}

export interface PostureCheck {
  id: CriterionId;
  category: Category | "host";
  title: string;
  status: "pass" | "warn" | "fail" | "unknown" | "disabled";
  summary: string;
  remediation?: string;
  evidenceIds: string[];
  sourceCoverage: Record<string, Coverage>;
}

export interface PostureSnapshot {
  id: string;
  capturedAt: number;
  checks: PostureCheck[];
  evidence: Evidence[];
}

export interface Listener {
  id: string;
  protocol: "tcp" | "udp";
  address: string;
  port: number;
  family: 4 | 6 | "unspecified";
  interfaceName?: string;
  pid?: number;
  process?: string;
}

export interface ExposureEntry {
  id: string;
  listener: Listener;
  reachability:
    | "exposed_v4_v6"
    | "exposed_lan"
    | "tailnet"
    | "blocked_by_ufw"
    | "local_only"
    | "unknown";
  firewallV4: "allow" | "deny" | "unknown" | "na";
  firewallV6: "allow" | "deny" | "unknown" | "na";
  publication: "serve" | "funnel" | "none" | "unknown";
  expected: boolean;
  evidenceIds: string[];
}

export interface SecurityEvent {
  id: string;
  source: "journal" | "socket";
  category: Category;
  severity: Severity;
  rule: string;
  target: string;
  firstAt: number;
  lastAt: number;
  count: number;
  isNoise: boolean;
  summary: string;
}

export interface SecurityFinding {
  id: string;
  source: "deterministic" | "ai";
  severity: Severity;
  summary: string;
  evidenceIds: string[];
}

export const evidenceTools = [
  "read_posture_detail",
  "read_listener_detail",
  "read_recent_events",
  "read_process_summary",
  "read_unit_status",
] as const;

export type EvidenceTool = (typeof evidenceTools)[number];

export interface InvestigationTrail {
  steps: {
    tool: EvidenceTool | "verdict";
    reason: string;
    outcome: "ok" | "rejected" | "unavailable";
    evidenceIds: string[];
  }[];
}

export interface AiVerdict {
  kind: "healthy" | "warn" | "breach";
  confidence: number;
  summary: string;
}

export interface SecurityScan {
  id: string;
  trigger: "scheduled" | "manual" | "event";
  startedAt: number;
  finishedAt: number;
  snapshot: PostureSnapshot;
  exposure: ExposureEntry[];
  findings: SecurityFinding[];
  trail: InvestigationTrail;
  aiStatus: "ready" | "unconfigured" | "offline";
  verdict?: AiVerdict;
}

export type ContainmentTarget =
  | { kind: "pause_workload"; workloadId: string; pid: number; startedAt: number }
  | { kind: "deny_peer_ip"; ip: string }
  | { kind: "isolate_lan_ingress" };

export interface LockdownProposal {
  id: string;
  scanId: string;
  revision: number;
  status: "pending" | "claimed" | "rejected" | "expired";
  target: ContainmentTarget;
  evidenceIds: string[];
  createdAt: number;
  expiresAt: number;
  leaseSeconds: number;
  rollbackDescription: string;
}

export interface LockdownAction {
  id: string;
  proposalId: string;
  idempotencyKey: string;
  target: ContainmentTarget;
  state: "pending" | "active" | "failed" | "rolling_back" | "rolled_back";
  createdAt: number;
  expiresAt: number;
  updatedAt: number;
  rollbackHandle?: string;
}

export interface SecurityAlert {
  id: string;
  fingerprint: string;
  severity: Severity;
  summary: string;
  createdAt: number;
  proposalId?: string;
}

export interface Corroboration {
  rule: "ssh_burst" | "unexpected_listener" | "system_anomaly" | "unexpected_workload";
  eventIds: string[];
  expiresAt: number;
  target?: ContainmentTarget;
}

export type CommandRequest =
  | {
      kind:
        | "sockets"
        | "ufw_status"
        | "tailscale_serve"
        | "tailscale_funnel"
        | "updates"
        | "arch_audit"
        | "block_devices"
        | "boot_status"
        | "sysctl"
        | "system_failed"
        | "user_failed"
        | "user_timers"
        | "processes"
        | "snapper_health"
        | "limine_health";
    }
  | { kind: "journal"; after?: string; limit: number }
  | { kind: "unit"; name: string; scope: "system" | "user" }
  | { kind: "desktop"; urgency: "normal" | "critical"; summary: string; body: string };

export type CommandResult =
  | { status: "ok"; stdout: string; exitCode: number }
  | { status: "overflow"; skippedCursor?: string }
  | { status: "unavailable" | "timeout" | "failed" | "cursor_expired" };

export interface CommandRunner {
  run(request: CommandRequest, signal?: AbortSignal): Promise<CommandResult>;
}

export interface EnrolledWorkload {
  id: string;
  unit: string;
  name?: string;
  ports?: number[];
}

export interface RuntimeOverrides {
  mode?: LockdownMode;
  scanIntervalMinutes?: number;
  criteria?: Partial<Record<CriterionId, boolean>>;
}

export interface ProcessSettings {
  host: string;
  port: number;
  securityDbPath: string;
  demo: boolean;
}

export interface SecuritySettings {
  mode: LockdownMode;
  scanIntervalMinutes: number;
  criteria: Record<CriterionId, boolean>;
  expectedPorts: number[];
  workloads: EnrolledWorkload[];
  ai: {
    baseURL: string;
    model: string;
    sessionHeader: boolean;
    confidenceThreshold: number;
    triageCooldownMinutes: number;
  };
  notifications: {
    channels: AlertChannel[];
    cooldownMinutes: number;
    ntfyUrl?: string;
    publicOrigin?: string;
  };
  lockdown: {
    proposalMinutes: number;
    leaseSeconds: number;
    helperEnabled: boolean;
  };
  process: ProcessSettings;
}

export interface SecuritySecrets {
  aiKey?: string;
  authToken?: string;
  ntfyToken?: string;
  discordWebhook?: string;
  telegramBotToken?: string;
  telegramChatId?: string;
}
