import { readFile } from "node:fs/promises";
import type { ProposalDraft } from "./ai-analyst";
import { isValidSystemdUnitName } from "./runner";
import type { SecurityStoreContract } from "./store";
import type {
  AiVerdict,
  Clock,
  ContainmentTarget,
  Corroboration,
  EnrolledWorkload,
  LockdownAction,
  LockdownMode,
  LockdownProposal,
  SecurityAlert,
  SecurityScan,
  SecuritySettings,
} from "./types";

const TRUSTED_SEARCH_PATH =
  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const DEFAULT_HELPER_PATH = "/usr/local/libexec/basho-lockdown-helper";
const DEFAULT_ADAPTER_TIMEOUT_MS = 10_000;
const MIN_LEASE_SECONDS = 30;
const MAX_LEASE_SECONDS = 1_800;
const PROCESS_START_TIME_TOLERANCE_MS = 2_000;
const SAFE_OP_ID_PATTERN = /^[A-Za-z0-9._:-]{1,64}$/;
const STRICT_IPV4_PATTERN =
  /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/;
const HEX_GROUP_PATTERN = /^[0-9a-fA-F]{1,4}$/;
const USER_RUNTIME_ENV_KEYS = [
  "XDG_RUNTIME_DIR",
  "DBUS_SESSION_BUS_ADDRESS",
] as const;

const CRITICAL_EXACT_COMMS = new Set<string>([
  "systemd",
  "basho",
  "tailscaled",
  "sshd",
  "sshd-session",
  "networkmanager",
  "hyprland",
  "sddm",
  "init",
]);

const CRITICAL_PREFIX_COMMS = ["systemd-", "sshd-", "dbus", "wayland"] as const;

const CRITICAL_EXACT_UNITS = new Set<string>([
  "init.scope",
  "sshd.service",
  "tailscaled.service",
  "networkmanager.service",
  "sddm.service",
  "basho.service",
]);

const CRITICAL_PREFIX_UNITS = ["systemd-", "dbus", "basho-"] as const;

export interface ProcessIdentity {
  pid: number;
  uid: number;
  startedAt: number;
  comm: string;
  unit?: string;
  uunit?: string;
}

export type ResolveProcess = (pid: number) => Promise<ProcessIdentity | null>;

export interface DeadMansSwitchContext {
  workloads?: readonly EnrolledWorkload[];
  currentProcess?: ProcessIdentity | null;
  currentUid?: number;
  expectedComm?: string;
  lanPolicyReady?: boolean;
}

export type ContainmentDecision = "report" | "queue" | "execute";

export interface DecisionInput {
  mode: LockdownMode;
  target: ContainmentTarget;
  now: number;
  threshold: number;
  verdict?: AiVerdict;
  corroboration: readonly Corroboration[];
  safe: boolean;
  rollbackReady: boolean;
}

export interface LockdownPreflightResult {
  rollbackReady: boolean;
  lanPolicyReady?: boolean;
  reason?: string;
}

export interface LockdownApplyResult {
  handle: string;
}

export type LockdownInspectResult =
  | { state: "active"; handle?: string }
  | { state: "absent" }
  | { state: "unknown" };

export type LockdownRollbackResult =
  | { state: "absent" }
  | { state: "unknown" };

export interface LockdownAdapter {
  preflight(target: ContainmentTarget): Promise<LockdownPreflightResult>;
  apply(action: LockdownAction): Promise<LockdownApplyResult>;
  inspect(action: LockdownAction): Promise<LockdownInspectResult>;
  rollback(action: LockdownAction): Promise<LockdownRollbackResult>;
}

export interface ConsiderResult {
  proposals: LockdownProposal[];
  actions: LockdownAction[];
  alerts: SecurityAlert[];
}

export interface LockdownEngineOptions {
  store: SecurityStoreContract;
  clock?: Clock;
  guard?: DeadMansSwitch;
  adapter: LockdownAdapter;
  resolveProcess?: ResolveProcess;
  currentUid?: number;
}

export interface SubprocessExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export type SubprocessExecutor = (
  argv: readonly string[],
  options?: { timeoutMs?: number; env?: Record<string, string> },
) => Promise<SubprocessExecResult>;

export interface HelperLockdownAdapterOptions {
  helperPath?: string;
  sudoPath?: string;
  clock?: Clock;
  timeoutMs?: number;
  exec?: SubprocessExecutor;
}

export interface UserWorkloadLockdownAdapterOptions {
  getWorkloads: () => readonly EnrolledWorkload[];
  systemctlPath?: string;
  systemdRunPath?: string;
  clock?: Clock;
  timeoutMs?: number;
  exec?: SubprocessExecutor;
  resolveProcess?: ResolveProcess;
  currentUid?: number;
}

export interface CompositeLockdownAdapterOptions {
  helper?: LockdownAdapter;
  workload?: LockdownAdapter;
  getWorkloads?: () => readonly EnrolledWorkload[];
  clock?: Clock;
  resolveProcess?: ResolveProcess;
  currentUid?: number;
}

type ParsedIp =
  | {
      version: 4;
      octets: readonly [number, number, number, number];
      canonical: string;
    }
  | {
      version: 6;
      groups: readonly [
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
      ];
      canonical: string;
    };

function parseIpv4Octets(
  raw: string,
): readonly [number, number, number, number] | null {
  const match = STRICT_IPV4_PATTERN.exec(raw);
  if (!match) return null;
  const o0 = Number(match[1]);
  const o1 = Number(match[2]);
  const o2 = Number(match[3]);
  const o3 = Number(match[4]);
  if (o0 > 255 || o1 > 255 || o2 > 255 || o3 > 255) {
    return null;
  }
  return [o0, o1, o2, o3] as const;
}

function formatCanonicalIpv6(
  groups: readonly [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
  ],
): string {
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;

  for (let i = 0; i < 8; i += 1) {
    if (groups[i] === 0) {
      if (curStart === -1) {
        curStart = i;
        curLen = 1;
      } else {
        curLen += 1;
      }
      if (curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  if (bestLen < 2) {
    return groups.map((g) => g.toString(16)).join(":");
  }

  const left = groups
    .slice(0, bestStart)
    .map((g) => g.toString(16))
    .join(":");
  const right = groups
    .slice(bestStart + bestLen)
    .map((g) => g.toString(16))
    .join(":");
  return `${left}::${right}`;
}

function parseIp(raw: string): ParsedIp | null {
  if (typeof raw !== "string" || raw.length === 0 || raw.trim() !== raw) {
    return null;
  }
  if (/[\/%\s]/.test(raw)) {
    return null;
  }

  const v4 = parseIpv4Octets(raw);
  if (v4) {
    return {
      version: 4,
      octets: v4,
      canonical: `${v4[0]}.${v4[1]}.${v4[2]}.${v4[3]}`,
    };
  }

  if (!raw.includes(":")) {
    return null;
  }

  if (raw.includes(":::")) {
    return null;
  }

  let working = raw;
  let embeddedV4: readonly [number, number] | null = null;
  const lastColon = working.lastIndexOf(":");
  const tail = working.slice(lastColon + 1);
  if (tail.includes(".")) {
    const octets = parseIpv4Octets(tail);
    if (!octets) return null;
    embeddedV4 = [
      (octets[0] << 8) | octets[1],
      (octets[2] << 8) | octets[3],
    ] as const;
    if (lastColon === 0) {
      return null;
    }
    if (working.charAt(lastColon - 1) === ":") {
      working = working.slice(0, lastColon + 1);
    } else {
      working = working.slice(0, lastColon);
    }
  }

  const expectedHexGroups = embeddedV4 ? 6 : 8;
  const doubleColonIndex = working.indexOf("::");
  let hexGroups: number[];

  if (doubleColonIndex !== -1) {
    if (working.indexOf("::", doubleColonIndex + 2) !== -1) {
      return null;
    }
    const leftStr = working.slice(0, doubleColonIndex);
    const rightStr = working.slice(doubleColonIndex + 2);
    if (leftStr.startsWith(":") || leftStr.endsWith(":")) return null;
    if (rightStr.startsWith(":") || rightStr.endsWith(":")) return null;

    const leftParts = leftStr.length > 0 ? leftStr.split(":") : [];
    const rightParts = rightStr.length > 0 ? rightStr.split(":") : [];
    const missing = expectedHexGroups - (leftParts.length + rightParts.length);
    if (missing < 1) {
      return null;
    }

    hexGroups = [];
    for (const part of leftParts) {
      if (!HEX_GROUP_PATTERN.test(part)) return null;
      hexGroups.push(Number.parseInt(part, 16));
    }
    for (let i = 0; i < missing; i += 1) {
      hexGroups.push(0);
    }
    for (const part of rightParts) {
      if (!HEX_GROUP_PATTERN.test(part)) return null;
      hexGroups.push(Number.parseInt(part, 16));
    }
  } else {
    if (working.startsWith(":") || working.endsWith(":")) return null;
    const parts = working.split(":");
    if (parts.length !== expectedHexGroups) {
      return null;
    }
    hexGroups = [];
    for (const part of parts) {
      if (!HEX_GROUP_PATTERN.test(part)) return null;
      hexGroups.push(Number.parseInt(part, 16));
    }
  }

  if (embeddedV4) {
    hexGroups.push(embeddedV4[0], embeddedV4[1]);
  }
  if (hexGroups.length !== 8) {
    return null;
  }

  const groups = hexGroups as unknown as readonly [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
  ];

  // Unwrap IPv4-mapped IPv6 (::ffff:0:0/96) to canonical IPv4 so protected ranges
  // and peer corroboration compare identically across representations.
  if (
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0xffff
  ) {
    const octets = [
      (groups[6] >> 8) & 0xff,
      groups[6] & 0xff,
      (groups[7] >> 8) & 0xff,
      groups[7] & 0xff,
    ] as const;
    return {
      version: 4,
      octets,
      canonical: `${octets[0]}.${octets[1]}.${octets[2]}.${octets[3]}`,
    };
  }

  return {
    version: 6,
    groups,
    canonical: formatCanonicalIpv6(groups),
  };
}

function isProtectedParsedIp(parsed: ParsedIp): boolean {
  if (parsed.version === 4) {
    const [b0, b1, b2, b3] = parsed.octets;
    if (b0 === 0) return true; // 0.0.0.0/8 unspecified
    if (b0 === 127) return true; // 127.0.0.0/8 loopback
    if (b0 === 100 && (b1 & 0xc0) === 64) return true; // 100.64.0.0/10 Tailscale CGNAT
    if ((b0 & 0xf0) === 224) return true; // 224.0.0.0/4 multicast
    if (b0 === 255 && b1 === 255 && b2 === 255 && b3 === 255) return true; // limited broadcast
    return false;
  }

  const g = parsed.groups;
  const allZero =
    g[0] === 0 &&
    g[1] === 0 &&
    g[2] === 0 &&
    g[3] === 0 &&
    g[4] === 0 &&
    g[5] === 0 &&
    g[6] === 0 &&
    g[7] === 0;
  if (allZero) return true; // :: unspecified

  const isLoopback =
    g[0] === 0 &&
    g[1] === 0 &&
    g[2] === 0 &&
    g[3] === 0 &&
    g[4] === 0 &&
    g[5] === 0 &&
    g[6] === 0 &&
    g[7] === 1;
  if (isLoopback) return true; // ::1 loopback

  if (g[0] === 0xfd7a && g[1] === 0x115c && g[2] === 0xa1e0) {
    return true; // fd7a:115c:a1e0::/48 Tailscale IPv6 ULA
  }

  if ((g[0] & 0xff00) === 0xff00) {
    return true; // ff00::/8 multicast
  }

  return false;
}

export function canonicalizeIp(raw: string): string | null {
  return parseIp(raw)?.canonical ?? null;
}

export function isProtectedIp(raw: string): boolean {
  const parsed = parseIp(raw);
  if (!parsed) return true;
  return isProtectedParsedIp(parsed);
}

function isCriticalProcessComm(comm: string): boolean {
  const normalized = comm.trim().toLowerCase();
  if (normalized.length === 0) return true;
  if (CRITICAL_EXACT_COMMS.has(normalized)) return true;
  return CRITICAL_PREFIX_COMMS.some((prefix) => normalized.startsWith(prefix));
}

function isCriticalUnitName(unit: string): boolean {
  const normalized = unit.trim().toLowerCase();
  if (normalized.length === 0) return true;
  if (CRITICAL_EXACT_UNITS.has(normalized)) return true;
  return CRITICAL_PREFIX_UNITS.some((prefix) => normalized.startsWith(prefix));
}

function normalizeUnitField(value?: string): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed === "-") return undefined;
  return trimmed;
}

export class DeadMansSwitch {
  allows(target: ContainmentTarget, context?: DeadMansSwitchContext): boolean {
    switch (target.kind) {
      case "deny_peer_ip": {
        const parsed = parseIp(target.ip);
        if (!parsed) return false;
        return !isProtectedParsedIp(parsed);
      }

      case "pause_workload": {
        if (
          typeof target.workloadId !== "string" ||
          target.workloadId.trim().length === 0 ||
          !Number.isSafeInteger(target.pid) ||
          target.pid <= 1 ||
          !Number.isSafeInteger(target.startedAt) ||
          target.startedAt <= 0
        ) {
          return false;
        }

        const enrolled = context?.workloads?.find(
          (item) => item.id === target.workloadId,
        );
        if (!enrolled || !isValidSystemdUnitName(enrolled.unit)) {
          return false;
        }
        if (isCriticalUnitName(enrolled.unit)) {
          return false;
        }

        const proc = context?.currentProcess;
        if (!proc) {
          return false;
        }
        if (
          !Number.isSafeInteger(proc.pid) ||
          proc.pid <= 1 ||
          proc.pid !== target.pid ||
          !Number.isSafeInteger(proc.startedAt) ||
          proc.startedAt <= 0 ||
          Math.abs(proc.startedAt - target.startedAt) >
            PROCESS_START_TIME_TOLERANCE_MS
        ) {
          return false;
        }

        if (typeof proc.comm !== "string" || isCriticalProcessComm(proc.comm)) {
          return false;
        }
        if (
          context?.expectedComm !== undefined &&
          proc.comm !== context.expectedComm
        ) {
          return false;
        }

        const expectedUid = context?.currentUid;
        if (
          typeof expectedUid !== "number" ||
          !Number.isSafeInteger(expectedUid) ||
          expectedUid <= 0 ||
          proc.uid !== expectedUid
        ) {
          return false;
        }

        const unit = normalizeUnitField(proc.unit);
        const uunit = normalizeUnitField(proc.uunit);
        const expectedUserManagerUnit = `user@${expectedUid}.service`;

        if (uunit !== undefined) {
          if (uunit !== enrolled.unit) {
            return false;
          }
          if (
            unit !== undefined &&
            unit !== expectedUserManagerUnit &&
            unit !== enrolled.unit
          ) {
            return false;
          }
        } else {
          if (unit !== enrolled.unit) {
            return false;
          }
        }

        return true;
      }

      case "isolate_lan_ingress": {
        return context?.lanPolicyReady === true;
      }
    }
  }
}

function corroborationMatchesTarget(
  entry: Corroboration,
  target: ContainmentTarget,
  now: number,
): boolean {
  if (
    !Number.isFinite(entry.expiresAt) ||
    entry.expiresAt <= now ||
    !Array.isArray(entry.eventIds) ||
    entry.eventIds.length === 0
  ) {
    return false;
  }

  switch (target.kind) {
    case "deny_peer_ip": {
      if (entry.rule !== "ssh_burst" || entry.target?.kind !== "deny_peer_ip") {
        return false;
      }
      const targetCanon = canonicalizeIp(target.ip);
      const corrobCanon = canonicalizeIp(entry.target.ip);
      return targetCanon !== null && corrobCanon !== null && targetCanon === corrobCanon;
    }

    case "pause_workload": {
      if (
        entry.rule !== "unexpected_workload" ||
        entry.target?.kind !== "pause_workload"
      ) {
        return false;
      }
      return (
        entry.target.workloadId === target.workloadId &&
        entry.target.pid === target.pid &&
        entry.target.startedAt === target.startedAt
      );
    }

    case "isolate_lan_ingress": {
      // LAN isolation stays approval-only until a dedicated scoped LAN corroboration signal exists.
      return false;
    }
  }
}

export function decideContainment(input: DecisionInput): ContainmentDecision {
  if (input.mode === "monitor" || !input.safe) {
    return "report";
  }

  if (input.mode !== "auto-lockdown") {
    return "queue";
  }

  if (!input.rollbackReady) {
    return "queue";
  }

  if (
    !input.verdict ||
    input.verdict.kind !== "breach" ||
    !Number.isFinite(input.verdict.confidence) ||
    input.verdict.confidence < input.threshold
  ) {
    return "queue";
  }

  const corroborated = input.corroboration.some((entry) =>
    corroborationMatchesTarget(entry, input.target, input.now),
  );
  return corroborated ? "execute" : "queue";
}

function normalizeTarget(target: ContainmentTarget): ContainmentTarget {
  if (target.kind === "deny_peer_ip") {
    const canonical = canonicalizeIp(target.ip);
    if (canonical) {
      return { kind: "deny_peer_ip", ip: canonical };
    }
  }
  return target;
}

function describeRollback(
  target: ContainmentTarget,
  leaseSeconds: number,
): string {
  switch (target.kind) {
    case "deny_peer_ip":
      return `Automatically removes temporary UFW deny rule for ${target.ip} after ${leaseSeconds}s lease expiry, or immediately via unlock.`;
    case "pause_workload":
      return `Automatically thaws user systemd workload ${target.workloadId} (PID ${target.pid}) after ${leaseSeconds}s lease expiry, or immediately via unlock.`;
    case "isolate_lan_ingress":
      return `Automatically restores LAN ingress firewall rules after ${leaseSeconds}s lease expiry while keeping loopback and Tailscale accessible, or immediately via unlock.`;
  }
}

function targetFingerprintKey(target: ContainmentTarget): string {
  switch (target.kind) {
    case "deny_peer_ip":
      return `deny_peer_ip:${target.ip}`;
    case "pause_workload":
      return `pause_workload:${target.workloadId}:${target.pid}:${target.startedAt}`;
    case "isolate_lan_ingress":
      return "isolate_lan_ingress";
  }
}

function defaultUid(): number {
  return typeof process.getuid === "function" ? process.getuid() : 0;
}

export class LockdownEngine {
  private readonly store: SecurityStoreContract;
  private readonly clock: Clock;
  private readonly guard: DeadMansSwitch;
  private readonly adapter: LockdownAdapter;
  private readonly resolveProcess: ResolveProcess;
  private readonly currentUid: number;
  private readonly observedWorkloads = new Map<string, ProcessIdentity>();
  private readonly inFlightActions = new Set<string>();

  constructor(options: LockdownEngineOptions) {
    this.store = options.store;
    this.clock = options.clock ?? { now: () => Date.now() };
    this.guard = options.guard ?? new DeadMansSwitch();
    this.adapter = options.adapter;
    this.resolveProcess = options.resolveProcess ?? createProcProcessResolver();
    this.currentUid = options.currentUid ?? defaultUid();
  }

  private async safePreflight(
    target: ContainmentTarget,
    settings?: SecuritySettings,
  ): Promise<LockdownPreflightResult> {
    if (
      settings &&
      !settings.lockdown.helperEnabled &&
      target.kind !== "pause_workload"
    ) {
      return {
        rollbackReady: false,
        lanPolicyReady: false,
        reason: "Privileged lockdown helper is disabled in settings.",
      };
    }

    try {
      const result = await this.adapter.preflight(target);
      return {
        rollbackReady: Boolean(result.rollbackReady),
        lanPolicyReady: result.lanPolicyReady ?? Boolean(result.rollbackReady),
        reason: result.reason,
      };
    } catch (error) {
      return {
        rollbackReady: false,
        lanPolicyReady: false,
        reason: error instanceof Error ? error.message : String(error),
      };
    }
  }

  private async applyClaimedAction(
    action: LockdownAction,
  ): Promise<{ succeeded: boolean; action: LockdownAction }> {
    this.inFlightActions.add(action.id);
    try {
      const applied = await this.adapter.apply(action);
      const updatedAt = this.clock.now();
      const transitioned = this.store.transitionAction(
        action.id,
        "pending",
        "active",
        updatedAt,
        applied.handle,
      );
      if (!transitioned) {
        const current =
          this.store.listActions().find((entry) => entry.id === action.id) ??
          action;
        return { succeeded: false, action: current };
      }
      return {
        succeeded: true,
        action: {
          ...action,
          state: "active",
          updatedAt,
          rollbackHandle: applied.handle,
        },
      };
    } catch {
      // Leave the action in "pending" state so reconcile() can inspect and settle it.
      return { succeeded: false, action };
    } finally {
      this.inFlightActions.delete(action.id);
    }
  }

  async consider(
    scan: SecurityScan,
    drafts: readonly ProposalDraft[],
    corroboration: readonly Corroboration[],
    settings: SecuritySettings,
  ): Promise<ConsiderResult> {
    const proposals: LockdownProposal[] = [];
    const actions: LockdownAction[] = [];
    const alerts: SecurityAlert[] = [];

    if (settings.mode === "monitor") {
      return { proposals, actions, alerts };
    }

    for (const draft of drafts) {
      const target = normalizeTarget(draft.target);
      const now = this.clock.now();

      let currentProcess: ProcessIdentity | null = null;
      if (target.kind === "pause_workload") {
        try {
          currentProcess = await this.resolveProcess(target.pid);
        } catch {
          currentProcess = null;
        }
      }

      let preflight: LockdownPreflightResult = { rollbackReady: false };
      let safe: boolean;
      if (target.kind === "isolate_lan_ingress") {
        preflight = await this.safePreflight(target, settings);
        safe = this.guard.allows(target, {
          workloads: settings.workloads,
          lanPolicyReady: preflight.lanPolicyReady,
        });
      } else {
        safe = this.guard.allows(target, {
          workloads: settings.workloads,
          currentProcess,
          currentUid: this.currentUid,
        });
        if (safe) {
          preflight = await this.safePreflight(target, settings);
        }
      }

      const decision = decideContainment({
        mode: settings.mode,
        target,
        now,
        threshold: settings.ai.confidenceThreshold,
        verdict: scan.verdict,
        corroboration,
        safe,
        rollbackReady: preflight.rollbackReady,
      });

      if (decision === "report") {
        continue;
      }

      const proposal: LockdownProposal = {
        id: crypto.randomUUID(),
        scanId: scan.id,
        revision: 1,
        status: "pending",
        target,
        evidenceIds: [...draft.evidenceIds],
        createdAt: now,
        expiresAt: now + settings.lockdown.proposalMinutes * 60_000,
        leaseSeconds: settings.lockdown.leaseSeconds,
        rollbackDescription: describeRollback(target, settings.lockdown.leaseSeconds),
      };

      this.store.insertProposal(proposal);
      if (target.kind === "pause_workload" && currentProcess) {
        this.observedWorkloads.set(proposal.id, { ...currentProcess });
      }
      proposals.push(proposal);

      if (decision === "execute") {
        const claimed = this.store.claimProposal(
          proposal.id,
          proposal.revision,
          this.clock.now(),
        );
        if (claimed) {
          this.observedWorkloads.delete(proposal.id);
          const applied = await this.applyClaimedAction(claimed);
          actions.push(applied.action);
        }
        continue;
      }

      // If auto-lockdown fell back to queue solely because rollback readiness was not met,
      // emit an urgent operator alert linked to the queued proposal.
      if (settings.mode === "auto-lockdown" && !preflight.rollbackReady) {
        const wouldExecuteIfReady =
          decideContainment({
            mode: settings.mode,
            target,
            now,
            threshold: settings.ai.confidenceThreshold,
            verdict: scan.verdict,
            corroboration,
            safe,
            rollbackReady: true,
          }) === "execute";

        if (wouldExecuteIfReady) {
          const alert: SecurityAlert = {
            id: crypto.randomUUID(),
            fingerprint: `lockdown-fallback:${targetFingerprintKey(target)}`,
            severity: "critical",
            summary:
              `Auto-lockdown queued ${target.kind} for manual approval because rollback/helper readiness could not be verified` +
              (preflight.reason ? ` (${preflight.reason})` : "."),
            createdAt: this.clock.now(),
            proposalId: proposal.id,
          };
          this.store.enqueueAlert(
            alert,
            settings.notifications.channels,
            settings.notifications.cooldownMinutes * 60_000,
          );
          alerts.push(alert);
        }
      }
    }

    return { proposals, actions, alerts };
  }

  async approve(
    id: string,
    revision: number,
    settings: SecuritySettings,
  ): Promise<boolean> {
    if (settings.mode === "monitor") {
      return false;
    }

    const proposal = this.store
      .listProposals()
      .find((entry) => entry.id === id);
    if (!proposal || proposal.status !== "pending") {
      return false;
    }
    if (proposal.revision !== revision) {
      return false;
    }
    if (proposal.expiresAt <= this.clock.now()) {
      return false;
    }

    let currentProcess: ProcessIdentity | null = null;
    if (proposal.target.kind === "pause_workload") {
      try {
        currentProcess = await this.resolveProcess(proposal.target.pid);
      } catch {
        currentProcess = null;
      }
    }

    const preflight = await this.safePreflight(proposal.target, settings);
    if (!preflight.rollbackReady) {
      return false;
    }

    const observed = this.observedWorkloads.get(proposal.id);
    const safe = this.guard.allows(proposal.target, {
      workloads: settings.workloads,
      currentProcess,
      currentUid: this.currentUid,
      expectedComm: observed?.comm,
      lanPolicyReady: preflight.lanPolicyReady,
    });
    if (!safe) {
      return false;
    }

    // SQLite atomic claim is the sole authorization to invoke adapter.apply().
    const claimed = this.store.claimProposal(id, revision, this.clock.now());
    if (!claimed) {
      return false;
    }
    this.observedWorkloads.delete(id);

    const applied = await this.applyClaimedAction(claimed);
    return applied.succeeded;
  }

  reject(id: string, revision: number): boolean {
    const rejected = this.store.rejectProposal(id, revision, this.clock.now());
    if (rejected) {
      this.observedWorkloads.delete(id);
    }
    return rejected;
  }

  async unlock(actionId: string): Promise<boolean> {
    const action = this.store
      .listActions()
      .find((entry) => entry.id === actionId);
    if (!action) {
      return false;
    }
    if (action.state === "rolled_back") {
      return true;
    }
    if (
      action.state !== "pending" &&
      action.state !== "active" &&
      action.state !== "rolling_back"
    ) {
      return false;
    }
    if (this.inFlightActions.has(action.id)) {
      return false;
    }

    this.inFlightActions.add(action.id);
    try {
      if (action.state === "pending" || action.state === "active") {
        const transitioned = this.store.transitionAction(
          action.id,
          action.state,
          "rolling_back",
          this.clock.now(),
        );
        if (!transitioned) {
          return false;
        }
      }

      return await this.executeRollback({ ...action, state: "rolling_back" });
    } finally {
      this.inFlightActions.delete(action.id);
    }
  }

  private async attemptRollback(action: LockdownAction): Promise<boolean> {
    if (this.inFlightActions.has(action.id)) {
      return false;
    }
    this.inFlightActions.add(action.id);
    try {
      return await this.executeRollback(action);
    } finally {
      this.inFlightActions.delete(action.id);
    }
  }

  private async executeRollback(action: LockdownAction): Promise<boolean> {
    try {
      const result = await this.adapter.rollback(action);
      if (result.state === "absent") {
        return this.store.transitionAction(
          action.id,
          "rolling_back",
          "rolled_back",
          this.clock.now(),
        );
      }
      return false;
    } catch {
      return false;
    }
  }

  async reconcile(): Promise<void> {
    const now = this.clock.now();
    this.store.expireProposals(now);

    const pendingIds = new Set(
      this.store
        .listProposals()
        .filter((proposal) => proposal.status === "pending")
        .map((proposal) => proposal.id),
    );
    for (const id of this.observedWorkloads.keys()) {
      if (!pendingIds.has(id)) {
        this.observedWorkloads.delete(id);
      }
    }

    const actions = this.store.listActions();
    for (const action of actions) {
      if (this.inFlightActions.has(action.id)) {
        continue;
      }

      if (action.state === "pending") {
        let inspected: LockdownInspectResult;
        try {
          inspected = await this.adapter.inspect(action);
        } catch {
          inspected = { state: "unknown" };
        }

        if (this.inFlightActions.has(action.id)) {
          continue;
        }

        if (inspected.state === "active") {
          const updatedAt = this.clock.now();
          const transitioned = this.store.transitionAction(
            action.id,
            "pending",
            "active",
            updatedAt,
            inspected.handle,
          );
          if (transitioned && action.expiresAt <= updatedAt) {
            const moved = this.store.transitionAction(
              action.id,
              "active",
              "rolling_back",
              this.clock.now(),
            );
            if (moved) {
              await this.attemptRollback({
                ...action,
                state: "rolling_back",
                rollbackHandle: inspected.handle ?? action.rollbackHandle,
              });
            }
          }
        } else if (inspected.state === "absent") {
          this.store.transitionAction(
            action.id,
            "pending",
            "failed",
            this.clock.now(),
          );
        } else if (action.expiresAt <= this.clock.now()) {
          const moved = this.store.transitionAction(
            action.id,
            "pending",
            "rolling_back",
            this.clock.now(),
          );
          if (moved) {
            await this.attemptRollback({ ...action, state: "rolling_back" });
          }
        }
        continue;
      }

      if (action.state === "rolling_back") {
        await this.attemptRollback(action);
        continue;
      }

      if (action.state === "active" && action.expiresAt <= this.clock.now()) {
        const moved = this.store.transitionAction(
          action.id,
          "active",
          "rolling_back",
          this.clock.now(),
        );
        if (moved) {
          await this.attemptRollback({ ...action, state: "rolling_back" });
        }
      }
    }
  }

  async helperReady(): Promise<boolean> {
    const preflight = await this.safePreflight({
      kind: "deny_peer_ip",
      ip: "198.51.100.1",
    });
    return preflight.rollbackReady;
  }
}

// ---------------------------------------------------------------------------
// Production adapters and process resolver
// ---------------------------------------------------------------------------

async function defaultSubprocessExec(
  argv: readonly string[],
  options: { timeoutMs?: number; env?: Record<string, string> } = {},
): Promise<SubprocessExecResult> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_ADAPTER_TIMEOUT_MS;
  const baseEnv: Record<string, string> = {
    PATH: TRUSTED_SEARCH_PATH,
    LC_ALL: "C",
    LANG: "C",
  };
  for (const key of USER_RUNTIME_ENV_KEYS) {
    const val = process.env[key];
    if (typeof val === "string" && val.length > 0) {
      baseEnv[key] = val;
    }
  }

  const proc = Bun.spawn([...argv], {
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
    env: options.env ? { ...baseEnv, ...options.env } : baseEnv,
  });

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    try {
      proc.kill("SIGKILL");
    } catch {
      // Ignore kill errors after exit.
    }
  }, timeoutMs);

  try {
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    if (timedOut) {
      return { exitCode: 124, stdout, stderr: `${stderr}\ntimed out`.trim() };
    }
    return { exitCode, stdout, stderr };
  } finally {
    clearTimeout(timer);
  }
}

function clampLeaseSeconds(expiresAt: number, now: number): number {
  const rawSeconds = Math.ceil((expiresAt - now) / 1_000);
  if (!Number.isFinite(rawSeconds) || rawSeconds < MIN_LEASE_SECONDS) {
    return MIN_LEASE_SECONDS;
  }
  if (rawSeconds > MAX_LEASE_SECONDS) {
    return MAX_LEASE_SECONDS;
  }
  return rawSeconds;
}

function assertSafeOpId(id: string): string {
  if (!SAFE_OP_ID_PATTERN.test(id) || id.startsWith("-") || id.includes("..")) {
    throw new Error(`Invalid containment operation ID: ${id}`);
  }
  return id;
}

export function createHelperLockdownAdapter(
  options: HelperLockdownAdapterOptions = {},
): LockdownAdapter {
  const helperPath = options.helperPath ?? DEFAULT_HELPER_PATH;
  const sudoPath = options.sudoPath ?? "/usr/bin/sudo";
  const clock = options.clock ?? { now: () => Date.now() };
  const timeoutMs = options.timeoutMs ?? DEFAULT_ADAPTER_TIMEOUT_MS;
  const exec = options.exec ?? defaultSubprocessExec;

  const invokeHelper = (args: readonly string[]) =>
    exec([sudoPath, "-n", helperPath, ...args], { timeoutMs });

  return {
    async preflight(target: ContainmentTarget): Promise<LockdownPreflightResult> {
      if (target.kind === "pause_workload") {
        return {
          rollbackReady: false,
          reason: "Helper adapter does not manage user workloads.",
        };
      }
      const res = await invokeHelper(["status"]);
      if (res.exitCode !== 0) {
        return {
          rollbackReady: false,
          lanPolicyReady: false,
          reason: res.stderr.trim() || "Privileged lockdown helper unavailable.",
        };
      }
      const lanPolicyReady = /\blan_policy=ready\b/i.test(res.stdout);
      if (target.kind === "isolate_lan_ingress") {
        return {
          rollbackReady: lanPolicyReady,
          lanPolicyReady,
          reason: lanPolicyReady
            ? undefined
            : "Root LAN isolation policy is missing or unverified.",
        };
      }
      return { rollbackReady: true, lanPolicyReady };
    },

    async apply(action: LockdownAction): Promise<LockdownApplyResult> {
      const opId = assertSafeOpId(action.id);
      const ttl = String(clampLeaseSeconds(action.expiresAt, clock.now()));

      if (action.target.kind === "deny_peer_ip") {
        const canonical = canonicalizeIp(action.target.ip);
        if (!canonical || isProtectedIp(canonical)) {
          throw new Error(`Refused protected or malformed IP: ${action.target.ip}`);
        }
        const res = await invokeHelper(["deny-ip", canonical, ttl, opId]);
        if (res.exitCode !== 0) {
          throw new Error(
            res.stderr.trim() || `Helper deny-ip failed with exit ${res.exitCode}`,
          );
        }
        return { handle: `helper:${opId}` };
      }

      if (action.target.kind === "isolate_lan_ingress") {
        const res = await invokeHelper(["isolate-lan", ttl, opId]);
        if (res.exitCode !== 0) {
          throw new Error(
            res.stderr.trim() ||
              `Helper isolate-lan failed with exit ${res.exitCode}`,
          );
        }
        return { handle: `helper:${opId}` };
      }

      throw new Error(`Unsupported target for helper adapter: ${action.target.kind}`);
    },

    async inspect(action: LockdownAction): Promise<LockdownInspectResult> {
      const opId = assertSafeOpId(action.id);
      const res = await invokeHelper(["inspect", opId]);
      if (res.exitCode !== 0) {
        return { state: "unknown" };
      }
      if (/\bactive\b/i.test(res.stdout)) {
        return { state: "active", handle: `helper:${opId}` };
      }
      if (/\babsent\b/i.test(res.stdout)) {
        return { state: "absent" };
      }
      return { state: "unknown" };
    },

    async rollback(action: LockdownAction): Promise<LockdownRollbackResult> {
      const opId = assertSafeOpId(action.id);
      const res = await invokeHelper(["rollback", opId]);
      if (res.exitCode === 0) {
        return { state: "absent" };
      }
      return { state: "unknown" };
    },
  };
}

const SAFE_TIMER_UNIT_PATTERN = /^basho-thaw-[A-Za-z0-9_.-]{1,64}$/;

function safeTimerUnitName(actionId: string): string {
  return `basho-thaw-${actionId.replace(/[^A-Za-z0-9_.-]/g, "_")}`;
}

function parseWorkloadHandle(
  handle: string | undefined,
): { unit: string; timerUnit?: string } | null {
  if (!handle) return null;
  const prefix = handle.startsWith("user-unit:")
    ? "user-unit:"
    : handle.startsWith("workload:")
      ? "workload:"
      : null;
  if (!prefix) return null;
  const rest = handle.slice(prefix.length);
  if (!rest) return null;

  const timerSep = rest.lastIndexOf(":basho-thaw-");
  if (timerSep !== -1) {
    const unit = rest.slice(0, timerSep);
    const timerUnit = rest.slice(timerSep + 1);
    if (isValidSystemdUnitName(unit) && SAFE_TIMER_UNIT_PATTERN.test(timerUnit)) {
      return { unit, timerUnit };
    }
    return null;
  }

  if (isValidSystemdUnitName(rest)) {
    return { unit: rest };
  }
  return null;
}

export function createUserWorkloadLockdownAdapter(
  options: UserWorkloadLockdownAdapterOptions,
): LockdownAdapter {
  const systemctlPath = options.systemctlPath ?? "/usr/bin/systemctl";
  const systemdRunPath = options.systemdRunPath ?? "/usr/bin/systemd-run";
  const clock = options.clock ?? { now: () => Date.now() };
  const timeoutMs = options.timeoutMs ?? DEFAULT_ADAPTER_TIMEOUT_MS;
  const exec = options.exec ?? defaultSubprocessExec;
  const resolveProcess = options.resolveProcess ?? createProcProcessResolver(exec);
  const currentUid = options.currentUid ?? defaultUid();
  const guard = new DeadMansSwitch();

  const resolveUnit = (action: LockdownAction): string | null => {
    if (action.target.kind !== "pause_workload") return null;
    const { workloadId } = action.target;
    const workload = options
      .getWorkloads()
      .find((entry) => entry.id === workloadId);
    if (!workload || !isValidSystemdUnitName(workload.unit)) {
      return null;
    }
    return workload.unit;
  };

  const resolveActionTarget = (
    action: LockdownAction,
  ): { unit: string; timerUnit: string } | null => {
    const opId = assertSafeOpId(action.id);
    const parsed = parseWorkloadHandle(action.rollbackHandle);
    const unit = parsed?.unit ?? resolveUnit(action);
    if (!unit) {
      return null;
    }
    const timerUnit = parsed?.timerUnit ?? safeTimerUnitName(opId);
    return { unit, timerUnit };
  };

  return {
    async preflight(target: ContainmentTarget): Promise<LockdownPreflightResult> {
      if (target.kind !== "pause_workload") {
        return {
          rollbackReady: false,
          reason: "User workload adapter only handles pause_workload targets.",
        };
      }
      const workload = options
        .getWorkloads()
        .find((entry) => entry.id === target.workloadId);
      if (!workload || !isValidSystemdUnitName(workload.unit)) {
        return {
          rollbackReady: false,
          reason: `Workload ${target.workloadId} is not enrolled with a valid user unit.`,
        };
      }
      const [ctl, run] = await Promise.all([
        exec([systemctlPath, "--user", "show", "-p", "FreezerState", "--value", workload.unit], {
          timeoutMs,
        }),
        exec([systemdRunPath, "--version"], { timeoutMs }),
      ]);
      const ready = ctl.exitCode === 0 && run.exitCode === 0;
      return {
        rollbackReady: ready,
        reason: ready
          ? undefined
          : ctl.stderr.trim() ||
            run.stderr.trim() ||
            "User systemd freeze/timer support unavailable.",
      };
    },

    async apply(action: LockdownAction): Promise<LockdownApplyResult> {
      const opId = assertSafeOpId(action.id);
      if (action.target.kind !== "pause_workload") {
        throw new Error(`Unsupported target for user workload adapter: ${action.target.kind}`);
      }
      const unit = resolveUnit(action);
      if (!unit) {
        throw new Error(`Enrolled unit not found for action ${opId}`);
      }

      // Re-verify live PID identity and enrolled user-unit ownership immediately
      // before arming the thaw timer or freezing the unit.
      let liveProcess: ProcessIdentity | null = null;
      try {
        liveProcess = await resolveProcess(action.target.pid);
      } catch {
        liveProcess = null;
      }
      const identityValid = guard.allows(action.target, {
        workloads: options.getWorkloads(),
        currentProcess: liveProcess,
        currentUid,
      });
      if (!identityValid) {
        throw new Error(
          `Workload process identity or unit ownership drifted before freeze for action ${opId}`,
        );
      }

      const ttl = clampLeaseSeconds(action.expiresAt, clock.now());
      const timerUnit = safeTimerUnitName(opId);

      // Arm automatic thaw timer BEFORE freezing the workload unit.
      const timerRes = await exec(
        [
          systemdRunPath,
          "--user",
          `--unit=${timerUnit}`,
          `--on-active=${ttl}s`,
          "--timer-property=AccuracySec=1s",
          "--",
          systemctlPath,
          "--user",
          "thaw",
          unit,
        ],
        { timeoutMs },
      );
      if (timerRes.exitCode !== 0) {
        throw new Error(
          timerRes.stderr.trim() ||
            `Failed to arm user thaw timer (exit ${timerRes.exitCode})`,
        );
      }

      const freezeRes = await exec([systemctlPath, "--user", "freeze", unit], {
        timeoutMs,
      });
      if (freezeRes.exitCode !== 0) {
        // On freeze timeout (exit 124), keep the thaw timer armed so reconcile() can settle it.
        // On other failures, stop the thaw timer ONLY if FreezerState confirms the unit is running.
        if (freezeRes.exitCode !== 124) {
          const stateRes = await exec(
            [systemctlPath, "--user", "show", "-p", "FreezerState", "--value", unit],
            { timeoutMs },
          ).catch(() => ({ exitCode: 1, stdout: "", stderr: "" }));
          const freezerState =
            stateRes.exitCode === 0 ? stateRes.stdout.trim().toLowerCase() : "";
          if (freezerState === "running") {
            await exec([systemctlPath, "--user", "stop", `${timerUnit}.timer`], {
              timeoutMs,
            }).catch(() => {});
          }
        }
        throw new Error(
          freezeRes.stderr.trim() ||
            `Failed to freeze user unit ${unit} (exit ${freezeRes.exitCode})`,
        );
      }

      return { handle: `user-unit:${unit}:${timerUnit}` };
    },

    async inspect(action: LockdownAction): Promise<LockdownInspectResult> {
      const resolved = resolveActionTarget(action);
      if (!resolved) {
        return { state: "unknown" };
      }
      const { unit, timerUnit } = resolved;

      const [timerRes, freezerRes] = await Promise.all([
        exec([systemctlPath, "--user", "is-active", `${timerUnit}.timer`], {
          timeoutMs,
        }),
        exec([systemctlPath, "--user", "show", "-p", "FreezerState", "--value", unit], {
          timeoutMs,
        }),
      ]);

      const timerOut = timerRes.stdout.trim().toLowerCase();
      let timerState: "active" | "inactive" | "unknown" = "unknown";
      if (
        timerRes.exitCode === 0 &&
        (timerOut === "" ||
          timerOut === "active" ||
          timerOut === "activating" ||
          timerOut === "reloading")
      ) {
        timerState = "active";
      } else if (
        timerRes.exitCode === 3 ||
        timerRes.exitCode === 4 ||
        timerOut === "inactive" ||
        timerOut === "dead" ||
        timerOut === "failed" ||
        timerOut === "deactivating"
      ) {
        timerState = "inactive";
      }

      let freezerState: "frozen" | "running" | "unknown" = "unknown";
      if (freezerRes.exitCode === 0) {
        const value = freezerRes.stdout.trim().toLowerCase();
        if (value === "frozen" || value === "freezing") {
          freezerState = "frozen";
        } else if (value === "running") {
          freezerState = "running";
        }
      }

      if (freezerState === "running") {
        return { state: "absent" };
      }
      if (timerState === "active" && freezerState === "frozen") {
        return {
          state: "active",
          handle: action.rollbackHandle ?? `user-unit:${unit}`,
        };
      }
      return { state: "unknown" };
    },

    async rollback(action: LockdownAction): Promise<LockdownRollbackResult> {
      const resolved = resolveActionTarget(action);
      if (!resolved) {
        return { state: "unknown" };
      }
      const { unit, timerUnit } = resolved;

      const thawRes = await exec([systemctlPath, "--user", "thaw", unit], {
        timeoutMs,
      });
      await exec([systemctlPath, "--user", "stop", `${timerUnit}.timer`], {
        timeoutMs,
      }).catch(() => {});

      if (thawRes.exitCode === 0) {
        return { state: "absent" };
      }
      return { state: "unknown" };
    },
  };
}

export function createCompositeLockdownAdapter(
  options: CompositeLockdownAdapterOptions = {},
): LockdownAdapter {
  const helper =
    options.helper ?? createHelperLockdownAdapter({ clock: options.clock });
  const workload =
    options.workload ??
    createUserWorkloadLockdownAdapter({
      getWorkloads: options.getWorkloads ?? (() => []),
      clock: options.clock,
      resolveProcess: options.resolveProcess,
      currentUid: options.currentUid,
    });

  const pick = (target: ContainmentTarget): LockdownAdapter =>
    target.kind === "pause_workload" ? workload : helper;

  return {
    preflight(target: ContainmentTarget): Promise<LockdownPreflightResult> {
      return pick(target).preflight(target);
    },
    apply(action: LockdownAction): Promise<LockdownApplyResult> {
      return pick(action.target).apply(action);
    },
    inspect(action: LockdownAction): Promise<LockdownInspectResult> {
      return pick(action.target).inspect(action);
    },
    rollback(action: LockdownAction): Promise<LockdownRollbackResult> {
      return pick(action.target).rollback(action);
    },
  };
}

export interface ProcProcessResolverOptions {
  exec?: SubprocessExecutor;
  procRoot?: string;
  clkTck?: number;
}

const DEFAULT_LINUX_CLK_TCK = 100;

export function createProcProcessResolver(
  execOrOptions: SubprocessExecutor | ProcProcessResolverOptions = defaultSubprocessExec,
): ResolveProcess {
  const exec =
    typeof execOrOptions === "function"
      ? execOrOptions
      : (execOrOptions.exec ?? defaultSubprocessExec);
  const procRoot =
    typeof execOrOptions === "function"
      ? "/proc"
      : (execOrOptions.procRoot ?? "/proc");
  const injectedClkTck =
    typeof execOrOptions === "function" ? undefined : execOrOptions.clkTck;

  let cachedClkTck: number | undefined =
    typeof injectedClkTck === "number" &&
    Number.isFinite(injectedClkTck) &&
    injectedClkTck > 0
      ? injectedClkTck
      : undefined;

  const getClkTck = async (): Promise<number> => {
    if (cachedClkTck !== undefined) {
      return cachedClkTck;
    }
    try {
      const res = await exec(["/usr/bin/getconf", "CLK_TCK"], {
        timeoutMs: 2_000,
      });
      if (res.exitCode === 0) {
        const parsed = Number(res.stdout.trim());
        if (Number.isSafeInteger(parsed) && parsed > 0) {
          cachedClkTck = parsed;
          return parsed;
        }
      }
    } catch {
      // Fall back to standard Linux USER_HZ (100).
    }
    cachedClkTck = DEFAULT_LINUX_CLK_TCK;
    return cachedClkTck;
  };

  return async (pid: number): Promise<ProcessIdentity | null> => {
    if (!Number.isSafeInteger(pid) || pid <= 0) {
      return null;
    }

    try {
      const [procStatRaw, statRaw, statusRaw, commRaw, psRes, clkTck] =
        await Promise.all([
          readFile(`${procRoot}/stat`, "utf8"),
          readFile(`${procRoot}/${pid}/stat`, "utf8"),
          readFile(`${procRoot}/${pid}/status`, "utf8"),
          readFile(`${procRoot}/${pid}/comm`, "utf8"),
          exec(["/usr/bin/ps", "-o", "unit=,uunit=", "-p", String(pid)], {
            timeoutMs: 3_000,
          }).catch(() => ({ exitCode: 1, stdout: "", stderr: "" })),
          getClkTck(),
        ]);

      const btimeMatch = /^btime\s+(\d+)/m.exec(procStatRaw);
      if (!btimeMatch) return null;
      const btimeSeconds = Number(btimeMatch[1]);
      if (!Number.isSafeInteger(btimeSeconds) || btimeSeconds <= 0) {
        return null;
      }

      const closeParen = statRaw.lastIndexOf(")");
      if (closeParen === -1) return null;
      const fields = statRaw.slice(closeParen + 2).trim().split(/\s+/);
      // In /proc/<pid>/stat, field 22 (1-indexed) is starttime in clock ticks since boot;
      // after comm (field 2), index 19.
      const startTicks = Number(fields[19]);
      if (!Number.isSafeInteger(startTicks) || startTicks < 0) {
        return null;
      }

      // Convert boot time + starttime ticks to Unix epoch milliseconds, preserving
      // sub-second tick precision so comparisons with events.ts/collector.ts
      // (now - etimes * 1000) stay within PROCESS_START_TIME_TOLERANCE_MS.
      const startedAt = Math.round((btimeSeconds + startTicks / clkTck) * 1_000);
      if (!Number.isSafeInteger(startedAt) || startedAt <= 0) {
        return null;
      }

      const uidMatch = /^Uid:\s*(\d+)/m.exec(statusRaw);
      if (!uidMatch) return null;
      const uid = Number(uidMatch[1]);
      if (!Number.isSafeInteger(uid) || uid < 0) return null;

      let unit: string | undefined;
      let uunit: string | undefined;
      if (psRes.exitCode === 0) {
        const parts = psRes.stdout.trim().split(/\s+/);
        unit = normalizeUnitField(parts[0]);
        uunit = normalizeUnitField(parts[1]);
      }

      return {
        pid,
        uid,
        startedAt,
        comm: commRaw.trim(),
        ...(unit ? { unit } : {}),
        ...(uunit ? { uunit } : {}),
      };
    } catch {
      return null;
    }
  };
}
