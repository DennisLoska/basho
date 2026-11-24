import { createHash } from "node:crypto";
import { parseListeners } from "./collector";
import { isValidJournalCursor, isValidSystemdUnitName } from "./runner";
import type { SecurityStoreContract } from "./store";
import type {
  Clock,
  CommandRunner,
  Corroboration,
  Coverage,
  EnrolledWorkload,
  ExposureEntry,
  Listener,
  SecurityAlert,
  SecurityEvent,
} from "./types";

const JOURNAL_PAGE_LIMIT = 200;
const BURST_WINDOW_MS = 300_000;
const SSH_BURST_THRESHOLD = 5;
const SSH_DEDUPE_WINDOW_MS = 15_000;
const MAX_SSH_DEDUPE_ENTRIES = 1_024;

const SYSTEMD_UNIT_SUFFIXES = [
  ".service",
  ".socket",
  ".device",
  ".mount",
  ".automount",
  ".swap",
  ".target",
  ".path",
  ".timer",
  ".slice",
  ".scope",
] as const;

const SAFE_PROC_NAME_PATTERN = /^[A-Za-z0-9._-]{1,32}$/;
const SAFE_USER_NAME_PATTERN = /^[A-Za-z0-9._-]{1,32}$/;
const SAFE_PROTO_PATTERN = /^[A-Za-z0-9]{1,16}$/;
const PACMAN_ACTION_PATTERN =
  /^(?:\[ALPM\]\s+)?(installed|upgraded|removed|downgraded)\s+([A-Za-z0-9@._+-]{1,128})(?:\s|$)/;

const HIGH_SIGNAL_JOURNAL_RULES = new Set([
  "oom_kill",
  "sudo_escalation",
  "polkit_escalation",
  "unit_failed",
]);

const SYSTEM_ANOMALY_RULES = new Set(["oom_kill", "unit_failed"]);

export interface MonitorResult {
  alerts: SecurityAlert[];
  corroboration: Corroboration[];
  coverage: Coverage;
}

export interface EventMonitorDeps {
  store: SecurityStoreContract;
  runner: CommandRunner;
  clock: Clock;
  workloads?: readonly EnrolledWorkload[];
}

export interface ParsedJournalRecord {
  cursor: string;
  event?: SecurityEvent;
}

// ---------------------------------------------------------------------------
// IP parsing, RFC 5952 canonicalization, and range classification
// ---------------------------------------------------------------------------

function parseIpv4ToUint32(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    value = (value << 8) | octet;
  }
  return value >>> 0;
}

function uint32ToIpv4(value: number): string {
  return [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ].join(".");
}

function parseIpv6Groups(raw: string): number[] | null {
  const trimmed = raw.trim().toLowerCase();
  if (!trimmed || !trimmed.includes(":")) return null;

  const parseSegment = (segment: string): number[] | null => {
    if (segment.length === 0) return [];
    const tokens = segment.split(":");
    const groups: number[] = [];
    for (let i = 0; i < tokens.length; i += 1) {
      const tok = tokens[i]!;
      if (tok.includes(".")) {
        if (i !== tokens.length - 1) return null;
        const v4 = parseIpv4ToUint32(tok);
        if (v4 === null) return null;
        groups.push((v4 >>> 16) & 0xffff, v4 & 0xffff);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(tok)) return null;
        groups.push(Number.parseInt(tok, 16));
      }
    }
    return groups;
  };

  const doubleColonParts = trimmed.split("::");
  if (doubleColonParts.length > 2) return null;

  if (doubleColonParts.length === 2) {
    const left = parseSegment(doubleColonParts[0]!);
    const right = parseSegment(doubleColonParts[1]!);
    if (!left || !right) return null;
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    return [...left, ...Array<number>(missing).fill(0), ...right];
  }

  const parsed = parseSegment(trimmed);
  if (!parsed || parsed.length !== 8) return null;
  return parsed;
}

function formatCanonicalIpv6(groups: readonly number[]): string {
  let bestStart = -1;
  let bestLen = 0;
  let runStart = -1;
  let runLen = 0;

  for (let i = 0; i < groups.length; i += 1) {
    if (groups[i] === 0) {
      if (runStart === -1) {
        runStart = i;
        runLen = 1;
      } else {
        runLen += 1;
      }
      if (runLen > bestLen) {
        bestStart = runStart;
        bestLen = runLen;
      }
    } else {
      runStart = -1;
      runLen = 0;
    }
  }

  // RFC 5952 section 4.2.2: do not compress a single zero field.
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

function canonicalizeIp(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 128) return null;

  const zoneIdx = trimmed.indexOf("%");
  let addrPart = trimmed;
  if (zoneIdx !== -1) {
    const zone = trimmed.slice(zoneIdx + 1);
    if (!/^[A-Za-z0-9_.-]{1,32}$/.test(zone)) return null;
    addrPart = trimmed.slice(0, zoneIdx);
  }

  const v4 = parseIpv4ToUint32(addrPart);
  if (v4 !== null) {
    return uint32ToIpv4(v4);
  }

  const groups = parseIpv6Groups(addrPart);
  if (!groups) return null;

  // Unwrap IPv4-mapped IPv6 addresses (::ffff:0:0/96) to canonical IPv4.
  if (
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0xffff
  ) {
    const mappedV4 = (((groups[6]! << 16) | groups[7]!) >>> 0);
    return uint32ToIpv4(mappedV4);
  }

  return formatCanonicalIpv6(groups);
}

function ipv6GroupsToBigInt(groups: readonly number[]): bigint {
  let value = 0n;
  for (const g of groups) {
    value = (value << 16n) | BigInt(g);
  }
  return value;
}

function isLoopbackIp(canonicalIp: string): boolean {
  const v4 = parseIpv4ToUint32(canonicalIp);
  if (v4 !== null) {
    return ((v4 >>> 24) & 0xff) === 127;
  }
  const groups = parseIpv6Groups(canonicalIp);
  if (groups) {
    return ipv6GroupsToBigInt(groups) === 1n;
  }
  return false;
}

function isFirewallNoiseMulticastIp(canonicalIp: string): boolean {
  return canonicalIp === "224.0.0.1" || canonicalIp === "ff02::1";
}

function isTailnetIp(canonicalIp: string): boolean {
  const v4 = parseIpv4ToUint32(canonicalIp);
  if (v4 !== null) {
    // Tailscale CGNAT: 100.64.0.0/10
    return ((v4 & 0xffc00000) >>> 0) === 0x64400000;
  }
  const groups = parseIpv6Groups(canonicalIp);
  if (groups) {
    // Tailscale ULA: fd7a:115c:a1e0::/48
    return groups[0] === 0xfd7a && groups[1] === 0x115c && groups[2] === 0xa1e0;
  }
  return false;
}

function isUnspecifiedIp(canonicalIp: string): boolean {
  if (canonicalIp === "0.0.0.0" || canonicalIp === "::") return true;
  const v4 = parseIpv4ToUint32(canonicalIp);
  if (v4 !== null) return v4 === 0;
  const groups = parseIpv6Groups(canonicalIp);
  if (groups) return ipv6GroupsToBigInt(groups) === 0n;
  return false;
}

function isProtectedPeerIp(canonicalIp: string): boolean {
  return (
    isLoopbackIp(canonicalIp) ||
    isTailnetIp(canonicalIp) ||
    isUnspecifiedIp(canonicalIp)
  );
}

function isWildcardAddress(address: string): boolean {
  if (address === "*") return true;
  const canonical = canonicalizeIp(address);
  return canonical === "0.0.0.0" || canonical === "::";
}

function isLoopbackListener(listener: Listener): boolean {
  if (listener.address === "*") return false;
  const canonical = canonicalizeIp(listener.address);
  return canonical !== null && isLoopbackIp(canonical);
}

// ---------------------------------------------------------------------------
// Journal record parsing
// ---------------------------------------------------------------------------

function deterministicJournalEventId(cursor: string): string {
  const digest = createHash("sha256").update(cursor).digest("hex").slice(0, 24);
  return `journal:${digest}`;
}

function deterministicJournalGapId(previousCursor: string, nextCursor: string): string {
  const digest = createHash("sha256")
    .update(`${previousCursor}\0${nextCursor}`)
    .digest("hex")
    .slice(0, 24);
  return `journal:cursor_gap:${digest}`;
}

function deterministicJournalOversizedId(cursor: string): string {
  const digest = createHash("sha256")
    .update(`oversized\0${cursor}`)
    .digest("hex")
    .slice(0, 24);
  return `journal:oversized_skipped:${digest}`;
}

function deterministicSocketEventId(
  nowMs: number,
  transition: "opened" | "closed",
  key: string,
): string {
  const digest = createHash("sha256")
    .update(`${nowMs}\0${transition}\0${key}`)
    .digest("hex")
    .slice(0, 24);
  return `socket:${nowMs}:${transition}:${digest}`;
}

interface SshPeer {
  ip: string;
  port?: number;
}

interface SshDedupeMeta {
  subtype: "failed_auth" | "companion";
  peerKey?: string;
}

interface ClassifiedJournalEvent {
  event: SecurityEvent;
  sshMeta?: SshDedupeMeta;
}

interface InternalParsedJournalRecord extends ParsedJournalRecord {
  sshMeta?: SshDedupeMeta;
}

function parseRealtimeTimestampMs(raw: unknown): number | null {
  if (typeof raw === "string") {
    if (!/^\d{1,20}$/.test(raw)) return null;
    const ms = Number(BigInt(raw) / 1000n);
    return Number.isSafeInteger(ms) && ms >= 0 ? ms : null;
  }
  if (typeof raw === "number" && Number.isSafeInteger(raw) && raw >= 0) {
    const ms = Math.floor(raw / 1000);
    return Number.isSafeInteger(ms) && ms >= 0 ? ms : null;
  }
  return null;
}

function extractSshPeer(message: string, isAuthenticatingClose: boolean): SshPeer | null {
  const patternsWithPort = isAuthenticatingClose
    ? [/\s([0-9a-fA-F:.]+(?:%[A-Za-z0-9_.-]{1,32})?)\s+port\s+(\d+)\b/g]
    : [/\bfrom\s+([0-9a-fA-F:.]+(?:%[A-Za-z0-9_.-]{1,32})?)\s+port\s+(\d+)\b/g];

  for (const pattern of patternsWithPort) {
    let lastCandidate: SshPeer | null = null;
    for (const match of message.matchAll(pattern)) {
      const candidate = match[1];
      const portRaw = match[2];
      if (!candidate) continue;
      const canonical = canonicalizeIp(candidate);
      if (canonical !== null) {
        const parsedPort = portRaw ? Number(portRaw) : NaN;
        const port =
          Number.isInteger(parsedPort) && parsedPort >= 0 && parsedPort <= 65535
            ? parsedPort
            : undefined;
        lastCandidate = port !== undefined ? { ip: canonical, port } : { ip: canonical };
      }
    }
    if (lastCandidate !== null) {
      return lastCandidate;
    }
  }

  const fallbackPattern = /\bfrom\s+([0-9a-fA-F:.]+(?:%[A-Za-z0-9_.-]{1,32})?)(?:\s|$)/g;
  let lastIp: string | null = null;
  for (const match of message.matchAll(fallbackPattern)) {
    const candidate = match[1];
    if (!candidate) continue;
    const canonical = canonicalizeIp(candidate);
    if (canonical !== null) {
      lastIp = canonical;
    }
  }
  return lastIp !== null ? { ip: lastIp } : null;
}

function parseUfwBlockEvent(
  id: string,
  timestampMs: number,
  message: string,
): SecurityEvent | null {
  const markerIndex = message.indexOf("[UFW BLOCK]");
  if (markerIndex === -1) return null;

  const rest = message.slice(markerIndex + "[UFW BLOCK]".length);
  let srcRaw: string | undefined;
  let dstRaw: string | undefined;
  let dptRaw: string | undefined;
  let protoRaw: string | undefined;

  for (const token of rest.split(/\s+/)) {
    if (!token) continue;
    const eqIdx = token.indexOf("=");
    if (eqIdx <= 0) continue;
    const key = token.slice(0, eqIdx);
    const val = token.slice(eqIdx + 1);
    if (!val) continue;
    if (key === "SRC" && srcRaw === undefined) srcRaw = val;
    else if (key === "DST" && dstRaw === undefined) dstRaw = val;
    else if (key === "DPT" && dptRaw === undefined) dptRaw = val;
    else if (key === "PROTO" && protoRaw === undefined) protoRaw = val;
  }

  if (!srcRaw || !dstRaw) return null;
  const srcIp = canonicalizeIp(srcRaw);
  const dstIp = canonicalizeIp(dstRaw);
  if (!srcIp || !dstIp) return null;

  const proto =
    protoRaw && SAFE_PROTO_PATTERN.test(protoRaw) ? protoRaw.toUpperCase() : "UNKNOWN";

  let port: number | null = null;
  if (dptRaw && /^\d{1,5}$/.test(dptRaw)) {
    const parsedPort = Number(dptRaw);
    if (Number.isInteger(parsedPort) && parsedPort >= 1 && parsedPort <= 65535) {
      port = parsedPort;
    }
  }

  const isNoise =
    isFirewallNoiseMulticastIp(dstIp) || isLoopbackIp(srcIp) || isLoopbackIp(dstIp);
  const summary =
    port !== null
      ? `UFW blocked ${proto} traffic from ${srcIp} to port ${port}`
      : `UFW blocked ${proto} traffic from ${srcIp}`;

  return {
    id,
    source: "journal",
    category: "firewall",
    severity: "info",
    rule: "ufw_block",
    target: srcIp,
    firstAt: timestampMs,
    lastAt: timestampMs,
    count: 1,
    isNoise,
    summary,
  };
}

function extractFailedUnitName(
  record: Record<string, unknown>,
  message: string,
): string {
  const candidates: unknown[] = [record.UNIT, record._SYSTEMD_UNIT];
  for (const candidate of candidates) {
    if (
      typeof candidate === "string" &&
      candidate !== "init.scope" &&
      isValidSystemdUnitName(candidate)
    ) {
      return candidate;
    }
  }

  const colonIdx = message.indexOf(":");
  if (colonIdx > 0) {
    const prefix = message.slice(0, colonIdx).trim();
    if (isValidSystemdUnitName(prefix)) {
      return prefix;
    }
  }

  return "unknown.service";
}

function verifyTrustedUidRoot(record: Record<string, unknown>): boolean {
  if (record._UID === undefined) return true;
  return record._UID === "0";
}

function verifyTrustedSystemUid(record: Record<string, unknown>): boolean {
  if (record._UID === undefined) return true;
  if (typeof record._UID !== "string" || !/^(?:0|[1-9]\d{0,9})$/.test(record._UID)) {
    return false;
  }
  const uid = Number(record._UID);
  return Number.isInteger(uid) && uid >= 0 && uid < 1000;
}

function verifyTrustedComm(
  record: Record<string, unknown>,
  allowedComms: readonly string[],
): boolean {
  if (record._COMM === undefined) return true;
  if (typeof record._COMM !== "string") return false;
  if (record._COMM === "logger") return false;
  return allowedComms.includes(record._COMM);
}

function hasSystemdUserUnit(record: Record<string, unknown>): boolean {
  return record._SYSTEMD_USER_UNIT !== undefined;
}

const SSHD_SYSTEMD_UNIT_PATTERN = /^(?:sshd|ssh)(?:@[^/]+)?\.service$/;

function classifyJournalMessage(
  record: Record<string, unknown>,
  cursor: string,
  timestampMs: number,
  message: string,
): ClassifiedJournalEvent | undefined {
  const identifier =
    typeof record.SYSLOG_IDENTIFIER === "string" ? record.SYSLOG_IDENTIFIER : "";
  const transport = typeof record._TRANSPORT === "string" ? record._TRANSPORT : "";
  const id = deterministicJournalEventId(cursor);

  // 1. Kernel events: UFW blocks and OOM kills (require unforgeable _TRANSPORT === "kernel")
  if (transport === "kernel") {
    if (
      !verifyTrustedUidRoot(record) ||
      record._COMM !== undefined ||
      hasSystemdUserUnit(record)
    ) {
      return undefined;
    }
    if (message.includes("[UFW BLOCK]")) {
      const event = parseUfwBlockEvent(id, timestampMs, message);
      return event ? { event } : undefined;
    }
    if (/\bOut of memory\b/i.test(message) || /\bKilled process\b/.test(message)) {
      const procMatch = /Killed process \d+ \(([^)]+)\)/.exec(message);
      const rawProc = procMatch?.[1]?.trim() ?? "";
      const safeProc = SAFE_PROC_NAME_PATTERN.test(rawProc) ? rawProc : null;
      return {
        event: {
          id,
          source: "journal",
          category: "units",
          severity: "critical",
          rule: "oom_kill",
          target: safeProc ?? "kernel",
          firstAt: timestampMs,
          lastAt: timestampMs,
          count: 1,
          isNoise: false,
          summary: safeProc
            ? `Kernel OOM killer terminated process ${safeProc}`
            : "Kernel OOM killer terminated a process",
        },
      };
    }
    return undefined;
  }

  // 2. SSH authentication failures
  if (identifier === "sshd" || identifier === "sshd-session") {
    if (
      !verifyTrustedUidRoot(record) ||
      !verifyTrustedComm(record, ["sshd", "sshd-session"]) ||
      hasSystemdUserUnit(record)
    ) {
      return undefined;
    }
    if (
      record._SYSTEMD_UNIT !== undefined &&
      (typeof record._SYSTEMD_UNIT !== "string" ||
        !SSHD_SYSTEMD_UNIT_PATTERN.test(record._SYSTEMD_UNIT))
    ) {
      return undefined;
    }

    const isFailedAuth =
      message.includes("Failed password") || message.includes("Failed publickey");
    const isAuthClose = message.includes("Connection closed by authenticating user");
    const isCompanion = !isFailedAuth && (isAuthClose || message.includes("Invalid user"));
    if (isFailedAuth || isCompanion) {
      const peer = extractSshPeer(message, isAuthClose);
      if (peer !== null) {
        return {
          event: {
            id,
            source: "journal",
            category: "auth",
            severity: "warning",
            rule: "ssh_auth_failure",
            target: peer.ip,
            firstAt: timestampMs,
            lastAt: timestampMs,
            count: 1,
            isNoise: false,
            summary: `SSH authentication failure from ${peer.ip}`,
          },
          sshMeta: {
            subtype: isFailedAuth ? "failed_auth" : "companion",
            ...(peer.port !== undefined ? { peerKey: `${peer.ip}:${peer.port}` } : {}),
          },
        };
      }
    }
    return undefined;
  }

  // 3. Privilege escalations: sudo & polkitd
  if (identifier === "sudo") {
    if (!verifyTrustedComm(record, ["sudo"])) {
      return undefined;
    }
    if (
      record._EXE !== undefined &&
      record._EXE !== "/usr/bin/sudo" &&
      record._EXE !== "/bin/sudo"
    ) {
      return undefined;
    }
    const isCommand = /\bCOMMAND=/.test(message);
    const isAuthError =
      /authentication failure|incorrect password|user NOT in sudoers/i.test(message);
    if (isCommand || isAuthError) {
      const commandIdx = message.indexOf("COMMAND=");
      const headerPart = commandIdx >= 0 ? message.slice(0, commandIdx) : message;
      const userMatch = /\bUSER=([A-Za-z0-9._-]{1,32})\b/.exec(headerPart);
      const rawTargetUser = userMatch?.[1] ?? "root";
      const targetUser = SAFE_USER_NAME_PATTERN.test(rawTargetUser)
        ? rawTargetUser
        : "root";
      return {
        event: {
          id,
          source: "journal",
          category: "auth",
          severity: "warning",
          rule: "sudo_escalation",
          target: `sudo:${targetUser}`,
          firstAt: timestampMs,
          lastAt: timestampMs,
          count: 1,
          isNoise: false,
          summary: isAuthError
            ? `Sudo authentication failure targeting ${targetUser}`
            : `Sudo privilege escalation targeting ${targetUser}`,
        },
      };
    }
    return undefined;
  }

  if (identifier === "polkitd") {
    if (
      !verifyTrustedSystemUid(record) ||
      !verifyTrustedComm(record, ["polkitd"]) ||
      hasSystemdUserUnit(record)
    ) {
      return undefined;
    }
    if (
      record._SYSTEMD_UNIT !== undefined &&
      record._SYSTEMD_UNIT !== "polkit.service" &&
      record._SYSTEMD_UNIT !== "polkitd.service"
    ) {
      return undefined;
    }
    if (
      record._EXE !== undefined &&
      (typeof record._EXE !== "string" ||
        !record._EXE.startsWith("/") ||
        !record._EXE.endsWith("/polkitd"))
    ) {
      return undefined;
    }
    if (/\b(?:authenticated|authorization)\b/i.test(message)) {
      return {
        event: {
          id,
          source: "journal",
          category: "auth",
          severity: "warning",
          rule: "polkit_escalation",
          target: "polkitd",
          firstAt: timestampMs,
          lastAt: timestampMs,
          count: 1,
          isNoise: false,
          summary: "Polkit privilege authorization event recorded",
        },
      };
    }
    return undefined;
  }

  // 4. Failed systemd units (system manager only)
  if (identifier === "systemd") {
    if (
      !verifyTrustedUidRoot(record) ||
      !verifyTrustedComm(record, ["systemd"]) ||
      hasSystemdUserUnit(record)
    ) {
      return undefined;
    }
    if (
      record._SYSTEMD_UNIT !== undefined &&
      (typeof record._SYSTEMD_UNIT !== "string" ||
        !isValidSystemdUnitName(record._SYSTEMD_UNIT))
    ) {
      return undefined;
    }
    if (
      /\bFailed with result\b|\bFailed to start\b|\bEntered failed state\b/i.test(message)
    ) {
      const unitName = extractFailedUnitName(record, message);
      return {
        event: {
          id,
          source: "journal",
          category: "units",
          severity: "warning",
          rule: "unit_failed",
          target: unitName,
          firstAt: timestampMs,
          lastAt: timestampMs,
          count: 1,
          isNoise: false,
          summary: `Systemd unit ${unitName} entered failed state`,
        },
      };
    }
    return undefined;
  }

  // 5. Pacman package changes
  if (identifier === "pacman" || identifier === "alpm") {
    if (!verifyTrustedUidRoot(record) || !verifyTrustedComm(record, ["pacman"])) {
      return undefined;
    }
    const match = PACMAN_ACTION_PATTERN.exec(message);
    if (match) {
      const action = match[1]!;
      const pkg = match[2]!;
      return {
        event: {
          id,
          source: "journal",
          category: "packages",
          severity: "info",
          rule: `pacman_${action}`,
          target: pkg,
          firstAt: timestampMs,
          lastAt: timestampMs,
          count: 1,
          isNoise: false,
          summary: `Package ${pkg} ${action}`,
        },
      };
    }
    return undefined;
  }

  return undefined;
}

function parseJournalRecordInternal(line: string): InternalParsedJournalRecord | null {
  if (typeof line !== "string" || line.length === 0) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return null;
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return null;
  }

  const record = parsed as Record<string, unknown>;
  const cursor = record.__CURSOR;
  if (typeof cursor !== "string" || !isValidJournalCursor(cursor)) {
    return null;
  }

  const rawTs = record.__REALTIME_TIMESTAMP;
  const timestampMs = rawTs === undefined ? null : parseRealtimeTimestampMs(rawTs);

  const message = typeof record.MESSAGE === "string" ? record.MESSAGE : "";
  if (!message || timestampMs === null) {
    return { cursor };
  }

  const classified = classifyJournalMessage(record, cursor, timestampMs, message);
  if (!classified) {
    return { cursor };
  }
  return classified.sshMeta
    ? { cursor, event: classified.event, sshMeta: classified.sshMeta }
    : { cursor, event: classified.event };
}

export function parseJournalRecord(line: string): ParsedJournalRecord | null {
  const parsed = parseJournalRecordInternal(line);
  if (parsed === null) return null;
  return parsed.event ? { cursor: parsed.cursor, event: parsed.event } : { cursor: parsed.cursor };
}

// ---------------------------------------------------------------------------
// Listener keying & workload identity matching
// ---------------------------------------------------------------------------

function listenerKey(listener: Listener): string {
  const addr =
    listener.address === "*" ? "*" : (canonicalizeIp(listener.address) ?? listener.address);
  return `${listener.family}|${listener.protocol}|${addr}|${listener.interfaceName ?? ""}|${listener.port}`;
}

function unitStem(unit: string): string {
  let base = unit.trim();
  for (const suffix of SYSTEMD_UNIT_SUFFIXES) {
    if (base.endsWith(suffix)) {
      base = base.slice(0, -suffix.length);
      break;
    }
  }
  const atIdx = base.indexOf("@");
  if (atIdx > 0) {
    base = base.slice(0, atIdx);
  }
  return base.toLowerCase();
}

function matchEnrolledWorkload(
  listener: Listener,
  candidate: ParsedProcessRow | undefined,
  workloads: readonly EnrolledWorkload[],
): EnrolledWorkload | null {
  if (
    workloads.length === 0 ||
    listener.pid === undefined ||
    !Number.isInteger(listener.pid) ||
    listener.pid <= 0 ||
    !candidate
  ) {
    return null;
  }

  if (candidate.hasUnitMetadata) {
    const unitMatches = workloads.filter((workload) => {
      const expectedUnit = workload.unit.trim();
      return candidate.uunit === expectedUnit || candidate.unit === expectedUnit;
    });
    if (unitMatches.length === 1) {
      return unitMatches[0]!;
    }
    return null;
  }

  const proc = (listener.process ?? candidate.comm).trim().toLowerCase();
  if (!proc) return null;

  const matches: EnrolledWorkload[] = [];
  for (const workload of workloads) {
    const names = new Set<string>();
    const idNorm = workload.id.trim().toLowerCase();
    if (idNorm) names.add(idNorm);
    const nameNorm = workload.name?.trim().toLowerCase();
    if (nameNorm) names.add(nameNorm);
    const stem = unitStem(workload.unit);
    if (stem) names.add(stem);

    if (!names.has(proc)) {
      continue;
    }

    matches.push(workload);
  }

  if (matches.length === 1) {
    return matches[0]!;
  }
  if (matches.length > 1) {
    const portMatches = matches.filter(
      (workload) => workload.ports !== undefined && workload.ports.includes(listener.port),
    );
    if (portMatches.length === 1) {
      return portMatches[0]!;
    }
  }
  return null;
}

interface ParsedProcessRow {
  pid: number;
  startedAt: number;
  comm: string;
  hasUnitMetadata: boolean;
  unit?: string;
  uunit?: string;
}

function parseProcessRows(stdout: string, nowMs: number): Map<number, ParsedProcessRow> {
  const map = new Map<number, ParsedProcessRow>();
  const isUnitToken = (tok: string): boolean => tok === "-" || isValidSystemdUnitName(tok);
  for (const rawLine of stdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const match = /^(\d+)\s+\d+\s+\d+\s+(\d+)\s+(.+)$/.exec(line);
    if (!match) continue;
    const pid = Number(match[1]);
    const etimes = Number(match[2]);
    const rest = match[3]!.trim();
    let hasUnitMetadata = false;
    let unit: string | undefined;
    let uunit: string | undefined;
    let comm = rest;
    const firstSpace = rest.search(/\s/);
    if (firstSpace !== -1) {
      const firstTok = rest.slice(0, firstSpace);
      const afterFirst = rest.slice(firstSpace).trim();
      if (afterFirst.length > 0 && isUnitToken(firstTok)) {
        hasUnitMetadata = true;
        unit = firstTok === "-" ? undefined : firstTok;
        comm = afterFirst;
        const secondSpace = afterFirst.search(/\s/);
        if (secondSpace !== -1) {
          const secondTok = afterFirst.slice(0, secondSpace);
          const afterSecond = afterFirst.slice(secondSpace).trim();
          if (afterSecond.length > 0 && isUnitToken(secondTok)) {
            uunit = secondTok === "-" ? undefined : secondTok;
            comm = afterSecond;
          }
        }
      }
    }
    if (
      !Number.isSafeInteger(pid) ||
      pid <= 0 ||
      !Number.isSafeInteger(etimes) ||
      etimes < 0 ||
      comm.length === 0
    ) {
      continue;
    }
    const startedAt = nowMs - etimes * 1000;
    if (!Number.isSafeInteger(startedAt)) {
      continue;
    }
    map.set(pid, {
      pid,
      startedAt,
      comm,
      hasUnitMetadata,
      ...(unit !== undefined ? { unit } : {}),
      ...(uunit !== undefined ? { uunit } : {}),
    });
  }
  return map;
}

interface RecentSshPeerState {
  lastFailedAuthAt?: number;
  unpairedCompanionAt?: number;
  lastSeenAt: number;
}

// ---------------------------------------------------------------------------
// EventMonitor
// ---------------------------------------------------------------------------

export class EventMonitor {
  private readonly store: SecurityStoreContract;
  private readonly runner: CommandRunner;
  private readonly clock: Clock;
  private readonly workloads: readonly EnrolledWorkload[];

  private hasSocketBaseline = false;
  private socketBaseline = new Map<string, Listener[]>();
  private recentSshPeers = new Map<string, RecentSshPeerState>();

  constructor(deps: EventMonitorDeps) {
    this.store = deps.store;
    this.runner = deps.runner;
    this.clock = deps.clock;
    this.workloads = deps.workloads ? [...deps.workloads] : [];
  }

  async pollJournal(signal?: AbortSignal): Promise<MonitorResult> {
    const previous = this.store.getCursor("journal");
    let result = await this.runner.run(
      {
        kind: "journal",
        after: previous ?? undefined,
        limit: JOURNAL_PAGE_LIMIT,
      },
      signal,
    );

    let cursorRecovered = false;
    if (result.status === "cursor_expired" && previous !== null) {
      cursorRecovered = true;
      result = await this.runner.run(
        {
          kind: "journal",
          after: undefined,
          limit: JOURNAL_PAGE_LIMIT,
        },
        signal,
      );
    }

    if (
      result.status === "overflow" &&
      result.skippedCursor !== undefined &&
      isValidJournalCursor(result.skippedCursor)
    ) {
      const now = this.clock.now();
      const skippedEvents: SecurityEvent[] = [];
      if (cursorRecovered && previous !== null) {
        skippedEvents.push({
          id: deterministicJournalGapId(previous, result.skippedCursor),
          source: "journal",
          category: "units",
          severity: "warning",
          rule: "journal_cursor_gap",
          target: "journald",
          firstAt: now,
          lastAt: now,
          count: 1,
          isNoise: false,
          summary:
            "Journal cursor expired; recovered from bounded recent window with potential telemetry gap",
        });
      }
      skippedEvents.push({
        id: deterministicJournalOversizedId(result.skippedCursor),
        source: "journal",
        category: "units",
        severity: "warning",
        rule: "journal_record_skipped",
        target: "journald",
        firstAt: now,
        lastAt: now,
        count: 1,
        isNoise: false,
        summary:
          "Skipped oversized journal record exceeding byte limit; cursor advanced with partial coverage",
      });
      this.store.commitEventBatch({
        events: skippedEvents,
        cursor: {
          source: "journal",
          expected: previous,
          next: result.skippedCursor,
        },
        burstWindowMs: BURST_WINDOW_MS,
      });
      return {
        alerts: [],
        corroboration: [],
        coverage: "partial",
      };
    }

    if (result.status !== "ok") {
      return {
        alerts: [],
        corroboration: [],
        coverage: result.status === "unavailable" ? "unavailable" : "partial",
      };
    }

    const parsedItems: ClassifiedJournalEvent[] = [];
    let lastCursor: string | null = null;
    let malformed = false;

    if (result.stdout.length > 0) {
      for (const rawLine of result.stdout.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (line.length === 0) continue;

        const parsed = parseJournalRecordInternal(line);
        if (parsed === null) {
          malformed = true;
          break;
        }

        lastCursor = parsed.cursor;
        if (parsed.event) {
          parsedItems.push(
            parsed.sshMeta ? { event: parsed.event, sshMeta: parsed.sshMeta } : { event: parsed.event },
          );
        }
      }
    }

    const batchFailedAuthTimes = new Map<string, number[]>();
    let maxSshEventTs: number | null = null;
    for (const item of parsedItems) {
      if (item.sshMeta?.peerKey !== undefined) {
        const ts = item.event.lastAt;
        if (maxSshEventTs === null || ts > maxSshEventTs) {
          maxSshEventTs = ts;
        }
        if (item.sshMeta.subtype === "failed_auth") {
          const list = batchFailedAuthTimes.get(item.sshMeta.peerKey);
          if (list) {
            list.push(ts);
          } else {
            batchFailedAuthTimes.set(item.sshMeta.peerKey, [ts]);
          }
        }
      }
    }

    const nextSshPeers = new Map<string, RecentSshPeerState>();
    for (const [key, state] of this.recentSshPeers.entries()) {
      nextSshPeers.set(key, { ...state });
    }

    const events: SecurityEvent[] = [];
    for (const item of parsedItems) {
      const sshMeta = item.sshMeta;
      if (!sshMeta || sshMeta.peerKey === undefined) {
        events.push(item.event);
        continue;
      }

      const peerKey = sshMeta.peerKey;
      const ts = item.event.lastAt;
      const prior = nextSshPeers.get(peerKey);

      if (sshMeta.subtype === "failed_auth") {
        if (
          prior?.unpairedCompanionAt !== undefined &&
          Math.abs(ts - prior.unpairedCompanionAt) <= SSH_DEDUPE_WINDOW_MS
        ) {
          // Pairs with an already-counted companion line from a prior poll; do not double-count.
          nextSshPeers.set(peerKey, {
            lastFailedAuthAt: ts,
            lastSeenAt: Math.max(prior.lastSeenAt, ts),
          });
          continue;
        }
        events.push(item.event);
        nextSshPeers.set(peerKey, {
          lastFailedAuthAt: ts,
          lastSeenAt: prior ? Math.max(prior.lastSeenAt, ts) : ts,
        });
        continue;
      }

      // Companion line (Invalid user / Connection closed by authenticating user)
      const batchAuthTimes = batchFailedAuthTimes.get(peerKey);
      if (batchAuthTimes?.some((authTs) => Math.abs(authTs - ts) <= SSH_DEDUPE_WINDOW_MS)) {
        continue;
      }
      if (
        prior?.lastFailedAuthAt !== undefined &&
        Math.abs(ts - prior.lastFailedAuthAt) <= SSH_DEDUPE_WINDOW_MS
      ) {
        nextSshPeers.set(peerKey, {
          ...prior,
          lastSeenAt: Math.max(prior.lastSeenAt, ts),
        });
        continue;
      }
      if (
        prior?.unpairedCompanionAt !== undefined &&
        Math.abs(ts - prior.unpairedCompanionAt) <= SSH_DEDUPE_WINDOW_MS
      ) {
        nextSshPeers.set(peerKey, {
          ...prior,
          lastSeenAt: Math.max(prior.lastSeenAt, ts),
        });
        continue;
      }

      events.push(item.event);
      nextSshPeers.set(peerKey, {
        ...(prior?.lastFailedAuthAt !== undefined
          ? { lastFailedAuthAt: prior.lastFailedAuthAt }
          : {}),
        unpairedCompanionAt: ts,
        lastSeenAt: prior ? Math.max(prior.lastSeenAt, ts) : ts,
      });
    }

    const coverage: Coverage = malformed || cursorRecovered ? "partial" : "complete";
    if (lastCursor === null && !cursorRecovered) {
      return { alerts: [], corroboration: [], coverage };
    }

    const now = this.clock.now();
    const batchEvents: SecurityEvent[] = cursorRecovered
      ? [
          {
            id: deterministicJournalGapId(previous!, lastCursor ?? ""),
            source: "journal",
            category: "units",
            severity: "warning",
            rule: "journal_cursor_gap",
            target: "journald",
            firstAt: now,
            lastAt: now,
            count: 1,
            isNoise: false,
            summary:
              "Journal cursor expired; recovered from bounded recent window with potential telemetry gap",
          },
          ...events,
        ]
      : events;

    const committed = this.store.commitEventBatch({
      events: batchEvents,
      cursor: {
        source: "journal",
        expected: previous,
        next: lastCursor,
      },
      burstWindowMs: BURST_WINDOW_MS,
    });

    if (!committed) {
      return { alerts: [], corroboration: [], coverage: "partial" };
    }

    const sshPruneCutoff =
      maxSshEventTs !== null
        ? Math.min(now, maxSshEventTs) - SSH_DEDUPE_WINDOW_MS
        : now - BURST_WINDOW_MS;
    for (const [key, state] of nextSshPeers.entries()) {
      if (state.lastSeenAt < sshPruneCutoff || now - state.lastSeenAt > BURST_WINDOW_MS) {
        nextSshPeers.delete(key);
      }
    }
    if (nextSshPeers.size > MAX_SSH_DEDUPE_ENTRIES) {
      const sorted = [...nextSshPeers.entries()].sort((a, b) => a[1].lastSeenAt - b[1].lastSeenAt);
      const excess = nextSshPeers.size - MAX_SSH_DEDUPE_ENTRIES;
      for (let i = 0; i < excess; i += 1) {
        nextSshPeers.delete(sorted[i]![0]);
      }
    }
    this.recentSshPeers = nextSshPeers;

    const windowStart = now - BURST_WINDOW_MS;
    const alerts: SecurityAlert[] = [];
    const seenAlertFingerprints = new Set<string>();
    const corroboration: Corroboration[] = [];
    const affectedSshPeers = new Set<string>();
    const anomalyEventIds: string[] = [];

    for (const event of events) {
      if (event.rule === "ssh_auth_failure") {
        affectedSshPeers.add(event.target);
        continue;
      }

      if (HIGH_SIGNAL_JOURNAL_RULES.has(event.rule)) {
        const fingerprint = `journal:${event.rule}:${event.target}`;
        if (!seenAlertFingerprints.has(fingerprint)) {
          seenAlertFingerprints.add(fingerprint);
          alerts.push({
            id: `alert:${event.id}`,
            fingerprint,
            severity: event.severity,
            summary: event.summary,
            createdAt: now,
          });
        }
        if (SYSTEM_ANOMALY_RULES.has(event.rule)) {
          anomalyEventIds.push(event.id);
        }
      }
    }

    for (const peer of affectedSshPeers) {
      if (isProtectedPeerIp(peer)) continue;
      const inWindow = this.store.recentObservations("ssh_auth_failure", peer, windowStart, now);
      const totalFailures = inWindow.reduce((sum, obs) => sum + obs.count, 0);

      if (totalFailures >= SSH_BURST_THRESHOLD) {
        const inWindowIds = inWindow.map((obs) => obs.id);
        corroboration.push({
          rule: "ssh_burst",
          eventIds: inWindowIds,
          expiresAt: now + BURST_WINDOW_MS,
          target: { kind: "deny_peer_ip", ip: peer },
        });

        const fingerprint = `ssh_burst:${peer}`;
        if (!seenAlertFingerprints.has(fingerprint)) {
          seenAlertFingerprints.add(fingerprint);
          alerts.push({
            id: `alert:ssh_burst:${peer}:${now}`,
            fingerprint,
            severity: "critical",
            summary: `SSH authentication failure burst from ${peer} (${totalFailures} failures in 5m)`,
            createdAt: now,
          });
        }
      }
    }

    if (anomalyEventIds.length > 0) {
      corroboration.push({
        rule: "system_anomaly",
        eventIds: anomalyEventIds,
        expiresAt: now + BURST_WINDOW_MS,
      });
    }

    return { alerts, corroboration, coverage };
  }

  async pollSockets(
    classify: (listeners: Listener[]) => Promise<ExposureEntry[]> | ExposureEntry[],
    signal?: AbortSignal,
  ): Promise<MonitorResult> {
    const result = await this.runner.run({ kind: "sockets" }, signal);
    if (result.status !== "ok") {
      return { alerts: [], corroboration: [], coverage: "unavailable" };
    }

    const listeners = parseListeners(result.stdout);
    const currentNonLoopback = new Map<string, Listener[]>();
    for (const listener of listeners) {
      if (isLoopbackListener(listener)) continue;
      const key = listenerKey(listener);
      const existing = currentNonLoopback.get(key);
      if (existing) {
        existing.push(listener);
      } else {
        currentNonLoopback.set(key, [listener]);
      }
    }

    const exposure = await classify(listeners);

    if (!this.hasSocketBaseline) {
      this.socketBaseline = currentNonLoopback;
      this.hasSocketBaseline = true;
      return { alerts: [], corroboration: [], coverage: "complete" };
    }

    const now = this.clock.now();

    const exposureByListenerId = new Map<string, ExposureEntry>();
    const exposureByKey = new Map<string, ExposureEntry[]>();
    for (const entry of exposure) {
      exposureByListenerId.set(entry.listener.id, entry);
      const key = listenerKey(entry.listener);
      const list = exposureByKey.get(key);
      if (list) {
        list.push(entry);
      } else {
        exposureByKey.set(key, [entry]);
      }
    }

    const events: SecurityEvent[] = [];
    const alerts: SecurityAlert[] = [];
    const corroboration: Corroboration[] = [];
    const seenAlertFingerprints = new Set<string>();
    let processesLoaded = false;
    let processMap: Map<number, ParsedProcessRow> | null = null;
    let coverage: Coverage = "complete";

    const getProcessTable = async (): Promise<Map<number, ParsedProcessRow> | null> => {
      if (processesLoaded) return processMap;
      processesLoaded = true;
      const procResult = await this.runner.run({ kind: "processes" }, signal);
      if (procResult.status !== "ok") {
        coverage = "partial";
        processMap = null;
        return null;
      }
      processMap = parseProcessRows(procResult.stdout, now);
      return processMap;
    };

    // Newly opened non-loopback listeners
    for (const [key, openedListeners] of currentNonLoopback.entries()) {
      if (this.socketBaseline.has(key)) continue;

      const primary = openedListeners[0]!;
      const matchingEntries = openedListeners
        .map((l) => exposureByListenerId.get(l.id))
        .filter((e): e is ExposureEntry => e !== undefined);
      const effectiveEntries =
        matchingEntries.length > 0 ? matchingEntries : (exposureByKey.get(key) ?? []);

      const unexpectedExposed = effectiveEntries.find(
        (entry) =>
          entry.expected === false &&
          (entry.reachability === "exposed_v4_v6" || entry.reachability === "exposed_lan") &&
          isWildcardAddress(entry.listener.address),
      );

      const eventId = deterministicSocketEventId(now, "opened", key);
      const target = `${primary.protocol}:${primary.address}:${primary.port}`;
      events.push({
        id: eventId,
        source: "socket",
        category: "network",
        severity: unexpectedExposed ? "critical" : "info",
        rule: "listener_opened",
        target,
        firstAt: now,
        lastAt: now,
        count: 1,
        isNoise: false,
        summary: `Network listener opened on ${primary.protocol} ${primary.address}:${primary.port}`,
      });

      if (unexpectedExposed) {
        const matchedListener = unexpectedExposed.listener;
        let workload: EnrolledWorkload | null = null;
        let verifiedProcess: ParsedProcessRow | null = null;
        if (
          this.workloads.length > 0 &&
          matchedListener.pid !== undefined &&
          Number.isInteger(matchedListener.pid) &&
          matchedListener.pid > 0 &&
          matchedListener.process
        ) {
          const table = await getProcessTable();
          const candidate = table?.get(matchedListener.pid);
          if (
            candidate &&
            candidate.comm.toLowerCase() === matchedListener.process.trim().toLowerCase()
          ) {
            workload = matchEnrolledWorkload(matchedListener, candidate, this.workloads);
            if (workload) {
              verifiedProcess = candidate;
            }
          }
        }

        if (workload && verifiedProcess !== null) {
          corroboration.push({
            rule: "unexpected_workload",
            eventIds: [eventId],
            expiresAt: now + BURST_WINDOW_MS,
            target: {
              kind: "pause_workload",
              workloadId: workload.id,
              pid: verifiedProcess.pid,
              startedAt: verifiedProcess.startedAt,
            },
          });

          const fingerprint = `unexpected_workload:${workload.id}:${matchedListener.protocol}:${matchedListener.port}`;
          if (!seenAlertFingerprints.has(fingerprint)) {
            seenAlertFingerprints.add(fingerprint);
            alerts.push({
              id: `alert:${eventId}`,
              fingerprint,
              severity: "critical",
              summary: `Unexpected exposed listener for workload ${workload.id} on ${matchedListener.protocol} ${matchedListener.address}:${matchedListener.port}`,
              createdAt: now,
            });
          }
        } else {
          corroboration.push({
            rule: "unexpected_listener",
            eventIds: [eventId],
            expiresAt: now + BURST_WINDOW_MS,
          });

          const fingerprint = `unexpected_listener:${matchedListener.protocol}:${matchedListener.address}:${matchedListener.port}`;
          if (!seenAlertFingerprints.has(fingerprint)) {
            seenAlertFingerprints.add(fingerprint);
            alerts.push({
              id: `alert:${eventId}`,
              fingerprint,
              severity: "critical",
              summary: `Unexpected exposed listener on ${matchedListener.protocol} ${matchedListener.address}:${matchedListener.port}`,
              createdAt: now,
            });
          }
        }
      }
    }

    // Closed non-loopback listeners
    for (const [key, closedListeners] of this.socketBaseline.entries()) {
      if (currentNonLoopback.has(key)) continue;

      const primary = closedListeners[0]!;
      const eventId = deterministicSocketEventId(now, "closed", key);
      const target = `${primary.protocol}:${primary.address}:${primary.port}`;
      events.push({
        id: eventId,
        source: "socket",
        category: "network",
        severity: "info",
        rule: "listener_closed",
        target,
        firstAt: now,
        lastAt: now,
        count: 1,
        isNoise: false,
        summary: `Network listener closed on ${primary.protocol} ${primary.address}:${primary.port}`,
      });
    }

    if (events.length > 0) {
      this.store.commitEventBatch({
        events,
        burstWindowMs: BURST_WINDOW_MS,
      });
    }

    this.socketBaseline = currentNonLoopback;
    return { alerts, corroboration, coverage };
  }
}
