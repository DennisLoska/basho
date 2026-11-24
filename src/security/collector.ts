import { constants as fsConstants } from "node:fs";
import { open, readdir } from "node:fs/promises";
import { basename, join } from "node:path";
import { isValidSystemdUnitName } from "./runner";
import {
  criterionIds,
  type Category,
  type Clock,
  type CommandRequest,
  type CommandResult,
  type CommandRunner,
  type Coverage,
  type CriterionId,
  type EnrolledWorkload,
  type Evidence,
  type ExposureEntry,
  type Facts,
  type Listener,
  type PostureCheck,
  type PostureSnapshot,
  type SecurityFinding,
  type SecuritySettings,
  type Severity,
} from "./types";

export type PostureFileSource =
  | "ufw-conf"
  | "ufw-v4"
  | "ufw-v6"
  | "ufw-default"
  | "sshd-main"
  | "pacman-log";

export interface SshDropIn {
  name: string;
  text: string;
}

export interface PostureFiles {
  read(source: PostureFileSource): Promise<string | null>;
  sshDropIns(): Promise<SshDropIn[] | null>;
}

export interface PostureFilePaths {
  "ufw-conf": string;
  "ufw-v4": string;
  "ufw-v6": string;
  "ufw-default": string;
  "sshd-main": string;
  "pacman-log": string;
  "sshd-drop-ins-dir": string;
}

export interface FirewallInputs {
  active: boolean | null;
  ipv6Enabled?: boolean | null;
  v4?: string | null;
  v6?: string | null;
  defaultInput?: "allow" | "deny" | "unknown" | null;
}

export type FirewallDecision = "allow" | "deny" | "unknown";

export interface PostureResult {
  snapshot: PostureSnapshot;
  exposure: ExposureEntry[];
  findings: SecurityFinding[];
}

export interface PostureCollectorOptions {
  runner: CommandRunner;
  files?: PostureFiles;
  clock?: Clock;
  concurrency?: number;
}

export interface ClassifyListenersOptions {
  listeners: readonly Listener[];
  firewall: FirewallInputs;
  publications: TailscalePublications;
  expectedPorts: ReadonlySet<number>;
  evidenceIdForListener: (listener: Listener, index: number) => string;
}

export interface TailscaleBackendTarget {
  host: string | null;
  family: 4 | 6 | "localhost" | "any";
  port: number;
}

export interface TailscalePublications {
  servePorts: ReadonlySet<number>;
  funnelPorts: ReadonlySet<number>;
  serveTargets: readonly TailscaleBackendTarget[];
  funnelTargets: readonly TailscaleBackendTarget[];
  serveCoverage: Coverage;
  funnelCoverage: Coverage;
  tailscaleAbsent?: boolean;
}

const DEFAULT_CONCURRENCY = 4;
const MAX_CONFIG_FILE_BYTES = 256 * 1024;
const MAX_PACMAN_TAIL_BYTES = 256 * 1024;
const MAX_SSH_DROPIN_FILES = 128;
const STALE_UPGRADE_DAYS = 14;
const DAY_MS = 86_400_000;

const DEFAULT_FILE_PATHS: PostureFilePaths = {
  "ufw-conf": "/etc/ufw/ufw.conf",
  "ufw-v4": "/etc/ufw/user.rules",
  "ufw-v6": "/etc/ufw/user6.rules",
  "ufw-default": "/etc/default/ufw",
  "sshd-main": "/etc/ssh/sshd_config",
  "pacman-log": "/var/log/pacman.log",
  "sshd-drop-ins-dir": "/etc/ssh/sshd_config.d",
};

const O_NOFOLLOW = fsConstants.O_NOFOLLOW ?? 0;
const O_DIRECTORY = fsConstants.O_DIRECTORY ?? 0;
const O_NONBLOCK = fsConstants.O_NONBLOCK ?? 0;

function lexicalCompare(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

async function readRegularFileBounded(
  filePath: string,
  maxBytes: number,
  mode: "full" | "tail",
): Promise<string | null> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(filePath, fsConstants.O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    const stat = await handle.stat();
    if (!stat.isFile()) {
      return null;
    }

    if (mode === "full") {
      if (stat.size > maxBytes) {
        return null;
      }
      const buffer = Buffer.allocUnsafe(stat.size);
      let offset = 0;
      while (offset < stat.size) {
        const { bytesRead } = await handle.read(buffer, offset, stat.size - offset, offset);
        if (bytesRead === 0) break;
        offset += bytesRead;
      }
      return buffer.subarray(0, offset).toString("utf8");
    }

    // Bounded tail read for potentially large logs (e.g. /var/log/pacman.log).
    const readSize = Math.min(stat.size, maxBytes);
    const startOffset = stat.size - readSize;
    const buffer = Buffer.allocUnsafe(readSize);
    let offset = 0;
    while (offset < readSize) {
      const { bytesRead } = await handle.read(
        buffer,
        offset,
        readSize - offset,
        startOffset + offset,
      );
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    const text = buffer.subarray(0, offset).toString("utf8");
    if (startOffset > 0) {
      const firstNewline = text.indexOf("\n");
      return firstNewline >= 0 ? text.slice(firstNewline + 1) : text;
    }
    return text;
  } catch {
    return null;
  } finally {
    await handle?.close().catch(() => {});
  }
}

export function createPostureFiles(overrides?: Partial<PostureFilePaths>): PostureFiles {
  const paths: PostureFilePaths = { ...DEFAULT_FILE_PATHS, ...overrides };

  return {
    async read(source: PostureFileSource): Promise<string | null> {
      const filePath = paths[source];
      if (source === "pacman-log") {
        return readRegularFileBounded(filePath, MAX_PACMAN_TAIL_BYTES, "tail");
      }
      return readRegularFileBounded(filePath, MAX_CONFIG_FILE_BYTES, "full");
    },

    async sshDropIns(): Promise<SshDropIn[] | null> {
      const dirPath = paths["sshd-drop-ins-dir"];
      let dirHandle: Awaited<ReturnType<typeof open>> | undefined;
      try {
        dirHandle = await open(dirPath, fsConstants.O_RDONLY | O_NOFOLLOW | O_DIRECTORY);
        const stat = await dirHandle.stat();
        if (!stat.isDirectory()) {
          return null;
        }
      } catch (err: unknown) {
        if (
          typeof err === "object" &&
          err !== null &&
          "code" in err &&
          (err as { code?: string }).code === "ENOENT"
        ) {
          return [];
        }
        return null;
      } finally {
        await dirHandle?.close().catch(() => {});
      }

      let entries: string[];
      try {
        entries = await readdir(dirPath);
      } catch {
        return null;
      }

      const confNames = entries
        .filter((name) => name.endsWith(".conf") && !name.includes("/") && !name.includes("\0"))
        .sort(lexicalCompare);

      if (confNames.length > MAX_SSH_DROPIN_FILES) {
        return null;
      }

      const dropIns: SshDropIn[] = [];
      for (const name of confNames) {
        const text = await readRegularFileBounded(
          join(dirPath, name),
          MAX_CONFIG_FILE_BYTES,
          "full",
        );
        if (text === null) {
          return null;
        }
        dropIns.push({ name, text });
      }
      return dropIns;
    },
  };
}

// ---------------------------------------------------------------------------
// Sanitization and IP/address helpers
// ---------------------------------------------------------------------------

function sanitizeToken(raw: string, maxLen = 64): string {
  const stripped = raw.replace(/[\x00-\x1f\x7f]/g, "").trim();
  return stripped.slice(0, maxLen);
}

function sanitizeProcessComm(raw: string): string {
  const firstWord = raw.trim().split(/\s+/)[0] ?? "";
  const base = basename(firstWord);
  return sanitizeToken(base, 64);
}

function parseIpv4ToUint32(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    value = (value << 8) | octet;
  }
  return value >>> 0;
}

function isValidIpv6Shape(ip: string): boolean {
  if (!ip.includes(":")) return false;
  return /^[0-9a-fA-F:.]+$/.test(ip);
}

function isLoopbackAddress(address: string, family: Listener["family"]): boolean {
  if (family === 4) {
    const num = parseIpv4ToUint32(address);
    return num !== null && ((num >>> 24) & 0xff) === 127;
  }
  if (family === 6) {
    if (isPureIpv6Loopback(address)) return true;
    const lower = address.toLowerCase();
    if (lower.startsWith("::ffff:")) {
      const mapped = parseIpv4ToUint32(lower.slice("::ffff:".length));
      return mapped !== null && ((mapped >>> 24) & 0xff) === 127;
    }
    return false;
  }
  return false;
}

function isTailnetListener(
  listener: Pick<Listener, "address" | "family" | "interfaceName">,
): boolean {
  if (listener.interfaceName && /^tailscale\d*$/i.test(listener.interfaceName)) {
    return true;
  }
  if (listener.family === 4) {
    const num = parseIpv4ToUint32(listener.address);
    // Tailscale IPv4 CGNAT range: 100.64.0.0/10
    if (num !== null && (num & 0xffc00000) >>> 0 === 0x64400000) {
      return true;
    }
  }
  if (listener.family === 6) {
    const lower = listener.address.toLowerCase();
    // Tailscale IPv6 ULA prefix: fd7a:115c:a1e0::/48
    if (lower.startsWith("fd7a:115c:a1e0:")) {
      return true;
    }
  }
  return false;
}

function isWildcardAddress(address: string): boolean {
  return address === "*" || address === "0.0.0.0" || address === "::" || address === "0:0:0:0:0:0:0:0";
}

function isAllSourcesCidr(cidr: string, family: 4 | 6): boolean {
  const lower = cidr.toLowerCase();
  if (family === 4) {
    return lower === "0.0.0.0/0" || lower === "0/0";
  }
  return lower === "::/0" || lower === "0:0:0:0:0:0:0:0/0";
}

function interfaceMatches(ruleIface: string, listenerIface: string | undefined): boolean {
  if (!listenerIface) return false;
  if (ruleIface.endsWith("+")) {
    return listenerIface.startsWith(ruleIface.slice(0, -1));
  }
  return ruleIface === listenerIface;
}

function ipv4InCidr(ip: string, cidr: string): boolean | null {
  const [netStr, prefixStr] = cidr.split("/");
  if (!netStr) return null;
  const ipNum = parseIpv4ToUint32(ip);
  const netNum = parseIpv4ToUint32(netStr);
  if (ipNum === null || netNum === null) return null;
  const prefix = prefixStr === undefined ? 32 : Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  if (prefix === 0) return true;
  const mask = (~0 << (32 - prefix)) >>> 0;
  return ((ipNum & mask) >>> 0) === ((netNum & mask) >>> 0);
}

function ipv6ToBigInt(ip: string): bigint | null {
  const trimmed = ip.trim().toLowerCase();
  if (!trimmed || !trimmed.includes(":")) return null;

  const parseGroups = (part: string): number[] | null => {
    if (!part) return [];
    const tokens = part.split(":");
    const groups: number[] = [];
    for (let i = 0; i < tokens.length; i++) {
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

  let groups: number[];
  if (doubleColonParts.length === 2) {
    const left = parseGroups(doubleColonParts[0]!);
    const right = parseGroups(doubleColonParts[1]!);
    if (!left || !right) return null;
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    groups = [...left, ...Array<number>(missing).fill(0), ...right];
  } else {
    const parsed = parseGroups(trimmed);
    if (!parsed || parsed.length !== 8) return null;
    groups = parsed;
  }

  let value = 0n;
  for (const g of groups) {
    value = (value << 16n) | BigInt(g);
  }
  return value;
}

function ipv6InCidr(ip: string, cidr: string): boolean | null {
  const [netStr, prefixStr, extra] = cidr.split("/");
  if (!netStr || extra !== undefined) return null;
  const ipVal = ipv6ToBigInt(ip);
  const netVal = ipv6ToBigInt(netStr);
  if (ipVal === null || netVal === null) return null;
  const prefix = prefixStr === undefined ? 128 : Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return null;
  if (prefix === 0) return true;
  const shift = BigInt(128 - prefix);
  return (ipVal >> shift) === (netVal >> shift);
}

function isPureIpv6Loopback(ip: string): boolean {
  return ipv6ToBigInt(ip) === 1n;
}

// ---------------------------------------------------------------------------
// parseListeners (`ss -tulnp`)
// ---------------------------------------------------------------------------

function parseLocalEndpoint(
  endpoint: string,
): { address: string; port: number; family: Listener["family"]; interfaceName?: string } | null {
  const lastColon = endpoint.lastIndexOf(":");
  if (lastColon <= 0 || lastColon === endpoint.length - 1) return null;

  const portText = endpoint.slice(lastColon + 1);
  if (!/^\d{1,5}$/.test(portText)) return null;
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;

  const hostPart = endpoint.slice(0, lastColon);
  const bracketed = /^\[([^\]]+)\](?:%([^%\s]+))?$/.exec(hostPart);
  if (bracketed) {
    const inner = bracketed[1] ?? "";
    const outerIface = bracketed[2];
    const [addr, innerIface] = inner.split("%", 2);
    if (!addr || !isValidIpv6Shape(addr)) return null;
    const iface = innerIface ?? outerIface;
    return {
      address: addr,
      port,
      family: 6,
      ...(iface ? { interfaceName: sanitizeToken(iface, 32) } : {}),
    };
  }

  const [rawAddr, iface] = hostPart.split("%", 2);
  if (!rawAddr) return null;

  if (rawAddr === "*") {
    return {
      address: "*",
      port,
      family: "unspecified",
      ...(iface ? { interfaceName: sanitizeToken(iface, 32) } : {}),
    };
  }

  if (rawAddr.includes(":")) {
    if (!isValidIpv6Shape(rawAddr)) return null;
    return {
      address: rawAddr,
      port,
      family: 6,
      ...(iface ? { interfaceName: sanitizeToken(iface, 32) } : {}),
    };
  }

  if (parseIpv4ToUint32(rawAddr) !== null) {
    return {
      address: rawAddr,
      port,
      family: 4,
      ...(iface ? { interfaceName: sanitizeToken(iface, 32) } : {}),
    };
  }

  return null;
}

export function parseListeners(text: string): Listener[] {
  if (!text) return [];
  const listeners: Listener[] = [];
  const seenIds = new Map<string, number>();

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;

    const parts = line.split(/\s+/);
    if (parts.length < 6) continue;

    const protoRaw = parts[0]?.toLowerCase();
    if (protoRaw !== "tcp" && protoRaw !== "udp") continue;

    const state = parts[1]?.toUpperCase();
    if (state !== "LISTEN" && state !== "UNCONN") continue;

    if (!/^\d+$/.test(parts[2] ?? "") || !/^\d+$/.test(parts[3] ?? "")) continue;

    const endpoint = parseLocalEndpoint(parts[4] ?? "");
    if (!endpoint) continue;

    let pid: number | undefined;
    let processName: string | undefined;
    const usersMatch = /users:\(\("([^"]+)",pid=(\d+)/.exec(line);
    if (usersMatch) {
      const parsedName = sanitizeProcessComm(usersMatch[1] ?? "");
      const parsedPid = Number(usersMatch[2]);
      if (parsedName.length > 0) {
        processName = parsedName;
      }
      if (Number.isInteger(parsedPid) && parsedPid > 0) {
        pid = parsedPid;
      }
    }

    const scopePart = endpoint.interfaceName ? `%${endpoint.interfaceName}` : "";
    const pidPart = pid !== undefined ? `:${pid}` : "";
    const baseId = `listener:${protoRaw}:${endpoint.family}:${endpoint.address}${scopePart}:${endpoint.port}${pidPart}`;
    const count = seenIds.get(baseId) ?? 0;
    seenIds.set(baseId, count + 1);
    const id = count === 0 ? baseId : `${baseId}#${count}`;

    listeners.push({
      id,
      protocol: protoRaw,
      address: endpoint.address,
      port: endpoint.port,
      family: endpoint.family,
      ...(endpoint.interfaceName ? { interfaceName: endpoint.interfaceName } : {}),
      ...(pid !== undefined ? { pid } : {}),
      ...(processName !== undefined ? { process: processName } : {}),
    });
  }

  return listeners;
}

// ---------------------------------------------------------------------------
// UFW parsing & evaluateFirewall
// ---------------------------------------------------------------------------

interface PortRange {
  start: number;
  end: number;
}

interface ParsedUfwRule {
  protocol?: "tcp" | "udp" | "all" | "other";
  dports?: PortRange[];
  inInterface?: string;
  source?: string;
  destination?: string;
  jump?: string;
  hasTarget: boolean;
  indeterminate: boolean;
}

function tokenizeRule(line: string): string[] | null {
  const tokens: string[] = [];
  let current = "";
  let inQuotes = false;
  let quoteChar = "";

  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (inQuotes) {
      if (ch === "\\" && i + 1 < line.length) {
        current += line[i + 1]!;
        i++;
      } else if (ch === quoteChar) {
        inQuotes = false;
        quoteChar = "";
      } else {
        current += ch;
      }
      continue;
    }

    if (ch === '"' || ch === "'") {
      inQuotes = true;
      quoteChar = ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (current.length > 0) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += ch;
  }

  if (inQuotes) return null;
  if (current.length > 0) tokens.push(current);
  return tokens;
}

function parsePortSpec(spec: string): PortRange[] | null {
  const ranges: PortRange[] = [];
  for (const part of spec.split(",")) {
    const trimmed = part.trim();
    if (!trimmed) return null;
    if (trimmed.includes(":")) {
      const [startStr, endStr, extra] = trimmed.split(":");
      if (extra !== undefined) return null;
      const start = startStr === "" ? 0 : Number(startStr);
      const end = endStr === "" ? 65535 : Number(endStr);
      if (
        !Number.isInteger(start) ||
        !Number.isInteger(end) ||
        start < 0 ||
        end > 65535 ||
        start > end
      ) {
        return null;
      }
      ranges.push({ start, end });
    } else {
      if (!/^\d{1,5}$/.test(trimmed)) return null;
      const port = Number(trimmed);
      if (!Number.isInteger(port) || port < 0 || port > 65535) return null;
      ranges.push({ start: port, end: port });
    }
  }
  return ranges.length > 0 ? ranges : null;
}

function portMatchesRanges(port: number, ranges: readonly PortRange[]): boolean {
  return ranges.some((range) => port >= range.start && port <= range.end);
}

const KNOWN_SAFE_MODULES = new Set(["comment", "tcp", "udp", "multiport"]);

const UFW_RATE_LIMIT_DROP_JUMPS = new Set(["ufw-user-limit", "ufw6-user-limit"]);

const UFW_RATE_LIMIT_ACCEPT_JUMPS = new Set([
  "ufw-user-limit-accept",
  "ufw6-user-limit-accept",
]);

const UFW_RATE_LIMIT_ALLOW_JUMPS = new Set([
  ...UFW_RATE_LIMIT_DROP_JUMPS,
  ...UFW_RATE_LIMIT_ACCEPT_JUMPS,
]);

function parseUfwChainRules(rulesText: string, chainName: string): ParsedUfwRule[] {
  const rules: ParsedUfwRule[] = [];

  for (const rawLine of rulesText.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("*") || line.startsWith(":") || line === "COMMIT") {
      continue;
    }

    const tokens = tokenizeRule(line);
    if (!tokens || tokens.length < 2) continue;

    if (tokens[0] !== "-A" || tokens[1] !== chainName) {
      continue;
    }

    const rule: ParsedUfwRule = { hasTarget: false, indeterminate: false };
    let negated = false;
    let hasRateLimitMatch = false;
    let sawConntrackModule = false;
    let sawRecentModule = false;

    for (let i = 2; i < tokens.length; i++) {
      const tok = tokens[i]!;
      const next = tokens[i + 1];

      if (tok === "!") {
        negated = true;
        rule.indeterminate = true;
        continue;
      }

      const isNegated = negated;
      negated = false;

      if (tok === "-p" || tok === "--protocol") {
        if (!next) {
          rule.indeterminate = true;
          break;
        }
        if (!isNegated) {
          const proto = next.toLowerCase();
          if (proto === "tcp" || proto === "udp" || proto === "all") {
            rule.protocol = proto;
          } else {
            rule.protocol = "other";
          }
        }
        i++;
        continue;
      }

      if (tok === "--dport" || tok === "--dports") {
        if (!next) {
          rule.indeterminate = true;
          break;
        }
        if (!isNegated) {
          const ranges = parsePortSpec(next);
          if (!ranges) {
            rule.indeterminate = true;
          } else {
            rule.dports = rule.dports ? [...rule.dports, ...ranges] : ranges;
          }
        }
        i++;
        continue;
      }

      if (tok === "-i" || tok === "--in-interface") {
        if (!next) {
          rule.indeterminate = true;
          break;
        }
        if (!isNegated) {
          rule.inInterface = next;
        }
        i++;
        continue;
      }

      if (tok === "-s" || tok === "--source") {
        if (!next) {
          rule.indeterminate = true;
          break;
        }
        if (!isNegated) {
          rule.source = next;
        }
        i++;
        continue;
      }

      if (tok === "-d" || tok === "--destination") {
        if (!next) {
          rule.indeterminate = true;
          break;
        }
        if (!isNegated) {
          rule.destination = next;
        }
        i++;
        continue;
      }

      if (tok === "-j" || tok === "--jump") {
        rule.hasTarget = true;
        if (!next) {
          rule.indeterminate = true;
          break;
        }
        rule.jump = next;
        i++;
        continue;
      }

      if (tok === "-g" || tok === "--goto") {
        rule.hasTarget = true;
        rule.indeterminate = true;
        if (next !== undefined) i++;
        continue;
      }

      if (tok === "-m" || tok === "--match") {
        if (!next) {
          rule.indeterminate = true;
          break;
        }
        const mod = next.toLowerCase();
        if (mod === "conntrack") {
          sawConntrackModule = true;
          hasRateLimitMatch = true;
        } else if (mod === "recent") {
          sawRecentModule = true;
          hasRateLimitMatch = true;
        } else if (!KNOWN_SAFE_MODULES.has(mod)) {
          rule.indeterminate = true;
        }
        i++;
        continue;
      }

      if (tok === "--ctstate") {
        if (!next) {
          rule.indeterminate = true;
          break;
        }
        if (sawConntrackModule && next.toUpperCase() === "NEW") {
          hasRateLimitMatch = true;
        } else {
          rule.indeterminate = true;
        }
        i++;
        continue;
      }

      if (tok === "--set" || tok === "--update") {
        if (sawRecentModule) {
          hasRateLimitMatch = true;
        } else {
          rule.indeterminate = true;
        }
        continue;
      }

      if (tok === "--seconds" || tok === "--hitcount") {
        if (!next) {
          rule.indeterminate = true;
          break;
        }
        if (sawRecentModule && /^\d+$/.test(next)) {
          hasRateLimitMatch = true;
        } else {
          rule.indeterminate = true;
        }
        i++;
        continue;
      }

      if (tok === "--comment") {
        if (next !== undefined) i++;
        continue;
      }

      // Any other option (e.g. --sport, --limit, --reject-with)
      if (tok === "--reject-with") {
        if (next !== undefined) i++;
        continue;
      }

      rule.indeterminate = true;
      if (next !== undefined && !next.startsWith("-")) {
        i++;
      }
    }

    // Allow conntrack/recent rate-limit matches only on non-terminating (no -j) rules
    // or UFW rate-limit jumps; arbitrary ACCEPT/DROP rules using them stay indeterminate.
    if (
      hasRateLimitMatch &&
      rule.hasTarget &&
      !(rule.jump !== undefined && UFW_RATE_LIMIT_ALLOW_JUMPS.has(rule.jump))
    ) {
      rule.indeterminate = true;
    }

    rules.push(rule);
  }

  return rules;
}

export function evaluateFirewall(
  listener: Pick<Listener, "family" | "protocol" | "port" | "address" | "interfaceName">,
  inputs: FirewallInputs,
): FirewallDecision {
  if (inputs.active === null || inputs.active === undefined) {
    return "unknown";
  }
  if (inputs.active === false) {
    return "allow";
  }
  if (listener.family === "unspecified") {
    const v4 = evaluateFirewall(
      {
        ...listener,
        family: 4,
        address: listener.address === "*" ? "0.0.0.0" : listener.address,
      },
      inputs,
    );
    const v6 = evaluateFirewall(
      {
        ...listener,
        family: 6,
        address: listener.address === "*" ? "::" : listener.address,
      },
      inputs,
    );
    if (v4 === "allow" || v6 === "allow") return "allow";
    if (v4 === "deny" && v6 === "deny") return "deny";
    return "unknown";
  }

  const family = listener.family;
  if (family === 6) {
    if (inputs.ipv6Enabled === false) {
      return "allow";
    }
    if (inputs.ipv6Enabled === null) {
      return "unknown";
    }
  }

  const rulesText = family === 4 ? inputs.v4 : inputs.v6;
  if (rulesText == null || rulesText.trim().length === 0) {
    return "unknown";
  }

  const chainName = family === 4 ? "ufw-user-input" : "ufw6-user-input";
  const rules = parseUfwChainRules(rulesText, chainName);

  for (const rule of rules) {
    // Non-terminating rules (no -j/-g, e.g. accounting or `recent --set`) never terminate the chain.
    if (!rule.hasTarget) {
      continue;
    }

    // Check protocol match first: an irrelevant protocol never blocks evaluation.
    if (rule.protocol !== undefined && rule.protocol !== "all") {
      if (rule.protocol !== listener.protocol) {
        continue;
      }
    }

    // Check destination port match: an irrelevant port never blocks evaluation.
    if (rule.dports !== undefined && !portMatchesRanges(listener.port, rule.dports)) {
      continue;
    }

    // Narrow source-scoped DROP/REJECT rules (e.g. `ufw prepend deny from <ip> to any`)
    // only block that specific peer/subnet and do not affect general reachability for all other peers.
    if (
      rule.source !== undefined &&
      !isAllSourcesCidr(rule.source, family) &&
      !rule.indeterminate &&
      (rule.jump === "DROP" || rule.jump === "REJECT")
    ) {
      continue;
    }

    // Interface-scoped rules:
    // - If the listener has an explicit interfaceName, match/mismatch normally.
    // - Loopback listeners only match lo.
    // - A tailscale*-scoped allow rule only admits Tailnet ingress, so for wildcard or
    //   non-Tailnet listeners without interfaceName, skip it and keep evaluating general LAN rules.
    // - Any other non-loopback listener without interfaceName cannot prove which interface owns
    //   its address, so a matching interface-scoped rule is indeterminate.
    let interfaceIndeterminate = false;
    if (rule.inInterface !== undefined) {
      if (listener.interfaceName !== undefined) {
        if (!interfaceMatches(rule.inInterface, listener.interfaceName)) {
          continue;
        }
      } else if (isLoopbackAddress(listener.address, listener.family)) {
        if (!interfaceMatches(rule.inInterface, "lo")) {
          continue;
        }
      } else if (
        /^tailscale/i.test(rule.inInterface) &&
        !isTailnetListener(listener) &&
        !rule.indeterminate &&
        (rule.jump === "ACCEPT" ||
          (rule.jump !== undefined && UFW_RATE_LIMIT_ALLOW_JUMPS.has(rule.jump)))
      ) {
        continue;
      } else {
        interfaceIndeterminate = true;
      }
    }

    // Destination-scoped rules
    if (rule.destination !== undefined && !isAllSourcesCidr(rule.destination, family)) {
      if (isWildcardAddress(listener.address)) {
        return "unknown";
      }
      if (family === 4) {
        const matched = ipv4InCidr(listener.address, rule.destination);
        if (matched === false) continue;
        if (matched === null) return "unknown";
      } else {
        const matched = ipv6InCidr(listener.address, rule.destination);
        if (matched === false) continue;
        if (matched === null) return "unknown";
      }
    }

    if (interfaceIndeterminate) {
      return "unknown";
    }

    // Unconditional RETURN ends the user-input chain and falls back to defaultInput.
    if (
      rule.jump === "RETURN" &&
      !rule.indeterminate &&
      rule.protocol === undefined &&
      rule.dports === undefined &&
      rule.inInterface === undefined &&
      rule.source === undefined &&
      rule.destination === undefined
    ) {
      break;
    }

    if (rule.indeterminate) {
      return "unknown";
    }

    // Source-scoped rules: non-wildcard source cannot be reduced to blanket allow/deny.
    if (rule.source !== undefined && !isAllSourcesCidr(rule.source, family)) {
      return "unknown";
    }

    if (
      rule.jump === "ACCEPT" ||
      (rule.jump !== undefined && UFW_RATE_LIMIT_ALLOW_JUMPS.has(rule.jump))
    ) {
      return "allow";
    }
    if (rule.jump === "DROP" || rule.jump === "REJECT") {
      return "deny";
    }

    // Non-terminal or unknown jump target on a matching rule.
    return "unknown";
  }

  if (inputs.defaultInput === "allow") return "allow";
  if (inputs.defaultInput === "deny") return "deny";
  return "unknown";
}

interface ParsedUfwStatus {
  active: boolean | null;
  defaultInput: "allow" | "deny" | "unknown";
}

export function parseUfwStatus(text: string): ParsedUfwStatus {
  let active: boolean | null = null;
  let defaultInput: "allow" | "deny" | "unknown" = "unknown";

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    const statusMatch = /^Status:\s*(active|inactive)\b/i.exec(line);
    if (statusMatch) {
      active = statusMatch[1]!.toLowerCase() === "active";
      continue;
    }
    const defaultMatch = /^Default:\s*(.+)$/i.exec(line);
    if (defaultMatch) {
      const incomingMatch = /(allow|deny|reject)\s*\(incoming\)/i.exec(defaultMatch[1]!);
      if (incomingMatch) {
        const action = incomingMatch[1]!.toLowerCase();
        defaultInput = action === "allow" ? "allow" : "deny";
      }
    }
  }

  return { active, defaultInput };
}

interface ParsedUfwDefault {
  defaultInput: "allow" | "deny" | "unknown";
  ipv6Enabled: boolean | null;
}

export function parseUfwDefault(text: string): ParsedUfwDefault {
  let defaultInput: "allow" | "deny" | "unknown" = "unknown";
  let ipv6Enabled: boolean | null = null;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const policyMatch =
      /^DEFAULT_INPUT_POLICY\s*=\s*["']?([A-Za-z_]+)["']?(?:\s*(?:#.*)?)?$/.exec(line);
    if (policyMatch) {
      const policy = policyMatch[1]!.toUpperCase();
      if (policy === "ACCEPT") defaultInput = "allow";
      else if (policy === "DROP" || policy === "REJECT") defaultInput = "deny";
      continue;
    }

    const ipv6Match = /^IPV6\s*=\s*["']?(yes|no)["']?(?:\s*(?:#.*)?)?$/i.exec(line);
    if (ipv6Match) {
      ipv6Enabled = ipv6Match[1]!.toLowerCase() === "yes";
    }
  }

  return { defaultInput, ipv6Enabled };
}

export function parseUfwConf(text: string): { active: boolean | null } {
  let active: boolean | null = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^ENABLED\s*=\s*["']?(yes|no)["']?(?:\s*(?:#.*)?)?$/i.exec(line);
    if (match) {
      active = match[1]!.toLowerCase() === "yes";
    }
  }
  return { active };
}

function parseSystemdUnitActiveState(stdout: string): string | null {
  for (const rawLine of stdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    const match = /^ActiveState=(.+)$/i.exec(line);
    if (match) {
      const value = match[1]!.trim().toLowerCase();
      return value.length > 0 ? value : null;
    }
  }
  return null;
}

function resolveUfwActiveState(
  ufwStatusParsed: ParsedUfwStatus | null,
  ufwConfParsed: { active: boolean | null } | null,
  ufwUnitRes: CommandResult | undefined,
): boolean | null {
  if (ufwStatusParsed && ufwStatusParsed.active !== null) {
    return ufwStatusParsed.active;
  }

  const confActive = ufwConfParsed?.active ?? null;
  const unitActiveState =
    ufwUnitRes?.status === "ok" ? parseSystemdUnitActiveState(ufwUnitRes.stdout) : null;

  if (
    confActive === false ||
    unitActiveState === "inactive" ||
    unitActiveState === "failed" ||
    unitActiveState === "deactivating"
  ) {
    return false;
  }

  if (unitActiveState === "active" && confActive === true) {
    return true;
  }

  return null;
}

function listenerMatchesAllowRule(
  listener: Listener,
  rule: ParsedUfwRule,
  family: 4 | 6,
): boolean {
  if (listener.family !== family && listener.family !== "unspecified") {
    return false;
  }

  if (
    rule.protocol !== undefined &&
    rule.protocol !== "all" &&
    rule.protocol !== listener.protocol
  ) {
    return false;
  }

  if (!rule.dports || !portMatchesRanges(listener.port, rule.dports)) {
    return false;
  }

  if (rule.inInterface !== undefined) {
    if (listener.interfaceName !== undefined) {
      if (!interfaceMatches(rule.inInterface, listener.interfaceName)) {
        return false;
      }
    } else if (isLoopbackAddress(listener.address, listener.family)) {
      if (!interfaceMatches(rule.inInterface, "lo")) {
        return false;
      }
    } else if (!isWildcardAddress(listener.address)) {
      if (isTailnetListener(listener)) {
        if (!/^tailscale/i.test(rule.inInterface)) {
          return false;
        }
      } else if (
        interfaceMatches(rule.inInterface, "lo") ||
        /^tailscale/i.test(rule.inInterface)
      ) {
        return false;
      }
    }
  }

  if (rule.destination !== undefined && !isAllSourcesCidr(rule.destination, family)) {
    if (listener.family !== "unspecified" && !isWildcardAddress(listener.address)) {
      const matched =
        family === 4
          ? ipv4InCidr(listener.address, rule.destination)
          : ipv6InCidr(listener.address, rule.destination);
      if (matched === false) {
        return false;
      }
    }
  }

  return true;
}

function countUnusedAllowRules(
  rulesText: string,
  chainName: string,
  family: 4 | 6,
  listeners: readonly Listener[],
): { totalRules: number; unusedCount: number; indeterminateCount: number } {
  const rules = parseUfwChainRules(rulesText, chainName);
  let unusedCount = 0;
  let indeterminateCount = 0;

  for (const rule of rules) {
    // Non-terminating rules (no -j/-g, e.g. accounting or `recent --set`) cannot accept traffic.
    if (!rule.hasTarget) {
      continue;
    }
    if (rule.protocol === "other") {
      continue;
    }
    if (
      rule.jump === "DROP" ||
      rule.jump === "REJECT" ||
      rule.jump === "RETURN" ||
      rule.jump === "LOG" ||
      rule.jump === "ufw-user-logging-input" ||
      rule.jump === "ufw6-user-logging-input"
    ) {
      continue;
    }

    // ufw-user-limit / ufw6-user-limit is the throttle/reject half of `ufw limit`,
    // paired with ufw-user-limit-accept / ufw6-user-limit-accept (audited below).
    if (rule.jump !== undefined && UFW_RATE_LIMIT_DROP_JUMPS.has(rule.jump)) {
      if (rule.indeterminate) {
        indeterminateCount++;
      }
      continue;
    }

    const isAllowJump =
      rule.jump === "ACCEPT" ||
      (rule.jump !== undefined && UFW_RATE_LIMIT_ACCEPT_JUMPS.has(rule.jump));
    if (!isAllowJump) {
      indeterminateCount++;
      continue;
    }

    if (rule.indeterminate || !rule.dports || rule.dports.length === 0) {
      indeterminateCount++;
      continue;
    }

    if (rule.destination !== undefined && !isAllSourcesCidr(rule.destination, family)) {
      const validCidr =
        family === 4
          ? ipv4InCidr("0.0.0.0", rule.destination)
          : ipv6InCidr("::", rule.destination);
      if (validCidr === null) {
        indeterminateCount++;
        continue;
      }
    }

    const hasMatchingListener = listeners.some((listener) =>
      listenerMatchesAllowRule(listener, rule, family),
    );
    if (!hasMatchingListener) {
      unusedCount++;
    }
  }

  return { totalRules: rules.length, unusedCount, indeterminateCount };
}

// ---------------------------------------------------------------------------
// Tailscale Serve / Funnel parsing & classifyListeners
// ---------------------------------------------------------------------------

function parseTailscaleBackendTarget(target: string): TailscaleBackendTarget | null {
  const trimmed = target.trim();
  if (!trimmed) return null;

  const normalizeHost = (
    rawHost: string,
    isBracketed: boolean,
    port: number,
  ): TailscaleBackendTarget | null => {
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
    const host = rawHost.trim().toLowerCase();
    if (!host) return null;

    if (!isBracketed && host === "localhost") {
      return { host: "localhost", family: "localhost", port };
    }
    if (isBracketed || host.includes(":")) {
      if (ipv6ToBigInt(host) === null) return null;
      return { host, family: 6, port };
    }
    if (parseIpv4ToUint32(host) !== null) {
      return { host, family: 4, port };
    }
    // Reject non-local / remote hostnames.
    return null;
  };

  // URL form: http://127.0.0.1:8080, https://[::1]:8443/path, http+insecure://localhost:3000
  const urlMatch =
    /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/(?:\[([^\]]+)\]|([^/:@#?]+)):(\d{1,5})(?:[/?#]|$)/.exec(
      trimmed,
    );
  if (urlMatch) {
    const bracketedHost = urlMatch[1];
    const plainHost = urlMatch[2];
    const port = Number(urlMatch[3]);
    return normalizeHost(bracketedHost ?? plainHost ?? "", bracketedHost !== undefined, port);
  }

  // Host:port form: 127.0.0.1:8443, [::1]:8443, localhost:8443
  const hostPortMatch = /^(?:\[([^\]]+)\]|([^/:@#?]+)):(\d{1,5})$/.exec(trimmed);
  if (hostPortMatch) {
    const bracketedHost = hostPortMatch[1];
    const plainHost = hostPortMatch[2];
    const port = Number(hostPortMatch[3]);
    return normalizeHost(bracketedHost ?? plainHost ?? "", bracketedHost !== undefined, port);
  }

  // Port-only form: "8080" or ":8080"
  const portOnlyMatch = /^:?(\d{1,5})$/.exec(trimmed);
  if (portOnlyMatch) {
    const port = Number(portOnlyMatch[1]);
    return Number.isInteger(port) && port >= 1 && port <= 65535
      ? { host: null, family: "any", port }
      : null;
  }

  return null;
}

type TailscaleTargetMatch = "match" | "unknown" | "no_match";

const IPV4_LOOPBACK_ADDR = 0x7f000001; // 127.0.0.1

function tailscaleTargetMatchesListener(
  target: TailscaleBackendTarget,
  listener: Listener,
  knownLocalV4: ReadonlySet<number>,
  knownLocalV6: ReadonlySet<bigint>,
): TailscaleTargetMatch {
  if (target.port !== listener.port) return "no_match";

  if (target.family === "any" || target.host === null) {
    return "match";
  }

  if (target.family === "localhost") {
    return isLoopbackAddress(listener.address, listener.family) || isWildcardAddress(listener.address)
      ? "match"
      : "no_match";
  }

  if (target.family === 4) {
    const rawTargetNum = parseIpv4ToUint32(target.host);
    if (rawTargetNum === null) return "no_match";

    // Explicit 0.0.0.0 connects to 127.0.0.1 on Linux, not unrelated LAN/tailnet IPs.
    const targetNum = rawTargetNum === 0 ? IPV4_LOOPBACK_ADDR : rawTargetNum;
    if (rawTargetNum === 0 || isLoopbackAddress(target.host, 4)) {
      if (listener.family === 4) {
        return parseIpv4ToUint32(listener.address) === targetNum ||
          isWildcardAddress(listener.address)
          ? "match"
          : "no_match";
      }
      return listener.family === "unspecified" && isWildcardAddress(listener.address)
        ? "match"
        : "no_match";
    }

    // Explicit non-loopback IPv4: match exact listener IP; wildcard matches if proven local,
    // otherwise preserve unknown because host interface IPs are not enumerated.
    if (listener.family === 4 && parseIpv4ToUint32(listener.address) === targetNum) {
      return "match";
    }
    if (
      (listener.family === 4 || listener.family === "unspecified") &&
      isWildcardAddress(listener.address)
    ) {
      return knownLocalV4.has(targetNum) ? "match" : "unknown";
    }
    return "no_match";
  }

  // target.family === 6
  const rawTargetVal = ipv6ToBigInt(target.host);
  if (rawTargetVal === null) return "no_match";

  // Explicit [::] connects to [::1] on Linux, not unrelated IPv6/tailnet IPs.
  if (rawTargetVal === 0n || rawTargetVal === 1n) {
    if (listener.family === 6) {
      return isPureIpv6Loopback(listener.address) || isWildcardAddress(listener.address)
        ? "match"
        : "no_match";
    }
    return listener.family === "unspecified" && isWildcardAddress(listener.address)
      ? "match"
      : "no_match";
  }

  // Explicit non-loopback IPv6: match exact listener IP; wildcard matches if proven local,
  // otherwise preserve unknown because host interface IPs are not enumerated.
  if (listener.family === 6 && ipv6ToBigInt(listener.address) === rawTargetVal) {
    return "match";
  }
  if (
    (listener.family === 6 || listener.family === "unspecified") &&
    isWildcardAddress(listener.address)
  ) {
    return knownLocalV6.has(rawTargetVal) ? "match" : "unknown";
  }
  return "no_match";
}

const KNOWN_TAILSCALE_SERVE_KEYS = new Set([
  "Web",
  "TCP",
  "AllowFunnel",
  "Foreground",
  "Services",
]);
const MAX_TAILSCALE_CONFIG_DEPTH = 4;

function collectTargetsFromTailscaleJson(
  rawJson: unknown,
  funnelOnly: boolean,
): {
  serve: TailscaleBackendTarget[];
  funnel: TailscaleBackendTarget[];
  hasUnknownKeys: boolean;
} | null {
  if (typeof rawJson !== "object" || rawJson === null || Array.isArray(rawJson)) {
    return null;
  }

  const serve: TailscaleBackendTarget[] = [];
  const funnel: TailscaleBackendTarget[] = [];
  let hasUnknownKeys = false;

  const visitConfig = (
    config: Record<string, unknown>,
    inheritedAllowFunnel: ReadonlyMap<string, boolean>,
    depth: number,
  ) => {
    for (const key of Object.keys(config)) {
      if (!KNOWN_TAILSCALE_SERVE_KEYS.has(key)) {
        hasUnknownKeys = true;
      }
    }

    const allowFunnelMap = new Map<string, boolean>(inheritedAllowFunnel);
    if (config.AllowFunnel !== undefined && config.AllowFunnel !== null) {
      if (typeof config.AllowFunnel === "object" && !Array.isArray(config.AllowFunnel)) {
        for (const [hostPort, allowed] of Object.entries(
          config.AllowFunnel as Record<string, unknown>,
        )) {
          if (typeof allowed === "boolean") {
            allowFunnelMap.set(hostPort, allowed);
          }
        }
      } else {
        hasUnknownKeys = true;
      }
    }

    if (typeof config.Web === "object" && config.Web !== null && !Array.isArray(config.Web)) {
      for (const [hostPort, webConfig] of Object.entries(config.Web as Record<string, unknown>)) {
        if (typeof webConfig !== "object" || webConfig === null || Array.isArray(webConfig)) {
          continue;
        }
        const handlers = (webConfig as Record<string, unknown>).Handlers;
        if (typeof handlers !== "object" || handlers === null || Array.isArray(handlers)) {
          continue;
        }
        const isFunnelHost = allowFunnelMap.get(hostPort) === true;
        for (const handler of Object.values(handlers as Record<string, unknown>)) {
          if (typeof handler !== "object" || handler === null || Array.isArray(handler)) {
            continue;
          }
          const proxy = (handler as Record<string, unknown>).Proxy;
          if (typeof proxy !== "string") continue;
          const parsedTarget = parseTailscaleBackendTarget(proxy);
          if (parsedTarget === null) continue;
          if (isFunnelHost) {
            funnel.push(parsedTarget);
          } else if (!funnelOnly) {
            serve.push(parsedTarget);
          }
        }
      }
    }

    if (typeof config.TCP === "object" && config.TCP !== null && !Array.isArray(config.TCP)) {
      for (const [listenPort, tcpConfig] of Object.entries(
        config.TCP as Record<string, unknown>,
      )) {
        if (typeof tcpConfig !== "object" || tcpConfig === null || Array.isArray(tcpConfig)) {
          continue;
        }
        const forward = (tcpConfig as Record<string, unknown>).TCPForward;
        if (typeof forward !== "string") continue;
        const parsedTarget = parseTailscaleBackendTarget(forward);
        if (parsedTarget === null) continue;
        const isFunnelTcp = [...allowFunnelMap.entries()].some(
          ([hostPort, allowed]) => allowed && hostPort.endsWith(`:${listenPort}`),
        );
        if (isFunnelTcp) {
          funnel.push(parsedTarget);
        } else if (!funnelOnly) {
          serve.push(parsedTarget);
        }
      }
    }

    const visitNestedMap = (nested: unknown) => {
      if (nested === undefined || nested === null) return;
      if (typeof nested !== "object" || Array.isArray(nested)) {
        hasUnknownKeys = true;
        return;
      }
      if (depth >= MAX_TAILSCALE_CONFIG_DEPTH) {
        hasUnknownKeys = true;
        return;
      }
      for (const child of Object.values(nested as Record<string, unknown>)) {
        if (typeof child === "object" && child !== null && !Array.isArray(child)) {
          visitConfig(child as Record<string, unknown>, allowFunnelMap, depth + 1);
        }
      }
    };

    visitNestedMap(config.Foreground);
    visitNestedMap(config.Services);
  };

  visitConfig(rawJson as Record<string, unknown>, new Map(), 0);
  return { serve, funnel, hasUnknownKeys };
}

export function parseTailscalePublications(
  serveResult: CommandResult | undefined,
  funnelResult: CommandResult | undefined,
): TailscalePublications {
  const servePorts = new Set<number>();
  const funnelPorts = new Set<number>();
  const serveTargets: TailscaleBackendTarget[] = [];
  const funnelTargets: TailscaleBackendTarget[] = [];
  let serveCoverage: Coverage = "unavailable";
  let funnelCoverage: Coverage = "unavailable";
  const tailscaleAbsent =
    serveResult?.status === "unavailable" && funnelResult?.status === "unavailable";

  if (serveResult?.status === "ok") {
    try {
      const parsed = JSON.parse(serveResult.stdout || "{}");
      const extracted = collectTargetsFromTailscaleJson(parsed, false);
      if (extracted) {
        serveCoverage = extracted.hasUnknownKeys ? "partial" : "complete";
        for (const t of extracted.serve) {
          serveTargets.push(t);
          servePorts.add(t.port);
        }
        for (const t of extracted.funnel) {
          funnelTargets.push(t);
          funnelPorts.add(t.port);
        }
      }
    } catch {
      serveCoverage = "unavailable";
    }
  }

  if (funnelResult?.status === "ok") {
    try {
      const parsed = JSON.parse(funnelResult.stdout || "{}");
      const extracted = collectTargetsFromTailscaleJson(parsed, true);
      if (extracted) {
        funnelCoverage = extracted.hasUnknownKeys ? "partial" : "complete";
        for (const t of extracted.funnel) {
          funnelTargets.push(t);
          funnelPorts.add(t.port);
        }
      }
    } catch {
      funnelCoverage = "unavailable";
    }
  }

  return {
    servePorts,
    funnelPorts,
    serveTargets,
    funnelTargets,
    serveCoverage,
    funnelCoverage,
    tailscaleAbsent,
  };
}

export function classifyListeners(options: ClassifyListenersOptions): ExposureEntry[] {
  const { listeners, firewall, publications, expectedPorts, evidenceIdForListener } = options;

  const knownLocalV4 = new Set<number>();
  const knownLocalV6 = new Set<bigint>();
  for (const listener of listeners) {
    if (listener.family === 4 && !isWildcardAddress(listener.address)) {
      const num = parseIpv4ToUint32(listener.address);
      if (num !== null) knownLocalV4.add(num);
    } else if (listener.family === 6 && !isWildcardAddress(listener.address)) {
      const val = ipv6ToBigInt(listener.address);
      if (val !== null) knownLocalV6.add(val);
    }
  }

  const preliminary = listeners.map((listener, index) => {
    const firewallV4: ExposureEntry["firewallV4"] =
      listener.family === 4
        ? evaluateFirewall(listener, firewall)
        : listener.family === "unspecified"
          ? evaluateFirewall(
              {
                ...listener,
                family: 4,
                address: listener.address === "*" ? "0.0.0.0" : listener.address,
              },
              firewall,
            )
          : "na";

    const firewallV6: ExposureEntry["firewallV6"] =
      listener.family === 6
        ? evaluateFirewall(listener, firewall)
        : listener.family === "unspecified"
          ? evaluateFirewall(
              {
                ...listener,
                family: 6,
                address: listener.address === "*" ? "::" : listener.address,
              },
              firewall,
            )
          : "na";

    let funnelMatch: TailscaleTargetMatch = "no_match";
    for (const target of publications.funnelTargets) {
      const m = tailscaleTargetMatchesListener(target, listener, knownLocalV4, knownLocalV6);
      if (m === "match") {
        funnelMatch = "match";
        break;
      }
      if (m === "unknown") {
        funnelMatch = "unknown";
      }
    }

    let serveMatch: TailscaleTargetMatch = "no_match";
    for (const target of publications.serveTargets) {
      const m = tailscaleTargetMatchesListener(target, listener, knownLocalV4, knownLocalV6);
      if (m === "match") {
        serveMatch = "match";
        break;
      }
      if (m === "unknown") {
        serveMatch = "unknown";
      }
    }

    let publication: ExposureEntry["publication"];
    if (listener.protocol !== "tcp") {
      publication = "none";
    } else if (publications.tailscaleAbsent) {
      publication = "none";
    } else if (funnelMatch === "match") {
      publication = "funnel";
    } else if (funnelMatch === "unknown" || publications.funnelCoverage !== "complete") {
      publication = "unknown";
    } else if (serveMatch === "match") {
      publication = "serve";
    } else if (serveMatch === "unknown" || publications.serveCoverage !== "complete") {
      publication = "unknown";
    } else {
      publication = "none";
    }

    const loopback = isLoopbackAddress(listener.address, listener.family);
    const tailnet = !loopback && isTailnetListener(listener);

    return {
      listener,
      index,
      firewallV4,
      firewallV6,
      publication,
      loopback,
      tailnet,
    };
  });

  // Track (protocol, port) pairs exposed via both IPv4 and IPv6 sockets.
  const v4AllowedKeys = new Set<string>();
  const v6AllowedKeys = new Set<string>();
  for (const item of preliminary) {
    if (item.loopback || item.tailnet) continue;
    const key = `${item.listener.protocol}:${item.listener.port}`;
    if (item.firewallV4 === "allow") {
      v4AllowedKeys.add(key);
    }
    if (item.firewallV6 === "allow") {
      v6AllowedKeys.add(key);
    }
  }

  return preliminary.map((item) => {
    const { listener, index, firewallV4, firewallV6, publication, loopback, tailnet } = item;
    const key = `${listener.protocol}:${listener.port}`;
    let reachability: ExposureEntry["reachability"];

    if (publication === "funnel") {
      reachability = "exposed_v4_v6";
    } else if (loopback) {
      reachability =
        publication === "serve"
          ? "tailnet"
          : publication === "unknown"
            ? "unknown"
            : "local_only";
    } else if (tailnet) {
      reachability = publication === "unknown" ? "unknown" : "tailnet";
    } else if (listener.family === "unspecified") {
      if (firewallV4 === "allow" && firewallV6 === "allow") {
        reachability = "exposed_v4_v6";
      } else if (firewallV4 === "allow" || firewallV6 === "allow") {
        reachability =
          v4AllowedKeys.has(key) && v6AllowedKeys.has(key) ? "exposed_v4_v6" : "exposed_lan";
      } else if (firewallV4 === "deny" && firewallV6 === "deny") {
        reachability =
          publication === "serve"
            ? "tailnet"
            : publication === "unknown"
              ? "unknown"
              : "blocked_by_ufw";
      } else {
        reachability = "unknown";
      }
    } else {
      const fw = listener.family === 4 ? firewallV4 : firewallV6;
      if (fw === "deny") {
        reachability =
          publication === "serve"
            ? "tailnet"
            : publication === "unknown"
              ? "unknown"
              : "blocked_by_ufw";
      } else if (fw === "allow") {
        reachability =
          v4AllowedKeys.has(key) && v6AllowedKeys.has(key) ? "exposed_v4_v6" : "exposed_lan";
      } else {
        reachability = "unknown";
      }
    }

    return {
      id: `exposure:${listener.id}`,
      listener,
      reachability,
      firewallV4,
      firewallV6,
      publication,
      expected: expectedPorts.has(listener.port),
      evidenceIds: [evidenceIdForListener(listener, index)],
    };
  });
}

// ---------------------------------------------------------------------------
// SSH config parser (OpenSSH first-value-wins + in-place lexical Include + Match)
// ---------------------------------------------------------------------------

interface ParsedSshdConfig {
  permitRootLogin: string | null;
  passwordAuthentication: string | null;
  kbdInteractiveAuthentication: string | null;
  ports: number[];
  hasMatchLoosening: boolean;
  includeReferenced: boolean;
  dropInsMissing: boolean;
  hasUnhandledInclude: boolean;
  hasUnmatchedDropInInclude: boolean;
}

function extractSshdDropInGlob(pattern: string): string | null {
  const normalized = pattern.trim().replace(/^["']|["']$/g, "");
  let remainder: string | null = null;
  if (normalized.startsWith("/etc/ssh/sshd_config.d/")) {
    remainder = normalized.slice("/etc/ssh/sshd_config.d/".length);
  } else if (normalized.startsWith("sshd_config.d/")) {
    remainder = normalized.slice("sshd_config.d/".length);
  }
  if (!remainder || remainder.includes("/") || remainder === "." || remainder === "..") {
    return null;
  }
  return remainder;
}

function matchGlob(pattern: string, candidate: string): boolean {
  const collapsed = pattern.replace(/\*+/g, "*");
  let regex = "^";
  for (let i = 0; i < collapsed.length; i++) {
    const ch = collapsed[i]!;
    if (ch === "*") {
      regex += ".*";
    } else if (ch === "?") {
      regex += ".";
    } else if (ch === "[") {
      const close = collapsed.indexOf("]", i + 1);
      if (close > i + 1) {
        let content = collapsed.slice(i + 1, close);
        if (content.startsWith("!")) {
          content = "^" + content.slice(1);
        }
        regex += `[${content.replace(/[\\[\]]/g, "\\$&")}]`;
        i = close;
      } else {
        regex += "\\[";
      }
    } else {
      regex += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  regex += "$";
  return new RegExp(regex).test(candidate);
}

function parseSshdDirective(line: string): { key: string; value: string; rawValue: string } | null {
  // Strip comments (respecting quotes)
  let clean = "";
  let inQuote = false;
  let quoteChar = "";
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (inQuote) {
      if (ch === quoteChar) inQuote = false;
      clean += ch;
    } else if (ch === '"' || ch === "'") {
      inQuote = true;
      quoteChar = ch;
      clean += ch;
    } else if (ch === "#") {
      break;
    } else {
      clean += ch;
    }
  }
  const trimmed = clean.trim();
  if (!trimmed) return null;

  const match = /^([A-Za-z][A-Za-z0-9]*)(?:[\s=]+)(.+)$/.exec(trimmed);
  if (!match) return null;
  const rawValue = match[2]!.trim();
  return {
    key: match[1]!.toLowerCase(),
    value: rawValue.replace(/^["']|["']$/g, ""),
    rawValue,
  };
}

function parseSshdConfig(
  mainText: string,
  dropIns: readonly SshDropIn[] | null,
): ParsedSshdConfig {
  const globals = new Map<string, string>();
  const ports: number[] = [];
  let hasMatchLoosening = false;
  let includeReferenced = false;
  let dropInsMissing = false;
  let hasUnhandledInclude = false;
  let hasUnmatchedDropInInclude = false;

  const sortedDropIns =
    dropIns !== null ? [...dropIns].sort((a, b) => lexicalCompare(a.name, b.name)) : null;

  const processLines = (text: string, allowInclude: boolean) => {
    let matchScope: "none" | "all" | "conditional" = "none";
    for (const rawLine of text.split(/\r?\n/)) {
      const directive = parseSshdDirective(rawLine);
      if (!directive) continue;

      const { key, value, rawValue } = directive;
      const lowerVal = value.toLowerCase();

      if (key === "match") {
        matchScope = lowerVal === "all" ? "all" : "conditional";
        continue;
      }

      if (key === "include") {
        includeReferenced = true;
        if (!allowInclude || matchScope !== "none") {
          hasUnhandledInclude = true;
          continue;
        }
        const patterns = tokenizeRule(rawValue);
        if (!patterns || patterns.length === 0) {
          hasUnhandledInclude = true;
          continue;
        }
        for (const pattern of patterns) {
          const filePattern = extractSshdDropInGlob(pattern);
          if (filePattern === null) {
            hasUnhandledInclude = true;
            continue;
          }
          if (sortedDropIns === null) {
            dropInsMissing = true;
            continue;
          }
          const matched = sortedDropIns.filter((dropIn) => matchGlob(filePattern, dropIn.name));
          for (const dropIn of matched) {
            processLines(dropIn.text, false);
          }
          if (!filePattern.endsWith(".conf")) {
            hasUnhandledInclude = true;
          } else if (matched.length === 0) {
            hasUnmatchedDropInInclude = true;
          }
        }
        continue;
      }

      if (matchScope === "all") {
        // `Match all` applies to every connection and overrides global settings for loosening directives.
        if (key === "passwordauthentication" && lowerVal === "yes") {
          globals.set("passwordauthentication", "yes");
        } else if (key === "permitrootlogin" && lowerVal !== "no") {
          if (lowerVal === "yes" || globals.get("permitrootlogin") !== "yes") {
            globals.set("permitrootlogin", lowerVal);
          }
        } else if (
          (key === "kbdinteractiveauthentication" || key === "challengeresponseauthentication") &&
          lowerVal === "yes"
        ) {
          globals.set("kbdinteractiveauthentication", "yes");
        }
        continue;
      }

      if (matchScope === "conditional") {
        if (
          (key === "passwordauthentication" && lowerVal === "yes") ||
          (key === "permitrootlogin" && lowerVal !== "no") ||
          ((key === "kbdinteractiveauthentication" || key === "challengeresponseauthentication") &&
            lowerVal === "yes")
        ) {
          hasMatchLoosening = true;
        }
        continue;
      }

      if (key === "port") {
        const parsedPort = Number(value);
        if (Number.isInteger(parsedPort) && parsedPort >= 1 && parsedPort <= 65535) {
          if (!ports.includes(parsedPort)) {
            ports.push(parsedPort);
          }
        }
        continue;
      }

      // OpenSSH first-value-wins semantics. Normalize ChallengeResponseAuthentication
      // to KbdInteractiveAuthentication before checking globals so the earlier directive wins.
      const effectiveKey =
        key === "challengeresponseauthentication" ? "kbdinteractiveauthentication" : key;
      if (!globals.has(effectiveKey)) {
        globals.set(effectiveKey, lowerVal);
      }
    }
  };

  processLines(mainText, true);

  return {
    permitRootLogin: globals.get("permitrootlogin") ?? null,
    passwordAuthentication: globals.get("passwordauthentication") ?? null,
    kbdInteractiveAuthentication: globals.get("kbdinteractiveauthentication") ?? null,
    ports: ports.length > 0 ? ports : [22],
    hasMatchLoosening,
    includeReferenced,
    dropInsMissing,
    hasUnhandledInclude,
    hasUnmatchedDropInInclude,
  };
}

// ---------------------------------------------------------------------------
// Package updates, pacman log, and arch-audit parsers
// ---------------------------------------------------------------------------

interface ParsedUpdates {
  totalCount: number;
  kernelCount: number;
}

function parsePacmanUpdates(stdout: string, exitCode: number): ParsedUpdates {
  if (exitCode === 1 && stdout.trim().length === 0) {
    return { totalCount: 0, kernelCount: 0 };
  }
  let totalCount = 0;
  let kernelCount = 0;
  for (const rawLine of stdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const pkg = line.split(/\s+/)[0] ?? "";
    if (!pkg) continue;
    totalCount++;
    if (pkg === "linux" || pkg.startsWith("linux-")) {
      kernelCount++;
    }
  }
  return { totalCount, kernelCount };
}

function parsePacmanLogLastUpgrade(text: string): number | null {
  let latest: number | null = null;
  for (const rawLine of text.split(/\r?\n/)) {
    if (!rawLine.includes("[ALPM]")) continue;
    if (
      !rawLine.includes("[ALPM] upgraded ") &&
      !rawLine.includes("[ALPM] starting full system upgrade")
    ) {
      continue;
    }
    const stampMatch = /^\[([^\]]+)\]/.exec(rawLine.trim());
    if (!stampMatch) continue;
    const normalized = stampMatch[1]!
      .replace(" ", "T")
      .replace(/([+-]\d{2})(\d{2})$/, "$1:$2");
    const parsed = Date.parse(normalized);
    if (!Number.isNaN(parsed) && (latest === null || parsed > latest)) {
      latest = parsed;
    }
  }
  return latest;
}

interface ParsedArchAudit {
  advisoryCount: number;
  highOrCriticalCount: number;
}

function parseArchAudit(stdout: string): ParsedArchAudit {
  let advisoryCount = 0;
  let highOrCriticalCount = 0;

  const lines = stdout.split(/\r?\n/);
  let foundStructured = false;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;
    if (/^Package:\s*\S+/i.test(line)) {
      foundStructured = true;
      advisoryCount++;
      continue;
    }
    const sevMatch = /^Severity:\s*(\S+)/i.exec(line);
    if (sevMatch) {
      const sev = sevMatch[1]!.toLowerCase();
      if (sev === "high" || sev === "critical") {
        highOrCriticalCount++;
      }
    }
  }

  if (!foundStructured) {
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line) continue;
      if (/^Package\s+\S+\s+is affected by\b/i.test(line) || /\bCVE-\d{4}-\d+\b/i.test(line)) {
        advisoryCount++;
        if (/\b(?:high|critical)\s+risk\b/i.test(line)) {
          highOrCriticalCount++;
        }
      }
    }
  }

  return { advisoryCount, highOrCriticalCount };
}

// ---------------------------------------------------------------------------
// Disk (`lsblk -J`) & Boot (`bootctl status`) parsers
// ---------------------------------------------------------------------------

interface LsblkNode {
  name?: unknown;
  type?: unknown;
  fstype?: unknown;
  mountpoint?: unknown;
  mountpoints?: unknown;
  children?: unknown;
}

interface ParsedBlockDevices {
  rootEncrypted: boolean | null;
  unencryptedSecondaryCount: number;
  mountedCount: number;
}

const IGNORED_UNENCRYPTED_MOUNTS = new Set(["/boot", "/boot/efi", "/efi", "[SWAP]"]);
const IGNORED_PSEUDO_FSTYPES = new Set(["squashfs", "iso9660", "tmpfs", "devtmpfs", "proc", "sysfs"]);

function parseBlockDevices(stdout: string): ParsedBlockDevices | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return null;
  }
  const devices = (parsed as { blockdevices?: unknown }).blockdevices;
  if (!Array.isArray(devices)) {
    return null;
  }

  let rootEncrypted: boolean | null = null;
  let unencryptedSecondaryCount = 0;
  let mountedCount = 0;

  const visit = (node: unknown, ancestorEncrypted: boolean) => {
    if (typeof node !== "object" || node === null || Array.isArray(node)) return;
    const dev = node as LsblkNode;
    const type = typeof dev.type === "string" ? dev.type.toLowerCase() : "";
    const fstype = typeof dev.fstype === "string" ? dev.fstype : "";
    const isEncrypted = ancestorEncrypted || type === "crypt" || fstype === "crypto_LUKS";

    const mountpoints: string[] = [];
    if (typeof dev.mountpoint === "string" && dev.mountpoint.length > 0) {
      mountpoints.push(dev.mountpoint);
    }
    if (Array.isArray(dev.mountpoints)) {
      for (const mp of dev.mountpoints) {
        if (typeof mp === "string" && mp.length > 0 && !mountpoints.includes(mp)) {
          mountpoints.push(mp);
        }
      }
    }

    for (const mp of mountpoints) {
      mountedCount++;
      if (mp === "/") {
        rootEncrypted = isEncrypted;
      } else if (
        !isEncrypted &&
        !IGNORED_UNENCRYPTED_MOUNTS.has(mp) &&
        !IGNORED_PSEUDO_FSTYPES.has(fstype.toLowerCase()) &&
        type !== "loop" &&
        type !== "rom"
      ) {
        unencryptedSecondaryCount++;
      }
    }

    if (Array.isArray(dev.children)) {
      for (const child of dev.children) {
        visit(child, isEncrypted);
      }
    }
  };

  for (const device of devices) {
    visit(device, false);
  }

  return { rootEncrypted, unencryptedSecondaryCount, mountedCount };
}

interface ParsedBootStatus {
  secureBoot: "enabled" | "disabled" | "unknown";
  tpm2: "yes" | "no" | "unknown";
}

function parseBootStatus(stdout: string): ParsedBootStatus {
  let secureBoot: ParsedBootStatus["secureBoot"] = "unknown";
  let tpm2: ParsedBootStatus["tpm2"] = "unknown";

  for (const rawLine of stdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    const sbMatch = /^Secure Boot:\s*(.+)$/i.exec(line);
    if (sbMatch) {
      const val = sbMatch[1]!.trim().toLowerCase();
      if (val.startsWith("enabled")) secureBoot = "enabled";
      else if (val.startsWith("disabled")) secureBoot = "disabled";
      continue;
    }

    const tpmMatch = /^TPM2 Support:\s*(.+)$/i.exec(line);
    if (tpmMatch) {
      const val = tpmMatch[1]!.trim().toLowerCase();
      if (val.startsWith("yes")) tpm2 = "yes";
      else if (val.startsWith("no")) tpm2 = "no";
    }
  }

  return { secureBoot, tpm2 };
}

// ---------------------------------------------------------------------------
// Sysctl parser
// ---------------------------------------------------------------------------

interface SysctlPolicy {
  key: string;
  isSafe: (value: number) => boolean;
}

const SYSCTL_POLICIES: readonly SysctlPolicy[] = [
  { key: "kernel.kptr_restrict", isSafe: (v) => v >= 1 },
  { key: "kernel.dmesg_restrict", isSafe: (v) => v === 1 },
  { key: "kernel.unprivileged_bpf_disabled", isSafe: (v) => v >= 1 },
  { key: "kernel.yama.ptrace_scope", isSafe: (v) => v >= 1 },
  { key: "kernel.kexec_load_disabled", isSafe: (v) => v === 1 },
  { key: "fs.suid_dumpable", isSafe: (v) => v === 0 },
  { key: "net.ipv4.conf.all.rp_filter", isSafe: (v) => v === 1 || v === 2 },
  { key: "net.ipv4.conf.all.accept_redirects", isSafe: (v) => v === 0 },
  { key: "net.ipv6.conf.all.accept_redirects", isSafe: (v) => v === 0 },
];

interface ParsedSysctl {
  observed: Map<string, number>;
  missingKeys: string[];
  unsafeKeys: string[];
}

function parseSysctl(stdout: string): ParsedSysctl {
  const observed = new Map<string, number>();

  for (const rawLine of stdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^([A-Za-z0-9_.-]+)\s*=\s*(-?\d+)$/.exec(line);
    if (!match) continue;
    observed.set(match[1]!, Number.parseInt(match[2]!, 10));
  }

  const missingKeys: string[] = [];
  const unsafeKeys: string[] = [];

  for (const policy of SYSCTL_POLICIES) {
    const value = observed.get(policy.key);
    if (value === undefined) {
      missingKeys.push(policy.key);
    } else if (!policy.isSafe(value)) {
      unsafeKeys.push(policy.key);
    }
  }

  return { observed, missingKeys, unsafeKeys };
}

// ---------------------------------------------------------------------------
// Systemd units, processes, and user timers parsers
// ---------------------------------------------------------------------------

interface ParsedUnit {
  unit: string;
  load: string;
  active: string;
  sub: string;
}

function parseSystemdUnits(stdout: string): ParsedUnit[] {
  const units: ParsedUnit[] = [];
  for (const rawLine of stdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 4) continue;
    const unit = sanitizeToken(parts[0]!, 128);
    const load = sanitizeToken(parts[1]!, 32).toLowerCase();
    const active = sanitizeToken(parts[2]!, 32).toLowerCase();
    const sub = sanitizeToken(parts[3]!, 32).toLowerCase();
    if (!unit.includes(".")) continue;
    units.push({ unit, load, active, sub });
  }
  return units;
}

interface ParsedProcess {
  pid: number;
  ppid: number;
  uid: number;
  startedAt: number;
  comm: string;
  hasUnitMetadata: boolean;
  unit?: string;
  uunit?: string;
}

function parseProcesses(stdout: string, nowMs: number): Map<number, ParsedProcess> {
  const map = new Map<number, ParsedProcess>();
  for (const rawLine of stdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const match = /^(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/.exec(line);
    if (!match) continue;
    const pid = Number(match[1]);
    const ppid = Number(match[2]);
    const uid = Number(match[3]);
    const etimes = Number(match[4]);
    const rest = match[5]!.trim();
    let hasUnitMetadata = false;
    let unit: string | undefined;
    let uunit: string | undefined;
    let commRaw = rest;
    const isUnitToken = (tok: string): boolean => tok === "-" || isValidSystemdUnitName(tok);
    const firstSpace = rest.search(/\s/);
    if (firstSpace !== -1) {
      const firstTok = rest.slice(0, firstSpace);
      const afterFirst = rest.slice(firstSpace).trim();
      if (afterFirst.length > 0 && isUnitToken(firstTok)) {
        hasUnitMetadata = true;
        unit = firstTok === "-" ? undefined : firstTok;
        commRaw = afterFirst;
        const secondSpace = afterFirst.search(/\s/);
        if (secondSpace !== -1) {
          const secondTok = afterFirst.slice(0, secondSpace);
          const afterSecond = afterFirst.slice(secondSpace).trim();
          if (afterSecond.length > 0 && isUnitToken(secondTok)) {
            uunit = secondTok === "-" ? undefined : secondTok;
            commRaw = afterSecond;
          }
        }
      }
    }
    const comm = sanitizeProcessComm(commRaw);
    if (!Number.isInteger(pid) || pid <= 0 || comm.length === 0) continue;
    map.set(pid, {
      pid,
      ppid,
      uid,
      startedAt: nowMs - etimes * 1000,
      comm,
      hasUnitMetadata,
      ...(unit !== undefined ? { unit } : {}),
      ...(uunit !== undefined ? { uunit } : {}),
    });
  }
  return map;
}

const COLLECTOR_UNIT_SUFFIXES = [
  ".service",
  ".scope",
  ".slice",
  ".socket",
  ".timer",
  ".mount",
  ".target",
  ".path",
  ".device",
  ".swap",
  ".automount",
] as const;

function collectorUnitStem(unit: string): string {
  let base = unit.trim();
  for (const suffix of COLLECTOR_UNIT_SUFFIXES) {
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

function matchEnrolledWorkloadForCollector(
  listener: Listener,
  proc: ParsedProcess | undefined,
  workloads: readonly EnrolledWorkload[],
): EnrolledWorkload | null {
  if (workloads.length === 0) {
    return null;
  }

  if (proc?.hasUnitMetadata) {
    const unitMatches = workloads.filter((workload) => {
      const expectedUnit = workload.unit.trim();
      return proc.uunit === expectedUnit || proc.unit === expectedUnit;
    });
    if (unitMatches.length === 1) {
      return unitMatches[0]!;
    }
    return null;
  }

  const rawName = (proc?.comm ?? listener.process)?.trim().toLowerCase();
  if (!rawName) return null;

  const matches: EnrolledWorkload[] = [];
  for (const workload of workloads) {
    const names = new Set<string>();
    const idNorm = workload.id.trim().toLowerCase();
    if (idNorm) names.add(idNorm);
    const nameNorm = workload.name?.trim().toLowerCase();
    if (nameNorm) names.add(nameNorm);
    const stem = collectorUnitStem(workload.unit);
    if (stem) names.add(stem);
    if (names.has(rawName)) {
      matches.push(workload);
    }
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

interface ParsedTimer {
  timerUnit: string;
  activatesUnit: string | null;
}

function parseUserTimers(stdout: string): ParsedTimer[] {
  const timers: ParsedTimer[] = [];
  for (const rawLine of stdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    const timerIdx = parts.findIndex((tok) => tok.endsWith(".timer"));
    if (timerIdx < 0) continue;
    const timerUnit = sanitizeToken(parts[timerIdx]!, 128);
    const activatesRaw = parts[timerIdx + 1];
    const activatesUnit =
      activatesRaw && activatesRaw.includes(".") ? sanitizeToken(activatesRaw, 128) : null;
    timers.push({ timerUnit, activatesUnit });
  }
  return timers;
}

// ---------------------------------------------------------------------------
// Bounded concurrency helper
// ---------------------------------------------------------------------------

async function runWithConcurrency(
  tasks: readonly (() => Promise<void>)[],
  concurrency: number,
): Promise<void> {
  const limit = Math.max(1, Math.min(concurrency, tasks.length || 1));
  let cursor = 0;

  const workers = Array.from({ length: limit }, async () => {
    for (;;) {
      const idx = cursor++;
      if (idx >= tasks.length) return;
      await tasks[idx]!();
    }
  });

  await Promise.all(workers);
}

// ---------------------------------------------------------------------------
// PostureCollector
// ---------------------------------------------------------------------------

type SimpleCommandKind = Extract<
  CommandRequest,
  {
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
>["kind"];

const CRITERION_META: Record<CriterionId, { category: Category | "host"; title: string }> = {
  firewall_ufw: { category: "firewall", title: "Firewall (UFW)" },
  network_exposure: { category: "network", title: "Network Exposure" },
  ssh_hardening: { category: "auth", title: "SSH Hardening" },
  package_updates: { category: "packages", title: "Package Updates" },
  disk_and_boot: { category: "host", title: "Disk & Boot" },
  kernel_sysctl: { category: "host", title: "Kernel Hardening (sysctl)" },
  systemd_health: { category: "units", title: "Systemd Health" },
  process_and_timers: { category: "host", title: "Processes & User Timers" },
};

interface EvaluationContext {
  capturedAt: number;
  commandResults: ReadonlyMap<SimpleCommandKind, CommandResult>;
  fileResults: ReadonlyMap<PostureFileSource, string | null>;
  sshDropInsResult: readonly SshDropIn[] | null;
  socketsAvailable: boolean;
  listeners: readonly Listener[];
  processMap: ReadonlyMap<number, ParsedProcess> | null;
  workloads: readonly EnrolledWorkload[];
  emittedProcessPids: Set<number>;
  ufwStatusRes: CommandResult | undefined;
  ufwStatusParsed: ParsedUfwStatus | null;
  ufwDefaultParsed: ParsedUfwDefault | null;
  ufwDefaultCoverage: Coverage;
  ufwV4Text: string | null;
  ufwV6Text: string | null;
  effectiveDefaultInput: "allow" | "deny" | "unknown";
  firewallInputs: FirewallInputs;
  publications: TailscalePublications;
  expectedPortSet: ReadonlySet<number>;
  exposure: readonly ExposureEntry[];
  addEvidence: (kind: Evidence["kind"], slug: string, facts: Facts) => string;
  addFinding: (
    criterionId: CriterionId,
    slug: string,
    severity: Severity,
    summary: string,
    evidenceIds: string[],
  ) => void;
}

function evaluateFirewallUfw(ctx: EvaluationContext): PostureCheck {
  const id: CriterionId = "firewall_ufw";
  const meta = CRITERION_META[id];
  const {
    socketsAvailable,
    listeners,
    ufwStatusRes,
    ufwStatusParsed,
    ufwDefaultParsed,
    ufwDefaultCoverage,
    ufwV4Text,
    ufwV6Text,
    effectiveDefaultInput,
    firewallInputs,
    addEvidence,
    addFinding,
  } = ctx;

  const v4RulesComplete = ufwV4Text !== null && ufwV4Text.trim().length > 0;
  const v6RulesComplete = ufwV6Text !== null && ufwV6Text.trim().length > 0;
  const v6Enabled = ufwDefaultParsed?.ipv6Enabled ?? null;

  const v4Stats =
    socketsAvailable && v4RulesComplete
      ? countUnusedAllowRules(ufwV4Text!, "ufw-user-input", 4, listeners)
      : null;
  const v6Stats =
    socketsAvailable && v6RulesComplete && v6Enabled === true
      ? countUnusedAllowRules(ufwV6Text!, "ufw6-user-input", 6, listeners)
      : null;

  const indeterminateAllowRuleCount =
    (v4Stats?.indeterminateCount ?? 0) + (v6Stats?.indeterminateCount ?? 0);

  const unusedRulesCoverageComplete =
    socketsAvailable &&
    v4RulesComplete &&
    (v6Enabled === false || (v6Enabled === true && v6RulesComplete)) &&
    indeterminateAllowRuleCount === 0;

  const sourceCoverage: Record<string, Coverage> = {
    ufw_status: firewallInputs.active !== null ? "complete" : "unavailable",
    ufw_default: ufwDefaultCoverage,
    ufw_v4: !v4RulesComplete
      ? "unavailable"
      : (v4Stats?.indeterminateCount ?? 0) > 0
        ? "partial"
        : "complete",
    ufw_v6: !v6RulesComplete
      ? "unavailable"
      : (v6Stats?.indeterminateCount ?? 0) > 0
        ? "partial"
        : "complete",
    sockets: socketsAvailable ? "complete" : "unavailable",
    rule_audit: unusedRulesCoverageComplete
      ? "complete"
      : v4Stats || v6Stats
        ? "partial"
        : "unavailable",
  };

  const unusedAllowRuleCount = (v4Stats?.unusedCount ?? 0) + (v6Stats?.unusedCount ?? 0);

  const evId = addEvidence("criterion", "firewall_ufw", {
    criterionId: "firewall_ufw",
    criterion: "firewall_ufw",
    active: firewallInputs.active,
    defaultInput: effectiveDefaultInput,
    ipv6Enabled: v6Enabled,
    v4RuleCount: v4Stats?.totalRules ?? null,
    v6RuleCount: v6Stats?.totalRules ?? null,
    unusedAllowRuleCount: v4Stats || v6Stats ? unusedAllowRuleCount : null,
    indeterminateAllowRuleCount: v4Stats || v6Stats ? indeterminateAllowRuleCount : null,
  });

  let status: PostureCheck["status"];
  let summary: string;
  let remediation: string | undefined;

  if (firewallInputs.active === null) {
    status = "unknown";
    summary = "UFW status could not be determined.";
  } else if (!firewallInputs.active) {
    status = "fail";
    summary = "UFW firewall is inactive.";
    remediation = "Enable UFW with default deny incoming policy (`ufw enable`).";
    addFinding(id, "inactive", "critical", summary, [evId]);
  } else if (effectiveDefaultInput === "allow") {
    status = "fail";
    summary = "UFW default incoming policy is set to allow.";
    remediation = "Set default incoming policy to deny (`ufw default deny incoming`).";
    addFinding(id, "default_allow", "critical", summary, [evId]);
  } else if (unusedAllowRuleCount > 0) {
    status = "warn";
    summary = `UFW has ${unusedAllowRuleCount} allow rule(s) with no matching active listener.`;
    remediation = "Review and remove unused UFW allow rules.";
    addFinding(id, "unused_rules", "warning", summary, [evId]);
  } else if (effectiveDefaultInput === "unknown") {
    status = "warn";
    summary = "UFW is active, but the default incoming policy could not be verified.";
    addFinding(id, "unknown_default", "warning", summary, [evId]);
  } else if (!unusedRulesCoverageComplete) {
    status = "unknown";
    summary =
      "UFW firewall is active with default deny incoming; unused allow rules could not be fully verified.";
  } else {
    status = "pass";
    summary = "UFW firewall is active with default deny incoming and no unused allow rules.";
  }

  return {
    id,
    category: meta.category,
    title: meta.title,
    status,
    summary,
    ...(remediation ? { remediation } : {}),
    evidenceIds: [evId],
    sourceCoverage,
  };
}

function evaluateNetworkExposure(ctx: EvaluationContext): PostureCheck {
  const id: CriterionId = "network_exposure";
  const meta = CRITERION_META[id];
  const {
    socketsAvailable,
    ufwDefaultCoverage,
    ufwV4Text,
    ufwV6Text,
    firewallInputs,
    publications,
    exposure,
    addEvidence,
    addFinding,
  } = ctx;

  const sourceCoverage: Record<string, Coverage> = {
    sockets: socketsAvailable ? "complete" : "unavailable",
    ufw_status: firewallInputs.active !== null ? "complete" : "unavailable",
    ufw_default: ufwDefaultCoverage,
    ufw_v4: ufwV4Text !== null && ufwV4Text.trim().length > 0 ? "complete" : "unavailable",
    ufw_v6: ufwV6Text !== null && ufwV6Text.trim().length > 0 ? "complete" : "unavailable",
    tailscale_serve: publications.serveCoverage,
    tailscale_funnel: publications.funnelCoverage,
  };

  if (!socketsAvailable) {
    const evId = addEvidence("criterion", "network_exposure", {
      criterionId: "network_exposure",
      criterion: "network_exposure",
      listenerCount: null,
      exposedCount: null,
      unexpectedExposedCount: null,
      funnelCount: null,
      unknownCount: null,
    });
    return {
      id,
      category: meta.category,
      title: meta.title,
      status: "unknown",
      summary: "Listening sockets could not be inspected.",
      evidenceIds: [evId],
      sourceCoverage,
    };
  }

  const unexpectedExposed = exposure.filter(
    (entry) =>
      !entry.expected &&
      (entry.reachability === "exposed_v4_v6" || entry.reachability === "exposed_lan"),
  );
  const funneledEntries = exposure.filter((entry) => entry.publication === "funnel");
  const unknownEntries = exposure.filter((entry) => entry.reachability === "unknown");
  const exposedCount = exposure.filter(
    (entry) => entry.reachability === "exposed_v4_v6" || entry.reachability === "exposed_lan",
  ).length;

  const evId = addEvidence("criterion", "network_exposure", {
    criterionId: "network_exposure",
    criterion: "network_exposure",
    listenerCount: exposure.length,
    exposedCount,
    unexpectedExposedCount: unexpectedExposed.length,
    funnelCount: funneledEntries.length,
    unknownCount: unknownEntries.length,
  });

  const checkEvidenceIds = [evId];
  let status: PostureCheck["status"];
  let summary: string;
  let remediation: string | undefined;

  if (unexpectedExposed.length > 0) {
    const flaggedIds = unexpectedExposed.flatMap((entry) => entry.evidenceIds);
    checkEvidenceIds.push(...flaggedIds);
    const hasPublicOrDualStack = unexpectedExposed.some(
      (entry) => entry.publication === "funnel" || entry.reachability === "exposed_v4_v6",
    );
    status = hasPublicOrDualStack ? "fail" : "warn";
    summary = `${unexpectedExposed.length} unexpected listener(s) are network-exposed.`;
    remediation =
      "Bind services to loopback/Tailnet, restrict UFW rules, or register expected ports.";
    addFinding(
      id,
      "unexpected_exposure",
      hasPublicOrDualStack ? "critical" : "warning",
      summary,
      [evId, ...flaggedIds],
    );
  } else if (unknownEntries.length > 0) {
    const unknownIds = unknownEntries.flatMap((entry) => entry.evidenceIds);
    checkEvidenceIds.push(...unknownIds);
    status = "warn";
    summary = `${unknownEntries.length} listener(s) have indeterminate network reachability.`;
    addFinding(id, "unknown_reachability", "warning", summary, [evId, ...unknownIds]);
  } else {
    status = "pass";
    summary = "No unexpected listeners are exposed beyond loopback or Tailnet.";
  }

  return {
    id,
    category: meta.category,
    title: meta.title,
    status,
    summary,
    ...(remediation ? { remediation } : {}),
    evidenceIds: checkEvidenceIds,
    sourceCoverage,
  };
}

function evaluateSshHardening(ctx: EvaluationContext): PostureCheck {
  const id: CriterionId = "ssh_hardening";
  const meta = CRITERION_META[id];
  const {
    fileResults,
    sshDropInsResult,
    socketsAvailable,
    ufwDefaultCoverage,
    ufwV4Text,
    ufwV6Text,
    firewallInputs,
    publications,
    exposure,
    addEvidence,
    addFinding,
  } = ctx;

  const sshdMainText = fileResults.get("sshd-main") ?? null;
  const sourceCoverage: Record<string, Coverage> = {
    sshd_main: sshdMainText !== null ? "complete" : "unavailable",
    sshd_dropins: sshDropInsResult !== null ? "complete" : "unavailable",
    sockets: socketsAvailable ? "complete" : "unavailable",
    ufw_status: firewallInputs.active !== null ? "complete" : "unavailable",
    ufw_default: ufwDefaultCoverage,
    ufw_v4: ufwV4Text !== null && ufwV4Text.trim().length > 0 ? "complete" : "unavailable",
    ufw_v6: ufwV6Text !== null && ufwV6Text.trim().length > 0 ? "complete" : "unavailable",
    tailscale_serve: publications.serveCoverage,
    tailscale_funnel: publications.funnelCoverage,
  };

  if (sshdMainText === null) {
    const evId = addEvidence("criterion", "ssh_hardening", {
      criterionId: "ssh_hardening",
      criterion: "ssh_hardening",
      readable: false,
    });
    return {
      id,
      category: meta.category,
      title: meta.title,
      status: "unknown",
      summary: "OpenSSH server configuration could not be read.",
      evidenceIds: [evId],
      sourceCoverage,
    };
  }

  const parsed = parseSshdConfig(sshdMainText, sshDropInsResult);
  if (parsed.hasMatchLoosening) {
    sourceCoverage.sshd_main = "partial";
  }
  if (parsed.dropInsMissing) {
    sourceCoverage.sshd_dropins = "unavailable";
  } else if (parsed.hasUnhandledInclude || parsed.hasUnmatchedDropInInclude) {
    sourceCoverage.sshd_dropins = "partial";
  }

  const sshPorts = new Set<number>(parsed.ports);
  const sshEntries = exposure.filter((entry) => sshPorts.has(entry.listener.port));
  const exposedSshEntries = sshEntries.filter(
    (entry) =>
      entry.reachability === "exposed_lan" ||
      entry.reachability === "exposed_v4_v6" ||
      entry.publication === "funnel",
  );
  const indeterminateSshEntries = sshEntries.filter(
    (entry) => entry.reachability === "unknown" || entry.publication === "unknown",
  );
  const sshReachabilityVerified = socketsAvailable && indeterminateSshEntries.length === 0;

  // OpenSSH defaults when unspecified:
  // PasswordAuthentication=yes, KbdInteractiveAuthentication=yes, PermitRootLogin=prohibit-password.
  // Only genuinely unreadable/out-of-scope includes can hide explicit overrides; a readable empty
  // sshd_config.d directory matching zero *.conf files cannot hide directives.
  const includeCouldHideDirectives = parsed.dropInsMissing || parsed.hasUnhandledInclude;
  const passwordEnabled =
    parsed.passwordAuthentication === "yes" ||
    (parsed.passwordAuthentication === null && !includeCouldHideDirectives);
  const rootLoginAllowed = parsed.permitRootLogin === "yes";
  const rootLoginNotDisabled =
    parsed.permitRootLogin !== "no" &&
    !(parsed.permitRootLogin === null && includeCouldHideDirectives);
  const kbdInteractiveEnabled =
    parsed.kbdInteractiveAuthentication === "yes" ||
    (parsed.kbdInteractiveAuthentication === null && !includeCouldHideDirectives);

  const evId = addEvidence("criterion", "ssh_hardening", {
    criterionId: "ssh_hardening",
    criterion: "ssh_hardening",
    permitRootLogin: parsed.permitRootLogin,
    passwordAuthentication: parsed.passwordAuthentication,
    kbdInteractiveAuthentication: parsed.kbdInteractiveAuthentication,
    hasMatchLoosening: parsed.hasMatchLoosening,
    hasUnhandledInclude: parsed.hasUnhandledInclude || parsed.hasUnmatchedDropInInclude,
    exposedOutsideTailnetCount: sshReachabilityVerified ? exposedSshEntries.length : null,
    indeterminateSshListenerCount: socketsAvailable ? indeterminateSshEntries.length : null,
  });

  const checkEvidenceIds = [
    evId,
    ...exposedSshEntries.flatMap((e) => e.evidenceIds),
    ...indeterminateSshEntries.flatMap((e) => e.evidenceIds),
  ];
  const issues: { slug: string; severity: Severity; text: string }[] = [];

  if (passwordEnabled) {
    issues.push({
      slug: "password_auth",
      severity: "critical",
      text: "SSH password authentication is enabled.",
    });
  }
  if (rootLoginAllowed) {
    issues.push({
      slug: "root_login",
      severity: "critical",
      text: "SSH root login is globally permitted.",
    });
  } else if (rootLoginNotDisabled && !includeCouldHideDirectives) {
    issues.push({
      slug: "root_login_unrestricted",
      severity: "warning",
      text: "SSH PermitRootLogin is not explicitly set to no.",
    });
  }
  if (kbdInteractiveEnabled) {
    issues.push({
      slug: "kbd_interactive",
      severity: "warning",
      text: "SSH keyboard-interactive authentication is enabled.",
    });
  }
  if (exposedSshEntries.length > 0) {
    issues.push({
      slug: "exposed_outside_tailnet",
      severity: "warning",
      text: "SSH port is reachable outside loopback and Tailnet.",
    });
  }
  if (parsed.hasMatchLoosening) {
    issues.push({
      slug: "match_loosening",
      severity: "warning",
      text: "Global SSH directives are hardened, but Match-scoped blocks loosen authentication.",
    });
  }

  let status: PostureCheck["status"];
  let summary: string;
  let remediation: string | undefined;

  if (issues.length > 0) {
    const hasCritical = issues.some((issue) => issue.severity === "critical");
    status = hasCritical ? "fail" : "warn";
    summary = issues.map((issue) => issue.text).join(" ");
    remediation =
      "Disable PasswordAuthentication, KbdInteractiveAuthentication, and PermitRootLogin, and restrict SSH to Tailnet/loopback.";
    for (const issue of issues) {
      addFinding(id, issue.slug, issue.severity, issue.text, checkEvidenceIds);
    }
  } else if (parsed.dropInsMissing) {
    status = "unknown";
    summary = "SSH drop-in configuration directory could not be read.";
  } else if (parsed.hasUnhandledInclude || parsed.hasUnmatchedDropInInclude) {
    status = "unknown";
    summary =
      "SSH configuration contains unresolved Include directives; full hardening could not be verified.";
  } else {
    status = "pass";
    summary = sshReachabilityVerified
      ? "SSH disables root and password authentication and is not exposed outside Tailnet."
      : "SSH disables root and password authentication; port exposure could not be verified.";
  }

  return {
    id,
    category: meta.category,
    title: meta.title,
    status,
    summary,
    ...(remediation ? { remediation } : {}),
    evidenceIds: checkEvidenceIds,
    sourceCoverage,
  };
}

function evaluatePackageUpdates(ctx: EvaluationContext): PostureCheck {
  const id: CriterionId = "package_updates";
  const meta = CRITERION_META[id];
  const { capturedAt, commandResults, fileResults, addEvidence, addFinding } = ctx;

  const updatesRes = commandResults.get("updates");
  const archAuditRes = commandResults.get("arch_audit");
  const pacmanLogText = fileResults.get("pacman-log") ?? null;

  const parsedUpdates =
    updatesRes?.status === "ok" ? parsePacmanUpdates(updatesRes.stdout, updatesRes.exitCode) : null;
  const lastUpgradeAt = pacmanLogText !== null ? parsePacmanLogLastUpgrade(pacmanLogText) : null;
  const daysSinceUpgrade =
    lastUpgradeAt !== null ? Math.floor((capturedAt - lastUpgradeAt) / DAY_MS) : null;
  const isStaleUpgrade =
    lastUpgradeAt !== null && capturedAt - lastUpgradeAt > STALE_UPGRADE_DAYS * DAY_MS;

  const auditParsed = archAuditRes?.status === "ok" ? parseArchAudit(archAuditRes.stdout) : null;

  const sourceCoverage: Record<string, Coverage> = {
    updates: updatesRes?.status === "ok" ? "complete" : "unavailable",
    pacman_log:
      pacmanLogText === null ? "unavailable" : lastUpgradeAt !== null ? "complete" : "partial",
    arch_audit: archAuditRes?.status === "ok" ? "complete" : "unavailable",
  };

  const evId = addEvidence("criterion", "package_updates", {
    criterionId: "package_updates",
    criterion: "package_updates",
    pendingCount: parsedUpdates?.totalCount ?? null,
    kernelUpdateCount: parsedUpdates?.kernelCount ?? null,
    daysSinceLastUpgrade: daysSinceUpgrade,
    advisoryCount: auditParsed?.advisoryCount ?? null,
    highAdvisoryCount: auditParsed?.highOrCriticalCount ?? null,
  });

  const issues: { slug: string; severity: Severity; text: string }[] = [];

  if (auditParsed && auditParsed.advisoryCount > 0) {
    issues.push({
      slug: "arch_audit",
      severity: auditParsed.highOrCriticalCount > 0 ? "critical" : "warning",
      text: `arch-audit reported ${auditParsed.advisoryCount} upgradable security advisory(ies).`,
    });
  }
  if (parsedUpdates !== null) {
    if (parsedUpdates.kernelCount > 0) {
      issues.push({
        slug: "kernel_updates",
        severity: "warning",
        text: `${parsedUpdates.kernelCount} pending kernel update(s) (${parsedUpdates.totalCount} total pending packages).`,
      });
    } else if (parsedUpdates.totalCount > 0) {
      issues.push({
        slug: "pending_updates",
        severity: "warning",
        text: `${parsedUpdates.totalCount} pending package update(s) available.`,
      });
    }
  }
  if (isStaleUpgrade) {
    issues.push({
      slug: "stale_upgrades",
      severity: "warning",
      text: `Last recorded package upgrade was ${daysSinceUpgrade} days ago (threshold: ${STALE_UPGRADE_DAYS} days).`,
    });
  }

  let status: PostureCheck["status"];
  let summary: string;
  let remediation: string | undefined;

  if (issues.length > 0) {
    status = issues.some((i) => i.severity === "critical") ? "fail" : "warn";
    summary =
      issues.map((i) => i.text).join(" ") +
      (parsedUpdates === null ? " Pending package updates could not be checked." : "");
    remediation = "Upgrade system packages and reboot if a kernel update is installed.";
    for (const issue of issues) {
      addFinding(id, issue.slug, issue.severity, issue.text, [evId]);
    }
  } else if (parsedUpdates === null) {
    status = "unknown";
    summary = "Pending package updates could not be checked.";
  } else {
    status = "pass";
    const hasUpgradeHistory = lastUpgradeAt !== null;
    const hasArchAudit = auditParsed !== null;
    if (hasUpgradeHistory && hasArchAudit) {
      summary = "Packages are up to date with recent upgrade history and no advisories.";
    } else if (hasUpgradeHistory) {
      summary = "Packages are up to date with recent upgrade history (arch-audit unavailable).";
    } else if (hasArchAudit) {
      summary = "No pending package updates or advisories detected (upgrade history unavailable).";
    } else {
      summary =
        "No pending package updates detected (upgrade history and arch-audit unavailable).";
    }
  }

  return {
    id,
    category: meta.category,
    title: meta.title,
    status,
    summary,
    ...(remediation ? { remediation } : {}),
    evidenceIds: [evId],
    sourceCoverage,
  };
}

function evaluateDiskAndBoot(ctx: EvaluationContext): PostureCheck {
  const id: CriterionId = "disk_and_boot";
  const meta = CRITERION_META[id];
  const { commandResults, addEvidence, addFinding } = ctx;

  const blockRes = commandResults.get("block_devices");
  const bootRes = commandResults.get("boot_status");

  const blockParsed = blockRes?.status === "ok" ? parseBlockDevices(blockRes.stdout) : null;
  const bootParsed = bootRes?.status === "ok" ? parseBootStatus(bootRes.stdout) : null;

  const bootFieldsComplete =
    bootParsed !== null && bootParsed.secureBoot !== "unknown" && bootParsed.tpm2 !== "unknown";

  const sourceCoverage: Record<string, Coverage> = {
    block_devices: blockParsed !== null ? "complete" : "unavailable",
    boot_status:
      bootParsed === null ? "unavailable" : bootFieldsComplete ? "complete" : "partial",
  };

  const evId = addEvidence("criterion", "disk_and_boot", {
    criterionId: "disk_and_boot",
    criterion: "disk_and_boot",
    rootEncrypted: blockParsed?.rootEncrypted ?? null,
    unencryptedSecondaryCount: blockParsed?.unencryptedSecondaryCount ?? null,
    secureBoot: bootParsed?.secureBoot ?? null,
    tpm2: bootParsed?.tpm2 ?? null,
  });

  if (blockParsed === null && bootParsed === null) {
    return {
      id,
      category: meta.category,
      title: meta.title,
      status: "unknown",
      summary: "Disk encryption and boot security status could not be inspected.",
      evidenceIds: [evId],
      sourceCoverage,
    };
  }

  const issues: { slug: string; severity: Severity; text: string }[] = [];

  if (blockParsed?.rootEncrypted === false) {
    issues.push({
      slug: "unencrypted_root",
      severity: "critical",
      text: "Root filesystem is not encrypted with LUKS.",
    });
  }
  if (blockParsed && blockParsed.unencryptedSecondaryCount > 0) {
    issues.push({
      slug: "unencrypted_secondary",
      severity: "warning",
      text: `${blockParsed.unencryptedSecondaryCount} unencrypted secondary mounted volume(s) detected.`,
    });
  }
  if (bootParsed?.secureBoot === "disabled") {
    issues.push({
      slug: "secure_boot_disabled",
      severity: "warning",
      text: "UEFI Secure Boot is disabled.",
    });
  }
  if (bootParsed?.tpm2 === "no") {
    issues.push({
      slug: "tpm2_missing",
      severity: "warning",
      text: "TPM2 support is not available.",
    });
  }
  if (bootParsed !== null && !bootFieldsComplete) {
    issues.push({
      slug: "boot_fields_missing",
      severity: "warning",
      text: "Secure Boot or TPM2 fields were missing from bootctl status.",
    });
  }

  let status: PostureCheck["status"];
  let summary: string;
  let remediation: string | undefined;

  if (issues.length > 0) {
    status = issues.some((i) => i.severity === "critical") ? "fail" : "warn";
    summary = issues.map((i) => i.text).join(" ");
    remediation =
      "Ensure root and secondary data volumes use LUKS encryption and enable UEFI Secure Boot with TPM2.";
    for (const issue of issues) {
      addFinding(id, issue.slug, issue.severity, issue.text, [evId]);
    }
  } else if (blockParsed === null || bootParsed === null || blockParsed.rootEncrypted === null) {
    status = "unknown";
    summary = "Disk encryption or boot status coverage is incomplete.";
  } else {
    status = "pass";
    summary = "Root and mounted data volumes are encrypted with Secure Boot and TPM2 enabled.";
  }

  return {
    id,
    category: meta.category,
    title: meta.title,
    status,
    summary,
    ...(remediation ? { remediation } : {}),
    evidenceIds: [evId],
    sourceCoverage,
  };
}

function evaluateKernelSysctl(ctx: EvaluationContext): PostureCheck {
  const id: CriterionId = "kernel_sysctl";
  const meta = CRITERION_META[id];
  const { commandResults, addEvidence, addFinding } = ctx;

  const sysctlRes = commandResults.get("sysctl");
  const parsed = sysctlRes?.status === "ok" ? parseSysctl(sysctlRes.stdout) : null;

  const coverage: Coverage =
    parsed === null || parsed.observed.size === 0
      ? "unavailable"
      : parsed.missingKeys.length > 0
        ? "partial"
        : "complete";

  const sourceCoverage: Record<string, Coverage> = { sysctl: coverage };

  const facts: Record<string, string | number | boolean | null> = {
    criterionId: "kernel_sysctl",
    criterion: "kernel_sysctl",
    observedCount: parsed?.observed.size ?? 0,
    missingCount: parsed?.missingKeys.length ?? SYSCTL_POLICIES.length,
    unsafeCount: parsed?.unsafeKeys.length ?? 0,
  };
  for (const policy of SYSCTL_POLICIES) {
    facts[policy.key] = parsed?.observed.get(policy.key) ?? null;
  }

  const evId = addEvidence("criterion", "kernel_sysctl", facts);

  let status: PostureCheck["status"];
  let summary: string;
  let remediation: string | undefined;

  if (coverage === "unavailable") {
    status = "unknown";
    summary = "Kernel sysctl hardening parameters could not be read.";
  } else if (parsed!.unsafeKeys.length > 0) {
    status = parsed!.unsafeKeys.length >= 3 ? "fail" : "warn";
    summary = `${parsed!.unsafeKeys.length} kernel sysctl parameter(s) have unsafe values: ${parsed!.unsafeKeys.join(", ")}.`;
    remediation = "Persist hardened sysctl values under /etc/sysctl.d/99-hardening.conf.";
    addFinding(id, "unsafe_sysctl", status === "fail" ? "critical" : "warning", summary, [evId]);
  } else {
    status = "pass";
    summary =
      coverage === "partial"
        ? `All ${parsed!.observed.size} observed kernel sysctl parameters meet hardening defaults (${parsed!.missingKeys.length} unavailable).`
        : "All kernel sysctl hardening parameters meet expected values.";
  }

  return {
    id,
    category: meta.category,
    title: meta.title,
    status,
    summary,
    ...(remediation ? { remediation } : {}),
    evidenceIds: [evId],
    sourceCoverage,
  };
}

function evaluateSystemdHealth(ctx: EvaluationContext): PostureCheck {
  const id: CriterionId = "systemd_health";
  const meta = CRITERION_META[id];
  const { commandResults, addEvidence, addFinding } = ctx;

  const sysFailedRes = commandResults.get("system_failed");
  const userFailedRes = commandResults.get("user_failed");
  const snapperRes = commandResults.get("snapper_health");
  const limineRes = commandResults.get("limine_health");

  const sourceCoverage: Record<string, Coverage> = {
    system_failed: sysFailedRes?.status === "ok" ? "complete" : "unavailable",
    user_failed: userFailedRes?.status === "ok" ? "complete" : "unavailable",
    snapper_health: snapperRes?.status === "ok" ? "complete" : "unavailable",
    limine_health: limineRes?.status === "ok" ? "complete" : "unavailable",
  };

  const allUnavailable =
    sysFailedRes?.status !== "ok" &&
    userFailedRes?.status !== "ok" &&
    snapperRes?.status !== "ok" &&
    limineRes?.status !== "ok";

  const systemFailed =
    sysFailedRes?.status === "ok" ? parseSystemdUnits(sysFailedRes.stdout) : [];
  const userFailed = userFailedRes?.status === "ok" ? parseSystemdUnits(userFailedRes.stdout) : [];
  const snapperDegraded =
    snapperRes?.status === "ok"
      ? parseSystemdUnits(snapperRes.stdout).filter(
          (u) => u.active === "failed" || u.sub === "failed" || u.load === "error",
        )
      : [];
  const limineDegraded =
    limineRes?.status === "ok"
      ? parseSystemdUnits(limineRes.stdout).filter(
          (u) => u.active === "failed" || u.sub === "failed" || u.load === "error",
        )
      : [];

  const evId = addEvidence("criterion", "systemd_health", {
    criterionId: "systemd_health",
    criterion: "systemd_health",
    systemFailedCount: sysFailedRes?.status === "ok" ? systemFailed.length : null,
    userFailedCount: userFailedRes?.status === "ok" ? userFailed.length : null,
    snapperDegradedCount: snapperRes?.status === "ok" ? snapperDegraded.length : null,
    limineDegradedCount: limineRes?.status === "ok" ? limineDegraded.length : null,
  });

  if (allUnavailable) {
    return {
      id,
      category: meta.category,
      title: meta.title,
      status: "unknown",
      summary: "Systemd unit health could not be queried.",
      evidenceIds: [evId],
      sourceCoverage,
    };
  }

  const checkEvidenceIds = [evId];
  const unitEvidenceIds: string[] = [];
  let unitIndex = 0;

  const recordUnitEvidence = (scope: string, units: readonly ParsedUnit[]) => {
    for (const u of units) {
      const unitEvId = addEvidence("unit", String(unitIndex++), {
        scope,
        unit: u.unit,
        load: u.load,
        active: u.active,
        sub: u.sub,
      });
      unitEvidenceIds.push(unitEvId);
      checkEvidenceIds.push(unitEvId);
    }
  };

  recordUnitEvidence("system", systemFailed);
  recordUnitEvidence("user", userFailed);
  recordUnitEvidence("snapper", snapperDegraded);
  recordUnitEvidence("limine", limineDegraded);

  const totalIssues =
    systemFailed.length + userFailed.length + snapperDegraded.length + limineDegraded.length;

  let status: PostureCheck["status"];
  let summary: string;
  let remediation: string | undefined;

  if (totalIssues > 0) {
    status = systemFailed.length > 0 ? "fail" : "warn";
    const parts: string[] = [];
    if (systemFailed.length > 0) parts.push(`${systemFailed.length} failed system unit(s)`);
    if (userFailed.length > 0) parts.push(`${userFailed.length} failed user unit(s)`);
    if (snapperDegraded.length > 0) parts.push(`${snapperDegraded.length} degraded Snapper unit(s)`);
    if (limineDegraded.length > 0) parts.push(`${limineDegraded.length} degraded Limine unit(s)`);
    summary = `Systemd reported ${parts.join(", ")}.`;
    remediation = "Inspect failed units with `systemctl status` and resolve underlying errors.";
    addFinding(
      id,
      "degraded_units",
      status === "fail" ? "critical" : "warning",
      summary,
      [evId, ...unitEvidenceIds],
    );
  } else {
    status = "pass";
    summary = "No failed system, user, Snapper, or Limine units detected.";
  }

  return {
    id,
    category: meta.category,
    title: meta.title,
    status,
    summary,
    ...(remediation ? { remediation } : {}),
    evidenceIds: checkEvidenceIds,
    sourceCoverage,
  };
}

function evaluateProcessAndTimers(ctx: EvaluationContext): PostureCheck {
  const id: CriterionId = "process_and_timers";
  const meta = CRITERION_META[id];
  const {
    commandResults,
    socketsAvailable,
    listeners,
    processMap,
    workloads,
    emittedProcessPids,
    expectedPortSet,
    addEvidence,
    addFinding,
  } = ctx;

  const procRes = commandResults.get("processes");
  const timersRes = commandResults.get("user_timers");

  const sourceCoverage: Record<string, Coverage> = {
    processes: procRes?.status === "ok" ? "complete" : "unavailable",
    user_timers: timersRes?.status === "ok" ? "complete" : "unavailable",
    sockets: socketsAvailable ? "complete" : "unavailable",
  };

  const userTimers = timersRes?.status === "ok" ? parseUserTimers(timersRes.stdout) : null;

  const unexpectedListeners: Listener[] = [];
  if (socketsAvailable) {
    const seen = new Set<string>();
    for (const listener of listeners) {
      if (expectedPortSet.has(listener.port)) continue;
      if (isLoopbackAddress(listener.address, listener.family)) continue;
      const dedupeKey = `${listener.protocol}:${listener.port}:${listener.pid ?? ""}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      unexpectedListeners.push(listener);
    }
  }

  const evId = addEvidence("criterion", "process_and_timers", {
    criterionId: "process_and_timers",
    criterion: "process_and_timers",
    processCount: processMap?.size ?? null,
    userTimerCount: userTimers?.length ?? null,
    unexpectedListenerCount: socketsAvailable ? unexpectedListeners.length : null,
  });

  if (processMap === null && userTimers === null && !socketsAvailable) {
    return {
      id,
      category: meta.category,
      title: meta.title,
      status: "unknown",
      summary: "Process, timer, and socket inventory could not be collected.",
      evidenceIds: [evId],
      sourceCoverage,
    };
  }

  const checkEvidenceIds = [evId];
  const flaggedProcessEvIds: string[] = [];

  for (let i = 0; i < unexpectedListeners.length; i++) {
    const listener = unexpectedListeners[i]!;
    const proc = listener.pid !== undefined ? processMap?.get(listener.pid) : undefined;
    const parent = proc !== undefined ? processMap?.get(proc.ppid) : undefined;
    const comm = proc?.comm ?? listener.process ?? null;
    const workload = matchEnrolledWorkloadForCollector(listener, proc, workloads);
    const resolvedPid = proc?.pid ?? listener.pid ?? null;

    const procEvId = addEvidence("process", `unexpected:${listener.port}:${i}`, {
      comm,
      pid: resolvedPid,
      uid: proc?.uid ?? null,
      startedAt: proc?.startedAt ?? null,
      parentComm: parent?.comm ?? null,
      protocol: listener.protocol,
      port: listener.port,
      workloadId: workload?.id ?? null,
      unit: proc?.uunit ?? proc?.unit ?? workload?.unit ?? null,
    });
    if (resolvedPid !== null) {
      emittedProcessPids.add(resolvedPid);
    }
    flaggedProcessEvIds.push(procEvId);
    checkEvidenceIds.push(procEvId);
  }

  let status: PostureCheck["status"];
  let summary: string;
  let remediation: string | undefined;

  if (unexpectedListeners.length > 0) {
    status = "warn";
    summary = `${unexpectedListeners.length} process(es) are listening on unexpected ports.`;
    remediation =
      "Verify the owning processes and either stop unauthorized listeners or enroll their ports.";
    addFinding(id, "unexpected_socket_owners", "warning", summary, [evId, ...flaggedProcessEvIds]);
  } else if (processMap === null || !socketsAvailable) {
    status = "unknown";
    summary = "Process or socket inventory is unavailable.";
  } else {
    status = "pass";
    summary = "All socket-owning processes listen only on expected ports.";
  }

  return {
    id,
    category: meta.category,
    title: meta.title,
    status,
    summary,
    ...(remediation ? { remediation } : {}),
    evidenceIds: checkEvidenceIds,
    sourceCoverage,
  };
}

const CRITERION_EVALUATORS: Record<CriterionId, (ctx: EvaluationContext) => PostureCheck> = {
  firewall_ufw: evaluateFirewallUfw,
  network_exposure: evaluateNetworkExposure,
  ssh_hardening: evaluateSshHardening,
  package_updates: evaluatePackageUpdates,
  disk_and_boot: evaluateDiskAndBoot,
  kernel_sysctl: evaluateKernelSysctl,
  systemd_health: evaluateSystemdHealth,
  process_and_timers: evaluateProcessAndTimers,
};

export class PostureCollector {
  private readonly runner: CommandRunner;
  private readonly files: PostureFiles;
  private readonly clock: Clock;
  private readonly concurrency: number;
  private latestFirewall: FirewallInputs | null = null;
  private latestPublications: TailscalePublications | null = null;

  constructor(options: PostureCollectorOptions) {
    this.runner = options.runner;
    this.files = options.files ?? createPostureFiles();
    this.clock = options.clock ?? { now: () => Date.now() };
    this.concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;
  }

  async primeNetworkContext(signal?: AbortSignal): Promise<void> {
    const commandKinds: SimpleCommandKind[] = [
      "ufw_status",
      "tailscale_serve",
      "tailscale_funnel",
    ];
    const fileSources: PostureFileSource[] = [
      "ufw-conf",
      "ufw-default",
      "ufw-v4",
      "ufw-v6",
    ];
    const commandResults = new Map<SimpleCommandKind, CommandResult>();
    const fileResults = new Map<PostureFileSource, string | null>();
    const tasks: (() => Promise<void>)[] = [];

    for (const kind of commandKinds) {
      tasks.push(async () => {
        commandResults.set(kind, await this.runner.run({ kind }, signal));
      });
    }
    for (const source of fileSources) {
      tasks.push(async () => {
        fileResults.set(source, await this.files.read(source));
      });
    }

    await runWithConcurrency(tasks, this.concurrency);

    if (signal?.aborted) {
      return;
    }

    const ufwStatusRes = commandResults.get("ufw_status");
    const ufwStatusParsed =
      ufwStatusRes?.status === "ok" ? parseUfwStatus(ufwStatusRes.stdout) : null;
    const ufwConfText = fileResults.get("ufw-conf") ?? null;
    const ufwConfParsed = ufwConfText !== null ? parseUfwConf(ufwConfText) : null;
    const ufwDefaultText = fileResults.get("ufw-default") ?? null;
    const ufwDefaultParsed = ufwDefaultText !== null ? parseUfwDefault(ufwDefaultText) : null;
    const ufwV4Text = fileResults.get("ufw-v4") ?? null;
    const ufwV6Text = fileResults.get("ufw-v6") ?? null;

    let ufwUnitRes: CommandResult | undefined;
    if (!(ufwStatusParsed && ufwStatusParsed.active !== null) && !signal?.aborted) {
      ufwUnitRes = await this.runner.run(
        { kind: "unit", name: "ufw.service", scope: "system" },
        signal,
      );
      if (signal?.aborted) {
        return;
      }
    }

    const effectiveUfwActive: boolean | null = resolveUfwActiveState(
      ufwStatusParsed,
      ufwConfParsed,
      ufwUnitRes,
    );
    const effectiveDefaultInput: "allow" | "deny" | "unknown" =
      ufwStatusParsed && ufwStatusParsed.defaultInput !== "unknown"
        ? ufwStatusParsed.defaultInput
        : ufwDefaultParsed?.defaultInput ?? "unknown";

    this.latestFirewall = {
      active: effectiveUfwActive,
      ipv6Enabled: ufwDefaultParsed ? ufwDefaultParsed.ipv6Enabled : null,
      v4: ufwV4Text,
      v6: ufwV6Text,
      defaultInput: effectiveDefaultInput,
    };
    this.latestPublications = parseTailscalePublications(
      commandResults.get("tailscale_serve"),
      commandResults.get("tailscale_funnel"),
    );
  }

  classifySockets(
    listeners: readonly Listener[],
    expectedPorts: ReadonlySet<number> | readonly number[],
  ): ExposureEntry[] {
    const expectedPortSet =
      expectedPorts instanceof Set ? expectedPorts : new Set<number>(expectedPorts);
    const firewall: FirewallInputs = this.latestFirewall ?? { active: null };
    const publications: TailscalePublications = this.latestPublications ?? {
      servePorts: new Set(),
      funnelPorts: new Set(),
      serveTargets: [],
      funnelTargets: [],
      serveCoverage: "unavailable",
      funnelCoverage: "unavailable",
    };

    return classifyListeners({
      listeners,
      firewall,
      publications,
      expectedPorts: expectedPortSet,
      evidenceIdForListener: (_listener, index) => `socket-poll:${index}`,
    });
  }

  async collect(
    scanId: string,
    settings: SecuritySettings,
    signal?: AbortSignal,
  ): Promise<PostureResult> {
    const capturedAt = this.clock.now();
    const enabled = new Set<CriterionId>(
      criterionIds.filter((id) => settings.criteria[id] !== false),
    );

    const neededCommands = new Set<SimpleCommandKind>();
    const neededFiles = new Set<PostureFileSource>();
    let needDropIns = false;

    const addFirewallDeps = () => {
      neededCommands.add("ufw_status");
      neededFiles.add("ufw-conf");
      neededFiles.add("ufw-default");
      neededFiles.add("ufw-v4");
      neededFiles.add("ufw-v6");
    };

    if (enabled.has("firewall_ufw")) {
      addFirewallDeps();
      neededCommands.add("sockets");
    }
    if (enabled.has("network_exposure")) {
      addFirewallDeps();
      neededCommands.add("sockets");
      neededCommands.add("tailscale_serve");
      neededCommands.add("tailscale_funnel");
    }
    if (enabled.has("ssh_hardening")) {
      neededFiles.add("sshd-main");
      needDropIns = true;
      neededCommands.add("sockets");
      addFirewallDeps();
      neededCommands.add("tailscale_serve");
      neededCommands.add("tailscale_funnel");
    }
    if (enabled.has("package_updates")) {
      neededCommands.add("updates");
      neededCommands.add("arch_audit");
      neededFiles.add("pacman-log");
    }
    if (enabled.has("disk_and_boot")) {
      neededCommands.add("block_devices");
      neededCommands.add("boot_status");
    }
    if (enabled.has("kernel_sysctl")) {
      neededCommands.add("sysctl");
    }
    if (enabled.has("systemd_health")) {
      neededCommands.add("system_failed");
      neededCommands.add("user_failed");
      neededCommands.add("snapper_health");
      neededCommands.add("limine_health");
    }
    if (enabled.has("process_and_timers")) {
      neededCommands.add("processes");
      neededCommands.add("user_timers");
      neededCommands.add("sockets");
    }
    if (settings.workloads.length > 0 && neededCommands.has("sockets")) {
      neededCommands.add("processes");
    }

    const commandResults = new Map<SimpleCommandKind, CommandResult>();
    const fileResults = new Map<PostureFileSource, string | null>();
    let sshDropInsResult: SshDropIn[] | null = null;

    const tasks: (() => Promise<void>)[] = [];

    for (const kind of [...neededCommands].sort(lexicalCompare) as SimpleCommandKind[]) {
      tasks.push(async () => {
        const result = await this.runner.run({ kind }, signal);
        commandResults.set(kind, result);
      });
    }

    for (const source of [...neededFiles].sort(lexicalCompare) as PostureFileSource[]) {
      tasks.push(async () => {
        const text = await this.files.read(source);
        fileResults.set(source, text);
      });
    }

    if (needDropIns) {
      tasks.push(async () => {
        sshDropInsResult = await this.files.sshDropIns();
      });
    }

    await runWithConcurrency(tasks, this.concurrency);

    // Build deterministic scan-scoped evidence, checks, exposure, and findings.
    const evidence: Evidence[] = [];
    const findings: SecurityFinding[] = [];
    const seenEvidenceIds = new Set<string>();
    const seenFindingIds = new Set<string>();

    const addEvidence = (kind: Evidence["kind"], slug: string, facts: Facts): string => {
      let id = `ev:${scanId}:${kind}:${slug}`;
      let suffix = 1;
      while (seenEvidenceIds.has(id)) {
        id = `ev:${scanId}:${kind}:${slug}#${suffix++}`;
      }
      seenEvidenceIds.add(id);
      evidence.push({ id, kind, facts });
      return id;
    };

    const addFinding = (
      criterionId: CriterionId,
      slug: string,
      severity: Severity,
      summary: string,
      evidenceIds: string[],
    ): void => {
      let id = `finding:${scanId}:${criterionId}:${slug}`;
      let suffix = 1;
      while (seenFindingIds.has(id)) {
        id = `finding:${scanId}:${criterionId}:${slug}#${suffix++}`;
      }
      seenFindingIds.add(id);
      findings.push({
        id,
        source: "deterministic",
        severity,
        summary,
        evidenceIds,
      });
    };

    // Shared parsed state for sockets, processes, firewall, and exposure
    const socketsRes = commandResults.get("sockets");
    const socketsAvailable = socketsRes?.status === "ok";
    const listeners = socketsAvailable ? parseListeners(socketsRes.stdout) : [];
    const procRes = commandResults.get("processes");
    const processMap = procRes?.status === "ok" ? parseProcesses(procRes.stdout, capturedAt) : null;

    const ufwStatusRes = commandResults.get("ufw_status");
    const ufwStatusParsed =
      ufwStatusRes?.status === "ok" ? parseUfwStatus(ufwStatusRes.stdout) : null;
    const ufwConfText = fileResults.get("ufw-conf") ?? null;
    const ufwConfParsed = ufwConfText !== null ? parseUfwConf(ufwConfText) : null;
    const ufwDefaultText = fileResults.get("ufw-default") ?? null;
    const ufwDefaultParsed = ufwDefaultText !== null ? parseUfwDefault(ufwDefaultText) : null;
    const ufwV4Text = fileResults.get("ufw-v4") ?? null;
    const ufwV6Text = fileResults.get("ufw-v6") ?? null;

    let ufwUnitRes: CommandResult | undefined;
    if (
      neededCommands.has("ufw_status") &&
      !(ufwStatusParsed && ufwStatusParsed.active !== null) &&
      !signal?.aborted
    ) {
      ufwUnitRes = await this.runner.run(
        { kind: "unit", name: "ufw.service", scope: "system" },
        signal,
      );
    }

    const effectiveUfwActive: boolean | null = resolveUfwActiveState(
      ufwStatusParsed,
      ufwConfParsed,
      ufwUnitRes,
    );

    const effectiveDefaultInput: "allow" | "deny" | "unknown" =
      ufwStatusParsed && ufwStatusParsed.defaultInput !== "unknown"
        ? ufwStatusParsed.defaultInput
        : ufwDefaultParsed?.defaultInput ?? "unknown";

    const ufwDefaultCoverage: Coverage =
      ufwDefaultText === null
        ? "unavailable"
        : ufwDefaultParsed !== null &&
            ufwDefaultParsed.ipv6Enabled !== null &&
            ufwDefaultParsed.defaultInput !== "unknown"
          ? "complete"
          : "partial";

    const firewallInputs: FirewallInputs = {
      active: effectiveUfwActive,
      ipv6Enabled: ufwDefaultParsed ? ufwDefaultParsed.ipv6Enabled : null,
      v4: ufwV4Text,
      v6: ufwV6Text,
      defaultInput: effectiveDefaultInput,
    };

    const publications = parseTailscalePublications(
      commandResults.get("tailscale_serve"),
      commandResults.get("tailscale_funnel"),
    );

    if (!signal?.aborted) {
      if (neededCommands.has("ufw_status")) {
        this.latestFirewall = firewallInputs;
      }
      if (neededCommands.has("tailscale_serve") || neededCommands.has("tailscale_funnel")) {
        this.latestPublications = publications;
      }
    }

    const expectedPortSet = new Set<number>(settings.expectedPorts);
    for (const workload of settings.workloads) {
      if (workload.ports) {
        for (const port of workload.ports) {
          expectedPortSet.add(port);
        }
      }
    }

    // Compute exposure entries when needed by network_exposure or ssh_hardening.
    let exposure: ExposureEntry[] = [];
    const shouldComputeExposure =
      socketsAvailable && (enabled.has("network_exposure") || enabled.has("ssh_hardening"));

    if (shouldComputeExposure) {
      const preClassified = classifyListeners({
        listeners,
        firewall: firewallInputs,
        publications,
        expectedPorts: expectedPortSet,
        evidenceIdForListener: (_listener, index) => `ev:${scanId}:listener:${index}`,
      });

      exposure = preClassified.map((entry, index) => {
        const listener = entry.listener;
        const proc = listener.pid !== undefined ? processMap?.get(listener.pid) : undefined;
        const workload = matchEnrolledWorkloadForCollector(listener, proc, settings.workloads);
        const evId = addEvidence("listener", String(index), {
          protocol: listener.protocol,
          family: String(listener.family),
          address: listener.address,
          port: listener.port,
          interfaceName: listener.interfaceName ?? null,
          pid: listener.pid ?? null,
          process: listener.process ?? null,
          ...(workload ? { workloadId: workload.id } : {}),
          ...(proc?.uunit ?? proc?.unit ?? workload?.unit
            ? { unit: proc?.uunit ?? proc?.unit ?? workload?.unit ?? null }
            : {}),
          reachability: entry.reachability,
          firewallV4: entry.firewallV4,
          firewallV6: entry.firewallV6,
          publication: entry.publication,
          expected: entry.expected,
        });
        return {
          ...entry,
          evidenceIds: [evId],
        };
      });
    }

    const emittedProcessPids = new Set<number>();

    const ctx: EvaluationContext = {
      capturedAt,
      commandResults,
      fileResults,
      sshDropInsResult,
      socketsAvailable,
      listeners,
      processMap,
      workloads: settings.workloads,
      emittedProcessPids,
      ufwStatusRes,
      ufwStatusParsed,
      ufwDefaultParsed,
      ufwDefaultCoverage,
      ufwV4Text,
      ufwV6Text,
      effectiveDefaultInput,
      firewallInputs,
      publications,
      expectedPortSet,
      exposure,
      addEvidence,
      addFinding,
    };

    // Evaluate all 8 criteria in exact criterionIds order.
    const checks: PostureCheck[] = criterionIds.map((id) => {
      const meta = CRITERION_META[id];
      if (!enabled.has(id)) {
        return {
          id,
          category: meta.category,
          title: meta.title,
          status: "disabled",
          summary: `${meta.title} check is disabled.`,
          evidenceIds: [],
          sourceCoverage: { policy: "complete" },
        };
      }
      return CRITERION_EVALUATORS[id](ctx);
    });

    // Ensure enrolled workload listeners always have corresponding process evidence
    // with pid, startedAt, comm, and workloadId for AI pause_workload proposals.
    if (socketsAvailable && settings.workloads.length > 0) {
      for (let i = 0; i < listeners.length; i++) {
        const listener = listeners[i]!;
        const proc = listener.pid !== undefined ? processMap?.get(listener.pid) : undefined;
        const workload = matchEnrolledWorkloadForCollector(listener, proc, settings.workloads);
        if (!workload) continue;
        const resolvedPid = proc?.pid ?? listener.pid ?? null;
        if (resolvedPid !== null && emittedProcessPids.has(resolvedPid)) {
          continue;
        }
        const parent = proc !== undefined ? processMap?.get(proc.ppid) : undefined;
        const comm = proc?.comm ?? listener.process ?? null;
        addEvidence("process", `workload:${workload.id}:${resolvedPid ?? i}`, {
          comm,
          pid: resolvedPid,
          uid: proc?.uid ?? null,
          startedAt: proc?.startedAt ?? null,
          parentComm: parent?.comm ?? null,
          protocol: listener.protocol,
          port: listener.port,
          workloadId: workload.id,
          unit: proc?.uunit ?? proc?.unit ?? workload.unit,
        });
        if (resolvedPid !== null) {
          emittedProcessPids.add(resolvedPid);
        }
      }
    }

    return {
      snapshot: {
        id: scanId,
        capturedAt,
        checks,
        evidence,
      },
      exposure,
      findings,
    };
  }
}
