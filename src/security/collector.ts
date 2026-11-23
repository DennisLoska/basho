import { constants as fsConstants } from "node:fs";
import { open, readdir } from "node:fs/promises";
import { basename, join } from "node:path";
import {
  criterionIds,
  type Category,
  type Clock,
  type CommandRequest,
  type CommandResult,
  type CommandRunner,
  type Coverage,
  type CriterionId,
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
  "ufw-v4": string;
  "ufw-v6": string;
  "ufw-default": string;
  "sshd-main": string;
  "pacman-log": string;
  "sshd-drop-ins-dir": string;
}

export interface FirewallInputs {
  active: boolean | null;
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

export interface TailscalePublications {
  servePorts: ReadonlySet<number>;
  funnelPorts: ReadonlySet<number>;
  serveCoverage: Coverage;
  funnelCoverage: Coverage;
}

const DEFAULT_CONCURRENCY = 4;
const MAX_CONFIG_FILE_BYTES = 256 * 1024;
const MAX_PACMAN_TAIL_BYTES = 256 * 1024;
const MAX_SSH_DROPIN_FILES = 128;
const STALE_UPGRADE_DAYS = 14;
const DAY_MS = 86_400_000;

const DEFAULT_FILE_PATHS: PostureFilePaths = {
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
    const lower = address.toLowerCase();
    if (lower === "::1" || lower === "0:0:0:0:0:0:0:1") return true;
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

    const rule: ParsedUfwRule = { indeterminate: false };
    let negated = false;

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
        if (!next) {
          rule.indeterminate = true;
          break;
        }
        rule.jump = next;
        i++;
        continue;
      }

      if (tok === "-m" || tok === "--match") {
        if (!next) {
          rule.indeterminate = true;
          break;
        }
        if (!KNOWN_SAFE_MODULES.has(next.toLowerCase())) {
          rule.indeterminate = true;
        }
        i++;
        continue;
      }

      if (tok === "--comment") {
        if (next !== undefined) i++;
        continue;
      }

      // Any other option (e.g. --sport, --ctstate, --limit, --reject-with)
      if (tok === "--reject-with") {
        if (next !== undefined) i++;
        continue;
      }

      rule.indeterminate = true;
      if (next !== undefined && !next.startsWith("-")) {
        i++;
      }
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
    return "unknown";
  }

  const family = listener.family;
  const rulesText = family === 4 ? inputs.v4 : inputs.v6;
  if (rulesText == null || rulesText.trim().length === 0) {
    return "unknown";
  }

  const chainName = family === 4 ? "ufw-user-input" : "ufw6-user-input";
  const rules = parseUfwChainRules(rulesText, chainName);

  for (const rule of rules) {
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

    // Interface-scoped rules apply only when listener matches that interface.
    if (rule.inInterface !== undefined && !interfaceMatches(rule.inInterface, listener.interfaceName)) {
      continue;
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
        const destBase = rule.destination.split("/")[0]?.toLowerCase();
        if (destBase !== listener.address.toLowerCase()) {
          return "unknown";
        }
      }
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

    if (rule.jump === "ACCEPT") {
      return "allow";
    }
    if (rule.jump === "DROP" || rule.jump === "REJECT") {
      return "deny";
    }

    // Non-terminal or unknown jump target (e.g. ufw-user-limit) on a matching rule.
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

    const policyMatch = /^DEFAULT_INPUT_POLICY\s*=\s*["']?([A-Za-z_]+)["']?/.exec(line);
    if (policyMatch) {
      const policy = policyMatch[1]!.toUpperCase();
      if (policy === "ACCEPT") defaultInput = "allow";
      else if (policy === "DROP" || policy === "REJECT") defaultInput = "deny";
      continue;
    }

    const ipv6Match = /^IPV6\s*=\s*["']?(yes|no)["']?/i.exec(line);
    if (ipv6Match) {
      ipv6Enabled = ipv6Match[1]!.toLowerCase() === "yes";
    }
  }

  return { defaultInput, ipv6Enabled };
}

function countUnusedAllowRules(
  rulesText: string,
  chainName: string,
  listeners: readonly Listener[],
): { totalRules: number; unusedCount: number } {
  const rules = parseUfwChainRules(rulesText, chainName);
  let unusedCount = 0;

  for (const rule of rules) {
    if (rule.jump !== "ACCEPT" || !rule.dports || rule.dports.length === 0) {
      continue;
    }
    const hasMatchingListener = listeners.some((listener) => {
      if (
        rule.protocol !== undefined &&
        rule.protocol !== "all" &&
        rule.protocol !== listener.protocol
      ) {
        return false;
      }
      return portMatchesRanges(listener.port, rule.dports!);
    });
    if (!hasMatchingListener) {
      unusedCount++;
    }
  }

  return { totalRules: rules.length, unusedCount };
}

// ---------------------------------------------------------------------------
// Tailscale Serve / Funnel parsing & classifyListeners
// ---------------------------------------------------------------------------

function extractPortFromTarget(target: string): number | null {
  const trimmed = target.trim();
  if (!trimmed) return null;

  // Handle URLs like http://127.0.0.1:8080, https://[::1]:8443/path, http+insecure://localhost:3000
  const urlMatch = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/(?:\[[^\]]+\]|[^/:]+):(\d{1,5})(?:[/?#]|$)/.exec(
    trimmed,
  );
  if (urlMatch) {
    const port = Number(urlMatch[1]);
    return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null;
  }

  // Handle host:port like 127.0.0.1:8443 or [::1]:8443
  const hostPortMatch = /^(?:\[[^\]]+\]|[^/:]+):(\d{1,5})$/.exec(trimmed);
  if (hostPortMatch) {
    const port = Number(hostPortMatch[1]);
    return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null;
  }

  // Bare port number
  if (/^\d{1,5}$/.test(trimmed)) {
    const port = Number(trimmed);
    return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null;
  }

  return null;
}

function collectPortsFromTailscaleJson(
  rawJson: unknown,
  funnelOnly: boolean,
): { serve: Set<number>; funnel: Set<number> } | null {
  if (typeof rawJson !== "object" || rawJson === null || Array.isArray(rawJson)) {
    return null;
  }
  const obj = rawJson as Record<string, unknown>;
  const serve = new Set<number>();
  const funnel = new Set<number>();

  const allowFunnelMap = new Map<string, boolean>();
  if (typeof obj.AllowFunnel === "object" && obj.AllowFunnel !== null && !Array.isArray(obj.AllowFunnel)) {
    for (const [hostPort, allowed] of Object.entries(obj.AllowFunnel as Record<string, unknown>)) {
      if (allowed === true) {
        allowFunnelMap.set(hostPort, true);
      }
    }
  }

  if (typeof obj.Web === "object" && obj.Web !== null && !Array.isArray(obj.Web)) {
    for (const [hostPort, webConfig] of Object.entries(obj.Web as Record<string, unknown>)) {
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
        const port = extractPortFromTarget(proxy);
        if (port === null) continue;
        if (isFunnelHost) {
          funnel.add(port);
        } else if (!funnelOnly) {
          serve.add(port);
        }
      }
    }
  }

  if (typeof obj.TCP === "object" && obj.TCP !== null && !Array.isArray(obj.TCP)) {
    for (const [listenPort, tcpConfig] of Object.entries(obj.TCP as Record<string, unknown>)) {
      if (typeof tcpConfig !== "object" || tcpConfig === null || Array.isArray(tcpConfig)) {
        continue;
      }
      const forward = (tcpConfig as Record<string, unknown>).TCPForward;
      if (typeof forward !== "string") continue;
      const port = extractPortFromTarget(forward);
      if (port === null) continue;
      const isFunnelTcp = [...allowFunnelMap.entries()].some(
        ([hostPort, allowed]) => allowed && hostPort.endsWith(`:${listenPort}`),
      );
      if (isFunnelTcp) {
        funnel.add(port);
      } else if (!funnelOnly) {
        serve.add(port);
      }
    }
  }

  return { serve, funnel };
}

export function parseTailscalePublications(
  serveResult: CommandResult | undefined,
  funnelResult: CommandResult | undefined,
): TailscalePublications {
  const servePorts = new Set<number>();
  const funnelPorts = new Set<number>();
  let serveCoverage: Coverage = "unavailable";
  let funnelCoverage: Coverage = "unavailable";

  if (serveResult?.status === "ok") {
    try {
      const parsed = JSON.parse(serveResult.stdout || "{}");
      const extracted = collectPortsFromTailscaleJson(parsed, false);
      if (extracted) {
        serveCoverage = "complete";
        for (const p of extracted.serve) servePorts.add(p);
        for (const p of extracted.funnel) funnelPorts.add(p);
      }
    } catch {
      serveCoverage = "unavailable";
    }
  }

  if (funnelResult?.status === "ok") {
    try {
      const parsed = JSON.parse(funnelResult.stdout || "{}");
      const extracted = collectPortsFromTailscaleJson(parsed, true);
      if (extracted) {
        funnelCoverage = "complete";
        for (const p of extracted.funnel) funnelPorts.add(p);
      }
    } catch {
      funnelCoverage = "unavailable";
    }
  }

  return { servePorts, funnelPorts, serveCoverage, funnelCoverage };
}

export function classifyListeners(options: ClassifyListenersOptions): ExposureEntry[] {
  const { listeners, firewall, publications, expectedPorts, evidenceIdForListener } = options;

  const preliminary = listeners.map((listener, index) => {
    const firewallV4: ExposureEntry["firewallV4"] =
      listener.family === 4
        ? evaluateFirewall(listener, firewall)
        : listener.family === 6
          ? "na"
          : "unknown";

    const firewallV6: ExposureEntry["firewallV6"] =
      listener.family === 6
        ? evaluateFirewall(listener, firewall)
        : listener.family === 4
          ? "na"
          : "unknown";

    let publication: ExposureEntry["publication"];
    if (listener.protocol !== "tcp") {
      publication =
        publications.serveCoverage === "complete" && publications.funnelCoverage === "complete"
          ? "none"
          : "unknown";
    } else if (publications.funnelPorts.has(listener.port)) {
      publication = "funnel";
    } else if (publications.servePorts.has(listener.port)) {
      publication = publications.funnelCoverage === "complete" ? "serve" : "unknown";
    } else if (
      publications.serveCoverage === "complete" &&
      publications.funnelCoverage === "complete"
    ) {
      publication = "none";
    } else {
      publication = "unknown";
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
    if (item.listener.family === 4 && item.firewallV4 === "allow") {
      v4AllowedKeys.add(key);
    } else if (item.listener.family === 6 && item.firewallV6 === "allow") {
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
      reachability = publication === "serve" ? "tailnet" : "local_only";
    } else if (tailnet) {
      reachability = "tailnet";
    } else if (listener.family === "unspecified") {
      reachability = "unknown";
    } else {
      const fw = listener.family === 4 ? firewallV4 : firewallV6;
      if (fw === "deny") {
        reachability = publication === "serve" ? "tailnet" : "blocked_by_ufw";
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
}

function isSshdDropInPattern(pattern: string): boolean {
  const normalized = pattern.trim().replace(/^["']|["']$/g, "");
  return (
    normalized === "/etc/ssh/sshd_config.d/*.conf" ||
    normalized === "sshd_config.d/*.conf" ||
    normalized.startsWith("/etc/ssh/sshd_config.d/") ||
    normalized.startsWith("sshd_config.d/")
  );
}

function parseSshdDirective(line: string): { key: string; value: string } | null {
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
  return {
    key: match[1]!.toLowerCase(),
    value: match[2]!.trim().replace(/^["']|["']$/g, ""),
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

  const sortedDropIns =
    dropIns !== null ? [...dropIns].sort((a, b) => lexicalCompare(a.name, b.name)) : null;

  const processLines = (text: string, allowInclude: boolean) => {
    let inMatch = false;
    for (const rawLine of text.split(/\r?\n/)) {
      const directive = parseSshdDirective(rawLine);
      if (!directive) continue;

      const { key, value } = directive;
      const lowerVal = value.toLowerCase();

      if (key === "match") {
        inMatch = lowerVal !== "all";
        continue;
      }

      if (key === "include" && allowInclude && !inMatch) {
        includeReferenced = true;
        const patterns = value.split(/\s+/).filter(Boolean);
        for (const pattern of patterns) {
          if (isSshdDropInPattern(pattern)) {
            if (sortedDropIns === null) {
              dropInsMissing = true;
            } else {
              for (const dropIn of sortedDropIns) {
                processLines(dropIn.text, false);
              }
            }
          } else {
            hasUnhandledInclude = true;
          }
        }
        continue;
      }

      if (inMatch) {
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

      // OpenSSH first-value-wins semantics.
      if (!globals.has(key)) {
        globals.set(key, lowerVal);
      }
    }
  };

  processLines(mainText, true);

  return {
    permitRootLogin: globals.get("permitrootlogin") ?? null,
    passwordAuthentication: globals.get("passwordauthentication") ?? null,
    kbdInteractiveAuthentication:
      globals.get("kbdinteractiveauthentication") ??
      globals.get("challengeresponseauthentication") ??
      null,
    ports: ports.length > 0 ? ports : [22],
    hasMatchLoosening,
    includeReferenced,
    dropInsMissing,
    hasUnhandledInclude,
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
    const comm = sanitizeProcessComm(match[5]!);
    if (!Number.isInteger(pid) || pid <= 0 || comm.length === 0) continue;
    map.set(pid, {
      pid,
      ppid,
      uid,
      startedAt: nowMs - etimes * 1000,
      comm,
    });
  }
  return map;
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

export class PostureCollector {
  private readonly runner: CommandRunner;
  private readonly files: PostureFiles;
  private readonly clock: Clock;
  private readonly concurrency: number;

  constructor(options: PostureCollectorOptions) {
    this.runner = options.runner;
    this.files = options.files ?? createPostureFiles();
    this.clock = options.clock ?? { now: () => Date.now() };
    this.concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;
  }

  async collect(scanId: string, settings: SecuritySettings): Promise<PostureResult> {
    const capturedAt = this.clock.now();
    const enabled = new Set<CriterionId>(
      criterionIds.filter((id) => settings.criteria[id] !== false),
    );

    const neededCommands = new Set<SimpleCommandKind>();
    const neededFiles = new Set<PostureFileSource>();
    let needDropIns = false;

    const addFirewallDeps = () => {
      neededCommands.add("ufw_status");
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

    const commandResults = new Map<SimpleCommandKind, CommandResult>();
    const fileResults = new Map<PostureFileSource, string | null>();
    let sshDropInsResult: SshDropIn[] | null = null;

    const tasks: (() => Promise<void>)[] = [];

    for (const kind of [...neededCommands].sort(lexicalCompare) as SimpleCommandKind[]) {
      tasks.push(async () => {
        const result = await this.runner.run({ kind });
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

    // Shared parsed state for sockets, firewall, and exposure
    const socketsRes = commandResults.get("sockets");
    const socketsAvailable = socketsRes?.status === "ok";
    const listeners = socketsAvailable ? parseListeners(socketsRes.stdout) : [];

    const ufwStatusRes = commandResults.get("ufw_status");
    const ufwStatusParsed =
      ufwStatusRes?.status === "ok" ? parseUfwStatus(ufwStatusRes.stdout) : null;
    const ufwDefaultText = fileResults.get("ufw-default") ?? null;
    const ufwDefaultParsed = ufwDefaultText !== null ? parseUfwDefault(ufwDefaultText) : null;
    const ufwV4Text = fileResults.get("ufw-v4") ?? null;
    const ufwV6Text = fileResults.get("ufw-v6") ?? null;

    const effectiveDefaultInput: "allow" | "deny" | "unknown" =
      ufwStatusParsed && ufwStatusParsed.defaultInput !== "unknown"
        ? ufwStatusParsed.defaultInput
        : ufwDefaultParsed?.defaultInput ?? "unknown";

    const firewallInputs: FirewallInputs = {
      active: ufwStatusParsed ? ufwStatusParsed.active : null,
      v4: ufwV4Text,
      v6: ufwV6Text,
      defaultInput: effectiveDefaultInput,
    };

    const publications = parseTailscalePublications(
      commandResults.get("tailscale_serve"),
      commandResults.get("tailscale_funnel"),
    );

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
        const evId = addEvidence("listener", String(index), {
          protocol: listener.protocol,
          family: String(listener.family),
          address: listener.address,
          port: listener.port,
          interfaceName: listener.interfaceName ?? null,
          pid: listener.pid ?? null,
          process: listener.process ?? null,
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

    // Evaluate all 8 criteria in exact criterionIds order.
    const checks: PostureCheck[] = [];

    for (const id of criterionIds) {
      const meta = CRITERION_META[id];
      if (!enabled.has(id)) {
        checks.push({
          id,
          category: meta.category,
          title: meta.title,
          status: "disabled",
          summary: `${meta.title} check is disabled.`,
          evidenceIds: [],
          sourceCoverage: { policy: "complete" },
        });
        continue;
      }

      switch (id) {
        case "firewall_ufw": {
          const sourceCoverage: Record<string, Coverage> = {
            ufw_status: ufwStatusRes?.status === "ok" && ufwStatusParsed?.active !== null ? "complete" : "unavailable",
            ufw_default: ufwDefaultText !== null ? "complete" : "unavailable",
            ufw_v4: ufwV4Text !== null && ufwV4Text.trim().length > 0 ? "complete" : "unavailable",
            ufw_v6: ufwV6Text !== null && ufwV6Text.trim().length > 0 ? "complete" : "unavailable",
            sockets: socketsAvailable ? "complete" : "unavailable",
          };

          const v4Stats =
            socketsAvailable && ufwV4Text !== null && ufwV4Text.trim().length > 0
              ? countUnusedAllowRules(ufwV4Text, "ufw-user-input", listeners)
              : null;
          const v6Stats =
            socketsAvailable && ufwV6Text !== null && ufwV6Text.trim().length > 0
              ? countUnusedAllowRules(ufwV6Text, "ufw6-user-input", listeners)
              : null;

          const unusedAllowRuleCount = (v4Stats?.unusedCount ?? 0) + (v6Stats?.unusedCount ?? 0);

          const evId = addEvidence("criterion", "firewall_ufw", {
            criterion: "firewall_ufw",
            active: firewallInputs.active,
            defaultInput: effectiveDefaultInput,
            ipv6Enabled: ufwDefaultParsed?.ipv6Enabled ?? null,
            v4RuleCount: v4Stats?.totalRules ?? null,
            v6RuleCount: v6Stats?.totalRules ?? null,
            unusedAllowRuleCount: v4Stats || v6Stats ? unusedAllowRuleCount : null,
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
          } else {
            status = "pass";
            summary = "UFW firewall is active with default deny incoming and no unused allow rules.";
          }

          checks.push({
            id,
            category: meta.category,
            title: meta.title,
            status,
            summary,
            ...(remediation ? { remediation } : {}),
            evidenceIds: [evId],
            sourceCoverage,
          });
          break;
        }

        case "network_exposure": {
          const sourceCoverage: Record<string, Coverage> = {
            sockets: socketsAvailable ? "complete" : "unavailable",
            ufw_status:
              ufwStatusRes?.status === "ok" && ufwStatusParsed?.active !== null
                ? "complete"
                : "unavailable",
            ufw_v4: ufwV4Text !== null && ufwV4Text.trim().length > 0 ? "complete" : "unavailable",
            ufw_v6: ufwV6Text !== null && ufwV6Text.trim().length > 0 ? "complete" : "unavailable",
            tailscale_serve: publications.serveCoverage,
            tailscale_funnel: publications.funnelCoverage,
          };

          if (!socketsAvailable) {
            const evId = addEvidence("criterion", "network_exposure", {
              criterion: "network_exposure",
              listenerCount: null,
              exposedCount: null,
              unexpectedExposedCount: null,
              funnelCount: null,
              unknownCount: null,
            });
            checks.push({
              id,
              category: meta.category,
              title: meta.title,
              status: "unknown",
              summary: "Listening sockets could not be inspected.",
              evidenceIds: [evId],
              sourceCoverage,
            });
            break;
          }

          const unexpectedExposed = exposure.filter(
            (entry) =>
              !entry.expected &&
              (entry.reachability === "exposed_v4_v6" || entry.reachability === "exposed_lan"),
          );
          const funneledEntries = exposure.filter((entry) => entry.publication === "funnel");
          const unknownEntries = exposure.filter((entry) => entry.reachability === "unknown");
          const exposedCount = exposure.filter(
            (entry) =>
              entry.reachability === "exposed_v4_v6" || entry.reachability === "exposed_lan",
          ).length;

          const evId = addEvidence("criterion", "network_exposure", {
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

          checks.push({
            id,
            category: meta.category,
            title: meta.title,
            status,
            summary,
            ...(remediation ? { remediation } : {}),
            evidenceIds: checkEvidenceIds,
            sourceCoverage,
          });
          break;
        }

        case "ssh_hardening": {
          const sshdMainText = fileResults.get("sshd-main") ?? null;
          const sourceCoverage: Record<string, Coverage> = {
            sshd_main: sshdMainText !== null ? "complete" : "unavailable",
            sshd_dropins: sshDropInsResult !== null ? "complete" : "unavailable",
            sockets: socketsAvailable ? "complete" : "unavailable",
          };

          if (sshdMainText === null) {
            const evId = addEvidence("criterion", "ssh_hardening", {
              criterion: "ssh_hardening",
              readable: false,
            });
            checks.push({
              id,
              category: meta.category,
              title: meta.title,
              status: "unknown",
              summary: "OpenSSH server configuration could not be read.",
              evidenceIds: [evId],
              sourceCoverage,
            });
            break;
          }

          const parsed = parseSshdConfig(sshdMainText, sshDropInsResult);
          if (parsed.hasMatchLoosening) {
            sourceCoverage.sshd_main = "partial";
          }
          if (parsed.dropInsMissing) {
            sourceCoverage.sshd_dropins = "unavailable";
          } else if (parsed.hasUnhandledInclude) {
            sourceCoverage.sshd_dropins = "partial";
          }

          const sshPorts = new Set<number>(parsed.ports);
          const exposedSshEntries = exposure.filter(
            (entry) =>
              sshPorts.has(entry.listener.port) &&
              (entry.reachability === "exposed_lan" ||
                entry.reachability === "exposed_v4_v6" ||
                entry.publication === "funnel"),
          );

          // OpenSSH defaults when unspecified: PasswordAuthentication=yes, PermitRootLogin=prohibit-password
          const passwordEnabled =
            parsed.passwordAuthentication === "yes" ||
            (parsed.passwordAuthentication === null && !parsed.dropInsMissing);
          const rootLoginAllowed = parsed.permitRootLogin === "yes";
          const rootLoginNotDisabled =
            parsed.permitRootLogin !== "no" &&
            !(parsed.permitRootLogin === null && parsed.dropInsMissing);
          const kbdInteractiveEnabled = parsed.kbdInteractiveAuthentication === "yes";

          const evId = addEvidence("criterion", "ssh_hardening", {
            criterion: "ssh_hardening",
            permitRootLogin: parsed.permitRootLogin,
            passwordAuthentication: parsed.passwordAuthentication,
            kbdInteractiveAuthentication: parsed.kbdInteractiveAuthentication,
            hasMatchLoosening: parsed.hasMatchLoosening,
            exposedOutsideTailnetCount: exposedSshEntries.length,
          });

          const checkEvidenceIds = [evId, ...exposedSshEntries.flatMap((e) => e.evidenceIds)];
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
          } else if (rootLoginNotDisabled && !parsed.dropInsMissing) {
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
          } else if (parsed.hasMatchLoosening) {
            status = "warn";
            summary =
              "Global SSH directives are hardened, but Match-scoped blocks loosen authentication.";
            addFinding(id, "match_loosening", "warning", summary, [evId]);
          } else {
            status = "pass";
            summary =
              "SSH disables root and password authentication and is not exposed outside Tailnet.";
          }

          checks.push({
            id,
            category: meta.category,
            title: meta.title,
            status,
            summary,
            ...(remediation ? { remediation } : {}),
            evidenceIds: checkEvidenceIds,
            sourceCoverage,
          });
          break;
        }

        case "package_updates": {
          const updatesRes = commandResults.get("updates");
          const archAuditRes = commandResults.get("arch_audit");
          const pacmanLogText = fileResults.get("pacman-log") ?? null;

          const sourceCoverage: Record<string, Coverage> = {
            updates: updatesRes?.status === "ok" ? "complete" : "unavailable",
            pacman_log: pacmanLogText !== null ? "complete" : "unavailable",
            arch_audit: archAuditRes?.status === "ok" ? "complete" : "unavailable",
          };

          const parsedUpdates =
            updatesRes?.status === "ok"
              ? parsePacmanUpdates(updatesRes.stdout, updatesRes.exitCode)
              : null;
          const lastUpgradeAt =
            pacmanLogText !== null ? parsePacmanLogLastUpgrade(pacmanLogText) : null;
          const daysSinceUpgrade =
            lastUpgradeAt !== null
              ? Math.floor((capturedAt - lastUpgradeAt) / DAY_MS)
              : null;
          const isStaleUpgrade =
            lastUpgradeAt !== null && capturedAt - lastUpgradeAt > STALE_UPGRADE_DAYS * DAY_MS;

          const auditParsed =
            archAuditRes?.status === "ok" ? parseArchAudit(archAuditRes.stdout) : null;

          const evId = addEvidence("criterion", "package_updates", {
            criterion: "package_updates",
            pendingCount: parsedUpdates?.totalCount ?? null,
            kernelUpdateCount: parsedUpdates?.kernelCount ?? null,
            daysSinceLastUpgrade: daysSinceUpgrade,
            advisoryCount: auditParsed?.advisoryCount ?? null,
            highAdvisoryCount: auditParsed?.highOrCriticalCount ?? null,
          });

          if (parsedUpdates === null) {
            checks.push({
              id,
              category: meta.category,
              title: meta.title,
              status: "unknown",
              summary: "Pending package updates could not be checked.",
              evidenceIds: [evId],
              sourceCoverage,
            });
            break;
          }

          const issues: { slug: string; severity: Severity; text: string }[] = [];

          if (auditParsed && auditParsed.advisoryCount > 0) {
            issues.push({
              slug: "arch_audit",
              severity: auditParsed.highOrCriticalCount > 0 ? "critical" : "warning",
              text: `arch-audit reported ${auditParsed.advisoryCount} upgradable security advisory(ies).`,
            });
          }
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
            summary = issues.map((i) => i.text).join(" ");
            remediation = "Upgrade system packages and reboot if a kernel update is installed.";
            for (const issue of issues) {
              addFinding(id, issue.slug, issue.severity, issue.text, [evId]);
            }
          } else {
            status = "pass";
            summary = "Packages are up to date with recent upgrade history and no advisories.";
          }

          checks.push({
            id,
            category: meta.category,
            title: meta.title,
            status,
            summary,
            ...(remediation ? { remediation } : {}),
            evidenceIds: [evId],
            sourceCoverage,
          });
          break;
        }

        case "disk_and_boot": {
          const blockRes = commandResults.get("block_devices");
          const bootRes = commandResults.get("boot_status");

          const blockParsed =
            blockRes?.status === "ok" ? parseBlockDevices(blockRes.stdout) : null;
          const bootParsed =
            bootRes?.status === "ok" ? parseBootStatus(bootRes.stdout) : null;

          const bootFieldsComplete =
            bootParsed !== null &&
            bootParsed.secureBoot !== "unknown" &&
            bootParsed.tpm2 !== "unknown";

          const sourceCoverage: Record<string, Coverage> = {
            block_devices: blockParsed !== null ? "complete" : "unavailable",
            boot_status:
              bootParsed === null
                ? "unavailable"
                : bootFieldsComplete
                  ? "complete"
                  : "partial",
          };

          const evId = addEvidence("criterion", "disk_and_boot", {
            criterion: "disk_and_boot",
            rootEncrypted: blockParsed?.rootEncrypted ?? null,
            unencryptedSecondaryCount: blockParsed?.unencryptedSecondaryCount ?? null,
            secureBoot: bootParsed?.secureBoot ?? null,
            tpm2: bootParsed?.tpm2 ?? null,
          });

          if (blockParsed === null && bootParsed === null) {
            checks.push({
              id,
              category: meta.category,
              title: meta.title,
              status: "unknown",
              summary: "Disk encryption and boot security status could not be inspected.",
              evidenceIds: [evId],
              sourceCoverage,
            });
            break;
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

          checks.push({
            id,
            category: meta.category,
            title: meta.title,
            status,
            summary,
            ...(remediation ? { remediation } : {}),
            evidenceIds: [evId],
            sourceCoverage,
          });
          break;
        }

        case "kernel_sysctl": {
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
            addFinding(
              id,
              "unsafe_sysctl",
              status === "fail" ? "critical" : "warning",
              summary,
              [evId],
            );
          } else {
            status = "pass";
            summary =
              coverage === "partial"
                ? `All ${parsed!.observed.size} observed kernel sysctl parameters meet hardening defaults (${parsed!.missingKeys.length} unavailable).`
                : "All kernel sysctl hardening parameters meet expected values.";
          }

          checks.push({
            id,
            category: meta.category,
            title: meta.title,
            status,
            summary,
            ...(remediation ? { remediation } : {}),
            evidenceIds: [evId],
            sourceCoverage,
          });
          break;
        }

        case "systemd_health": {
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
          const userFailed =
            userFailedRes?.status === "ok" ? parseSystemdUnits(userFailedRes.stdout) : [];
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
            criterion: "systemd_health",
            systemFailedCount: sysFailedRes?.status === "ok" ? systemFailed.length : null,
            userFailedCount: userFailedRes?.status === "ok" ? userFailed.length : null,
            snapperDegradedCount: snapperRes?.status === "ok" ? snapperDegraded.length : null,
            limineDegradedCount: limineRes?.status === "ok" ? limineDegraded.length : null,
          });

          if (allUnavailable) {
            checks.push({
              id,
              category: meta.category,
              title: meta.title,
              status: "unknown",
              summary: "Systemd unit health could not be queried.",
              evidenceIds: [evId],
              sourceCoverage,
            });
            break;
          }

          const checkEvidenceIds = [evId];
          const unitEvidenceIds: string[] = [];

          const recordUnitEvidence = (scope: string, units: readonly ParsedUnit[]) => {
            for (const u of units) {
              const unitEvId = addEvidence("unit", `${scope}:${u.unit}`, {
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
            systemFailed.length +
            userFailed.length +
            snapperDegraded.length +
            limineDegraded.length;

          let status: PostureCheck["status"];
          let summary: string;
          let remediation: string | undefined;

          if (totalIssues > 0) {
            status = systemFailed.length > 0 ? "fail" : "warn";
            const parts: string[] = [];
            if (systemFailed.length > 0) parts.push(`${systemFailed.length} failed system unit(s)`);
            if (userFailed.length > 0) parts.push(`${userFailed.length} failed user unit(s)`);
            if (snapperDegraded.length > 0)
              parts.push(`${snapperDegraded.length} degraded Snapper unit(s)`);
            if (limineDegraded.length > 0)
              parts.push(`${limineDegraded.length} degraded Limine unit(s)`);
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

          checks.push({
            id,
            category: meta.category,
            title: meta.title,
            status,
            summary,
            ...(remediation ? { remediation } : {}),
            evidenceIds: checkEvidenceIds,
            sourceCoverage,
          });
          break;
        }

        case "process_and_timers": {
          const procRes = commandResults.get("processes");
          const timersRes = commandResults.get("user_timers");

          const sourceCoverage: Record<string, Coverage> = {
            processes: procRes?.status === "ok" ? "complete" : "unavailable",
            user_timers: timersRes?.status === "ok" ? "complete" : "unavailable",
            sockets: socketsAvailable ? "complete" : "unavailable",
          };

          const processMap =
            procRes?.status === "ok" ? parseProcesses(procRes.stdout, capturedAt) : null;
          const userTimers =
            timersRes?.status === "ok" ? parseUserTimers(timersRes.stdout) : null;

          const unexpectedListeners = socketsAvailable
            ? listeners.filter((listener) => !expectedPortSet.has(listener.port))
            : [];

          const evId = addEvidence("criterion", "process_and_timers", {
            criterion: "process_and_timers",
            processCount: processMap?.size ?? null,
            userTimerCount: userTimers?.length ?? null,
            unexpectedListenerCount: socketsAvailable ? unexpectedListeners.length : null,
          });

          if (processMap === null && userTimers === null && !socketsAvailable) {
            checks.push({
              id,
              category: meta.category,
              title: meta.title,
              status: "unknown",
              summary: "Process, timer, and socket inventory could not be collected.",
              evidenceIds: [evId],
              sourceCoverage,
            });
            break;
          }

          const checkEvidenceIds = [evId];
          const flaggedProcessEvIds: string[] = [];

          for (let i = 0; i < unexpectedListeners.length; i++) {
            const listener = unexpectedListeners[i]!;
            const proc = listener.pid !== undefined ? processMap?.get(listener.pid) : undefined;
            const parent = proc !== undefined ? processMap?.get(proc.ppid) : undefined;
            const comm = proc?.comm ?? listener.process ?? null;

            const procEvId = addEvidence("process", `unexpected:${listener.port}:${i}`, {
              comm,
              pid: proc?.pid ?? listener.pid ?? null,
              uid: proc?.uid ?? null,
              startedAt: proc?.startedAt ?? null,
              parentComm: parent?.comm ?? null,
              protocol: listener.protocol,
              port: listener.port,
            });
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
            addFinding(id, "unexpected_socket_owners", "warning", summary, [
              evId,
              ...flaggedProcessEvIds,
            ]);
          } else if (processMap === null || !socketsAvailable) {
            status = "unknown";
            summary = "Process or socket inventory is unavailable.";
          } else {
            status = "pass";
            summary = "All socket-owning processes listen only on expected ports.";
          }

          checks.push({
            id,
            category: meta.category,
            title: meta.title,
            status,
            summary,
            ...(remediation ? { remediation } : {}),
            evidenceIds: checkEvidenceIds,
            sourceCoverage,
          });
          break;
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
