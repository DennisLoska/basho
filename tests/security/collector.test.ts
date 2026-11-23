import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createPostureFiles,
  evaluateFirewall,
  parseListeners,
  PostureCollector,
} from "../../src/security/collector";
import { criterionIds } from "../../src/security/types";
import type {
  CommandRequest,
  CommandResult,
  Coverage,
  CriterionId,
  SecuritySettings,
} from "../../src/security/types";

const NOW = 1_796_000_000_000;
const DAY_MS = 86_400_000;

const COVERAGE_VALUES: readonly Coverage[] = ["complete", "partial", "unavailable"];
const SEVERITIES: readonly string[] = ["info", "warning", "critical", "breach"];

type FileSource = "ufw-v4" | "ufw-v6" | "ufw-default" | "sshd-main" | "pacman-log";
type CollectResult = Awaited<ReturnType<PostureCollector["collect"]>>;

const okResult = (stdout: string, exitCode = 0): CommandResult => ({
  status: "ok",
  stdout,
  exitCode,
});

const UNAVAILABLE: CommandResult = { status: "unavailable" };

function settings(patch: Partial<SecuritySettings> = {}): SecuritySettings {
  return {
    mode: "approve",
    scanIntervalMinutes: 60,
    criteria: Object.fromEntries(criterionIds.map((id) => [id, true])) as Record<
      CriterionId,
      boolean
    >,
    expectedPorts: [22, 6969],
    workloads: [],
    ai: {
      baseURL: "https://example.test/v1",
      model: "test-model",
      sessionHeader: true,
      confidenceThreshold: 0.85,
      triageCooldownMinutes: 10,
    },
    notifications: { channels: ["in-app"], cooldownMinutes: 15 },
    lockdown: { proposalMinutes: 30, leaseSeconds: 600, helperEnabled: false },
    process: { host: "127.0.0.1", port: 6969, securityDbPath: ":memory:", demo: true },
    ...patch,
  };
}

function disabledExcept(enabled: CriterionId[]): Record<CriterionId, boolean> {
  const on = new Set(enabled);
  return Object.fromEntries(criterionIds.map((id) => [id, on.has(id)])) as Record<
    CriterionId,
    boolean
  >;
}

function pacmanStamp(daysAgo: number): string {
  const at = new Date(NOW - daysAgo * DAY_MS);
  const pad = (value: number) => String(value).padStart(2, "0");
  const date = `${at.getUTCFullYear()}-${pad(at.getUTCMonth() + 1)}-${pad(at.getUTCDate())}`;
  const time = `${pad(at.getUTCHours())}:${pad(at.getUTCMinutes())}:${pad(at.getUTCSeconds())}`;
  return `[${date}T${time}+0000]`;
}

const SS_HEADER =
  "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess";

function ss(...rows: string[]): string {
  return [SS_HEADER, ...rows].join("\n");
}

const UFW_STATUS_ACTIVE = [
  "Status: active",
  "Logging: on (low)",
  "Default: deny (incoming), allow (outgoing), disabled (routed)",
  "New profiles: skip",
].join("\n");

const UFW_DEFAULT_DROP = ['IPV6=yes', 'DEFAULT_INPUT_POLICY="DROP"', 'DEFAULT_OUTPUT_POLICY="ACCEPT"'].join(
  "\n",
);

const HARDENED_SSHD = [
  "Port 22",
  "PermitRootLogin no",
  "PasswordAuthentication no",
  "KbdInteractiveAuthentication no",
].join("\n");

const ENCRYPTED_LSBLK = JSON.stringify({
  blockdevices: [
    {
      name: "nvme0n1",
      type: "disk",
      fstype: null,
      mountpoint: null,
      children: [
        {
          name: "nvme0n1p2",
          type: "part",
          fstype: "crypto_LUKS",
          mountpoint: null,
          children: [
            { name: "luks-root", type: "crypt", fstype: "btrfs", mountpoint: "/" },
          ],
        },
        { name: "nvme0n1p1", type: "part", fstype: "vfat", mountpoint: null },
      ],
    },
  ],
});

const BOOT_OK = [
  "System:",
  "      Firmware: UEFI 2.70 (American Megatrends 5.17)",
  " Firmware Arch: x64",
  "   Secure Boot: enabled (user)",
  "  TPM2 Support: yes",
  "  Boot into FW: supported",
].join("\n");

const SYSCTL_SAFE = [
  "kernel.kptr_restrict = 2",
  "kernel.dmesg_restrict = 1",
  "kernel.unprivileged_bpf_disabled = 1",
  "kernel.yama.ptrace_scope = 1",
  "kernel.kexec_load_disabled = 1",
  "fs.suid_dumpable = 0",
  "net.ipv4.conf.all.rp_filter = 1",
  "net.ipv4.conf.all.accept_redirects = 0",
  "net.ipv6.conf.all.accept_redirects = 0",
].join("\n");

const DEFAULT_FILES: Record<FileSource, string | null> = {
  "ufw-v4": "-A ufw-user-input -p tcp --dport 6969 -j ACCEPT",
  "ufw-v6": "-A ufw6-user-input -j RETURN",
  "ufw-default": UFW_DEFAULT_DROP,
  "sshd-main": HARDENED_SSHD,
  "pacman-log": `${pacmanStamp(2)} [ALPM] upgraded bash (5.2.026-1 -> 5.3.0-1)`,
};

const DEFAULT_COMMANDS: Record<string, CommandResult> = {
  ufw_status: okResult(UFW_STATUS_ACTIVE),
  sockets: okResult(
    ss('tcp   LISTEN 0      128    127.0.0.1:6969    0.0.0.0:*    users:(("bun",pid=4242,fd=18))'),
  ),
  tailscale_serve: okResult("{}"),
  tailscale_funnel: okResult("{}"),
  updates: okResult("", 1),
  arch_audit: UNAVAILABLE,
  block_devices: okResult(ENCRYPTED_LSBLK),
  boot_status: okResult(BOOT_OK),
  sysctl: okResult(SYSCTL_SAFE),
  system_failed: okResult(""),
  user_failed: okResult(""),
  user_timers: okResult(""),
  processes: okResult("  4242     1  1000     900 bun"),
  snapper_health: okResult("snapper-timeline.timer loaded active waiting ..."),
  limine_health: okResult(""),
};

const ALL_COMMANDS_UNAVAILABLE: Record<string, CommandResult> = Object.fromEntries(
  Object.keys(DEFAULT_COMMANDS).map((kind) => [kind, UNAVAILABLE]),
);

const ALL_FILES_UNAVAILABLE: Record<FileSource, null> = {
  "ufw-v4": null,
  "ufw-v6": null,
  "ufw-default": null,
  "sshd-main": null,
  "pacman-log": null,
};

interface HarnessOptions {
  commands?: Record<string, CommandResult>;
  files?: Partial<Record<FileSource, string | null>>;
  dropIns?: { name: string; text: string }[] | null;
  now?: number;
}

function harness(options: HarnessOptions = {}) {
  const requests: CommandRequest[] = [];
  const fileReads: string[] = [];
  const commands = { ...DEFAULT_COMMANDS, ...options.commands };
  const files = { ...DEFAULT_FILES, ...options.files };

  const runner = {
    async run(request: CommandRequest): Promise<CommandResult> {
      requests.push(request);
      return commands[request.kind] ?? UNAVAILABLE;
    },
  };

  const fileReader = {
    async read(source: FileSource): Promise<string | null> {
      fileReads.push(source);
      return files[source] ?? null;
    },
    async sshDropIns(): Promise<{ name: string; text: string }[] | null> {
      return options.dropIns === undefined ? [] : options.dropIns;
    },
  };

  const now = options.now ?? NOW;
  const collector = new PostureCollector({
    runner,
    files: fileReader,
    clock: { now: () => now },
  });

  return { collector, requests, fileReads, now };
}

function knownEvidenceIds(result: CollectResult): Set<string> {
  return new Set(result.snapshot.evidence.map((entry) => entry.id));
}

function checkById(result: CollectResult, id: CriterionId) {
  const check = result.snapshot.checks.find((candidate) => candidate.id === id);
  expect(check).toBeDefined();
  return check!;
}

function findingsFor(result: CollectResult, check: ReturnType<typeof checkById>) {
  const ids = new Set(check.evidenceIds);
  return result.findings.filter((finding) => finding.evidenceIds.some((id) => ids.has(id)));
}

function entryByPort(result: CollectResult, port: number) {
  const entry = result.exposure.find((candidate) => candidate.listener.port === port);
  expect(entry).toBeDefined();
  return entry!;
}

describe("parseListeners", () => {
  test("keeps protocol, bind family, address, port, and process metadata", () => {
    const listeners = parseListeners(
      ss(
        'tcp   LISTEN 0      128    [::1]:22               [::]:*               users:(("sshd",pid=123,fd=3))',
        "udp   UNCONN 0      0      0.0.0.0:41641          0.0.0.0:*",
      ),
    );

    expect(listeners).toHaveLength(2);
    expect(listeners[0]).toMatchObject({
      protocol: "tcp",
      family: 6,
      address: "::1",
      port: 22,
      pid: 123,
      process: "sshd",
    });
    expect(listeners[1]).toMatchObject({
      protocol: "udp",
      family: 4,
      address: "0.0.0.0",
      port: 41641,
    });
    expect(listeners[1]!.pid).toBeUndefined();
  });

  test("parses interface-scoped IPv6, wildcard binds, and IPv4 loopback", () => {
    const listeners = parseListeners(
      ss(
        "tcp   LISTEN 0      128    [fd7a:115c:a1e0::1]%tailscale0:443   [::]:*",
        "tcp   LISTEN 0      128    *:3003                          *:*",
        "tcp   LISTEN 0      128    127.0.0.1:6969                  0.0.0.0:*",
      ),
    );

    expect(listeners).toHaveLength(3);
    expect(listeners[0]).toMatchObject({
      family: 6,
      address: "fd7a:115c:a1e0::1",
      port: 443,
      interfaceName: "tailscale0",
    });
    expect(listeners[1]).toMatchObject({ family: "unspecified", address: "*", port: 3003 });
    expect(listeners[2]).toMatchObject({ family: 4, address: "127.0.0.1", port: 6969 });
  });

  test("skips the header, blank lines, and unparsable rows", () => {
    const listeners = parseListeners(
      ["", SS_HEADER, "tcp", "", "tcp   LISTEN 0      128    0.0.0.0:8080   0.0.0.0:*", ""].join(
        "\n",
      ),
    );

    expect(listeners).toHaveLength(1);
    expect(listeners[0]).toMatchObject({ protocol: "tcp", address: "0.0.0.0", port: 8080 });
  });

  test("assigns unique non-empty ids and numeric ports", () => {
    const listeners = parseListeners(
      ss(
        "tcp   LISTEN 0      128    0.0.0.0:8080   0.0.0.0:*",
        "udp   UNCONN 0      0      0.0.0.0:8080   0.0.0.0:*",
      ),
    );

    expect(listeners).toHaveLength(2);
    for (const listener of listeners) {
      expect(typeof listener.id).toBe("string");
      expect(listener.id.length).toBeGreaterThan(0);
      expect(typeof listener.port).toBe("number");
    }
    expect(new Set(listeners.map((listener) => listener.id)).size).toBe(2);
  });

  test("returns an empty list for empty or header-only input", () => {
    expect(parseListeners("")).toEqual([]);
    expect(parseListeners(SS_HEADER)).toEqual([]);
  });
});

describe("evaluateFirewall", () => {
  const DROP_THEN_ACCEPT = [
    "-A ufw-user-input -p tcp --dport 8188 -j DROP",
    "-A ufw-user-input -p tcp --dport 8188 -j ACCEPT",
  ].join("\n");

  const ACCEPT_THEN_DROP = [
    "-A ufw-user-input -p tcp --dport 8188 -j ACCEPT",
    "-A ufw-user-input -p tcp --dport 8188 -j DROP",
  ].join("\n");

  test("applies the first matching terminal rule", () => {
    const listener = { family: 4 as const, protocol: "tcp" as const, port: 8188, address: "0.0.0.0" };

    expect(
      evaluateFirewall(listener, {
        active: true,
        v4: DROP_THEN_ACCEPT,
        defaultInput: "allow",
      }),
    ).toBe("deny");

    expect(
      evaluateFirewall(listener, {
        active: true,
        v4: ACCEPT_THEN_DROP,
        defaultInput: "deny",
      }),
    ).toBe("allow");
  });

  test("evaluates IPv4 and IPv6 families independently", () => {
    const v4Rules = "-A ufw-user-input -p tcp --dport 8188 -j ACCEPT";
    const v4Listener = { family: 4 as const, protocol: "tcp" as const, port: 8188, address: "0.0.0.0" };
    const v6Listener = { family: 6 as const, protocol: "tcp" as const, port: 8188, address: "::" };

    expect(
      evaluateFirewall(v4Listener, { active: true, v4: v4Rules, defaultInput: "deny" }),
    ).toBe("allow");

    expect(
      evaluateFirewall(v6Listener, { active: true, v4: v4Rules, defaultInput: "deny" }),
    ).toBe("unknown");

    expect(
      evaluateFirewall(v6Listener, { active: true, v4: v4Rules, v6: "", defaultInput: "deny" }),
    ).toBe("unknown");

    expect(
      evaluateFirewall(v6Listener, {
        active: true,
        v4: v4Rules,
        v6: "-A ufw6-user-input -p tcp --dport 8188 -j DROP",
        defaultInput: "allow",
      }),
    ).toBe("deny");
  });

  test("treats an inactive firewall as allow and an unknown state as unknown", () => {
    const listener = { family: 4 as const, protocol: "tcp" as const, port: 8188, address: "0.0.0.0" };

    expect(evaluateFirewall(listener, { active: false })).toBe("allow");
    expect(evaluateFirewall(listener, { active: false, v4: DROP_THEN_ACCEPT })).toBe("allow");
    expect(evaluateFirewall(listener, { active: null })).toBe("unknown");
  });

  test("falls back to the default input policy when no rule matches", () => {
    const listener = { family: 4 as const, protocol: "tcp" as const, port: 8188, address: "0.0.0.0" };
    const unrelated = "-A ufw-user-input -p tcp --dport 3000 -j ACCEPT";

    expect(
      evaluateFirewall(listener, { active: true, v4: unrelated, defaultInput: "deny" }),
    ).toBe("deny");
    expect(
      evaluateFirewall(listener, { active: true, v4: unrelated, defaultInput: "allow" }),
    ).toBe("allow");
  });

  test("requires protocol and port to match before a rule is terminal", () => {
    const tcpOnly = "-A ufw-user-input -p tcp --dport 8188 -j ACCEPT";

    expect(
      evaluateFirewall(
        { family: 4, protocol: "udp", port: 8188, address: "0.0.0.0" },
        { active: true, v4: tcpOnly, defaultInput: "deny" },
      ),
    ).toBe("deny");

    expect(
      evaluateFirewall(
        { family: 4, protocol: "tcp", port: 8189, address: "0.0.0.0" },
        { active: true, v4: tcpOnly, defaultInput: "deny" },
      ),
    ).toBe("deny");
  });

  test("honors interface-scoped rules only for the matching interface", () => {
    const rules = "-A ufw-user-input -i tailscale0 -p tcp --dport 22 -j ACCEPT";

    expect(
      evaluateFirewall(
        { family: 4, protocol: "tcp", port: 22, address: "100.101.102.103", interfaceName: "tailscale0" },
        { active: true, v4: rules, defaultInput: "deny" },
      ),
    ).toBe("allow");

    expect(
      evaluateFirewall(
        { family: 4, protocol: "tcp", port: 22, address: "0.0.0.0", interfaceName: "eth0" },
        { active: true, v4: rules, defaultInput: "deny" },
      ),
    ).toBe("deny");

    expect(
      evaluateFirewall(
        { family: 4, protocol: "tcp", port: 22, address: "0.0.0.0" },
        { active: true, v4: rules, defaultInput: "deny" },
      ),
    ).toBe("unknown");
  });

  test("honors source-scoped rules that cover every source", () => {
    const rules = "-A ufw-user-input -s 0.0.0.0/0 -p tcp --dport 8443 -j ACCEPT";

    expect(
      evaluateFirewall(
        { family: 4, protocol: "tcp", port: 8443, address: "0.0.0.0" },
        { active: true, v4: rules, defaultInput: "deny" },
      ),
    ).toBe("allow");
  });

  test("returns unknown for relevant rule syntax it cannot evaluate", () => {
    const listener = { family: 4 as const, protocol: "tcp" as const, port: 8188, address: "0.0.0.0" };

    // A jump into ufw's rate-limit chain cannot be resolved to allow or deny statically.
    expect(
      evaluateFirewall(listener, {
        active: true,
        v4: "-A ufw-user-input -p tcp --dport 8188 -j ufw-user-limit",
        defaultInput: "allow",
      }),
    ).toBe("unknown");
  });

  test("returns unknown for an unspecified bind family", () => {
    expect(
      evaluateFirewall(
        { family: "unspecified", protocol: "tcp", port: 3003, address: "*" },
        { active: true, v4: "-A ufw-user-input -p tcp --dport 3003 -j ACCEPT", defaultInput: "deny" },
      ),
    ).toBe("unknown");
  });
});

describe("PostureCollector", () => {
  test("emits exactly one well-formed check per criterion", async () => {
    const { collector, now } = harness();
    const result = await collector.collect("scan-shape", settings());

    expect(result.snapshot.id).toBe("scan-shape");
    expect(result.snapshot.capturedAt).toBe(now);
    expect(result.snapshot.checks.map((check) => check.id).sort()).toEqual(
      [...criterionIds].sort(),
    );
    expect(result.snapshot.checks).toHaveLength(criterionIds.length);

    const evidenceIds = result.snapshot.evidence.map((entry) => entry.id);
    expect(new Set(evidenceIds).size).toBe(evidenceIds.length);
    for (const evidence of result.snapshot.evidence) {
      expect(["criterion", "listener", "event", "process", "unit"]).toContain(evidence.kind);
    }

    const known = knownEvidenceIds(result);
    for (const check of result.snapshot.checks) {
      for (const id of check.evidenceIds) {
        expect(known.has(id)).toBe(true);
      }
      const coverage: string[] = Object.values(check.sourceCoverage);
      expect(coverage.length).toBeGreaterThan(0);
      for (const value of coverage) {
        expect(COVERAGE_VALUES.includes(value as Coverage)).toBe(true);
      }
    }
  });

  test("passes every criterion on a hardened host", async () => {
    const { collector } = harness();
    const result = await collector.collect("scan-healthy", settings());

    expect(result.snapshot.checks.filter((check) => check.status !== "pass").map((check) => check.id)).toEqual(
      [],
    );
  });

  test("disabled criteria emit disabled checks while enabled ones still evaluate", async () => {
    const { collector } = harness();
    const result = await collector.collect(
      "scan-disabled",
      settings({ criteria: disabledExcept(["firewall_ufw"]) }),
    );

    expect(result.snapshot.checks).toHaveLength(criterionIds.length);
    const disabled = result.snapshot.checks
      .filter((check) => check.status === "disabled")
      .map((check) => check.id)
      .sort();
    expect(disabled).toEqual(criterionIds.filter((id) => id !== "firewall_ufw").sort());
    expect(checkById(result, "firewall_ufw").status).not.toBe("disabled");
  });

  test("issues only read-only collection recipes", async () => {
    const { collector, requests } = harness();
    await collector.collect("scan-recipes", settings());

    const kinds: string[] = requests.map((request) => request.kind);
    for (const expected of ["sockets", "ufw_status", "block_devices", "boot_status", "sysctl"]) {
      expect(kinds).toContain(expected);
    }
    for (const forbidden of ["desktop", "journal", "unit"]) {
      expect(kinds).not.toContain(forbidden);
    }
  });

  test("emits deterministic findings that cite valid warn/fail evidence", async () => {
    const { collector } = harness({
      commands: {
        ufw_status: UNAVAILABLE,
        updates: okResult("linux 6.6.1 -> 6.6.2\nbash 5.2 -> 5.3\n"),
        sysctl: okResult("kernel.kptr_restrict = 0\nfs.suid_dumpable = 2"),
        system_failed: okResult("sshd.service loaded failed failed OpenSSH Daemon"),
      },
      files: {
        "sshd-main": "PasswordAuthentication yes\nPermitRootLogin yes",
      },
    });
    const result = await collector.collect("scan-messy", settings());
    const known = knownEvidenceIds(result);

    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(finding.source).toBe("deterministic");
      expect(finding.evidenceIds.length).toBeGreaterThan(0);
      for (const id of finding.evidenceIds) {
        expect(known.has(id)).toBe(true);
      }
      expect(SEVERITIES).toContain(finding.severity);
    }

    const flagged = result.snapshot.checks.filter(
      (check) => check.status === "warn" || check.status === "fail",
    );
    expect(flagged.length).toBeGreaterThan(2);
    for (const check of flagged) {
      expect(check.evidenceIds.length).toBeGreaterThan(0);
      expect(findingsFor(result, check).length).toBeGreaterThan(0);
    }
  });

  test("produces identical results for identical inputs", async () => {
    const options: HarnessOptions = {
      commands: {
        updates: okResult("linux 6.6.1 -> 6.6.2"),
        system_failed: okResult("sshd.service loaded failed failed OpenSSH Daemon"),
      },
      files: { "sshd-main": "PasswordAuthentication yes\nPermitRootLogin yes" },
    };
    const first = await harness(options).collector.collect("scan-det", settings());
    const second = await harness(options).collector.collect("scan-det", settings());

    expect(second.snapshot).toEqual(first.snapshot);
    expect(second.findings).toEqual(first.findings);
    expect(second.exposure).toEqual(first.exposure);
  });

  test("degrades every criterion to unknown when tools and files are unavailable", async () => {
    const { collector } = harness({
      commands: ALL_COMMANDS_UNAVAILABLE,
      files: ALL_FILES_UNAVAILABLE,
      dropIns: null,
    });
    const result = await collector.collect("scan-nothing", settings());

    expect(result.snapshot.checks).toHaveLength(criterionIds.length);
    expect(result.snapshot.checks.map((check) => check.status)).toEqual(
      criterionIds.map(() => "unknown"),
    );
  });
});

describe("PostureCollector firewall_ufw", () => {
  test("flags unused allow rules once socket and rule coverage are complete", async () => {
    const { collector } = harness({
      files: {
        "ufw-v4": [
          "-A ufw-user-input -p tcp --dport 6969 -j ACCEPT",
          "-A ufw-user-input -p tcp --dport 9999 -j ACCEPT",
        ].join("\n"),
      },
    });
    const result = await collector.collect("scan-unused", settings());
    const check = checkById(result, "firewall_ufw");

    expect(check.status).not.toBe("pass");
    expect(findingsFor(result, check).length).toBeGreaterThan(0);
  });

  test("degrades to unknown with unavailable coverage when ufw status is missing", async () => {
    const { collector } = harness({ commands: { ufw_status: UNAVAILABLE } });
    const result = await collector.collect("scan-ufw-missing", settings());
    const check = checkById(result, "firewall_ufw");

    expect(check.status).toBe("unknown");
    expect(Object.values(check.sourceCoverage)).toContain("unavailable");
  });
});

describe("PostureCollector network_exposure", () => {
  test("marks loopback listeners local_only and compares expectedPorts", async () => {
    const { collector } = harness({
      commands: {
        sockets: okResult(
          ss(
            'tcp   LISTEN 0      128    127.0.0.1:6969    0.0.0.0:*',
            'tcp   LISTEN 0      128    127.0.0.1:12345   0.0.0.0:*',
          ),
        ),
      },
    });
    const result = await collector.collect("scan-loopback", settings());

    const expected = entryByPort(result, 6969);
    expect(expected.reachability).toBe("local_only");
    expect(expected.publication).toBe("none");
    expect(expected.expected).toBe(true);

    const unexpected = entryByPort(result, 12345);
    expect(unexpected.reachability).toBe("local_only");
    expect(unexpected.expected).toBe(false);

    const known = knownEvidenceIds(result);
    for (const entry of result.exposure) {
      expect(entry.evidenceIds.length).toBeGreaterThan(0);
      for (const id of entry.evidenceIds) {
        expect(known.has(id)).toBe(true);
      }
    }
  });

  test("classifies a UFW-allowed wildcard bind as exposed_lan", async () => {
    const { collector } = harness({
      commands: {
        sockets: okResult(ss("tcp   LISTEN 0      128    0.0.0.0:8188    0.0.0.0:*")),
      },
      files: {
        "ufw-v4": "-A ufw-user-input -p tcp --dport 8188 -j ACCEPT",
        "ufw-v6": "-A ufw6-user-input -p tcp --dport 6969 -j ACCEPT",
      },
    });
    const result = await collector.collect("scan-lan", settings());
    const entry = entryByPort(result, 8188);

    expect(entry.reachability).toBe("exposed_lan");
    expect(entry.firewallV4).toBe("allow");
    expect(entry.expected).toBe(false);
  });

  test("classifies a default-denied wildcard bind as blocked_by_ufw", async () => {
    const { collector } = harness({
      commands: {
        sockets: okResult(ss("tcp   LISTEN 0      128    0.0.0.0:7000    0.0.0.0:*")),
      },
      files: {
        "ufw-v4": "-A ufw-user-input -p tcp --dport 6969 -j ACCEPT",
        "ufw-v6": "-A ufw6-user-input -p tcp --dport 6969 -j ACCEPT",
      },
    });
    const result = await collector.collect("scan-blocked", settings());
    const entry = entryByPort(result, 7000);

    expect(entry.reachability).toBe("blocked_by_ufw");
    expect(entry.firewallV4).toBe("deny");
  });

  test("classifies a dual-stack allowed port as exposed_v4_v6", async () => {
    const { collector } = harness({
      commands: {
        sockets: okResult(
          ss(
            "tcp   LISTEN 0      128    0.0.0.0:8443    0.0.0.0:*",
            "tcp   LISTEN 0      128    [::]:8443       [::]:*",
          ),
        ),
      },
      files: {
        "ufw-v4": "-A ufw-user-input -p tcp --dport 8443 -j ACCEPT",
        "ufw-v6": "-A ufw6-user-input -p tcp --dport 8443 -j ACCEPT",
      },
    });
    const result = await collector.collect("scan-dual-stack", settings());
    const entries = result.exposure.filter((entry) => entry.listener.port === 8443);

    expect(entries.length).toBeGreaterThan(0);
    expect(entries.map((entry) => entry.reachability)).toContain("exposed_v4_v6");
    expect(entries.map((entry) => entry.reachability)).not.toContain("unknown");
  });

  test("classifies a loopback bind published through Tailscale Serve as tailnet", async () => {
    const { collector } = harness({
      commands: {
        sockets: okResult(ss("tcp   LISTEN 0      128    127.0.0.1:8080    0.0.0.0:*")),
        tailscale_serve: okResult(
          JSON.stringify({
            Web: {
              "basho.tailnet.ts.net:443": {
                Handlers: { "/": { Proxy: "http://127.0.0.1:8080" } },
              },
            },
          }),
        ),
        tailscale_funnel: okResult("{}"),
      },
    });
    const result = await collector.collect("scan-serve", settings());
    const entry = entryByPort(result, 8080);

    expect(entry.publication).toBe("serve");
    expect(entry.reachability).toBe("tailnet");
  });

  test("classifies a Tailscale Funnel publication as publicly exposed", async () => {
    const { collector } = harness({
      commands: {
        sockets: okResult(ss("tcp   LISTEN 0      128    127.0.0.1:8081    0.0.0.0:*")),
        tailscale_serve: okResult("{}"),
        tailscale_funnel: okResult(
          JSON.stringify({
            Web: {
              "basho.tailnet.ts.net:443": {
                Handlers: { "/": { Proxy: "http://127.0.0.1:8081" } },
              },
            },
            AllowFunnel: { "basho.tailnet.ts.net:443": true },
          }),
        ),
      },
    });
    const result = await collector.collect("scan-funnel", settings());
    const entry = entryByPort(result, 8081);

    expect(entry.publication).toBe("funnel");
    expect(["exposed_v4_v6", "exposed_lan"]).toContain(entry.reachability);
  });

  test("classifies a bind on a Tailscale address as tailnet", async () => {
    const { collector } = harness({
      commands: {
        sockets: okResult(
          ss(
            "tcp   LISTEN 0      128    [fd7a:115c:a1e0::1]%tailscale0:443   [::]:*",
            "tcp   LISTEN 0      128    100.101.102.103:9443             0.0.0.0:*",
          ),
        ),
      },
    });
    const result = await collector.collect("scan-tailnet-bind", settings());

    expect(entryByPort(result, 443).reachability).toBe("tailnet");
    expect(entryByPort(result, 9443).reachability).toBe("tailnet");
  });

  test("leaves wildcard binds unknown when publication tools are unavailable", async () => {
    const { collector } = harness({
      commands: {
        sockets: okResult(ss("tcp   LISTEN 0      128    *:3003    *:*")),
        tailscale_serve: UNAVAILABLE,
        tailscale_funnel: UNAVAILABLE,
      },
    });
    const result = await collector.collect("scan-wildcard", settings());
    const entry = entryByPort(result, 3003);

    expect(entry.reachability).toBe("unknown");
    expect(entry.publication).toBe("unknown");
  });

  test("never projects unrelated command output into the snapshot", async () => {
    const canary = "CANARY5f3a91";
    const { collector } = harness({
      commands: {
        tailscale_serve: okResult(JSON.stringify({ Web: {}, Ephemeral: canary })),
      },
      files: {
        "ufw-v4": `### ${canary}\n-A ufw-user-input -p tcp --dport 6969 -j ACCEPT`,
      },
    });
    const result = await collector.collect("scan-canary", settings());

    expect(JSON.stringify(result.snapshot)).not.toContain(canary);
    expect(JSON.stringify(result.exposure)).not.toContain(canary);
  });
});

describe("PostureCollector ssh_hardening", () => {
  test("applies first-value-wins across lexically ordered include drop-ins", async () => {
    const { collector } = harness({
      files: { "sshd-main": "Include /etc/ssh/sshd_config.d/*.conf" },
      dropIns: [
        {
          name: "20-relaxed.conf",
          text: "PasswordAuthentication yes\nPermitRootLogin yes\nKbdInteractiveAuthentication yes",
        },
        {
          name: "10-hardening.conf",
          text: "PasswordAuthentication no\nPermitRootLogin no\nKbdInteractiveAuthentication no",
        },
      ],
    });
    const result = await collector.collect("scan-ssh-include", settings());

    expect(checkById(result, "ssh_hardening").status).toBe("pass");
  });

  test("flags password authentication and root login when globally enabled", async () => {
    const { collector } = harness({
      files: {
        "sshd-main": [
          "PasswordAuthentication yes",
          "PermitRootLogin yes",
          "KbdInteractiveAuthentication no",
        ].join("\n"),
      },
    });
    const result = await collector.collect("scan-ssh-weak", settings());
    const check = checkById(result, "ssh_hardening");

    expect(check.status).not.toBe("pass");
    expect(findingsFor(result, check).length).toBeGreaterThan(0);
  });

  test("keeps Match-scoped loosenings out of the global verdict", async () => {
    const { collector } = harness({
      files: {
        "sshd-main": [
          "PasswordAuthentication no",
          "PermitRootLogin no",
          "KbdInteractiveAuthentication no",
          "Match User backup",
          "  PasswordAuthentication yes",
          "  PermitRootLogin yes",
        ].join("\n"),
      },
    });
    const result = await collector.collect("scan-ssh-match", settings());
    const check = checkById(result, "ssh_hardening");

    expect(["pass", "warn"]).toContain(check.status);
    if (check.status === "warn") {
      expect(Object.values(check.sourceCoverage)).toContain("partial");
    }
  });

  test("flags port 22 reachable outside the Tailnet", async () => {
    const { collector } = harness({
      commands: {
        sockets: okResult(ss("tcp   LISTEN 0      128    0.0.0.0:22    0.0.0.0:*")),
      },
      files: { "ufw-v4": "-A ufw-user-input -p tcp --dport 22 -j ACCEPT" },
    });
    const result = await collector.collect("scan-ssh-lan", settings());
    const check = checkById(result, "ssh_hardening");

    expect(check.status).not.toBe("pass");
    expect(findingsFor(result, check).length).toBeGreaterThan(0);
  });

  test("accepts sshd bound only to loopback and the Tailnet interface", async () => {
    const { collector } = harness({
      commands: {
        sockets: okResult(
          ss(
            "tcp   LISTEN 0      128    127.0.0.1:22                   0.0.0.0:*",
            "tcp   LISTEN 0      128    [fd7a:115c:a1e0::1]%tailscale0:22   [::]:*",
          ),
        ),
      },
      files: { "ufw-v4": "-A ufw-user-input -p tcp --dport 22 -j ACCEPT" },
    });
    const result = await collector.collect("scan-ssh-tailnet", settings());

    expect(checkById(result, "ssh_hardening").status).toBe("pass");
  });

  test("reports unknown plus unavailable coverage when sshd config is unreadable", async () => {
    const { collector } = harness({ files: { "sshd-main": null }, dropIns: null });
    const result = await collector.collect("scan-ssh-missing", settings());
    const check = checkById(result, "ssh_hardening");

    expect(check.status).toBe("unknown");
    expect(Object.values(check.sourceCoverage)).toContain("unavailable");
  });
});

describe("PostureCollector package_updates", () => {
  test("flags pending kernel updates", async () => {
    const { collector } = harness({
      commands: { updates: okResult("linux 6.6.1 -> 6.6.2\nbash 5.2 -> 5.3\n") },
    });
    const result = await collector.collect("scan-updates", settings());
    const check = checkById(result, "package_updates");

    expect(check.status).not.toBe("pass");
    expect(findingsFor(result, check).length).toBeGreaterThan(0);
  });

  test("treats exit 1 with empty stdout as up to date", async () => {
    const { collector } = harness({ commands: { updates: okResult("", 1) } });
    const result = await collector.collect("scan-up-to-date", settings());

    expect(checkById(result, "package_updates").status).toBe("pass");
  });

  test("degrades to unknown with unavailable coverage when pacman is missing", async () => {
    const { collector } = harness({ commands: { updates: UNAVAILABLE } });
    const result = await collector.collect("scan-pacman-missing", settings());
    const check = checkById(result, "package_updates");

    expect(check.status).toBe("unknown");
    expect(Object.values(check.sourceCoverage)).toContain("unavailable");
  });

  test("flags upgrades older than fourteen days", async () => {
    const { collector } = harness({
      commands: { updates: okResult("", 1) },
      files: {
        "pacman-log": `${pacmanStamp(30)} [ALPM] upgraded bash (5.2.026-1 -> 5.3.0-1)`,
      },
    });
    const result = await collector.collect("scan-stale-upgrade", settings());
    const check = checkById(result, "package_updates");

    expect(check.status).not.toBe("pass");
    expect(findingsFor(result, check).length).toBeGreaterThan(0);
  });

  test("tolerates a missing arch-audit binary", async () => {
    const { collector } = harness({
      commands: { updates: okResult("", 1), arch_audit: UNAVAILABLE },
    });
    const result = await collector.collect("scan-arch-audit-missing", settings());

    expect(checkById(result, "package_updates").status).toBe("pass");
  });

  test("flags arch-audit advisories when arch-audit reports them", async () => {
    const { collector } = harness({
      commands: {
        updates: okResult("", 1),
        arch_audit: okResult(
          [
            "Package:   xz",
            "Severity:  High",
            "Type:      CVE-2024-3094",
            "",
            "Package:   bash",
            "Severity:  Medium",
            "Type:      CVE-2024-1234",
          ].join("\n"),
        ),
      },
    });
    const result = await collector.collect("scan-arch-audit", settings());
    const check = checkById(result, "package_updates");

    expect(check.status).not.toBe("pass");
  });
});

describe("PostureCollector disk_and_boot", () => {
  test("flags an unencrypted secondary mounted volume", async () => {
    const { collector } = harness({
      commands: {
        block_devices: okResult(
          JSON.stringify({
            blockdevices: [
              {
                name: "nvme0n1",
                type: "disk",
                children: [
                  {
                    name: "nvme0n1p2",
                    type: "part",
                    fstype: "crypto_LUKS",
                    children: [
                      { name: "luks-root", type: "crypt", fstype: "btrfs", mountpoint: "/" },
                    ],
                  },
                ],
              },
              { name: "sda1", type: "part", fstype: "ext4", mountpoint: "/mnt/data" },
            ],
          }),
        ),
      },
    });
    const result = await collector.collect("scan-secondary", settings());
    const check = checkById(result, "disk_and_boot");

    expect(check.status).not.toBe("pass");
    expect(findingsFor(result, check).length).toBeGreaterThan(0);
  });

  test("flags an unencrypted root filesystem", async () => {
    const { collector } = harness({
      commands: {
        block_devices: okResult(
          JSON.stringify({
            blockdevices: [{ name: "sda2", type: "part", fstype: "ext4", mountpoint: "/" }],
          }),
        ),
      },
    });
    const result = await collector.collect("scan-plain-root", settings());

    expect(checkById(result, "disk_and_boot").status).not.toBe("pass");
  });

  test("does not pass when boot status lacks Secure Boot or TPM2 fields", async () => {
    const { collector } = harness({
      commands: { boot_status: okResult("System:\n      Firmware: UEFI 2.70\n") },
    });
    const result = await collector.collect("scan-boot-unknown", settings());

    expect(checkById(result, "disk_and_boot").status).not.toBe("pass");
  });
});

describe("PostureCollector kernel_sysctl", () => {
  test("flags unsafe sysctl values", async () => {
    const { collector } = harness({
      commands: {
        sysctl: okResult(
          [
            "kernel.kptr_restrict = 0",
            "kernel.dmesg_restrict = 1",
            "kernel.unprivileged_bpf_disabled = 1",
            "kernel.yama.ptrace_scope = 1",
            "kernel.kexec_load_disabled = 0",
            "fs.suid_dumpable = 2",
            "net.ipv4.conf.all.rp_filter = 1",
            "net.ipv4.conf.all.accept_redirects = 0",
            "net.ipv6.conf.all.accept_redirects = 0",
          ].join("\n"),
        ),
      },
    });
    const result = await collector.collect("scan-sysctl-unsafe", settings());
    const check = checkById(result, "kernel_sysctl");

    expect(check.status).not.toBe("pass");
    expect(findingsFor(result, check).length).toBeGreaterThan(0);
  });

  test("preserves missing-key coverage as partial", async () => {
    const { collector } = harness({
      commands: {
        sysctl: okResult(
          SYSCTL_SAFE.split("\n")
            .filter((line) => !line.startsWith("kernel.kptr_restrict"))
            .join("\n"),
        ),
      },
    });
    const result = await collector.collect("scan-sysctl-partial", settings());
    const check = checkById(result, "kernel_sysctl");

    expect(Object.values(check.sourceCoverage)).toContain("partial");
  });
});

describe("PostureCollector systemd_health", () => {
  test("flags failed system units", async () => {
    const { collector } = harness({
      commands: { system_failed: okResult("sshd.service loaded failed failed OpenSSH Daemon") },
    });
    const result = await collector.collect("scan-system-failed", settings());
    const check = checkById(result, "systemd_health");

    expect(check.status).not.toBe("pass");
    expect(findingsFor(result, check).length).toBeGreaterThan(0);
  });

  test("flags failed user units", async () => {
    const { collector } = harness({
      commands: { user_failed: okResult("basho-agent.service loaded failed failed Basho agent") },
    });
    const result = await collector.collect("scan-user-failed", settings());
    const check = checkById(result, "systemd_health");

    expect(check.status).not.toBe("pass");
    expect(findingsFor(result, check).length).toBeGreaterThan(0);
  });

  test("flags degraded snapper units", async () => {
    const { collector } = harness({
      commands: {
        snapper_health: okResult("snapper-cleanup.service loaded failed failed Snapper cleanup"),
      },
    });
    const result = await collector.collect("scan-snapper-failed", settings());
    const check = checkById(result, "systemd_health");

    expect(check.status).not.toBe("pass");
    expect(findingsFor(result, check).length).toBeGreaterThan(0);
  });

  test("passes when no unit is failing and no snapper unit exists", async () => {
    const { collector } = harness({
      commands: {
        system_failed: okResult(""),
        user_failed: okResult(""),
        snapper_health: okResult(""),
        limine_health: okResult(""),
      },
    });
    const result = await collector.collect("scan-units-clean", settings());

    expect(checkById(result, "systemd_health").status).toBe("pass");
  });
});

describe("PostureCollector process_and_timers", () => {
  test("flags socket owners that listen on unexpected ports", async () => {
    const { collector } = harness({
      commands: {
        sockets: okResult(
          ss(
            'tcp   LISTEN 0      128    0.0.0.0:5321    0.0.0.0:*    users:(("weird-daemon",pid=5150,fd=3))',
          ),
        ),
        processes: okResult("  5150     1  1000     120 weird-daemon"),
      },
    });
    const result = await collector.collect("scan-unexpected-listener", settings());
    const check = checkById(result, "process_and_timers");

    expect(check.status).not.toBe("pass");
    expect(findingsFor(result, check).length).toBeGreaterThan(0);
  });

  test("passes when every socket owner listens on an expected port", async () => {
    const { collector } = harness({
      commands: {
        sockets: okResult(
          ss('tcp   LISTEN 0      128    127.0.0.1:6969    0.0.0.0:*    users:(("bun",pid=4242,fd=18))'),
        ),
        processes: okResult("  4242     1  1000     900 bun"),
        user_timers: okResult("Mon 2026-11-23 06:00:00 UTC 2h left n/a n/a bun-backup.timer bun-backup.service"),
      },
    });
    const result = await collector.collect("scan-expected-listener", settings());
    const check = checkById(result, "process_and_timers");

    expect(check.status).toBe("pass");
    expect(Object.values(check.sourceCoverage)).not.toContain("unavailable");
  });

  test("projects only sanitized process basenames and never leaks cmdline secrets", async () => {
    const secret = "SECRET_TOKEN_991122";
    const { collector } = harness({
      commands: {
        sockets: okResult(
          ss(
            `tcp   LISTEN 0      128    0.0.0.0:5321    0.0.0.0:*    users:(("/opt/app/worker --api-key=${secret}",pid=5150,fd=3))`,
          ),
        ),
        processes: okResult(`  5150     1  1000     120 /opt/app/worker --api-key=${secret}`),
      },
    });
    const result = await collector.collect("scan-proc-sanitize", settings());

    expect(JSON.stringify(result.snapshot)).not.toContain(secret);
    expect(JSON.stringify(result.exposure)).not.toContain(secret);
    expect(JSON.stringify(result.findings)).not.toContain(secret);
    const procEvidence = result.snapshot.evidence.find((e) => e.kind === "process");
    expect(procEvidence?.facts.comm).toBe("worker");
  });
});

describe("evaluateFirewall additional edge cases", () => {
  test("matches port ranges and multiport rules", () => {
    const rules = [
      "-A ufw-user-input -p tcp --dport 8000:8010 -j ACCEPT",
      "-A ufw-user-input -p tcp -m multiport --dports 80,443 -j ACCEPT",
    ].join("\n");

    expect(
      evaluateFirewall(
        { family: 4, protocol: "tcp", port: 8005, address: "0.0.0.0" },
        { active: true, v4: rules, defaultInput: "deny" },
      ),
    ).toBe("allow");
    expect(
      evaluateFirewall(
        { family: 4, protocol: "tcp", port: 443, address: "0.0.0.0" },
        { active: true, v4: rules, defaultInput: "deny" },
      ),
    ).toBe("allow");
    expect(
      evaluateFirewall(
        { family: 4, protocol: "tcp", port: 8011, address: "0.0.0.0" },
        { active: true, v4: rules, defaultInput: "deny" },
      ),
    ).toBe("deny");
  });

  test("returns unknown when a negated destination port rule could match the listener", () => {
    expect(
      evaluateFirewall(
        { family: 4, protocol: "tcp", port: 8080, address: "0.0.0.0" },
        {
          active: true,
          v4: "-A ufw-user-input -p tcp ! --dport 80 -j DROP",
          defaultInput: "allow",
        },
      ),
    ).toBe("unknown");
  });
});

describe("PostureCollector concurrency and ssh drop-in coverage", () => {
  test("caps concurrent command execution", async () => {
    let inFlight = 0;
    let maxInFlight = 0;

    const runner = {
      async run(request: CommandRequest): Promise<CommandResult> {
        inFlight++;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise((resolve) => setTimeout(resolve, 5));
        inFlight--;
        return DEFAULT_COMMANDS[request.kind] ?? UNAVAILABLE;
      },
    };

    const files = {
      async read(source: FileSource): Promise<string | null> {
        return DEFAULT_FILES[source];
      },
      async sshDropIns(): Promise<{ name: string; text: string }[] | null> {
        return [];
      },
    };

    const collector = new PostureCollector({
      runner,
      files,
      clock: { now: () => NOW },
      concurrency: 3,
    });

    await collector.collect("scan-concurrency", settings());
    expect(maxInFlight).toBeLessThanOrEqual(3);
    expect(maxInFlight).toBeGreaterThan(1);
  });

  test("degrades ssh_hardening to unknown when Include drop-ins are unreadable", async () => {
    const { collector } = harness({
      files: { "sshd-main": "Include /etc/ssh/sshd_config.d/*.conf" },
      dropIns: null,
    });
    const result = await collector.collect("scan-ssh-dropin-null", settings());
    const check = checkById(result, "ssh_hardening");

    expect(check.status).toBe("unknown");
    expect(check.sourceCoverage.sshd_dropins).toBe("unavailable");
  });
});

describe("createPostureFiles", () => {
  test("reads regular files, rejects symlinks, tails large pacman logs, and sorts drop-ins lexically", async () => {
    const dir = await mkdtemp(join(tmpdir(), "basho-posture-files-"));
    try {
      const target = join(dir, "real.rules");
      const link = join(dir, "link.rules");
      const pacmanLog = join(dir, "pacman.log");
      const dropInDir = join(dir, "sshd_config.d");

      await writeFile(target, "-A ufw-user-input -p tcp --dport 22 -j ACCEPT\n");
      await symlink(target, link);

      const fillerLine = `${pacmanStamp(40)} [ALPM] upgraded oldpkg (1.0 -> 1.1)\n`;
      const recentLine = `${pacmanStamp(1)} [ALPM] upgraded linux (6.6.1 -> 6.6.2)\n`;
      await writeFile(pacmanLog, fillerLine.repeat(6000) + recentLine);

      const { mkdir } = await import("node:fs/promises");
      await mkdir(dropInDir);
      await writeFile(join(dropInDir, "20-b.conf"), "PasswordAuthentication yes\n");
      await writeFile(join(dropInDir, "10-a.conf"), "PasswordAuthentication no\n");
      await writeFile(join(dropInDir, "README.txt"), "ignored\n");

      const files = createPostureFiles({
        "ufw-v4": target,
        "ufw-v6": link,
        "ufw-default": join(dir, "missing.conf"),
        "pacman-log": pacmanLog,
        "sshd-drop-ins-dir": dropInDir,
      });

      expect(await files.read("ufw-v4")).toContain("--dport 22");
      expect(await files.read("ufw-v6")).toBeNull();
      expect(await files.read("ufw-default")).toBeNull();

      const tail = await files.read("pacman-log");
      expect(tail).not.toBeNull();
      expect(tail!).toContain("upgraded linux");
      expect(tail!.length).toBeLessThanOrEqual(256 * 1024);

      const dropIns = await files.sshDropIns();
      expect(dropIns?.map((d) => d.name)).toEqual(["10-a.conf", "20-b.conf"]);

      // Symlink inside drop-in dir must cause safe null return.
      await symlink(target, join(dropInDir, "30-link.conf"));
      expect(await files.sshDropIns()).toBeNull();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("PostureCollector spec hardening regressions", () => {
  test("finding 1: treats IPV6=no as IPv6 UFW inactive (allow) and missing IPV6 as unknown", async () => {
    const dualSockets = okResult(
      ss(
        "tcp   LISTEN 0      128    0.0.0.0:8188    0.0.0.0:*",
        "tcp   LISTEN 0      128    [::]:8188       [::]:*",
      ),
    );

    const disabledV6 = await harness({
      commands: { sockets: dualSockets },
      files: {
        "ufw-default": 'IPV6=no\nDEFAULT_INPUT_POLICY="DROP"',
        "ufw-v4": "-A ufw-user-input -j RETURN",
        "ufw-v6": "-A ufw6-user-input -p tcp --dport 8188 -j DROP",
      },
    }).collector.collect("scan-ipv6-off", settings());

    const v4EntryOff = disabledV6.exposure.find((e) => e.listener.family === 4)!;
    const v6EntryOff = disabledV6.exposure.find((e) => e.listener.family === 6)!;
    expect(v4EntryOff.firewallV4).toBe("deny");
    expect(v4EntryOff.reachability).toBe("blocked_by_ufw");
    expect(v6EntryOff.firewallV6).toBe("allow");
    expect(v6EntryOff.reachability).toBe("exposed_lan");

    const missingIpv6Setting = await harness({
      commands: { sockets: dualSockets },
      files: {
        "ufw-default": 'DEFAULT_INPUT_POLICY="DROP"',
        "ufw-v4": "-A ufw-user-input -j RETURN",
        "ufw-v6": "-A ufw6-user-input -j RETURN",
      },
    }).collector.collect("scan-ipv6-missing", settings());

    const v4EntryMissing = missingIpv6Setting.exposure.find((e) => e.listener.family === 4)!;
    const v6EntryMissing = missingIpv6Setting.exposure.find((e) => e.listener.family === 6)!;
    expect(v4EntryMissing.firewallV4).toBe("deny");
    expect(v4EntryMissing.reachability).toBe("blocked_by_ufw");
    expect(v6EntryMissing.firewallV6).toBe("unknown");
    expect(v6EntryMissing.reachability).toBe("unknown");
  });

  test("finding 2: keeps reachability unknown for UFW-denied non-loopback listeners when publication is unknown", async () => {
    const result = await harness({
      commands: {
        sockets: okResult(
          ss(
            "tcp   LISTEN 0      128    0.0.0.0:7000    0.0.0.0:*",
            "tcp   LISTEN 0      128    [::]:7001       [::]:*",
          ),
        ),
        tailscale_serve: UNAVAILABLE,
        tailscale_funnel: UNAVAILABLE,
      },
      files: {
        "ufw-v4": "-A ufw-user-input -j RETURN",
        "ufw-v6": "-A ufw6-user-input -j RETURN",
      },
    }).collector.collect("scan-pub-unknown", settings());

    const v4Entry = entryByPort(result, 7000);
    expect(v4Entry.firewallV4).toBe("deny");
    expect(v4Entry.publication).toBe("unknown");
    expect(v4Entry.reachability).toBe("unknown");

    const v6Entry = entryByPort(result, 7001);
    expect(v6Entry.firewallV6).toBe("deny");
    expect(v6Entry.publication).toBe("unknown");
    expect(v6Entry.reachability).toBe("unknown");
  });

  test("finding 3: matches Tailscale Serve/Funnel backend host, family, and rejects remote hosts", async () => {
    const result = await harness({
      commands: {
        sockets: okResult(
          ss(
            "tcp   LISTEN 0      128    127.0.0.1:8080       0.0.0.0:*",
            "tcp   LISTEN 0      128    [::1]:8080           [::]:*",
            "tcp   LISTEN 0      128    [::1]:8081           [::]:*",
            "tcp   LISTEN 0      128    127.0.0.1:8081       0.0.0.0:*",
            "tcp   LISTEN 0      128    0.0.0.0:8082         0.0.0.0:*",
            "tcp   LISTEN 0      128    127.0.0.1:8082       0.0.0.0:*",
            "tcp   LISTEN 0      128    192.168.1.50:8083    0.0.0.0:*",
            "tcp   LISTEN 0      128    127.0.0.1:8084       0.0.0.0:*",
            "tcp   LISTEN 0      128    [::1]:8084           [::]:*",
            "tcp   LISTEN 0      128    127.0.0.1:8085       0.0.0.0:*",
          ),
        ),
        tailscale_serve: okResult(
          JSON.stringify({
            Web: {
              "host.ts.net:443": {
                Handlers: {
                  "/v4": { Proxy: "http://127.0.0.1:8080" },
                  "/v6": { Proxy: "http://[::1]:8081" },
                  "/remote": { Proxy: "http://198.51.100.9:8082" },
                  "/explicit": { Proxy: "http://192.168.1.50:8083" },
                  "/localhost": { Proxy: "http://localhost:8084" },
                },
              },
            },
            TCP: {
              "8085": { TCPForward: "8085" },
            },
          }),
        ),
        tailscale_funnel: okResult("{}"),
      },
      files: {
        "ufw-v4": "-A ufw-user-input -j RETURN",
        "ufw-v6": "-A ufw6-user-input -j RETURN",
      },
    }).collector.collect("scan-ts-backends", settings());

    const byAddrPort = (addr: string, port: number) =>
      result.exposure.find((e) => e.listener.address === addr && e.listener.port === port)!;

    // 127.0.0.1 matches IPv4 loopback only, not ::1
    expect(byAddrPort("127.0.0.1", 8080).publication).toBe("serve");
    expect(byAddrPort("::1", 8080).publication).toBe("none");

    // [::1] matches IPv6 loopback only, not 127.0.0.1
    expect(byAddrPort("::1", 8081).publication).toBe("serve");
    expect(byAddrPort("127.0.0.1", 8081).publication).toBe("none");

    // Non-loopback IP 198.51.100.9 not proven non-host leaves 0.0.0.0 wildcard unknown,
    // while an explicit non-matching address stays none
    expect(byAddrPort("0.0.0.0", 8082).publication).toBe("unknown");
    expect(byAddrPort("127.0.0.1", 8082).publication).toBe("none");

    // Explicit local IP matches matching listener IP
    expect(byAddrPort("192.168.1.50", 8083).publication).toBe("serve");

    // localhost matches both IPv4 and IPv6 loopback
    expect(byAddrPort("127.0.0.1", 8084).publication).toBe("serve");
    expect(byAddrPort("::1", 8084).publication).toBe("serve");

    // Port-only TCPForward matches port
    expect(byAddrPort("127.0.0.1", 8085).publication).toBe("serve");
  });

  test("finding 4: matches unused UFW allow rules by family, destination IP, interface, and suppresses on incomplete coverage", async () => {
    // IPv6 allow rule with only IPv4 listener on same port is unused
    const v6Mismatch = await harness({
      commands: {
        sockets: okResult(ss("tcp   LISTEN 0      128    127.0.0.1:6969    0.0.0.0:*")),
      },
      files: {
        "ufw-v4": "-A ufw-user-input -p tcp --dport 6969 -j ACCEPT",
        "ufw-v6": "-A ufw6-user-input -p tcp --dport 6969 -j ACCEPT",
      },
    }).collector.collect("scan-ufw-v6-unused", settings());
    expect(checkById(v6Mismatch, "firewall_ufw").status).toBe("warn");

    // Destination IP mismatch is flagged as unused
    const destMismatch = await harness({
      commands: {
        sockets: okResult(ss("tcp   LISTEN 0      128    127.0.0.1:6969    0.0.0.0:*")),
      },
      files: {
        "ufw-v4": "-A ufw-user-input -d 192.168.1.50 -p tcp --dport 6969 -j ACCEPT",
        "ufw-v6": "-A ufw6-user-input -j RETURN",
      },
    }).collector.collect("scan-ufw-dest-unused", settings());
    expect(checkById(destMismatch, "firewall_ufw").status).toBe("warn");

    // Interface scope mismatch is flagged as unused
    const ifaceMismatch = await harness({
      commands: {
        sockets: okResult(
          ss("tcp   LISTEN 0      128    100.101.102.103%tailscale0:22    0.0.0.0:*"),
        ),
      },
      files: {
        "ufw-v4": "-A ufw-user-input -i eth0 -p tcp --dport 22 -j ACCEPT",
        "ufw-v6": "-A ufw6-user-input -j RETURN",
      },
    }).collector.collect("scan-ufw-iface-unused", settings());
    expect(checkById(ifaceMismatch, "firewall_ufw").status).toBe("warn");

    // Matching interface + destination is NOT unused
    const ifaceMatch = await harness({
      commands: {
        sockets: okResult(
          ss("tcp   LISTEN 0      128    100.101.102.103%tailscale0:22    0.0.0.0:*"),
        ),
      },
      files: {
        "ufw-v4": "-A ufw-user-input -i tailscale0 -d 100.101.102.103 -p tcp --dport 22 -j ACCEPT",
        "ufw-v6": "-A ufw6-user-input -j RETURN",
      },
    }).collector.collect("scan-ufw-iface-match", settings());
    expect(checkById(ifaceMatch, "firewall_ufw").status).toBe("pass");

    // Suppress unused-rule findings when sockets are unavailable
    const noSockets = await harness({
      commands: { sockets: UNAVAILABLE },
      files: {
        "ufw-v4": "-A ufw-user-input -p tcp --dport 9999 -j ACCEPT",
        "ufw-v6": "-A ufw6-user-input -j RETURN",
      },
    }).collector.collect("scan-ufw-no-sockets", settings());
    const noSocketsCheck = checkById(noSockets, "firewall_ufw");
    expect(findingsFor(noSockets, noSocketsCheck)).toHaveLength(0);
  });

  test("finding 5: firewall_ufw does not claim no unused rules when sockets or rule files are missing", async () => {
    const missingSockets = await harness({
      commands: { sockets: UNAVAILABLE },
    }).collector.collect("scan-ufw-missing-sockets", settings());
    const checkMissingSockets = checkById(missingSockets, "firewall_ufw");
    expect(checkMissingSockets.summary.toLowerCase()).not.toContain("no unused");
    expect(checkMissingSockets.status).toBe("unknown");
    expect(checkMissingSockets.sourceCoverage.sockets).toBe("unavailable");

    const missingV6 = await harness({
      files: { "ufw-v6": null },
    }).collector.collect("scan-ufw-missing-v6", settings());
    const checkMissingV6 = checkById(missingV6, "firewall_ufw");
    expect(checkMissingV6.summary.toLowerCase()).not.toContain("no unused");
    expect(checkMissingV6.status).toBe("unknown");
    expect(checkMissingV6.sourceCoverage.ufw_v6).toBe("unavailable");
  });

  test("finding 6: ssh_hardening matches Include patterns selectively and marks unresolved includes partial", async () => {
    const selective = await harness({
      files: { "sshd-main": "Include /etc/ssh/sshd_config.d/10-hardening.conf" },
      dropIns: [
        {
          name: "05-weak.conf",
          text: "PasswordAuthentication yes\nPermitRootLogin yes",
        },
        {
          name: "10-hardening.conf",
          text: "PasswordAuthentication no\nPermitRootLogin no\nKbdInteractiveAuthentication no",
        },
      ],
    }).collector.collect("scan-ssh-selective-include", settings());
    const selectiveCheck = checkById(selective, "ssh_hardening");
    expect(selectiveCheck.status).toBe("pass");
    expect(selectiveCheck.sourceCoverage.sshd_dropins).toBe("complete");

    const unresolved = await harness({
      files: {
        "sshd-main": [
          "Include /etc/ssh/sshd_config.d/99-missing.conf",
          "PasswordAuthentication no",
          "PermitRootLogin no",
          "KbdInteractiveAuthentication no",
        ].join("\n"),
      },
      dropIns: [],
    }).collector.collect("scan-ssh-unresolved-include", settings());
    const unresolvedCheck = checkById(unresolved, "ssh_hardening");
    expect(unresolvedCheck.sourceCoverage.sshd_dropins).toBe("partial");
    expect(unresolvedCheck.status).not.toBe("pass");
  });

  test("finding 7: ssh_hardening tracks firewall/publication coverage and narrows summary when exposure is unverified", async () => {
    const noSockets = await harness({
      commands: { sockets: UNAVAILABLE },
    }).collector.collect("scan-ssh-no-sockets", settings());
    const noSocketsCheck = checkById(noSockets, "ssh_hardening");
    expect(noSocketsCheck.sourceCoverage.ufw_status).toBe("complete");
    expect(noSocketsCheck.sourceCoverage.tailscale_serve).toBe("complete");
    expect(noSocketsCheck.sourceCoverage.tailscale_funnel).toBe("complete");
    expect(noSocketsCheck.sourceCoverage.sockets).toBe("unavailable");
    expect(noSocketsCheck.summary.toLowerCase()).not.toContain("not exposed outside tailnet");

    const unknownPort22 = await harness({
      commands: {
        sockets: okResult(ss("tcp   LISTEN 0      128    0.0.0.0:22    0.0.0.0:*")),
        ufw_status: UNAVAILABLE,
      },
    }).collector.collect("scan-ssh-port22-unknown", settings());
    const unknownPort22Check = checkById(unknownPort22, "ssh_hardening");
    expect(unknownPort22Check.sourceCoverage.ufw_status).toBe("unavailable");
    expect(unknownPort22Check.summary.toLowerCase()).not.toContain("not exposed outside tailnet");
  });

  test("finding 8: package_updates still evaluates stale pacman-log and arch-audit when pacman -Qu is unavailable", async () => {
    const staleResult = await harness({
      commands: { updates: UNAVAILABLE },
      files: {
        "pacman-log": `${pacmanStamp(30)} [ALPM] upgraded bash (5.2.026-1 -> 5.3.0-1)`,
      },
    }).collector.collect("scan-pkg-stale-no-qu", settings());
    const staleCheck = checkById(staleResult, "package_updates");
    expect(staleCheck.status).toBe("warn");
    expect(findingsFor(staleResult, staleCheck).length).toBeGreaterThan(0);
    const staleEv = staleResult.snapshot.evidence.find((e) => e.id === staleCheck.evidenceIds[0])!;
    expect(staleEv.facts.pendingCount).toBeNull();

    const auditResult = await harness({
      commands: {
        updates: UNAVAILABLE,
        arch_audit: okResult("Package: xz\nSeverity: High\nType: CVE-2024-3094\n"),
      },
    }).collector.collect("scan-pkg-audit-no-qu", settings());
    const auditCheck = checkById(auditResult, "package_updates");
    expect(auditCheck.status).toBe("fail");
    expect(findingsFor(auditResult, auditCheck).length).toBeGreaterThan(0);
    const auditEv = auditResult.snapshot.evidence.find((e) => e.id === auditCheck.evidenceIds[0])!;
    expect(auditEv.facts.pendingCount).toBeNull();
  });

  test("finding 9: package_updates does not claim recent upgrade history when pacman-log is missing or unparseable", async () => {
    const missingLog = await harness({
      commands: { updates: okResult("", 1) },
      files: { "pacman-log": null },
    }).collector.collect("scan-pkg-no-log", settings());
    const missingCheck = checkById(missingLog, "package_updates");
    expect(missingCheck.sourceCoverage.pacman_log).toBe("unavailable");
    expect(missingCheck.summary.toLowerCase()).not.toContain("recent upgrade history");

    const unparseableLog = await harness({
      commands: { updates: okResult("", 1) },
      files: { "pacman-log": "not an alpm upgrade log\n" },
    }).collector.collect("scan-pkg-bad-log", settings());
    const unparseableCheck = checkById(unparseableLog, "package_updates");
    expect(unparseableCheck.sourceCoverage.pacman_log).toBe("partial");
    expect(unparseableCheck.summary.toLowerCase()).not.toContain("recent upgrade history");
  });

  test("finding 10: systemd unit evidence uses opaque scan-scoped IDs and keeps sanitized unit name in facts", async () => {
    const result = await harness({
      commands: {
        system_failed: okResult("secret-service@prod.service loaded failed failed Secret Service"),
        user_failed: okResult("my-timer.service loaded failed failed My Timer"),
      },
    }).collector.collect("scan-unit-ids", settings());

    const unitEvidence = result.snapshot.evidence.filter((e) => e.kind === "unit");
    expect(unitEvidence).toHaveLength(2);
    for (const ev of unitEvidence) {
      expect(ev.id).not.toContain("secret-service");
      expect(ev.id).not.toContain("my-timer");
      expect(ev.id).toMatch(/^ev:scan-unit-ids:unit:\d+$/);
    }
    expect(unitEvidence[0]!.facts.unit).toBe("secret-service@prod.service");
    expect(unitEvidence[1]!.facts.unit).toBe("my-timer.service");
  });
});

describe("PostureCollector spec re-review regressions (findings 1-6)", () => {
  test("re-review finding 1: wildcard listeners without interfaceName are indeterminate on matching interface-scoped rules", () => {
    const v4Rule = "-A ufw-user-input -i tailscale0 -p tcp --dport 22 -j ACCEPT";
    const v6Rule = "-A ufw6-user-input -i tailscale0 -p tcp --dport 22 -j ACCEPT";

    // Wildcard without interfaceName is indeterminate on matching interface-scoped rule
    expect(
      evaluateFirewall(
        { family: 4, protocol: "tcp", port: 22, address: "0.0.0.0" },
        { active: true, v4: v4Rule, defaultInput: "deny" },
      ),
    ).toBe("unknown");
    expect(
      evaluateFirewall(
        { family: 6, protocol: "tcp", port: 22, address: "::" },
        { active: true, ipv6Enabled: true, v6: v6Rule, defaultInput: "deny" },
      ),
    ).toBe("unknown");

    // Wildcard WITH a specific interfaceName matches or mismatches normally
    expect(
      evaluateFirewall(
        { family: 4, protocol: "tcp", port: 22, address: "0.0.0.0", interfaceName: "tailscale0" },
        { active: true, v4: v4Rule, defaultInput: "deny" },
      ),
    ).toBe("allow");
    expect(
      evaluateFirewall(
        { family: 4, protocol: "tcp", port: 22, address: "0.0.0.0", interfaceName: "eth0" },
        { active: true, v4: v4Rule, defaultInput: "deny" },
      ),
    ).toBe("deny");
    expect(
      evaluateFirewall(
        { family: 6, protocol: "tcp", port: 22, address: "::", interfaceName: "eth0" },
        { active: true, ipv6Enabled: true, v6: v6Rule, defaultInput: "deny" },
      ),
    ).toBe("deny");

    // Unrelated port or protocol does NOT trigger indeterminate
    expect(
      evaluateFirewall(
        { family: 4, protocol: "tcp", port: 8080, address: "0.0.0.0" },
        { active: true, v4: v4Rule, defaultInput: "deny" },
      ),
    ).toBe("deny");
    expect(
      evaluateFirewall(
        { family: 4, protocol: "udp", port: 22, address: "0.0.0.0" },
        { active: true, v4: v4Rule, defaultInput: "deny" },
      ),
    ).toBe("deny");
  });

  test("re-review finding 2: unknown publication reports unknown reachability for loopback and Tailnet listeners while retaining firewall verdicts", async () => {
    const result = await harness({
      commands: {
        sockets: okResult(
          ss(
            "tcp   LISTEN 0      128    127.0.0.1:6969                     0.0.0.0:*",
            "tcp   LISTEN 0      128    [::1]:6970                         [::]:*",
            "tcp   LISTEN 0      128    100.101.102.103:9443               0.0.0.0:*",
            "tcp   LISTEN 0      128    [fd7a:115c:a1e0::1]%tailscale0:443 [::]:*",
          ),
        ),
        tailscale_serve: UNAVAILABLE,
        tailscale_funnel: UNAVAILABLE,
      },
      files: {
        "ufw-v4": "-A ufw-user-input -p tcp --dport 6969 -j ACCEPT",
        "ufw-v6": "-A ufw6-user-input -i tailscale0 -p tcp --dport 443 -j ACCEPT",
      },
    }).collector.collect("scan-pub-unknown-loopback-tailnet", settings());

    const loV4 = entryByPort(result, 6969);
    expect(loV4.publication).toBe("unknown");
    expect(loV4.reachability).toBe("unknown");
    expect(loV4.firewallV4).toBe("allow");
    expect(loV4.firewallV6).toBe("na");

    const loV6 = entryByPort(result, 6970);
    expect(loV6.publication).toBe("unknown");
    expect(loV6.reachability).toBe("unknown");
    expect(loV6.firewallV4).toBe("na");
    expect(loV6.firewallV6).toBe("deny");

    const tsV4 = entryByPort(result, 9443);
    expect(tsV4.publication).toBe("unknown");
    expect(tsV4.reachability).toBe("unknown");
    expect(tsV4.firewallV4).toBe("deny");
    expect(tsV4.firewallV6).toBe("na");

    const tsV6 = entryByPort(result, 443);
    expect(tsV6.publication).toBe("unknown");
    expect(tsV6.reachability).toBe("unknown");
    expect(tsV6.firewallV4).toBe("na");
    expect(tsV6.firewallV6).toBe("allow");
  });

  test("re-review finding 3: resolves explicit 0.0.0.0 and [::] Tailscale targets to loopback/wildcard only, not unrelated LAN or Tailnet IPs", async () => {
    const result = await harness({
      commands: {
        sockets: okResult(
          ss(
            "tcp   LISTEN 0      128    127.0.0.1:8090            0.0.0.0:*",
            "tcp   LISTEN 0      128    0.0.0.0:8090              0.0.0.0:*",
            "tcp   LISTEN 0      128    192.168.1.50:8090         0.0.0.0:*",
            "tcp   LISTEN 0      128    100.101.102.103:8090      0.0.0.0:*",
            "tcp   LISTEN 0      128    [::1]:8090                [::]:*",
            "tcp   LISTEN 0      128    [::1]:8091                [::]:*",
            "tcp   LISTEN 0      128    [::]:8091                 [::]:*",
            "tcp   LISTEN 0      128    [fd7a:115c:a1e0::1]:8091  [::]:*",
            "tcp   LISTEN 0      128    127.0.0.1:8091            0.0.0.0:*",
            "tcp   LISTEN 0      128    0.0.0.0:8091              0.0.0.0:*",
          ),
        ),
        tailscale_serve: okResult(
          JSON.stringify({
            Web: {
              "host.ts.net:443": {
                Handlers: {
                  "/v4zero": { Proxy: "http://0.0.0.0:8090" },
                  "/v6zero": { Proxy: "http://[::]:8091" },
                },
              },
            },
          }),
        ),
        tailscale_funnel: okResult("{}"),
      },
      files: {
        "ufw-v4": "-A ufw-user-input -j RETURN",
        "ufw-v6": "-A ufw6-user-input -j RETURN",
      },
    }).collector.collect("scan-ts-zero-targets", settings());

    const byAddrPort = (addr: string, port: number) =>
      result.exposure.find((e) => e.listener.address === addr && e.listener.port === port)!;

    // 0.0.0.0 -> 127.0.0.1 (matches IPv4 loopback and wildcard, not LAN/tailnet or IPv6)
    expect(byAddrPort("127.0.0.1", 8090).publication).toBe("serve");
    expect(byAddrPort("0.0.0.0", 8090).publication).toBe("serve");
    expect(byAddrPort("192.168.1.50", 8090).publication).toBe("none");
    expect(byAddrPort("100.101.102.103", 8090).publication).toBe("none");
    expect(byAddrPort("::1", 8090).publication).toBe("none");

    // [::] -> ::1 (matches IPv6 loopback and wildcard, not tailnet IPv6 or IPv4)
    expect(byAddrPort("::1", 8091).publication).toBe("serve");
    expect(byAddrPort("::", 8091).publication).toBe("serve");
    expect(byAddrPort("fd7a:115c:a1e0::1", 8091).publication).toBe("none");
    expect(byAddrPort("127.0.0.1", 8091).publication).toBe("none");
    expect(byAddrPort("0.0.0.0", 8091).publication).toBe("none");
  });

  test("re-review finding 4: wildcard listeners preserve unknown publication for non-loopback non-proven-local IPv4 and IPv6 targets", async () => {
    const result = await harness({
      commands: {
        sockets: okResult(
          ss(
            "tcp   LISTEN 0      128    0.0.0.0:8092        0.0.0.0:*",
            "tcp   LISTEN 0      128    127.0.0.1:8092      0.0.0.0:*",
            "tcp   LISTEN 0      128    [::]:8093           [::]:*",
            "tcp   LISTEN 0      128    [::1]:8093          [::]:*",
            "tcp   LISTEN 0      128    192.168.1.60:9000   0.0.0.0:*",
            "tcp   LISTEN 0      128    0.0.0.0:8094        0.0.0.0:*",
          ),
        ),
        tailscale_serve: okResult(
          JSON.stringify({
            Web: {
              "host.ts.net:443": {
                Handlers: {
                  "/v4unproven": { Proxy: "http://198.51.100.9:8092" },
                  "/v6unproven": { Proxy: "http://[2001:db8::9]:8093" },
                  "/v4local": { Proxy: "http://192.168.1.60:8094" },
                },
              },
            },
          }),
        ),
        tailscale_funnel: okResult("{}"),
      },
      files: {
        "ufw-v4": "-A ufw-user-input -j RETURN",
        "ufw-v6": "-A ufw6-user-input -j RETURN",
      },
    }).collector.collect("scan-ts-wildcard-unproven", settings());

    const byAddrPort = (addr: string, port: number) =>
      result.exposure.find((e) => e.listener.address === addr && e.listener.port === port)!;

    expect(byAddrPort("0.0.0.0", 8092).publication).toBe("unknown");
    expect(byAddrPort("0.0.0.0", 8092).reachability).toBe("unknown");
    expect(byAddrPort("127.0.0.1", 8092).publication).toBe("none");

    expect(byAddrPort("::", 8093).publication).toBe("unknown");
    expect(byAddrPort("::", 8093).reachability).toBe("unknown");
    expect(byAddrPort("::1", 8093).publication).toBe("none");

    // Proven-local IP (observed on another listener) still matches wildcard
    expect(byAddrPort("0.0.0.0", 8094).publication).toBe("serve");
  });

  test("re-review finding 5: indeterminate UFW allow rules mark audit coverage partial and never claim no unused allow rules", async () => {
    const indeterminateMatch = await harness({
      files: {
        "ufw-v4": [
          "-A ufw-user-input -p tcp --dport 6969 -j ACCEPT",
          "-A ufw-user-input -p tcp --dport 9999 -m conntrack --ctstate NEW -j ACCEPT",
        ].join("\n"),
        "ufw-v6": "-A ufw6-user-input -j RETURN",
      },
    }).collector.collect("scan-ufw-indeterminate-match", settings());

    const checkMatch = checkById(indeterminateMatch, "firewall_ufw");
    expect(checkMatch.sourceCoverage.rule_audit).toBe("partial");
    expect(checkMatch.status).toBe("unknown");
    expect(checkMatch.summary.toLowerCase()).not.toContain("no unused");

    const negatedPort = await harness({
      files: {
        "ufw-v4": [
          "-A ufw-user-input -p tcp --dport 6969 -j ACCEPT",
          "-A ufw-user-input -p tcp ! --dport 80 -j ACCEPT",
        ].join("\n"),
        "ufw-v6": "-A ufw6-user-input -j RETURN",
      },
    }).collector.collect("scan-ufw-negated-allow", settings());

    const checkNegated = checkById(negatedPort, "firewall_ufw");
    expect(checkNegated.sourceCoverage.rule_audit).toBe("partial");
    expect(checkNegated.status).toBe("unknown");
    expect(checkNegated.summary.toLowerCase()).not.toContain("no unused");

    const rateLimitJump = await harness({
      files: {
        "ufw-v4": [
          "-A ufw-user-input -p tcp --dport 6969 -j ACCEPT",
          "-A ufw-user-input -p tcp --dport 22 -j ufw-user-limit",
        ].join("\n"),
        "ufw-v6": "-A ufw6-user-input -j RETURN",
      },
    }).collector.collect("scan-ufw-limit-jump", settings());

    const checkLimit = checkById(rateLimitJump, "firewall_ufw");
    expect(checkLimit.sourceCoverage.rule_audit).toBe("partial");
    expect(checkLimit.status).toBe("unknown");
    expect(checkLimit.summary.toLowerCase()).not.toContain("no unused");
  });

  test("re-review finding 6: SSH Include glob matching zero drop-in files marks coverage partial", async () => {
    const emptyGlob = await harness({
      files: {
        "sshd-main": [
          "Include /etc/ssh/sshd_config.d/*.conf",
          "PasswordAuthentication no",
          "PermitRootLogin no",
          "KbdInteractiveAuthentication no",
        ].join("\n"),
      },
      dropIns: [],
    }).collector.collect("scan-ssh-empty-glob", settings());

    const checkEmpty = checkById(emptyGlob, "ssh_hardening");
    expect(checkEmpty.sourceCoverage.sshd_dropins).toBe("partial");
    expect(checkEmpty.status).toBe("unknown");

    const unmatchedPrefixGlob = await harness({
      files: {
        "sshd-main": [
          "Include /etc/ssh/sshd_config.d/10-*.conf",
          "PasswordAuthentication no",
          "PermitRootLogin no",
          "KbdInteractiveAuthentication no",
        ].join("\n"),
      },
      dropIns: [{ name: "99-other.conf", text: "Port 22" }],
    }).collector.collect("scan-ssh-unmatched-glob", settings());

    const checkUnmatched = checkById(unmatchedPrefixGlob, "ssh_hardening");
    expect(checkUnmatched.sourceCoverage.sshd_dropins).toBe("partial");
    expect(checkUnmatched.status).toBe("unknown");
  });
});
