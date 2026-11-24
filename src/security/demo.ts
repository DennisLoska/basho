import type { SystemStats } from "../monitors/system";
import type { ServiceEntry } from "../services/registry";
import { loadSecurityConfig } from "./config";
import {
  validateAndMergeOverrides,
  type SecurityRuntime,
  type SecurityUpdate,
  type SecurityView,
} from "./runtime";
import { SecurityStore } from "./store";
import type {
  AlertChannel,
  Evidence,
  ExposureEntry,
  LockdownProposal,
  PostureCheck,
  RuntimeOverrides,
  SecurityAlert,
  SecurityEvent,
  SecurityFinding,
  SecurityScan,
  SecuritySettings,
} from "./types";

const HOUR_MS = 3_600_000;
const MINUTE_MS = 60_000;
const DAY_MS = 86_400_000;
const DEMO_HOST_LABEL = "lab-node-01";
const DEMO_START_MS = 1_764_000_000_000;

// Strictly RFC 5737 (IPv4 TEST-NET-2 / TEST-NET-3) and RFC 3849 (IPv6 documentation) addresses.
const DEMO_IP_ATTACKER = "198.51.100.42";
const DEMO_IP_CONTAINED = "203.0.113.19";
const DEMO_IPV6_DOC = "2001:db8::10";

function buildDemoScan(
  scanId: string,
  trigger: SecurityScan["trigger"],
  now: number,
  settings: SecuritySettings,
): SecurityScan {
  const evUfw = `ev:${scanId}:criterion:firewall_ufw`;
  const evSsh = `ev:${scanId}:criterion:ssh_hardening`;
  const evPkg = `ev:${scanId}:criterion:package_updates`;
  const evDisk = `ev:${scanId}:criterion:disk_and_boot`;
  const evSysctl = `ev:${scanId}:criterion:kernel_sysctl`;
  const evUnits = `ev:${scanId}:criterion:systemd_health`;
  const evProc = `ev:${scanId}:criterion:process_and_timers`;

  const evListenerLan = `ev:${scanId}:listener:lan-8188`;
  const evListenerTailnet = `ev:${scanId}:listener:tailnet-8091`;
  const evListenerLocal = `ev:${scanId}:listener:local-6969`;
  const evListenerBlocked = `ev:${scanId}:listener:blocked-9090`;
  const evListenerV6 = `ev:${scanId}:listener:v6-22`;

  const evidence: Evidence[] = [
    {
      id: evUfw,
      kind: "criterion",
      facts: {
        criterionId: "firewall_ufw",
        active: true,
        defaultInput: "deny",
        ipv6Enabled: true,
        unusedOpenRules: 1,
      },
    },
    {
      id: evSsh,
      kind: "criterion",
      facts: {
        criterionId: "ssh_hardening",
        passwordAuthentication: "no",
        permitRootLogin: "no",
        kbdInteractiveAuthentication: "no",
        exposedOutsideTailnet: true,
      },
    },
    {
      id: evPkg,
      kind: "criterion",
      facts: {
        criterionId: "package_updates",
        pendingCount: 7,
        kernelUpdatePending: true,
        daysSinceLastUpgrade: 9,
      },
    },
    {
      id: evDisk,
      kind: "criterion",
      facts: {
        criterionId: "disk_and_boot",
        rootEncrypted: true,
        secureBoot: true,
        tpm2Enrolled: true,
      },
    },
    {
      id: evSysctl,
      kind: "criterion",
      facts: {
        criterionId: "kernel_sysctl",
        kptrRestrict: 2,
        dmesgRestrict: 1,
        ptraceScope: 1,
      },
    },
    {
      id: evUnits,
      kind: "criterion",
      facts: {
        criterionId: "systemd_health",
        systemFailed: 0,
        userFailed: 0,
        snapperHealthy: true,
      },
    },
    {
      id: evProc,
      kind: "criterion",
      facts: {
        criterionId: "process_and_timers",
        activeUserTimers: 3,
        unexpectedListeners: 1,
      },
    },
    {
      id: evListenerLan,
      kind: "listener",
      facts: {
        protocol: "tcp",
        address: "0.0.0.0",
        port: 8188,
        family: 4,
        process: "comfyui",
        pid: 4182,
        reachability: "exposed_lan",
        firewallV4: "allow",
        firewallV6: "deny",
        publication: "none",
        expected: false,
      },
    },
    {
      id: evListenerTailnet,
      kind: "listener",
      facts: {
        protocol: "tcp",
        address: "100.64.10.12",
        port: 8091,
        family: 4,
        interfaceName: "tailscale0",
        process: "ntfy",
        pid: 2210,
        reachability: "tailnet",
        firewallV4: "allow",
        firewallV6: "na",
        publication: "serve",
        expected: true,
      },
    },
    {
      id: evListenerLocal,
      kind: "listener",
      facts: {
        protocol: "tcp",
        address: "127.0.0.1",
        port: 6969,
        family: 4,
        process: "basho",
        pid: 1844,
        reachability: "local_only",
        firewallV4: "deny",
        firewallV6: "na",
        publication: "none",
        expected: true,
      },
    },
    {
      id: evListenerBlocked,
      kind: "listener",
      facts: {
        protocol: "tcp",
        address: "0.0.0.0",
        port: 9090,
        family: 4,
        process: "prometheus",
        pid: 3108,
        reachability: "blocked_by_ufw",
        firewallV4: "deny",
        firewallV6: "deny",
        publication: "none",
        expected: false,
      },
    },
    {
      id: evListenerV6,
      kind: "listener",
      facts: {
        protocol: "tcp",
        address: DEMO_IPV6_DOC,
        port: 22,
        family: 6,
        process: "sshd",
        pid: 912,
        reachability: "exposed_v4_v6",
        firewallV4: "allow",
        firewallV6: "allow",
        publication: "none",
        expected: true,
      },
    },
  ];

  const exposure: ExposureEntry[] = [
    {
      id: `exp:${scanId}:8188`,
      listener: {
        id: "listener:tcp:4:0.0.0.0:8188:4182",
        protocol: "tcp",
        address: "0.0.0.0",
        port: 8188,
        family: 4,
        pid: 4182,
        process: "comfyui",
      },
      reachability: "exposed_lan",
      firewallV4: "allow",
      firewallV6: "deny",
      publication: "none",
      expected: false,
      evidenceIds: [evListenerLan],
    },
    {
      id: `exp:${scanId}:22-v6`,
      listener: {
        id: `listener:tcp:6:${DEMO_IPV6_DOC}:22:912`,
        protocol: "tcp",
        address: DEMO_IPV6_DOC,
        port: 22,
        family: 6,
        pid: 912,
        process: "sshd",
      },
      reachability: "exposed_v4_v6",
      firewallV4: "allow",
      firewallV6: "allow",
      publication: "none",
      expected: true,
      evidenceIds: [evListenerV6],
    },
    {
      id: `exp:${scanId}:8091`,
      listener: {
        id: "listener:tcp:4:100.64.10.12:8091:2210",
        protocol: "tcp",
        address: "100.64.10.12",
        port: 8091,
        family: 4,
        interfaceName: "tailscale0",
        pid: 2210,
        process: "ntfy",
      },
      reachability: "tailnet",
      firewallV4: "allow",
      firewallV6: "na",
      publication: "serve",
      expected: true,
      evidenceIds: [evListenerTailnet],
    },
    {
      id: `exp:${scanId}:6969`,
      listener: {
        id: "listener:tcp:4:127.0.0.1:6969:1844",
        protocol: "tcp",
        address: "127.0.0.1",
        port: 6969,
        family: 4,
        pid: 1844,
        process: "basho",
      },
      reachability: "local_only",
      firewallV4: "deny",
      firewallV6: "na",
      publication: "none",
      expected: true,
      evidenceIds: [evListenerLocal],
    },
    {
      id: `exp:${scanId}:9090`,
      listener: {
        id: "listener:tcp:4:0.0.0.0:9090:3108",
        protocol: "tcp",
        address: "0.0.0.0",
        port: 9090,
        family: 4,
        pid: 3108,
        process: "prometheus",
      },
      reachability: "blocked_by_ufw",
      firewallV4: "deny",
      firewallV6: "deny",
      publication: "none",
      expected: false,
      evidenceIds: [evListenerBlocked],
    },
  ];

  const checkDisabled = (id: PostureCheck["id"]): boolean => settings.criteria[id] === false;

  const checks: PostureCheck[] = [
    {
      id: "firewall_ufw",
      category: "firewall",
      title: "UFW Firewall Policy",
      status: checkDisabled("firewall_ufw") ? "disabled" : "pass",
      summary: checkDisabled("firewall_ufw")
        ? "UFW Firewall Policy check is disabled."
        : "UFW is active with default-deny incoming policy on IPv4 and IPv6.",
      evidenceIds: checkDisabled("firewall_ufw") ? [] : [evUfw],
      sourceCoverage: { ufw: "complete" },
    },
    {
      id: "network_exposure",
      category: "network",
      title: "Network Exposure",
      status: checkDisabled("network_exposure") ? "disabled" : "fail",
      summary: checkDisabled("network_exposure")
        ? "Network Exposure check is disabled."
        : "Unexpected LAN-exposed listener on tcp 0.0.0.0:8188 (comfyui) is allowed by UFW.",
      remediation: "Bind comfyui to 127.0.0.1 or remove UFW allow rule: sudo ufw delete allow 8188/tcp",
      evidenceIds: checkDisabled("network_exposure") ? [] : [evListenerLan, evListenerV6],
      sourceCoverage: { sockets: "complete", ufw: "complete", tailscale: "complete" },
    },
    {
      id: "ssh_hardening",
      category: "auth",
      title: "SSH Hardening",
      status: checkDisabled("ssh_hardening") ? "disabled" : "warn",
      summary: checkDisabled("ssh_hardening")
        ? "SSH Hardening check is disabled."
        : `Key-only SSH enforced, but port 22 is reachable on ${DEMO_IPV6_DOC} outside tailscale0.`,
      remediation: "Restrict SSH to tailscale0: sudo ufw allow in on tailscale0 to any port 22 proto tcp",
      evidenceIds: checkDisabled("ssh_hardening") ? [] : [evSsh, evListenerV6],
      sourceCoverage: { sshd: "complete", ufw: "complete" },
    },
    {
      id: "package_updates",
      category: "packages",
      title: "Package Updates",
      status: checkDisabled("package_updates") ? "disabled" : "warn",
      summary: checkDisabled("package_updates")
        ? "Package Updates check is disabled."
        : "7 package updates pending including linux-6.12.9 kernel upgrade.",
      remediation: "Review and upgrade packages: sudo pacman -Syu",
      evidenceIds: checkDisabled("package_updates") ? [] : [evPkg],
      sourceCoverage: { pacman: "complete" },
    },
    {
      id: "disk_and_boot",
      category: "host",
      title: "Disk & Boot Integrity",
      status: checkDisabled("disk_and_boot") ? "disabled" : "pass",
      summary: checkDisabled("disk_and_boot")
        ? "Disk & Boot Integrity check is disabled."
        : "Root volume is LUKS-encrypted with Secure Boot and TPM2 enabled.",
      evidenceIds: checkDisabled("disk_and_boot") ? [] : [evDisk],
      sourceCoverage: { lsblk: "complete", bootctl: "complete" },
    },
    {
      id: "kernel_sysctl",
      category: "host",
      title: "Kernel Hardening (sysctl)",
      status: checkDisabled("kernel_sysctl") ? "disabled" : "pass",
      summary: checkDisabled("kernel_sysctl")
        ? "Kernel Hardening check is disabled."
        : "Core kernel sysctl hardening parameters match recommended values.",
      evidenceIds: checkDisabled("kernel_sysctl") ? [] : [evSysctl],
      sourceCoverage: { sysctl: "complete" },
    },
    {
      id: "systemd_health",
      category: "units",
      title: "Systemd & Snapshot Health",
      status: checkDisabled("systemd_health") ? "disabled" : "pass",
      summary: checkDisabled("systemd_health")
        ? "Systemd & Snapshot Health check is disabled."
        : "Zero failed system or user units; Snapper snapshots healthy.",
      evidenceIds: checkDisabled("systemd_health") ? [] : [evUnits],
      sourceCoverage: { systemd: "complete" },
    },
    {
      id: "process_and_timers",
      category: "units",
      title: "Processes & User Timers",
      status: checkDisabled("process_and_timers") ? "disabled" : "warn",
      summary: checkDisabled("process_and_timers")
        ? "Processes & User Timers check is disabled."
        : "1 unexpected listening workload detected on LAN port 8188.",
      remediation: "Inspect workload comfyui.service and restrict its bind interface.",
      evidenceIds: checkDisabled("process_and_timers") ? [] : [evProc, evListenerLan],
      sourceCoverage: { processes: "complete", timers: "complete" },
    },
  ];

  const findings: SecurityFinding[] = [
    {
      id: `finding:det:${scanId}:exposure-8188`,
      source: "deterministic",
      severity: "warning",
      summary: "ComfyUI listener on 0.0.0.0:8188 is reachable from LAN under active UFW rules.",
      evidenceIds: [evListenerLan],
    },
    {
      id: `finding:det:${scanId}:ssh-v6`,
      source: "deterministic",
      severity: "warning",
      summary: `SSH daemon listens on ${DEMO_IPV6_DOC}:22 beyond tailscale0.`,
      evidenceIds: [evSsh, evListenerV6],
    },
    {
      id: `finding:ai:${scanId}:ssh-burst`,
      source: "ai",
      severity: "breach",
      summary: `Sustained SSH brute-force burst from ${DEMO_IP_ATTACKER} targeting ${DEMO_HOST_LABEL} alongside exposed port 8188; temporary peer IP block recommended.`,
      evidenceIds: [evSsh, evListenerV6, evListenerLan],
    },
  ];

  return {
    id: scanId,
    trigger,
    startedAt: now - 1_200,
    finishedAt: now,
    snapshot: {
      id: `snapshot:${scanId}`,
      capturedAt: now - 800,
      checks,
      evidence,
    },
    exposure,
    findings,
    trail: {
      steps: [
        {
          tool: "read_posture_detail",
          reason: "Reviewed ssh_hardening and network_exposure checklist findings",
          outcome: "ok",
          evidenceIds: [evSsh, evListenerLan],
        },
        {
          tool: "read_listener_detail",
          reason: "Inspected exposed tcp/8188 and IPv6 sshd listeners",
          outcome: "ok",
          evidenceIds: [evListenerLan, evListenerV6],
        },
        {
          tool: "read_recent_events",
          reason: `Correlated repeated SSH authentication failures from ${DEMO_IP_ATTACKER}`,
          outcome: "ok",
          evidenceIds: [evSsh],
        },
        {
          tool: "verdict",
          reason: "Completed structured security verdict",
          outcome: "ok",
          evidenceIds: [evSsh, evListenerV6, evListenerLan],
        },
      ],
    },
    aiStatus: "ready",
    verdict: {
      kind: "breach",
      confidence: 0.92,
      summary: `Active SSH authentication burst from ${DEMO_IP_ATTACKER} and unexpected LAN exposure on :8188 on ${DEMO_HOST_LABEL}.`,
    },
  };
}

function seedDemoEvents(store: SecurityStore, now: number): void {
  const events: SecurityEvent[] = [];

  // Distribute signal and benign multicast noise across the past 24 hours.
  const signalHours = [1, 2, 4, 6, 9, 12, 15, 18, 20, 22, 23];
  for (const offset of signalHours) {
    const ts = now - (23 - offset) * HOUR_MS - 10 * MINUTE_MS;
    events.push({
      id: `demo:ev:fw-sig-${offset}`,
      source: "journal",
      category: "firewall",
      severity: "info",
      rule: "ufw_block",
      target: offset % 2 === 0 ? DEMO_IP_ATTACKER : DEMO_IP_CONTAINED,
      firstAt: ts,
      lastAt: ts,
      count: 2 + (offset % 3),
      isNoise: false,
      summary: `UFW blocked TCP probe from ${offset % 2 === 0 ? DEMO_IP_ATTACKER : DEMO_IP_CONTAINED} to port 445`,
    });
  }

  for (let offset = 0; offset < 24; offset += 2) {
    const ts = now - (23 - offset) * HOUR_MS - 20 * MINUTE_MS;
    events.push({
      id: `demo:ev:noise-${offset}`,
      source: "journal",
      category: "firewall",
      severity: "info",
      rule: "ufw_block",
      target: offset % 4 === 0 ? "224.0.0.1" : "ff02::1",
      firstAt: ts,
      lastAt: ts,
      count: 3,
      isNoise: true,
      summary: `UFW blocked benign multicast IGMP/MLD packet to ${offset % 4 === 0 ? "224.0.0.1" : "ff02::1"}`,
    });
  }

  // Recent high-signal events across categories.
  events.push(
    {
      id: "demo:ev:ssh-burst",
      source: "journal",
      category: "auth",
      severity: "critical",
      rule: "ssh_auth_failure",
      target: DEMO_IP_ATTACKER,
      firstAt: now - 8 * MINUTE_MS,
      lastAt: now - 2 * MINUTE_MS,
      count: 14,
      isNoise: false,
      summary: `SSH authentication failure burst from ${DEMO_IP_ATTACKER} (14 attempts)`,
    },
    {
      id: "demo:ev:listener-8188",
      source: "socket",
      category: "network",
      severity: "warning",
      rule: "listener_opened",
      target: "tcp:0.0.0.0:8188",
      firstAt: now - 25 * MINUTE_MS,
      lastAt: now - 25 * MINUTE_MS,
      count: 1,
      isNoise: false,
      summary: "Network listener opened on tcp 0.0.0.0:8188 (comfyui)",
    },
    {
      id: "demo:ev:ipv6-probe",
      source: "journal",
      category: "firewall",
      severity: "info",
      rule: "ufw_block",
      target: DEMO_IPV6_DOC,
      firstAt: now - 40 * MINUTE_MS,
      lastAt: now - 40 * MINUTE_MS,
      count: 2,
      isNoise: false,
      summary: `UFW blocked TCP probe targeting ${DEMO_IPV6_DOC} port 2222`,
    },
    {
      id: "demo:ev:unit-check",
      source: "journal",
      category: "units",
      severity: "info",
      rule: "unit_reloaded",
      target: "snapper-timeline.timer",
      firstAt: now - 2 * HOUR_MS,
      lastAt: now - 2 * HOUR_MS,
      count: 1,
      isNoise: false,
      summary: "Systemd timer snapper-timeline.timer completed scheduled run",
    },
    {
      id: "demo:ev:pkg-upgraded",
      source: "journal",
      category: "packages",
      severity: "info",
      rule: "pacman_upgraded",
      target: "openssl",
      firstAt: now - 5 * HOUR_MS,
      lastAt: now - 5 * HOUR_MS,
      count: 1,
      isNoise: false,
      summary: "Package openssl upgraded via pacman",
    },
  );

  store.commitEventBatch({
    events,
    burstWindowMs: 5 * MINUTE_MS,
  });
}

function seedDemoContainmentAndAlerts(
  store: SecurityStore,
  initialScan: SecurityScan,
  now: number,
): void {
  const sshEvId = initialScan.snapshot.evidence[1]?.id ?? "ev:demo:ssh";
  const v6EvId = initialScan.snapshot.evidence.at(-1)?.id ?? "ev:demo:v6";

  // 1. Seed a pending proposal targeting 198.51.100.42
  const pendingProposal: LockdownProposal = {
    id: "demo-proposal-pending-1",
    scanId: initialScan.id,
    revision: 1,
    status: "pending",
    target: { kind: "deny_peer_ip", ip: DEMO_IP_ATTACKER },
    evidenceIds: [sshEvId, v6EvId],
    createdAt: now - 3 * MINUTE_MS,
    expiresAt: now + 27 * MINUTE_MS,
    leaseSeconds: 600,
    rollbackDescription: `Automatically removes temporary UFW deny rule for ${DEMO_IP_ATTACKER} after 600s lease expiry, or immediately via unlock.`,
  };
  store.insertProposal(pendingProposal);

  // 2. Seed an active containment lease targeting 203.0.113.19
  const activeSourceProposal: LockdownProposal = {
    id: "demo-proposal-active-source",
    scanId: initialScan.id,
    revision: 1,
    status: "pending",
    target: { kind: "deny_peer_ip", ip: DEMO_IP_CONTAINED },
    evidenceIds: [sshEvId],
    createdAt: now - 15 * MINUTE_MS,
    expiresAt: now + 15 * MINUTE_MS,
    leaseSeconds: 600,
    rollbackDescription: `Automatically removes temporary UFW deny rule for ${DEMO_IP_CONTAINED} after 600s lease expiry, or immediately via unlock.`,
  };
  store.insertProposal(activeSourceProposal);
  const claimedAction = store.claimProposal(
    activeSourceProposal.id,
    activeSourceProposal.revision,
    now - 5 * MINUTE_MS,
  );
  if (claimedAction) {
    store.transitionAction(
      claimedAction.id,
      "pending",
      "active",
      now - 5 * MINUTE_MS,
      "demo-ufw-deny-203-0-113-19",
    );
  }

  // 3. Seed both warning and breach alerts + settle channel deliveries for health
  const warningAlert: SecurityAlert = {
    id: "demo-alert-warning-1",
    fingerprint: "demo:exposure:8188",
    severity: "warning",
    summary: `Unexpected LAN exposure on ${DEMO_HOST_LABEL}: comfyui listening on 0.0.0.0:8188.`,
    createdAt: now - 20 * MINUTE_MS,
  };
  const breachAlert: SecurityAlert = {
    id: "demo-alert-breach-1",
    fingerprint: `demo:ssh_burst:${DEMO_IP_ATTACKER}`,
    severity: "breach",
    summary: `Active SSH auth failure burst from ${DEMO_IP_ATTACKER} on ${DEMO_HOST_LABEL}; containment proposal awaiting approval.`,
    createdAt: now - 2 * MINUTE_MS,
    proposalId: pendingProposal.id,
  };

  store.enqueueAlert(warningAlert, ["in-app", "ntfy"], 0);
  store.enqueueAlert(breachAlert, ["in-app", "ntfy"], 0);

  const claimed = store.claimDeliveries(now, 16, 30_000);
  for (const delivery of claimed) {
    store.settleDelivery(delivery.id, delivery.claimToken, now, "sent");
  }
}

export function createDemoSecurityRuntime(): SecurityRuntime {
  const store = new SecurityStore(":memory:");
  let now = DEMO_START_MS;
  let scanSeq = 1;
  let stopped = false;

  const { settings: initialSettings } = loadSecurityConfig({ env: {}, fileConfig: {} });
  let currentSettings: SecuritySettings = {
    ...initialSettings,
    mode: "approve",
    scanIntervalMinutes: 60,
    lockdown: {
      ...initialSettings.lockdown,
      helperEnabled: true,
    },
    notifications: {
      ...initialSettings.notifications,
      channels: ["in-app", "ntfy"],
    },
  };
  let currentOverrides: RuntimeOverrides = {};
  let nextScanAt: number | null = now + currentSettings.scanIntervalMinutes * MINUTE_MS;

  const listeners = new Set<(update: SecurityUpdate) => void>();

  const emit = (update: SecurityUpdate): void => {
    if (stopped) return;
    for (const listener of [...listeners]) {
      try {
        listener(update);
      } catch {
        // Isolate listener errors in demo mode.
      }
    }
  };

  // Seed fictional state in the isolated in-memory SQLite store.
  const initialScan = buildDemoScan("demo-scan-1", "scheduled", now, currentSettings);
  store.saveScan(initialScan);
  seedDemoEvents(store, now);
  seedDemoContainmentAndAlerts(store, initialScan, now);

  return {
    start(): void {
      if (stopped) return;
      nextScanAt = now + currentSettings.scanIntervalMinutes * MINUTE_MS;
    },

    async stop(): Promise<void> {
      if (stopped) return;
      stopped = true;
      nextScanAt = null;
      listeners.clear();
      store.close();
    },

    view(): SecurityView {
      const latestScan = store.latestScan();
      return {
        hostLabel: DEMO_HOST_LABEL,
        latestScan,
        events: store.recentEvents(now - DAY_MS, 100),
        hourly: store.hourlyEvents(now),
        proposals: store.listProposals(),
        actions: store.listActions(),
        alerts: store.recentAlerts(now - 7 * DAY_MS),
        channelHealth: store.channelHealth(),
        settings: {
          mode: currentSettings.mode,
          criteria: { ...currentSettings.criteria },
          scanIntervalMinutes: currentSettings.scanIntervalMinutes,
        },
        aiStatus: latestScan?.aiStatus ?? "ready",
        scanRunning: false,
        nextScanAt,
        helperReady: true,
      };
    },

    subscribe(listener: (update: SecurityUpdate) => void): () => void {
      if (stopped) {
        return () => {};
      }
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },

    async requestScan(trigger: SecurityScan["trigger"]): Promise<SecurityScan> {
      if (stopped) {
        throw new Error("Demo SecurityRuntime has been stopped");
      }
      now += 1_000;
      scanSeq += 1;
      const scan = buildDemoScan(`demo-scan-${scanSeq}`, trigger, now, currentSettings);
      store.saveScan(scan);
      nextScanAt = now + currentSettings.scanIntervalMinutes * MINUTE_MS;
      emit({ kind: "scan" });
      return scan;
    },

    updateSettings(overrides: RuntimeOverrides): void {
      if (stopped) return;
      const { nextSettings, nextOverrides } = validateAndMergeOverrides(
        currentSettings,
        currentOverrides,
        overrides,
      );
      store.writeOverrides(nextOverrides);
      currentSettings = nextSettings;
      currentOverrides = nextOverrides;
      nextScanAt = now + currentSettings.scanIntervalMinutes * MINUTE_MS;
      emit({ kind: "settings" });
    },

    async approve(id: string, revision: number): Promise<boolean> {
      if (stopped || currentSettings.mode === "monitor") return false;
      now += 1_000;
      const claimed = store.claimProposal(id, revision, now);
      if (!claimed) {
        return false;
      }
      store.transitionAction(
        claimed.id,
        "pending",
        "active",
        now,
        `demo-rollback-${claimed.id.slice(0, 8)}`,
      );
      emit({ kind: "containment" });
      return true;
    },

    reject(id: string, revision: number): boolean {
      if (stopped) return false;
      now += 1_000;
      const rejected = store.rejectProposal(id, revision, now);
      if (rejected) {
        emit({ kind: "containment" });
      }
      return rejected;
    },

    async unlock(id: string): Promise<boolean> {
      if (stopped) return false;
      const action = store.listActions().find((entry) => entry.id === id);
      if (!action) return false;
      if (action.state === "rolled_back") return true;
      if (
        action.state !== "active" &&
        action.state !== "pending" &&
        action.state !== "rolling_back"
      ) {
        return false;
      }
      now += 1_000;
      if (action.state !== "rolling_back") {
        const startedRollback = store.transitionAction(
          action.id,
          action.state,
          "rolling_back",
          now,
        );
        if (!startedRollback) return false;
      }
      const completed = store.transitionAction(action.id, "rolling_back", "rolled_back", now);
      if (completed) {
        emit({ kind: "containment" });
      }
      return completed;
    },

    dismissAlert(id: string): boolean {
      if (stopped) return false;
      now += 1_000;
      const dismissed = store.dismissAlert(id, now);
      if (dismissed) {
        emit({ kind: "alert" });
      }
      return dismissed;
    },

    sendTestAlert(channel?: AlertChannel): string {
      if (stopped) {
        throw new Error("Demo SecurityRuntime has been stopped");
      }
      now += 1_000;
      const id = `demo-test-${crypto.randomUUID()}`;
      const targetChannel: AlertChannel = channel ?? "in-app";
      const alert: SecurityAlert = {
        id,
        fingerprint: `demo:test:${targetChannel}:${id}`,
        severity: "info",
        summary: `Demo test alert delivered via ${targetChannel} on ${DEMO_HOST_LABEL}.`,
        createdAt: now,
      };
      store.enqueueAlert(alert, [targetChannel], 0);
      const deliveries = store.claimDeliveries(now, 8, 30_000);
      for (const delivery of deliveries) {
        store.settleDelivery(delivery.id, delivery.claimToken, now, "sent");
      }
      emit({ kind: "alert" });
      return id;
    },
  };
}

export function getDemoServices(): ServiceEntry[] {
  return [
    {
      name: "Basho",
      url: "http://127.0.0.1:6969",
      description: "lab-node-01 local dashboard on port 6969",
      icon: "⚡",
    },
    {
      name: "Ntfy Alerts",
      url: "http://198.51.100.42:8091",
      description: "Tailnet push notification relay on port 8091",
      icon: "🔌",
    },
    {
      name: "ComfyUI",
      url: "http://198.51.100.42:8188",
      description: "Synthetic image workflow service on port 8188",
      icon: "🎨",
    },
    {
      name: "Ollama",
      url: "http://127.0.0.1:11434",
      description: "Local model runtime on port 11434",
      icon: "🦙",
    },
  ];
}

export function getDemoSystemStats(): SystemStats {
  return {
    cpu: {
      cores: [
        { usage: 24 },
        { usage: 31 },
        { usage: 18 },
        { usage: 42 },
        { usage: 27 },
        { usage: 15 },
        { usage: 36 },
        { usage: 22 },
      ],
      average: 27,
      count: 8,
    },
    ram: {
      used: 14.2,
      total: 32,
      percent: 44,
      cached: 6.4,
    },
    gpu: {
      utilization: 34,
      memoryUsed: 4608,
      memoryTotal: 16384,
      temperature: 54,
      fanSpeed: 41,
    },
    disks: [
      {
        device: "nvme0n1",
        name: "Lab-NVMe-Root",
        type: "NVMe",
        totalSize: 1000,
        used: 412.5,
        usePercent: 41,
      },
      {
        device: "nvme1n1",
        name: "Lab-NVMe-Data",
        type: "NVMe",
        totalSize: 2000,
        used: 780.2,
        usePercent: 39,
      },
    ],
    diskIO: {
      totalIO_sec: 142,
      readIO_sec: 88,
      writeIO_sec: 54,
    },
  };
}
