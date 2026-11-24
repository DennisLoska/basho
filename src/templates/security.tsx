import type { SecurityView } from "../security/runtime";
import {
  alertChannels,
  criterionIds,
  lockdownModes,
  type AlertChannel,
  type ContainmentTarget,
  type CriterionId,
  type ExposureEntry,
  type LockdownAction,
  type LockdownMode,
  type PostureCheck,
  type SecurityAlert,
  type SecurityEvent,
  type Severity,
} from "../security/types";

export interface SecurityFlash {
  kind: "info" | "success" | "error";
  message: string;
}

export interface SecurityPanelProps {
  view: SecurityView;
  csrfToken?: string;
  flash?: SecurityFlash;
  serverNow?: number;
}

export interface SecurityLoginProps {
  error?: string;
}

const CRITERION_LABELS: Record<CriterionId, string> = {
  firewall_ufw: "UFW Firewall Policy",
  network_exposure: "Network Exposure",
  ssh_hardening: "SSH Hardening",
  package_updates: "Package Updates",
  disk_and_boot: "Disk & Boot Integrity",
  kernel_sysctl: "Kernel Hardening (sysctl)",
  systemd_health: "Systemd & Snapshot Health",
  process_and_timers: "Processes & User Timers",
};

const MODE_LABELS: Record<LockdownMode, string> = {
  monitor: "Monitor",
  approve: "Approve",
  "auto-lockdown": "Auto-Lockdown",
};

const REACHABILITY_LABELS: Record<ExposureEntry["reachability"], string> = {
  exposed_v4_v6: "Exposed v4+v6",
  exposed_lan: "Exposed LAN",
  tailnet: "Tailnet",
  blocked_by_ufw: "Blocked",
  local_only: "Local",
  unknown: "Unknown",
};

const EVENT_CATEGORIES = [
  { id: "all", label: "All" },
  { id: "auth", label: "Auth" },
  { id: "firewall", label: "Firewall" },
  { id: "network", label: "Network" },
  { id: "units", label: "Units" },
  { id: "packages", label: "Packages" },
] as const;

function severityBadgeClass(severity: Severity): string {
  switch (severity) {
    case "breach":
      return "bg-error/20 border-error/50 text-error";
    case "critical":
      return "bg-error/15 border-error/40 text-error";
    case "warning":
      return "bg-warning/15 border-warning/40 text-warning";
    case "info":
      return "bg-info/15 border-info/40 text-info";
  }
}

function checkStatusBadge(status: PostureCheck["status"]): {
  label: string;
  cls: string;
} {
  switch (status) {
    case "pass":
      return { label: "PASS", cls: "bg-success/15 border-success/40 text-success" };
    case "warn":
      return { label: "WARN", cls: "bg-warning/15 border-warning/40 text-warning" };
    case "fail":
      return { label: "FAIL", cls: "bg-error/15 border-error/40 text-error" };
    case "disabled":
      return {
        label: "DISABLED",
        cls: "bg-base-300/70 border-base-300 text-base-content/50",
      };
    case "unknown":
      return {
        label: "UNKNOWN",
        cls: "bg-base-300/70 border-base-300 text-base-content/70",
      };
  }
}

function reachabilityBadgeClass(reachability: ExposureEntry["reachability"]): string {
  switch (reachability) {
    case "exposed_v4_v6":
      return "bg-error/15 border-error/40 text-error";
    case "exposed_lan":
      return "bg-warning/15 border-warning/40 text-warning";
    case "tailnet":
      return "bg-info/15 border-info/40 text-info";
    case "blocked_by_ufw":
      return "bg-base-300/80 border-base-300 text-base-content/70";
    case "local_only":
      return "bg-success/15 border-success/40 text-success";
    case "unknown":
      return "bg-base-300/70 border-base-300 text-base-content/60";
  }
}

function actionStateBadge(state: LockdownAction["state"]): {
  label: string;
  cls: string;
} {
  switch (state) {
    case "active":
      return { label: "ACTIVE", cls: "bg-error/15 border-error/40 text-error" };
    case "pending":
      return { label: "PENDING", cls: "bg-warning/15 border-warning/40 text-warning" };
    case "rolling_back":
      return { label: "ROLLING BACK", cls: "bg-info/15 border-info/40 text-info" };
    case "rolled_back":
      return { label: "ROLLED BACK", cls: "bg-success/15 border-success/40 text-success" };
    case "failed":
      return { label: "FAILED", cls: "bg-error/15 border-error/40 text-error" };
  }
}

function aiStatusInfo(status: SecurityView["aiStatus"]): {
  label: string;
  dot: string;
  cls: string;
} {
  switch (status) {
    case "ready":
      return {
        label: "READY",
        dot: "bg-success",
        cls: "bg-success/10 border-success/35 text-success",
      };
    case "unconfigured":
      return {
        label: "UNCONFIGURED",
        dot: "bg-warning",
        cls: "bg-warning/10 border-warning/35 text-warning",
      };
    case "offline":
      return {
        label: "OFFLINE",
        dot: "bg-error",
        cls: "bg-error/10 border-error/35 text-error",
      };
  }
}

function formatTarget(target: ContainmentTarget): string {
  switch (target.kind) {
    case "deny_peer_ip":
      return `deny_peer_ip · ${target.ip}`;
    case "pause_workload":
      return `pause_workload · ${target.workloadId} (pid ${target.pid})`;
    case "isolate_lan_ingress":
      return "isolate_lan_ingress · enrolled LAN ports";
  }
}

function formatUtcShort(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "--:--";
  const d = new Date(ms);
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mm = String(d.getUTCMinutes()).padStart(2, "0");
  const ss = String(d.getUTCSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}Z`;
}

function formatDurationMs(deltaMs: number): string {
  if (!Number.isFinite(deltaMs) || deltaMs <= 0) return "due now";
  const totalSec = Math.ceil(deltaMs / 1_000);
  const hours = Math.floor(totalSec / 3_600);
  const mins = Math.floor((totalSec % 3_600) / 60);
  const secs = totalSec % 60;
  if (hours > 0) return `${hours}h ${mins}m`;
  if (mins > 0) return `${mins}m ${secs}s`;
  return `${secs}s`;
}

function deriveReferenceNow(view: SecurityView): number {
  const candidates: number[] = [];
  if (view.latestScan) {
    candidates.push(view.latestScan.finishedAt, view.latestScan.startedAt);
  }
  for (const ev of view.events) candidates.push(ev.lastAt);
  for (const al of view.alerts) candidates.push(al.createdAt);
  for (const act of view.actions) candidates.push(act.updatedAt, act.createdAt);
  const maxSeen = candidates.length > 0 ? Math.max(...candidates) : 0;
  return maxSeen > 0 ? maxSeen : Date.now();
}

function derivePostureSummary(view: SecurityView): {
  label: string;
  toneClass: string;
  dotClass: string;
  subtext: string;
} {
  const scan = view.latestScan;
  const checks = scan?.snapshot.checks ?? [];
  const failCount = checks.filter((c) => c.status === "fail").length;
  const warnCount = checks.filter((c) => c.status === "warn").length;
  const findingCount = scan?.findings.length ?? 0;
  const verdict = scan?.verdict?.kind;

  if (verdict === "breach" || view.alerts.some((a) => a.severity === "breach")) {
    return {
      label: "BREACH",
      toneClass: "text-error",
      dotClass: "bg-error",
      subtext: `${failCount} fail · ${warnCount} warn · ${findingCount} findings`,
    };
  }
  if (verdict === "warn" || failCount > 0 || warnCount > 0) {
    return {
      label: "WARN",
      toneClass: "text-warning",
      dotClass: "bg-warning",
      subtext: `${failCount} fail · ${warnCount} warn · ${findingCount} findings`,
    };
  }
  if (scan) {
    return {
      label: "HEALTHY",
      toneClass: "text-success",
      dotClass: "bg-success",
      subtext: `${checks.length} checks · ${findingCount} findings`,
    };
  }
  return {
    label: "PENDING",
    toneClass: "text-base-content/70",
    dotClass: "bg-base-content/40",
    subtext: "Awaiting first scan",
  };
}

function deriveUpdatesSummary(view: SecurityView): {
  value: string;
  toneClass: string;
  kernelLabel: string;
  kernelCls: string;
} {
  const scan = view.latestScan;
  const pkgCheck = scan?.snapshot.checks.find((c) => c.id === "package_updates");
  const pkgEvidence = scan?.snapshot.evidence.find(
    (ev) => ev.kind === "criterion" && ev.facts.criterionId === "package_updates",
  );
  const pendingRaw = pkgEvidence?.facts.pendingCount;
  const kernelPending = pkgEvidence?.facts.kernelUpdatePending === true;

  if (typeof pendingRaw === "number") {
    return {
      value: pendingRaw > 0 ? `${pendingRaw} PENDING` : "UP TO DATE",
      toneClass: pendingRaw > 0 ? "text-warning" : "text-success",
      kernelLabel: kernelPending ? "KERNEL PENDING" : "KERNEL CURRENT",
      kernelCls: kernelPending
        ? "bg-warning/15 border-warning/40 text-warning"
        : "bg-success/15 border-success/40 text-success",
    };
  }

  if (pkgCheck?.status === "pass") {
    return {
      value: "UP TO DATE",
      toneClass: "text-success",
      kernelLabel: "KERNEL OK",
      kernelCls: "bg-success/15 border-success/40 text-success",
    };
  }
  if (pkgCheck?.status === "warn" || pkgCheck?.status === "fail") {
    return {
      value: "UPDATES DUE",
      toneClass: "text-warning",
      kernelLabel: "CHECK KERNEL",
      kernelCls: "bg-warning/15 border-warning/40 text-warning",
    };
  }
  return {
    value: "UNKNOWN",
    toneClass: "text-base-content/60",
    kernelLabel: "NO DATA",
    kernelCls: "bg-base-300/70 border-base-300 text-base-content/60",
  };
}

function ActivitySvg({ hourly }: { hourly: SecurityView["hourly"] }) {
  const buckets =
    hourly.length > 0
      ? hourly.slice(-24)
      : Array.from({ length: 24 }, (_, idx) => ({ hour: idx, signal: 0, noise: 0 }));

  let maxVal = 1;
  for (const b of buckets) {
    const total = b.signal + b.noise;
    if (total > maxVal) maxVal = total;
  }

  const width = 240;
  const height = 56;
  const padX = 6;
  const padTop = 6;
  const padBottom = 10;
  const chartW = width - padX * 2;
  const chartH = height - padTop - padBottom;
  const step = chartW / Math.max(buckets.length, 1);
  const barW = Math.max(2.5, step * 0.68);

  return (
    <svg
      class="w-full h-24 sm:h-28 block"
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      role="img"
      aria-label="24h security event activity chart"
    >
      <line
        x1={padX}
        y1={padTop}
        x2={width - padX}
        y2={padTop}
        stroke="var(--color-base-content)"
        stroke-opacity="0.08"
        stroke-width="0.5"
        stroke-dasharray="2,2"
      />
      <line
        x1={padX}
        y1={padTop + chartH / 2}
        x2={width - padX}
        y2={padTop + chartH / 2}
        stroke="var(--color-base-content)"
        stroke-opacity="0.1"
        stroke-width="0.5"
        stroke-dasharray="2,2"
      />
      <line
        x1={padX}
        y1={padTop + chartH}
        x2={width - padX}
        y2={padTop + chartH}
        stroke="var(--color-base-content)"
        stroke-opacity="0.2"
        stroke-width="0.6"
      />

      {buckets.map((bucket, idx) => {
        const x = padX + idx * step + (step - barW) / 2;
        const noiseH = bucket.noise > 0 ? Math.max(1.5, (bucket.noise / maxVal) * chartH) : 0;
        const signalH =
          bucket.signal > 0 ? Math.max(2, (bucket.signal / maxVal) * chartH) : 0;
        const signalY = padTop + chartH - signalH;
        const noiseY = Math.max(padTop, signalY - noiseH);

        return (
          <g key={String(bucket.hour)}>
            {noiseH > 0 && (
              <rect
                x={x.toFixed(1)}
                y={noiseY.toFixed(1)}
                width={barW.toFixed(1)}
                height={noiseH.toFixed(1)}
                rx="0.8"
                fill="var(--color-base-content)"
                fill-opacity="0.22"
              />
            )}
            {signalH > 0 && (
              <rect
                x={x.toFixed(1)}
                y={signalY.toFixed(1)}
                width={barW.toFixed(1)}
                height={signalH.toFixed(1)}
                rx="0.8"
                fill="var(--color-primary)"
                fill-opacity="0.9"
              />
            )}
          </g>
        );
      })}

      <text
        x={padX}
        y={height - 2}
        fill="var(--color-base-content)"
        fill-opacity="0.45"
        font-size="4.2"
        font-family="monospace"
      >
        -24h
      </text>
      <text
        x={(width / 2).toFixed(1)}
        y={height - 2}
        text-anchor="middle"
        fill="var(--color-base-content)"
        fill-opacity="0.45"
        font-size="4.2"
        font-family="monospace"
      >
        -12h
      </text>
      <text
        x={width - padX}
        y={height - 2}
        text-anchor="end"
        fill="var(--color-base-content)"
        fill-opacity="0.45"
        font-size="4.2"
        font-family="monospace"
      >
        now
      </text>
    </svg>
  );
}

function isLoopbackBindAddress(address: string): boolean {
  const normalized = address.trim().toLowerCase();
  if (
    normalized === "::1" ||
    normalized === "0:0:0:0:0:0:0:1" ||
    normalized === "localhost"
  ) {
    return true;
  }
  if (normalized.startsWith("127.")) return true;
  if (normalized.startsWith("::ffff:127.")) return true;
  return false;
}

function isLanBoundExposure(entry: ExposureEntry): boolean {
  if (entry.reachability === "local_only" || entry.reachability === "tailnet") {
    return false;
  }
  const iface = entry.listener.interfaceName?.toLowerCase();
  if (iface === "lo" || iface === "tailscale0") {
    return false;
  }
  return !isLoopbackBindAddress(entry.listener.address);
}

export const SecurityPanel = ({ view, csrfToken, flash, serverNow }: SecurityPanelProps) => {
  const resolvedServerNow =
    typeof serverNow === "number" && Number.isFinite(serverNow) && serverNow > 0
      ? serverNow
      : Date.now();
  const refNow = deriveReferenceNow(view);
  const posture = derivePostureSummary(view);
  const updates = deriveUpdatesSummary(view);
  const aiInfo = aiStatusInfo(view.aiStatus);

  const exposure = view.latestScan?.exposure ?? [];
  const ufwOpenCount = exposure.filter(
    (e) => e.reachability === "exposed_v4_v6" || e.reachability === "exposed_lan",
  ).length;
  const lanBoundCount = exposure.filter((e) => isLanBoundExposure(e)).length;

  const checks = view.latestScan?.snapshot.checks ?? [];
  const findings = view.latestScan?.findings ?? [];
  const trailSteps = view.latestScan?.trail.steps ?? [];

  const pendingProposals = view.proposals.filter((p) => p.status === "pending");
  const historicalProposals = view.proposals.filter((p) => p.status !== "pending");
  const activeActions = view.actions.filter(
    (a) => a.state === "active" || a.state === "pending" || a.state === "rolling_back",
  );
  const recentAuditActions = view.actions.filter(
    (a) => a.state !== "active" && a.state !== "pending" && a.state !== "rolling_back",
  );

  const urgentAlerts = view.alerts.filter(
    (a) => a.severity === "breach" || a.severity === "critical",
  );
  const secondaryAlerts = view.alerts.filter(
    (a) => a.severity !== "breach" && a.severity !== "critical",
  );
  const linkedProposalIds = new Set(
    urgentAlerts.map((a) => a.proposalId).filter((id): id is string => Boolean(id)),
  );
  const unlinkedPendingProposals = pendingProposals.filter(
    (p) => !linkedProposalIds.has(p.id),
  );

  const signalEventsCount = view.events
    .filter((ev) => !ev.isNoise)
    .reduce((sum, ev) => sum + ev.count, 0);
  const noiseEventsCount = view.events
    .filter((ev) => ev.isNoise)
    .reduce((sum, ev) => sum + ev.count, 0);

  const nextScanText =
    view.nextScanAt !== null
      ? formatDurationMs(view.nextScanAt - refNow)
      : "paused";

  const channelEntries = Object.entries(view.channelHealth) as Array<
    [AlertChannel, { status: "sent" | "failed" | "retrying"; at: number } | undefined]
  >;

  const flashClass =
    flash?.kind === "error"
      ? "border-error/45 bg-error/10 text-error"
      : flash?.kind === "success"
        ? "border-success/45 bg-success/10 text-success"
        : "border-info/45 bg-info/10 text-info";

  return (
    <div
      id="security-panel"
      hx-history="false"
      data-security-stream="/sse/security"
      class="space-y-4 sm:space-y-5 min-w-0"
    >
      {/* Accessible live status announcer */}
      <div
        id="security-status-announcer"
        role="status"
        aria-live="polite"
        class={
          flash
            ? `oc-panel px-3.5 py-2.5 font-mono text-xs flex items-center justify-between gap-2 ${flashClass}`
            : "sr-only"
        }
      >
        {flash ? flash.message : ""}
      </div>

      {/* Sticky Dismissible Breach / Pending Proposal Banner */}
      {(urgentAlerts.length > 0 || unlinkedPendingProposals.length > 0) && (
        <div
          id="security-sticky-banner"
          class="sticky top-14 z-30 space-y-2"
        >
          {urgentAlerts.map((alert: SecurityAlert) => (
            <div
              key={alert.id}
              id={alert.id}
              class="oc-panel border-error/60 bg-base-200/95 backdrop-blur-md p-3 sm:p-3.5 shadow-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2.5"
            >
              <div class="flex items-start sm:items-center gap-2.5 min-w-0">
                <span
                  class={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border font-mono text-[11px] font-bold uppercase shrink-0 ${severityBadgeClass(alert.severity)}`}
                >
                  <span class="w-1.5 h-1.5 rounded-full bg-error animate-pulse" />
                  {alert.severity}
                </span>
                <p class="font-mono text-xs sm:text-sm text-base-content break-words min-w-0">
                  {alert.summary}
                </p>
              </div>

              <div class="flex items-center gap-2 shrink-0 flex-wrap">
                {alert.proposalId && (
                  <a
                    href={`#proposal-${alert.proposalId}`}
                    class="inline-flex items-center h-8 px-2.5 rounded bg-error/15 hover:bg-error/25 border border-error/40 font-mono text-xs font-semibold text-error transition-colors no-underline"
                  >
                    Review Proposal
                  </a>
                )}
                <form
                  method="post"
                  action={`/security/alerts/${encodeURIComponent(alert.id)}/dismiss`}
                  hx-post={`/security/alerts/${encodeURIComponent(alert.id)}/dismiss`}
                  hx-target="#security-panel"
                  hx-swap="outerHTML"
                >
                  {csrfToken && (
                    <input type="hidden" name="csrf" value={csrfToken} />
                  )}
                  <button
                    type="submit"
                    class="inline-flex items-center h-8 px-2.5 rounded bg-base-300/70 hover:bg-base-300 border border-base-300 font-mono text-xs text-base-content/80 hover:text-base-content transition-colors cursor-pointer"
                  >
                    Dismiss
                  </button>
                </form>
              </div>
            </div>
          ))}

          {unlinkedPendingProposals.map((proposal) => (
            <div
              key={proposal.id}
              class="oc-panel border-warning/60 bg-base-200/95 backdrop-blur-md p-3 sm:p-3.5 shadow-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2.5"
            >
              <div class="flex items-center gap-2.5 min-w-0">
                <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded border bg-warning/15 border-warning/40 text-warning font-mono text-[11px] font-bold uppercase shrink-0">
                  PENDING APPROVAL
                </span>
                <span class="font-mono text-xs sm:text-sm text-base-content truncate">
                  {formatTarget(proposal.target)}
                </span>
              </div>
              <a
                href={`#proposal-${proposal.id}`}
                class="inline-flex items-center h-8 px-2.5 rounded bg-warning/15 hover:bg-warning/25 border border-warning/40 font-mono text-xs font-semibold text-warning transition-colors no-underline shrink-0"
              >
                Jump to Proposal
              </a>
            </div>
          ))}
        </div>
      )}

      {/* 4 KPI Tiles */}
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-2.5 sm:gap-3">
        <div class="oc-panel p-3 sm:p-3.5 flex flex-col justify-between gap-1.5 min-w-0">
          <div class="flex items-center justify-between gap-1.5 font-mono text-[11px] uppercase tracking-wider text-base-content/55">
            <span class="flex items-center gap-1.5">
              <span class={`w-1.5 h-1.5 rounded-full ${posture.dotClass}`} />
              POSTURE
            </span>
            <span class="text-[10px] text-base-content/45 truncate">
              {view.hostLabel}
            </span>
          </div>
          <div
            class={`font-mono tabular-nums text-lg sm:text-xl font-bold tracking-tight ${posture.toneClass}`}
          >
            {posture.label}
          </div>
          <div class="font-mono text-[11px] text-base-content/55 truncate">
            {posture.subtext}
          </div>
        </div>

        <div class="oc-panel p-3 sm:p-3.5 flex flex-col justify-between gap-1.5 min-w-0">
          <div class="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-base-content/55">
            <span class="w-1.5 h-1.5 rounded-full bg-warning" />
            EXPOSURE
          </div>
          <div class="font-mono tabular-nums text-lg sm:text-xl font-bold text-primary tracking-tight">
            {ufwOpenCount} UFW-OPEN
          </div>
          <div class="font-mono text-[11px] text-base-content/55 truncate">
            {lanBoundCount} LAN-bound · {exposure.length} sockets
          </div>
        </div>

        <div class="oc-panel p-3 sm:p-3.5 flex flex-col justify-between gap-1.5 min-w-0">
          <div class="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-base-content/55">
            <span class="w-1.5 h-1.5 rounded-full bg-accent" />
            UPDATES
          </div>
          <div
            class={`font-mono tabular-nums text-lg sm:text-xl font-bold tracking-tight ${updates.toneClass}`}
          >
            {updates.value}
          </div>
          <div>
            <span
              class={`inline-flex items-center px-1.5 py-0.5 rounded border font-mono text-[10px] font-semibold uppercase ${updates.kernelCls}`}
            >
              {updates.kernelLabel}
            </span>
          </div>
        </div>

        <div class="oc-panel p-3 sm:p-3.5 flex flex-col justify-between gap-1.5 min-w-0">
          <div class="flex items-center justify-between gap-1.5 font-mono text-[11px] uppercase tracking-wider text-base-content/55">
            <span class="flex items-center gap-1.5">
              <span class="w-1.5 h-1.5 rounded-full bg-info" />
              ALERTS 24H
            </span>
          </div>
          <div class="font-mono tabular-nums text-lg sm:text-xl font-bold text-info tracking-tight">
            {view.alerts.length} active · {signalEventsCount} sig
          </div>
          <div class="flex items-center gap-1.5 flex-wrap">
            <span
              class={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border font-mono text-[10px] font-semibold uppercase ${aiInfo.cls}`}
            >
              <span class={`w-1.5 h-1.5 rounded-full ${aiInfo.dot}`} />
              AI {aiInfo.label}
            </span>
          </div>
        </div>
      </div>

      {/* Control Bar & Collapsible Settings */}
      <section class="oc-panel p-3.5 sm:p-4 space-y-3.5">
        <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div class="flex flex-wrap items-center gap-2 font-mono text-xs">
            <span class="text-primary font-bold">//</span>
            <span class="font-semibold text-base-content">{view.hostLabel}</span>
            <span
              class={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[11px] font-semibold uppercase ${aiInfo.cls}`}
            >
              <span class={`w-1.5 h-1.5 rounded-full ${aiInfo.dot}`} />
              AI: {aiInfo.label}
            </span>
            <span
              id="security-next-scan"
              data-next-scan-at={view.nextScanAt !== null ? String(view.nextScanAt) : ""}
              data-server-now={String(resolvedServerNow)}
              data-scan-running={view.scanRunning ? "true" : "false"}
              class="px-2 py-0.5 rounded bg-base-300/70 border border-base-300 text-[11px] text-base-content/75 tabular-nums"
            >
              {view.scanRunning ? "Scan running..." : `Next scan: ${nextScanText}`}
            </span>
          </div>

          <div class="flex flex-wrap items-center gap-2">
            <form
              method="post"
              action="/security/scan"
              hx-post="/security/scan"
              hx-target="#security-panel"
              hx-swap="outerHTML"
            >
              {csrfToken && <input type="hidden" name="csrf" value={csrfToken} />}
              <button
                type="submit"
                class="inline-flex items-center gap-1.5 h-9 px-3 rounded bg-primary/15 hover:bg-primary/25 border border-primary/45 font-mono text-xs font-semibold text-primary transition-colors cursor-pointer touch-manipulation"
              >
                <span>Scan Now</span>
              </button>
            </form>

            <form
              method="post"
              action="/security/mode"
              hx-post="/security/mode"
              hx-target="#security-panel"
              hx-swap="outerHTML"
              class="inline-flex items-center gap-1.5"
            >
              {csrfToken && <input type="hidden" name="csrf" value={csrfToken} />}
              <label for="security-mode-select" class="sr-only">
                Lockdown mode
              </label>
              <select
                id="security-mode-select"
                name="mode"
                aria-label="Lockdown mode"
                class="h-9 px-2.5 rounded bg-base-100 border border-base-300 focus:border-primary focus:outline-none font-mono text-xs text-base-content"
              >
                {lockdownModes.map((mode) => (
                  <option
                    key={mode}
                    value={mode}
                    selected={view.settings.mode === mode}
                  >
                    {MODE_LABELS[mode]}
                  </option>
                ))}
              </select>
              <button
                type="submit"
                class="inline-flex items-center h-9 px-3 rounded bg-base-300/70 hover:bg-base-300 border border-base-300 font-mono text-xs font-medium text-base-content/85 hover:text-primary transition-colors cursor-pointer"
              >
                Set Mode
              </button>
            </form>

            <form
              method="post"
              action="/security/test-alert"
              hx-post="/security/test-alert"
              hx-target="#security-panel"
              hx-swap="outerHTML"
              class="inline-flex items-center gap-1.5"
            >
              {csrfToken && <input type="hidden" name="csrf" value={csrfToken} />}
              <label for="security-test-channel" class="sr-only">
                Alert channel
              </label>
              <select
                id="security-test-channel"
                name="channel"
                aria-label="Test alert channel"
                class="h-9 px-2.5 rounded bg-base-100 border border-base-300 focus:border-primary focus:outline-none font-mono text-xs text-base-content"
              >
                {alertChannels.map((ch) => (
                  <option key={ch} value={ch}>
                    {ch}
                  </option>
                ))}
              </select>
              <button
                type="submit"
                class="inline-flex items-center h-9 px-3 rounded bg-base-300/70 hover:bg-base-300 border border-base-300 font-mono text-xs font-medium text-base-content/85 hover:text-primary transition-colors cursor-pointer"
              >
                Test Alert
              </button>
            </form>
          </div>
        </div>

        {/* Channel Health & Secondary Alerts */}
        <div class="flex flex-wrap items-center justify-between gap-2 pt-2.5 border-t border-base-300/60">
          <div class="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
            <span class="text-base-content/50 uppercase">Channels:</span>
            {channelEntries.length > 0 ? (
              channelEntries.map(([channel, entry]) => {
                if (!entry) return null;
                const cls =
                  entry.status === "sent"
                    ? "bg-success/10 border-success/30 text-success"
                    : entry.status === "retrying"
                      ? "bg-warning/10 border-warning/30 text-warning"
                      : "bg-error/10 border-error/30 text-error";
                return (
                  <span
                    key={channel}
                    class={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] uppercase ${cls}`}
                  >
                    <span>{channel}</span>
                    <span>· {entry.status}</span>
                  </span>
                );
              })
            ) : (
              <span class="text-base-content/50">in-app · ready</span>
            )}
          </div>

          <span class="font-mono text-[11px] text-base-content/55 tabular-nums">
            Cadence: every {view.settings.scanIntervalMinutes}m
          </span>
        </div>

        {secondaryAlerts.length > 0 && (
          <div class="space-y-1.5 pt-2 border-t border-base-300/50">
            {secondaryAlerts.map((alert) => (
              <div
                key={alert.id}
                id={alert.id}
                class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded bg-base-100/70 border border-base-300/80 px-3 py-2"
              >
                <div class="flex items-center gap-2 min-w-0">
                  <span
                    class={`px-1.5 py-0.5 rounded border font-mono text-[10px] font-semibold uppercase shrink-0 ${severityBadgeClass(alert.severity)}`}
                  >
                    {alert.severity}
                  </span>
                  <span class="font-mono text-xs text-base-content/85 break-words min-w-0">
                    {alert.summary}
                  </span>
                </div>
                <form
                  method="post"
                  action={`/security/alerts/${encodeURIComponent(alert.id)}/dismiss`}
                  hx-post={`/security/alerts/${encodeURIComponent(alert.id)}/dismiss`}
                  hx-target="#security-panel"
                  hx-swap="outerHTML"
                  class="shrink-0"
                >
                  {csrfToken && <input type="hidden" name="csrf" value={csrfToken} />}
                  <button
                    type="submit"
                    class="h-7 px-2 rounded bg-base-300/60 hover:bg-base-300 border border-base-300 font-mono text-[11px] text-base-content/75 cursor-pointer"
                  >
                    Dismiss
                  </button>
                </form>
              </div>
            ))}
          </div>
        )}

        {/* Collapsible Criteria & Schedule Settings */}
        <details
          data-detail-id="criteria-settings"
          class="rounded border border-base-300/80 bg-base-100/50"
        >
          <summary class="px-3 py-2 font-mono text-xs font-semibold text-base-content/80 cursor-pointer select-none flex items-center justify-between">
            <span>Criteria &amp; Schedule Settings</span>
            <span class="text-[11px] text-base-content/45">expand</span>
          </summary>
          <form
            method="post"
            action="/security/settings"
            hx-post="/security/settings"
            hx-target="#security-panel"
            hx-swap="outerHTML"
            class="p-3 pt-2 border-t border-base-300/60 space-y-3"
          >
            {csrfToken && <input type="hidden" name="csrf" value={csrfToken} />}

            <div class="flex flex-col sm:flex-row sm:items-center gap-2">
              <label
                for="scan-interval-input"
                class="font-mono text-xs text-base-content/75 sm:w-56 shrink-0"
              >
                Scan interval (minutes)
              </label>
              <input
                id="scan-interval-input"
                type="number"
                name="scanIntervalMinutes"
                min="1"
                max="1440"
                value={String(view.settings.scanIntervalMinutes)}
                class="h-8 w-28 px-2.5 rounded bg-base-200 border border-base-300 focus:border-primary focus:outline-none font-mono text-xs tabular-nums text-base-content"
              />
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
              {criterionIds.map((criterionId) => {
                const enabled = view.settings.criteria[criterionId] !== false;
                return (
                  <div
                    key={criterionId}
                    class="rounded border border-base-300/70 bg-base-200/70 p-2 flex items-center justify-between gap-2"
                  >
                    <label
                      for={`criterion-${criterionId}`}
                      class="font-mono text-[11px] text-base-content/85 min-w-0"
                    >
                      <span class="block truncate font-semibold">
                        {CRITERION_LABELS[criterionId]}
                      </span>
                      <span class="block text-[10px] text-base-content/45 truncate">
                        {criterionId}
                      </span>
                    </label>
                    <select
                      id={`criterion-${criterionId}`}
                      name={`criteria.${criterionId}`}
                      class="h-7 px-1.5 rounded bg-base-100 border border-base-300 font-mono text-[11px] text-base-content shrink-0"
                    >
                      <option value="on" selected={enabled}>
                        On
                      </option>
                      <option value="off" selected={!enabled}>
                        Off
                      </option>
                    </select>
                  </div>
                );
              })}
            </div>

            <div class="flex justify-end">
              <button
                type="submit"
                class="h-8 px-3 rounded bg-primary/15 hover:bg-primary/25 border border-primary/45 font-mono text-xs font-semibold text-primary cursor-pointer"
              >
                Save Settings
              </button>
            </div>
          </form>
        </details>
      </section>

      {/* Containment & Dead-Man's Switch */}
      <section class="oc-panel p-4 sm:p-5 space-y-4">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-base-300/80">
          <div class="flex items-center gap-2 font-mono text-xs sm:text-sm font-bold uppercase tracking-wider text-base-content">
            <span class="text-primary">//</span>
            <h2>Containment &amp; Dead-Man&apos;s Switch</h2>
          </div>

          <div class="flex flex-wrap items-center gap-2 font-mono text-[11px]">
            <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-success/10 border border-success/35 text-success font-semibold">
              <span class="w-1.5 h-1.5 rounded-full bg-success" />
              lo + tailscale0 PROTECTED
            </span>
            <span
              class={
                view.helperReady
                  ? "inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-info/10 border border-info/35 text-info font-semibold"
                  : "inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-warning/10 border border-warning/35 text-warning font-semibold"
              }
            >
              Helper: {view.helperReady ? "Ready" : "User-space only"}
            </span>
          </div>
        </div>

        {/* Pending Proposals */}
        <div class="space-y-2.5">
          <h3 class="font-mono text-xs uppercase tracking-wider text-base-content/65">
            Queued Proposals ({pendingProposals.length})
          </h3>
          {pendingProposals.length === 0 ? (
            <p class="font-mono text-xs text-base-content/50">
              No pending containment proposals.
            </p>
          ) : (
            <div class="space-y-2.5">
              {pendingProposals.map((proposal) => (
                <div
                  key={proposal.id}
                  id={`proposal-${proposal.id}`}
                  class="rounded border border-warning/40 bg-base-100/70 p-3.5 space-y-2.5 scroll-mt-24"
                >
                  <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div class="flex flex-wrap items-center gap-2 min-w-0">
                      <span class="px-1.5 py-0.5 rounded border bg-warning/15 border-warning/40 text-warning font-mono text-[10px] font-bold uppercase">
                        PENDING · rev {proposal.revision}
                      </span>
                      <span class="font-mono text-xs sm:text-sm font-bold text-base-content break-all">
                        {formatTarget(proposal.target)}
                      </span>
                    </div>
                    <span class="font-mono text-[11px] text-base-content/55 tabular-nums shrink-0">
                      Lease {proposal.leaseSeconds}s · expires{" "}
                      {formatDurationMs(proposal.expiresAt - refNow)}
                    </span>
                  </div>

                  <p class="font-mono text-xs text-base-content/75 break-words">
                    Rollback: {proposal.rollbackDescription}
                  </p>

                  <div class="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
                    <span class="text-base-content/50">Evidence:</span>
                    {proposal.evidenceIds.map((evId) => (
                      <span
                        key={evId}
                        class="px-1.5 py-0.5 rounded bg-base-300/70 border border-base-300 text-base-content/75 break-all"
                      >
                        {evId}
                      </span>
                    ))}
                    <span class="text-[10px] text-base-content/45 ml-auto">
                      ID: {proposal.id}
                    </span>
                  </div>

                  <div class="flex flex-wrap items-center gap-2 pt-1">
                    <form
                      method="post"
                      action={`/security/proposals/${encodeURIComponent(proposal.id)}/approve`}
                      hx-post={`/security/proposals/${encodeURIComponent(proposal.id)}/approve`}
                      hx-target="#security-panel"
                      hx-swap="outerHTML"
                    >
                      {csrfToken && (
                        <input type="hidden" name="csrf" value={csrfToken} />
                      )}
                      <input
                        type="hidden"
                        name="revision"
                        value={String(proposal.revision)}
                      />
                      <button
                        type="submit"
                        class="h-8 px-3 rounded bg-error/15 hover:bg-error/25 border border-error/45 font-mono text-xs font-semibold text-error cursor-pointer"
                      >
                        Approve Containment
                      </button>
                    </form>

                    <form
                      method="post"
                      action={`/security/proposals/${encodeURIComponent(proposal.id)}/reject`}
                      hx-post={`/security/proposals/${encodeURIComponent(proposal.id)}/reject`}
                      hx-target="#security-panel"
                      hx-swap="outerHTML"
                    >
                      {csrfToken && (
                        <input type="hidden" name="csrf" value={csrfToken} />
                      )}
                      <input
                        type="hidden"
                        name="revision"
                        value={String(proposal.revision)}
                      />
                      <button
                        type="submit"
                        class="h-8 px-3 rounded bg-base-300/70 hover:bg-base-300 border border-base-300 font-mono text-xs font-medium text-base-content/80 cursor-pointer"
                      >
                        Reject
                      </button>
                    </form>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Active Containment Leases */}
        <div class="space-y-2.5 pt-2 border-t border-base-300/60">
          <h3 class="font-mono text-xs uppercase tracking-wider text-base-content/65">
            Active Leases ({activeActions.length})
          </h3>
          {activeActions.length === 0 ? (
            <p class="font-mono text-xs text-base-content/50">
              No active containment leases.
            </p>
          ) : (
            <div class="space-y-2">
              {activeActions.map((action) => {
                const badge = actionStateBadge(action.state);
                return (
                  <div
                    key={action.id}
                    class="rounded border border-error/35 bg-base-100/70 p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5"
                  >
                    <div class="space-y-1 min-w-0">
                      <div class="flex flex-wrap items-center gap-2">
                        <span
                          class={`px-1.5 py-0.5 rounded border font-mono text-[10px] font-bold uppercase ${badge.cls}`}
                        >
                          {badge.label}
                        </span>
                        <span class="font-mono text-xs font-semibold text-base-content break-all">
                          {formatTarget(action.target)}
                        </span>
                      </div>
                      <div class="font-mono text-[11px] text-base-content/55 tabular-nums">
                        Remaining: {formatDurationMs(action.expiresAt - refNow)}
                        {action.rollbackHandle
                          ? ` · handle ${action.rollbackHandle}`
                          : ""}
                      </div>
                    </div>

                    <form
                      method="post"
                      action={`/security/actions/${encodeURIComponent(action.id)}/unlock`}
                      hx-post={`/security/actions/${encodeURIComponent(action.id)}/unlock`}
                      hx-target="#security-panel"
                      hx-swap="outerHTML"
                      class="shrink-0"
                    >
                      {csrfToken && (
                        <input type="hidden" name="csrf" value={csrfToken} />
                      )}
                      <button
                        type="submit"
                        class="h-8 px-3 rounded bg-success/15 hover:bg-success/25 border border-success/40 font-mono text-xs font-semibold text-success cursor-pointer"
                      >
                        Unlock / Rollback
                      </button>
                    </form>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Recent Containment Audit */}
        {(recentAuditActions.length > 0 || historicalProposals.length > 0) && (
          <details
            data-detail-id="containment-audit"
            class="rounded border border-base-300/70 bg-base-100/50"
          >
            <summary class="px-3 py-2 font-mono text-xs text-base-content/70 cursor-pointer select-none">
              Recent Containment Audit ({recentAuditActions.length} actions ·{" "}
              {historicalProposals.length} settled proposals)
            </summary>
            <div class="p-3 pt-2 border-t border-base-300/60 space-y-1.5 font-mono text-[11px]">
              {recentAuditActions.map((action) => {
                const badge = actionStateBadge(action.state);
                return (
                  <div
                    key={action.id}
                    class="flex flex-wrap items-center justify-between gap-2 py-1 border-b border-base-300/40 last:border-b-0"
                  >
                    <div class="flex items-center gap-2 min-w-0">
                      <span
                        class={`px-1.5 py-0.5 rounded border text-[10px] uppercase ${badge.cls}`}
                      >
                        {badge.label}
                      </span>
                      <span class="text-base-content/80 truncate">
                        {formatTarget(action.target)}
                      </span>
                    </div>
                    <span class="text-base-content/45 tabular-nums">
                      {formatUtcShort(action.updatedAt)}
                    </span>
                  </div>
                );
              })}
              {historicalProposals.map((proposal) => (
                <div
                  key={proposal.id}
                  class="flex flex-wrap items-center justify-between gap-2 py-1 border-b border-base-300/40 last:border-b-0"
                >
                  <div class="flex items-center gap-2 min-w-0">
                    <span class="px-1.5 py-0.5 rounded border border-base-300 bg-base-300/60 text-base-content/65 text-[10px] uppercase">
                      {proposal.status}
                    </span>
                    <span class="text-base-content/75 truncate">
                      {formatTarget(proposal.target)}
                    </span>
                  </div>
                  <span class="text-base-content/45 tabular-nums">
                    {formatUtcShort(proposal.createdAt)}
                  </span>
                </div>
              ))}
            </div>
          </details>
        )}
      </section>

      {/* Network Exposure Matrix */}
      <section class="oc-panel p-4 sm:p-5 space-y-3.5">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pb-3 border-b border-base-300/80">
          <div class="flex items-center gap-2 font-mono text-xs sm:text-sm font-bold uppercase tracking-wider text-base-content">
            <span class="text-info">//</span>
            <h2>Network Exposure Matrix</h2>
            <span class="px-1.5 py-0.5 rounded bg-base-300 text-base-content text-[11px] tabular-nums">
              {exposure.length}
            </span>
          </div>

          <div class="flex flex-col xs:flex-row sm:flex-row items-stretch sm:items-center gap-2">
            <div class="flex items-center gap-1.5">
              <label
                for="exposure-reachability-filter"
                class="font-mono text-[11px] text-base-content/60 shrink-0"
              >
                Reachability
              </label>
              <select
                id="exposure-reachability-filter"
                data-exposure-reachability="true"
                class="h-8 px-2 rounded bg-base-100 border border-base-300 focus:border-primary focus:outline-none font-mono text-xs text-base-content"
              >
                <option value="all">All</option>
                <option value="exposed_v4_v6">Exposed v4+v6</option>
                <option value="exposed_lan">Exposed LAN</option>
                <option value="tailnet">Tailnet</option>
                <option value="blocked_by_ufw">Blocked</option>
                <option value="local_only">Local</option>
                <option value="unknown">Unknown</option>
              </select>
            </div>

            <input
              id="exposure-search"
              type="search"
              name="q"
              aria-label="Search network exposure"
              placeholder="Filter process, IP, :port..."
              data-exposure-search="true"
              class="h-8 sm:w-52 px-2.5 rounded bg-base-100 border border-base-300 focus:border-primary focus:outline-none font-mono text-xs text-base-content placeholder:text-base-content/35"
            />
          </div>
        </div>

        {exposure.length === 0 ? (
          <p class="font-mono text-xs text-base-content/50">
            No listening sockets recorded yet.
          </p>
        ) : (
          <div class="overflow-x-auto">
            <table class="w-full text-left border-collapse font-mono text-xs">
              <thead>
                <tr class="border-b border-base-300/70 text-[11px] uppercase text-base-content/50">
                  <th class="py-2 pr-3 font-semibold">Process</th>
                  <th class="py-2 pr-3 font-semibold">Listener</th>
                  <th class="py-2 pr-3 font-semibold">Reachability</th>
                  <th class="py-2 pr-3 font-semibold">Firewall</th>
                  <th class="py-2 pr-3 font-semibold">Tailscale</th>
                  <th class="py-2 font-semibold">Policy</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-base-300/40">
                {exposure.map((entry) => {
                  const searchHay = [
                    entry.listener.process ?? "",
                    entry.listener.address,
                    `:${entry.listener.port}`,
                    entry.listener.protocol,
                    entry.reachability,
                    entry.publication,
                  ]
                    .join(" ")
                    .toLowerCase();
                  return (
                    <tr
                      key={entry.id}
                      data-exposure-row="true"
                      data-reachability={entry.reachability}
                      data-search={searchHay}
                    >
                      <td class="py-2 pr-3 text-base-content font-semibold whitespace-nowrap">
                        {entry.listener.process ?? "unknown"}
                        {entry.listener.pid !== undefined && (
                          <span class="text-base-content/45 font-normal ml-1">
                            #{entry.listener.pid}
                          </span>
                        )}
                      </td>
                      <td class="py-2 pr-3 text-base-content/85 tabular-nums whitespace-nowrap">
                        {entry.listener.protocol} {entry.listener.address}:
                        {entry.listener.port}
                      </td>
                      <td class="py-2 pr-3 whitespace-nowrap">
                        <span
                          class={`inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-semibold uppercase ${reachabilityBadgeClass(entry.reachability)}`}
                        >
                          {REACHABILITY_LABELS[entry.reachability]}
                        </span>
                      </td>
                      <td class="py-2 pr-3 text-[11px] text-base-content/70 whitespace-nowrap">
                        v4:{entry.firewallV4} · v6:{entry.firewallV6}
                      </td>
                      <td class="py-2 pr-3 text-[11px] text-base-content/70 whitespace-nowrap uppercase">
                        {entry.publication}
                      </td>
                      <td class="py-2 whitespace-nowrap">
                        <span
                          class={
                            entry.expected
                              ? "text-success text-[11px]"
                              : "text-warning font-semibold text-[11px]"
                          }
                        >
                          {entry.expected ? "expected" : "unexpected"}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* AI Investigation & Posture Audit */}
      <section class="oc-panel p-4 sm:p-5 space-y-4">
        <div class="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-base-300/80">
          <div class="flex items-center gap-2 font-mono text-xs sm:text-sm font-bold uppercase tracking-wider text-base-content">
            <span class="text-secondary">//</span>
            <h2>AI Investigation &amp; Posture Audit</h2>
          </div>
          {view.latestScan && (
            <span class="font-mono text-[11px] text-base-content/50 tabular-nums">
              Scan {view.latestScan.trigger} · {formatUtcShort(view.latestScan.finishedAt)}
            </span>
          )}
        </div>

        {/* AI Verdict */}
        {view.latestScan?.verdict ? (
          <div class="rounded border border-base-300 bg-base-100/75 p-3.5 space-y-1.5">
            <div class="flex flex-wrap items-center justify-between gap-2 font-mono text-xs">
              <div class="flex items-center gap-2">
                <span
                  class={`px-2 py-0.5 rounded border text-[11px] font-bold uppercase ${
                    view.latestScan.verdict.kind === "breach"
                      ? "bg-error/15 border-error/40 text-error"
                      : view.latestScan.verdict.kind === "warn"
                        ? "bg-warning/15 border-warning/40 text-warning"
                        : "bg-success/15 border-success/40 text-success"
                  }`}
                >
                  VERDICT: {view.latestScan.verdict.kind}
                </span>
                <span class="text-base-content/60 tabular-nums">
                  Confidence {Math.round(view.latestScan.verdict.confidence * 100)}%
                </span>
              </div>
              <span class="text-[11px] text-base-content/50">AI Analyst</span>
            </div>
            <p class="font-mono text-xs sm:text-sm text-base-content/90 break-words">
              {view.latestScan.verdict.summary}
            </p>
          </div>
        ) : (
          <div class="rounded border border-base-300/70 bg-base-100/50 p-3 font-mono text-xs text-base-content/60">
            AI status: {aiInfo.label}. Deterministic host checks continue without interruption.
          </div>
        )}

        {/* Posture Checklist */}
        <div class="space-y-2">
          <h3 class="font-mono text-xs uppercase tracking-wider text-base-content/65">
            Posture Checklist ({checks.length})
          </h3>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
            {checks.map((check) => {
              const badge = checkStatusBadge(check.status);
              return (
                <details
                  key={check.id}
                  data-detail-id={`check-${check.id}`}
                  class="rounded border border-base-300/80 bg-base-100/60"
                >
                  <summary class="p-2.5 cursor-pointer select-none flex items-start justify-between gap-2 font-mono text-xs">
                    <div class="min-w-0 space-y-1">
                      <div class="flex flex-wrap items-center gap-1.5">
                        <span
                          class={`px-1.5 py-0.5 rounded border text-[10px] font-bold uppercase ${badge.cls}`}
                        >
                          {badge.label}
                        </span>
                        <span class="font-semibold text-base-content">
                          {check.title}
                        </span>
                      </div>
                      <p class="text-[11px] text-base-content/70 break-words">
                        {check.summary}
                      </p>
                    </div>
                  </summary>
                  <div class="px-3 pb-3 pt-2 border-t border-base-300/60 space-y-2 font-mono text-[11px]">
                    {check.remediation && (
                      <div class="rounded bg-base-200 border border-base-300 p-2 text-base-content/85 break-words">
                        <span class="text-primary font-semibold">Remediation: </span>
                        {check.remediation}
                      </div>
                    )}
                    {check.evidenceIds.length > 0 && (
                      <div class="flex flex-wrap items-center gap-1">
                        <span class="text-base-content/50">Evidence:</span>
                        {check.evidenceIds.map((evId) => (
                          <span
                            key={evId}
                            class="px-1.5 py-0.5 rounded bg-base-300/70 text-base-content/70 break-all"
                          >
                            {evId}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </details>
              );
            })}
          </div>
        </div>

        {/* Findings */}
        {findings.length > 0 && (
          <div class="space-y-2 pt-2 border-t border-base-300/60">
            <h3 class="font-mono text-xs uppercase tracking-wider text-base-content/65">
              Findings ({findings.length})
            </h3>
            <div class="space-y-2">
              {findings.map((finding) => (
                <div
                  key={finding.id}
                  class="rounded border border-base-300/80 bg-base-100/60 p-3 space-y-1.5 font-mono text-xs"
                >
                  <div class="flex flex-wrap items-center gap-1.5">
                    <span
                      class={`px-1.5 py-0.5 rounded border text-[10px] font-bold uppercase ${severityBadgeClass(finding.severity)}`}
                    >
                      {finding.severity}
                    </span>
                    <span class="px-1.5 py-0.5 rounded bg-base-300/70 text-base-content/70 text-[10px] uppercase">
                      {finding.source}
                    </span>
                  </div>
                  <p class="text-base-content/90 break-words">{finding.summary}</p>
                  {finding.evidenceIds.length > 0 && (
                    <div class="flex flex-wrap items-center gap-1 text-[11px]">
                      <span class="text-base-content/50">Evidence:</span>
                      {finding.evidenceIds.map((evId) => (
                        <span
                          key={evId}
                          class="px-1.5 py-0.5 rounded bg-base-300/70 text-base-content/70 break-all"
                        >
                          {evId}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Investigation Trail */}
        <details
          data-detail-id="investigation-trail"
          class="rounded border border-base-300/80 bg-base-100/50"
        >
          <summary class="px-3 py-2 font-mono text-xs font-semibold text-base-content/80 cursor-pointer select-none flex items-center justify-between">
            <span>Investigation Trail ({trailSteps.length} steps)</span>
            <span class="text-[11px] text-base-content/45">read-only tools</span>
          </summary>
          <div class="p-3 pt-2 border-t border-base-300/60 space-y-2 font-mono text-[11px]">
            {trailSteps.length === 0 ? (
              <p class="text-base-content/50">No AI tool steps recorded.</p>
            ) : (
              trailSteps.map((step, index) => (
                <div
                  key={`${step.tool}-${index}`}
                  class="rounded bg-base-200/70 border border-base-300/70 p-2.5 space-y-1"
                >
                  <div class="flex flex-wrap items-center justify-between gap-2">
                    <span class="font-semibold text-secondary">{step.tool}</span>
                    <span
                      class={
                        step.outcome === "ok"
                          ? "px-1.5 py-0.5 rounded bg-success/15 text-success text-[10px] uppercase"
                          : step.outcome === "rejected"
                            ? "px-1.5 py-0.5 rounded bg-error/15 text-error text-[10px] uppercase"
                            : "px-1.5 py-0.5 rounded bg-base-300 text-base-content/65 text-[10px] uppercase"
                      }
                    >
                      {step.outcome}
                    </span>
                  </div>
                  <p class="text-base-content/80 break-words">{step.reason}</p>
                  {step.evidenceIds.length > 0 && (
                    <div class="flex flex-wrap items-center gap-1">
                      <span class="text-base-content/50">Evidence:</span>
                      {step.evidenceIds.map((evId) => (
                        <span
                          key={evId}
                          class="px-1.5 py-0.5 rounded bg-base-300/70 text-base-content/70 break-all"
                        >
                          {evId}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </details>
      </section>

      {/* Live Security Event Stream & 24h Activity */}
      <section class="oc-panel p-4 sm:p-5 space-y-4">
        <div class="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-base-300/80">
          <div class="flex items-center gap-2 font-mono text-xs sm:text-sm font-bold uppercase tracking-wider text-base-content">
            <span class="text-accent">//</span>
            <h2>Events &amp; 24h Activity</h2>
          </div>
          <div class="flex items-center gap-3 font-mono text-[11px] text-base-content/60">
            <span class="inline-flex items-center gap-1">
              <span class="w-2 h-2 rounded-xs bg-primary" />
              Signal ({signalEventsCount})
            </span>
            <span class="inline-flex items-center gap-1">
              <span class="w-2 h-2 rounded-xs bg-base-content/30" />
              Noise ({noiseEventsCount})
            </span>
          </div>
        </div>

        <div class="rounded border border-base-300/70 bg-base-100/60 p-2.5">
          <ActivitySvg hourly={view.hourly} />
        </div>

        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
          <div
            class="flex flex-wrap items-center gap-1.5"
            role="group"
            aria-label="Filter events by category"
          >
            {EVENT_CATEGORIES.map((cat) => (
              <button
                key={cat.id}
                type="button"
                data-event-category={cat.id}
                aria-pressed={cat.id === "all" ? "true" : "false"}
                class={
                  cat.id === "all"
                    ? "h-7 px-2.5 rounded border font-mono text-[11px] font-semibold bg-primary/15 border-primary/45 text-primary cursor-pointer"
                    : "h-7 px-2.5 rounded border font-mono text-[11px] bg-base-100 border-base-300 text-base-content/70 hover:text-base-content cursor-pointer"
                }
              >
                {cat.label}
              </button>
            ))}
          </div>

          <label class="inline-flex items-center gap-2 font-mono text-xs text-base-content/75 cursor-pointer select-none">
            <input
              id="security-hide-noise"
              type="checkbox"
              checked
              data-hide-noise="true"
              class="accent-primary"
            />
            <span>Hide noise</span>
            <span class="text-[11px] text-base-content/50 tabular-nums">
              ({noiseEventsCount} benign multicast drops hidden)
            </span>
          </label>
        </div>

        {view.events.length === 0 ? (
          <p class="font-mono text-xs text-base-content/50">
            No security events recorded in the past 24 hours.
          </p>
        ) : (
          <div class="space-y-1.5" id="security-events-list">
            {view.events.map((event: SecurityEvent) => (
              <div
                key={event.id}
                data-event-row="true"
                data-category={event.category}
                data-noise={event.isNoise ? "true" : "false"}
                class={`${
                  event.isNoise ? "hidden " : ""
                }rounded border border-base-300/70 bg-base-100/60 px-3 py-2 flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 font-mono text-xs`}
              >
                <div class="flex flex-wrap items-center gap-2 min-w-0">
                  <span
                    class={`px-1.5 py-0.5 rounded border text-[10px] font-bold uppercase shrink-0 ${severityBadgeClass(event.severity)}`}
                  >
                    {event.severity}
                  </span>
                  <span class="px-1.5 py-0.5 rounded bg-base-300/70 text-base-content/70 text-[10px] uppercase shrink-0">
                    {event.category}
                  </span>
                  <span class="text-base-content/90 break-words min-w-0">
                    {event.summary}
                  </span>
                </div>

                <div class="flex items-center gap-2 text-[11px] text-base-content/50 tabular-nums shrink-0">
                  {event.count > 1 && (
                    <span class="px-1.5 py-0.5 rounded bg-base-300/70 text-base-content/80">
                      ×{event.count}
                    </span>
                  )}
                  <span>{formatUtcShort(event.lastAt)}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
};

export const SecurityLogin = ({ error }: SecurityLoginProps) => (
  <div id="security-login" hx-history="false" class="max-w-md mx-auto py-8 sm:py-14">
    <section class="oc-panel p-5 sm:p-6 space-y-5">
      <div class="space-y-1.5 pb-3 border-b border-base-300/80">
        <div class="flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-primary font-semibold">
          <span>//</span>
          <span>Security Access</span>
        </div>
        <h2 class="font-mono text-base sm:text-lg font-bold text-base-content">
          Sign in to Basho Security
        </h2>
        <p class="font-mono text-xs text-base-content/60">
          Enter the configured <code class="text-primary">BASHO_AUTH_TOKEN</code>{" "}
          to access host posture, alerts, and containment controls.
        </p>
      </div>

      {error && (
        <div
          role="alert"
          class="rounded border border-error/45 bg-error/10 px-3 py-2 font-mono text-xs text-error"
        >
          {error}
        </div>
      )}

      <form method="post" action="/security/login" class="space-y-4">
        <div class="space-y-1.5">
          <label
            for="security-token-input"
            class="block font-mono text-xs font-semibold text-base-content/80"
          >
            Access Token
          </label>
          <input
            id="security-token-input"
            name="token"
            type="password"
            autocomplete="current-password"
            required
            placeholder="Enter access token..."
            class="w-full h-10 px-3 rounded bg-base-100 border border-base-300 focus:border-primary focus:outline-none font-mono text-sm text-base-content placeholder:text-base-content/35"
          />
        </div>

        <button
          type="submit"
          class="w-full h-10 rounded bg-primary/20 hover:bg-primary/30 border border-primary/50 font-mono text-xs font-bold uppercase tracking-wider text-primary transition-colors cursor-pointer"
        >
          Sign In
        </button>
      </form>
    </section>
  </div>
);
