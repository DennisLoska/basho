import { accessSync, constants as fsConstants } from "node:fs";
import { hostname } from "node:os";
import {
  AiAnalyst,
  createAiProviderClient,
  EvidenceBroker,
  type InvestigationResult,
  type ProposalDraft,
} from "./ai-analyst";
import {
  classifyListeners,
  createPostureFiles,
  PostureCollector,
  type PostureResult,
} from "./collector";
import { loadSecurityConfig } from "./config";
import { EventMonitor, type MonitorResult } from "./events";
import {
  createCompositeLockdownAdapter,
  createProcProcessResolver,
  DeadMansSwitch,
  LockdownEngine,
  type ConsiderResult,
} from "./lockdown";
import { NotificationDispatcher } from "./notifications";
import { createCommandRunner } from "./runner";
import { SecurityStore, type SecurityStoreContract } from "./store";
import {
  criterionIds,
  lockdownModes,
  type AlertChannel,
  type Clock,
  type CommandRunner,
  type Corroboration,
  type CriterionId,
  type ExposureEntry,
  type Facts,
  type Listener,
  type LockdownAction,
  type LockdownMode,
  type LockdownProposal,
  type RuntimeOverrides,
  type SecurityAlert,
  type SecurityEvent,
  type SecurityScan,
  type SecuritySecrets,
  type SecuritySettings,
} from "./types";

const MINUTE_MS = 60_000;
const DAY_MS = 86_400_000;
const SOCKET_POLL_MS = 30_000;
const JOURNAL_POLL_MS = 5_000;
const DRAIN_INTERVAL_MS = 10_000;
const RECONCILE_INTERVAL_MS = 15_000;
const PRUNE_INTERVAL_MS = 6 * 60 * MINUTE_MS;
const RECENT_EVENTS_WINDOW_MS = DAY_MS;
const RECENT_EVENTS_LIMIT = 100;
const RECENT_ALERTS_WINDOW_MS = 7 * DAY_MS;
const DEFAULT_HELPER_PATH = "/usr/local/libexec/basho-lockdown-helper";

const CRITERION_SET = new Set<string>(criterionIds);
const MODE_SET = new Set<string>(lockdownModes);
const OVERRIDE_KEYS = new Set(["mode", "scanIntervalMinutes", "criteria"]);

export type SecurityUpdate = {
  kind: "scan" | "events" | "alert" | "containment" | "settings" | "status";
};

export interface SecurityView {
  hostLabel: string;
  latestScan: SecurityScan | null;
  events: SecurityEvent[];
  hourly: { hour: number; signal: number; noise: number }[];
  proposals: LockdownProposal[];
  actions: LockdownAction[];
  alerts: SecurityAlert[];
  channelHealth: ReturnType<SecurityStore["channelHealth"]>;
  settings: Pick<SecuritySettings, "mode" | "criteria" | "scanIntervalMinutes">;
  aiStatus: SecurityScan["aiStatus"];
  scanRunning: boolean;
  nextScanAt: number | null;
  helperReady: boolean;
}

export interface SecurityRuntime {
  start(): void;
  stop(): Promise<void>;
  view(): SecurityView;
  subscribe(listener: (update: SecurityUpdate) => void): () => void;
  requestScan(trigger: SecurityScan["trigger"]): Promise<SecurityScan>;
  updateSettings(overrides: RuntimeOverrides): void;
  approve(id: string, revision: number): Promise<boolean>;
  reject(id: string, revision: number): boolean;
  unlock(id: string): Promise<boolean>;
  dismissAlert(id: string): boolean;
  sendTestAlert(channel?: AlertChannel): string;
}

export interface Scheduler {
  every(ms: number, run: () => unknown): () => void;
}

export interface RuntimeCollector {
  collect(
    scanId: string,
    settings: SecuritySettings,
    signal?: AbortSignal,
  ): Promise<PostureResult>;
}

export interface RuntimeMonitor {
  pollJournal(signal?: AbortSignal): Promise<MonitorResult>;
  pollSockets:
    | ((
        classify: (listeners: Listener[]) => Promise<ExposureEntry[]> | ExposureEntry[],
        signal?: AbortSignal,
      ) => Promise<MonitorResult>)
    | ((signal?: AbortSignal) => Promise<MonitorResult>);
}

export interface RuntimeAnalyst {
  investigate(
    scanId: string,
    broker: EvidenceBroker,
    signal?: AbortSignal,
  ): Promise<InvestigationResult>;
}

export interface RuntimeLockdown {
  consider(
    scan: SecurityScan,
    drafts: readonly ProposalDraft[],
    corroboration: readonly Corroboration[],
    settings: SecuritySettings,
  ): Promise<ConsiderResult>;
  approve(id: string, revision: number, settings: SecuritySettings): Promise<boolean>;
  reject(id: string, revision: number): boolean;
  unlock(actionId: string): Promise<boolean>;
  reconcile(): Promise<void>;
}

export interface RuntimeDispatcher {
  publish(alert: SecurityAlert): boolean;
  sendTestAlert(channel?: AlertChannel): string;
  drain(): Promise<void>;
  health(): ReturnType<SecurityStore["channelHealth"]>;
}

export interface SecurityRuntimeOptions {
  store: SecurityStoreContract;
  collector: RuntimeCollector;
  monitor: RuntimeMonitor;
  analyst: RuntimeAnalyst;
  lockdown: RuntimeLockdown;
  dispatcher: RuntimeDispatcher;
  clock?: Clock;
  scheduler?: Scheduler;
  settings: SecuritySettings;
  hostLabel?: string;
  helperReady?: boolean | (() => boolean);
  runner?: CommandRunner;
  classifySockets?: (listeners: Listener[]) => Promise<ExposureEntry[]> | ExposureEntry[];
}

export function createSystemScheduler(): Scheduler {
  return {
    every(ms: number, run: () => unknown): () => void {
      const timer = setInterval(() => {
        run();
      }, ms);
      if (typeof timer === "object" && timer !== null && "unref" in timer) {
        (timer as { unref?: () => void }).unref?.();
      }
      return () => {
        clearInterval(timer);
      };
    },
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function validateAndMergeOverrides(
  currentSettings: SecuritySettings,
  currentOverrides: RuntimeOverrides,
  incoming: RuntimeOverrides,
): { nextSettings: SecuritySettings; nextOverrides: RuntimeOverrides } {
  if (!isPlainObject(incoming)) {
    throw new Error("Invalid overrides: expected object");
  }

  for (const key of Object.keys(incoming)) {
    if (!OVERRIDE_KEYS.has(key)) {
      throw new Error(`Invalid override field: "${key}"`);
    }
  }

  let nextMode: LockdownMode = currentSettings.mode;
  let overrideMode: LockdownMode | undefined = currentOverrides.mode;
  if (incoming.mode !== undefined) {
    if (typeof incoming.mode !== "string" || !MODE_SET.has(incoming.mode)) {
      throw new Error(`Invalid lockdown mode: ${String(incoming.mode)}`);
    }
    nextMode = incoming.mode as LockdownMode;
    overrideMode = nextMode;
  }

  let nextScanInterval = currentSettings.scanIntervalMinutes;
  let overrideScanInterval: number | undefined = currentOverrides.scanIntervalMinutes;
  if (incoming.scanIntervalMinutes !== undefined) {
    if (
      typeof incoming.scanIntervalMinutes !== "number" ||
      !Number.isInteger(incoming.scanIntervalMinutes) ||
      incoming.scanIntervalMinutes < 1 ||
      incoming.scanIntervalMinutes > 1440
    ) {
      throw new Error("Invalid scanIntervalMinutes: expected integer between 1 and 1440");
    }
    nextScanInterval = incoming.scanIntervalMinutes;
    overrideScanInterval = nextScanInterval;
  }

  const nextCriteria: Record<CriterionId, boolean> = { ...currentSettings.criteria };
  let overrideCriteria: Partial<Record<CriterionId, boolean>> | undefined =
    currentOverrides.criteria ? { ...currentOverrides.criteria } : undefined;

  if (incoming.criteria !== undefined) {
    if (!isPlainObject(incoming.criteria)) {
      throw new Error("Invalid overrides.criteria: expected object");
    }
    const mergedOverrideCriteria: Partial<Record<CriterionId, boolean>> = {
      ...(overrideCriteria ?? {}),
    };
    for (const [key, value] of Object.entries(incoming.criteria)) {
      if (!CRITERION_SET.has(key)) {
        throw new Error(`Invalid overrides.criteria: unknown criterion "${key}"`);
      }
      if (typeof value !== "boolean") {
        throw new Error(`Invalid overrides.criteria.${key}: expected boolean`);
      }
      nextCriteria[key as CriterionId] = value;
      mergedOverrideCriteria[key as CriterionId] = value;
    }
    overrideCriteria = mergedOverrideCriteria;
  }

  const nextOverrides: RuntimeOverrides = {
    ...(overrideMode !== undefined ? { mode: overrideMode } : {}),
    ...(overrideScanInterval !== undefined ? { scanIntervalMinutes: overrideScanInterval } : {}),
    ...(overrideCriteria !== undefined ? { criteria: overrideCriteria } : {}),
  };

  const nextSettings: SecuritySettings = {
    ...currentSettings,
    mode: nextMode,
    scanIntervalMinutes: nextScanInterval,
    criteria: nextCriteria,
  };

  return { nextSettings, nextOverrides };
}

function cloneSettings(settings: SecuritySettings): SecuritySettings {
  return {
    ...settings,
    criteria: { ...settings.criteria },
    expectedPorts: [...settings.expectedPorts],
    workloads: settings.workloads.map((w) => ({
      ...w,
      ...(w.ports ? { ports: [...w.ports] } : {}),
    })),
    ai: { ...settings.ai },
    notifications: {
      ...settings.notifications,
      channels: [...settings.notifications.channels],
    },
    lockdown: { ...settings.lockdown },
    process: { ...settings.process },
  };
}

function defaultHostLabel(): string {
  try {
    const raw = hostname().trim();
    if (raw.length > 0) {
      return raw.slice(0, 64);
    }
  } catch {
    // Fall back to localhost when hostname cannot be read.
  }
  return "localhost";
}

function createUnitStatusReader(
  runner: CommandRunner,
  signal: AbortSignal,
): (name: string, scope: "system" | "user") => Promise<Facts | null> {
  return async (name: string, scope: "system" | "user"): Promise<Facts | null> => {
    const res = await runner.run({ kind: "unit", name, scope }, signal);
    if (res.status !== "ok") {
      return null;
    }
    const facts: Record<string, string | number | boolean | null> = {};
    for (const line of res.stdout.split(/\r?\n/)) {
      const eq = line.indexOf("=");
      if (eq <= 0) continue;
      const key = line.slice(0, eq).trim();
      const val = line.slice(eq + 1).trim();
      if (
        key === "ActiveState" ||
        key === "SubState" ||
        key === "Result" ||
        key === "ExecMainStatus"
      ) {
        facts[key] = val;
      }
    }
    return Object.keys(facts).length > 0 ? facts : null;
  };
}

function fallbackClassifySockets(
  listeners: Listener[],
  settings: SecuritySettings,
): ExposureEntry[] {
  const expectedPorts = new Set<number>(settings.expectedPorts);
  for (const workload of settings.workloads) {
    for (const port of workload.ports ?? []) {
      expectedPorts.add(port);
    }
  }
  return classifyListeners({
    listeners,
    firewall: { active: null },
    publications: {
      servePorts: new Set(),
      funnelPorts: new Set(),
      serveTargets: [],
      funnelTargets: [],
      serveCoverage: "unavailable",
      funnelCoverage: "unavailable",
    },
    expectedPorts,
    evidenceIdForListener: (_listener, index) => `socket-poll:${index}`,
  });
}

export function createSecurityRuntime(options: SecurityRuntimeOptions): SecurityRuntime {
  const clock: Clock = options.clock ?? { now: () => Date.now() };
  const scheduler: Scheduler = options.scheduler ?? createSystemScheduler();
  const store = options.store;
  const collector = options.collector;
  const monitor = options.monitor;
  const analyst = options.analyst;
  const lockdown = options.lockdown;
  const dispatcher = options.dispatcher;
  const hostLabel = options.hostLabel?.trim() || defaultHostLabel();

  let currentOverrides: RuntimeOverrides = {};
  let currentSettings: SecuritySettings = cloneSettings(options.settings);
  try {
    const persisted = store.readOverrides();
    if (Object.keys(persisted).length > 0) {
      const applied = validateAndMergeOverrides(currentSettings, currentOverrides, persisted);
      currentSettings = applied.nextSettings;
      currentOverrides = applied.nextOverrides;
    }
  } catch {
    // Keep provided validated settings if persisted overrides cannot be loaded.
  }

  const listeners = new Set<(update: SecurityUpdate) => void>();
  const fixedUnsubs: Array<() => void> = [];
  let scanTickUnsub: (() => void) | null = null;

  let started = false;
  let stopped = false;
  let stopPromise: Promise<void> | null = null;
  let runtimeAbort = new AbortController();

  let scanRunning = false;
  let activeScanPromise: Promise<SecurityScan> | null = null;
  let activeScanInputAt = 0;
  let activeScanEvidenceVersion = 0;
  let pendingEventFollowUp: {
    promise: Promise<SecurityScan>;
    resolve: (scan: SecurityScan) => void;
    reject: (error: unknown) => void;
  } | null = null;
  let lastEventAiAt: number | null = null;
  let lastEvidenceAt = 0;
  let evidenceVersion = 0;
  let nextScanAt: number | null = null;
  let lastAiStatus: SecurityScan["aiStatus"] =
    store.latestScan()?.aiStatus ?? "unconfigured";

  const activeCorroborations: Corroboration[] = [];
  const inFlightTasks = new Set<Promise<unknown>>();

  const latestEvidenceAt = (): number => {
    const latestStoreEventAt = store.recentEvents(0, 1)[0]?.lastAt ?? 0;
    return Math.max(lastEvidenceAt, latestStoreEventAt);
  };

  const emit = (update: SecurityUpdate): void => {
    if (stopped) return;
    for (const listener of [...listeners]) {
      try {
        listener(update);
      } catch {
        // Isolate subscriber exceptions so runtime updates continue.
      }
    }
  };

  const trackTask = <T>(promise: Promise<T>): Promise<T> => {
    const tracked = promise.finally(() => {
      inFlightTasks.delete(tracked);
    });
    inFlightTasks.add(tracked);
    return tracked;
  };

  const recordCorroborations = (entries: readonly Corroboration[]): void => {
    const now = clock.now();
    for (let i = activeCorroborations.length - 1; i >= 0; i -= 1) {
      if (activeCorroborations[i]!.expiresAt <= now) {
        activeCorroborations.splice(i, 1);
      }
    }
    for (const entry of entries) {
      if (entry.expiresAt > now) {
        activeCorroborations.push(entry);
      }
    }
  };

  const getActiveCorroborations = (): Corroboration[] => {
    const now = clock.now();
    for (let i = activeCorroborations.length - 1; i >= 0; i -= 1) {
      if (activeCorroborations[i]!.expiresAt <= now) {
        activeCorroborations.splice(i, 1);
      }
    }
    return [...activeCorroborations];
  };

  const handleMonitorResult = (result: MonitorResult): void => {
    if (stopped) return;
    const now = clock.now();
    if (result.corroboration.length > 0) {
      recordCorroborations(result.corroboration);
    }

    let publishedAny = false;
    for (const alert of result.alerts) {
      if (dispatcher.publish(alert)) {
        publishedAny = true;
      }
    }

    if (publishedAny) {
      emit({ kind: "alert" });
      void trackTask(dispatcher.drain().catch(() => {}));
    }

    if (result.alerts.length > 0 || result.corroboration.length > 0) {
      lastEvidenceAt = Math.max(lastEvidenceAt, now);
      evidenceVersion += 1;
      emit({ kind: "events" });
      void requestScan("event").catch(() => {});
    }
  };

  const runSingleScan = async (trigger: SecurityScan["trigger"]): Promise<SecurityScan> => {
    if (stopped) {
      throw new Error("SecurityRuntime has been stopped");
    }

    const scanId = crypto.randomUUID();
    const startedAt = clock.now();
    activeScanInputAt = Math.max(startedAt, latestEvidenceAt());
    activeScanEvidenceVersion = evidenceVersion;
    const scanSettings = cloneSettings(currentSettings);
    const scanAbort = new AbortController();

    const onRuntimeAbort = () => {
      scanAbort.abort();
    };
    if (runtimeAbort.signal.aborted) {
      scanAbort.abort();
    } else {
      runtimeAbort.signal.addEventListener("abort", onRuntimeAbort, { once: true });
    }

    scanRunning = true;
    emit({ kind: "status" });

    try {
      const posture = await collector.collect(scanId, scanSettings, scanAbort.signal);

      if (stopped || scanAbort.signal.aborted) {
        throw new Error("Security scan aborted");
      }

      const deterministicScan: SecurityScan = {
        id: scanId,
        trigger,
        startedAt,
        finishedAt: clock.now(),
        snapshot: posture.snapshot,
        exposure: posture.exposure,
        findings: [...posture.findings],
        trail: { steps: [] },
        aiStatus: lastAiStatus,
      };

      store.saveScan(deterministicScan);
      emit({ kind: "scan" });

      const eventCooldownMs = Math.max(0, scanSettings.ai.triageCooldownMinutes) * MINUTE_MS;
      const skipAiForCooldown =
        trigger === "event" &&
        lastEventAiAt !== null &&
        eventCooldownMs > 0 &&
        startedAt - lastEventAiAt < eventCooldownMs;

      if (skipAiForCooldown) {
        return deterministicScan;
      }

      if (trigger === "event") {
        lastEventAiAt = startedAt;
      }

      const broker = new EvidenceBroker({
        scanId,
        evidence: posture.snapshot.evidence,
        recentEvents: (category, windowMinutes, limit) =>
          store.recentEvents(clock.now() - windowMinutes * MINUTE_MS, limit, category),
        ...(options.runner
          ? { unitStatus: createUnitStatusReader(options.runner, scanAbort.signal) }
          : {}),
      });

      const investigation = await analyst.investigate(scanId, broker, scanAbort.signal);

      if (stopped || scanAbort.signal.aborted) {
        throw new Error("Security scan aborted");
      }

      lastAiStatus = investigation.status;
      const completedScan: SecurityScan = {
        ...deterministicScan,
        finishedAt: clock.now(),
        findings: [...posture.findings, ...investigation.findings],
        trail: investigation.trail,
        aiStatus: investigation.status,
        ...(investigation.verdict ? { verdict: investigation.verdict } : {}),
      };

      store.saveScan(completedScan);
      emit({ kind: "scan" });

      let linkedProposalId: string | undefined;
      if (investigation.proposals.length > 0 && !stopped) {
        const considerResult = await lockdown.consider(
          completedScan,
          investigation.proposals,
          getActiveCorroborations(),
          scanSettings,
        );
        if (considerResult.proposals.length > 0 || considerResult.actions.length > 0) {
          linkedProposalId = considerResult.proposals[0]?.id;
          emit({ kind: "containment" });
        }
        if (considerResult.alerts.length > 0) {
          emit({ kind: "alert" });
          void trackTask(dispatcher.drain().catch(() => {}));
        }
      }

      if (completedScan.verdict?.kind === "breach" && !stopped) {
        const breachAlert: SecurityAlert = {
          id: `alert:verdict:${scanId}`,
          fingerprint: "ai:verdict:breach",
          severity: "breach",
          summary: completedScan.verdict.summary,
          createdAt: clock.now(),
          ...(linkedProposalId ? { proposalId: linkedProposalId } : {}),
        };
        if (dispatcher.publish(breachAlert)) {
          emit({ kind: "alert" });
          void trackTask(dispatcher.drain().catch(() => {}));
        }
      }

      return completedScan;
    } finally {
      runtimeAbort.signal.removeEventListener("abort", onRuntimeAbort);
      scanRunning = false;
      emit({ kind: "status" });
    }
  };

  const launchScan = (trigger: SecurityScan["trigger"]): Promise<SecurityScan> => {
    const run = runSingleScan(trigger).finally(() => {
      activeScanPromise = null;
      const followUp = pendingEventFollowUp;
      pendingEventFollowUp = null;
      if (followUp) {
        if (stopped) {
          followUp.reject(new Error("SecurityRuntime has been stopped"));
        } else {
          launchScan("event").then(followUp.resolve, followUp.reject);
        }
      }
    });
    activeScanPromise = run;
    trackTask(run.catch(() => undefined));
    return run;
  };

  const requestScan = (trigger: SecurityScan["trigger"]): Promise<SecurityScan> => {
    if (stopped) {
      return Promise.reject(new Error("SecurityRuntime has been stopped"));
    }

    if (activeScanPromise !== null) {
      if (trigger === "event") {
        const hasNewEvidence =
          latestEvidenceAt() > activeScanInputAt ||
          evidenceVersion > activeScanEvidenceVersion;
        if (hasNewEvidence) {
          if (!pendingEventFollowUp) {
            let resolve!: (scan: SecurityScan) => void;
            let reject!: (error: unknown) => void;
            const promise = new Promise<SecurityScan>((res, rej) => {
              resolve = res;
              reject = rej;
            });
            pendingEventFollowUp = { promise, resolve, reject };
          }
          return pendingEventFollowUp.promise;
        }
      }
      return activeScanPromise;
    }

    return launchScan(trigger);
  };

  const createNonOverlappingRunner = (
    fn: (signal: AbortSignal) => Promise<void> | void,
  ): (() => void) => {
    let running = false;
    return () => {
      if (stopped || running) return;
      running = true;
      const execution = Promise.resolve()
        .then(() => fn(runtimeAbort.signal))
        .catch(() => {})
        .finally(() => {
          running = false;
        });
      trackTask(execution);
    };
  };

  const scheduleNonOverlapping = (
    ms: number,
    fn: (signal: AbortSignal) => Promise<void> | void,
  ): { run: () => void; unsub: () => void } => {
    const run = createNonOverlappingRunner(fn);
    const unsub = scheduler.every(ms, run);
    return { run, unsub };
  };

  const schedulePeriodicScan = (): void => {
    if (scanTickUnsub) {
      scanTickUnsub();
      scanTickUnsub = null;
    }
    if (stopped) return;
    const intervalMs = currentSettings.scanIntervalMinutes * MINUTE_MS;
    nextScanAt = clock.now() + intervalMs;
    scanTickUnsub = scheduleNonOverlapping(intervalMs, async () => {
      nextScanAt = clock.now() + currentSettings.scanIntervalMinutes * MINUTE_MS;
      await requestScan("scheduled");
    }).unsub;
  };

  const invokeSocketPoll = async (signal: AbortSignal): Promise<MonitorResult> => {
    if (options.classifySockets) {
      return (
        monitor.pollSockets as (
          classify: (listeners: Listener[]) => Promise<ExposureEntry[]> | ExposureEntry[],
          signal?: AbortSignal,
        ) => Promise<MonitorResult>
      )(options.classifySockets, signal);
    }
    if (monitor instanceof EventMonitor || monitor.pollSockets.length >= 2) {
      return (
        monitor.pollSockets as (
          classify: (listeners: Listener[]) => Promise<ExposureEntry[]> | ExposureEntry[],
          signal?: AbortSignal,
        ) => Promise<MonitorResult>
      )((listeners) => fallbackClassifySockets(listeners, currentSettings), signal);
    }
    return (monitor.pollSockets as (signal?: AbortSignal) => Promise<MonitorResult>)(signal);
  };

  return {
    start(): void {
      if (started || stopped) return;
      started = true;

      // Independent non-overlapping periodic schedules.
      fixedUnsubs.push(
        scheduleNonOverlapping(JOURNAL_POLL_MS, async (signal) => {
          const beforeLast = store.recentEvents(0, 1)[0]?.lastAt ?? 0;
          const result = await monitor.pollJournal(signal);
          const afterLast = store.recentEvents(0, 1)[0]?.lastAt ?? 0;
          if (!stopped && afterLast > beforeLast) {
            lastEvidenceAt = Math.max(lastEvidenceAt, afterLast, clock.now());
            evidenceVersion += 1;
            if (result.alerts.length === 0 && result.corroboration.length === 0) {
              emit({ kind: "events" });
            }
          }
          handleMonitorResult(result);
        }).unsub,
      );

      fixedUnsubs.push(
        scheduleNonOverlapping(SOCKET_POLL_MS, async (signal) => {
          const beforeLast = store.recentEvents(0, 1)[0]?.lastAt ?? 0;
          const result = await invokeSocketPoll(signal);
          const afterLast = store.recentEvents(0, 1)[0]?.lastAt ?? 0;
          if (!stopped && afterLast > beforeLast) {
            lastEvidenceAt = Math.max(lastEvidenceAt, afterLast, clock.now());
            evidenceVersion += 1;
            if (result.alerts.length === 0 && result.corroboration.length === 0) {
              emit({ kind: "events" });
            }
          }
          handleMonitorResult(result);
        }).unsub,
      );

      const drainSchedule = scheduleNonOverlapping(DRAIN_INTERVAL_MS, async () => {
        await dispatcher.drain();
      });
      fixedUnsubs.push(drainSchedule.unsub);

      const reconcileSchedule = scheduleNonOverlapping(RECONCILE_INTERVAL_MS, async () => {
        await lockdown.reconcile();
      });
      fixedUnsubs.push(reconcileSchedule.unsub);

      const pruneSchedule = scheduleNonOverlapping(PRUNE_INTERVAL_MS, () => {
        store.prune(clock.now());
      });
      fixedUnsubs.push(pruneSchedule.unsub);

      schedulePeriodicScan();

      // Startup recovery: route through the exact same per-schedule non-overlapping guards.
      pruneSchedule.run();
      reconcileSchedule.run();
      drainSchedule.run();
    },

    stop(): Promise<void> {
      if (stopPromise) {
        return stopPromise;
      }

      stopped = true;
      nextScanAt = null;

      // Stop all scheduled intervals immediately.
      for (const unsub of fixedUnsubs.splice(0, fixedUnsubs.length)) {
        try {
          unsub();
        } catch {
          // Ignore scheduler cleanup errors.
        }
      }
      if (scanTickUnsub) {
        try {
          scanTickUnsub();
        } catch {
          // Ignore scheduler cleanup errors.
        }
        scanTickUnsub = null;
      }

      // Drop all subscriber listeners so no further updates can fire during or after shutdown.
      listeners.clear();

      // Abort any in-flight bounded I/O.
      runtimeAbort.abort();

      if (pendingEventFollowUp) {
        const followUp = pendingEventFollowUp;
        pendingEventFollowUp = null;
        followUp.reject(new Error("SecurityRuntime has been stopped"));
      }

      stopPromise = (async () => {
        while (inFlightTasks.size > 0) {
          const pending = [...inFlightTasks];
          await Promise.allSettled(pending);
        }
        store.close();
      })();

      return stopPromise;
    },

    view(): SecurityView {
      const now = clock.now();
      const latestScan = store.latestScan();
      const helperReady =
        typeof options.helperReady === "function"
          ? options.helperReady()
          : (options.helperReady ?? currentSettings.lockdown.helperEnabled);

      return {
        hostLabel,
        latestScan,
        events: store.recentEvents(now - RECENT_EVENTS_WINDOW_MS, RECENT_EVENTS_LIMIT),
        hourly: store.hourlyEvents(now),
        proposals: store.listProposals(),
        actions: store.listActions(),
        alerts: store.recentAlerts(now - RECENT_ALERTS_WINDOW_MS),
        channelHealth: dispatcher.health(),
        settings: {
          mode: currentSettings.mode,
          criteria: { ...currentSettings.criteria },
          scanIntervalMinutes: currentSettings.scanIntervalMinutes,
        },
        aiStatus: latestScan?.aiStatus ?? lastAiStatus,
        scanRunning,
        nextScanAt,
        helperReady,
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

    requestScan,

    updateSettings(overrides: RuntimeOverrides): void {
      if (stopped) {
        throw new Error("SecurityRuntime has been stopped");
      }
      const { nextSettings, nextOverrides } = validateAndMergeOverrides(
        currentSettings,
        currentOverrides,
        overrides,
      );
      const intervalChanged =
        nextSettings.scanIntervalMinutes !== currentSettings.scanIntervalMinutes;

      store.writeOverrides(nextOverrides);
      currentSettings = nextSettings;
      currentOverrides = nextOverrides;

      if (started && !stopped && intervalChanged) {
        schedulePeriodicScan();
      }

      emit({ kind: "settings" });
    },

    approve(id: string, revision: number): Promise<boolean> {
      if (stopped) return Promise.resolve(false);
      return trackTask(
        (async () => {
          const ok = await lockdown.approve(id, revision, cloneSettings(currentSettings));
          if (ok) {
            emit({ kind: "containment" });
          }
          return ok;
        })(),
      );
    },

    reject(id: string, revision: number): boolean {
      if (stopped) return false;
      const ok = lockdown.reject(id, revision);
      if (ok) {
        emit({ kind: "containment" });
      }
      return ok;
    },

    unlock(id: string): Promise<boolean> {
      if (stopped) return Promise.resolve(false);
      return trackTask(
        (async () => {
          const ok = await lockdown.unlock(id);
          if (ok) {
            emit({ kind: "containment" });
          }
          return ok;
        })(),
      );
    },

    dismissAlert(id: string): boolean {
      if (stopped) return false;
      const ok = store.dismissAlert(id, clock.now());
      if (ok) {
        emit({ kind: "alert" });
      }
      return ok;
    },

    sendTestAlert(channel?: AlertChannel): string {
      if (stopped) {
        throw new Error("SecurityRuntime has been stopped");
      }
      const id = dispatcher.sendTestAlert(channel);
      emit({ kind: "alert" });
      void trackTask(dispatcher.drain().catch(() => {}));
      return id;
    },
  };
}

export interface LiveSecurityRuntimeOptions {
  settings?: SecuritySettings;
  secrets?: SecuritySecrets;
  clock?: Clock;
  scheduler?: Scheduler;
  hostLabel?: string;
  helperPath?: string;
}

function isHelperBinaryExecutable(path: string): boolean {
  try {
    accessSync(path, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export function createLiveSecurityRuntime(
  options: LiveSecurityRuntimeOptions = {},
): SecurityRuntime {
  const loaded =
    options.settings && options.secrets
      ? { settings: options.settings, secrets: options.secrets }
      : loadSecurityConfig();
  const clock: Clock = options.clock ?? { now: () => Date.now() };
  const store = new SecurityStore(loaded.settings.process.securityDbPath);
  const storedOverrides = store.readOverrides();
  const { nextSettings: effectiveSettings } = validateAndMergeOverrides(
    loaded.settings,
    {},
    storedOverrides,
  );

  const runner = createCommandRunner();
  const collector = new PostureCollector({
    runner,
    files: createPostureFiles(),
    clock,
  });
  const monitor = new EventMonitor({
    store,
    runner,
    clock,
    workloads: effectiveSettings.workloads,
  });

  const aiClient = createAiProviderClient(effectiveSettings, loaded.secrets);
  const analyst = new AiAnalyst({
    client: aiClient,
    clock,
  });

  const resolveProcess = createProcProcessResolver();
  const adapter = createCompositeLockdownAdapter({
    getWorkloads: () => effectiveSettings.workloads,
    clock,
    resolveProcess,
  });
  const lockdown = new LockdownEngine({
    store,
    clock,
    guard: new DeadMansSwitch(),
    adapter,
    resolveProcess,
  });

  let emitInApp: (() => void) | null = null;
  const dispatcher = new NotificationDispatcher({
    store,
    clock,
    config: effectiveSettings.notifications,
    secrets: loaded.secrets,
    runner,
    onInApp: () => {
      emitInApp?.();
    },
  });

  const helperPath = options.helperPath ?? DEFAULT_HELPER_PATH;
  const runtime = createSecurityRuntime({
    store,
    collector,
    monitor,
    analyst,
    lockdown,
    dispatcher,
    clock,
    scheduler: options.scheduler ?? createSystemScheduler(),
    settings: effectiveSettings,
    hostLabel: options.hostLabel,
    helperReady: () =>
      effectiveSettings.lockdown.helperEnabled && isHelperBinaryExecutable(helperPath),
    runner,
  });

  emitInApp = () => {
    // In-app alerts are persisted in SQLite before delivery; runtime already emits on publish.
  };

  return runtime;
}
