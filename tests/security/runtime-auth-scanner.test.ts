import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDemoSecurityRuntime,
  getDemoServices,
  getDemoSystemStats,
} from "../../src/security/demo";
import { createSecurityAuth } from "../../src/security/auth";
import { createLiveSecurityRuntime, createSecurityRuntime } from "../../src/security/runtime";
import { scan } from "../../src/services/scanner";
import { loadSecurityConfig } from "../../src/security/config";
import { SecurityStore } from "../../src/security/store";
import type { InvestigationResult, ProposalDraft } from "../../src/security/ai-analyst";
import { PostureCollector, type PostureFiles, type PostureResult } from "../../src/security/collector";
import { EventMonitor, type MonitorResult } from "../../src/security/events";
import type { ConsiderResult } from "../../src/security/lockdown";
import type {
  AlertChannel,
  CommandRequest,
  CommandResult,
  CommandRunner,
  Corroboration,
  RuntimeOverrides,
  SecurityAlert,
  SecurityFinding,
  SecurityScan,
  SecuritySettings,
} from "../../src/security/types";

// ---------------------------------------------------------------------------
// Fixtures and helpers
// ---------------------------------------------------------------------------

const MINUTE_MS = 60_000;
const DAY_MS = 86_400_000;
const FIXTURE_TOKEN = "fixture-secret-token";

const POSTURE_EVIDENCE_ID = "evidence-listener-1";

function postureResult(scanId: string, capturedAt: number): PostureResult {
  return {
    snapshot: {
      id: `snapshot-${scanId}`,
      capturedAt,
      checks: [
        {
          id: "network_exposure",
          category: "network",
          title: "Network exposure",
          status: "warn",
          summary: "Fixture listener bound to loopback only",
          evidenceIds: [POSTURE_EVIDENCE_ID],
          sourceCoverage: { sockets: "complete" },
        },
      ],
      evidence: [
        {
          id: POSTURE_EVIDENCE_ID,
          kind: "listener",
          facts: { address: "127.0.0.1", port: 6969, protocol: "tcp" },
        },
      ],
    },
    exposure: [
      {
        id: `exposure-${scanId}`,
        listener: {
          id: "listener-1",
          protocol: "tcp",
          address: "127.0.0.1",
          port: 6969,
          family: 4,
        },
        reachability: "local_only",
        firewallV4: "deny",
        firewallV6: "na",
        publication: "none",
        expected: true,
        evidenceIds: [POSTURE_EVIDENCE_ID],
      },
    ],
    findings: [
      {
        id: `finding-det-${scanId}`,
        source: "deterministic",
        severity: "info",
        summary: "Fixture deterministic finding",
        evidenceIds: [POSTURE_EVIDENCE_ID],
      },
    ],
  };
}

function emptyMonitorResult(): MonitorResult {
  return { alerts: [], corroboration: [], coverage: "complete" };
}

function unconfiguredInvestigation(): InvestigationResult {
  return { status: "unconfigured", findings: [], proposals: [], trail: { steps: [] } };
}

function settingsFixture(patch: (settings: SecuritySettings) => void = () => {}): SecuritySettings {
  const { settings } = loadSecurityConfig({ env: {}, fileConfig: {} });
  settings.scanIntervalMinutes = 60;
  settings.ai.triageCooldownMinutes = 10;
  patch(settings);
  return settings;
}

function fakeClock(start = 1_700_000_000_000) {
  let now = start;
  return {
    now: () => now,
    advance(ms: number) {
      now += ms;
    },
  };
}

interface Tick {
  ms: number;
  run: () => unknown;
  cleared: boolean;
}

// Contract: scheduler.every(intervalMs, run) registers a recurring tick and
// returns an unsubscribe that marks the tick as cleared.
function fakeScheduler() {
  const ticks: Tick[] = [];
  return {
    ticks,
    every(ms: number, run: () => unknown) {
      const tick: Tick = { ms, run, cleared: false };
      ticks.push(tick);
      return () => {
        tick.cleared = true;
      };
    },
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

async function flushMicrotasks(rounds = 200): Promise<void> {
  for (let index = 0; index < rounds; index += 1) {
    await Promise.resolve();
  }
}

async function flushUntil(predicate: () => boolean, label: string): Promise<void> {
  for (let index = 0; index < 500; index += 1) {
    if (predicate()) return;
    await Promise.resolve();
    await new Promise<void>((resolve) => queueMicrotask(resolve));
  }
  throw new Error(`Timed out waiting for ${label}`);
}

interface SavedScan {
  id: string;
  trigger: SecurityScan["trigger"];
  aiStatus: SecurityScan["aiStatus"];
  verdict: SecurityScan["verdict"];
  findings: SecurityFinding[];
}

class SpyStore extends SecurityStore {
  readonly savedScans: SavedScan[] = [];
  readonly overrideWrites: RuntimeOverrides[] = [];
  readonly calls = { prune: 0, close: 0 };

  override saveScan(scan: SecurityScan): void {
    this.savedScans.push({
      id: scan.id,
      trigger: scan.trigger,
      aiStatus: scan.aiStatus,
      verdict: scan.verdict,
      findings: scan.findings.map((finding) => ({
        ...finding,
        evidenceIds: [...finding.evidenceIds],
      })),
    });
    super.saveScan(scan);
  }

  override writeOverrides(overrides: RuntimeOverrides): void {
    this.overrideWrites.push(overrides);
    super.writeOverrides(overrides);
  }

  override prune(now: number): void {
    this.calls.prune += 1;
    super.prune(now);
  }

  override close(): void {
    this.calls.close += 1;
    super.close();
  }
}

interface CollectorCall {
  scanId: string;
  settings: SecuritySettings;
  signal?: AbortSignal;
}

type CollectImpl = (
  scanId: string,
  settings: SecuritySettings,
  signal?: AbortSignal,
) => Promise<PostureResult>;

type InvestigateImpl = (
  scanId: string,
  broker: unknown,
  signal?: AbortSignal,
) => Promise<InvestigationResult>;

type JournalImpl = (signal?: AbortSignal) => Promise<MonitorResult>;
type ApproveImpl = (id: string, revision: number, settings: SecuritySettings) => Promise<boolean>;
type UnlockImpl = (actionId: string) => Promise<boolean>;
type ReconcileImpl = () => Promise<void>;

function createHarness(options: { settings?: SecuritySettings } = {}) {
  const clock = fakeClock();
  const scheduler = fakeScheduler();
  const store = new SpyStore(":memory:");
  const settings = options.settings ?? settingsFixture();

  const collectorCalls: CollectorCall[] = [];
  let collectImpl: CollectImpl = async (scanId) => postureResult(scanId, clock.now());

  const monitorCalls = { journal: 0, sockets: 0 };
  let journalImpl: JournalImpl = async () => emptyMonitorResult();

  const analystCalls: { scanId: string; broker: unknown; signal?: AbortSignal }[] = [];
  let investigateImpl: InvestigateImpl = async () => unconfiguredInvestigation();

  const lockdownCalls = {
    consider: 0,
    approve: [] as [string, number][],
    reject: [] as [string, number][],
    unlock: [] as string[],
    reconcile: 0,
  };
  let approveImpl: ApproveImpl = async () => true;
  let unlockImpl: UnlockImpl = async () => true;
  let reconcileImpl: ReconcileImpl = async () => {};

  const dispatcherCalls = {
    publish: 0,
    drain: 0,
    testAlerts: [] as (AlertChannel | undefined)[],
  };

  const collector = {
    async collect(scanId: string, scanSettings: SecuritySettings, signal?: AbortSignal) {
      collectorCalls.push({ scanId, settings: scanSettings, signal });
      return collectImpl(scanId, scanSettings, signal);
    },
  };

  const monitor = {
    async pollJournal(signal?: AbortSignal) {
      monitorCalls.journal += 1;
      return journalImpl(signal);
    },
    async pollSockets(_signal?: AbortSignal) {
      monitorCalls.sockets += 1;
      return emptyMonitorResult();
    },
  };

  const analyst = {
    async investigate(scanId: string, broker: unknown, signal?: AbortSignal) {
      analystCalls.push({ scanId, broker, signal });
      return investigateImpl(scanId, broker, signal);
    },
  };

  const lockdown = {
    async consider(
      _scan: SecurityScan,
      _drafts: readonly ProposalDraft[],
      _corroboration: readonly Corroboration[],
      _settings: SecuritySettings,
    ): Promise<ConsiderResult> {
      lockdownCalls.consider += 1;
      return { proposals: [], actions: [], alerts: [] };
    },
    async approve(id: string, revision: number, scanSettings: SecuritySettings) {
      lockdownCalls.approve.push([id, revision]);
      return approveImpl(id, revision, scanSettings);
    },
    reject(id: string, revision: number) {
      lockdownCalls.reject.push([id, revision]);
      return true;
    },
    async unlock(actionId: string) {
      lockdownCalls.unlock.push(actionId);
      return unlockImpl(actionId);
    },
    async reconcile() {
      lockdownCalls.reconcile += 1;
      return reconcileImpl();
    },
  };

  const dispatcher = {
    publish(_alert: SecurityAlert) {
      dispatcherCalls.publish += 1;
      return true;
    },
    sendTestAlert(channel?: AlertChannel) {
      dispatcherCalls.testAlerts.push(channel);
      return "test-alert-fixture";
    },
    async drain() {
      dispatcherCalls.drain += 1;
    },
    health() {
      return {};
    },
  };

  const runtime = createSecurityRuntime({
    store,
    collector,
    monitor,
    analyst,
    lockdown,
    dispatcher,
    clock,
    scheduler,
    settings,
  });

  return {
    runtime,
    store,
    clock,
    scheduler,
    settings,
    collectorCalls,
    monitorCalls,
    analystCalls,
    lockdownCalls,
    dispatcherCalls,
    setCollect(next: CollectImpl) {
      collectImpl = next;
    },
    setJournal(next: JournalImpl) {
      journalImpl = next;
    },
    setInvestigate(next: InvestigateImpl) {
      investigateImpl = next;
    },
    setApprove(next: ApproveImpl) {
      approveImpl = next;
    },
    setUnlock(next: UnlockImpl) {
      unlockImpl = next;
    },
    setReconcile(next: ReconcileImpl) {
      reconcileImpl = next;
    },
  };
}

// ---------------------------------------------------------------------------
// Verbatim Step 1 tests from the plan
// ---------------------------------------------------------------------------

test("demo manual scans emit one update and retain fictional data", async () => {
  const runtime = createDemoSecurityRuntime();
  const updates: unknown[] = [];
  const unsubscribe = runtime.subscribe((event: unknown) => updates.push(event));
  try {
    await runtime.requestScan("manual");
    expect(runtime.view().hostLabel).toBe("lab-node-01");
    expect(runtime.view().latestScan?.trigger).toBe("manual");
    expect(updates).toContainEqual({ kind: "scan" });
  } finally { unsubscribe(); await runtime.stop(); }
});

test("remote writes are denied without authentication, including spoofed proxy headers", () => {
  const auth = createSecurityAuth({ clock: { now: () => 100 } });
  const request = new Request("http://basho.example.test/security/mode", {
    method: "POST", headers: { Origin: "http://basho.example.test", "X-Forwarded-For": "127.0.0.1" },
  });
  expect(auth.authorizeMutation(request, "198.51.100.42", "fixture")).toBe(false);
});

test("expected web port is probed and port 22 never reaches TCP or HTTP clients", async () => {
  const probed: number[] = [];
  const titles: number[] = [];
  await scan({
    ports: [22, 80],
    probe: async (_host, port) => { probed.push(port); return true; },
    title: async (_host, port) => { titles.push(port); return null; },
  });
  expect(probed).toEqual([80]);
  expect(titles).toEqual([80]);
});

// ---------------------------------------------------------------------------
// Demo runtime
// ---------------------------------------------------------------------------

test("demo runtime seeds fictional host fixtures without real adapters", async () => {
  const runtime = createDemoSecurityRuntime();
  try {
    const view = runtime.view();
    expect(view.hostLabel).toBe("lab-node-01");
    expect(view.latestScan).not.toBeNull();
    expect(view.latestScan?.trail.steps.length).toBeGreaterThan(0);
    expect(view.latestScan?.exposure.length).toBeGreaterThan(0);

    const serialized = JSON.stringify(view);
    expect(serialized).toContain("192.0.2.12");
    expect(serialized).toContain("198.51.100.42");
    expect(serialized).toContain("203.0.113.19");
    expect(serialized).toContain("2001:db8::10");
    expect(serialized).not.toContain("100.64.");

    expect(view.proposals.some((proposal: { status: string }) => proposal.status === "pending")).toBe(true);
    expect(view.actions.some((action: { state: string }) => action.state === "active")).toBe(true);

    const severities = view.alerts.map((alert: { severity: string }) => alert.severity);
    expect(severities).toContain("warning");
    expect(severities).toContain("breach");

    expect(view.hourly.length).toBe(24);
    for (const bucket of view.hourly) {
      expect(typeof bucket.hour).toBe("number");
      expect(typeof bucket.signal).toBe("number");
      expect(typeof bucket.noise).toBe("number");
    }
    expect(view.hourly.some((bucket: { signal: number }) => bucket.signal > 0)).toBe(true);

    expect(view.scanRunning).toBe(false);
    expect(["ready", "unconfigured", "offline"]).toContain(view.aiStatus);
    expect(["monitor", "approve", "auto-lockdown"]).toContain(view.settings.mode);
  } finally {
    await runtime.stop();
  }
});

test("demo approve claims a pending proposal and rejects stale revisions", async () => {
  const runtime = createDemoSecurityRuntime();
  const updates: unknown[] = [];
  const unsubscribe = runtime.subscribe((event: unknown) => updates.push(event));
  try {
    const proposal = runtime.view().proposals.find(
      (entry: { status: string }) => entry.status === "pending",
    );
    expect(proposal).toBeDefined();
    if (!proposal) throw new Error("expected a pending proposal");

    await expect(runtime.approve(proposal.id, proposal.revision + 7)).resolves.toBe(false);
    await expect(runtime.approve(proposal.id, proposal.revision)).resolves.toBe(true);

    const view = runtime.view();
    expect(
      view.proposals.find((entry: { id: string }) => entry.id === proposal.id)?.status,
    ).not.toBe("pending");
    expect(
      view.actions.some(
        (action: { proposalId: string; state: string }) =>
          action.proposalId === proposal.id && action.state === "active",
      ),
    ).toBe(true);
    expect(updates).toContainEqual({ kind: "containment" });
  } finally {
    unsubscribe();
    await runtime.stop();
  }
});

test("demo reject rejects a pending proposal and publishes containment", async () => {
  const runtime = createDemoSecurityRuntime();
  const updates: unknown[] = [];
  const unsubscribe = runtime.subscribe((event: unknown) => updates.push(event));
  try {
    const proposal = runtime.view().proposals.find(
      (entry: { status: string }) => entry.status === "pending",
    );
    expect(proposal).toBeDefined();
    if (!proposal) throw new Error("expected a pending proposal");

    expect(runtime.reject(proposal.id, proposal.revision)).toBe(true);
    expect(runtime.reject(proposal.id, proposal.revision)).toBe(false);
    expect(
      runtime.view().proposals.find((entry: { id: string }) => entry.id === proposal.id)?.status,
    ).toBe("rejected");
    expect(updates).toContainEqual({ kind: "containment" });
  } finally {
    unsubscribe();
    await runtime.stop();
  }
});

test("demo unlock rolls back an active lease and publishes containment", async () => {
  const runtime = createDemoSecurityRuntime();
  const updates: unknown[] = [];
  const unsubscribe = runtime.subscribe((event: unknown) => updates.push(event));
  try {
    const action = runtime.view().actions.find(
      (entry: { state: string }) => entry.state === "active",
    );
    expect(action).toBeDefined();
    if (!action) throw new Error("expected an active action");

    await expect(runtime.unlock(action.id)).resolves.toBe(true);
    expect(
      runtime.view().actions.find((entry: { id: string }) => entry.id === action.id)?.state,
    ).toBe("rolled_back");
    expect(updates).toContainEqual({ kind: "containment" });
  } finally {
    unsubscribe();
    await runtime.stop();
  }
});

test("demo dismissAlert removes the alert and publishes an alert update", async () => {
  const runtime = createDemoSecurityRuntime();
  const updates: unknown[] = [];
  const unsubscribe = runtime.subscribe((event: unknown) => updates.push(event));
  try {
    const alert = runtime.view().alerts[0];
    expect(alert).toBeDefined();
    if (!alert) throw new Error("expected an alert");

    expect(runtime.dismissAlert(alert.id)).toBe(true);
    expect(runtime.view().alerts.some((entry: { id: string }) => entry.id === alert.id)).toBe(false);
    expect(updates).toContainEqual({ kind: "alert" });
  } finally {
    unsubscribe();
    await runtime.stop();
  }
});

test("demo updateSettings changes the view mode and publishes settings", async () => {
  const runtime = createDemoSecurityRuntime();
  const updates: unknown[] = [];
  const unsubscribe = runtime.subscribe((event: unknown) => updates.push(event));
  try {
    runtime.updateSettings({ mode: "monitor" });
    expect(runtime.view().settings.mode).toBe("monitor");
    expect(updates).toContainEqual({ kind: "settings" });
  } finally {
    unsubscribe();
    await runtime.stop();
  }
});

test("demo sendTestAlert returns an alert id and publishes an alert update", async () => {
  const runtime = createDemoSecurityRuntime();
  const updates: unknown[] = [];
  const unsubscribe = runtime.subscribe((event: unknown) => updates.push(event));
  try {
    const id = runtime.sendTestAlert("in-app");
    expect(typeof id).toBe("string");
    expect(id.length).toBeGreaterThan(0);
    expect(updates).toContainEqual({ kind: "alert" });
  } finally {
    unsubscribe();
    await runtime.stop();
  }
});

// ---------------------------------------------------------------------------
// Composed runtime
// ---------------------------------------------------------------------------

test("composed runtime exposes the plan contract and coalesces manual scans", async () => {
  const harness = createHarness();
  try {
    for (const method of [
      "start",
      "stop",
      "view",
      "subscribe",
      "requestScan",
      "updateSettings",
      "approve",
      "reject",
      "unlock",
      "dismissAlert",
      "sendTestAlert",
    ] as const) {
      expect(typeof harness.runtime[method]).toBe("function");
    }

    const updates: unknown[] = [];
    const unsubscribe = harness.runtime.subscribe((event: unknown) => updates.push(event));

    const first = harness.runtime.requestScan("manual");
    const second = harness.runtime.requestScan("manual");
    expect(first).toBe(second);

    const [scanA, scanB] = await Promise.all([first, second]);
    expect(scanA.id).toBe(scanB.id);
    expect(scanA.trigger).toBe("manual");
    expect(harness.collectorCalls.length).toBe(1);
    expect(harness.runtime.view().latestScan?.trigger).toBe("manual");
    expect(typeof harness.runtime.view().hostLabel).toBe("string");
    expect(harness.runtime.view().hostLabel.length).toBeGreaterThan(0);
    expect(updates).toContainEqual({ kind: "scan" });

    unsubscribe();
  } finally {
    await harness.runtime.stop();
    harness.store.close();
  }
});

test("an event request during an active scan runs exactly one follow-up scan when new evidence arrives", async () => {
  const harness = createHarness();
  try {
    harness.runtime.start();
    await flushMicrotasks();

    const gate = deferred<PostureResult>();
    let collected = 0;
    harness.setCollect(async (scanId) => {
      collected += 1;
      if (collected === 1) return gate.promise;
      return postureResult(scanId, harness.clock.now());
    });

    const activePromise = harness.runtime.requestScan("manual");
    await flushUntil(() => harness.collectorCalls.length === 1, "active scan start");

    harness.clock.advance(1_000);
    const journalTick = harness.scheduler.ticks.find((tick) => tick.ms === 5_000);
    expect(journalTick).toBeDefined();
    harness.setJournal(async () => ({
      alerts: [
        {
          id: "alert-during-scan",
          fingerprint: "ssh:burst:198.51.100.42",
          severity: "critical",
          summary: "New SSH burst arrived during active scan",
          createdAt: harness.clock.now(),
        },
      ],
      corroboration: [],
      coverage: "complete",
    }));
    journalTick!.run();
    await flushMicrotasks();
    const eventPromise = harness.runtime.requestScan("event");
    await flushMicrotasks();
    expect(harness.collectorCalls.length).toBe(1);

    gate.resolve(postureResult("scan-active", harness.clock.now()));
    const active = await activePromise;
    await eventPromise;
    await flushUntil(() => harness.collectorCalls.length === 2, "follow-up scan");

    expect(active.trigger).toBe("manual");
    expect(harness.collectorCalls.length).toBe(2);
    expect(harness.store.savedScans.some((scan) => scan.trigger === "event")).toBe(true);
    expect(harness.runtime.view().latestScan?.trigger).toBe("event");
  } finally {
    await harness.runtime.stop();
    harness.store.close();
  }
});

test("event requests without new evidence coalesce without queuing a redundant follow-up scan", async () => {
  const harness = createHarness();
  try {
    const gate = deferred<PostureResult>();
    harness.setCollect(async () => gate.promise);

    const activePromise = harness.runtime.requestScan("manual");
    await flushUntil(() => harness.collectorCalls.length === 1, "active scan start");

    harness.clock.advance(5_000);
    const eventPromise = harness.runtime.requestScan("event");
    expect(eventPromise).toBe(activePromise);

    gate.resolve(postureResult("scan-only", harness.clock.now()));
    const [active, coalesced] = await Promise.all([activePromise, eventPromise]);
    await flushMicrotasks();

    expect(coalesced.id).toBe(active.id);
    expect(harness.collectorCalls.length).toBe(1);
    expect(harness.store.savedScans.some((scan) => scan.trigger === "event")).toBe(false);
  } finally {
    await harness.runtime.stop();
    harness.store.close();
  }
});

test("event-triggered AI investigations obey the ten-minute cooldown while manual and scheduled scans bypass it", async () => {
  const harness = createHarness();
  try {
    await harness.runtime.requestScan("event");
    expect(harness.analystCalls.length).toBe(1);

    harness.clock.advance(5 * MINUTE_MS);
    await harness.runtime.requestScan("event");
    expect(harness.analystCalls.length).toBe(1);
    expect(harness.runtime.view().latestScan?.exposure.length).toBeGreaterThan(0);

    harness.clock.advance(6 * MINUTE_MS);
    await harness.runtime.requestScan("event");
    expect(harness.analystCalls.length).toBe(2);

    await harness.runtime.requestScan("manual");
    expect(harness.analystCalls.length).toBe(3);

    await harness.runtime.requestScan("scheduled");
    expect(harness.analystCalls.length).toBe(4);

    expect(harness.collectorCalls.length).toBe(5);
  } finally {
    await harness.runtime.stop();
    harness.store.close();
  }
});

test("deterministic scan data is persisted before the AI promise resolves and updated in place", async () => {
  const harness = createHarness();
  try {
    const gate = deferred<InvestigationResult>();
    harness.setInvestigate(async () => gate.promise);

    const scanPromise = harness.runtime.requestScan("manual");
    await flushUntil(() => harness.store.savedScans.length === 1, "deterministic scan persistence");

    const deterministic = harness.store.savedScans[0]!;
    const scanId = deterministic.id;
    expect(deterministic.verdict).toBeUndefined();
    expect(deterministic.findings.length).toBeGreaterThan(0);
    expect(deterministic.findings.every((finding) => finding.source === "deterministic")).toBe(true);
    expect(harness.store.latestScan()?.id).toBe(scanId);

    gate.resolve({
      status: "ready",
      verdict: { kind: "breach", confidence: 0.93, summary: "Fixture breach verdict" },
      findings: [
        {
          id: "finding-ai-1",
          source: "ai",
          severity: "breach",
          summary: "Fixture AI finding",
          evidenceIds: [POSTURE_EVIDENCE_ID],
        },
      ],
      proposals: [],
      trail: {
        steps: [
          {
            tool: "read_posture_detail",
            reason: "Fixture investigation reason",
            outcome: "ok",
            evidenceIds: [POSTURE_EVIDENCE_ID],
          },
        ],
      },
    });

    const finished = await scanPromise;
    expect(finished.id).toBe(scanId);
    expect(finished.verdict?.kind).toBe("breach");

    expect(harness.store.savedScans.length).toBe(2);
    expect(harness.store.savedScans[1]!.id).toBe(scanId);

    const persisted = harness.store.latestScan();
    expect(persisted?.id).toBe(scanId);
    expect(persisted?.aiStatus).toBe("ready");
    expect(persisted?.verdict?.kind).toBe("breach");
    expect(persisted?.findings.some((finding) => finding.source === "ai")).toBe(true);
    expect(persisted?.trail.steps.length).toBe(1);
  } finally {
    await harness.runtime.stop();
    harness.store.close();
  }
});

test("updateSettings persists validated overrides before emitting and applies them to later scans", async () => {
  const harness = createHarness();
  try {
    harness.runtime.start();

    let writesWhenEmitted = -1;
    const emitted: unknown[] = [];
    const unsubscribe = harness.runtime.subscribe((event: unknown) => {
      emitted.push(event);
      if ((event as { kind?: string }).kind === "settings") {
        writesWhenEmitted = harness.store.overrideWrites.length;
      }
    });

    harness.runtime.updateSettings({ mode: "monitor" });
    expect(harness.store.overrideWrites.length).toBe(1);
    expect(harness.store.overrideWrites[0]).toMatchObject({ mode: "monitor" });
    expect(harness.runtime.view().settings.mode).toBe("monitor");
    expect(writesWhenEmitted).toBe(1);
    expect(emitted).toContainEqual({ kind: "settings" });

    await harness.runtime.requestScan("manual");
    expect(harness.collectorCalls.at(-1)!.settings.mode).toBe("monitor");

    harness.runtime.updateSettings({ scanIntervalMinutes: 5 });
    expect(harness.store.overrideWrites.at(-1)).toMatchObject({ scanIntervalMinutes: 5 });
    expect(harness.scheduler.ticks.some((tick) => tick.ms === 5 * MINUTE_MS)).toBe(true);

    expect(() => harness.runtime.updateSettings({ scanIntervalMinutes: 0 })).toThrow();
    expect(harness.store.overrideWrites.length).toBe(2);

    unsubscribe();
  } finally {
    await harness.runtime.stop();
    harness.store.close();
  }
});

test("start runs startup recovery and schedules independent non-overlapping intervals", async () => {
  const harness = createHarness();
  try {
    harness.runtime.start();
    await flushMicrotasks();

    expect(harness.scheduler.ticks.some((tick) => tick.ms === 30_000)).toBe(true);
    expect(harness.scheduler.ticks.some((tick) => tick.ms === 5_000)).toBe(true);
    expect(
      harness.scheduler.ticks.some(
        (tick) => tick.ms === harness.settings.scanIntervalMinutes * MINUTE_MS,
      ),
    ).toBe(true);
    expect(harness.scheduler.ticks.length).toBeGreaterThanOrEqual(5);
    expect(harness.store.calls.prune).toBeGreaterThanOrEqual(1);
    expect(harness.lockdownCalls.reconcile).toBeGreaterThanOrEqual(1);
    expect(harness.dispatcherCalls.drain).toBeGreaterThanOrEqual(1);

    const journalTick = harness.scheduler.ticks.find((tick) => tick.ms === 5_000);
    expect(journalTick).toBeDefined();

    const gate = deferred<void>();
    harness.setJournal(async () => {
      await gate.promise;
      return emptyMonitorResult();
    });

    const before = harness.monitorCalls.journal;
    journalTick!.run();
    journalTick!.run();
    await flushMicrotasks();
    expect(harness.monitorCalls.journal).toBe(before + 1);

    gate.resolve();
    await flushMicrotasks();
    journalTick!.run();
    await flushMicrotasks();
    expect(harness.monitorCalls.journal).toBe(before + 2);
  } finally {
    await harness.runtime.stop();
    harness.store.close();
  }
});

test("stop aborts in-flight scans, clears schedules, drops subscribers, and closes the store", async () => {
  const harness = createHarness();
  const updates: unknown[] = [];
  try {
    harness.runtime.start();
    await flushMicrotasks();

    const unsubscribe = harness.runtime.subscribe((event: unknown) => updates.push(event));

    const gate = deferred<PostureResult>();
    harness.setCollect(async (scanId) => {
      await gate.promise;
      return postureResult(scanId, harness.clock.now());
    });

    const callsBefore = harness.collectorCalls.length;
    const scanPromise = harness.runtime.requestScan("manual");
    await flushUntil(
      () => harness.collectorCalls.length > callsBefore,
      "in-flight scan start",
    );
    const inFlight = harness.collectorCalls.at(-1)!;
    expect(inFlight.signal).toBeDefined();
    expect(inFlight.signal?.aborted).toBe(false);

    let stopSettled = false;
    const stopPromise = harness.runtime.stop().then(() => {
      stopSettled = true;
    });
    await flushMicrotasks();
    expect(stopSettled).toBe(false);
    expect(inFlight.signal?.aborted).toBe(true);

    gate.resolve(postureResult(inFlight.scanId, harness.clock.now()));
    await scanPromise.catch(() => undefined);
    await stopPromise;
    expect(stopSettled).toBe(true);

    for (const tick of harness.scheduler.ticks) {
      expect(tick.cleared).toBe(true);
    }
    expect(harness.store.calls.close).toBe(1);

    for (const tick of harness.scheduler.ticks) {
      tick.run();
    }
    await flushMicrotasks();
    expect(updates).not.toContainEqual({ kind: "scan" });

    unsubscribe();
  } finally {
    if (harness.store.calls.close === 0) {
      harness.store.close();
    }
  }
});

test("startup reconcile shares the non-overlapping guard with periodic reconcile ticks", async () => {
  const harness = createHarness();
  try {
    const startupGate = deferred<void>();
    let calls = 0;
    harness.setReconcile(async () => {
      calls += 1;
      if (calls === 1) {
        await startupGate.promise;
      }
    });

    harness.runtime.start();
    await flushUntil(() => harness.lockdownCalls.reconcile === 1, "startup reconcile start");

    const reconcileTick = harness.scheduler.ticks.find((tick) => tick.ms === 15_000);
    expect(reconcileTick).toBeDefined();

    reconcileTick!.run();
    reconcileTick!.run();
    await flushMicrotasks();
    expect(harness.lockdownCalls.reconcile).toBe(1);

    startupGate.resolve();
    await flushMicrotasks();

    reconcileTick!.run();
    await flushUntil(() => harness.lockdownCalls.reconcile === 2, "post-startup reconcile tick");
    expect(harness.lockdownCalls.reconcile).toBe(2);
  } finally {
    await harness.runtime.stop();
    harness.store.close();
  }
});

test("stop awaits in-flight approve and unlock writes before closing the store and refuses new mutations", async () => {
  const harness = createHarness();
  try {
    const approveGate = deferred<boolean>();
    const unlockGate = deferred<boolean>();
    harness.setApprove(async () => approveGate.promise);
    harness.setUnlock(async () => unlockGate.promise);

    const approvePromise = harness.runtime.approve("proposal-1", 1);
    const unlockPromise = harness.runtime.unlock("action-1");
    await flushUntil(
      () => harness.lockdownCalls.approve.length === 1 && harness.lockdownCalls.unlock.length === 1,
      "in-flight approve and unlock start",
    );

    let stopSettled = false;
    const stopPromise = harness.runtime.stop().then(() => {
      stopSettled = true;
    });
    await flushMicrotasks();

    expect(stopSettled).toBe(false);
    expect(harness.store.calls.close).toBe(0);

    // New mutations must be refused once stop() has begun.
    await expect(harness.runtime.approve("proposal-2", 1)).resolves.toBe(false);
    await expect(harness.runtime.unlock("action-2")).resolves.toBe(false);
    expect(harness.runtime.reject("proposal-2", 1)).toBe(false);
    expect(harness.runtime.dismissAlert("alert-1")).toBe(false);
    expect(() => harness.runtime.updateSettings({ mode: "monitor" })).toThrow();
    expect(() => harness.runtime.sendTestAlert("in-app")).toThrow();
    await expect(harness.runtime.requestScan("manual")).rejects.toThrow();
    expect(harness.lockdownCalls.approve.length).toBe(1);
    expect(harness.lockdownCalls.unlock.length).toBe(1);

    approveGate.resolve(true);
    await expect(approvePromise).resolves.toBe(true);
    await flushMicrotasks();
    expect(stopSettled).toBe(false);
    expect(harness.store.calls.close).toBe(0);

    unlockGate.resolve(true);
    await expect(unlockPromise).resolves.toBe(true);
    await stopPromise;
    expect(stopSettled).toBe(true);
    expect(harness.store.calls.close).toBe(1);
  } finally {
    if (harness.store.calls.close === 0) {
      harness.store.close();
    }
  }
});

test("stop aborts an in-flight analyst.investigate call via its AbortSignal", async () => {
  const harness = createHarness();
  try {
    const gate = deferred<InvestigationResult>();
    harness.setInvestigate(async (_scanId, _broker, signal) => {
      if (signal?.aborted) {
        return { status: "offline", findings: [], proposals: [], trail: { steps: [] }, reason: "timeout" };
      }
      return gate.promise;
    });

    const scanPromise = harness.runtime.requestScan("manual");
    await flushUntil(() => harness.analystCalls.length === 1, "analyst investigate start");

    const activeCall = harness.analystCalls[0]!;
    expect(activeCall.signal).toBeDefined();
    expect(activeCall.signal?.aborted).toBe(false);

    let stopSettled = false;
    const stopPromise = harness.runtime.stop().then(() => {
      stopSettled = true;
    });
    await flushMicrotasks();

    expect(activeCall.signal?.aborted).toBe(true);
    expect(stopSettled).toBe(false);
    expect(harness.store.calls.close).toBe(0);

    gate.resolve({ status: "offline", findings: [], proposals: [], trail: { steps: [] }, reason: "timeout" });
    await scanPromise.catch(() => undefined);
    await stopPromise;

    expect(stopSettled).toBe(true);
    expect(harness.store.calls.close).toBe(1);
  } finally {
    if (harness.store.calls.close === 0) {
      harness.store.close();
    }
  }
});

test("composed runtime delegates containment and test alert actions", async () => {
  const harness = createHarness();
  try {
    await expect(harness.runtime.approve("proposal-1", 3)).resolves.toBe(true);
    expect(harness.lockdownCalls.approve).toContainEqual(["proposal-1", 3]);

    expect(harness.runtime.reject("proposal-1", 4)).toBe(true);
    expect(harness.lockdownCalls.reject).toContainEqual(["proposal-1", 4]);

    await expect(harness.runtime.unlock("action-1")).resolves.toBe(true);
    expect(harness.lockdownCalls.unlock).toContainEqual("action-1");

    const alertId = harness.runtime.sendTestAlert("in-app");
    expect(typeof alertId).toBe("string");
    expect(alertId.length).toBeGreaterThan(0);
    expect(harness.dispatcherCalls.testAlerts).toContainEqual("in-app");
  } finally {
    await harness.runtime.stop();
    harness.store.close();
  }
});

// ---------------------------------------------------------------------------
// Auth and CSRF
// ---------------------------------------------------------------------------

interface CsrfIssue {
  token: string;
  cookie?: string;
}

interface LoginResult {
  ok: boolean;
  cookie?: string;
}

interface SecurityAuthLike {
  authorizeRead(request: Request, peer: string): boolean;
  authorizeMutation(request: Request, peer: string, csrf?: string): boolean;
  login(request: Request, suppliedToken: string): LoginResult;
  csrfToken(request: Request, peer: string): CsrfIssue | null;
}

const LOCAL_ORIGIN = "http://127.0.0.1:6969";

function asAuth(value: unknown): SecurityAuthLike {
  return value as SecurityAuthLike;
}

function cookieHeader(setCookie: string | undefined): string {
  if (!setCookie) throw new Error("expected a Set-Cookie value");
  return setCookie.split(";")[0]!;
}

function tamper(value: string): string {
  const last = value.at(-1);
  return `${value.slice(0, -1)}${last === "a" ? "b" : "a"}`;
}

function csrfFor(
  auth: SecurityAuthLike,
  peer: string,
  cookie?: string,
  origin = LOCAL_ORIGIN,
): CsrfIssue {
  const headers: Record<string, string> = {};
  if (cookie !== undefined) headers.Cookie = cookie;
  const issued = auth.csrfToken(new Request(`${origin}/security`, { headers }), peer);
  expect(issued).not.toBeNull();
  return issued!;
}

interface MutationOptions {
  peer: string;
  origin?: string;
  referer?: string;
  cookie?: string;
  csrf?: string;
  url?: string;
  headers?: Record<string, string>;
}

function mutate(auth: SecurityAuthLike, options: MutationOptions): boolean {
  const headers: Record<string, string> = { ...(options.headers ?? {}) };
  if (options.origin !== undefined) headers.Origin = options.origin;
  if (options.referer !== undefined) headers.Referer = options.referer;
  if (options.cookie !== undefined) headers.Cookie = options.cookie;
  if (options.csrf !== undefined) headers["X-CSRF-Token"] = options.csrf;
  const request = new Request(options.url ?? `${LOCAL_ORIGIN}/security/mode`, {
    method: "POST",
    headers,
  });
  return auth.authorizeMutation(request, options.peer, options.csrf);
}

test("tokenless mode allows loopback reads and local CSRF-bound writes only", () => {
  const auth = asAuth(createSecurityAuth({ clock: fakeClock() }));
  const readRequest = new Request(`${LOCAL_ORIGIN}/security`);
  expect(auth.authorizeRead(readRequest, "127.0.0.1")).toBe(true);
  expect(auth.authorizeRead(readRequest, "::1")).toBe(true);
  expect(auth.authorizeRead(readRequest, "::ffff:127.0.0.1")).toBe(true);

  const issued = csrfFor(auth, "127.0.0.1");
  expect(issued.token.length).toBeGreaterThan(0);
  expect(issued.cookie).toBeDefined();

  expect(
    mutate(auth, {
      peer: "127.0.0.1",
      origin: LOCAL_ORIGIN,
      cookie: cookieHeader(issued.cookie),
      csrf: issued.token,
    }),
  ).toBe(true);
});

test("tokenless mode refuses spoofed proxy headers, ambiguous peers, and remote peers", () => {
  const auth = asAuth(createSecurityAuth({ clock: fakeClock() }));
  const issued = csrfFor(auth, "127.0.0.1");
  const cookie = cookieHeader(issued.cookie);

  for (const [name, value] of [
    ["X-Forwarded-For", "127.0.0.1"],
    ["Forwarded", "for=127.0.0.1"],
    ["X-Real-IP", "127.0.0.1"],
  ] as const) {
    expect(
      mutate(auth, {
        peer: "127.0.0.1",
        origin: LOCAL_ORIGIN,
        cookie,
        csrf: issued.token,
        headers: { [name]: value },
      }),
    ).toBe(false);
  }

  expect(
    mutate(auth, { peer: undefined as unknown as string, origin: LOCAL_ORIGIN, cookie, csrf: issued.token }),
  ).toBe(false);
  expect(mutate(auth, { peer: "", origin: LOCAL_ORIGIN, cookie, csrf: issued.token })).toBe(false);
  expect(
    mutate(auth, { peer: "   ", origin: LOCAL_ORIGIN, cookie, csrf: issued.token }),
  ).toBe(false);
  expect(
    mutate(auth, {
      peer: "127.0.0.1, 203.0.113.9",
      origin: LOCAL_ORIGIN,
      cookie,
      csrf: issued.token,
    }),
  ).toBe(false);
  expect(
    mutate(auth, {
      peer: "198.51.100.42",
      origin: "http://basho.example.test",
      cookie,
      csrf: issued.token,
      url: "http://basho.example.test/security/mode",
    }),
  ).toBe(false);
});

test("tokenless mode rejects cross-origin, bad referer, missing, tampered, and expired CSRF", () => {
  const clock = fakeClock();
  const auth = asAuth(createSecurityAuth({ clock }));
  const issued = csrfFor(auth, "127.0.0.1");
  const cookie = cookieHeader(issued.cookie);

  expect(
    mutate(auth, {
      peer: "127.0.0.1",
      origin: "http://basho.example.test",
      cookie,
      csrf: issued.token,
    }),
  ).toBe(false);

  expect(
    mutate(auth, { peer: "127.0.0.1", referer: `${LOCAL_ORIGIN}/security`, cookie, csrf: issued.token }),
  ).toBe(true);

  expect(
    mutate(auth, {
      peer: "127.0.0.1",
      referer: "http://basho.example.test/security",
      cookie,
      csrf: issued.token,
    }),
  ).toBe(false);

  expect(mutate(auth, { peer: "127.0.0.1", origin: LOCAL_ORIGIN, cookie })).toBe(false);
  expect(
    mutate(auth, {
      peer: "127.0.0.1",
      origin: LOCAL_ORIGIN,
      cookie,
      csrf: tamper(issued.token),
    }),
  ).toBe(false);

  clock.advance(365 * DAY_MS);
  expect(
    mutate(auth, {
      peer: "127.0.0.1",
      origin: LOCAL_ORIGIN,
      cookie,
      csrf: issued.token,
    }),
  ).toBe(false);
});

test("token-configured mode denies loopback reads without a session", () => {
  const auth = asAuth(createSecurityAuth({ token: FIXTURE_TOKEN, clock: fakeClock() }));
  expect(auth.authorizeRead(new Request(`${LOCAL_ORIGIN}/security`), "127.0.0.1")).toBe(false);
  expect(
    mutate(auth, { peer: "127.0.0.1", origin: LOCAL_ORIGIN, csrf: "fixture" }),
  ).toBe(false);
});

test("login rejects a wrong token or mismatched origin and issues a Secure-free HTTP session cookie", () => {
  const auth = asAuth(createSecurityAuth({ token: FIXTURE_TOKEN, clock: fakeClock() }));

  const wrongToken = auth.login(
    new Request(`${LOCAL_ORIGIN}/security/login`, {
      method: "POST",
      headers: { Origin: LOCAL_ORIGIN },
    }),
    "wrong-fixture-token",
  );
  expect(wrongToken.ok).toBe(false);
  expect(wrongToken.cookie).toBeUndefined();

  const wrongOrigin = auth.login(
    new Request(`${LOCAL_ORIGIN}/security/login`, {
      method: "POST",
      headers: { Origin: "https://basho.example.test" },
    }),
    FIXTURE_TOKEN,
  );
  expect(wrongOrigin.ok).toBe(false);
  expect(wrongOrigin.cookie).toBeUndefined();

  const accepted = auth.login(
    new Request(`${LOCAL_ORIGIN}/security/login`, {
      method: "POST",
      headers: { Origin: LOCAL_ORIGIN },
    }),
    FIXTURE_TOKEN,
  );
  expect(accepted.ok).toBe(true);
  const setCookie = accepted.cookie ?? "";
  const lowered = setCookie.toLowerCase();
  expect(lowered).toContain("httponly");
  expect(lowered).toContain("samesite=lax");
  expect(lowered).toContain("path=/");
  expect(lowered).not.toContain("secure");
  expect(setCookie).not.toContain(FIXTURE_TOKEN);
});

test("login adds Secure only for HTTPS requests or matched HTTPS publicOrigin, not plain-HTTP requests", () => {
  const auth = asAuth(createSecurityAuth({ token: FIXTURE_TOKEN, clock: fakeClock() }));
  const httpsLogin = auth.login(
    new Request("https://basho.example.test/security/login", {
      method: "POST",
      headers: { Origin: "https://basho.example.test" },
    }),
    FIXTURE_TOKEN,
  );
  expect(httpsLogin.ok).toBe(true);
  expect((httpsLogin.cookie ?? "").toLowerCase()).toContain("secure");

  const withHttpsPublicOrigin = asAuth(
    createSecurityAuth({
      token: FIXTURE_TOKEN,
      clock: fakeClock(),
      publicOrigin: "https://basho.example.test",
    }),
  );

  // Plain-HTTP localhost request must NOT get ; Secure even when publicOrigin is HTTPS.
  const plainHttpLocalhost = withHttpsPublicOrigin.login(
    new Request("http://localhost/security/login", {
      method: "POST",
      headers: { Origin: "http://localhost" },
    }),
    FIXTURE_TOKEN,
  );
  expect(plainHttpLocalhost.ok).toBe(true);
  expect((plainHttpLocalhost.cookie ?? "").toLowerCase()).not.toContain("secure");

  // Plain-HTTP loopback request with loopback Origin must NOT get ; Secure either.
  const plainHttpLoopback = withHttpsPublicOrigin.login(
    new Request(`${LOCAL_ORIGIN}/security/login`, {
      method: "POST",
      headers: { Origin: LOCAL_ORIGIN },
    }),
    FIXTURE_TOKEN,
  );
  expect(plainHttpLoopback.ok).toBe(true);
  expect((plainHttpLoopback.cookie ?? "").toLowerCase()).not.toContain("secure");

  // Request carrying matched HTTPS publicOrigin Origin DOES get ; Secure.
  const proxiedByOrigin = withHttpsPublicOrigin.login(
    new Request(`${LOCAL_ORIGIN}/security/login`, {
      method: "POST",
      headers: { Origin: "https://basho.example.test" },
    }),
    FIXTURE_TOKEN,
  );
  expect(proxiedByOrigin.ok).toBe(true);
  expect((proxiedByOrigin.cookie ?? "").toLowerCase()).toContain("secure");

  // Request carrying matched HTTPS publicOrigin Referer (without Origin) DOES get ; Secure.
  const proxiedByReferer = withHttpsPublicOrigin.login(
    new Request(`${LOCAL_ORIGIN}/security/login`, {
      method: "POST",
      headers: { Referer: "https://basho.example.test/security" },
    }),
    FIXTURE_TOKEN,
  );
  expect(proxiedByReferer.ok).toBe(true);
  expect((proxiedByReferer.cookie ?? "").toLowerCase()).toContain("secure");
});

test("an authenticated session passes reads and origin-checked CSRF mutations", () => {
  const clock = fakeClock();
  const auth = asAuth(createSecurityAuth({ token: FIXTURE_TOKEN, clock }));
  const loginRequest = new Request(`${LOCAL_ORIGIN}/security/login`, {
    method: "POST",
    headers: { Origin: LOCAL_ORIGIN },
  });
  const login = auth.login(loginRequest, FIXTURE_TOKEN);
  expect(login.ok).toBe(true);
  const sessionCookie = cookieHeader(login.cookie);

  expect(
    auth.authorizeRead(
      new Request(`${LOCAL_ORIGIN}/security`, { headers: { Cookie: sessionCookie } }),
      "127.0.0.1",
    ),
  ).toBe(true);

  const issued = csrfFor(auth, "127.0.0.1", sessionCookie);
  expect(issued.token.length).toBeGreaterThan(0);

  expect(
    mutate(auth, {
      peer: "127.0.0.1",
      origin: LOCAL_ORIGIN,
      cookie: sessionCookie,
      csrf: issued.token,
    }),
  ).toBe(true);

  expect(
    mutate(auth, {
      peer: "127.0.0.1",
      origin: "https://basho.example.test",
      cookie: sessionCookie,
      csrf: issued.token,
    }),
  ).toBe(false);

  expect(
    mutate(auth, {
      peer: "127.0.0.1",
      origin: LOCAL_ORIGIN,
      referer: `${LOCAL_ORIGIN}/security`,
      cookie: sessionCookie,
      csrf: issued.token,
    }),
  ).toBe(true);

  expect(
    mutate(auth, {
      peer: "127.0.0.1",
      referer: "http://basho.example.test/security",
      cookie: sessionCookie,
      csrf: issued.token,
    }),
  ).toBe(false);
});

test("session cookies and CSRF tokens reject tampering, expiry, and cross-session reuse", () => {
  const clock = fakeClock();
  const auth = asAuth(createSecurityAuth({ token: FIXTURE_TOKEN, clock }));
  const loginRequest = () =>
    new Request(`${LOCAL_ORIGIN}/security/login`, {
      method: "POST",
      headers: { Origin: LOCAL_ORIGIN },
    });

  const first = auth.login(loginRequest(), FIXTURE_TOKEN);
  const firstCookie = cookieHeader(first.cookie);
  const firstCsrf = csrfFor(auth, "127.0.0.1", firstCookie);

  expect(
    auth.authorizeRead(
      new Request(`${LOCAL_ORIGIN}/security`, {
        headers: { Cookie: tamper(firstCookie) },
      }),
      "127.0.0.1",
    ),
  ).toBe(false);

  clock.advance(1_000);
  const second = auth.login(loginRequest(), FIXTURE_TOKEN);
  const secondCookie = cookieHeader(second.cookie);
  expect(secondCookie).not.toBe(firstCookie);

  expect(
    mutate(auth, {
      peer: "127.0.0.1",
      origin: LOCAL_ORIGIN,
      cookie: secondCookie,
      csrf: firstCsrf.token,
    }),
  ).toBe(false);

  expect(
    mutate(auth, {
      peer: "127.0.0.1",
      origin: LOCAL_ORIGIN,
      cookie: secondCookie,
      csrf: tamper(firstCsrf.token),
    }),
  ).toBe(false);

  clock.advance(365 * DAY_MS);
  expect(
    auth.authorizeRead(
      new Request(`${LOCAL_ORIGIN}/security`, { headers: { Cookie: secondCookie } }),
      "127.0.0.1",
    ),
  ).toBe(false);
});

test("explicit bearer tokens authorize reads and originless mutations but reject conflicts and wrong tokens", () => {
  const auth = asAuth(createSecurityAuth({ token: FIXTURE_TOKEN, clock: fakeClock() }));
  const peer = "203.0.113.19";

  expect(
    auth.authorizeRead(
      new Request("https://basho.example.test/api/security/status", {
        headers: { Authorization: `Bearer ${FIXTURE_TOKEN}` },
      }),
      peer,
    ),
  ).toBe(true);

  expect(
    mutate(auth, {
      peer,
      url: "https://basho.example.test/security/mode",
      headers: { Authorization: `Bearer ${FIXTURE_TOKEN}` },
    }),
  ).toBe(true);

  expect(
    mutate(auth, {
      peer,
      url: "https://basho.example.test/security/mode",
      origin: "https://evil.example.test",
      headers: { Authorization: `Bearer ${FIXTURE_TOKEN}` },
    }),
  ).toBe(false);

  expect(
    auth.authorizeRead(
      new Request("https://basho.example.test/api/security/status", {
        headers: { Authorization: "Bearer wrong-fixture-token" },
      }),
      peer,
    ),
  ).toBe(false);

  expect(
    mutate(auth, {
      peer,
      url: "https://basho.example.test/security/mode",
      headers: { Authorization: "Bearer wrong-fixture-token" },
    }),
  ).toBe(false);
});

test("query-string tokens are never accepted or emitted", () => {
  const clock = fakeClock();
  const auth = asAuth(createSecurityAuth({ token: FIXTURE_TOKEN, clock }));

  expect(
    auth.authorizeRead(
      new Request(`${LOCAL_ORIGIN}/security?token=${FIXTURE_TOKEN}`),
      "127.0.0.1",
    ),
  ).toBe(false);
  expect(
    auth.authorizeRead(
      new Request(`https://basho.example.test/api/security/status?token=${FIXTURE_TOKEN}`),
      "198.51.100.42",
    ),
  ).toBe(false);

  const login = auth.login(
    new Request(`${LOCAL_ORIGIN}/security/login`, {
      method: "POST",
      headers: { Origin: LOCAL_ORIGIN },
    }),
    FIXTURE_TOKEN,
  );
  expect(login.ok).toBe(true);
  expect(login.cookie ?? "").not.toContain(FIXTURE_TOKEN);

  const issued = csrfFor(auth, "127.0.0.1", cookieHeader(login.cookie));
  expect(issued.token).not.toContain(FIXTURE_TOKEN);
});

// ---------------------------------------------------------------------------
// Scanner options
// ---------------------------------------------------------------------------

test("injected scanner options bypass the module cache", async () => {
  const firstProbe = { calls: 0 };
  const secondProbe = { calls: 0 };

  const first = await scan({
    ports: [80],
    probe: async () => {
      firstProbe.calls += 1;
      return true;
    },
    title: async () => "first-fixture-title",
  });

  const second = await scan({
    ports: [80],
    probe: async () => {
      secondProbe.calls += 1;
      return true;
    },
    title: async () => "second-fixture-title",
  });

  expect(firstProbe.calls).toBe(1);
  expect(secondProbe.calls).toBe(1);
  expect(first.length).toBe(1);
  expect(second.length).toBe(1);
  expect(first[0]?.name).toBe("first-fixture-title");
  expect(second[0]?.name).toBe("second-fixture-title");
});

// ---------------------------------------------------------------------------
// Additional edge-case checks
// ---------------------------------------------------------------------------

test("runtime passes scanId into EvidenceBroker and rejects invalid mode or unknown criteria overrides", async () => {
  const harness = createHarness();
  try {
    const scanResult = await harness.runtime.requestScan("manual");
    expect(harness.analystCalls.length).toBe(1);
    expect((harness.analystCalls[0]?.broker as { scanId?: string }).scanId).toBe(scanResult.id);

    expect(() =>
      harness.runtime.updateSettings({ mode: "invalid-mode" as unknown as RuntimeOverrides["mode"] }),
    ).toThrow();
    expect(() =>
      harness.runtime.updateSettings({
        criteria: { unknown_criterion: false } as unknown as RuntimeOverrides["criteria"],
      }),
    ).toThrow();
    expect(harness.store.overrideWrites.length).toBe(0);
  } finally {
    await harness.runtime.stop();
    harness.store.close();
  }
});

test("demo services and system stats fixtures return fictional lab-node-01 data", () => {
  const services = getDemoServices();
  expect(services.length).toBeGreaterThan(0);
  const serializedServices = JSON.stringify(services);
  expect(serializedServices).toContain("lab-node-01");
  expect(serializedServices).toContain("192.0.2.12");
  expect(serializedServices).not.toContain("100.64.");
  expect(serializedServices).not.toContain("198.51.100.42");

  const stats = getDemoSystemStats();
  expect(stats.cpu.count).toBe(stats.cpu.cores.length);
  expect(stats.ram.total).toBeGreaterThan(0);
  expect(stats.disks.length).toBeGreaterThan(0);
  expect(stats.gpu).not.toBeNull();
});

// ---------------------------------------------------------------------------
// Stage 2 code quality hardening tests
// ---------------------------------------------------------------------------

test("real PostureCollector + EventMonitor socket classifier detects newly exposed 0.0.0.0:8188 listener and feeds unexpected_workload corroboration to lockdown.consider", async () => {
  const clock = fakeClock();
  const scheduler = fakeScheduler();
  const store = new SpyStore(":memory:");
  const settings = settingsFixture((s) => {
    s.expectedPorts = [22, 6969];
    s.workloads = [{ id: "comfy", unit: "comfy.service", name: "comfy", ports: [8188] }];
  });

  const ssHeader = "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess";
  const ssLoopback = 'tcp   LISTEN 0      128    127.0.0.1:6969   0.0.0.0:*    users:(("bun",pid=1001,fd=3))';
  const ssExposedComfy = 'tcp   LISTEN 0      128    0.0.0.0:8188     0.0.0.0:*    users:(("comfy",pid=4242,fd=7))';

  let exposeComfy = false;
  const runner: CommandRunner = {
    async run(request: CommandRequest): Promise<CommandResult> {
      if (request.kind === "ufw_status") {
        return {
          status: "ok",
          exitCode: 0,
          stdout: [
            "Status: active",
            "Default: deny (incoming), allow (outgoing), disabled (routed)",
          ].join("\n"),
        };
      }
      if (request.kind === "tailscale_serve" || request.kind === "tailscale_funnel") {
        return { status: "ok", exitCode: 0, stdout: "{}" };
      }
      if (request.kind === "sockets") {
        return {
          status: "ok",
          exitCode: 0,
          stdout: exposeComfy
            ? [ssHeader, ssLoopback, ssExposedComfy].join("\n")
            : [ssHeader, ssLoopback].join("\n"),
        };
      }
      if (request.kind === "processes") {
        return {
          status: "ok",
          exitCode: 0,
          stdout: "  4242     1  1000   120 user@1000.service comfy.service comfy\n",
        };
      }
      return { status: "unavailable" };
    },
  };

  const files: PostureFiles = {
    async read(source) {
      if (source === "ufw-v4") return "-A ufw-user-input -p tcp --dport 8188 -j ACCEPT";
      if (source === "ufw-v6") return "-A ufw6-user-input -j RETURN";
      if (source === "ufw-default") return 'IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"';
      return null;
    },
    async sshDropIns() {
      return [];
    },
  };

  const collector = new PostureCollector({ runner, files, clock });
  const monitor = new EventMonitor({
    store,
    runner,
    clock,
    workloads: settings.workloads,
  });

  const publishedAlerts: SecurityAlert[] = [];
  let drainCount = 0;
  const considerCalls: { scan: SecurityScan; drafts: readonly ProposalDraft[]; corroboration: readonly Corroboration[] }[] = [];

  const runtime = createSecurityRuntime({
    store,
    collector,
    monitor,
    analyst: {
      async investigate(scanId): Promise<InvestigationResult> {
        if (!exposeComfy) {
          return unconfiguredInvestigation();
        }
        return {
          status: "ready",
          verdict: { kind: "warn", confidence: 0.9, summary: "Unexpected comfy listener" },
          findings: [],
          proposals: [
            {
              target: {
                kind: "pause_workload",
                workloadId: "comfy",
                pid: 4242,
                startedAt: clock.now() - 120_000,
              },
              evidenceIds: [`ev:${scanId}:listener:0`],
            },
          ],
          trail: { steps: [] },
        };
      },
    },
    lockdown: {
      async consider(scan, drafts, corroboration) {
        considerCalls.push({ scan, drafts, corroboration });
        return { proposals: [], actions: [], alerts: [] };
      },
      async approve() { return true; },
      reject() { return true; },
      async unlock() { return true; },
      async reconcile() {},
    },
    dispatcher: {
      publish(alert) {
        publishedAlerts.push(alert);
        return true;
      },
      sendTestAlert() { return "test"; },
      async drain() { drainCount += 1; },
      health() { return {}; },
    },
    clock,
    scheduler,
    settings,
    runner,
    classifySockets: (listeners) => collector.classifySockets(listeners, settings.expectedPorts),
  });

  try {
    runtime.start();
    await flushMicrotasks();

    // 1. Initial scan captures UFW/Tailscale context in PostureCollector.
    await runtime.requestScan("manual");

    // 2. First 30s socket poll establishes EventMonitor baseline (loopback only).
    const socketTick = scheduler.ticks.find((tick) => tick.ms === 30_000);
    expect(socketTick).toBeDefined();
    socketTick!.run();
    await flushMicrotasks();

    const drainBefore = drainCount;
    expect(publishedAlerts.length).toBe(0);

    // 3. New 0.0.0.0:8188 listener opens for enrolled workload comfy.
    clock.advance(30_000);
    exposeComfy = true;
    socketTick!.run();

    await flushUntil(() => considerCalls.length === 1, "event scan lockdown.consider call");

    // Verify critical listener_opened event persisted, critical alert published & drained.
    const openedEvent = store
      .recentEvents(0, 50)
      .find((ev) => ev.rule === "listener_opened" && ev.target === "tcp:0.0.0.0:8188");
    expect(openedEvent).toBeDefined();
    expect(openedEvent?.severity).toBe("critical");

    expect(publishedAlerts.some((a) => a.severity === "critical" && a.fingerprint.includes("unexpected_workload:comfy"))).toBe(true);
    expect(drainCount).toBeGreaterThan(drainBefore);

    // Verify unexpected_workload corroboration was fed into lockdown.consider.
    const corroboration = considerCalls[0]!.corroboration;
    const workloadCorr = corroboration.find((c) => c.rule === "unexpected_workload");
    expect(workloadCorr).toBeDefined();
    expect(workloadCorr?.target).toMatchObject({
      kind: "pause_workload",
      workloadId: "comfy",
      pid: 4242,
    });
  } finally {
    await runtime.stop();
    if (store.calls.close === 0) store.close();
  }
});

test("handleMonitorResult publishes and drains alerts on scheduled journal and socket ticks", async () => {
  const clock = fakeClock();
  const scheduler = fakeScheduler();
  const store = new SpyStore(":memory:");
  const settings = settingsFixture();

  const publishedAlerts: SecurityAlert[] = [];
  let drainCalls = 0;
  let journalAlert: SecurityAlert | null = null;
  let socketAlert: SecurityAlert | null = null;

  const runtime = createSecurityRuntime({
    store,
    collector: {
      async collect(scanId) {
        return postureResult(scanId, clock.now());
      },
    },
    monitor: {
      async pollJournal(): Promise<MonitorResult> {
        const next = journalAlert;
        journalAlert = null;
        return next
          ? { alerts: [next], corroboration: [], coverage: "complete" }
          : emptyMonitorResult();
      },
      async pollSockets(): Promise<MonitorResult> {
        const next = socketAlert;
        socketAlert = null;
        return next
          ? { alerts: [next], corroboration: [], coverage: "complete" }
          : emptyMonitorResult();
      },
    },
    analyst: {
      async investigate() {
        return unconfiguredInvestigation();
      },
    },
    lockdown: {
      async consider() { return { proposals: [], actions: [], alerts: [] }; },
      async approve() { return true; },
      reject() { return true; },
      async unlock() { return true; },
      async reconcile() {},
    },
    dispatcher: {
      publish(alert) {
        publishedAlerts.push(alert);
        return true;
      },
      sendTestAlert() { return "test"; },
      async drain() { drainCalls += 1; },
      health() { return {}; },
    },
    clock,
    scheduler,
    settings,
  });

  const updates: unknown[] = [];
  const unsub = runtime.subscribe((u) => updates.push(u));
  try {
    runtime.start();
    await flushMicrotasks();

    const journalTick = scheduler.ticks.find((t) => t.ms === 5_000)!;
    const socketTick = scheduler.ticks.find((t) => t.ms === 30_000)!;

    const drainBeforeJournal = drainCalls;
    journalAlert = {
      id: "alert-journal-tick",
      fingerprint: "ssh_burst:198.51.100.42",
      severity: "critical",
      summary: "Journal SSH burst",
      createdAt: clock.now(),
    };
    journalTick.run();
    await flushUntil(() => publishedAlerts.some((a) => a.id === "alert-journal-tick"), "journal alert publish");
    await flushMicrotasks();
    expect(drainCalls).toBeGreaterThan(drainBeforeJournal);
    expect(updates).toContainEqual({ kind: "alert" });
    expect(updates).toContainEqual({ kind: "events" });

    const drainBeforeSocket = drainCalls;
    socketAlert = {
      id: "alert-socket-tick",
      fingerprint: "unexpected_listener:tcp:0.0.0.0:8188",
      severity: "critical",
      summary: "Socket exposed listener",
      createdAt: clock.now(),
    };
    socketTick.run();
    await flushUntil(() => publishedAlerts.some((a) => a.id === "alert-socket-tick"), "socket alert publish");
    await flushMicrotasks();
    expect(drainCalls).toBeGreaterThan(drainBeforeSocket);
  } finally {
    unsub();
    await runtime.stop();
    if (store.calls.close === 0) store.close();
  }
});

test("createLiveSecurityRuntime boots with a temp DB and falls back safely on corrupt persisted overrides", async () => {
  const tempDir = mkdtempSync(join(tmpdir(), "basho-live-runtime-"));
  const dbPath = join(tempDir, "security.db");
  try {
    const { settings, secrets } = loadSecurityConfig({ env: {}, fileConfig: {} });
    settings.process.securityDbPath = dbPath;
    settings.mode = "approve";
    settings.scanIntervalMinutes = 45;

    // 1. Smoke test: live runtime constructs, serves view, stops cleanly, and view remains safe after stop.
    const smokeRuntime = createLiveSecurityRuntime({
      settings,
      secrets,
      scheduler: fakeScheduler(),
      hostLabel: "live-smoke-host",
    });
    const liveView = smokeRuntime.view();
    expect(liveView.hostLabel).toBe("live-smoke-host");
    expect(liveView.settings.mode).toBe("approve");
    expect(liveView.settings.scanIntervalMinutes).toBe(45);
    await smokeRuntime.stop();
    const stoppedView = smokeRuntime.view();
    expect(stoppedView.hostLabel).toBe("live-smoke-host");
    expect(stoppedView.scanRunning).toBe(false);
    expect(stoppedView.nextScanAt).toBeNull();

    // 2. Corrupt JSON in runtime_settings overrides must fall back safely without crashing startup.
    const rawDb = new Database(dbPath);
    try {
      rawDb
        .query(
          `INSERT INTO runtime_settings (key, value_json, updated_at)
           VALUES ('overrides', ?, ?)
           ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
        )
        .run("{corrupt-json", Date.now());
    } finally {
      rawDb.close();
    }

    const corruptJsonRuntime = createLiveSecurityRuntime({
      settings,
      secrets,
      scheduler: fakeScheduler(),
    });
    expect(corruptJsonRuntime.view().settings.mode).toBe("approve");
    expect(corruptJsonRuntime.view().settings.scanIntervalMinutes).toBe(45);
    await corruptJsonRuntime.stop();

    // 3. Semantically invalid override fields must also fall back safely without crashing startup.
    const invalidDb = new Database(dbPath);
    try {
      invalidDb
        .query(
          `UPDATE runtime_settings SET value_json = ? WHERE key = 'overrides'`,
        )
        .run(JSON.stringify({ mode: "nonexistent-mode", scanIntervalMinutes: -1 }));
    } finally {
      invalidDb.close();
    }

    const invalidOverrideRuntime = createLiveSecurityRuntime({
      settings,
      secrets,
      scheduler: fakeScheduler(),
    });
    expect(invalidOverrideRuntime.view().settings.mode).toBe("approve");
    expect(invalidOverrideRuntime.view().settings.scanIntervalMinutes).toBe(45);
    await invalidOverrideRuntime.stop();
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test("view() remains safe after stop() on both real and demo runtimes", async () => {
  // Real runtime: with prior scan and with/without prior view() call.
  const harness = createHarness();
  try {
    await harness.runtime.requestScan("manual");
    await harness.runtime.stop();
    expect(harness.store.calls.close).toBe(1);

    const frozen = harness.runtime.view();
    expect(frozen.scanRunning).toBe(false);
    expect(frozen.nextScanAt).toBeNull();
    expect(frozen.latestScan?.trigger).toBe("manual");
  } finally {
    if (harness.store.calls.close === 0) harness.store.close();
  }

  // Demo runtime: stop() without ever calling view() beforehand, then call view().
  const demo = createDemoSecurityRuntime();
  await demo.stop();
  const demoFrozen = demo.view();
  expect(demoFrozen.hostLabel).toBe("lab-node-01");
  expect(demoFrozen.scanRunning).toBe(false);
  expect(demoFrozen.nextScanAt).toBeNull();
  expect(demoFrozen.latestScan).not.toBeNull();
});

test("stop() resolves within bounded stopTimeoutMs when an in-flight task hangs and catches late closed-DB errors", async () => {
  const clock = fakeClock();
  const scheduler = fakeScheduler();
  const store = new SpyStore(":memory:");
  const settings = settingsFixture();

  const hungCollect = deferred<PostureResult>();
  const hungApprove = deferred<boolean>();

  const runtime = createSecurityRuntime({
    store,
    collector: {
      async collect() {
        return hungCollect.promise;
      },
    },
    monitor: {
      async pollJournal() { return emptyMonitorResult(); },
      async pollSockets() { return emptyMonitorResult(); },
    },
    analyst: {
      async investigate() { return unconfiguredInvestigation(); },
    },
    lockdown: {
      async consider() { return { proposals: [], actions: [], alerts: [] }; },
      async approve() { return hungApprove.promise; },
      reject() { return true; },
      async unlock() { return true; },
      async reconcile() {},
    },
    dispatcher: {
      publish() { return true; },
      sendTestAlert() { return "test"; },
      async drain() {},
      health() { return {}; },
    },
    clock,
    scheduler,
    settings,
    stopTimeoutMs: 40,
  });

  const warnings: unknown[][] = [];
  const origWarn = console.warn;
  console.warn = (...args: unknown[]) => {
    warnings.push(args);
  };

  try {
    const scanPromise = runtime.requestScan("manual").catch(() => undefined);
    const approvePromise = runtime.approve("prop-hung", 1);
    await flushMicrotasks();

    const t0 = Date.now();
    await runtime.stop();
    const elapsed = Date.now() - t0;

    expect(elapsed).toBeLessThan(1_000);
    expect(store.calls.close).toBe(1);
    expect(warnings.length).toBeGreaterThan(0);
    expect(runtime.view().scanRunning).toBe(false);
    expect(runtime.view().nextScanAt).toBeNull();

    // Late settlement after SQLite is already closed must not produce unhandled rejections.
    hungCollect.resolve(postureResult("late-scan", clock.now()));
    hungApprove.reject(new Error("SQLite database is closed"));
    await scanPromise;
    await expect(approvePromise).resolves.toBe(false);
    await flushMicrotasks();
  } finally {
    console.warn = origWarn;
    if (store.calls.close === 0) store.close();
  }
});

test("breach verdict alert is still published and drained when lockdown.consider throws", async () => {
  const clock = fakeClock();
  const scheduler = fakeScheduler();
  const store = new SpyStore(":memory:");
  const settings = settingsFixture();

  const publishedAlerts: SecurityAlert[] = [];
  let drainCount = 0;

  const runtime = createSecurityRuntime({
    store,
    collector: {
      async collect(scanId) {
        return postureResult(scanId, clock.now());
      },
    },
    monitor: {
      async pollJournal() { return emptyMonitorResult(); },
      async pollSockets() { return emptyMonitorResult(); },
    },
    analyst: {
      async investigate() {
        return {
          status: "ready",
          verdict: {
            kind: "breach",
            confidence: 0.96,
            summary: "Confirmed host breach from active intrusion",
          },
          findings: [
            {
              id: "finding-breach-1",
              source: "ai",
              severity: "breach",
              summary: "Active intrusion detected",
              evidenceIds: [POSTURE_EVIDENCE_ID],
            },
          ],
          proposals: [
            {
              target: { kind: "deny_peer_ip", ip: "198.51.100.42" },
              evidenceIds: [POSTURE_EVIDENCE_ID],
            },
          ],
          trail: { steps: [] },
        };
      },
    },
    lockdown: {
      async consider() {
        throw new Error("preflight containment check failed");
      },
      async approve() { return true; },
      reject() { return true; },
      async unlock() { return true; },
      async reconcile() {},
    },
    dispatcher: {
      publish(alert) {
        publishedAlerts.push(alert);
        return true;
      },
      sendTestAlert() { return "test"; },
      async drain() { drainCount += 1; },
      health() { return {}; },
    },
    clock,
    scheduler,
    settings,
  });

  const updates: unknown[] = [];
  const unsub = runtime.subscribe((u) => updates.push(u));
  const origWarn = console.warn;
  console.warn = () => {};
  try {
    const scan = await runtime.requestScan("manual");
    await flushMicrotasks();

    expect(scan.verdict?.kind).toBe("breach");
    expect(store.latestScan()?.verdict?.kind).toBe("breach");

    const breachAlert = publishedAlerts.find((a) => a.fingerprint === "ai:verdict:breach");
    expect(breachAlert).toBeDefined();
    expect(breachAlert?.severity).toBe("breach");
    expect(breachAlert?.summary).toBe("Confirmed host breach from active intrusion");
    expect(breachAlert?.proposalId).toBeUndefined();
    expect(drainCount).toBeGreaterThanOrEqual(1);
    expect(updates).toContainEqual({ kind: "alert" });
  } finally {
    console.warn = origWarn;
    unsub();
    await runtime.stop();
    if (store.calls.close === 0) store.close();
  }
});

// ---------------------------------------------------------------------------
// Council round 1 regressions (F06, F09, F17, F19, F24)
// ---------------------------------------------------------------------------

test("F09: updateSettings({ mode: 'monitor' }) during in-flight AI passes live monitor mode to lockdown.consider and executes no containment", async () => {
  const clock = fakeClock();
  const scheduler = fakeScheduler();
  const store = new SpyStore(":memory:");
  const settings = settingsFixture((s) => {
    s.mode = "auto-lockdown";
  });

  let releaseAi!: () => void;
  const aiGate = new Promise<void>((resolve) => {
    releaseAi = resolve;
  });
  let aiStarted = false;

  const considerModes: SecuritySettings["mode"][] = [];
  let appliedActions = 0;

  const runtime = createSecurityRuntime({
    store,
    collector: {
      async collect(scanId) {
        return postureResult(scanId, clock.now());
      },
    },
    monitor: {
      async pollJournal() {
        return emptyMonitorResult();
      },
      async pollSockets() {
        return emptyMonitorResult();
      },
    },
    analyst: {
      async investigate(): Promise<InvestigationResult> {
        aiStarted = true;
        await aiGate;
        return {
          status: "ready",
          verdict: { kind: "breach", confidence: 0.99, summary: "Active breach" },
          findings: [],
          proposals: [
            {
              target: { kind: "deny_peer_ip", ip: "198.51.100.42" },
              evidenceIds: [POSTURE_EVIDENCE_ID],
            },
          ],
          trail: { steps: [] },
        };
      },
    },
    lockdown: {
      async consider(_scan, _drafts, _corr, liveSettings) {
        considerModes.push(liveSettings.mode);
        if (liveSettings.mode !== "monitor") {
          appliedActions += 1;
        }
        return { proposals: [], actions: [], alerts: [] };
      },
      async approve() {
        return true;
      },
      reject() {
        return true;
      },
      async unlock() {
        return true;
      },
      async reconcile() {},
    },
    dispatcher: {
      publish() {
        return true;
      },
      sendTestAlert() {
        return "test";
      },
      async drain() {},
      health() {
        return {};
      },
    },
    clock,
    scheduler,
    settings,
  });

  try {
    const scanPromise = runtime.requestScan("manual");
    await flushUntil(() => aiStarted, "AI investigation to start");

    runtime.updateSettings({ mode: "monitor" });
    releaseAi();

    await scanPromise;
    expect(considerModes).toEqual(["monitor"]);
    expect(appliedActions).toBe(0);
  } finally {
    await runtime.stop();
    if (store.calls.close === 0) store.close();
  }
});

test("F17 & F06: createLiveSecurityRuntime primes UFW/Tailscale context on startup and merges workload ports for socket polls", async () => {
  const dir = mkdtempSync(join(tmpdir(), "basho-live-f17-"));
  const dbPath = join(dir, "state", "security.db");
  const clock = fakeClock();
  const scheduler = fakeScheduler();
  const settings = settingsFixture((s) => {
    s.expectedPorts = [22, 6969];
    s.workloads = [{ id: "comfy", unit: "comfy.service", name: "comfy", ports: [8199] }];
    s.process.securityDbPath = dbPath;
  });

  const ssHeader = "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess";
  const ssLoopback =
    'tcp   LISTEN 0      128    127.0.0.1:6969   0.0.0.0:*    users:(("bun",pid=1001,fd=3))';
  const ssDeclaredComfy =
    'tcp   LISTEN 0      128    0.0.0.0:8199     0.0.0.0:*    users:(("comfy",pid=4242,fd=6))';
  const ssUnexpectedComfy =
    'tcp   LISTEN 0      128    0.0.0.0:8188     0.0.0.0:*    users:(("comfy",pid=4242,fd=7))';

  let stage = 0;
  const runner: CommandRunner = {
    async run(request: CommandRequest): Promise<CommandResult> {
      if (request.kind === "ufw_status") {
        return {
          status: "ok",
          exitCode: 0,
          stdout:
            "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n",
        };
      }
      if (request.kind === "tailscale_serve" || request.kind === "tailscale_funnel") {
        return { status: "ok", exitCode: 0, stdout: "{}" };
      }
      if (request.kind === "sockets") {
        if (stage === 0) return { status: "ok", exitCode: 0, stdout: [ssHeader, ssLoopback].join("\n") };
        if (stage === 1) {
          return {
            status: "ok",
            exitCode: 0,
            stdout: [ssHeader, ssLoopback, ssDeclaredComfy].join("\n"),
          };
        }
        return {
          status: "ok",
          exitCode: 0,
          stdout: [ssHeader, ssLoopback, ssDeclaredComfy, ssUnexpectedComfy].join("\n"),
        };
      }
      if (request.kind === "processes") {
        return {
          status: "ok",
          exitCode: 0,
          stdout: "  4242     1  1000   120 user@1000.service comfy.service comfy\n",
        };
      }
      return { status: "unavailable" };
    },
  };

  const files: PostureFiles = {
    async read(source) {
      if (source === "ufw-v4") {
        return [
          "-A ufw-user-input -p tcp --dport 8199 -j ACCEPT",
          "-A ufw-user-input -p tcp --dport 8188 -j ACCEPT",
        ].join("\n");
      }
      if (source === "ufw-v6") return "-A ufw6-user-input -j RETURN";
      if (source === "ufw-default") return 'IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"';
      return null;
    },
    async sshDropIns() {
      return [];
    },
  };

  const runtime = createLiveSecurityRuntime({
    settings,
    secrets: {},
    clock,
    scheduler,
    runner,
    files,
  } as Parameters<typeof createLiveSecurityRuntime>[0] & {
    runner?: CommandRunner;
    files?: PostureFiles;
  });

  try {
    // Notice: NO manual or scheduled scan has run yet!
    runtime.start();
    await flushMicrotasks();

    const socketTick = scheduler.ticks.find((tick) => tick.ms === 30_000);
    expect(socketTick).toBeDefined();

    // Baseline poll (loopback only).
    socketTick!.run();
    await flushMicrotasks();

    // Poll 2: declared workload port 8199 opens -> expected (no critical alert).
    clock.advance(30_000);
    stage = 1;
    socketTick!.run();
    await flushMicrotasks();
    expect(runtime.view().alerts).toHaveLength(0);

    // Poll 3: undeclared port 8188 opens before any 60m scan -> classified exposed_lan (NOT unknown), raises critical event + alert!
    clock.advance(30_000);
    stage = 2;
    socketTick!.run();
    await flushUntil(
      () => runtime.view().alerts.some((a) => a.fingerprint.includes("unexpected_workload:comfy")),
      "critical unexpected_workload alert before first scheduled scan",
    );

    const view = runtime.view();
    const openedEvent = view.events.find(
      (ev) => ev.rule === "listener_opened" && ev.target === "tcp:0.0.0.0:8188",
    );
    expect(openedEvent).toBeDefined();
    expect(openedEvent?.severity).toBe("critical");
  } finally {
    await runtime.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("F19: cooldown-skipped event scan carries forward previous AI verdict, AI findings, and investigation trail", async () => {
  const clock = fakeClock();
  const scheduler = fakeScheduler();
  const store = new SpyStore(":memory:");
  const settings = settingsFixture((s) => {
    s.ai.triageCooldownMinutes = 10;
  });

  let analystCalls = 0;
  const runtime = createSecurityRuntime({
    store,
    collector: {
      async collect(scanId) {
        return postureResult(scanId, clock.now());
      },
    },
    monitor: {
      async pollJournal() {
        return emptyMonitorResult();
      },
      async pollSockets() {
        return emptyMonitorResult();
      },
    },
    analyst: {
      async investigate(): Promise<InvestigationResult> {
        analystCalls += 1;
        return {
          status: "ready",
          verdict: { kind: "breach", confidence: 0.95, summary: "Ongoing intrusion" },
          findings: [
            {
              id: "ai-finding-1",
              source: "ai",
              severity: "breach",
              summary: "Unauthorized workload exposure confirmed",
              evidenceIds: [POSTURE_EVIDENCE_ID],
            },
          ],
          proposals: [],
          trail: {
            steps: [
              {
                tool: "read_posture_detail",
                reason: "Inspect network exposure",
                outcome: "ok",
                evidenceIds: [POSTURE_EVIDENCE_ID],
              },
            ],
          },
        };
      },
    },
    lockdown: {
      async consider() {
        return { proposals: [], actions: [], alerts: [] };
      },
      async approve() {
        return true;
      },
      reject() {
        return true;
      },
      async unlock() {
        return true;
      },
      async reconcile() {},
    },
    dispatcher: {
      publish() {
        return true;
      },
      sendTestAlert() {
        return "test";
      },
      async drain() {},
      health() {
        return {};
      },
    },
    clock,
    scheduler,
    settings,
  });

  try {
    // First event scan runs AI and records breach verdict + AI finding + trail.
    await runtime.requestScan("event");
    expect(analystCalls).toBe(1);

    // Second event scan within 10m cooldown skips AI but MUST preserve verdict, AI findings, and trail.
    clock.advance(60_000);
    await runtime.requestScan("event");
    expect(analystCalls).toBe(1);

    const latest = runtime.view().latestScan;
    expect(latest).not.toBeNull();
    expect(latest!.aiStatus).toBe("ready");
    expect(latest!.verdict).toEqual({
      kind: "breach",
      confidence: 0.95,
      summary: "Ongoing intrusion",
    });
    expect(latest!.findings.some((f) => f.source === "ai" && f.id === "ai-finding-1")).toBe(true);
    expect(latest!.trail.steps).toHaveLength(1);
    expect(latest!.trail.steps[0]?.tool).toBe("read_posture_detail");
  } finally {
    await runtime.stop();
    if (store.calls.close === 0) store.close();
  }
});

test("F24: reconcileSchedule, approve, and unlock emit containment updates whenever persisted containment state changes", async () => {
  const clock = fakeClock();
  const scheduler = fakeScheduler();
  const store = new SpyStore(":memory:");
  const settings = settingsFixture();

  const proposalId = "prop-f24";
  store.insertProposal({
    id: proposalId,
    scanId: "scan-f24",
    revision: 1,
    status: "pending",
    target: { kind: "deny_peer_ip", ip: "198.51.100.42" },
    evidenceIds: [POSTURE_EVIDENCE_ID],
    createdAt: clock.now(),
    expiresAt: clock.now() + 60_000,
    leaseSeconds: 60,
    rollbackDescription: "Remove deny rule",
  });

  const updates: string[] = [];
  const runtime = createSecurityRuntime({
    store,
    collector: {
      async collect(scanId) {
        return postureResult(scanId, clock.now());
      },
    },
    monitor: {
      async pollJournal() {
        return emptyMonitorResult();
      },
      async pollSockets() {
        return emptyMonitorResult();
      },
    },
    analyst: {
      async investigate() {
        return unconfiguredInvestigation();
      },
    },
    lockdown: {
      async consider() {
        return { proposals: [], actions: [], alerts: [] };
      },
      async approve(id, rev) {
        // Simulates claiming (creating a pending action) then failing apply -> returns false.
        store.claimProposal(id, rev, clock.now());
        return false;
      },
      reject() {
        return false;
      },
      async unlock(actionId) {
        // Simulates transitioning to rolling_back then adapter returning unknown -> returns false.
        store.transitionAction(actionId, "pending", "rolling_back", clock.now());
        return false;
      },
      async reconcile() {
        // Simulates settling rolling_back -> rolled_back and expiring proposals.
        store.expireProposals(clock.now());
        for (const action of store.listActions()) {
          if (action.state === "rolling_back") {
            store.transitionAction(action.id, "rolling_back", "rolled_back", clock.now());
          }
        }
      },
    },
    dispatcher: {
      publish() {
        return true;
      },
      sendTestAlert() {
        return "test";
      },
      async drain() {},
      health() {
        return {};
      },
    },
    clock,
    scheduler,
    settings,
  });

  const unsub = runtime.subscribe((u) => updates.push(u.kind));
  try {
    runtime.start();
    await flushMicrotasks();
    updates.length = 0;

    // approve() returns false after persisting a pending action -> MUST still emit containment!
    expect(await runtime.approve(proposalId, 1)).toBe(false);
    expect(updates).toContain("containment");
    const actionId = store.listActions()[0]!.id;

    // unlock() returns false after persisting rolling_back -> MUST still emit containment!
    updates.length = 0;
    expect(await runtime.unlock(actionId)).toBe(false);
    expect(updates).toContain("containment");

    // reconcileSchedule transitions rolling_back -> rolled_back -> MUST emit containment!
    updates.length = 0;
    const reconcileTick = scheduler.ticks.find((tick) => tick.ms === 15_000);
    expect(reconcileTick).toBeDefined();
    reconcileTick!.run();
    await flushMicrotasks();
    expect(updates).toContain("containment");

    // A no-op reconcile tick MUST NOT emit spurious containment updates.
    updates.length = 0;
    reconcileTick!.run();
    await flushMicrotasks();
    expect(updates).not.toContain("containment");
  } finally {
    unsub();
    await runtime.stop();
    if (store.calls.close === 0) store.close();
  }
});
