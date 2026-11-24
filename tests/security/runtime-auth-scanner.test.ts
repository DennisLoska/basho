import { expect, test } from "bun:test";
import {
  createDemoSecurityRuntime,
  getDemoServices,
  getDemoSystemStats,
} from "../../src/security/demo";
import { createSecurityAuth } from "../../src/security/auth";
import { createSecurityRuntime } from "../../src/security/runtime";
import { scan } from "../../src/services/scanner";
import { loadSecurityConfig } from "../../src/security/config";
import { SecurityStore } from "../../src/security/store";
import type { InvestigationResult, ProposalDraft } from "../../src/security/ai-analyst";
import type { PostureResult } from "../../src/security/collector";
import type { MonitorResult } from "../../src/security/events";
import type { ConsiderResult } from "../../src/security/lockdown";
import type {
  AlertChannel,
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

type InvestigateImpl = (scanId: string, broker: unknown) => Promise<InvestigationResult>;

type JournalImpl = (signal?: AbortSignal) => Promise<MonitorResult>;

function createHarness(options: { settings?: SecuritySettings } = {}) {
  const clock = fakeClock();
  const scheduler = fakeScheduler();
  const store = new SpyStore(":memory:");
  const settings = options.settings ?? settingsFixture();

  const collectorCalls: CollectorCall[] = [];
  let collectImpl: CollectImpl = async (scanId) => postureResult(scanId, clock.now());

  const monitorCalls = { journal: 0, sockets: 0 };
  let journalImpl: JournalImpl = async () => emptyMonitorResult();

  const analystCalls: { scanId: string; broker: unknown }[] = [];
  let investigateImpl: InvestigateImpl = async () => unconfiguredInvestigation();

  const lockdownCalls = {
    consider: 0,
    approve: [] as [string, number][],
    reject: [] as [string, number][],
    unlock: [] as string[],
    reconcile: 0,
  };

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
    async investigate(scanId: string, broker: unknown) {
      analystCalls.push({ scanId, broker });
      return investigateImpl(scanId, broker);
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
    async approve(id: string, revision: number, _settings: SecuritySettings) {
      lockdownCalls.approve.push([id, revision]);
      return true;
    },
    reject(id: string, revision: number) {
      lockdownCalls.reject.push([id, revision]);
      return true;
    },
    async unlock(actionId: string) {
      lockdownCalls.unlock.push(actionId);
      return true;
    },
    async reconcile() {
      lockdownCalls.reconcile += 1;
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
    expect(serialized).toContain("198.51.100.42");
    expect(serialized).toContain("203.0.113.19");
    expect(serialized).toContain("2001:db8::10");

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

test("an event request during an active scan runs exactly one follow-up scan", async () => {
  const harness = createHarness();
  try {
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

test("login adds Secure for HTTPS requests and when a public origin is configured", () => {
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

  const proxied = asAuth(
    createSecurityAuth({
      token: FIXTURE_TOKEN,
      clock: fakeClock(),
      publicOrigin: "https://basho.example.test",
    }),
  );
  const proxiedLogin = proxied.login(
    new Request(`${LOCAL_ORIGIN}/security/login`, {
      method: "POST",
      headers: { Origin: LOCAL_ORIGIN },
    }),
    FIXTURE_TOKEN,
  );
  expect(proxiedLogin.ok).toBe(true);
  expect((proxiedLogin.cookie ?? "").toLowerCase()).toContain("secure");
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
  expect(JSON.stringify(services)).toContain("lab-node-01");
  expect(JSON.stringify(services)).toContain("198.51.100.42");

  const stats = getDemoSystemStats();
  expect(stats.cpu.count).toBe(stats.cpu.cores.length);
  expect(stats.ram.total).toBeGreaterThan(0);
  expect(stats.disks.length).toBeGreaterThan(0);
  expect(stats.gpu).not.toBeNull();
});
