import { afterAll, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { ProposalDraft } from "../../src/security/ai-analyst";
import {
  DeadMansSwitch,
  LockdownEngine,
  createCompositeLockdownAdapter,
  createHelperLockdownAdapter,
  createUserWorkloadLockdownAdapter,
  decideContainment,
} from "../../src/security/lockdown";
import type { LockdownAdapter } from "../../src/security/lockdown";
import { SecurityStore } from "../../src/security/store";
import { criterionIds } from "../../src/security/types";
import type {
  Clock,
  ContainmentTarget,
  Corroboration,
  CriterionId,
  EnrolledWorkload,
  Evidence,
  LockdownAction,
  SecurityAlert,
  SecurityScan,
  SecuritySettings,
} from "../../src/security/types";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const NOW = 1_796_000_000_000;
const SECOND = 1_000;
const MINUTE = 60 * SECOND;

const PEER = "198.51.100.42";
const OTHER_PEER = "203.0.113.19";
const ENROLLED_ID = "ollama";
const ENROLLED_UNIT = "ollama.service";
const ENROLLED_PID = 4242;
const ENROLLED_STARTED_AT = 1_700_000_000;
const CURRENT_UID = 1000;

const PEER_TARGET: ContainmentTarget = { kind: "deny_peer_ip", ip: PEER };
const WORKLOAD_TARGET: ContainmentTarget = {
  kind: "pause_workload",
  workloadId: ENROLLED_ID,
  pid: ENROLLED_PID,
  startedAt: ENROLLED_STARTED_AT,
};
const LAN_TARGET: ContainmentTarget = { kind: "isolate_lan_ingress" };

const ENROLLED_WORKLOAD: EnrolledWorkload = {
  id: ENROLLED_ID,
  unit: ENROLLED_UNIT,
  name: "Ollama",
};

type ProcessIdentity = {
  pid: number;
  uid: number;
  startedAt: number;
  comm: string;
  unit?: string;
  uunit?: string;
};

type ResolveProcess = (pid: number) => Promise<ProcessIdentity | null>;

async function waitUntil(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
  const startedAt = Date.now();
  while (!predicate()) {
    if (Date.now() - startedAt > timeoutMs) {
      throw new Error("timed out waiting for condition");
    }
    await new Promise((resolveTick) => setTimeout(resolveTick, 1));
  }
}

function makeSettings(overrides: Partial<SecuritySettings> = {}): SecuritySettings {
  return {
    mode: "approve",
    scanIntervalMinutes: 60,
    criteria: Object.fromEntries(criterionIds.map((id) => [id, true])) as Record<
      CriterionId,
      boolean
    >,
    expectedPorts: [22],
    workloads: [],
    ai: {
      baseURL: "https://ai.example.test/v1",
      model: "fixture-model",
      sessionHeader: false,
      confidenceThreshold: 0.85,
      triageCooldownMinutes: 15,
    },
    notifications: { channels: ["in-app"], cooldownMinutes: 15 },
    lockdown: { proposalMinutes: 30, leaseSeconds: 600, helperEnabled: true },
    process: { host: "127.0.0.1", port: 6969, securityDbPath: ":memory:", demo: false },
    ...overrides,
  };
}

function scanFixture(overrides: Partial<SecurityScan> = {}): SecurityScan {
  const evidence: Evidence[] = [
    { id: "ev-1", kind: "event", facts: { rule: "ssh_burst", target: PEER } },
    { id: "ev-2", kind: "process", facts: { pid: ENROLLED_PID, unit: ENROLLED_UNIT } },
  ];
  return {
    id: "scan-1",
    trigger: "manual",
    startedAt: NOW - SECOND,
    finishedAt: NOW,
    snapshot: { id: "snapshot-1", capturedAt: NOW, checks: [], evidence },
    exposure: [],
    findings: [],
    trail: { steps: [] },
    aiStatus: "ready",
    verdict: {
      kind: "breach",
      confidence: 0.95,
      summary: "Repeated authentication failures from a single peer",
    },
    ...overrides,
  };
}

const PEER_DRAFT: ProposalDraft = { target: PEER_TARGET, evidenceIds: ["ev-1"] };
const WORKLOAD_DRAFT: ProposalDraft = { target: WORKLOAD_TARGET, evidenceIds: ["ev-2"] };

function peerCorroboration(overrides: Partial<Corroboration> = {}): Corroboration {
  return {
    rule: "ssh_burst",
    eventIds: ["event-1"],
    expiresAt: NOW + 5 * MINUTE,
    target: PEER_TARGET,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// DeadMansSwitch
// ---------------------------------------------------------------------------

describe("DeadMansSwitch", () => {
  const guard = new DeadMansSwitch();

  test("rejects protected management peers after canonicalization", () => {
    const protectedIps = [
      "127.0.0.1",
      "127.42.0.1",
      "::1",
      "::ffff:127.0.0.1",
      "100.64.0.5",
      "100.127.255.254",
      "::ffff:100.79.86.17",
      "fd7a:115c:a1e0::34",
      "0.0.0.0",
      "::",
    ];
    for (const ip of protectedIps) {
      expect({ ip, allowed: guard.allows({ kind: "deny_peer_ip", ip }) }).toEqual({
        ip,
        allowed: false,
      });
    }
  });

  test("rejects malformed peer addresses", () => {
    const malformed = [
      "",
      "not-an-ip",
      "999.1.1.1",
      "198.51.100.42/32",
      " 198.51.100.42",
      "198.51.100.42 ",
      "fe80::1%eth0",
      "2001:db8::10/64",
    ];
    for (const ip of malformed) {
      expect({ ip, allowed: guard.allows({ kind: "deny_peer_ip", ip }) }).toEqual({
        ip,
        allowed: false,
      });
    }
  });

  test("allows canonical external peers", () => {
    const allowedIps = ["198.51.100.42", "203.0.113.19", "2001:db8::10"];
    for (const ip of allowedIps) {
      expect({ ip, allowed: guard.allows({ kind: "deny_peer_ip", ip }) }).toEqual({
        ip,
        allowed: true,
      });
    }
  });

  test("pause_workload requires a verified enrolled user-owned identity", () => {
    const context = {
      workloads: [ENROLLED_WORKLOAD],
      currentProcess: {
        pid: ENROLLED_PID,
        uid: CURRENT_UID,
        startedAt: ENROLLED_STARTED_AT,
        comm: "ollama",
        unit: ENROLLED_UNIT,
      },
      currentUid: CURRENT_UID,
    };

    expect(guard.allows(WORKLOAD_TARGET, context)).toBe(true);

    // Unknown workload IDs are never actionable, even with a live matching process.
    expect(
      guard.allows(
        { kind: "pause_workload", workloadId: "not-enrolled", pid: ENROLLED_PID, startedAt: ENROLLED_STARTED_AT },
        context,
      ),
    ).toBe(false);

    // Without live process evidence there is nothing safe to act on.
    expect(guard.allows(WORKLOAD_TARGET, { ...context, currentProcess: null })).toBe(false);

    // Mismatched PID.
    expect(
      guard.allows(
        { ...WORKLOAD_TARGET, pid: ENROLLED_PID + 1 } as ContainmentTarget,
        context,
      ),
    ).toBe(false);

    // Mismatched process start time (PID reuse).
    expect(
      guard.allows(
        { ...WORKLOAD_TARGET, startedAt: ENROLLED_STARTED_AT + 1 } as ContainmentTarget,
        context,
      ),
    ).toBe(false);

    // Mismatched owning uid.
    expect(
      guard.allows(WORKLOAD_TARGET, {
        ...context,
        currentProcess: { ...context.currentProcess, uid: 0 },
      }),
    ).toBe(false);

    // Mismatched unit.
    expect(
      guard.allows(WORKLOAD_TARGET, {
        ...context,
        currentProcess: { ...context.currentProcess, unit: "other.service" },
      }),
    ).toBe(false);

    // Mismatched live PID.
    expect(
      guard.allows(WORKLOAD_TARGET, {
        ...context,
        currentProcess: { ...context.currentProcess, pid: ENROLLED_PID + 1 },
      }),
    ).toBe(false);
  });

  test("pause_workload refuses PID 1 and critical services", () => {
    const criticalComms = [
      "systemd",
      "systemd-journald",
      "basho",
      "tailscaled",
      "sshd",
      "NetworkManager",
      "dbus-broker",
      "dbus-daemon",
      "hyprland",
      "sddm",
      "wayland-wm",
    ];

    for (const comm of criticalComms) {
      const allowed = guard.allows(WORKLOAD_TARGET, {
        workloads: [ENROLLED_WORKLOAD],
        currentProcess: {
          pid: ENROLLED_PID,
          uid: CURRENT_UID,
          startedAt: ENROLLED_STARTED_AT,
          comm,
          unit: ENROLLED_UNIT,
        },
        currentUid: CURRENT_UID,
      });
      expect({ comm, allowed }).toEqual({ comm, allowed: false });
    }

    expect(
      guard.allows(
        { kind: "pause_workload", workloadId: ENROLLED_ID, pid: 1, startedAt: 1 },
        {
          workloads: [ENROLLED_WORKLOAD],
          currentProcess: {
            pid: 1,
            uid: 0,
            startedAt: 1,
            comm: "systemd",
            unit: "init.scope",
          },
          currentUid: 0,
        },
      ),
    ).toBe(false);
  });

  test("isolate_lan_ingress requires verified LAN policy readiness", () => {
    expect(guard.allows(LAN_TARGET)).toBe(false);
    expect(guard.allows(LAN_TARGET, { lanPolicyReady: false })).toBe(false);
    expect(guard.allows(LAN_TARGET, { lanPolicyReady: true })).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// decideContainment
// ---------------------------------------------------------------------------

type DecisionInput = Parameters<typeof decideContainment>[0];

function decisionInput(overrides: Partial<DecisionInput> = {}): DecisionInput {
  return {
    mode: "auto-lockdown",
    target: PEER_TARGET,
    now: NOW,
    threshold: 0.85,
    verdict: {
      kind: "breach",
      confidence: 0.95,
      summary: "Repeated authentication failures from a single peer",
    },
    corroboration: [peerCorroboration()],
    safe: true,
    rollbackReady: true,
    ...overrides,
  };
}

describe("decideContainment", () => {
  test("monitor mode only reports", () => {
    expect(decideContainment(decisionInput({ mode: "monitor" }))).toBe("report");
  });

  test("unsafe targets only report in every mode", () => {
    for (const mode of ["monitor", "approve", "auto-lockdown"] as const) {
      expect({ mode, decision: decideContainment(decisionInput({ mode, safe: false })) }).toEqual({
        mode,
        decision: "report",
      });
    }
  });

  test("approve mode queues eligible targets", () => {
    expect(decideContainment(decisionInput({ mode: "approve" }))).toBe("queue");
    expect(
      decideContainment(decisionInput({ mode: "approve", rollbackReady: false, corroboration: [] })),
    ).toBe("queue");
  });

  test("auto-lockdown executes when every precondition holds", () => {
    expect(decideContainment(decisionInput())).toBe("execute");
  });

  test("auto-lockdown falls back to queue without rollback readiness", () => {
    expect(decideContainment(decisionInput({ rollbackReady: false }))).toBe("queue");
  });

  test("auto-lockdown requires a breach verdict", () => {
    const warn = decisionInput({
      verdict: { kind: "warn", confidence: 0.99, summary: "Suspicious but unconfirmed" },
    });
    const healthy = decisionInput({
      verdict: { kind: "healthy", confidence: 0.99, summary: "All clear" },
    });
    const missing = decisionInput({ verdict: undefined });

    expect(decideContainment(warn)).toBe("queue");
    expect(decideContainment(healthy)).toBe("queue");
    expect(decideContainment(missing)).toBe("queue");
  });

  test("auto-lockdown requires confidence at or above the threshold", () => {
    expect(
      decideContainment(
        decisionInput({
          threshold: 0.85,
          verdict: { kind: "breach", confidence: 0.84, summary: "Borderline" },
        }),
      ),
    ).toBe("queue");
    expect(
      decideContainment(
        decisionInput({
          threshold: 0.85,
          verdict: { kind: "breach", confidence: 0.85, summary: "At threshold" },
        }),
      ),
    ).toBe("execute");
  });

  test("auto-lockdown rejects stale or empty corroboration", () => {
    expect(
      decideContainment(decisionInput({ corroboration: [peerCorroboration({ expiresAt: NOW })] })),
    ).toBe("queue");
    expect(
      decideContainment(
        decisionInput({ corroboration: [peerCorroboration({ expiresAt: NOW - 1 })] }),
      ),
    ).toBe("queue");
    expect(
      decideContainment(decisionInput({ corroboration: [peerCorroboration({ eventIds: [] })] })),
    ).toBe("queue");
    expect(decideContainment(decisionInput({ corroboration: [] }))).toBe("queue");
  });

  test("auto-lockdown requires corroboration for the exact canonical peer", () => {
    expect(
      decideContainment(
        decisionInput({
          corroboration: [
            peerCorroboration({ target: { kind: "deny_peer_ip", ip: OTHER_PEER } }),
          ],
        }),
      ),
    ).toBe("queue");
    expect(
      decideContainment(
        decisionInput({ corroboration: [peerCorroboration({ target: undefined })] }),
      ),
    ).toBe("queue");
    expect(
      decideContainment(
        decisionInput({
          corroboration: [peerCorroboration({ rule: "unexpected_listener" })],
        }),
      ),
    ).toBe("queue");

    // Canonical equivalence: an IPv4-mapped corroboration peer is the same peer.
    expect(
      decideContainment(
        decisionInput({
          target: { kind: "deny_peer_ip", ip: `::ffff:${PEER}` },
          corroboration: [peerCorroboration()],
        }),
      ),
    ).toBe("execute");
  });

  test("auto-lockdown requires exact workload identity corroboration", () => {
    const workloadCorroboration: Corroboration = {
      rule: "unexpected_workload",
      eventIds: ["event-2"],
      expiresAt: NOW + 5 * MINUTE,
      target: WORKLOAD_TARGET,
    };
    expect(
      decideContainment(
        decisionInput({ target: WORKLOAD_TARGET, corroboration: [workloadCorroboration] }),
      ),
    ).toBe("execute");

    const mismatches: Partial<Corroboration>[] = [
      { target: { ...WORKLOAD_TARGET, workloadId: "other" } as ContainmentTarget },
      { target: { ...WORKLOAD_TARGET, pid: ENROLLED_PID + 1 } as ContainmentTarget },
      { target: { ...WORKLOAD_TARGET, startedAt: ENROLLED_STARTED_AT + 1 } as ContainmentTarget },
      { rule: "ssh_burst" },
    ];
    for (const mismatch of mismatches) {
      expect(
        decideContainment(
          decisionInput({
            target: WORKLOAD_TARGET,
            corroboration: [{ ...workloadCorroboration, ...mismatch }],
          }),
        ),
      ).toBe("queue");
    }
  });

  test("LAN isolation stays queued until explicitly corroborated", () => {
    expect(decideContainment(decisionInput({ target: LAN_TARGET, corroboration: [] }))).toBe(
      "queue",
    );
    expect(
      decideContainment(
        decisionInput({
          target: LAN_TARGET,
          corroboration: [
            { rule: "system_anomaly", eventIds: ["event-3"], expiresAt: NOW + MINUTE },
          ],
        }),
      ),
    ).toBe("queue");
    // A peer-scoped burst never authorizes LAN isolation.
    expect(decideContainment(decisionInput({ target: LAN_TARGET }))).toBe("queue");
    // The positive LAN corroboration rule is intentionally not pinned here: the
    // engine only requires that isolation never auto-executes without an
    // explicitly scoped deterministic signal, and operator approval is always
    // covered by the approve() tests below.
  });
});

// ---------------------------------------------------------------------------
// LockdownEngine
// ---------------------------------------------------------------------------

type InspectResult = Awaited<ReturnType<LockdownAdapter["inspect"]>>;
type RollbackResult = Awaited<ReturnType<LockdownAdapter["rollback"]>>;

interface AdapterConfig {
  rollbackReady?: boolean;
  apply?: LockdownAdapter["apply"];
  inspect?: LockdownAdapter["inspect"];
  rollback?: LockdownAdapter["rollback"];
}

interface AdapterCalls {
  preflight: ContainmentTarget[];
  apply: LockdownAction[];
  inspect: LockdownAction[];
  rollback: LockdownAction[];
}

function createAdapter(config: AdapterConfig = {}): {
  adapter: LockdownAdapter;
  calls: AdapterCalls;
} {
  const calls: AdapterCalls = { preflight: [], apply: [], inspect: [], rollback: [] };
  const adapter: LockdownAdapter = {
    async preflight(target: ContainmentTarget) {
      calls.preflight.push(target);
      return { rollbackReady: config.rollbackReady ?? true };
    },
    async apply(action: LockdownAction) {
      calls.apply.push(action);
      if (config.apply) return config.apply(action);
      return { handle: `handle-${action.id}` };
    },
    async inspect(action: LockdownAction) {
      calls.inspect.push(action);
      if (config.inspect) return config.inspect(action);
      return { state: "active", handle: `handle-${action.id}` };
    },
    async rollback(action: LockdownAction) {
      calls.rollback.push(action);
      if (config.rollback) return config.rollback(action);
      return { state: "absent" };
    },
  };
  return { adapter, calls };
}

interface MutableClock {
  clock: Clock;
  advance(ms: number): void;
  set(at: number): void;
}

function createClock(start = NOW): MutableClock {
  let current = start;
  return {
    clock: { now: () => current },
    advance(ms: number) {
      current += ms;
    },
    set(at: number) {
      current = at;
    },
  };
}

function defaultProcess(pid: number): ProcessIdentity {
  return {
    pid,
    uid: CURRENT_UID,
    startedAt: ENROLLED_STARTED_AT,
    comm: "ollama",
    unit: ENROLLED_UNIT,
  };
}

function createEngine(options: {
  adapterConfig?: AdapterConfig;
  resolveProcess?: ResolveProcess;
  settings?: Partial<SecuritySettings>;
} = {}): {
  engine: LockdownEngine;
  store: SecurityStore;
  adapter: LockdownAdapter;
  calls: AdapterCalls;
  clock: MutableClock;
  settings: SecuritySettings;
} {
  const clock = createClock();
  const store = new SecurityStore(":memory:");
  const { adapter, calls } = createAdapter(options.adapterConfig ?? {});
  const settings = makeSettings(options.settings ?? {});
  const resolveProcess: ResolveProcess =
    options.resolveProcess ?? (async (pid: number) => defaultProcess(pid));

  const engine = new LockdownEngine({
    store,
    clock: clock.clock,
    guard: new DeadMansSwitch(),
    adapter,
    resolveProcess,
    currentUid: CURRENT_UID,
  });

  return { engine, store, adapter, calls, clock, settings };
}

function onlyProposal(store: SecurityStore) {
  const proposals = store.listProposals();
  expect(proposals).toHaveLength(1);
  return proposals[0]!;
}

function onlyAction(store: SecurityStore) {
  const actions = store.listActions();
  expect(actions).toHaveLength(1);
  return actions[0]!;
}

describe("LockdownEngine.consider", () => {
  test("persists a pending proposal with revision 1, default expiry, and rollback text", async () => {
    const harness = createEngine();
    const result = await harness.engine.consider(
      scanFixture(),
      [PEER_DRAFT],
      [],
      harness.settings,
    );

    expect(Array.isArray(result.alerts)).toBe(true);
    expect(harness.calls.apply).toHaveLength(0);

    const proposal = onlyProposal(harness.store);
    expect(proposal.status).toBe("pending");
    expect(proposal.revision).toBe(1);
    expect(proposal.scanId).toBe("scan-1");
    expect(proposal.target).toEqual(PEER_TARGET);
    expect(proposal.evidenceIds).toEqual(["ev-1"]);
    expect(proposal.createdAt).toBe(NOW);
    expect(proposal.expiresAt).toBe(NOW + 30 * MINUTE);
    expect(proposal.leaseSeconds).toBe(600);
    expect(typeof proposal.rollbackDescription).toBe("string");
    expect(proposal.rollbackDescription.length).toBeGreaterThan(0);
  });

  test("monitor mode never queues or executes containment", async () => {
    const harness = createEngine({ settings: { mode: "monitor" } });
    await harness.engine.consider(scanFixture(), [PEER_DRAFT], [peerCorroboration()], harness.settings);

    expect(harness.store.listProposals()).toHaveLength(0);
    expect(harness.store.listActions()).toHaveLength(0);
    expect(harness.calls.apply).toHaveLength(0);
  });

  test("targets rejected by the DeadMansSwitch are only reported", async () => {
    const harness = createEngine();
    await harness.engine.consider(
      scanFixture(),
      [{ target: { kind: "deny_peer_ip", ip: "127.0.0.1" }, evidenceIds: ["ev-1"] }],
      [],
      harness.settings,
    );

    expect(harness.store.listProposals()).toHaveLength(0);
    expect(harness.store.listActions()).toHaveLength(0);
  });

  test("auto-lockdown claims and executes when every precondition holds", async () => {
    const harness = createEngine({ settings: { mode: "auto-lockdown" } });
    await harness.engine.consider(
      scanFixture(),
      [PEER_DRAFT],
      [peerCorroboration()],
      harness.settings,
    );

    expect(harness.calls.preflight.length).toBeGreaterThan(0);
    expect(harness.calls.apply).toHaveLength(1);

    const action = onlyAction(harness.store);
    expect(action.state).toBe("active");
    expect(action.target).toEqual(PEER_TARGET);
    expect(action.proposalId).toBe(onlyProposal(harness.store).id);
    expect(action.rollbackHandle).toBe(`handle-${action.id}`);
    expect(onlyProposal(harness.store).status).toBe("claimed");
  });

  test("auto-lockdown falls back to the queue with an urgent proposal alert when rollback is not ready", async () => {
    const harness = createEngine({
      adapterConfig: { rollbackReady: false },
      settings: { mode: "auto-lockdown" },
    });
    const result = await harness.engine.consider(
      scanFixture(),
      [PEER_DRAFT],
      [peerCorroboration()],
      harness.settings,
    );

    expect(harness.calls.apply).toHaveLength(0);
    const proposal = onlyProposal(harness.store);
    expect(proposal.status).toBe("pending");

    const urgent = result.alerts.find(
      (alert: SecurityAlert) => alert.proposalId === proposal.id,
    );
    expect(urgent).toBeDefined();
    expect(["critical", "breach"]).toContain(urgent!.severity);
  });

  test("auto-lockdown falls back to the queue without matching corroboration", async () => {
    const harness = createEngine({ settings: { mode: "auto-lockdown" } });
    await harness.engine.consider(scanFixture(), [PEER_DRAFT], [], harness.settings);

    expect(harness.calls.apply).toHaveLength(0);
    expect(onlyProposal(harness.store).status).toBe("pending");
  });
});

describe("LockdownEngine.approve", () => {
  test("claims the proposal and executes exactly once", async () => {
    const harness = createEngine();
    await harness.engine.consider(scanFixture(), [PEER_DRAFT], [], harness.settings);
    const proposal = onlyProposal(harness.store);

    expect(await harness.engine.approve(proposal.id, proposal.revision, harness.settings)).toBe(
      true,
    );
    expect(harness.calls.apply).toHaveLength(1);
    expect(onlyAction(harness.store).state).toBe("active");
    expect(onlyProposal(harness.store).status).toBe("claimed");
  });

  test("concurrent double approval executes the adapter only once", async () => {
    const harness = createEngine();
    await harness.engine.consider(scanFixture(), [PEER_DRAFT], [], harness.settings);
    const proposal = onlyProposal(harness.store);

    const results = await Promise.all([
      harness.engine.approve(proposal.id, proposal.revision, harness.settings),
      harness.engine.approve(proposal.id, proposal.revision, harness.settings),
    ]);

    expect(results.filter((value: boolean) => value)).toHaveLength(1);
    expect(harness.calls.apply).toHaveLength(1);
    expect(onlyAction(harness.store).state).toBe("active");
  });

  test("stale revisions are refused", async () => {
    const harness = createEngine();
    await harness.engine.consider(scanFixture(), [PEER_DRAFT], [], harness.settings);
    const proposal = onlyProposal(harness.store);

    expect(
      await harness.engine.approve(proposal.id, proposal.revision + 1, harness.settings),
    ).toBe(false);
    expect(await harness.engine.approve(proposal.id, 0, harness.settings)).toBe(false);
    expect(harness.calls.apply).toHaveLength(0);
  });

  test("expired proposals are refused", async () => {
    const harness = createEngine();
    await harness.engine.consider(scanFixture(), [PEER_DRAFT], [], harness.settings);
    const proposal = onlyProposal(harness.store);

    harness.clock.advance(30 * MINUTE);

    expect(await harness.engine.approve(proposal.id, proposal.revision, harness.settings)).toBe(
      false,
    );
    expect(harness.calls.apply).toHaveLength(0);
  });

  test("switching to monitor mode blocks approval", async () => {
    const harness = createEngine();
    await harness.engine.consider(scanFixture(), [PEER_DRAFT], [], harness.settings);
    const proposal = onlyProposal(harness.store);

    const monitorSettings = makeSettings({ mode: "monitor" });
    expect(await harness.engine.approve(proposal.id, proposal.revision, monitorSettings)).toBe(
      false,
    );
    expect(harness.calls.apply).toHaveLength(0);
  });

  test("approval is refused when preflight cannot guarantee rollback", async () => {
    const harness = createEngine({ adapterConfig: { rollbackReady: false } });
    await harness.engine.consider(scanFixture(), [PEER_DRAFT], [], harness.settings);
    const proposal = onlyProposal(harness.store);

    expect(await harness.engine.approve(proposal.id, proposal.revision, harness.settings)).toBe(
      false,
    );
    expect(harness.calls.apply).toHaveLength(0);
    expect(noActionsActive(harness.store)).toBe(true);
  });

  test("approval is refused when the process start time drifted", async () => {
    const identity: ProcessIdentity = defaultProcess(ENROLLED_PID);
    const harness = createEngine({
      settings: { workloads: [ENROLLED_WORKLOAD] },
      resolveProcess: async (pid) => (pid === identity.pid ? identity : null),
    });
    await harness.engine.consider(scanFixture(), [WORKLOAD_DRAFT], [], harness.settings);
    const proposal = onlyProposal(harness.store);

    identity.startedAt = ENROLLED_STARTED_AT + 5;

    expect(await harness.engine.approve(proposal.id, proposal.revision, harness.settings)).toBe(
      false,
    );
    expect(harness.calls.apply).toHaveLength(0);
  });

  test("approval is refused when the process command changed", async () => {
    const identity: ProcessIdentity = defaultProcess(ENROLLED_PID);
    const harness = createEngine({
      settings: { workloads: [ENROLLED_WORKLOAD] },
      resolveProcess: async (pid) => (pid === identity.pid ? identity : null),
    });
    await harness.engine.consider(scanFixture(), [WORKLOAD_DRAFT], [], harness.settings);
    const proposal = onlyProposal(harness.store);

    identity.comm = "other-daemon";

    expect(await harness.engine.approve(proposal.id, proposal.revision, harness.settings)).toBe(
      false,
    );
    expect(harness.calls.apply).toHaveLength(0);
  });

  test("enrolled workload approval executes when identity still matches", async () => {
    const harness = createEngine({ settings: { workloads: [ENROLLED_WORKLOAD] } });
    await harness.engine.consider(scanFixture(), [WORKLOAD_DRAFT], [], harness.settings);
    const proposal = onlyProposal(harness.store);

    expect(await harness.engine.approve(proposal.id, proposal.revision, harness.settings)).toBe(
      true,
    );
    expect(harness.calls.apply).toHaveLength(1);
    expect(onlyAction(harness.store).target).toEqual(WORKLOAD_TARGET);
  });
});

describe("LockdownEngine.reject", () => {
  test("rejects with revision CAS", async () => {
    const harness = createEngine();
    await harness.engine.consider(scanFixture(), [PEER_DRAFT], [], harness.settings);
    const proposal = onlyProposal(harness.store);

    expect(harness.engine.reject(proposal.id, proposal.revision + 3)).toBe(false);
    expect(harness.engine.reject(proposal.id, proposal.revision)).toBe(true);

    const rejected = onlyProposal(harness.store);
    expect(rejected.status).toBe("rejected");
    expect(rejected.revision).toBe(proposal.revision + 1);
    expect(harness.calls.apply).toHaveLength(0);
  });
});

describe("LockdownEngine.unlock", () => {
  test("rolls an active lease back and exposes the rolling_back state", async () => {
    let releaseRollback: (value: RollbackResult) => void = () => {};
    let rollbackStarted = false;
    const pendingRollback = new Promise<RollbackResult>((resolveRollback) => {
      releaseRollback = resolveRollback;
    });

    const harness = createEngine({
      adapterConfig: {
        rollback: async () => {
          rollbackStarted = true;
          return pendingRollback;
        },
      },
    });
    await harness.engine.consider(scanFixture(), [PEER_DRAFT], [], harness.settings);
    const proposal = onlyProposal(harness.store);
    expect(await harness.engine.approve(proposal.id, proposal.revision, harness.settings)).toBe(
      true,
    );
    const action = onlyAction(harness.store);
    expect(action.state).toBe("active");

    const unlockPromise = harness.engine.unlock(action.id);
    await waitUntil(() => rollbackStarted);
    expect(onlyAction(harness.store).state).toBe("rolling_back");

    releaseRollback({ state: "absent" });
    expect(await unlockPromise).toBe(true);
    expect(onlyAction(harness.store).state).toBe("rolled_back");
    expect(harness.calls.rollback).toHaveLength(1);
  });

  test("keeps the lease rolling_back when the adapter cannot confirm removal", async () => {
    const harness = createEngine({ adapterConfig: { rollback: async () => ({ state: "unknown" }) } });
    await harness.engine.consider(scanFixture(), [PEER_DRAFT], [], harness.settings);
    const proposal = onlyProposal(harness.store);
    expect(await harness.engine.approve(proposal.id, proposal.revision, harness.settings)).toBe(
      true,
    );
    const action = onlyAction(harness.store);

    await harness.engine.unlock(action.id);

    expect(onlyAction(harness.store).state).toBe("rolling_back");
  });
});

describe("LockdownEngine.reconcile", () => {
  function uncertainEngine(applyError: Error) {
    let inspectResult: InspectResult = { state: "unknown" };
    const harness = createEngine({
      adapterConfig: {
        apply: async () => {
          throw applyError;
        },
        inspect: async () => inspectResult,
      },
    });
    return {
      harness,
      setInspect(next: InspectResult) {
        inspectResult = next;
      },
    };
  }

  async function leaveUncertain(applyError = new Error("connection lost after apply")) {
    const uncertain = uncertainEngine(applyError);
    await uncertain.harness.engine.consider(
      scanFixture(),
      [PEER_DRAFT],
      [],
      uncertain.harness.settings,
    );
    const proposal = onlyProposal(uncertain.harness.store);
    await uncertain.harness.engine.approve(proposal.id, proposal.revision, uncertain.harness.settings);
    return uncertain;
  }

  test("an uncertain apply keeps the action pending", async () => {
    const { harness } = await leaveUncertain();
    expect(onlyAction(harness.store).state).toBe("pending");

    await harness.engine.reconcile();
    expect(harness.calls.inspect.length).toBeGreaterThan(0);
    expect(onlyAction(harness.store).state).toBe("pending");
  });

  test("reconcile adopts an active action reported by the adapter", async () => {
    const { harness, setInspect } = await leaveUncertain();
    setInspect({ state: "active", handle: "handle-recovered" });

    await harness.engine.reconcile();

    const action = onlyAction(harness.store);
    expect(action.state).toBe("active");
    expect(action.rollbackHandle).toBe("handle-recovered");
  });

  test("reconcile fails an action only when the adapter confirms absence", async () => {
    const { harness, setInspect } = await leaveUncertain();
    setInspect({ state: "absent" });

    await harness.engine.reconcile();

    expect(onlyAction(harness.store).state).toBe("failed");
  });

  test("reconcile rolls back expired active leases", async () => {
    const harness = createEngine({
      settings: { lockdown: { proposalMinutes: 30, leaseSeconds: 1, helperEnabled: true } },
    });
    await harness.engine.consider(scanFixture(), [PEER_DRAFT], [], harness.settings);
    const proposal = onlyProposal(harness.store);
    expect(await harness.engine.approve(proposal.id, proposal.revision, harness.settings)).toBe(
      true,
    );
    expect(onlyAction(harness.store).state).toBe("active");

    harness.clock.advance(2 * SECOND);

    await harness.engine.reconcile();

    expect(harness.calls.rollback).toHaveLength(1);
    expect(onlyAction(harness.store).state).toBe("rolled_back");
  });

  test("expires stale pending proposals", async () => {
    const harness = createEngine();
    await harness.engine.consider(scanFixture(), [PEER_DRAFT], [], harness.settings);
    harness.clock.advance(31 * MINUTE);

    await harness.engine.reconcile();

    expect(onlyProposal(harness.store).status).toBe("expired");
  });
});

describe("LockdownEngine.helperReady", () => {
  test("reports helper availability as a boolean", async () => {
    const harness = createEngine();
    expect(typeof (await harness.engine.helperReady())).toBe("boolean");
  });
});

function noActionsActive(store: SecurityStore): boolean {
  return store.listActions().every((action) => action.state !== "active");
}

// ---------------------------------------------------------------------------
// scripts/basho-lockdown-helper.sh contract
// ---------------------------------------------------------------------------
//
// The helper is a root-only script, so every behaviour test runs a copy inside a
// throwaway temp directory with fixture executables and fixture state. Nothing
// here may touch the real firewall, service manager, or policy paths.
//
// Fixture injection contract (production defaults stay fixed and root-owned):
//   BASHO_LOCKDOWN_UFW            path to the ufw executable
//   BASHO_LOCKDOWN_SYSTEMCTL      path to the systemctl executable
//   BASHO_LOCKDOWN_SYSTEMD_RUN    path to the systemd-run executable (timer arming)
//   BASHO_LOCKDOWN_POLICY_DIR     root policy directory
//   BASHO_LOCKDOWN_STATE_DIR      root state directory
//   BASHO_LOCKDOWN_TEST_UID       test-only override for the invoking uid check
//                                 (simulates root for privilege/ownership checks)

const repoRoot = resolve(import.meta.dir, "../..");
const helperSourcePath = resolve(repoRoot, "scripts/basho-lockdown-helper.sh");
const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), `basho-lockdown-${prefix}-`));
  tempDirs.push(dir);
  return dir;
}

afterAll(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
});

const FAKE_UFW = `#!/usr/bin/env bash
set -u
log="\${BASHO_FAKE_LOG:?}"
rules="\${BASHO_FAKE_UFW_RULES:?}"
printf 'ufw %s\\n' "$*" >>"$log"

cmd="\${1:-}"
case "$cmd" in
  status)
    if [ "\${BASHO_FAKE_UFW_STATUS_FAIL:-0}" = "1" ]; then
      printf 'ERROR: problem running iptables\\n' >&2
      exit 1
    fi
    if [ -f "$rules" ]; then
      n=0
      while IFS= read -r line; do
        n=$((n + 1))
        printf '[%2d] %s\\n' "$n" "$line"
      done <"$rules"
    fi
    exit 0
    ;;
  --force|-f)
    shift
    exec "$0" "$@"
    ;;
  delete)
    shift
    while [ "\${1:-}" = "--force" ] || [ "\${1:-}" = "-f" ]; do shift; done
    pattern="$*"
    [ -f "$rules" ] || exit 0
    if printf '%s' "$pattern" | grep -Eq '^[0-9]+$'; then
      awk -v target="$pattern" '{ n = n + 1 } n != target { print }' "$rules" >"$rules.tmp"
      mv "$rules.tmp" "$rules"
      exit 0
    fi
    tokens=()
    for word in $pattern; do
      case "$word" in
        deny|allow|reject|limit|from|to|any|anywhere|in|out|on|comment|proto|tcp|udp|insert|prepend|status) continue ;;
        *[0-9]*) tokens+=("$word") ;;
      esac
    done
    while IFS= read -r line; do
      remove=0
      if [ "\${#tokens[@]}" -gt 0 ]; then
        remove=1
        for token in "\${tokens[@]}"; do
          if ! printf '%s' "$line" | grep -Fqi -- "$token"; then
            remove=0
            break
          fi
        done
      fi
      [ "$remove" = "1" ] || printf '%s\\n' "$line"
    done <"$rules" >"$rules.tmp"
    mv "$rules.tmp" "$rules"
    exit 0
    ;;
  deny|allow|reject|limit|insert|prepend|route)
    ip=""
    tag=""
    prev=""
    position=""
    for word in "$@"; do
      case "$word" in
        *.*.*.*|*:*) ip="$word" ;;
      esac
      if [ "$prev" = "comment" ]; then tag="$word"; fi
      if [ "$prev" = "insert" ] && printf '%s' "$word" | grep -Eq '^[0-9]+$'; then position="$word"; fi
      prev="$word"
    done
    if [ "$cmd" = "prepend" ]; then position="1"; fi
    action="DENY"
    if [ "$cmd" = "allow" ]; then action="ALLOW"; fi
    line="$(printf 'Anywhere                   %s IN     %s' "$action" "\${ip:-unknown}")"
    if [ -n "$tag" ]; then line="$line # $tag"; fi
    if [ -n "$position" ] && [ -f "$rules" ]; then
      awk -v pos="$position" -v text="$line" 'BEGIN { n = 0; placed = 0 } { n++; if (!placed && n == pos) { print text; placed = 1 } print } END { if (!placed) print text }' "$rules" >"$rules.tmp"
      mv "$rules.tmp" "$rules"
    else
      printf '%s\\n' "$line" >>"$rules"
    fi
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
`;

const FAKE_SYSTEMCTL = `#!/usr/bin/env bash
set -u
printf 'systemctl %s\\n' "$*" >>"\${BASHO_FAKE_LOG:?}"
exit 0
`;

const FAKE_SYSTEMD_RUN = `#!/usr/bin/env bash
set -u
printf 'systemd-run %s\\n' "$*" >>"\${BASHO_FAKE_LOG:?}"
exit 0
`;

interface HelperFixture {
  root: string;
  script: string;
  bin: string;
  policyDir: string;
  stateDir: string;
  logPath: string;
  rulesPath: string;
  env: Record<string, string>;
}

function installHelperFixture(options: { ufwStatusFails?: boolean } = {}): HelperFixture {
  const root = makeTempDir("helper");
  const bin = join(root, "bin");
  const policyDir = join(root, "etc");
  const stateDir = join(root, "state");
  const script = join(root, "basho-lockdown-helper.sh");
  const logPath = join(root, "calls.log");
  const rulesPath = join(root, "ufw-rules.txt");

  mkdirSync(bin, { recursive: true });
  mkdirSync(policyDir, { recursive: true });
  mkdirSync(stateDir, { recursive: true });
  copyFileSync(helperSourcePath, script);
  chmodSync(script, 0o700);
  writeFileSync(logPath, "", "utf8");
  writeFileSync(rulesPath, "22/tcp ALLOW IN Anywhere\n", "utf8");

  const executables: [string, string][] = [
    ["ufw", FAKE_UFW],
    ["systemctl", FAKE_SYSTEMCTL],
    ["systemd-run", FAKE_SYSTEMD_RUN],
  ];
  for (const [name, body] of executables) {
    const target = join(bin, name);
    writeFileSync(target, body, "utf8");
    chmodSync(target, 0o755);
  }

  const env: Record<string, string> = {
    BASHO_LOCKDOWN_UFW: join(bin, "ufw"),
    BASHO_LOCKDOWN_SYSTEMCTL: join(bin, "systemctl"),
    BASHO_LOCKDOWN_SYSTEMD_RUN: join(bin, "systemd-run"),
    BASHO_LOCKDOWN_POLICY_DIR: policyDir,
    BASHO_LOCKDOWN_STATE_DIR: stateDir,
    BASHO_LOCKDOWN_TEST_UID: "0",
    BASHO_FAKE_LOG: logPath,
    BASHO_FAKE_UFW_RULES: rulesPath,
    BASHO_FAKE_UFW_STATUS_FAIL: options.ufwStatusFails ? "1" : "0",
  };

  return { root, script, bin, policyDir, stateDir, logPath, rulesPath, env };
}

function runHelper(
  fixture: HelperFixture,
  args: string[],
  envOverrides: Record<string, string> = {},
): { code: number; stdout: string; stderr: string } {
  const result = spawnSync("bash", [fixture.script, ...args], {
    encoding: "utf8",
    timeout: 20_000,
    env: {
      PATH: `${fixture.bin}:/usr/local/bin:/usr/bin:/bin`,
      HOME: fixture.root,
      ...fixture.env,
      ...envOverrides,
    },
  });
  return {
    code: result.status ?? -1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function firewallMutations(fixture: HelperFixture): string[] {
  return readFileSync(fixture.logPath, "utf8")
    .split("\n")
    .filter((line) => line.startsWith("ufw ") && !/\bstatus\b/.test(line));
}

describe("scripts/basho-lockdown-helper.sh", () => {
  test("helper script exists and passes a bash syntax check", () => {
    expect(existsSync(helperSourcePath)).toBe(true);
    const result = spawnSync("bash", ["-n", helperSourcePath], { encoding: "utf8" });
    expect({ status: result.status, stderr: result.stderr }).toEqual({
      status: 0,
      stderr: "",
    });
  });

  test("helper exposes the fixture injection hooks used by these tests", () => {
    expect(existsSync(helperSourcePath)).toBe(true);
    const source = readFileSync(helperSourcePath, "utf8");
    const hooks = [
      "BASHO_LOCKDOWN_UFW",
      "BASHO_LOCKDOWN_SYSTEMCTL",
      "BASHO_LOCKDOWN_SYSTEMD_RUN",
      "BASHO_LOCKDOWN_POLICY_DIR",
      "BASHO_LOCKDOWN_STATE_DIR",
      "BASHO_LOCKDOWN_TEST_UID",
    ];
    for (const hook of hooks) {
      expect({ hook, present: source.includes(hook) }).toEqual({ hook, present: true });
    }
  });

  test("invalid and missing verbs exit 64 without mutating the firewall", () => {
    const fixture = installHelperFixture();

    expect(runHelper(fixture, ["poke-a-hole", PEER, "600", "op-bogus"]).code).toBe(64);
    expect(runHelper(fixture, []).code).toBe(64);

    expect(firewallMutations(fixture)).toEqual([]);
  });

  test("unprivileged execution is refused before any firewall mutation", () => {
    const fixture = installHelperFixture();
    const result = runHelper(fixture, ["deny-ip", PEER, "600", "op-unprivileged"], {
      BASHO_LOCKDOWN_TEST_UID: "1000",
    });

    expect(result.code).not.toBe(0);
    expect(firewallMutations(fixture)).toEqual([]);
  });

  test("protected management peers are refused with zero firewall mutations", () => {
    const fixture = installHelperFixture();
    const protectedIps = ["127.0.0.1", "::1", "::ffff:127.0.0.1", "100.64.0.5", "fd7a:115c:a1e0::1"];

    protectedIps.forEach((ip, index) => {
      const result = runHelper(fixture, ["deny-ip", ip, "600", `op-protected-${index}`]);
      expect({ ip, succeeded: result.code === 0 }).toEqual({ ip, succeeded: false });
    });

    expect(firewallMutations(fixture)).toEqual([]);
    expect(readFileSync(fixture.rulesPath, "utf8")).not.toContain("198.51.100");
  });

  test("deny-ip arms the rollback timer before the tagged rule and rolls back idempotently", () => {
    const fixture = installHelperFixture();

    const deny = runHelper(fixture, ["deny-ip", PEER, "600", "op-test-1"]);
    expect(deny.code).toBe(0);

    const calls = readFileSync(fixture.logPath, "utf8").split("\n").filter(Boolean);
    const timerIndex = calls.findIndex(
      (line) => line.startsWith("systemd-run") || line.startsWith("systemctl"),
    );
    const mutationIndex = calls.findIndex(
      (line) => line.startsWith("ufw ") && !/\bstatus\b/.test(line),
    );

    expect(timerIndex).toBeGreaterThan(-1);
    expect(mutationIndex).toBeGreaterThan(-1);
    expect(timerIndex).toBeLessThan(mutationIndex);

    const insertedRule = calls[mutationIndex]!;
    expect(insertedRule).toContain(PEER);
    expect(insertedRule).toContain("op-test-1");

    const activeInspect = runHelper(fixture, ["inspect", "op-test-1"]);
    expect(activeInspect.code).toBe(0);
    expect(activeInspect.stdout).toMatch(/\bactive\b/i);
    expect(readFileSync(fixture.rulesPath, "utf8")).toContain("22/tcp");

    expect(runHelper(fixture, ["rollback", "op-test-1"]).code).toBe(0);
    expect(runHelper(fixture, ["rollback", "op-test-1"]).code).toBe(0);

    const rulesAfterRollback = readFileSync(fixture.rulesPath, "utf8");
    expect(rulesAfterRollback).not.toContain(PEER);
    expect(rulesAfterRollback).toContain("22/tcp");

    const afterRollback = runHelper(fixture, ["inspect", "op-test-1"]);
    expect(afterRollback.code === 0 && /\bactive\b/i.test(afterRollback.stdout)).toBe(false);
  });

  test("isolate-lan refuses without a root policy file", () => {
    const fixture = installHelperFixture();
    const result = runHelper(fixture, ["isolate-lan", "600", "op-lan-missing"]);

    expect(result.code).not.toBe(0);
    expect(firewallMutations(fixture)).toEqual([]);
  });

  test("isolate-lan refuses when preserved paths cannot be verified", () => {
    const fixture = installHelperFixture({ ufwStatusFails: true });
    writeFileSync(
      join(fixture.policyDir, "lan-policy"),
      "LAN_INTERFACE=enp1s0\nLAN_PORTS=8188,7000\n",
      "utf8",
    );

    const result = runHelper(fixture, ["isolate-lan", "600", "op-lan-unverified"]);

    expect(result.code).not.toBe(0);
    expect(firewallMutations(fixture)).toEqual([]);
  });

  test("status reports readiness and isolate-lan arms timer before mutating when policy and tailscale path are verified", () => {
    const fixture = installHelperFixture();
    writeFileSync(
      fixture.rulesPath,
      "22/tcp ALLOW IN Anywhere\n41641/udp ALLOW IN Anywhere\nAnywhere ALLOW IN on tailscale0\n",
      "utf8",
    );
    writeFileSync(
      join(fixture.policyDir, "lan-policy.conf"),
      "LAN_INTERFACE=enp1s0\nLAN_PORTS=8188,7000\n",
      "utf8",
    );

    const status = runHelper(fixture, ["status"]);
    expect(status.code).toBe(0);
    expect(status.stdout).toContain("status=ready");
    expect(status.stdout).toContain("lan_policy=ready");

    const iso = runHelper(fixture, ["isolate-lan", "600", "op-lan-1"]);
    expect(iso.code).toBe(0);

    const calls = readFileSync(fixture.logPath, "utf8").split("\n").filter(Boolean);
    const timerIndex = calls.findIndex((line) => line.startsWith("systemd-run"));
    const mutationIndex = calls.findIndex(
      (line) => line.startsWith("ufw ") && !/\bstatus\b/.test(line),
    );
    expect(timerIndex).toBeGreaterThan(-1);
    expect(mutationIndex).toBeGreaterThan(timerIndex);

    expect(runHelper(fixture, ["inspect", "op-lan-1"]).stdout).toMatch(/\bactive\b/);
    expect(runHelper(fixture, ["rollback", "op-lan-1"]).code).toBe(0);
    expect(runHelper(fixture, ["inspect", "op-lan-1"]).stdout).toMatch(/\babsent\b/);
  });

  test("deny-ip rejects out-of-range ttl and unsafe operation IDs", () => {
    const fixture = installHelperFixture();
    expect(runHelper(fixture, ["deny-ip", PEER, "10", "op-bad-ttl"]).code).toBe(64);
    expect(runHelper(fixture, ["deny-ip", PEER, "9999", "op-bad-ttl"]).code).toBe(64);
    expect(runHelper(fixture, ["deny-ip", PEER, "600", "../escape"]).code).toBe(64);
    expect(firewallMutations(fixture)).toEqual([]);
  });
});

describe("DeadMansSwitch user-unit scope and production adapters", () => {
  test("verifies user@<uid>.service scope when uunit metadata is present", () => {
    const guard = new DeadMansSwitch();
    expect(
      guard.allows(WORKLOAD_TARGET, {
        workloads: [ENROLLED_WORKLOAD],
        currentProcess: {
          pid: ENROLLED_PID,
          uid: CURRENT_UID,
          startedAt: ENROLLED_STARTED_AT,
          comm: "ollama",
          unit: `user@${CURRENT_UID}.service`,
          uunit: ENROLLED_UNIT,
        },
        currentUid: CURRENT_UID,
      }),
    ).toBe(true);

    expect(
      guard.allows(WORKLOAD_TARGET, {
        workloads: [ENROLLED_WORKLOAD],
        currentProcess: {
          pid: ENROLLED_PID,
          uid: CURRENT_UID,
          startedAt: ENROLLED_STARTED_AT,
          comm: "ollama",
          unit: "user@2000.service",
          uunit: ENROLLED_UNIT,
        },
        currentUid: CURRENT_UID,
      }),
    ).toBe(false);
  });

  test("reconcile retries actions left in rolling_back state", async () => {
    let rollbackAttempts = 0;
    const harness = createEngine({
      adapterConfig: {
        rollback: async () => {
          rollbackAttempts += 1;
          return rollbackAttempts === 1 ? { state: "unknown" } : { state: "absent" };
        },
      },
    });
    await harness.engine.consider(scanFixture(), [PEER_DRAFT], [], harness.settings);
    const proposal = onlyProposal(harness.store);
    expect(await harness.engine.approve(proposal.id, proposal.revision, harness.settings)).toBe(
      true,
    );
    const action = onlyAction(harness.store);

    expect(await harness.engine.unlock(action.id)).toBe(false);
    expect(onlyAction(harness.store).state).toBe("rolling_back");

    await harness.engine.reconcile();
    expect(onlyAction(harness.store).state).toBe("rolled_back");
  });

  test("composite adapter routes network actions to sudo helper and workloads to user systemd", async () => {
    const calls: string[][] = [];
    const exec = async (argv: readonly string[]) => {
      calls.push([...argv]);
      if (argv.includes("status")) {
        return { exitCode: 0, stdout: "status=ready\nlan_policy=ready\n", stderr: "" };
      }
      if (argv.includes("inspect")) {
        return { exitCode: 0, stdout: "active\n", stderr: "" };
      }
      if (argv.includes("FreezerState")) {
        return { exitCode: 0, stdout: "frozen\n", stderr: "" };
      }
      return { exitCode: 0, stdout: "", stderr: "" };
    };

    const clock = createClock();
    const adapter = createCompositeLockdownAdapter({
      helper: createHelperLockdownAdapter({ exec, clock: clock.clock }),
      workload: createUserWorkloadLockdownAdapter({
        getWorkloads: () => [ENROLLED_WORKLOAD],
        exec,
        clock: clock.clock,
      }),
    });

    const netPre = await adapter.preflight(PEER_TARGET);
    expect(netPre.rollbackReady).toBe(true);
    expect(calls[0]).toEqual([
      "/usr/bin/sudo",
      "-n",
      "/usr/local/libexec/basho-lockdown-helper",
      "status",
    ]);

    const workloadAction: LockdownAction = {
      id: "act-work-1",
      proposalId: "prop-1",
      idempotencyKey: "prop-1:1",
      target: WORKLOAD_TARGET,
      state: "pending",
      createdAt: NOW,
      expiresAt: NOW + 120 * SECOND,
      updatedAt: NOW,
    };
    const applied = await adapter.apply(workloadAction);
    expect(applied.handle).toContain(ENROLLED_UNIT);
    const timerCallIdx = calls.findIndex((argv) => argv[0] === "/usr/bin/systemd-run");
    const freezeCallIdx = calls.findIndex(
      (argv) => argv[0] === "/usr/bin/systemctl" && argv.includes("freeze"),
    );
    expect(timerCallIdx).toBeGreaterThan(-1);
    expect(freezeCallIdx).toBeGreaterThan(timerCallIdx);

    expect(await adapter.inspect(workloadAction)).toEqual({
      state: "active",
      handle: `user-unit:${ENROLLED_UNIT}`,
    });
    expect(await adapter.rollback(workloadAction)).toEqual({ state: "absent" });
  });
});
