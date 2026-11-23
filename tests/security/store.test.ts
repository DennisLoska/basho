import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { SecurityStore } from "../../src/security/store";
import type {
  Evidence,
  ExposureEntry,
  LockdownProposal,
  PostureCheck,
  RuntimeOverrides,
  SecurityAlert,
  SecurityEvent,
  SecurityScan,
  Severity,
} from "../../src/security/types";

const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;
const SECOND_MS = 1_000;

function memoryStore(): SecurityStore {
  return new SecurityStore(":memory:");
}

function eventFixture(
  id: string,
  at: number,
  overrides: Partial<SecurityEvent> = {},
): SecurityEvent {
  return {
    id,
    source: "journal",
    category: "auth",
    severity: "warning",
    rule: "ssh_burst",
    target: "198.51.100.42",
    firstAt: at,
    lastAt: at,
    count: 1,
    isNoise: false,
    summary: `fixture ${id}`,
    ...overrides,
  };
}

function alertFixture(
  id: string,
  fingerprint: string,
  severity: Severity,
  createdAt: number,
  overrides: Partial<SecurityAlert> = {},
): SecurityAlert {
  return {
    id,
    fingerprint,
    severity,
    summary: `alert ${id}`,
    createdAt,
    ...overrides,
  };
}

function proposalFixture(overrides: Partial<LockdownProposal> = {}): LockdownProposal {
  return {
    id: "proposal-1",
    scanId: "scan-1",
    revision: 1,
    status: "pending",
    target: { kind: "deny_peer_ip", ip: "198.51.100.42" },
    evidenceIds: ["ev-1"],
    createdAt: 100,
    expiresAt: 60_000,
    leaseSeconds: 60,
    rollbackDescription: "Remove the leased peer rule",
    ...overrides,
  };
}

function scanFixture(overrides: Partial<SecurityScan> = {}): SecurityScan {
  const capturedAt = 1_700_000_000_000;

  const evidence: Evidence[] = [
    {
      id: "ev-posture-ufw",
      kind: "criterion",
      facts: { active: true, ruleCount: 12, defaultPolicy: "deny", lastError: null },
    },
    {
      id: "ev-listener-22",
      kind: "listener",
      facts: { port: 22, address: "0.0.0.0", protocol: "tcp" },
    },
  ];

  const checks: PostureCheck[] = [
    {
      id: "firewall_ufw",
      category: "host",
      title: "UFW firewall",
      status: "pass",
      summary: "ufw is active with a default deny policy",
      remediation: "systemctl enable --now ufw",
      evidenceIds: ["ev-posture-ufw"],
      sourceCoverage: { ufw: "complete", nftables: "unavailable" },
    },
    {
      id: "ssh_hardening",
      category: "auth",
      title: "SSH hardening",
      status: "warn",
      summary: "Password authentication is enabled",
      evidenceIds: [],
      sourceCoverage: { sshd: "partial" },
    },
    {
      id: "package_updates",
      category: "packages",
      title: "Package updates",
      status: "unknown",
      summary: "Update check unavailable",
      evidenceIds: [],
      sourceCoverage: { pacman: "unavailable" },
    },
  ];

  const exposure: ExposureEntry[] = [
    {
      id: "exposure-ssh",
      listener: {
        id: "listener-ssh",
        protocol: "tcp",
        address: "0.0.0.0",
        port: 22,
        family: 4,
        pid: 4242,
        process: "sshd",
        interfaceName: "eth0",
      },
      reachability: "exposed_lan",
      firewallV4: "allow",
      firewallV6: "deny",
      publication: "none",
      expected: true,
      evidenceIds: ["ev-listener-22"],
    },
  ];

  return {
    id: "scan-1",
    trigger: "scheduled",
    startedAt: capturedAt,
    finishedAt: capturedAt + 5_000,
    snapshot: {
      id: "snapshot-1",
      capturedAt,
      checks,
      evidence,
    },
    exposure,
    findings: [
      {
        id: "finding-1",
        source: "deterministic",
        severity: "warning",
        summary: "Password authentication is enabled",
        evidenceIds: ["ev-posture-ufw"],
      },
      {
        id: "finding-2",
        source: "ai",
        severity: "critical",
        summary: "LAN exposed SSH listener",
        evidenceIds: ["ev-listener-22"],
      },
    ],
    trail: {
      steps: [
        {
          tool: "read_posture_detail",
          reason: "Confirm firewall state",
          outcome: "ok",
          evidenceIds: ["ev-posture-ufw"],
        },
        {
          tool: "read_recent_events",
          reason: "Check auth failures",
          outcome: "rejected",
          evidenceIds: [],
        },
        {
          tool: "verdict",
          reason: "Summarize the host posture",
          outcome: "ok",
          evidenceIds: ["ev-listener-22"],
        },
      ],
    },
    aiStatus: "ready",
    verdict: {
      kind: "warn",
      confidence: 0.82,
      summary: "SSH is reachable from the LAN",
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Empty store
// ---------------------------------------------------------------------------

test("an empty store reports nulls and empty collections", () => {
  const store = memoryStore();
  try {
    expect(store.latestScan()).toBeNull();
    expect(store.getCursor("journal")).toBeNull();
    expect(store.recentEvents(0, 10)).toEqual([]);
    expect(store.hourlyEvents(Date.now())).toHaveLength(24);
    expect(store.listProposals()).toEqual([]);
    expect(store.listActions()).toEqual([]);
    expect(store.recentAlerts(0)).toEqual([]);
    expect(store.claimDeliveries(0, 10, SECOND_MS)).toEqual([]);
    expect(store.channelHealth()).toEqual({});
    expect(store.readOverrides()).toEqual({});
  } finally {
    store.close();
  }
});

// ---------------------------------------------------------------------------
// Proposal claiming and revision contention
// ---------------------------------------------------------------------------

test("claimProposal requires the matching revision and returns one pending action", () => {
  const store = memoryStore();
  try {
    store.insertProposal(proposalFixture({ id: "proposal-1", revision: 1 }));

    expect(store.claimProposal("proposal-1", 0, 200)).toBeNull();
    expect(store.claimProposal("missing-proposal", 1, 200)).toBeNull();

    const claim = store.claimProposal("proposal-1", 1, 200);
    expect(claim).not.toBeNull();
    expect(claim).toMatchObject({
      proposalId: "proposal-1",
      idempotencyKey: "proposal-1:1",
      state: "pending",
      expiresAt: 200 + 60 * SECOND_MS,
      target: { kind: "deny_peer_ip", ip: "198.51.100.42" },
    });

    expect(store.claimProposal("proposal-1", 1, 200)).toBeNull();
    expect(store.claimProposal("proposal-1", 2, 200)).toBeNull();

    expect(store.listActions().map((action) => action.id)).toEqual([claim!.id]);
    expect(store.listProposals()).toHaveLength(1);
    expect(store.listProposals()[0]!.status).toBe("claimed");
  } finally {
    store.close();
  }
});

test("claimProposal refuses a proposal at or past its expiry", () => {
  const store = memoryStore();
  try {
    store.insertProposal(
      proposalFixture({ id: "proposal-expiring", createdAt: 100, expiresAt: 1_000, leaseSeconds: 30 }),
    );

    expect(store.claimProposal("proposal-expiring", 1, 1_000)).toBeNull();

    const claim = store.claimProposal("proposal-expiring", 1, 999);
    expect(claim).not.toBeNull();
    expect(claim!.expiresAt).toBe(999 + 30 * SECOND_MS);
    expect(store.listActions()).toHaveLength(1);
  } finally {
    store.close();
  }
});

test("rejectProposal is compare-and-set on revision and pending status", () => {
  const store = memoryStore();
  try {
    store.insertProposal(proposalFixture({ id: "proposal-reject", expiresAt: 50_000 }));

    expect(store.rejectProposal("proposal-reject", 2, 200)).toBe(false);
    expect(store.rejectProposal("missing-proposal", 1, 200)).toBe(false);
    expect(store.rejectProposal("proposal-reject", 1, 200)).toBe(true);
    expect(store.rejectProposal("proposal-reject", 1, 200)).toBe(false);
    expect(store.claimProposal("proposal-reject", 1, 200)).toBeNull();
    expect(store.listProposals()[0]!.status).toBe("rejected");
    expect(store.listActions()).toEqual([]);
  } finally {
    store.close();
  }
});

test("expireProposals marks only pending proposals past their deadline", () => {
  const store = memoryStore();
  try {
    store.insertProposal(proposalFixture({ id: "proposal-old", expiresAt: 5_000 }));
    store.insertProposal(proposalFixture({ id: "proposal-new", expiresAt: 50_000 }));
    store.insertProposal(proposalFixture({ id: "proposal-claimed", expiresAt: 5_000 }));

    expect(store.claimProposal("proposal-claimed", 1, 1_000)).not.toBeNull();

    store.expireProposals(10_000);

    const statuses = new Map(store.listProposals().map((proposal) => [proposal.id, proposal.status]));
    expect(statuses.get("proposal-old")).toBe("expired");
    expect(statuses.get("proposal-new")).toBe("pending");
    expect(statuses.get("proposal-claimed")).toBe("claimed");
    expect(store.claimProposal("proposal-old", 1, 10_000)).toBeNull();
  } finally {
    store.close();
  }
});

// ---------------------------------------------------------------------------
// Action state transitions
// ---------------------------------------------------------------------------

test("transitionAction compares the current state and persists the rollback handle", () => {
  const store = memoryStore();
  try {
    store.insertProposal(
      proposalFixture({ id: "proposal-action", expiresAt: 60_000, leaseSeconds: 60 }),
    );
    const action = store.claimProposal("proposal-action", 1, 1_000);
    expect(action).not.toBeNull();

    expect(store.transitionAction(action!.id, "active", "rolling_back", 1_100)).toBe(false);
    expect(store.transitionAction(action!.id, "pending", "active", 1_100, "handle-1")).toBe(true);

    const active = store.listActions().find((entry) => entry.id === action!.id)!;
    expect(active.state).toBe("active");
    expect(active.rollbackHandle).toBe("handle-1");
    expect(active.updatedAt).toBe(1_100);

    expect(store.transitionAction(action!.id, "pending", "failed", 1_200)).toBe(false);
    expect(store.transitionAction(action!.id, "active", "rolling_back", 1_300, "handle-2")).toBe(true);
    expect(store.transitionAction(action!.id, "rolling_back", "rolled_back", 1_400)).toBe(true);
    expect(store.transitionAction("missing-action", "pending", "active", 1_500)).toBe(false);

    const rolledBack = store.listActions().find((entry) => entry.id === action!.id)!;
    expect(rolledBack.state).toBe("rolled_back");
    expect(rolledBack.rollbackHandle).toBe("handle-2");
    expect(rolledBack.updatedAt).toBe(1_400);
    expect(store.transitionAction(action!.id, "active", "failed", 1_600)).toBe(false);
  } finally {
    store.close();
  }
});

// ---------------------------------------------------------------------------
// Alert cooldown, outbox, leases, and channel health
// ---------------------------------------------------------------------------

test("enqueueAlert creates one outbox delivery per channel", () => {
  const store = memoryStore();
  try {
    const createdAt = 1_000_000;
    const alert = alertFixture("alert-1", "auth:ssh_burst:198.51.100.42", "warning", createdAt);

    expect(store.enqueueAlert(alert, ["in-app", "desktop", "ntfy"], 900_000)).toBe(true);

    const deliveries = store.claimDeliveries(createdAt, 10, 30_000);
    expect(deliveries.map((delivery) => delivery.channel).sort()).toEqual([
      "desktop",
      "in-app",
      "ntfy",
    ]);
    expect(new Set(deliveries.map((delivery) => delivery.id)).size).toBe(3);
    expect(deliveries.every((delivery) => delivery.alert.id === "alert-1")).toBe(true);
    expect(deliveries.every((delivery) => delivery.claimToken.length > 0)).toBe(true);
    expect(deliveries.every((delivery) => typeof delivery.attempts === "number")).toBe(true);
  } finally {
    store.close();
  }
});

test("enqueueAlert deduplicates a fingerprint inside the cooldown", () => {
  const store = memoryStore();
  try {
    const createdAt = 1_000_000;
    const cooldown = 900_000;
    const fingerprint = "auth:ssh_burst:198.51.100.42";

    expect(
      store.enqueueAlert(alertFixture("alert-1", fingerprint, "warning", createdAt), ["ntfy"], cooldown),
    ).toBe(true);
    expect(
      store.enqueueAlert(
        alertFixture("alert-2", fingerprint, "warning", createdAt + 1_000),
        ["ntfy"],
        cooldown,
      ),
    ).toBe(false);
    expect(
      store.enqueueAlert(
        alertFixture("alert-3", fingerprint, "info", createdAt + 2_000),
        ["ntfy"],
        cooldown,
      ),
    ).toBe(false);
    expect(
      store.enqueueAlert(
        alertFixture("alert-4", "network:unexpected_listener:8080", "warning", createdAt + 3_000),
        ["ntfy"],
        cooldown,
      ),
    ).toBe(true);
    expect(
      store.enqueueAlert(
        alertFixture("alert-5", fingerprint, "info", createdAt + cooldown + 4_000),
        ["ntfy"],
        cooldown,
      ),
    ).toBe(true);

    const alerts = store.recentAlerts(0);
    expect(alerts.map((alert) => alert.id).sort()).toEqual(["alert-1", "alert-4", "alert-5"]);
    expect(store.recentAlerts(createdAt + 3_500).map((alert) => alert.id)).toEqual(["alert-5"]);

    const deliveries = store.claimDeliveries(createdAt + cooldown + 5_000, 20, 60_000);
    expect(deliveries).toHaveLength(3);
  } finally {
    store.close();
  }
});

test("enqueueAlert bypasses the cooldown only for severity escalation", () => {
  const store = memoryStore();
  try {
    const createdAt = 2_000_000;
    const cooldown = 900_000;
    const fingerprint = "auth:ssh_burst:203.0.113.9";

    const enqueue = (id: string, severity: Severity, offset: number) =>
      store.enqueueAlert(
        alertFixture(id, fingerprint, severity, createdAt + offset),
        ["in-app"],
        cooldown,
      );

    expect(enqueue("alert-a1", "info", 0)).toBe(true);
    expect(enqueue("alert-a2", "warning", 1)).toBe(true);
    expect(enqueue("alert-a3", "warning", 2)).toBe(false);
    expect(enqueue("alert-a4", "critical", 3)).toBe(true);
    expect(enqueue("alert-a5", "warning", 4)).toBe(false);
    expect(enqueue("alert-a6", "breach", 5)).toBe(true);
    expect(enqueue("alert-a7", "critical", 6)).toBe(false);

    expect(store.recentAlerts(0).map((alert) => alert.id).sort()).toEqual([
      "alert-a1",
      "alert-a2",
      "alert-a4",
      "alert-a6",
    ]);
  } finally {
    store.close();
  }
});

test("claimDeliveries leases with a fresh token and rejects stale settlement", () => {
  const store = memoryStore();
  try {
    const createdAt = 5_000_000;
    store.enqueueAlert(
      alertFixture("lease-alert", "auth:ssh_burst:lease", "warning", createdAt),
      ["ntfy"],
      900_000,
    );

    const first = store.claimDeliveries(createdAt, 5, 30_000)[0]!;
    expect(first).toBeDefined();
    expect(store.settleDelivery(first.id, "stale-token", createdAt + 1, "sent")).toBe(false);
    expect(store.settleDelivery("missing-delivery", first.claimToken, createdAt + 1, "sent")).toBe(false);

    expect(store.claimDeliveries(createdAt + 29_999, 5, 30_000)).toHaveLength(0);

    const second = store.claimDeliveries(createdAt + 30_001, 5, 30_000)[0]!;
    expect(second.id).toBe(first.id);
    expect(second.claimToken).not.toBe(first.claimToken);
    expect(second.attempts).toBeGreaterThan(first.attempts);

    expect(store.settleDelivery(first.id, first.claimToken, createdAt + 30_002, "sent")).toBe(false);
    expect(store.settleDelivery(second.id, second.claimToken, createdAt + 30_003, "sent")).toBe(true);
    expect(store.claimDeliveries(createdAt + 100_000, 5, 30_000)).toHaveLength(0);
    expect(store.channelHealth().ntfy).toEqual({ status: "sent", at: createdAt + 30_003 });
  } finally {
    store.close();
  }
});

test("a retry schedules a later claim and reports retrying channel health", () => {
  const store = memoryStore();
  try {
    const createdAt = 6_000_000;
    store.enqueueAlert(
      alertFixture("retry-alert", "auth:ssh_burst:retry", "critical", createdAt),
      ["ntfy"],
      900_000,
    );

    const leased = store.claimDeliveries(createdAt, 5, 30_000)[0]!;
    expect(store.settleDelivery(leased.id, leased.claimToken, createdAt + 100, { retryAt: createdAt + 60_000 })).toBe(true);
    expect(store.channelHealth().ntfy).toEqual({ status: "retrying", at: createdAt + 100 });

    expect(store.claimDeliveries(createdAt + 59_999, 5, 30_000)).toHaveLength(0);

    const retried = store.claimDeliveries(createdAt + 60_000, 5, 30_000)[0]!;
    expect(retried.id).toBe(leased.id);
    expect(retried.claimToken).not.toBe(leased.claimToken);

    expect(store.settleDelivery(retried.id, retried.claimToken, createdAt + 60_100, "sent")).toBe(true);
    expect(store.channelHealth().ntfy).toEqual({ status: "sent", at: createdAt + 60_100 });
  } finally {
    store.close();
  }
});

test("a failed delivery is terminal and marks channel health failed", () => {
  const store = memoryStore();
  try {
    const createdAt = 7_000_000;
    store.enqueueAlert(
      alertFixture("failed-alert", "network:unexpected_listener:8080", "warning", createdAt),
      ["desktop"],
      900_000,
    );

    const delivery = store.claimDeliveries(createdAt, 5, 30_000)[0]!;
    expect(store.settleDelivery(delivery.id, delivery.claimToken, createdAt + 100, "failed")).toBe(true);
    expect(store.channelHealth().desktop).toEqual({ status: "failed", at: createdAt + 100 });
    expect(store.claimDeliveries(createdAt + 200_000, 5, 30_000)).toHaveLength(0);
  } finally {
    store.close();
  }
});

test("dismissAlert hides the alert without changing its delivery", () => {
  const store = memoryStore();
  try {
    const createdAt = 8_000_000;
    store.enqueueAlert(
      alertFixture("dismiss-alert", "auth:ssh_burst:dismiss", "warning", createdAt),
      ["ntfy"],
      900_000,
    );

    expect(store.recentAlerts(0)).toHaveLength(1);
    expect(store.dismissAlert("dismiss-alert", createdAt + 1)).toBe(true);
    expect(store.recentAlerts(0)).toEqual([]);

    const deliveries = store.claimDeliveries(createdAt + 2, 10, 30_000);
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0]!.alert.id).toBe("dismiss-alert");
  } finally {
    store.close();
  }
});

// ---------------------------------------------------------------------------
// Scan round-trip
// ---------------------------------------------------------------------------

test("saveScan and latestScan preserve every scan field", () => {
  const store = memoryStore();
  try {
    const scan = scanFixture();
    store.saveScan(scan);
    expect(store.latestScan()).toEqual(scan);

    const withoutVerdict = scanFixture({
      id: "scan-2",
      trigger: "manual",
      startedAt: scan.startedAt + 10_000,
      finishedAt: scan.finishedAt + 10_000,
      aiStatus: "unconfigured",
      verdict: undefined,
    });
    store.saveScan(withoutVerdict);
    expect(store.latestScan()).toEqual(withoutVerdict);
    expect(store.latestScan()!.verdict).toBeUndefined();
  } finally {
    store.close();
  }
});

test("saveScan keeps children attached to the scan that owns them", () => {
  const store = memoryStore();
  try {
    store.saveScan(scanFixture({ id: "scan-old", startedAt: 1_000, finishedAt: 2_000 }));

    const newest = scanFixture({
      id: "scan-new",
      startedAt: 3_000,
      finishedAt: 4_000,
      snapshot: {
        ...scanFixture().snapshot,
        id: "snapshot-new",
        checks: [
          {
            id: "kernel_sysctl",
            category: "host",
            title: "Kernel sysctl",
            status: "fail",
            summary: "ip_forward is enabled",
            evidenceIds: [],
            sourceCoverage: { sysctl: "complete" },
          },
        ],
        evidence: [
          { id: "ev-sysctl", kind: "criterion", facts: { ip_forward: true } },
        ],
      },
      exposure: [],
      findings: [
        {
          id: "finding-ai",
          source: "ai",
          severity: "critical",
          summary: "Forwarding enabled",
          evidenceIds: ["ev-sysctl"],
        },
      ],
      aiStatus: "ready",
      verdict: { kind: "breach", confidence: 0.99, summary: "Forwarding enabled" },
    });
    store.saveScan(newest);

    const latest = store.latestScan()!;
    expect(latest.id).toBe("scan-new");
    expect(latest.snapshot.id).toBe("snapshot-new");
    expect(latest.snapshot.checks).toHaveLength(1);
    expect(latest.snapshot.checks[0]!.evidenceIds).toEqual([]);
    expect(latest.snapshot.evidence).toEqual([{ id: "ev-sysctl", kind: "criterion", facts: { ip_forward: true } }]);
    expect(latest.exposure).toEqual([]);
    expect(latest.findings).toHaveLength(1);
    expect(latest.verdict).toEqual({ kind: "breach", confidence: 0.99, summary: "Forwarding enabled" });
  } finally {
    store.close();
  }
});

// ---------------------------------------------------------------------------
// Event batching, cursor compare-and-set, dedupe, bursts, and hourly buckets
// ---------------------------------------------------------------------------

test("commitEventBatch rejects a stale expected cursor without committing", () => {
  const store = memoryStore();
  try {
    expect(store.getCursor("journal")).toBeNull();

    expect(
      store.commitEventBatch({
        events: [eventFixture("cursor-1", 1_000)],
        cursor: { source: "journal", expected: null, next: "cursor-a" },
        burstWindowMs: 1_000,
      }),
    ).toBe(true);
    expect(store.getCursor("journal")).toBe("cursor-a");

    expect(
      store.commitEventBatch({
        events: [eventFixture("cursor-2", 2_000, { rule: "other_rule" })],
        cursor: { source: "journal", expected: null, next: "cursor-b" },
        burstWindowMs: 1_000,
      }),
    ).toBe(false);
    expect(store.getCursor("journal")).toBe("cursor-a");
    expect(store.recentEvents(0, 10).map((event) => event.id)).toEqual(["cursor-1"]);

    expect(
      store.commitEventBatch({
        events: [eventFixture("cursor-2", 2_000, { rule: "other_rule" })],
        cursor: { source: "journal", expected: "cursor-a", next: "cursor-b" },
        burstWindowMs: 1_000,
      }),
    ).toBe(true);
    expect(store.getCursor("journal")).toBe("cursor-b");
    expect(store.recentEvents(0, 10).map((event) => event.id).sort()).toEqual([
      "cursor-1",
      "cursor-2",
    ]);
    expect(store.getCursor("socket")).toBeNull();
  } finally {
    store.close();
  }
});

test("commitEventBatch without a cursor leaves the stored cursor untouched", () => {
  const store = memoryStore();
  try {
    store.commitEventBatch({
      events: [eventFixture("cursorless-1", 1_000)],
      burstWindowMs: 1_000,
    });
    expect(store.getCursor("journal")).toBeNull();

    store.commitEventBatch({
      events: [eventFixture("cursorless-2", 2_000)],
      cursor: { source: "journal", expected: null, next: "cursor-x" },
      burstWindowMs: 1_000,
    });
    store.commitEventBatch({
      events: [eventFixture("cursorless-3", 3_000)],
      burstWindowMs: 1_000,
    });
    expect(store.getCursor("journal")).toBe("cursor-x");
    expect(store.recentEvents(0, 10)).toHaveLength(3);
  } finally {
    store.close();
  }
});

test("commitEventBatch deduplicates repeated event IDs across batches", () => {
  const store = memoryStore();
  try {
    const base = 100_000;
    store.commitEventBatch({
      events: [eventFixture("dup-1", base, { rule: "rule_a" })],
      cursor: { source: "journal", expected: null, next: "dup-c1" },
      burstWindowMs: 1_000,
    });
    store.commitEventBatch({
      events: [
        eventFixture("dup-1", base, { rule: "rule_a" }),
        eventFixture("dup-2", base + 1_000_000, { rule: "rule_b" }),
      ],
      cursor: { source: "journal", expected: "dup-c1", next: "dup-c2" },
      burstWindowMs: 1_000,
    });

    const events = store.recentEvents(0, 10);
    expect(events).toHaveLength(2);
    expect(events.reduce((total, event) => total + event.count, 0)).toBe(2);
    expect(events.find((event) => event.rule === "rule_a")!.count).toBe(1);
  } finally {
    store.close();
  }
});

test("commitEventBatch aggregates matching events inside the burst window and splits outside it", () => {
  const store = memoryStore();
  try {
    const base = 10_000_000;
    const burstWindowMs = 2_000;

    expect(
      store.commitEventBatch({
        events: [eventFixture("burst-1", base, { rule: "ssh_burst", target: "198.51.100.42" })],
        cursor: { source: "journal", expected: null, next: "burst-c1" },
        burstWindowMs,
      }),
    ).toBe(true);
    expect(
      store.commitEventBatch({
        events: [eventFixture("burst-2", base + 500, { rule: "ssh_burst", target: "198.51.100.42" })],
        cursor: { source: "journal", expected: "burst-c1", next: "burst-c2" },
        burstWindowMs,
      }),
    ).toBe(true);
    expect(
      store.commitEventBatch({
        events: [eventFixture("burst-3", base + 3_000, { rule: "ssh_burst", target: "198.51.100.42" })],
        cursor: { source: "journal", expected: "burst-c2", next: "burst-c3" },
        burstWindowMs,
      }),
    ).toBe(true);
    expect(
      store.commitEventBatch({
        events: [
          eventFixture("burst-4", base + 4_000, {
            rule: "ssh_burst",
            target: "198.51.100.42",
            isNoise: true,
            category: "network",
          }),
          eventFixture("burst-5", base + 4_100, { rule: "ssh_burst", target: "203.0.113.9" }),
        ],
        cursor: { source: "journal", expected: "burst-c3", next: "burst-c4" },
        burstWindowMs,
      }),
    ).toBe(true);

    const shape = store.recentEvents(0, 20).map((event) => ({
      rule: event.rule,
      target: event.target,
      isNoise: event.isNoise,
      count: event.count,
      firstAt: event.firstAt,
      lastAt: event.lastAt,
    }));

    expect(shape).toHaveLength(4);
    expect(shape).toEqual(
      expect.arrayContaining([
        {
          rule: "ssh_burst",
          target: "198.51.100.42",
          isNoise: false,
          count: 2,
          firstAt: base,
          lastAt: base + 500,
        },
        {
          rule: "ssh_burst",
          target: "198.51.100.42",
          isNoise: false,
          count: 1,
          firstAt: base + 3_000,
          lastAt: base + 3_000,
        },
        {
          rule: "ssh_burst",
          target: "198.51.100.42",
          isNoise: true,
          count: 1,
          firstAt: base + 4_000,
          lastAt: base + 4_000,
        },
        {
          rule: "ssh_burst",
          target: "203.0.113.9",
          isNoise: false,
          count: 1,
          firstAt: base + 4_100,
          lastAt: base + 4_100,
        },
      ]),
    );
  } finally {
    store.close();
  }
});

test("hourlyEvents returns 24 UTC buckets and keeps signal and noise exact across hour boundaries", () => {
  const store = memoryStore();
  try {
    const now = Date.UTC(2026, 0, 15, 12, 30, 0);
    const currentHour = Math.floor(now / HOUR_MS) * HOUR_MS;

    store.commitEventBatch({
      events: [
        eventFixture("h1", currentHour + 1_000, { rule: "ssh_burst" }),
        eventFixture("h2", currentHour + 2_000, { rule: "ssh_burst" }),
        eventFixture("h3", currentHour + 3_000, { rule: "ssh_burst" }),
        eventFixture("h4", currentHour + 5_000, {
          rule: "multicast_noise",
          category: "network",
          isNoise: true,
          severity: "info",
        }),
        eventFixture("h5", currentHour - HOUR_MS + 60_000, { rule: "ssh_prev" }),
        eventFixture("h6", currentHour - 500, { rule: "ssh_cross" }),
        eventFixture("h7", currentHour + 500, { rule: "ssh_cross" }),
      ],
      burstWindowMs: 2_000,
    });

    const buckets = store.hourlyEvents(now);
    expect(buckets).toHaveLength(24);

    const byHour = new Map(buckets.map((bucket) => [bucket.hour, bucket]));
    expect(byHour.get(currentHour)).toEqual({ hour: currentHour, signal: 4, noise: 1 });
    expect(byHour.get(currentHour - HOUR_MS)).toEqual({
      hour: currentHour - HOUR_MS,
      signal: 2,
      noise: 0,
    });
    expect(byHour.get(currentHour - 23 * HOUR_MS)).toEqual({
      hour: currentHour - 23 * HOUR_MS,
      signal: 0,
      noise: 0,
    });

    expect(buckets[0]!.hour).toBe(currentHour - 23 * HOUR_MS);
    expect(buckets.at(-1)!.hour).toBe(currentHour);
    for (let index = 1; index < buckets.length; index += 1) {
      expect(buckets[index]!.hour - buckets[index - 1]!.hour).toBe(HOUR_MS);
    }
  } finally {
    store.close();
  }
});

test("hourlyEvents shifts its window with the supplied clock", () => {
  const store = memoryStore();
  try {
    const now = Date.UTC(2026, 5, 1, 0, 5, 0);
    const currentHour = Math.floor(now / HOUR_MS) * HOUR_MS;

    store.commitEventBatch({
      events: [eventFixture("window-1", currentHour + 1_000, { rule: "ssh_burst" })],
      burstWindowMs: 1_000,
    });

    const current = store.hourlyEvents(now);
    expect(current.at(-1)!.hour).toBe(currentHour);
    expect(current.at(-1)!.signal).toBe(1);

    const later = store.hourlyEvents(now + 3 * HOUR_MS);
    expect(later.at(-1)!.hour).toBe(currentHour + 3 * HOUR_MS);
    expect(later.at(-1)!.signal).toBe(0);
    expect(later.find((bucket) => bucket.hour === currentHour)!.signal).toBe(1);
  } finally {
    store.close();
  }
});

test("recentEvents filters by time window, category, and limit", () => {
  const store = memoryStore();
  try {
    store.commitEventBatch({
      events: [
        eventFixture("ev-auth-old", 1_000, { category: "auth", rule: "ssh_failed" }),
        eventFixture("ev-auth-new", 20_000, { category: "auth", rule: "ssh_burst" }),
        eventFixture("ev-net", 30_000, { category: "network", rule: "listener_drift" }),
      ],
      burstWindowMs: 1_000,
    });

    expect(store.recentEvents(0, 10).map((event) => event.id).sort()).toEqual([
      "ev-auth-new",
      "ev-auth-old",
      "ev-net",
    ]);
    expect(store.recentEvents(15_000, 10).map((event) => event.id).sort()).toEqual([
      "ev-auth-new",
      "ev-net",
    ]);
    expect(store.recentEvents(0, 10, "network").map((event) => event.id)).toEqual(["ev-net"]);
    expect(store.recentEvents(0, 1).map((event) => event.id)).toEqual(["ev-net"]);
  } finally {
    store.close();
  }
});

// ---------------------------------------------------------------------------
// Runtime overrides
// ---------------------------------------------------------------------------

test("writeOverrides and readOverrides round-trip runtime overrides", () => {
  const store = memoryStore();
  try {
    expect(store.readOverrides()).toEqual({});

    const overrides: RuntimeOverrides = {
      mode: "monitor",
      scanIntervalMinutes: 30,
      criteria: { firewall_ufw: false, ssh_hardening: true },
    };
    store.writeOverrides(overrides);
    expect(store.readOverrides()).toEqual(overrides);
  } finally {
    store.close();
  }
});

// ---------------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------------

test("prune keeps only the newest 50 scans", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-prune-"));
  const dbPath = join(root, "scans.db");
  try {
    const store = new SecurityStore(dbPath);
    try {
      for (let index = 1; index <= 55; index += 1) {
        store.saveScan(
          scanFixture({
            id: `scan-${index}`,
            startedAt: index * 1_000,
            finishedAt: index * 1_000 + 10,
            snapshot: { ...scanFixture().snapshot, id: `snapshot-${index}` },
          }),
        );
      }
      store.prune(100_000);
      expect(store.latestScan()!.id).toBe("scan-55");
    } finally {
      store.close();
    }

    // Retention of scans is not otherwise observable through the public API.
    const db = new Database(dbPath, { readonly: true });
    try {
      const row = db.query("select count(*) as n from scans").get() as { n: number } | null;
      expect(row?.n).toBe(50);
    } finally {
      db.close();
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("prune drops events older than 14 days", () => {
  const store = memoryStore();
  try {
    const now = 100 * DAY_MS;
    store.commitEventBatch({
      events: [
        eventFixture("event-old", now - 15 * DAY_MS, { rule: "old_rule" }),
        eventFixture("event-recent", now - 13 * DAY_MS, { rule: "recent_rule" }),
      ],
      burstWindowMs: 1_000,
    });

    store.prune(now);
    expect(store.recentEvents(0, 100).map((event) => event.id)).toEqual(["event-recent"]);
  } finally {
    store.close();
  }
});

test("prune keeps unresolved actions and drops terminal actions past 90 days", () => {
  const store = memoryStore();
  try {
    const start = 50 * DAY_MS;

    store.insertProposal(
      proposalFixture({ id: "proposal-terminal", expiresAt: start + 600_000 }),
    );
    const terminal = store.claimProposal("proposal-terminal", 1, start);
    expect(terminal).not.toBeNull();
    expect(store.transitionAction(terminal!.id, "pending", "active", start + 1_000)).toBe(true);
    expect(store.transitionAction(terminal!.id, "active", "failed", start + 2_000)).toBe(true);

    store.insertProposal(proposalFixture({ id: "proposal-open", expiresAt: start + 600_000 }));
    const open = store.claimProposal("proposal-open", 1, start);
    expect(open).not.toBeNull();
    expect(store.transitionAction(open!.id, "pending", "active", start + 1_000)).toBe(true);

    store.prune(start + 2_000 + 90 * DAY_MS + 1);

    expect(store.listActions().map((action) => action.id)).toEqual([open!.id]);
  } finally {
    store.close();
  }
});

// ---------------------------------------------------------------------------
// File-backed database: WAL, permissions, reopen, and two-connection contention
// ---------------------------------------------------------------------------

test("file-backed store uses WAL, private permissions, and survives close and reopen", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-store-"));
  const dbPath = join(root, "private", "state.db");
  try {
    const scan = scanFixture();
    const overrides: RuntimeOverrides = {
      mode: "approve",
      scanIntervalMinutes: 15,
      criteria: { ssh_hardening: false },
    };

    const store = new SecurityStore(dbPath);
    try {
      store.saveScan(scan);
      store.writeOverrides(overrides);
      store.commitEventBatch({
        events: [eventFixture("persisted-event", 5_000)],
        cursor: { source: "journal", expected: null, next: "cursor-1" },
        burstWindowMs: 1_000,
      });

      expect(existsSync(dbPath)).toBe(true);
      expect(existsSync(`${dbPath}-wal`)).toBe(true);
      expect(statSync(dbPath).mode & 0o777).toBe(0o600);
      expect(statSync(join(root, "private")).mode & 0o777).toBe(0o700);
    } finally {
      store.close();
    }

    const reopened = new SecurityStore(dbPath);
    try {
      expect(reopened.latestScan()).toEqual(scan);
      expect(reopened.readOverrides()).toEqual(overrides);
      expect(reopened.getCursor("journal")).toBe("cursor-1");
      expect(reopened.recentEvents(0, 10).map((event) => event.id)).toEqual(["persisted-event"]);
    } finally {
      reopened.close();
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("two connections racing one proposal produce a single winner", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-race-"));
  const dbPath = join(root, "race.db");
  const first = new SecurityStore(dbPath);
  const second = new SecurityStore(dbPath);
  try {
    first.insertProposal(proposalFixture({ id: "race-a", expiresAt: 60_000 }));
    first.insertProposal(proposalFixture({ id: "race-b", expiresAt: 60_000 }));

    const contestA = [first.claimProposal("race-a", 1, 500), second.claimProposal("race-a", 1, 500)];
    expect(contestA.filter((action) => action !== null)).toHaveLength(1);

    const contestB = [second.claimProposal("race-b", 1, 500), first.claimProposal("race-b", 1, 500)];
    expect(contestB.filter((action) => action !== null)).toHaveLength(1);

    expect(first.listActions()).toHaveLength(2);
    expect(second.listActions().map((action) => action.id).sort()).toEqual(
      first.listActions().map((action) => action.id).sort(),
    );
  } finally {
    first.close();
    second.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("two connections enforce cursor compare-and-set", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-cursor-"));
  const dbPath = join(root, "cursor.db");
  const first = new SecurityStore(dbPath);
  const second = new SecurityStore(dbPath);
  try {
    expect(
      first.commitEventBatch({
        events: [eventFixture("conn-1", 1_000)],
        cursor: { source: "journal", expected: null, next: "conn-c1" },
        burstWindowMs: 1_000,
      }),
    ).toBe(true);
    expect(second.getCursor("journal")).toBe("conn-c1");

    expect(
      second.commitEventBatch({
        events: [eventFixture("conn-2", 2_000, { rule: "other_rule" })],
        cursor: { source: "journal", expected: null, next: "conn-c2" },
        burstWindowMs: 1_000,
      }),
    ).toBe(false);
    expect(second.getCursor("journal")).toBe("conn-c1");
    expect(first.recentEvents(0, 10).map((event) => event.id)).toEqual(["conn-1"]);

    expect(
      second.commitEventBatch({
        events: [eventFixture("conn-2", 2_000, { rule: "other_rule" })],
        cursor: { source: "journal", expected: "conn-c1", next: "conn-c2" },
        burstWindowMs: 1_000,
      }),
    ).toBe(true);
    expect(first.getCursor("journal")).toBe("conn-c2");
    expect(first.recentEvents(0, 10)).toHaveLength(2);
  } finally {
    first.close();
    second.close();
    rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Additional edge-case coverage
// ---------------------------------------------------------------------------

test("saveScan updates an existing scan ID in place and replaces child rows cleanly", () => {
  const store = memoryStore();
  try {
    const initial = scanFixture({
      id: "scan-upsert",
      aiStatus: "offline",
      verdict: undefined,
      findings: [
        {
          id: "finding-det",
          source: "deterministic",
          severity: "warning",
          summary: "Initial deterministic finding",
          evidenceIds: ["ev-posture-ufw"],
        },
      ],
      trail: { steps: [] },
    });
    store.saveScan(initial);
    expect(store.latestScan()).toEqual(initial);

    const completed = scanFixture({
      id: "scan-upsert",
      finishedAt: initial.finishedAt + 2_000,
      aiStatus: "ready",
      verdict: {
        kind: "warn",
        confidence: 0.91,
        summary: "AI investigation completed",
      },
    });
    store.saveScan(completed);
    expect(store.latestScan()).toEqual(completed);
  } finally {
    store.close();
  }
});

test("file-backed store never alters permissions of an existing shared parent directory", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-shared-parent-"));
  const privateDir = join(root, "private");
  const dbPath = join(privateDir, "state.db");
  try {
    chmodSync(root, 0o755);
    const store = new SecurityStore(dbPath);
    try {
      expect(statSync(root).mode & 0o777).toBe(0o755);
      expect(statSync(privateDir).mode & 0o777).toBe(0o700);
      expect(statSync(dbPath).mode & 0o777).toBe(0o600);
    } finally {
      store.close();
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("no-arg SecurityStore uses BASHO_SECURITY_DB when set", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-env-db-"));
  const dbPath = join(root, "private", "env-state.db");
  const previous = process.env.BASHO_SECURITY_DB;
  try {
    process.env.BASHO_SECURITY_DB = `  ${dbPath}  `;
    const store = new SecurityStore();
    try {
      store.writeOverrides({ mode: "monitor", scanIntervalMinutes: 10 });
      expect(existsSync(dbPath)).toBe(true);
      expect(statSync(dbPath).mode & 0o777).toBe(0o600);
    } finally {
      store.close();
    }

    const reopened = new SecurityStore(dbPath);
    try {
      expect(reopened.readOverrides()).toEqual({ mode: "monitor", scanIntervalMinutes: 10 });
    } finally {
      reopened.close();
    }

    process.env.BASHO_SECURITY_DB = ":memory:";
    const memStore = new SecurityStore();
    try {
      expect(memStore.latestScan()).toBeNull();
    } finally {
      memStore.close();
    }
  } finally {
    if (previous === undefined) {
      delete process.env.BASHO_SECURITY_DB;
    } else {
      process.env.BASHO_SECURITY_DB = previous;
    }
    rmSync(root, { recursive: true, force: true });
  }
});

test("file-backed store rejects an existing unsafe state directory without altering its mode", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-unsafe-dir-"));
  const dbPath = join(root, "state.db");
  try {
    chmodSync(root, 0o755);
    expect(() => new SecurityStore(dbPath)).toThrow(/private.*directory/i);
    expect(statSync(root).mode & 0o777).toBe(0o755);
    expect(existsSync(dbPath)).toBe(false);

    chmodSync(root, 0o777);
    expect(() => new SecurityStore(dbPath)).toThrow(/private.*directory/i);
    expect(statSync(root).mode & 0o777).toBe(0o777);
    expect(existsSync(dbPath)).toBe(false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("file-backed store rejects an existing unsafe database file without altering its mode", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-unsafe-file-"));
  const dbPath = join(root, "state.db");
  try {
    writeFileSync(dbPath, "", { mode: 0o644 });
    chmodSync(dbPath, 0o644);
    expect(() => new SecurityStore(dbPath)).toThrow(/private.*file/i);
    expect(statSync(dbPath).mode & 0o777).toBe(0o644);

    chmodSync(dbPath, 0o640);
    expect(() => new SecurityStore(dbPath)).toThrow(/private.*file/i);
    expect(statSync(dbPath).mode & 0o777).toBe(0o640);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("commitEventBatch merges multiple bursts bridged by a late observation while preserving hourly counts", () => {
  const store = memoryStore();
  try {
    const hourStart = Date.UTC(2026, 2, 10, 14, 0, 0);
    const burstWindowMs = 2_000;

    // Burst 1 in the previous hour: [hourStart - 1_500, hourStart - 1_000], count 2
    store.commitEventBatch({
      events: [
        eventFixture("b1-a", hourStart - 1_500, {
          severity: "warning",
          summary: "burst-1-first",
        }),
        eventFixture("b1-b", hourStart - 1_000, {
          severity: "warning",
          summary: "burst-1-second",
        }),
      ],
      burstWindowMs,
    });

    // Burst 2 in the current hour: [hourStart + 1_500, hourStart + 1_500], count 1 (outside 2s window of burst 1)
    store.commitEventBatch({
      events: [
        eventFixture("b2-a", hourStart + 1_500, {
          severity: "info",
          summary: "burst-2-latest",
        }),
      ],
      burstWindowMs,
    });

    expect(store.recentEvents(0, 10)).toHaveLength(2);

    // Late observation at hourStart + 250 bridges both bursts:
    // distance to burst 1 lastAt (hourStart - 1_000) is 1_250 < 2_000
    // distance to burst 2 firstAt (hourStart + 1_500) is 1_250 < 2_000
    store.commitEventBatch({
      events: [
        eventFixture("b-bridge", hourStart + 250, {
          severity: "critical",
          summary: "bridge-critical",
        }),
      ],
      burstWindowMs,
    });

    const events = store.recentEvents(0, 10);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      rule: "ssh_burst",
      target: "198.51.100.42",
      count: 4,
      firstAt: hourStart - 1_500,
      lastAt: hourStart + 1_500,
      severity: "critical",
      summary: "burst-2-latest",
    });

    const buckets = store.hourlyEvents(hourStart + 30_000);
    const byHour = new Map(buckets.map((bucket) => [bucket.hour, bucket]));
    expect(byHour.get(hourStart - HOUR_MS)).toEqual({
      hour: hourStart - HOUR_MS,
      signal: 2,
      noise: 0,
    });
    expect(byHour.get(hourStart)).toEqual({
      hour: hourStart,
      signal: 2,
      noise: 0,
    });
  } finally {
    store.close();
  }
});

test("two connections reclaim expired delivery lease and reject first connection stale claimToken", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-delivery-race-"));
  const dbPath = join(root, "deliveries.db");
  const first = new SecurityStore(dbPath);
  const second = new SecurityStore(dbPath);
  try {
    const createdAt = 5_000_000;
    expect(
      first.enqueueAlert(
        alertFixture("race-delivery-alert", "auth:ssh_burst:203.0.113.77", "critical", createdAt),
        ["ntfy"],
        900_000,
      ),
    ).toBe(true);

    const claim1 = first.claimDeliveries(createdAt, 5, 30_000)[0]!;
    expect(claim1).toBeDefined();
    expect(claim1.attempts).toBe(1);

    // Before expiry, second connection cannot steal the lease.
    expect(second.claimDeliveries(createdAt + 29_999, 5, 30_000)).toEqual([]);

    // After expiry, second connection reclaims with a new claimToken.
    const claim2 = second.claimDeliveries(createdAt + 30_001, 5, 30_000)[0]!;
    expect(claim2).toBeDefined();
    expect(claim2.id).toBe(claim1.id);
    expect(claim2.claimToken).not.toBe(claim1.claimToken);
    expect(claim2.attempts).toBe(2);

    // First connection's stale claimToken is rejected.
    expect(first.settleDelivery(claim1.id, claim1.claimToken, createdAt + 30_002, "sent")).toBe(false);
    expect(first.channelHealth()).toEqual({});

    // Second connection settles cleanly and first connection observes the settled health.
    expect(second.settleDelivery(claim2.id, claim2.claimToken, createdAt + 30_003, "sent")).toBe(true);
    expect(first.channelHealth().ntfy).toEqual({ status: "sent", at: createdAt + 30_003 });
    expect(first.claimDeliveries(createdAt + 100_000, 5, 30_000)).toEqual([]);
  } finally {
    first.close();
    second.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("two connections observe pruned scans, events, and terminal actions while retaining unresolved actions", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-prune-two-conn-"));
  const dbPath = join(root, "prune-two-conn.db");
  const writer = new SecurityStore(dbPath);
  const reader = new SecurityStore(dbPath);
  try {
    const start = 50 * DAY_MS;
    const now = start + 2_000 + 90 * DAY_MS + 1;

    for (let index = 1; index <= 55; index += 1) {
      writer.saveScan(
        scanFixture({
          id: `scan-${index}`,
          startedAt: index * 1_000,
          finishedAt: index * 1_000 + 10,
          snapshot: { ...scanFixture().snapshot, id: `snapshot-${index}` },
        }),
      );
    }

    writer.commitEventBatch({
      events: [
        eventFixture("ev-expired", now - 15 * DAY_MS, { rule: "old_rule" }),
        eventFixture("ev-kept", now - 13 * DAY_MS, { rule: "recent_rule" }),
      ],
      burstWindowMs: 1_000,
    });

    writer.insertProposal(proposalFixture({ id: "prop-terminal", expiresAt: start + 600_000 }));
    const terminal = writer.claimProposal("prop-terminal", 1, start)!;
    expect(writer.transitionAction(terminal.id, "pending", "active", start + 1_000)).toBe(true);
    expect(writer.transitionAction(terminal.id, "active", "rolled_back", start + 2_000)).toBe(true);

    writer.insertProposal(proposalFixture({ id: "prop-active", expiresAt: start + 600_000 }));
    const unresolvedActive = writer.claimProposal("prop-active", 1, start)!;
    expect(writer.transitionAction(unresolvedActive.id, "pending", "active", start + 1_000)).toBe(true);

    writer.insertProposal(proposalFixture({ id: "prop-pending", expiresAt: start + 600_000 }));
    const unresolvedPending = writer.claimProposal("prop-pending", 1, start)!;

    writer.prune(now);

    expect(reader.latestScan()!.id).toBe("scan-55");
    expect(reader.recentEvents(0, 100).map((event) => event.id)).toEqual(["ev-kept"]);
    expect(reader.listActions().map((action) => action.id).sort()).toEqual(
      [unresolvedActive.id, unresolvedPending.id].sort(),
    );

    const inspectDb = new Database(dbPath, { readonly: true });
    try {
      const scanCount = (inspectDb.query("SELECT COUNT(*) AS n FROM scans").get() as { n: number }).n;
      expect(scanCount).toBe(50);
    } finally {
      inspectDb.close();
    }
  } finally {
    writer.close();
    reader.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("latestScan reads a consistent snapshot in a deferred read transaction under WAL concurrency", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-latest-snapshot-"));
  const dbPath = join(root, "snapshot.db");
  const writer = new SecurityStore(dbPath);
  const reader = new SecurityStore(dbPath);
  try {
    const committed = scanFixture({ id: "scan-committed", startedAt: 1_000, finishedAt: 2_000 });
    writer.saveScan(committed);

    // Hold an uncommitted write transaction modifying scans and deleting child rows on a third connection.
    const rawWriter = new Database(dbPath);
    try {
      rawWriter.run("BEGIN IMMEDIATE");
      rawWriter
        .query("UPDATE scans SET ai_status = 'offline', verdict_json = NULL WHERE id = ?")
        .run("scan-committed");
      rawWriter.query("DELETE FROM posture_checks WHERE scan_id = ?").run("scan-committed");
      rawWriter.query("DELETE FROM findings WHERE scan_id = ?").run("scan-committed");

      // Deferred read transaction on reader must see the complete committed snapshot without blocking.
      expect(reader.latestScan()).toEqual(committed);

      rawWriter.run("ROLLBACK");
    } finally {
      rawWriter.close();
    }
  } finally {
    writer.close();
    reader.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("prune cascades scan children while keeping actions independent of scan retention", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-cascade-"));
  const dbPath = join(root, "cascade.db");
  try {
    const store = new SecurityStore(dbPath);
    try {
      for (let index = 1; index <= 52; index += 1) {
        store.saveScan(
          scanFixture({
            id: `scan-${index}`,
            startedAt: index * 1_000,
            finishedAt: index * 1_000 + 10,
            snapshot: { ...scanFixture().snapshot, id: `snapshot-${index}` },
          }),
        );
      }

      store.insertProposal(
        proposalFixture({ id: "proposal-from-scan-1", scanId: "scan-1", expiresAt: 100_000 }),
      );
      const action = store.claimProposal("proposal-from-scan-1", 1, 2_000);
      expect(action).not.toBeNull();

      store.prune(200_000);
      expect(store.listActions().map((entry) => entry.id)).toEqual([action!.id]);
    } finally {
      store.close();
    }

    const db = new Database(dbPath, { readonly: true });
    try {
      const scanCount = (db.query("SELECT COUNT(*) AS n FROM scans").get() as { n: number }).n;
      const orphanChecks = (
        db
          .query("SELECT COUNT(*) AS n FROM posture_checks WHERE scan_id IN ('scan-1', 'scan-2')")
          .get() as { n: number }
      ).n;
      const orphanFindings = (
        db
          .query("SELECT COUNT(*) AS n FROM findings WHERE scan_id IN ('scan-1', 'scan-2')")
          .get() as { n: number }
      ).n;
      expect(scanCount).toBe(50);
      expect(orphanChecks).toBe(0);
      expect(orphanFindings).toBe(0);
    } finally {
      db.close();
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("file-backed store rejects symlinked database, state directory, and WAL/SHM sidecars before opening SQLite", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-symlink-"));
  const outsideDir = mkdtempSync(join(tmpdir(), "basho-symlink-outside-"));
  try {
    // 1. Database path is a symlink to a private file outside the state directory.
    const outsideTarget = join(outsideDir, "outside.db");
    writeFileSync(outsideTarget, "", { mode: 0o600 });
    chmodSync(outsideTarget, 0o600);
    const dbLink = join(root, "state.db");
    symlinkSync(outsideTarget, dbLink);

    expect(() => new SecurityStore(dbLink)).toThrow(/symbolic link/i);
    // SQLite must not have been opened against the symlink target.
    expect(statSync(outsideTarget).size).toBe(0);
    expect(existsSync(`${dbLink}-wal`)).toBe(false);
    expect(existsSync(`${outsideTarget}-wal`)).toBe(false);

    // 2. State directory itself is a symlink to another private directory.
    const dirLink = join(root, "linked-dir");
    symlinkSync(outsideDir, dirLink);
    const dbInLinkedDir = join(dirLink, "nested.db");
    expect(() => new SecurityStore(dbInLinkedDir)).toThrow(/symbolic link/i);
    expect(existsSync(join(outsideDir, "nested.db"))).toBe(false);

    // 3. WAL or SHM sidecar is a symlink.
    const realDb = join(root, "real.db");
    writeFileSync(realDb, "", { mode: 0o600 });
    chmodSync(realDb, 0o600);

    const walTarget = join(outsideDir, "outside.wal");
    writeFileSync(walTarget, "", { mode: 0o600 });
    chmodSync(walTarget, 0o600);
    symlinkSync(walTarget, `${realDb}-wal`);
    expect(() => new SecurityStore(realDb)).toThrow(/symbolic link/i);
    expect(statSync(realDb).size).toBe(0);
    rmSync(`${realDb}-wal`);

    const shmTarget = join(outsideDir, "outside.shm");
    writeFileSync(shmTarget, "", { mode: 0o600 });
    chmodSync(shmTarget, 0o600);
    symlinkSync(shmTarget, `${realDb}-shm`);
    expect(() => new SecurityStore(realDb)).toThrow(/symbolic link/i);
    expect(statSync(realDb).size).toBe(0);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outsideDir, { recursive: true, force: true });
  }
});

test("commitEventBatch transitively merges chained bursts when a larger burstWindowMs connects A -> B -> C", () => {
  const store = memoryStore();
  try {
    const base = Date.UTC(2026, 3, 20, 10, 0, 0);

    // Three separate bursts created with a tight 1s window, spaced 3s apart:
    // A at [base + 1_000, base + 1_500] (count 2)
    // B at [base + 4_500, base + 5_000] (count 2)
    // C at [base + 8_000, base + 8_500] (count 1)
    store.commitEventBatch({
      events: [
        eventFixture("chain-a1", base + 1_000, { severity: "info", summary: "a1" }),
        eventFixture("chain-a2", base + 1_500, { severity: "info", summary: "a2" }),
      ],
      burstWindowMs: 1_000,
    });
    store.commitEventBatch({
      events: [
        eventFixture("chain-b1", base + 4_500, { severity: "warning", summary: "b1" }),
        eventFixture("chain-b2", base + 5_000, { severity: "warning", summary: "b2" }),
      ],
      burstWindowMs: 1_000,
    });
    store.commitEventBatch({
      events: [eventFixture("chain-c1", base + 8_000, { severity: "critical", summary: "c1-latest" })],
      burstWindowMs: 1_000,
    });

    expect(store.recentEvents(0, 10)).toHaveLength(3);

    // Incoming observation near A with burstWindowMs = 4_000:
    // Initial window [base - 2_800, base + 5_200] overlaps A and B, NOT C (base + 8_000).
    // Merging A + B expands mergedLast to base + 5_000; new window reaches base + 9_000,
    // which transitively connects C.
    store.commitEventBatch({
      events: [
        eventFixture("chain-trigger", base + 1_200, {
          severity: "info",
          summary: "trigger-near-a",
        }),
      ],
      burstWindowMs: 4_000,
    });

    const events = store.recentEvents(0, 10);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      rule: "ssh_burst",
      target: "198.51.100.42",
      count: 6,
      firstAt: base + 1_000,
      lastAt: base + 8_000,
      severity: "critical",
      summary: "c1-latest",
    });

    // Reverse direction (right-to-left transitive merge) on a separate target:
    // D at [base + 1_000, base + 1_500], E at [base + 4_500, base + 5_000], F at [base + 8_000, base + 8_500]
    const reverseTarget = "203.0.113.55";
    store.commitEventBatch({
      events: [
        eventFixture("rev-d1", base + 1_000, { target: reverseTarget, severity: "breach", summary: "d1" }),
      ],
      burstWindowMs: 1_000,
    });
    store.commitEventBatch({
      events: [
        eventFixture("rev-e1", base + 4_500, { target: reverseTarget, severity: "warning", summary: "e1" }),
      ],
      burstWindowMs: 1_000,
    });
    store.commitEventBatch({
      events: [
        eventFixture("rev-f1", base + 8_000, { target: reverseTarget, severity: "info", summary: "f1" }),
      ],
      burstWindowMs: 1_000,
    });
    store.commitEventBatch({
      events: [
        eventFixture("rev-trigger", base + 8_200, {
          target: reverseTarget,
          severity: "info",
          summary: "rev-trigger-latest",
        }),
      ],
      burstWindowMs: 4_000,
    });

    const revEvents = store.recentEvents(0, 10).filter((event) => event.target === reverseTarget);
    expect(revEvents).toHaveLength(1);
    expect(revEvents[0]).toMatchObject({
      target: reverseTarget,
      count: 4,
      firstAt: base + 1_000,
      lastAt: base + 8_200,
      severity: "breach",
      summary: "rev-trigger-latest",
    });
  } finally {
    store.close();
  }
});

test("file-backed store rejects symlinked or unsafe -journal sidecar before opening SQLite", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-journal-sidecar-"));
  const outsideDir = mkdtempSync(join(tmpdir(), "basho-journal-outside-"));
  try {
    const realDb = join(root, "real.db");
    writeFileSync(realDb, "", { mode: 0o600 });
    chmodSync(realDb, 0o600);

    const journalTarget = join(outsideDir, "outside.journal");
    writeFileSync(journalTarget, "", { mode: 0o600 });
    chmodSync(journalTarget, 0o600);
    symlinkSync(journalTarget, `${realDb}-journal`);

    expect(() => new SecurityStore(realDb)).toThrow(/symbolic link/i);
    expect(statSync(realDb).size).toBe(0);
    expect(statSync(journalTarget).size).toBe(0);
    rmSync(`${realDb}-journal`);

    writeFileSync(`${realDb}-journal`, "", { mode: 0o644 });
    chmodSync(`${realDb}-journal`, 0o644);
    expect(() => new SecurityStore(realDb)).toThrow(/private.*sidecar/i);
    expect(statSync(`${realDb}-journal`).mode & 0o777).toBe(0o644);
    expect(statSync(realDb).size).toBe(0);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outsideDir, { recursive: true, force: true });
  }
});

test("file-backed store configures PRAGMA synchronous = FULL and opens the validated absolute path", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-sync-full-"));
  const subDir = join(root, "private");
  const unnormalizedPath = join(subDir, "nested", "..", "durable.db");
  const expectedResolvedPath = resolve(unnormalizedPath);
  const relPath = relative(process.cwd(), unnormalizedPath);

  try {
    const store = new SecurityStore(relPath);
    try {
      const internalDb = (store as unknown as { db: Database }).db;
      const syncRow = internalDb.query("PRAGMA synchronous").get() as { synchronous: number } | null;
      expect(syncRow?.synchronous).toBe(2); // 2 = FULL
      expect(internalDb.filename).toBe(expectedResolvedPath);
    } finally {
      store.close();
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("commitEventBatch fails and rolls back cursor and batch on invalid observations", () => {
  const store = memoryStore();
  try {
    expect(
      store.commitEventBatch({
        events: [eventFixture("valid-initial", 1_000)],
        cursor: { source: "journal", expected: null, next: "c-1" },
        burstWindowMs: 1_000,
      }),
    ).toBe(true);

    // Invalid NaN count after a valid event in the same batch must throw and roll back both event and cursor.
    expect(() =>
      store.commitEventBatch({
        events: [
          eventFixture("rolled-back-1", 2_000, { rule: "rule_rolled_back" }),
          eventFixture("bad-nan-count", 3_000, { count: Number.NaN }),
        ],
        cursor: { source: "journal", expected: "c-1", next: "c-2" },
        burstWindowMs: 1_000,
      }),
    ).toThrow();

    expect(store.getCursor("journal")).toBe("c-1");
    expect(store.recentEvents(0, 10).map((event) => event.id)).toEqual(["valid-initial"]);

    // Non-positive, non-integer, or non-finite count must also reject and preserve cursor.
    for (const badCount of [0, -1, 1.5, Number.POSITIVE_INFINITY]) {
      expect(() =>
        store.commitEventBatch({
          events: [eventFixture(`bad-count-${String(badCount)}`, 4_000, { count: badCount })],
          cursor: { source: "journal", expected: "c-1", next: "c-2" },
          burstWindowMs: 1_000,
        }),
      ).toThrow();
    }

    // Non-finite timestamps or inverted [firstAt, lastAt] must reject and preserve cursor.
    expect(() =>
      store.commitEventBatch({
        events: [eventFixture("bad-first-nan", 5_000, { firstAt: Number.NaN })],
        cursor: { source: "journal", expected: "c-1", next: "c-2" },
        burstWindowMs: 1_000,
      }),
    ).toThrow();
    expect(() =>
      store.commitEventBatch({
        events: [eventFixture("bad-last-inf", 5_000, { lastAt: Number.POSITIVE_INFINITY })],
        cursor: { source: "journal", expected: "c-1", next: "c-2" },
        burstWindowMs: 1_000,
      }),
    ).toThrow();
    expect(() =>
      store.commitEventBatch({
        events: [eventFixture("bad-inverted", 5_000, { firstAt: 6_000, lastAt: 5_000 })],
        cursor: { source: "journal", expected: "c-1", next: "c-2" },
        burstWindowMs: 1_000,
      }),
    ).toThrow();

    // NOT NULL violation (e.g. runtime null rule) must fail instead of being silently ignored by INSERT OR IGNORE.
    expect(() =>
      store.commitEventBatch({
        events: [
          eventFixture("bad-null-rule", 5_000, {
            rule: null as unknown as string,
          }),
        ],
        cursor: { source: "journal", expected: "c-1", next: "c-2" },
        burstWindowMs: 1_000,
      }),
    ).toThrow();

    expect(store.getCursor("journal")).toBe("c-1");
    expect(store.recentEvents(0, 10).map((event) => event.id)).toEqual(["valid-initial"]);
  } finally {
    store.close();
  }
});

test("prune preserves observation dedupe rows for surviving spanning bursts so replay does not double-count", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-prune-dedupe-"));
  const dbPath = join(root, "dedupe.db");
  const store = new SecurityStore(dbPath);
  try {
    const now = 100 * DAY_MS;
    const cutoff = now - 14 * DAY_MS;

    // A burst spanning the 14-day retention cutoff:
    // obs-before is 1s before cutoff, obs-after is 1s after cutoff, within a 5s burst window.
    const preCutoffObs = eventFixture("span-before", cutoff - 1_000, {
      rule: "ssh_burst",
      target: "198.51.100.77",
      count: 2,
    });
    const postCutoffObs = eventFixture("span-after", cutoff + 1_000, {
      rule: "ssh_burst",
      target: "198.51.100.77",
      count: 3,
    });

    // A separate fully expired burst for the exact same (source, category, rule, target, is_noise)
    // far earlier than the surviving burst.
    const expiredObs = eventFixture("expired-separate", cutoff - 5 * DAY_MS, {
      rule: "ssh_burst",
      target: "198.51.100.77",
      count: 4,
    });

    store.commitEventBatch({
      events: [expiredObs, preCutoffObs, postCutoffObs],
      burstWindowMs: 5_000,
    });

    store.prune(now);

    // The spanning burst survives with count 5; the expired burst was pruned.
    const afterPrune = store.recentEvents(0, 10);
    expect(afterPrune).toHaveLength(1);
    expect(afterPrune[0]).toMatchObject({
      rule: "ssh_burst",
      target: "198.51.100.77",
      firstAt: cutoff - 1_000,
      lastAt: cutoff + 1_000,
      count: 5,
    });

    // Replaying the pre-cutoff observation must NOT double-count the surviving burst.
    store.commitEventBatch({
      events: [preCutoffObs],
      burstWindowMs: 5_000,
    });

    const afterReplay = store.recentEvents(0, 10);
    expect(afterReplay).toHaveLength(1);
    expect(afterReplay[0]!.count).toBe(5);

    // The expired separate burst's observation row was properly pruned (no unbounded leak).
    const inspectDb = new Database(dbPath, { readonly: true });
    try {
      const obsIds = (
        inspectDb
          .query(
            "SELECT observation_id FROM security_events WHERE row_kind = 'observation' ORDER BY observation_id",
          )
          .all() as { observation_id: string }[]
      ).map((row) => row.observation_id);
      expect(obsIds).toEqual(["span-after", "span-before"]);
    } finally {
      inspectDb.close();
    }

    // Once the spanning burst itself ages past 14 days, both its aggregate and observations are pruned.
    store.prune(cutoff + 1_000 + 14 * DAY_MS + 1);
    expect(store.recentEvents(0, 10)).toEqual([]);
    const inspectAfterFinalPrune = new Database(dbPath, { readonly: true });
    try {
      const remaining = (
        inspectAfterFinalPrune.query("SELECT COUNT(*) AS n FROM security_events").get() as {
          n: number;
        }
      ).n;
      expect(remaining).toBe(0);
    } finally {
      inspectAfterFinalPrune.close();
    }
  } finally {
    store.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("two-connection write-transaction contention on claimProposal is atomic and never produces two claims", async () => {
  const root = mkdtempSync(join(tmpdir(), "basho-lock-contend-"));
  const dbPath = join(root, "contend.db");
  const store = new SecurityStore(dbPath);
  const storeZeroTimeout = new SecurityStore(dbPath);
  try {
    // Part 1: busy_timeout = 0 contention check against an active BEGIN IMMEDIATE transaction.
    store.insertProposal(proposalFixture({ id: "contend-busy", expiresAt: 60_000 }));
    const zeroDb = (storeZeroTimeout as unknown as { db: Database }).db;
    zeroDb.run("PRAGMA busy_timeout = 0");

    const rawLocker = new Database(dbPath);
    try {
      rawLocker.run("BEGIN IMMEDIATE");
      expect(() => storeZeroTimeout.claimProposal("contend-busy", 1, 500)).toThrow(
        /locked|busy/i,
      );
      rawLocker.run("ROLLBACK");
    } finally {
      rawLocker.close();
    }

    // After rollback, the proposal is still untouched and can be claimed exactly once.
    const wonAfterRollback = storeZeroTimeout.claimProposal("contend-busy", 1, 500);
    expect(wonAfterRollback).not.toBeNull();
    expect(store.claimProposal("contend-busy", 1, 500)).toBeNull();
    expect(store.listActions().filter((a) => a.proposalId === "contend-busy")).toHaveLength(1);

    // Part 2: real concurrent child-process contention while parent holds BEGIN IMMEDIATE.
    store.insertProposal(proposalFixture({ id: "contend-proc-commit", expiresAt: 60_000 }));
    store.insertProposal(proposalFixture({ id: "contend-proc-rollback", expiresAt: 60_000 }));

    const runChildClaim = async (
      proposalId: string,
      whileLocked: (locker: Database) => "commit" | "rollback",
    ) => {
      const storeModulePath = resolve("src/security/store.ts");
      const childScript = `
        import { SecurityStore } from ${JSON.stringify(storeModulePath)};
        const store = new SecurityStore(${JSON.stringify(dbPath)});
        try {
          const db = store.db;
          const busyRow = db.query("PRAGMA busy_timeout").get();
          const defaultBusyTimeout = Object.values(busyRow)[0];
          console.log("READY");
          for await (const _line of console) {
            break;
          }
          // Deterministically observe SQLITE_BUSY against the parent's active BEGIN IMMEDIATE lock.
          db.run("PRAGMA busy_timeout = 0");
          let observedBusy = false;
          let busyMessage = "";
          try {
            store.claimProposal(${JSON.stringify(proposalId)}, 1, 500);
          } catch (error) {
            observedBusy = true;
            busyMessage = error instanceof Error ? error.message : String(error);
          } finally {
            db.run(\`PRAGMA busy_timeout = \${defaultBusyTimeout}\`);
          }
          if (!observedBusy) {
            throw new Error("Expected SQLITE_BUSY while parent held BEGIN IMMEDIATE lock");
          }
          const startedAt = Date.now();
          console.log("BUSY_OBSERVED");
          const action = store.claimProposal(${JSON.stringify(proposalId)}, 1, 500);
          const finishedAt = Date.now();
          console.log(
            JSON.stringify({
              defaultBusyTimeout,
              observedBusy,
              busyMessage,
              action,
              startedAt,
              finishedAt,
            }),
          );
        } finally {
          store.close();
        }
      `;

      const child = Bun.spawn([process.execPath, "-e", childScript], {
        stdin: "pipe",
        stdout: "pipe",
        stderr: "pipe",
      });

      const reader = child.stdout.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      const waitForMarker = async (marker: string) => {
        while (!buffer.includes(marker)) {
          const chunk = await reader.read();
          if (chunk.done) {
            const stderrText = await new Response(child.stderr).text();
            throw new Error(`Child exited before ${marker.trim()}: ${stderrText}`);
          }
          buffer += decoder.decode(chunk.value, { stream: true });
        }
        const markerEnd = buffer.indexOf(marker) + marker.length;
        buffer = buffer.slice(markerEnd);
      };

      await waitForMarker("READY\n");

      const locker = new Database(dbPath);
      let lockReleasedAt = 0;
      let pendingRead: ReturnType<typeof reader.read>;
      try {
        locker.run("BEGIN IMMEDIATE");
        child.stdin.write("GO\n");
        child.stdin.end();
        // Wait for the child to deterministically observe SQLITE_BUSY while we hold the lock
        // and restore busy_timeout before entering normal claimProposal.
        await waitForMarker("BUSY_OBSERVED\n");
        expect(buffer).toBe("");

        // Hold BEGIN IMMEDIATE for ~45ms and prove the child remains blocked until lock release.
        pendingRead = reader.read();
        const holdOutcome = await Promise.race([
          pendingRead.then(() => "unblocked-early" as const),
          Bun.sleep(45).then(() => "still-blocked" as const),
        ]);
        expect(holdOutcome).toBe("still-blocked");

        const outcome = whileLocked(locker);
        lockReleasedAt = Date.now();
        locker.run(outcome === "commit" ? "COMMIT" : "ROLLBACK");
      } finally {
        locker.close();
      }

      let rest = buffer;
      const firstAfterRelease = await pendingRead;
      if (!firstAfterRelease.done) {
        rest += decoder.decode(firstAfterRelease.value, { stream: true });
        while (true) {
          const chunk = await reader.read();
          if (chunk.done) break;
          rest += decoder.decode(chunk.value, { stream: true });
        }
      }
      const exitCode = await child.exited;
      const stderrText = await new Response(child.stderr).text();
      expect(exitCode, `child stderr: ${stderrText}`).toBe(0);
      const parsed = JSON.parse(rest.trim()) as {
        defaultBusyTimeout: number;
        observedBusy: boolean;
        busyMessage: string;
        action: { id: string } | null;
        startedAt: number;
        finishedAt: number;
      };
      expect(parsed.defaultBusyTimeout).toBeGreaterThan(0);
      expect(parsed.observedBusy).toBe(true);
      expect(parsed.busyMessage).toMatch(/locked|busy/i);
      expect(parsed.finishedAt).toBeGreaterThanOrEqual(lockReleasedAt);
      expect(parsed.finishedAt - parsed.startedAt).toBeGreaterThanOrEqual(35);
      return parsed;
    };

    // Parent holds write lock, claims proposal and commits -> child waits on busy_timeout, unblocks, sees claimed, returns null.
    const commitRace = await runChildClaim("contend-proc-commit", (locker) => {
      const updated = locker
        .query(
          `UPDATE lockdown_proposals
           SET status = 'claimed', revision = revision + 1, updated_at = 500
           WHERE id = 'contend-proc-commit' AND revision = 1 AND status = 'pending'
           RETURNING target_json, lease_seconds`,
        )
        .get() as { target_json: string; lease_seconds: number };
      locker
        .query(
          `INSERT INTO lockdown_actions (
            id, proposal_id, idempotency_key, target_json, state,
            created_at, expires_at, updated_at, rollback_handle
          ) VALUES (?, 'contend-proc-commit', 'contend-proc-commit:1', ?, 'pending', 500, ?, 500, NULL)`,
        )
        .run("parent-action-id", updated.target_json, 500 + updated.lease_seconds * 1_000);
      return "commit";
    });
    expect(commitRace.action).toBeNull();
    expect(
      store.listActions().filter((a) => a.proposalId === "contend-proc-commit").map((a) => a.id),
    ).toEqual(["parent-action-id"]);

    // Parent holds write lock and rolls back -> child waits on busy_timeout, unblocks, and atomically wins the single claim.
    const rollbackRace = await runChildClaim("contend-proc-rollback", () => "rollback");
    expect(rollbackRace.action).not.toBeNull();
    expect(store.claimProposal("contend-proc-rollback", 1, 500)).toBeNull();
    expect(
      store.listActions().filter((a) => a.proposalId === "contend-proc-rollback").map((a) => a.id),
    ).toEqual([rollbackRace.action!.id]);
  } finally {
    storeZeroTimeout.close();
    store.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("commitEventBatch validates every SecurityEvent field and rolls back batch and cursor on invalid input", () => {
  const store = memoryStore();
  try {
    expect(
      store.commitEventBatch({
        events: [eventFixture("val-baseline", 1_000)],
        cursor: { source: "journal", expected: null, next: "val-c1" },
        burstWindowMs: 1_000,
      }),
    ).toBe(true);

    const invalidCases: { name: string; event: SecurityEvent }[] = [
      {
        name: "invalid severity",
        event: eventFixture("bad-sev", 2_000, { severity: "fatal" as Severity }),
      },
      {
        name: "missing summary",
        event: eventFixture("bad-summary-empty", 2_000, { summary: "" }),
      },
      {
        name: "whitespace summary",
        event: eventFixture("bad-summary-ws", 2_000, { summary: "   " }),
      },
      {
        name: "empty id",
        event: eventFixture("", 2_000),
      },
      {
        name: "empty rule",
        event: eventFixture("bad-rule", 2_000, { rule: "" }),
      },
      {
        name: "empty target",
        event: eventFixture("bad-target", 2_000, { target: "  " }),
      },
      {
        name: "invalid source",
        event: eventFixture("bad-source", 2_000, {
          source: "syslog" as SecurityEvent["source"],
        }),
      },
      {
        name: "invalid category",
        event: eventFixture("bad-category", 2_000, {
          category: "kernel" as SecurityEvent["category"],
        }),
      },
      {
        name: "non-boolean isNoise",
        event: eventFixture("bad-noise", 2_000, {
          isNoise: 1 as unknown as boolean,
        }),
      },
      {
        name: "fractional firstAt",
        event: eventFixture("bad-first-float", 2_000, {
          firstAt: 1_999.5,
          lastAt: 2_000,
        }),
      },
      {
        name: "fractional lastAt",
        event: eventFixture("bad-last-float", 2_000, {
          firstAt: 2_000,
          lastAt: 2_000.5,
        }),
      },
    ];

    for (const testCase of invalidCases) {
      expect(
        () =>
          store.commitEventBatch({
            events: [
              eventFixture(`rolled-back-${testCase.name}`, 1_500, { rule: "should_rollback" }),
              testCase.event,
            ],
            cursor: { source: "journal", expected: "val-c1", next: "val-c2" },
            burstWindowMs: 1_000,
          }),
        testCase.name,
      ).toThrow();

      expect(store.getCursor("journal"), testCase.name).toBe("val-c1");
      expect(
        store.recentEvents(0, 10).map((event) => event.id),
        testCase.name,
      ).toEqual(["val-baseline"]);
    }
  } finally {
    store.close();
  }
});

test("commitEventBatch rejects unsafe counts and guards aggregate and hourly totals against integer overflow", () => {
  const store = memoryStore();
  try {
    const baseHour = Date.UTC(2026, 4, 1, 10, 0, 0);

    expect(
      store.commitEventBatch({
        events: [eventFixture("cnt-init", baseHour + 1_000, { count: 1_000_000_000 })],
        cursor: { source: "journal", expected: null, next: "cnt-c1" },
        burstWindowMs: 5_000,
      }),
    ).toBe(true);
    expect(store.recentEvents(0, 10)[0]!.count).toBe(1_000_000_000);

    // Above 1_000_000_000 cap and unsafe integer counts must be rejected without advancing cursor.
    for (const badCount of [1_000_000_001, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() =>
        store.commitEventBatch({
          events: [
            eventFixture(`cnt-rolled-${badCount}`, baseHour + 1_200, { rule: "other_rule" }),
            eventFixture(`cnt-bad-${badCount}`, baseHour + 1_500, { count: badCount }),
          ],
          cursor: { source: "journal", expected: "cnt-c1", next: "cnt-c2" },
          burstWindowMs: 5_000,
        }),
      ).toThrow(RangeError);
      expect(store.getCursor("journal")).toBe("cnt-c1");
      expect(store.recentEvents(0, 10)).toHaveLength(1);
    }

    // Aggregate total overflow guard: push existing aggregate near MAX_SAFE_INTEGER and try to merge.
    const internalDb = (store as unknown as { db: Database }).db;
    internalDb
      .query("UPDATE security_events SET count = ? WHERE row_kind = 'aggregate' AND event_id = 'cnt-init'")
      .run(Number.MAX_SAFE_INTEGER - 5);

    expect(() =>
      store.commitEventBatch({
        events: [eventFixture("cnt-agg-overflow", baseHour + 2_000, { count: 10 })],
        cursor: { source: "journal", expected: "cnt-c1", next: "cnt-c2" },
        burstWindowMs: 5_000,
      }),
    ).toThrow(RangeError);
    expect(store.getCursor("journal")).toBe("cnt-c1");
    expect(store.recentEvents(0, 10)[0]!.count).toBe(Number.MAX_SAFE_INTEGER - 5);

    // Hourly total overflow guard: seed an observation near MAX_SAFE_INTEGER in another hour
    // and insert a separate-rule event in that same hour so only the hourly sum overflows.
    const nextHour = baseHour + HOUR_MS;
    expect(
      store.commitEventBatch({
        events: [eventFixture("hourly-seed", nextHour + 1_000, { rule: "rule_hourly_a", count: 1 })],
        cursor: { source: "journal", expected: "cnt-c1", next: "cnt-c2" },
        burstWindowMs: 5_000,
      }),
    ).toBe(true);

    internalDb
      .query("UPDATE security_events SET count = ? WHERE row_kind = 'observation' AND observation_id = 'hourly-seed'")
      .run(Number.MAX_SAFE_INTEGER - 5);

    expect(() =>
      store.commitEventBatch({
        events: [
          eventFixture("hourly-overflow", nextHour + 2_000, { rule: "rule_hourly_b", count: 10 }),
        ],
        cursor: { source: "journal", expected: "cnt-c2", next: "cnt-c3" },
        burstWindowMs: 5_000,
      }),
    ).toThrow(RangeError);
    expect(store.getCursor("journal")).toBe("cnt-c2");
    expect(store.recentEvents(0, 10).map((event) => event.rule)).not.toContain("rule_hourly_b");
  } finally {
    store.close();
  }
});

test("commitEventBatch caps aggregate burst span at 24h so continuously active bursts and dedupe observations prune cleanly", () => {
  const root = mkdtempSync(join(tmpdir(), "basho-burst-cap-"));
  const dbPath = join(root, "burst-cap.db");
  const store = new SecurityStore(dbPath);
  try {
    const start = 100 * DAY_MS;
    const burstWindowMs = 2 * HOUR_MS;

    // 37 hourly events (hours 0..36), each 1h apart (well inside 2h burstWindowMs).
    // Hours 0..24 span exactly 24h -> single aggregate; hour 25 starts a new aggregate (hours 25..36).
    const events: SecurityEvent[] = [];
    for (let h = 0; h <= 36; h += 1) {
      events.push(
        eventFixture(`cont-${h}`, start + h * HOUR_MS, {
          rule: "ssh_burst",
          target: "198.51.100.88",
        }),
      );
    }
    store.commitEventBatch({ events, burstWindowMs });

    const aggregates = store
      .recentEvents(0, 20)
      .sort((left, right) => left.firstAt - right.firstAt);
    expect(aggregates).toHaveLength(2);
    expect(aggregates[0]).toMatchObject({
      firstAt: start,
      lastAt: start + 24 * HOUR_MS,
      count: 25,
    });
    expect(aggregates[1]).toMatchObject({
      firstAt: start + 25 * HOUR_MS,
      lastAt: start + 36 * HOUR_MS,
      count: 12,
    });

    // Prune at cutoff = start + 26h:
    // - Aggregate 1 (lastAt = start + 24h < cutoff) and all 25 of its observation rows must be reclaimed.
    // - Aggregate 2 (firstAt = start + 25h, lastAt = start + 36h) spans cutoff and survives with dedupe intact.
    const cutoff = start + 26 * HOUR_MS;
    store.prune(cutoff + 14 * DAY_MS);

    const afterPrune = store.recentEvents(0, 20);
    expect(afterPrune).toHaveLength(1);
    expect(afterPrune[0]).toMatchObject({
      firstAt: start + 25 * HOUR_MS,
      lastAt: start + 36 * HOUR_MS,
      count: 12,
    });

    const inspectDb = new Database(dbPath, { readonly: true });
    try {
      const obsCount = (
        inspectDb
          .query("SELECT COUNT(*) AS n FROM security_events WHERE row_kind = 'observation'")
          .get() as { n: number }
      ).n;
      expect(obsCount).toBe(12);
    } finally {
      inspectDb.close();
    }

    // Replaying the pre-cutoff observation from the surviving second burst must NOT double-count.
    store.commitEventBatch({
      events: [events[25]!],
      burstWindowMs,
    });
    expect(store.recentEvents(0, 20)[0]!.count).toBe(12);

    // Transitive burst merge must also respect the 24h maximum span cap.
    const transTarget = "203.0.113.88";
    const tBase = start + 10 * DAY_MS;
    store.commitEventBatch({
      events: [
        eventFixture("tr-a", tBase, {
          target: transTarget,
          firstAt: tBase,
          lastAt: tBase + 10 * HOUR_MS,
          count: 2,
        }),
        eventFixture("tr-b", tBase + 11 * HOUR_MS, {
          target: transTarget,
          firstAt: tBase + 11 * HOUR_MS,
          lastAt: tBase + 20 * HOUR_MS,
          count: 2,
        }),
        eventFixture("tr-c", tBase + 21 * HOUR_MS, {
          target: transTarget,
          firstAt: tBase + 21 * HOUR_MS,
          lastAt: tBase + 26 * HOUR_MS,
          count: 2,
        }),
      ],
      burstWindowMs: 1_000,
    });

    // Trigger near A with burstWindowMs = 2h: bridges A [0, 10h] + B [11h, 20h] (span 20h <= 24h),
    // but must NOT transitively merge C [21h, 26h] (span 26h > 24h).
    store.commitEventBatch({
      events: [eventFixture("tr-bridge", tBase + 9 * HOUR_MS, { target: transTarget })],
      burstWindowMs: 2 * HOUR_MS,
    });

    const transAggs = store
      .recentEvents(0, 20)
      .filter((event) => event.target === transTarget)
      .sort((left, right) => left.firstAt - right.firstAt);
    expect(transAggs).toHaveLength(2);
    expect(transAggs[0]).toMatchObject({
      firstAt: tBase,
      lastAt: tBase + 20 * HOUR_MS,
      count: 5,
    });
    expect(transAggs[1]).toMatchObject({
      firstAt: tBase + 21 * HOUR_MS,
      lastAt: tBase + 26 * HOUR_MS,
      count: 2,
    });
  } finally {
    store.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("commitEventBatch rejects a singleton observation whose span exceeds 24h and rolls back batch and cursor", () => {
  const store = memoryStore();
  try {
    const base = 100 * DAY_MS;

    // Exact 24h span (MAX_BURST_SPAN_MS) is accepted.
    expect(
      store.commitEventBatch({
        events: [
          eventFixture("span-exact-24h", base, {
            firstAt: base,
            lastAt: base + 24 * HOUR_MS,
            count: 2,
          }),
        ],
        cursor: { source: "journal", expected: null, next: "span-c1" },
        burstWindowMs: 5_000,
      }),
    ).toBe(true);
    expect(store.getCursor("journal")).toBe("span-c1");
    expect(store.recentEvents(0, 10)).toHaveLength(1);

    // A singleton observation with lastAt - firstAt > 24h must be rejected atomically.
    expect(() =>
      store.commitEventBatch({
        events: [
          eventFixture("span-rolled-back", base + 1_000, { rule: "should_rollback" }),
          eventFixture("span-over-24h", base, {
            firstAt: base,
            lastAt: base + 24 * HOUR_MS + 1,
            count: 1,
          }),
        ],
        cursor: { source: "journal", expected: "span-c1", next: "span-c2" },
        burstWindowMs: 5_000,
      }),
    ).toThrow(RangeError);

    expect(store.getCursor("journal")).toBe("span-c1");
    expect(store.recentEvents(0, 10).map((event) => event.id)).toEqual(["span-exact-24h"]);
  } finally {
    store.close();
  }
});

test("commitEventBatch caches per-hour totals by (hourBucket, isNoise) without double-counting duplicates and catches intra-batch overflow", () => {
  const store = memoryStore();
  try {
    const baseHour = Date.UTC(2026, 4, 2, 14, 0, 0);

    expect(
      store.commitEventBatch({
        events: [eventFixture("cache-seed", baseHour + 1_000, { rule: "rule_a", count: 1 })],
        cursor: { source: "journal", expected: null, next: "cache-c1" },
        burstWindowMs: 5_000,
      }),
    ).toBe(true);

    const internalDb = (store as unknown as { db: Database }).db;
    internalDb
      .query("UPDATE security_events SET count = ? WHERE row_kind = 'observation' AND observation_id = 'cache-seed'")
      .run(Number.MAX_SAFE_INTEGER - 10);

    // Fits exactly at MAX_SAFE_INTEGER for signal: 6 (unique) + 6 (dup ignored) + 4 (unique) = +10;
    // noise bucket is tracked independently and does not interfere with signal headroom.
    expect(
      store.commitEventBatch({
        events: [
          eventFixture("cache-sig-1", baseHour + 2_000, { rule: "rule_b", count: 6 }),
          eventFixture("cache-sig-1", baseHour + 2_000, { rule: "rule_b", count: 6 }),
          eventFixture("cache-noise-1", baseHour + 2_500, { rule: "rule_noise", isNoise: true, count: 100 }),
          eventFixture("cache-sig-2", baseHour + 3_000, { rule: "rule_c", count: 4 }),
        ],
        cursor: { source: "journal", expected: "cache-c1", next: "cache-c2" },
        burstWindowMs: 5_000,
      }),
    ).toBe(true);
    expect(store.getCursor("journal")).toBe("cache-c2");

    // Seed another hour near MAX_SAFE_INTEGER and verify a second unique event in the same batch
    // triggers overflow via the in-transaction hourly cache and rolls back the entire batch.
    const nextHour = baseHour + HOUR_MS;
    expect(
      store.commitEventBatch({
        events: [eventFixture("cache-seed-2", nextHour + 1_000, { rule: "rule_d", count: 1 })],
        cursor: { source: "journal", expected: "cache-c2", next: "cache-c3" },
        burstWindowMs: 5_000,
      }),
    ).toBe(true);

    internalDb
      .query("UPDATE security_events SET count = ? WHERE row_kind = 'observation' AND observation_id = 'cache-seed-2'")
      .run(Number.MAX_SAFE_INTEGER - 5);

    expect(() =>
      store.commitEventBatch({
        events: [
          eventFixture("cache-intra-1", nextHour + 2_000, { rule: "rule_e", count: 4 }),
          eventFixture("cache-intra-2", nextHour + 3_000, { rule: "rule_f", count: 2 }),
        ],
        cursor: { source: "journal", expected: "cache-c3", next: "cache-c4" },
        burstWindowMs: 5_000,
      }),
    ).toThrow(RangeError);

    expect(store.getCursor("journal")).toBe("cache-c3");
    const rules = store.recentEvents(0, 20).map((event) => event.rule);
    expect(rules).not.toContain("rule_e");
    expect(rules).not.toContain("rule_f");
  } finally {
    store.close();
  }
});

test("recentObservations queries exact observation rows by rule, target, and time window", () => {
  const store = new SecurityStore(":memory:");
  try {
    const base = 1_796_000_000_000;
    expect(
      store.commitEventBatch({
        events: [
          eventFixture("obs-old", base - 360_000, {
            rule: "ssh_auth_failure",
            target: "198.51.100.42",
          }),
          eventFixture("obs-in-1", base - 200_000, {
            rule: "ssh_auth_failure",
            target: "198.51.100.42",
          }),
          eventFixture("obs-in-2", base - 60_000, {
            rule: "ssh_auth_failure",
            target: "198.51.100.42",
          }),
          eventFixture("obs-future", base + 10_000, {
            rule: "ssh_auth_failure",
            target: "198.51.100.42",
          }),
          eventFixture("obs-other-target", base - 60_000, {
            rule: "ssh_auth_failure",
            target: "203.0.113.7",
          }),
          eventFixture("obs-other-rule", base - 60_000, {
            rule: "ufw_block",
            target: "198.51.100.42",
          }),
        ],
        burstWindowMs: 300_000,
      }),
    ).toBe(true);

    // Even though all 4 observations for 198.51.100.42 merged into a single aggregate,
    // recentObservations returns individual observation rows within [since, until].
    expect(store.recentEvents(0, 20).filter((e) => e.rule === "ssh_auth_failure" && e.target === "198.51.100.42")).toHaveLength(1);

    const sinceOnly = store.recentObservations("ssh_auth_failure", "198.51.100.42", base - 300_000);
    expect(sinceOnly.map((e) => e.id).sort()).toEqual(["obs-future", "obs-in-1", "obs-in-2"]);

    const bounded = store.recentObservations(
      "ssh_auth_failure",
      "198.51.100.42",
      base - 300_000,
      base,
    );
    expect(bounded.map((e) => e.id).sort()).toEqual(["obs-in-1", "obs-in-2"]);
  } finally {
    store.close();
  }
});
