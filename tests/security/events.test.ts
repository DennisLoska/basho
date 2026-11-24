import { describe, expect, spyOn, test } from "bun:test";
import { EventMonitor, parseJournalRecord } from "../../src/security/events";
import { createCommandRunner } from "../../src/security/runner";
import { SecurityStore } from "../../src/security/store";
import type {
  Clock,
  CommandRequest,
  CommandResult,
  CommandRunner,
  EnrolledWorkload,
  ExposureEntry,
  Listener,
  SecurityEvent,
} from "../../src/security/types";

const SECOND_MS = 1_000;
const MINUTE_MS = 60 * SECOND_MS;
const HOUR_MS = 60 * MINUTE_MS;
const NOW = 1_796_000_000_000;
const PEER = "198.51.100.42";

function memoryStore(): SecurityStore {
  return new SecurityStore(":memory:");
}

function clockAt(now: number): Clock {
  return { now: () => now };
}

function runnerStub(
  handler: (request: CommandRequest) => CommandResult,
  requests: CommandRequest[] = [],
): CommandRunner {
  return {
    async run(request: CommandRequest): Promise<CommandResult> {
      requests.push(request);
      return handler(request);
    },
  };
}

function ok(stdout: string): CommandResult {
  return { status: "ok", stdout, exitCode: 0 };
}

/** Builds a journalctl -o json line with fixture defaults. */
function jline(overrides: Record<string, unknown>): string {
  return JSON.stringify({
    __REALTIME_TIMESTAMP: String(NOW * 1000),
    _TRANSPORT: "syslog",
    SYSLOG_IDENTIFIER: "sshd",
    ...overrides,
  });
}

function sshFailureMessage(peer: string, kind = "Failed password for invalid user admin"): string {
  return `${kind} from ${peer} port 49822 ssh2`;
}

function parsedEvent(line: string): SecurityEvent {
  const parsed = parseJournalRecord(line);
  if (!parsed || !parsed.event) {
    throw new Error(`expected a parsed security event, got ${JSON.stringify(parsed)}`);
  }
  return parsed.event;
}

function journalPage(lines: string[]): CommandResult {
  return ok(lines.join("\n"));
}

const SS_LOOPBACK =
  'tcp   LISTEN 0      4096   127.0.0.1:3000       0.0.0.0:*    users:(("node",pid=1111,fd=20))';
const SS_ALT_LOOPBACK =
  'tcp   LISTEN 0      4096   127.0.0.1:3001       0.0.0.0:*    users:(("node",pid=1112,fd=20))';
const SS_WILDCARD =
  'tcp   LISTEN 0      4096   0.0.0.0:8188         0.0.0.0:*    users:(("python3",pid=4242,fd=3))';
const SS_WORKLOAD =
  'tcp   LISTEN 0      4096   0.0.0.0:8188         0.0.0.0:*    users:(("comfy",pid=4242,fd=3))';
const SS_ROGUE =
  'tcp   LISTEN 0      4096   0.0.0.0:9999         0.0.0.0:*    users:(("rogue",pid=5555,fd=3))';

function ssOutput(...lines: string[]): CommandResult {
  return ok(lines.join("\n"));
}

function benignEntries(listeners: Listener[]): ExposureEntry[] {
  return listeners.map((listener) => ({
    id: `exposure:${listener.id}`,
    listener,
    reachability: listener.address === "127.0.0.1" ? "local_only" : "exposed_lan",
    firewallV4: "allow",
    firewallV6: "na",
    publication: "none",
    expected: true,
    evidenceIds: [`evidence:${listener.id}`],
  }));
}

function unexpectedEntries(listeners: Listener[]): ExposureEntry[] {
  return listeners.map((listener) => ({
    id: `exposure:${listener.id}`,
    listener,
    reachability: listener.address === "127.0.0.1" ? "local_only" : "exposed_v4_v6",
    firewallV4: listener.address === "127.0.0.1" ? "deny" : "allow",
    firewallV6: "na",
    publication: "none",
    expected: listener.address === "127.0.0.1",
    evidenceIds: [`evidence:${listener.id}`],
  }));
}

function networkEventTotal(store: SecurityStore): number {
  return store
    .recentEvents(0, 500)
    .filter((event) => event.category === "network")
    .reduce((total, event) => total + event.count, 0);
}

function authEventTotal(store: SecurityStore, target: string): number {
  return store
    .recentEvents(0, 500)
    .filter((event) => event.category === "auth" && event.target === target)
    .reduce((total, event) => total + event.count, 0);
}

describe("parseJournalRecord", () => {
  test("classifies SSH auth failures with a canonical peer target", () => {
    const cases = [
      { identifier: "sshd", message: sshFailureMessage(PEER) },
      {
        identifier: "sshd-session",
        message: sshFailureMessage(PEER, "Invalid user admin"),
      },
      {
        identifier: "sshd-session",
        message: sshFailureMessage(PEER, "Failed publickey for admin"),
      },
    ];

    for (const [index, entry] of cases.entries()) {
      const event = parsedEvent(
        jline({
          __CURSOR: `s=ssh;i=${index}`,
          SYSLOG_IDENTIFIER: entry.identifier,
          MESSAGE: entry.message,
        }),
      );

      expect(event.source).toBe("journal");
      expect(event.category).toBe("auth");
      expect(event.isNoise).toBe(false);
      expect(event.target).toBe(PEER);
      expect(event.count).toBe(1);
    }
  });

  test("canonicalizes IPv4-mapped peer addresses", () => {
    const event = parsedEvent(
      jline({
        __CURSOR: "s=mapped;i=1",
        MESSAGE: sshFailureMessage("::ffff:198.51.100.42"),
      }),
    );

    expect(event.target).toBe(PEER);
    expect(event.isNoise).toBe(false);
  });

  test("keeps injected message text out of the controlled summary", () => {
    const message = `${sshFailureMessage(PEER)} <img src=x onerror=alert(1)>`;
    const event = parsedEvent(
      jline({ __CURSOR: "s=inject;i=1", MESSAGE: message }),
    );

    expect(event.summary).not.toBe(message);
    expect(event.summary).not.toContain("<img");
    expect(event.summary).not.toContain("onerror");
    expect(event.summary.length).toBeGreaterThan(0);
  });

  test("marks recognized multicast and loopback firewall blocks as noise", () => {
    const noiseMessages = [
      "[UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=203.0.113.9 DST=224.0.0.1 LEN=36 PROTO=2",
      "[UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=2001:db8::9 DST=ff02::1 LEN=80 PROTO=58",
      "[UFW BLOCK] IN=lo OUT= MAC=00:00:00:00:00:00 SRC=127.0.0.1 DST=127.0.0.1 LEN=60 PROTO=TCP SPT=51234 DPT=8188",
      "[UFW BLOCK] IN=lo OUT= MAC=00:00:00:00:00:00 SRC=::1 DST=::1 LEN=80 PROTO=TCP SPT=51234 DPT=8188",
    ];

    for (const [index, message] of noiseMessages.entries()) {
      const event = parsedEvent(
        jline({
          __CURSOR: `s=noise;i=${index}`,
          _TRANSPORT: "kernel",
          SYSLOG_IDENTIFIER: "kernel",
          MESSAGE: message,
        }),
      );

      expect(event.category).toBe("firewall");
      expect(event.isNoise).toBe(true);
    }
  });

  test("keeps non-multicast firewall blocks as signal with the canonical source target", () => {
    const event = parsedEvent(
      jline({
        __CURSOR: "s=fw;i=1",
        _TRANSPORT: "kernel",
        SYSLOG_IDENTIFIER: "kernel",
        MESSAGE:
          "[UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=198.51.100.42 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=51234 DPT=8188 WINDOW=65535 SYN",
      }),
    );

    expect(event.category).toBe("firewall");
    expect(event.isNoise).toBe(false);
    expect(event.target).toBe(PEER);
  });

  test("classifies OOM, privilege escalation, failed units, and package changes", () => {
    const oom = parsedEvent(
      jline({
        __CURSOR: "s=oom;i=1",
        _TRANSPORT: "kernel",
        SYSLOG_IDENTIFIER: "kernel",
        MESSAGE:
          "Out of memory: Killed process 4242 (node) total-vm:1048576kB, anon-rss:524288kB, file-rss:0kB, shmem-rss:0kB",
      }),
    );
    expect(oom.category).toBe("units");
    expect(oom.severity).toBe("critical");
    expect(oom.isNoise).toBe(false);

    const sudo = parsedEvent(
      jline({
        __CURSOR: "s=sudo;i=1",
        SYSLOG_IDENTIFIER: "sudo",
        MESSAGE: "dennis : TTY=pts/0 ; PWD=/home/dennis ; USER=root ; COMMAND=/usr/bin/id",
      }),
    );
    expect(sudo.category).toBe("auth");
    expect(sudo.isNoise).toBe(false);

    const polkit = parsedEvent(
      jline({
        __CURSOR: "s=polkit;i=1",
        SYSLOG_IDENTIFIER: "polkitd",
        MESSAGE:
          "Operator of unix-process:1234:5678 successfully authenticated as unix-user:dennis to gain one-shot authorization for org.freedesktop.systemd1.manage-units",
      }),
    );
    expect(polkit.category).toBe("auth");
    expect(polkit.isNoise).toBe(false);

    const failedUnit = parsedEvent(
      jline({
        __CURSOR: "s=unit;i=1",
        SYSLOG_IDENTIFIER: "systemd",
        _SYSTEMD_UNIT: "backup.service",
        MESSAGE: "backup.service: Failed with result 'exit-code'.",
      }),
    );
    expect(failedUnit.category).toBe("units");
    expect(failedUnit.isNoise).toBe(false);

    const installed = parsedEvent(
      jline({
        __CURSOR: "s=pkg-install;i=1",
        SYSLOG_IDENTIFIER: "pacman",
        MESSAGE: "[ALPM] installed zlib (1:1.3.1-1)",
      }),
    );
    expect(installed.category).toBe("packages");
    expect(installed.isNoise).toBe(false);
    expect(installed.summary.length).toBeGreaterThan(0);
    expect(installed.summary).not.toContain("[ALPM]");

    const upgraded = parsedEvent(
      jline({
        __CURSOR: "s=pkg-upgrade;i=1",
        SYSLOG_IDENTIFIER: "pacman",
        MESSAGE: "[ALPM] upgraded openssl (3.5.0-1 -> 3.5.1-1)",
      }),
    );
    expect(upgraded.category).toBe("packages");
    expect(upgraded.isNoise).toBe(false);
  });

  test("returns the cursor without an event for irrelevant records", () => {
    const parsed = parseJournalRecord(
      jline({
        __CURSOR: "s=irrelevant;i=7",
        SYSLOG_IDENTIFIER: "cron",
        MESSAGE: "(root) CMD (run-parts /etc/cron.hourly)",
      }),
    );

    expect(parsed).not.toBeNull();
    expect(parsed!.cursor).toBe("s=irrelevant;i=7");
    expect(parsed!.event).toBeUndefined();
  });

  test("returns null for malformed or cursor-less records", () => {
    expect(parseJournalRecord("{not json")).toBeNull();
    expect(
      parseJournalRecord(
        JSON.stringify({
          __REALTIME_TIMESTAMP: String(NOW * 1000),
          SYSLOG_IDENTIFIER: "sshd",
          MESSAGE: sshFailureMessage(PEER),
        }),
      ),
    ).toBeNull();
    expect(
      parseJournalRecord(jline({ __CURSOR: "", MESSAGE: sshFailureMessage(PEER) })),
    ).toBeNull();
    expect(
      parseJournalRecord(jline({ __CURSOR: "bad cursor!", MESSAGE: sshFailureMessage(PEER) })),
    ).toBeNull();
  });
});

describe("EventMonitor.pollJournal", () => {
  test("requests the bounded replay window and resumes from the committed cursor", async () => {
    const store = memoryStore();
    const requests: CommandRequest[] = [];
    let poll = 0;
    const runner = runnerStub(() => {
      poll += 1;
      return poll === 1
        ? journalPage([
            jline({
              __CURSOR: "s=cursor;i=1",
              SYSLOG_IDENTIFIER: "cron",
              MESSAGE: "(root) CMD (true)",
            }),
          ])
        : ok("");
    }, requests);
    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

    try {
      const first = await monitor.pollJournal();
      expect(first.alerts).toEqual([]);
      expect(first.corroboration).toEqual([]);
      expect(requests[0]).toEqual({ kind: "journal", after: undefined, limit: 200 });

      await monitor.pollJournal();
      expect(requests[1]).toEqual({ kind: "journal", after: "s=cursor;i=1", limit: 200 });
    } finally {
      store.close();
    }
  });

  test("aggregates SSH failures in the window and corroborates a deny_peer_ip target", async () => {
    const store = memoryStore();
    const lines = Array.from({ length: 5 }, (_, index) =>
      jline({
        __CURSOR: `s=burst;i=${index}`,
        __REALTIME_TIMESTAMP: String((NOW - index * SECOND_MS) * 1000),
        MESSAGE: sshFailureMessage(PEER),
      }),
    );
    const runner = runnerStub(() => journalPage(lines));
    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

    try {
      const result = await monitor.pollJournal();
      const burst = result.corroboration.find((entry) => entry.rule === "ssh_burst");

      expect(burst).toBeDefined();
      expect(burst!.target).toEqual({ kind: "deny_peer_ip", ip: PEER });
      expect(burst!.eventIds.length).toBeGreaterThan(0);
      expect(burst!.expiresAt).toBeGreaterThan(NOW);

      expect(result.alerts.length).toBeGreaterThan(0);
      expect(authEventTotal(store, PEER)).toBe(5);
    } finally {
      store.close();
    }
  });

  test("never targets excluded loopback or tailnet peers", async () => {
    const store = memoryStore();
    const excluded = ["127.0.0.1", "::1", "100.64.0.5", "fd7a:115c:a1e0::34"];
    const lines = excluded.flatMap((peer, peerIndex) =>
      Array.from({ length: 5 }, (_, index) =>
        jline({
          __CURSOR: `s=excluded;${peerIndex};${index}`,
          __REALTIME_TIMESTAMP: String(
            (NOW - (peerIndex * 5 + index) * SECOND_MS) * 1000,
          ),
          MESSAGE: sshFailureMessage(peer),
        }),
      ),
    );
    const runner = runnerStub(() => journalPage(lines));
    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

    try {
      const result = await monitor.pollJournal();
      const denied = result.corroboration.filter(
        (entry) => entry.target?.kind === "deny_peer_ip",
      );

      expect(denied).toEqual([]);
    } finally {
      store.close();
    }
  });

  test("does not trigger when only one failure lands in the current five-minute window", async () => {
    const store = memoryStore();
    const staleLines = Array.from({ length: 4 }, (_, index) =>
      jline({
        __CURSOR: `s=stale;i=${index}`,
        __REALTIME_TIMESTAMP: String((NOW - 6 * MINUTE_MS - index * SECOND_MS) * 1000),
        MESSAGE: sshFailureMessage(PEER),
      }),
    );
    const freshLine = jline({
      __CURSOR: "s=fresh;i=1",
      __REALTIME_TIMESTAMP: String(NOW * 1000),
      MESSAGE: sshFailureMessage(PEER),
    });
    const runner = runnerStub(() => journalPage([...staleLines, freshLine]));
    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

    try {
      const result = await monitor.pollJournal();

      expect(result.corroboration.some((entry) => entry.rule === "ssh_burst")).toBe(false);
      expect(authEventTotal(store, PEER)).toBe(5);
    } finally {
      store.close();
    }
  });

  test("keeps per-hour counts accurate across a UTC hour boundary", async () => {
    const store = memoryStore();
    const hourStart = Math.floor(NOW / HOUR_MS) * HOUR_MS;
    const now = hourStart + 2 * MINUTE_MS;
    const times = [
      hourStart - MINUTE_MS,
      hourStart - 30 * SECOND_MS,
      hourStart + 30 * SECOND_MS,
      hourStart + 60 * SECOND_MS,
      now,
    ];
    const lines = times.map((at, index) =>
      jline({
        __CURSOR: `s=hour;i=${index}`,
        __REALTIME_TIMESTAMP: String(at * 1000),
        MESSAGE: sshFailureMessage(PEER),
      }),
    );
    const runner = runnerStub(() => journalPage(lines));
    const monitor = new EventMonitor({ store, runner, clock: clockAt(now) });

    try {
      const result = await monitor.pollJournal();
      expect(result.corroboration.some((entry) => entry.rule === "ssh_burst")).toBe(true);

      const buckets = store.hourlyEvents(now);
      const currentHour = buckets.find((bucket) => bucket.hour === hourStart);
      const previousHour = buckets.find((bucket) => bucket.hour === hourStart - HOUR_MS);

      expect(currentHour?.signal).toBe(3);
      expect(previousHour?.signal).toBe(2);
      expect(buckets.every((bucket) => bucket.noise === 0)).toBe(true);
    } finally {
      store.close();
    }
  });

  test("preserves the committed cursor and degrades coverage on a temporary read failure", async () => {
    for (const status of ["failed", "timeout", "unavailable"] as const) {
      const store = memoryStore();
      const requests: CommandRequest[] = [];
      let poll = 0;
      const runner = runnerStub(() => {
        poll += 1;
        if (poll === 1) {
          return journalPage([
            jline({
              __CURSOR: "s=kept;i=1",
              SYSLOG_IDENTIFIER: "cron",
              MESSAGE: "(root) CMD (true)",
            }),
          ]);
        }
        if (poll === 2) {
          return { status };
        }
        return ok("");
      }, requests);
      const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

      try {
        await monitor.pollJournal();
        const failed = await monitor.pollJournal();

        expect(failed.alerts).toEqual([]);
        expect(failed.corroboration).toEqual([]);
        expect(["partial", "unavailable"]).toContain(failed.coverage);

        await monitor.pollJournal();
        expect(requests[2]).toEqual({ kind: "journal", after: "s=kept;i=1", limit: 200 });
      } finally {
        store.close();
      }
    }
  });

  test("stops at a malformed record without advancing past it", async () => {
    const store = memoryStore();
    const requests: CommandRequest[] = [];
    const runner = runnerStub(() => {
      if (requests.length === 1) {
        return journalPage([
          jline({
            __CURSOR: "s=ok;i=1",
            SYSLOG_IDENTIFIER: "cron",
            MESSAGE: "(root) CMD (true)",
          }),
          "{not json",
        ]);
      }
      return ok("");
    }, requests);
    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

    try {
      const first = await monitor.pollJournal();
      expect(["partial", "unavailable"]).toContain(first.coverage);

      await monitor.pollJournal();
      expect(requests[1]).toEqual({ kind: "journal", after: "s=ok;i=1", limit: 200 });
    } finally {
      store.close();
    }
  });

  test("does not advance the cursor when the first record is corrupt", async () => {
    const store = memoryStore();
    const requests: CommandRequest[] = [];
    const runner = runnerStub(() => {
      if (requests.length === 1) {
        return journalPage([
          "{not json",
          jline({
            __CURSOR: "s=after-corrupt;i=1",
            SYSLOG_IDENTIFIER: "cron",
            MESSAGE: "(root) CMD (true)",
          }),
        ]);
      }
      return ok("");
    }, requests);
    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

    try {
      const first = await monitor.pollJournal();
      expect(["partial", "unavailable"]).toContain(first.coverage);

      await monitor.pollJournal();
      expect(requests[1]).toEqual({ kind: "journal", after: undefined, limit: 200 });
    } finally {
      store.close();
    }
  });

  test("raises alerts for high-signal events without inferring containment from message text", async () => {
    const store = memoryStore();
    const lines = [
      jline({
        __CURSOR: "s=oom;i=1",
        _TRANSPORT: "kernel",
        SYSLOG_IDENTIFIER: "kernel",
        MESSAGE:
          "Out of memory: Killed process 4242 (node) listening on 0.0.0.0:8188 behind ufw allow from 203.0.113.9",
      }),
      jline({
        __CURSOR: "s=sudo;i=1",
        SYSLOG_IDENTIFIER: "sudo",
        MESSAGE:
          "dennis : TTY=pts/0 ; PWD=/home/dennis ; USER=root ; COMMAND=/usr/bin/id deny 203.0.113.9",
      }),
      jline({
        __CURSOR: "s=unit;i=1",
        SYSLOG_IDENTIFIER: "systemd",
        _SYSTEMD_UNIT: "backup.service",
        MESSAGE: "backup.service: Failed with result 'exit-code'. ufw deny 203.0.113.9",
      }),
    ];
    const runner = runnerStub(() => journalPage(lines));
    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

    try {
      const result = await monitor.pollJournal();

      expect(result.alerts.length).toBeGreaterThan(0);
      expect(result.corroboration.every((entry) => entry.target === undefined)).toBe(true);
    } finally {
      store.close();
    }
  });
});

describe("EventMonitor.pollSockets", () => {
  test("establishes a baseline without cold start events", async () => {
    const store = memoryStore();
    const requests: CommandRequest[] = [];
    const runner = runnerStub(() => ssOutput(SS_LOOPBACK), requests);
    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });
    let classified: Listener[] = [];

    try {
      const result = await monitor.pollSockets(async (listeners) => {
        classified = listeners;
        return benignEntries(listeners);
      });

      expect(requests[0]?.kind).toBe("sockets");
      expect(classified).toHaveLength(1);
      expect(classified[0]?.port).toBe(3000);
      expect(result.alerts).toEqual([]);
      expect(result.corroboration).toEqual([]);
      expect(networkEventTotal(store)).toBe(0);
    } finally {
      store.close();
    }
  });

  test("emits events for a new non-loopback listener and its closure", async () => {
    const store = memoryStore();
    let poll = 0;
    const runner = runnerStub(() => {
      poll += 1;
      if (poll === 1) return ssOutput(SS_LOOPBACK);
      if (poll === 2) return ssOutput(SS_LOOPBACK, SS_WILDCARD);
      return ssOutput(SS_LOOPBACK);
    });
    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

    try {
      await monitor.pollSockets(async (listeners) => benignEntries(listeners));
      expect(networkEventTotal(store)).toBe(0);

      await monitor.pollSockets(async (listeners) => benignEntries(listeners));
      const afterOpen = networkEventTotal(store);
      expect(afterOpen).toBeGreaterThan(0);

      await monitor.pollSockets(async (listeners) => benignEntries(listeners));
      expect(networkEventTotal(store)).toBeGreaterThan(afterOpen);
    } finally {
      store.close();
    }
  });

  test("preserves the baseline across a failed socket read", async () => {
    const store = memoryStore();
    let poll = 0;
    const runner = runnerStub(() => {
      poll += 1;
      if (poll === 1) return ssOutput(SS_WILDCARD);
      if (poll === 2) return { status: "failed" };
      if (poll === 3) return ssOutput(SS_WILDCARD);
      return ssOutput(SS_LOOPBACK);
    });
    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

    try {
      await monitor.pollSockets(async (listeners) => benignEntries(listeners));
      expect(networkEventTotal(store)).toBe(0);

      const failed = await monitor.pollSockets(async (listeners) => benignEntries(listeners));
      expect(failed.alerts).toEqual([]);
      expect(networkEventTotal(store)).toBe(0);

      await monitor.pollSockets(async (listeners) => benignEntries(listeners));
      expect(networkEventTotal(store)).toBe(0);

      await monitor.pollSockets(async (listeners) => benignEntries(listeners));
      expect(networkEventTotal(store)).toBeGreaterThan(0);
    } finally {
      store.close();
    }
  });

  test("ignores loopback listener drift", async () => {
    const store = memoryStore();
    let poll = 0;
    const runner = runnerStub(() => {
      poll += 1;
      return poll === 1 ? ssOutput(SS_LOOPBACK) : ssOutput(SS_ALT_LOOPBACK);
    });
    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

    try {
      await monitor.pollSockets(async (listeners) => benignEntries(listeners));
      await monitor.pollSockets(async (listeners) => benignEntries(listeners));

      expect(networkEventTotal(store)).toBe(0);
    } finally {
      store.close();
    }
  });

  for (const reachability of ["exposed_v4_v6", "exposed_lan"] as const) {
    test(`alerts on an unexpected wildcard listener classified ${reachability}`, async () => {
      const store = memoryStore();
      let poll = 0;
      const runner = runnerStub(() => {
        poll += 1;
        return poll === 1 ? ssOutput(SS_LOOPBACK) : ssOutput(SS_LOOPBACK, SS_WILDCARD);
      });
      const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

      try {
        await monitor.pollSockets(async (listeners) => benignEntries(listeners));

        const result = await monitor.pollSockets(async (listeners) =>
          listeners.map((listener) =>
            listener.port === 8188
              ? {
                  id: `exposure:${listener.id}`,
                  listener,
                  reachability,
                  firewallV4: "allow",
                  firewallV6: "na",
                  publication: "none",
                  expected: false,
                  evidenceIds: [`evidence:${listener.id}`],
                }
              : unexpectedEntries([listener])[0]!,
          ),
        );

        expect(result.alerts.length).toBeGreaterThan(0);

        const corroborated = result.corroboration.find(
          (entry) =>
            entry.rule === "unexpected_listener" || entry.rule === "unexpected_workload",
        );
        expect(corroborated).toBeDefined();
        expect(result.corroboration.every((entry) => entry.target === undefined)).toBe(true);
      } finally {
        store.close();
      }
    });
  }

  test("attaches an exact workload target when an enrolled identity matches", async () => {
    const store = memoryStore();
    const workloads: EnrolledWorkload[] = [
      { id: "comfy", unit: "comfy.service", name: "comfy", ports: [8188] },
    ];
    let poll = 0;
    const runner = runnerStub((request) => {
      if (request.kind === "processes") {
        return ok("  4242     1  1000   120 user@1000.service comfy.service comfy\n");
      }
      poll += 1;
      return poll === 1 ? ssOutput(SS_LOOPBACK) : ssOutput(SS_LOOPBACK, SS_WORKLOAD);
    });
    const monitor = new EventMonitor({
      store,
      runner,
      clock: clockAt(NOW),
      workloads,
    });

    try {
      await monitor.pollSockets(async (listeners) => benignEntries(listeners));

      const result = await monitor.pollSockets(async (listeners) =>
        unexpectedEntries(listeners),
      );

      const corroborated = result.corroboration.find(
        (entry) => entry.target?.kind === "pause_workload",
      );

      expect(corroborated).toBeDefined();
      expect(corroborated!.rule === "unexpected_workload" || corroborated!.rule === "unexpected_listener").toBe(
        true,
      );
      expect(corroborated!.target).toMatchObject({
        kind: "pause_workload",
        workloadId: "comfy",
        pid: 4242,
      });
      expect(result.alerts.length).toBeGreaterThan(0);
    } finally {
      store.close();
    }
  });

  test("leaves an unmatched listener without a containment target", async () => {
    const store = memoryStore();
    const workloads: EnrolledWorkload[] = [
      { id: "comfy", unit: "comfy.service", name: "comfy", ports: [8188] },
    ];
    let poll = 0;
    const runner = runnerStub(() => {
      poll += 1;
      return poll === 1 ? ssOutput(SS_LOOPBACK) : ssOutput(SS_LOOPBACK, SS_ROGUE);
    });
    const monitor = new EventMonitor({
      store,
      runner,
      clock: clockAt(NOW),
      workloads,
    });

    try {
      await monitor.pollSockets(async (listeners) => benignEntries(listeners));

      const result = await monitor.pollSockets(async (listeners) =>
        unexpectedEntries(listeners),
      );

      expect(result.alerts.length).toBeGreaterThan(0);
      expect(result.corroboration.every((entry) => entry.target === undefined)).toBe(true);
    } finally {
      store.close();
    }
  });
});

describe("EventMonitor edge cases", () => {
  test("canonicalizes full IPv6 peer addresses and resists SSH username spoofing", () => {
    const ipv6Event = parsedEvent(
      jline({
        __CURSOR: "s=v6;i=1",
        SYSLOG_IDENTIFIER: "sshd-session",
        MESSAGE:
          "Connection closed by authenticating user admin from 203.0.113.9 port 22 2001:0DB8:0000:0000:0000:0000:0000:0009 port 49822 [preauth]",
      }),
    );

    expect(ipv6Event.category).toBe("auth");
    expect(ipv6Event.target).toBe("2001:db8::9");
    expect(ipv6Event.summary).not.toContain("203.0.113.9");
  });

  test("ages out stale SSH failures across stored bursts when adjacent gaps stay under 5 minutes", async () => {
    const store = memoryStore();
    let currentTime = NOW;
    const clock: Clock = { now: () => currentTime };
    let poll = 0;
    const runner = runnerStub(() => {
      poll += 1;
      if (poll === 1) {
        return journalPage([
          jline({
            __CURSOR: "s=chain;i=1",
            __REALTIME_TIMESTAMP: String((NOW - 6 * MINUTE_MS) * 1000),
            MESSAGE: sshFailureMessage(PEER),
          }),
          jline({
            __CURSOR: "s=chain;i=2",
            __REALTIME_TIMESTAMP: String((NOW - 4 * MINUTE_MS) * 1000),
            MESSAGE: sshFailureMessage(PEER),
          }),
          jline({
            __CURSOR: "s=chain;i=3",
            __REALTIME_TIMESTAMP: String((NOW - 3 * MINUTE_MS) * 1000),
            MESSAGE: sshFailureMessage(PEER),
          }),
          jline({
            __CURSOR: "s=chain;i=4",
            __REALTIME_TIMESTAMP: String((NOW - 2 * MINUTE_MS) * 1000),
            MESSAGE: sshFailureMessage(PEER),
          }),
        ]);
      }
      return journalPage([
        jline({
          __CURSOR: "s=chain;i=5",
          __REALTIME_TIMESTAMP: String(NOW * 1000),
          MESSAGE: sshFailureMessage(PEER),
        }),
      ]);
    });
    const monitor = new EventMonitor({ store, runner, clock });

    try {
      const first = await monitor.pollJournal();
      expect(first.corroboration.some((entry) => entry.rule === "ssh_burst")).toBe(false);

      const second = await monitor.pollJournal();
      // Only 4 failures fall inside [NOW - 5m, NOW] even though the store merged all 5 into one aggregate.
      expect(second.corroboration.some((entry) => entry.rule === "ssh_burst")).toBe(false);
      expect(authEventTotal(store, PEER)).toBe(5);
    } finally {
      store.close();
    }
  });

  test("does not match an enrolled workload when process name differs on the same port", async () => {
    const store = memoryStore();
    const workloads: EnrolledWorkload[] = [
      { id: "comfy", unit: "comfy.service", name: "comfy", ports: [8188] },
    ];
    let poll = 0;
    const runner = runnerStub(() => {
      poll += 1;
      return poll === 1 ? ssOutput(SS_LOOPBACK) : ssOutput(SS_LOOPBACK, SS_WILDCARD);
    });
    const monitor = new EventMonitor({
      store,
      runner,
      clock: clockAt(NOW),
      workloads,
    });

    try {
      await monitor.pollSockets(async (listeners) => benignEntries(listeners));
      const result = await monitor.pollSockets(async (listeners) =>
        unexpectedEntries(listeners),
      );

      expect(result.alerts.length).toBeGreaterThan(0);
      expect(result.corroboration).toHaveLength(1);
      expect(result.corroboration[0]?.rule).toBe("unexpected_listener");
      expect(result.corroboration[0]?.target).toBeUndefined();
    } finally {
      store.close();
    }
  });

  test("does not mark non-listed multicast firewall blocks such as SSDP 239.255.255.250 as noise", () => {
    const nonNoiseMulticast = [
      "[UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=198.51.100.42 DST=239.255.255.250 LEN=60 PROTO=UDP SPT=51234 DPT=1900",
      "[UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=198.51.100.42 DST=224.0.0.251 LEN=60 PROTO=UDP SPT=5353 DPT=5353",
      "[UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=2001:db8::9 DST=ff02::2 LEN=80 PROTO=58",
    ];

    for (const [index, message] of nonNoiseMulticast.entries()) {
      const event = parsedEvent(
        jline({
          __CURSOR: `s=non-noise-mcast;i=${index}`,
          _TRANSPORT: "kernel",
          SYSLOG_IDENTIFIER: "kernel",
          MESSAGE: message,
        }),
      );

      expect(event.category).toBe("firewall");
      expect(event.isNoise).toBe(false);
    }
  });

  test("recovers from an expired journal cursor via bounded recent window with gap notice and partial coverage", async () => {
    const store = memoryStore();
    const requests: CommandRequest[] = [];
    let stage = 0;
    const runner = runnerStub((request) => {
      stage += 1;
      if (stage === 1) {
        return journalPage([
          jline({
            __CURSOR: "s=expired;i=1",
            SYSLOG_IDENTIFIER: "cron",
            MESSAGE: "(root) CMD (true)",
          }),
        ]);
      }
      if (stage === 2) {
        expect(request).toEqual({ kind: "journal", after: "s=expired;i=1", limit: 200 });
        return { status: "cursor_expired" };
      }
      if (stage === 3) {
        expect(request).toEqual({ kind: "journal", after: undefined, limit: 200 });
        return journalPage([
          jline({
            __CURSOR: "s=recovered;i=9",
            SYSLOG_IDENTIFIER: "sshd",
            MESSAGE: sshFailureMessage(PEER),
          }),
        ]);
      }
      return ok("");
    }, requests);
    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

    try {
      const initial = await monitor.pollJournal();
      expect(initial.coverage).toBe("complete");
      expect(store.getCursor("journal")).toBe("s=expired;i=1");

      const recovered = await monitor.pollJournal();
      expect(recovered.coverage).toBe("partial");
      expect(store.getCursor("journal")).toBe("s=recovered;i=9");

      const stored = store.recentEvents(0, 50);
      const gapEvent = stored.find((event) => event.rule === "journal_cursor_gap");
      expect(gapEvent).toBeDefined();
      expect(gapEvent!.source).toBe("journal");
      expect(gapEvent!.isNoise).toBe(false);
      expect(gapEvent!.severity).toBe("warning");
      expect(authEventTotal(store, PEER)).toBe(1);

      await monitor.pollJournal();
      expect(requests[3]).toEqual({ kind: "journal", after: "s=recovered;i=9", limit: 200 });
    } finally {
      store.close();
    }
  });

  test("aborts expired-cursor recovery atomically on cursor CAS mismatch without writing gap or recovered events", async () => {
    const store = memoryStore();
    let stage = 0;
    const runner = runnerStub(() => {
      stage += 1;
      if (stage === 1) {
        return journalPage([
          jline({
            __CURSOR: "s=cas-old;i=1",
            SYSLOG_IDENTIFIER: "cron",
            MESSAGE: "(root) CMD (true)",
          }),
        ]);
      }
      if (stage === 2) {
        return { status: "cursor_expired" };
      }
      // Simulate a concurrent poller advancing the cursor before recovery commits.
      const raced = store.commitEventBatch({
        events: [],
        cursor: { source: "journal", expected: "s=cas-old;i=1", next: "s=cas-winner;i=99" },
        burstWindowMs: 300_000,
      });
      expect(raced).toBe(true);

      return journalPage([
        jline({
          __CURSOR: "s=cas-stale-recovery;i=5",
          SYSLOG_IDENTIFIER: "sshd",
          MESSAGE: sshFailureMessage(PEER),
        }),
      ]);
    });
    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

    try {
      await monitor.pollJournal();
      expect(store.getCursor("journal")).toBe("s=cas-old;i=1");

      const result = await monitor.pollJournal();
      expect(result).toEqual({ alerts: [], corroboration: [], coverage: "partial" });
      expect(store.getCursor("journal")).toBe("s=cas-winner;i=99");
      expect(store.recentEvents(0, 50)).toEqual([]);
    } finally {
      store.close();
    }
  });

  test("persists the 5-minute SSH failure window across EventMonitor restarts", async () => {
    const store = memoryStore();
    const firstRunner = runnerStub(() =>
      journalPage([
        jline({
          __CURSOR: "s=restart;i=1",
          __REALTIME_TIMESTAMP: String((NOW - 120 * SECOND_MS) * 1000),
          MESSAGE: sshFailureMessage(PEER),
        }),
        jline({
          __CURSOR: "s=restart;i=2",
          __REALTIME_TIMESTAMP: String((NOW - 90 * SECOND_MS) * 1000),
          MESSAGE: sshFailureMessage(PEER),
        }),
        jline({
          __CURSOR: "s=restart;i=3",
          __REALTIME_TIMESTAMP: String((NOW - 60 * SECOND_MS) * 1000),
          MESSAGE: sshFailureMessage(PEER),
        }),
      ]),
    );
    const secondRunner = runnerStub(() =>
      journalPage([
        jline({
          __CURSOR: "s=restart;i=4",
          __REALTIME_TIMESTAMP: String((NOW - 30 * SECOND_MS) * 1000),
          MESSAGE: sshFailureMessage(PEER),
        }),
        jline({
          __CURSOR: "s=restart;i=5",
          __REALTIME_TIMESTAMP: String(NOW * 1000),
          MESSAGE: sshFailureMessage(PEER),
        }),
      ]),
    );

    const monitor1 = new EventMonitor({ store, runner: firstRunner, clock: clockAt(NOW) });
    const monitor2 = new EventMonitor({ store, runner: secondRunner, clock: clockAt(NOW) });

    try {
      const first = await monitor1.pollJournal();
      expect(first.corroboration.some((entry) => entry.rule === "ssh_burst")).toBe(false);

      const second = await monitor2.pollJournal();
      const burst = second.corroboration.find((entry) => entry.rule === "ssh_burst");
      expect(burst).toBeDefined();
      expect(burst!.target).toEqual({ kind: "deny_peer_ip", ip: PEER });
      expect(burst!.eventIds).toHaveLength(5);
      expect(second.alerts.some((alert) => alert.fingerprint === `ssh_burst:${PEER}`)).toBe(true);
    } finally {
      store.close();
    }
  });

  test("computes pause_workload startedAt from real ps etimes instead of fabricating now", async () => {
    const store = memoryStore();
    const workloads: EnrolledWorkload[] = [
      { id: "comfy", unit: "comfy.service", name: "comfy", ports: [8188] },
    ];
    const etimesSeconds = 345;
    let socketPoll = 0;
    const runner = runnerStub((request) => {
      if (request.kind === "processes") {
        return ok(`  4242     1  1000   ${etimesSeconds} user@1000.service comfy.service comfy\n`);
      }
      socketPoll += 1;
      return socketPoll === 1 ? ssOutput(SS_LOOPBACK) : ssOutput(SS_LOOPBACK, SS_WORKLOAD);
    });
    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW), workloads });

    try {
      await monitor.pollSockets(async (listeners) => benignEntries(listeners));
      const result = await monitor.pollSockets(async (listeners) =>
        unexpectedEntries(listeners),
      );

      const corroborated = result.corroboration.find(
        (entry) => entry.rule === "unexpected_workload",
      );
      expect(corroborated).toBeDefined();
      expect(corroborated!.target).toEqual({
        kind: "pause_workload",
        workloadId: "comfy",
        pid: 4242,
        startedAt: NOW - etimesSeconds * 1000,
      });
    } finally {
      store.close();
    }
  });

  test("falls back to unexpected_listener without a target when processes is unavailable, missing PID, or comm mismatches", async () => {
    const workloads: EnrolledWorkload[] = [
      { id: "comfy", unit: "comfy.service", name: "comfy", ports: [8188] },
    ];
    const cases: { label: string; processResult: CommandResult }[] = [
      { label: "processes unavailable", processResult: { status: "unavailable" } },
      { label: "PID missing from ps", processResult: ok("  1111     1  1000    90 node\n") },
      { label: "PID comm mismatch", processResult: ok("  4242     1  1000    90 python3\n") },
    ];

    for (const testCase of cases) {
      const store = memoryStore();
      let socketPoll = 0;
      const runner = runnerStub((request) => {
        if (request.kind === "processes") {
          return testCase.processResult;
        }
        socketPoll += 1;
        return socketPoll === 1 ? ssOutput(SS_LOOPBACK) : ssOutput(SS_LOOPBACK, SS_WORKLOAD);
      });
      const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW), workloads });

      try {
        await monitor.pollSockets(async (listeners) => benignEntries(listeners));
        const result = await monitor.pollSockets(async (listeners) =>
          unexpectedEntries(listeners),
        );

        expect(result.alerts.length).toBeGreaterThan(0);
        expect(result.corroboration).toHaveLength(1);
        expect(result.corroboration[0]?.rule).toBe("unexpected_listener");
        expect(result.corroboration[0]?.target).toBeUndefined();
      } finally {
        store.close();
      }
    }
  });

  test("rejects spoofed logger -t sshd and logger -t kernel records while advancing cursor with zero alerts", async () => {
    const store = memoryStore();
    const spoofedLines = [
      // logger -t sshd from unprivileged user
      ...Array.from({ length: 6 }, (_, index) =>
        jline({
          __CURSOR: `s=spoof-ssh;i=${index}`,
          _TRANSPORT: "syslog",
          _UID: "1000",
          _COMM: "logger",
          SYSLOG_IDENTIFIER: "sshd",
          MESSAGE: sshFailureMessage(PEER),
        }),
      ),
      // logger -t kernel spoofing UFW BLOCK and OOM kill
      jline({
        __CURSOR: "s=spoof-kernel;i=1",
        _TRANSPORT: "syslog",
        _UID: "1000",
        _COMM: "logger",
        SYSLOG_IDENTIFIER: "kernel",
        MESSAGE:
          "[UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=198.51.100.42 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=51234 DPT=8188 SYN",
      }),
      jline({
        __CURSOR: "s=spoof-kernel;i=2",
        _TRANSPORT: "syslog",
        _UID: "1000",
        _COMM: "logger",
        SYSLOG_IDENTIFIER: "kernel",
        MESSAGE: "Out of memory: Killed process 4242 (node)",
      }),
      // kernel identifier with missing _TRANSPORT must also be rejected
      JSON.stringify({
        __CURSOR: "s=spoof-kernel;i=3",
        __REALTIME_TIMESTAMP: String(NOW * 1000),
        SYSLOG_IDENTIFIER: "kernel",
        MESSAGE: "Out of memory: Killed process 4242 (node)",
      }),
      // spoofed sudo, polkitd, systemd, pacman via logger / non-root UID
      jline({
        __CURSOR: "s=spoof-sudo;i=1",
        _TRANSPORT: "syslog",
        _UID: "1000",
        _COMM: "logger",
        SYSLOG_IDENTIFIER: "sudo",
        MESSAGE: "dennis : TTY=pts/0 ; PWD=/home/dennis ; USER=root ; COMMAND=/usr/bin/id",
      }),
      jline({
        __CURSOR: "s=spoof-polkit;i=1",
        _TRANSPORT: "syslog",
        _UID: "1000",
        _COMM: "logger",
        SYSLOG_IDENTIFIER: "polkitd",
        MESSAGE: "Operator successfully authenticated to gain authorization",
      }),
      jline({
        __CURSOR: "s=spoof-systemd;i=1",
        _TRANSPORT: "journal",
        _UID: "1000",
        _COMM: "systemd",
        _SYSTEMD_USER_UNIT: "evil.service",
        SYSLOG_IDENTIFIER: "systemd",
        MESSAGE: "backup.service: Failed with result 'exit-code'.",
      }),
      jline({
        __CURSOR: "s=spoof-pacman;i=1",
        _TRANSPORT: "syslog",
        _UID: "1000",
        _COMM: "pacman",
        SYSLOG_IDENTIFIER: "pacman",
        MESSAGE: "[ALPM] installed backdoor (1.0-1)",
      }),
    ];

    // Unit-level check on parseJournalRecord: cursor returned, no event.
    for (const line of spoofedLines) {
      const parsed = parseJournalRecord(line);
      expect(parsed).not.toBeNull();
      expect(parsed!.event).toBeUndefined();
    }

    // Legitimate records with full trusted metadata are still accepted.
    expect(
      parseJournalRecord(
        jline({
          __CURSOR: "s=legit-ssh;i=1",
          _TRANSPORT: "syslog",
          _UID: "0",
          _COMM: "sshd-session",
          _SYSTEMD_UNIT: "sshd.service",
          SYSLOG_IDENTIFIER: "sshd-session",
          MESSAGE: sshFailureMessage(PEER),
        }),
      )?.event?.rule,
    ).toBe("ssh_auth_failure");

    const runner = runnerStub(() => journalPage(spoofedLines));
    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

    try {
      const result = await monitor.pollJournal();
      expect(result.alerts).toEqual([]);
      expect(result.corroboration).toEqual([]);
      expect(result.coverage).toBe("complete");
      expect(store.getCursor("journal")).toBe("s=spoof-pacman;i=1");
      expect(store.recentEvents(0, 50)).toEqual([]);
    } finally {
      store.close();
    }
  });

  test("deduplicates real 3-line OpenSSH failure sequences per (ip, srcPort) within a batch", async () => {
    const makeAttempt = (attemptIndex: number, port: number, atMs: number): string[] => [
      jline({
        __CURSOR: `s=openssh;a=${attemptIndex};l=1`,
        __REALTIME_TIMESTAMP: String(atMs * 1000),
        SYSLOG_IDENTIFIER: "sshd-session",
        MESSAGE: `Invalid user admin from ${PEER} port ${port}`,
      }),
      jline({
        __CURSOR: `s=openssh;a=${attemptIndex};l=2`,
        __REALTIME_TIMESTAMP: String((atMs + 10) * 1000),
        SYSLOG_IDENTIFIER: "sshd-session",
        MESSAGE: `Failed password for invalid user admin from ${PEER} port ${port} ssh2`,
      }),
      jline({
        __CURSOR: `s=openssh;a=${attemptIndex};l=3`,
        __REALTIME_TIMESTAMP: String((atMs + 20) * 1000),
        SYSLOG_IDENTIFIER: "sshd-session",
        MESSAGE: `Connection closed by authenticating user admin ${PEER} port ${port} [preauth]`,
      }),
    ];

    // 2 real attempts = 6 log lines -> must count as 2 and NOT trigger a 5-failure burst.
    const storeTwo = memoryStore();
    const twoAttempts = [
      ...makeAttempt(1, 51001, NOW - 20 * SECOND_MS),
      ...makeAttempt(2, 51002, NOW - 10 * SECOND_MS),
    ];
    try {
      const monitor = new EventMonitor({
        store: storeTwo,
        runner: runnerStub(() => journalPage(twoAttempts)),
        clock: clockAt(NOW),
      });
      const result = await monitor.pollJournal();
      expect(result.corroboration.some((entry) => entry.rule === "ssh_burst")).toBe(false);
      expect(result.alerts).toEqual([]);
      expect(authEventTotal(storeTwo, PEER)).toBe(2);
    } finally {
      storeTwo.close();
    }

    // 5 real attempts = 15 log lines -> must count as 5 and DO trigger a 5-failure burst.
    const storeFive = memoryStore();
    const fiveAttempts = Array.from({ length: 5 }, (_, idx) =>
      makeAttempt(idx + 1, 52000 + idx, NOW - (5 - idx) * 10 * SECOND_MS),
    ).flat();
    try {
      const monitor = new EventMonitor({
        store: storeFive,
        runner: runnerStub(() => journalPage(fiveAttempts)),
        clock: clockAt(NOW),
      });
      const result = await monitor.pollJournal();
      const burst = result.corroboration.find((entry) => entry.rule === "ssh_burst");
      expect(burst).toBeDefined();
      expect(burst!.target).toEqual({ kind: "deny_peer_ip", ip: PEER });
      expect(burst!.eventIds).toHaveLength(5);
      expect(authEventTotal(storeFive, PEER)).toBe(5);
    } finally {
      storeFive.close();
    }
  });

  test("commits complete journal prefix and advances cursor when a journal page exceeds 256 KiB", async () => {
    const store = memoryStore();
    const realSpawn = Bun.spawn.bind(Bun);
    const whichSpy = spyOn(Bun, "which").mockImplementation((cmd) =>
      cmd === "journalctl" ? "/usr/bin/journalctl" : null,
    );

    // Emit 3 complete valid JSON records (~1 KiB total) followed by a >270 KiB fourth record.
    const line1 = jline({
      __CURSOR: "s=over;i=1",
      MESSAGE: sshFailureMessage(PEER),
    });
    const line2 = jline({
      __CURSOR: "s=over;i=2",
      MESSAGE: sshFailureMessage(PEER),
    });
    const line3 = jline({
      __CURSOR: "s=over;i=3",
      MESSAGE: sshFailureMessage(PEER),
    });
    const script = [
      `printf '%s\\n%s\\n%s\\n' '${line1}' '${line2}' '${line3}'`,
      `printf '{"__CURSOR":"s=over;i=4","__REALTIME_TIMESTAMP":"${NOW * 1000}","MESSAGE":"'`,
      `head -c 280000 /dev/zero | tr '\\0' 'A'`,
      `printf '"}\\n'`,
    ].join("; ");

    const spawnSpy = spyOn(Bun, "spawn").mockImplementation(((_argv, options) =>
      realSpawn(
        ["/bin/sh", "-c", script],
        options as Parameters<typeof Bun.spawn>[1],
      )) as typeof Bun.spawn);

    try {
      const runner = createCommandRunner({ timeoutMs: 2_000 });
      const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });
      const result = await monitor.pollJournal();

      expect(result.coverage).toBe("complete");
      expect(store.getCursor("journal")).toBe("s=over;i=3");
      expect(authEventTotal(store, PEER)).toBe(3);
    } finally {
      spawnSpy.mockRestore();
      whichSpy.mockRestore();
      store.close();
    }
  });

  test("uses restart-safe socket observation IDs so EventMonitor restarts do not collide in SQLite", async () => {
    const store = memoryStore();
    let now = NOW;
    const clock: Clock = { now: () => now };

    const makeRunner = () => {
      let poll = 0;
      return runnerStub(() => {
        poll += 1;
        return poll === 1 ? ssOutput(SS_LOOPBACK) : ssOutput(SS_LOOPBACK, SS_WILDCARD);
      });
    };

    try {
      const monitor1 = new EventMonitor({ store, runner: makeRunner(), clock });
      await monitor1.pollSockets(async (listeners) => benignEntries(listeners));
      const firstOpen = await monitor1.pollSockets(async (listeners) =>
        unexpectedEntries(listeners),
      );
      expect(firstOpen.corroboration).toHaveLength(1);
      expect(networkEventTotal(store)).toBe(1);

      // Restart EventMonitor on the same SQLite store at a later timestamp.
      now += 15 * SECOND_MS;
      const monitor2 = new EventMonitor({ store, runner: makeRunner(), clock });
      await monitor2.pollSockets(async (listeners) => benignEntries(listeners));
      const secondOpen = await monitor2.pollSockets(async (listeners) =>
        unexpectedEntries(listeners),
      );
      expect(secondOpen.corroboration).toHaveLength(1);
      expect(secondOpen.corroboration[0]?.eventIds[0]).not.toBe(
        firstOpen.corroboration[0]?.eventIds[0],
      );
      expect(networkEventTotal(store)).toBe(2);
    } finally {
      store.close();
    }
  });

  test("rejects 6-column ps output without user-manager uunit even when system unit and comm match", async () => {
    const workloads: EnrolledWorkload[] = [
      { id: "comfy", unit: "comfy.service", name: "comfy", ports: [8188] },
    ];

    // System unit only (no uunit column) or non-unit ("-") with matching comm -> falls back to unexpected_listener.
    const unverifiedRows = [
      "  4242     1  1000   120 comfy.service                   comfy\n",
      "  4242     1  1000   120 session-2.scope                 comfy\n",
      "  4242     1  1000   120 user@1000.service               comfy\n",
      "  4242     1  1000   120 -                               comfy\n",
      "  4242     1  1000   120 comfy\n",
    ];
    for (const psLine of unverifiedRows) {
      const store = memoryStore();
      let socketPoll = 0;
      const runner = runnerStub((request) => {
        if (request.kind === "processes") {
          return ok(psLine);
        }
        socketPoll += 1;
        return socketPoll === 1 ? ssOutput(SS_LOOPBACK) : ssOutput(SS_LOOPBACK, SS_WORKLOAD);
      });
      const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW), workloads });
      try {
        await monitor.pollSockets(async (listeners) => benignEntries(listeners));
        const result = await monitor.pollSockets(async (listeners) =>
          unexpectedEntries(listeners),
        );
        expect(result.alerts.length).toBeGreaterThan(0);
        expect(result.corroboration).toHaveLength(1);
        expect(result.corroboration[0]?.rule).toBe("unexpected_listener");
        expect(result.corroboration[0]?.target).toBeUndefined();
      } finally {
        store.close();
      }
    }
  });

  test("advances cursor past records with invalid or missing __REALTIME_TIMESTAMP without stalling", async () => {
    const invalidTsRecord = JSON.stringify({
      __CURSOR: "s=bad-ts;i=1",
      __REALTIME_TIMESTAMP: "not-a-timestamp",
      _TRANSPORT: "syslog",
      SYSLOG_IDENTIFIER: "sshd",
      MESSAGE: sshFailureMessage(PEER),
    });
    const missingTsRecord = JSON.stringify({
      __CURSOR: "s=bad-ts;i=2",
      _TRANSPORT: "syslog",
      SYSLOG_IDENTIFIER: "sshd",
      MESSAGE: sshFailureMessage(PEER),
    });
    const validFollowingRecord = jline({
      __CURSOR: "s=bad-ts;i=3",
      MESSAGE: sshFailureMessage(PEER),
    });

    expect(parseJournalRecord(invalidTsRecord)).toEqual({ cursor: "s=bad-ts;i=1" });
    expect(parseJournalRecord(missingTsRecord)).toEqual({ cursor: "s=bad-ts;i=2" });

    const store = memoryStore();
    const monitor = new EventMonitor({
      store,
      runner: runnerStub(() =>
        journalPage([invalidTsRecord, missingTsRecord, validFollowingRecord]),
      ),
      clock: clockAt(NOW),
    });

    try {
      const result = await monitor.pollJournal();
      expect(result.coverage).toBe("complete");
      expect(store.getCursor("journal")).toBe("s=bad-ts;i=3");
      expect(authEventTotal(store, PEER)).toBe(1);
    } finally {
      store.close();
    }
  });

  test("commits journal_cursor_gap and clears expired cursor on empty recovery page without looping", async () => {
    const store = memoryStore();
    const requests: CommandRequest[] = [];
    let stage = 0;
    const runner = runnerStub((request) => {
      stage += 1;
      if (stage === 1) {
        return journalPage([
          jline({
            __CURSOR: "s=expired-empty;i=1",
            SYSLOG_IDENTIFIER: "cron",
            MESSAGE: "(root) CMD (true)",
          }),
        ]);
      }
      if (stage === 2) {
        expect(request).toEqual({ kind: "journal", after: "s=expired-empty;i=1", limit: 200 });
        return { status: "cursor_expired" };
      }
      if (stage === 3) {
        expect(request).toEqual({ kind: "journal", after: undefined, limit: 200 });
        return ok("");
      }
      return ok("");
    }, requests);

    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

    try {
      await monitor.pollJournal();
      expect(store.getCursor("journal")).toBe("s=expired-empty;i=1");

      const recovered = await monitor.pollJournal();
      expect(recovered.coverage).toBe("partial");
      expect(store.getCursor("journal")).toBeNull();

      const gapEvent = store
        .recentEvents(0, 50)
        .find((event) => event.rule === "journal_cursor_gap");
      expect(gapEvent).toBeDefined();
      expect(gapEvent!.severity).toBe("warning");

      // Next poll starts fresh with after: undefined instead of looping on the expired cursor.
      await monitor.pollJournal();
      expect(requests[3]).toEqual({ kind: "journal", after: undefined, limit: 200 });
    } finally {
      store.close();
    }
  });

  test("verifies user-owned systemd uunit from 7-column ps output for pause_workload and rejects mismatched uunit", async () => {
    const workloads: EnrolledWorkload[] = [
      { id: "comfy", unit: "comfy.service", name: "comfy", ports: [8188] },
    ];

    // User unit matching uunit while system unit is user@1000.service -> emits pause_workload.
    {
      const store = memoryStore();
      let socketPoll = 0;
      const runner = runnerStub((request) => {
        if (request.kind === "processes") {
          return ok("  4242     1  1000   120 user@1000.service comfy.service comfy\n");
        }
        socketPoll += 1;
        return socketPoll === 1 ? ssOutput(SS_LOOPBACK) : ssOutput(SS_LOOPBACK, SS_WORKLOAD);
      });
      const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW), workloads });
      try {
        await monitor.pollSockets(async (listeners) => benignEntries(listeners));
        const result = await monitor.pollSockets(async (listeners) =>
          unexpectedEntries(listeners),
        );
        const corroborated = result.corroboration.find(
          (entry) => entry.rule === "unexpected_workload",
        );
        expect(corroborated).toBeDefined();
        expect(corroborated!.target).toEqual({
          kind: "pause_workload",
          workloadId: "comfy",
          pid: 4242,
          startedAt: NOW - 120 * 1000,
        });
      } finally {
        store.close();
      }
    }

    // System service matching unit with uunit="-" (R3-F01) -> MUST be rejected (no pause_workload).
    {
      const store = memoryStore();
      let socketPoll = 0;
      const runner = runnerStub((request) => {
        if (request.kind === "processes") {
          return ok("  4242     1  1000   120 comfy.service - comfy\n");
        }
        socketPoll += 1;
        return socketPoll === 1 ? ssOutput(SS_LOOPBACK) : ssOutput(SS_LOOPBACK, SS_WORKLOAD);
      });
      const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW), workloads });
      try {
        await monitor.pollSockets(async (listeners) => benignEntries(listeners));
        const result = await monitor.pollSockets(async (listeners) =>
          unexpectedEntries(listeners),
        );
        expect(result.alerts.length).toBeGreaterThan(0);
        expect(result.corroboration).toHaveLength(1);
        expect(result.corroboration[0]?.rule).toBe("unexpected_listener");
        expect(result.corroboration[0]?.target).toBeUndefined();
      } finally {
        store.close();
      }
    }

    // Mismatched uunit, mismatched user@<uid>.service, or missing units ("-") -> falls back to unexpected_listener.
    const mismatchedRows = [
      "  4242     1  1000   120 user@1000.service other.service comfy\n",
      "  4242     1  1000   120 user@2000.service comfy.service comfy\n",
      "  4242     1  1000   120 user@1000.service - comfy\n",
      "  4242     1  1000   120 - - comfy\n",
    ];
    for (const psLine of mismatchedRows) {
      const store = memoryStore();
      let socketPoll = 0;
      const runner = runnerStub((request) => {
        if (request.kind === "processes") {
          return ok(psLine);
        }
        socketPoll += 1;
        return socketPoll === 1 ? ssOutput(SS_LOOPBACK) : ssOutput(SS_LOOPBACK, SS_WORKLOAD);
      });
      const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW), workloads });
      try {
        await monitor.pollSockets(async (listeners) => benignEntries(listeners));
        const result = await monitor.pollSockets(async (listeners) =>
          unexpectedEntries(listeners),
        );
        expect(result.alerts.length).toBeGreaterThan(0);
        expect(result.corroboration).toHaveLength(1);
        expect(result.corroboration[0]?.rule).toBe("unexpected_listener");
        expect(result.corroboration[0]?.target).toBeUndefined();
      } finally {
        store.close();
      }
    }
  });

  test("accepts polkitd running as system UID (<1000) and rejects regular user UIDs or spoofed metadata", () => {
    const polkitMsg =
      "Operator of unix-process:1234:5678 successfully authenticated as unix-user:dennis to gain one-shot authorization for org.freedesktop.systemd1.manage-units";

    // Positive: system UID 102 with polkitd comm, polkit.service unit, and /polkitd exe
    const legitPolkit = parsedEvent(
      jline({
        __CURSOR: "s=polkit-sys;i=1",
        _UID: "102",
        _COMM: "polkitd",
        _SYSTEMD_UNIT: "polkit.service",
        _EXE: "/usr/lib/polkit-1/polkitd",
        SYSLOG_IDENTIFIER: "polkitd",
        MESSAGE: polkitMsg,
      }),
    );
    expect(legitPolkit.rule).toBe("polkit_escalation");
    expect(legitPolkit.category).toBe("auth");

    // Positive without _EXE
    const legitPolkitNoExe = parsedEvent(
      jline({
        __CURSOR: "s=polkit-sys;i=2",
        _UID: "102",
        _COMM: "polkitd",
        _SYSTEMD_UNIT: "polkit.service",
        SYSLOG_IDENTIFIER: "polkitd",
        MESSAGE: polkitMsg,
      }),
    );
    expect(legitPolkitNoExe.rule).toBe("polkit_escalation");

    // Negative: regular user UID >= 1000, spoofed _COMM, spoofed _SYSTEMD_UNIT, spoofed _EXE
    const rejectedCases = [
      {
        __CURSOR: "s=polkit-bad;i=1",
        _UID: "1000",
        _COMM: "polkitd",
        _SYSTEMD_UNIT: "polkit.service",
        _EXE: "/usr/lib/polkit-1/polkitd",
        SYSLOG_IDENTIFIER: "polkitd",
        MESSAGE: polkitMsg,
      },
      {
        __CURSOR: "s=polkit-bad;i=2",
        _UID: "102",
        _COMM: "fake-polkitd",
        _SYSTEMD_UNIT: "polkit.service",
        SYSLOG_IDENTIFIER: "polkitd",
        MESSAGE: polkitMsg,
      },
      {
        __CURSOR: "s=polkit-bad;i=3",
        _UID: "102",
        _COMM: "polkitd",
        _SYSTEMD_UNIT: "evil.service",
        SYSLOG_IDENTIFIER: "polkitd",
        MESSAGE: polkitMsg,
      },
      {
        __CURSOR: "s=polkit-bad;i=4",
        _UID: "102",
        _COMM: "polkitd",
        _SYSTEMD_UNIT: "polkit.service",
        _EXE: "/usr/bin/logger",
        SYSLOG_IDENTIFIER: "polkitd",
        MESSAGE: polkitMsg,
      },
    ];

    for (const record of rejectedCases) {
      const parsed = parseJournalRecord(jline(record));
      expect(parsed).not.toBeNull();
      expect(parsed!.event).toBeUndefined();
    }
  });

  test("verifies sudo _EXE when present and ignores renamed fake sudo binaries", () => {
    const sudoMsg = "dennis : TTY=pts/0 ; PWD=/home/dennis ; USER=root ; COMMAND=/usr/bin/id";

    for (const exe of ["/usr/bin/sudo", "/bin/sudo"]) {
      const legit = parsedEvent(
        jline({
          __CURSOR: `s=sudo-ok;e=${exe.replaceAll("/", "_")}`,
          _COMM: "sudo",
          _EXE: exe,
          SYSLOG_IDENTIFIER: "sudo",
          MESSAGE: sudoMsg,
        }),
      );
      expect(legit.rule).toBe("sudo_escalation");
    }

    for (const badExe of ["/tmp/fake-sudo", "/tmp/sudo", "/usr/bin/logger"]) {
      const parsed = parseJournalRecord(
        jline({
          __CURSOR: `s=sudo-bad;e=${badExe.replaceAll("/", "_")}`,
          _COMM: "sudo",
          _EXE: badExe,
          SYSLOG_IDENTIFIER: "sudo",
          MESSAGE: sudoMsg,
        }),
      );
      expect(parsed).not.toBeNull();
      expect(parsed!.event).toBeUndefined();
    }
  });

  test("advances past a single oversized journal record with synthetic skipped notice and partial coverage", async () => {
    const store = memoryStore();
    const realSpawn = Bun.spawn.bind(Bun);
    const whichSpy = spyOn(Bun, "which").mockImplementation((cmd) =>
      cmd === "journalctl" ? "/usr/bin/journalctl" : null,
    );

    const oversizedScript = [
      `printf '{"__CURSOR":"s=giant;i=1","__REALTIME_TIMESTAMP":"${NOW * 1000}","MESSAGE":"'`,
      `head -c 280000 /dev/zero | tr '\\0' 'A'`,
      `printf '"}\\n'`,
    ].join("; ");
    const nextLine = jline({
      __CURSOR: "s=giant;i=2",
      MESSAGE: sshFailureMessage(PEER),
    });

    let call = 0;
    const seenArgvs: unknown[] = [];
    const spawnSpy = spyOn(Bun, "spawn").mockImplementation(((argv, options) => {
      call += 1;
      seenArgvs.push(argv);
      const script = call === 1 ? oversizedScript : `printf '%s\\n' '${nextLine}'`;
      return realSpawn(
        ["/bin/sh", "-c", script],
        options as Parameters<typeof Bun.spawn>[1],
      );
    }) as typeof Bun.spawn);

    try {
      const runner = createCommandRunner({ timeoutMs: 2_000 });
      const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW) });

      const first = await monitor.pollJournal();
      expect(first.coverage).toBe("partial");
      expect(first.alerts).toEqual([]);
      expect(first.corroboration).toEqual([]);
      expect(store.getCursor("journal")).toBe("s=giant;i=1");

      const gapOrSkipped = store
        .recentEvents(0, 50)
        .find((event) => event.rule === "journal_record_skipped");
      expect(gapOrSkipped).toBeDefined();
      expect(gapOrSkipped!.severity).toBe("warning");
      expect(gapOrSkipped!.isNoise).toBe(false);

      // Next poll resumes after s=giant;i=1 and ingests s=giant;i=2 instead of stalling.
      const second = await monitor.pollJournal();
      expect(second.coverage).toBe("complete");
      expect(store.getCursor("journal")).toBe("s=giant;i=2");
      expect(authEventTotal(store, PEER)).toBe(1);
      expect(seenArgvs[1]).toContain("--after-cursor=s=giant;i=1");
    } finally {
      spawnSpy.mockRestore();
      whichSpy.mockRestore();
      store.close();
    }
  });

  test("deduplicates SSH multi-line companion and failed_auth records across consecutive polls within 15s", async () => {
    const store = memoryStore();
    let poll = 0;
    const runner = runnerStub(() => {
      poll += 1;
      if (poll === 1) {
        // 3 attempts split across poll boundary:
        // - ports 53001 & 53002 send Invalid user at end of poll 1
        // - port 53003 sends Failed password at end of poll 1
        return journalPage([
          jline({
            __CURSOR: "s=xpoll;i=1",
            __REALTIME_TIMESTAMP: String((NOW - 10 * SECOND_MS) * 1000),
            SYSLOG_IDENTIFIER: "sshd-session",
            MESSAGE: `Invalid user admin from ${PEER} port 53001`,
          }),
          jline({
            __CURSOR: "s=xpoll;i=2",
            __REALTIME_TIMESTAMP: String((NOW - 8 * SECOND_MS) * 1000),
            SYSLOG_IDENTIFIER: "sshd-session",
            MESSAGE: `Invalid user admin from ${PEER} port 53002`,
          }),
          jline({
            __CURSOR: "s=xpoll;i=3",
            __REALTIME_TIMESTAMP: String((NOW - 6 * SECOND_MS) * 1000),
            SYSLOG_IDENTIFIER: "sshd-session",
            MESSAGE: `Failed password for invalid user admin from ${PEER} port 53003 ssh2`,
          }),
        ]);
      }
      if (poll === 2) {
        // Companion / paired lines arrive at start of poll 2 within 15s:
        // - port 53001 & 53002 send Failed password + Connection closed
        // - port 53003 sends Connection closed
        // None of these should double-count against the 5-failure threshold!
        return journalPage([
          jline({
            __CURSOR: "s=xpoll;i=4",
            __REALTIME_TIMESTAMP: String((NOW - 9 * SECOND_MS) * 1000),
            SYSLOG_IDENTIFIER: "sshd-session",
            MESSAGE: `Failed password for invalid user admin from ${PEER} port 53001 ssh2`,
          }),
          jline({
            __CURSOR: "s=xpoll;i=5",
            __REALTIME_TIMESTAMP: String((NOW - 9 * SECOND_MS + 10) * 1000),
            SYSLOG_IDENTIFIER: "sshd-session",
            MESSAGE: `Connection closed by authenticating user admin ${PEER} port 53001 [preauth]`,
          }),
          jline({
            __CURSOR: "s=xpoll;i=6",
            __REALTIME_TIMESTAMP: String((NOW - 7 * SECOND_MS) * 1000),
            SYSLOG_IDENTIFIER: "sshd-session",
            MESSAGE: `Failed password for invalid user admin from ${PEER} port 53002 ssh2`,
          }),
          jline({
            __CURSOR: "s=xpoll;i=7",
            __REALTIME_TIMESTAMP: String((NOW - 5 * SECOND_MS) * 1000),
            SYSLOG_IDENTIFIER: "sshd-session",
            MESSAGE: `Connection closed by authenticating user admin ${PEER} port 53003 [preauth]`,
          }),
        ]);
      }
      // Poll 3: Same port 53001 reused 20s later (> 15s window) + one new port -> now reaches 5 total.
      return journalPage([
        jline({
          __CURSOR: "s=xpoll;i=8",
          __REALTIME_TIMESTAMP: String((NOW + 12 * SECOND_MS) * 1000),
          SYSLOG_IDENTIFIER: "sshd-session",
          MESSAGE: `Failed password for invalid user admin from ${PEER} port 53001 ssh2`,
        }),
        jline({
          __CURSOR: "s=xpoll;i=9",
          __REALTIME_TIMESTAMP: String((NOW + 13 * SECOND_MS) * 1000),
          SYSLOG_IDENTIFIER: "sshd-session",
          MESSAGE: `Failed password for invalid user admin from ${PEER} port 53004 ssh2`,
        }),
      ]);
    });

    let now = NOW;
    const monitor = new EventMonitor({ store, runner, clock: { now: () => now } });

    try {
      const first = await monitor.pollJournal();
      expect(first.corroboration.some((entry) => entry.rule === "ssh_burst")).toBe(false);
      expect(authEventTotal(store, PEER)).toBe(3);

      const second = await monitor.pollJournal();
      expect(second.corroboration.some((entry) => entry.rule === "ssh_burst")).toBe(false);
      expect(second.alerts).toEqual([]);
      expect(authEventTotal(store, PEER)).toBe(3);

      now = NOW + 15 * SECOND_MS;
      const third = await monitor.pollJournal();
      const burst = third.corroboration.find((entry) => entry.rule === "ssh_burst");
      expect(burst).toBeDefined();
      expect(burst!.target).toEqual({ kind: "deny_peer_ip", ip: PEER });
      expect(authEventTotal(store, PEER)).toBe(5);
    } finally {
      store.close();
    }
  });

  test("F06: enrolled workload opening an undeclared exposed port still matches and emits unexpected_workload corroboration", async () => {
    const store = memoryStore();
    const workloads: EnrolledWorkload[] = [
      { id: "comfy", unit: "comfy.service", name: "comfy", ports: [8188] },
    ];
    const ssUndeclaredPort =
      'tcp   LISTEN 0      128    0.0.0.0:9999     0.0.0.0:*    users:(("comfy",pid=4242,fd=8))';
    let socketPoll = 0;
    const runner = runnerStub((request) => {
      if (request.kind === "processes") {
        return ok("  4242     1  1000   120 user@1000.service comfy.service comfy\n");
      }
      socketPoll += 1;
      if (socketPoll === 1) return ssOutput(SS_LOOPBACK);
      if (socketPoll === 2) return ssOutput(SS_LOOPBACK, SS_WORKLOAD);
      return ssOutput(SS_LOOPBACK, SS_WORKLOAD, ssUndeclaredPort);
    });
    const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW), workloads });

    const classifyWithDeclaredPorts = (listeners: Listener[]): ExposureEntry[] => {
      const expected = new Set<number>([22, 6969, ...workloads.flatMap((w) => w.ports ?? [])]);
      return listeners.map((listener) => ({
        id: `exp:${listener.id}`,
        listener,
        reachability:
          listener.address === "127.0.0.1" ? "local_only" : "exposed_lan",
        firewallV4: listener.address === "127.0.0.1" ? "na" : "allow",
        firewallV6: "na",
        publication: "none",
        expected: expected.has(listener.port),
        evidenceIds: [`ev:${listener.id}`],
      }));
    };

    try {
      await monitor.pollSockets(classifyWithDeclaredPorts);

      // (a) Enrolled workload on its declared port (8188) is expected -> no false alert/corroboration.
      const declaredResult = await monitor.pollSockets(classifyWithDeclaredPorts);
      expect(declaredResult.alerts).toEqual([]);
      expect(declaredResult.corroboration).toEqual([]);

      // (b) Same enrolled workload opens an undeclared exposed port (9999) -> emits unexpected_workload!
      const undeclaredResult = await monitor.pollSockets(classifyWithDeclaredPorts);
      const corr = undeclaredResult.corroboration.find(
        (entry) => entry.rule === "unexpected_workload",
      );
      expect(corr).toBeDefined();
      expect(corr?.target).toEqual({
        kind: "pause_workload",
        workloadId: "comfy",
        pid: 4242,
        startedAt: NOW - 120 * 1000,
      });
      expect(
        undeclaredResult.alerts.some((alert) =>
          alert.fingerprint.includes("unexpected_workload:comfy"),
        ),
      ).toBe(true);
    } finally {
      store.close();
    }
  });

  test("R2-F03: pollSockets matches enrolled workload by systemd uunit/unit before comm (generic runtime and truncated comm)", async () => {
    const cases = [
      {
        label: "generic python3 runtime",
        workload: { id: "comfy", unit: "comfyui.service", ports: [8188] } satisfies EnrolledWorkload,
        ssLine:
          'tcp   LISTEN 0      128    0.0.0.0:8189     0.0.0.0:*    users:(("python3",pid=5151,fd=9))',
        psLine: "  5151     1  1000   120 user@1000.service comfyui.service python3\n",
        expectedPid: 5151,
      },
      {
        label: "truncated 15-char comm",
        workload: {
          id: "comfy",
          unit: "comfyui.service",
          ports: [8188],
        } satisfies EnrolledWorkload,
        ssLine:
          'tcp   LISTEN 0      128    0.0.0.0:8189     0.0.0.0:*    users:(("comfyui-inferen",pid=5152,fd=9))',
        psLine: "  5152     1  1000   120 user@1000.service comfyui.service comfyui-inferen\n",
        expectedPid: 5152,
      },
    ] as const;

    for (const tc of cases) {
      const store = memoryStore();
      const workloads: EnrolledWorkload[] = [tc.workload];
      let socketPoll = 0;
      const runner = runnerStub((request) => {
        if (request.kind === "processes") {
          return ok(tc.psLine);
        }
        socketPoll += 1;
        return socketPoll === 1
          ? ssOutput(SS_LOOPBACK)
          : ssOutput(SS_LOOPBACK, tc.ssLine);
      });
      const monitor = new EventMonitor({ store, runner, clock: clockAt(NOW), workloads });

      try {
        await monitor.pollSockets(async (listeners) => benignEntries(listeners));
        const result = await monitor.pollSockets(async (listeners) =>
          unexpectedEntries(listeners),
        );

        const corr = result.corroboration.find(
          (entry) => entry.rule === "unexpected_workload",
        );
        expect(corr, tc.label).toBeDefined();
        expect(corr?.target).toEqual({
          kind: "pause_workload",
          workloadId: "comfy",
          pid: tc.expectedPid,
          startedAt: NOW - 120 * 1000,
        });
        expect(
          result.alerts.some((alert) =>
            alert.fingerprint.includes("unexpected_workload:comfy"),
          ),
        ).toBe(true);
      } finally {
        store.close();
      }
    }
  });
});
