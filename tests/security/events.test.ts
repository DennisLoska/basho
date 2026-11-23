import { describe, expect, test } from "bun:test";
import { EventMonitor, parseJournalRecord } from "../../src/security/events";
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
    const runner = runnerStub(() => {
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
});
