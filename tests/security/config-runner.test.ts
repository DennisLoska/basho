import { expect, spyOn, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadSecurityConfig } from "../../src/security/config";
import { createCommandRunner, readBounded } from "../../src/security/runner";
import { criterionIds } from "../../src/security/types";
import type { LockdownMode } from "../../src/security/types";

const SECRET_ENV_KEYS = [
  "OPENCODE_API_KEY",
  "BASHO_AUTH_TOKEN",
  "BASHO_NTFY_TOKEN",
  "BASHO_DISCORD_WEBHOOK",
  "BASHO_TELEGRAM_BOT_TOKEN",
  "BASHO_TELEGRAM_CHAT_ID",
] as const;

const allCriteriaEnabled = () =>
  Object.fromEntries(criterionIds.map((id) => [id, true])) as Record<string, boolean>;

function textStream(text: string, chunkBytes?: number[]): ReadableStream<Uint8Array> {
  const encoded = new TextEncoder().encode(text);
  const cuts = chunkBytes ?? [encoded.byteLength];
  return new ReadableStream<Uint8Array>({
    start(controller) {
      let offset = 0;
      for (const size of cuts) {
        controller.enqueue(encoded.slice(offset, offset + size));
        offset += size;
      }
      if (offset < encoded.byteLength) controller.enqueue(encoded.slice(offset));
      controller.close();
    },
  });
}

async function rejectionOf(fn: () => Promise<unknown>): Promise<Error> {
  try {
    await fn();
  } catch (error) {
    return error instanceof Error ? error : new Error(String(error));
  }
  throw new Error("expected the operation to reject, but it resolved");
}

// ---------------------------------------------------------------------------
// Defaults and shape
// ---------------------------------------------------------------------------

test("default settings match the documented security defaults", () => {
  const { settings } = loadSecurityConfig({ env: {} });

  expect(settings.mode).toBe("approve");
  expect(settings.scanIntervalMinutes).toBe(60);
  expect(settings.expectedPorts).toEqual([22, 6969]);
  expect(settings.workloads).toEqual([]);

  expect(settings.ai.baseURL).toBe("https://opencode.ai/zen/go/v1");
  expect(settings.ai.model).toBe("deepseek-v4.1-flash");
  expect(settings.ai.sessionHeader).toBe(true);
  expect(settings.ai.confidenceThreshold).toBe(0.85);
  expect(settings.ai.triageCooldownMinutes).toBe(10);

  expect(settings.notifications.channels).toEqual(["in-app"]);
  expect(settings.notifications.cooldownMinutes).toBe(15);

  expect(settings.lockdown.proposalMinutes).toBe(30);
  expect(settings.lockdown.leaseSeconds).toBe(600);
  expect(settings.lockdown.helperEnabled).toBe(false);

  expect(settings.criteria).toEqual(allCriteriaEnabled());
  expect(Object.keys(settings.criteria).sort()).toEqual([...criterionIds].sort());
});

test("default process settings are typed and public", () => {
  const { settings } = loadSecurityConfig({ env: {} });

  expect(settings.process.host).toBe("0.0.0.0");
  expect(settings.process.port).toBe(6969);
  expect(settings.process.securityDbPath).toBe("data/basho-security.db");
  expect(settings.process.demo).toBe(false);
});

test("missing secrets stay undefined and never become settings fields", () => {
  const { settings, secrets } = loadSecurityConfig({ env: {} });

  expect(secrets.aiKey).toBeUndefined();
  expect(secrets.authToken).toBeUndefined();
  expect(secrets.ntfyToken).toBeUndefined();
  expect(secrets.discordWebhook).toBeUndefined();
  expect(secrets.telegramBotToken).toBeUndefined();
  expect(secrets.telegramChatId).toBeUndefined();
  expect(Object.keys(settings)).not.toContain("aiKey");
  expect(Object.keys(settings)).not.toContain("secrets");
});

// ---------------------------------------------------------------------------
// Precedence: defaults, config file content, overrides, environment
// ---------------------------------------------------------------------------

test("runtime overrides and environment have distinct destinations", () => {
  const { settings, secrets } = loadSecurityConfig({
    env: {
      OPENCODE_API_KEY: "fixture-secret",
      OPENCODE_BASE_URL: "https://ai.example.test/v1",
    },
    overrides: { scanIntervalMinutes: 30 },
  });

  expect(settings.scanIntervalMinutes).toBe(30);
  expect(settings.ai.baseURL).toBe("https://ai.example.test/v1");
  expect(settings.mode).toBe("approve");
  expect(secrets.aiKey).toBe("fixture-secret");
  expect(JSON.stringify(settings)).not.toContain("fixture-secret");
});

test("every environment secret lands only in the secrets object", () => {
  const values = Object.fromEntries(
    SECRET_ENV_KEYS.map((key, index) => [key, `sentinel-${index}-secret`]),
  ) as Record<(typeof SECRET_ENV_KEYS)[number], string>;

  const { settings, secrets } = loadSecurityConfig({ env: values });
  const serializedSettings = JSON.stringify(settings);

  expect(secrets).toEqual({
    aiKey: values.OPENCODE_API_KEY,
    authToken: values.BASHO_AUTH_TOKEN,
    ntfyToken: values.BASHO_NTFY_TOKEN,
    discordWebhook: values.BASHO_DISCORD_WEBHOOK,
    telegramBotToken: values.BASHO_TELEGRAM_BOT_TOKEN,
    telegramChatId: values.BASHO_TELEGRAM_CHAT_ID,
  });

  for (const value of Object.values(values)) {
    expect(serializedSettings).not.toContain(value);
  }
});

test("runtime overrides replace only the fields they name", () => {
  const { settings } = loadSecurityConfig({
    env: {},
    overrides: {
      mode: "auto-lockdown",
      scanIntervalMinutes: 15,
      criteria: { ssh_hardening: false, firewall_ufw: false },
    },
  });

  expect(settings.mode).toBe("auto-lockdown");
  expect(settings.scanIntervalMinutes).toBe(15);
  expect(settings.criteria.ssh_hardening).toBe(false);
  expect(settings.criteria.firewall_ufw).toBe(false);
  expect(settings.criteria.network_exposure).toBe(true);
  expect(settings.criteria.process_and_timers).toBe(true);
  expect(settings.ai.confidenceThreshold).toBe(0.85);
});

test("file content is merged under overrides and environment", () => {
  const { settings } = loadSecurityConfig({
    env: { OPENCODE_BASE_URL: "https://env.example.test/v1" },
    fileConfig: {
      scanIntervalMinutes: 120,
      ai: { baseURL: "https://file.example.test/v1", model: "file-model" },
      notifications: { cooldownMinutes: 45 },
    },
    overrides: { scanIntervalMinutes: 30 },
  });

  expect(settings.scanIntervalMinutes).toBe(30);
  expect(settings.ai.baseURL).toBe("https://env.example.test/v1");
  expect(settings.ai.model).toBe("file-model");
  expect(settings.notifications.cooldownMinutes).toBe(45);
});

test("criteria overrides cannot drop unnamed criteria", () => {
  const { settings } = loadSecurityConfig({
    env: {},
    overrides: { criteria: { disk_and_boot: false } },
  });

  expect(settings.criteria.disk_and_boot).toBe(false);
  for (const id of criterionIds) {
    if (id === "disk_and_boot") continue;
    expect(settings.criteria[id]).toBe(true);
  }
});

test("OPENCODE_BASE_URL overrides the configured AI endpoint", () => {
  const custom = loadSecurityConfig({
    env: { OPENCODE_BASE_URL: "https://ai.example.test/v1" },
  });
  expect(custom.settings.ai.baseURL).toBe("https://ai.example.test/v1");

  const fallback = loadSecurityConfig({ env: {} });
  expect(fallback.settings.ai.baseURL).toBe("https://opencode.ai/zen/go/v1");
});

test("process environment variables parse into typed settings", () => {
  const { settings } = loadSecurityConfig({
    env: {
      BASHO_HOST: "127.0.0.1",
      BASHO_PORT: "16969",
      BASHO_SECURITY_DB: "/tmp/basho-security-test.db",
      BASHO_DEMO_SECURITY: "1",
    },
  });

  expect(settings.process.host).toBe("127.0.0.1");
  expect(settings.process.port).toBe(16969);
  expect(settings.process.securityDbPath).toBe("/tmp/basho-security-test.db");
  expect(settings.process.demo).toBe(true);

  const demoOff = loadSecurityConfig({ env: { BASHO_DEMO_SECURITY: "0" } });
  expect(demoOff.settings.process.demo).toBe(false);
});

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

test("scan interval outside 1 to 1440 minutes is rejected", () => {
  expect(() => loadSecurityConfig({ env: {}, overrides: { scanIntervalMinutes: 0 } })).toThrow();
  expect(() => loadSecurityConfig({ env: {}, overrides: { scanIntervalMinutes: -5 } })).toThrow();
  expect(() => loadSecurityConfig({ env: {}, overrides: { scanIntervalMinutes: 1441 } })).toThrow();

  expect(loadSecurityConfig({ env: {}, overrides: { scanIntervalMinutes: 1 } }).settings.scanIntervalMinutes).toBe(1);
  expect(loadSecurityConfig({ env: {}, overrides: { scanIntervalMinutes: 1440 } }).settings.scanIntervalMinutes).toBe(1440);
});

test("invalid bind port is rejected", () => {
  expect(() => loadSecurityConfig({ env: { BASHO_PORT: "0" } })).toThrow();
  expect(() => loadSecurityConfig({ env: { BASHO_PORT: "70000" } })).toThrow();
  expect(() => loadSecurityConfig({ env: { BASHO_PORT: "not-a-port" } })).toThrow();
  expect(() => loadSecurityConfig({ env: { BASHO_PORT: "6969.5" } })).toThrow();
});

test("expected ports outside 1 to 65535 are rejected", () => {
  expect(() => loadSecurityConfig({ env: {}, fileConfig: { expectedPorts: [0] } })).toThrow();
  expect(() => loadSecurityConfig({ env: {}, fileConfig: { expectedPorts: [70000] } })).toThrow();
  expect(() => loadSecurityConfig({ env: {}, fileConfig: { expectedPorts: [22, 65535] } })).not.toThrow();
});

test("AI confidence outside 0 to 1 is rejected", () => {
  expect(() =>
    loadSecurityConfig({ env: {}, fileConfig: { ai: { confidenceThreshold: 1.5 } } }),
  ).toThrow();
  expect(() =>
    loadSecurityConfig({ env: {}, fileConfig: { ai: { confidenceThreshold: -0.1 } } }),
  ).toThrow();

  const bounded = loadSecurityConfig({ env: {}, fileConfig: { ai: { confidenceThreshold: 1 } } });
  expect(bounded.settings.ai.confidenceThreshold).toBe(1);
});

test("lockdown lease outside 30 to 1800 seconds is rejected", () => {
  expect(() => loadSecurityConfig({ env: {}, fileConfig: { lockdown: { leaseSeconds: 29 } } })).toThrow();
  expect(() => loadSecurityConfig({ env: {}, fileConfig: { lockdown: { leaseSeconds: 1801 } } })).toThrow();

  const bounded = loadSecurityConfig({ env: {}, fileConfig: { lockdown: { leaseSeconds: 30 } } });
  expect(bounded.settings.lockdown.leaseSeconds).toBe(30);
  expect(
    loadSecurityConfig({ env: {}, fileConfig: { lockdown: { leaseSeconds: 1800 } } }).settings.lockdown.leaseSeconds,
  ).toBe(1800);
});

test("URLs with embedded credentials or fragments are rejected", () => {
  expect(() =>
    loadSecurityConfig({ env: {}, fileConfig: { ai: { baseURL: "https://user:pass@ai.example.test/v1" } } }),
  ).toThrow();
  expect(() =>
    loadSecurityConfig({ env: {}, fileConfig: { ai: { baseURL: "https://ai.example.test/v1#frag" } } }),
  ).toThrow();
  expect(() =>
    loadSecurityConfig({
      env: {},
      fileConfig: { notifications: { ntfyUrl: "https://user:pass@notify.example.test/basho" } },
    }),
  ).toThrow();

  expect(() =>
    loadSecurityConfig({ env: { OPENCODE_BASE_URL: "https://user:pass@ai.example.test/v1" } }),
  ).toThrow();
  expect(() => loadSecurityConfig({ env: { OPENCODE_BASE_URL: "https://ai.example.test/v1#frag" } })).toThrow();
});

test("notification URLs accept http for private and Tailscale endpoints", () => {
  expect(() =>
    loadSecurityConfig({
      env: {},
      fileConfig: { notifications: { ntfyUrl: "http://flux.tailnet.ts.net:8091/basho-security" } },
    }),
  ).not.toThrow();

  expect(() =>
    loadSecurityConfig({
      env: {},
      fileConfig: { ai: { baseURL: "http://127.0.0.1:1234/v1" } },
    }),
  ).not.toThrow();
});

test("publicOrigin must be a bare origin", () => {
  expect(() =>
    loadSecurityConfig({ env: {}, fileConfig: { notifications: { publicOrigin: "https://basho.example.test/foo" } } }),
  ).toThrow();
  expect(() =>
    loadSecurityConfig({ env: {}, fileConfig: { notifications: { publicOrigin: "https://basho.example.test?x=1" } } }),
  ).toThrow();
  expect(() =>
    loadSecurityConfig({ env: {}, fileConfig: { notifications: { publicOrigin: "basho.example.test" } } }),
  ).toThrow();

  const valid = loadSecurityConfig({
    env: {},
    fileConfig: { notifications: { publicOrigin: "https://basho.example.test" } },
  });
  expect(valid.settings.notifications.publicOrigin).toBe("https://basho.example.test");
});

test("unknown lockdown modes are rejected", () => {
  expect(() =>
    loadSecurityConfig({ env: {}, overrides: { mode: "yolo" as LockdownMode } }),
  ).toThrow();
  expect(() =>
    loadSecurityConfig({ env: {}, overrides: { mode: "MONITOR" as LockdownMode } }),
  ).toThrow();
  expect(loadSecurityConfig({ env: {}, overrides: { mode: "monitor" } }).settings.mode).toBe("monitor");
});

// ---------------------------------------------------------------------------
// readBounded
// ---------------------------------------------------------------------------

test("readBounded returns UTF-8 text within the byte quota", async () => {
  expect(await readBounded(textStream("hello"), 64)).toBe("hello");
  expect(await readBounded(textStream(""), 64)).toBe("");
});

test("readBounded accepts a payload exactly at the quota boundary", async () => {
  expect(await readBounded(textStream("abcd"), 4)).toBe("abcd");
});

test("readBounded decodes multi-byte characters split across chunks", async () => {
  const text = "héllo ✓ 世界";
  const encoded = new TextEncoder().encode(text);

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoded.slice(0, 2));
      controller.enqueue(encoded.slice(2, 3));
      controller.enqueue(encoded.slice(3));
      controller.close();
    },
  });

  expect(await readBounded(stream, 1024)).toBe(text);
});

test("a stream is canceled as soon as it exceeds its byte quota", async () => {
  let canceled = false;
  const input = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(5));
    },
    cancel() {
      canceled = true;
    },
  });

  await expect(readBounded(input, 4)).rejects.toThrow("output limit");
  expect(canceled).toBe(true);
});

test("readBounded cancels a stream that overflows on a later chunk", async () => {
  let canceled = false;
  let pulls = 0;
  const input = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulls += 1;
      if (pulls === 1) controller.enqueue(new Uint8Array(2));
      else if (pulls === 2) controller.enqueue(new Uint8Array(3));
      else controller.close();
    },
    cancel() {
      canceled = true;
    },
  });

  await expect(readBounded(input, 4)).rejects.toThrow("output limit");
  expect(canceled).toBe(true);
});

// ---------------------------------------------------------------------------
// createCommandRunner
// ---------------------------------------------------------------------------

test("invalid unit names are rejected before spawning", async () => {
  const runner = createCommandRunner();
  const invalidNames = [
    "",
    "basho-test",
    "basho test.service",
    "basho;reboot.service",
    "basho$(reboot).service",
    "basho\n.service",
    "../basho.service",
  ];

  for (const name of invalidNames) {
    const error = await rejectionOf(() =>
      runner.run({ kind: "unit", name, scope: "system" }),
    );
    expect(error.message).toMatch(/unit/i);
  }
});

test("invalid journal cursors are rejected before spawning", async () => {
  const runner = createCommandRunner();
  const invalidCursors = [
    "",
    "cursor with spaces",
    "cursor\nwith-newline",
    "s=" + "a".repeat(4096),
  ];

  for (const after of invalidCursors) {
    const error = await rejectionOf(() =>
      runner.run({ kind: "journal", after, limit: 10 }),
    );
    expect(error.message).toMatch(/cursor/i);
  }
});

test("a benign recipe resolves without leaking environment secrets", async () => {
  const canary = "canary-secret-should-not-leak-9f3a";
  const saved = new Map<string, string | undefined>();

  for (const key of SECRET_ENV_KEYS) {
    saved.set(key, process.env[key]);
    process.env[key] = canary;
  }

  try {
    const result = await createCommandRunner().run({ kind: "processes" });
    expect(["ok", "unavailable", "timeout", "overflow", "failed"]).toContain(result.status);
    expect(JSON.stringify(result)).not.toContain(canary);
    if (result.status === "ok") {
      expect(result.stdout).not.toContain(canary);
      expect(typeof result.exitCode).toBe("number");
    }
  } finally {
    for (const key of SECRET_ENV_KEYS) {
      const value = saved.get(key);
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

// ---------------------------------------------------------------------------
// Regression tests (Task 1 review findings)
// ---------------------------------------------------------------------------

test("explicit null in overrides is rejected instead of falling back to defaults", () => {
  expect(() =>
    loadSecurityConfig({
      env: {},
      overrides: { mode: null as unknown as LockdownMode },
    }),
  ).toThrow();
  expect(() =>
    loadSecurityConfig({
      env: {},
      overrides: { scanIntervalMinutes: null as unknown as number },
    }),
  ).toThrow();
  expect(() =>
    loadSecurityConfig({
      env: {},
      overrides: { criteria: null as unknown as Record<string, boolean> },
    }),
  ).toThrow();
});

test("explicit null in fileConfig fields is rejected instead of applying defaults", () => {
  const nullConfigs: unknown[] = [
    { mode: null },
    { scanIntervalMinutes: null },
    { expectedPorts: null },
    { workloads: null },
    { ai: { baseURL: null } },
    { ai: { model: null } },
    { ai: { sessionHeader: null } },
    { ai: { confidenceThreshold: null } },
    { ai: { triageCooldownMinutes: null } },
    { notifications: { channels: null } },
    { notifications: { cooldownMinutes: null } },
    { notifications: { ntfyUrl: null } },
    { notifications: { publicOrigin: null } },
    { lockdown: { proposalMinutes: null } },
    { lockdown: { leaseSeconds: null } },
    { lockdown: { helperEnabled: null } },
  ];

  for (const fileConfig of nullConfigs) {
    expect(() => loadSecurityConfig({ env: {}, fileConfig })).toThrow();
  }

  // Omitted or explicit undefined still falls back to defaults.
  const withUndefined = loadSecurityConfig({
    env: {},
    fileConfig: {
      mode: undefined,
      scanIntervalMinutes: undefined,
      expectedPorts: undefined,
      ai: { confidenceThreshold: undefined },
      lockdown: { leaseSeconds: undefined },
    },
    overrides: { mode: undefined, scanIntervalMinutes: undefined },
  });
  expect(withUndefined.settings.mode).toBe("approve");
  expect(withUndefined.settings.scanIntervalMinutes).toBe(60);
  expect(withUndefined.settings.expectedPorts).toEqual([22, 6969]);
  expect(withUndefined.settings.ai.confidenceThreshold).toBe(0.85);
  expect(withUndefined.settings.lockdown.leaseSeconds).toBe(600);
});

test("publicOrigin rejects raw paths that normalize to root", () => {
  const invalidOrigins = [
    "https://basho.example.test/dashboard/..",
    "https://basho.example.test/.",
    "https://basho.example.test/..",
    "https://basho.example.test//",
    "https://basho.example.test/a/../",
    "https://basho.example.test\\dashboard\\..",
    "https://basho.example.test/?",
    "https://basho.example.test/#",
  ];

  for (const publicOrigin of invalidOrigins) {
    expect(() =>
      loadSecurityConfig({
        env: {},
        fileConfig: { notifications: { publicOrigin } },
      }),
    ).toThrow();
  }

  expect(
    loadSecurityConfig({
      env: {},
      fileConfig: { notifications: { publicOrigin: "https://basho.example.test/" } },
    }).settings.notifications.publicOrigin,
  ).toBe("https://basho.example.test");
  expect(
    loadSecurityConfig({
      env: {},
      fileConfig: { notifications: { publicOrigin: "https://basho.example.test:8443/" } },
    }).settings.notifications.publicOrigin,
  ).toBe("https://basho.example.test:8443");
});

test("readBounded still throws output limit when stream cancel rejects", async () => {
  let canceled = false;
  const input = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(5));
    },
    cancel() {
      canceled = true;
      return Promise.reject(new Error("cancel exploded"));
    },
  });

  const error = await rejectionOf(() => readBounded(input, 4));
  expect(error.message).toBe("output limit");
  expect(canceled).toBe(true);
});

test("readBounded throws output limit immediately when stream cancel stalls", async () => {
  let canceled = false;
  const input = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(5));
    },
    cancel() {
      canceled = true;
      return new Promise(() => {
        // Intentionally never settles.
      });
    },
  });

  const outcome = await Promise.race([
    rejectionOf(() => readBounded(input, 4)).then((error) => ({
      kind: "rejected" as const,
      message: error.message,
    })),
    new Promise<{ kind: "stalled" }>((resolve) =>
      setTimeout(() => resolve({ kind: "stalled" }), 250),
    ),
  ]);

  expect(outcome).toEqual({ kind: "rejected", message: "output limit" });
  expect(canceled).toBe(true);
});

test("journal after-cursor fails when command emits a full page and exits non-zero", async () => {
  const realSpawn = Bun.spawn.bind(Bun);
  const whichSpy = spyOn(Bun, "which").mockReturnValue("/bin/sh");
  const scripts = [
    'printf \'{"MESSAGE":"one"}\\n{"MESSAGE":"two"}\\n\'; exit 7',
    'printf \'{"MESSAGE":"one"}\\n{"MESSAGE":"two"}\\n\'; sleep 0.02; exit 7',
  ];

  try {
    for (const script of scripts) {
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const spawnSpy = spyOn(Bun, "spawn").mockImplementation(((_argv, options) =>
          realSpawn(
            ["/bin/sh", "-c", script],
            options as Parameters<typeof Bun.spawn>[1],
          )) as typeof Bun.spawn);
        try {
          const result = await createCommandRunner().run({
            kind: "journal",
            after: "s=abc123",
            limit: 2,
          });
          expect(result).toEqual({ status: "failed" });
        } finally {
          spawnSpy.mockRestore();
        }
      }
    }
  } finally {
    whichSpy.mockRestore();
  }
});

test("journal after-cursor fails when command emits a full page and exits with SIGPIPE", async () => {
  const realSpawn = Bun.spawn.bind(Bun);
  const whichSpy = spyOn(Bun, "which").mockReturnValue("/bin/sh");
  const scripts = [
    'printf \'{"MESSAGE":"one"}\\n{"MESSAGE":"two"}\\n\'; kill -PIPE $$',
    'printf \'{"MESSAGE":"one"}\\n{"MESSAGE":"two"}\\n\'; sleep 0.02; kill -PIPE $$',
  ];

  try {
    for (const script of scripts) {
      const spawnSpy = spyOn(Bun, "spawn").mockImplementation(((_argv, options) =>
        realSpawn(
          ["/bin/sh", "-c", script],
          options as Parameters<typeof Bun.spawn>[1],
        )) as typeof Bun.spawn);
      try {
        const result = await createCommandRunner().run({
          kind: "journal",
          after: "s=abc123",
          limit: 2,
        });
        expect(result).toEqual({ status: "failed" });
      } finally {
        spawnSpy.mockRestore();
      }
    }
  } finally {
    whichSpy.mockRestore();
  }
});

test("journal after-cursor succeeds when command emits an exact full page and exits zero", async () => {
  const realSpawn = Bun.spawn.bind(Bun);
  const whichSpy = spyOn(Bun, "which").mockReturnValue("/bin/sh");
  const spawnSpy = spyOn(Bun, "spawn").mockImplementation(((_argv, options) =>
    realSpawn(
      ["/bin/sh", "-c", 'printf \'{"MESSAGE":"one"}\\n{"MESSAGE":"two"}\\n\'; exit 0'],
      options as Parameters<typeof Bun.spawn>[1],
    )) as typeof Bun.spawn);

  try {
    const result = await createCommandRunner().run({
      kind: "journal",
      after: "s=abc123",
      limit: 2,
    });
    expect(result).toEqual({
      status: "ok",
      stdout: '{"MESSAGE":"one"}\n{"MESSAGE":"two"}',
      exitCode: 0,
    });
  } finally {
    spawnSpy.mockRestore();
    whichSpy.mockRestore();
  }
});

test("journal after-cursor succeeds when runner stops a streaming command exceeding the line limit", async () => {
  const realSpawn = Bun.spawn.bind(Bun);
  const whichSpy = spyOn(Bun, "which").mockReturnValue("/bin/sh");
  const scripts = [
    'printf \'{"MESSAGE":"one"}\\n{"MESSAGE":"two"}\\n{"MESSAGE":"three"}\\n\'; sleep 5',
    'printf \'{"MESSAGE":"one"}\\n{"MESSAGE":"two"}\\n\'; sleep 0.02; printf \'{"MESSAGE":"three"}\\n\'; sleep 5',
    'printf \'{"MESSAGE":"one"}\\n{"MESSAGE":"two"}\\n\'; while true; do printf \'{"MESSAGE":"more"}\\n\'; done',
  ];

  try {
    for (const script of scripts) {
      let spawned: ReturnType<typeof Bun.spawn> | undefined;
      const spawnSpy = spyOn(Bun, "spawn").mockImplementation(((_argv, options) => {
        spawned = realSpawn(
          ["/bin/sh", "-c", script],
          options as Parameters<typeof Bun.spawn>[1],
        );
        return spawned;
      }) as typeof Bun.spawn);

      try {
        const startedAt = performance.now();
        const result = await createCommandRunner().run({
          kind: "journal",
          after: "s=abc123",
          limit: 2,
        });
        const elapsedMs = performance.now() - startedAt;
        expect(result).toEqual({
          status: "ok",
          stdout: '{"MESSAGE":"one"}\n{"MESSAGE":"two"}',
          exitCode: 0,
        });
        expect(elapsedMs).toBeLessThan(1_000);
        expect(spawned).toBeDefined();
        expect(spawned!.signalCode).toBe("SIGKILL");
        let alive = true;
        try {
          process.kill(spawned!.pid, 0);
        } catch {
          alive = false;
        }
        expect(alive).toBe(false);
      } finally {
        spawnSpy.mockRestore();
      }
    }
  } finally {
    whichSpy.mockRestore();
  }
});

test("journal after-cursor returns full page promptly and reaps child when exact page keeps stdout open", async () => {
  const realSpawn = Bun.spawn.bind(Bun);
  const whichSpy = spyOn(Bun, "which").mockReturnValue("/bin/sh");
  let spawned: ReturnType<typeof Bun.spawn> | undefined;
  const spawnSpy = spyOn(Bun, "spawn").mockImplementation(((_argv, options) => {
    spawned = realSpawn(
      ["/bin/sh", "-c", 'printf \'{"MESSAGE":"one"}\\n{"MESSAGE":"two"}\\n\'; exec sleep 10'],
      options as Parameters<typeof Bun.spawn>[1],
    );
    return spawned;
  }) as typeof Bun.spawn);

  try {
    const startedAt = performance.now();
    const result = await createCommandRunner({ timeoutMs: 500 }).run({
      kind: "journal",
      after: "s=abc123",
      limit: 2,
    });
    const elapsedMs = performance.now() - startedAt;

    expect(result).toEqual({
      status: "ok",
      stdout: '{"MESSAGE":"one"}\n{"MESSAGE":"two"}',
      exitCode: 0,
    });
    expect(elapsedMs).toBeLessThan(1_000);
    expect(spawned).toBeDefined();
    expect(spawned!.signalCode).toBe("SIGKILL");
    let alive = true;
    try {
      process.kill(spawned!.pid, 0);
    } catch {
      alive = false;
    }
    expect(alive).toBe(false);
  } finally {
    spawnSpy.mockRestore();
    whichSpy.mockRestore();
  }
});

test("abort returns promptly when a grandchild keeps stdout and stderr pipes open", async () => {
  const dir = mkdtempSync(join(tmpdir(), "basho-runner-abort-"));
  const pidFile = join(dir, "grandchild.pid");
  const realSpawn = Bun.spawn.bind(Bun);
  const whichSpy = spyOn(Bun, "which").mockReturnValue("/bin/sh");
  const spawnSpy = spyOn(Bun, "spawn").mockImplementation(((_argv, options) =>
    realSpawn(
      ["/bin/sh", "-c", `sleep 5 & echo $! > '${pidFile}'; sleep 5`],
      options as Parameters<typeof Bun.spawn>[1],
    )) as typeof Bun.spawn);

  const controller = new AbortController();
  const abortTimer = setTimeout(() => controller.abort(), 100);

  try {
    const startedAt = performance.now();
    const result = await createCommandRunner().run({ kind: "processes" }, controller.signal);
    const elapsedMs = performance.now() - startedAt;

    expect(result).toEqual({ status: "failed" });
    expect(elapsedMs).toBeLessThan(1_000);
  } finally {
    clearTimeout(abortTimer);
    spawnSpy.mockRestore();
    whichSpy.mockRestore();
    try {
      const pid = Number(readFileSync(pidFile, "utf8").trim());
      if (Number.isInteger(pid) && pid > 0) {
        process.kill(pid, "SIGKILL");
      }
    } catch {
      // Grandchild may have already exited.
    }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("timeout returns promptly when a grandchild keeps stdout and stderr pipes open", async () => {
  const dir = mkdtempSync(join(tmpdir(), "basho-runner-timeout-"));
  const pidFile = join(dir, "grandchild.pid");
  const realSpawn = Bun.spawn.bind(Bun);
  const whichSpy = spyOn(Bun, "which").mockReturnValue("/bin/sh");
  const spawnSpy = spyOn(Bun, "spawn").mockImplementation(((_argv, options) =>
    realSpawn(
      ["/bin/sh", "-c", `sleep 5 & echo $! > '${pidFile}'; sleep 5`],
      options as Parameters<typeof Bun.spawn>[1],
    )) as typeof Bun.spawn);

  try {
    const startedAt = performance.now();
    const result = await createCommandRunner({ timeoutMs: 150 }).run({ kind: "processes" });
    const elapsedMs = performance.now() - startedAt;

    expect(result).toEqual({ status: "timeout" });
    expect(elapsedMs).toBeLessThan(1_000);
  } finally {
    spawnSpy.mockRestore();
    whichSpy.mockRestore();
    try {
      const pid = Number(readFileSync(pidFile, "utf8").trim());
      if (Number.isInteger(pid) && pid > 0) {
        process.kill(pid, "SIGKILL");
      }
    } catch {
      // Grandchild may have already exited.
    }
    rmSync(dir, { recursive: true, force: true });
  }
});
