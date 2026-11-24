import { expect, test } from "bun:test";
import { NotificationDispatcher } from "../../src/security/notifications";
import { SecurityStore } from "../../src/security/store";

test("ntfy uses authorization headers and a token-free deep link", async () => {
  const store = new SecurityStore(":memory:");
  const requests: { url: string; init: RequestInit }[] = [];
  const dispatcher = new NotificationDispatcher({
    store, clock: { now: () => 100 },
    config: {
      channels: ["ntfy"], cooldownMinutes: 15,
      ntfyUrl: "http://notify.example.test/basho", publicOrigin: "https://basho.example.test",
    },
    secrets: { ntfyToken: "fixture-token" },
    runner: { async run() { return { status: "unavailable" }; } },
    fetcher: async (url, init) => { requests.push({ url, init }); return new Response(null, { status: 204 }); },
    onInApp: () => {},
  });
  try {
    dispatcher.publish({
      id: "alert-1", fingerprint: "auth:ssh_burst:198.51.100.42", severity: "breach",
      summary: "Repeated failures", createdAt: 100, proposalId: "p-1",
    });
    await dispatcher.drain();
    const call = requests[0]!;
    expect(call.url).toBe("http://notify.example.test/basho");
    expect(call.init.redirect).toBe("error");
    const headers = new Headers(call.init.headers);
    expect(headers.get("Authorization")).toBe("Bearer fixture-token");
    expect(headers.get("Click")).toBe("https://basho.example.test/security#proposal-p-1");
    expect(headers.get("Priority")).toBe("urgent");
    expect(String(call.init.body)).not.toContain("fixture-token");
    expect(store.channelHealth().ntfy?.status).toBe("sent");
  } finally { store.close(); }
});

import type {
  AlertChannel,
  Clock,
  CommandRequest,
  CommandResult,
  HttpFetcher,
  SecurityAlert,
  SecuritySecrets,
  SecuritySettings,
  Severity,
} from "../../src/security/types";

const NTFY_URL = "http://notify.example.test/basho";
const PUBLIC_ORIGIN = "https://basho.example.test";
const NTFY_TOKEN = "fixture-token";
const DISCORD_WEBHOOK = "https://discord.com/api/webhooks/123456789/secret-fixture-token";
const TELEGRAM_BOT_TOKEN = "123456789:fixture-bot-token";
const TELEGRAM_CHAT_ID = "42";
const HOUR_MS = 3_600_000;

type NotificationConfig = SecuritySettings["notifications"];

interface HarnessOptions {
  channels?: AlertChannel[];
  notifications?: Partial<NotificationConfig>;
  secrets?: SecuritySecrets;
  fetchResponse?: (url: string, init: RequestInit) => Response | Promise<Response>;
  runnerResult?: (request: CommandRequest) => CommandResult;
  now?: () => number;
}

interface Harness {
  store: SecurityStore;
  dispatcher: NotificationDispatcher;
  requests: { url: string; init: RequestInit }[];
  inApp: SecurityAlert[];
  runnerCalls: { request: CommandRequest; signal?: AbortSignal }[];
}

function fakeClock(start = 1_000): Clock & { advance(ms: number): void } {
  let current = start;
  return {
    now: () => current,
    advance(ms: number) {
      current += ms;
    },
  };
}

function alertFixture(id: string, overrides: Partial<SecurityAlert> = {}): SecurityAlert {
  return {
    id,
    fingerprint: `auth:ssh_burst:${id}`,
    severity: "warning",
    summary: `Alert ${id}`,
    createdAt: 100,
    ...overrides,
  };
}

function createHarness(options: HarnessOptions = {}): Harness {
  const store = new SecurityStore(":memory:");
  const requests: { url: string; init: RequestInit }[] = [];
  const inApp: SecurityAlert[] = [];
  const runnerCalls: { request: CommandRequest; signal?: AbortSignal }[] = [];
  const fetcher: HttpFetcher = async (url, init) => {
    requests.push({ url, init });
    return options.fetchResponse ? options.fetchResponse(url, init) : new Response(null, { status: 204 });
  };

  const dispatcher = new NotificationDispatcher({
    store,
    clock: { now: options.now ?? (() => 100) },
    config: { channels: options.channels ?? ["in-app"], cooldownMinutes: 15, ...options.notifications },
    secrets: options.secrets ?? {},
    runner: {
      async run(request: CommandRequest, signal?: AbortSignal): Promise<CommandResult> {
        runnerCalls.push({ request, signal });
        return options.runnerResult ? options.runnerResult(request) : { status: "unavailable" };
      },
    },
    fetcher,
    onInApp: (alert) => {
      inApp.push(alert);
    },
  });

  return { store, dispatcher, requests, inApp, runnerCalls };
}

function ntfyHarness(overrides: HarnessOptions = {}): Harness {
  return createHarness({
    channels: ["ntfy"],
    notifications: { ntfyUrl: NTFY_URL },
    ...overrides,
  });
}

function jsonBody(init: RequestInit): string {
  return String(init.body);
}

test("publish suppresses a duplicate fingerprint inside the cooldown at equal or lower severity", () => {
  const harness = createHarness({ channels: ["in-app"] });
  const { dispatcher, store } = harness;
  try {
    const cooldownMs = 15 * 60_000;

    expect(dispatcher.publish(alertFixture("dedupe-1", { fingerprint: "auth:ssh_burst:198.51.100.42" }))).toBe(true);
    expect(dispatcher.publish(alertFixture("dedupe-2", {
      fingerprint: "auth:ssh_burst:198.51.100.42",
      createdAt: 100 + cooldownMs - 1,
    }))).toBe(false);
    expect(dispatcher.publish(alertFixture("dedupe-3", {
      fingerprint: "auth:ssh_burst:198.51.100.42",
      severity: "info",
      createdAt: 100 + 5_000,
    }))).toBe(false);

    expect(store.recentAlerts(0).map((alert) => alert.id)).toEqual(["dedupe-1"]);
  } finally {
    store.close();
  }
});

test("publish escalates severity inside the cooldown", () => {
  const harness = createHarness({ channels: ["in-app"] });
  const { dispatcher, store } = harness;
  const fingerprint = "network:unexpected_listener:203.0.113.19";
  try {
    expect(dispatcher.publish(alertFixture("escalate-info", { fingerprint, severity: "info" }))).toBe(true);
    expect(dispatcher.publish(alertFixture("escalate-warning", { fingerprint, severity: "warning", createdAt: 200 }))).toBe(true);
    expect(dispatcher.publish(alertFixture("escalate-critical", { fingerprint, severity: "critical", createdAt: 300 }))).toBe(true);
    expect(dispatcher.publish(alertFixture("escalate-breach", { fingerprint, severity: "breach", createdAt: 400 }))).toBe(true);
    expect(dispatcher.publish(alertFixture("escalate-lower", { fingerprint, severity: "warning", createdAt: 500 }))).toBe(false);

    expect(store.recentAlerts(0)).toHaveLength(4);
  } finally {
    store.close();
  }
});

test("publish accepts the same fingerprint after the cooldown window", () => {
  const harness = createHarness({ channels: ["in-app"] });
  const { dispatcher, store } = harness;
  const fingerprint = "units:system_anomaly:2001:db8::10";
  const cooldownMs = 15 * 60_000;
  try {
    expect(dispatcher.publish(alertFixture("window-1", { fingerprint, createdAt: 100 }))).toBe(true);
    expect(dispatcher.publish(alertFixture("window-2", { fingerprint, createdAt: 100 + cooldownMs }))).toBe(true);
    expect(dispatcher.publish(alertFixture("window-3", { fingerprint, createdAt: 100 + cooldownMs + 1_000 }))).toBe(false);
    expect(store.recentAlerts(0)).toHaveLength(2);
  } finally {
    store.close();
  }
});

test("the in-app channel emits only after the alert is committed", async () => {
  const store = new SecurityStore(":memory:");
  const seen: { alert: SecurityAlert; persisted: boolean }[] = [];
  const dispatcher = new NotificationDispatcher({
    store,
    clock: { now: () => 1_000 },
    config: { channels: ["in-app"], cooldownMinutes: 15 },
    secrets: {},
    runner: { async run() { return { status: "unavailable" }; } },
    fetcher: async () => new Response(null, { status: 204 }),
    onInApp: (alert) => {
      seen.push({ alert, persisted: store.recentAlerts(0).some((row) => row.id === alert.id) });
    },
  });
  const alert = alertFixture("alert-in-app");
  try {
    expect(dispatcher.publish(alert)).toBe(true);
    expect(seen).toHaveLength(0);

    await dispatcher.drain();
    expect(seen).toHaveLength(1);
    expect(seen[0]!.persisted).toBe(true);
    expect(seen[0]!.alert).toEqual(alert);
    expect(store.channelHealth()["in-app"]?.status).toBe("sent");
    expect(store.recentAlerts(0).map((row) => row.id)).toEqual(["alert-in-app"]);

    await dispatcher.drain();
    expect(seen).toHaveLength(1);
  } finally {
    store.close();
  }
});

test("ntfy maps priority and tags for every severity", async () => {
  const cases: { severity: Severity; priority: string; tag: string }[] = [
    { severity: "breach", priority: "urgent", tag: "rotating_light" },
    { severity: "critical", priority: "high", tag: "shield" },
    { severity: "warning", priority: "default", tag: "shield" },
    { severity: "info", priority: "default", tag: "shield" },
  ];
  for (const expected of cases) {
    const harness = ntfyHarness();
    try {
      expect(harness.dispatcher.publish(alertFixture(`severity-${expected.severity}`, {
        severity: expected.severity,
      }))).toBe(true);
      await harness.dispatcher.drain();
      const headers = new Headers(harness.requests[0]!.init.headers);
      expect(headers.get("Priority")).toBe(expected.priority);
      expect(headers.get("Tags")).toBe(expected.tag);
    } finally {
      harness.store.close();
    }
  }
});

test("ntfy omits authorization and deep links when secrets and origin are absent", async () => {
  const harness = ntfyHarness();
  try {
    harness.dispatcher.publish(alertFixture("ntfy-bare"));
    await harness.dispatcher.drain();

    const request = harness.requests[0]!;
    const headers = new Headers(request.init.headers);
    expect(headers.get("Authorization")).toBeNull();
    expect(headers.get("Click")).toBeNull();
    expect(headers.get("Priority")).toBe("default");
    expect(jsonBody(request.init)).not.toContain(NTFY_TOKEN);
  } finally {
    harness.store.close();
  }
});

test("ntfy deep links to the security view when no proposal is attached", async () => {
  const harness = ntfyHarness({ notifications: { ntfyUrl: NTFY_URL, publicOrigin: PUBLIC_ORIGIN } });
  try {
    harness.dispatcher.publish(alertFixture("ntfy-no-proposal"));
    await harness.dispatcher.drain();

    const headers = new Headers(harness.requests[0]!.init.headers);
    expect(headers.get("Click")).toBe(`${PUBLIC_ORIGIN}/security`);
  } finally {
    harness.store.close();
  }
});

test("ntfy passes a redirect guard and an abort signal", async () => {
  const harness = ntfyHarness();
  try {
    harness.dispatcher.publish(alertFixture("ntfy-guard"));
    await harness.dispatcher.drain();

    const init = harness.requests[0]!.init;
    expect(init.redirect).toBe("error");
    expect(init.signal).toBeInstanceOf(AbortSignal);
  } finally {
    harness.store.close();
  }
});

test("ntfy settles failed without fetching when the url is unconfigured", async () => {
  const harness = createHarness({ channels: ["ntfy"] });
  try {
    harness.dispatcher.publish(alertFixture("ntfy-unconfigured"));
    await harness.dispatcher.drain();

    expect(harness.requests).toHaveLength(0);
    expect(harness.store.channelHealth().ntfy?.status).toBe("failed");
  } finally {
    harness.store.close();
  }
});

test("desktop maps severity to notify-send urgency and marks the channel sent", async () => {
  const cases: { severity: Severity; urgency: "normal" | "critical" }[] = [
    { severity: "breach", urgency: "critical" },
    { severity: "critical", urgency: "critical" },
    { severity: "warning", urgency: "normal" },
    { severity: "info", urgency: "normal" },
  ];
  for (const expected of cases) {
    const harness = createHarness({
      channels: ["desktop"],
      runnerResult: () => ({ status: "ok", stdout: "", exitCode: 0 }),
    });
    try {
      const summary = `Desk ${expected.severity}`;
      harness.dispatcher.publish(alertFixture(`desk-${expected.severity}`, { severity: expected.severity, summary }));
      await harness.dispatcher.drain();

      expect(harness.runnerCalls).toHaveLength(1);
      const request = harness.runnerCalls[0]!.request;
      expect(request.kind).toBe("desktop");
      if (request.kind !== "desktop") throw new Error("expected a desktop command");
      expect(request.urgency).toBe(expected.urgency);
      expect(request.summary).toContain(summary);
      expect(request.body).toContain(summary);
      expect(harness.store.channelHealth().desktop?.status).toBe("sent");
    } finally {
      harness.store.close();
    }
  }
});

test("desktop treats an unavailable runner as a permanent failure", async () => {
  const harness = createHarness({ channels: ["desktop"], runnerResult: () => ({ status: "unavailable" }) });
  try {
    harness.dispatcher.publish(alertFixture("desk-unavailable"));
    await harness.dispatcher.drain();
    expect(harness.runnerCalls).toHaveLength(1);
    expect(harness.store.channelHealth().desktop?.status).toBe("failed");

    await harness.dispatcher.drain();
    expect(harness.runnerCalls).toHaveLength(1);
  } finally {
    harness.store.close();
  }
});

test("desktop retries transient runner failures up to five attempts", async () => {
  for (const status of ["timeout", "failed"] as const) {
    const clock = fakeClock(1_000);
    const harness = createHarness({
      channels: ["desktop"],
      now: clock.now,
      runnerResult: () => ({ status }),
    });
    try {
      harness.dispatcher.publish(alertFixture(`desk-${status}`));
      await harness.dispatcher.drain();
      expect(harness.runnerCalls).toHaveLength(1);
      expect(harness.store.channelHealth().desktop?.status).toBe("retrying");

      await harness.dispatcher.drain();
      expect(harness.runnerCalls).toHaveLength(1);

      for (let round = 0; round < 4; round += 1) {
        clock.advance(HOUR_MS);
        await harness.dispatcher.drain();
      }
      expect(harness.runnerCalls).toHaveLength(5);
      expect(harness.store.channelHealth().desktop?.status).toBe("failed");
    } finally {
      harness.store.close();
    }
  }
});

test("discord posts an embed with allowed_mentions and a token-free deep link", async () => {
  const harness = createHarness({
    channels: ["discord"],
    notifications: { publicOrigin: PUBLIC_ORIGIN },
    secrets: { discordWebhook: DISCORD_WEBHOOK },
  });
  try {
    harness.dispatcher.publish(alertFixture("discord-1", { severity: "breach", summary: "Repeated failures", proposalId: "p-1" }));
    await harness.dispatcher.drain();

    const request = harness.requests[0]!;
    expect(request.url).toBe(DISCORD_WEBHOOK);
    expect(request.init.method).toBe("POST");
    expect(request.init.redirect).toBe("error");
    expect(request.init.signal).toBeInstanceOf(AbortSignal);
    expect(new Headers(request.init.headers).get("Content-Type")).toContain("application/json");

    const payload = JSON.parse(jsonBody(request.init));
    expect(payload.allowed_mentions).toEqual({ parse: [] });
    const embeds = payload.embeds as { url?: string }[];
    expect(embeds.length).toBeGreaterThan(0);
    const rendered = JSON.stringify(embeds).toLowerCase();
    expect(rendered).toContain("repeated failures");
    expect(rendered).toContain("breach");
    expect(embeds[0]?.url).toBe(`${PUBLIC_ORIGIN}/security#proposal-p-1`);
    expect(jsonBody(request.init)).not.toContain("secret-fixture-token");
    expect(harness.store.channelHealth().discord?.status).toBe("sent");
  } finally {
    harness.store.close();
  }
});

test("discord rejects non-https or non-discord webhooks without fetching", async () => {
  const rejected = [
    "http://discord.com/api/webhooks/123456789/secret-fixture-token",
    "http://discordapp.com/api/webhooks/123456789/secret-fixture-token",
    "https://evil.example.test/api/webhooks/123456789/secret-fixture-token",
    "https://discord.com.evil.example.test/api/webhooks/123456789/secret-fixture-token",
    "not-a-url",
  ];
  for (const webhook of rejected) {
    const harness = createHarness({
      channels: ["discord"],
      notifications: { publicOrigin: PUBLIC_ORIGIN },
      secrets: { discordWebhook: webhook },
    });
    try {
      harness.dispatcher.publish(alertFixture(`discord-bad-${rejected.indexOf(webhook)}`));
      await harness.dispatcher.drain();

      expect(harness.requests).toHaveLength(0);
      expect(harness.store.channelHealth().discord?.status).toBe("failed");
      expect(JSON.stringify(harness.dispatcher.health())).not.toContain("secret-fixture-token");
    } finally {
      harness.store.close();
    }
  }
});

test("discord redacts the webhook secret from permanent failures", async () => {
  const clock = fakeClock(1_000);
  const harness = createHarness({
    channels: ["discord"],
    now: clock.now,
    notifications: { publicOrigin: PUBLIC_ORIGIN },
    secrets: { discordWebhook: DISCORD_WEBHOOK },
    fetchResponse: () => new Response(null, { status: 500 }),
  });
  try {
    harness.dispatcher.publish(alertFixture("discord-fail"));
    for (let round = 0; round < 5; round += 1) {
      await harness.dispatcher.drain();
      clock.advance(HOUR_MS);
    }

    expect(harness.requests).toHaveLength(5);
    expect(harness.store.channelHealth().discord?.status).toBe("failed");
    const projected = JSON.stringify(harness.dispatcher.health());
    expect(projected).not.toContain("secret-fixture-token");
  } finally {
    harness.store.close();
  }
});

test("telegram posts plain text with disabled link previews and a token-free link", async () => {
  const harness = createHarness({
    channels: ["telegram"],
    notifications: { publicOrigin: PUBLIC_ORIGIN },
    secrets: { telegramBotToken: TELEGRAM_BOT_TOKEN, telegramChatId: TELEGRAM_CHAT_ID },
  });
  try {
    harness.dispatcher.publish(alertFixture("telegram-1", { severity: "critical", summary: "Repeated failures", proposalId: "p-1" }));
    await harness.dispatcher.drain();

    const request = harness.requests[0]!;
    expect(request.url).toBe(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`);
    expect(request.init.method).toBe("POST");
    expect(request.init.redirect).toBe("error");
    expect(request.init.signal).toBeInstanceOf(AbortSignal);
    expect(new Headers(request.init.headers).get("Content-Type")).toContain("application/json");

    const payload = JSON.parse(jsonBody(request.init));
    expect(String(payload.chat_id)).toBe(TELEGRAM_CHAT_ID);
    expect(typeof payload.text).toBe("string");
    expect(payload.text).toContain("Repeated failures");
    expect(payload.text).toContain(`${PUBLIC_ORIGIN}/security#proposal-p-1`);
    expect(payload.text).not.toContain(TELEGRAM_BOT_TOKEN);
    expect(payload.parse_mode).toBeUndefined();
    const previewDisabled =
      payload.link_preview_options?.is_disabled === true || payload.disable_web_page_preview === true;
    expect(previewDisabled).toBe(true);
    expect(jsonBody(request.init)).not.toContain(TELEGRAM_BOT_TOKEN);
    expect(harness.store.channelHealth().telegram?.status).toBe("sent");
  } finally {
    harness.store.close();
  }
});

test("telegram settles failed without fetching when credentials are missing", async () => {
  const cases: SecuritySecrets[] = [
    {},
    { telegramBotToken: TELEGRAM_BOT_TOKEN },
    { telegramChatId: TELEGRAM_CHAT_ID },
  ];
  for (const [index, secrets] of cases.entries()) {
    const harness = createHarness({ channels: ["telegram"], secrets });
    try {
      harness.dispatcher.publish(alertFixture(`telegram-missing-${index}`));
      await harness.dispatcher.drain();

      expect(harness.requests).toHaveLength(0);
      expect(harness.store.channelHealth().telegram?.status).toBe("failed");
      expect(JSON.stringify(harness.dispatcher.health())).not.toContain(TELEGRAM_BOT_TOKEN);
    } finally {
      harness.store.close();
    }
  }
});

test("5xx responses retry with backoff and stop at five attempts", async () => {
  const clock = fakeClock(1_000);
  let calls = 0;
  const harness = ntfyHarness({
    now: clock.now,
    fetchResponse: () => {
      calls += 1;
      return new Response(null, { status: 503 });
    },
  });
  try {
    harness.dispatcher.publish(alertFixture("retry-5xx"));
    await harness.dispatcher.drain();
    expect(calls).toBe(1);
    expect(harness.store.channelHealth().ntfy?.status).toBe("retrying");

    await harness.dispatcher.drain();
    expect(calls).toBe(1);

    for (let round = 0; round < 4; round += 1) {
      clock.advance(HOUR_MS);
      await harness.dispatcher.drain();
    }
    expect(calls).toBe(5);
    expect(harness.store.channelHealth().ntfy?.status).toBe("failed");

    clock.advance(HOUR_MS);
    await harness.dispatcher.drain();
    expect(calls).toBe(5);
  } finally {
    harness.store.close();
  }
});

test("429 throttling retries instead of failing permanently", async () => {
  const clock = fakeClock(1_000);
  let calls = 0;
  const harness = ntfyHarness({
    now: clock.now,
    fetchResponse: () => {
      calls += 1;
      return new Response(null, { status: calls === 1 ? 429 : 204 });
    },
  });
  try {
    harness.dispatcher.publish(alertFixture("retry-429"));
    await harness.dispatcher.drain();
    expect(calls).toBe(1);
    expect(harness.store.channelHealth().ntfy?.status).toBe("retrying");

    clock.advance(HOUR_MS);
    await harness.dispatcher.drain();
    expect(calls).toBe(2);
    expect(harness.store.channelHealth().ntfy?.status).toBe("sent");
  } finally {
    harness.store.close();
  }
});

test("permanent 4xx responses fail immediately without retrying", async () => {
  for (const status of [400, 401, 403, 404]) {
    const harness = ntfyHarness({ fetchResponse: () => new Response(null, { status }) });
    try {
      harness.dispatcher.publish(alertFixture(`fatal-${status}`));
      await harness.dispatcher.drain();
      expect(harness.requests).toHaveLength(1);
      expect(harness.store.channelHealth().ntfy?.status).toBe("failed");

      await harness.dispatcher.drain();
      expect(harness.requests).toHaveLength(1);
    } finally {
      harness.store.close();
    }
  }
});

test("network errors retry with backoff", async () => {
  const clock = fakeClock(1_000);
  let calls = 0;
  const harness = ntfyHarness({
    now: clock.now,
    fetchResponse: () => {
      calls += 1;
      if (calls === 1) throw new TypeError("fetch failed: ECONNREFUSED");
      return new Response(null, { status: 204 });
    },
  });
  try {
    harness.dispatcher.publish(alertFixture("network-error"));
    await harness.dispatcher.drain();
    expect(harness.store.channelHealth().ntfy?.status).toBe("retrying");

    clock.advance(HOUR_MS);
    await harness.dispatcher.drain();
    expect(harness.store.channelHealth().ntfy?.status).toBe("sent");
  } finally {
    harness.store.close();
  }
});

test("a redirect rejection fails permanently without leaking credentials", async () => {
  const harness = ntfyHarness({
    secrets: { ntfyToken: NTFY_TOKEN },
    fetchResponse: () => {
      throw new TypeError("fetch failed: unexpected redirect blocked");
    },
  });
  try {
    harness.dispatcher.publish(alertFixture("redirect-blocked"));
    await harness.dispatcher.drain();

    expect(harness.requests).toHaveLength(1);
    expect(harness.store.channelHealth().ntfy?.status).toBe("failed");
    expect(JSON.stringify(harness.dispatcher.health())).not.toContain(NTFY_TOKEN);

    await harness.dispatcher.drain();
    expect(harness.requests).toHaveLength(1);
  } finally {
    harness.store.close();
  }
});

test("drain claims with a lease longer than the request timeout and settles with the claim token", async () => {
  const harness = ntfyHarness();
  const { store } = harness;
  const claims: { limit: number; leaseMs: number }[] = [];
  const claimTokens: string[] = [];
  const settlements: { token: string; settled: boolean }[] = [];
  const claim = store.claimDeliveries.bind(store);
  const settle = store.settleDelivery.bind(store);
  store.claimDeliveries = (now, limit, leaseMs) => {
    claims.push({ limit, leaseMs });
    const claimed = claim(now, limit, leaseMs);
    for (const delivery of claimed) claimTokens.push(delivery.claimToken);
    return claimed;
  };
  store.settleDelivery = (id, claimToken, now, result) => {
    const settled = settle(id, claimToken, now, result);
    settlements.push({ token: claimToken, settled });
    return settled;
  };
  try {
    expect(harness.dispatcher.publish(alertFixture("lease-1", { fingerprint: "auth:ssh_burst:198.51.100.42" }))).toBe(true);
    expect(harness.dispatcher.publish(alertFixture("lease-2", { fingerprint: "auth:ssh_burst:203.0.113.19" }))).toBe(true);
    await harness.dispatcher.drain();

    expect(harness.requests).toHaveLength(2);
    expect(claims.length).toBeGreaterThan(0);
    expect(claims.every((entry) => entry.leaseMs >= 15_000)).toBe(true);
    expect(claims.every((entry) => entry.limit > 0 && entry.limit <= 10)).toBe(true);
    expect(settlements).toHaveLength(2);
    expect(settlements.every((entry) => claimTokens.includes(entry.token))).toBe(true);
    expect(settlements.every((entry) => entry.settled)).toBe(true);
  } finally {
    store.close();
  }
});

test("drain bounds concurrent channel requests", async () => {
  let active = 0;
  let maxActive = 0;
  const harness = ntfyHarness({
    fetchResponse: async () => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      await new Promise((resolve) => setTimeout(resolve, 1));
      active -= 1;
      return new Response(null, { status: 204 });
    },
  });
  try {
    for (let index = 0; index < 12; index += 1) {
      expect(harness.dispatcher.publish(alertFixture(`burst-${index}`))).toBe(true);
    }
    await harness.dispatcher.drain();

    expect(harness.requests).toHaveLength(12);
    expect(maxActive).toBeGreaterThan(0);
    expect(maxActive).toBeLessThanOrEqual(8);
  } finally {
    harness.store.close();
  }
});

test("drain is a no-op when the outbox is empty", async () => {
  const harness = ntfyHarness();
  try {
    await harness.dispatcher.drain();
    expect(harness.requests).toHaveLength(0);
    expect(harness.store.channelHealth()).toEqual({});
  } finally {
    harness.store.close();
  }
});

test("sendTestAlert enqueues a unique alert per call and delivers through the outbox", async () => {
  const clock = fakeClock(1_000);
  const harness = ntfyHarness({ now: clock.now });
  try {
    const first = harness.dispatcher.sendTestAlert("ntfy");
    expect(typeof first).toBe("string");
    expect(first.length).toBeGreaterThan(0);
    expect(harness.requests).toHaveLength(0);

    await harness.dispatcher.drain();
    expect(harness.requests).toHaveLength(1);

    const second = harness.dispatcher.sendTestAlert("ntfy");
    expect(second).not.toBe(first);
    await harness.dispatcher.drain();
    expect(harness.requests).toHaveLength(2);

    expect(harness.store.channelHealth().ntfy?.status).toBe("sent");
    expect(harness.store.recentAlerts(0)).toHaveLength(2);
  } finally {
    harness.store.close();
  }
});

test("sendTestAlert rejects unready channels with a controlled error", () => {
  const cases: { channel: AlertChannel; secrets?: SecuritySecrets }[] = [
    { channel: "ntfy" },
    { channel: "discord" },
    { channel: "discord", secrets: { discordWebhook: "https://evil.example.test/api/webhooks/1/secret-fixture-token" } },
    { channel: "telegram" },
    { channel: "telegram", secrets: { telegramBotToken: TELEGRAM_BOT_TOKEN } },
    { channel: "telegram", secrets: { telegramChatId: TELEGRAM_CHAT_ID } },
  ];
  for (const entry of cases) {
    const harness = createHarness({ channels: [entry.channel], secrets: entry.secrets });
    try {
      let message = "";
      try {
        harness.dispatcher.sendTestAlert(entry.channel);
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }
      expect(message.length).toBeGreaterThan(0);
      expect(message).not.toContain("secret-fixture-token");
      expect(message).not.toContain(TELEGRAM_BOT_TOKEN);
      expect(harness.store.recentAlerts(0)).toHaveLength(0);
    } finally {
      harness.store.close();
    }
  }
});

test("sendTestAlert without a channel picks a ready channel or throws when none is ready", async () => {
  const ready = ntfyHarness();
  try {
    const id = ready.dispatcher.sendTestAlert();
    expect(typeof id).toBe("string");
    expect(id.length).toBeGreaterThan(0);
    await ready.dispatcher.drain();
    expect(ready.requests).toHaveLength(1);
  } finally {
    ready.store.close();
  }

  const unready = createHarness({ channels: ["ntfy"] });
  try {
    expect(() => unready.dispatcher.sendTestAlert()).toThrow();
    expect(unready.store.recentAlerts(0)).toHaveLength(0);
  } finally {
    unready.store.close();
  }
});

test("health mirrors channel health with zero secrets", async () => {
  const harness = ntfyHarness({ secrets: { ntfyToken: NTFY_TOKEN } });
  try {
    harness.dispatcher.publish(alertFixture("health-1"));
    await harness.dispatcher.drain();

    const health = harness.dispatcher.health();
    expect(health.ntfy?.status).toBe("sent");
    expect(health.ntfy?.status).toBe(harness.store.channelHealth().ntfy?.status);
    expect(JSON.stringify(health)).not.toContain(NTFY_TOKEN);
  } finally {
    harness.store.close();
  }
});

test("discord and telegram treat redirects as permanent failures without leaking secrets", async () => {
  const discordHarness = createHarness({
    channels: ["discord"],
    secrets: { discordWebhook: DISCORD_WEBHOOK },
    fetchResponse: () => new Response(null, { status: 302, headers: { Location: "https://evil.example.test/" } }),
  });
  try {
    discordHarness.dispatcher.publish(alertFixture("discord-redirect"));
    await discordHarness.dispatcher.drain();
    expect(discordHarness.requests).toHaveLength(1);
    expect(discordHarness.store.channelHealth().discord?.status).toBe("failed");
    expect(JSON.stringify(discordHarness.dispatcher.health())).not.toContain("secret-fixture-token");

    await discordHarness.dispatcher.drain();
    expect(discordHarness.requests).toHaveLength(1);
  } finally {
    discordHarness.store.close();
  }

  const telegramHarness = createHarness({
    channels: ["telegram"],
    secrets: { telegramBotToken: TELEGRAM_BOT_TOKEN, telegramChatId: TELEGRAM_CHAT_ID },
    fetchResponse: () => {
      throw new TypeError("fetch failed: redirect mode is set to error");
    },
  });
  try {
    telegramHarness.dispatcher.publish(alertFixture("telegram-redirect"));
    await telegramHarness.dispatcher.drain();
    expect(telegramHarness.requests).toHaveLength(1);
    expect(telegramHarness.store.channelHealth().telegram?.status).toBe("failed");
    expect(JSON.stringify(telegramHarness.dispatcher.health())).not.toContain(TELEGRAM_BOT_TOKEN);

    await telegramHarness.dispatcher.drain();
    expect(telegramHarness.requests).toHaveLength(1);
  } finally {
    telegramHarness.store.close();
  }
});

test("429 honors a numeric Retry-After header before retrying", async () => {
  const clock = fakeClock(10_000);
  let calls = 0;
  const harness = ntfyHarness({
    now: clock.now,
    fetchResponse: () => {
      calls += 1;
      if (calls === 1) {
        return new Response(null, { status: 429, headers: { "Retry-After": "60" } });
      }
      return new Response(null, { status: 204 });
    },
  });
  try {
    harness.dispatcher.publish(alertFixture("retry-after-429"));
    await harness.dispatcher.drain();
    expect(calls).toBe(1);
    expect(harness.store.channelHealth().ntfy?.status).toBe("retrying");

    clock.advance(59_000);
    await harness.dispatcher.drain();
    expect(calls).toBe(1);

    clock.advance(1_000);
    await harness.dispatcher.drain();
    expect(calls).toBe(2);
    expect(harness.store.channelHealth().ntfy?.status).toBe("sent");
  } finally {
    harness.store.close();
  }
});

test("ntfy rejects embedded URL credentials and telegram rejects path-injecting bot tokens without fetching", async () => {
  const ntfyBad = createHarness({
    channels: ["ntfy"],
    notifications: { ntfyUrl: "http://user:supersecret@notify.example.test/basho" },
  });
  try {
    ntfyBad.dispatcher.publish(alertFixture("ntfy-userinfo"));
    await ntfyBad.dispatcher.drain();
    expect(ntfyBad.requests).toHaveLength(0);
    expect(ntfyBad.store.channelHealth().ntfy?.status).toBe("failed");
    expect(JSON.stringify(ntfyBad.dispatcher.health())).not.toContain("supersecret");
  } finally {
    ntfyBad.store.close();
  }

  const tgBad = createHarness({
    channels: ["telegram"],
    secrets: { telegramBotToken: "123456:bad/../../token?x=1", telegramChatId: TELEGRAM_CHAT_ID },
  });
  try {
    tgBad.dispatcher.publish(alertFixture("telegram-bad-token"));
    await tgBad.dispatcher.drain();
    expect(tgBad.requests).toHaveLength(0);
    expect(tgBad.store.channelHealth().telegram?.status).toBe("failed");
    expect(JSON.stringify(tgBad.dispatcher.health())).not.toContain("bad/../../token");
  } finally {
    tgBad.store.close();
  }
});

test("discord rejects query parameters and malformed webhook paths without fetching", async () => {
  const invalidWebhooks = [
    "https://discord.com/api/webhooks/123456789/secret-fixture-token?wait=true",
    "https://discord.com/api/webhooks/not-numeric/secret-fixture-token",
    "https://discord.com/api/other/123456789/secret-fixture-token",
    "https://discord.com:8443/api/webhooks/123456789/secret-fixture-token",
  ];
  for (const [index, webhook] of invalidWebhooks.entries()) {
    const harness = createHarness({
      channels: ["discord"],
      secrets: { discordWebhook: webhook },
    });
    try {
      harness.dispatcher.publish(alertFixture(`discord-malformed-${index}`));
      await harness.dispatcher.drain();
      expect(harness.requests).toHaveLength(0);
      expect(harness.store.channelHealth().discord?.status).toBe("failed");
      expect(JSON.stringify(harness.dispatcher.health())).not.toContain("secret-fixture-token");
    } finally {
      harness.store.close();
    }
  }
});

test("Bun UnexpectedRedirect error shape fails permanently on attempt 1 without leaking secrets", async () => {
  const errorCases: Error[] = [
    Object.assign(
      new Error(`UnexpectedRedirect fetching "${NTFY_URL}"`),
      { code: "UnexpectedRedirect" },
    ),
    new Error("fetch failed", {
      cause: Object.assign(new Error("blocked"), { code: "UnexpectedRedirect" }),
    }),
  ];

  for (const [index, redirectError] of errorCases.entries()) {
    const harness = ntfyHarness({
      secrets: { ntfyToken: NTFY_TOKEN },
      fetchResponse: () => {
        throw redirectError;
      },
    });
    try {
      harness.dispatcher.publish(alertFixture(`bun-redirect-${index}`));
      await harness.dispatcher.drain();

      expect(harness.requests).toHaveLength(1);
      expect(harness.store.channelHealth().ntfy?.status).toBe("failed");
      expect(JSON.stringify(harness.dispatcher.health())).not.toContain(NTFY_TOKEN);

      await harness.dispatcher.drain();
      expect(harness.requests).toHaveLength(1);
    } finally {
      harness.store.close();
    }
  }
});

test("real Bun fetch with redirect:error settles 302 as permanent failure in 1 request without following", async () => {
  let originHits = 0;
  let targetHits = 0;
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request): Response {
      const url = new URL(request.url);
      if (url.pathname === "/redirected") {
        targetHits += 1;
        return new Response("followed", { status: 200 });
      }
      originHits += 1;
      return new Response(null, {
        status: 302,
        headers: { Location: new URL("/redirected", url).href },
      });
    },
  });

  const store = new SecurityStore(":memory:");
  try {
    const dispatcher = new NotificationDispatcher({
      store,
      clock: { now: () => 1_000 },
      config: {
        channels: ["ntfy"],
        cooldownMinutes: 15,
        ntfyUrl: `http://127.0.0.1:${server.port}/basho`,
      },
      secrets: { ntfyToken: NTFY_TOKEN },
      runner: { async run() { return { status: "unavailable" }; } },
      onInApp: () => {},
    });

    dispatcher.publish(alertFixture("real-302"));
    await dispatcher.drain();

    expect(originHits).toBe(1);
    expect(targetHits).toBe(0);
    expect(store.channelHealth().ntfy?.status).toBe("failed");
    expect(JSON.stringify(dispatcher.health())).not.toContain(NTFY_TOKEN);

    await dispatcher.drain();
    expect(originHits).toBe(1);
    expect(targetHits).toBe(0);
  } finally {
    store.close();
    server.stop(true);
  }
});

test("overlapping drain calls coalesce to preserve global concurrency cap and drain mid-drain alerts", async () => {
  let active = 0;
  let maxActive = 0;
  let started = 0;
  let releaseGate!: () => void;
  const gate = new Promise<void>((resolve) => {
    releaseGate = resolve;
  });
  let midDrainPromise: Promise<void> | undefined;
  let harness!: Harness;

  harness = ntfyHarness({
    fetchResponse: async (_url, init) => {
      started += 1;
      active += 1;
      maxActive = Math.max(maxActive, active);
      const body = String(init.body);

      if (started <= 4) {
        await gate;
      } else {
        if (started === 9) {
          harness.dispatcher.publish(alertFixture("mid-drain-late"));
          midDrainPromise = harness.dispatcher.drain();
        }
        await new Promise((resolve) => setTimeout(resolve, 2));
      }

      active -= 1;
      return new Response(body, { status: 204 });
    },
  });

  let first: Promise<void> | undefined;
  let second: Promise<void> | undefined;
  let third: Promise<void> | undefined;
  try {
    for (let index = 0; index < 10; index += 1) {
      expect(harness.dispatcher.publish(alertFixture(`overlap-${index}`))).toBe(true);
    }

    first = harness.dispatcher.drain();
    second = harness.dispatcher.drain();
    third = harness.dispatcher.drain();

    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(maxActive).toBeLessThanOrEqual(4);

    releaseGate();
    await Promise.all([first, second, third]);
    if (midDrainPromise) {
      await midDrainPromise;
    }

    expect(maxActive).toBeGreaterThan(0);
    expect(maxActive).toBeLessThanOrEqual(4);
    expect(harness.requests).toHaveLength(11);
    expect(harness.requests.map((entry) => String(entry.init.body))).toContain("Alert mid-drain-late");
  } finally {
    releaseGate();
    await Promise.allSettled([first, second, third, midDrainPromise].filter(Boolean));
    harness.store.close();
  }
});

test("throwing onInApp subscriber settles permanently as failed in 1 attempt without retrying", async () => {
  const clock = fakeClock(1_000);
  const store = new SecurityStore(":memory:");
  let calls = 0;
  const dispatcher = new NotificationDispatcher({
    store,
    clock,
    config: { channels: ["in-app"], cooldownMinutes: 15 },
    secrets: {},
    runner: { async run() { return { status: "unavailable" }; } },
    fetcher: async () => new Response(null, { status: 204 }),
    onInApp: () => {
      calls += 1;
      throw new Error("subscriber failure");
    },
  });
  try {
    dispatcher.publish(alertFixture("in-app-throws"));
    await dispatcher.drain();

    expect(calls).toBe(1);
    expect(store.channelHealth()["in-app"]?.status).toBe("failed");

    clock.advance(HOUR_MS);
    await dispatcher.drain();
    expect(calls).toBe(1);
    expect(store.channelHealth()["in-app"]?.status).toBe("failed");
  } finally {
    store.close();
  }
});

test("429 honors HTTP-date Retry-After headers and caps backoff at 300 seconds", async () => {
  const start = Date.UTC(2026, 0, 1, 0, 0, 0);

  // HTTP-date Retry-After within cap (90s)
  {
    const clock = fakeClock(start);
    let calls = 0;
    const retryDate = new Date(start + 90_000).toUTCString();
    const harness = ntfyHarness({
      now: clock.now,
      fetchResponse: () => {
        calls += 1;
        if (calls === 1) {
          return new Response(null, { status: 429, headers: { "Retry-After": retryDate } });
        }
        return new Response(null, { status: 204 });
      },
    });
    try {
      harness.dispatcher.publish(alertFixture("retry-after-http-date"));
      await harness.dispatcher.drain();
      expect(calls).toBe(1);
      expect(harness.store.channelHealth().ntfy?.status).toBe("retrying");

      clock.advance(89_000);
      await harness.dispatcher.drain();
      expect(calls).toBe(1);

      clock.advance(1_000);
      await harness.dispatcher.drain();
      expect(calls).toBe(2);
      expect(harness.store.channelHealth().ntfy?.status).toBe("sent");
    } finally {
      harness.store.close();
    }
  }

  // Numeric and HTTP-date Retry-After exceeding 300s are capped at 300s
  for (const [label, headerValue] of [
    ["numeric-cap", "3600"],
    ["http-date-cap", new Date(start + HOUR_MS).toUTCString()],
  ] as const) {
    const clock = fakeClock(start);
    let calls = 0;
    const harness = ntfyHarness({
      now: clock.now,
      fetchResponse: () => {
        calls += 1;
        if (calls === 1) {
          return new Response(null, { status: 429, headers: { "Retry-After": headerValue } });
        }
        return new Response(null, { status: 204 });
      },
    });
    try {
      harness.dispatcher.publish(alertFixture(`retry-after-${label}`));
      await harness.dispatcher.drain();
      expect(calls).toBe(1);

      clock.advance(299_000);
      await harness.dispatcher.drain();
      expect(calls).toBe(1);

      clock.advance(1_000);
      await harness.dispatcher.drain();
      expect(calls).toBe(2);
      expect(harness.store.channelHealth().ntfy?.status).toBe("sent");
    } finally {
      harness.store.close();
    }
  }
});

test("local in-app and desktop deliveries complete promptly ahead of slow remote channels in the same batch", async () => {
  let releaseRemote!: () => void;
  const remoteGate = new Promise<void>((resolve) => {
    releaseRemote = resolve;
  });
  const dispatchOrder: string[] = [];

  const store = new SecurityStore(":memory:");
  const inApp: SecurityAlert[] = [];
  const desktopAlerts: string[] = [];

  const dispatcher = new NotificationDispatcher({
    store,
    clock: { now: () => 1_000 },
    config: {
      channels: ["ntfy", "discord", "desktop", "in-app"],
      cooldownMinutes: 15,
      ntfyUrl: NTFY_URL,
    },
    secrets: { discordWebhook: DISCORD_WEBHOOK },
    runner: {
      async run(request) {
        if (request.kind === "desktop") {
          dispatchOrder.push(`desktop:${request.summary}`);
          desktopAlerts.push(request.summary);
        }
        return { status: "ok", stdout: "", exitCode: 0 };
      },
    },
    fetcher: async (url) => {
      dispatchOrder.push(`remote:${url}`);
      await remoteGate;
      return new Response(null, { status: 204 });
    },
    onInApp: (alert) => {
      dispatchOrder.push(`in-app:${alert.id}`);
      inApp.push(alert);
    },
  });

  let drainPromise: Promise<void> | undefined;
  try {
    expect(dispatcher.publish(alertFixture("local-prio-1", { severity: "breach" }))).toBe(true);
    expect(dispatcher.publish(alertFixture("local-prio-2", { severity: "breach" }))).toBe(true);

    drainPromise = dispatcher.drain();

    // Yield briefly so local channels finish while remote requests remain blocked
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(inApp.map((alert) => alert.id)).toEqual(["local-prio-1", "local-prio-2"]);
    expect(desktopAlerts).toHaveLength(2);
    expect(dispatchOrder.slice(0, 2)).toEqual(["in-app:local-prio-1", "in-app:local-prio-2"]);
    expect(dispatchOrder[2]?.startsWith("desktop:")).toBe(true);
    expect(dispatchOrder[3]?.startsWith("desktop:")).toBe(true);

    releaseRemote();
    await drainPromise;

    expect(store.channelHealth()["in-app"]?.status).toBe("sent");
    expect(store.channelHealth().desktop?.status).toBe("sent");
    expect(store.channelHealth().ntfy?.status).toBe("sent");
    expect(store.channelHealth().discord?.status).toBe("sent");
  } finally {
    releaseRemote();
    await drainPromise?.catch(() => {});
    store.close();
  }
});
