import type { AlertDelivery, SecurityStoreContract } from "./store";
import type {
  AlertChannel,
  Clock,
  CommandRunner,
  HttpFetcher,
  SecurityAlert,
  SecuritySecrets,
  SecuritySettings,
  Severity,
} from "./types";

const REQUEST_TIMEOUT_MS = 8_000;
const CLAIM_BATCH_SIZE = 8;
const CLAIM_LEASE_MS = 30_000;
const MAX_CONCURRENCY = 4;
const MAX_ATTEMPTS = 5;
const BASE_BACKOFF_MS = 5_000;
const MAX_BACKOFF_MS = 300_000;
const MAX_RETRY_AFTER_MS = 300_000;

const DISCORD_ALLOWED_HOSTS = new Set(["discord.com", "discordapp.com"]);
const DISCORD_WEBHOOK_PATH = /^\/api\/webhooks\/\d+\/[A-Za-z0-9._-]+$/;
const TELEGRAM_BOT_TOKEN_PATTERN = /^\d+:[A-Za-z0-9_-]+$/;

const DISCORD_SEVERITY_COLOR: Record<Severity, number> = {
  breach: 0xdc2626,
  critical: 0xea580c,
  warning: 0xd97706,
  info: 0x2563eb,
};

const CHANNEL_PRIORITY: Record<AlertChannel, number> = {
  "in-app": 0,
  desktop: 1,
  ntfy: 2,
  discord: 2,
  telegram: 2,
};

function prioritizeDeliveries(batch: readonly AlertDelivery[]): AlertDelivery[] {
  return [...batch].sort(
    (a, b) => (CHANNEL_PRIORITY[a.channel] ?? 3) - (CHANNEL_PRIORITY[b.channel] ?? 3),
  );
}

export type NotificationStore = Pick<
  SecurityStoreContract,
  "enqueueAlert" | "claimDeliveries" | "settleDelivery" | "channelHealth"
>;

export interface ChannelHealthEntry {
  status: "sent" | "failed" | "retrying";
  at: number;
}

export interface NotificationDispatcherOptions {
  store: NotificationStore;
  clock: Clock;
  config: SecuritySettings["notifications"];
  secrets: SecuritySecrets;
  runner: CommandRunner;
  fetcher?: HttpFetcher;
  onInApp?: (alert: SecurityAlert) => void;
}

type DeliveryOutcome =
  | { kind: "sent" }
  | { kind: "permanent_failure" }
  | { kind: "transient_failure"; retryAfterMs?: number };

function validateNtfyUrl(raw: string | undefined): string | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (trimmed === "" || trimmed.includes("#")) return null;
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
  if (parsed.username !== "" || parsed.password !== "") return null;
  if (parsed.hash !== "" || !parsed.hostname) return null;
  if (parsed.pathname === "" || parsed.pathname === "/") return null;
  return parsed.href;
}

function validateDiscordWebhook(raw: string | undefined): string | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (
    trimmed === "" ||
    trimmed.includes("?") ||
    trimmed.includes("#") ||
    trimmed.includes("\\")
  ) {
    return null;
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return null;
  }
  if (parsed.protocol !== "https:") return null;
  if (parsed.username !== "" || parsed.password !== "") return null;
  if (parsed.port !== "") return null;
  if (!DISCORD_ALLOWED_HOSTS.has(parsed.hostname.toLowerCase())) return null;
  if (parsed.search !== "" || parsed.hash !== "") return null;
  if (!DISCORD_WEBHOOK_PATH.test(parsed.pathname)) return null;
  return parsed.href;
}

function validateTelegramCredentials(
  botTokenRaw: string | undefined,
  chatIdRaw: string | undefined,
): { botToken: string; chatId: string } | null {
  if (typeof botTokenRaw !== "string" || typeof chatIdRaw !== "string") return null;
  const botToken = botTokenRaw.trim();
  const chatId = chatIdRaw.trim();
  if (botToken === "" || chatId === "") return null;
  if (!TELEGRAM_BOT_TOKEN_PATTERN.test(botToken)) return null;
  if (/[\0\r\n]/.test(chatId)) return null;
  return { botToken, chatId };
}

function buildDeepLink(
  publicOrigin: string | undefined,
  proposalId: string | undefined,
): string | undefined {
  if (typeof publicOrigin !== "string") return undefined;
  const trimmed = publicOrigin.trim();
  if (trimmed === "" || trimmed.includes("#") || trimmed.includes("?")) return undefined;
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return undefined;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return undefined;
  if (parsed.username !== "" || parsed.password !== "") return undefined;
  if (parsed.search !== "" || parsed.hash !== "") return undefined;

  const link = new URL("/security", parsed.origin);
  if (typeof proposalId === "string" && proposalId.trim() !== "") {
    link.hash = `proposal-${encodeURIComponent(proposalId.trim())}`;
  }
  return link.href;
}

function parseRetryAfterMs(headerValue: string | null, now: number): number | undefined {
  if (!headerValue) return undefined;
  const trimmed = headerValue.trim();
  if (/^\d+$/.test(trimmed)) {
    const seconds = Number(trimmed);
    if (Number.isFinite(seconds) && seconds > 0) {
      return Math.min(seconds * 1_000, MAX_RETRY_AFTER_MS);
    }
    return undefined;
  }
  const timestamp = Date.parse(trimmed);
  if (Number.isFinite(timestamp)) {
    const delta = timestamp - now;
    if (delta > 0) {
      return Math.min(delta, MAX_RETRY_AFTER_MS);
    }
  }
  return undefined;
}

function computeBackoffMs(attempts: number, retryAfterMs?: number): number {
  const exponent = Math.max(0, attempts - 1);
  const exponential = Math.min(BASE_BACKOFF_MS * 2 ** exponent, MAX_BACKOFF_MS);
  if (retryAfterMs !== undefined && retryAfterMs > exponential) {
    return Math.min(retryAfterMs, MAX_RETRY_AFTER_MS);
  }
  return exponential;
}

function isRedirectError(error: unknown): boolean {
  let current: unknown = error;
  const seen = new Set<unknown>();
  while (current !== null && current !== undefined && !seen.has(current)) {
    if (typeof current === "string") {
      return /redirect/i.test(current);
    }
    if (typeof current !== "object") {
      return false;
    }
    seen.add(current);
    if ("code" in current && current.code === "UnexpectedRedirect") {
      return true;
    }
    if (
      "message" in current &&
      typeof current.message === "string" &&
      /redirect/i.test(current.message)
    ) {
      return true;
    }
    current = "cause" in current ? current.cause : undefined;
  }
  return false;
}

function sanitizeDesktopText(text: string): string {
  return text.replace(/\0/g, "");
}

function classifyHttpResponse(response: Response, now: number): DeliveryOutcome {
  void response.body?.cancel().catch(() => {});

  if (response.status >= 200 && response.status < 300) {
    return { kind: "sent" };
  }
  if (response.status >= 300 && response.status < 400) {
    return { kind: "permanent_failure" };
  }
  if (response.status === 429 || response.status === 408) {
    return {
      kind: "transient_failure",
      retryAfterMs: parseRetryAfterMs(response.headers.get("Retry-After"), now),
    };
  }
  if (response.status >= 400 && response.status < 500) {
    return { kind: "permanent_failure" };
  }
  if (response.status >= 500) {
    return {
      kind: "transient_failure",
      retryAfterMs: parseRetryAfterMs(response.headers.get("Retry-After"), now),
    };
  }
  return { kind: "permanent_failure" };
}

async function runWithConcurrency<T>(
  items: readonly T[],
  limit: number,
  worker: (item: T) => Promise<void>,
): Promise<void> {
  if (items.length === 0) return;
  const workerCount = Math.min(Math.max(1, limit), items.length);
  let nextIndex = 0;

  const workers = Array.from({ length: workerCount }, async () => {
    for (;;) {
      const index = nextIndex;
      if (index >= items.length) return;
      nextIndex += 1;
      await worker(items[index]!);
    }
  });

  await Promise.all(workers);
}

export class NotificationDispatcher {
  private readonly store: NotificationStore;
  private readonly clock: Clock;
  private readonly config: SecuritySettings["notifications"];
  private readonly secrets: SecuritySecrets;
  private readonly runner: CommandRunner;
  private readonly fetcher: HttpFetcher;
  private readonly onInApp: (alert: SecurityAlert) => void;
  private activeDrain: Promise<void> | null = null;
  private drainRequested = false;

  constructor(options: NotificationDispatcherOptions) {
    this.store = options.store;
    this.clock = options.clock;
    this.config = options.config;
    this.secrets = options.secrets;
    this.runner = options.runner;
    this.fetcher = options.fetcher ?? ((url, init) => fetch(url, init));
    this.onInApp = options.onInApp ?? (() => {});
  }

  publish(alert: SecurityAlert): boolean {
    const cooldownMs = Math.max(0, this.config.cooldownMinutes) * 60_000;
    return this.store.enqueueAlert(alert, this.config.channels, cooldownMs);
  }

  sendTestAlert(channel?: AlertChannel): string {
    let targetChannels: AlertChannel[];
    if (channel !== undefined) {
      this.assertChannelReady(channel);
      targetChannels = [channel];
    } else {
      targetChannels = this.config.channels.filter((candidate) =>
        this.isChannelReady(candidate),
      );
      if (targetChannels.length === 0) {
        throw new Error("No notification channel is ready for test delivery");
      }
    }

    const id = `test-${crypto.randomUUID()}`;
    const alert: SecurityAlert = {
      id,
      fingerprint: `test:${channel ?? "all"}:${id}`,
      severity: "info",
      summary: "Basho Security test alert",
      createdAt: this.clock.now(),
    };

    const enqueued = this.store.enqueueAlert(alert, targetChannels, 0);
    if (!enqueued) {
      throw new Error("Failed to enqueue test alert");
    }
    return id;
  }

  async drain(): Promise<void> {
    if (this.activeDrain) {
      this.drainRequested = true;
      return this.activeDrain;
    }

    let completed = false;
    const run = this.runDrainLoop(() => {
      completed = true;
      this.activeDrain = null;
    });
    if (!completed) {
      this.activeDrain = run;
    }
    return run;
  }

  private async runDrainLoop(onComplete: () => void): Promise<void> {
    const seenInDrain = new Set<string>();
    try {
      for (;;) {
        this.drainRequested = false;
        const batch = this.store.claimDeliveries(
          this.clock.now(),
          CLAIM_BATCH_SIZE,
          CLAIM_LEASE_MS,
        );
        if (batch.length === 0) {
          if (this.drainRequested) {
            continue;
          }
          return;
        }

        let anyNew = false;
        for (const delivery of batch) {
          if (!seenInDrain.has(delivery.id)) {
            seenInDrain.add(delivery.id);
            anyNew = true;
          }
        }

        const prioritized = prioritizeDeliveries(batch);
        await runWithConcurrency(prioritized, MAX_CONCURRENCY, async (delivery) => {
          await this.deliverOne(delivery);
        });

        if (!anyNew && !this.drainRequested) {
          return;
        }
      }
    } finally {
      onComplete();
    }
  }

  health(): Partial<Record<AlertChannel, ChannelHealthEntry>> {
    return this.store.channelHealth();
  }

  private isChannelReady(channel: AlertChannel): boolean {
    switch (channel) {
      case "in-app":
      case "desktop":
        return true;
      case "ntfy":
        return validateNtfyUrl(this.config.ntfyUrl) !== null;
      case "discord":
        return validateDiscordWebhook(this.secrets.discordWebhook) !== null;
      case "telegram":
        return (
          validateTelegramCredentials(
            this.secrets.telegramBotToken,
            this.secrets.telegramChatId,
          ) !== null
        );
      default:
        return false;
    }
  }

  private assertChannelReady(channel: AlertChannel): void {
    switch (channel) {
      case "in-app":
      case "desktop":
        return;
      case "ntfy":
        if (validateNtfyUrl(this.config.ntfyUrl) === null) {
          throw new Error("Notification channel ntfy is not ready: ntfyUrl is missing or invalid");
        }
        return;
      case "discord":
        if (validateDiscordWebhook(this.secrets.discordWebhook) === null) {
          throw new Error(
            "Notification channel discord is not ready: webhook URL is missing or invalid",
          );
        }
        return;
      case "telegram":
        if (
          validateTelegramCredentials(
            this.secrets.telegramBotToken,
            this.secrets.telegramChatId,
          ) === null
        ) {
          throw new Error(
            "Notification channel telegram is not ready: bot token or chat id is missing or invalid",
          );
        }
        return;
      default:
        throw new Error("Unsupported notification channel");
    }
  }

  private async deliverOne(delivery: AlertDelivery): Promise<void> {
    let outcome: DeliveryOutcome;
    try {
      outcome = await this.dispatchDelivery(delivery);
    } catch (error) {
      outcome = isRedirectError(error)
        ? { kind: "permanent_failure" }
        : { kind: "transient_failure" };
    }

    const settledAt = this.clock.now();
    if (outcome.kind === "sent") {
      this.store.settleDelivery(delivery.id, delivery.claimToken, settledAt, "sent");
      return;
    }

    if (outcome.kind === "permanent_failure" || delivery.attempts >= MAX_ATTEMPTS) {
      this.store.settleDelivery(delivery.id, delivery.claimToken, settledAt, "failed");
      return;
    }

    const delayMs = Math.max(1, computeBackoffMs(delivery.attempts, outcome.retryAfterMs));
    this.store.settleDelivery(delivery.id, delivery.claimToken, settledAt, {
      retryAt: settledAt + delayMs,
    });
  }

  private async dispatchDelivery(delivery: AlertDelivery): Promise<DeliveryOutcome> {
    switch (delivery.channel) {
      case "in-app":
        return this.deliverInApp(delivery.alert);
      case "ntfy":
        return this.deliverNtfy(delivery.alert);
      case "desktop":
        return this.deliverDesktop(delivery.alert);
      case "discord":
        return this.deliverDiscord(delivery.alert);
      case "telegram":
        return this.deliverTelegram(delivery.alert);
      default:
        return { kind: "permanent_failure" };
    }
  }

  private async deliverInApp(alert: SecurityAlert): Promise<DeliveryOutcome> {
    try {
      await this.onInApp(alert);
      return { kind: "sent" };
    } catch {
      return { kind: "permanent_failure" };
    }
  }

  private async deliverNtfy(alert: SecurityAlert): Promise<DeliveryOutcome> {
    const url = validateNtfyUrl(this.config.ntfyUrl);
    if (!url) {
      return { kind: "permanent_failure" };
    }

    const headers = new Headers({
      Title: "Basho Security",
      Priority:
        alert.severity === "breach"
          ? "urgent"
          : alert.severity === "critical"
            ? "high"
            : "default",
      Tags: alert.severity === "breach" ? "rotating_light" : "shield",
    });

    const deepLink = buildDeepLink(this.config.publicOrigin, alert.proposalId);
    if (deepLink) {
      headers.set("Click", deepLink);
    }

    const token = this.secrets.ntfyToken?.trim();
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }

    const response = await this.fetcher(url, {
      method: "POST",
      headers,
      body: alert.summary,
      redirect: "error",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    return classifyHttpResponse(response, this.clock.now());
  }

  private async deliverDesktop(alert: SecurityAlert): Promise<DeliveryOutcome> {
    const urgency: "normal" | "critical" =
      alert.severity === "breach" || alert.severity === "critical" ? "critical" : "normal";
    const cleanSummary = sanitizeDesktopText(alert.summary);
    const deepLink = buildDeepLink(this.config.publicOrigin, alert.proposalId);
    const summary = `Basho Security [${alert.severity.toUpperCase()}]: ${cleanSummary}`;
    const body = deepLink ? `${cleanSummary}\n${deepLink}` : cleanSummary;

    const result = await this.runner.run(
      {
        kind: "desktop",
        urgency,
        summary,
        body,
      },
      AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    );

    if (result.status === "ok" && result.exitCode === 0) {
      return { kind: "sent" };
    }
    if (result.status === "unavailable") {
      return { kind: "permanent_failure" };
    }
    return { kind: "transient_failure" };
  }

  private async deliverDiscord(alert: SecurityAlert): Promise<DeliveryOutcome> {
    const webhookUrl = validateDiscordWebhook(this.secrets.discordWebhook);
    if (!webhookUrl) {
      return { kind: "permanent_failure" };
    }

    const deepLink = buildDeepLink(this.config.publicOrigin, alert.proposalId);
    const embed: Record<string, unknown> = {
      title: `Basho Security (${alert.severity.toUpperCase()})`,
      description: alert.summary,
      color: DISCORD_SEVERITY_COLOR[alert.severity],
      fields: [{ name: "Severity", value: alert.severity, inline: true }],
    };
    if (deepLink) {
      embed.url = deepLink;
    }

    const response = await this.fetcher(webhookUrl, {
      method: "POST",
      headers: new Headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        allowed_mentions: { parse: [] },
        embeds: [embed],
      }),
      redirect: "error",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    return classifyHttpResponse(response, this.clock.now());
  }

  private async deliverTelegram(alert: SecurityAlert): Promise<DeliveryOutcome> {
    const credentials = validateTelegramCredentials(
      this.secrets.telegramBotToken,
      this.secrets.telegramChatId,
    );
    if (!credentials) {
      return { kind: "permanent_failure" };
    }

    const deepLink = buildDeepLink(this.config.publicOrigin, alert.proposalId);
    const lines = [`Basho Security [${alert.severity.toUpperCase()}]`, alert.summary];
    if (deepLink) {
      lines.push(deepLink);
    }

    const endpoint = `https://api.telegram.org/bot${credentials.botToken}/sendMessage`;
    const response = await this.fetcher(endpoint, {
      method: "POST",
      headers: new Headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        chat_id: credentials.chatId,
        text: lines.join("\n"),
        link_preview_options: { is_disabled: true },
      }),
      redirect: "error",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    return classifyHttpResponse(response, this.clock.now());
  }
}
