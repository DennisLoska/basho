// RED STEP tests for the OpenCode local harness AI provider.
//
// Required implementation contract (this file is the spec):
//
//   src/security/ai-analyst.ts
//     export function createOpencodeHarnessClient(
//       options: OpencodeHarnessClientOptions,
//     ): AiProviderClient & { dispose(): void | Promise<void> }
//
//     interface OpencodeHarnessClientOptions {
//       model: string;                      // settings.ai.model, e.g. "opencode-go/deepseek-v4.1-flash"
//       serverUrl?: string;                 // settings.ai.serverUrl, skips discovery when set
//       serverPassword?: string;            // secrets.opencodeServerPassword
//       generateText?: (call: HarnessGenerateTextCall) => Promise<{ text: string }>;
//       getPort?: () => number | undefined | Promise<number | undefined>;
//       timeoutMs?: number;
//     }
//
//     interface HarnessGenerateTextCall {
//       model: { providerID: string; id: string };
//       messages: unknown[];                // flattened AiTurnRequest messages
//       tools?: unknown[];                  // forward request.tools, empty on tool-free turns
//       abortSignal?: AbortSignal;          // forward request.signal
//     }
//
//     The concrete client must conform to the existing AiProviderClient:
//       complete(request: AiTurnRequest): Promise<AiTurnResponse>   // { content?: string; calls: AiToolCall[] }
//     so `calls` (not `toolCalls`) is the tool-call envelope, `request.signal` is
//     the abort seam, and failures are AiProviderError with `reason` /
//     `retryAfter` (the class that already exists in this module).
//
//   src/security/config.ts
//     settings.ai.provider: "opencode-harness" | "openai-compatible"
//       default "opencode-harness"; env override BASHO_AI_PROVIDER
//     settings.ai.serverUrl?: string
//       env override OPENCODE_SERVER_URL (validated like ai.baseURL, so cleartext
//       http is only accepted for local, private, or Tailscale endpoints)
//     secrets.opencodeServerPassword?: string
//       env override OPENCODE_SERVER_PASSWORD
//     export function redactSecrets(text: string, secrets: SecuritySecrets): string
//       removes loaded secret values and Basic auth credentials from text.
//
// All tests are hermetic: the harness port is an injected fake seam, no real
// OpenCode daemon, no remote HTTP. The two live-runtime tests use a fake
// CommandRunner/PostureFiles and point serverUrl at closed loopback port 1, so
// the only socket touched is an instantly refused local connect.

import { describe, expect, test } from "bun:test";
import * as aiAnalystModule from "../../src/security/ai-analyst";
import * as configModule from "../../src/security/config";
import { AiAnalyst, AiProviderError, EvidenceBroker } from "../../src/security/ai-analyst";
import type {
  AiProviderClient,
  AiTurnRequest,
  AiTurnResponse,
} from "../../src/security/ai-analyst";
import { loadSecurityConfig } from "../../src/security/config";
import { createLiveSecurityRuntime } from "../../src/security/runtime";
import type { PostureFiles } from "../../src/security/collector";
import type {
  CommandRequest,
  CommandResult,
  CommandRunner,
  Evidence,
  SecuritySettings,
  SecuritySecrets,
} from "../../src/security/types";

// ---------------------------------------------------------------------------
// Access to the not-yet-implemented exports (kept untyped so this file is a
// clean red step: each test fails on its own assertion, not on module load).
// ---------------------------------------------------------------------------

interface HarnessGenerateTextCall {
  model: { providerID: string; id: string };
  messages: unknown[];
  tools?: unknown[];
  abortSignal?: AbortSignal;
}

interface OpencodeHarnessClientOptions {
  model: string;
  serverUrl?: string;
  serverPassword?: string;
  generateText?: (call: HarnessGenerateTextCall) => Promise<{ text: string }>;
  getPort?: () => number | undefined | Promise<number | undefined>;
  timeoutMs?: number;
}

type HarnessClient = AiProviderClient & { dispose?: () => void | Promise<void> };

type CreateOpencodeHarnessClientFn = (
  options: OpencodeHarnessClientOptions,
) => HarnessClient;

const createOpencodeHarnessClient = (
  aiAnalystModule as unknown as {
    createOpencodeHarnessClient?: CreateOpencodeHarnessClientFn;
  }
).createOpencodeHarnessClient;

type RedactSecretsFn = (text: string, secrets: SecuritySecrets) => string;

const redactSecrets = (
  configModule as unknown as { redactSecrets?: RedactSecretsFn }
).redactSecrets;

// The new fields land with the implementation; reading them through widened
// views keeps this red step about behaviour, not about type plumbing.
type AiSettingsWithHarness = SecuritySettings["ai"] & {
  provider?: "opencode-harness" | "openai-compatible";
  serverUrl?: string;
};

type SecretsWithOpencode = SecuritySecrets & {
  opencodeServerPassword?: string;
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const NOW = 1_700_000_000_000;
const SCAN_ID = "scan-opencode-harness-1";
const SERVER_PASSWORD = "sup3r-s3cret-opencode-password";
const EVIDENCE_ID = "ev-criterion-1";
const MODEL = "opencode-go/deepseek-v4.1-flash";

const TOOL_CALL_ENVELOPE = JSON.stringify({
  tool_calls: [
    {
      name: "read_posture_detail",
      arguments: { criterionId: "firewall_ufw" },
    },
  ],
});

const FENCED_TOOL_CALL_ENVELOPE = "```json\n" + TOOL_CALL_ENVELOPE + "\n```";

const FINAL_VERDICT = {
  verdict: {
    kind: "warn",
    confidence: 0.88,
    summary: "Host firewall enforcement is disabled",
  },
  findings: [
    {
      severity: "warning",
      summary: "UFW is inactive while expected to enforce ingress policy",
      evidenceIds: [EVIDENCE_ID],
    },
  ],
  proposals: [],
};

function criterionEvidence(): Evidence[] {
  return [
    {
      id: EVIDENCE_ID,
      kind: "criterion",
      facts: {
        criterionId: "firewall_ufw",
        status: "warn",
        active: false,
      },
    },
  ];
}

function makeBroker(scanId: string = SCAN_ID): EvidenceBroker {
  return new EvidenceBroker({
    scanId,
    evidence: criterionEvidence(),
    recentEvents: () => [],
  });
}

interface FakeSeam {
  generateText: (call: HarnessGenerateTextCall) => Promise<{ text: string }>;
  calls: HarnessGenerateTextCall[];
}

function fakeSeam(
  impl: (call: HarnessGenerateTextCall, index: number) => { text: string },
): FakeSeam {
  const calls: HarnessGenerateTextCall[] = [];
  return {
    calls,
    async generateText(call: HarnessGenerateTextCall) {
      calls.push(call);
      return impl(call, calls.length);
    },
  };
}

function requiresClient(): CreateOpencodeHarnessClientFn {
  expect(typeof createOpencodeHarnessClient).toBe("function");
  return createOpencodeHarnessClient as CreateOpencodeHarnessClientFn;
}

function buildClient(
  overrides: Partial<OpencodeHarnessClientOptions> & { model?: string } = {},
): HarnessClient {
  const create = requiresClient();
  return create({
    model: MODEL,
    serverUrl: "http://127.0.0.1:49374",
    ...overrides,
  });
}

function turnRequest(
  tools: AiTurnRequest["tools"] = [],
  signal: AbortSignal = new AbortController().signal,
): AiTurnRequest {
  return {
    scanId: SCAN_ID,
    messages: [{ role: "user", content: '{"scanId":"' + SCAN_ID + '"}' }],
    tools,
    signal,
  };
}

function findPropertyDeep(value: unknown, key: string, seen = new Set<unknown>()): unknown {
  if (!value || typeof value !== "object") return undefined;
  if (value instanceof AbortSignal) return undefined;
  if (seen.has(value)) return undefined;
  seen.add(value);

  const record = value as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(record, key)) {
    return record[key];
  }
  for (const child of Object.values(record)) {
    const found = findPropertyDeep(child, key, seen);
    if (found !== undefined) return found;
  }
  return undefined;
}

function findAbortSignal(value: unknown, seen = new Set<unknown>()): AbortSignal | undefined {
  if (!value || typeof value !== "object") return undefined;
  if (value instanceof AbortSignal) return value;
  if (seen.has(value)) return undefined;
  seen.add(value);
  for (const child of Object.values(value as Record<string, unknown>)) {
    const found = findAbortSignal(child, seen);
    if (found) return found;
  }
  return undefined;
}

function capturedModel(call: unknown): { providerID?: string; id?: string } {
  const candidates: unknown[] = [
    findPropertyDeep(call, "model"),
    findPropertyDeep(call, "languageModel"),
    call,
  ];
  for (const candidate of candidates) {
    if (!candidate || typeof candidate !== "object") continue;
    const record = candidate as Record<string, unknown>;
    const providerID = record.providerID ?? record.provider ?? record.providerId;
    const id = record.id ?? record.modelID ?? record.modelId;
    if (typeof providerID === "string" && typeof id === "string") {
      return { providerID, id };
    }
  }
  return {};
}

async function captureError(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (error) {
    return error;
  }
  throw new Error("expected the harness client call to reject");
}

function httpError(
  message: string,
  status: number,
  headers?: Record<string, string>,
): Error {
  return Object.assign(new Error(message), {
    status,
    ...(headers ? { headers: new Headers(headers) } : {}),
  });
}

function basicCredentials(password: string): { header: string; blob: string } {
  const blob = Buffer.from(`opencode:${password}`, "utf8").toString("base64");
  return { header: `Basic ${blob}`, blob };
}

function redacted(secrets: SecuritySecrets, text: string): string {
  expect(typeof redactSecrets).toBe("function");
  return (redactSecrets as RedactSecretsFn)(text, secrets);
}

function aiProviderOf(settings: SecuritySettings): string | undefined {
  return (settings.ai as AiSettingsWithHarness).provider;
}

function aiServerUrlOf(settings: SecuritySettings): string | undefined {
  return (settings.ai as AiSettingsWithHarness).serverUrl;
}

// ---------------------------------------------------------------------------
// 1. Config and provider selection
// ---------------------------------------------------------------------------

describe("loadSecurityConfig: opencode harness provider selection", () => {
  test("defaults to opencode-harness and does not require OPENCODE_API_KEY", () => {
    const { settings, secrets } = loadSecurityConfig({ env: {}, fileConfig: {} });

    expect(aiProviderOf(settings)).toBe("opencode-harness");
    expect(secrets.aiKey).toBeUndefined();
    expect(aiServerUrlOf(settings)).toBeUndefined();
  });

  test("defaults to opencode-harness when ai options are omitted from the file config", () => {
    const { settings } = loadSecurityConfig({
      env: {},
      fileConfig: { ai: { model: "deepseek-v4.1-flash" } },
    });

    expect(aiProviderOf(settings)).toBe("opencode-harness");
    expect(settings.ai.model).toBe("deepseek-v4.1-flash");
  });

  test("BASHO_AI_PROVIDER=openai-compatible switches the provider", () => {
    const { settings } = loadSecurityConfig({
      env: { BASHO_AI_PROVIDER: "openai-compatible" },
      fileConfig: {},
    });

    expect(aiProviderOf(settings)).toBe("openai-compatible");
  });

  test("an invalid BASHO_AI_PROVIDER value is rejected", () => {
    expect(() =>
      loadSecurityConfig({
        env: { BASHO_AI_PROVIDER: "definitely-not-a-provider" },
        fileConfig: {},
      }),
    ).toThrow(/BASHO_AI_PROVIDER|ai\.provider/i);
  });

  test("OPENCODE_SERVER_URL sets settings.ai.serverUrl", () => {
    const { settings } = loadSecurityConfig({
      env: { OPENCODE_SERVER_URL: "http://127.0.0.1:49374" },
      fileConfig: {},
    });

    const serverUrl = aiServerUrlOf(settings);
    expect(typeof serverUrl).toBe("string");
    expect(new URL(serverUrl as string).origin).toBe("http://127.0.0.1:49374");
  });

  test("OPENCODE_SERVER_URL rejects cleartext http to a public host", () => {
    expect(() =>
      loadSecurityConfig({
        env: { OPENCODE_SERVER_URL: "http://public.example.test:49374" },
        fileConfig: {},
      }),
    ).toThrow(/local, private|http is only permitted|OPENCODE_SERVER_URL|ai\.serverUrl/i);
  });

  test("OPENCODE_SERVER_PASSWORD loads into secrets and is redacted", () => {
    const { secrets } = loadSecurityConfig({
      env: {
        OPENCODE_SERVER_URL: "http://127.0.0.1:49374",
        OPENCODE_SERVER_PASSWORD: SERVER_PASSWORD,
      },
      fileConfig: {},
    });

    expect((secrets as SecretsWithOpencode).opencodeServerPassword).toBe(SERVER_PASSWORD);

    const credentials = basicCredentials(SERVER_PASSWORD);
    const output = redacted(
      secrets,
      `request failed password=${SERVER_PASSWORD} authorization=${credentials.header}`,
    );

    expect(output).not.toContain(SERVER_PASSWORD);
    expect(output).not.toContain(credentials.blob);
    expect(output).toContain("[redacted]");
  });
});

// ---------------------------------------------------------------------------
// 2. createOpencodeHarnessClient contract
// ---------------------------------------------------------------------------

describe("createOpencodeHarnessClient", () => {
  test("is exported and implements AiProviderClient with a disposer", async () => {
    const client = buildClient({
      generateText: fakeSeam(() => ({ text: "{}" })).generateText,
    });

    expect(typeof client.complete).toBe("function");
    expect(typeof client.dispose).toBe("function");

    const response: AiTurnResponse = await client.complete(turnRequest());
    expect(Array.isArray(response.calls)).toBe(true);
  });

  test("resolves a qualified model id into providerID/id and skips port discovery", async () => {
    let discoveryCalls = 0;
    const seam = fakeSeam(() => ({ text: JSON.stringify({ verdict: "none" }) }));

    const client = buildClient({
      model: "opencode-go/deepseek-v4.1-flash",
      generateText: seam.generateText,
      getPort: () => {
        discoveryCalls += 1;
        return 49374;
      },
    });

    await client.complete(turnRequest());

    expect(seam.calls).toHaveLength(1);
    expect(capturedModel(seam.calls[0])).toEqual({
      providerID: "opencode-go",
      id: "deepseek-v4.1-flash",
    });
    expect(discoveryCalls).toBe(0);
  });

  test("defaults a bare model id to the opencode-go provider", async () => {
    const seam = fakeSeam(() => ({ text: JSON.stringify({ verdict: "none" }) }));

    const client = buildClient({
      model: "deepseek-v4.1-flash",
      generateText: seam.generateText,
    });

    await client.complete(turnRequest());

    expect(seam.calls).toHaveLength(1);
    expect(capturedModel(seam.calls[0])).toEqual({
      providerID: "opencode-go",
      id: "deepseek-v4.1-flash",
    });
  });

  test("forwards the abort signal and the tool schema to the harness seam", async () => {
    const seam = fakeSeam(() => ({ text: JSON.stringify({ tool_calls: [] }) }));
    const controller = new AbortController();
    const broker = makeBroker();

    const client = buildClient({ generateText: seam.generateText });
    await client.complete({
      ...turnRequest(broker.getToolDefinitions(), controller.signal),
      messages: [{ role: "user", content: broker.buildInitialEvidencePayload(SCAN_ID) }],
    });

    expect(seam.calls).toHaveLength(1);
    const signal = findAbortSignal(seam.calls[0]);
    expect(signal).toBeInstanceOf(AbortSignal);
    expect(JSON.stringify(seam.calls[0])).toContain("read_posture_detail");
    expect(JSON.stringify(seam.calls[0])).toContain(EVIDENCE_ID);
  });

  test("parses a fenced or bare tool-call envelope into AiTurnResponse.calls", async () => {
    for (const text of [FENCED_TOOL_CALL_ENVELOPE, TOOL_CALL_ENVELOPE]) {
      const seam = fakeSeam(() => ({ text }));
      const broker = makeBroker();
      const client = buildClient({ generateText: seam.generateText });

      const response = await client.complete(turnRequest(broker.getToolDefinitions()));

      expect(response.calls).toHaveLength(1);
      const call = response.calls[0]!;
      expect(call.name).toBe("read_posture_detail");
      expect(typeof call.id).toBe("string");
      expect(JSON.parse(call.arguments)).toEqual({ criterionId: "firewall_ufw" });
      if (response.content !== undefined) {
        expect(response.content).not.toContain("tool_calls");
      }
    }
  });

  test("never emits tool calls on a tool-free final turn", async () => {
    const seam = fakeSeam(() => ({ text: FENCED_TOOL_CALL_ENVELOPE }));
    const client = buildClient({ generateText: seam.generateText });

    const response = await client.complete(turnRequest([]));

    expect(response.calls).toEqual([]);
    expect(typeof response.content).toBe("string");
    expect(response.content as string).toContain("tool_calls");
  });

  test("maps a 429 with Retry-After to a rate_limited AiProviderError", async () => {
    const client = buildClient({
      generateText: async () => {
        throw httpError("429 Too Many Requests", 429, { "retry-after": "30" });
      },
    });

    const error = await captureError(() => client.complete(turnRequest()));

    expect(error).toBeInstanceOf(AiProviderError);
    const providerError = error as AiProviderError;
    expect(providerError.reason).toBe("rate_limited");
    expect(providerError.retryAfter).toEqual({ kind: "seconds", seconds: 30 });
  });

  test("maps timeout and AbortError failures to a timeout AiProviderError", async () => {
    const timeoutClient = buildClient({
      generateText: async () => {
        throw Object.assign(new Error("The operation timed out"), {
          name: "TimeoutError",
        });
      },
    });
    const timeoutError = await captureError(() => timeoutClient.complete(turnRequest()));
    expect(timeoutError).toBeInstanceOf(AiProviderError);
    expect((timeoutError as AiProviderError).reason).toBe("timeout");

    const abortClient = buildClient({
      generateText: async () => {
        throw Object.assign(new Error("The operation was aborted"), {
          name: "AbortError",
        });
      },
    });
    const abortError = await captureError(() => abortClient.complete(turnRequest()));
    expect(abortError).toBeInstanceOf(AiProviderError);
    expect((abortError as AiProviderError).reason).toBe("timeout");
  });

  test("maps an already aborted request signal to a timeout AiProviderError", async () => {
    let seamCalls = 0;
    const client = buildClient({
      generateText: async () => {
        seamCalls += 1;
        return { text: "{}" };
      },
    });
    const controller = new AbortController();
    controller.abort();

    const error = await captureError(() =>
      client.complete(turnRequest([], controller.signal)),
    );

    expect(error).toBeInstanceOf(AiProviderError);
    expect((error as AiProviderError).reason).toBe("timeout");
    expect(seamCalls).toBe(0);
  });

  test("maps auth and connection failures without leaking the server password", async () => {
    const credentials = basicCredentials(SERVER_PASSWORD);
    const client = buildClient({
      serverPassword: SERVER_PASSWORD,
      generateText: async () => {
        throw httpError(
          `401 Unauthorized: password=${SERVER_PASSWORD} authorization=${credentials.header}`,
          401,
        );
      },
    });

    const error = await captureError(() => client.complete(turnRequest()));

    expect(error).toBeInstanceOf(AiProviderError);
    const providerError = error as AiProviderError;
    expect(providerError.reason).toBe("provider_unavailable");

    const serialized = [
      providerError.message,
      String((providerError as Error).stack),
      JSON.stringify(providerError),
    ].join("\n");
    expect(serialized).not.toContain(SERVER_PASSWORD);
    expect(serialized).not.toContain(credentials.blob);
    expect(serialized).not.toMatch(/Basic\s+[A-Za-z0-9+/=]+/);
  });

  test("dispose() is graceful and idempotent", async () => {
    const client = buildClient({
      generateText: fakeSeam(() => ({ text: "{}" })).generateText,
    });

    expect(typeof client.dispose).toBe("function");
    await Promise.resolve(client.dispose?.());
    await Promise.resolve(client.dispose?.());
  });
});

// ---------------------------------------------------------------------------
// 3. AiAnalyst + EvidenceBroker end-to-end through the harness client
// ---------------------------------------------------------------------------

describe("AiAnalyst investigation through the opencode harness client", () => {
  test("executes a read-only tool call and validates the final verdict citing issued evidence", async () => {
    const seam = fakeSeam((_call, index) =>
      index === 1 ? { text: FENCED_TOOL_CALL_ENVELOPE } : { text: JSON.stringify(FINAL_VERDICT) },
    );
    const client = buildClient({ generateText: seam.generateText });
    const analyst = new AiAnalyst({ client, clock: { now: () => NOW } });
    const broker = makeBroker();

    const result = await analyst.investigate(SCAN_ID, broker);

    expect(seam.calls.length).toBeGreaterThanOrEqual(2);

    expect(result.status).toBe("ready");
    expect(result.verdict).toEqual({
      kind: "warn",
      confidence: 0.88,
      summary: "Host firewall enforcement is disabled",
    });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.evidenceIds).toEqual([EVIDENCE_ID]);
    expect(result.findings[0]!.source).toBe("ai");

    const toolSteps = result.trail.steps.filter(
      (step) => step.tool === "read_posture_detail",
    );
    expect(toolSteps).toHaveLength(1);
    expect(toolSteps[0]!.outcome).toBe("ok");
    expect(toolSteps[0]!.evidenceIds).toEqual([EVIDENCE_ID]);

    const verdictSteps = result.trail.steps.filter((step) => step.tool === "verdict");
    expect(verdictSteps.at(-1)!.outcome).toBe("ok");
    expect(verdictSteps.at(-1)!.evidenceIds).toEqual([EVIDENCE_ID]);

    // The final turn is tool-free, so no tool schema is forwarded to the harness.
    const finalTools = findPropertyDeep(seam.calls.at(-1), "tools");
    expect(
      finalTools === undefined ||
        (Array.isArray(finalTools) && finalTools.length === 0),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 4. Live runtime composition
// ---------------------------------------------------------------------------

const noopScheduler = { every: () => () => {} };

const unavailableRunner: CommandRunner = {
  async run(_request: CommandRequest): Promise<CommandResult> {
    return { status: "unavailable" };
  },
};

const emptyFiles: PostureFiles = {
  async read() {
    return null;
  },
  async sshDropIns() {
    return [];
  },
};

function liveSettings(env: Record<string, string | undefined>) {
  const loaded = loadSecurityConfig({ env, fileConfig: {} });
  loaded.settings.process.securityDbPath = ":memory:";
  return loaded;
}

describe("createLiveSecurityRuntime AI provider composition", () => {
  test(
    "composes a real harness client by default without OPENCODE_API_KEY",
    async () => {
      const { settings, secrets } = liveSettings({
        BASHO_AI_PROVIDER: "opencode-harness",
        OPENCODE_SERVER_URL: "http://127.0.0.1:1",
      });

      expect(aiProviderOf(settings)).toBe("opencode-harness");
      expect(secrets.aiKey).toBeUndefined();

      const runtime = createLiveSecurityRuntime({
        settings,
        secrets,
        clock: { now: () => NOW },
        scheduler: noopScheduler,
        runner: unavailableRunner,
        files: emptyFiles,
      } as Parameters<typeof createLiveSecurityRuntime>[0]);

      try {
        const scan = await runtime.requestScan("manual");
        // "unconfigured" means the analyst was built with no client at all.
        expect(scan.aiStatus).not.toBe("unconfigured");
      } finally {
        await runtime.stop();
      }
    },
    20_000,
  );

  test("keeps the openai-compatible provider unconfigured without OPENCODE_API_KEY", async () => {
    const { settings, secrets } = liveSettings({
      BASHO_AI_PROVIDER: "openai-compatible",
    });

    expect(aiProviderOf(settings)).toBe("openai-compatible");
    expect(secrets.aiKey).toBeUndefined();

    const runtime = createLiveSecurityRuntime({
      settings,
      secrets,
      clock: { now: () => NOW },
      scheduler: noopScheduler,
      runner: unavailableRunner,
      files: emptyFiles,
    } as Parameters<typeof createLiveSecurityRuntime>[0]);

    try {
      const scan = await runtime.requestScan("manual");
      expect(scan.aiStatus).toBe("unconfigured");
    } finally {
      await runtime.stop();
    }
  });

  test("createAiProviderClient selects the harness client without an API key", () => {
    const harness = liveSettings({
      BASHO_AI_PROVIDER: "opencode-harness",
      OPENCODE_SERVER_URL: "http://127.0.0.1:1",
    });
    const harnessClient = aiAnalystModule.createAiProviderClient(
      harness.settings,
      harness.secrets,
    );
    expect(harnessClient).toBeDefined();
    expect(typeof harnessClient?.complete).toBe("function");

    const compatible = liveSettings({ BASHO_AI_PROVIDER: "openai-compatible" });
    expect(
      aiAnalystModule.createAiProviderClient(compatible.settings, compatible.secrets),
    ).toBeUndefined();
  });
});
