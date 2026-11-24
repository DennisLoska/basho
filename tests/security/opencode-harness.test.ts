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
  prompt?: string;
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
  fetcher?: (url: string, init: RequestInit) => Promise<Response>;
  createProvider?: (options?: Record<string, unknown>) => {
    getClientManager: () => {
      getPort: () => Promise<{
        generate: {
          text: (
            input: { prompt: string; model: { providerID: string; id: string } },
            opts?: { signal?: AbortSignal },
          ) => Promise<{ text: string }>;
        };
      }>;
    };
    dispose: () => Promise<void>;
  };
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

  test("defaults to openai-compatible when ai.provider and BASHO_AI_PROVIDER are omitted and OPENCODE_API_KEY is set", () => {
    const { settings, secrets } = loadSecurityConfig({
      env: { OPENCODE_API_KEY: "test-api-key" },
      fileConfig: { ai: { model: "opencode-go/deepseek-v4.1-flash" } },
    });

    expect(aiProviderOf(settings)).toBe("openai-compatible");
    expect(secrets.aiKey).toBe("test-api-key");

    // Explicit fileConfig.ai.provider still takes precedence over OPENCODE_API_KEY.
    const explicit = loadSecurityConfig({
      env: { OPENCODE_API_KEY: "test-api-key" },
      fileConfig: { ai: { provider: "opencode-harness" } },
    });
    expect(aiProviderOf(explicit.settings)).toBe("opencode-harness");
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

  test("races getPort() against turn timeout, disposes hung provider, and recovers on Turn 2", async () => {
    let providerCreateCount = 0;
    let turn1Disposed = 0;

    const client = buildClient({
      timeoutMs: 40,
      createProvider: () => {
        providerCreateCount += 1;
        const instance = providerCreateCount;
        return {
          getClientManager: () => ({
            getPort: () => {
              if (instance === 1) {
                // Simulate a hung getPort() promise that never settles.
                return new Promise(() => {});
              }
              return Promise.resolve({
                generate: {
                  text: async () => ({
                    text: JSON.stringify({ verdict: { kind: "healthy" } }),
                  }),
                },
              });
            },
          }),
          dispose: async () => {
            if (instance === 1) {
              turn1Disposed += 1;
            }
          },
        };
      },
    });

    const firstError = await captureError(() => client.complete(turnRequest()));
    expect(firstError).toBeInstanceOf(AiProviderError);
    expect((firstError as AiProviderError).reason).toBe("timeout");
    expect(turn1Disposed).toBe(1);

    const second = await client.complete(turnRequest());
    expect(providerCreateCount).toBe(2);
    expect(second.content).toBe(JSON.stringify({ verdict: { kind: "healthy" } }));
    expect(second.calls).toEqual([]);
  });

  test("resets cached provider when port.generate.text() fails with a 401/transport error and recovers on Turn 3", async () => {
    let providerCreateCount = 0;
    let provider1Disposed = 0;
    let provider1Calls = 0;

    const client = requiresClient()({
      model: MODEL,
      createProvider: () => {
        providerCreateCount += 1;
        const instance = providerCreateCount;
        return {
          getClientManager: () => ({
            getPort: async () => ({
              generate: {
                text: async () => {
                  if (instance === 1) {
                    provider1Calls += 1;
                    if (provider1Calls === 1) {
                      return { text: JSON.stringify({ turn: 1 }) };
                    }
                    throw httpError("401 Unauthorized: stale service credentials", 401);
                  }
                  return { text: JSON.stringify({ turn: 3, recovered: true }) };
                },
              },
            }),
          }),
          dispose: async () => {
            if (instance === 1) {
              provider1Disposed += 1;
            }
          },
        };
      },
    });

    const turn1 = await client.complete(turnRequest());
    expect(turn1.content).toBe(JSON.stringify({ turn: 1 }));
    expect(providerCreateCount).toBe(1);
    expect(provider1Disposed).toBe(0);

    const turn2Err = await captureError(() => client.complete(turnRequest()));
    expect(turn2Err).toBeInstanceOf(AiProviderError);
    expect((turn2Err as AiProviderError).reason).toBe("provider_unavailable");
    expect(provider1Disposed).toBe(1);

    const turn3 = await client.complete(turnRequest());
    expect(providerCreateCount).toBe(2);
    expect(turn3.content).toBe(JSON.stringify({ turn: 3, recovered: true }));
    expect(turn3.calls).toEqual([]);
  });

  test("does not reset cached provider when port.generate.text() fails with HTTP 429 rate limit", async () => {
    let providerCreateCount = 0;
    let provider1Disposed = 0;
    let provider1Calls = 0;

    const client = requiresClient()({
      model: MODEL,
      createProvider: () => {
        providerCreateCount += 1;
        const instance = providerCreateCount;
        return {
          getClientManager: () => ({
            getPort: async () => ({
              generate: {
                text: async () => {
                  provider1Calls += 1;
                  if (provider1Calls === 2) {
                    throw httpError("429 Too Many Requests", 429, { "retry-after": "15" });
                  }
                  return { text: JSON.stringify({ instance, call: provider1Calls }) };
                },
              },
            }),
          }),
          dispose: async () => {
            if (instance === 1) {
              provider1Disposed += 1;
            }
          },
        };
      },
    });

    const turn1 = await client.complete(turnRequest());
    expect(turn1.content).toBe(JSON.stringify({ instance: 1, call: 1 }));
    expect(providerCreateCount).toBe(1);

    const turn2Err = await captureError(() => client.complete(turnRequest()));
    expect(turn2Err).toBeInstanceOf(AiProviderError);
    const providerError = turn2Err as AiProviderError;
    expect(providerError.reason).toBe("rate_limited");
    expect(providerError.retryAfter).toEqual({ kind: "seconds", seconds: 15 });
    expect(provider1Disposed).toBe(0);

    const turn3 = await client.complete(turnRequest());
    expect(providerCreateCount).toBe(1);
    expect(provider1Disposed).toBe(0);
    expect(turn3.content).toBe(JSON.stringify({ instance: 1, call: 3 }));
  });

  test("resets cached provider on turn timeout during port.generate.text() but preserves it on caller abort", async () => {
    // Part A: turn timeout (turnAbort fires while caller request.signal is NOT aborted) resets provider.
    let timeoutCreates = 0;
    let timeoutProvider1Disposed = 0;
    let timeoutProvider1Calls = 0;

    const timeoutClient = requiresClient()({
      model: MODEL,
      timeoutMs: 30,
      createProvider: () => {
        timeoutCreates += 1;
        const instance = timeoutCreates;
        return {
          getClientManager: () => ({
            getPort: async () => ({
              generate: {
                text: async (_input, opts) => {
                  if (instance === 1) {
                    timeoutProvider1Calls += 1;
                    if (timeoutProvider1Calls === 1) {
                      return { text: JSON.stringify({ ok: 1 }) };
                    }
                    return await new Promise<{ text: string }>((_resolve, reject) => {
                      opts?.signal?.addEventListener(
                        "abort",
                        () => {
                          reject(
                            Object.assign(new Error("The operation was aborted"), {
                              name: "AbortError",
                            }),
                          );
                        },
                        { once: true },
                      );
                    });
                  }
                  return { text: JSON.stringify({ ok: 3 }) };
                },
              },
            }),
          }),
          dispose: async () => {
            if (instance === 1) {
              timeoutProvider1Disposed += 1;
            }
          },
        };
      },
    });

    expect((await timeoutClient.complete(turnRequest())).content).toBe(JSON.stringify({ ok: 1 }));
    const timeoutErr = await captureError(() => timeoutClient.complete(turnRequest()));
    expect(timeoutErr).toBeInstanceOf(AiProviderError);
    expect((timeoutErr as AiProviderError).reason).toBe("timeout");
    expect(timeoutProvider1Disposed).toBe(1);

    const recovered = await timeoutClient.complete(turnRequest());
    expect(timeoutCreates).toBe(2);
    expect(recovered.content).toBe(JSON.stringify({ ok: 3 }));

    // Part B: caller abort (request.signal.aborted === true) preserves the cached healthy provider.
    let abortCreates = 0;
    let abortProvider1Disposed = 0;
    let abortProvider1Calls = 0;

    const abortClient = requiresClient()({
      model: MODEL,
      timeoutMs: 5_000,
      createProvider: () => {
        abortCreates += 1;
        const instance = abortCreates;
        return {
          getClientManager: () => ({
            getPort: async () => ({
              generate: {
                text: async (_input, opts) => {
                  abortProvider1Calls += 1;
                  if (abortProvider1Calls === 2) {
                    return await new Promise<{ text: string }>((_resolve, reject) => {
                      opts?.signal?.addEventListener(
                        "abort",
                        () => {
                          reject(
                            Object.assign(new Error("Caller aborted"), {
                              name: "AbortError",
                            }),
                          );
                        },
                        { once: true },
                      );
                    });
                  }
                  return { text: JSON.stringify({ instance, call: abortProvider1Calls }) };
                },
              },
            }),
          }),
          dispose: async () => {
            if (instance === 1) {
              abortProvider1Disposed += 1;
            }
          },
        };
      },
    });

    expect((await abortClient.complete(turnRequest())).content).toBe(
      JSON.stringify({ instance: 1, call: 1 }),
    );
    const callerController = new AbortController();
    const pendingTurn2 = captureError(() =>
      abortClient.complete(turnRequest([], callerController.signal)),
    );
    setTimeout(() => callerController.abort(), 10);
    const abortErr = await pendingTurn2;
    expect(abortErr).toBeInstanceOf(AiProviderError);
    expect((abortErr as AiProviderError).reason).toBe("timeout");
    expect(abortProvider1Disposed).toBe(0);

    const turn3 = await abortClient.complete(turnRequest());
    expect(abortCreates).toBe(1);
    expect(abortProvider1Disposed).toBe(0);
    expect(turn3.content).toBe(JSON.stringify({ instance: 1, call: 3 }));
  });

  test("does not inject OPENCODE_SERVER_PASSWORD Basic auth header in service-discovery mode", async () => {
    const capturedOptions: Record<string, unknown>[] = [];

    const client = requiresClient()({
      model: MODEL,
      serverPassword: SERVER_PASSWORD,
      createProvider: (opts) => {
        capturedOptions.push(opts ?? {});
        return {
          getClientManager: () => ({
            getPort: async () => ({
              generate: {
                text: async () => ({ text: "{}" }),
              },
            }),
          }),
          dispose: async () => {},
        };
      },
    });

    await client.complete(turnRequest());

    expect(capturedOptions).toHaveLength(1);
    const clientOptions = capturedOptions[0]?.clientOptions as
      | { headers?: Record<string, string>; fetch?: typeof fetch }
      | undefined;
    expect(clientOptions).toBeDefined();
    const headerKeys = Object.keys(clientOptions?.headers ?? {}).map((k) => k.toLowerCase());
    expect(headerKeys).not.toContain("authorization");
    expect(typeof clientOptions?.fetch).toBe("function");

    // Contrast: explicit serverUrl attaches Basic auth for OPENCODE_SERVER_PASSWORD.
    const explicitOptions: Record<string, unknown>[] = [];
    const explicitClient = requiresClient()({
      model: MODEL,
      serverUrl: "http://127.0.0.1:49374",
      serverPassword: SERVER_PASSWORD,
      createProvider: (opts) => {
        explicitOptions.push(opts ?? {});
        return {
          getClientManager: () => ({
            getPort: async () => ({
              generate: {
                text: async () => ({ text: "{}" }),
              },
            }),
          }),
          dispose: async () => {},
        };
      },
    });
    await explicitClient.complete(turnRequest());
    const explicitHeaders = (
      explicitOptions[0]?.clientOptions as { headers?: Record<string, string> } | undefined
    )?.headers;
    expect(explicitHeaders?.Authorization).toBe(basicCredentials(SERVER_PASSWORD).header);
  });

  test("enforces redirect: error and origin/userinfo safety in service-discovery mode fetcher", async () => {
    const capturedOptions: Record<string, unknown>[] = [];
    const transportCalls: { url: string; init: RequestInit }[] = [];

    const client = requiresClient()({
      model: MODEL,
      fetcher: async (url, init) => {
        transportCalls.push({ url, init });
        return new Response(null, {
          status: 302,
          headers: { location: "https://evil.example.test/steal" },
        });
      },
      createProvider: (opts) => {
        capturedOptions.push(opts ?? {});
        return {
          getClientManager: () => ({
            getPort: async () => ({
              generate: {
                text: async () => ({ text: "{}" }),
              },
            }),
          }),
          dispose: async () => {},
        };
      },
    });

    await client.complete(turnRequest());

    const clientOptions = capturedOptions[0]?.clientOptions as
      | { fetch?: typeof fetch }
      | undefined;
    expect(typeof clientOptions?.fetch).toBe("function");
    const discoveryFetch = clientOptions!.fetch!;

    // 1. 3xx redirect must be rejected and outbound init must enforce redirect: "error".
    const redirectErr = await captureError(() =>
      discoveryFetch("http://127.0.0.1:49374/api/info", { method: "GET" }),
    );
    expect(redirectErr).toBeInstanceOf(AiProviderError);
    expect(transportCalls).toHaveLength(1);
    expect(transportCalls[0]!.init.redirect).toBe("error");

    // 2. Public cleartext http origin must be rejected before calling transport.
    const publicHttpErr = await captureError(() =>
      discoveryFetch("http://public.example.test/api/info", { method: "GET" }),
    );
    expect(publicHttpErr).toBeInstanceOf(AiProviderError);
    expect(transportCalls).toHaveLength(1);

    // 3. Embedded URL userinfo must be rejected before calling transport.
    const userinfoErr = await captureError(() =>
      discoveryFetch("http://user:pass@127.0.0.1:49374/api/info", { method: "GET" }),
    );
    expect(userinfoErr).toBeInstanceOf(AiProviderError);
    expect(transportCalls).toHaveLength(1);
  });

  test("defaults turn timeout to 30_000 ms and still respects custom timeoutMs", async () => {
    const exportedTimeout = (
      aiAnalystModule as unknown as { OPENCODE_HARNESS_TIMEOUT_MS?: number }
    ).OPENCODE_HARNESS_TIMEOUT_MS;
    expect(exportedTimeout).toBe(30_000);

    const originalSetTimeout = globalThis.setTimeout;
    const recordedDelays: number[] = [];
    globalThis.setTimeout = ((
      fn: (...args: unknown[]) => void,
      delay?: number,
      ...args: unknown[]
    ) => {
      if (typeof delay === "number") {
        recordedDelays.push(delay);
      }
      return originalSetTimeout(fn, delay, ...args);
    }) as typeof setTimeout;

    try {
      const defaultClient = buildClient({
        generateText: fakeSeam(() => ({ text: "{}" })).generateText,
      });
      await defaultClient.complete(turnRequest());
      expect(recordedDelays).toContain(30_000);

      recordedDelays.length = 0;
      const customClient = buildClient({
        timeoutMs: 4_321,
        generateText: fakeSeam(() => ({ text: "{}" })).generateText,
      });
      await customClient.complete(turnRequest());
      expect(recordedDelays).toContain(4_321);
      expect(recordedDelays).not.toContain(30_000);
    } finally {
      globalThis.setTimeout = originalSetTimeout;
    }

    const fastTimeoutClient = buildClient({
      timeoutMs: 25,
      generateText: async (call) =>
        await new Promise<{ text: string }>((_resolve, reject) => {
          call.abortSignal?.addEventListener(
            "abort",
            () => {
              reject(Object.assign(new Error("Timed out"), { name: "AbortError" }));
            },
            { once: true },
          );
        }),
    });
    const timeoutErr = await captureError(() => fastTimeoutClient.complete(turnRequest()));
    expect(timeoutErr).toBeInstanceOf(AiProviderError);
    expect((timeoutErr as AiProviderError).reason).toBe("timeout");
  });

  test("includes the exact final verdict JSON schema in both tool-enabled and tool-free prompts", async () => {
    const expectedSchema =
      '{"verdict":{"kind":"healthy|warn|breach","confidence":0.0,"summary":"..."},"findings":[{"severity":"info|warning|critical|breach","summary":"...","evidenceIds":["..."]}],"proposals":[{"target":{"kind":"deny_peer_ip","ip":"..."}|{"kind":"pause_workload","workloadId":"...","pid":123,"startedAt":123}|{"kind":"isolate_lan_ingress"},"evidenceIds":["..."]}]}';
    const seam = fakeSeam(() => ({ text: JSON.stringify(FINAL_VERDICT) }));
    const broker = makeBroker();
    const client = buildClient({ generateText: seam.generateText });

    await client.complete(turnRequest(broker.getToolDefinitions()));
    await client.complete(turnRequest([]));

    expect(seam.calls).toHaveLength(2);
    const toolTurnPrompt = seam.calls[0]?.prompt ?? "";
    const finalTurnPrompt = seam.calls[1]?.prompt ?? "";
    expect(toolTurnPrompt).toContain(expectedSchema);
    expect(finalTurnPrompt).toContain(expectedSchema);
    expect(finalTurnPrompt).toContain("Do NOT output tool_calls");
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

  test("strips leading opencode-go/ prefix before calling openai-compatible chat.completions.create", async () => {
    const sentBodies: Record<string, unknown>[] = [];
    const fetcher = async (_url: string, init: RequestInit): Promise<Response> => {
      if (typeof init.body === "string") {
        sentBodies.push(JSON.parse(init.body) as Record<string, unknown>);
      }
      return new Response(
        JSON.stringify({
          id: "chatcmpl-test",
          object: "chat.completion",
          created: 1_700_000_000,
          model: "deepseek-v4.1-flash",
          choices: [
            {
              index: 0,
              finish_reason: "stop",
              message: { role: "assistant", content: "{}" },
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    };

    const { settings, secrets } = loadSecurityConfig({
      env: {
        BASHO_AI_PROVIDER: "openai-compatible",
        OPENCODE_API_KEY: "test-key",
      },
      fileConfig: {
        ai: {
          baseURL: "https://opencode.ai/zen/go/v1",
          model: "opencode-go/deepseek-v4.1-flash",
        },
      },
    });

    const client = aiAnalystModule.createAiProviderClient(settings, secrets, fetcher);
    expect(client).toBeDefined();

    await client!.complete(turnRequest());

    expect(sentBodies).toHaveLength(1);
    expect(sentBodies[0]!.model).toBe("deepseek-v4.1-flash");
  });

  test(
    "wires a 130_000 ms AiAnalyst deadline for opencode-harness while preserving default 45_000 ms for openai-compatible",
    async () => {
      expect(aiAnalystModule.OPENCODE_HARNESS_DEADLINE_MS).toBe(130_000);
      expect(aiAnalystModule.OPENCODE_HARNESS_DEADLINE_MS).toBeGreaterThanOrEqual(
        (aiAnalystModule.MAX_TOOL_ROUNDS + 1) * aiAnalystModule.OPENCODE_HARNESS_TIMEOUT_MS,
      );

      const originalSetTimeout = globalThis.setTimeout;
      const recordedDelays: number[] = [];
      globalThis.setTimeout = ((
        fn: (...args: unknown[]) => void,
        delay?: number,
        ...args: unknown[]
      ) => {
        if (typeof delay === "number") {
          recordedDelays.push(delay);
        }
        return originalSetTimeout(fn, delay, ...args);
      }) as typeof setTimeout;

      try {
        const harness = liveSettings({
          BASHO_AI_PROVIDER: "opencode-harness",
          OPENCODE_SERVER_URL: "http://127.0.0.1:1",
        });
        const harnessRuntime = createLiveSecurityRuntime({
          settings: harness.settings,
          secrets: harness.secrets,
          clock: { now: () => NOW },
          scheduler: noopScheduler,
          runner: unavailableRunner,
          files: emptyFiles,
        });
        try {
          await harnessRuntime.requestScan("manual");
        } finally {
          await harnessRuntime.stop();
        }
        expect(recordedDelays).toContain(130_000);
        expect(recordedDelays).toContain(30_000);

        recordedDelays.length = 0;
        const compat = liveSettings({
          BASHO_AI_PROVIDER: "openai-compatible",
          OPENCODE_API_KEY: "test-key",
        });
        compat.settings.ai.baseURL = "http://127.0.0.1:1";
        const compatRuntime = createLiveSecurityRuntime({
          settings: compat.settings,
          secrets: compat.secrets,
          clock: { now: () => NOW },
          scheduler: noopScheduler,
          runner: unavailableRunner,
          files: emptyFiles,
        });
        try {
          await compatRuntime.requestScan("manual");
        } finally {
          await compatRuntime.stop();
        }
        expect(recordedDelays).toContain(45_000);
        expect(recordedDelays).not.toContain(130_000);
      } finally {
        globalThis.setTimeout = originalSetTimeout;
      }
    },
    20_000,
  );
});
