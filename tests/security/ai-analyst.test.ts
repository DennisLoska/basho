import { describe, expect, test } from "bun:test";
import {
  AiAnalyst,
  EvidenceBroker,
  createAiProviderClient,
} from "../../src/security/ai-analyst";
import type {
  AiProviderClient,
  AiTurnRequest,
  InvestigationResult,
} from "../../src/security/ai-analyst";
import { criterionIds, evidenceTools } from "../../src/security/types";
import type {
  Category,
  Clock,
  CriterionId,
  Evidence,
  Facts,
  HttpFetcher,
  SecurityEvent,
  SecuritySettings,
} from "../../src/security/types";

const NOW = 1_796_000_000_000;
const SECOND = 1_000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const PEER = "198.51.100.42";
const API_KEY = "fixture-key-do-not-leak";

interface ToolCallResult {
  id: string;
  name: string;
  arguments: string;
}

interface TurnResult {
  content?: string;
  calls: ToolCallResult[];
}

interface CapturedRequest {
  url: string;
  init: RequestInit;
  headers: Headers;
  body: Record<string, unknown>;
}

function makeSettings(ai: Partial<SecuritySettings["ai"]> = {}): SecuritySettings {
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
      baseURL: "https://opencode.example.test/zen/go/v1",
      model: "deepseek-v4.1-flash",
      sessionHeader: true,
      confidenceThreshold: 0.85,
      triageCooldownMinutes: 10,
      ...ai,
    },
    notifications: { channels: ["in-app"], cooldownMinutes: 15 },
    lockdown: { proposalMinutes: 30, leaseSeconds: 600, helperEnabled: false },
    process: { host: "127.0.0.1", port: 6969, securityDbPath: ":memory:", demo: false },
  };
}

function clockAt(now: number): Clock {
  return { now: () => now };
}

function jsonResponse(payload: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers as any);
  if (!headers.has("content-type")) headers.set("content-type", "application/json");
  return new Response(JSON.stringify(payload), { ...init, status: init.status ?? 200, headers });
}

function recordingFetch(
  handler: (request: CapturedRequest) => Response | Promise<Response>,
): { fetcher: HttpFetcher; requests: CapturedRequest[] } {
  const requests: CapturedRequest[] = [];
  const fetcher: HttpFetcher = async (url, init) => {
    let body: Record<string, unknown> = {};
    if (typeof init.body === "string") {
      try {
        body = JSON.parse(init.body) as Record<string, unknown>;
      } catch {
        body = {};
      }
    }
    const captured: CapturedRequest = {
      url: String(url),
      init,
      headers: new Headers(init.headers as any),
      body,
    };
    requests.push(captured);
    return handler(captured);
  };
  return { fetcher, requests };
}

function completionBody(content: string | null, calls: ToolCallResult[] = []): unknown {
  return {
    id: "chatcmpl-fixture",
    object: "chat.completion",
    created: 0,
    model: "deepseek-v4.1-flash",
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          content,
          ...(calls.length > 0
            ? {
                tool_calls: calls.map((entry) => ({
                  id: entry.id,
                  type: "function",
                  function: { name: entry.name, arguments: entry.arguments },
                })),
              }
            : {}),
        },
        finish_reason: calls.length > 0 ? "tool_calls" : "stop",
      },
    ],
    usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
  };
}

function turnRequest(scanId = "scan-1", tools: AiTurnRequest["tools"] = []): AiTurnRequest {
  return {
    scanId,
    messages: [{ role: "user", content: `Investigate ${scanId}` }],
    tools,
    signal: new AbortController().signal,
  };
}

function call(
  id: string,
  name: string,
  args: string | Record<string, unknown>,
): ToolCallResult {
  return {
    id,
    name,
    arguments: typeof args === "string" ? args : JSON.stringify(args),
  };
}

function healthyFinal(): Record<string, unknown> {
  return {
    verdict: { kind: "healthy", confidence: 0.9, summary: "No material changes since the last scan" },
    findings: [],
    proposals: [],
  };
}

function finalTurn(content: unknown = healthyFinal()): TurnResult {
  return { calls: [], content: typeof content === "string" ? content : JSON.stringify(content) };
}

function scriptedClient(
  turns: ((request: AiTurnRequest, index: number) => Promise<TurnResult> | TurnResult)[],
  requests: AiTurnRequest[] = [],
): AiProviderClient {
  let index = 0;
  return {
    async complete(request: AiTurnRequest): Promise<TurnResult> {
      requests.push(request);
      const current = Math.min(index, turns.length - 1);
      index += 1;
      return await turns[current]!(request, current);
    },
  };
}

function makeBroker(
  options: {
    scanId?: string;
    evidence?: Evidence[];
    recentEvents?: (category: Category, windowMinutes: number, limit: number) => SecurityEvent[];
    unitStatus?: (name: string, scope: "system" | "user") => Promise<Facts | null>;
  } = {},
): EvidenceBroker {
  return new EvidenceBroker({
    ...(options.scanId !== undefined ? { scanId: options.scanId } : {}),
    evidence: options.evidence ?? [],
    recentEvents: options.recentEvents ?? (() => []),
    ...(options.unitStatus ? { unitStatus: options.unitStatus } : {}),
  });
}

function postureEvidence(): Evidence[] {
  return [
    {
      id: "ev-1",
      kind: "criterion",
      facts: { criterionId: "ssh_hardening", status: "warn", detail: "PasswordAuthentication yes" },
    },
  ];
}

function eventFixture(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    id: "event-1",
    source: "journal",
    category: "auth",
    severity: "critical",
    rule: "ssh_burst",
    target: PEER,
    firstAt: NOW - 5 * MINUTE,
    lastAt: NOW - MINUTE,
    count: 12,
    isNoise: false,
    summary: "Repeated SSH authentication failures",
    ...overrides,
  };
}

function toolMessages(request: AiTurnRequest): { id: string; content: string }[] {
  return request.messages
    .filter((message) => message.role === "tool")
    .map((message) => ({
      id: String((message as { tool_call_id?: string }).tool_call_id ?? ""),
      content: String(message.content ?? ""),
    }));
}

function toolResult(request: AiTurnRequest, callId: string, fallbackIndex: number): string {
  const messages = toolMessages(request);
  const byId = messages.find((message) => message.id === callId);
  if (byId) return byId.content;
  const byIndex = messages[fallbackIndex];
  if (byIndex) return byIndex.content;
  throw new Error(
    `missing tool result for ${callId}; tool message ids: ${messages.map((m) => m.id).join(",")}`,
  );
}

function toolSchema(tool: unknown): { name: string; parameters: Record<string, any> } {
  const fn = (tool as { function?: { name?: string; parameters?: Record<string, any> } }).function;
  return { name: String(fn?.name), parameters: fn?.parameters ?? {} };
}

function rejectedSteps(result: InvestigationResult) {
  return result.trail.steps.filter((step) => step.outcome === "rejected");
}

function describeError(error: unknown): string {
  const err = error as Error & { status?: number; headers?: unknown };
  return [
    String(err?.name),
    String(err?.message),
    String(err?.stack),
    JSON.stringify({ status: err?.status, headers: err?.headers }),
  ].join("\n");
}

async function captureError(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (error) {
    return error;
  }
  throw new Error("expected the provider call to reject");
}

function toolsOnRequest(requests: AiTurnRequest[]): AiTurnRequest[] {
  return requests.filter((request) => request.tools.length > 0);
}

describe("createAiProviderClient", () => {
  test("returns undefined when the AI key is missing or empty", () => {
    const { fetcher } = recordingFetch(() => jsonResponse(completionBody("{}")));
    expect(createAiProviderClient(makeSettings(), {}, fetcher)).toBeUndefined();
    expect(createAiProviderClient(makeSettings(), { aiKey: "" }, fetcher)).toBeUndefined();
  });

  test("sends baseURL, bearer auth, user agent, session header, model, token cap and JSON response format", async () => {
    const { fetcher, requests } = recordingFetch(() =>
      jsonResponse(completionBody("{\"verdict\":null}")),
    );
    const client = createAiProviderClient(makeSettings(), { aiKey: API_KEY }, fetcher);
    expect(client).toBeDefined();

    const result = await client!.complete(turnRequest("scan-42"));

    expect(result.content).toBe("{\"verdict\":null}");
    expect(result.calls).toEqual([]);
    expect(requests).toHaveLength(1);

    const sent = requests[0]!;
    expect(sent.url.startsWith("https://opencode.example.test/zen/go/v1")).toBe(true);
    expect(sent.url).toContain("/chat/completions");
    expect(sent.headers.get("authorization")).toBe(`Bearer ${API_KEY}`);
    expect(sent.headers.get("user-agent")).toBe("basho-security-analyst/1.0");
    expect(sent.headers.get("x-opencode-session")).toBe("scan-42");
    expect(sent.body.model).toBe("deepseek-v4.1-flash");
    expect(sent.body.max_tokens).toBe(1500);
    expect(sent.body.response_format).toEqual({ type: "json_object" });
    expect(sent.body.tools).toBeUndefined();
  });

  test("omits the session header when the setting is disabled", async () => {
    const { fetcher, requests } = recordingFetch(() => jsonResponse(completionBody("{}")));
    const client = createAiProviderClient(
      makeSettings({ sessionHeader: false }),
      { aiKey: API_KEY },
      fetcher,
    );

    await client!.complete(turnRequest("scan-7"));

    expect(requests[0]!.headers.get("x-opencode-session")).toBeNull();
  });

  test("passes closed tools through and maps tool calls from the first choice", async () => {
    const { fetcher, requests } = recordingFetch(() =>
      jsonResponse(
        completionBody(null, [
          { id: "call-1", name: "read_listener_detail", arguments: "{\"listenerId\":\"listener-1\"}" },
        ]),
      ),
    );
    const client = createAiProviderClient(makeSettings(), { aiKey: API_KEY }, fetcher);
    const tools = [
      {
        type: "function" as const,
        function: {
          name: "read_listener_detail",
          description: "Read one listener",
          parameters: {
            type: "object",
            properties: { listenerId: { type: "string" } },
            required: ["listenerId"],
            additionalProperties: false,
          },
        },
      },
    ];

    const result = await client!.complete(turnRequest("scan-1", tools));

    expect(result.calls).toEqual([
      { id: "call-1", name: "read_listener_detail", arguments: "{\"listenerId\":\"listener-1\"}" },
    ]);
    expect(requests[0]!.body.tools).toEqual(tools);
    expect(requests[0]!.body.response_format).toBeUndefined();
  });

  test("a 429 response rejects without leaking the key or raw provider text", async () => {
    const { fetcher } = recordingFetch(() =>
      jsonResponse(
        { error: { message: "RAW_PROVIDER_BODY_MARKER slow down" } },
        { status: 429, headers: { "retry-after": "60" } },
      ),
    );
    const client = createAiProviderClient(makeSettings(), { aiKey: API_KEY }, fetcher);

    const error = await captureError(() => client!.complete(turnRequest("scan-1")));
    const surface = describeError(error);

    expect(error).toBeInstanceOf(Error);
    expect(surface).not.toContain(API_KEY);
    expect(surface).not.toContain("RAW_PROVIDER_BODY_MARKER");
  });

  test("a 5xx response rejects without leaking the key or raw provider text", async () => {
    const { fetcher } = recordingFetch(() =>
      jsonResponse(
        { error: { message: "RAW_PROVIDER_BODY_MARKER upstream exploded" } },
        { status: 503 },
      ),
    );
    const client = createAiProviderClient(makeSettings(), { aiKey: API_KEY }, fetcher);

    const error = await captureError(() => client!.complete(turnRequest("scan-1")));
    const surface = describeError(error);

    expect(error).toBeInstanceOf(Error);
    expect(surface).not.toContain(API_KEY);
    expect(surface).not.toContain("RAW_PROVIDER_BODY_MARKER");
  });

  test("a transport timeout rejects without leaking the key", async () => {
    const fetcher: HttpFetcher = async () => {
      const error = new Error("The operation was aborted due to timeout");
      error.name = "TimeoutError";
      throw error;
    };
    const client = createAiProviderClient(makeSettings(), { aiKey: API_KEY }, fetcher);

    const error = await captureError(() => client!.complete(turnRequest("scan-1")));

    expect(error).toBeInstanceOf(Error);
    expect(describeError(error)).not.toContain(API_KEY);
  });
});

describe("EvidenceBroker closed tool schemas", () => {
  test("advertises all five read-only tools as closed JSON schemas", async () => {
    const requests: AiTurnRequest[] = [];
    const client = scriptedClient([() => finalTurn()], requests);

    await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({ evidence: postureEvidence() }),
    );

    const tools = requests[0]!.tools;
    expect(tools).toHaveLength(evidenceTools.length);

    const schemas = new Map<string, Record<string, any>>();
    for (const tool of tools) {
      const parsed = toolSchema(tool);
      schemas.set(parsed.name, parsed.parameters);
      expect((tool as { type?: string }).type).toBe("function");
    }

    for (const name of evidenceTools) {
      const schema = schemas.get(name);
      expect(schema).toBeDefined();
      expect(schema!.type).toBe("object");
      expect(schema!.additionalProperties).toBe(false);
    }

    const posture = schemas.get("read_posture_detail")!;
    expect(new Set(posture.properties.criterionId.enum)).toEqual(new Set(criterionIds));
    expect(posture.required).toContain("criterionId");

    const listener = schemas.get("read_listener_detail")!;
    expect(listener.properties.listenerId.type).toBe("string");
    expect(listener.required).toContain("listenerId");

    const events = schemas.get("read_recent_events")!;
    expect(new Set(events.properties.category.enum)).toEqual(
      new Set(["auth", "firewall", "network", "units", "packages"]),
    );
    expect(events.properties.windowMinutes).toMatchObject({ minimum: 1, maximum: 1440 });
    expect(events.properties.limit).toMatchObject({ minimum: 1, maximum: 50 });
    expect(events.required).toEqual(expect.arrayContaining(["category", "windowMinutes", "limit"]));

    const process = schemas.get("read_process_summary")!;
    expect(process.properties.pid).toMatchObject({ type: "integer", minimum: 1 });
    expect(process.required).toContain("pid");

    const unit = schemas.get("read_unit_status")!;
    expect(unit.properties.unitName.type).toBe("string");
    expect(unit.properties.unitName.pattern).toBe("^[A-Za-z0-9_@.:-]{1,128}$");
    expect(new Set(unit.properties.scope.enum)).toEqual(new Set(["system", "user"]));
    expect(unit.required).toEqual(expect.arrayContaining(["unitName", "scope"]));
  });
});

describe("EvidenceBroker tool dispatch", () => {
  test("read_posture_detail serves registered criteria and rejects unknown criterion ids", async () => {
    const requests: AiTurnRequest[] = [];
    const client = scriptedClient(
      [
        () => ({
          calls: [
            call("c1", "read_posture_detail", { criterionId: "ssh_hardening" }),
            call("c2", "read_posture_detail", { criterionId: "made_up_criterion" }),
          ],
        }),
        () => finalTurn(),
      ],
      requests,
    );

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({ evidence: postureEvidence() }),
    );

    const payload = toolResult(requests[1]!, "c1", 0);
    expect(payload).toContain("ssh_hardening");
    expect(payload).toContain("warn");
    expect(payload).not.toContain("made_up_criterion");
    expect(rejectedSteps(result).map((step) => step.tool)).toContain("read_posture_detail");
  });

  test("read_listener_detail rejects listener ids outside this scan registry", async () => {
    const requests: AiTurnRequest[] = [];
    const client = scriptedClient(
      [
        () => ({
          calls: [
            call("c1", "read_listener_detail", { listenerId: "listener-1" }),
            call("c2", "read_listener_detail", { listenerId: "listener-from-another-scan" }),
          ],
        }),
        () => finalTurn(),
      ],
      requests,
    );

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({
        evidence: [
          {
            id: "listener-1",
            kind: "listener",
            facts: { protocol: "tcp", address: "0.0.0.0", port: 22, family: 4 },
          },
        ],
      }),
    );

    const payload = toolResult(requests[1]!, "c1", 0);
    expect(payload).toContain("listener-1");
    expect(payload).toContain("22");
    expect(payload).not.toContain("listener-from-another-scan");
    expect(rejectedSteps(result).map((step) => step.tool)).toContain("read_listener_detail");
  });

  test("read_recent_events validates bounds and registers returned events for citations", async () => {
    const recentCalls: [Category, number, number][] = [];
    const requests: AiTurnRequest[] = [];
    const client = scriptedClient(
      [
        () => ({
          calls: [
            call("c1", "read_recent_events", { category: "auth", windowMinutes: 60, limit: 10 }),
            call("c2", "read_recent_events", { category: "kernel", windowMinutes: 60, limit: 10 }),
            call("c3", "read_recent_events", { category: "auth", windowMinutes: 0, limit: 10 }),
            call("c4", "read_recent_events", { category: "auth", windowMinutes: 1441, limit: 10 }),
            call("c5", "read_recent_events", { category: "auth", windowMinutes: 60, limit: 0 }),
            call("c6", "read_recent_events", { category: "auth", windowMinutes: 60, limit: 51 }),
          ],
        }),
        () =>
          finalTurn({
            verdict: { kind: "warn", confidence: 0.9, summary: "Repeated authentication failures" },
            findings: [
              {
                severity: "warning",
                summary: "Repeated SSH authentication failures",
                evidenceIds: ["event-1"],
              },
            ],
            proposals: [],
          }),
      ],
      requests,
    );

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({
        recentEvents: (category, windowMinutes, limit) => {
          recentCalls.push([category, windowMinutes, limit]);
          return [eventFixture()];
        },
      }),
    );

    expect(recentCalls).toEqual([["auth", 60, 10]]);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.evidenceIds).toEqual(["event-1"]);
    expect(rejectedSteps(result)).toHaveLength(5);
    expect(rejectedSteps(result).every((step) => step.tool === "read_recent_events")).toBe(true);
  });

  test("read_process_summary returns only sanitized process fields", async () => {
    const requests: AiTurnRequest[] = [];
    const client = scriptedClient(
      [
        () => ({
          calls: [
            call("c1", "read_process_summary", { pid: 4242 }),
            call("c2", "read_process_summary", { pid: 4242, file: "/etc/shadow" }),
            call("c3", "read_process_summary", { pid: 99 }),
            call("c4", "read_process_summary", { pid: -1 }),
            call("c5", "read_process_summary", { pid: 0 }),
          ],
        }),
        () => finalTurn(),
      ],
      requests,
    );

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({
        evidence: [
          {
            id: "process-4242",
            kind: "process",
            facts: {
              pid: 4242,
              comm: "nginx",
              uid: 33,
              startedAt: NOW - HOUR,
              executableBasename: "nginx",
              parentComm: "systemd",
              argv: "--token=hunter2",
              environ: "API_KEY=hunter2",
              openFiles: "/home/operator/.ssh/id_ed25519",
            },
          },
        ],
      }),
    );

    const payload = JSON.parse(toolResult(requests[1]!, "c1", 0)) as Record<string, unknown>;
    expect(payload.comm).toBe("nginx");
    expect(payload.uid).toBe(33);
    expect(payload.startedAt).toBe(NOW - HOUR);
    expect(payload.executableBasename).toBe("nginx");
    expect(payload.parentComm).toBe("systemd");

    const raw = JSON.stringify(payload);
    expect(raw).not.toContain("hunter2");
    expect(raw).not.toContain(".ssh");
    expect(raw).not.toContain("argv");
    expect(raw).not.toContain("environ");
    expect(raw).not.toContain("openFiles");

    expect(rejectedSteps(result)).toHaveLength(4);
    expect(JSON.stringify(requests[1]!.messages)).not.toContain("/etc/shadow");
  });

  test("read_unit_status validates unit identity and projects only status fields", async () => {
    const unitCalls: [string, "system" | "user"][] = [];
    const requests: AiTurnRequest[] = [];
    const client = scriptedClient(
      [
        () => ({
          calls: [
            call("c1", "read_unit_status", { unitName: "sshd.service", scope: "system" }),
            call("c2", "read_unit_status", { unitName: "demo-app.timer", scope: "user" }),
            call("c3", "read_unit_status", { unitName: "sshd", scope: "system" }),
            call("c4", "read_unit_status", { unitName: "../etc/passwd", scope: "system" }),
            call("c5", "read_unit_status", { unitName: "sshd.service", scope: "global" }),
            call("c6", "read_unit_status", {
              unitName: `${"a".repeat(129)}.service`,
              scope: "system",
            }),
          ],
        }),
        () => finalTurn(),
      ],
      requests,
    );

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({
        evidence: [
          {
            id: "unit-sshd",
            kind: "unit",
            facts: { unitName: "sshd.service", scope: "system" },
          },
          {
            id: "unit-demo-timer",
            kind: "unit",
            facts: { unitName: "demo-app.timer", scope: "user" },
          },
        ],
        unitStatus: async (name, scope) => {
          unitCalls.push([name, scope]);
          return {
            ActiveState: "active",
            SubState: "running",
            Result: "success",
            ExecMainStatus: 0,
            FragmentPath: "/run/systemd/system/sshd.service",
            Environment: "TOKEN=hunter2",
          };
        },
      }),
    );

    expect(unitCalls).toEqual([
      ["sshd.service", "system"],
      ["demo-app.timer", "user"],
    ]);

    const payload = JSON.parse(toolResult(requests[1]!, "c1", 0)) as Record<string, unknown>;
    expect(payload.ActiveState).toBe("active");
    expect(payload.SubState).toBe("running");
    expect(payload.Result).toBe("success");
    expect(payload.ExecMainStatus).toBe(0);

    const raw = JSON.stringify(payload);
    expect(raw).not.toContain("FragmentPath");
    expect(raw).not.toContain("Environment");
    expect(raw).not.toContain("hunter2");

    expect(rejectedSteps(result)).toHaveLength(4);
  });

  test("read_unit_status rejects undiscovered units and scope mismatches before calling unitStatus", async () => {
    const unitCalls: [string, "system" | "user"][] = [];
    const requests: AiTurnRequest[] = [];
    const client = scriptedClient(
      [
        () => ({
          calls: [
            call("c1", "read_unit_status", { unitName: "cron.service", scope: "system" }),
            call("c2", "read_unit_status", { unitName: "sshd.service", scope: "user" }),
            call("c3", "read_unit_status", { unitName: "sshd.service", scope: "system" }),
          ],
        }),
        () => finalTurn(),
      ],
      requests,
    );

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({
        evidence: [
          {
            id: "unit-sshd",
            kind: "unit",
            facts: { unitName: "sshd.service", scope: "system" },
          },
        ],
        unitStatus: async (name, scope) => {
          unitCalls.push([name, scope]);
          return {
            ActiveState: "active",
            SubState: "running",
            Result: "success",
            ExecMainStatus: 0,
          };
        },
      }),
    );

    expect(unitCalls).toEqual([["sshd.service", "system"]]);
    expect(rejectedSteps(result)).toHaveLength(2);
    expect(rejectedSteps(result).every((step) => step.tool === "read_unit_status")).toBe(true);
    expect(JSON.stringify(requests[1]!.messages)).not.toContain("cron.service");
  });

  test("unknown tools, malformed JSON and extra arguments are rejected and never echoed back", async () => {
    const requests: AiTurnRequest[] = [];
    const client = scriptedClient(
      [
        () => ({
          calls: [
            call("c1", "run_shell", { command: "rm -rf /" }),
            call("c2", "read_posture_detail", "{not-json"),
            call("c3", "read_unit_status", {
              unitName: "sshd.service",
              scope: "system",
              extra: "/etc/shadow",
            }),
          ],
        }),
        () => finalTurn(),
      ],
      requests,
    );

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({ evidence: postureEvidence() }),
    );

    expect(rejectedSteps(result)).toHaveLength(3);
    expect(new Set(rejectedSteps(result).map((step) => step.tool))).toEqual(
      new Set(["unknown", "read_posture_detail", "read_unit_status"]),
    );

    const nextMessages = JSON.stringify(requests[1]!.messages);
    expect(nextMessages).not.toContain("rm -rf /");
    expect(nextMessages).not.toContain("/etc/shadow");
    expect(nextMessages).not.toContain("run_shell");
    expect(JSON.stringify(result.trail)).not.toContain("run_shell");

    const assistant = requests[1]!.messages.find((message) => message.role === "assistant") as
      | { tool_calls?: { function: { arguments: string } }[] }
      | undefined;
    for (const entry of assistant?.tool_calls ?? []) {
      expect(entry.function.arguments).toBe("{}");
    }
  });

  test("records unknown tool calls in InvestigationTrail without echoing untrusted tool names", async () => {
    const requests: AiTurnRequest[] = [];
    const client = scriptedClient(
      [
        () => ({
          calls: [call("c1", "exec_shell", { cmd: "cat /etc/shadow" })],
        }),
        () => finalTurn(),
      ],
      requests,
    );

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({ evidence: postureEvidence() }),
    );

    expect(result.trail.steps).toContainEqual({
      tool: "unknown",
      reason: "Rejected unknown tool call",
      outcome: "rejected",
      evidenceIds: [],
    });
    expect(JSON.stringify(result.trail)).not.toContain("exec_shell");
    expect(JSON.stringify(requests[1]!.messages)).not.toContain("exec_shell");
    expect(JSON.stringify(requests[1]!.messages)).not.toContain("/etc/shadow");
  });

  test("strips camelCase sensitive criterion keys while preserving safe SSH posture keys", async () => {
    const requests: AiTurnRequest[] = [];
    const client = scriptedClient(
      [
        () => ({
          calls: [call("c1", "read_posture_detail", { criterionId: "ssh_hardening" })],
        }),
        () => finalTurn(),
      ],
      requests,
    );

    await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({
        evidence: [
          {
            id: "ev-ssh",
            kind: "criterion",
            facts: {
              criterionId: "ssh_hardening",
              passwordAuthentication: "no",
              passwordAuth: "no",
              kbdInteractiveAuthentication: "no",
              permitRootLogin: "no",
              pubkeyAuthentication: "yes",
              authToken: "secret-auth-token",
              sshPrivateKey: "secret-ssh-private-key",
              rootPassword: "secret-root-password",
              cmdlineArgs: "--token=secret-cmdline",
              apiKey: "secret-api-key",
              secretValue: "secret-val",
            },
          },
        ],
      }),
    );

    const initialPayload = JSON.stringify(requests[0]!.messages);
    const detailPayload = toolResult(requests[1]!, "c1", 0);

    for (const surface of [initialPayload, detailPayload]) {
      expect(surface).toContain("passwordAuthentication");
      expect(surface).toContain("passwordAuth");
      expect(surface).toContain("kbdInteractiveAuthentication");
      expect(surface).toContain("permitRootLogin");
      expect(surface).toContain("pubkeyAuthentication");

      expect(surface).not.toContain("authToken");
      expect(surface).not.toContain("sshPrivateKey");
      expect(surface).not.toContain("rootPassword");
      expect(surface).not.toContain("cmdlineArgs");
      expect(surface).not.toContain("apiKey");
      expect(surface).not.toContain("secretValue");
      expect(surface).not.toContain("secret-");
    }
  });

  test("caps a single tool response at 4 KiB of UTF-8", async () => {
    const requests: AiTurnRequest[] = [];
    const client = scriptedClient(
      [
        () => ({
          calls: [call("c1", "read_recent_events", { category: "auth", windowMinutes: 60, limit: 5 })],
        }),
        () => finalTurn(),
      ],
      requests,
    );

    const events = Array.from({ length: 5 }, (_, index) =>
      eventFixture({ id: `event-${index + 1}`, summary: "x".repeat(2_000) }),
    );

    await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({ recentEvents: () => events }),
    );

    const content = toolResult(requests[1]!, "c1", 0);
    expect(Buffer.byteLength(content, "utf8")).toBeLessThanOrEqual(4 * 1024);
  });
});

describe("AiAnalyst investigation", () => {
  test("a missing provider degrades independently of the broker", async () => {
    const result = await new AiAnalyst({ clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker(),
    );

    expect(result).toEqual({
      status: "unconfigured",
      findings: [],
      proposals: [],
      trail: { steps: [] },
    });
  });

  test("the initial prompt marks evidence as untrusted telemetry", async () => {
    const requests: AiTurnRequest[] = [];
    const client = scriptedClient([() => finalTurn()], requests);

    await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-trusted",
      makeBroker({ evidence: postureEvidence() }),
    );

    const first = requests[0]!;
    expect(first.scanId).toBe("scan-trusted");
    expect(first.signal).toBeInstanceOf(AbortSignal);
    expect(first.tools).toHaveLength(evidenceTools.length);

    const system = first.messages
      .filter((message) => message.role === "system")
      .map((message) => String(message.content))
      .join("\n");
    expect(system).toMatch(/untrusted/i);
    expect(JSON.stringify(first.messages)).toContain("ev-1");
  });

  test("accepts findings that cite issued evidence and assigns local ids", async () => {
    const client = scriptedClient([
      () =>
        finalTurn({
          verdict: { kind: "warn", confidence: 0.82, summary: "SSH hardening drift detected" },
          findings: [
            {
              severity: "warning",
              summary: "SSH password authentication is enabled",
              evidenceIds: ["ev-1"],
            },
          ],
          proposals: [],
        }),
    ]);

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({ evidence: postureEvidence() }),
    );

    expect(result.status).toBe("ready");
    expect(result.verdict).toEqual({
      kind: "warn",
      confidence: 0.82,
      summary: "SSH hardening drift detected",
    });
    expect(result.findings).toHaveLength(1);

    const finding = result.findings[0]!;
    expect(finding.source).toBe("ai");
    expect(finding.severity).toBe("warning");
    expect(finding.evidenceIds).toEqual(["ev-1"]);
    expect(typeof finding.id).toBe("string");
    expect(finding.id.length).toBeGreaterThan(0);
  });

  test("rejects findings containing extra keys such as id or source", async () => {
    const client = scriptedClient([
      () =>
        finalTurn({
          verdict: { kind: "warn", confidence: 0.82, summary: "SSH hardening drift detected" },
          findings: [
            {
              id: "model-supplied-id",
              severity: "warning",
              summary: "Extra id key must be rejected",
              evidenceIds: ["ev-1"],
            },
            {
              source: "deterministic",
              severity: "warning",
              summary: "Extra source key must be rejected",
              evidenceIds: ["ev-1"],
            },
            {
              extra: "unexpected",
              severity: "warning",
              summary: "Arbitrary extra key must be rejected",
              evidenceIds: ["ev-1"],
            },
            {
              severity: "warning",
              summary: "Exact schema finding is accepted",
              evidenceIds: ["ev-1"],
            },
          ],
          proposals: [],
        }),
    ]);

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({ evidence: postureEvidence() }),
    );

    expect(result.status).toBe("ready");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.summary).toBe("Exact schema finding is accepted");
    expect(result.findings[0]!.source).toBe("ai");
    expect(rejectedSteps(result)).toHaveLength(3);
  });

  test("always finishes with a dedicated tool-free final turn even when a tool turn returns no calls", async () => {
    const requests: AiTurnRequest[] = [];
    const client = scriptedClient(
      [
        () =>
          finalTurn({
            verdict: { kind: "breach", confidence: 1, summary: "Premature tool-turn verdict" },
            findings: [],
            proposals: [],
          }),
        () =>
          finalTurn({
            verdict: { kind: "healthy", confidence: 0.91, summary: "Final tool-free verdict" },
            findings: [],
            proposals: [],
          }),
      ],
      requests,
    );

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({ evidence: postureEvidence() }),
    );

    expect(requests).toHaveLength(2);
    expect(requests[0]!.tools).toHaveLength(evidenceTools.length);
    expect(requests[1]!.tools).toEqual([]);
    expect(result.status).toBe("ready");
    expect(result.verdict).toEqual({
      kind: "healthy",
      confidence: 0.91,
      summary: "Final tool-free verdict",
    });
  });

  test("tool results stay bounded and invented evidence cannot support a finding", async () => {
    const broker = new EvidenceBroker({
      evidence: [{ id: "ev-1", kind: "criterion", facts: { criterionId: "ssh_hardening", status: "warn" } }],
      recentEvents: () => [],
    });
    const requests: AiTurnRequest[] = [];
    const analyst = new AiAnalyst({
      clock: { now: () => 100 },
      client: { async complete(request) {
        requests.push(request);
        if (requests.length === 1) return { calls: [
          { id: "call-1", name: "read_posture_detail", arguments: '{"criterionId":"ssh_hardening"}' },
          { id: "call-2", name: "read_process_summary", arguments: '{"pid":99,"file":"/etc/shadow"}' },
        ] };
        return { calls: [], content: JSON.stringify({
          verdict: { kind: "warn", confidence: 0.9, summary: "SSH posture warning" },
          findings: [{ severity: "warning", summary: "Unsupported", evidenceIds: ["invented"] }],
          proposals: [],
        }) };
      } },
    });
    const result = await analyst.investigate("scan-1", broker);
    expect(result.findings).toEqual([]);
    expect(result.trail.steps.map((step) => step.outcome)).toContain("rejected");
    expect(requests.at(-1)!.tools).toEqual([]);
    expect(JSON.stringify(requests.at(-1))).not.toContain("/etc/shadow");
  });

  test("discards findings that cite invented evidence ids and records rejected steps", async () => {
    const client = scriptedClient([
      () =>
        finalTurn({
          verdict: { kind: "warn", confidence: 0.8, summary: "SSH posture warning" },
          findings: [
            {
              severity: "critical",
              summary: "Invented evidence supports this finding",
              evidenceIds: ["invented-evidence"],
            },
            {
              severity: "warning",
              summary: "No evidence at all",
              evidenceIds: [],
            },
          ],
          proposals: [],
        }),
    ]);

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({ evidence: postureEvidence() }),
    );

    expect(result.findings).toEqual([]);
    expect(rejectedSteps(result).length).toBeGreaterThanOrEqual(2);
  });

  test("invalid verdict payloads map to invalid_response and accept nothing", async () => {
    const invalidVerdicts: Record<string, unknown>[] = [
      { kind: "catastrophe", confidence: 0.5, summary: "Unknown verdict kind" },
      { kind: "warn", confidence: 1.4, summary: "Confidence above range" },
      { kind: "warn", confidence: -0.1, summary: "Confidence below range" },
      { kind: "warn", confidence: 0.5 },
      { kind: "warn", confidence: "high", summary: "Non-numeric confidence" },
    ];

    for (const [index, verdict] of invalidVerdicts.entries()) {
      const client = scriptedClient([
        () =>
          finalTurn({
            verdict,
            findings: [
              {
                severity: "warning",
                summary: "Valid looking finding that must not survive",
                evidenceIds: ["ev-1"],
              },
            ],
            proposals: [
              { target: { kind: "deny_peer_ip", ip: PEER }, evidenceIds: ["ev-1"] },
            ],
          }),
      ]);

      const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
        `scan-${index}`,
        makeBroker({ evidence: postureEvidence() }),
      );

      expect(result.reason).toBe("invalid_response");
      expect(result.verdict).toBeUndefined();
      expect(result.findings).toEqual([]);
      expect(result.proposals).toEqual([]);
    }
  });

  test("malformed JSON output maps to invalid_response", async () => {
    const client = scriptedClient([() => finalTurn("Everything looks fine, no JSON here.")]);

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({ evidence: postureEvidence() }),
    );

    expect(result.reason).toBe("invalid_response");
    expect(result.verdict).toBeUndefined();
    expect(result.findings).toEqual([]);
    expect(result.proposals).toEqual([]);
  });

  test("accepts valid proposal drafts and discards malformed containment targets", async () => {
    const validClient = scriptedClient([
      () =>
        finalTurn({
          verdict: { kind: "warn", confidence: 0.9, summary: "Repeated peer failures" },
          findings: [],
          proposals: [
            { target: { kind: "deny_peer_ip", ip: PEER }, evidenceIds: ["ev-1"] },
          ],
        }),
    ]);

    const accepted = await new AiAnalyst({ client: validClient, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({ evidence: postureEvidence() }),
    );

    expect(accepted.proposals).toHaveLength(1);
    expect(accepted.proposals[0]!.target).toEqual({ kind: "deny_peer_ip", ip: PEER });
    expect(Object.keys(accepted.proposals[0]!.target).sort()).toEqual(["ip", "kind"]);
    expect(accepted.proposals[0]!.evidenceIds).toEqual(["ev-1"]);

    const invalidClient = scriptedClient([
      () =>
        finalTurn({
          verdict: { kind: "warn", confidence: 0.9, summary: "Repeated peer failures" },
          findings: [],
          proposals: [
            { target: { kind: "run_shell", command: "rm -rf /tmp/basho" }, evidenceIds: ["ev-1"] },
            { target: { kind: "deny_peer_ip", ip: "999.1.1.1" }, evidenceIds: ["ev-1"] },
            { target: { kind: "deny_peer_ip", ip: PEER, port: 22 }, evidenceIds: ["ev-1"] },
            { target: { kind: "deny_peer_ip", ip: PEER }, evidenceIds: ["invented-evidence"] },
            { target: { kind: "isolate_lan_ingress", interface: "eth0" }, evidenceIds: ["ev-1"] },
          ],
        }),
    ]);

    const rejected = await new AiAnalyst({
      client: invalidClient,
      clock: clockAt(NOW),
    }).investigate("scan-2", makeBroker({ evidence: postureEvidence() }));

    expect(rejected.proposals).toEqual([]);
    expect(rejectedSteps(rejected).length).toBeGreaterThanOrEqual(5);
    expect(JSON.stringify(rejected)).not.toContain("rm -rf /tmp/basho");
  });

  test("stops tool access after the round and call budgets and finishes tool-free", async () => {
    const requests: AiTurnRequest[] = [];
    const client: AiProviderClient = {
      async complete(request: AiTurnRequest): Promise<TurnResult> {
        requests.push(request);
        if (request.tools.length > 0) {
          return {
            calls: [
              call("a", "read_posture_detail", { criterionId: "ssh_hardening" }),
              call("b", "read_posture_detail", { criterionId: "network_exposure" }),
            ],
          };
        }
        return finalTurn();
      },
    };

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({
        evidence: [
          ...postureEvidence(),
          {
            id: "ev-2",
            kind: "criterion",
            facts: { criterionId: "network_exposure", status: "warn" },
          },
        ],
      }),
    );

    const toolRequests = toolsOnRequest(requests);
    expect(toolRequests).toHaveLength(3);

    const finalRequest = requests.at(-1)!;
    expect(finalRequest.tools).toEqual([]);
    expect(requests).toHaveLength(4);
    expect(toolMessages(finalRequest)).toHaveLength(6);

    const toolSteps = result.trail.steps.filter((step) => step.tool !== "verdict");
    expect(toolSteps).toHaveLength(6);
    expect(result.status).toBe("ready");
  });

  test("caps tool dispatches at 6 when a single turn requests 8 tool calls", async () => {
    const requests: AiTurnRequest[] = [];
    let dispatchedCount = 0;
    const client = scriptedClient(
      [
        () => ({
          calls: Array.from({ length: 8 }, (_, index) =>
            call(`c${index + 1}`, "read_recent_events", {
              category: "auth",
              windowMinutes: 60,
              limit: 1,
            }),
          ),
        }),
        () => finalTurn(),
      ],
      requests,
    );

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({
        recentEvents: () => {
          dispatchedCount += 1;
          return [eventFixture({ id: `event-${dispatchedCount}` })];
        },
      }),
    );

    expect(dispatchedCount).toBe(6);
    expect(toolsOnRequest(requests)).toHaveLength(1);
    expect(requests).toHaveLength(2);
    expect(requests[1]!.tools).toEqual([]);
    expect(toolMessages(requests[1]!)).toHaveLength(6);
    expect(result.trail.steps.filter((step) => step.tool !== "verdict")).toHaveLength(6);
    expect(result.status).toBe("ready");
  });

  test("cuts off tool access early when estimated input tokens exceed 12,000 and trims the final request", async () => {
    const requests: AiTurnRequest[] = [];
    const client = scriptedClient(
      [
        () => ({
          calls: [
            call("c1", "read_recent_events", { category: "auth", windowMinutes: 60, limit: 15 }),
            call("c2", "read_recent_events", { category: "auth", windowMinutes: 60, limit: 15 }),
            call("c3", "read_recent_events", { category: "auth", windowMinutes: 60, limit: 15 }),
            call("c4", "read_recent_events", { category: "auth", windowMinutes: 60, limit: 15 }),
          ],
        }),
        () => finalTurn(),
      ],
      requests,
    );

    const largeInitialEvidence: Evidence[] = Array.from({ length: 65 }, (_, index) => ({
      id: `ev-pad-${index + 1}`,
      kind: "criterion",
      facts: {
        criterionId: "ssh_hardening",
        detail: "d".repeat(250),
      },
    }));

    const largeEvents = Array.from({ length: 15 }, (_, index) =>
      eventFixture({
        id: `big-ev-${index + 1}`,
        summary: "s".repeat(240),
        rule: "r".repeat(60),
      }),
    );

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-1",
      makeBroker({
        evidence: largeInitialEvidence,
        recentEvents: () => largeEvents,
      }),
    );

    expect(toolsOnRequest(requests)).toHaveLength(1);
    expect(requests).toHaveLength(2);

    const finalRequest = requests[1]!;
    expect(finalRequest.tools).toEqual([]);
    const finalEstimatedTokens = Math.ceil(
      Buffer.byteLength(JSON.stringify(finalRequest.messages), "utf8") / 3,
    );
    expect(finalEstimatedTokens).toBeLessThanOrEqual(12_000);
    expect(toolMessages(finalRequest).some((m) => m.content === '{"truncated":true}')).toBe(true);
    expect(result.status).toBe("ready");
  });

  test("rejects a cross-scan evidence broker before calling the provider", async () => {
    let providerCalls = 0;
    const client: AiProviderClient = {
      async complete() {
        providerCalls += 1;
        return finalTurn();
      },
    };
    const broker = makeBroker({ scanId: "scan-1", evidence: postureEvidence() });
    expect(broker.scanId).toBe("scan-1");

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-2",
      broker,
    );

    expect(providerCalls).toBe(0);
    expect(result).toEqual({
      status: "offline",
      findings: [],
      proposals: [],
      trail: {
        steps: [
          {
            tool: "verdict",
            reason: "Rejected cross-scan evidence broker",
            outcome: "rejected",
            evidenceIds: [],
          },
        ],
      },
      reason: "invalid_response",
    });
  });

  test("rejects findings and proposals citing evidence IDs from another scan", async () => {
    const scan1Broker = makeBroker({
      scanId: "scan-1",
      evidence: [
        {
          id: "scan-1-ev-1",
          kind: "criterion",
          facts: { criterionId: "ssh_hardening", status: "warn" },
        },
      ],
    });
    const scan2Broker = makeBroker({
      scanId: "scan-2",
      evidence: [
        {
          id: "scan-2-ev-1",
          kind: "criterion",
          facts: { criterionId: "ssh_hardening", status: "pass" },
        },
      ],
    });

    const client = scriptedClient([
      () =>
        finalTurn({
          verdict: { kind: "warn", confidence: 0.9, summary: "Cross-scan citation attempt" },
          findings: [
            {
              severity: "critical",
              summary: "Stale finding citing scan-1 evidence",
              evidenceIds: ["scan-1-ev-1"],
            },
            {
              severity: "info",
              summary: "Valid finding citing scan-2 evidence",
              evidenceIds: ["scan-2-ev-1"],
            },
          ],
          proposals: [
            { target: { kind: "deny_peer_ip", ip: PEER }, evidenceIds: ["scan-1-ev-1"] },
          ],
        }),
    ]);

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-2",
      scan2Broker,
    );

    expect(scan1Broker.hasEvidenceId("scan-1-ev-1")).toBe(true);
    expect(scan2Broker.hasEvidenceId("scan-1-ev-1")).toBe(false);
    expect(result.status).toBe("ready");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.evidenceIds).toEqual(["scan-2-ev-1"]);
    expect(result.proposals).toEqual([]);
    expect(rejectedSteps(result)).toHaveLength(2);
  });
});

describe("AiAnalyst provider backoff and degradation", () => {
  test("a 429 with Retry-After seconds parks the analyst until the window passes", async () => {
    let now = NOW;
    const { fetcher, requests } = recordingFetch(() =>
      jsonResponse(
        { error: { message: "RAW_PROVIDER_BODY_MARKER slow down" } },
        { status: 429, headers: { "retry-after": "60" } },
      ),
    );
    const client = createAiProviderClient(makeSettings(), { aiKey: API_KEY }, fetcher)!;
    const analyst = new AiAnalyst({ client, clock: { now: () => now } });
    const broker = makeBroker({ evidence: postureEvidence() });

    const first = await analyst.investigate("scan-1", broker);
    expect(first.status).toBe("offline");
    expect(first.reason).toBe("rate_limited");
    expect(first.findings).toEqual([]);
    expect(first.proposals).toEqual([]);
    expect(JSON.stringify(first)).not.toContain(API_KEY);
    expect(JSON.stringify(first)).not.toContain("RAW_PROVIDER_BODY_MARKER");

    const baseline = requests.length;
    now = NOW + 59 * SECOND;
    const parked = await analyst.investigate("scan-2", broker);
    expect(parked.status).toBe("offline");
    expect(parked.reason).toBe("rate_limited");
    expect(requests.length).toBe(baseline);

    now = NOW + 61 * SECOND;
    const resumed = await analyst.investigate("scan-3", broker);
    expect(resumed.status).toBe("offline");
    expect(requests.length).toBeGreaterThan(baseline);
  });

  test("a 429 with an HTTP-date Retry-After is honored, capped at 30 minutes", async () => {
    let now = NOW;
    const { fetcher, requests } = recordingFetch(() =>
      jsonResponse(
        { error: { message: "RAW_PROVIDER_BODY_MARKER" } },
        {
          status: 429,
          headers: { "retry-after": new Date(NOW + 2 * MINUTE).toUTCString() },
        },
      ),
    );
    const client = createAiProviderClient(makeSettings(), { aiKey: API_KEY }, fetcher)!;
    const analyst = new AiAnalyst({ client, clock: { now: () => now } });
    const broker = makeBroker();

    await analyst.investigate("scan-1", broker);
    const baseline = requests.length;

    now = NOW + 119 * SECOND;
    await analyst.investigate("scan-2", broker);
    expect(requests.length).toBe(baseline);

    now = NOW + 121 * SECOND;
    await analyst.investigate("scan-3", broker);
    expect(requests.length).toBeGreaterThan(baseline);

    // A far-future date must not park the analyst beyond the 30 minute cap.
    const capped = recordingFetch(() =>
      jsonResponse(
        { error: { message: "RAW_PROVIDER_BODY_MARKER" } },
        {
          status: 429,
          headers: { "retry-after": new Date(NOW + 12 * HOUR).toUTCString() },
        },
      ),
    );
    const cappedClient = createAiProviderClient(
      makeSettings(),
      { aiKey: API_KEY },
      capped.fetcher,
    )!;
    now = NOW;
    const cappedAnalyst = new AiAnalyst({ client: cappedClient, clock: { now: () => now } });

    await cappedAnalyst.investigate("scan-4", broker);
    const cappedBaseline = capped.requests.length;

    now = NOW + 29 * MINUTE;
    await cappedAnalyst.investigate("scan-5", broker);
    expect(capped.requests.length).toBe(cappedBaseline);

    now = NOW + 31 * MINUTE;
    await cappedAnalyst.investigate("scan-6", broker);
    expect(capped.requests.length).toBeGreaterThan(cappedBaseline);
  });

  test("repeated 5xx responses back off exponentially from 30s to 30m and reset after success", async () => {
    let now = NOW;
    let unhealthy = true;
    const { fetcher, requests } = recordingFetch(() =>
      unhealthy
        ? jsonResponse(
            { error: { message: "RAW_PROVIDER_BODY_MARKER upstream exploded" } },
            { status: 500 },
          )
        : jsonResponse(completionBody(JSON.stringify(healthyFinal()))),
    );
    const client = createAiProviderClient(makeSettings(), { aiKey: API_KEY }, fetcher)!;
    const analyst = new AiAnalyst({ client, clock: { now: () => now } });
    const broker = makeBroker();

    const first = await analyst.investigate("scan-1", broker);
    expect(first.status).toBe("offline");
    expect(first.reason).toBe("provider_unavailable");
    expect(JSON.stringify(first)).not.toContain("RAW_PROVIDER_BODY_MARKER");

    let baseline = requests.length;
    const delays = [30 * SECOND, MINUTE, 2 * MINUTE, 4 * MINUTE, 8 * MINUTE, 16 * MINUTE, 30 * MINUTE];

    for (const delay of delays) {
      now += delay - SECOND;
      const parked = await analyst.investigate("scan-parked", broker);
      expect(parked.status).toBe("offline");
      expect(requests.length).toBe(baseline);

      now += SECOND;
      const retried = await analyst.investigate("scan-retried", broker);
      expect(retried.status).toBe("offline");
      expect(requests.length).toBeGreaterThan(baseline);
      baseline = requests.length;
    }

    // A successful completion resets the backoff to the 30s floor.
    unhealthy = false;
    now += 30 * MINUTE;
    const healthy = await analyst.investigate("scan-healthy", broker);
    expect(healthy.status).toBe("ready");

    unhealthy = true;
    await analyst.investigate("scan-failure", broker);
    baseline = requests.length;

    now += 29 * SECOND;
    await analyst.investigate("scan-early", broker);
    expect(requests.length).toBe(baseline);

    now += SECOND;
    await analyst.investigate("scan-due", broker);
    expect(requests.length).toBeGreaterThan(baseline);
  });

  test("the investigation deadline defaults to 45 seconds and aborts a hanging provider call as a timeout", async () => {
    let sawAbort = false;
    const client: AiProviderClient = {
      complete({ signal }) {
        return new Promise<never>((_resolve, reject) => {
          const fail = () => {
            sawAbort = true;
            const error = new Error("The operation was aborted");
            error.name = "AbortError";
            reject(error);
          };
          if (signal.aborted) fail();
          else signal.addEventListener("abort", fail, { once: true });
        });
      },
    };

    const defaultAnalyst = new AiAnalyst({ client, clock: { now: () => Date.now() } });
    expect(defaultAnalyst.deadlineMs).toBe(45 * SECOND);

    const started = Date.now();
    const result = await new AiAnalyst({
      client,
      clock: { now: () => Date.now() },
      deadlineMs: 80,
    }).investigate("scan-1", makeBroker());
    const elapsed = Date.now() - started;

    expect(sawAbort).toBe(true);
    expect(elapsed).toBeGreaterThanOrEqual(80);
    expect(elapsed).toBeLessThan(1_000);
    expect(result.status).toBe("offline");
    expect(result.reason).toBe("timeout");
    expect(result.findings).toEqual([]);
    expect(result.proposals).toEqual([]);
  });

  test("aborts an in-flight provider call immediately when an external AbortSignal aborts", async () => {
    let sawAbort = false;
    let calls = 0;
    const client: AiProviderClient = {
      complete({ signal }) {
        calls += 1;
        if (calls >= 2) {
          return Promise.resolve(finalTurn());
        }
        return new Promise<never>((_resolve, reject) => {
          const fail = () => {
            sawAbort = true;
            const error = new Error("The operation was aborted");
            error.name = "AbortError";
            reject(error);
          };
          if (signal.aborted) fail();
          else signal.addEventListener("abort", fail, { once: true });
        });
      },
    };

    const analyst = new AiAnalyst({
      client,
      clock: clockAt(NOW),
      deadlineMs: 10_000,
    });
    const external = new AbortController();
    const started = Date.now();
    const pending = analyst.investigate("scan-ext-abort", makeBroker(), external.signal);
    queueMicrotask(() => external.abort());

    const result = await pending;
    const elapsed = Date.now() - started;

    expect(sawAbort).toBe(true);
    expect(elapsed).toBeLessThan(1_000);
    expect(result.status).toBe("offline");
    expect(result.reason).toBe("timeout");
    expect(result.findings).toEqual([]);
    expect(result.proposals).toEqual([]);

    // External cancellation should not park the analyst in provider backoff.
    const next = await analyst.investigate("scan-after-abort", makeBroker());
    expect(next.status).toBe("ready");
    expect(calls).toBe(3);
  });

  test("aborts a hanging broker.dispatch cleanly when the investigation deadline fires", async () => {
    const client = scriptedClient([
      () => ({
        calls: [call("c1", "read_unit_status", { unitName: "sshd.service", scope: "system" })],
      }),
      () => finalTurn(),
    ]);

    const broker = makeBroker({
      evidence: [
        {
          id: "unit-sshd",
          kind: "unit",
          facts: { unitName: "sshd.service", scope: "system" },
        },
      ],
      unitStatus: () => new Promise<Facts | null>(() => {}),
    });

    const started = Date.now();
    const result = await new AiAnalyst({
      client,
      clock: { now: () => Date.now() },
      deadlineMs: 80,
    }).investigate("scan-1", broker);
    const elapsed = Date.now() - started;

    expect(elapsed).toBeGreaterThanOrEqual(80);
    expect(elapsed).toBeLessThan(1_000);
    expect(result.status).toBe("offline");
    expect(result.reason).toBe("timeout");
    expect(result.findings).toEqual([]);
    expect(result.proposals).toEqual([]);
  });

  test("sets redirect: error on outbound requests and rejects cross-origin 3xx redirects", async () => {
    const { fetcher, requests } = recordingFetch(
      () =>
        new Response(null, {
          status: 302,
          headers: { location: "https://evil.example.test/steal" },
        }),
    );
    const client = createAiProviderClient(makeSettings(), { aiKey: API_KEY }, fetcher)!;

    const error = await captureError(() => client.complete(turnRequest("scan-redirect")));
    expect(error).toBeInstanceOf(Error);
    expect(requests).toHaveLength(1);
    expect(requests[0]!.init.redirect).toBe("error");
    expect(describeError(error)).not.toContain(API_KEY);
    expect(describeError(error)).not.toContain("evil.example.test");
  });

  test("accepts valid pause_workload and isolate_lan_ingress proposal drafts", async () => {
    const client = scriptedClient([
      () =>
        finalTurn({
          verdict: { kind: "breach", confidence: 0.96, summary: "Confirmed workload anomaly" },
          findings: [],
          proposals: [
            {
              target: {
                kind: "pause_workload",
                workloadId: "demo-app",
                pid: 4242,
                startedAt: NOW - HOUR,
              },
              evidenceIds: ["ev-1"],
            },
            {
              target: { kind: "isolate_lan_ingress" },
              evidenceIds: ["ev-1"],
            },
          ],
        }),
    ]);

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-targets",
      makeBroker({ evidence: postureEvidence() }),
    );

    expect(result.status).toBe("ready");
    expect(result.proposals).toEqual([
      {
        target: {
          kind: "pause_workload",
          workloadId: "demo-app",
          pid: 4242,
          startedAt: NOW - HOUR,
        },
        evidenceIds: ["ev-1"],
      },
      {
        target: { kind: "isolate_lan_ingress" },
        evidenceIds: ["ev-1"],
      },
    ]);
  });

  test("normalizes unsafe or duplicate provider tool call IDs locally", async () => {
    const requests: AiTurnRequest[] = [];
    const client = scriptedClient(
      [
        () => ({
          calls: [call("bad id /etc/shadow", "read_posture_detail", { criterionId: "ssh_hardening" })],
        }),
        () => ({
          calls: [call("call-1", "read_posture_detail", { criterionId: "ssh_hardening" })],
        }),
        () => finalTurn(),
      ],
      requests,
    );

    const result = await new AiAnalyst({ client, clock: clockAt(NOW) }).investigate(
      "scan-ids",
      makeBroker({ evidence: postureEvidence() }),
    );

    expect(result.status).toBe("ready");
    expect(JSON.stringify(requests[1]!.messages)).not.toContain("/etc/shadow");
    const ids = toolMessages(requests[2]!).map((m) => m.id);
    expect(new Set(ids).size).toBe(2);
    expect(ids.every((id) => /^[A-Za-z0-9._:-]+$/.test(id))).toBe(true);
  });
});
