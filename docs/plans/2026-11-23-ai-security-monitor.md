# AI-Driven Security Monitor Implementation Plan

> **For agentic workers:** REQUIRED SKILL: invoke the dispatch skill via the skill tool to implement this plan task-by-task. Execution is subagent-driven only: never execute inline. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Security tab that monitors Linux host posture and exposure, investigates security signals, delivers alerts, and supports reversible containment under an operator-selected policy.

**Architecture:** Run the security modules inside Basho, with SQLite as the durable boundary for scans, journal checkpoints, alerts, and containment. Keep telemetry collection unprivileged, project bounded structured evidence into the AI client, and authorize typed containment through deterministic policy and independently recoverable adapters.

**Tech Stack:** Bun, `bun:sqlite`, Hono JSX, HTMX, SSE, Tailwind CSS, DaisyUI, the official `openai` SDK, Linux system tools, and an optional root-owned Bash helper.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `package.json`, `bun.lock` | Declare the SDK and test command, and pin the dependency resolution. |
| `.gitignore` | Exclude `/data/` and its SQLite sidecars. |
| `config/security.json` | Supply validated, non-secret security defaults. |
| `src/security/types.ts` | Define the shared security domain and dependency seams. |
| `src/security/config.ts` | Load and validate configuration, overrides, and environment inputs. |
| `src/security/runner.ts` | Execute named, bounded command recipes. |
| `src/security/store.ts` | Own security schema, transactions, queries, and retention. |
| `src/security/collector.ts` | Collect deterministic posture and infer listener reachability. |
| `src/security/events.ts` | Normalize and aggregate journal and socket observations, and derive triage signals. |
| `src/security/ai-analyst.ts` | Run the bounded AI investigation and broker its evidence. |
| `src/security/lockdown.ts` | Authorize, apply, reconcile, and roll back typed containment. |
| `scripts/basho-lockdown-helper.sh` | Enforce independent policy and lease recovery for privileged network containment. |
| `src/security/notifications.ts` | Queue and deliver alerts and report channel health. |
| `src/security/runtime.ts` | Compose modules and own scheduling, operation lifecycle, and live view updates. |
| `src/security/demo.ts` | Supply isolated fictional fixtures and simulated operations. |
| `src/security/auth.ts` | Authenticate security requests and enforce browser mutation guards. |
| `src/services/scanner.ts` | Discover local web services while excluding SSH from active probing. |
| `src/templates/security.tsx` | Render the Security view, login form, and replaceable fragments. |
| `src/routes/security.tsx` | Bind the Security page, authenticated API, and mutation forms to the runtime. |
| `src/templates/app.tsx` | Render the three-tab shell and Security status dot. |
| `src/routes/pages.tsx` | Share full-page/HTMX rendering with Security. |
| `src/routes/sse.ts` | Serve Security updates alongside existing resource telemetry. |
| `src/main.ts` | Wire app routes, bind settings, socket peer identity, and runtime lifecycle. |
| `static/handlers.js` | Manage Security SSE, countdowns, and client-side filters across HTMX navigation. |
| `static/style.css` | Publish the generated stylesheet with Security utilities. |
| `tests/security/config-runner.test.ts` | Verify configuration precedence and command execution bounds. |
| `tests/security/store.test.ts` | Verify persistence, atomic transitions, claims, and retention. |
| `tests/security/collector.test.ts` | Verify posture parsing and exposure inference from fixtures. |
| `tests/security/events.test.ts` | Verify cursor progression, aggregation, drift, and triage. |
| `tests/security/ai-analyst.test.ts` | Verify SDK request mapping and the evidence boundary. |
| `tests/security/lockdown.test.ts` | Verify containment policy, leases, recovery, and helper contracts with fakes. |
| `tests/security/notifications.test.ts` | Verify deduplication, recipient payloads, and retries. |
| `tests/security/runtime-auth-scanner.test.ts` | Verify runtime lifecycle, demo isolation, request guards, and scanner behavior. |
| `tests/security/routes-ui.test.ts` | Verify app routing, HTML fragments, escaping, and SSE cleanup. |
| `tests/security/docs.test.ts` | Verify README examples and screenshot artifacts. |
| `docs/screenshots/security-desktop.png`, `docs/screenshots/security-mobile.png` | Show the fictional Security view at desktop and mobile widths. |
| `README.md` | Document Security setup, policies, integrations, and demo screenshots. |

Use epoch milliseconds throughout the runtime and SQLite. Use opaque IDs throughout the UI and evidence broker. Tests use fixture text, injected clocks, mocked commands and HTTP, and ephemeral databases. Resolve test paths from the repository root. The text examples under each implementation step define the main contract and code path, with accompanying acceptance cases defining the rest of that task's behavior.

### Task 1: Establish configuration, shared types, and command execution

**Files:**

- Create: `config/security.json`, `src/security/types.ts`, `src/security/config.ts`, `src/security/runner.ts`
- Modify: `package.json`, `bun.lock`, `.gitignore`
- Test: `tests/security/config-runner.test.ts`

**Terms and seams:** `LockdownMode`, `AlertChannel`, `Clock`, `CommandRunner`, `HttpFetcher`. Keep public settings and secrets in separate objects.

- [ ] **Step 1: Write the failing test**

```ts
import { expect, test } from "bun:test";
import { loadSecurityConfig } from "../../src/security/config";
import { readBounded } from "../../src/security/runner";

test("runtime overrides and environment have distinct destinations", () => {
  const { settings, secrets } = loadSecurityConfig({
    env: { OPENCODE_API_KEY: "fixture-secret", OPENCODE_BASE_URL: "https://ai.example.test/v1" },
    overrides: { scanIntervalMinutes: 30 },
  });
  expect(settings.scanIntervalMinutes).toBe(30);
  expect(settings.ai.baseURL).toBe("https://ai.example.test/v1");
  expect(settings.mode).toBe("approve");
  expect(secrets.aiKey).toBe("fixture-secret");
  expect(JSON.stringify(settings)).not.toContain("fixture-secret");
  expect(() => loadSecurityConfig({ env: {}, overrides: { scanIntervalMinutes: 0 } })).toThrow();
});

test("a stream is canceled as soon as it exceeds its byte quota", async () => {
  let canceled = false;
  const input = new ReadableStream<Uint8Array>({
    start(controller) { controller.enqueue(new Uint8Array(5)); },
    cancel() { canceled = true; },
  });
  await expect(readBounded(input, 4)).rejects.toThrow("output limit");
  expect(canceled).toBe(true);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run `bun test tests/security/config-runner.test.ts`. Expected: `src/security/config` and `src/security/runner` cannot be resolved.

- [ ] **Step 3: Write minimal implementation**

Run `bun add openai`, add `"test": "bun test"` to `package.json`, and add `/data/` to `.gitignore`. Define the shared records in `types.ts`:

```ts
export const criterionIds = [
  "firewall_ufw", "network_exposure", "ssh_hardening", "package_updates",
  "disk_and_boot", "kernel_sysctl", "systemd_health", "process_and_timers",
] as const;
export type CriterionId = typeof criterionIds[number];
export type Category = "auth" | "firewall" | "network" | "units" | "packages";
export type Severity = "info" | "warning" | "critical" | "breach";
export type LockdownMode = "monitor" | "approve" | "auto-lockdown";
export type AlertChannel = "in-app" | "desktop" | "ntfy" | "discord" | "telegram";
export type Coverage = "complete" | "partial" | "unavailable";
export type Facts = Record<string, string | number | boolean | null>;

export interface Clock { now(): number }
export type HttpFetcher = (url: string, init: RequestInit) => Promise<Response>;

export interface Evidence {
  id: string;
  kind: "criterion" | "listener" | "event" | "process" | "unit";
  facts: Facts;
}

export interface PostureCheck {
  id: CriterionId;
  category: Category | "host";
  title: string;
  status: "pass" | "warn" | "fail" | "unknown" | "disabled";
  summary: string;
  remediation?: string;
  evidenceIds: string[];
  sourceCoverage: Record<string, Coverage>;
}

export interface PostureSnapshot {
  id: string;
  capturedAt: number;
  checks: PostureCheck[];
  evidence: Evidence[];
}

export interface Listener {
  id: string;
  protocol: "tcp" | "udp";
  address: string;
  port: number;
  family: 4 | 6 | "unspecified";
  interfaceName?: string;
  pid?: number;
  process?: string;
}

export interface ExposureEntry {
  id: string;
  listener: Listener;
  reachability: "exposed_v4_v6" | "exposed_lan" | "tailnet" |
    "blocked_by_ufw" | "local_only" | "unknown";
  firewallV4: "allow" | "deny" | "unknown" | "na";
  firewallV6: "allow" | "deny" | "unknown" | "na";
  publication: "serve" | "funnel" | "none" | "unknown";
  expected: boolean;
  evidenceIds: string[];
}

export interface SecurityEvent {
  id: string;
  source: "journal" | "socket";
  category: Category;
  severity: Severity;
  rule: string;
  target: string;
  firstAt: number;
  lastAt: number;
  count: number;
  isNoise: boolean;
  summary: string;
}

export interface SecurityFinding {
  id: string;
  source: "deterministic" | "ai";
  severity: Severity;
  summary: string;
  evidenceIds: string[];
}

export const evidenceTools = [
  "read_posture_detail", "read_listener_detail", "read_recent_events",
  "read_process_summary", "read_unit_status",
] as const;
export type EvidenceTool = typeof evidenceTools[number];

export interface InvestigationTrail {
  steps: {
    tool: EvidenceTool | "verdict";
    reason: string;
    outcome: "ok" | "rejected" | "unavailable";
    evidenceIds: string[];
  }[];
}

export interface AiVerdict {
  kind: "healthy" | "warn" | "breach";
  confidence: number;
  summary: string;
}

export interface SecurityScan {
  id: string;
  trigger: "scheduled" | "manual" | "event";
  startedAt: number;
  finishedAt: number;
  snapshot: PostureSnapshot;
  exposure: ExposureEntry[];
  findings: SecurityFinding[];
  trail: InvestigationTrail;
  aiStatus: "ready" | "unconfigured" | "offline";
  verdict?: AiVerdict;
}

export type ContainmentTarget =
  | { kind: "pause_workload"; workloadId: string; pid: number; startedAt: number }
  | { kind: "deny_peer_ip"; ip: string }
  | { kind: "isolate_lan_ingress" };

export interface LockdownProposal {
  id: string;
  scanId: string;
  revision: number;
  status: "pending" | "claimed" | "rejected" | "expired";
  target: ContainmentTarget;
  evidenceIds: string[];
  createdAt: number;
  expiresAt: number;
  leaseSeconds: number;
  rollbackDescription: string;
}

export interface LockdownAction {
  id: string;
  proposalId: string;
  idempotencyKey: string;
  target: ContainmentTarget;
  state: "pending" | "active" | "failed" | "rolling_back" | "rolled_back";
  createdAt: number;
  expiresAt: number;
  updatedAt: number;
  rollbackHandle?: string;
}

export interface SecurityAlert {
  id: string;
  fingerprint: string;
  severity: Severity;
  summary: string;
  createdAt: number;
  proposalId?: string;
}

export interface Corroboration {
  rule: "ssh_burst" | "unexpected_listener" | "system_anomaly" | "unexpected_workload";
  eventIds: string[];
  expiresAt: number;
  target?: ContainmentTarget;
}

export type CommandRequest =
  | { kind: "sockets" | "ufw_status" | "tailscale_serve" | "tailscale_funnel" |
      "updates" | "arch_audit" | "block_devices" | "boot_status" | "sysctl" |
      "system_failed" | "user_failed" | "user_timers" | "processes" |
      "snapper_health" | "limine_health" }
  | { kind: "journal"; after?: string; limit: number }
  | { kind: "unit"; name: string; scope: "system" | "user" }
  | { kind: "desktop"; urgency: "normal" | "critical"; summary: string; body: string };

export type CommandResult =
  | { status: "ok"; stdout: string; exitCode: number }
  | { status: "unavailable" | "timeout" | "overflow" | "failed" };

export interface CommandRunner {
  run(request: CommandRequest, signal?: AbortSignal): Promise<CommandResult>;
}
```

Expose `loadSecurityConfig(input?: { env?: Record<string, string | undefined>; overrides?: RuntimeOverrides }): { settings: SecuritySettings; secrets: SecuritySecrets }`. Use these defaults:

```json
{
  "mode": "approve",
  "scanIntervalMinutes": 60,
  "criteria": {},
  "expectedPorts": [22, 6969],
  "workloads": [],
  "ai": {
    "baseURL": "https://opencode.ai/zen/go/v1",
    "model": "deepseek-v4.1-flash",
    "sessionHeader": true,
    "confidenceThreshold": 0.85,
    "triageCooldownMinutes": 10
  },
  "notifications": { "channels": ["in-app"], "cooldownMinutes": 15 },
  "lockdown": { "proposalMinutes": 30, "leaseSeconds": 600, "helperEnabled": false }
}
```

`RuntimeOverrides` accepts only `mode`, `scanIntervalMinutes`, and boolean `criteria` indexed by `CriterionId`. Merge criterion keys over defaults and treat omitted criteria as enabled. Accept scan intervals from 1–1440 minutes, ports from 1–65535, confidence from 0–1, and leases from 30–1800 seconds. Expose `settings.notifications.ntfyUrl?` and `settings.notifications.publicOrigin?` as validated config fields. Reject URL credentials and fragments, and require `publicOrigin` to be an origin. Allow HTTP for private/Tailscale `ntfy` and explicitly configured local AI endpoints. Keep `OPENCODE_API_KEY`, `BASHO_AUTH_TOKEN`, `BASHO_NTFY_TOKEN`, `BASHO_DISCORD_WEBHOOK`, `BASHO_TELEGRAM_BOT_TOKEN`, and `BASHO_TELEGRAM_CHAT_ID` in `SecuritySecrets` as `aiKey`, `authToken`, `ntfyToken`, `discordWebhook`, `telegramBotToken`, and `telegramChatId`. Apply `OPENCODE_BASE_URL` over the configured URL. Parse `BASHO_HOST`, `BASHO_PORT`, `BASHO_SECURITY_DB`, and `BASHO_DEMO_SECURITY` into typed process settings.

Export `createCommandRunner(): CommandRunner`. Use named recipes that return argv arrays. Use an explicit executable search path, `LC_ALL=C`, and only the user runtime environment fields necessary for user systemd and desktop notifications. Never pass application secrets to a child. Keep helper mutation recipes in the containment adapter.

```ts
export async function readBounded(stream: ReadableStream<Uint8Array>, max: number) {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let bytes = 0;
  let text = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return text + decoder.decode();
      bytes += value.byteLength;
      if (bytes > max) {
        await reader.cancel();
        throw new Error("output limit");
      }
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
}
```

Drain stdout and stderr concurrently, cap each at 256 KiB, and kill and reap the child on overflow, caller abort, or the 5-second deadline. Return stderr-free failure classifications. Permit command-specific benign exit statuses, including read-only cached `pacman -Qu` (exit 0 for pending updates, exit 1 with empty stdout and empty stderr for up-to-date, unavailable when missing). For initial journal reads, pass `--lines=N`; for cursor reads, stream forward from `--after-cursor` and stop after `N` complete JSON lines. Never checkpoint a truncated line. Validate cursor length and character set, unit names, and the desktop urgency enum before forming argv. End option parsing before dynamic desktop text.

- [ ] **Step 4: Run test to verify it passes**

Run `bun test tests/security/config-runner.test.ts`. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add package.json bun.lock .gitignore config/security.json src/security/types.ts src/security/config.ts src/security/runner.ts tests/security/config-runner.test.ts
git commit -m "feat(security): define config and bounded command execution"
```

### Task 2: Persist security state and atomic operations

**Files:**

- Create: `src/security/store.ts`
- Modify: none
- Test: `tests/security/store.test.ts`

**Terms and seams:** `SecurityStore`, `SecurityScan`, `SecurityEvent`, `LockdownProposal`, `LockdownAction`, `SecurityAlert`, `AlertChannel`. Implement ADR 0002 here.

- [ ] **Step 1: Write the failing test**

```ts
import { expect, test } from "bun:test";
import { SecurityStore } from "../../src/security/store";
import type { LockdownProposal } from "../../src/security/types";

test("claim is revision checked and records exactly one pending action", () => {
  const store = new SecurityStore(":memory:");
  try {
    const proposal: LockdownProposal = {
      id: "proposal-1", scanId: "scan-1", revision: 1, status: "pending",
      target: { kind: "deny_peer_ip", ip: "198.51.100.42" },
      evidenceIds: ["ev-1"], createdAt: 100, expiresAt: 60_000,
      leaseSeconds: 60, rollbackDescription: "Remove the leased peer rule",
    };
    store.insertProposal(proposal);
    expect(store.claimProposal("proposal-1", 0, 200)).toBeNull();
    const claim = store.claimProposal("proposal-1", 1, 200);
    expect(claim).toMatchObject({ state: "pending", expiresAt: 60_200 });
    expect(store.claimProposal("proposal-1", 1, 200)).toBeNull();
    expect(store.listActions()).toEqual([claim]);
  } finally {
    store.close();
  }
});

test("cooldown survives worker claims and permits escalation", () => {
  const store = new SecurityStore(":memory:");
  try {
    const alert = {
      id: "a", fingerprint: "auth:ssh_burst:198.51.100.42",
      severity: "warning" as const, summary: "Repeated failures", createdAt: 100,
    };
    expect(store.enqueueAlert(alert, ["ntfy"], 900_000)).toBe(true);
    expect(store.enqueueAlert({ ...alert, id: "b", createdAt: 200 }, ["ntfy"], 900_000)).toBe(false);
    expect(store.enqueueAlert({ ...alert, id: "c", severity: "breach", createdAt: 300 }, ["ntfy"], 900_000)).toBe(true);
    const [delivery] = store.claimDeliveries(300, 1, 30_000);
    expect(delivery!.alert.id).toBe("a");
    expect(store.claimDeliveries(301, 1, 30_000)[0]!.alert.id).toBe("c");
  } finally {
    store.close();
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run `bun test tests/security/store.test.ts`. Expected: `src/security/store` cannot be resolved.

- [ ] **Step 3: Write minimal implementation**

Use `Database` from `bun:sqlite`, `foreign_keys=ON`, a finite `busy_timeout`, and WAL for file-backed databases. Open the default `data/basho-security.db` or `BASHO_SECURITY_DB`; require a private state directory and create new directories/files with `0700`/`0600` permissions. Never change permissions on a shared parent directory. Support `:memory:` for tests and demo.

Apply migration `1` transactionally and record it in `schema_migrations`. Map `scans`, `posture_checks`, `exposure_entries`, `findings`, and `investigation_steps` to scan metadata and child rows. Use scan foreign keys with cascading deletion for those children. Store event index fields separately from projected JSON. Create `source_cursors`, `lockdown_proposals`, `lockdown_actions`, `security_alerts`, `alert_deliveries`, and `runtime_settings`. Keep action audit independent of scan retention. Use unique constraints on event ID, action idempotency key, and `(alert_id, channel)`.

```ts
export interface EventBatch {
  events: SecurityEvent[];
  cursor?: { source: string; expected: string | null; next: string };
  burstWindowMs: number;
}

export interface AlertDelivery {
  id: string;
  alert: SecurityAlert;
  channel: AlertChannel;
  attempts: number;
  claimToken: string;
}

export interface SecurityStoreContract {
  saveScan(scan: SecurityScan): void;
  latestScan(): SecurityScan | null;
  getCursor(source: string): string | null;
  commitEventBatch(batch: EventBatch): boolean;
  recentEvents(since: number, limit: number, category?: Category): SecurityEvent[];
  hourlyEvents(now: number): { hour: number; signal: number; noise: number }[];
  insertProposal(proposal: LockdownProposal): void;
  listProposals(): LockdownProposal[];
  claimProposal(id: string, revision: number, now: number): LockdownAction | null;
  rejectProposal(id: string, revision: number, now: number): boolean;
  expireProposals(now: number): void;
  listActions(): LockdownAction[];
  transitionAction(id: string, from: LockdownAction["state"], to: LockdownAction["state"],
    now: number, rollbackHandle?: string): boolean;
  enqueueAlert(alert: SecurityAlert, channels: AlertChannel[], cooldownMs: number): boolean;
  claimDeliveries(now: number, limit: number, leaseMs: number): AlertDelivery[];
  settleDelivery(id: string, claimToken: string, now: number,
    result: "sent" | "failed" | { retryAt: number }): boolean;
  recentAlerts(since: number): SecurityAlert[];
  dismissAlert(id: string, now: number): boolean;
  channelHealth(): Partial<Record<AlertChannel, { status: "sent" | "failed" | "retrying"; at: number }>>;
  readOverrides(): RuntimeOverrides;
  writeOverrides(overrides: RuntimeOverrides): void;
  prune(now: number): void;
  close(): void;
}
```

In `commitEventBatch`, compare the expected cursor under a write transaction, insert unique observations, update burst counts and per-hour counts, and publish the new cursor in the same transaction. Use one event row kind for observations and another for aggregates within `security_events`. Preserve source observation IDs for dedupe and exact hourly counts when a burst crosses an hour. Compute 24 buckets including the current UTC hour, with zeroes for empty buckets. Aggregate only matching source/category/rule/target/noise within the supplied sliding window.

Use one immediate transaction for proposal claiming and action creation:

```sql
UPDATE lockdown_proposals
SET status = 'claimed', revision = revision + 1
WHERE id = $id AND revision = $revision AND status = 'pending'
  AND expires_at > $now
RETURNING id, target_json, lease_seconds;
```

Insert the pending action before committing, using `${id}:${revision}` as the idempotency key. Use compare-and-set for revision-sensitive rejection, action state, and delivery settlement. Deduplicate against the highest severity already emitted for that fingerprint inside the cooldown, using `info < warning < critical < breach`. Persist each accepted alert and all selected deliveries in one transaction. Allow reclaim of expired delivery claims with a fresh claim token. Dismissal updates in-app visibility without changing delivery.

Prune to 50 scans, 14 days of events, and 90 days of completed actions. Retain unresolved actions and the data needed to recover them. Add tests using two connections to one temporary database for stale event cursor rejection, action claim contention, stale delivery tokens, retention, and reopening persisted state.

- [ ] **Step 4: Run test to verify it passes**

Run `bun test tests/security/store.test.ts`. Expected: PASS, including file-backed reopen and contention cases.

- [ ] **Step 5: Commit**

```bash
git add src/security/store.ts tests/security/store.test.ts
git commit -m "feat(security): persist monitor state in sqlite"
```

### Task 3: Collect host posture and infer network exposure

**Files:**

- Create: `src/security/collector.ts`
- Modify: none
- Test: `tests/security/collector.test.ts`

**Terms and seams:** `PostureCollector`, `PostureSnapshot`, `ExposureEntry`, `SecurityFinding`, `CommandRunner`, `Clock`. Use an injected fixed-source file reader.

- [ ] **Step 1: Write the failing test**

```ts
import { expect, test } from "bun:test";
import { parseListeners, evaluateFirewall } from "../../src/security/collector";

test("socket parsing keeps protocol and bind family", () => {
  expect(parseListeners(
    'tcp LISTEN 0 128 [::1]:22 [::]:* users:(("sshd",pid=123,fd=3))\n' +
    'udp UNCONN 0 0 0.0.0.0:41641 0.0.0.0:*',
  )).toMatchObject([
    { protocol: "tcp", family: 6, address: "::1", port: 22, pid: 123 },
    { protocol: "udp", family: 4, address: "0.0.0.0", port: 41641 },
  ]);
});

test("ordered firewall rules and family stay independent", () => {
  const rules = [
    "-A ufw-user-input -p tcp --dport 8188 -j DROP",
    "-A ufw-user-input -p tcp --dport 8188 -j ACCEPT",
  ].join("\n");
  expect(evaluateFirewall(
    { family: 4, protocol: "tcp", port: 8188, address: "0.0.0.0" },
    { active: true, v4: rules, v6: "", defaultInput: "allow" },
  )).toBe("deny");
  expect(evaluateFirewall(
    { family: 6, protocol: "tcp", port: 8188, address: "::" },
    { active: true, v4: rules, defaultInput: "deny" },
  )).toBe("unknown");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run `bun test tests/security/collector.test.ts`. Expected: `src/security/collector` cannot be resolved.

- [ ] **Step 3: Write minimal implementation**

```ts
export interface PostureFiles {
  read(source: "ufw-v4" | "ufw-v6" | "ufw-default" | "sshd-main" | "pacman-log"):
    Promise<string | null>;
  sshDropIns(): Promise<{ name: string; text: string }[] | null>;
}

export interface FirewallInputs {
  active: boolean | null;
  v4?: string;
  v6?: string;
  defaultInput?: "allow" | "deny";
}

export interface PostureResult {
  snapshot: PostureSnapshot;
  exposure: ExposureEntry[];
  findings: SecurityFinding[];
}

export class PostureCollector {
  constructor(private readonly deps: {
    runner: CommandRunner;
    files: PostureFiles;
    clock: Clock;
  }) {}

  async collect(scanId: string, settings: SecuritySettings): Promise<PostureResult> {
    // collectCriteria creates exactly one row per criterionId.
    const capturedAt = this.deps.clock.now();
    const { checks, evidence, exposure, findings } =
      await collectCriteria(this.deps, scanId, settings);
    return { snapshot: { id: scanId, capturedAt, checks, evidence }, exposure, findings };
  }
}
```

Export `parseListeners(text: string): Listener[]` and `evaluateFirewall(listener: Pick<Listener, "family" | "protocol" | "port" | "address" | "interfaceName">, inputs: FirewallInputs): "allow" | "deny" | "unknown"`. The file reader uses fixed paths, lexical basename ordering for SSH drop-ins, size limits, and a bounded tail for the pacman log. Collect independent recipes concurrently with a small concurrency cap. Use stable check IDs and opaque evidence IDs scoped to the scan. Populate `sourceCoverage` for every consulted source. A disabled check emits `disabled`; insufficient evidence emits `unknown` or `partial` coverage on a narrower verified result.

| Criterion | Parsing and evaluation |
| --- | --- |
| `firewall_ufw` | Read `ufw status`, IPv4/IPv6 user rules, and defaults. Use first matching terminal rule per family. Track protocol, port/range, interface, destination and source scope. Report unused allow rules only when socket inventory and corresponding rule coverage are complete. Report indeterminate for relevant rule syntax the collector cannot evaluate. |
| `network_exposure` | Parse `ss -tulnp` TCP/UDP local bindings, IPv6 brackets, interface scope, and optional PID/comm. Match Serve/Funnel JSON by supported local backend endpoint or port and declared publication. Recognize loopback, LAN-bound, Tailnet bind/Serve, verified UFW deny, and publicly published/proven dual-stack exposure. Treat wildcard `*`, uncertain family, or unverifiable firewall and publication as unknown unless independent evidence proves a narrower class. Compare ports with `expectedPorts`. |
| `ssh_hardening` | Parse global OpenSSH first-value semantics, resolving supported `Include` directives in place and preserving `Match` scope. Evaluate password auth, root login, keyboard-interactive auth, and port 22 reachability outside Tailnet. Report partial coverage for unresolved includes or conditional settings that affect the result. |
| `package_updates` | Run read-only cached `pacman -Qu` (exit 0 pending updates, exit 1 with empty stdout up-to-date, unavailable when missing), count pending updates, mark `linux-*` updates, parse the last pacman upgrade, flag age greater than 14 days, and optionally summarize `arch-audit` counts. Keep update count unknown when `pacman` is unavailable. |
| `disk_and_boot` | Walk `lsblk -J` parent/child chains by mount point and encryption type, then project root encryption and unencrypted secondary volumes. Read Secure Boot and TPM2 fields from `bootctl status`, with unknown for absent values. |
| `kernel_sysctl` | Read `kernel.kptr_restrict`, `kernel.dmesg_restrict`, `kernel.unprivileged_bpf_disabled`, `kernel.yama.ptrace_scope`, `kernel.kexec_load_disabled`, `fs.suid_dumpable`, `net.ipv4.conf.all.rp_filter`, and IPv4/IPv6 redirect settings. Flag unsafe known values; preserve per-key missing coverage. |
| `systemd_health` | Parse failed system and user units, and report readable Snapper and Limine health signals. Use sanitized unit identifiers and counts. |
| `process_and_timers` | Read user timers and process inventory, and correlate non-standard listeners. Project only bounded names, PID, UID, start time, parent comm, and executable basename. |

Use fixture tests for both active UFW families, per-source restrictions, overlapping ordered rules, Serve/Funnel matching, local-only bindings, SSH include ordering, absent tool results, and one fixture per remaining criterion. Populate findings from deterministic `warn`/`fail` results using valid evidence IDs and curated remediation text.

- [ ] **Step 4: Run test to verify it passes**

Run `bun test tests/security/collector.test.ts`. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/security/collector.ts tests/security/collector.test.ts
git commit -m "feat(security): collect posture and listener exposure"
```

### Task 4: Monitor journal events and listener changes

**Files:**

- Create: `src/security/events.ts`
- Modify: none
- Test: `tests/security/events.test.ts`

**Terms and seams:** `EventMonitor`, `SecurityEvent`, `Corroboration`, `SecurityStore`, `CommandRunner`, `Clock`.

- [ ] **Step 1: Write the failing test**

```ts
import { expect, test } from "bun:test";
import { EventMonitor, parseJournalRecord } from "../../src/security/events";
import { SecurityStore } from "../../src/security/store";

test("journal failures resume from the committed cursor and trigger absolute-count triage", async () => {
  const store = new SecurityStore(":memory:");
  const now = 1_796_000_000_000;
  const lines = Array.from({ length: 5 }, (_, i) => JSON.stringify({
    __CURSOR: `s=fixture;i=${i}`, __REALTIME_TIMESTAMP: String((now - i * 1000) * 1000),
    SYSLOG_IDENTIFIER: "sshd", MESSAGE: "Failed password for invalid user from 198.51.100.42 port 49822 ssh2",
  })).join("\n");
  const requests: unknown[] = [];
  const monitor = new EventMonitor({
    store, clock: { now: () => now },
    runner: { async run(request) {
      requests.push(request);
      return { status: "ok", exitCode: 0, stdout: requests.length === 1 ? lines : "" };
    } },
  });
  try {
    expect((await monitor.pollJournal()).corroboration[0]).toMatchObject({
      rule: "ssh_burst", target: { kind: "deny_peer_ip", ip: "198.51.100.42" },
    });
    expect(store.recentEvents(now - 300_000, 10)[0]!.count).toBe(5);
    await monitor.pollJournal();
    expect(requests[1]).toEqual({ kind: "journal", after: "s=fixture;i=4", limit: 200 });
  } finally { store.close(); }
});

test("recognized multicast destinations are noise", () => {
  expect(parseJournalRecord(JSON.stringify({
    __CURSOR: "s=noise", __REALTIME_TIMESTAMP: "1796000000000000",
    _TRANSPORT: "kernel", MESSAGE: "[UFW BLOCK] IN=eth0 DST=224.0.0.1 PROTO=2",
  }))?.event).toMatchObject({ category: "firewall", isNoise: true });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run `bun test tests/security/events.test.ts`. Expected: `src/security/events` cannot be resolved.

- [ ] **Step 3: Write minimal implementation**

Export `parseJournalRecord(line): { cursor: string; event?: SecurityEvent } | null` and the monitor:

```ts
export interface MonitorResult {
  alerts: SecurityAlert[];
  corroboration: Corroboration[];
}

export class EventMonitor {
  constructor(private readonly deps: {
    store: SecurityStore;
    runner: CommandRunner;
    clock: Clock;
  }) {}

  async pollJournal(): Promise<MonitorResult> {
    const { store, runner } = this.deps;
    const previous = store.getCursor("journal");
    const result = await runner.run({ kind: "journal", after: previous ?? undefined, limit: 200 });
    if (result.status !== "ok") return this.handleJournalFailure(previous, result.status);
    const records = result.stdout.split("\n").filter(Boolean).map(parseJournalRecord);
    return this.commitJournalPage(previous, records);
  }

  // Takes a function so classification uses the newly observed socket set.
  pollSockets(classify: (listeners: Listener[]) => Promise<ExposureEntry[]>): Promise<MonitorResult> {
    return this.diffSockets(classify);
  }
}
```

`handleJournalFailure`, `commitJournalPage`, and `diffSockets` are private methods on `EventMonitor`. On initial start request up to 200 entries. On resume consume up to 200 complete lines after the cursor and save the last valid source cursor in the same transaction as observations. Valid irrelevant records advance the cursor. Stop at malformed records lacking a valid cursor and surface degraded coverage. When journald specifically reports an expired cursor, attempt a bounded recent-window recovery with an explicit gap notice and cursor compare-and-set. Preserve the checkpoint on temporary read failure. Generate observation IDs from source cursor or socket transition identity.

Recognize SSH auth failures using journal identity and fixed message patterns, UFW records using fixed key/value fields, and critical OOM, sudo, unit, and package events from recognized metadata and patterns. Canonicalize peer IPs before using them as targets, including IPv4-mapped forms. Generate summaries from controlled templates. Mark recognized `224.0.0.1`, `ff02::1`, and loopback probe traffic as noise. Use a five-minute aggregate window for SSH failures and ordinary repeated firewall records. Compute SSH thresholds from observations inside the current five-minute window, even when a stored burst began earlier. Trigger at five failures from the exact non-Tailnet peer. Alert on high-signal unit, OOM, and sudo events with no containment target inferred from their message.

For sockets, use successful reads to establish a baseline and diff stable keys `(family, protocol, address, interface, port)`. Emit opened and closed events for non-loopback listeners. Do not change the baseline on a failed read. Use freshly classified exposure to trigger on unexpected wildcard listeners on open UFW ports. Corroborate a workload only when a current enrolled identity matches the unexpected listener. Give independent signals explicit freshness cutoffs and exact targets where applicable. Count signal and noise by observation hour through the store. Test failed reads, expired cursors, qualified versus excluded peers, windows crossing hour boundaries, threshold aging, and drift.

- [ ] **Step 4: Run test to verify it passes**

Run `bun test tests/security/events.test.ts`. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/security/events.ts tests/security/events.test.ts
git commit -m "feat(security): monitor journal and socket changes"
```

### Task 5: Investigate using bounded structured evidence

**Files:**

- Create: `src/security/ai-analyst.ts`
- Modify: none
- Test: `tests/security/ai-analyst.test.ts`

**Terms and seams:** `AiAnalyst`, `AiProviderClient`, `EvidenceBroker`, `InvestigationTrail`, `SecurityFinding`, `LockdownProposal`. Implement ADR 0003 here.

- [ ] **Step 1: Write the failing test**

```ts
import { expect, test } from "bun:test";
import { AiAnalyst, EvidenceBroker } from "../../src/security/ai-analyst";
import type { AiTurnRequest } from "../../src/security/ai-analyst";

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

test("a missing provider degrades independently of the broker", async () => {
  const analyst = new AiAnalyst({ clock: { now: () => 100 } });
  expect((await analyst.investigate("scan-1", new EvidenceBroker({
    evidence: [], recentEvents: () => [],
  }))).status).toBe("unconfigured");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run `bun test tests/security/ai-analyst.test.ts`. Expected: `src/security/ai-analyst` cannot be resolved.

- [ ] **Step 3: Write minimal implementation**

```ts
import OpenAI from "openai";
import type { ChatCompletionMessageParam, ChatCompletionTool } from "openai/resources/chat/completions";

export interface AiTurnRequest {
  scanId: string;
  messages: ChatCompletionMessageParam[];
  tools: ChatCompletionTool[];
  signal: AbortSignal;
}

export interface AiProviderClient {
  complete(request: AiTurnRequest): Promise<{
    content?: string;
    calls: { id: string; name: string; arguments: string }[];
  }>;
}

export interface ProposalDraft {
  target: ContainmentTarget;
  evidenceIds: string[];
}

export interface InvestigationResult {
  status: SecurityScan["aiStatus"];
  verdict?: AiVerdict;
  findings: SecurityFinding[];
  proposals: ProposalDraft[];
  trail: InvestigationTrail;
  reason?: "rate_limited" | "timeout" | "provider_unavailable" | "invalid_response";
}
```

`createAiProviderClient(settings, secrets, fetcher?)` returns `undefined` without `aiKey`, otherwise wraps this request:

```ts
const client = new OpenAI({
  apiKey: secrets.aiKey,
  baseURL: settings.ai.baseURL,
  timeout: 12_000,
  maxRetries: 0,
  ...(fetcher ? { fetch: fetcher } : {}),
  defaultHeaders: { "User-Agent": "basho-security-analyst/1.0" },
});

const response = await client.chat.completions.create({
  model: settings.ai.model,
  messages: request.messages,
  max_tokens: 1500,
  ...(request.tools.length ? { tools: request.tools } : {
    response_format: { type: "json_object" as const },
  }),
}, {
  signal: request.signal,
  headers: settings.ai.sessionHeader ? { "x-opencode-session": request.scanId } : {},
});
```

Map only function calls and `message.content` from the first choice. Use an initial decision turn with tools available, up to three tool rounds and six total calls, then issue a final tool-free JSON turn. Budget each request at a conservative 12,000 estimated input tokens, each tool result at 4 KiB of UTF-8, and the whole investigation at 45 seconds using an abort signal. A budget hit ends tool access and proceeds to the final turn if time and input budget permit. Serialize only sanitized, accepted tool arguments or `{}` for rejected calls when reconstructing assistant messages. Validate provider tool call IDs and use locally generated correlation IDs if necessary. Store controlled reason text such as `"Inspect referenced SSH criterion"`.

`EvidenceBroker` accepts `{ evidence: Evidence[]; recentEvents: (category: Category, windowMinutes: number, limit: number) => SecurityEvent[]; unitStatus?: (name: string, scope: "system" | "user") => Promise<Facts | null> }`. Build closed function schemas with these exact argument names and reject extra properties before dispatch:

| Tool | Allowed arguments and result |
| --- | --- |
| `read_posture_detail` | `{ criterionId }` from `criterionIds`, returning the matching check facts. |
| `read_listener_detail` | `{ listenerId }` from the scan registry, returning projected listener facts. |
| `read_recent_events` | `{ category, windowMinutes, limit }` with category enum, 1–1440 minutes, 1–50 rows. Register any returned projected events before accepting citations. |
| `read_process_summary` | `{ pid }` as a positive integer present in the scan registry. Return only comm, UID, start time, executable basename, and parent comm. |
| `read_unit_status` | `{ unitName, scope }` with discovered unit identity, `^[A-Za-z0-9_@.:-]{1,128}$` and a recognized systemd suffix, and `system`/`user` enum. Return only `ActiveState`, `SubState`, `Result`, `ExecMainStatus`. |

Build prompt input from typed evidence only. Mark evidence as untrusted data in the system message. Never include raw journal lines, command lines, process environments, file contents, or provider error text. Construct the verdict from exact keys `kind`, `confidence`, and `summary` with finite confidence in `[0,1]`. Validate exact finding and `ProposalDraft` shapes, cap array/string sizes, require nonempty issued evidence IDs, discard invalid rows, and append `rejected` trail steps. Assign finding IDs locally. Neither accepted drafts nor verdicts execute actions.

Track bounded provider backoff in the analyst instance. On `429`, honor valid `Retry-After` seconds or dates up to the configured maximum backoff of 30 minutes. Use exponential retry delay from 30 seconds to 30 minutes for repeated unavailable responses, reset after success, and surface sanitized status only. Add mocked SDK transport tests for `baseURL`, optional session header, 429 and timeout, and broker tests for cross-scan ID rejection and exhausted budgets.

- [ ] **Step 4: Run test to verify it passes**

Run `bun test tests/security/ai-analyst.test.ts`. Expected: PASS with the SDK transport mocked.

- [ ] **Step 5: Commit**

```bash
git add src/security/ai-analyst.ts tests/security/ai-analyst.test.ts
git commit -m "feat(security): investigate through bounded evidence tools"
```

### Task 6: Enforce reversible containment policy

**Files:**

- Create: `src/security/lockdown.ts`, `scripts/basho-lockdown-helper.sh`
- Modify: none
- Test: `tests/security/lockdown.test.ts`

**Terms and seams:** `LockdownMode`, `LockdownProposal`, `LockdownAction`, `DeadMansSwitch`, `LockdownAdapter`, `Corroboration`. Implement ADR 0001 here.

- [ ] **Step 1: Write the failing test**

```ts
import { expect, test } from "bun:test";
import { DeadMansSwitch, decideContainment } from "../../src/security/lockdown";

test("management IPs remain protected after canonicalization", () => {
  const guard = new DeadMansSwitch();
  for (const ip of ["127.0.0.1", "::1", "::ffff:127.0.0.1", "100.64.0.5", "fd7a:115c:a1e0::34"]) {
    expect(guard.allows({ kind: "deny_peer_ip", ip })).toBe(false);
  }
  expect(guard.allows({ kind: "deny_peer_ip", ip: "198.51.100.42" })).toBe(true);
});

test("auto containment requires fresh corroboration for the same peer", () => {
  const target = { kind: "deny_peer_ip", ip: "198.51.100.42" } as const;
  const input = {
    mode: "auto-lockdown" as const, target, now: 100, threshold: 0.85,
    verdict: { kind: "breach" as const, confidence: 0.95, summary: "Repeated authentication failures" },
    safe: true, rollbackReady: true,
    corroboration: [{
      rule: "ssh_burst" as const, eventIds: ["event-1"], expiresAt: 200,
      target: { kind: "deny_peer_ip" as const, ip: "203.0.113.19" },
    }],
  };
  expect(decideContainment(input)).toBe("queue");
  expect(decideContainment({ ...input, mode: "monitor" })).toBe("report");
  expect(decideContainment({
    ...input, corroboration: [{ ...input.corroboration[0]!, target }],
  })).toBe("execute");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run `bun test tests/security/lockdown.test.ts`. Expected: `src/security/lockdown` cannot be resolved.

- [ ] **Step 3: Write minimal implementation**

```ts
export interface LockdownAdapter {
  preflight(target: ContainmentTarget): Promise<{ rollbackReady: boolean }>;
  apply(action: LockdownAction): Promise<{ handle: string }>;
  inspect(action: LockdownAction): Promise<
    { state: "absent" } | { state: "active"; handle: string } | { state: "unknown" }
  >;
  rollback(action: LockdownAction): Promise<{ state: "absent" | "unknown" }>;
}

export function decideContainment(input: {
  mode: LockdownMode;
  target: ContainmentTarget;
  now: number;
  threshold: number;
  verdict?: AiVerdict;
  corroboration: Corroboration[];
  safe: boolean;
  rollbackReady: boolean;
}): "report" | "queue" | "execute" {
  if (input.mode === "monitor" || !input.safe) return "report";
  if (input.mode === "auto-lockdown" && input.rollbackReady &&
    input.verdict?.kind === "breach" && input.verdict.confidence >= input.threshold &&
    input.corroboration.some((signal) =>
      signal.expiresAt > input.now && signal.eventIds.length > 0 &&
      corroboratesTarget(signal, input.target))) return "execute";
  return "queue";
}
```

Implement `corroboratesTarget` for exact canonical peer plus `ssh_burst`, and exact workload ID/PID/start time plus `unexpected_workload`. Require explicitly scoped deterministic corroboration for LAN isolation. Until such a signal is collected, keep LAN isolation eligible for operator approval only. Use `DeadMansSwitch.allows(target, context?)` to reject malformed or protected peer addresses, protected interfaces and paths, and unknown or protected process identities. Match by address bits, covering IPv4-mapped IPv6, `127.0.0.0/8`, `::1`, `100.64.0.0/10`, and `fd7a:115c:a1e0::/48`. For a workload require a current enrolled user-owned identity and reject PID 1 and the critical service names and prefixes in the spec. For LAN isolation require an enrolled port set and verified preserved paths. Critical-process checks apply to current process metadata, never model-supplied process names.

Expose `LockdownEngine.consider(scan, drafts, corroboration, settings)`, `approve(id, revision, settings)`, `reject(id, revision)`, `unlock(actionId)`, `reconcile()`, and `helperReady()`. `consider` returns alerts to publish, including urgent approval fallbacks and linked proposal IDs. Create pending proposals with revision `1`, 30-minute default expiry, validated evidence, and action-specific rollback text. Re-check current mode, target, lease, enrollment, and rollback readiness before claiming and immediately before side effects. Use the SQLite claim result as the sole permission to call `apply`. Expire proposals, process expired leases independently of scans, and let unlock work in any mode. On lost adapter responses, inspect by idempotency key before setting final state. Keep uncertain execution or rollback visible and retry reconciliation. Persist terminal failure only once the adapter confirms absence.

For enrolled workloads use specific user-owned systemd units. Validate enrolled PID and start time against the unit immediately before applying. Arm a user systemd lease that thaws or resumes the same unit before freezing it. Report unavailable where the controller or verified recovery scheduling is absent.

For the privileged helper define `status`, `deny-ip <ip> <ttl> <id>`, `isolate-lan <ttl> <id>`, `inspect <id>`, and `rollback <id>`. Use fixed-path trusted executables, a root-only state directory, `flock` on mutation/recovery, and root-owned LAN enrollment. Assign a locally generated opaque operation ID stable across retries. Keep the control flow in the script explicit:

```bash
case "$verb" in
  status)      require_no_args "$@"; report_readiness ;;
  deny-ip)     require_peer_args "$@"; lease_peer_rule "$@" ;;
  isolate-lan) require_lease_args "$@"; lease_lan_rules "$@" ;;
  inspect)     require_id_arg "$@"; inspect_lease "$1" ;;
  rollback)    require_id_arg "$@"; rollback_lease "$1" ;;
  *)           exit 64 ;;
esac
```

`require_peer_args` validates canonical IP, bounded decimal TTL, and operation ID, then checks protected ranges independently. `lease_peer_rule` writes root-only rollback state and arms a root-owned systemd rollback timer before inserting an operation-tagged rule. `lease_lan_rules` adds temporary ingress restrictions only for the enrolled LAN interface and configured destination ports. Preserve `lo`, `tailscale0`, Tailnet source ranges, established flows, and UDP/41641. Refuse if policy inspection cannot verify protection, exact rollback, or rule precedence. `inspect_lease` reports tagged-rule presence. `rollback_lease` removes only this lease's tagged rules, tolerates already removed rules, and preserves recovery state if a removal fails. Use `sudo -n` with explicit helper subcommands in Basho. Root timers, helper tests, and installation docs must share the exact argument contract.

Add tests for mode gates, concurrent approval, identity change, critical process refusal, crash/reconcile outcomes, independent expiry, and one-click unlock. For helper tests use a temporary copy with fixture executable paths, fake root policy and fake service manager; assert protected input produces zero fake firewall mutations and that rollback is armed before a permitted fixture mutation. Keep production paths fixed and reject unprivileged execution. Run `bash -n` against the actual script.

- [ ] **Step 4: Run test to verify it passes**

Run `bun test tests/security/lockdown.test.ts` and `bash -n scripts/basho-lockdown-helper.sh`. Expected: PASS; shell syntax check exits zero.

- [ ] **Step 5: Commit**

```bash
git add src/security/lockdown.ts scripts/basho-lockdown-helper.sh tests/security/lockdown.test.ts
git commit -m "feat(security): enforce leased containment and rollback"
```

### Task 7: Deliver deduplicated alerts through an outbox

**Files:**

- Create: `src/security/notifications.ts`
- Modify: none
- Test: `tests/security/notifications.test.ts`

**Terms and seams:** `NotificationDispatcher`, `SecurityAlert`, `AlertChannel`, `SecurityStore`, `HttpFetcher`, `CommandRunner`.

- [ ] **Step 1: Write the failing test**

```ts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run `bun test tests/security/notifications.test.ts`. Expected: `src/security/notifications` cannot be resolved.

- [ ] **Step 3: Write minimal implementation**

Expose constructor dependencies `{ store, clock, config: SecuritySettings["notifications"], secrets: SecuritySecrets, runner, fetcher, onInApp }` and methods `publish(alert): boolean`, `sendTestAlert(channel?: AlertChannel): string`, `drain(): Promise<void>`, and `health()`. Explicitly validate channel readiness for test calls. Create a unique test fingerprint and use the normal outbox path.

```ts
const click = config.publicOrigin ? new URL("/security", config.publicOrigin) : undefined;
if (click && alert.proposalId) click.hash = `proposal-${alert.proposalId}`;
const headers = new Headers({
  Title: "Basho Security",
  Priority: alert.severity === "breach" ? "urgent" : alert.severity === "critical" ? "high" : "default",
  Tags: alert.severity === "breach" ? "rotating_light" : "shield",
});
if (click) headers.set("Click", click.href);
if (secrets.ntfyToken) headers.set("Authorization", `Bearer ${secrets.ntfyToken}`);
await fetcher(config.ntfyUrl!, {
  method: "POST", headers, body: alert.summary, redirect: "error",
  signal: AbortSignal.timeout(8_000),
});
```

Use the same committed outbox for `in-app`, desktop, Discord, and Telegram. Emit in-app updates only after commit and render persistent alerts on reconnect. Dispatch `notify-send` through `CommandRunner`. Use Discord embeds with `allowed_mentions: { parse: [] }`; validate the configured HTTPS Discord webhook host/path. Use Telegram plain text with disabled link previews. Telegram Bot API requires its bot token in the server-to-server request path. Keep that complete URL inside the adapter and redact it from failures, UI, SQLite, and logs; similarly protect the configured Discord webhook URL. Never include any integration token in a user-visible link.

Use an 8-second request timeout and bounded concurrency. Claim a small batch with a lease longer than the request timeout. Retry transient and throttled deliveries with bounded exponential backoff and a maximum of five attempts. Report permanent failures and unconfigured channels with a controlled status, and settle with the matching claim token. Assert in fixtures that payloads, projected failures, and deep links contain no secrets, and that Discord and Telegram redirects cannot forward credentials.

- [ ] **Step 4: Run test to verify it passes**

Run `bun test tests/security/notifications.test.ts`. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/security/notifications.ts tests/security/notifications.test.ts
git commit -m "feat(security): deliver notifications through sqlite outbox"
```

### Task 8: Compose the runtime, isolate demo mode, and guard requests

**Files:**

- Create: `src/security/runtime.ts`, `src/security/demo.ts`, `src/security/auth.ts`
- Modify: `src/services/scanner.ts`
- Test: `tests/security/runtime-auth-scanner.test.ts`

**Terms and seams:** `SecurityRuntime`, `SecurityScan`, `LockdownMode`, `SecurityAlert`, `Clock`, `CommandRunner`. Verify remote identity at the HTTP boundary.

- [ ] **Step 1: Write the failing test**

```ts
import { expect, test } from "bun:test";
import { createDemoSecurityRuntime } from "../../src/security/demo";
import { createSecurityAuth } from "../../src/security/auth";
import { scan } from "../../src/services/scanner";

test("demo manual scans emit one update and retain fictional data", async () => {
  const runtime = createDemoSecurityRuntime();
  const updates: unknown[] = [];
  const unsubscribe = runtime.subscribe((event) => updates.push(event));
  try {
    await runtime.requestScan("manual");
    expect(runtime.view().hostLabel).toBe("lab-node-01");
    expect(runtime.view().latestScan?.trigger).toBe("manual");
    expect(updates).toContainEqual({ kind: "scan" });
  } finally { unsubscribe(); await runtime.stop(); }
});

test("remote writes are denied without authentication, including spoofed proxy headers", () => {
  const auth = createSecurityAuth({ clock: { now: () => 100 } });
  const request = new Request("http://basho.example.test/security/mode", {
    method: "POST", headers: { Origin: "http://basho.example.test", "X-Forwarded-For": "127.0.0.1" },
  });
  expect(auth.authorizeMutation(request, "198.51.100.42", "fixture")).toBe(false);
});

test("expected web port is probed and port 22 never reaches TCP or HTTP clients", async () => {
  const probed: number[] = [];
  const titles: number[] = [];
  await scan({
    ports: [22, 80],
    probe: async (_host, port) => { probed.push(port); return true; },
    title: async (_host, port) => { titles.push(port); return null; },
  });
  expect(probed).toEqual([80]);
  expect(titles).toEqual([80]);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run `bun test tests/security/runtime-auth-scanner.test.ts`. Expected: demo/auth imports cannot be resolved; the scanner has no injected options.

- [ ] **Step 3: Write minimal implementation**

```ts
export type SecurityUpdate = { kind: "scan" | "events" | "alert" | "containment" | "settings" | "status" };

export interface SecurityView {
  hostLabel: string;
  latestScan: SecurityScan | null;
  events: SecurityEvent[];
  hourly: { hour: number; signal: number; noise: number }[];
  proposals: LockdownProposal[];
  actions: LockdownAction[];
  alerts: SecurityAlert[];
  channelHealth: ReturnType<SecurityStore["channelHealth"]>;
  settings: Pick<SecuritySettings, "mode" | "criteria" | "scanIntervalMinutes">;
  aiStatus: SecurityScan["aiStatus"];
  scanRunning: boolean;
  nextScanAt: number | null;
  helperReady: boolean;
}

export interface SecurityRuntime {
  start(): void;
  stop(): Promise<void>;
  view(): SecurityView;
  subscribe(listener: (update: SecurityUpdate) => void): () => void;
  requestScan(trigger: SecurityScan["trigger"]): Promise<SecurityScan>;
  updateSettings(overrides: RuntimeOverrides): void;
  approve(id: string, revision: number): Promise<boolean>;
  reject(id: string, revision: number): boolean;
  unlock(id: string): Promise<boolean>;
  dismissAlert(id: string): boolean;
  sendTestAlert(channel?: AlertChannel): string;
}
```

Implement `createSecurityRuntime` with injected store, collector, monitor, analyst, lockdown engine, dispatcher, clock, and scheduler. Coalesce concurrent scans by returning the active scan promise. A single pending event request may follow an active scan if its evidence was absent from the active scan input. Apply the ten-minute cooldown only to event-triggered AI requests. Persist deterministic data before waiting for AI and update the same scan ID transactionally on completion. Persist validated overrides before rescheduling and apply them to the next scan. Poll sockets every 30 seconds and journals on a short five-second interval. Run delivery, reconciliation, and retention on independent non-overlapping schedules, including startup recovery. Publish data updates only after persistence. Stop scheduling, abort bounded I/O, wait for in-flight state writes, clear listeners, and close the database on shutdown.

Implement `createDemoSecurityRuntime()` with a separate memory store, fixed clock and synthetic `lab-node-01` fixtures. Use `198.51.100.42`, `203.0.113.19`, and `2001:db8::10`; seed a pending proposal, active lease, warning and breach alerts, AI trail, event buckets, and listener rows. Simulate all mutations and publish updates with no real adapters constructed. The app factory switches before creating collectors, SDK clients, real notifications, or lockdown adapters. In demo, render fixture Services and fixture Resources telemetry as well.

For auth export `createSecurityAuth({ token?, clock, publicOrigin? })` with `authorizeRead(request, peer)`, `authorizeMutation(request, peer, csrf)`, `login(request, suppliedToken)`, and `csrfToken(request, peer)`. Use fixed-length digests with constant-time comparison. Issue an expiring signed `HttpOnly; SameSite=Lax` cookie with `Path=/` and `Secure` on verified HTTPS. Use an unpredictable signed CSRF value bound to the authenticated session or a short-lived local cookie. Derive client address from Bun's actual socket peer and treat a missing or ambiguous peer as remote. Without a token, enable local mutation for a direct loopback peer and loopback origin only. Treat proxy forwarding headers as reasons to disallow tokenless writes rather than as authentication. Require configured auth for Security views and SSE when a token exists. For browser writes verify exact configured or direct origin, using `Referer` only if `Origin` is absent, then verify CSRF. For explicit bearer API clients allow originless requests; reject conflicting origins when supplied. Never put the bearer or session token in URLs. Test invalid signatures, expiration, origin mismatch, missing CSRF, remote without token, and authenticated cookie/bearer behavior.

Add an optional `ScanOptions` seam with `ports`, `probe`, and `title`. Keep existing caching on the default call and bypass it in injected tests.

```ts
const ports = (options?.ports ?? Array.from({ length: 9999 }, (_, i) => i + 1))
  .filter((port) => port !== 22);
const openPorts = await scanHost("localhost", ports, options?.probe ?? probeTCP);
const titles = await fetchAllTitles(openPorts, options?.title ?? fetchTitle);
```

- [ ] **Step 4: Run test to verify it passes**

Run `bun test tests/security/runtime-auth-scanner.test.ts`. Expected: PASS, including shutdown and scan coalescing with a fake scheduler.

- [ ] **Step 5: Commit**

```bash
git add src/security/runtime.ts src/security/demo.ts src/security/auth.ts src/services/scanner.ts tests/security/runtime-auth-scanner.test.ts
git commit -m "feat(security): compose runtime and guard dashboard operations"
```

### Task 9: Ship the Security tab, mutation routes, and SSE updates

**Files:**

- Create: `src/templates/security.tsx`, `src/routes/security.tsx`
- Modify: `src/templates/app.tsx`, `src/routes/pages.tsx`, `src/routes/sse.ts`, `src/main.ts`, `static/handlers.js`, `static/style.css`
- Test: `tests/security/routes-ui.test.ts`

**Terms and seams:** `SecurityRuntime`, `SecurityView`, `InvestigationTrail`, `LockdownProposal`, `LockdownAction`, `SecurityAlert`, `AlertChannel`.

- [ ] **Step 1: Write the failing test**

```ts
import { expect, test } from "bun:test";
import { createApp } from "../../src/main";
import { createDemoSecurityRuntime } from "../../src/security/demo";
import { createSecurityAuth } from "../../src/security/auth";

test("Security uses the existing shell and HTMX partial convention", async () => {
  const runtime = createDemoSecurityRuntime();
  const app = createApp({
    runtime, peer: () => "127.0.0.1", demo: true,
    auth: createSecurityAuth({ clock: { now: () => Date.now() } }),
  });
  try {
    const full = await (await app.request("http://localhost/security")).text();
    expect(full).toContain("grid-cols-3");
    expect(full).toContain("lab-node-01");
    expect(full).toContain("data-security-stream");
    const partial = await (await app.request("http://localhost/security", {
      headers: { "HX-Request": "true" },
    })).text();
    expect(partial).toContain('hx-swap-oob="innerHTML"');
    expect(partial).not.toContain('id="bottom-nav"');
    expect((await app.request("http://localhost/security/mode", {
      method: "POST", body: new URLSearchParams({ mode: "monitor" }),
    })).status).toBe(403);
  } finally { await runtime.stop(); }
});

test("Security SSE publishes readiness and removes its subscription on cancellation", async () => {
  const runtime = createDemoSecurityRuntime();
  let subscriptions = 0;
  const subscribe = runtime.subscribe.bind(runtime);
  runtime.subscribe = (listener) => {
    subscriptions++;
    const unsubscribe = subscribe(listener);
    return () => { subscriptions--; unsubscribe(); };
  };
  const app = createApp({
    runtime, peer: () => "127.0.0.1", demo: true,
    auth: createSecurityAuth({ clock: { now: () => Date.now() } }),
  });
  try {
    const response = await app.request("http://localhost/sse/security");
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    expect(response.headers.has("access-control-allow-origin")).toBe(false);
    const reader = response.body!.getReader();
    expect(new TextDecoder().decode((await reader.read()).value)).toContain("event: security");
    await reader.cancel();
    expect(subscriptions).toBe(0);
  } finally { await runtime.stop(); }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run `bun test tests/security/routes-ui.test.ts`. Expected: `createApp` export is missing.

- [ ] **Step 3: Write minimal implementation**

Export side-effect-free `createApp({ runtime, auth, peer, demo })` from `src/main.ts`. Use `import.meta.main` for startup, with validated bind config, service registry load, and real or demo composition. Resolve the peer using `server.requestIP(request)`. Start the runtime after `Bun.serve` succeeds. On termination stop accepting requests, close SSE subscriptions, and await runtime shutdown. Preserve non-demo Resources and Services behavior. Pass demo fixture providers to existing page and stats routes before any real system collector or service probe runs.

Refactor `renderPage` in `src/routes/pages.tsx` into a shared export that renders a `Layout` and `App` for full navigation and the view plus out-of-band header for HTMX. Extend the app's active-link logic to distinguish all three titles. Add `grid-cols-3`, a `/security` navigation link, and a status dot derived from authenticated view state. Use an out-of-band dot update for partials.

Register the Security route group with these paths:

| Method and path | Behavior |
| --- | --- |
| `GET /security/login` | Render login form; only reachable unauthenticated where configured. |
| `POST /security/login` | Verify origin before login and issue session on a correct token; redirect to `/security`. |
| `GET /security` | Render full shell or an HTMX partial. |
| `GET /security/fragment` | Render the replaceable Security panel and status dot. |
| `GET /api/security/status` | Return the authenticated, sanitized view model. |
| `POST /security/scan` | Queue/coalesce a manual scan and return running state immediately. |
| `POST /security/mode`, `POST /security/settings` | Validate the submitted mode or exact runtime override fields. |
| `POST /security/proposals/:id/approve`, `POST /security/proposals/:id/reject` | Require a positive revision and return `409` for stale or ineligible proposals. |
| `POST /security/actions/:id/unlock` | Request idempotent rollback and show current action state. |
| `POST /security/test-alert` | Queue a test delivery for the selected eligible channel. |
| `POST /security/alerts/:id/dismiss` | Clear an in-app banner persisted in SQLite. |

Route mutations through one shared guard that checks auth, content type, bounded body size, duplicate form fields, same-origin policy, and CSRF before dispatch. Escape all dynamic text through Hono JSX. Return `400` for malformed fields, `403` for failed authorization/CSRF, and sanitized conflict/service messages. Handle ordinary form success with `303` and HTMX requests with a scoped fragment. Set `Cache-Control: no-store` for protected pages, fragments, API, and login responses.

Render the four KPI tiles; sticky dismissible critical/breach or proposal banner; AI status and next-run countdown; Scan Now, Test Alert, channel status, mode and criterion controls; protected-path and helper indicators; revision-aware proposal forms and linked evidence; remaining leases, rollback and action audit; exposure reachability filter and search; expandable checklist and findings/remediation; investigation trail; and 24-hour SVG activity with category chips and noise suppression counts. Keep event and exposure filter state across live fragment updates. Include accessible labels, a status announcement region, and text equivalents for indicator colors.

In `src/routes/sse.ts`, terminate heartbeats and subscription on request abort, stream cancellation, or server shutdown. Validate auth before opening and close the stream when its session expires.

```ts
const encode = (update: SecurityUpdate) =>
  new TextEncoder().encode(`event: security\ndata: ${JSON.stringify(update)}\n\n`);
```

Send an initial `{ kind: "status" }`, committed update messages, and 15-second comment heartbeats. In `static/handlers.js` keep one `EventSource("/sse/security")` on the Security page, close it on HTMX removal or navigation, and coalesce updates into a same-origin fragment refresh. Never insert raw SSE fields as HTML. Preserve filter values, keyboard focus where the control survives, and open details across fragment swaps. Treat failed Security requests as status messages and stop reconnecting when navigation or session expiry requires login.

Add integration cases for valid local and authenticated flows, stale revision, escaped fixture content, live updates, unauthenticated SSE, and navigation to both existing tabs. Run CSS generation from the existing build script.

- [ ] **Step 4: Run test to verify it passes**

Run `bun test tests/security/routes-ui.test.ts`, `bun test`, and `bun run build:css`. Expected: suite PASS and `static/style.css` regenerated with the Security utilities.

- [ ] **Step 5: Commit**

```bash
git add src/templates/security.tsx src/routes/security.tsx src/templates/app.tsx src/routes/pages.tsx src/routes/sse.ts src/main.ts static/handlers.js static/style.css tests/security/routes-ui.test.ts
git commit -m "feat(security): add the security dashboard and live updates"
```

### Task 10: Document operations and verify fictional screenshots

**Files:**

- Create: `docs/screenshots/security-desktop.png`, `docs/screenshots/security-mobile.png`
- Modify: `README.md`
- Test: `tests/security/docs.test.ts`

**Terms and seams:** `SecurityScan`, `LockdownMode`, `DeadMansSwitch`, `SecurityAlert`, `AlertChannel`, demo runtime.

- [ ] **Step 1: Write the failing test**

```ts
import { expect, test } from "bun:test";

test("README links the demo screenshots and documents security setup", async () => {
  const readme = await Bun.file("README.md").text();
  for (const term of [
    "OPENCODE_API_KEY", "OPENCODE_BASE_URL", "BASHO_HOST", "BASHO_PORT",
    "BASHO_AUTH_TOKEN", "BASHO_SECURITY_DB", "BASHO_DEMO_SECURITY=1",
    "BASHO_NTFY_TOKEN", "BASHO_DISCORD_WEBHOOK", "BASHO_TELEGRAM_BOT_TOKEN",
    "BASHO_TELEGRAM_CHAT_ID", "auto-lockdown", "sudoers.d", "UDP/41641",
  ]) expect(readme).toContain(term);

  for (const [name, width, height] of [
    ["security-desktop", 1440, 1080], ["security-mobile", 390, 844],
  ] as const) {
    const path = `docs/screenshots/${name}.png`;
    expect(readme).toContain(path);
    const png = new Uint8Array(await Bun.file(path).arrayBuffer());
    expect(Array.from(png.subarray(0, 8))).toEqual([137, 80, 78, 71, 13, 10, 26, 10]);
    const dimensions = new DataView(png.buffer, png.byteOffset, png.byteLength);
    expect(dimensions.getUint32(16)).toBe(width);
    expect(dimensions.getUint32(20)).toBeGreaterThanOrEqual(height);
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run `bun test tests/security/docs.test.ts`. Expected: README is missing the security configuration and screenshot links.

- [ ] **Step 3: Write minimal implementation**

Build CSS and launch loopback-only demo mode with an empty environment. Use Bun's absolute path if the installed binary is outside the standard path.

```bash
bun run build:css
env -i PATH="$PATH" BASHO_DEMO_SECURITY=1 BASHO_HOST=127.0.0.1 BASHO_PORT=16969 bun run start
```

Use a fresh browser context at `http://127.0.0.1:16969/security`. Capture dark-theme PNGs at 1440×1080 and 390×844 with device scale factor 1. Full-page height may exceed the viewport. Before capture, inspect the rendered page and network request list. Confirm the host is `lab-node-01`, displayed peer/sample host addresses are reserved documentation addresses, and all process names, service names, paths, audit entries, and channel statuses come from demo fixtures. Inspect the actual saved PNGs and their metadata for real host details or credentials. Confirm Scan, Approve, and Rollback simulate fixture updates, then stop the demo server.

Add the screenshots under a Security subsection and document the feature using this setup example:

````markdown
### Security

The Security tab collects host posture and network exposure and shows recent events
and investigation findings. Run it with `bun run start`, or preview fictional data with:

```bash
BASHO_DEMO_SECURITY=1 BASHO_HOST=127.0.0.1 BASHO_PORT=16969 bun run start
```

Set `OPENCODE_API_KEY` in the server environment to enable AI investigation.
Basho uses the official OpenAI SDK with the configurable OpenCode Go endpoint
`https://opencode.ai/zen/go/v1`. Set `OPENCODE_BASE_URL` for a compatible endpoint.
Posture and event monitoring continue when AI is unavailable.

Configure `notifications.ntfyUrl` with the topic URL reachable from Basho over
Tailscale, and `notifications.publicOrigin` with the dashboard origin reachable
from your phone. Add `ntfy` to `notifications.channels` and use `BASHO_NTFY_TOKEN`
for a private topic. Use Test Alert to verify delivery.
````

Add all configuration names tested above with their defaults and purpose. Describe same-origin session login and remote mutation requirements, supported providers and channel setup, monitored criteria, 60-minute scan cadence, event-triggered cooldown, SQLite retention and directory permissions, and the port-22 discovery exclusion. Describe `monitor`, `approve`, and `auto-lockdown`, with exact corroboration and recovery requirements. Document optional installation at `/usr/local/libexec/basho-lockdown-helper` as root-owned and non-writable by Basho, a `sudoers.d` entry restricted to that executable and its supported subcommands, root-owned LAN enrollment, readiness check, and independent timer rollback. Match paths and subcommands to the delivered helper. Document preserved loopback, Tailnet management, and UDP/41641, and show how to disable helper access. Include `bun test` in Available Scripts and update the architecture tree with the Security runtime and routes.

- [ ] **Step 4: Run test to verify it passes**

Run `bun test tests/security/docs.test.ts`, `bun test`, and `git diff --check`. Expected: PASS and zero whitespace errors. Confirm both PNGs were visually inspected in demo mode.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/screenshots/security-desktop.png docs/screenshots/security-mobile.png tests/security/docs.test.ts
git commit -m "docs(security): document setup and add demo screenshots"
```
