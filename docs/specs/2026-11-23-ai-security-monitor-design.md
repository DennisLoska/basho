# AI-Driven Security Monitor, Breach Notifications & Guardrailed Lockdown for Basho

**Date:** 2026-11-23
**Branch:** `feat/ai-security-monitor`
**Status:** Proposed (awaiting Gate 1 approval)

## 1. Purpose & Success Criteria

Extend Basho—currently a two-tab Bun + Hono + HTMX + SSE local dashboard (`Resources`, `Services`)—with a third **`Security`** tab and background security runtime that:

1. **Deterministic Host Posture & Network Exposure:** Continuously monitors Linux/Omarchy host posture across an editable criteria checklist and correlates listening sockets (`ss -tlpn`) against firewall rules (`ufw` IPv4/IPv6) and Tailscale Serve/Funnel without requiring root.
2. **Scheduled & Event-Triggered AI Investigation (OpenAI SDK + OpenCode):** Uses the official `openai` npm SDK pointed at an OpenCode OpenAI-compatible endpoint (`baseURL` configurable, default `https://opencode.ai/zen/go/v1`, model default `deepseek-v4.1-flash`, optional `x-opencode-session` header, API key via `OPENCODE_API_KEY`). Runs on a configurable schedule, on-demand ("Scan Now"), and on high-signal live anomalies—starting from the dedicated checklist while giving the AI bounded, read-only investigation tools to inspect suspicious leads.
3. **Tailscale-First Breach Notifications:** Dispatches deduplicated security alerts via In-App SSE banner, Linux desktop (`notify-send`), **ntfy** (first-class support for self-hosted `ntfy` over Tailscale to the user's phone), Discord webhooks, and Telegram Bot API.
4. **Tiered Guardrailed Lockdown:** Supports `monitor`, `approve` (default), and `auto-lockdown` modes over a strict typed allowlist with a non-bypassable `DeadMansSwitch` (always preserving loopback `lo`/`127.0.0.1`/`::1`, `tailscale0`, SSH over Tailscale, Basho, and system services) and an optional, separately audited root helper script (`scripts/basho-lockdown-helper.sh`) for privileged network isolation.
5. **Basho Self-Hygiene, Tests & Non-Sensitive Docs:** Stops `src/services/scanner.ts` from spamming `sshd` on port 22, hardens Basho's host/auth/CSRF posture for security mutations, ships a full `bun test` suite (zero host mutations or live network calls), and updates `README.md` with documentation and non-sensitive screenshots generated from `BASHO_DEMO_SECURITY=1`.

---

## 2. Architectural Approaches Considered

| Approach | Summary | Trade-offs |
| :--- | :--- | :--- |
| **A. In-process runtime + JSON/JSONL files** | Run collectors, journal monitor, and AI loop inside Basho; store history in JSON snapshots and append-only JSONL files. | Easy to inspect on disk, but crash-safe journal cursor checkpoints, atomic proposal claiming, cooldown deduplication, and outbox retries require fragile custom file locking and replay logic. |
| **B. In-process runtime + `bun:sqlite` (Recommended)** | Run bounded background security runtime inside Basho with `bun:sqlite` (WAL mode) for durable state, HTMX/SSE UI integration, and an optional standalone root helper for privileged lockdown. | Fits Basho's zero-dependency single-process Bun deployment, gives atomic transactions for cursors, proposals, audits, and alert outbox, and requires no separate daemon install. Collection pauses when Basho stops (journal cursors catch up on restart). |
| **C. Separate monitor daemon + IPC** | Dedicated systemd daemon owns collection, SQLite, AI loop, and lockdown; Basho connects via authenticated Unix socket IPC. | Survives dashboard restarts independently, but doubles installation, supervision, and IPC auth complexity—over-engineered for a local-first single-user dashboard. |

**Decision:** **Approach B (In-process runtime + `bun:sqlite` + optional privileged helper)** delivers crash-safe state, atomic lockdown claiming, and clean SSE/HTMX integration while preserving Basho's single-command `bun run start` ergonomics.

---

## 3. System Architecture & Deep Modules

All new security code lives under `src/security/` with narrow interfaces and injected dependencies (`Clock`, `CommandRunner`, `AiProviderClient`, `HttpFetcher`, `LockdownAdapter`) so every module is unit- and integration-testable without touching the host or network.

```text
                       ┌───────────────────────────────┐
                       │  Hono Routes (/security,      │
                       │  /api/security/*,             │
                       │  /sse/security)               │
                       └──────────────┬────────────────┘
                                      │ narrow runtime interface
                       ┌──────────────▼────────────────┐
                       │       SecurityRuntime         │
                       │  (scheduler, coalescing,      │
                       │   triage, SSE fan-out)        │
                       └───┬──────┬──────┬──────┬──────┘
                           │      │      │      │
          ┌────────────────┘      │      │      └────────────────┐
          ▼                       ▼      ▼                       ▼
┌───────────────────┐  ┌───────────────┐ ┌────────────────┐  ┌────────────────────┐
│ PostureCollector  │  │ EventMonitor  │ │   AiAnalyst    │  │  LockdownEngine    │
│ (ss, ufw, sshd,   │  │ (journald     │ │ (OpenAI SDK +  │  │ (Monitor/Approve/  │
│  sysctl, pacman,  │  │  cursor +     │ │  EvidenceBroker│  │  Auto + DeadMan's  │
│  systemd, lsblk,  │  │  socket diff) │ │  read-only     │  │  Switch + Helper   │
│  tailscale)       │  └───────┬───────┘ │  tool loop)    │  │  Adapter)          │
└─────────┬─────────┘          │         └───────┬────────┘  └─────────┬──────────┘
          │                    │                 │                     │
          └────────────────────┴────────┬────────┴─────────────────────┘
                                        ▼
                       ┌────────────────────────────────┐
                       │  SecurityStore (bun:sqlite)    │
                       │  snapshots, events, findings,  │
                       │  proposals, actions, alerts,   │
                       │  outbox, cursors, overrides    │
                       └────────────────┬───────────────┘
                                        ▼
                       ┌────────────────────────────────┐
                       │    NotificationDispatcher      │
                       │  (ntfy, desktop, discord,      │
                       │   telegram, in-app SSE banner) │
                       └────────────────────────────────┘
```

### Module Interfaces & Responsibilities

1. **`src/security/config.ts` — Config & Policy Loader**
   - Loads defaults from `config/security.json` (checked into git with safe non-secret defaults) and overlays validated runtime overrides from `SecurityStore` (e.g., checklist criterion toggles, scan interval, active `LockdownMode`).
   - Reads secrets strictly from environment variables (`OPENCODE_API_KEY`, `OPENCODE_BASE_URL`, `BASHO_AUTH_TOKEN`, `BASHO_NTFY_TOKEN`, `BASHO_DISCORD_WEBHOOK`, `BASHO_TELEGRAM_BOT_TOKEN`, `BASHO_TELEGRAM_CHAT_ID`). Never persists secrets to SQLite or returns them in HTML/JSON responses.
2. **`src/security/runner.ts` — Safe Command Runner Seam**
   - Executes only fixed executable names/arguments via `Bun.spawn` (never `sh -c` with interpolated data), with per-command timeouts (default `5s`), bounded stdout/stderr caps (`256 KiB`), and a minimal sanitized environment.
3. **`src/security/collector.ts` — `PostureCollector` & `ExposureEntry` Builder**
   - Deterministic, unprivileged Linux/Omarchy checklist collector with stable criterion IDs:
     - `firewall_ufw`: UFW active, default policies, IPv4 & IPv6 rule extraction (`/etc/ufw/user.rules`, `/etc/ufw/user6.rules`, `/etc/default/ufw`), unused open rules.
     - `network_exposure`: Parses `ss -tulnp` + UFW rules + `tailscale serve status` / `tailscale funnel status` into typed `ExposureEntry` rows classified as `exposed_v4_v6`, `exposed_lan`, `tailnet`, `blocked_by_ufw`, `local_only`, or `unknown`. Compares against configured expected ports.
     - `ssh_hardening`: Parses `/etc/ssh/sshd_config` + `/etc/ssh/sshd_config.d/*.conf` (`PasswordAuthentication`, `PermitRootLogin`, `KbdInteractiveAuthentication`) and whether port `22` is open beyond `tailscale0`.
     - `package_updates`: Checks cached/non-mutating update state (`checkupdates` when present, last upgrade timestamp in `/var/log/pacman.log`, flags pending `linux-*` kernel updates or stale upgrades > 14 days; optional `arch-audit` if installed).
     - `disk_and_boot`: `lsblk -J` (LUKS root encryption + unencrypted secondary volumes) and `bootctl status` (Secure Boot / TPM2).
     - `kernel_sysctl`: Reads key sysctl values (`kernel.kptr_restrict`, `kernel.dmesg_restrict`, `kernel.unprivileged_bpf_disabled`, `kernel.yama.ptrace_scope`, `kernel.kexec_load_disabled`, `fs.suid_dumpable`, `net.ipv4.conf.all.rp_filter`, `accept_redirects`).
     - `systemd_health`: `systemctl --failed` and `systemctl --user --failed` counts + Snapper/Limine health signals.
     - `process_and_timers`: Active user systemd timers, non-standard listening processes, and user workload inventory (strictly sanitized — no env vars or sensitive file paths).
   - Every criterion returns `{ id, category, title, status: "pass" | "warn" | "fail" | "unknown" | "disabled", summary, remediation?, evidenceIds, sourceCoverage }`.
4. **`src/security/events.ts` — `EventMonitor` (Live Journal & Socket Drift)**
   - Polls/streams `journalctl -o json` resuming from a durable SQLite cursor (`--after-cursor`) with bounded replay on startup (max 200 records) so restarts neither miss bursts nor flood the DB.
   - Polls `ss -tlpn` snapshots every 30s to emit `new_listener` / `listener_closed` events when a new non-loopback port appears.
   - **Noise filtering & aggregation:** Classifies benign multicast noise (IGMP `224.0.0.1`, IPv6 link-local `ff02::1`, loopback probes) with `isNoise: true` so the UI hides noise by default while reporting the suppressed count. Collapses identical bursts within a sliding window into aggregated `SecurityEvent` counts.
   - **Deterministic breach/triage triggers:** High-signal patterns (e.g., `>= 5` remote SSH auth failures within 5 min from a non-tailnet IP, unexpected `0.0.0.0` listener on an open UFW port, critical systemd/OOM/sudo anomaly) emit a `SecurityAlert` and trigger an immediate rate-limited AI fast-triage scan.
5. **`src/security/ai-analyst.ts` — `AiAnalyst` & `EvidenceBroker`**
   - Uses the official `openai` npm package:
     ```ts
     new OpenAI({
       apiKey: config.apiKey,
       baseURL: config.baseURL, // default: "https://opencode.ai/zen/go/v1", configurable (e.g. https://opencode.ai/inference/go/openai/v1)
       timeout: 12_000,
       maxRetries: 0,
       defaultHeaders: {
         "User-Agent": "basho-security-analyst/1.0",
         "x-opencode-session": scanSessionId,
       },
     });
     ```
   - **Bounded Agentic Tool-Calling Loop:**
     - Overall scan deadline: `45s`; max tool rounds: `3`; max total tool calls: `6`; final tool-free JSON verdict turn; per-tool response cap: `4 KiB`; estimated input cap: `12,000` tokens; completion cap: `1,500` tokens.
     - Advertises closed-schema read-only investigation tools (`additionalProperties: false`, validated locally before dispatch):
       - `read_posture_detail({ criterionId })`
       - `read_listener_detail({ listenerId })` (only IDs present in this scan's evidence registry)
       - `read_recent_events({ category, windowMinutes, limit })` (projected structured fields only, never raw log dumps)
       - `read_process_summary({ pid })` (only PIDs referenced by current scan listeners/anomalies; returns comm, uid, startedAt, sanitized executable basename, parent comm — NEVER `/proc/<pid>/environ`, `.env`, `.ssh/*`, or secret arguments)
       - `read_unit_status({ unitName, scope })` (validated systemd unit name regex; returns ActiveState, SubState, Result, ExecMainStatus)
     - **Prompt-Injection Defense:** System prompt explicitly marks all evidence fields as untrusted telemetry. Every `SecurityFinding` and `LockdownProposal` returned in the final JSON verdict is schema-validated locally; unknown evidence IDs, unknown action types, or invalid targets are discarded and logged in the `InvestigationTrail`.
   - **Graceful Degradation:** Missing `OPENCODE_API_KEY` → status `unconfigured`; HTTP 429/timeout/network failure → status `offline` with sanitized reason and bounded backoff (`Retry-After` honored). Deterministic posture, exposure, and events always continue uninterrupted.
6. **`src/security/lockdown.ts` — `LockdownEngine` & `DeadMansSwitch`**
   - Three modes (`LockdownMode`):
     - `monitor`: Logs findings and sends alerts; never queues or executes containment.
     - `approve` (default): Queues eligible `LockdownProposal` entries (with 30-min default expiry, revision, evidence IDs, and rollback preview) for operator approval/rejection in the UI.
     - `auto-lockdown`: Automatically executes eligible proposals **only when** ALL of the following hold:
       1. Validated AI `breach` verdict with confidence `>= 0.85` (configurable threshold), AND
       2. Fresh, independent deterministic corroboration (e.g., active remote SSH auth failure burst from that exact non-protected IP, or active unexpected enrolled workload process), AND
       3. Target passes the `DeadMansSwitch` check, AND
       4. Required adapter (user-space enrolled workload controller or installed privileged helper) is available and reports rollback readiness. Otherwise, falls back to `approve` queue + urgent alert.
   - **Closed Typed Action Allowlist:**
     1. `pause_workload`: Stops/pauses an explicitly enrolled user-space service/process (verified PID + start time + enrolled workload ID; bounded lease + one-click resume).
     2. `deny_peer_ip`: Invokes `scripts/basho-lockdown-helper.sh deny-ip <canonical-ip> <ttl-seconds>` to insert a temporary UFW deny rule for a single external/LAN attacker IP, with helper-owned expiry timer and rollback ID.
     3. `isolate_lan_ingress`: Invokes `scripts/basho-lockdown-helper.sh isolate-lan <ttl-seconds>` to temporarily remove/deny enrolled LAN service ingress ports (e.g., `8188`, `7000`, `3000`) while strictly preserving `lo`, `tailscale0`, and Tailscale's underlying UDP/41641 + established outbound path.
   - **Hard `DeadMansSwitch` Protected Set (enforced in Basho AND independently inside `scripts/basho-lockdown-helper.sh`):**
     - Never blocks/alters `lo`, `127.0.0.0/8`, `::1`, `tailscale0`, `100.64.0.0/10` (CGNAT/Tailnet), `fd7a:115c:a1e0::/48` (Tailnet IPv6), or Tailscale transport (`udp/41641`).
     - Never terminates PID 1, `systemd*`, `basho`, `tailscaled`, `sshd`, `NetworkManager`, `dbus*`, or Wayland/compositor processes (`hyprland`, `sddm`, `wayland-*`).
   - **Atomic Execution & Recovery:** Claims proposals transactionally in SQLite with an `idempotencyKey`, persists `LockdownAction` as `pending` before calling the adapter, updates to `active`/`failed` after, and supports one-click **Rollback / Unlock** in the UI plus automatic lease expiry.
7. **`src/security/notifications.ts` — `NotificationDispatcher`**
   - Persists `SecurityAlert` + per-channel outbox rows transactionally in SQLite.
   - Deduplicates by stable `fingerprint` (`category:rule:target`) over a configurable cooldown (default `15m`), allowing immediate bypass if severity escalates (e.g., `warning` → `breach`).
   - **Adapters:**
     - `in-app`: Committed alert pushed over `/sse/security` to render a sticky dismissible alert banner with jump link to the pending `LockdownProposal`.
     - `ntfy`: HTTP POST to configured Tailscale/self-hosted or public `ntfy` topic URL (e.g., `http://flux.tailnet.ts.net:8091/basho-security`) with `Title`, `Priority` (`urgent`/`high`/`default`), `Tags`, optional `Authorization: Bearer <BASHO_NTFY_TOKEN>`, and `Click` deep link to Basho's `/security` URL (no auth tokens in URLs, redirects disabled).
     - `desktop`: Fixed-arg `notify-send` (`--urgency`, `--app-name=Basho`, summary, body) when available.
     - `discord`: Discord webhook JSON embed (`BASHO_DISCORD_WEBHOOK`).
     - `telegram`: Telegram Bot `sendMessage` API (`BASHO_TELEGRAM_BOT_TOKEN` + `BASHO_TELEGRAM_CHAT_ID`).
   - Exposes per-channel health & last delivery status in the UI + a **"Send Test Alert"** button.
8. **`src/security/store.ts` — `SecurityStore` (`bun:sqlite`)**
   - Stored in `data/basho-security.db` (path configurable via `BASHO_SECURITY_DB`, directory gitignored & `0700`).
   - Tables: `schema_migrations`, `scans`, `posture_checks`, `exposure_entries`, `findings`, `investigation_steps`, `security_events`, `source_cursors`, `lockdown_proposals`, `lockdown_actions`, `security_alerts`, `alert_deliveries`, `runtime_settings`.
   - Retention pruning: keeps last 50 scans, 14 days of `security_events`, and 90 days of `lockdown_actions` audit rows.
9. **`src/security/demo.ts` — Isolated Non-Sensitive Demo Mode (`BASHO_DEMO_SECURITY=1`)**
   - Returns deterministic, realistic, 100% fictional fixtures (host `lab-node-01`, RFC 5737 IPs `198.51.100.42` / `203.0.113.19`, RFC 3849 IPv6 `2001:db8::10`, synthetic services & alerts, simulated Scan / Approve / Rollback) while disabling all real command execution, AI API calls, notification sends, and lockdown adapters. Used to capture safe README screenshots with zero real host data.

---

## 4. UI & UX Design (3rd Tab: `/security`)

Matches Basho's OpenCode Dark/Light design tokens (`oc-panel`, `font-mono`, `tabular-nums`, DaisyUI 5, HTMX partial swaps, zero-dependency SVG charts):

- **Bottom Navbar (`src/templates/app.tsx`):** Upgraded from `grid-cols-2` to `grid-cols-3`: **Resources** (`/`) · **Services** (`/services`) · **Security** (`/security`), with a subtle status dot on the Security icon when unread alerts or pending proposals exist.
- **Sticky Breach/Alert Banner (top of Security tab, SSE-updated):** Appears immediately on active `critical`/`breach` alerts or pending `LockdownProposal`s, with severity badge, summary, and direct action button.
- **Quick Telemetry Strip (4 `oc-panel` KPI tiles):**
  1. `POSTURE` (`HEALTHY` / `WARN` / `BREACH` + finding counts)
  2. `EXPOSURE` (`N UFW-OPEN` + `M LAN-BOUND`)
  3. `UPDATES` (`N PENDING` + kernel badge)
  4. `ALERTS 24H` (noise-filtered count + AI status pill `READY` / `UNCONFIGURED` / `OFFLINE`)
- **Control Bar:**
  - `LockdownMode` selector (`Monitor` | `Approve` | `Auto-Lockdown`)
  - AI Scan status + next scheduled run countdown + **`Scan Now`** HTMX button
  - **`Test Alert`** button + collapsible **Criteria & Schedule** settings panel (toggle checklist rules, change scan interval)
- **Pending & Active Lockdown Card (`// Containment & Dead-Man's Switch`):**
  - Displays protected-path indicator (`lo + tailscale0 PROTECTED`), helper availability badge (`Helper: Ready` / `Helper: User-space only`), queued `LockdownProposal` cards with evidence tags + **`Approve`** / **`Reject`** buttons, active leases with countdown + **`Unlock / Rollback`**, and recent audit history.
- **Network Exposure Matrix (`// Listening & Firewall`):**
  - Filterable by reachability badge (`Exposed v4+v6`, `Exposed LAN`, `Tailnet`, `Blocked`, `Local`) and search input.
- **AI Investigation & Posture Audit (`// Checklist & AI Findings`):**
  - Shows AI executive verdict, checklist pass/warn/fail rows with expandable plain-English remediation commands, AI investigative findings with linked evidence IDs, and an expandable **`Investigation Trail`** showing the exact read-only tools the AI called and why.
- **Live Security Event Stream (`// Events & 24h Activity`):**
  - Reuses Basho's zero-dependency SVG sparkline (`24h` hourly event volume) + category filter chips (`All`, `Auth`, `Firewall`, `Network`, `Units`, `Packages`) + **`Hide noise`** toggle (ON by default, showing `N benign multicast drops hidden`).

---

## 5. Basho Self-Hygiene, Security & Scanner Fix

1. **Stop `sshd` log spam (`src/services/scanner.ts`):** Skip TCP connect-probing port `22` (inspect local listener table via `ss -tlpn` or exclude port `22` from active TCP connect probes in `scanner.ts`) so Basho never triggers `sshd-session [preauth]` warnings.
2. **Configurable Bind & Optional Auth (`src/main.ts`, `src/security/auth.ts`):**
   - `BASHO_HOST` (default `0.0.0.0` to preserve existing LAN mobile access, or `127.0.0.1` when running strictly behind `tailscale serve`) and `BASHO_PORT` (default `6969`).
   - When `BASHO_AUTH_TOKEN` is set: API routes accept `Authorization: Bearer <token>`, browser users authenticate once via a minimal `/security/login` form setting an `HttpOnly; SameSite=Lax` signed session cookie (so HTMX + SSE work without tokens in URLs).
   - Security mutation endpoints (`POST /security/*`) enforce same-origin `Origin`/`Referer` + CSRF token verification, and security endpoints NEVER send `Access-Control-Allow-Origin: *`.
   - Remote (non-loopback) requests to mutating security actions require `BASHO_AUTH_TOKEN` to be configured (fail closed if an unauthenticated remote client attempts to change lockdown mode or approve containment).

---

## 6. Testing & Verification Strategy

- Establish `bun test` suite (`package.json` `"test": "bun test"`):
  - **Collector & Exposure unit tests:** IPv4 + IPv6 UFW rule parsing, `ss -tlpn` correlation, Tailscale Serve/Funnel matching, SSH config parsing, missing-tool `unknown` coverage.
  - **Event monitor tests:** Journald JSON parsing, cursor resume & bounded replay, multicast noise filtering, SSH failure burst aggregation, listener drift detection.
  - **AI analyst tests:** OpenAI SDK adapter with mocked HTTP/client, multi-turn read-only tool loop, strict tool argument validation, prompt-injection / unknown evidence ID rejection, missing key (`unconfigured`), 429/timeout (`offline`).
  - **Lockdown & Dead-Man's-Switch tests:** Mode rules (`monitor`/`approve`/`auto-lockdown`), corroboration requirement, protected target refusal (`127.0.0.1`, `::1`, `tailscale0`, `100.64.0.0/10`, `sshd`, `basho`, `tailscaled`), atomic proposal claiming, expiry, rollback, and `scripts/basho-lockdown-helper.sh` unit tests with mocked `ufw`.
  - **Notifications tests:** Outbox persistence, cooldown dedupe, severity escalation bypass, `ntfy`/Discord/Telegram/`notify-send` payload formatting (verifying no secrets/tokens leak in URLs or payloads).
  - **Routes, HTMX, SSE, Auth & Scanner tests:** Full-page & HTMX partial rendering for `/security`, SSE stream lifecycle & HTML escaping, CSRF/auth enforcement, and verifying `scanner.ts` no longer connects to port `22`.
- **Non-Sensitive Screenshots & README:**
  - Start Basho with `BASHO_DEMO_SECURITY=1` on a temporary local port, capture desktop & mobile screenshots (dark theme + light theme if helpful) of the Security tab using headless browser / preview, inspect every screenshot to verify zero real host details appear, save under `docs/screenshots/`, and update `README.md`.

---

## 7. Assumptions & Open Notes for Gate 1

1. **OpenCode Go Endpoint:** Default `baseURL` is `https://opencode.ai/zen/go/v1` with `x-opencode-session` header support, overridable via `config/security.json` or `OPENCODE_BASE_URL` (e.g., `https://opencode.ai/inference/go/openai/v1` or local OpenAI-compatible server) so it works across OpenCode Console endpoint revisions.
2. **Default Cadence & Mode:** Scheduled AI scan defaults to every `60` minutes; event-triggered fast triage has a `10`-minute AI cooldown; `LockdownMode` defaults to `approve`.
3. **Host Safety:** Running Basho tests and generating README screenshots will NEVER execute real firewall mutations or modify your live host `ufw` rules; the privileged helper (`scripts/basho-lockdown-helper.sh`) is shipped with installation instructions for explicit operator opt-in.
4. **Remote Access & Auth:** Mutating `/security` endpoints from a non-loopback IP (e.g., phone over Tailscale) requires setting `BASHO_AUTH_TOKEN` so an unauthenticated LAN peer cannot trigger or approve lockdowns.
