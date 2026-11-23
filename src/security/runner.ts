import type { CommandRequest, CommandResult, CommandRunner } from "./types";

const TRUSTED_SEARCH_PATH =
  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

const MAX_OUTPUT_BYTES = 256 * 1024;
const COMMAND_TIMEOUT_MS = 5_000;
const DEFAULT_PAGE_SETTLE_MS = 50;
const POST_EXIT_DRAIN_MS = 50;
const EARLY_STOP_REAP_GRACE_MS = 150;
const MAX_CURSOR_LENGTH = 512;
const MAX_JOURNAL_LIMIT = 1_000;

const SYSTEMD_UNIT_PATTERN = /^[A-Za-z0-9_@.:-]{1,128}$/;
const SYSTEMD_UNIT_SUFFIXES = [
  ".service",
  ".socket",
  ".device",
  ".mount",
  ".automount",
  ".swap",
  ".target",
  ".path",
  ".timer",
  ".slice",
  ".scope",
] as const;

const JOURNAL_CURSOR_PATTERN = /^[A-Za-z0-9=;_:.,-]{1,512}$/;

const EXPIRED_JOURNAL_CURSOR_PATTERNS = [
  /failed to seek to cursor/i,
  /cannot seek.*cursor/i,
  /cursor.*(?:not found|expired|cannot seek|invalid)/i,
  /(?:invalid|expired|missing)\s+cursor/i,
] as const;

function isExpiredJournalCursorStderr(stderr: string): boolean {
  return EXPIRED_JOURNAL_CURSOR_PATTERNS.some((pattern) => pattern.test(stderr));
}

const USER_RUNTIME_ENV_KEYS = [
  "XDG_RUNTIME_DIR",
  "DBUS_SESSION_BUS_ADDRESS",
  "DISPLAY",
  "WAYLAND_DISPLAY",
  "XAUTHORITY",
] as const;

const SYSCTL_KEYS = [
  "kernel.kptr_restrict",
  "kernel.dmesg_restrict",
  "kernel.unprivileged_bpf_disabled",
  "kernel.yama.ptrace_scope",
  "kernel.kexec_load_disabled",
  "fs.suid_dumpable",
  "net.ipv4.conf.all.rp_filter",
  "net.ipv4.conf.all.accept_redirects",
  "net.ipv6.conf.all.accept_redirects",
] as const;

export function isValidSystemdUnitName(name: string): boolean {
  if (!SYSTEMD_UNIT_PATTERN.test(name)) return false;
  if (name.startsWith("-") || name.includes("..")) return false;
  const suffix = SYSTEMD_UNIT_SUFFIXES.find((ext) => name.endsWith(ext));
  if (!suffix) return false;
  return name.length > suffix.length;
}

export function isValidJournalCursor(cursor: string): boolean {
  if (cursor.length === 0 || cursor.length > MAX_CURSOR_LENGTH) return false;
  if (cursor.startsWith("-")) return false;
  return JOURNAL_CURSOR_PATTERN.test(cursor);
}

async function readBoundedStream(
  stream: ReadableStream<Uint8Array>,
  max: number,
  registerCancel?: (cancel: () => void) => void,
): Promise<{ text: string; complete: boolean }> {
  if (!Number.isInteger(max) || max < 0) {
    throw new RangeError("max must be a non-negative integer");
  }
  const reader = stream.getReader();
  let canceled = false;
  const cancel = () => {
    if (canceled) return;
    canceled = true;
    try {
      void reader.cancel().catch(() => {});
    } catch {
      // Ignore cancel errors so they never mask the caller's error.
    }
  };
  registerCancel?.(cancel);

  const decoder = new TextDecoder();
  let bytes = 0;
  let text = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return { text: text + decoder.decode(), complete: !canceled };
      bytes += value.byteLength;
      if (bytes > max) {
        cancel();
        throw new Error("output limit");
      }
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    canceled = true;
    reader.releaseLock();
  }
}

export function readBounded(
  stream: ReadableStream<Uint8Array>,
  max: number,
): Promise<string> {
  return readBoundedStream(stream, max).then((res) => res.text);
}

async function readBoundedJsonLines(
  stream: ReadableStream<Uint8Array>,
  maxBytes: number,
  maxLines: number,
  onLimitReached: () => void,
  registerCancel?: (cancel: () => void) => void,
  pageSettleMs: number = DEFAULT_PAGE_SETTLE_MS,
): Promise<{ text: string; reachedLimit: boolean; complete: boolean }> {
  if (!Number.isFinite(pageSettleMs) || pageSettleMs < 0) {
    throw new RangeError("pageSettleMs must be a non-negative finite number");
  }
  const reader = stream.getReader();
  let canceled = false;
  let settleTimerId: ReturnType<typeof setTimeout> | undefined;
  let abortSettleWait: (() => void) | undefined;
  const clearSettleTimer = () => {
    if (settleTimerId !== undefined) {
      clearTimeout(settleTimerId);
      settleTimerId = undefined;
    }
  };
  const cancel = () => {
    if (canceled) return;
    canceled = true;
    clearSettleTimer();
    abortSettleWait?.();
    try {
      void reader.cancel().catch(() => {});
    } catch {
      // Ignore cancel errors so they never mask the caller's error.
    }
  };
  registerCancel?.(cancel);

  const decoder = new TextDecoder();
  let bytes = 0;
  let pending = "";
  const lines: string[] = [];
  let reachedLimit = false;
  let settleDeadlineMs: number | undefined;
  try {
    for (;;) {
      if (lines.length >= maxLines) {
        if (settleDeadlineMs === undefined) {
          settleDeadlineMs = performance.now() + pageSettleMs;
        }
        const remainingMs = Math.max(0, settleDeadlineMs - performance.now());
        if (canceled) {
          return { text: lines.join("\n"), reachedLimit, complete: true };
        }
        const readPromise = reader.read();
        type SettleOutcome =
          | { kind: "read"; result: Awaited<typeof readPromise> }
          | { kind: "timeout" }
          | { kind: "canceled" };
        const settleOutcome = await new Promise<SettleOutcome>((resolve, reject) => {
          let settled = false;
          const finish = (outcome: SettleOutcome) => {
            if (settled) return;
            settled = true;
            abortSettleWait = undefined;
            clearSettleTimer();
            resolve(outcome);
          };

          abortSettleWait = () => finish({ kind: "canceled" });
          settleTimerId = setTimeout(() => finish({ kind: "timeout" }), remainingMs);

          readPromise.then(
            (result) => finish({ kind: "read", result }),
            (error) => {
              if (settled) return;
              settled = true;
              abortSettleWait = undefined;
              clearSettleTimer();
              reject(error);
            },
          );
        });

        if (settleOutcome.kind === "canceled") {
          return { text: lines.join("\n"), reachedLimit, complete: true };
        }
        if (settleOutcome.kind === "timeout") {
          reachedLimit = true;
          onLimitReached();
          cancel();
          return { text: lines.join("\n"), reachedLimit, complete: true };
        }
        const { done, value } = settleOutcome.result;
        if (done) {
          pending += decoder.decode();
          return { text: lines.join("\n"), reachedLimit, complete: true };
        }
        if (value.byteLength === 0) {
          if (performance.now() >= settleDeadlineMs) {
            reachedLimit = true;
            onLimitReached();
            cancel();
            return { text: lines.join("\n"), reachedLimit, complete: true };
          }
          continue;
        }
        reachedLimit = true;
        onLimitReached();
        cancel();
        return { text: lines.join("\n"), reachedLimit, complete: true };
      }

      const { done, value } = await reader.read();
      if (done) {
        pending += decoder.decode();
        // Never emit a trailing unterminated/truncated line; only complete newline-delimited records.
        return { text: lines.join("\n"), reachedLimit, complete: !canceled };
      }
      bytes += value.byteLength;
      if (bytes > maxBytes) {
        cancel();
        throw new Error("output limit");
      }
      pending += decoder.decode(value, { stream: true });
      let newlineIdx = pending.indexOf("\n");
      while (newlineIdx !== -1) {
        const line = pending.slice(0, newlineIdx);
        pending = pending.slice(newlineIdx + 1);
        if (line.length > 0) {
          lines.push(line);
          if (lines.length >= maxLines) {
            const hasTrailingBytesInChunk =
              pending.length > 0 ||
              (value.byteLength > 0 && value[value.byteLength - 1] !== 0x0a);
            if (hasTrailingBytesInChunk) {
              reachedLimit = true;
              onLimitReached();
              cancel();
              return { text: lines.join("\n"), reachedLimit, complete: true };
            }
            // Exactly maxLines complete lines arrived with no extra bytes yet:
            // wait up to pageSettleMs for EOF (honoring the child's actual exit code/signal)
            // or an additional byte confirming more records exist.
            break;
          }
        }
        newlineIdx = pending.indexOf("\n");
      }
    }
  } finally {
    canceled = true;
    abortSettleWait = undefined;
    clearSettleTimer();
    try {
      reader.releaseLock();
    } catch {
      // Lock may still have a pending read if stopped on settle timeout/cancel.
    }
  }
}

interface BuiltRecipe {
  argv: string[];
  benignExitCodes: readonly number[];
  includeUserRuntimeEnv: boolean;
  streamLineLimit?: number;
  requireEmptyStderr?: boolean;
  requireEmptyStdoutOnExitCodes?: readonly number[];
}

function buildRecipe(request: CommandRequest): BuiltRecipe {
  switch (request.kind) {
    case "sockets":
      return {
        argv: ["ss", "-tulnp"],
        benignExitCodes: [0],
        includeUserRuntimeEnv: false,
      };
    case "ufw_status":
      return {
        argv: ["ufw", "status"],
        benignExitCodes: [0],
        includeUserRuntimeEnv: false,
      };
    case "tailscale_serve":
      return {
        argv: ["tailscale", "serve", "status", "--json"],
        benignExitCodes: [0],
        includeUserRuntimeEnv: false,
      };
    case "tailscale_funnel":
      return {
        argv: ["tailscale", "funnel", "status", "--json"],
        benignExitCodes: [0],
        includeUserRuntimeEnv: false,
      };
    case "updates":
      return {
        argv: ["pacman", "-Qu"],
        benignExitCodes: [0, 1],
        includeUserRuntimeEnv: false,
        requireEmptyStderr: true,
        requireEmptyStdoutOnExitCodes: [1],
      };
    case "arch_audit":
      return {
        argv: ["arch-audit", "--upgradable"],
        benignExitCodes: [0],
        includeUserRuntimeEnv: false,
      };
    case "block_devices":
      return {
        argv: ["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS"],
        benignExitCodes: [0],
        includeUserRuntimeEnv: false,
      };
    case "boot_status":
      return {
        argv: ["bootctl", "status"],
        benignExitCodes: [0],
        includeUserRuntimeEnv: false,
      };
    case "sysctl":
      return {
        argv: ["sysctl", "-e", ...SYSCTL_KEYS],
        benignExitCodes: [0],
        includeUserRuntimeEnv: false,
      };
    case "system_failed":
      return {
        argv: ["systemctl", "--failed", "--no-legend", "--no-pager", "--plain"],
        benignExitCodes: [0],
        includeUserRuntimeEnv: false,
      };
    case "user_failed":
      return {
        argv: [
          "systemctl",
          "--user",
          "--failed",
          "--no-legend",
          "--no-pager",
          "--plain",
        ],
        benignExitCodes: [0],
        includeUserRuntimeEnv: true,
      };
    case "user_timers":
      return {
        argv: [
          "systemctl",
          "--user",
          "list-timers",
          "--all",
          "--no-legend",
          "--no-pager",
          "--plain",
        ],
        benignExitCodes: [0],
        includeUserRuntimeEnv: true,
      };
    case "processes":
      return {
        argv: ["ps", "-eo", "pid=,ppid=,uid=,etimes=,comm="],
        benignExitCodes: [0],
        includeUserRuntimeEnv: false,
      };
    case "snapper_health":
      return {
        argv: [
          "systemctl",
          "list-units",
          "--all",
          "--no-legend",
          "--no-pager",
          "--plain",
          "snapper*",
        ],
        benignExitCodes: [0],
        includeUserRuntimeEnv: false,
      };
    case "limine_health":
      return {
        argv: [
          "systemctl",
          "list-units",
          "--all",
          "--no-legend",
          "--no-pager",
          "--plain",
          "limine*",
        ],
        benignExitCodes: [0],
        includeUserRuntimeEnv: false,
      };
    case "journal": {
      if (
        !Number.isInteger(request.limit) ||
        request.limit < 1 ||
        request.limit > MAX_JOURNAL_LIMIT
      ) {
        throw new Error(
          `Invalid journal limit: expected integer between 1 and ${MAX_JOURNAL_LIMIT}`,
        );
      }
      if (request.after !== undefined) {
        if (!isValidJournalCursor(request.after)) {
          throw new Error("Invalid journal cursor");
        }
        return {
          argv: [
            "journalctl",
            "--no-pager",
            "-o",
            "json",
            `--after-cursor=${request.after}`,
          ],
          benignExitCodes: [0],
          includeUserRuntimeEnv: false,
          streamLineLimit: request.limit,
        };
      }
      return {
        argv: [
          "journalctl",
          "--no-pager",
          "-o",
          "json",
          `--lines=${request.limit}`,
        ],
        benignExitCodes: [0],
        includeUserRuntimeEnv: false,
      };
    }
    case "unit": {
      if (request.scope !== "system" && request.scope !== "user") {
        throw new Error("Invalid systemd unit scope");
      }
      if (!isValidSystemdUnitName(request.name)) {
        throw new Error("Invalid systemd unit name");
      }
      const argv =
        request.scope === "user"
          ? [
              "systemctl",
              "--user",
              "show",
              "--property=ActiveState,SubState,Result,ExecMainStatus",
              "--no-pager",
              "--",
              request.name,
            ]
          : [
              "systemctl",
              "show",
              "--property=ActiveState,SubState,Result,ExecMainStatus",
              "--no-pager",
              "--",
              request.name,
            ];
      return {
        argv,
        benignExitCodes: [0],
        includeUserRuntimeEnv: request.scope === "user",
      };
    }
    case "desktop": {
      if (request.urgency !== "normal" && request.urgency !== "critical") {
        throw new Error("Invalid desktop notification urgency");
      }
      if (
        typeof request.summary !== "string" ||
        typeof request.body !== "string" ||
        request.summary.includes("\0") ||
        request.body.includes("\0")
      ) {
        throw new Error("Invalid desktop notification text");
      }
      return {
        argv: [
          "notify-send",
          `--urgency=${request.urgency}`,
          "--app-name=Basho",
          "--",
          request.summary,
          request.body,
        ],
        benignExitCodes: [0],
        includeUserRuntimeEnv: true,
      };
    }
  }
}

function buildChildEnv(includeUserRuntimeEnv: boolean): Record<string, string> {
  const env: Record<string, string> = {
    PATH: TRUSTED_SEARCH_PATH,
    LC_ALL: "C",
  };
  if (includeUserRuntimeEnv) {
    for (const key of USER_RUNTIME_ENV_KEYS) {
      const value = process.env[key];
      if (value !== undefined && value !== "") {
        env[key] = value;
      }
    }
  }
  return env;
}

export interface CommandRunnerOptions {
  timeoutMs?: number;
}

export function createCommandRunner(options: CommandRunnerOptions = {}): CommandRunner {
  const timeoutMs = options.timeoutMs ?? COMMAND_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError("timeoutMs must be a positive finite number");
  }

  return {
    async run(request: CommandRequest, signal?: AbortSignal): Promise<CommandResult> {
      const recipe = buildRecipe(request);
      if (signal?.aborted) {
        return { status: "failed" };
      }

      const executableName = recipe.argv[0];
      if (!executableName) {
        return { status: "unavailable" };
      }
      const executable = Bun.which(executableName, { PATH: TRUSTED_SEARCH_PATH });
      if (!executable) {
        return { status: "unavailable" };
      }

      const argv = [executable, ...recipe.argv.slice(1)];
      const env = buildChildEnv(recipe.includeUserRuntimeEnv);
      const useProcessGroup = process.platform !== "win32";

      let proc: ReturnType<typeof Bun.spawn>;
      try {
        proc = Bun.spawn(argv, {
          stdin: "ignore",
          stdout: "pipe",
          stderr: "pipe",
          env,
          ...(useProcessGroup ? { detached: true } : {}),
        });
      } catch {
        return { status: "unavailable" };
      }

      let timedOut = false;
      let aborted = false;
      let overflowed = false;
      let stoppedByLineLimit = false;
      let processExited = false;
      let finished = false;
      let killInitiated = false;
      const cancelCallbacks: Array<() => void> = [];

      const registerCancel = (cancel: () => void) => {
        cancelCallbacks.push(cancel);
      };

      const cancelReaders = () => {
        for (const cancel of cancelCallbacks) {
          cancel();
        }
      };

      const killProcessGroup = (): boolean => {
        if (!useProcessGroup || !Number.isInteger(proc.pid) || proc.pid <= 0) {
          return false;
        }
        try {
          process.kill(-proc.pid, "SIGKILL");
          return true;
        } catch {
          return false;
        }
      };

      const killChild = () => {
        if (killInitiated) return;
        killInitiated = true;
        if (killProcessGroup()) {
          return;
        }
        try {
          proc.kill("SIGKILL");
        } catch {
          // Process may have already exited.
        }
      };

      let resolveTerminate!: () => void;
      const terminatedPromise = new Promise<void>((resolve) => {
        resolveTerminate = resolve;
      });

      let postExitTimer: ReturnType<typeof setTimeout> | undefined;
      const exitedPromise = proc.exited.then(
        (code) => {
          processExited = true;
          if (!finished) {
            // Descendants can hold either pipe open after the direct child exits.
            postExitTimer = setTimeout(() => {
              cancelReaders();
              killProcessGroup();
            }, POST_EXIT_DRAIN_MS);
          }
          return code;
        },
        (err) => {
          processExited = true;
          throw err;
        },
      );

      const terminateEarly = () => {
        cancelReaders();
        killChild();
        resolveTerminate();
      };

      const timeoutId = setTimeout(() => {
        timedOut = true;
        terminateEarly();
      }, timeoutMs);

      const onAbort = () => {
        aborted = true;
        terminateEarly();
      };
      if (signal) {
        signal.addEventListener("abort", onAbort, { once: true });
      }

      const stdoutStream = proc.stdout;
      const stderrStream = proc.stderr;

      const stdoutPromise: Promise<{ text: string; complete: boolean }> =
        stdoutStream && typeof stdoutStream !== "number"
          ? recipe.streamLineLimit !== undefined
            ? readBoundedJsonLines(
                stdoutStream,
                MAX_OUTPUT_BYTES,
                recipe.streamLineLimit,
                () => {
                  if (!processExited && proc.exitCode === null && proc.signalCode === null) {
                    stoppedByLineLimit = true;
                    killChild();
                  }
                  cancelReaders();
                },
                registerCancel,
              )
                .then((res) => ({ text: res.text, complete: res.complete }))
                .catch((err: unknown) => {
                  if (err instanceof Error && err.message === "output limit") {
                    overflowed = true;
                    terminateEarly();
                  }
                  throw err;
                })
            : readBoundedStream(stdoutStream, MAX_OUTPUT_BYTES, registerCancel).catch(
                (err: unknown) => {
                  if (err instanceof Error && err.message === "output limit") {
                    overflowed = true;
                    terminateEarly();
                  }
                  throw err;
                },
              )
          : Promise.resolve({ text: "", complete: true });

      const stderrPromise: Promise<{ text: string; complete: boolean }> =
        stderrStream && typeof stderrStream !== "number"
          ? readBoundedStream(stderrStream, MAX_OUTPUT_BYTES, registerCancel).catch(
              (err: unknown) => {
                if (err instanceof Error && err.message === "output limit") {
                  overflowed = true;
                  terminateEarly();
                }
                throw err;
              },
            )
          : Promise.resolve({ text: "", complete: true });

      if (signal?.aborted) {
        onAbort();
      }

      const stdoutOutcome = stdoutPromise.then(
        (result) => ({ ok: true as const, value: result.text, complete: result.complete }),
        () => ({ ok: false as const }),
      );
      const stderrOutcome = stderrPromise.then(
        (result) => ({ ok: true as const, value: result.text, complete: result.complete }),
        () => ({ ok: false as const }),
      );

      const allDone = Promise.all([stdoutOutcome, stderrOutcome, exitedPromise]).then(
        ([stdoutResult, stderrResult, exitCode]) => ({
          kind: "completed" as const,
          stdoutResult,
          stderrResult,
          exitCode,
        }),
      );
      void allDone.catch(() => {});

      let reapGraceTimer: ReturnType<typeof setTimeout> | undefined;
      const earlyStop = terminatedPromise.then(async () => {
        void exitedPromise.catch(() => {});
        await Promise.race([
          exitedPromise,
          new Promise<void>((resolve) => {
            reapGraceTimer = setTimeout(resolve, EARLY_STOP_REAP_GRACE_MS);
          }),
        ]);
        return { kind: "terminated" as const };
      });

      try {
        const outcome = await Promise.race([allDone, earlyStop]);

        if (overflowed) return { status: "overflow" };
        if (timedOut) return { status: "timeout" };
        if (aborted) return { status: "failed" };

        if (outcome.kind === "terminated") {
          return { status: "failed" };
        }

        const { stdoutResult, stderrResult, exitCode } = outcome;
        const terminatedByLineLimit =
          stoppedByLineLimit &&
          ((proc.signalCode === null && exitCode === 0) || proc.signalCode === "SIGKILL");

        if (terminatedByLineLimit && stdoutResult.ok && stdoutResult.complete && stderrResult.ok) {
          return { status: "ok", stdout: stdoutResult.value, exitCode: 0 };
        }
        if (!stdoutResult.ok || !stdoutResult.complete || !stderrResult.ok) {
          return { status: "failed" };
        }
        if (proc.signalCode === null && recipe.benignExitCodes.includes(exitCode)) {
          if (
            recipe.requireEmptyStderr &&
            (!stderrResult.complete || stderrResult.value.length > 0)
          ) {
            return { status: "failed" };
          }
          if (
            recipe.requireEmptyStdoutOnExitCodes?.includes(exitCode) &&
            stdoutResult.value.length > 0
          ) {
            return { status: "failed" };
          }
          return { status: "ok", stdout: stdoutResult.value, exitCode };
        }
        if (
          request.kind === "journal" &&
          request.after !== undefined &&
          proc.signalCode === null &&
          exitCode !== 0 &&
          isExpiredJournalCursorStderr(stderrResult.value)
        ) {
          return { status: "cursor_expired" };
        }
        return { status: "failed" };
      } finally {
        finished = true;
        clearTimeout(timeoutId);
        clearTimeout(postExitTimer);
        clearTimeout(reapGraceTimer);
        killProcessGroup();
        if (signal) {
          signal.removeEventListener("abort", onAbort);
        }
      }
    },
  };
}
