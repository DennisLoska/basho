import type { CommandRequest, CommandResult, CommandRunner } from "./types";

const TRUSTED_SEARCH_PATH =
  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

const MAX_OUTPUT_BYTES = 256 * 1024;
const COMMAND_TIMEOUT_MS = 5_000;
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
): Promise<string> {
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
      if (done) return text + decoder.decode();
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
  return readBoundedStream(stream, max);
}

async function readBoundedJsonLines(
  stream: ReadableStream<Uint8Array>,
  maxBytes: number,
  maxLines: number,
  onLimitReached: () => void,
  registerCancel?: (cancel: () => void) => void,
): Promise<{ text: string; reachedLimit: boolean }> {
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
  let pending = "";
  const lines: string[] = [];
  let reachedLimit = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        pending += decoder.decode();
        // Never emit a trailing unterminated/truncated line; only complete newline-delimited records.
        return { text: lines.join("\n"), reachedLimit };
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
            reachedLimit = true;
            onLimitReached();
            cancel();
            return { text: lines.join("\n"), reachedLimit };
          }
        }
        newlineIdx = pending.indexOf("\n");
      }
    }
  } finally {
    canceled = true;
    reader.releaseLock();
  }
}

interface BuiltRecipe {
  argv: string[];
  benignExitCodes: readonly number[];
  includeUserRuntimeEnv: boolean;
  streamLineLimit?: number;
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
        argv: ["checkupdates"],
        benignExitCodes: [0, 2],
        includeUserRuntimeEnv: false,
      };
    case "arch_audit":
      return {
        argv: ["arch-audit", "--upgradable"],
        benignExitCodes: [0],
        includeUserRuntimeEnv: false,
      };
    case "block_devices":
      return {
        argv: ["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"],
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

      let proc: ReturnType<typeof Bun.spawn>;
      try {
        proc = Bun.spawn(argv, {
          stdin: "ignore",
          stdout: "pipe",
          stderr: "pipe",
          env,
        });
      } catch {
        return { status: "unavailable" };
      }

      let timedOut = false;
      let aborted = false;
      let overflowed = false;
      let stoppedByLineLimit = false;
      let processExited = false;
      const cancelCallbacks: Array<() => void> = [];

      const registerCancel = (cancel: () => void) => {
        cancelCallbacks.push(cancel);
      };

      const cancelReaders = () => {
        for (const cancel of cancelCallbacks) {
          cancel();
        }
      };

      const killChild = () => {
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

      const exitedPromise = proc.exited.then((code) => {
        processExited = true;
        return code;
      });

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

      const stdoutPromise: Promise<string> =
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
                    cancelReaders();
                  }
                },
                registerCancel,
              )
                .then((res) => res.text)
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
          : Promise.resolve("");

      const stderrPromise: Promise<string> =
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
          : Promise.resolve("");

      if (signal?.aborted) {
        onAbort();
      }

      const stdoutOutcome = stdoutPromise.then(
        (value) => ({ ok: true as const, value }),
        () => ({ ok: false as const }),
      );
      const stderrOutcome = stderrPromise.then(
        () => ({ ok: true as const }),
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

      const earlyStop = terminatedPromise.then(async () => {
        await exitedPromise;
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
          (proc.signalCode === "SIGKILL" || proc.signalCode === "SIGPIPE");

        if (terminatedByLineLimit && stdoutResult.ok) {
          return { status: "ok", stdout: stdoutResult.value, exitCode: 0 };
        }
        if (!stdoutResult.ok || !stderrResult.ok) return { status: "failed" };
        if (recipe.benignExitCodes.includes(exitCode)) {
          return { status: "ok", stdout: stdoutResult.value, exitCode };
        }
        return { status: "failed" };
      } finally {
        clearTimeout(timeoutId);
        if (signal) {
          signal.removeEventListener("abort", onAbort);
        }
      }
    },
  };
}
