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

export async function readBounded(
  stream: ReadableStream<Uint8Array>,
  max: number,
): Promise<string> {
  if (!Number.isInteger(max) || max < 0) {
    throw new RangeError("max must be a non-negative integer");
  }
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

async function readBoundedJsonLines(
  stream: ReadableStream<Uint8Array>,
  maxBytes: number,
  maxLines: number,
  onLimitReached: () => void,
): Promise<{ text: string; reachedLimit: boolean }> {
  const reader = stream.getReader();
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
        await reader.cancel();
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
            await reader.cancel();
            onLimitReached();
            return { text: lines.join("\n"), reachedLimit };
          }
        }
        newlineIdx = pending.indexOf("\n");
      }
    }
  } finally {
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

export function createCommandRunner(): CommandRunner {
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
      let stoppedAfterLimit = false;

      const killChild = () => {
        try {
          proc.kill("SIGKILL");
        } catch {
          // Process may have already exited.
        }
      };

      const timeoutId = setTimeout(() => {
        timedOut = true;
        killChild();
      }, COMMAND_TIMEOUT_MS);

      const onAbort = () => {
        aborted = true;
        killChild();
      };
      if (signal) {
        signal.addEventListener("abort", onAbort, { once: true });
        if (signal.aborted) {
          onAbort();
        }
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
                  stoppedAfterLimit = true;
                  killChild();
                },
              )
                .then((res) => res.text)
                .catch((err: unknown) => {
                  if (err instanceof Error && err.message === "output limit") {
                    overflowed = true;
                    killChild();
                  }
                  throw err;
                })
            : readBounded(stdoutStream, MAX_OUTPUT_BYTES).catch((err: unknown) => {
                if (err instanceof Error && err.message === "output limit") {
                  overflowed = true;
                  killChild();
                }
                throw err;
              })
          : Promise.resolve("");

      const stderrPromise: Promise<string> =
        stderrStream && typeof stderrStream !== "number"
          ? readBounded(stderrStream, MAX_OUTPUT_BYTES).catch((err: unknown) => {
              if (err instanceof Error && err.message === "output limit") {
                overflowed = true;
                killChild();
              }
              throw err;
            })
          : Promise.resolve("");

      try {
        const [stdoutResult, stderrResult, exitCode] = await Promise.all([
          stdoutPromise.then(
            (value) => ({ ok: true as const, value }),
            () => ({ ok: false as const }),
          ),
          stderrPromise.then(
            () => ({ ok: true as const }),
            () => ({ ok: false as const }),
          ),
          proc.exited,
        ]);

        if (stoppedAfterLimit && !overflowed && !timedOut && !aborted && stdoutResult.ok) {
          return { status: "ok", stdout: stdoutResult.value, exitCode: 0 };
        }
        if (overflowed) return { status: "overflow" };
        if (timedOut) return { status: "timeout" };
        if (aborted) return { status: "failed" };
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
