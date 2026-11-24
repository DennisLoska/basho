import type { Child } from "hono/jsx";

export interface SecurityDotState {
  active: boolean;
  severity?: "breach" | "critical" | "warning" | "info";
  count?: number;
}

export interface AppProps {
  children: Child;
  title?: string;
  securityDot?: SecurityDotState | boolean;
}

function normalizeDotState(input?: SecurityDotState | boolean): SecurityDotState {
  if (typeof input === "boolean") {
    return { active: input, severity: input ? "warning" : undefined };
  }
  return input ?? { active: false };
}

export const SecurityNavDot = ({
  state,
  oob = false,
}: {
  state?: SecurityDotState | boolean;
  oob?: boolean;
}) => {
  const dot = normalizeDotState(state);
  const colorClass =
    dot.severity === "breach" || dot.severity === "critical"
      ? "bg-error ring-2 ring-error/30 animate-pulse"
      : dot.severity === "warning"
        ? "bg-warning ring-2 ring-warning/30"
        : "bg-info ring-2 ring-info/30";
  const count = dot.count ?? 0;
  const label = dot.active
    ? count > 0
      ? `${count} active security ${count === 1 ? "item" : "items"} requiring attention`
      : "Security attention required"
    : "Security status clear";

  return (
    <span
      id="security-nav-dot"
      {...(oob ? { "hx-swap-oob": "outerHTML" } : {})}
      data-active={dot.active ? "true" : "false"}
      class={
        dot.active
          ? `absolute -top-0.5 -right-1.5 inline-block w-2 h-2 rounded-full ${colorClass}`
          : "sr-only"
      }
      title={label}
    >
      <span class="sr-only">{label}</span>
    </span>
  );
};

export const App = ({ children, title = "Resources", securityDot }: AppProps) => {
  const normalizedTitle = title.trim().toLowerCase();
  const isServices = normalizedTitle === "services";
  const isSecurity =
    normalizedTitle === "security" || normalizedTitle === "security login";
  const isResources = !isServices && !isSecurity;

  return (
    <div class="min-h-dvh bg-base-100 oc-backdrop flex flex-col">
      {/* Compact OpenCode Top Status Bar */}
      <header class="sticky top-0 z-40 h-13 border-b border-base-300 bg-base-200/90 backdrop-blur-md px-3 sm:px-6">
        <div class="max-w-7xl mx-auto h-full flex items-center justify-between gap-2">
          <div class="flex items-center gap-2 sm:gap-3 min-w-0">
            <a
              href="/"
              hx-get="/"
              hx-target="#content"
              hx-swap="innerHTML"
              hx-push-url="true"
              class="flex items-center gap-2 group shrink-0 focus:outline-none"
            >
              <span class="inline-flex items-center justify-center w-7 h-7 rounded bg-primary/15 border border-primary/40 text-primary text-sm font-mono font-bold group-hover:bg-primary/25 transition-colors">
                ⚡
              </span>
              <span class="font-mono font-bold tracking-tight text-sm sm:text-base text-base-content">
                basho
              </span>
            </a>

            <span class="text-base-content/30 font-mono text-sm select-none">
              /
            </span>

            <h1
              id="header-title"
              class="font-mono text-xs sm:text-sm font-semibold uppercase tracking-wider text-primary truncate"
            >
              {title}
            </h1>
          </div>

          <div class="flex items-center gap-2 shrink-0">
            <div
              id="telemetry-pill"
              class="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-base-300/70 border border-base-300 font-mono text-[11px] text-base-content/75"
            >
              <span
                id="telemetry-dot"
                class="w-1.5 h-1.5 rounded-full bg-success animate-pulse"
              />
              <span id="telemetry-label" class="hidden xs:inline sm:inline">
                LIVE
              </span>
            </div>

            <button
              id="theme-toggle"
              type="button"
              aria-label="Toggle color theme"
              title="Toggle theme"
              class="inline-flex items-center justify-center w-8 h-8 rounded bg-base-300/60 hover:bg-base-300 border border-base-300 text-base-content/80 hover:text-primary transition-colors cursor-pointer touch-manipulation"
              onclick="toggleTheme()"
            >
              <svg
                id="theme-icon-sun"
                xmlns="http://www.w3.org/2000/svg"
                class="h-4 w-4"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width={2}
                  d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
                />
              </svg>
              <svg
                id="theme-icon-moon"
                class="h-4 w-4 hidden"
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width={2}
                  d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
                />
              </svg>
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main class="flex-1 w-full max-w-7xl mx-auto px-3 sm:px-6 pt-3 sm:pt-5 pb-safe-nav">
        <div id="content" class="w-full">
          {children}
        </div>
      </main>

      {/* Fixed Mobile-First Bottom Navbar */}
      <nav
        id="bottom-nav"
        aria-label="Primary Navigation"
        class="fixed bottom-0 inset-x-0 z-50 bg-base-200/95 backdrop-blur-xl border-t border-base-300 bottom-nav-safe shadow-[0_-8px_30px_rgba(0,0,0,0.45)]"
      >
        <div class="max-w-md mx-auto grid grid-cols-3 h-15 px-2 gap-1.5 items-center">
          <a
            href="/"
            hx-get="/"
            hx-target="#content"
            hx-swap="innerHTML"
            hx-push-url="true"
            data-nav-path="/"
            aria-current={isResources ? "page" : undefined}
            class={`oc-nav-item flex flex-col items-center justify-center h-12 rounded-md font-mono text-xs font-medium tracking-wide select-none touch-manipulation ${
              isResources ? "active" : ""
            }`}
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              class="h-5 w-5 mb-0.5"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width={1.8}
                d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"
              />
            </svg>
            <span>Resources</span>
          </a>

          <a
            href="/services"
            hx-get="/services"
            hx-target="#content"
            hx-swap="innerHTML"
            hx-push-url="true"
            data-nav-path="/services"
            aria-current={isServices ? "page" : undefined}
            class={`oc-nav-item flex flex-col items-center justify-center h-12 rounded-md font-mono text-xs font-medium tracking-wide select-none touch-manipulation ${
              isServices ? "active" : ""
            }`}
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              class="h-5 w-5 mb-0.5"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width={1.8}
                d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"
              />
            </svg>
            <span>Services</span>
          </a>

          <a
            href="/security"
            hx-get="/security"
            hx-target="#content"
            hx-swap="innerHTML"
            hx-push-url="true"
            data-nav-path="/security"
            aria-current={isSecurity ? "page" : undefined}
            class={`oc-nav-item flex flex-col items-center justify-center h-12 rounded-md font-mono text-xs font-medium tracking-wide select-none touch-manipulation ${
              isSecurity ? "active" : ""
            }`}
          >
            <span class="relative inline-flex items-center justify-center mb-0.5">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                class="h-5 w-5"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width={1.8}
                  d="M12 3l7 4v5c0 4.5-3 8-7 9-4-1-7-4.5-7-9V7l7-4z"
                />
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width={1.8}
                  d="M9.5 12l1.75 1.75L14.75 10"
                />
              </svg>
              <SecurityNavDot state={securityDot} />
            </span>
            <span>Security</span>
          </a>
        </div>
      </nav>
    </div>
  );
};
