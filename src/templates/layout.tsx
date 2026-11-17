import type { Child } from "hono/jsx";
import { html } from "hono/html";

export const Layout = ({ children }: { children: Child }) => (
  <html lang="en" data-theme="opencode">
    <head>
      <meta charset="UTF-8" />
      <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0, maximum-scale=5.0, viewport-fit=cover"
      />
      <meta name="theme-color" content="#09090b" id="meta-theme-color" />
      <meta name="apple-mobile-web-app-capable" content="yes" />
      <meta
        name="apple-mobile-web-app-status-bar-style"
        content="black-translucent"
      />
      <title>Basho // System Monitor</title>
      <link rel="icon" type="image/svg+xml" href="/static/favicon.svg" />
      <link href="/static/style.css" rel="stylesheet" />
      {html`
        <script>
          (function() {
            try {
              var saved = localStorage.getItem('basho-theme') || sessionStorage.getItem('basho-theme');
              if (saved === 'bumblebee') saved = 'opencode-light';
              if (saved === 'dracula') saved = 'opencode';
              if (saved) document.documentElement.setAttribute('data-theme', saved);
            } catch (e) {}
          })();
        </script>
      `}
      <script src="/static/htmx.min.js"></script>
      <script src="/static/htmx-ext-sse.min.js"></script>
      <script defer src="/static/handlers.js"></script>
    </head>
    <body class="min-h-dvh bg-base-100 text-base-content antialiased selection:bg-primary/25 selection:text-primary">
      {children}
    </body>
  </html>
);
