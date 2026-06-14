#!/usr/bin/env bash
set -euo pipefail

bunx @tailwindcss/cli -i src/templates/app.css -o static/style.css
