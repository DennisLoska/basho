# SQLite for security state

Security monitoring requires atomic coordination across journald cursors, event burst aggregation, scan history, proposal claims with idempotency keys, and notification outbox retries. We store all security runtime state in a private local SQLite database using Bun's built-in `bun:sqlite` in WAL mode rather than flat JSON/JSONL files or an external database server.

**Considered Options:**
- JSON snapshots + append-only JSONL files: rejected because crash-safe cursor checkpoints, atomic proposal claiming, and outbox locking would require fragile custom file-locking logic.
- External Postgres/Redis: rejected to preserve Basho's zero-external-dependency, single-process local-first architecture.

**Consequences:**
- Schema changes use lightweight versioned SQL migrations inside Basho's store module.
- Event history and audit logs enforce bounded retention policies inside SQLite without manual log rotation.
