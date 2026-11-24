# Structured evidence at the AI trust boundary

Host logs, process names, and network peer metadata are attacker-controlled inputs that can contain prompt injections designed to exfiltrate secrets or trigger false lockdowns. Basho never sends raw logs, environment variables, or arbitrary files to the AI provider; instead, an evidence broker projects deterministic typed facts with opaque evidence IDs, exposes only closed-schema read-only investigation tools, and prevents AI output from authorizing containment without independent deterministic corroboration.

**Considered Options:**
- Feed raw `journalctl` output and allow shell-execution tools for the AI: rejected because untrusted log entries could hijack tool calls or leak `.env`/`.ssh` secrets to an external endpoint.
- Deterministic rules only (no AI investigation): rejected because the operator explicitly wants scheduled and event-driven AI investigation across a checklist plus suspicious leads.

**Consequences:**
- Every AI `SecurityFinding` and `LockdownProposal` is validated locally against evidence IDs issued during that `SecurityScan`; unrecognized IDs or malformed outputs are discarded safely.
- Deterministic monitoring, exposure mapping, and alerting remain fully functional even when the AI provider is unconfigured or offline.
