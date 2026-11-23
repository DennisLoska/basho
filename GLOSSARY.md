# Basho Security Domain

Domain language for Basho's host security monitoring, AI-assisted investigation, breach alerting, and guardrailed containment subsystem.

## Language

**PostureSnapshot**:
A timestamped evaluation of enabled host security checklist criteria together with typed evidence references and per-source collection coverage.
_Avoid_: System health dump, audit blob

**SecurityEvent**:
A normalized host observation bound to a source, category, severity, and timestamp, optionally aggregating repeated equivalent occurrences into a count.
_Avoid_: Raw log line, breach

**SecurityFinding**:
An evidence-backed security assessment produced either by a deterministic rule or by the AI analyst referencing verified snapshot or event evidence IDs.
_Avoid_: Event, alert, log entry

**ExposureEntry**:
A local listening socket correlated with its bind scope, ordered firewall rules, and Tailscale publication state to classify inferred network reachability.
_Avoid_: Open port, service card

**SecurityScan**:
A single scheduled, manual, or event-triggered run that captures a `PostureSnapshot`, computes `ExposureEntry` records, and optionally executes an AI investigation.
_Avoid_: Audit, cron tick

**InvestigationTrail**:
The bounded, sanitized record of read-only evidence views requested by the AI analyst during a `SecurityScan`, their outcomes, and the evidence IDs cited in findings.
_Avoid_: Prompt transcript, raw chat log

**LockdownMode**:
The operator-selected containment policy (`monitor`, `approve`, or `auto-lockdown`) that determines whether eligible proposals are only reported, queued for approval, or automatically executed.
_Avoid_: AI autonomy level, defense level

**LockdownProposal**:
An expiring, typed containment draft referencing a closed allowlisted action, target, corroborating evidence, preconditions, and rollback description.
_Avoid_: Command, shell script, remediation string

**LockdownAction**:
A recorded execution attempt of an approved or auto-authorized `LockdownProposal`, tracking its idempotency key, outcome, lease expiry, and rollback handle.
_Avoid_: Proposal, mitigation

**DeadMansSwitch**:
The non-bypassable invariant set and recovery checks—enforced in Basho and independently in the privileged helper—that preserve loopback and Tailscale management access and require verified rollback before mutation.
_Avoid_: Safety warning, manual override

**SecurityAlert**:
A deduplicated operator-facing notice of a security condition or containment event persisted alongside its channel delivery outbox.
_Avoid_: Finding, webhook payload

**AlertChannel**:
A server-configured notification destination and delivery adapter (`in-app`, `desktop`, `ntfy`, `discord`, or `telegram`) with independent retry and delivery status tracking.
_Avoid_: Alert, generic webhook

**Corroboration**:
An expiring deterministic signal—linking a rule, supporting `SecurityEvent` IDs, and an optional containment target—that confirms an active threat condition before autonomous containment is eligible.
_Avoid_: AI hunch, raw alert

**EnrolledWorkload**:
An operator-registered host service identified by a unique ID and systemd unit name (with optional display name and expected ports) that Basho monitors and may target for guardrailed containment.
_Avoid_: Arbitrary PID, unmanaged process

**Evidence**:
A typed, immutable host observation identified by a stable ID and structured scalar facts (for a criterion, listener, event, process, or unit) that rules, `SecurityFinding` records, and `LockdownProposal` drafts cite.
_Avoid_: Raw command output, unparsed log blob

**PostureCheck**:
The evaluated result of a single host security checklist criterion inside a `PostureSnapshot`, pairing a status (`pass`, `warn`, `fail`, `unknown`, or `disabled`) with summary, optional remediation, cited `Evidence` IDs, and per-source collection coverage.
_Avoid_: Snapshot, raw scan finding

**Listener**:
A raw local TCP or UDP listening socket observed on the host (address, port, IP family, and optional interface, PID, and process name). Unlike `ExposureEntry`, a `Listener` records only the local bind before firewall or Tailscale reachability correlation.
_Avoid_: ExposureEntry, open port, exposed service

**AiVerdict**:
The single scan-level disposition (`healthy`, `warn`, or `breach`) with confidence score and summary produced by the AI analyst at the end of an investigation. Unlike `SecurityFinding`, which captures an individual evidence-backed issue, `AiVerdict` summarizes the overall host assessment for a `SecurityScan`.
_Avoid_: SecurityFinding, alert, containment decision

**ContainmentTarget**:
A closed, typed union identifying the exact allowlisted subject of a containment operation (`pause_workload`, `deny_peer_ip`, or `isolate_lan_ingress`) referenced by `Corroboration`, `LockdownProposal`, and `LockdownAction`.
_Avoid_: Target string, shell argument, arbitrary host resource
