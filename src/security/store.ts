import { Database } from "bun:sqlite";
import {
  chmodSync,
  closeSync,
  constants,
  fchmodSync,
  lstatSync,
  mkdirSync,
  openSync,
  type Stats,
} from "node:fs";
import { dirname, resolve } from "node:path";
import type {
  AiVerdict,
  AlertChannel,
  Category,
  ContainmentTarget,
  Coverage,
  CriterionId,
  Evidence,
  EvidenceTool,
  ExposureEntry,
  InvestigationTrail,
  Listener,
  LockdownAction,
  LockdownProposal,
  PostureCheck,
  RuntimeOverrides,
  SecurityAlert,
  SecurityEvent,
  SecurityFinding,
  SecurityScan,
  Severity,
} from "./types";

const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;
const DEFAULT_DB_PATH = "data/basho-security.db";
const BUSY_TIMEOUT_MS = 5_000;
const MAX_RETAINED_SCANS = 50;
const EVENT_RETENTION_DAYS = 14;
const ACTION_RETENTION_DAYS = 90;

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  warning: 1,
  critical: 2,
  breach: 3,
};

export interface EventBatch {
  events: SecurityEvent[];
  cursor?: { source: string; expected: string | null; next: string };
  burstWindowMs: number;
}

export interface AlertDelivery {
  id: string;
  alert: SecurityAlert;
  channel: AlertChannel;
  attempts: number;
  claimToken: string;
}

export interface SecurityStoreContract {
  saveScan(scan: SecurityScan): void;
  latestScan(): SecurityScan | null;
  getCursor(source: string): string | null;
  commitEventBatch(batch: EventBatch): boolean;
  recentEvents(since: number, limit: number, category?: Category): SecurityEvent[];
  hourlyEvents(now: number): { hour: number; signal: number; noise: number }[];
  insertProposal(proposal: LockdownProposal): void;
  listProposals(): LockdownProposal[];
  claimProposal(id: string, revision: number, now: number): LockdownAction | null;
  rejectProposal(id: string, revision: number, now: number): boolean;
  expireProposals(now: number): void;
  listActions(): LockdownAction[];
  transitionAction(
    id: string,
    from: LockdownAction["state"],
    to: LockdownAction["state"],
    now: number,
    rollbackHandle?: string,
  ): boolean;
  enqueueAlert(alert: SecurityAlert, channels: AlertChannel[], cooldownMs: number): boolean;
  claimDeliveries(now: number, limit: number, leaseMs: number): AlertDelivery[];
  settleDelivery(
    id: string,
    claimToken: string,
    now: number,
    result: "sent" | "failed" | { retryAt: number },
  ): boolean;
  recentAlerts(since: number): SecurityAlert[];
  dismissAlert(id: string, now: number): boolean;
  channelHealth(): Partial<
    Record<AlertChannel, { status: "sent" | "failed" | "retrying"; at: number }>
  >;
  readOverrides(): RuntimeOverrides;
  writeOverrides(overrides: RuntimeOverrides): void;
  prune(now: number): void;
  close(): void;
}

function lstatIfExists(path: string): Stats | null {
  try {
    return lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

function ensurePrivateDatabasePath(dbPath: string): void {
  const resolvedDbPath = resolve(dbPath);
  const parentDir = dirname(resolvedDbPath);
  const dirsToCreate: string[] = [];
  let cursor = parentDir;

  while (lstatIfExists(cursor) === null) {
    dirsToCreate.push(cursor);
    const next = dirname(cursor);
    if (next === cursor) break;
    cursor = next;
  }

  for (let index = dirsToCreate.length - 1; index >= 0; index -= 1) {
    const dir = dirsToCreate[index]!;
    try {
      mkdirSync(dir, { mode: 0o700 });
      chmodSync(dir, 0o700);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
        throw error;
      }
    }
  }

  const dirStat = lstatSync(parentDir);
  if (dirStat.isSymbolicLink()) {
    throw new Error(`SecurityStore state directory must not be a symbolic link: ${parentDir}`);
  }
  if (!dirStat.isDirectory()) {
    throw new Error(`SecurityStore state path is not a directory: ${parentDir}`);
  }
  if ((dirStat.mode & 0o077) !== 0) {
    const modeOctal = (dirStat.mode & 0o7777).toString(8).padStart(4, "0");
    throw new Error(
      `SecurityStore requires a private state directory (0700): ${parentDir} has mode ${modeOctal}`,
    );
  }

  const existingDbStat = lstatIfExists(resolvedDbPath);
  if (existingDbStat?.isSymbolicLink()) {
    throw new Error(`SecurityStore database path must not be a symbolic link: ${resolvedDbPath}`);
  }

  if (existingDbStat === null) {
    try {
      const fd = openSync(
        resolvedDbPath,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
        0o600,
      );
      try {
        fchmodSync(fd, 0o600);
      } finally {
        closeSync(fd);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
        throw error;
      }
    }
  }

  const fileStat = lstatSync(resolvedDbPath);
  if (fileStat.isSymbolicLink()) {
    throw new Error(`SecurityStore database path must not be a symbolic link: ${resolvedDbPath}`);
  }
  if (!fileStat.isFile()) {
    throw new Error(`SecurityStore database path is not a regular file: ${resolvedDbPath}`);
  }
  if ((fileStat.mode & 0o077) !== 0) {
    const modeOctal = (fileStat.mode & 0o7777).toString(8).padStart(4, "0");
    throw new Error(
      `SecurityStore requires a private database file (0600): ${resolvedDbPath} has mode ${modeOctal}`,
    );
  }

  for (const suffix of ["-wal", "-shm", "-journal"] as const) {
    const sidecarPath = `${resolvedDbPath}${suffix}`;
    const sidecarStat = lstatIfExists(sidecarPath);
    if (sidecarStat === null) {
      continue;
    }
    if (sidecarStat.isSymbolicLink()) {
      throw new Error(`SecurityStore sidecar path must not be a symbolic link: ${sidecarPath}`);
    }
    if (!sidecarStat.isFile()) {
      throw new Error(`SecurityStore sidecar path is not a regular file: ${sidecarPath}`);
    }
    if ((sidecarStat.mode & 0o077) !== 0) {
      const modeOctal = (sidecarStat.mode & 0o7777).toString(8).padStart(4, "0");
      throw new Error(
        `SecurityStore requires a private sidecar file (0600): ${sidecarPath} has mode ${modeOctal}`,
      );
    }
  }
}

interface ScanRow {
  id: string;
  trigger_kind: SecurityScan["trigger"];
  started_at: number;
  finished_at: number;
  snapshot_id: string;
  snapshot_captured_at: number;
  evidence_json: string;
  ai_status: SecurityScan["aiStatus"];
  verdict_json: string | null;
}

interface PostureCheckRow {
  check_id: CriterionId;
  category: PostureCheck["category"];
  title: string;
  status: PostureCheck["status"];
  summary: string;
  remediation: string | null;
  evidence_ids_json: string;
  source_coverage_json: string;
}

interface ExposureEntryRow {
  entry_id: string;
  listener_json: string;
  reachability: ExposureEntry["reachability"];
  firewall_v4: ExposureEntry["firewallV4"];
  firewall_v6: ExposureEntry["firewallV6"];
  publication: ExposureEntry["publication"];
  expected: number;
  evidence_ids_json: string;
}

interface FindingRow {
  finding_id: string;
  source: SecurityFinding["source"];
  severity: Severity;
  summary: string;
  evidence_ids_json: string;
}

interface InvestigationStepRow {
  tool: EvidenceTool | "verdict";
  reason: string;
  outcome: InvestigationTrail["steps"][number]["outcome"];
  evidence_ids_json: string;
}

interface SecurityEventRow {
  row_id: number;
  event_id: string;
  source: SecurityEvent["source"];
  category: Category;
  severity: Severity;
  rule: string;
  target: string;
  first_at: number;
  last_at: number;
  count: number;
  is_noise: number;
  payload_json: string;
}

interface ProposalRow {
  id: string;
  scan_id: string;
  revision: number;
  status: LockdownProposal["status"];
  target_json: string;
  evidence_ids_json: string;
  created_at: number;
  expires_at: number;
  lease_seconds: number;
  rollback_description: string;
}

interface ActionRow {
  id: string;
  proposal_id: string;
  idempotency_key: string;
  target_json: string;
  state: LockdownAction["state"];
  created_at: number;
  expires_at: number;
  updated_at: number;
  rollback_handle: string | null;
}

interface AlertRow {
  id: string;
  fingerprint: string;
  severity: Severity;
  summary: string;
  created_at: number;
  proposal_id: string | null;
}

interface DueDeliveryRow {
  delivery_id: string;
  channel: AlertChannel;
  attempts: number;
  alert_id: string;
  fingerprint: string;
  severity: Severity;
  summary: string;
  created_at: number;
  proposal_id: string | null;
}

export class SecurityStore implements SecurityStoreContract {
  private readonly db: Database;

  constructor(dbPath?: string) {
    const resolvedPath = dbPath ?? (process.env.BASHO_SECURITY_DB?.trim() || DEFAULT_DB_PATH);
    const isMemory = resolvedPath === ":memory:";
    if (!isMemory) {
      ensurePrivateDatabasePath(resolvedPath);
    }

    this.db = new Database(resolvedPath, { create: true });
    this.db.run(`PRAGMA busy_timeout = ${BUSY_TIMEOUT_MS}`);
    this.db.run("PRAGMA foreign_keys = ON");
    if (!isMemory) {
      this.db.run("PRAGMA journal_mode = WAL");
      this.db.run("PRAGMA synchronous = NORMAL");
    }

    this.applyMigrations();
  }

  private inImmediateTransaction<T>(fn: () => T): T {
    this.db.run("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.db.run("COMMIT");
      return result;
    } catch (error) {
      try {
        this.db.run("ROLLBACK");
      } catch {
        // Ignore rollback failure when SQLite has already rolled back.
      }
      throw error;
    }
  }

  private applyMigrations(): void {
    this.inImmediateTransaction(() => {
      this.db.run(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
          version INTEGER PRIMARY KEY,
          applied_at INTEGER NOT NULL
        )
      `);

      const existing = this.db
        .query("SELECT version FROM schema_migrations WHERE version = 1")
        .get() as { version: number } | null;
      if (existing) {
        return;
      }

      this.db.run(`
        CREATE TABLE scans (
          id TEXT PRIMARY KEY,
          trigger_kind TEXT NOT NULL,
          started_at INTEGER NOT NULL,
          finished_at INTEGER NOT NULL,
          snapshot_id TEXT NOT NULL,
          snapshot_captured_at INTEGER NOT NULL,
          evidence_json TEXT NOT NULL,
          ai_status TEXT NOT NULL,
          verdict_json TEXT
        )
      `);
      this.db.run(
        "CREATE INDEX idx_scans_order ON scans(finished_at DESC, started_at DESC)",
      );

      this.db.run(`
        CREATE TABLE posture_checks (
          scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
          position INTEGER NOT NULL,
          check_id TEXT NOT NULL,
          category TEXT NOT NULL,
          title TEXT NOT NULL,
          status TEXT NOT NULL,
          summary TEXT NOT NULL,
          remediation TEXT,
          evidence_ids_json TEXT NOT NULL,
          source_coverage_json TEXT NOT NULL,
          PRIMARY KEY (scan_id, position)
        )
      `);

      this.db.run(`
        CREATE TABLE exposure_entries (
          scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
          position INTEGER NOT NULL,
          entry_id TEXT NOT NULL,
          listener_json TEXT NOT NULL,
          reachability TEXT NOT NULL,
          firewall_v4 TEXT NOT NULL,
          firewall_v6 TEXT NOT NULL,
          publication TEXT NOT NULL,
          expected INTEGER NOT NULL,
          evidence_ids_json TEXT NOT NULL,
          PRIMARY KEY (scan_id, position)
        )
      `);

      this.db.run(`
        CREATE TABLE findings (
          scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
          position INTEGER NOT NULL,
          finding_id TEXT NOT NULL,
          source TEXT NOT NULL,
          severity TEXT NOT NULL,
          summary TEXT NOT NULL,
          evidence_ids_json TEXT NOT NULL,
          PRIMARY KEY (scan_id, position)
        )
      `);

      this.db.run(`
        CREATE TABLE investigation_steps (
          scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
          position INTEGER NOT NULL,
          tool TEXT NOT NULL,
          reason TEXT NOT NULL,
          outcome TEXT NOT NULL,
          evidence_ids_json TEXT NOT NULL,
          PRIMARY KEY (scan_id, position)
        )
      `);

      this.db.run(`
        CREATE TABLE security_events (
          row_id INTEGER PRIMARY KEY AUTOINCREMENT,
          row_kind TEXT NOT NULL CHECK (row_kind IN ('observation', 'aggregate')),
          observation_id TEXT UNIQUE,
          event_id TEXT NOT NULL,
          source TEXT NOT NULL,
          category TEXT NOT NULL,
          severity TEXT NOT NULL,
          rule TEXT NOT NULL,
          target TEXT NOT NULL,
          first_at INTEGER NOT NULL,
          last_at INTEGER NOT NULL,
          hour_bucket INTEGER NOT NULL,
          count INTEGER NOT NULL,
          is_noise INTEGER NOT NULL,
          payload_json TEXT NOT NULL
        )
      `);
      this.db.run(`
        CREATE INDEX idx_security_events_agg_lookup
        ON security_events(row_kind, source, category, rule, target, is_noise, last_at DESC)
      `);
      this.db.run(`
        CREATE INDEX idx_security_events_recent
        ON security_events(row_kind, last_at DESC)
      `);
      this.db.run(`
        CREATE INDEX idx_security_events_recent_cat
        ON security_events(row_kind, category, last_at DESC)
      `);
      this.db.run(`
        CREATE INDEX idx_security_events_hourly
        ON security_events(row_kind, hour_bucket)
      `);

      this.db.run(`
        CREATE TABLE source_cursors (
          source TEXT PRIMARY KEY,
          cursor TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        )
      `);

      this.db.run(`
        CREATE TABLE lockdown_proposals (
          id TEXT PRIMARY KEY,
          scan_id TEXT NOT NULL,
          revision INTEGER NOT NULL,
          status TEXT NOT NULL CHECK (status IN ('pending', 'claimed', 'rejected', 'expired')),
          target_json TEXT NOT NULL,
          evidence_ids_json TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          lease_seconds INTEGER NOT NULL,
          rollback_description TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        )
      `);
      this.db.run(`
        CREATE INDEX idx_lockdown_proposals_status_exp
        ON lockdown_proposals(status, expires_at)
      `);

      this.db.run(`
        CREATE TABLE lockdown_actions (
          id TEXT PRIMARY KEY,
          proposal_id TEXT NOT NULL,
          idempotency_key TEXT NOT NULL UNIQUE,
          target_json TEXT NOT NULL,
          state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'failed', 'rolling_back', 'rolled_back')),
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          rollback_handle TEXT
        )
      `);
      this.db.run(`
        CREATE INDEX idx_lockdown_actions_state_updated
        ON lockdown_actions(state, updated_at)
      `);

      this.db.run(`
        CREATE TABLE security_alerts (
          id TEXT PRIMARY KEY,
          fingerprint TEXT NOT NULL,
          severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical', 'breach')),
          severity_rank INTEGER NOT NULL,
          summary TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          proposal_id TEXT,
          dismissed_at INTEGER
        )
      `);
      this.db.run(`
        CREATE INDEX idx_security_alerts_fp_created
        ON security_alerts(fingerprint, created_at)
      `);
      this.db.run(`
        CREATE INDEX idx_security_alerts_recent
        ON security_alerts(dismissed_at, created_at DESC)
      `);

      this.db.run(`
        CREATE TABLE alert_deliveries (
          id TEXT PRIMARY KEY,
          alert_id TEXT NOT NULL REFERENCES security_alerts(id) ON DELETE CASCADE,
          channel TEXT NOT NULL,
          status TEXT NOT NULL CHECK (status IN ('pending', 'claimed', 'retrying', 'sent', 'failed')),
          attempts INTEGER NOT NULL DEFAULT 0,
          claim_token TEXT,
          lease_expires_at INTEGER,
          next_attempt_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          last_settled_status TEXT CHECK (last_settled_status IN ('sent', 'failed', 'retrying')),
          last_settled_at INTEGER,
          UNIQUE (alert_id, channel)
        )
      `);
      this.db.run(`
        CREATE INDEX idx_alert_deliveries_due
        ON alert_deliveries(status, next_attempt_at)
      `);
      this.db.run(`
        CREATE INDEX idx_alert_deliveries_lease
        ON alert_deliveries(status, lease_expires_at)
      `);
      this.db.run(`
        CREATE INDEX idx_alert_deliveries_channel_health
        ON alert_deliveries(channel, last_settled_at DESC)
      `);

      this.db.run(`
        CREATE TABLE runtime_settings (
          key TEXT PRIMARY KEY,
          value_json TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        )
      `);

      this.db
        .query("INSERT INTO schema_migrations (version, applied_at) VALUES (1, ?)")
        .run(Date.now());
    });
  }

  saveScan(scan: SecurityScan): void {
    this.inImmediateTransaction(() => {
      this.db
        .query(
          `INSERT INTO scans (
            id, trigger_kind, started_at, finished_at,
            snapshot_id, snapshot_captured_at, evidence_json,
            ai_status, verdict_json
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            trigger_kind = excluded.trigger_kind,
            started_at = excluded.started_at,
            finished_at = excluded.finished_at,
            snapshot_id = excluded.snapshot_id,
            snapshot_captured_at = excluded.snapshot_captured_at,
            evidence_json = excluded.evidence_json,
            ai_status = excluded.ai_status,
            verdict_json = excluded.verdict_json`,
        )
        .run(
          scan.id,
          scan.trigger,
          scan.startedAt,
          scan.finishedAt,
          scan.snapshot.id,
          scan.snapshot.capturedAt,
          JSON.stringify(scan.snapshot.evidence),
          scan.aiStatus,
          scan.verdict ? JSON.stringify(scan.verdict) : null,
        );

      this.db.query("DELETE FROM posture_checks WHERE scan_id = ?").run(scan.id);
      this.db.query("DELETE FROM exposure_entries WHERE scan_id = ?").run(scan.id);
      this.db.query("DELETE FROM findings WHERE scan_id = ?").run(scan.id);
      this.db.query("DELETE FROM investigation_steps WHERE scan_id = ?").run(scan.id);

      const insertCheck = this.db.query(
        `INSERT INTO posture_checks (
          scan_id, position, check_id, category, title, status, summary,
          remediation, evidence_ids_json, source_coverage_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      );
      for (let index = 0; index < scan.snapshot.checks.length; index += 1) {
        const check = scan.snapshot.checks[index]!;
        insertCheck.run(
          scan.id,
          index,
          check.id,
          check.category,
          check.title,
          check.status,
          check.summary,
          check.remediation ?? null,
          JSON.stringify(check.evidenceIds),
          JSON.stringify(check.sourceCoverage),
        );
      }

      const insertExposure = this.db.query(
        `INSERT INTO exposure_entries (
          scan_id, position, entry_id, listener_json, reachability,
          firewall_v4, firewall_v6, publication, expected, evidence_ids_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      );
      for (let index = 0; index < scan.exposure.length; index += 1) {
        const entry = scan.exposure[index]!;
        insertExposure.run(
          scan.id,
          index,
          entry.id,
          JSON.stringify(entry.listener),
          entry.reachability,
          entry.firewallV4,
          entry.firewallV6,
          entry.publication,
          entry.expected ? 1 : 0,
          JSON.stringify(entry.evidenceIds),
        );
      }

      const insertFinding = this.db.query(
        `INSERT INTO findings (
          scan_id, position, finding_id, source, severity, summary, evidence_ids_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      );
      for (let index = 0; index < scan.findings.length; index += 1) {
        const finding = scan.findings[index]!;
        insertFinding.run(
          scan.id,
          index,
          finding.id,
          finding.source,
          finding.severity,
          finding.summary,
          JSON.stringify(finding.evidenceIds),
        );
      }

      const insertStep = this.db.query(
        `INSERT INTO investigation_steps (
          scan_id, position, tool, reason, outcome, evidence_ids_json
        ) VALUES (?, ?, ?, ?, ?, ?)`,
      );
      for (let index = 0; index < scan.trail.steps.length; index += 1) {
        const step = scan.trail.steps[index]!;
        insertStep.run(
          scan.id,
          index,
          step.tool,
          step.reason,
          step.outcome,
          JSON.stringify(step.evidenceIds),
        );
      }
    });
  }

  latestScan(): SecurityScan | null {
    return this.db
      .transaction((): SecurityScan | null => {
        const row = this.db
          .query(
            `SELECT id, trigger_kind, started_at, finished_at,
                    snapshot_id, snapshot_captured_at, evidence_json,
                    ai_status, verdict_json
             FROM scans
             ORDER BY finished_at DESC, started_at DESC, rowid DESC
             LIMIT 1`,
          )
          .get() as ScanRow | null;
        if (!row) {
          return null;
        }

        const checkRows = this.db
          .query(
            `SELECT check_id, category, title, status, summary,
                    remediation, evidence_ids_json, source_coverage_json
             FROM posture_checks
             WHERE scan_id = ?
             ORDER BY position ASC`,
          )
          .all(row.id) as PostureCheckRow[];

        const checks: PostureCheck[] = checkRows.map((checkRow) => {
          const check: PostureCheck = {
            id: checkRow.check_id,
            category: checkRow.category,
            title: checkRow.title,
            status: checkRow.status,
            summary: checkRow.summary,
            evidenceIds: JSON.parse(checkRow.evidence_ids_json) as string[],
            sourceCoverage: JSON.parse(checkRow.source_coverage_json) as Record<string, Coverage>,
          };
          if (checkRow.remediation !== null) {
            check.remediation = checkRow.remediation;
          }
          return check;
        });

        const exposureRows = this.db
          .query(
            `SELECT entry_id, listener_json, reachability, firewall_v4,
                    firewall_v6, publication, expected, evidence_ids_json
             FROM exposure_entries
             WHERE scan_id = ?
             ORDER BY position ASC`,
          )
          .all(row.id) as ExposureEntryRow[];

        const exposure: ExposureEntry[] = exposureRows.map((entryRow) => ({
          id: entryRow.entry_id,
          listener: JSON.parse(entryRow.listener_json) as Listener,
          reachability: entryRow.reachability,
          firewallV4: entryRow.firewall_v4,
          firewallV6: entryRow.firewall_v6,
          publication: entryRow.publication,
          expected: entryRow.expected === 1,
          evidenceIds: JSON.parse(entryRow.evidence_ids_json) as string[],
        }));

        const findingRows = this.db
          .query(
            `SELECT finding_id, source, severity, summary, evidence_ids_json
             FROM findings
             WHERE scan_id = ?
             ORDER BY position ASC`,
          )
          .all(row.id) as FindingRow[];

        const findings: SecurityFinding[] = findingRows.map((findingRow) => ({
          id: findingRow.finding_id,
          source: findingRow.source,
          severity: findingRow.severity,
          summary: findingRow.summary,
          evidenceIds: JSON.parse(findingRow.evidence_ids_json) as string[],
        }));

        const stepRows = this.db
          .query(
            `SELECT tool, reason, outcome, evidence_ids_json
             FROM investigation_steps
             WHERE scan_id = ?
             ORDER BY position ASC`,
          )
          .all(row.id) as InvestigationStepRow[];

        const trail: InvestigationTrail = {
          steps: stepRows.map((stepRow) => ({
            tool: stepRow.tool,
            reason: stepRow.reason,
            outcome: stepRow.outcome,
            evidenceIds: JSON.parse(stepRow.evidence_ids_json) as string[],
          })),
        };

        const scan: SecurityScan = {
          id: row.id,
          trigger: row.trigger_kind,
          startedAt: row.started_at,
          finishedAt: row.finished_at,
          snapshot: {
            id: row.snapshot_id,
            capturedAt: row.snapshot_captured_at,
            checks,
            evidence: JSON.parse(row.evidence_json) as Evidence[],
          },
          exposure,
          findings,
          trail,
          aiStatus: row.ai_status,
        };

        if (row.verdict_json !== null) {
          scan.verdict = JSON.parse(row.verdict_json) as AiVerdict;
        }

        return scan;
      })
      .deferred();
  }

  getCursor(source: string): string | null {
    const row = this.db
      .query("SELECT cursor FROM source_cursors WHERE source = ?")
      .get(source) as { cursor: string } | null;
    return row ? row.cursor : null;
  }

  commitEventBatch(batch: EventBatch): boolean {
    return this.inImmediateTransaction(() => {
      if (batch.cursor) {
        const currentRow = this.db
          .query("SELECT cursor FROM source_cursors WHERE source = ?")
          .get(batch.cursor.source) as { cursor: string } | null;
        const currentCursor = currentRow ? currentRow.cursor : null;
        if (currentCursor !== batch.cursor.expected) {
          return false;
        }
      }

      const insertObservation = this.db.query(
        `INSERT OR IGNORE INTO security_events (
          row_kind, observation_id, event_id, source, category, severity,
          rule, target, first_at, last_at, hour_bucket, count, is_noise, payload_json
        ) VALUES ('observation', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      );

      const findAggregates = this.db.query(
        `SELECT row_id, event_id, source, category, severity, rule, target,
                first_at, last_at, count, is_noise, payload_json
         FROM security_events
         WHERE row_kind = 'aggregate'
           AND source = ?
           AND category = ?
           AND rule = ?
           AND target = ?
           AND is_noise = ?
           AND last_at > ?
           AND first_at < ?
         ORDER BY first_at ASC, row_id ASC`,
      );

      const updateAggregate = this.db.query(
        `UPDATE security_events
         SET severity = ?, first_at = ?, last_at = ?, hour_bucket = ?, count = ?, payload_json = ?
         WHERE row_id = ?`,
      );

      const deleteAggregate = this.db.query(
        "DELETE FROM security_events WHERE row_id = ? AND row_kind = 'aggregate'",
      );

      const insertAggregate = this.db.query(
        `INSERT INTO security_events (
          row_kind, observation_id, event_id, source, category, severity,
          rule, target, first_at, last_at, hour_bucket, count, is_noise, payload_json
        ) VALUES ('aggregate', NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      );

      const burstWindowMs = Math.max(0, batch.burstWindowMs);

      for (const event of batch.events) {
        const isNoiseInt = event.isNoise ? 1 : 0;
        const eventCount = Math.max(1, event.count);
        const hourBucket = Math.floor(event.lastAt / HOUR_MS) * HOUR_MS;
        const payloadJson = JSON.stringify({ summary: event.summary });

        const obsResult = insertObservation.run(
          event.id,
          event.id,
          event.source,
          event.category,
          event.severity,
          event.rule,
          event.target,
          event.firstAt,
          event.lastAt,
          hourBucket,
          eventCount,
          isNoiseInt,
          payloadJson,
        );

        if (obsResult.changes === 0) {
          continue;
        }

        const collectedByRowId = new Map<number, SecurityEventRow>();
        let mergedFirst = event.firstAt;
        let mergedLast = event.lastAt;

        while (true) {
          const prevFirst = mergedFirst;
          const prevLast = mergedLast;
          const candidates = findAggregates.all(
            event.source,
            event.category,
            event.rule,
            event.target,
            isNoiseInt,
            mergedFirst - burstWindowMs,
            mergedLast + burstWindowMs,
          ) as SecurityEventRow[];

          let added = false;
          for (const agg of candidates) {
            if (collectedByRowId.has(agg.row_id)) {
              continue;
            }
            collectedByRowId.set(agg.row_id, agg);
            added = true;
            if (agg.first_at < mergedFirst) {
              mergedFirst = agg.first_at;
            }
            if (agg.last_at > mergedLast) {
              mergedLast = agg.last_at;
            }
          }

          if (!added || (mergedFirst === prevFirst && mergedLast === prevLast)) {
            break;
          }
        }

        if (collectedByRowId.size > 0) {
          const matchingAggs = [...collectedByRowId.values()].sort(
            (left, right) => left.first_at - right.first_at || left.row_id - right.row_id,
          );
          const keeper = matchingAggs[0]!;
          let nextCount = eventCount;
          let nextSeverity: Severity = event.severity;
          let latestAt = -Infinity;
          let latestPayloadJson = payloadJson;

          for (const agg of matchingAggs) {
            nextCount += agg.count;
            if (SEVERITY_RANK[agg.severity] > SEVERITY_RANK[nextSeverity]) {
              nextSeverity = agg.severity;
            }
            if (agg.last_at >= latestAt) {
              latestAt = agg.last_at;
              latestPayloadJson = agg.payload_json;
            }
          }

          if (event.lastAt >= latestAt) {
            latestPayloadJson = payloadJson;
          }

          const nextHourBucket = Math.floor(mergedLast / HOUR_MS) * HOUR_MS;

          updateAggregate.run(
            nextSeverity,
            mergedFirst,
            mergedLast,
            nextHourBucket,
            nextCount,
            latestPayloadJson,
            keeper.row_id,
          );

          for (let index = 1; index < matchingAggs.length; index += 1) {
            deleteAggregate.run(matchingAggs[index]!.row_id);
          }
        } else {
          insertAggregate.run(
            event.id,
            event.source,
            event.category,
            event.severity,
            event.rule,
            event.target,
            event.firstAt,
            event.lastAt,
            hourBucket,
            eventCount,
            isNoiseInt,
            payloadJson,
          );
        }
      }

      if (batch.cursor) {
        this.db
          .query(
            `INSERT INTO source_cursors (source, cursor, updated_at)
             VALUES (?, ?, ?)
             ON CONFLICT(source) DO UPDATE SET
               cursor = excluded.cursor,
               updated_at = excluded.updated_at`,
          )
          .run(batch.cursor.source, batch.cursor.next, Date.now());
      }

      return true;
    });
  }

  recentEvents(since: number, limit: number, category?: Category): SecurityEvent[] {
    if (limit <= 0) {
      return [];
    }

    const rows = (
      category
        ? this.db
            .query(
              `SELECT row_id, event_id, source, category, severity, rule, target,
                      first_at, last_at, count, is_noise, payload_json
               FROM security_events
               WHERE row_kind = 'aggregate'
                 AND last_at >= ?
                 AND category = ?
               ORDER BY last_at DESC, row_id DESC
               LIMIT ?`,
            )
            .all(since, category, limit)
        : this.db
            .query(
              `SELECT row_id, event_id, source, category, severity, rule, target,
                      first_at, last_at, count, is_noise, payload_json
               FROM security_events
               WHERE row_kind = 'aggregate'
                 AND last_at >= ?
               ORDER BY last_at DESC, row_id DESC
               LIMIT ?`,
            )
            .all(since, limit)
    ) as SecurityEventRow[];

    return rows.map((row) => {
      const payload = JSON.parse(row.payload_json) as { summary: string };
      return {
        id: row.event_id,
        source: row.source,
        category: row.category,
        severity: row.severity,
        rule: row.rule,
        target: row.target,
        firstAt: row.first_at,
        lastAt: row.last_at,
        count: row.count,
        isNoise: row.is_noise === 1,
        summary: payload.summary,
      };
    });
  }

  hourlyEvents(now: number): { hour: number; signal: number; noise: number }[] {
    const currentHour = Math.floor(now / HOUR_MS) * HOUR_MS;
    const startHour = currentHour - 23 * HOUR_MS;

    const rows = this.db
      .query(
        `SELECT hour_bucket, is_noise, SUM(count) AS total
         FROM security_events
         WHERE row_kind = 'observation'
           AND hour_bucket >= ?
           AND hour_bucket <= ?
         GROUP BY hour_bucket, is_noise`,
      )
      .all(startHour, currentHour) as {
      hour_bucket: number;
      is_noise: number;
      total: number;
    }[];

    const byHour = new Map<number, { signal: number; noise: number }>();
    for (const row of rows) {
      const entry = byHour.get(row.hour_bucket) ?? { signal: 0, noise: 0 };
      if (row.is_noise === 1) {
        entry.noise += row.total;
      } else {
        entry.signal += row.total;
      }
      byHour.set(row.hour_bucket, entry);
    }

    const buckets: { hour: number; signal: number; noise: number }[] = [];
    for (let index = 0; index < 24; index += 1) {
      const hour = startHour + index * HOUR_MS;
      const entry = byHour.get(hour);
      buckets.push({
        hour,
        signal: entry?.signal ?? 0,
        noise: entry?.noise ?? 0,
      });
    }
    return buckets;
  }

  insertProposal(proposal: LockdownProposal): void {
    this.inImmediateTransaction(() => {
      this.db
        .query(
          `INSERT INTO lockdown_proposals (
            id, scan_id, revision, status, target_json, evidence_ids_json,
            created_at, expires_at, lease_seconds, rollback_description, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          proposal.id,
          proposal.scanId,
          proposal.revision,
          proposal.status,
          JSON.stringify(proposal.target),
          JSON.stringify(proposal.evidenceIds),
          proposal.createdAt,
          proposal.expiresAt,
          proposal.leaseSeconds,
          proposal.rollbackDescription,
          proposal.createdAt,
        );
    });
  }

  listProposals(): LockdownProposal[] {
    const rows = this.db
      .query(
        `SELECT id, scan_id, revision, status, target_json, evidence_ids_json,
                created_at, expires_at, lease_seconds, rollback_description
         FROM lockdown_proposals
         ORDER BY created_at DESC, rowid DESC`,
      )
      .all() as ProposalRow[];

    return rows.map((row) => ({
      id: row.id,
      scanId: row.scan_id,
      revision: row.revision,
      status: row.status,
      target: JSON.parse(row.target_json) as ContainmentTarget,
      evidenceIds: JSON.parse(row.evidence_ids_json) as string[],
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      leaseSeconds: row.lease_seconds,
      rollbackDescription: row.rollback_description,
    }));
  }

  claimProposal(id: string, revision: number, now: number): LockdownAction | null {
    return this.inImmediateTransaction(() => {
      const claimed = this.db
        .query(
          `UPDATE lockdown_proposals
           SET status = 'claimed', revision = revision + 1, updated_at = ?
           WHERE id = ? AND revision = ? AND status = 'pending' AND expires_at > ?
           RETURNING id, target_json, lease_seconds`,
        )
        .get(now, id, revision, now) as {
        id: string;
        target_json: string;
        lease_seconds: number;
      } | null;

      if (!claimed) {
        return null;
      }

      const action: LockdownAction = {
        id: crypto.randomUUID(),
        proposalId: claimed.id,
        idempotencyKey: `${claimed.id}:${revision}`,
        target: JSON.parse(claimed.target_json) as ContainmentTarget,
        state: "pending",
        createdAt: now,
        expiresAt: now + claimed.lease_seconds * 1_000,
        updatedAt: now,
      };

      this.db
        .query(
          `INSERT INTO lockdown_actions (
            id, proposal_id, idempotency_key, target_json, state,
            created_at, expires_at, updated_at, rollback_handle
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
        )
        .run(
          action.id,
          action.proposalId,
          action.idempotencyKey,
          claimed.target_json,
          action.state,
          action.createdAt,
          action.expiresAt,
          action.updatedAt,
        );

      return action;
    });
  }

  rejectProposal(id: string, revision: number, now: number): boolean {
    return this.inImmediateTransaction(() => {
      const result = this.db
        .query(
          `UPDATE lockdown_proposals
           SET status = 'rejected', revision = revision + 1, updated_at = ?
           WHERE id = ? AND revision = ? AND status = 'pending' AND expires_at > ?`,
        )
        .run(now, id, revision, now);
      return result.changes > 0;
    });
  }

  expireProposals(now: number): void {
    this.inImmediateTransaction(() => {
      this.db
        .query(
          `UPDATE lockdown_proposals
           SET status = 'expired', revision = revision + 1, updated_at = ?
           WHERE status = 'pending' AND expires_at <= ?`,
        )
        .run(now, now);
    });
  }

  listActions(): LockdownAction[] {
    const rows = this.db
      .query(
        `SELECT id, proposal_id, idempotency_key, target_json, state,
                created_at, expires_at, updated_at, rollback_handle
         FROM lockdown_actions
         ORDER BY created_at DESC, rowid DESC`,
      )
      .all() as ActionRow[];

    return rows.map((row) => {
      const action: LockdownAction = {
        id: row.id,
        proposalId: row.proposal_id,
        idempotencyKey: row.idempotency_key,
        target: JSON.parse(row.target_json) as ContainmentTarget,
        state: row.state,
        createdAt: row.created_at,
        expiresAt: row.expires_at,
        updatedAt: row.updated_at,
      };
      if (row.rollback_handle !== null) {
        action.rollbackHandle = row.rollback_handle;
      }
      return action;
    });
  }

  transitionAction(
    id: string,
    from: LockdownAction["state"],
    to: LockdownAction["state"],
    now: number,
    rollbackHandle?: string,
  ): boolean {
    return this.inImmediateTransaction(() => {
      const result = this.db
        .query(
          `UPDATE lockdown_actions
           SET state = ?, updated_at = ?, rollback_handle = COALESCE(?, rollback_handle)
           WHERE id = ? AND state = ?`,
        )
        .run(to, now, rollbackHandle ?? null, id, from);
      return result.changes > 0;
    });
  }

  enqueueAlert(alert: SecurityAlert, channels: AlertChannel[], cooldownMs: number): boolean {
    return this.inImmediateTransaction(() => {
      const incomingRank = SEVERITY_RANK[alert.severity];
      const cooldownStart = alert.createdAt - Math.max(0, cooldownMs);

      const prior = this.db
        .query(
          `SELECT MAX(severity_rank) AS max_rank
           FROM security_alerts
           WHERE fingerprint = ? AND created_at > ?`,
        )
        .get(alert.fingerprint, cooldownStart) as { max_rank: number | null } | null;

      if (prior && prior.max_rank !== null && incomingRank <= prior.max_rank) {
        return false;
      }

      this.db
        .query(
          `INSERT INTO security_alerts (
            id, fingerprint, severity, severity_rank, summary,
            created_at, proposal_id, dismissed_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
        )
        .run(
          alert.id,
          alert.fingerprint,
          alert.severity,
          incomingRank,
          alert.summary,
          alert.createdAt,
          alert.proposalId ?? null,
        );

      const insertDelivery = this.db.query(
        `INSERT INTO alert_deliveries (
          id, alert_id, channel, status, attempts, claim_token,
          lease_expires_at, next_attempt_at, updated_at,
          last_settled_status, last_settled_at
        ) VALUES (?, ?, ?, 'pending', 0, NULL, NULL, 0, ?, NULL, NULL)`,
      );

      for (const channel of new Set(channels)) {
        insertDelivery.run(crypto.randomUUID(), alert.id, channel, alert.createdAt);
      }

      return true;
    });
  }

  claimDeliveries(now: number, limit: number, leaseMs: number): AlertDelivery[] {
    if (limit <= 0) {
      return [];
    }

    return this.inImmediateTransaction(() => {
      const dueRows = this.db
        .query(
          `SELECT d.id AS delivery_id, d.channel, d.attempts,
                  a.id AS alert_id, a.fingerprint, a.severity,
                  a.summary, a.created_at, a.proposal_id
           FROM alert_deliveries d
           INNER JOIN security_alerts a ON a.id = d.alert_id
           WHERE (d.status IN ('pending', 'retrying') AND d.next_attempt_at <= ?)
              OR (d.status = 'claimed' AND d.lease_expires_at <= ?)
           ORDER BY a.created_at ASC, d.next_attempt_at ASC, d.rowid ASC
           LIMIT ?`,
        )
        .all(now, now, limit) as DueDeliveryRow[];

      const updateDelivery = this.db.query(
        `UPDATE alert_deliveries
         SET status = 'claimed',
             attempts = ?,
             claim_token = ?,
             lease_expires_at = ?,
             updated_at = ?
         WHERE id = ?`,
      );

      const leaseExpiresAt = now + Math.max(0, leaseMs);
      const claimed: AlertDelivery[] = [];

      for (const row of dueRows) {
        const claimToken = crypto.randomUUID();
        const attempts = row.attempts + 1;

        updateDelivery.run(attempts, claimToken, leaseExpiresAt, now, row.delivery_id);

        const alert: SecurityAlert = {
          id: row.alert_id,
          fingerprint: row.fingerprint,
          severity: row.severity,
          summary: row.summary,
          createdAt: row.created_at,
        };
        if (row.proposal_id !== null) {
          alert.proposalId = row.proposal_id;
        }

        claimed.push({
          id: row.delivery_id,
          alert,
          channel: row.channel,
          attempts,
          claimToken,
        });
      }

      return claimed;
    });
  }

  settleDelivery(
    id: string,
    claimToken: string,
    now: number,
    result: "sent" | "failed" | { retryAt: number },
  ): boolean {
    return this.inImmediateTransaction(() => {
      if (result === "sent" || result === "failed") {
        const updateResult = this.db
          .query(
            `UPDATE alert_deliveries
             SET status = ?,
                 claim_token = NULL,
                 lease_expires_at = NULL,
                 updated_at = ?,
                 last_settled_status = ?,
                 last_settled_at = ?
             WHERE id = ? AND status = 'claimed' AND claim_token = ?`,
          )
          .run(result, now, result, now, id, claimToken);
        return updateResult.changes > 0;
      }

      const updateResult = this.db
        .query(
          `UPDATE alert_deliveries
           SET status = 'retrying',
               claim_token = NULL,
               lease_expires_at = NULL,
               next_attempt_at = ?,
               updated_at = ?,
               last_settled_status = 'retrying',
               last_settled_at = ?
           WHERE id = ? AND status = 'claimed' AND claim_token = ?`,
        )
        .run(result.retryAt, now, now, id, claimToken);
      return updateResult.changes > 0;
    });
  }

  recentAlerts(since: number): SecurityAlert[] {
    const rows = this.db
      .query(
        `SELECT id, fingerprint, severity, summary, created_at, proposal_id
         FROM security_alerts
         WHERE dismissed_at IS NULL AND created_at >= ?
         ORDER BY created_at DESC, rowid DESC`,
      )
      .all(since) as AlertRow[];

    return rows.map((row) => {
      const alert: SecurityAlert = {
        id: row.id,
        fingerprint: row.fingerprint,
        severity: row.severity,
        summary: row.summary,
        createdAt: row.created_at,
      };
      if (row.proposal_id !== null) {
        alert.proposalId = row.proposal_id;
      }
      return alert;
    });
  }

  dismissAlert(id: string, now: number): boolean {
    return this.inImmediateTransaction(() => {
      const result = this.db
        .query(
          `UPDATE security_alerts
           SET dismissed_at = ?
           WHERE id = ? AND dismissed_at IS NULL`,
        )
        .run(now, id);
      return result.changes > 0;
    });
  }

  channelHealth(): Partial<
    Record<AlertChannel, { status: "sent" | "failed" | "retrying"; at: number }>
  > {
    const rows = this.db
      .query(
        `SELECT channel, last_settled_status, last_settled_at
         FROM alert_deliveries
         WHERE last_settled_status IS NOT NULL
         ORDER BY last_settled_at DESC, rowid DESC`,
      )
      .all() as {
      channel: AlertChannel;
      last_settled_status: "sent" | "failed" | "retrying";
      last_settled_at: number;
    }[];

    const health: Partial<
      Record<AlertChannel, { status: "sent" | "failed" | "retrying"; at: number }>
    > = {};
    for (const row of rows) {
      if (!(row.channel in health)) {
        health[row.channel] = {
          status: row.last_settled_status,
          at: row.last_settled_at,
        };
      }
    }
    return health;
  }

  readOverrides(): RuntimeOverrides {
    const row = this.db
      .query("SELECT value_json FROM runtime_settings WHERE key = 'overrides'")
      .get() as { value_json: string } | null;
    if (!row) {
      return {};
    }
    return JSON.parse(row.value_json) as RuntimeOverrides;
  }

  writeOverrides(overrides: RuntimeOverrides): void {
    this.inImmediateTransaction(() => {
      this.db
        .query(
          `INSERT INTO runtime_settings (key, value_json, updated_at)
           VALUES ('overrides', ?, ?)
           ON CONFLICT(key) DO UPDATE SET
             value_json = excluded.value_json,
             updated_at = excluded.updated_at`,
        )
        .run(JSON.stringify(overrides), Date.now());
    });
  }

  prune(now: number): void {
    this.inImmediateTransaction(() => {
      this.db
        .query(
          `DELETE FROM scans
           WHERE id NOT IN (
             SELECT id FROM scans
             ORDER BY finished_at DESC, started_at DESC, rowid DESC
             LIMIT ?
           )`,
        )
        .run(MAX_RETAINED_SCANS);

      const eventCutoff = now - EVENT_RETENTION_DAYS * DAY_MS;
      this.db
        .query("DELETE FROM security_events WHERE last_at < ?")
        .run(eventCutoff);

      const actionCutoff = now - ACTION_RETENTION_DAYS * DAY_MS;
      this.db
        .query(
          `DELETE FROM lockdown_actions
           WHERE state IN ('failed', 'rolled_back') AND updated_at < ?`,
        )
        .run(actionCutoff);
    });
  }

  close(): void {
    this.db.close();
  }
}
