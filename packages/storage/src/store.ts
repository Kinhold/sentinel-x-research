import { createHash } from 'node:crypto';
import type {
  ActivityItem,
  CreateTargetBody,
  DashboardStats,
  DiscoveryFinding,
  PayoutPotential,
  Report,
  Scan,
  ScanLogEntry,
  ScanPhase,
  ScanSourceMode,
  ScanStatus,
  SeverityCount,
  Target,
  TargetLanguage,
  Vulnerability,
  VulnerabilitySeverity,
  VulnerabilityStatus,
} from '@sentinel-x/contracts';
import { SEVERITY_PAYOUT_WEIGHT } from '@sentinel-x/contracts';
import type { SentinelDatabase } from './db.js';

type TargetRow = {
  id: number;
  repo_url: string;
  name: string;
  language: TargetLanguage;
  description: string | null;
  bounty_platform: string | null;
  max_payout: number | null;
  created_at: string;
};

type ScanRow = {
  id: number;
  target_id: number;
  status: ScanStatus;
  phase: ScanPhase | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  error_message: string | null;
  bugs_found: number;
  bugs_verified: number;
  source_mode: ScanSourceMode | null;
  source_path: string | null;
  source_commit: string | null;
};

type VulnerabilityRow = {
  id: number;
  scan_id: number;
  target_id: number;
  title: string;
  description: string;
  severity: VulnerabilitySeverity;
  vuln_type: string;
  target_language: TargetLanguage;
  status: VulnerabilityStatus;
  affected_file: string | null;
  affected_function: string | null;
  line_number: number | null;
  poc_code: string | null;
  fv_harness: string | null;
  fv_log: string | null;
  counter_example: string | null;
  estimated_payout: number | null;
  confidence_score: number | null;
  rule_id: string | null;
  fingerprint: string | null;
  created_at: string;
  verified_at: string | null;
};

type ReportRow = {
  vulnerability_id: number;
  title: string;
  severity: string;
  markdown: string;
  generated_at: string;
};

function mapTarget(row: TargetRow): Target {
  return {
    id: row.id,
    repoUrl: row.repo_url,
    name: row.name,
    language: row.language,
    description: row.description,
    bountyPlatform: row.bounty_platform,
    maxPayout: row.max_payout,
    createdAt: row.created_at,
  };
}

function mapScan(row: ScanRow, target?: Target | null): Scan {
  return {
    id: row.id,
    targetId: row.target_id,
    status: row.status,
    phase: row.phase,
    startedAt: row.started_at,
    completedAt: row.completed_at,
    createdAt: row.created_at,
    errorMessage: row.error_message,
    bugsFound: row.bugs_found,
    bugsVerified: row.bugs_verified,
    sourceMode: row.source_mode,
    sourcePath: row.source_path,
    sourceCommit: row.source_commit,
    target: target ?? null,
  };
}

function mapVulnerability(row: VulnerabilityRow): Vulnerability {
  return {
    id: row.id,
    scanId: row.scan_id,
    targetId: row.target_id,
    title: row.title,
    description: row.description,
    severity: row.severity,
    vulnType: row.vuln_type as Vulnerability['vulnType'],
    targetLanguage: row.target_language,
    status: row.status,
    affectedFile: row.affected_file,
    affectedFunction: row.affected_function,
    lineNumber: row.line_number,
    pocCode: row.poc_code,
    fvHarness: row.fv_harness,
    fvLog: row.fv_log,
    counterExample: row.counter_example,
    estimatedPayout: row.estimated_payout,
    confidenceScore: row.confidence_score,
    ruleId: row.rule_id,
    fingerprint: row.fingerprint,
    createdAt: row.created_at,
    verifiedAt: row.verified_at,
  };
}

function mapReport(row: ReportRow): Report {
  return {
    vulnerabilityId: row.vulnerability_id,
    title: row.title,
    severity: row.severity,
    markdown: row.markdown,
    generatedAt: row.generated_at,
  };
}

export class SentinelStore {
  constructor(private readonly db: SentinelDatabase) {}

  listTargets(): Target[] {
    const rows = this.db.prepare('SELECT * FROM targets ORDER BY id DESC').all() as TargetRow[];
    return rows.map(mapTarget);
  }

  getTarget(id: number): Target | null {
    const row = this.db.prepare('SELECT * FROM targets WHERE id = ?').get(id) as TargetRow | undefined;
    return row ? mapTarget(row) : null;
  }

  createTarget(body: CreateTargetBody): Target {
    const stmt = this.db.prepare(`
      INSERT INTO targets (repo_url, name, language, description, bounty_platform, max_payout)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(
      body.repoUrl,
      body.name,
      body.language,
      body.description ?? null,
      body.bountyPlatform ?? null,
      body.maxPayout ?? null,
    );
    return this.getTarget(Number(result.lastInsertRowid))!;
  }

  deleteTarget(id: number): boolean {
    const result = this.db.prepare('DELETE FROM targets WHERE id = ?').run(id);
    return result.changes > 0;
  }

  listScans(filters: { status?: ScanStatus; targetId?: number } = {}): Scan[] {
    const clauses: string[] = [];
    const params: Array<string | number> = [];
    if (filters.status) {
      clauses.push('s.status = ?');
      params.push(filters.status);
    }
    if (filters.targetId) {
      clauses.push('s.target_id = ?');
      params.push(filters.targetId);
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = this.db
      .prepare(`SELECT s.* FROM scans s ${where} ORDER BY s.id DESC`)
      .all(...params) as ScanRow[];
    return rows.map((row) => mapScan(row, this.getTarget(row.target_id)));
  }

  getScan(id: number): Scan | null {
    const row = this.db.prepare('SELECT * FROM scans WHERE id = ?').get(id) as ScanRow | undefined;
    if (!row) return null;
    return mapScan(row, this.getTarget(row.target_id));
  }

  createScan(targetId: number): Scan {
    const target = this.getTarget(targetId);
    if (!target) throw new Error('Target not found');
    const result = this.db
      .prepare(`INSERT INTO scans (target_id, status, phase) VALUES (?, 'pending', 'idle')`)
      .run(targetId);
    return this.getScan(Number(result.lastInsertRowid))!;
  }

  updateScan(
    id: number,
    patch: Partial<{
      status: ScanStatus;
      phase: ScanPhase | null;
      startedAt: string | null;
      completedAt: string | null;
      errorMessage: string | null;
      bugsFound: number;
      bugsVerified: number;
      sourceMode: ScanSourceMode | null;
      sourcePath: string | null;
      sourceCommit: string | null;
    }>,
  ): Scan | null {
    const current = this.getScan(id);
    if (!current) return null;
    const next = {
      status: patch.status ?? current.status,
      phase: patch.phase === undefined ? current.phase ?? null : patch.phase,
      startedAt: patch.startedAt === undefined ? current.startedAt ?? null : patch.startedAt,
      completedAt: patch.completedAt === undefined ? current.completedAt ?? null : patch.completedAt,
      errorMessage: patch.errorMessage === undefined ? current.errorMessage ?? null : patch.errorMessage,
      bugsFound: patch.bugsFound ?? current.bugsFound,
      bugsVerified: patch.bugsVerified ?? current.bugsVerified,
      sourceMode: patch.sourceMode === undefined ? current.sourceMode ?? null : patch.sourceMode,
      sourcePath: patch.sourcePath === undefined ? current.sourcePath ?? null : patch.sourcePath,
      sourceCommit: patch.sourceCommit === undefined ? current.sourceCommit ?? null : patch.sourceCommit,
    };
    this.db
      .prepare(
        `UPDATE scans SET status = ?, phase = ?, started_at = ?, completed_at = ?, error_message = ?, bugs_found = ?, bugs_verified = ?, source_mode = ?, source_path = ?, source_commit = ? WHERE id = ?`,
      )
      .run(
        next.status,
        next.phase,
        next.startedAt,
        next.completedAt,
        next.errorMessage,
        next.bugsFound,
        next.bugsVerified,
        next.sourceMode,
        next.sourcePath,
        next.sourceCommit,
        id,
      );
    return this.getScan(id);
  }

  insertVulnerability(
    scanId: number,
    targetId: number,
    finding: DiscoveryFinding,
    targetLanguage: TargetLanguage,
  ): Vulnerability {
    const target = this.getTarget(targetId);
    const estimatedPayout = this.estimatePayout(finding.severity, target?.maxPayout ?? null);
    const result = this.db
      .prepare(
        `INSERT INTO vulnerabilities (
          scan_id, target_id, title, description, severity, vuln_type, target_language,
          affected_file, affected_function, line_number, poc_code, estimated_payout, confidence_score,
          rule_id, fingerprint
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        scanId,
        targetId,
        finding.title,
        finding.description,
        finding.severity,
        finding.vulnType,
        targetLanguage,
        finding.affectedFile ?? null,
        finding.affectedFunction ?? null,
        finding.lineNumber ?? null,
        finding.pocCode ?? null,
        estimatedPayout,
        finding.confidenceScore,
        finding.ruleId ?? null,
        finding.fingerprint ?? null,
      );
    return this.getVulnerability(Number(result.lastInsertRowid))!;
  }

  listVulnerabilities(
    filters: {
      status?: VulnerabilityStatus;
      severity?: VulnerabilitySeverity;
      targetLanguage?: TargetLanguage;
      scanId?: number;
    } = {},
  ): Vulnerability[] {
    const clauses: string[] = [];
    const params: Array<string | number> = [];
    if (filters.status) {
      clauses.push('status = ?');
      params.push(filters.status);
    }
    if (filters.severity) {
      clauses.push('severity = ?');
      params.push(filters.severity);
    }
    if (filters.targetLanguage) {
      clauses.push('target_language = ?');
      params.push(filters.targetLanguage);
    }
    if (filters.scanId) {
      clauses.push('scan_id = ?');
      params.push(filters.scanId);
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = this.db
      .prepare(`SELECT * FROM vulnerabilities ${where} ORDER BY id DESC`)
      .all(...params) as VulnerabilityRow[];
    return rows.map(mapVulnerability);
  }

  getVulnerability(id: number): Vulnerability | null {
    const row = this.db.prepare('SELECT * FROM vulnerabilities WHERE id = ?').get(id) as VulnerabilityRow | undefined;
    return row ? mapVulnerability(row) : null;
  }

  findVerifiedByFingerprint(fingerprint: string, targetId?: number): Vulnerability | null {
    const row = (
      targetId == null
        ? this.db
            .prepare(
              `SELECT * FROM vulnerabilities
               WHERE fingerprint = ? AND status IN ('verified', 'reported')
               ORDER BY id DESC LIMIT 1`,
            )
            .get(fingerprint)
        : this.db
            .prepare(
              `SELECT * FROM vulnerabilities
               WHERE fingerprint = ? AND target_id = ? AND status IN ('verified', 'reported')
               ORDER BY id DESC LIMIT 1`,
            )
            .get(fingerprint, targetId)
    ) as VulnerabilityRow | undefined;
    return row ? mapVulnerability(row) : null;
  }

  updateVulnerabilityStatus(id: number, status: VulnerabilityStatus): Vulnerability | null {
    const verifiedAt =
      status === 'verified' || status === 'reported' ? new Date().toISOString() : null;
    const result = this.db
      .prepare(
        status === 'verified' || status === 'reported'
          ? 'UPDATE vulnerabilities SET status = ?, verified_at = COALESCE(?, verified_at) WHERE id = ?'
          : 'UPDATE vulnerabilities SET status = ?, verified_at = ? WHERE id = ?',
      )
      .run(status, verifiedAt, id);
    if (!result.changes) return null;
    return this.getVulnerability(id);
  }

  updateVulnerabilityVerification(
    id: number,
    patch: {
      status: VulnerabilityStatus;
      fvHarness?: string | null;
      fvLog?: string | null;
      counterExample?: string | null;
      confidenceScore?: number | null;
    },
  ): Vulnerability | null {
    const current = this.getVulnerability(id);
    if (!current) return null;
    const verifiedAt =
      patch.status === 'verified' || patch.status === 'reported'
        ? new Date().toISOString()
        : patch.status === 'false_positive' || patch.status === 'discovered'
          ? null
          : (current.verifiedAt ?? null);
    this.db
      .prepare(
        `UPDATE vulnerabilities
         SET status = ?, fv_harness = ?, fv_log = ?, counter_example = ?, confidence_score = ?, verified_at = ?
         WHERE id = ?`,
      )
      .run(
        patch.status,
        patch.fvHarness ?? current.fvHarness ?? null,
        patch.fvLog ?? current.fvLog ?? null,
        patch.counterExample ?? current.counterExample ?? null,
        patch.confidenceScore ?? current.confidenceScore ?? null,
        verifiedAt,
        id,
      );
    return this.getVulnerability(id);
  }

  upsertReport(report: Report): Report {
    this.db
      .prepare(
        `INSERT INTO reports (vulnerability_id, title, severity, markdown, generated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(vulnerability_id) DO UPDATE SET
           title = excluded.title,
           severity = excluded.severity,
           markdown = excluded.markdown,
           generated_at = excluded.generated_at`,
      )
      .run(report.vulnerabilityId, report.title, report.severity, report.markdown, report.generatedAt);
    return this.getReport(report.vulnerabilityId)!;
  }

  getReport(vulnerabilityId: number): Report | null {
    const row = this.db
      .prepare('SELECT * FROM reports WHERE vulnerability_id = ?')
      .get(vulnerabilityId) as ReportRow | undefined;
    return row ? mapReport(row) : null;
  }

  appendActivity(
    type: ActivityItem['type'],
    message: string,
    severity: string | null = null,
    scanId?: number,
    vulnerabilityId?: number,
  ): ActivityItem {
    const result = this.db
      .prepare('INSERT INTO activities (type, message, severity, scan_id, vulnerability_id) VALUES (?, ?, ?, ?, ?)')
      .run(type, message, severity, scanId ?? null, vulnerabilityId ?? null);
    const row = this.db.prepare('SELECT * FROM activities WHERE id = ?').get(Number(result.lastInsertRowid)) as {
      id: number;
      type: ActivityItem['type'];
      message: string;
      timestamp: string;
      severity: string | null;
    };
    return {
      id: row.id,
      type: row.type,
      message: row.message,
      timestamp: row.timestamp,
      severity: row.severity,
    };
  }

  appendScanLog(scanId: number, level: ScanLogEntry['level'], phase: ScanPhase, message: string): ScanLogEntry {
    const result = this.db
      .prepare('INSERT INTO scan_logs (scan_id, level, phase, message) VALUES (?, ?, ?, ?)')
      .run(scanId, level, phase, message);
    const row = this.db.prepare('SELECT * FROM scan_logs WHERE id = ?').get(Number(result.lastInsertRowid)) as {
      scan_id: number;
      level: ScanLogEntry['level'];
      phase: ScanPhase;
      message: string;
      timestamp: string;
    };
    return {
      scanId: row.scan_id,
      level: row.level,
      phase: row.phase,
      message: row.message,
      timestamp: row.timestamp,
    };
  }

  listScanLogs(scanId: number): ScanLogEntry[] {
    const rows = this.db
      .prepare('SELECT scan_id, level, phase, message, timestamp FROM scan_logs WHERE scan_id = ? ORDER BY id ASC')
      .all(scanId) as Array<{
      scan_id: number;
      level: ScanLogEntry['level'];
      phase: ScanPhase;
      message: string;
      timestamp: string;
    }>;
    return rows.map((row) => ({
      scanId: row.scan_id,
      level: row.level,
      phase: row.phase,
      message: row.message,
      timestamp: row.timestamp,
    }));
  }

  getDashboardStats(): DashboardStats {
    const totalScans = (this.db.prepare('SELECT COUNT(*) AS count FROM scans').get() as { count: number }).count;
    const activeScans = (
      this.db.prepare("SELECT COUNT(*) AS count FROM scans WHERE status = 'running'").get() as { count: number }
    ).count;
    const totalTargets = (this.db.prepare('SELECT COUNT(*) AS count FROM targets').get() as { count: number }).count;
    const totalVulnerabilities = (
      this.db.prepare('SELECT COUNT(*) AS count FROM vulnerabilities').get() as { count: number }
    ).count;
    const verifiedVulnerabilities = (
      this.db.prepare("SELECT COUNT(*) AS count FROM vulnerabilities WHERE status IN ('verified', 'reported')").get() as {
        count: number;
      }
    ).count;
    const criticalCount = (
      this.db.prepare("SELECT COUNT(*) AS count FROM vulnerabilities WHERE severity = 'critical'").get() as {
        count: number;
      }
    ).count;
    const highCount = (
      this.db.prepare("SELECT COUNT(*) AS count FROM vulnerabilities WHERE severity = 'high'").get() as { count: number }
    ).count;
    const payoutPotential = (
      this.db
        .prepare("SELECT COALESCE(SUM(estimated_payout), 0) AS total FROM vulnerabilities WHERE status IN ('verified', 'reported')")
        .get() as { total: number }
    ).total;
    const recentActivity = (
      this.db.prepare('SELECT id, type, message, timestamp, severity FROM activities ORDER BY id DESC LIMIT 12').all() as unknown as ActivityItem[]
    ).reverse();
    const severityBreakdown = this.db
      .prepare(
        `SELECT severity,
                COUNT(*) AS count,
                SUM(CASE WHEN status IN ('verified', 'reported') THEN 1 ELSE 0 END) AS verified
         FROM vulnerabilities
         GROUP BY severity`,
      )
      .all() as unknown as SeverityCount[];

    return {
      totalScans,
      activeScans,
      totalTargets,
      totalVulnerabilities,
      verifiedVulnerabilities,
      criticalCount,
      highCount,
      payoutPotential,
      recentActivity,
      severityBreakdown,
    };
  }

  getPayoutPotential(): PayoutPotential {
    const total = (
      this.db
        .prepare("SELECT COALESCE(SUM(estimated_payout), 0) AS total FROM vulnerabilities WHERE status IN ('verified', 'reported')")
        .get() as { total: number }
    ).total;
    const byTarget = this.db
      .prepare(
        `SELECT v.target_id AS targetId,
                t.name AS targetName,
                COALESCE(SUM(v.estimated_payout), 0) AS payout,
                SUM(CASE WHEN v.status IN ('verified', 'reported') THEN 1 ELSE 0 END) AS verifiedCount
         FROM vulnerabilities v
         JOIN targets t ON t.id = v.target_id
         WHERE v.status IN ('verified', 'reported')
         GROUP BY v.target_id, t.name
         ORDER BY payout DESC`,
      )
      .all() as unknown as PayoutPotential['byTarget'];
    const bySeverity = this.db
      .prepare(
        `SELECT severity,
                COALESCE(SUM(estimated_payout), 0) AS payout,
                COUNT(*) AS count
         FROM vulnerabilities
         WHERE status IN ('verified', 'reported')
         GROUP BY severity
         ORDER BY payout DESC`,
      )
      .all() as unknown as PayoutPotential['bySeverity'];
    return { total, byTarget, bySeverity };
  }

  private estimatePayout(severity: VulnerabilitySeverity, maxPayout: number | null): number | null {
    if (maxPayout === null) return null;
    return Math.round(maxPayout * SEVERITY_PAYOUT_WEIGHT[severity] * 100) / 100;
  }

  appendProvenance(scanId: number, event: string, payload: unknown): {
    seq: number;
    entryHash: string;
    prevHash: string | null;
  } {
    const last = this.db
      .prepare('SELECT seq, entry_hash FROM provenance WHERE scan_id = ? ORDER BY seq DESC LIMIT 1')
      .get(scanId) as { seq: number; entry_hash: string } | undefined;
    const seq = (last?.seq ?? 0) + 1;
    const prevHash = last?.entry_hash ?? null;
    const payloadJson = JSON.stringify(payload);
    const entryHash = createHash('sha256')
      .update([String(scanId), String(seq), event, payloadJson, prevHash ?? ''].join('|'))
      .digest('hex');
    this.db
      .prepare(
        `INSERT INTO provenance (scan_id, seq, event, payload_json, prev_hash, entry_hash)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(scanId, seq, event, payloadJson, prevHash, entryHash);
    return { seq, entryHash, prevHash };
  }

  listProvenance(scanId: number): Array<{
    seq: number;
    event: string;
    payload: unknown;
    prevHash: string | null;
    entryHash: string;
    createdAt: string;
  }> {
    const rows = this.db
      .prepare(
        `SELECT seq, event, payload_json, prev_hash, entry_hash, created_at
         FROM provenance WHERE scan_id = ? ORDER BY seq ASC`,
      )
      .all(scanId) as Array<{
      seq: number;
      event: string;
      payload_json: string;
      prev_hash: string | null;
      entry_hash: string;
      created_at: string;
    }>;
    return rows.map((row) => ({
      seq: row.seq,
      event: row.event,
      payload: JSON.parse(row.payload_json) as unknown,
      prevHash: row.prev_hash,
      entryHash: row.entry_hash,
      createdAt: row.created_at,
    }));
  }

  verifyProvenanceChain(scanId: number): boolean {
    const entries = this.listProvenance(scanId);
    let prevHash: string | null = null;
    for (const entry of entries) {
      if (entry.prevHash !== prevHash) return false;
      const material = [String(scanId), String(entry.seq), entry.event, JSON.stringify(entry.payload), prevHash ?? ''].join(
        '|',
      );
      const expectedHash: string = createHash('sha256').update(material).digest('hex');
      if (expectedHash !== entry.entryHash) return false;
      prevHash = entry.entryHash;
    }
    return true;
  }

  appendAudit(event: {
    actor?: string;
    action: string;
    resourceType?: string;
    resourceId?: string;
    detail?: string;
    requestId?: string;
  }): void {
    this.db
      .prepare(
        `INSERT INTO audit_events (actor, action, resource_type, resource_id, detail, request_id)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        event.actor ?? 'operator',
        event.action,
        event.resourceType ?? null,
        event.resourceId ?? null,
        event.detail ?? null,
        event.requestId ?? null,
      );
  }

  listAuditEvents(limit = 50): Array<{
    id: number;
    actor: string;
    action: string;
    resourceType: string | null;
    resourceId: string | null;
    detail: string | null;
    requestId: string | null;
    createdAt: string;
  }> {
    const rows = this.db
      .prepare(
        `SELECT id, actor, action, resource_type, resource_id, detail, request_id, created_at
         FROM audit_events ORDER BY id DESC LIMIT ?`,
      )
      .all(limit) as Array<{
      id: number;
      actor: string;
      action: string;
      resource_type: string | null;
      resource_id: string | null;
      detail: string | null;
      request_id: string | null;
      created_at: string;
    }>;
    return rows.map((row) => ({
      id: row.id,
      actor: row.actor,
      action: row.action,
      resourceType: row.resource_type,
      resourceId: row.resource_id,
      detail: row.detail,
      requestId: row.request_id,
      createdAt: row.created_at,
    }));
  }

  getRuleFalsePositiveRate(ruleId: string): number | null {
    const row = this.db
      .prepare(
        `SELECT
           SUM(CASE WHEN status = 'false_positive' THEN 1 ELSE 0 END) AS fp,
           COUNT(*) AS total
         FROM vulnerabilities
         WHERE rule_id = ?`,
      )
      .get(ruleId) as { fp: number; total: number } | undefined;
    if (!row || row.total < 3) return null;
    return row.fp / row.total;
  }

  getLastCompletedCommit(targetId: number): string | null {
    const row = this.db
      .prepare(
        `SELECT source_commit FROM scans
         WHERE target_id = ? AND status = 'completed' AND source_commit IS NOT NULL
         ORDER BY id DESC LIMIT 1`,
      )
      .get(targetId) as { source_commit: string | null } | undefined;
    return row?.source_commit ?? null;
  }

  getMetricsSnapshot(): {
    scansTotal: number;
    scansActive: number;
    scansFailed: number;
    vulnsTotal: number;
    vulnsVerified: number;
    vulnsFalsePositive: number;
    targetsTotal: number;
  } {
    const q = (sql: string) => (this.db.prepare(sql).get() as { count: number }).count;
    return {
      scansTotal: q('SELECT COUNT(*) AS count FROM scans'),
      scansActive: q("SELECT COUNT(*) AS count FROM scans WHERE status = 'running'"),
      scansFailed: q("SELECT COUNT(*) AS count FROM scans WHERE status = 'failed'"),
      vulnsTotal: q('SELECT COUNT(*) AS count FROM vulnerabilities'),
      vulnsVerified: q("SELECT COUNT(*) AS count FROM vulnerabilities WHERE status IN ('verified', 'reported')"),
      vulnsFalsePositive: q("SELECT COUNT(*) AS count FROM vulnerabilities WHERE status = 'false_positive'"),
      targetsTotal: q('SELECT COUNT(*) AS count FROM targets'),
    };
  }
}
