import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const schemaPath = join(dirname(fileURLToPath(import.meta.url)), 'schema.sql');

export function createDatabase(path = ':memory:'): DatabaseSync {
  const db = new DatabaseSync(path);
  db.exec('PRAGMA foreign_keys = ON;');
  if (path !== ':memory:') {
    try {
      db.exec('PRAGMA journal_mode = WAL;');
    } catch {
      // Some environments reject WAL; foreign_keys alone is enough for correctness.
    }
  }
  db.exec(readFileSync(schemaPath, 'utf8'));
  migrate(db);
  return db;
}

/** Lightweight additive migrations for existing on-disk DBs. */
function migrate(db: DatabaseSync): void {
  const columns = (table: string) =>
    (db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).map((row) => row.name);

  const scanCols = new Set(columns('scans'));
  if (!scanCols.has('source_mode')) db.exec('ALTER TABLE scans ADD COLUMN source_mode TEXT');
  if (!scanCols.has('source_path')) db.exec('ALTER TABLE scans ADD COLUMN source_path TEXT');
  if (!scanCols.has('source_commit')) db.exec('ALTER TABLE scans ADD COLUMN source_commit TEXT');

  const vulnCols = new Set(columns('vulnerabilities'));
  if (!vulnCols.has('rule_id')) db.exec('ALTER TABLE vulnerabilities ADD COLUMN rule_id TEXT');
  if (!vulnCols.has('fingerprint')) db.exec('ALTER TABLE vulnerabilities ADD COLUMN fingerprint TEXT');

  db.exec(`
    CREATE TABLE IF NOT EXISTS reports (
      vulnerability_id INTEGER PRIMARY KEY REFERENCES vulnerabilities(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      markdown TEXT NOT NULL,
      generated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS provenance (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      seq INTEGER NOT NULL,
      event TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      prev_hash TEXT,
      entry_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(scan_id, seq)
    );
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor TEXT NOT NULL DEFAULT 'operator',
      action TEXT NOT NULL,
      resource_type TEXT,
      resource_id TEXT,
      detail TEXT,
      request_id TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS suppressions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      fingerprint TEXT,
      rule_id TEXT,
      path_glob TEXT,
      reason TEXT NOT NULL,
      created_by TEXT NOT NULL DEFAULT 'operator',
      expires_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS campaigns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS campaign_targets (
      campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
      target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
      PRIMARY KEY (campaign_id, target_id)
    );
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS campaign_scans (
      campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
      scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      PRIMARY KEY (campaign_id, scan_id)
    );
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS attestations (
      scan_id INTEGER PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
      content_hash TEXT NOT NULL,
      signature TEXT,
      manifest_json TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
}

export type SentinelDatabase = DatabaseSync;
