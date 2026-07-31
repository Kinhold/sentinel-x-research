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
}

export type SentinelDatabase = DatabaseSync;
