import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const schemaPath = join(dirname(fileURLToPath(import.meta.url)), 'schema.sql');

export function createDatabase(path = ':memory:'): DatabaseSync {
  const db = new DatabaseSync(path);
  db.exec(readFileSync(schemaPath, 'utf8'));
  return db;
}

export type SentinelDatabase = DatabaseSync;
