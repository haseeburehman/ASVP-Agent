import { mkdirSync } from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

const schema = `
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  hostname TEXT,
  auth_token_hash TEXT NOT NULL UNIQUE,
  encryption_key TEXT NOT NULL,
  registered_at TEXT NOT NULL,
  last_heartbeat_at TEXT,
  status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  agent_id TEXT REFERENCES agents(id),
  collector_name TEXT NOT NULL,
  params TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','dispatched','completed','failed')),
  created_at TEXT NOT NULL,
  dispatched_at TEXT
);
CREATE TABLE IF NOT EXISTS results (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  task_id TEXT REFERENCES tasks(id),
  collector TEXT NOT NULL,
  status TEXT NOT NULL,
  raw_data TEXT NOT NULL,
  received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_poll ON tasks(status, agent_id, created_at);
CREATE INDEX IF NOT EXISTS idx_results_agent ON results(agent_id, received_at);
`;

export function createDatabase({ filename = 'var/management.sqlite', cwd = process.cwd() } = {}) {
  const resolved = filename === ':memory:' ? filename : path.resolve(cwd, filename);
  if (resolved !== ':memory:') mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  const database = new Database(resolved);
  database.pragma('foreign_keys = ON');
  if (resolved !== ':memory:') database.pragma('journal_mode = WAL');
  database.exec(schema);
  return database;
}
