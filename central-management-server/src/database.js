import { mkdirSync } from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

export const DEFAULT_TENANT_ID = '00000000-0000-4000-8000-000000000000';
export const DEFAULT_TENANT_NAME = 'Default tenant';

const schema = `
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  hostname TEXT,
  auth_token_hash TEXT NOT NULL UNIQUE,
  encryption_key TEXT NOT NULL,
  registered_at TEXT NOT NULL,
  last_heartbeat_at TEXT,
  status TEXT NOT NULL,
  platform TEXT,
  architecture TEXT,
  last_poll_at TEXT,
  agent_version TEXT,
  deregistered_at TEXT,
  task_sequence INTEGER NOT NULL DEFAULT 0,
  machine_fingerprint TEXT
);
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  agent_id TEXT REFERENCES agents(id),
  collector_name TEXT NOT NULL,
  params TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','dispatched','completed','failed')),
  created_at TEXT NOT NULL,
  dispatched_at TEXT
);
CREATE TABLE IF NOT EXISTS results (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  agent_id TEXT NOT NULL REFERENCES agents(id),
  task_id TEXT REFERENCES tasks(id),
  collector TEXT NOT NULL,
  status TEXT NOT NULL,
  raw_data TEXT NOT NULL,
  received_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS normalized_software (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  agent_id TEXT NOT NULL REFERENCES agents(id),
  source_result_id TEXT NOT NULL REFERENCES results(id) ON DELETE CASCADE,
  source_collector TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  raw_name TEXT NOT NULL,
  raw_version TEXT,
  vendor TEXT,
  product TEXT,
  normalized_version TEXT,
  cpe23_candidate TEXT,
  match_confidence TEXT NOT NULL CHECK(match_confidence IN ('high','medium','low','unmatched')),
  match_method TEXT NOT NULL,
  normalized_at TEXT NOT NULL,
  UNIQUE(source_result_id, ordinal)
);
CREATE TABLE IF NOT EXISTS patch_feed_cache (
  feed_name TEXT PRIMARY KEY,
  source_url TEXT NOT NULL,
  source_format TEXT NOT NULL,
  advisories_json TEXT NOT NULL,
  fetched_at TEXT,
  last_attempt_at TEXT NOT NULL,
  last_error TEXT
);
CREATE TABLE IF NOT EXISTS missing_patches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  agent_id TEXT NOT NULL REFERENCES agents(id),
  source_result_id TEXT NOT NULL REFERENCES results(id) ON DELETE CASCADE,
  advisory_id TEXT NOT NULL,
  severity TEXT,
  title TEXT,
  published_date TEXT,
  source TEXT NOT NULL,
  source_url TEXT,
  confidence TEXT NOT NULL CHECK(confidence IN ('high','low')),
  rationale TEXT NOT NULL,
  feed_fetched_at TEXT NOT NULL,
  matched_at TEXT NOT NULL,
  UNIQUE(source_result_id, advisory_id, source)
);
CREATE TABLE IF NOT EXISTS enrollment_tokens (
  token_hash TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  max_uses INTEGER,
  use_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS agent_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  agent_id TEXT REFERENCES agents(id),
  event_type TEXT NOT NULL,
  details TEXT NOT NULL,
  created_at TEXT NOT NULL
);
`;

function addColumn(database, table, definition) {
  const name = definition.split(/\s+/)[0];
  const columns = database.prepare(`PRAGMA table_info(${table})`).all();
  if (!columns.some((column) => column.name === name)) database.exec(`ALTER TABLE ${table} ADD COLUMN ${definition}`);
}

function migrateTenantFoundation(database) {
  const migratedAt = new Date(0).toISOString();
  database.prepare('INSERT OR IGNORE INTO tenants (id, name, created_at, status) VALUES (?, ?, ?, ?)')
    .run(DEFAULT_TENANT_ID, DEFAULT_TENANT_NAME, migratedAt, 'active');

  // SQLite cannot add a NOT NULL foreign-key column to populated tables in place.
  // New databases get the strict schema above; legacy tables get the FK column and
  // are immediately backfilled before foreign-key enforcement is checked.
  for (const table of ['agents', 'tasks', 'results', 'agent_events', 'enrollment_tokens']) {
    addColumn(database, table, 'tenant_id TEXT REFERENCES tenants(id)');
    database.prepare(`UPDATE ${table} SET tenant_id = ? WHERE tenant_id IS NULL`).run(DEFAULT_TENANT_ID);
  }

  database.exec(`
    CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents(tenant_id, id);
    CREATE INDEX IF NOT EXISTS idx_tasks_poll ON tasks(tenant_id, status, agent_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_results_agent ON results(tenant_id, agent_id, received_at);
    CREATE INDEX IF NOT EXISTS idx_normalized_software_agent ON normalized_software(tenant_id, agent_id, normalized_at);
    CREATE INDEX IF NOT EXISTS idx_normalized_software_source ON normalized_software(tenant_id, source_result_id);
    CREATE INDEX IF NOT EXISTS idx_missing_patches_agent ON missing_patches(tenant_id, agent_id, matched_at);
    CREATE INDEX IF NOT EXISTS idx_missing_patches_source ON missing_patches(tenant_id, source_result_id);
    CREATE INDEX IF NOT EXISTS idx_events_agent ON agent_events(tenant_id, agent_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_tenant ON enrollment_tokens(tenant_id, expires_at);
  `);
  const violations = database.prepare('PRAGMA foreign_key_check').all();
  if (violations.length) throw new Error(`Tenant migration left ${violations.length} foreign-key violation(s)`);
}

export function createDatabase({ filename = 'var/management.sqlite', cwd = process.cwd() } = {}) {
  const resolved = filename === ':memory:' ? filename : path.resolve(cwd, filename);
  if (resolved !== ':memory:') mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  const database = new Database(resolved);
  database.pragma('foreign_keys = ON');
  if (resolved !== ':memory:') database.pragma('journal_mode = WAL');
  database.exec(schema);
  addColumn(database, 'agents', 'platform TEXT');
  addColumn(database, 'agents', 'architecture TEXT');
  addColumn(database, 'agents', 'last_poll_at TEXT');
  addColumn(database, 'agents', 'agent_version TEXT');
  addColumn(database, 'agents', 'deregistered_at TEXT');
  addColumn(database, 'agents', 'task_sequence INTEGER NOT NULL DEFAULT 0');
  addColumn(database, 'agents', 'machine_fingerprint TEXT');
  database.transaction(() => migrateTenantFoundation(database))();
  return database;
}
