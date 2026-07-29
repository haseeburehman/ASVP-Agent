import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { createDatabase, DEFAULT_TENANT_ID } from '../src/database.js';
import { createPatchFeedCache } from '../src/vulnerability/patch-feed-cache.js';

const logger = { info() {}, warn() {}, error() {} };

function insertAgent(database, id, tenantId = DEFAULT_TENANT_ID) {
  database.prepare(`INSERT INTO agents (id, tenant_id, hostname, auth_token_hash, encryption_key, registered_at, status, machine_fingerprint)
    VALUES (?, ?, ?, ?, ?, ?, 'registered', ?)`).run(id, tenantId, id, randomBytes(32).toString('hex'), randomBytes(32).toString('base64'), new Date().toISOString(), randomBytes(32).toString('hex'));
}

function insertOsResult(database, { id, agentId, prettyName, version, patches, tenantId = DEFAULT_TENANT_ID }) {
  database.prepare(`INSERT INTO results (id, tenant_id, agent_id, task_id, collector, status, raw_data, received_at)
    VALUES (?, ?, ?, NULL, 'os-info', 'success', ?, ?)`).run(id, tenantId, agentId,
    JSON.stringify({ collector: 'os-info', status: 'success', data: { prettyName, version, patches } }), new Date().toISOString());
}

test('cached advisories asynchronously derive tenant-scoped missing OS patches', async (t) => {
  const database = createDatabase({ filename: ':memory:' });
  t.after(() => database.close());
  const fetchedAt = '2026-07-20T00:00:00.000Z';
  const cache = createPatchFeedCache({ database, logger, now: () => new Date(fetchedAt), refresh: async () => ({
    ubuntu: { error: null, advisories: [{ advisoryId: 'USN-7000-1', severity: 'high', title: 'Kernel security update', releaseDate: '2026-07-10T00:00:00.000Z', affected: [{ os: 'Ubuntu', versionRange: 'Ubuntu 24.04 LTS' }], source: { name: 'Ubuntu Security Notices', url: 'https://ubuntu.com/security/notices/USN-7000-1' } }] },
    windowsMsrc: { error: null, advisories: [{ advisoryId: 'CVE-2026-1000', severity: 'critical', title: 'Windows security update', releaseDate: '2026-06-01T00:00:00.000Z', affected: [{ os: 'Microsoft Windows', versionRange: 'Windows 11' }], source: { name: 'Microsoft Security Response Center CVRF API', url: 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun' } }] },
  }) });
  await cache.refreshAll();

  insertAgent(database, 'ubuntu-agent');
  insertAgent(database, 'windows-agent');
  insertOsResult(database, { id: 'ubuntu-result', agentId: 'ubuntu-agent', prettyName: 'Ubuntu 24.04 LTS', version: '24.04', patches: { items: [{ identifier: 'linux-image', installedAt: '2026-06-01' }], totalCount: 1, mostRecentInstalledAt: '2026-06-01', reason: null } });
  insertOsResult(database, { id: 'windows-result', agentId: 'windows-agent', prettyName: 'Windows 11', version: '11', patches: { items: [{ identifier: 'KB5000000', installedAt: '2026-07-01' }], totalCount: 1, mostRecentInstalledAt: '2026-07-01', reason: null } });

  const app = createApp({ database, adminToken: 'admin', taskSigningSecret: 'secret', baselineCollectors: [], logger });
  await app.locals.normalizationWorker.drain();
  const api = request(app);
  const missing = await api.get(`/api/admin/tenants/${DEFAULT_TENANT_ID}/agents/ubuntu-agent/missing-patches`).set('Authorization', 'Bearer admin').expect(200);
  assert.equal(missing.body.patches.length, 1);
  assert.equal(missing.body.patches[0].advisoryId, 'USN-7000-1');
  assert.equal(missing.body.patches[0].confidence, 'low');
  assert.equal(missing.body.patches[0].feedFetchedAt, fetchedAt);
  assert.match(missing.body.assessment, /not vendor confirmation/i);
  assert.ok(missing.body.feedCache.some((feed) => feed.feedName === 'ubuntu' && feed.fetchedAt === fetchedAt));

  const current = await api.get(`/api/admin/tenants/${DEFAULT_TENANT_ID}/agents/windows-agent/missing-patches`).set('Authorization', 'Bearer admin').expect(200);
  assert.deepEqual(current.body.patches, []);
  await api.get(`/api/admin/tenants/11111111-1111-4111-8111-111111111111/agents/ubuntu-agent/missing-patches`).set('Authorization', 'Bearer admin').expect(404);
  await api.get(`/api/admin/tenants/${DEFAULT_TENANT_ID}/agents/ubuntu-agent/missing-patches`).expect(401);
});

test('first feed failure is visible with no successful fetchedAt timestamp', async (t) => {
  const database = createDatabase({ filename: ':memory:' });
  t.after(() => database.close());
  const cache = createPatchFeedCache({ database, logger, now: () => new Date('2026-07-20T00:00:00.000Z'), refresh: async () => ({
    debian: { advisories: [], error: { message: 'network unreachable' } },
  }) });
  await cache.refreshAll();
  const row = database.prepare("SELECT fetched_at, last_attempt_at, last_error FROM patch_feed_cache WHERE feed_name = 'debian'").get();
  assert.equal(row.fetched_at, null);
  assert.equal(row.last_attempt_at, '2026-07-20T00:00:00.000Z');
  assert.equal(row.last_error, 'network unreachable');
});

test('feed failure retains cached advisories and exposes staleness metadata', async (t) => {
  const database = createDatabase({ filename: ':memory:' });
  t.after(() => database.close());
  let fail = false;
  let clock = '2026-07-20T00:00:00.000Z';
  const cache = createPatchFeedCache({ database, logger, now: () => new Date(clock), refresh: async () => ({
    ubuntu: fail ? { advisories: [], error: { message: 'upstream unavailable' } } : { advisories: [{ advisoryId: 'USN-1' }], error: null },
  }) });
  await cache.refreshAll();
  fail = true; clock = '2026-07-21T00:00:00.000Z';
  await cache.refreshAll();
  const row = database.prepare("SELECT advisories_json, fetched_at, last_attempt_at, last_error FROM patch_feed_cache WHERE feed_name = 'ubuntu'").get();
  assert.equal(JSON.parse(row.advisories_json)[0].advisoryId, 'USN-1');
  assert.equal(row.fetched_at, '2026-07-20T00:00:00.000Z');
  assert.equal(row.last_attempt_at, '2026-07-21T00:00:00.000Z');
  assert.equal(row.last_error, 'upstream unavailable');
});
