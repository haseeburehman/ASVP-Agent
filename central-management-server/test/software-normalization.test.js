import assert from 'node:assert/strict';
import { createCipheriv, randomBytes, randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import { gzip } from 'node:zlib';
import test from 'node:test';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { createDatabase, DEFAULT_TENANT_ID } from '../src/database.js';
import { KNOWN_VENDOR_PRODUCTS, normalizeSoftwareEntry, normalizeStoredResult } from '../src/vulnerability/normalize.js';

const gzipAsync = promisify(gzip);
const logger = { info() {}, warn() {}, error() {} };

async function envelope(identity, result) {
  const compressed = await gzipAsync(Buffer.from(JSON.stringify(result)));
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(identity.encryptionKey, 'base64'), iv);
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
  return {
    schemaVersion: 1, queueItemId: randomUUID(), agentId: identity.agentId,
    machineFingerprint: identity.machineFingerprint, enqueuedAt: new Date().toISOString(),
    contentEncoding: 'gzip', encryption: 'aes-256-gcm', iv: iv.toString('base64'),
    authTag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64'),
  };
}

async function register(api, machineFingerprint) {
  const body = (await api.post('/api/agents/register')
    .send({ hostname: `agent-${machineFingerprint[0]}`, platform: 'linux', architecture: 'x64', machineFingerprint })
    .expect(201)).body;
  return { ...body, machineFingerprint };
}

test('known table is modest and normalization labels exact, heuristic, and unmatched results honestly', () => {
  assert.equal(KNOWN_VENDOR_PRODUCTS.length, 20);
  assert.deepEqual(normalizeSoftwareEntry({ name: 'Google Chrome', version: '126.0.1' }), {
    rawName: 'Google Chrome', rawVersion: '126.0.1', vendor: 'google', product: 'chrome', version: '126.0.1',
    cpe23Candidate: 'cpe:2.3:a:google:chrome:126.0.1:*:*:*:*:*:*:*', matchConfidence: 'high', matchMethod: 'exact-known-vendor-table',
  });
  const heuristic = normalizeSoftwareEntry({ name: 'Acme - Widget Server', version: 'v2.4.0' });
  assert.equal(heuristic.vendor, 'Acme');
  assert.equal(heuristic.product, 'Widget Server');
  assert.equal(heuristic.version, '2.4.0');
  assert.equal(heuristic.matchConfidence, 'low');
  assert.equal(heuristic.matchMethod, 'heuristic-parse');
  const unmatched = normalizeSoftwareEntry({ name: 'MysteryTool', version: null });
  assert.equal(unmatched.vendor, null);
  assert.equal(unmatched.cpe23Candidate, null);
  assert.equal(unmatched.matchConfidence, 'unmatched');
  assert.equal(unmatched.matchMethod, 'unmatched');
});

test('collector-specific extraction handles apps, OS, dependencies, and container packages', () => {
  const examples = [
    { collector: 'apps', status: 'success', data: { applications: { items: [{ name: 'Firefox', version: '1' }] } } },
    { collector: 'os-info', status: 'success', data: { prettyName: 'Ubuntu 24.04 LTS', version: '24.04' } },
    { collector: 'sca-deps', status: 'success', data: { dependencies: [{ name: 'node', version: '^20.0.0' }] } },
    { collector: 'containers', status: 'success', data: { containers: [{ sbom: { packages: [{ name: 'nginx', version: '1.26' }] } }] } },
  ];
  assert.deepEqual(examples.map((result) => normalizeStoredResult(result).length), [1, 1, 1, 1]);
  const [ubuntu] = normalizeStoredResult(examples[1]);
  assert.match(ubuntu.cpe23Candidate, /^cpe:2\.3:o:/);
  assert.doesNotMatch(ubuntu.cpe23Candidate, /^cpe:2\.3:a:/);
  assert.match(normalizeStoredResult(examples[0])[0].cpe23Candidate, /^cpe:2\.3:a:/);
  assert.deepEqual(normalizeStoredResult({ collector: 'apps', status: 'failed', data: {} }), []);
});

test('supported Fedora normalizes as OS while an unknown OS stays unmatched', () => {
  const [fedora] = normalizeStoredResult({ collector: 'os-info', status: 'success', data: { prettyName: 'Fedora Linux 40', version: '40' } });
  assert.equal(fedora.vendor, 'fedoraproject');
  assert.equal(fedora.product, 'fedora_linux');
  assert.equal(fedora.matchConfidence, 'high');
  assert.match(fedora.cpe23Candidate, /^cpe:2\.3:o:/);
  const [unknown] = normalizeStoredResult({ collector: 'os-info', status: 'success', data: { prettyName: 'Mystery OS', version: '1' } });
  assert.equal(unknown.matchConfidence, 'unmatched');
  assert.equal(unknown.cpe23Candidate, null);
});

test('startup asynchronously backfills relevant stored results missing derived rows', async (t) => {
  const database = createDatabase({ filename: ':memory:' });
  t.after(() => database.close());
  const timestamp = new Date().toISOString();
  database.prepare(`INSERT INTO agents (id, tenant_id, hostname, auth_token_hash, encryption_key, registered_at, status, machine_fingerprint)
    VALUES ('agent-backfill', ?, 'backfill', ?, ?, ?, 'registered', ?)`)
    .run(DEFAULT_TENANT_ID, 'c'.repeat(64), randomBytes(32).toString('base64'), timestamp, 'c'.repeat(64));
  database.prepare(`INSERT INTO results (id, tenant_id, agent_id, task_id, collector, status, raw_data, received_at)
    VALUES ('result-backfill', ?, 'agent-backfill', NULL, 'os-info', 'success', ?, ?)`)
    .run(DEFAULT_TENANT_ID, JSON.stringify({ collector: 'os-info', status: 'success', data: { prettyName: 'Ubuntu 24.04 LTS', version: '24.04' } }), timestamp);

  const app = createApp({ database, adminToken: 'admin', taskSigningSecret: 'signing-secret', baselineCollectors: [], logger });
  await app.locals.normalizationWorker.drain();
  assert.equal(database.prepare("SELECT COUNT(*) AS count FROM normalized_software WHERE source_result_id = 'result-backfill'").get().count, 1);
});

test('result ingestion schedules derived rows and admin endpoint enforces tenant plus agent scope', async (t) => {
  const database = createDatabase({ filename: ':memory:' });
  t.after(() => database.close());
  const app = createApp({ database, adminToken: 'admin', taskSigningSecret: 'signing-secret', baselineCollectors: [], logger });
  const api = request(app);
  const agentA = await register(api, 'a'.repeat(64));
  const tenantB = '11111111-1111-4111-8111-111111111111';
  database.prepare('INSERT INTO tenants (id, name, created_at, status) VALUES (?, ?, ?, ?)').run(tenantB, 'Tenant B', new Date().toISOString(), 'active');
  const agentBId = randomUUID();
  database.prepare(`INSERT INTO agents (id, tenant_id, hostname, auth_token_hash, encryption_key, registered_at, status, machine_fingerprint)
    VALUES (?, ?, 'agent-b', ?, ?, ?, 'registered', ?)`)
    .run(agentBId, tenantB, 'b'.repeat(64), randomBytes(32).toString('base64'), new Date().toISOString(), 'b'.repeat(64));

  const result = { collector: 'apps', status: 'success', data: { applications: { items: [
    { name: 'Google Chrome', version: '126.0.1' },
    { name: 'Acme - Widget Server', version: 'v2.4.0' },
  ] } } };
  const upload = await envelope(agentA, result);
  await api.post('/api/agents/results').set('Authorization', `Bearer ${agentA.authToken}`).send(upload).expect(200, { accepted: true, queueItemId: upload.queueItemId });
  await app.locals.normalizationWorker.drain();
  assert.equal(database.prepare('SELECT COUNT(*) AS count FROM normalized_software WHERE tenant_id = ? AND agent_id = ?').get(DEFAULT_TENANT_ID, agentA.agentId).count, 2);
  assert.equal(JSON.parse(database.prepare('SELECT raw_data FROM results WHERE id = ?').get(upload.queueItemId).raw_data).data.applications.items[0].name, 'Google Chrome');

  const response = await api.get(`/api/admin/tenants/${DEFAULT_TENANT_ID}/agents/${agentA.agentId}/normalized-software`)
    .set('Authorization', 'Bearer admin').expect(200);
  assert.equal(response.body.software.length, 2);
  assert.equal(response.body.software[0].sourceResultId, upload.queueItemId);
  assert.equal(Object.hasOwn(response.body.software[0], 'raw_data'), false);
  await api.get(`/api/admin/tenants/${tenantB}/agents/${agentA.agentId}/normalized-software`)
    .set('Authorization', 'Bearer admin').expect(404);
  await api.get(`/api/admin/tenants/${DEFAULT_TENANT_ID}/agents/${agentBId}/normalized-software`)
    .set('Authorization', 'Bearer admin').expect(404);
  await api.get(`/api/admin/tenants/${DEFAULT_TENANT_ID}/agents/${agentA.agentId}/normalized-software`).expect(401);
});
