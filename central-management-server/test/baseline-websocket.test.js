import assert from 'node:assert/strict';
import { createCipheriv, randomBytes, randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import { gzip } from 'node:zlib';
import test from 'node:test';
import request from 'supertest';
import { WebSocket } from 'ws';
import { BASELINE_COLLECTORS, createApp } from '../src/app.js';
import { createDashboardSessions } from '../src/dashboard-session.js';
import { createDatabase } from '../src/database.js';
import { createFleetWebSocketHub } from '../src/fleet-websocket.js';

const gzipAsync = promisify(gzip);
const logger = { info() {}, warn() {}, error() {} };
function listen(app) { return new Promise((resolve, reject) => { const server = app.listen(0, '127.0.0.1', () => resolve(server)); server.once('error', reject); }); }
function nextMessage(socket, type) { return new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${type}`)), 3000); const handler = (raw) => { const message = JSON.parse(raw.toString()); if (message.type !== type) return; clearTimeout(timer); socket.off('message', handler); resolve(message); }; socket.on('message', handler); }); }
async function envelope(result, identity) {
  const plaintext = Buffer.from(JSON.stringify(result)); const compressed = await gzipAsync(plaintext); const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(identity.encryptionKey, 'base64'), iv);
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
  return { schemaVersion: 1, queueItemId: randomUUID(), agentId: identity.agentId, enqueuedAt: new Date().toISOString(), contentEncoding: 'gzip', encryption: 'aes-256-gcm', iv: iv.toString('base64'), authTag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') };
}

test('new registration enqueues only the local baseline bundle and reschedules when due', async (t) => {
  const database = createDatabase({ filename: ':memory:' }); t.after(() => database.close());
  let clock = new Date('2026-01-01T00:00:00.000Z');
  const app = createApp({ database, adminToken: 'admin', logger, now: () => new Date(clock), baselineRescanIntervalMs: 60000 });
  const api = request(app);
  const identity = (await api.post('/api/agents/register').send({ hostname: 'baseline-host', platform: 'linux', architecture: 'x64' }).expect(201)).body;
  const initial = database.prepare('SELECT collector_name FROM tasks WHERE agent_id = ? ORDER BY collector_name').all(identity.agentId).map((row) => row.collector_name);
  assert.deepEqual(initial, [...BASELINE_COLLECTORS].sort());
  assert.equal(initial.includes('network-scan'), false); assert.equal(initial.includes('tls-checks'), false);
  await api.post('/api/agents/tasks/poll').set('Authorization', `Bearer ${identity.authToken}`).send({ agentId: identity.agentId }).expect(200);
  assert.equal(database.prepare('SELECT COUNT(*) count FROM tasks WHERE agent_id = ?').get(identity.agentId).count, 5);
  clock = new Date('2026-01-01T00:01:01.000Z');
  const recurring = await api.post('/api/agents/tasks/poll').set('Authorization', `Bearer ${identity.authToken}`).send({ agentId: identity.agentId }).expect(200);
  assert.deepEqual(recurring.body.map((task) => task.collectorName).sort(), [...BASELINE_COLLECTORS].sort());
});

test('authenticated fleet websocket receives a push when a decrypted result arrives', async (t) => {
  const database = createDatabase({ filename: ':memory:' });
  const sessions = createDashboardSessions({ adminToken: 'admin' });
  const hub = createFleetWebSocketHub({ sessions, logger });
  const app = createApp({ database, adminToken: 'admin', dashboardSessions: sessions, fleetHub: hub, baselineCollectors: [], logger });
  const server = await listen(app); hub.attach(server);
  t.after(async () => { for (const client of hub.server.clients) client.terminate(); await hub.close(); await new Promise((resolve) => server.close(resolve)); database.close(); });
  const api = request(app);
  const identity = (await api.post('/api/agents/register').send({ hostname: 'push-host', platform: 'linux', architecture: 'x64' }).expect(201)).body;
  const login = await api.post('/api/dashboard/session').send({ token: 'admin' }).expect(200);
  const cookie = login.headers['set-cookie'][0].split(';')[0];
  const port = server.address().port;
  await new Promise((resolve) => { const unauthorized = new WebSocket(`ws://127.0.0.1:${port}/api/dashboard/live`); unauthorized.once('unexpected-response', (_request, response) => { assert.equal(response.statusCode, 401); resolve(); }); });
  const socket = new WebSocket(`ws://127.0.0.1:${port}/api/dashboard/live`, { headers: { Cookie: cookie } });
  await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
  const pushed = nextMessage(socket, 'result-received');
  const result = { taskId: null, collector: 'antivirus-status', status: 'success', data: { status: 'protected', products: [{ name: 'Fixture AV' }] } };
  await api.post('/api/agents/results').set('Authorization', `Bearer ${identity.authToken}`).send(await envelope(result, identity)).expect(200);
  const message = await pushed;
  assert.equal(message.agentId, identity.agentId); assert.equal(message.collector, 'antivirus-status'); assert.equal(message.status, 'success');
  assert.deepEqual(message.summary.keys, ['status', 'products']);
  socket.close();
});
