import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { IntegrityService } from '../../src/security/integrity.js';

class MemoryStore { async loadIntegrityBaseline() { return this.value ?? null; } async saveIntegrityBaseline(value) { this.value = structuredClone(value); } }

test('first run establishes separate binary, config, and identity SHA-256 baselines', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'asvp-integrity-')); t.after(() => rm(dir, { recursive: true, force: true }));
  for (const [name, value] of [['agent', 'binary'], ['config.json', '{}'], ['identity.json', '{"agentId":"a"}']]) await writeFile(path.join(dir, name), value);
  const store = new MemoryStore();
  const service = new IntegrityService({ credentialStore: store, executablePath: 'agent', configPath: 'config.json', identityPath: 'identity.json', cwd: dir });
  const result = await service.verifyOrEstablish();
  assert.equal(result.established, true); assert.deepEqual(result.events, []);
  assert.match(store.value.hashes.binary.sha256, /^[a-f0-9]{64}$/);
  assert.match(store.value.hashes.config.sha256, /^[a-f0-9]{64}$/);
  assert.match(store.value.hashes.identity.sha256, /^[a-f0-9]{64}$/);
});

test('detects binary plus config/identity changes without blocking and does not trust them automatically', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'asvp-integrity-')); t.after(() => rm(dir, { recursive: true, force: true }));
  for (const [name, value] of [['agent', 'binary-v1'], ['config.json', '{"v":1}'], ['identity.json', '{"v":1}']]) await writeFile(path.join(dir, name), value);
  const store = new MemoryStore(); const service = new IntegrityService({ credentialStore: store, executablePath: 'agent', configPath: 'config.json', identityPath: 'identity.json', cwd: dir });
  await service.verifyOrEstablish(); const original = structuredClone(store.value);
  await writeFile(path.join(dir, 'agent'), 'binary-tampered'); await writeFile(path.join(dir, 'config.json'), '{"v":2}'); await writeFile(path.join(dir, 'identity.json'), '{"v":2}');
  const result = await service.verifyOrEstablish();
  assert.deepEqual(result.events.map((event) => [event.type, event.target]), [
    ['binary-integrity-mismatch', 'binary'], ['config-integrity-mismatch', 'config'], ['config-integrity-mismatch', 'identity'],
  ]);
  assert.deepEqual(store.value, original);
});

test('authorized upgrade rebaseline explicitly trusts changed files', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'asvp-integrity-')); t.after(() => rm(dir, { recursive: true, force: true }));
  await writeFile(path.join(dir, 'agent'), 'v1'); await writeFile(path.join(dir, 'config.json'), '{}');
  const store = new MemoryStore(); const service = new IntegrityService({ credentialStore: store, executablePath: 'agent', configPath: 'config.json', cwd: dir });
  await service.verifyOrEstablish(); await writeFile(path.join(dir, 'agent'), 'signed-release-v2');
  assert.equal((await service.verifyOrEstablish()).events.length, 1);
  await service.rebaseline(['binary'], 'authorized-install-or-upgrade');
  assert.deepEqual((await service.verifyOrEstablish()).events, []);
});
