import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { loadConfig } from '../../src/config/loader.js';
import { validateManagementServerUrl, writeEnrollmentConfig } from '../../src/enrollment/index.js';

test('enrollment URL validation rejects placeholders, malformed URLs, and unsafe HTTP', () => {
  assert.throws(() => validateManagementServerUrl('https://management.example.invalid'), /real management server URL/);
  assert.throws(() => validateManagementServerUrl('not-a-url'), /well-formed/);
  assert.throws(() => validateManagementServerUrl('http://management.example.com'), /must use HTTPS/);
  assert.throws(() => validateManagementServerUrl('https://user:pass@example.com'), /credentials/);
  assert.equal(validateManagementServerUrl('https://asvp.company.com/'), 'https://asvp.company.com');
  assert.equal(validateManagementServerUrl('http://127.0.0.1:8080'), 'http://127.0.0.1:8080');
});

test('enrollment preserves config and is loaded on the next start', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-enroll-'));
  const configPath = path.join(directory, 'config.json');
  try {
    await writeFile(configPath, JSON.stringify({ agent: { logLevel: 'warn' } }));
    const result = await writeEnrollmentConfig({ configPath, serverUrl: 'https://asvp.company.com/', enrollmentToken: 'short-lived-token' });
    assert.equal(result.enrollmentTokenConfigured, true);
    const written = JSON.parse(await readFile(configPath, 'utf8'));
    assert.equal(written.agent.logLevel, 'warn');
    assert.equal(written.server.url, 'https://asvp.company.com');
    assert.equal(written.server.enrollmentToken, 'short-lived-token');
    const loaded = await loadConfig({ configPath, env: {}, loadDotEnv: false });
    assert.equal(loaded.server.url, 'https://asvp.company.com');
    assert.equal(loaded.server.enrollmentToken, 'short-lived-token');
  } finally { await rm(directory, { recursive: true, force: true }); }
});
