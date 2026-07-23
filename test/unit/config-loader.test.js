import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { loadConfig } from '../../src/config/loader.js';

async function withTempDirectory(callback) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-config-'));
  try {
    await callback(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test('loads defaults, alternate config, and environment in precedence order', async () => {
  await withTempDirectory(async (directory) => {
    const alternatePath = path.join(directory, 'agent.json');
    await writeFile(alternatePath, JSON.stringify({
      agent: { heartbeatIntervalMs: 5000, logLevel: 'warn' },
    }));

    const config = await loadConfig({
      configPath: alternatePath,
      env: { ASVP_LOG_LEVEL: 'debug', ASVP_HEARTBEAT_INTERVAL_MS: '2500' },
      loadDotEnv: false,
    });

    assert.equal(config.server.mode, 'http');
    assert.equal(config.server.resultsPath, '/api/agents/results');
    assert.equal(config.agent.logLevel, 'debug');
    assert.equal(config.agent.heartbeatIntervalMs, 2500);
  });
});

test('fails fast with a clear validation error', async () => {
  await withTempDirectory(async (directory) => {
    const alternatePath = path.join(directory, 'invalid.json');
    await writeFile(alternatePath, JSON.stringify({ server: { url: null } }));

    await assert.rejects(
      loadConfig({ configPath: alternatePath, env: {}, loadDotEnv: false }),
      /Invalid agent configuration: \/server\/url must be string/,
    );
  });
});

test('allows plain HTTP only for a loopback development management server', async () => {
  await withTempDirectory(async (directory) => {
    const alternatePath = path.join(directory, 'loopback.json');
    await writeFile(alternatePath, JSON.stringify({
      server: { mode: 'http', url: 'http://127.0.0.1:8080' },
    }));
    const config = await loadConfig({ configPath: alternatePath, env: {}, loadDotEnv: false });
    assert.equal(config.server.url, 'http://127.0.0.1:8080');
  });
});

test('requires HTTPS when the real HTTP transport is selected for a non-loopback host', async () => {
  await withTempDirectory(async (directory) => {
    const alternatePath = path.join(directory, 'insecure.json');
    await writeFile(alternatePath, JSON.stringify({
      server: { mode: 'http', url: 'http://example.test' },
    }));

    await assert.rejects(
      loadConfig({ configPath: alternatePath, env: {}, loadDotEnv: false }),
      /must match pattern.*https/,
    );
  });
});
