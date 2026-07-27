import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { loadConfig } from '../../src/config/loader.js';
import { validateScaScanPaths } from '../../src/security/sca-scan-paths.js';

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

test('rejects non-loopback dashboard bind addresses during config validation', async () => {
  await withTempDirectory(async (directory) => {
    for (const bindAddress of ['0.0.0.0', '192.168.1.50']) {
      const alternatePath = path.join(directory, `${bindAddress}.json`);
      await writeFile(alternatePath, JSON.stringify({ dashboard: { bindAddress } }));
      await assert.rejects(
        loadConfig({ configPath: alternatePath, env: {}, loadDotEnv: false }),
        /Invalid agent configuration: \/dashboard\/bindAddress must be equal to one of the allowed values/,
      );
    }
  });
});

test('accepts every supported loopback dashboard bind address', async () => {
  await withTempDirectory(async (directory) => {
    for (const bindAddress of ['127.0.0.1', '::1', 'localhost']) {
      const alternatePath = path.join(directory, `${bindAddress.replaceAll(':', '_')}.json`);
      await writeFile(alternatePath, JSON.stringify({ dashboard: { bindAddress } }));
      const config = await loadConfig({ configPath: alternatePath, env: {}, loadDotEnv: false });
      assert.equal(config.dashboard.bindAddress, bindAddress);
    }
  });
});

test('rejects broad or sensitive SCA scan roots during config validation', async () => {
  await withTempDirectory(async (directory) => {
    const credentialPath = path.join(directory, '.ssh', 'project');
    const identityDirectory = path.join(directory, 'var');
    await mkdir(credentialPath, { recursive: true });
    await mkdir(identityDirectory, { recursive: true });
    const cases = [
      { scanPath: path.parse(directory).root, reason: 'filesystem root paths are not allowed' },
      { scanPath: os.homedir(), reason: 'current user home directory is not allowed' },
      { scanPath: credentialPath, reason: 'credential directories' },
      { scanPath: identityDirectory, reason: 'agent identity storage directory is not allowed' },
    ];
    for (const [index, entry] of cases.entries()) {
      const alternatePath = path.join(directory, `sensitive-${index}.json`);
      await writeFile(alternatePath, JSON.stringify({ collectors: { 'sca-deps': { scanPaths: [entry.scanPath] } } }));
      await assert.rejects(
        loadConfig({ configPath: alternatePath, env: {}, cwd: directory, loadDotEnv: false }),
        new RegExp(`SCA scan path.*is forbidden:.*${entry.reason}`),
      );
    }
  });
});

test('rejects a Windows home root when realpath returns a canonical alias', async () => {
  const lexicalHome = 'C:\\Users\\runneradmin';
  const canonicalHome = 'C:\\Users\\RUNNER~1';
  await assert.rejects(
    validateScaScanPaths([lexicalHome], {
      cwd: 'D:\\a\\ASVP-Agent',
      homeDirectory: lexicalHome,
      pathApi: path.win32,
      resolveRealPath: async (value) => value === lexicalHome ? canonicalHome : value,
    }),
    /SCA scan path.*is forbidden: the current user home directory is not allowed/,
  );
});

test('rejects a configured symlink root resolving to the user home directory', async () => {
  await withTempDirectory(async (directory) => {
    const linkedRoot = path.join(directory, 'linked-home');
    await symlink(os.homedir(), linkedRoot, process.platform === 'win32' ? 'junction' : 'dir');
    const alternatePath = path.join(directory, 'linked-home.json');
    await writeFile(alternatePath, JSON.stringify({ collectors: { 'sca-deps': { scanPaths: [linkedRoot] } } }));
    await assert.rejects(
      loadConfig({ configPath: alternatePath, env: {}, cwd: directory, loadDotEnv: false }),
      /SCA scan path.*linked-home.*is forbidden: the current user home directory is not allowed/,
    );
  });
});

test('fails config validation when an SCA root cannot be canonicalized', async () => {
  await withTempDirectory(async (directory) => {
    const missing = path.join(directory, 'missing-project');
    const alternatePath = path.join(directory, 'missing.json');
    await writeFile(alternatePath, JSON.stringify({ collectors: { 'sca-deps': { scanPaths: [missing] } } }));
    await assert.rejects(
      loadConfig({ configPath: alternatePath, env: {}, cwd: directory, loadDotEnv: false }),
      /SCA scan path.*missing-project.*cannot be resolved to a canonical path/,
    );
  });
});

test('accepts a specific SCA project directory', async () => {
  await withTempDirectory(async (directory) => {
    const project = path.join(directory, 'apps', 'service');
    await mkdir(project, { recursive: true });
    const alternatePath = path.join(directory, 'project.json');
    await writeFile(alternatePath, JSON.stringify({ collectors: { 'sca-deps': { scanPaths: [project] } } }));
    const config = await loadConfig({ configPath: alternatePath, env: {}, cwd: directory, loadDotEnv: false });
    assert.deepEqual(config.collectors['sca-deps'].scanPaths, [project]);
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
