import assert from 'node:assert/strict';
import test from 'node:test';
import { executeCollector } from '../../src/core/collector.js';
import osInfoCollector, {
  collectInstalledPatches,
  createOsInfoCollector,
} from '../../src/collectors/os-info/index.js';

const mockedOsData = {
  distro: 'Example Linux',
  release: '24.04',
  kernel: '6.8.0-example',
  arch: 'x64',
  hostname: 'test-host',
  platform: 'linux',
};

test('os-info maps mocked systeminformation output and patch data', async () => {
  const collector = createOsInfoCollector({
    systemInformation: { async osInfo() { return mockedOsData; } },
    patchChecker: async () => ({
      items: [{ name: 'openssl', installedVersion: '3.0.1' }],
      source: 'test-source',
      reason: null,
    }),
  });

  const data = await collector.run({}, {});

  assert.deepEqual(data, {
    prettyName: 'Example Linux 24.04',
    version: '24.04',
    kernelRelease: '6.8.0-example',
    architecture: 'x64',
    hostname: 'test-host',
    platform: 'linux',
    patches: {
      items: [{ name: 'openssl', installedVersion: '3.0.1' }],
      source: 'test-source',
      reason: null,
    },
  });
});

test('os-info keeps base information when the patch sub-check fails', async () => {
  const collector = createOsInfoCollector({
    systemInformation: { async osInfo() { return mockedOsData; } },
    patchChecker: async () => { throw new Error('tool unavailable'); },
  });

  const data = await collector.run({}, {});

  assert.equal(data.hostname, 'test-host');
  assert.equal(data.patches.items, null);
  assert.equal(data.patches.source, null);
  assert.match(data.patches.reason, /tool unavailable/);
});

test('isolated Windows patch check normalizes mocked Get-HotFix output', async () => {
  const patches = await collectInstalledPatches('win32', {
    runCommand: async (executable, args) => {
      assert.equal(executable, 'powershell.exe');
      assert.ok(args.includes('-NonInteractive'));
      return JSON.stringify({
        HotFixID: 'KB5000001',
        Description: 'Security Update',
        InstalledOn: '2026-01-02',
      });
    },
  });

  assert.deepEqual(patches, {
    items: [{
      hotfixId: 'KB5000001',
      description: 'Security Update',
      installedOn: '2026-01-02',
    }],
    source: 'powershell-get-hotfix',
    reason: null,
  });
});

test('isolated Linux patch check reports unavailable sources without throwing', async () => {
  const patches = await collectInstalledPatches('linux', {
    readTextFile: async () => {
      const error = new Error('permission denied');
      error.code = 'EACCES';
      throw error;
    },
    runCommand: async () => { throw new Error('dnf missing'); },
  });

  assert.equal(patches.items, null);
  assert.equal(patches.source, null);
  assert.match(patches.reason, /elevated privileges/);
  assert.match(patches.reason, /EACCES/);
});

test('real os-info collector produces the normalized result shape', async () => {
  const result = await executeCollector({
    collector: osInfoCollector,
    params: {},
    context: {},
    timeoutMs: 15000,
  });

  assert.equal(result.collector, 'os-info');
  assert.equal(result.status, 'success');
  assert.equal(result.error, null);
  assert.equal(typeof result.startedAt, 'string');
  assert.equal(typeof result.finishedAt, 'string');
  assert.equal(typeof result.data.prettyName, 'string');
  assert.ok(result.data.prettyName.length > 0);
  assert.ok(result.data.version === null || typeof result.data.version === 'string');
  assert.ok(result.data.kernelRelease === null || typeof result.data.kernelRelease === 'string');
  assert.ok(result.data.architecture === null || typeof result.data.architecture === 'string');
  assert.ok(result.data.hostname === null || typeof result.data.hostname === 'string');
  assert.ok(['linux', 'win32', 'darwin'].includes(result.data.platform));
  assert.equal(typeof result.data.patches, 'object');
  assert.ok(Array.isArray(result.data.patches.items) || result.data.patches.items === null);
  assert.ok(result.data.patches.reason === null || typeof result.data.patches.reason === 'string');
});
