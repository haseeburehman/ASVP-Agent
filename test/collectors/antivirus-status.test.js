import assert from 'node:assert/strict';
import test from 'node:test';
import { executeCollector } from '../../src/core/collector.js';
import antivirusStatusCollector, { createAntivirusStatusCollector } from '../../src/collectors/antivirus-status/index.js';

function commandMock(handler) {
  return async (executable, args, options) => handler(executable, args, options);
}

test('Windows uses fixed PowerShell and combines SecurityCenter2 with Defender status', async () => {
  const collector = createAntivirusStatusCollector({
    platform: 'win32',
    runCommand: commandMock(async (executable, args) => {
      assert.equal(executable, 'powershell.exe');
      assert.deepEqual(args.slice(0, 3), ['-NoProfile', '-NonInteractive', '-Command']);
      assert.match(args[3], /root\/SecurityCenter2/);
      assert.match(args[3], /Get-MpComputerStatus/);
      assert.match(args[3], /Get-MpPreference/);
      return JSON.stringify({
        SecurityCenter: [{ displayName: 'Microsoft Defender Antivirus', productState: 397568 }],
        Defender: {
          AntivirusEnabled: true,
          RealTimeProtectionEnabled: true,
          AntivirusSignatureVersion: '1.2.3.4',
          AntivirusSignatureLastUpdated: '2026-07-24T00:00:00Z',
        },
        Preference: null,
        Errors: [],
      });
    }),
  });

  const data = await collector.run({ ignored: 'not interpolated' });

  assert.equal(data.status, 'protected');
  assert.equal(data.products.length, 1);
  assert.equal(data.products[0].name, 'Microsoft Defender Antivirus');
  assert.equal(data.products[0].realTimeProtectionEnabled, true);
  assert.equal(data.products[0].version, '1.2.3.4');
    assert.equal(data.products[0].lastDefinitionUpdateTime, '2026-07-24T00:00:00Z');
});

test('Linux detects common AV/EDR from fixed local inventories', async () => {
  const calls = [];
  const collector = createAntivirusStatusCollector({
    platform: 'linux',
    runCommand: commandMock(async (executable, args) => {
      calls.push([executable, args]);
      if (executable === 'systemctl') return 'clamav-daemon.service enabled\nssh.service enabled';
      if (executable === 'ps') return 'systemd\nfalcon-sensor\n';
      throw new Error('unexpected command');
    }),
  });

  const data = await collector.run();

  assert.deepEqual(calls, [
    ['systemctl', ['list-unit-files', '--type=service', '--no-legend', '--no-pager', '--plain']],
    ['ps', ['-eo', 'comm=']],
  ]);
  assert.equal(data.status, 'protected');
  assert.deepEqual(data.products.map((item) => item.name), ['ClamAV', 'CrowdStrike Falcon']);
});

test('Linux distinguishes no detected AV from an undetermined inventory', async () => {
  const noAv = createAntivirusStatusCollector({
    platform: 'linux',
    runCommand: async (executable) => executable === 'ps' ? 'systemd\nsshd' : '',
  });
  const unavailable = createAntivirusStatusCollector({
    platform: 'linux',
    runCommand: async () => { throw new Error('not available'); },
  });

  const noAvData = await noAv.run();
  const unavailableData = await unavailable.run();

  assert.equal(noAvData.status, 'unprotected');
  assert.match(noAvData.reason, /No supported antivirus or EDR/);
  assert.equal(unavailableData.status, 'undetermined');
  assert.match(unavailableData.reason, /Unable to inspect/);
});

test('macOS checks Gatekeeper and XProtect with fixed absolute commands', async () => {
  const collector = createAntivirusStatusCollector({
    platform: 'darwin',
    runCommand: commandMock(async (executable, args) => {
      if (executable === '/usr/sbin/spctl') {
        assert.deepEqual(args, ['--status']);
        return 'assessments enabled';
      }
      assert.equal(executable, '/usr/sbin/pkgutil');
      assert.deepEqual(args, ['--pkg-info', 'com.apple.pkg.XProtectPlistConfigData']);
      return 'package-id: com.apple.pkg.XProtectPlistConfigData\nversion: 2200';
    }),
  });

  const data = await collector.run();

  assert.equal(data.status, 'protected');
  assert.deepEqual(data.checks, { gatekeeper: true, xprotect: true });
  assert.equal(data.products[0].version, '2200');
});

test('collector preserves abort behavior', async () => {
  const controller = new AbortController();
  controller.abort();
  const collector = createAntivirusStatusCollector({ platform: 'linux' });

  await assert.rejects(collector.run({}, { signal: controller.signal }), { name: 'AbortError', code: 'ABORT_ERR' });
});

test('real collector performs only bounded local checks and returns normalized data', async () => {
  const result = await executeCollector({
    collector: antivirusStatusCollector,
    params: {},
    context: {},
    timeoutMs: 25000,
  });

  assert.equal(result.collector, 'antivirus-status');
  assert.equal(result.status, 'success');
  assert.equal(result.error, null);
  assert.ok(['linux', 'win32', 'darwin'].includes(result.data.platform));
  assert.ok(['protected', 'unprotected', 'undetermined'].includes(result.data.status));
  assert.ok(Array.isArray(result.data.products));
  assert.equal(typeof result.data.checks, 'object');
  assert.ok(result.data.reason === null || typeof result.data.reason === 'string');
  for (const product of result.data.products) {
    assert.equal(typeof product.name, 'string');
    assert.ok(product.enabled === null || typeof product.enabled === 'boolean');
    assert.ok(product.upToDate === null || typeof product.upToDate === 'boolean');
    assert.ok(product.version === null || typeof product.version === 'string');
    assert.equal(typeof product.source, 'string');
  }
});
