import assert from 'node:assert/strict';
import test from 'node:test';
import * as plist from 'plist';
import { executeCollector } from '../../src/core/collector.js';
import appsCollector, { createAppsCollector } from '../../src/collectors/apps/index.js';

function commandMock(handlers) {
  return async (executable, args, options) => {
    const handler = handlers[executable];
    if (!handler) throw new Error(`Unexpected command: ${executable}`);
    return handler(args, options);
  };
}

test('Linux adapter parses dpkg packages, systemd services, and correlates names', async () => {
  const collector = createAppsCollector({
    platform: 'linux',
    runCommand: commandMock({
      'dpkg-query': async () => 'nginx\t1.24.0\nopenssl\t3.0.0',
      systemctl: async () => [
        'nginx.service loaded active running nginx web server',
        'ssh.service loaded inactive dead OpenSSH server',
      ].join('\n'),
    }),
  });

  const data = await collector.run({}, { collectorConfig: { maxItems: 10 } });

  assert.equal(data.applications.source, 'dpkg');
  assert.equal(data.applications.items[0].name, 'nginx');
  assert.equal(data.applications.items[0].version, '1.24.0');
  assert.equal(data.applications.items[0].binaryPath, null);
  assert.equal(data.applications.items[0].serviceStatus, 'running');
  assert.equal(data.applications.items[0].correlated, true);
  assert.equal(data.services.items[1].serviceStatus, 'stopped');
  assert.equal(data.correlation.successful, true);
  assert.equal(data.correlation.matchedCount, 1);
});

test('Windows adapter parses uninstall registry and Get-Service JSON', async () => {
  const collector = createAppsCollector({
    platform: 'win32',
    runCommand: commandMock({
      'powershell.exe': async (args) => {
        const script = args.at(-1);
        if (script.includes('Get-ItemProperty')) {
          assert.match(script, /WOW6432Node/);
          return JSON.stringify({
            DisplayName: 'MySQL Server',
            DisplayVersion: '8.4.0',
            InstallLocation: 'C:\\Program Files\\MySQL',
            DisplayIcon: 'C:\\Program Files\\MySQL\\mysql.exe,0',
          });
        }
        assert.match(script, /Get-Service/);
        return JSON.stringify({
          Name: 'MySQL',
          DisplayName: 'MySQL Server',
          Status: 'Running',
          BinaryPathName: '"C:\\Program Files\\MySQL\\mysqld.exe" --defaults-file=config.ini',
        });
      },
    }),
  });

  const data = await collector.run({}, { collectorConfig: { maxItems: 10 } });

  assert.equal(data.applications.items[0].name, 'MySQL Server');
  assert.equal(data.applications.items[0].version, '8.4.0');
  assert.equal(data.applications.items[0].binaryPath, 'C:\\Program Files\\MySQL\\mysql.exe');
  assert.equal(data.applications.items[0].serviceStatus, 'running');
  assert.equal(data.services.items[0].serviceName, 'MySQL');
  assert.equal(data.services.items[0].binaryPath, 'C:\\Program Files\\MySQL\\mysqld.exe');
  assert.equal(data.correlation.matchedCount, 1);
});

test('macOS adapter parses app bundle plists and launchctl services', async () => {
  const infoPlist = plist.build({
    CFBundleDisplayName: 'Example App',
    CFBundleShortVersionString: '2.5.1',
    CFBundleExecutable: 'example-bin',
  });
  const collector = createAppsCollector({
    platform: 'darwin',
    readDirectory: async (root) => root === '/Applications'
      ? [{ name: 'Example.app', isDirectory: () => true }]
      : [],
    readTextFile: async () => infoPlist,
    runCommand: commandMock({
      launchctl: async () => 'PID\tStatus\tLabel\n123\t0\tcom.example.app\n-\t1\tcom.example.stopped',
    }),
  });

  const data = await collector.run({}, { collectorConfig: { maxItems: 10 } });

  assert.equal(data.applications.items[0].name, 'Example App');
  assert.equal(data.applications.items[0].version, '2.5.1');
  assert.equal(data.applications.items[0].binaryPath, '/Applications/Example.app/Contents/MacOS/example-bin');
  assert.equal(data.services.items[0].serviceStatus, 'running');
  assert.equal(data.services.items[1].serviceStatus, 'stopped');
});

test('apps collector caps combined output and reports truncation', async () => {
  const collector = createAppsCollector({
    platform: 'linux',
    runCommand: commandMock({
      'dpkg-query': async () => 'a\t1\nb\t2\nc\t3',
      systemctl: async () => [
        'a.service loaded active running A',
        'b.service loaded active running B',
        'c.service loaded active running C',
      ].join('\n'),
    }),
  });

  const data = await collector.run({}, { collectorConfig: { maxItems: 2 } });

  assert.equal(data.summary.maxItems, 2);
  assert.equal(data.summary.totalDetected, 6);
  assert.equal(data.summary.returnedItems, 2);
  assert.equal(data.summary.truncated, 4);
  assert.equal(data.applications.items.length, 1);
  assert.equal(data.services.items.length, 1);
  assert.equal(data.applications.truncated, 2);
  assert.equal(data.services.truncated, 2);
});

test('service failure degrades gracefully while package results remain available', async () => {
  const collector = createAppsCollector({
    platform: 'linux',
    runCommand: commandMock({
      'dpkg-query': async () => 'nginx\t1.24.0',
      systemctl: async () => { throw new Error('systemd unavailable'); },
    }),
  });

  const data = await collector.run({}, { collectorConfig: { maxItems: 10 } });

  assert.equal(data.applications.items.length, 1);
  assert.equal(data.services.items, null);
  assert.match(data.services.reason, /systemd unavailable/);
  assert.equal(data.correlation.successful, false);
  assert.match(data.correlation.reason, /both be available/);
});

test('real apps collector produces a bounded normalized result shape', async () => {
  const result = await executeCollector({
    collector: appsCollector,
    params: {},
    context: { collectorConfig: { maxItems: 20 } },
    timeoutMs: 25000,
  });

  assert.equal(result.collector, 'apps');
  assert.equal(result.status, 'success');
  assert.equal(result.error, null);
  assert.ok(['linux', 'win32', 'darwin'].includes(result.data.platform));
  assert.equal(result.data.summary.maxItems, 20);
  assert.ok(result.data.summary.returnedItems <= 20);
  assert.equal(typeof result.data.summary.truncated, 'number');
  for (const section of [result.data.applications, result.data.services]) {
    assert.ok(section.items === null || Array.isArray(section.items));
    assert.ok(section.reason === null || typeof section.reason === 'string');
    for (const item of section.items ?? []) {
      assert.equal(typeof item.name, 'string');
      assert.ok(item.version === null || typeof item.version === 'string');
      assert.ok(['running', 'stopped', 'unknown'].includes(item.serviceStatus));
      assert.ok(item.binaryPath === null || typeof item.binaryPath === 'string');
    }
  }
});
