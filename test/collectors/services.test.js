import assert from 'node:assert/strict';
import test from 'node:test';
import { createServicesCollector } from '../../src/collectors/services/index.js';

function collectorFor(platform, output, inspectCommand = () => {}) {
  return createServicesCollector({
    platform,
    runCommand: async (executable, args, options) => {
      inspectCommand(executable, args, options);
      return output;
    },
  });
}

test('Windows uses fixed Win32_Service/Get-Service PowerShell and normalizes running services', async () => {
  const collector = collectorFor('win32', JSON.stringify({
    Name: 'Spooler',
    DisplayName: 'Print Spooler',
    Status: 'Running',
    StartMode: 'Auto',
    PathName: 'C:\\Windows\\System32\\spoolsv.exe',
    StartName: 'LocalSystem',
  }), (executable, args, options) => {
    assert.equal(executable, 'powershell.exe');
    assert.deepEqual(args.slice(0, 3), ['-NoProfile', '-NonInteractive', '-Command']);
    assert.match(args[3], /Get-CimInstance Win32_Service/);
    assert.match(args[3], /Get-Service/);
    assert.match(args[3], /State='Running'/);
    assert.equal(options.timeoutMs, 10000);
  });

  const result = await collector.run();

  assert.equal(result.services[0].name, 'Spooler');
  assert.equal(result.services[0].displayName, 'Print Spooler');
  assert.equal(result.services[0].status, 'running');
  assert.equal(result.services[0].startupType, 'automatic');
  assert.equal(result.services[0].binaryPath, 'C:\\Windows\\System32\\spoolsv.exe');
  assert.equal(result.services[0].runningUser, 'LocalSystem');
  assert.equal(result.services[0].version, null);
  assert.equal(result.services[0].fieldAvailability.version.status, 'unavailable');
  assert.equal(result.reason, null);
});

test('Linux uses one bounded systemctl show call and parses service properties', async () => {
  let calls = 0;
  const output = [
    'Id=ssh.service',
    'Description=OpenSSH server daemon',
    'ActiveState=active',
    'SubState=running',
    'UnitFileState=enabled',
    'ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; }',
    'User=root',
    '',
    'Id=completed.service',
    'Description=Completed oneshot',
    'ActiveState=active',
    'SubState=exited',
    'UnitFileState=static',
    'ExecStart={ path=/usr/bin/true ; }',
    'User=',
  ].join('\n');
  const collector = collectorFor('linux', output, (executable, args, options) => {
    calls += 1;
    assert.equal(executable, 'systemctl');
    assert.deepEqual(args.slice(0, 3), ['show', '--type=service', '--state=running']);
    assert.match(args.at(-1), /ExecStart/);
    assert.equal(options.maxOutputBytes, 2 * 1024 * 1024);
  });

  const result = await collector.run();

  assert.equal(calls, 1);
  assert.equal(result.services.length, 1);
  assert.equal(result.services[0].name, 'ssh');
  assert.equal(result.services[0].startupType, 'automatic');
  assert.equal(result.services[0].binaryPath, '/usr/sbin/sshd');
  assert.equal(result.services[0].runningUser, 'root');
});

test('macOS reports launchctl-unavailable fields honestly', async () => {
  const collector = collectorFor(
    'darwin',
    'PID\tStatus\tLabel\n321\t0\tcom.example.running\n-\t0\tcom.example.not-running',
    (executable, args) => {
      assert.equal(executable, 'launchctl');
      assert.deepEqual(args, ['list']);
    },
  );

  const result = await collector.run();

  assert.equal(result.services.length, 1);
  assert.equal(result.services[0].name, 'com.example.running');
  assert.equal(result.services[0].startupType, null);
  assert.equal(result.services[0].fieldAvailability.startupType.status, 'unavailable');
  assert.match(result.services[0].fieldAvailability.startupType.reason, /launchctl list/);
});

test('services deterministically caps sorted output and reports truncation', async () => {
  const output = ['zeta', 'alpha', 'middle'].map((name) => [
    `Id=${name}.service`,
    `Description=${name}`,
    'ActiveState=active',
    'SubState=running',
    'UnitFileState=enabled',
    'ExecStart=',
    'User=',
  ].join('\n')).join('\n\n');
  const collector = collectorFor('linux', output);

  const result = await collector.run({}, { collectorConfig: { maxItems: 2 } });

  assert.deepEqual(result.services.map(({ name }) => name), ['alpha', 'middle']);
  assert.deepEqual(result.summary, {
    maxItems: 2,
    totalDetected: 3,
    returnedItems: 2,
    truncated: 1,
  });
});

test('services reports command failures and insufficient privilege', async () => {
  const collector = createServicesCollector({
    platform: 'linux',
    runCommand: async () => { throw new Error('Permission denied while contacting system bus'); },
  });

  const result = await collector.run();

  assert.equal(result.services, null);
  assert.equal(result.insufficientPrivilege, true);
  assert.match(result.reason, /insufficient privilege/i);
  assert.match(result.reason, /Permission denied/);
});
