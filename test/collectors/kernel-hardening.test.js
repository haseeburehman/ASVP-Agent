import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import {
  COMMAND_TIMEOUT_MS,
  createKernelHardeningCollector,
  LINUX_SYSCTLS,
  MAX_COMMAND_OUTPUT_BYTES,
  MAX_SYSCTL_BYTES,
  WINDOWS_PROCESS_MITIGATION_COMMAND,
} from '../../src/collectors/kernel-hardening/index.js';

const expectedSysctlNames = [
  'kernel.kptr_restrict',
  'kernel.dmesg_restrict',
  'kernel.yama.ptrace_scope',
  'net.ipv4.conf.all.accept_source_route',
  'net.ipv4.conf.all.accept_redirects',
  'kernel.randomize_va_space',
];

test('Linux reads only the fixed sysctl sources and wraps every value', async () => {
  const calls = [];
  const values = new Map(LINUX_SYSCTLS.map(({ path }, index) => [path, `${index % 3}\n`]));
  const collector = createKernelHardeningCollector({
    platform: 'linux',
    readSource: async (path, options) => {
      calls.push({ path, options });
      return values.get(path);
    },
    runCommand: async () => assert.fail('Linux must not invoke PowerShell'),
  });

  const result = await collector.run({ untrusted: 'must-not-be-used' });

  assert.deepEqual(calls.map(({ path }) => path), LINUX_SYSCTLS.map(({ path }) => path));
  assert.ok(calls.every(({ options }) => options.maxBytes === MAX_SYSCTL_BYTES));
  assert.deepEqual(Object.keys(result.sysctls), expectedSysctlNames);
  assert.equal(result.status, 'available');
  for (const [index, setting] of Object.values(result.sysctls).entries()) {
    assert.deepEqual(setting, {
      status: 'available',
      reasonCode: null,
      reason: null,
      source: LINUX_SYSCTLS[index].path,
      value: index % 3,
    });
  }
  assert.equal(result.processMitigations.status, 'unavailable');
});

test('Linux reports individual read failures without hiding available fields', async () => {
  const failedPath = LINUX_SYSCTLS[2].path;
  const collector = createKernelHardeningCollector({
    platform: 'linux',
    readSource: async (path) => {
      if (path === failedPath) throw new Error('permission denied');
      return '1\n';
    },
  });

  const result = await collector.run();
  assert.equal(result.status, 'available');
  assert.equal(result.sysctls['kernel.yama.ptrace_scope'].status, 'insufficient_privilege');
  assert.equal(result.sysctls['kernel.yama.ptrace_scope'].reasonCode, 'insufficient_privilege');
  assert.match(result.sysctls['kernel.yama.ptrace_scope'].reason, /permission denied/);
  assert.equal(result.sysctls['kernel.kptr_restrict'].status, 'available');
});

test('Windows uses one fixed bounded read-only mitigation command and normalizes JSON', async () => {
  const calls = [];
  const collector = createKernelHardeningCollector({
    platform: 'win32',
    readSource: async () => assert.fail('Windows must not read procfs'),
    runCommand: async (executable, args, options) => {
      calls.push({ executable, args, options });
      return '{"DEP":{"Enable":"ON"},"ASLR":{"BottomUp":"ON"}}';
    },
  });

  const result = await collector.run({ command: 'must-not-be-used' });

  assert.deepEqual(calls, [{
    executable: WINDOWS_PROCESS_MITIGATION_COMMAND.executable,
    args: [...WINDOWS_PROCESS_MITIGATION_COMMAND.args],
    options: {
      signal: undefined,
      timeoutMs: COMMAND_TIMEOUT_MS,
      maxOutputBytes: MAX_COMMAND_OUTPUT_BYTES,
    },
  }]);
  assert.deepEqual(result.processMitigations.value, {
    DEP: { Enable: 'ON' },
    ASLR: { BottomUp: 'ON' },
  });
  assert.equal(result.processMitigations.status, 'available');
  assert.ok(Object.values(result.sysctls).every(({ status }) => status === 'unavailable'));
});

test('Windows command and parse failures are explicitly unavailable', async () => {
  for (const runCommand of [
    async () => { throw new Error('cmdlet missing'); },
    async () => 'not json',
  ]) {
    const result = await createKernelHardeningCollector({ platform: 'win32', runCommand }).run();
    assert.equal(result.status, 'unavailable');
    assert.equal(result.processMitigations.status, 'unavailable');
    assert.equal(result.processMitigations.reasonCode, 'unavailable');
    assert.match(result.processMitigations.reason, /Windows process mitigations is unavailable/);
  }
});

test('macOS marks every fixed field unavailable without reading or executing', async () => {
  const collector = createKernelHardeningCollector({
    platform: 'darwin',
    readSource: async () => assert.fail('macOS must not read Linux sysctls'),
    runCommand: async () => assert.fail('macOS must not run Windows commands'),
  });

  const result = await collector.run();

  assert.equal(result.status, 'unavailable');
  assert.equal(result.reasonCode, 'unavailable');
  assert.deepEqual(Object.keys(result.sysctls), expectedSysctlNames);
  assert.ok(Object.values(result.sysctls).every((item) => (
    item.status === 'unavailable'
    && item.reasonCode === 'unavailable'
    && item.value === null
    && /macOS/.test(item.reason)
  )));
  assert.equal(result.processMitigations.status, 'unavailable');
});

test('collector source keeps procfs and command reads bounded', async () => {
  const source = await readFile(new URL('../../src/collectors/kernel-hardening/index.js', import.meta.url), 'utf8');

  assert.match(source, /Buffer\.alloc\(MAX_SYSCTL_BYTES\)/);
  assert.match(source, /maxOutputBytes:\s*MAX_COMMAND_OUTPUT_BYTES/);
  assert.match(source, /timeoutMs:\s*COMMAND_TIMEOUT_MS/);
  assert.doesNotMatch(source, /\bsysctl\b[^\n]*-w|Set-ProcessMitigation|\/proc\/sys\/[^'\s]+\/\$\{/i);
});

test('an already-aborted collection does not access any source', async () => {
  const controller = new AbortController();
  controller.abort();
  let invoked = false;
  const collector = createKernelHardeningCollector({
    platform: 'linux',
    readSource: async () => { invoked = true; return '1'; },
  });

  await assert.rejects(collector.run({}, { signal: controller.signal }), {
    name: 'AbortError',
    code: 'ABORT_ERR',
  });
  assert.equal(invoked, false);
});
