import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import {
  COMMAND_TIMEOUT_MS,
  createFilePermissionsCollector,
  LINUX_EXECUTABLE_DIRECTORIES,
  MAX_COMMAND_OUTPUT_BYTES,
  MAX_LINUX_CHILDREN,
  UNIX_PERMISSION_PATHS,
  WINDOWS_ACL_PATHS,
  WINDOWS_ICACLS_COMMAND,
} from '../../src/collectors/file-permissions/index.js';

function metadata(mode, symbolicLink = false) {
  return { mode, isSymbolicLink: () => symbolicLink };
}

function linuxFs(overrides = {}) {
  return {
    async stat() { return metadata(0o100644); },
    async lstat() { return metadata(0o100755); },
    async readdir() { return []; },
    ...overrides,
  };
}

test('Linux stats only fixed paths and reports modes and missing paths', async () => {
  const statCalls = [];
  const missing = '/srv/www';
  const fsApi = linuxFs({
    async stat(target) {
      statCalls.push(target);
      if (target === missing) {
        const error = new Error('no such file or directory');
        error.code = 'ENOENT';
        throw error;
      }
      return metadata(target === '/tmp' ? 0o41777 : 0o100644);
    },
  });

  const result = await createFilePermissionsCollector({ platform: 'linux', fsApi }).run({ path: '/untrusted' });

  assert.deepEqual(statCalls, [...UNIX_PERMISSION_PATHS]);
  assert.equal(result.paths.find(({ path }) => path === '/tmp').mode, '1777');
  assert.equal(result.paths.find(({ path }) => path === '/tmp').worldWritable, true);
  assert.equal(result.paths.find(({ path }) => path === '/tmp').overlyPermissive, false);
  assert.deepEqual(result.paths.find(({ path }) => path === missing), {
    path: missing,
    exists: false,
    mode: null,
    aclSummary: null,
    worldWritable: null,
    overlyPermissive: null,
    status: 'not_present',
    reason: 'Path is not present',
  });
});

test('Linux flags a world-writable temporary directory only when the sticky bit is absent', async () => {
  const fsApi = linuxFs({
    async stat(target) { return metadata(target === '/tmp' ? 0o40777 : 0o100644); },
  });

  const result = await createFilePermissionsCollector({ platform: 'linux', fsApi }).run();
  const temporaryDirectory = result.paths.find(({ path }) => path === '/tmp');
  assert.equal(temporaryDirectory.mode, '0777');
  assert.equal(temporaryDirectory.worldWritable, true);
  assert.equal(temporaryDirectory.overlyPermissive, true);
});

test('Linux scans only direct children of fixed executable directories for SUID/SGID', async () => {
  const readdirCalls = [];
  const lstatCalls = [];
  const fsApi = linuxFs({
    async readdir(directory, options) {
      readdirCalls.push({ directory, options });
      return [{ name: 'normal' }, { name: 'privileged' }];
    },
    async lstat(target) {
      lstatCalls.push(target);
      return metadata(target.endsWith('/privileged') ? 0o104755 : 0o100755);
    },
  });

  const result = await createFilePermissionsCollector({ platform: 'linux', fsApi }).run();

  assert.deepEqual(readdirCalls.map(({ directory }) => directory), [...LINUX_EXECUTABLE_DIRECTORIES]);
  assert.ok(readdirCalls.every(({ options }) => options.withFileTypes === true));
  assert.equal(lstatCalls.length, LINUX_EXECUTABLE_DIRECTORIES.length * 2);
  assert.ok(lstatCalls.every((target) => !target.includes('**')));
  assert.equal(result.privilegedExecutables.length, LINUX_EXECUTABLE_DIRECTORIES.length);
  assert.ok(result.privilegedExecutables.every(({ mode }) => mode === '4755'));
});

test('Linux executable inspection obeys a global hard cap', async () => {
  let lstatCalls = 0;
  const entries = Array.from({ length: MAX_LINUX_CHILDREN + 5 }, (_, index) => ({ name: `tool-${index}` }));
  const fsApi = linuxFs({
    async readdir() { return entries; },
    async lstat() { lstatCalls += 1; return metadata(0o100755); },
  });

  const result = await createFilePermissionsCollector({ platform: 'linux', fsApi }).run();

  assert.equal(lstatCalls, MAX_LINUX_CHILDREN);
  assert.equal(result.scan.inspectedChildren, MAX_LINUX_CHILDREN);
  assert.equal(result.scan.truncated, true);
  assert.equal(result.scan.hardCap, MAX_LINUX_CHILDREN);
});

test('permission failures are explicit at path and wrapper levels', async () => {
  const error = new Error('permission denied');
  error.code = 'EACCES';
  const fsApi = linuxFs({ async stat() { throw error; } });

  const result = await createFilePermissionsCollector({ platform: 'linux', fsApi }).run();

  assert.equal(result.status, 'insufficient_privilege');
  assert.equal(result.reasonCode, 'insufficient_privilege');
  assert.match(result.reason, /privileges/i);
  assert.ok(result.paths.every(({ status, exists, reason }) => (
    status === 'insufficient_privilege' && exists === null && /current privileges/i.test(reason)
  )));
});

test('macOS stats the fixed Unix paths without running the Linux SUID scan', async () => {
  const statCalls = [];
  const fsApi = linuxFs({
    async stat(target) { statCalls.push(target); return metadata(0o100640); },
    async readdir() { assert.fail('macOS must not enumerate Linux executable directories'); },
  });

  const result = await createFilePermissionsCollector({ platform: 'darwin', fsApi }).run();
  assert.deepEqual(statCalls, [...UNIX_PERMISSION_PATHS]);
  assert.equal(result.status, 'available');
  assert.deepEqual(result.privilegedExecutables, []);
  assert.equal(result.scan, null);
});

test('Windows runs fixed bounded read-only icacls checks and detects broad Full Control', async () => {
  const calls = [];
  const collector = createFilePermissionsCollector({
    platform: 'win32',
    fsApi: linuxFs({
      async stat() { assert.fail('Windows must not stat Unix paths'); },
      async readdir() { assert.fail('Windows must not enumerate executable directories'); },
    }),
    async runCommand(executable, args, options) {
      calls.push({ executable, args, options });
      return args[0] === WINDOWS_ACL_PATHS[0]
        ? `${args[0]} Everyone:(OI)(CI)(F)`
        : `${args[0]} NT AUTHORITY\\SYSTEM:(F)`;
    },
  });

  const result = await collector.run({ target: 'C:\\untrusted' });

  assert.deepEqual(calls, WINDOWS_ACL_PATHS.map((target) => ({
    executable: WINDOWS_ICACLS_COMMAND.executable,
    args: [target],
    options: { signal: undefined, timeoutMs: COMMAND_TIMEOUT_MS, maxOutputBytes: MAX_COMMAND_OUTPUT_BYTES },
  })));
  assert.equal(result.paths[0].overlyPermissive, true);
  assert.equal(result.paths[0].worldWritable, null);
  assert.equal(result.paths[1].overlyPermissive, false);
  assert.ok(result.paths.every(({ exists, status }) => exists && status === 'available'));
});

test('Windows normalizes absent and inaccessible ACL targets', async () => {
  let call = 0;
  const collector = createFilePermissionsCollector({
    platform: 'win32',
    async runCommand() {
      call += 1;
      const error = new Error(call === 1 ? 'The system cannot find the path specified' : 'Access is denied');
      error.code = call === 2 ? 'EACCES' : undefined;
      throw error;
    },
  });

  const result = await collector.run();
  assert.equal(result.paths[0].status, 'not_present');
  assert.equal(result.paths[0].exists, false);
  assert.equal(result.paths[1].status, 'insufficient_privilege');
  assert.equal(result.status, 'insufficient_privilege');
});

test('source safety forbids recursive traversal and file-content access', async () => {
  const source = await readFile(new URL('../../src/collectors/file-permissions/index.js', import.meta.url), 'utf8');

  assert.doesNotMatch(source, /fast-glob|globSync|\bglob\s*\(|\bwalk(?:dir)?\s*\(|recursive\s*:\s*true|\*\*/i);
  assert.doesNotMatch(source, /\breadFile(?:Sync)?\b|\bcreateReadStream\b|\bopen\s*\(/);
  assert.doesNotMatch(source, /['"]\/etc\/shadow['"][\s\S]{0,120}(?:read|open)/i);
  assert.match(source, /fsApi\.stat\(target\)/);
  assert.match(source, /if \(metadata\.isSymbolicLink\(\)\) continue/);
  assert.match(source, /fsApi\.readdir\(directory,\s*\{ withFileTypes: true \}\)/);
});
