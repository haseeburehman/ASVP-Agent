import assert from 'node:assert/strict';
import test from 'node:test';
import { executeCollector } from '../../src/core/collector.js';
import usersGroupsCollector, { createUsersGroupsCollector, parsePasswdStatus } from '../../src/collectors/users-groups/index.js';

function fileMock(files) {
  return async (filePath) => {
    const value = files[filePath];
    if (value instanceof Error) throw value;
    if (value === undefined) throw new Error(`Unexpected file: ${filePath}`);
    return value;
  };
}

test('Linux adapter parses passwd and group while tolerating unavailable passwd status', async () => {
  const calls = [];
  const collector = createUsersGroupsCollector({
    platform: 'linux',
    readTextFile: fileMock({
      '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/sh',
      '/etc/group': 'root:x:0:\nusers:x:1000:alice,bob',
    }),
    readDirectory: async () => { const error = new Error('permission denied'); error.code = 'EACCES'; throw error; },
    runCommand: async (executable, args) => {
      calls.push([executable, args]);
      throw new Error('permission denied');
    },
  });

  const data = await collector.run();

  assert.deepEqual(calls, [['passwd', ['-S', 'root']], ['passwd', ['-S', 'alice']]]);
  assert.equal(data.platform, 'linux');
  assert.equal(data.users.items[1].name, 'alice');
  assert.equal(data.users.items[1].uid, 1000);
  assert.equal(data.users.items[1].primaryGroupId, 1000);
  assert.equal(data.users.items[1].enabled, null);
  assert.equal(data.users.accountStatus, 'insufficient_privilege');
  assert.equal(data.users.reasonCode, 'insufficient_privilege');
  assert.match(data.users.reason, /permission denied/);
  assert.deepEqual(data.groups.items[1], { name: 'users', gid: 1000, members: ['alice', 'bob'] });
  assert.equal(data.adminMembership.status, 'available');
  assert.deepEqual(data.adminMembership.items[1], { user: 'alice', sudo: false, wheel: false });
  assert.equal(data.sudoersDropInFiles.status, 'insufficient_privilege');
  assert.equal(data.sudoersDropInFiles.reasonCode, 'insufficient_privilege');
});

test('Linux adapter derives lock and expiry state from passwd status without credential files', async () => {
  const filesRead = [];
  const collector = createUsersGroupsCollector({
    platform: 'linux',
    readTextFile: async (filePath) => {
      filesRead.push(filePath);
      if (filePath === '/etc/passwd') return 'locked:x:1000:1000::/home/locked:/bin/sh\nactive:x:1001:1001::/home/active:/bin/sh';
      if (filePath === '/etc/group') return '';
      throw new Error(`Unexpected file: ${filePath}`);
    },
    readDirectory: async () => [],
    runCommand: async (executable, args) => {
      assert.equal(executable, 'passwd');
      assert.deepEqual(args.slice(0, 1), ['-S']);
      return args[1] === 'locked'
        ? 'locked L 2026-01-01 0 99999 7 -1'
        : 'active P 2026-01-01 0 90 7 -1';
    },
  });

  const data = await collector.run();

  assert.deepEqual(filesRead, ['/etc/passwd', '/etc/group']);
  assert.equal(data.users.items[0].passwordLocked, true);
  assert.equal(data.users.items[0].enabled, false);
  assert.equal(data.users.items[0].passwordNeverExpires, true);
  assert.equal(data.users.items[1].passwordLocked, false);
  assert.equal(data.users.items[1].enabled, true);
  assert.equal(data.users.items[1].passwordNeverExpires, false);
  assert.equal(data.users.accountStatus, 'available');
  assert.equal(data.users.reasonCode, null);
  assert.equal(data.users.reason, null);
  assert.equal(data.sudoersDropInFiles.status, 'available');
});

test('Linux adapter reports sudo and wheel membership and bounds sudoers file names', async () => {
  const entries = Array.from({ length: 300 }, (_, index) => ({ name: `rule-${String(index).padStart(3, '0')}`, isFile: () => true }));
  const collector = createUsersGroupsCollector({
    platform: 'linux',
    readTextFile: fileMock({
      '/etc/passwd': 'alice:x:1000:10::/home/alice:/bin/sh\nbob:x:1001:20::/home/bob:/bin/sh',
      '/etc/group': 'wheel:x:10:\nsudo:x:20:alice',
    }),
    readDirectory: async (directory, options) => {
      assert.equal(directory, '/etc/sudoers.d');
      assert.deepEqual(options, { withFileTypes: true });
      return entries;
    },
    runCommand: async (_executable, args) => `${args[1]} P 2026-01-01 0 90 7 -1`,
  });

  const data = await collector.run();

  assert.deepEqual(data.adminMembership.items, [
    { user: 'alice', sudo: true, wheel: true },
    { user: 'bob', sudo: true, wheel: false },
  ]);
  assert.equal(data.sudoersDropInFiles.items.length, 256);
  assert.deepEqual(data.sudoersDropInFiles.items.slice(0, 2), ['rule-000', 'rule-001']);
  assert.match(data.sudoersDropInFiles.reason, /limited to 256/);
});

test('passwd status parser consumes only non-secret account-state fields', () => {
  assert.deepEqual(parsePasswdStatus('alice P 2026-01-01 0 90 7 -1'), {
    name: 'alice', locked: false, enabled: true, neverExpires: false,
  });
  assert.deepEqual(parsePasswdStatus('service L 2026-01-01 0 99999 7 -1'), {
    name: 'service', locked: true, enabled: false, neverExpires: true,
  });
});

test('Windows adapter uses one fixed non-interactive PowerShell script', async () => {
  const collector = createUsersGroupsCollector({
    platform: 'win32',
    runCommand: async (executable, args) => {
      assert.equal(executable, 'powershell.exe');
      assert.deepEqual(args.slice(0, 3), ['-NoProfile', '-NonInteractive', '-Command']);
      assert.match(args[3], /Get-LocalUser/);
      assert.match(args[3], /Get-LocalGroupMember/);
      assert.match(args[3], /Win32_Service/);
      assert.match(args[3], /PrincipalSource -eq 'Local'/);
      assert.equal(args.length, 4);
      return JSON.stringify({
        Users: [{ Name: 'local-user', SID: 'S-1-5-21-1', Enabled: true, Description: 'Local user' }],
        Groups: [{
          Name: 'Administrators',
          SID: 'S-1-5-32-544',
          Members: [{ Name: 'HOST\\local-user', SID: 'S-1-5-21-1', ObjectClass: 'User', PrincipalSource: 'Local' }],
        }],
        Services: [
          { Name: 'system-service', DisplayName: 'System service', StartName: 'LocalSystem', State: 'Running' },
          { Name: 'user-service', DisplayName: 'User service', StartName: '.\\local-user', State: 'Stopped' },
          { Name: 'limited-service', DisplayName: 'Limited service', StartName: 'NT AUTHORITY\\LocalService', State: 'Running' },
        ],
      });
    },
  });

  const data = await collector.run({ ignored: 'not interpolated' });

  assert.equal(data.users.items[0].name, 'local-user');
  assert.equal(data.users.items[0].enabled, true);
  assert.equal(data.groups.items[0].name, 'Administrators');
  assert.equal(data.groups.items[0].members[0].principalSource, 'Local');
  assert.deepEqual(data.adminMembership.items, [{ user: 'local-user', administrators: true }]);
  assert.deepEqual(data.services.items.map((service) => service.runsAsPrivileged), [true, true, false]);
  assert.equal(data.services.items[1].account, '.\\local-user');
});

test('macOS adapter uses fixed dscl commands and joins group memberships', async () => {
  const calls = [];
  const collector = createUsersGroupsCollector({
    platform: 'darwin',
    runCommand: async (executable, args) => {
      calls.push([executable, args]);
      assert.equal(executable, '/usr/bin/dscl');
      if (args.at(-1) === 'UniqueID') return '_daemon 1\nalice 501';
      if (args.at(-1) === 'PrimaryGroupID') return 'staff 20\nadmin 80';
      if (args.at(-1) === 'GroupMembership') return 'staff alice\nadmin root alice';
      throw new Error('Unexpected dscl command');
    },
  });

  const data = await collector.run();

  assert.equal(calls.length, 3);
  assert.deepEqual(calls.map(([, args]) => args), [
    ['.', '-list', '/Users', 'UniqueID'],
    ['.', '-list', '/Groups', 'PrimaryGroupID'],
    ['.', '-list', '/Groups', 'GroupMembership'],
  ]);
  assert.deepEqual(data.users.items[1], {
    name: 'alice',
    uid: 501,
    enabled: null,
    isAdministrator: true,
    lastLogin: null,
    passwordNeverExpires: null,
  });
  assert.deepEqual(data.groups.items[0], { name: 'staff', gid: 20, members: ['alice'] });
  assert.deepEqual(data.adminMembership.items[1], { user: 'alice', admin: true, staff: true });
  assert.equal(data.adminMembership.status, 'available');
});

test('macOS membership check reports insufficient privilege independently', async () => {
  const collector = createUsersGroupsCollector({
    platform: 'darwin',
    runCommand: async (_executable, args) => {
      if (args.at(-1) === 'UniqueID') return 'alice 501';
      if (args.at(-1) === 'PrimaryGroupID') return 'staff 20';
      const error = new Error('permission denied');
      error.code = 'EACCES';
      throw error;
    },
  });

  const data = await collector.run();

  assert.equal(data.users.items[0].isAdministrator, false);
  assert.equal(data.adminMembership.status, 'insufficient_privilege');
  assert.equal(data.adminMembership.reasonCode, 'insufficient_privilege');
  assert.equal(data.groups.items[0].members.length, 0);
});

test('collector rejects an already-aborted run', async () => {
  const controller = new AbortController();
  controller.abort();
  const collector = createUsersGroupsCollector({
    platform: 'linux',
    readTextFile: async () => { throw new Error('should not read'); },
  });

  await assert.rejects(collector.run({}, { signal: controller.signal }), { name: 'AbortError', code: 'ABORT_ERR' });
});

test('real local collector produces local normalized users and groups safely', async () => {
  const result = await executeCollector({
    collector: usersGroupsCollector,
    params: {},
    context: {},
    timeoutMs: 15000,
  });

  assert.equal(result.collector, 'users-groups');
  assert.equal(result.status, 'success');
  assert.equal(result.error, null);
  assert.ok(['linux', 'win32', 'darwin'].includes(result.data.platform));
  for (const section of [result.data.users, result.data.groups]) {
    assert.ok(section.items === null || Array.isArray(section.items));
    assert.equal(typeof section.source, 'string');
    assert.ok(section.reason === null || typeof section.reason === 'string');
  }
  for (const user of result.data.users.items ?? []) assert.equal(typeof user.name, 'string');
  for (const group of result.data.groups.items ?? []) {
    assert.equal(typeof group.name, 'string');
    assert.ok(Array.isArray(group.members));
  }
});
