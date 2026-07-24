import assert from 'node:assert/strict';
import test from 'node:test';
import { executeCollector } from '../../src/core/collector.js';
import usersGroupsCollector, { createUsersGroupsCollector } from '../../src/collectors/users-groups/index.js';

function fileMock(files) {
  return async (filePath) => {
    const value = files[filePath];
    if (value instanceof Error) throw value;
    if (value === undefined) throw new Error(`Unexpected file: ${filePath}`);
    return value;
  };
}

test('Linux adapter parses passwd and group while tolerating unreadable shadow', async () => {
  const permissionError = new Error('permission denied');
  permissionError.code = 'EACCES';
  const collector = createUsersGroupsCollector({
    platform: 'linux',
    readTextFile: fileMock({
      '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/sh',
      '/etc/group': 'root:x:0:\nusers:x:1000:alice,bob',
      '/etc/shadow': permissionError,
    }),
  });

  const data = await collector.run();

  assert.equal(data.platform, 'linux');
  assert.equal(data.users.items[1].name, 'alice');
  assert.equal(data.users.items[1].uid, 1000);
  assert.equal(data.users.items[1].primaryGroupId, 1000);
  assert.equal(data.users.items[1].enabled, null);
  assert.match(data.users.reason, /permission denied/);
  assert.deepEqual(data.groups.items[1], { name: 'users', gid: 1000, members: ['alice', 'bob'] });
});

test('Linux adapter derives password lock state when shadow is readable', async () => {
  const collector = createUsersGroupsCollector({
    platform: 'linux',
    readTextFile: fileMock({
      '/etc/passwd': 'locked:x:1000:1000::/home/locked:/bin/sh\nactive:x:1001:1001::/home/active:/bin/sh',
      '/etc/group': '',
      '/etc/shadow': 'locked:!:20000:0:99999:7:::\nactive:$6$hash:20000:0:99999:7:::',
    }),
  });

  const data = await collector.run();

  assert.equal(data.users.items[0].passwordLocked, true);
  assert.equal(data.users.items[0].enabled, false);
  assert.equal(data.users.items[1].passwordLocked, false);
  assert.equal(data.users.items[1].enabled, true);
  assert.equal(data.users.reason, null);
});

test('Windows adapter uses one fixed non-interactive PowerShell script', async () => {
  const collector = createUsersGroupsCollector({
    platform: 'win32',
    runCommand: async (executable, args) => {
      assert.equal(executable, 'powershell.exe');
      assert.deepEqual(args.slice(0, 3), ['-NoProfile', '-NonInteractive', '-Command']);
      assert.match(args[3], /Get-LocalUser/);
      assert.match(args[3], /Get-LocalGroupMember/);
      assert.equal(args.length, 4);
      return JSON.stringify({
        Users: [{ Name: 'local-user', SID: 'S-1-5-21-1', Enabled: true, Description: 'Local user' }],
        Groups: [{
          Name: 'Administrators',
          SID: 'S-1-5-32-544',
          Members: [{ Name: 'HOST\\local-user', SID: 'S-1-5-21-1', ObjectClass: 'User', PrincipalSource: 'Local' }],
        }],
      });
    },
  });

  const data = await collector.run({ ignored: 'not interpolated' });

  assert.equal(data.users.items[0].name, 'local-user');
  assert.equal(data.users.items[0].enabled, true);
  assert.equal(data.groups.items[0].name, 'Administrators');
  assert.equal(data.groups.items[0].members[0].principalSource, 'Local');
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
