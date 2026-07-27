import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createDiskSecurityCollector,
  LINUX_LUKS_COMMAND,
  MACOS_FILEVAULT_COMMAND,
  WINDOWS_BITLOCKER_COMMAND,
} from '../../src/collectors/disk-security/index.js';

const volumes = [
  { fs: '/dev/mapper/root', type: 'ext4', size: 1000, used: 400, available: 600, use: 40, mount: '/', rw: true },
  { fs: '/dev/sdb1', type: 'ext4', size: 2000, used: 500, available: 1500, use: 25, mount: '/data', rw: false },
];

function systemInformation(items = volumes) {
  return { async fsSize() { return items; } };
}

test('Linux reports capacity/free and LUKS status from a fixed lsblk query', async () => {
  const calls = [];
  const collector = createDiskSecurityCollector({
    platform: 'linux',
    systemInformation: systemInformation(),
    runCommand: async (executable, args) => {
      calls.push({ executable, args });
      return JSON.stringify({ blockdevices: [
        { name: 'sda2', type: 'part', fstype: 'crypto_LUKS', mountpoints: [null], children: [
          { name: 'root', type: 'crypt', fstype: 'ext4', mountpoints: ['/'] },
        ] },
        { name: 'sdb1', type: 'part', fstype: 'ext4', mountpoints: ['/data'] },
      ] });
    },
  });

  const result = await collector.run();

  assert.deepEqual(calls, [{ executable: LINUX_LUKS_COMMAND.executable, args: [...LINUX_LUKS_COMMAND.args] }]);
  assert.equal(result.status, 'available');
  assert.equal(result.volumes[0].capacityBytes, 1000);
  assert.equal(result.volumes[0].freeBytes, 600);
  assert.equal(result.volumes[0].encryption.status, 'encrypted');
  assert.equal(result.volumes[1].encryption.status, 'not_encrypted');
  assert.equal(result.volumes[1].readOnly, true);
});

test('Windows maps fixed manage-bde output to volumes', async () => {
  const collector = createDiskSecurityCollector({
    platform: 'win32',
    systemInformation: systemInformation([{ fs: 'C:', mount: 'C:', size: 500, available: 100 }]),
    runCommand: async (executable, args) => {
      assert.equal(executable, WINDOWS_BITLOCKER_COMMAND.executable);
      assert.deepEqual(args, [...WINDOWS_BITLOCKER_COMMAND.args]);
      return 'Volume C: [OS]\n    Conversion Status:    Fully Encrypted\n    Protection Status:    Protection On';
    },
  });

  const result = await collector.run({ taskValue: 'must-not-enter-command' });
  assert.equal(result.volumes[0].encryption.status, 'encrypted');
  assert.equal(result.volumes[0].encryption.source, 'bitlocker');
});

test('macOS only attributes FileVault status to the startup volume', async () => {
  const collector = createDiskSecurityCollector({
    platform: 'darwin',
    systemInformation: systemInformation(),
    runCommand: async (executable, args) => {
      assert.equal(executable, MACOS_FILEVAULT_COMMAND.executable);
      assert.deepEqual(args, [...MACOS_FILEVAULT_COMMAND.args]);
      return 'FileVault is On.';
    },
  });

  const result = await collector.run();
  assert.equal(result.volumes[0].encryption.status, 'encrypted');
  assert.equal(result.volumes[1].encryption.status, 'unavailable');
  assert.equal(result.volumes[1].encryption.reasonCode, 'unavailable');
});

test('permission failures are explicit insufficient_privilege results', async () => {
  const error = new Error('Access is denied; administrator privileges are required');
  error.code = 'EACCES';
  const collector = createDiskSecurityCollector({
    platform: 'win32',
    systemInformation: systemInformation([{ fs: 'C:', mount: 'C:', size: 500, available: 100 }]),
    runCommand: async () => { throw error; },
  });

  const result = await collector.run();
  assert.equal(result.status, 'insufficient_privilege');
  assert.equal(result.reasonCode, 'insufficient_privilege');
  assert.equal(result.volumes[0].encryption.status, 'insufficient_privilege');
  assert.equal(result.volumes[0].encryption.reasonCode, 'insufficient_privilege');
  assert.match(result.volumes[0].encryption.reason, /privileges/i);
});

test('unavailable capacity and encryption checks are normalized rather than guessed', async () => {
  const volumeFailure = createDiskSecurityCollector({
    platform: 'linux',
    volumeProvider: async () => { throw new Error('filesystem inventory unavailable'); },
  });
  const encryptionFailure = createDiskSecurityCollector({
    platform: 'linux',
    systemInformation: systemInformation(),
    runCommand: async () => { throw new Error('lsblk missing'); },
  });

  const noVolumes = await volumeFailure.run();
  const noEncryption = await encryptionFailure.run();
  assert.equal(noVolumes.status, 'unavailable');
  assert.equal(noVolumes.reasonCode, 'unavailable');
  assert.deepEqual(noVolumes.volumes, []);
  assert.equal(noEncryption.status, 'unavailable');
  assert.ok(noEncryption.volumes.every((volume) => volume.encryption.status === 'unavailable'));
});

test('maxItems caps output and injectable encryption provider receives selected volumes', async () => {
  let received;
  const collector = createDiskSecurityCollector({
    platform: 'test-os',
    systemInformation: systemInformation([...volumes, { fs: 'third', mount: '/third', size: 3, available: 1 }]),
    encryptionProvider: async ({ platform, volumes: selected }) => {
      received = { platform, count: selected.length };
      return selected.map(() => ({ status: 'encrypted', reasonCode: null, reason: null, source: 'test' }));
    },
  });

  const result = await collector.run({}, { collectorConfig: { maxItems: 1 } });
  assert.deepEqual(received, { platform: 'test-os', count: 1 });
  assert.equal(result.volumes.length, 1);
  assert.equal(result.totalDetected, 3);
  assert.equal(result.truncated, 2);
});

test('abort is preserved before and during provider work', async () => {
  const before = new AbortController();
  before.abort();
  const collector = createDiskSecurityCollector({ systemInformation: systemInformation() });
  await assert.rejects(collector.run({}, { signal: before.signal }), { name: 'AbortError', code: 'ABORT_ERR' });

  const during = new AbortController();
  const laterCollector = createDiskSecurityCollector({
    volumeProvider: async () => {
      during.abort();
      return volumes;
    },
  });
  await assert.rejects(laterCollector.run({}, { signal: during.signal }), { name: 'AbortError', code: 'ABORT_ERR' });
});
