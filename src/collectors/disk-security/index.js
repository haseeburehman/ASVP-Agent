import systeminformation from 'systeminformation';
import { createAbortError, runBoundedCommand } from '../shared/exec-utils.js';

const COMMAND_TIMEOUT_MS = 8000;
const DEFAULT_MAX_ITEMS = 100;
const MAX_MAX_ITEMS = 1000;

export const WINDOWS_BITLOCKER_COMMAND = Object.freeze({
  executable: 'manage-bde.exe',
  args: Object.freeze(['-status']),
});
export const MACOS_FILEVAULT_COMMAND = Object.freeze({
  executable: '/usr/bin/fdesetup',
  args: Object.freeze(['status']),
});
export const LINUX_LUKS_COMMAND = Object.freeze({
  executable: 'lsblk',
  args: Object.freeze(['--json', '--bytes', '--output', 'NAME,TYPE,FSTYPE,MOUNTPOINTS,PKNAME']),
});

function abortIfNeeded(signal) {
  if (signal?.aborted) throw createAbortError('Disk security collection was aborted');
}

function positiveLimit(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return DEFAULT_MAX_ITEMS;
  return Math.min(MAX_MAX_ITEMS, Math.max(0, Math.floor(parsed)));
}

function nullableNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : null;
}

function privilegeFailure(error) {
  const text = `${error?.code ?? ''} ${error?.message ?? ''}`;
  return ['EACCES', 'EPERM'].includes(error?.code)
    || /access is denied|permission denied|not permitted|requires? elevation|administrator privileges|must be root|not authorized/i.test(text);
}

function encryption(status, source, reason = null) {
  return {
    status,
    reasonCode: status === 'unavailable' || status === 'insufficient_privilege' ? status : null,
    reason,
    source,
  };
}

function commandFailure(error, source) {
  if (privilegeFailure(error)) {
    return encryption('insufficient_privilege', source, `Encryption status requires additional privileges: ${error.message}`);
  }
  return encryption('unavailable', source, `Encryption status is unavailable: ${error.message}`);
}

function volumeKey(value) {
  return String(value ?? '').replace(/[\\/]+$/, '').toLowerCase();
}

function parseWindowsBitLocker(output) {
  const records = new Map();
  let current = null;
  for (const line of output.split(/\r?\n/)) {
    const heading = line.match(/^\s*Volume\s+([A-Za-z]:)/i);
    if (heading) {
      current = { key: volumeKey(heading[1]), conversion: null, protection: null };
      records.set(current.key, current);
      continue;
    }
    if (!current) continue;
    const conversion = line.match(/^\s*Conversion Status:\s*(.+?)\s*$/i);
    const protection = line.match(/^\s*Protection Status:\s*(.+?)\s*$/i);
    if (conversion) current.conversion = conversion[1];
    if (protection) current.protection = protection[1];
  }
  return records;
}

function windowsEncryption(output, volumes) {
  const records = parseWindowsBitLocker(output);
  return volumes.map((volume) => {
    const record = records.get(volumeKey(volume.mount)) ?? records.get(volumeKey(volume.fs));
    if (!record) return encryption('unavailable', 'bitlocker', 'BitLocker returned no status for this volume');
    if (/fully encrypted|encryption in progress|encryption paused/i.test(record.conversion ?? '')) {
      return encryption('encrypted', 'bitlocker');
    }
    if (/fully decrypted/i.test(record.conversion ?? '')) return encryption('not_encrypted', 'bitlocker');
    return encryption('unavailable', 'bitlocker', 'BitLocker returned an unrecognized conversion status');
  });
}

function macOsEncryption(output, volumes) {
  const enabled = /filevault is on/i.test(output);
  const disabled = /filevault is off/i.test(output);
  return volumes.map((volume) => {
    if (volume.mount !== '/') {
      return encryption('unavailable', 'filevault', 'FileVault status is only safely attributable to the startup volume');
    }
    if (enabled) return encryption('encrypted', 'filevault');
    if (disabled) return encryption('not_encrypted', 'filevault');
    return encryption('unavailable', 'filevault', 'FileVault returned an unrecognized status');
  });
}

function flattenBlockDevices(devices, parentEncrypted = false, result = []) {
  for (const device of devices ?? []) {
    const encrypted = parentEncrypted || device.type === 'crypt' || device.fstype === 'crypto_LUKS';
    const mountpoints = Array.isArray(device.mountpoints) ? device.mountpoints : [device.mountpoint];
    for (const mountpoint of mountpoints.filter(Boolean)) result.push({ mountpoint, encrypted });
    flattenBlockDevices(device.children, encrypted, result);
  }
  return result;
}

function linuxEncryption(output, volumes) {
  const data = JSON.parse(output || '{}');
  const mounted = flattenBlockDevices(data.blockdevices);
  return volumes.map((volume) => {
    const match = mounted.find((device) => device.mountpoint === volume.mount);
    if (!match) return encryption('unavailable', 'luks-lsblk', 'No block-device encryption evidence was available for this mount');
    return encryption(match.encrypted ? 'encrypted' : 'not_encrypted', 'luks-lsblk');
  });
}

async function inspectEncryption(platform, volumes, { runCommand, signal, encryptionProvider }) {
  if (encryptionProvider) return encryptionProvider({ platform, volumes, signal });
  const command = platform === 'win32' ? WINDOWS_BITLOCKER_COMMAND
    : platform === 'darwin' ? MACOS_FILEVAULT_COMMAND
      : platform === 'linux' ? LINUX_LUKS_COMMAND : null;
  if (!command) return volumes.map(() => encryption('unavailable', null, `Encryption inspection is unsupported on platform "${platform}"`));

  try {
    const output = await runCommand(command.executable, [...command.args], { signal, timeoutMs: COMMAND_TIMEOUT_MS });
    abortIfNeeded(signal);
    if (platform === 'win32') return windowsEncryption(output, volumes);
    if (platform === 'darwin') return macOsEncryption(output, volumes);
    return linuxEncryption(output, volumes);
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    const failure = commandFailure(error, platform === 'win32' ? 'bitlocker' : platform === 'darwin' ? 'filevault' : 'luks-lsblk');
    return volumes.map(() => ({ ...failure }));
  }
}

function normalizeVolume(item) {
  const capacityBytes = nullableNumber(item.size);
  const freeBytes = nullableNumber(item.available);
  return {
    filesystem: item.fs || null,
    mount: item.mount || null,
    type: item.type || null,
    capacityBytes,
    freeBytes,
    usedBytes: nullableNumber(item.used),
    usedPercent: nullableNumber(item.use),
    readOnly: typeof item.rw === 'boolean' ? !item.rw : null,
  };
}

export function createDiskSecurityCollector({
  platform = process.platform,
  systemInformation = systeminformation,
  volumeProvider,
  encryptionProvider,
  runCommand = runBoundedCommand,
} = {}) {
  return {
    name: 'disk-security',
    version: '1.0.0',
    async run(_params = {}, context = {}) {
      const signal = context.signal;
      abortIfNeeded(signal);
      const maxItems = positiveLimit(context.collectorConfig?.maxItems);
      let rawVolumes;
      try {
        rawVolumes = await (volumeProvider ? volumeProvider({ signal }) : systemInformation.fsSize());
      } catch (error) {
        if (error.name === 'AbortError') throw error;
        const status = privilegeFailure(error) ? 'insufficient_privilege' : 'unavailable';
        return {
          platform,
          status,
          reasonCode: status,
          reason: `Volume capacity information is ${status === 'insufficient_privilege' ? 'not accessible with current privileges' : 'unavailable'}: ${error.message}`,
          volumes: [],
          totalDetected: 0,
          truncated: 0,
        };
      }
      abortIfNeeded(signal);

      const normalized = (Array.isArray(rawVolumes) ? rawVolumes : []).map(normalizeVolume);
      const selected = normalized.slice(0, maxItems);
      const statuses = await inspectEncryption(platform, selected, { runCommand, signal, encryptionProvider });
      abortIfNeeded(signal);
      const volumes = selected.map((volume, index) => ({
        ...volume,
        encryption: statuses[index] ?? encryption('unavailable', null, 'Encryption provider returned no status for this volume'),
      }));
      const insufficient = volumes.some((volume) => volume.encryption.status === 'insufficient_privilege');
      const allUnavailable = volumes.length > 0 && volumes.every((volume) => volume.encryption.status === 'unavailable');
      return {
        platform,
        status: insufficient ? 'insufficient_privilege' : allUnavailable ? 'unavailable' : 'available',
        reasonCode: insufficient ? 'insufficient_privilege' : allUnavailable ? 'unavailable' : null,
        reason: insufficient
          ? 'One or more encryption statuses require additional privileges'
          : allUnavailable ? 'Encryption status could not be determined for any returned volume' : null,
        volumes,
        totalDetected: normalized.length,
        truncated: Math.max(0, normalized.length - selected.length),
      };
    },
  };
}

export const diskSecurityCollector = createDiskSecurityCollector();
export default diskSecurityCollector;
