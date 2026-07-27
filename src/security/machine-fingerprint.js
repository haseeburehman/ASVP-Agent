import { createHash } from 'node:crypto';
import os from 'node:os';
import systeminformation from 'systeminformation';

function usable(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase();
  if (!normalized || /^(unknown|none|not specified|to be filled by o\.e\.m\.|0+|f+)$/i.test(normalized)) return null;
  return normalized;
}

function localMacAddresses(networkInterfaces = os.networkInterfaces()) {
  return Object.values(networkInterfaces)
    .flatMap((addresses) => addresses ?? [])
    .filter((address) => !address.internal && usable(address.mac) && address.mac !== '00:00:00:00:00:00')
    .map((address) => address.mac.toLowerCase())
    .filter((value, index, values) => values.indexOf(value) === index)
    .sort();
}

export async function deriveMachineFingerprint({ system = () => systeminformation.system(), networkInterfaces } = {}) {
  const hardware = await system();
  const components = [
    ['system.uuid', usable(hardware?.uuid)],
    ['system.serial', usable(hardware?.serial)],
    ...localMacAddresses(networkInterfaces).map((mac, index) => [`network.mac.${index}`, mac]),
  ].filter(([, value]) => value);

  if (components.length < 2) {
    throw new Error('Unable to derive a stable machine fingerprint from at least two hardware characteristics');
  }

  const canonical = components.map(([name, value]) => `${name}=${value}`).join('\n');
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}
