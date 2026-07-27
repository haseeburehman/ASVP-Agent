import { getServers } from 'node:dns';
import systeminformation from 'systeminformation';

const DEFAULT_MAX_ITEMS = 100;

function abortError() {
  const error = new Error('Network configuration collection was aborted');
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

function checkAbort(signal) {
  if (signal?.aborted) throw abortError();
}

function waitForLocalResult(operation, signal) {
  checkAbort(signal);
  if (!signal) return Promise.resolve().then(operation);

  return new Promise((resolve, reject) => {
    const onAbort = () => reject(abortError());
    signal.addEventListener('abort', onAbort, { once: true });

    Promise.resolve()
      .then(operation)
      .then(resolve, reject)
      .finally(() => signal.removeEventListener('abort', onAbort));
  });
}

function cleanString(value) {
  const normalized = typeof value === 'string' ? value.trim() : '';
  return normalized || null;
}

function addAddress(addresses, value, family) {
  const values = Array.isArray(value) ? value : [value];
  for (const candidate of values) {
    const address = cleanString(candidate);
    if (address && !addresses.some((item) => item.address === address && item.family === family)) {
      addresses.push({ address, family });
    }
  }
}

export function normalizeNetworkInterfaces(records = []) {
  const interfacesByName = new Map();

  for (const record of Array.isArray(records) ? records : []) {
    const name = cleanString(record?.iface) ?? cleanString(record?.ifaceName);
    if (!name) continue;

    let normalized = interfacesByName.get(name);
    if (!normalized) {
      normalized = { name, addresses: [], macs: [], default: false };
      interfacesByName.set(name, normalized);
    }

    addAddress(normalized.addresses, record.ip4, 'IPv4');
    addAddress(normalized.addresses, record.ip6, 'IPv6');

    const mac = cleanString(record.mac)?.toLowerCase();
    if (mac && !normalized.macs.includes(mac)) normalized.macs.push(mac);
    normalized.default ||= record.default === true;
  }

  return [...interfacesByName.values()]
    .map((networkInterface) => ({
      ...networkInterface,
      addresses: networkInterface.addresses.sort((left, right) => (
        left.family.localeCompare(right.family) || left.address.localeCompare(right.address)
      )),
      macs: networkInterface.macs.sort(),
    }))
    .sort((left, right) => left.name.localeCompare(right.name));
}

function normalizeStringList(values) {
  return [...new Set((Array.isArray(values) ? values : [])
    .map(cleanString)
    .filter(Boolean))]
    .sort((left, right) => left.localeCompare(right));
}

export function createNetworkConfigCollector({
  interfaceProvider = () => systeminformation.networkInterfaces(),
  gatewayProvider = () => systeminformation.networkGatewayDefault(),
  dnsProvider = getServers,
} = {}) {
  return {
    name: 'network-config',
    version: '1.0.0',
    async run(_params = {}, context = {}) {
      const signal = context.signal;
      const configuredMax = context.collectorConfig?.maxItems;
      const maxItems = Number.isInteger(configuredMax) && configuredMax > 0 ? configuredMax : DEFAULT_MAX_ITEMS;
      checkAbort(signal);

      const [interfaceRecords, gateway] = await Promise.all([
        waitForLocalResult(interfaceProvider, signal),
        waitForLocalResult(gatewayProvider, signal),
      ]);
      checkAbort(signal);

      const dnsServers = normalizeStringList(dnsProvider());
      checkAbort(signal);

      const allInterfaces = normalizeNetworkInterfaces(interfaceRecords);
      const interfaces = allInterfaces.slice(0, maxItems);
      return {
        interfaces,
        dnsServers,
        defaultGateway: cleanString(gateway),
        summary: {
          maxItems,
          totalDetected: allInterfaces.length,
          returnedItems: interfaces.length,
          truncated: allInterfaces.length - interfaces.length,
        },
      };
    },
  };
}

export const networkConfigCollector = createNetworkConfigCollector();
export default networkConfigCollector;
