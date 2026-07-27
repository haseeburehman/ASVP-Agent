import systeminformation from 'systeminformation';

function abortError() {
  const error = new Error('Local port enumeration was aborted');
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

function checkAbort(signal) {
  if (signal?.aborted) throw abortError();
}

function bindingScope(address) {
  const value = String(address ?? '').trim().toLowerCase();
  if (['0.0.0.0', '::', '*'].includes(value)) {
    return { scope: 'all-interfaces', externallyReachable: true };
  }
  if (value === '::1' || value.startsWith('127.')) {
    return { scope: 'loopback-only', externallyReachable: false };
  }
  return { scope: 'specific-interface', externallyReachable: true };
}

export async function collectLocalListeningPorts({
  connectionProvider = () => systeminformation.networkConnections(),
  signal,
} = {}) {
  checkAbort(signal);
  try {
    const connections = await connectionProvider();
    checkAbort(signal);
    const bindings = connections
      .filter((connection) => String(connection.state).toLowerCase() === 'listen')
      .map((connection) => ({
        address: connection.localAddress,
        port: Number(connection.localPort),
        protocol: String(connection.protocol ?? 'tcp').toLowerCase(),
        process: connection.process || null,
        pid: connection.pid == null ? null : Number(connection.pid),
        ...bindingScope(connection.localAddress),
      }))
      .sort((left, right) => left.port - right.port || String(left.address).localeCompare(String(right.address)));
    return { bindings, reason: null };
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return { bindings: null, reason: `Unable to enumerate local listening ports: ${error.message}` };
  }
}

export function createLocalPortsCollector({ connectionProvider } = {}) {
  return {
    name: 'local-ports',
    version: '1.0.0',
    async run(_params = {}, context = {}) {
      const result = await collectLocalListeningPorts({ connectionProvider, signal: context.signal });
      return {
        platform: process.platform,
        ...result,
      };
    },
  };
}

export const localPortsCollector = createLocalPortsCollector();
export default localPortsCollector;
