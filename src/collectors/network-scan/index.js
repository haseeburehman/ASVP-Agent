import net from 'node:net';
import ipaddr from 'ipaddr.js';
import pLimit from 'p-limit';
import systeminformation from 'systeminformation';
import { authorizeNetworkScan } from './authorization.js';

export const COMMON_TCP_PORTS = Object.freeze([
  21, 22, 23, 25, 53, 80, 110, 111, 135,
  139, 143, 443, 445, 993, 995, 1433, 1521,
  2049, 2375, 3000, 3306, 3389, 5432, 6379,
  8000, 8080, 8443,
]);

const HTTP_HEAD_PROBE = Buffer.from(
  'HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n',
  'ascii',
);

export const ACTIVE_PROBES = Object.freeze({
  80: HTTP_HEAD_PROBE,
  3000: HTTP_HEAD_PROBE,
  8000: HTTP_HEAD_PROBE,
  8080: HTTP_HEAD_PROBE,
});

function abortError() {
  const error = new Error('Network scan was aborted');
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

function checkAbort(signal) {
  if (signal?.aborted) throw abortError();
}

function wait(milliseconds, signal) {
  if (milliseconds <= 0) return Promise.resolve();
  if (signal?.aborted) return Promise.reject(abortError());
  return new Promise((resolve, reject) => {
    const timer = setTimeout(finish, milliseconds);
    const abortHandler = () => {
      clearTimeout(timer);
      signal.removeEventListener('abort', abortHandler);
      reject(abortError());
    };
    function finish() {
      signal?.removeEventListener('abort', abortHandler);
      resolve();
    }
    signal?.addEventListener('abort', abortHandler, { once: true });
  });
}

function addressToBigInt(address) {
  return address.toByteArray().reduce((value, byte) => (value << 8n) | BigInt(byte), 0n);
}

function bigIntToAddress(value, kind) {
  const byteLength = kind === 'ipv4' ? 4 : 16;
  const bytes = new Array(byteLength);
  let remaining = value;
  for (let index = byteLength - 1; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 255n);
    remaining >>= 8n;
  }
  return ipaddr.fromByteArray(bytes).toString();
}

export function expandApprovedTargets(approvedTargets) {
  const hosts = [];
  for (const approved of approvedTargets) {
    const [address, prefixLength] = ipaddr.parseCIDR(approved.canonicalTarget);
    const kind = address.kind();
    const bitLength = kind === 'ipv4' ? 32 : 128;
    const count = 1n << BigInt(bitLength - prefixLength);
    const first = addressToBigInt(address);
    for (let offset = 0n; offset < count; offset += 1n) {
      hosts.push({ target: bigIntToAddress(first + offset, kind), authorization: approved });
    }
  }
  return hosts;
}

function sanitizeBanner(buffer) {
  let text = '';
  for (const byte of buffer) {
    if (byte >= 0x20 && byte <= 0x7e) text += String.fromCharCode(byte);
    else if (byte === 0x0d) text += '\\r';
    else if (byte === 0x0a) text += '\\n';
    else if (byte === 0x09) text += '\\t';
    else text += `\\x${byte.toString(16).padStart(2, '0')}`;
  }
  return text;
}

export function scanTcpPort(target, port, options = {}) {
  const {
    signal,
    perPortTimeoutMs,
    bannerTimeoutMs,
    maxBannerBytes,
    activeProbes = ACTIVE_PROBES,
    socketFactory = () => new net.Socket(),
  } = options;
  checkAbort(signal);

  return new Promise((resolve, reject) => {
    const socket = socketFactory();
    const chunks = [];
    let bytesCaptured = 0;
    let connected = false;
    let settled = false;
    let truncated = false;
    const probe = activeProbes[port] ?? null;

    const cleanup = () => {
      signal?.removeEventListener('abort', abortHandler);
      socket.removeAllListeners();
      socket.destroy();
    };
    const finish = (result) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(result);
    };
    const failAbort = () => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(abortError());
    };
    const abortHandler = () => failAbort();
    const openResult = () => {
      const raw = Buffer.concat(chunks, bytesCaptured);
      return {
        port,
        status: 'open',
        banner: raw.length > 0
          ? {
            data: sanitizeBanner(raw),
            bytesCaptured: raw.length,
            truncated,
          }
          : null,
        probeUsed: Boolean(probe),
      };
    };

    signal?.addEventListener('abort', abortHandler, { once: true });
    socket.setTimeout(perPortTimeoutMs);
    socket.once('connect', () => {
      connected = true;
      socket.setTimeout(bannerTimeoutMs);
      if (probe) socket.write(probe);
    });
    socket.on('data', (chunk) => {
      const remaining = maxBannerBytes - bytesCaptured;
      if (remaining <= 0) {
        truncated = true;
        finish(openResult());
        return;
      }
      if (chunk.length > remaining) {
        chunks.push(chunk.subarray(0, remaining));
        bytesCaptured += remaining;
        truncated = true;
        finish(openResult());
      } else {
        chunks.push(chunk);
        bytesCaptured += chunk.length;
      }
    });
    socket.once('timeout', () => finish(connected ? openResult() : null));
    socket.once('end', () => finish(connected ? openResult() : null));
    socket.once('close', () => finish(connected ? openResult() : null));
    socket.once('error', () => finish(connected ? openResult() : null));
    socket.connect({ host: target, port });
  });
}

function createHostStartGate(delayMs, signal) {
  let previous = Promise.resolve();
  let lastStart = 0;
  return async () => {
    const current = previous.then(async () => {
      const remaining = Math.max(0, delayMs - (Date.now() - lastStart));
      await wait(remaining, signal);
      checkAbort(signal);
      lastStart = Date.now();
    });
    previous = current.catch(() => {});
    return current;
  };
}

async function scanHost(host, ports, plan, options) {
  const {
    signal,
    maxConcurrentPortsPerHost,
    bannerTimeoutMs,
    maxBannerBytes,
    connectPort,
    hooks,
  } = options;
  checkAbort(signal);
  hooks?.onHostScanStart?.(host.target);
  try {
    const limit = pLimit(maxConcurrentPortsPerHost);
    const results = await Promise.all(ports.map((port) => limit(async () => {
      checkAbort(signal);
      hooks?.onPortScanStart?.(host.target, port);
      try {
        return await connectPort(host.target, port, {
          signal,
          perPortTimeoutMs: plan.limits.perPortTimeoutMs,
          bannerTimeoutMs,
          maxBannerBytes,
        });
      } finally {
        hooks?.onPortScanEnd?.(host.target, port);
      }
    })));
    const openPorts = results.filter(Boolean);
    return {
      target: host.target,
      status: openPorts.length > 0 ? 'up' : 'no-response',
      discoveryMethod: 'tcp-liveness',
      openPorts,
      scannedPortCount: ports.length,
      respondedPortCount: openPorts.length,
    };
  } finally {
    hooks?.onHostScanEnd?.(host.target);
  }
}

export async function scanAuthorizedPlan(plan, options = {}) {
  if (!plan?.authorized || !Array.isArray(plan.approvedTargets) || plan.approvedTargets.length === 0) {
    throw new Error('Remote scanning requires a non-empty approved authorization plan');
  }
  const {
    signal,
    maxConcurrentPortsPerHost = 50,
    bannerTimeoutMs = 2000,
    maxBannerBytes = 1024,
    connectPort = scanTcpPort,
    hooks,
  } = options;
  const hosts = expandApprovedTargets(plan.approvedTargets);
  const ports = plan.portPlan.ports ?? [...COMMON_TCP_PORTS];
  const hostLimit = pLimit(plan.limits.maxConcurrentTargets);
  const waitForStart = createHostStartGate(plan.limits.perHostDelayMs, signal);

  return Promise.all(hosts.map((host) => hostLimit(async () => {
    checkAbort(signal);
    await waitForStart();
    return scanHost(host, ports, plan, {
      signal,
      maxConcurrentPortsPerHost,
      bannerTimeoutMs,
      maxBannerBytes,
      connectPort,
      hooks,
    });
  })));
}

function bindingScope(address) {
  const value = String(address ?? '').toLowerCase();
  if (['0.0.0.0', '::', '*'].includes(value)) return { scope: 'all-interfaces', externallyReachable: true };
  if (value === '::1' || value.startsWith('127.')) return { scope: 'loopback-only', externallyReachable: false };
  return { scope: 'specific-interface', externallyReachable: true };
}

export async function detectLocalPortBindings({
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
      .sort((left, right) => left.port - right.port || left.address.localeCompare(right.address));
    return { bindings, reason: null };
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return { bindings: null, reason: `Unable to enumerate local listening ports: ${error.message}` };
  }
}

export function createNetworkScanCollector({
  authorize = authorizeNetworkScan,
  scanPlan = scanAuthorizedPlan,
  connectionProvider,
  hooks,
} = {}) {
  return {
    name: 'network-scan',
    version: '1.0.0',
    async run(params = {}, context = {}) {
      const config = context.collectorConfig ?? {};
      const authorization = authorize({ config, taskParams: params });
      const localBindings = await detectLocalPortBindings({ connectionProvider, signal: context.signal });
      const authorizationSummary = {
        authorized: authorization.authorized,
        code: authorization.code,
        reason: authorization.reason,
        approvedTargets: authorization.approvedTargets,
        deniedTargets: authorization.deniedTargets,
        estimatedHosts: authorization.estimatedHosts ?? 0,
        estimatedOperations: authorization.estimatedOperations ?? 0,
      };

      if (!authorization.authorized) {
        return {
          reason: authorization.reason,
          metadata: {
            discoveryMethod: 'tcp-liveness',
            icmpUsed: false,
            icmpLimitation: 'Raw ICMP is not used because it commonly requires elevated privileges or native addons; no-response means no scanned TCP port accepted a connection, not that the host is definitively down.',
          },
          authorization: authorizationSummary,
          hosts: [],
          localPortBindings: localBindings,
        };
      }

      const hosts = await scanPlan(authorization, {
        signal: context.signal,
        maxConcurrentPortsPerHost: config.maxConcurrentPortsPerHost ?? 50,
        bannerTimeoutMs: config.bannerTimeoutMs ?? 2000,
        maxBannerBytes: config.maxBannerBytes ?? 1024,
        hooks,
      });
      return {
        reason: null,
        metadata: {
          discoveryMethod: 'tcp-liveness',
          icmpUsed: false,
          icmpLimitation: 'Raw ICMP is not used because it commonly requires elevated privileges or native addons; no-response means no scanned TCP port accepted a connection, not that the host is definitively down.',
          commonPortsUsedWhenTaskOmitsPorts: COMMON_TCP_PORTS,
          activeProbePorts: Object.keys(ACTIVE_PROBES).map(Number),
          activeProbePayload: HTTP_HEAD_PROBE.toString('ascii'),
        },
        authorization: authorizationSummary,
        hosts,
        localPortBindings: localBindings,
      };
    },
  };
}

export const networkScanCollector = createNetworkScanCollector();
export default networkScanCollector;
