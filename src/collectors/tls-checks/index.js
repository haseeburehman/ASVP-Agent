import tls from 'node:tls';
import pLimit from 'p-limit';
import { XMLParser } from 'fast-xml-parser';
import { authorizeNetworkScan } from '../network-scan/authorization.js';
import { expandApprovedTargets } from '../network-scan/index.js';
import { runBoundedCommand } from '../shared/exec-utils.js';

export const DEFAULT_TLS_PORTS = Object.freeze([443, 8443]);
export const TLS_VERSIONS = Object.freeze([
  { label: 'TLS 1.0', nodeName: 'TLSv1' },
  { label: 'TLS 1.1', nodeName: 'TLSv1.1' },
  { label: 'TLS 1.2', nodeName: 'TLSv1.2' },
  { label: 'TLS 1.3', nodeName: 'TLSv1.3' },
]);
export const TLS_OPERATIONS_PER_ENDPOINT = 6;

function abortError() {
  const error = new Error('TLS posture check was aborted');
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

function checkAbort(signal) {
  if (signal?.aborted) throw abortError();
}

function isWeakCipher(cipher) {
  return /rc4|3des|des-cbc3/i.test(`${cipher?.name ?? ''} ${cipher?.standardName ?? ''}`);
}

function isLocalTlsLimitation(error) {
  return [
    'ERR_SSL_NO_CIPHERS_AVAILABLE',
    'ERR_SSL_NO_PROTOCOLS_AVAILABLE',
    'ERR_SSL_UNSUPPORTED_PROTOCOL',
    'ERR_SSL_LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED',
    'ERR_OSSL_EVP_UNSUPPORTED',
  ].includes(error?.code)
    || /no ciphers available|no protocols available|legacy sigalg|disabled for this runtime/i.test(error?.message ?? '');
}

export function createVersionContext(version, tlsApi = tls) {
  try {
    return {
      available: true,
      context: tlsApi.createSecureContext({
        minVersion: version.nodeName,
        maxVersion: version.nodeName,
      }),
      reason: null,
    };
  } catch (error) {
    return {
      available: false,
      context: null,
      reason: `The local Node/OpenSSL runtime cannot create a ${version.label} context: ${error.message}`,
    };
  }
}

export function performTlsHandshake(target, port, options = {}) {
  const {
    signal,
    timeoutMs,
    secureContext,
    minVersion,
    maxVersion,
    ciphers,
    tlsApi = tls,
  } = options;
  checkAbort(signal);

  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = tlsApi.connect({
      host: target,
      port,
      secureContext,
      minVersion,
      maxVersion,
      ciphers,
      rejectUnauthorized: false,
    });
    const timer = setTimeout(() => {
      const error = new Error(`TLS handshake exceeded ${timeoutMs}ms`);
      error.code = 'TLS_HANDSHAKE_TIMEOUT';
      finish(reject, error);
    }, timeoutMs);
    const abortHandler = () => finish(reject, abortError());
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abortHandler);
      socket.removeAllListeners();
      socket.destroy();
      callback(value);
    };

    signal?.addEventListener('abort', abortHandler, { once: true });
    socket.once('secureConnect', () => finish(resolve, {
      protocol: socket.getProtocol(),
      cipher: socket.getCipher(),
      certificate: socket.getPeerCertificate(),
      authorized: socket.authorized,
      authorizationError: socket.authorizationError ?? null,
    }));
    socket.once('error', (error) => finish(reject, error));
  });
}

async function checkVersion(target, port, version, options) {
  const capability = createVersionContext(version, options.tlsApi);
  if (!capability.available) {
    return {
      version: version.label,
      status: 'client-limitation',
      supportedByTarget: null,
      reason: capability.reason,
      negotiatedCipher: null,
      weakCipher: null,
      handshake: null,
    };
  }
  try {
    const handshake = await options.handshake(target, port, {
      signal: options.signal,
      timeoutMs: options.timeoutMs,
      secureContext: capability.context,
      minVersion: version.nodeName,
      maxVersion: version.nodeName,
      tlsApi: options.tlsApi,
    });
    return {
      version: version.label,
      status: 'supported',
      supportedByTarget: true,
      reason: null,
      negotiatedCipher: handshake.cipher,
      weakCipher: isWeakCipher(handshake.cipher),
      handshake,
    };
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    const clientLimitation = isLocalTlsLimitation(error);
    return {
      version: version.label,
      status: clientLimitation ? 'client-limitation' : 'not-supported',
      supportedByTarget: clientLimitation ? null : false,
      reason: clientLimitation
        ? `The local Node/OpenSSL runtime could not attempt ${version.label}: ${error.message}`
        : `The target did not complete a ${version.label} handshake: ${error.message}`,
      negotiatedCipher: null,
      weakCipher: null,
      handshake: null,
    };
  }
}

export function evaluateCertificate(certificate, expiryWarningDays, now = new Date()) {
  if (!certificate?.valid_from || !certificate?.valid_to) {
    return {
      validFrom: null,
      validTo: null,
      daysUntilExpiry: null,
      status: 'unavailable',
      reason: 'The server did not provide a certificate with parseable validity dates',
    };
  }
  const validFrom = new Date(certificate.valid_from);
  const validTo = new Date(certificate.valid_to);
  if (Number.isNaN(validFrom.getTime()) || Number.isNaN(validTo.getTime())) {
    return {
      validFrom: certificate.valid_from,
      validTo: certificate.valid_to,
      daysUntilExpiry: null,
      status: 'unavailable',
      reason: 'The certificate validity dates could not be parsed',
    };
  }
  const daysUntilExpiry = Math.ceil((validTo.getTime() - now.getTime()) / 86400000);
  const status = daysUntilExpiry < 0
    ? 'expired'
    : daysUntilExpiry <= expiryWarningDays
      ? 'expiring-soon'
      : 'valid';
  return {
    validFrom: validFrom.toISOString(),
    validTo: validTo.toISOString(),
    daysUntilExpiry,
    status,
    reason: null,
    subject: certificate.subject ?? null,
    issuer: certificate.issuer ?? null,
    fingerprint256: certificate.fingerprint256 ?? null,
  };
}

function localWeakCipherCapability(tlsApi = tls) {
  const ciphers = tlsApi.getCiphers().filter((name) => /rc4|3des|des-cbc3/i.test(name));
  return {
    available: ciphers.length > 0,
    ciphers,
    reason: ciphers.length === 0
      ? 'The local Node/OpenSSL runtime exposes no RC4 or 3DES cipher suites; server acceptance cannot be tested'
      : null,
  };
}

async function assessWeakCipherAcceptance(target, port, capability, options) {
  if (!capability.available) {
    return {
      attempted: false,
      serverAcceptsWeakCipher: null,
      negotiatedCipher: null,
      reason: capability.reason,
    };
  }
  try {
    const handshake = await options.handshake(target, port, {
      signal: options.signal,
      timeoutMs: options.timeoutMs,
      minVersion: 'TLSv1',
      maxVersion: 'TLSv1.2',
      ciphers: capability.ciphers.join(':').toUpperCase(),
      tlsApi: options.tlsApi,
    });
    return {
      attempted: true,
      serverAcceptsWeakCipher: true,
      negotiatedCipher: handshake.cipher,
      reason: null,
    };
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    if (isLocalTlsLimitation(error)) {
      return {
        attempted: false,
        serverAcceptsWeakCipher: null,
        negotiatedCipher: null,
        reason: `The local Node/OpenSSL runtime could not offer its listed weak ciphers: ${error.message}`,
      };
    }
    return {
      attempted: true,
      serverAcceptsWeakCipher: false,
      negotiatedCipher: null,
      reason: `The target did not negotiate any locally available RC4/3DES cipher: ${error.message}`,
    };
  }
}

export function parseNmapHeartbleedXml(output) {
  let parsed;
  try {
    parsed = new XMLParser({ ignoreAttributes: false }).parse(output);
  } catch (error) {
    return { status: 'inconclusive', vulnerable: null, reason: `Unable to parse nmap XML: ${error.message}`, rawSummary: null };
  }
  const ports = parsed?.nmaprun?.host?.ports?.port;
  const portRecords = Array.isArray(ports) ? ports : ports ? [ports] : [];
  const scripts = portRecords.flatMap((record) => {
    const value = record.script;
    return Array.isArray(value) ? value : value ? [value] : [];
  });
  const script = scripts.find((record) => record['@_id'] === 'ssl-heartbleed');
  if (!script) {
    return { status: 'inconclusive', vulnerable: null, reason: 'nmap returned no ssl-heartbleed script result', rawSummary: null };
  }
  const summary = String(script['@_output'] ?? '');
  if (/NOT\s+VULNERABLE/i.test(summary)) {
    return { status: 'not-vulnerable', vulnerable: false, reason: null, rawSummary: summary };
  }
  if (/VULNERABLE/i.test(summary)) {
    return { status: 'vulnerable', vulnerable: true, reason: null, rawSummary: summary };
  }
  if (/could not identify|not enough data|failed|error/i.test(summary)) {
    return { status: 'inconclusive', vulnerable: null, reason: summary || 'nmap could not identify Heartbleed status', rawSummary: summary };
  }
  return { status: 'inconclusive', vulnerable: null, reason: 'nmap ssl-heartbleed output did not contain a recognized result', rawSummary: summary };
}

async function detectNmap(runCommand, signal) {
  try {
    const version = await runCommand('nmap', ['--version'], {
      signal,
      timeoutMs: 3000,
      maxOutputBytes: 64 * 1024,
    });
    return { available: true, version: version.split(/\r?\n/, 1)[0], reason: null };
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return { available: false, version: null, reason: `nmap is unavailable; Heartbleed was not assessed: ${error.message}` };
  }
}

async function checkHeartbleed(target, port, nmap, options) {
  if (!nmap.available) {
    return { status: 'not-assessed', vulnerable: null, reason: nmap.reason, scanner: null };
  }
  const args = ['-p', String(port), '--script', 'ssl-heartbleed', target, '-oX', '-'];
  try {
    const output = await options.runCommand('nmap', args, {
      signal: options.signal,
      timeoutMs: options.nmapTimeoutMs,
      maxOutputBytes: 2 * 1024 * 1024,
    });
    return { ...parseNmapHeartbleedXml(output), scanner: nmap.version, arguments: args };
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return {
      status: 'inconclusive',
      vulnerable: null,
      reason: `nmap ssl-heartbleed check failed: ${error.message}`,
      scanner: nmap.version,
      arguments: args,
    };
  }
}

function wait(milliseconds, signal) {
  if (milliseconds <= 0) return Promise.resolve();
  checkAbort(signal);
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

function createStartGate(delayMs, signal) {
  let previous = Promise.resolve();
  let lastStart = 0;
  return async () => {
    const current = previous.then(async () => {
      await wait(Math.max(0, delayMs - (Date.now() - lastStart)), signal);
      lastStart = Date.now();
    });
    previous = current.catch(() => {});
    return current;
  };
}

async function inspectEndpoint(target, port, options) {
  const versions = [];
  for (const version of TLS_VERSIONS) {
    checkAbort(options.signal);
    versions.push(await checkVersion(target, port, version, options));
  }
  const successful = versions.find((record) => record.handshake);
  const certificate = evaluateCertificate(
    successful?.handshake?.certificate,
    options.expiryWarningDays,
    options.now(),
  );
  const weakCapability = localWeakCipherCapability(options.tlsApi);
  const forcedWeakCipher = await assessWeakCipherAcceptance(target, port, weakCapability, options);
  const defaultNegotiatedCiphers = versions
    .filter((record) => record.negotiatedCipher)
    .map((record) => ({
      version: record.version,
      cipher: record.negotiatedCipher,
      weak: record.weakCipher,
    }));
  const heartbleed = await checkHeartbleed(target, port, options.nmap, options);
  return {
    target,
    port,
    reachable: Boolean(successful),
    versions: versions.map(({ handshake, ...record }) => record),
    weakCiphers: {
      defaultNegotiatedCiphers,
      anyDefaultNegotiatedCipherWeak: defaultNegotiatedCiphers.some((record) => record.weak),
      localWeakCipherCapability: weakCapability,
      forcedOffer: forcedWeakCipher,
    },
    certificate,
    heartbleed,
  };
}

export function createTlsChecksCollector({
  authorize = authorizeNetworkScan,
  handshake = performTlsHandshake,
  runCommand = runBoundedCommand,
  tlsApi = tls,
  now = () => new Date(),
  hooks,
} = {}) {
  return {
    name: 'tls-checks',
    version: '1.0.0',
    async run(params = {}, context = {}) {
      const config = context.collectorConfig ?? {};
      const authorization = authorize({
        config: {
          ...config,
          perPortTimeoutMs: config.perHandshakeTimeoutMs ?? 5000,
        },
        taskParams: {
          ...params,
          ports: params.ports ?? [...DEFAULT_TLS_PORTS],
        },
      });
      const authorizationSummary = {
        authorized: authorization.authorized,
        code: authorization.code,
        reason: authorization.reason,
        approvedTargets: authorization.approvedTargets,
        deniedTargets: authorization.deniedTargets,
      };
      if (!authorization.authorized) {
        return {
          reason: authorization.reason,
          authorization: authorizationSummary,
          endpoints: [],
          metadata: { heartbleedScanner: 'nmap ssl-heartbleed only; no raw fallback' },
        };
      }

      const ports = authorization.portPlan.ports;
      const endpointOperationCount = BigInt(authorization.estimatedHosts)
        * BigInt(ports.length)
        * BigInt(TLS_OPERATIONS_PER_ENDPOINT);
      if (endpointOperationCount > BigInt(authorization.limits.maxScanOperationsPerTask)) {
        const reason = `TLS task requires ${endpointOperationCount} operations, exceeding maxScanOperationsPerTask=${authorization.limits.maxScanOperationsPerTask}`;
        return {
          reason,
          authorization: { ...authorizationSummary, authorized: false, code: 'tls-operation-limit-exceeded', reason },
          endpoints: [],
          metadata: { heartbleedScanner: 'nmap ssl-heartbleed only; no raw fallback' },
        };
      }

      const nmap = await detectNmap(runCommand, context.signal);
      const hosts = expandApprovedTargets(authorization.approvedTargets);
      const endpoints = hosts.flatMap((host) => ports.map((port) => ({ target: host.target, port })));
      const limit = pLimit(authorization.limits.maxConcurrentTargets);
      const startGate = createStartGate(authorization.limits.perHostDelayMs, context.signal);
      const results = await Promise.all(endpoints.map((endpoint) => limit(async () => {
        checkAbort(context.signal);
        await startGate();
        hooks?.onEndpointStart?.(endpoint);
        try {
          return await inspectEndpoint(endpoint.target, endpoint.port, {
            signal: context.signal,
            timeoutMs: config.perHandshakeTimeoutMs ?? 5000,
            nmapTimeoutMs: config.nmapTimeoutMs ?? 15000,
            expiryWarningDays: config.expiryWarningDays ?? 30,
            nmap,
            handshake,
            runCommand,
            tlsApi,
            now,
          });
        } finally {
          hooks?.onEndpointEnd?.(endpoint);
        }
      })));

      return {
        reason: null,
        authorization: {
          ...authorizationSummary,
          estimatedTlsOperations: Number(endpointOperationCount),
        },
        endpoints: results,
        metadata: {
          defaultPorts: DEFAULT_TLS_PORTS,
          versionsAttempted: TLS_VERSIONS.map((version) => version.label),
          heartbleedScanner: 'nmap ssl-heartbleed only; no raw fallback',
          nmap,
          nodeVersion: process.version,
          opensslVersion: process.versions.openssl,
          oldTlsLimitation: 'Node accepts TLSv1/TLSv1.1 minVersion and maxVersion values, but OpenSSL policy or unavailable ciphers can still prevent a local attempt; those errors are reported as client-limitation.',
        },
      };
    },
  };
}

export const tlsChecksCollector = createTlsChecksCollector();
export default tlsChecksCollector;
