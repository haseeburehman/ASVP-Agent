import ipaddr from 'ipaddr.js';

export const DEFAULT_SCAN_LIMITS = Object.freeze({
  maxCidrSize: 16,
  allowWideRanges: false,
  maxConcurrentTargets: 5,
  maxPortsPerHost: 1000,
  perHostDelayMs: 100,
  perPortTimeoutMs: 1000,
  maxScanOperationsPerTask: 100000,
});

function refusal(code, reason, extra = {}) {
  return {
    authorized: false,
    code,
    reason,
    approvedTargets: [],
    deniedTargets: [],
    ...extra,
  };
}

function parseNetwork(value) {
  if (typeof value !== 'string' || value.trim() === '') throw new Error('Target must be a non-empty IP address or CIDR string');
  const input = value.trim();
  const [address, prefixLength] = input.includes('/')
    ? ipaddr.parseCIDR(input)
    : (() => {
      const parsed = ipaddr.parse(input);
      return [parsed, parsed.kind() === 'ipv4' ? 32 : 128];
    })();
  const bitLength = address.kind() === 'ipv4' ? 32 : 128;
  return {
    input,
    address,
    kind: address.kind(),
    prefixLength,
    bitLength,
    canonical: `${address.toString()}/${prefixLength}`,
    addressCount: 1n << BigInt(bitLength - prefixLength),
  };
}

function printableCount(value) {
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString();
}

function validatePositiveInteger(value, name, { minimum = 1, allowZero = false } = {}) {
  const lowerBound = allowZero ? 0 : minimum;
  if (!Number.isInteger(value) || value < lowerBound) throw new Error(`${name} must be an integer greater than or equal to ${lowerBound}`);
  return value;
}

export function resolveScanLimits(config = {}) {
  const limits = {
    maxCidrSize: config.maxCidrSize ?? DEFAULT_SCAN_LIMITS.maxCidrSize,
    allowWideRanges: config.allowWideRanges ?? DEFAULT_SCAN_LIMITS.allowWideRanges,
    maxConcurrentTargets: config.maxConcurrentTargets ?? DEFAULT_SCAN_LIMITS.maxConcurrentTargets,
    maxPortsPerHost: config.maxPortsPerHost ?? DEFAULT_SCAN_LIMITS.maxPortsPerHost,
    perHostDelayMs: config.perHostDelayMs ?? DEFAULT_SCAN_LIMITS.perHostDelayMs,
    perPortTimeoutMs: config.perPortTimeoutMs ?? DEFAULT_SCAN_LIMITS.perPortTimeoutMs,
    maxScanOperationsPerTask: config.maxScanOperationsPerTask
      ?? DEFAULT_SCAN_LIMITS.maxScanOperationsPerTask,
  };

  validatePositiveInteger(limits.maxCidrSize, 'maxCidrSize');
  if (typeof limits.allowWideRanges !== 'boolean') throw new Error('allowWideRanges must be a boolean');
  validatePositiveInteger(limits.maxConcurrentTargets, 'maxConcurrentTargets');
  validatePositiveInteger(limits.maxPortsPerHost, 'maxPortsPerHost');
  validatePositiveInteger(limits.perHostDelayMs, 'perHostDelayMs', { allowZero: true });
  validatePositiveInteger(limits.perPortTimeoutMs, 'perPortTimeoutMs');
  validatePositiveInteger(limits.maxScanOperationsPerTask, 'maxScanOperationsPerTask');
  return limits;
}

function validateAllowlist(allowedCidrs, limits) {
  if (!Array.isArray(allowedCidrs)) throw new Error('allowedCidrs must be an array');
  const parsed = [];
  for (const value of allowedCidrs) {
    const network = parseNetwork(value);
    if (limits.maxCidrSize > network.bitLength) {
      throw new Error(`maxCidrSize /${limits.maxCidrSize} is invalid for ${network.kind}`);
    }
    const isDefaultRoute = network.prefixLength === 0;
    const isTooWide = network.prefixLength < limits.maxCidrSize;
    if (!limits.allowWideRanges && (isDefaultRoute || isTooWide)) {
      throw new Error(
        `Allowlist range "${value}" is wider than /${limits.maxCidrSize}; set allowWideRanges=true only after explicit review`,
      );
    }
    parsed.push(network);
  }
  return parsed;
}

function isContained(requested, allowed) {
  return requested.kind === allowed.kind
    && requested.prefixLength >= allowed.prefixLength
    && requested.address.match(allowed.address, allowed.prefixLength);
}

function validatePorts(ports, limits) {
  if (ports === undefined) {
    return {
      count: limits.maxPortsPerHost,
      ports: null,
      usesScannerDefault: true,
    };
  }
  if (!Array.isArray(ports) || ports.length === 0) throw new Error('ports must be a non-empty array when provided');
  const unique = new Set();
  for (const port of ports) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`Invalid TCP port "${port}"`);
    unique.add(port);
  }
  if (unique.size > limits.maxPortsPerHost) {
    throw new Error(`Task requests ${unique.size} ports per host, exceeding maxPortsPerHost=${limits.maxPortsPerHost}`);
  }
  return { count: unique.size, ports: [...unique], usesScannerDefault: false };
}

export function authorizeNetworkScan({ config = {}, taskParams = {} } = {}) {
  let limits;
  try {
    limits = resolveScanLimits(config);
  } catch (error) {
    return refusal('invalid-safety-config', `Network scan safety configuration is invalid: ${error.message}`);
  }

  const allowedCidrs = config.allowedCidrs ?? [];
  if (!Array.isArray(allowedCidrs) || allowedCidrs.length === 0) {
    return refusal(
      'allowlist-not-configured',
      'No local allowedCidrs are configured; network scanning is disabled by default',
      { limits },
    );
  }

  let allowlist;
  try {
    allowlist = validateAllowlist(allowedCidrs, limits);
  } catch (error) {
    return refusal('invalid-allowlist', `Local network scan allowlist is unsafe or invalid: ${error.message}`, { limits });
  }

  if (!Array.isArray(taskParams.targets) || taskParams.targets.length === 0) {
    return refusal(
      'task-targets-required',
      'The task did not include an explicit non-empty targets array; the local allowlist is never used as a default target set',
      { limits },
    );
  }

  let portPlan;
  try {
    portPlan = validatePorts(taskParams.ports, limits);
  } catch (error) {
    return refusal('invalid-port-plan', `Network scan task port plan was refused: ${error.message}`, { limits });
  }

  const approvedTargets = [];
  const deniedTargets = [];
  for (const value of taskParams.targets) {
    let requested;
    try {
      requested = parseNetwork(value);
    } catch (error) {
      deniedTargets.push({ target: value, status: 'authorization-denied', reason: `Invalid target: ${error.message}` });
      continue;
    }
    const ceiling = allowlist.find((allowed) => isContained(requested, allowed));
    if (!ceiling) {
      deniedTargets.push({
        target: value,
        status: 'authorization-denied',
        reason: 'Target is not fully contained within any locally configured allowed CIDR',
      });
      continue;
    }
    approvedTargets.push({
      target: value,
      canonicalTarget: requested.canonical,
      addressCount: printableCount(requested.addressCount),
      authorizedBy: ceiling.canonical,
    });
  }

  if (approvedTargets.length === 0) {
    return refusal(
      'no-authorized-targets',
      'None of the task targets passed the local allowlist',
      { limits, deniedTargets, portPlan },
    );
  }

  const approvedHostCount = approvedTargets.reduce(
    (total, target) => total + BigInt(target.addressCount),
    0n,
  );
  const operationCount = approvedHostCount * BigInt(portPlan.count);
  if (operationCount > BigInt(limits.maxScanOperationsPerTask)) {
    const reason = `Task requires ${operationCount} host-port operations, exceeding maxScanOperationsPerTask=${limits.maxScanOperationsPerTask}`;
    return refusal('task-operation-limit-exceeded', reason, {
      limits,
      portPlan,
      estimatedHosts: printableCount(approvedHostCount),
      estimatedOperations: printableCount(operationCount),
      deniedTargets: [
        ...deniedTargets,
        ...approvedTargets.map((target) => ({
          target: target.target,
          status: 'authorization-denied',
          reason,
        })),
      ],
    });
  }

  return {
    authorized: true,
    code: 'authorized',
    reason: null,
    approvedTargets,
    deniedTargets,
    limits,
    portPlan,
    estimatedHosts: printableCount(approvedHostCount),
    estimatedOperations: printableCount(operationCount),
  };
}
