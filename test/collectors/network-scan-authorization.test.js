import assert from 'node:assert/strict';
import test from 'node:test';
import {
  authorizeNetworkScan,
  DEFAULT_SCAN_LIMITS,
  resolveScanLimits,
} from '../../src/collectors/network-scan/authorization.js';

const safeConfig = {
  allowedCidrs: ['10.20.0.0/16', '192.168.50.0/24'],
  maxCidrSize: 16,
  maxConcurrentTargets: 5,
  maxPortsPerHost: 1000,
  perHostDelayMs: 100,
  perPortTimeoutMs: 1000,
  maxScanOperationsPerTask: 100000,
};

test('empty local allowlist refuses all scanning', () => {
  const result = authorizeNetworkScan({
    config: { allowedCidrs: [] },
    taskParams: { targets: ['10.20.1.1'], ports: [443] },
  });

  assert.equal(result.authorized, false);
  assert.equal(result.code, 'allowlist-not-configured');
  assert.deepEqual(result.approvedTargets, []);
  assert.match(result.reason, /disabled by default/);
});

test('allowlist rejects ranges wider than the configured /16 ceiling', () => {
  const result = authorizeNetworkScan({
    config: { ...safeConfig, allowedCidrs: ['10.0.0.0/8'] },
    taskParams: { targets: ['10.1.2.3'], ports: [443] },
  });

  assert.equal(result.authorized, false);
  assert.equal(result.code, 'invalid-allowlist');
  assert.match(result.reason, /wider than \/16/);
});

test('default routes are rejected unless wide ranges are explicitly enabled', () => {
  for (const defaultRoute of ['0.0.0.0/0', '::/0']) {
    const denied = authorizeNetworkScan({
      config: { ...safeConfig, allowedCidrs: [defaultRoute] },
      taskParams: { targets: ['10.1.2.3'], ports: [443] },
    });
    assert.equal(denied.code, 'invalid-allowlist');
  }

  const explicitlyApproved = authorizeNetworkScan({
    config: {
      ...safeConfig,
      allowedCidrs: ['0.0.0.0/0'],
      allowWideRanges: true,
      maxScanOperationsPerTask: 10,
    },
    taskParams: { targets: ['203.0.113.7'], ports: [443] },
  });
  assert.equal(explicitlyApproved.authorized, true);
});

test('mixed task targets are independently approved or denied', () => {
  const result = authorizeNetworkScan({
    config: safeConfig,
    taskParams: {
      targets: ['10.20.1.10', '192.168.50.0/28', '172.16.1.1', 'not-an-ip'],
      ports: [22, 443],
    },
  });

  assert.equal(result.authorized, true);
  assert.deepEqual(result.approvedTargets.map((item) => item.target), [
    '10.20.1.10',
    '192.168.50.0/28',
  ]);
  assert.deepEqual(result.deniedTargets.map((item) => item.target), ['172.16.1.1', 'not-an-ip']);
  assert.ok(result.deniedTargets.every((item) => item.status === 'authorization-denied'));
  assert.equal(result.estimatedHosts, 17);
  assert.equal(result.estimatedOperations, 34);
});

test('IPv4 CIDR containment requires the full requested range to be inside an allowlist entry', () => {
  const inside = authorizeNetworkScan({
    config: safeConfig,
    taskParams: { targets: ['192.168.50.128/25'], ports: [80] },
  });
  assert.equal(inside.authorized, true);
  assert.equal(inside.approvedTargets[0].authorizedBy, '192.168.50.0/24');

  const broaderThanCeiling = authorizeNetworkScan({
    config: safeConfig,
    taskParams: { targets: ['192.168.50.0/23'], ports: [80] },
  });
  assert.equal(broaderThanCeiling.authorized, false);
  assert.equal(broaderThanCeiling.deniedTargets[0].status, 'authorization-denied');

  const boundaryOutside = authorizeNetworkScan({
    config: safeConfig,
    taskParams: { targets: ['192.168.51.0/24'], ports: [80] },
  });
  assert.equal(boundaryOutside.authorized, false);
});

test('task without explicit targets is refused and never falls back to the allowlist', () => {
  for (const taskParams of [{}, { targets: [] }, { ports: [443] }]) {
    const result = authorizeNetworkScan({ config: safeConfig, taskParams });
    assert.equal(result.authorized, false);
    assert.equal(result.code, 'task-targets-required');
    assert.deepEqual(result.approvedTargets, []);
    assert.match(result.reason, /never used as a default target set/);
  }
});

test('task requesting too many ports is refused rather than truncated', () => {
  const result = authorizeNetworkScan({
    config: { ...safeConfig, maxPortsPerHost: 2 },
    taskParams: { targets: ['10.20.1.1'], ports: [22, 80, 443] },
  });

  assert.equal(result.authorized, false);
  assert.equal(result.code, 'invalid-port-plan');
  assert.match(result.reason, /exceeding maxPortsPerHost=2/);
});

test('oversized host-port operation plan is refused in full before scanning', () => {
  const result = authorizeNetworkScan({
    config: { ...safeConfig, maxScanOperationsPerTask: 100 },
    taskParams: { targets: ['192.168.50.0/24'], ports: [80] },
  });

  assert.equal(result.authorized, false);
  assert.equal(result.code, 'task-operation-limit-exceeded');
  assert.deepEqual(result.approvedTargets, []);
  assert.equal(result.estimatedHosts, 256);
  assert.equal(result.estimatedOperations, 256);
  assert.equal(result.deniedTargets[0].status, 'authorization-denied');
  assert.match(result.deniedTargets[0].reason, /exceeding maxScanOperationsPerTask=100/);
});

test('duplicate ports count once for safety-plan calculations', () => {
  const result = authorizeNetworkScan({
    config: safeConfig,
    taskParams: { targets: ['10.20.1.1'], ports: [443, 443, 80] },
  });

  assert.equal(result.authorized, true);
  assert.deepEqual(result.portPlan.ports, [443, 80]);
  assert.equal(result.estimatedOperations, 2);
});

test('rate-limit defaults are explicit and validated', () => {
  assert.deepEqual(resolveScanLimits({}), DEFAULT_SCAN_LIMITS);
  assert.throws(() => resolveScanLimits({ maxConcurrentTargets: 0 }), /maxConcurrentTargets/);
  assert.throws(() => resolveScanLimits({ maxPortsPerHost: 0 }), /maxPortsPerHost/);
  assert.throws(() => resolveScanLimits({ perHostDelayMs: -1 }), /perHostDelayMs/);
  assert.throws(() => resolveScanLimits({ perPortTimeoutMs: 0 }), /perPortTimeoutMs/);
  assert.throws(() => resolveScanLimits({ maxScanOperationsPerTask: 0 }), /maxScanOperationsPerTask/);
});

test('invalid target does not prevent a separate valid target from being authorized', () => {
  const result = authorizeNetworkScan({
    config: safeConfig,
    taskParams: { targets: ['invalid', '10.20.4.5'], ports: [443] },
  });

  assert.equal(result.authorized, true);
  assert.equal(result.approvedTargets.length, 1);
  assert.equal(result.deniedTargets.length, 1);
  assert.equal(result.deniedTargets[0].target, 'invalid');
});
