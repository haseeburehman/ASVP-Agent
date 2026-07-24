import assert from 'node:assert/strict';
import test from 'node:test';
import { applicationMetrics, describeCheck, unwrapCollectorPayload } from '../src/public/dashboard/posture-data.js';

test('posture data unwraps normalized results and reports all 347 detected apps', () => {
  const stored = {
    collector: 'apps',
    status: 'success',
    data: {
      summary: { totalDetected: 347, returnedItems: 500, truncated: 0 },
      applications: { totalDetected: 347, items: [{ name: 'One' }, { name: 'Two' }], truncated: 0 },
      services: { totalDetected: 153, items: [] },
    },
  };
  const payload = unwrapCollectorPayload(stored, 'apps');
  assert.equal(applicationMetrics(payload).totalDetected, 347);
  assert.equal(applicationMetrics(payload).shown, 2);
});

test('posture checks distinguish failures from not-applicable with reasons', () => {
  assert.equal(describeCheck({ status: 'check-failed', reason: 'Get-NetFirewallProfile timed out' }), 'check-failed: Get-NetFirewallProfile timed out');
  assert.equal(describeCheck({ status: 'not-applicable', reason: 'OpenSSH Server is not installed' }), 'not applicable: OpenSSH Server is not installed');
  assert.equal(describeCheck({ status: 'checked', active: true }, (active) => active ? 'active' : 'inactive'), 'active');
});
