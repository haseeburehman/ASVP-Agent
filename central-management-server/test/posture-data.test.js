import assert from 'node:assert/strict';
import test from 'node:test';
import { applicationMetrics, describeCheck, latestCollectorState, unwrapCollectorPayload } from '../src/public/dashboard/posture-data.js';

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

test('all baseline cards prefer full latest results and only show pending for active tasks', () => {
  const results = [
    {
      id: 'result-os', collector: 'os-info', status: 'success', received_at: '2026-07-24T10:05:00.000Z',
      data: { collector: 'os-info', status: 'success', data: { prettyName: 'Ubuntu 24.04 LTS', version: '24.04', architecture: 'x64' } },
    },
    {
      id: 'result-apps', collector: 'apps', status: 'failed', received_at: '2026-07-24T10:04:00.000Z',
      data: { collector: 'apps', status: 'failed', error: 'Registry inventory access denied', data: null },
    },
    {
      id: 'result-users', collector: 'users-groups', status: 'failed', received_at: '2026-07-24T10:03:30.000Z',
      data: { collector: 'users-groups', status: 'failed', error: 'Get-LocalGroupMember failed', data: null },
    },
    {
      id: 'result-antivirus', collector: 'antivirus-status', status: 'failed', received_at: '2026-07-24T10:03:15.000Z',
      data: { collector: 'antivirus-status', status: 'failed', error: 'SecurityCenter2 query failed', data: null },
    },
  ];
  const tasks = [
    { id: 'task-os-newer', collector_name: 'os-info', status: 'dispatched', created_at: '2026-07-24T10:06:00.000Z' },
    { id: 'task-apps', collector_name: 'apps', status: 'completed', created_at: '2026-07-24T10:03:00.000Z' },
    { id: 'task-users', collector_name: 'users-groups', status: 'pending', created_at: '2026-07-24T10:02:00.000Z' },
    { id: 'task-antivirus', collector_name: 'antivirus-status', status: 'dispatched', created_at: '2026-07-24T10:01:00.000Z' },
    { id: 'task-compliance', collector_name: 'compliance-checks', status: 'pending', created_at: '2026-07-24T10:00:00.000Z' },
  ];

  const os = latestCollectorState(results, tasks, 'os-info');
  const apps = latestCollectorState(results, tasks, 'apps');
  const users = latestCollectorState(results, tasks, 'users-groups');
  const antivirus = latestCollectorState(results, tasks, 'antivirus-status');
  const compliance = latestCollectorState(results, tasks, 'compliance-checks');

  assert.equal(os.state, 'success');
  assert.equal(os.envelope, results[0].data);
  assert.equal(os.result, results[0]);
  assert.equal(os.payload.prettyName, 'Ubuntu 24.04 LTS');
  assert.equal(apps.state, 'failed');
  assert.equal(apps.error, 'Registry inventory access denied');
  assert.equal(apps.envelope, results[1].data);
  assert.equal(users.state, 'failed');
  assert.equal(users.error, 'Get-LocalGroupMember failed');
  assert.equal(antivirus.state, 'failed');
  assert.equal(antivirus.error, 'SecurityCenter2 query failed');
  assert.equal(compliance.state, 'pending');
});

test('completed task without a result is missing rather than pending', () => {
  const state = latestCollectorState([], [{ collector_name: 'compliance-checks', status: 'completed' }], 'compliance-checks');
  assert.equal(state.state, 'missing');
});

test('posture checks distinguish failures from not-applicable with reasons', () => {
  assert.equal(describeCheck({ status: 'check-failed', reason: 'Get-NetFirewallProfile timed out' }), 'check-failed: Get-NetFirewallProfile timed out');
  assert.equal(describeCheck({ status: 'not-applicable', reason: 'OpenSSH Server is not installed' }), 'not applicable: OpenSSH Server is not installed');
  assert.equal(describeCheck({ status: 'checked', active: true }, (active) => active ? 'active' : 'inactive'), 'active');
});
