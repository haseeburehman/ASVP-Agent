import assert from 'node:assert/strict';
import test from 'node:test';
import { TaskRateTracker } from '../../src/task/rate-tracker.js';

function tasks(count, offset = 0) {
  return Array.from({ length: count }, (_, index) => ({ taskId: `task-${offset + index}`, collectorName: 'noop' }));
}

test('enforces a cumulative rolling execution limit across polls', () => {
  let now = 1_000_000;
  const tracker = new TaskRateTracker({ maxExecutions: 3, windowMs: 300_000, clock: () => now });
  assert.deepEqual(tracker.admit(tasks(2)).accepted.map(({ taskId }) => taskId), ['task-0', 'task-1']);
  const second = tracker.admit(tasks(3, 2));
  assert.deepEqual(second.accepted.map(({ taskId }) => taskId), ['task-2']);
  assert.deepEqual(second.rejected.map(({ task }) => task.taskId), ['task-3', 'task-4']);
  assert.ok(second.rejected.every(({ reasonCode }) => reasonCode === 'TASK_RATE_LIMIT_EXCEEDED'));

  now += 300_001;
  assert.equal(tracker.admit(tasks(3, 5)).accepted.length, 3);
});

test('uses the documented default of 30 executions per five minutes', () => {
  const tracker = new TaskRateTracker({ clock: () => 1_000_000 });
  const result = tracker.admit(tasks(31));
  assert.equal(result.maxExecutions, 30);
  assert.equal(result.windowMs, 300_000);
  assert.equal(result.accepted.length, 30);
  assert.equal(result.rejected.length, 1);
});
