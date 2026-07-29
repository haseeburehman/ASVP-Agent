import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createProcessSummaryCollector } from '../../src/collectors/process-summary/index.js';

const sampleProcesses = [
  { pid: 42, parentPid: 7, name: 'worker', user: 'service-user', started: '2026-07-27 10:00:00', cpu: 1.25, mem: 2.5, memRss: 128, memVsz: 512, command: '/opt/worker --secret token', params: '--secret token', path: '/opt/worker' },
  { pid: 3, parentPid: 1, name: 'daemon', cpu: 0, mem: 0.5, memRss: 64, memVsz: 256 },
  { pid: 11, parentPid: 3, name: 'helper', cpu: 0.1, mem: 0.75, memRss: 96, memVsz: 384 },
];
function collector(overrides = {}) { return createProcessSummaryCollector({ processProvider: async () => ({ list: sampleProcesses }), connectionProvider: async () => [], hashProvider: async () => 'a'.repeat(64), ...overrides }); }

test('process-summary returns an enriched allowlisted process projection without arguments', async () => {
  const result = await collector({ connectionProvider: async () => [{ pid: 42, state: 'ESTABLISHED' }, { pid: 42, state: 'established' }] }).run({}, { collectorConfig: { maxItems: 10 } });
  assert.deepEqual(result.processes.map(({ pid }) => pid), [3, 11, 42]);
  const worker = result.processes[2];
  assert.equal(worker.user, 'service-user'); assert.equal(worker.binaryPath, '/opt/worker');
  assert.equal(worker.binarySha256, 'a'.repeat(64)); assert.equal(worker.binaryHashAvailability.status, 'available');
  assert.equal(worker.establishedConnectionCount, 2); assert.equal(worker.connectionCountAvailability.status, 'available');
  assert.deepEqual(worker.memory, { percent: 2.5, rssBytes: 131072, virtualBytes: 524288 });
  assert.equal(JSON.stringify(result).includes('--secret'), false);
});

test('hashing is bounded by process count and reports oversized or denied files honestly', async () => {
  let attempts = 0;
  const result = await collector({ hashProvider: async (_path, { maxBytes }) => { attempts += 1; assert.equal(maxBytes, 100); const error = new Error('Executable is 500 bytes, exceeding the 100-byte hashing limit'); error.code = 'HASH_SIZE_LIMIT'; throw error; } })
    .run({}, { collectorConfig: { maxItems: 10, maxHashedProcesses: 1, maxHashFileBytes: 100 } });
  assert.equal(attempts, 1); assert.equal(result.summary.hashAttempts, 1);
  assert.equal(result.processes[2].binarySha256, null); assert.equal(result.processes[2].binaryHashAvailability.status, 'unavailable');
  assert.match(result.processes[2].binaryHashAvailability.reason, /hashing limit/);
});

test('connection inventory failure is per-field and privilege-aware', async () => {
  const error = new Error('permission denied'); error.code = 'EACCES';
  const result = await collector({ connectionProvider: async () => { throw error; } }).run({}, { collectorConfig: { maxItems: 2 } });
  assert.equal(result.processes[0].establishedConnectionCount, null);
  assert.equal(result.processes[0].connectionCountAvailability.status, 'insufficient_privilege');
});

test('process-summary deterministically caps output and reports enrichment bounds', async () => {
  const result = await collector().run({}, { collectorConfig: { maxItems: 2, maxHashedProcesses: 0 } });
  assert.deepEqual(result.processes.map(({ pid }) => pid), [3, 11]);
  assert.equal(result.summary.maxItems, 2); assert.equal(result.summary.totalDetected, 3); assert.equal(result.summary.truncated, 1); assert.equal(result.summary.hashAttempts, 0);
});

test('process-summary uses sane defaults and handles aborts', async () => {
  const result = await collector().run({}, { collectorConfig: { maxItems: 0 } });
  assert.equal(result.summary.maxItems, 250); assert.equal(result.summary.maxHashedProcesses, 25); assert.equal(result.summary.maxHashFileBytes, 200 * 1024 * 1024);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(collector().run({}, { signal: controller.signal }), { name: 'AbortError', code: 'ABORT_ERR' });
});

test('process-summary source never requests arguments, environment, or memory contents', async () => {
  const source = await readFile(new URL('../../src/collectors/process-summary/index.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /\.command\b|\.params\b|\.args\b|\.env\b/);
  assert.doesNotMatch(source, /node:child_process|\b(?:spawn|exec|execFile)\s*\(/);
  assert.doesNotMatch(source, /readProcessMemory|processMemoryContents/);
});
