import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createProcessSummaryCollector } from '../../src/collectors/process-summary/index.js';

const sampleProcesses = [
  {
    pid: 42,
    parentPid: 7,
    name: 'worker',
    user: 'service-user',
    started: '2026-07-27 10:00:00',
    cpu: 1.25,
    mem: 2.5,
    memRss: 128,
    memVsz: 512,
    command: '/opt/worker --secret token',
    params: '--secret token',
    path: '/opt/worker',
  },
  { pid: 3, parentPid: 1, name: 'daemon', cpu: 0, mem: 0.5, memRss: 64, memVsz: 256 },
  { pid: 11, parentPid: 3, name: 'helper', cpu: 0.1, mem: 0.75, memRss: 96, memVsz: 384 },
];

test('process-summary returns a read-only allowlisted process projection', async () => {
  const collector = createProcessSummaryCollector({
    processProvider: async () => ({ list: sampleProcesses }),
  });

  const result = await collector.run({}, { collectorConfig: { maxItems: 10 } });

  assert.deepEqual(result.processes.map(({ pid }) => pid), [3, 11, 42]);
  assert.deepEqual(result.processes[2], {
    name: 'worker',
    pid: 42,
    parentPid: 7,
    user: 'service-user',
    startTime: '2026-07-27 10:00:00',
    cpuPercent: 1.25,
    memory: { percent: 2.5, rssBytes: 131072, virtualBytes: 524288 },
  });
  assert.equal(JSON.stringify(result).includes('--secret'), false);
  assert.equal(result.reason, null);
});

test('process-summary deterministically caps output and reports truncation', async () => {
  const collector = createProcessSummaryCollector({
    processProvider: async () => ({ list: sampleProcesses }),
  });

  const result = await collector.run({}, { collectorConfig: { maxItems: 2 } });

  assert.deepEqual(result.processes.map(({ pid }) => pid), [3, 11]);
  assert.deepEqual(result.summary, {
    maxItems: 2,
    totalDetected: 3,
    returnedItems: 2,
    truncated: 1,
  });
});

test('process-summary uses a sane default for invalid maxItems', async () => {
  const collector = createProcessSummaryCollector({
    processProvider: async () => ({ list: sampleProcesses }),
  });

  const result = await collector.run({}, { collectorConfig: { maxItems: 0 } });

  assert.equal(result.summary.maxItems, 250);
  assert.equal(result.summary.returnedItems, 3);
});

test('process-summary handles aborts before and during collection', async () => {
  const before = new AbortController();
  before.abort();
  const collector = createProcessSummaryCollector({
    processProvider: async () => ({ list: sampleProcesses }),
  });
  await assert.rejects(collector.run({}, { signal: before.signal }), { name: 'AbortError', code: 'ABORT_ERR' });

  const during = new AbortController();
  const abortingCollector = createProcessSummaryCollector({
    processProvider: async () => {
      during.abort();
      return { list: sampleProcesses };
    },
  });
  await assert.rejects(abortingCollector.run({}, { signal: during.signal }), { name: 'AbortError', code: 'ABORT_ERR' });
});

test('process-summary source never requests commands, arguments, or memory contents', async () => {
  const source = await readFile(new URL('../../src/collectors/process-summary/index.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /\.command\b|\.params\b|\.args\b/);
  assert.doesNotMatch(source, /node:child_process|\b(?:spawn|exec|execFile)\s*\(/);
  assert.doesNotMatch(source, /readProcessMemory|processMemoryContents/);
});
