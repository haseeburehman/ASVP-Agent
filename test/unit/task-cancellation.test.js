import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { TaskRunner } from '../../src/core/task-runner.js';
import { TaskJournal } from '../../src/task/task-journal.js';

const logger = { info() {}, warn() {}, error() {}, debug() {} };

async function withDirectory(callback) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-task-cancel-'));
  try { await callback(directory); } finally { await rm(directory, { recursive: true, force: true }); }
}

test('runAll propagates shutdown cancellation and journals interruption', async () => {
  await withDirectory(async (directory) => {
    let collectorSignal;
    const collector = {
      name: 'waiting',
      version: '1.0.0',
      async run(_params, { signal }) {
        collectorSignal = signal;
        return new Promise(() => {});
      },
    };
    const registry = {
      getDefinition: () => ({ implemented: true, timeoutMs: 60_000, concurrency: 1 }),
      async get() { return collector; },
    };
    const journal = new TaskJournal({ path: 'journal.json', cwd: directory, logger });
    await journal.initialize();
    const handedOff = [];
    const runner = new TaskRunner({ registry, logger, taskJournal: journal, onResult: async (result) => handedOff.push(result) });
    const controller = new AbortController();
    const startedAt = Date.now();
    const execution = runner.runAll([{ taskId: 'task-cancelled', collectorName: 'waiting', params: {} }], { signal: controller.signal });
    await new Promise((resolve) => setTimeout(resolve, 20));
    controller.abort();
    const [result] = await execution;

    assert.equal(collectorSignal.aborted, true);
    assert.ok(Date.now() - startedAt < 1000);
    assert.equal(result.status, 'failed');
    assert.equal(result.error.name, 'AbortError');
    assert.ok(result.error.code === 'ABORT_ERR' || result.error.code === 20);
    assert.equal(handedOff.length, 1);
    const entries = JSON.parse(await readFile(path.join(directory, 'journal.json'), 'utf8')).entries;
    assert.equal(entries[0].status, 'interrupted');
    assert.equal(entries[0].reason, 'Interrupted by agent shutdown');
    assert.ok(entries[0].startedAt);
    assert.ok(entries[0].finishedAt);
  });
});
