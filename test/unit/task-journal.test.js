import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { TaskJournal } from '../../src/task/task-journal.js';

const silentLogger = { debug() {}, info() {}, warn() {}, error() {} };

async function withTempDirectory(callback) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-task-journal-'));
  try {
    await callback(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function createJournal(directory, overrides = {}) {
  return new TaskJournal({
    path: 'state/task-journal.json',
    cwd: directory,
    logger: silentLogger,
    maxEntries: 100,
    maxAgeMs: 86_400_000,
    ...overrides,
  });
}

async function readEntries(directory) {
  return JSON.parse(await readFile(path.join(directory, 'state/task-journal.json'), 'utf8')).entries;
}

function task(number) {
  return { taskId: `task-${number}`, collectorName: `collector-${number}` };
}

test('state transitions are persisted with their applicable fields', async () => {
  await withTempDirectory(async (directory) => {
    let now = Date.parse('2026-01-01T00:00:00.000Z');
    const journal = createJournal(directory, { clock: () => new Date(now) });
    assert.deepEqual(await journal.initialize(), []);

    const accepted = await journal.accept(task(1));
    assert.deepEqual(accepted, {
      taskId: 'task-1', collectorName: 'collector-1', acceptedAt: '2026-01-01T00:00:00.000Z', status: 'accepted',
    });
    now += 1000;
    const running = await journal.markRunning('task-1');
    assert.equal(running.startedAt, '2026-01-01T00:00:01.000Z');
    now += 1000;
    const failed = await journal.markTerminal('task-1', 'failed', 'collector error');
    assert.equal(failed.finishedAt, '2026-01-01T00:00:02.000Z');
    assert.equal(failed.reason, 'collector error');
    assert.deepEqual(await readEntries(directory), [failed]);

    await assert.rejects(journal.markRunning('task-1'), /from status failed/);
    await assert.rejects(journal.markTerminal('task-1', 'cancelled'), /Invalid terminal task status/);
    await assert.rejects(journal.markTerminal('missing', 'completed'), /not found/);
  });
});

test('restart recovers accepted and running tasks exactly once', async () => {
  await withTempDirectory(async (directory) => {
    let now = Date.parse('2026-02-01T00:00:00.000Z');
    const first = createJournal(directory, { clock: () => new Date(now) });
    await first.initialize();
    await first.accept(task(1));
    await first.accept(task(2));
    await first.markRunning('task-2');
    await first.accept(task(3));
    await first.markTerminal('task-3', 'completed');

    now += 5000;
    const restarted = createJournal(directory, { clock: () => new Date(now) });
    const abandoned = await restarted.initialize();
    assert.deepEqual(abandoned.map((entry) => [entry.taskId, entry.status]), [
      ['task-1', 'accepted'], ['task-2', 'running'],
    ]);
    const recovered = await readEntries(directory);
    assert.equal(recovered.find((entry) => entry.taskId === 'task-1').status, 'interrupted');
    assert.equal(recovered.find((entry) => entry.taskId === 'task-2').finishedAt, '2026-02-01T00:00:05.000Z');
    assert.match(recovered.find((entry) => entry.taskId === 'task-2').reason, /crash recovery/i);

    const nextRestart = createJournal(directory, { clock: () => new Date(now + 1000) });
    assert.deepEqual(await nextRestart.initialize(), []);
  });
});

test('terminal state survives restart without being recovered', async () => {
  await withTempDirectory(async (directory) => {
    const first = createJournal(directory);
    await first.initialize();
    await first.accept(task(1));
    await first.markRunning('task-1');
    await first.markTerminal('task-1', 'completed');

    const restarted = createJournal(directory);
    assert.deepEqual(await restarted.initialize(), []);
    assert.equal((await readEntries(directory))[0].status, 'completed');
  });
});

test('age and count bounds prune only terminal entries', async () => {
  await withTempDirectory(async (directory) => {
    let now = 1_700_000_000_000;
    const journal = createJournal(directory, {
      clock: () => new Date(now), maxEntries: 2, maxAgeMs: 1000,
    });
    await journal.initialize();
    await journal.accept(task(1));
    await journal.accept(task(2));
    await journal.markTerminal('task-1', 'completed');
    now += 2000;
    await journal.accept(task(3));

    let entries = await readEntries(directory);
    assert.deepEqual(entries.map((entry) => entry.taskId), ['task-2', 'task-3']);
    assert.ok(entries.every((entry) => entry.status === 'accepted'));

    await journal.markTerminal('task-2', 'failed');
    await journal.accept(task(4));
    await journal.markTerminal('task-3', 'completed');
    entries = await readEntries(directory);
    assert.deepEqual(entries.map((entry) => entry.taskId).sort(), ['task-3', 'task-4']);
  });
});

test('concurrent operations are serialized without lost entries or corrupt JSON', async () => {
  await withTempDirectory(async (directory) => {
    let tick = 0;
    const journal = createJournal(directory, { clock: () => new Date(1_700_000_000_000 + tick++) });
    await journal.initialize();
    await Promise.all(Array.from({ length: 25 }, (_, index) => journal.accept(task(index))));
    await Promise.all(Array.from({ length: 25 }, (_, index) => journal.markRunning(`task-${index}`)));
    await Promise.all(Array.from({ length: 25 }, (_, index) => journal.markTerminal(`task-${index}`, 'completed')));

    const entries = await readEntries(directory);
    assert.equal(entries.length, 25);
    assert.ok(entries.every((entry) => entry.status === 'completed'));
    assert.deepEqual((await readdir(path.join(directory, 'state'))).sort(), ['task-journal.json']);
  });
});

test('corrupt journal fails initialization with a clear error', async () => {
  await withTempDirectory(async (directory) => {
    await writeFile(path.join(directory, 'corrupt.json'), '{not json', 'utf8');
    const journal = new TaskJournal({ path: 'corrupt.json', cwd: directory });
    await assert.rejects(journal.initialize(), /Unable to read task journal.*JSON/);
  });
});
