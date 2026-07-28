import { randomUUID } from 'node:crypto';
import { chmod, mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { verifyTaskEnvelopeSignature } from '../security/task-envelope.js';

const DEFAULT_CLOCK_SKEW_MS = 30_000;
const DEFAULT_MAX_REPLAY_ENTRIES = 10_000;

async function readLedger(ledgerPath) {
  try {
    const value = JSON.parse(await readFile(ledgerPath, 'utf8'));
    return Array.isArray(value?.entries) ? value.entries : [];
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw new Error(`Unable to read task replay ledger: ${error.message}`, { cause: error });
  }
}

async function syncDirectory(directory) {
  let handle;
  try {
    handle = await open(directory, 'r');
    await handle.sync();
  } catch (error) {
    if (process.platform !== 'win32') throw error;
  } finally {
    await handle?.close();
  }
}

async function writeLedger(ledgerPath, entries) {
  const directory = path.dirname(ledgerPath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporaryPath = `${ledgerPath}.${process.pid}.${randomUUID()}.tmp`;
  let handle;
  try {
    handle = await open(temporaryPath, 'wx', 0o600);
    await handle.writeFile(`${JSON.stringify({ entries }, null, 2)}\n`, 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await rename(temporaryPath, ledgerPath);
    await chmod(ledgerPath, 0o600).catch((error) => {
      if (process.platform !== 'win32') throw error;
    });
    await syncDirectory(directory);
  } catch (error) {
    await handle?.close().catch(() => {});
    await rm(temporaryPath, { force: true }).catch(() => {});
    throw error;
  }
}

function parseTimestamp(value, name) {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) throw new Error(`${name} must be a valid timestamp`);
  return timestamp;
}

export class TaskEnvelopeVerifier {
  constructor({ identity, ledgerPath, logger, cwd = process.cwd(), clock = Date.now, clockSkewMs = DEFAULT_CLOCK_SKEW_MS, maxReplayEntries = DEFAULT_MAX_REPLAY_ENTRIES }) {
    this.identity = identity;
    this.ledgerPath = path.resolve(cwd, ledgerPath ?? 'var/task-replay-ledger.json');
    this.logger = logger;
    this.clock = clock;
    this.clockSkewMs = clockSkewMs;
    this.maxReplayEntries = maxReplayEntries;
    this.operation = Promise.resolve();
  }

  verifyAll(tasks) {
    const run = this.operation.then(() => this.#verifyAll(tasks));
    this.operation = run.catch(() => {});
    return run;
  }

  listReplayClaims() {
    const run = this.operation.then(async () => {
      const now = this.clock();
      return (await readLedger(this.ledgerPath))
        .filter((entry) => Number.isFinite(entry.expiresAt) && entry.expiresAt + this.clockSkewMs >= now)
        .map((entry) => ({ ...entry }));
    });
    this.operation = run.catch(() => {});
    return run;
  }

  async #verifyAll(tasks) {
    const now = this.clock();
    let entries = (await readLedger(this.ledgerPath))
      .filter((entry) => Number.isFinite(entry.expiresAt) && entry.expiresAt + this.clockSkewMs >= now);
    const accepted = [];

    for (const task of tasks) {
      try {
        const replayEntry = this.#verify(task, entries, now);
        entries.push(replayEntry);
        accepted.push(task);
      } catch (error) {
        this.logger?.warn({
          taskId: task?.taskId,
          reason: error.message,
        }, 'Rejected invalid task envelope');
      }
    }

    entries = entries.slice(-this.maxReplayEntries);
    await writeLedger(this.ledgerPath, entries);
    return accepted;
  }

  #verify(task, entries, now) {
    if (!task || typeof task !== 'object' || Array.isArray(task)) throw new Error('task envelope must be an object');
    if (task.keyId !== this.identity.taskSigningKeyId) throw new Error('task signing keyId does not match identity');
    if (task.tenantId !== this.identity.tenantId) throw new Error('task tenantId does not match identity');
    if (task.agentId !== this.identity.agentId) throw new Error('task agentId does not match identity');
    if (!verifyTaskEnvelopeSignature(task, this.identity.taskSigningKey)) throw new Error('task signature is invalid');

    const issuedAt = parseTimestamp(task.issuedAt, 'issuedAt');
    const expiresAt = parseTimestamp(task.expiresAt, 'expiresAt');
    if (expiresAt <= issuedAt) throw new Error('expiresAt must be later than issuedAt');
    if (issuedAt > now + this.clockSkewMs) throw new Error('task was issued in the future');
    if (expiresAt < now - this.clockSkewMs) throw new Error('task has expired');
    if (typeof task.nonce !== 'string' || task.nonce.trim().length === 0) throw new Error('nonce must be a non-empty string');
    if (!Number.isSafeInteger(task.sequence) || task.sequence <= 0) throw new Error('sequence must be a positive safe integer');

    if (entries.some((entry) => entry.keyId === task.keyId && entry.nonce === task.nonce)) throw new Error('task nonce was already accepted');
    if (entries.some((entry) => entry.keyId === task.keyId && entry.sequence === task.sequence)) throw new Error('task sequence was already accepted');

    return {
      taskId: task.taskId,
      collectorName: task.collectorName,
      keyId: task.keyId,
      nonce: task.nonce,
      sequence: task.sequence,
      expiresAt,
    };
  }
}
