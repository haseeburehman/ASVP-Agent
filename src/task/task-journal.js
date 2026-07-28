import { randomUUID } from 'node:crypto';
import { chmod, mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import path from 'node:path';

const ACTIVE_STATUSES = new Set(['accepted', 'running']);
const TERMINAL_STATUSES = new Set(['completed', 'failed', 'interrupted']);
const VALID_STATUSES = new Set([...ACTIVE_STATUSES, ...TERMINAL_STATUSES]);
const CRASH_RECOVERY_REASON = 'Interrupted during crash recovery';

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

async function atomicWriteJson(filePath, value) {
  const temporaryPath = `${filePath}.${process.pid}.${randomUUID()}.tmp`;
  let handle;
  try {
    handle = await open(temporaryPath, 'wx', 0o600);
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await rename(temporaryPath, filePath);
    await chmod(filePath, 0o600).catch((error) => {
      if (process.platform !== 'win32') throw error;
    });
    await syncDirectory(path.dirname(filePath));
  } catch (error) {
    await handle?.close().catch(() => {});
    await rm(temporaryPath, { force: true }).catch(() => {});
    throw error;
  }
}

function validateEntries(value) {
  if (!value || !Array.isArray(value.entries)) throw new Error('journal must contain an entries array');
  for (const entry of value.entries) {
    if (!entry || typeof entry.taskId !== 'string' || !entry.taskId
      || typeof entry.collectorName !== 'string' || !entry.collectorName
      || typeof entry.acceptedAt !== 'string' || !VALID_STATUSES.has(entry.status)) {
      throw new Error('journal contains an invalid task entry');
    }
  }
  return value.entries;
}

export class TaskJournal {
  constructor({
    path: journalPath,
    cwd = process.cwd(),
    logger,
    clock = () => new Date(),
    maxEntries = 10_000,
    maxAgeMs = 30 * 24 * 60 * 60 * 1000,
  }) {
    if (!journalPath) throw new Error('TaskJournal requires a path');
    if (!Number.isInteger(maxEntries) || maxEntries < 1) throw new Error('TaskJournal maxEntries must be a positive integer');
    if (!Number.isFinite(maxAgeMs) || maxAgeMs < 0) throw new Error('TaskJournal maxAgeMs must be non-negative');
    this.path = path.resolve(cwd, journalPath);
    this.logger = logger;
    this.clock = clock;
    this.maxEntries = maxEntries;
    this.maxAgeMs = maxAgeMs;
    this.entries = [];
    this.initialized = false;
    this.operationChain = Promise.resolve();
  }

  initialize({ resultQueueItems = [] } = {}) {
    return this.#serialize(async () => {
      await mkdir(path.dirname(this.path), { recursive: true, mode: 0o700 });
      await chmod(path.dirname(this.path), 0o700).catch((error) => {
        if (process.platform !== 'win32') throw error;
      });
      try {
        this.entries = validateEntries(JSON.parse(await readFile(this.path, 'utf8')));
      } catch (error) {
        if (error.code !== 'ENOENT') {
          throw new Error(`Unable to read task journal ${this.path}: ${error.message}`, { cause: error });
        }
        this.entries = [];
      }

      const resultsByTaskId = new Map();
      for (const item of resultQueueItems) {
        if (typeof item?.taskId !== 'string' || resultsByTaskId.has(item.taskId)) continue;
        resultsByTaskId.set(item.taskId, item);
      }
      const abandoned = this.entries.filter((entry) => ACTIVE_STATUSES.has(entry.status)).map((entry) => {
        const queueItem = resultsByTaskId.get(entry.taskId);
        const reconciledStatus = queueItem
          ? queueItem.resultStatus === 'success' ? 'completed' : 'failed'
          : 'interrupted';
        return {
          ...entry,
          reconciledStatus,
          resultQueueItemId: queueItem?.id ?? null,
          resultQueueState: queueItem?.state ?? null,
        };
      });
      const recoveredAt = this.#timestamp();
      if (abandoned.length > 0) {
        const recoveryByTaskId = new Map(abandoned.map((entry) => [entry.taskId, entry]));
        this.entries = this.entries.map((entry) => {
          const recovery = recoveryByTaskId.get(entry.taskId);
          if (!recovery) return entry;
          return {
            ...entry,
            status: recovery.reconciledStatus,
            finishedAt: recoveredAt,
            reason: recovery.resultQueueItemId
              ? `Reconciled with durable result queue item ${recovery.resultQueueItemId} during crash recovery`
              : CRASH_RECOVERY_REASON,
          };
        });
      }
      const pruned = this.#prune();
      if (abandoned.length > 0 || pruned || !(await this.#exists())) await this.#persist();
      this.initialized = true;
      return abandoned;
    }, false);
  }

  listEntries() {
    return this.#serialize(async () => this.entries.map((entry) => ({ ...entry })));
  }

  accept(task) {
    return this.#serialize(async () => {
      if (!task || typeof task.taskId !== 'string' || !task.taskId
        || typeof task.collectorName !== 'string' || !task.collectorName) {
        throw new Error('TaskJournal accept requires taskId and collectorName');
      }
      if (this.entries.some((entry) => entry.taskId === task.taskId)) {
        throw new Error(`Task journal entry already exists: ${task.taskId}`);
      }
      const entry = {
        taskId: task.taskId,
        collectorName: task.collectorName,
        acceptedAt: this.#timestamp(),
        status: 'accepted',
      };
      this.entries.push(entry);
      this.#prune();
      await this.#persist();
      return { ...entry };
    });
  }

  markRunning(taskId) {
    return this.#transition(taskId, 'running');
  }

  markTerminal(taskId, status, reason) {
    if (!TERMINAL_STATUSES.has(status)) {
      return Promise.reject(new Error(`Invalid terminal task status: ${status}`));
    }
    return this.#transition(taskId, status, reason);
  }

  #transition(taskId, status, reason) {
    return this.#serialize(async () => {
      const index = this.entries.findIndex((entry) => entry.taskId === taskId);
      if (index < 0) throw new Error(`Task journal entry not found: ${taskId}`);
      const current = this.entries[index];
      if (status === 'running' && current.status !== 'accepted') {
        throw new Error(`Cannot mark task ${taskId} running from status ${current.status}`);
      }
      if (TERMINAL_STATUSES.has(status) && !ACTIVE_STATUSES.has(current.status)) {
        throw new Error(`Cannot mark task ${taskId} terminal from status ${current.status}`);
      }
      const timestamp = this.#timestamp();
      const updated = status === 'running'
        ? { ...current, status, startedAt: timestamp }
        : { ...current, status, finishedAt: timestamp, ...(reason === undefined ? {} : { reason: String(reason) }) };
      this.entries[index] = updated;
      this.#prune();
      await this.#persist();
      return { ...updated };
    });
  }

  #prune() {
    const now = this.clock().getTime();
    const before = this.entries.length;
    this.entries = this.entries.filter((entry) => !TERMINAL_STATUSES.has(entry.status)
      || now - new Date(entry.finishedAt ?? entry.acceptedAt).getTime() <= this.maxAgeMs);

    const activeCount = this.entries.filter((entry) => ACTIVE_STATUSES.has(entry.status)).length;
    const terminalLimit = Math.max(0, this.maxEntries - activeCount);
    const terminals = this.entries
      .map((entry, index) => ({ entry, index }))
      .filter(({ entry }) => TERMINAL_STATUSES.has(entry.status))
      .sort((left, right) => {
        const time = new Date(left.entry.finishedAt ?? left.entry.acceptedAt).getTime()
          - new Date(right.entry.finishedAt ?? right.entry.acceptedAt).getTime();
        return time || left.index - right.index;
      });
    const evict = new Set(terminals.slice(0, Math.max(0, terminals.length - terminalLimit)).map(({ entry }) => entry));
    this.entries = this.entries.filter((entry) => !evict.has(entry));
    if (this.entries.length !== before) {
      this.logger?.debug?.({ removed: before - this.entries.length }, 'Pruned task journal entries');
      return true;
    }
    return false;
  }

  async #persist() {
    await atomicWriteJson(this.path, { entries: this.entries });
  }

  async #exists() {
    try {
      const handle = await open(this.path, 'r');
      await handle.close();
      return true;
    } catch (error) {
      if (error.code === 'ENOENT') return false;
      throw error;
    }
  }

  #timestamp() {
    const value = this.clock();
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) throw new Error('TaskJournal clock must return a valid Date');
    return value.toISOString();
  }

  #serialize(operation, requireInitialized = true) {
    const execute = async () => {
      if (requireInitialized && !this.initialized) throw new Error('TaskJournal must be initialized before use');
      return operation();
    };
    const current = this.operationChain.then(execute, execute);
    this.operationChain = current.catch(() => {});
    return current;
  }
}
