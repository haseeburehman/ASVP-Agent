import { randomUUID } from 'node:crypto';
import {
  chmod,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
  stat,
} from 'node:fs/promises';
import path from 'node:path';
import { decrypt, encrypt } from '../security/crypto.js';

const METRICS_FILE = '_metrics.json';
const ITEM_SUFFIX = '.json';
const VALID_STATES = new Set(['pending', 'in-flight', 'delivered', 'failed-permanent']);
const ENCRYPTED_ITEM_VERSION = 1;

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

async function atomicWriteEncryptedItem(filePath, item, encryptionKey) {
  const protectedPayload = encrypt(Buffer.from(JSON.stringify(item), 'utf8'), encryptionKey);
  await atomicWriteJson(filePath, {
    version: ENCRYPTED_ITEM_VERSION,
    algorithm: protectedPayload.algorithm,
    iv: protectedPayload.iv,
    authTag: protectedPayload.authTag,
    ciphertext: protectedPayload.ciphertext,
  });
}

function decryptItem(value, encryptionKey) {
  if (value?.version !== ENCRYPTED_ITEM_VERSION || value?.algorithm !== 'aes-256-gcm') return null;
  return JSON.parse(decrypt(value.ciphertext, encryptionKey, value.iv, value.authTag).toString('utf8'));
}

function normalizeError(error) {
  if (error == null) return null;
  if (typeof error === 'string') return error;
  return error.message ?? String(error);
}

export class ResultStore {
  constructor({
    queueDir,
    maxQueueSizeBytes,
    maxQueueItems,
    maxItemAgeMs,
    logger,
    encryptionKey,
    cwd = process.cwd(),
    now = () => new Date(),
  }) {
    this.queueDir = path.resolve(cwd, queueDir);
    this.maxQueueSizeBytes = maxQueueSizeBytes;
    this.maxQueueItems = maxQueueItems;
    this.maxItemAgeMs = maxItemAgeMs;
    this.logger = logger;
    this.encryptionKey = encryptionKey;
    this.now = now;
    this.operationChain = Promise.resolve();
    this.initialized = false;
  }

  setEncryptionKey(encryptionKey) {
    if (this.initialized) throw new Error('ResultStore encryption key cannot be changed after initialization');
    this.encryptionKey = encryptionKey;
    return this;
  }

  async initialize() {
    return this.#serialize(async () => {
      if (!this.encryptionKey) throw new Error('ResultStore requires the registered agent encryptionKey');
      await mkdir(this.queueDir, { recursive: true, mode: 0o700 });
      await chmod(this.queueDir, 0o700).catch((error) => {
        if (process.platform !== 'win32') throw error;
      });
      const probePath = path.join(this.queueDir, `.write-probe.${process.pid}.${randomUUID()}`);
      try {
        const probe = await open(probePath, 'wx', 0o600);
        await probe.writeFile('queue-write-probe', 'utf8');
        await probe.sync();
        await probe.close();
        await rm(probePath);
      } catch (error) {
        await rm(probePath, { force: true }).catch(() => {});
        throw new Error(`Result queue directory is not writable: ${this.queueDir}: ${error.message}`, { cause: error });
      }
      await this.#migratePlaintextItems();
      this.initialized = true;
      await this.#readMetrics();
      return this;
    }, false);
  }

  enqueue(result) {
    return this.#serialize(async () => {
      const timestamp = this.now().toISOString();
      const item = {
        id: randomUUID(),
        result,
        enqueuedAt: timestamp,
        state: 'pending',
        attemptCount: 0,
        lastAttemptAt: null,
        lastError: null,
      };
      await atomicWriteEncryptedItem(this.#itemPath(item.id), item, this.encryptionKey);
      const eviction = await this.#enforceLimits();
      return {
        ...item,
        retained: !eviction.evictedIds.includes(item.id),
        evictedDuringEnqueue: eviction.evictedIds,
      };
    });
  }

  listPending() {
    return this.#serialize(async () => {
      const items = await this.#readItems();
      return items
        .filter((item) => item.state === 'pending')
        .sort((left, right) => left.enqueuedAt.localeCompare(right.enqueuedAt));
    });
  }

  listForStartupReconciliation() {
    return this.#serialize(async () => (await this.#readItems())
      .filter((item) => typeof item.result?.taskId === 'string' && item.result.taskId)
      .map((item) => ({
        id: item.id,
        state: item.state,
        enqueuedAt: item.enqueuedAt,
        taskId: item.result.taskId,
        collectorName: item.result.collector,
        resultStatus: item.result.status,
      })));
  }

  markInFlight(id) {
    return this.#update(id, (item) => ({
      ...item,
      state: 'in-flight',
      attemptCount: item.attemptCount + 1,
      lastAttemptAt: this.now().toISOString(),
      lastError: null,
    }));
  }

  markDelivered(id) {
    return this.#update(id, (item) => ({ ...item, state: 'delivered', lastError: null }));
  }

  markFailed(id, error) {
    return this.#update(id, (item) => ({
      ...item,
      state: 'failed-permanent',
      lastError: normalizeError(error),
    }));
  }

  requeue(id, error) {
    return this.#update(id, (item) => ({
      ...item,
      state: 'pending',
      lastError: normalizeError(error),
    }));
  }

  requeueStaleInFlight() {
    return this.#serialize(async () => {
      const items = await this.#readItems();
      let recoveredCount = 0;
      for (const item of items) {
        if (item.state !== 'in-flight') continue;
        await atomicWriteEncryptedItem(this.#itemPath(item.id), {
          ...item,
          state: 'pending',
          lastError: 'Recovered an in-flight queue item after process restart',
        }, this.encryptionKey);
        recoveredCount += 1;
      }
      await this.#enforceLimits();
      return recoveredCount;
    });
  }

  getStats() {
    return this.#serialize(async () => {
      const items = await this.#readItemsWithSizes();
      const metrics = await this.#readMetrics();
      const failedPermanent = items.filter(({ item }) => item.state === 'failed-permanent');
      const failedPermanentRetainUntil = failedPermanent.length > 0
        ? new Date(Math.min(...failedPermanent.map(({ item }) => new Date(item.enqueuedAt).getTime() + this.maxItemAgeMs))).toISOString()
        : null;
      return {
        pendingCount: items.filter(({ item }) => item.state === 'pending').length,
        inFlightCount: items.filter(({ item }) => item.state === 'in-flight').length,
        deliveredCount: items.filter(({ item }) => item.state === 'delivered').length,
        failedPermanentCount: failedPermanent.length,
        failedPermanentRetainUntil,
        totalItems: items.length,
        totalBytes: items.reduce((total, entry) => total + entry.size, 0),
        evictedCount: metrics.evictedCount,
        lastEvictedAt: metrics.lastEvictedAt,
      };
    });
  }

  #update(id, transform) {
    return this.#serialize(async () => {
      const item = await this.#readItem(id);
      const updated = transform(item);
      if (!VALID_STATES.has(updated.state)) throw new Error(`Invalid queue delivery state: ${updated.state}`);
      await atomicWriteEncryptedItem(this.#itemPath(id), updated, this.encryptionKey);
      return updated;
    });
  }

  async #enforceLimits() {
    const entries = await this.#readItemsWithSizes();
    const now = this.now().getTime();
    const stale = entries.filter(({ item }) => now - new Date(item.enqueuedAt).getTime() > this.maxItemAgeMs);
    const evictedIds = [];
    const remaining = new Map(entries.map((entry) => [entry.item.id, entry]));

    for (const entry of stale.sort((left, right) => left.item.enqueuedAt.localeCompare(right.item.enqueuedAt))) {
      await this.#evict(entry, 'max-item-age');
      evictedIds.push(entry.item.id);
      remaining.delete(entry.item.id);
    }

    const oldestFirst = () => [...remaining.values()]
      .sort((left, right) => left.item.enqueuedAt.localeCompare(right.item.enqueuedAt));
    while (remaining.size > this.maxQueueItems) {
      const entry = oldestFirst()[0];
      await this.#evict(entry, 'max-queue-items');
      evictedIds.push(entry.item.id);
      remaining.delete(entry.item.id);
    }
    let totalBytes = [...remaining.values()].reduce((total, entry) => total + entry.size, 0);
    while (totalBytes > this.maxQueueSizeBytes && remaining.size > 0) {
      const entry = oldestFirst()[0];
      await this.#evict(entry, 'max-queue-size');
      evictedIds.push(entry.item.id);
      remaining.delete(entry.item.id);
      totalBytes -= entry.size;
    }

    if (evictedIds.length > 0) {
      const metrics = await this.#readMetrics();
      const updated = {
        evictedCount: metrics.evictedCount + evictedIds.length,
        lastEvictedAt: this.now().toISOString(),
      };
      await atomicWriteJson(path.join(this.queueDir, METRICS_FILE), updated);
    }
    return { evictedIds };
  }

  async #evict(entry, reason) {
    await rm(this.#itemPath(entry.item.id), { force: true });
    this.logger?.warn({
      queueItemId: entry.item.id,
      enqueuedAt: entry.item.enqueuedAt,
      reason,
    }, 'Evicted result queue item');
  }

  async #readMetrics() {
    const metricsPath = path.join(this.queueDir, METRICS_FILE);
    try {
      const value = JSON.parse(await readFile(metricsPath, 'utf8'));
      return {
        evictedCount: Number(value.evictedCount) || 0,
        lastEvictedAt: value.lastEvictedAt ?? null,
      };
    } catch (error) {
      if (error.code !== 'ENOENT') throw new Error(`Unable to read result queue metrics: ${error.message}`, { cause: error });
      return { evictedCount: 0, lastEvictedAt: null };
    }
  }

  async #readItems() {
    return (await this.#readItemsWithSizes()).map(({ item }) => item);
  }

  async #readItemsWithSizes() {
    const names = await readdir(this.queueDir);
    const itemNames = names.filter((name) => name.endsWith(ITEM_SUFFIX) && name !== METRICS_FILE);
    const entries = [];
    for (const name of itemNames) {
      const filePath = path.join(this.queueDir, name);
      try {
        const [content, details] = await Promise.all([readFile(filePath, 'utf8'), stat(filePath)]);
        const item = decryptItem(JSON.parse(content), this.encryptionKey);
        if (!item) throw new Error('queue item is not encrypted');
        if (!item.id || !VALID_STATES.has(item.state)) throw new Error('missing id or invalid state');
        entries.push({ item, size: details.size });
      } catch (error) {
        throw new Error(`Unable to read result queue item ${filePath}: ${error.message}`, { cause: error });
      }
    }
    return entries;
  }

  async #readItem(id) {
    try {
      const item = decryptItem(JSON.parse(await readFile(this.#itemPath(id), 'utf8')), this.encryptionKey);
      if (!item) throw new Error('queue item is not encrypted');
      if (!VALID_STATES.has(item.state)) throw new Error(`invalid state ${item.state}`);
      return item;
    } catch (error) {
      if (error.code === 'ENOENT') throw new Error(`Result queue item not found: ${id}`, { cause: error });
      throw new Error(`Unable to read result queue item ${id}: ${error.message}`, { cause: error });
    }
  }

  async #migratePlaintextItems() {
    const names = (await readdir(this.queueDir)).filter((name) => name.endsWith(ITEM_SUFFIX) && name !== METRICS_FILE);
    for (const name of names) {
      const filePath = path.join(this.queueDir, name);
      const value = JSON.parse(await readFile(filePath, 'utf8'));
      if (value?.version === ENCRYPTED_ITEM_VERSION && value?.algorithm === 'aes-256-gcm') {
        decryptItem(value, this.encryptionKey);
        continue;
      }
      if (!value?.id || !VALID_STATES.has(value.state)) throw new Error(`Unable to migrate invalid result queue item ${filePath}`);
      await atomicWriteEncryptedItem(filePath, value, this.encryptionKey);
    }
  }

  #itemPath(id) {
    return path.join(this.queueDir, `${id}${ITEM_SUFFIX}`);
  }

  #serialize(operation, requireInitialized = true) {
    const execute = async () => {
      if (requireInitialized && !this.initialized) throw new Error('ResultStore must be initialized before use');
      return operation();
    };
    const current = this.operationChain.then(execute, execute);
    this.operationChain = current.catch(() => {});
    return current;
  }
}
