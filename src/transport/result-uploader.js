import { promisify } from 'node:util';
import { gzip, gunzip } from 'node:zlib';
import pLimit from 'p-limit';
import { encrypt } from '../security/crypto.js';

const gzipAsync = promisify(gzip);
const gunzipAsync = promisify(gunzip);

export async function compressResult(result) {
  const serialized = Buffer.from(JSON.stringify(result), 'utf8');
  const compressed = await gzipAsync(serialized);
  return {
    compressed,
    uncompressedSizeBytes: serialized.length,
    compressedSizeBytes: compressed.length,
  };
}

export async function decompressResult(compressed) {
  return JSON.parse((await gunzipAsync(compressed)).toString('utf8'));
}

export function isPermanentUploadError(error) {
  const status = Number(error?.status);
  return [400, 413, 415, 422].includes(status);
}

function isAbort(error, signal) {
  return signal?.aborted || error?.name === 'AbortError' || error?.code === 'ABORT_ERR';
}

export class ResultUploader {
  constructor({
    resultStore,
    apiClient,
    identity,
    logger,
    uploadConcurrency = 3,
    maxPayloadWarningBytes = 10 * 1024 * 1024,
    compressor = compressResult,
    encryptor = encrypt,
  }) {
    this.resultStore = resultStore;
    this.apiClient = apiClient;
    this.identity = identity;
    this.logger = logger;
    this.uploadConcurrency = uploadConcurrency;
    this.maxPayloadWarningBytes = maxPayloadWarningBytes;
    this.compressor = compressor;
    this.encryptor = encryptor;
  }

  async drain({ signal } = {}) {
    const pending = await this.resultStore.listPending();
    const limit = pLimit(this.uploadConcurrency);
    const outcomes = await Promise.all(pending.map((item) => limit(() => this.#uploadItem(item, signal))));
    return {
      attempted: outcomes.length,
      delivered: outcomes.filter((outcome) => outcome === 'delivered').length,
      requeued: outcomes.filter((outcome) => outcome === 'requeued').length,
      failedPermanent: outcomes.filter((outcome) => outcome === 'failed-permanent').length,
      interrupted: outcomes.filter((outcome) => outcome === 'interrupted').length,
    };
  }

  async #uploadItem(item, signal) {
    if (signal?.aborted) return 'interrupted';
    await this.resultStore.markInFlight(item.id);
    try {
      const sizes = await this.compressor(item.result);
      if (sizes.uncompressedSizeBytes > this.maxPayloadWarningBytes) {
        this.logger?.warn({
          queueItemId: item.id,
          uncompressedSizeBytes: sizes.uncompressedSizeBytes,
        }, 'Queued result payload is unexpectedly large; attempting upload');
      }
      const protectedPayload = this.encryptor(sizes.compressed, this.identity.encryptionKey);
      const payload = {
        schemaVersion: 1,
        queueItemId: item.id,
        agentId: this.identity.agentId,
        enqueuedAt: item.enqueuedAt,
        contentEncoding: 'gzip',
        encryption: protectedPayload.algorithm,
        iv: protectedPayload.iv,
        authTag: protectedPayload.authTag,
        ciphertext: protectedPayload.ciphertext,
        uncompressedSizeBytes: sizes.uncompressedSizeBytes,
        compressedSizeBytes: sizes.compressedSizeBytes,
      };
      const acknowledgement = await this.apiClient.uploadResult(this.identity, payload, { signal });
      if (acknowledgement?.accepted !== true) {
        throw new Error('Management server did not explicitly acknowledge the uploaded result');
      }
      if (acknowledgement.queueItemId && acknowledgement.queueItemId !== item.id) {
        throw new Error(`Management server acknowledged unexpected queue item ${acknowledgement.queueItemId}`);
      }
      await this.resultStore.markDelivered(item.id);
      this.logger?.info({
        queueItemId: item.id,
        uncompressedSizeBytes: sizes.uncompressedSizeBytes,
        compressedSizeBytes: sizes.compressedSizeBytes,
      }, 'Queued result uploaded and marked delivered');
      return 'delivered';
    } catch (error) {
      if (isAbort(error, signal)) {
        this.logger?.info({ queueItemId: item.id }, 'Result upload interrupted; in-flight item will be recovered on startup');
        return 'interrupted';
      }
      if (isPermanentUploadError(error)) {
        await this.resultStore.markFailed(item.id, error);
        this.logger?.error({ err: error, queueItemId: item.id }, 'Result upload permanently rejected');
        return 'failed-permanent';
      }
      await this.resultStore.requeue(item.id, error);
      this.logger?.warn({ err: error, queueItemId: item.id }, 'Result upload failed transiently; item returned to pending');
      return 'requeued';
    }
  }
}
