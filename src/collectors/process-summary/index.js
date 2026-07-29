import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import systeminformation from 'systeminformation';

const DEFAULT_MAX_ITEMS = 250;
const DEFAULT_MAX_HASHED_PROCESSES = 25;
const DEFAULT_MAX_HASH_FILE_BYTES = 200 * 1024 * 1024;

function createAbortError() { const error = new Error('Process summary collection was aborted'); error.name = 'AbortError'; error.code = 'ABORT_ERR'; return error; }
function checkAbort(signal) { if (signal?.aborted) throw createAbortError(); }
function finiteNumber(value) { const number = Number(value); return Number.isFinite(number) ? number : null; }
function availability(value, reason = null, status = value == null ? 'unavailable' : 'available') { return { status, reason: value == null ? reason : null }; }

function processItem(process) {
  const rssKiB = finiteNumber(process.memRss); const virtualKiB = finiteNumber(process.memVsz);
  const binaryPath = process.path ? String(process.path) : null;
  return {
    name: process.name ? String(process.name) : 'Unknown', pid: finiteNumber(process.pid), parentPid: finiteNumber(process.parentPid),
    user: process.user ? String(process.user) : null, startTime: process.started ? String(process.started) : null,
    cpuPercent: finiteNumber(process.cpu),
    memory: { percent: finiteNumber(process.mem), rssBytes: rssKiB === null ? null : rssKiB * 1024, virtualBytes: virtualKiB === null ? null : virtualKiB * 1024 },
    binaryPath,
    binaryPathAvailability: availability(binaryPath, 'The process provider did not expose an executable path; this is common for protected or kernel processes'),
    binarySha256: null,
    binaryHashAvailability: availability(null, 'Not selected within the bounded hashing allowance'),
    establishedConnectionCount: null,
    connectionCountAvailability: availability(null, 'Local connection inventory has not been correlated'),
  };
}
function compareProcesses(left, right) { return (left.pid ?? Number.MAX_SAFE_INTEGER) - (right.pid ?? Number.MAX_SAFE_INTEGER) || left.name.localeCompare(right.name); }
function permissionStatus(error) { return /EACCES|EPERM|permission|access denied/i.test(`${error?.code ?? ''} ${error?.message ?? ''}`) ? 'insufficient_privilege' : 'unavailable'; }

async function hashBinary(binaryPath, { signal, maxBytes = DEFAULT_MAX_HASH_FILE_BYTES } = {}) {
  checkAbort(signal);
  const metadata = await stat(binaryPath);
  if (!metadata.isFile()) { const error = new Error('Executable path is not a regular file'); error.code = 'NOT_REGULAR_FILE'; throw error; }
  if (metadata.size > maxBytes) { const error = new Error(`Executable is ${metadata.size} bytes, exceeding the ${maxBytes}-byte hashing limit`); error.code = 'HASH_SIZE_LIMIT'; throw error; }
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256'); const stream = createReadStream(binaryPath); let settled = false;
    const finish = (callback, value) => { if (settled) return; settled = true; signal?.removeEventListener('abort', abort); callback(value); };
    const abort = () => { stream.destroy(); finish(reject, createAbortError()); };
    signal?.addEventListener('abort', abort, { once: true });
    stream.on('data', (chunk) => hash.update(chunk)); stream.once('error', (error) => finish(reject, error)); stream.once('end', () => finish(resolve, hash.digest('hex')));
  });
}

export function createProcessSummaryCollector({
  processProvider = () => systeminformation.processes(),
  connectionProvider = () => systeminformation.networkConnections(),
  hashProvider = hashBinary,
} = {}) {
  return {
    name: 'process-summary', version: '1.1.0',
    async run(_params = {}, context = {}) {
      const { signal, collectorConfig = {} } = context; checkAbort(signal);
      const maxItems = Number.isInteger(collectorConfig.maxItems) && collectorConfig.maxItems > 0 ? collectorConfig.maxItems : DEFAULT_MAX_ITEMS;
      const maxHashedProcesses = Number.isInteger(collectorConfig.maxHashedProcesses) && collectorConfig.maxHashedProcesses >= 0 ? collectorConfig.maxHashedProcesses : DEFAULT_MAX_HASHED_PROCESSES;
      const maxHashFileBytes = Number.isInteger(collectorConfig.maxHashFileBytes) && collectorConfig.maxHashFileBytes > 0 ? collectorConfig.maxHashFileBytes : DEFAULT_MAX_HASH_FILE_BYTES;
      try {
        const result = await processProvider(); checkAbort(signal);
        const normalized = (Array.isArray(result?.list) ? result.list : []).map(processItem).sort(compareProcesses);
        const processes = normalized.slice(0, maxItems);
        try {
          const connections = await connectionProvider(); checkAbort(signal);
          const counts = new Map();
          for (const connection of Array.isArray(connections) ? connections : []) {
            if (String(connection.state ?? '').toLowerCase() !== 'established') continue;
            const pid = finiteNumber(connection.pid); if (pid !== null) counts.set(pid, (counts.get(pid) ?? 0) + 1);
          }
          for (const item of processes) { item.establishedConnectionCount = counts.get(item.pid) ?? 0; item.connectionCountAvailability = availability(item.establishedConnectionCount); }
        } catch (error) {
          if (error.name === 'AbortError') throw error;
          for (const item of processes) item.connectionCountAvailability = availability(null, `Unable to enumerate local connections: ${error.message}`, permissionStatus(error));
        }
        let selected = 0;
        for (const item of processes) {
          if (!item.binaryPath || selected >= maxHashedProcesses) continue;
          selected += 1;
          try { item.binarySha256 = await hashProvider(item.binaryPath, { signal, maxBytes: maxHashFileBytes }); item.binaryHashAvailability = availability(item.binarySha256); }
          catch (error) { if (error.name === 'AbortError') throw error; item.binaryHashAvailability = availability(null, error.message, permissionStatus(error)); }
        }
        return { platform: process.platform, processes, summary: { maxItems, totalDetected: normalized.length, returnedItems: processes.length, truncated: normalized.length - processes.length, maxHashedProcesses, hashAttempts: selected, maxHashFileBytes }, reason: null };
      } catch (error) {
        if (error.name === 'AbortError' || signal?.aborted) throw createAbortError();
        return { platform: process.platform, processes: null, summary: { maxItems, totalDetected: 0, returnedItems: 0, truncated: 0, maxHashedProcesses, hashAttempts: 0, maxHashFileBytes }, reason: `Unable to enumerate running processes: ${error.message}` };
      }
    },
  };
}
export const processSummaryCollector = createProcessSummaryCollector();
export default processSummaryCollector;
