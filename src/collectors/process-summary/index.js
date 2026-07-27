import systeminformation from 'systeminformation';

const DEFAULT_MAX_ITEMS = 250;

function createAbortError() {
  const error = new Error('Process summary collection was aborted');
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

function checkAbort(signal) {
  if (signal?.aborted) throw createAbortError();
}

function finiteNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function processItem(process) {
  const rssKiB = finiteNumber(process.memRss);
  const virtualKiB = finiteNumber(process.memVsz);
  return {
    name: process.name ? String(process.name) : 'Unknown',
    pid: finiteNumber(process.pid),
    parentPid: finiteNumber(process.parentPid),
    user: process.user ? String(process.user) : null,
    startTime: process.started ? String(process.started) : null,
    cpuPercent: finiteNumber(process.cpu),
    memory: {
      percent: finiteNumber(process.mem),
      rssBytes: rssKiB === null ? null : rssKiB * 1024,
      virtualBytes: virtualKiB === null ? null : virtualKiB * 1024,
    },
  };
}

function compareProcesses(left, right) {
  const leftPid = left.pid ?? Number.MAX_SAFE_INTEGER;
  const rightPid = right.pid ?? Number.MAX_SAFE_INTEGER;
  return leftPid - rightPid || left.name.localeCompare(right.name);
}

export function createProcessSummaryCollector({
  processProvider = () => systeminformation.processes(),
} = {}) {
  return {
    name: 'process-summary',
    version: '1.0.0',
    async run(_params = {}, context = {}) {
      const { signal, collectorConfig = {} } = context;
      checkAbort(signal);
      const configuredMax = collectorConfig.maxItems;
      const maxItems = Number.isInteger(configuredMax) && configuredMax > 0
        ? configuredMax
        : DEFAULT_MAX_ITEMS;

      try {
        const result = await processProvider();
        checkAbort(signal);
        const sourceProcesses = Array.isArray(result?.list) ? result.list : [];
        const normalized = [];
        for (const process of sourceProcesses) {
          checkAbort(signal);
          normalized.push(processItem(process));
        }
        normalized.sort(compareProcesses);
        const processes = normalized.slice(0, maxItems);

        return {
          platform: process.platform,
          processes,
          summary: {
            maxItems,
            totalDetected: normalized.length,
            returnedItems: processes.length,
            truncated: normalized.length - processes.length,
          },
          reason: null,
        };
      } catch (error) {
        if (error.name === 'AbortError' || signal?.aborted) throw createAbortError();
        return {
          platform: process.platform,
          processes: null,
          summary: {
            maxItems,
            totalDetected: 0,
            returnedItems: 0,
            truncated: 0,
          },
          reason: `Unable to enumerate running processes: ${error.message}`,
        };
      }
    },
  };
}

export const processSummaryCollector = createProcessSummaryCollector();
export default processSummaryCollector;
