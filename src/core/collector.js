export class CollectorTimeoutError extends Error {
  constructor(collectorName, timeoutMs) {
    super(`Collector "${collectorName}" exceeded its ${timeoutMs}ms timeout`);
    this.name = 'CollectorTimeoutError';
    this.code = 'COLLECTOR_TIMEOUT';
  }
}

export function validateCollector(collector) {
  if (!collector || typeof collector !== 'object') throw new TypeError('Collector module must export an object');
  if (typeof collector.name !== 'string' || !collector.name) throw new TypeError('Collector must define a name');
  if (typeof collector.version !== 'string' || !collector.version) throw new TypeError(`Collector "${collector.name}" must define a version`);
  if (typeof collector.run !== 'function') throw new TypeError(`Collector "${collector.name}" must define run(params, context)`);
  return collector;
}

function serializeError(error) {
  return {
    name: error.name ?? 'Error',
    code: error.code ?? null,
    message: error.message ?? String(error),
  };
}

export async function executeCollector({ collector, params = {}, context = {}, timeoutMs, signal }) {
  validateCollector(collector);
  const startedAt = new Date().toISOString();
  const abortController = new AbortController();
  let rejectAbort;
  const aborted = new Promise((_, reject) => { rejectAbort = reject; });
  const externalAbortHandler = () => {
    abortController.abort(signal?.reason);
    const error = signal?.reason instanceof Error ? signal.reason : new Error('Collector execution was aborted');
    error.code ??= 'ABORT_ERR';
    rejectAbort(error);
  };
  let timer;

  if (signal?.aborted) externalAbortHandler();
  else signal?.addEventListener('abort', externalAbortHandler, { once: true });

  try {
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => {
        abortController.abort();
        reject(new CollectorTimeoutError(collector.name, timeoutMs));
      }, timeoutMs);
    });
    const data = await Promise.race([
      Promise.resolve().then(() => collector.run(params, { ...context, signal: abortController.signal })),
      timeout,
      aborted,
    ]);
    return {
      collector: collector.name,
      startedAt,
      finishedAt: new Date().toISOString(),
      status: 'success',
      data: data ?? null,
      error: null,
    };
  } catch (error) {
    return {
      collector: collector.name,
      startedAt,
      finishedAt: new Date().toISOString(),
      status: error instanceof CollectorTimeoutError ? 'timeout' : 'failed',
      data: null,
      error: serializeError(error),
    };
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', externalAbortHandler);
  }
}

export function createFailureResult(collectorName, error) {
  const timestamp = new Date().toISOString();
  return {
    collector: collectorName,
    startedAt: timestamp,
    finishedAt: timestamp,
    status: 'failed',
    data: null,
    error: serializeError(error),
  };
}
