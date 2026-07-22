const sleep = (milliseconds, signal) => new Promise((resolve) => {
  const timer = setTimeout(resolve, milliseconds);
  signal?.addEventListener('abort', () => {
    clearTimeout(timer);
    resolve();
  }, { once: true });
});

export class RetryScheduler {
  #abortController;
  #loopPromise;

  constructor({ operation, operationName, intervalMs, initialRetryMs, maximumRetryMs, logger }) {
    this.operation = operation;
    this.operationName = operationName;
    this.intervalMs = intervalMs;
    this.initialRetryMs = initialRetryMs;
    this.maximumRetryMs = maximumRetryMs;
    this.logger = logger;
  }

  start() {
    if (this.#loopPromise) return;
    this.#abortController = new AbortController();
    this.#loopPromise = this.#run(this.#abortController.signal);
  }

  async stop() {
    this.#abortController?.abort();
    await this.#loopPromise;
    this.#loopPromise = undefined;
  }

  async #run(signal) {
    let retryDelay = this.initialRetryMs;
    while (!signal.aborted) {
      try {
        await this.operation();
        retryDelay = this.initialRetryMs;
        await sleep(this.intervalMs, signal);
      } catch (error) {
        this.logger.warn(
          { err: error, operation: this.operationName, retryDelayMs: retryDelay },
          `${this.operationName} failed; retrying`,
        );
        await sleep(retryDelay, signal);
        retryDelay = Math.min(retryDelay * 2, this.maximumRetryMs);
      }
    }
  }
}

export class HeartbeatScheduler extends RetryScheduler {
  constructor({ heartbeat, ...options }) {
    super({ operation: heartbeat, operationName: 'Heartbeat', ...options });
  }
}

export class TaskPollScheduler extends RetryScheduler {
  constructor({ pollTasks, ...options }) {
    super({ operation: pollTasks, operationName: 'Task poll', ...options });
  }
}
