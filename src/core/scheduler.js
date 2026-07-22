const sleep = (milliseconds, signal) => new Promise((resolve) => {
  const timer = setTimeout(resolve, milliseconds);
  signal?.addEventListener('abort', () => {
    clearTimeout(timer);
    resolve();
  }, { once: true });
});

export class HeartbeatScheduler {
  #abortController;
  #loopPromise;

  constructor({ heartbeat, intervalMs, initialRetryMs, maximumRetryMs, logger }) {
    this.heartbeat = heartbeat;
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
        await this.heartbeat();
        retryDelay = this.initialRetryMs;
        await sleep(this.intervalMs, signal);
      } catch (error) {
        this.logger.warn({ err: error, retryDelayMs: retryDelay }, 'Heartbeat failed; retrying');
        await sleep(retryDelay, signal);
        retryDelay = Math.min(retryDelay * 2, this.maximumRetryMs);
      }
    }
  }
}
