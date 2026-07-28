import pLimit from 'p-limit';
import { createFailureResult, executeCollector } from './collector.js';

export class TaskRunner {
  constructor({ registry, logger, onResult, collectorConfig = {}, taskJournal }) {
    this.registry = registry;
    this.logger = logger;
    this.onResult = onResult ?? (async (result) => logger.info({ result }, 'Collector result ready'));
    this.collectorConfig = collectorConfig;
    this.taskJournal = taskJournal;
    this.limiters = new Map();
  }

  async run(task, { signal, journaled = false } = {}) {
    const collectorName = task?.collectorName ?? 'unknown';
    let result;
    try {
      const definition = this.registry.getDefinition(collectorName);
      if (!definition?.implemented) await this.registry.get(collectorName);
      const limiter = this.#getLimiter(collectorName, definition);
      result = await limiter(async () => {
        if (journaled) await this.taskJournal.markRunning(task.taskId);
        return this.#execute(task, definition, signal);
      });
    } catch (error) {
      result = { taskId: task?.taskId ?? null, ...createFailureResult(collectorName, error) };
    }
    await this.#handoff(result);
    if (journaled) {
      const interrupted = signal?.aborted;
      await this.taskJournal.markTerminal(
        task.taskId,
        interrupted ? 'interrupted' : result.status === 'success' ? 'completed' : 'failed',
        interrupted ? 'Interrupted by agent shutdown' : result.error?.message,
      );
    }
    return result;
  }

  async runAll(tasks, { signal } = {}) {
    if (this.taskJournal) await Promise.all(tasks.map((task) => this.taskJournal.accept(task)));
    return Promise.all(tasks.map((task) => this.run(task, { signal, journaled: Boolean(this.taskJournal) })));
  }

  async #execute(task, definition, signal) {
    const collector = await this.registry.get(task.collectorName);
    const options = this.collectorConfig[task.collectorName] ?? {};
    const result = {
      taskId: task.taskId,
      ...await executeCollector({
        collector,
        params: task.params,
        context: {
          taskId: task.taskId,
          scheduledAt: task.scheduledAt,
          collectorConfig: options,
        },
        timeoutMs: options.timeoutMs ?? definition.timeoutMs ?? 30000,
        signal,
      }),
    };
    return result;
  }

  #getLimiter(name, definition) {
    if (!this.limiters.has(name)) {
      const options = this.collectorConfig[name] ?? {};
      this.limiters.set(name, pLimit(options.concurrency ?? definition.concurrency ?? 1));
    }
    return this.limiters.get(name);
  }

  async #handoff(result) {
    await this.onResult(result);
  }
}
