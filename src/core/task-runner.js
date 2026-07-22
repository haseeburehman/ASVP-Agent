import pLimit from 'p-limit';
import { createFailureResult, executeCollector } from './collector.js';

export class TaskRunner {
  constructor({ registry, logger, onResult, collectorConfig = {} }) {
    this.registry = registry;
    this.logger = logger;
    this.onResult = onResult ?? (async (result) => logger.info({ result }, 'Collector result ready'));
    this.collectorConfig = collectorConfig;
    this.limiters = new Map();
  }

  async run(task) {
    const collectorName = task?.collectorName ?? 'unknown';
    let definition;
    try {
      definition = this.registry.getDefinition(collectorName);
      if (!definition?.implemented) await this.registry.get(collectorName);
      const limiter = this.#getLimiter(collectorName, definition);
      return await limiter(() => this.#execute(task, definition));
    } catch (error) {
      const result = { taskId: task?.taskId ?? null, ...createFailureResult(collectorName, error) };
      await this.#handoff(result);
      return result;
    }
  }

  async runAll(tasks) {
    return Promise.all(tasks.map((task) => this.run(task)));
  }

  async #execute(task, definition) {
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
      }),
    };
    await this.#handoff(result);
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
