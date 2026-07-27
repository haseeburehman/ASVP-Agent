const DEFAULT_MAX_EXECUTIONS = 30;
const DEFAULT_WINDOW_MS = 5 * 60 * 1000;

export class TaskRateTracker {
  constructor({ maxExecutions = DEFAULT_MAX_EXECUTIONS, windowMs = DEFAULT_WINDOW_MS, clock = Date.now } = {}) {
    if (!Number.isInteger(maxExecutions) || maxExecutions < 1) throw new Error('Task rate maxExecutions must be a positive integer');
    if (!Number.isInteger(windowMs) || windowMs < 1) throw new Error('Task rate windowMs must be a positive integer');
    this.maxExecutions = maxExecutions;
    this.windowMs = windowMs;
    this.clock = clock;
    this.executions = [];
  }

  admit(tasks) {
    const now = this.clock();
    if (!Number.isFinite(now)) throw new Error('Task rate tracker clock must return a finite timestamp');
    this.executions = this.executions.filter((timestamp) => timestamp > now - this.windowMs);
    const available = Math.max(0, this.maxExecutions - this.executions.length);
    const accepted = tasks.slice(0, available);
    const rejected = tasks.slice(available).map((task) => ({
      task,
      reasonCode: 'TASK_RATE_LIMIT_EXCEEDED',
      reason: `Cumulative task execution limit of ${this.maxExecutions} per ${this.windowMs}ms was exceeded`,
    }));
    this.executions.push(...accepted.map(() => now));
    return { accepted, rejected, maxExecutions: this.maxExecutions, windowMs: this.windowMs };
  }
}
