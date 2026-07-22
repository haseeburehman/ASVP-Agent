import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { CollectorRegistry } from '../core/collector-registry.js';
import { HeartbeatScheduler, TaskPollScheduler } from '../core/scheduler.js';
import { TaskRunner } from '../core/task-runner.js';

async function writeStatus(statusPath, status) {
  await mkdir(path.dirname(statusPath), { recursive: true, mode: 0o700 });
  const temporaryPath = `${statusPath}.${process.pid}.tmp`;
  await writeFile(temporaryPath, `${JSON.stringify(status, null, 2)}\n`, { mode: 0o600 });
  await rename(temporaryPath, statusPath);
}

export async function readStatus(statusPath) {
  try {
    return JSON.parse(await readFile(statusPath, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

export class AgentRuntime {
  constructor({
    config,
    identity,
    apiClient,
    logger,
    version,
    registry,
    taskRunner,
    onResult,
    cwd = process.cwd(),
  }) {
    this.config = config;
    this.identity = identity;
    this.apiClient = apiClient;
    this.logger = logger;
    this.version = version;
    this.startedAt = Date.now();
    this.statusPath = path.resolve(cwd, config.storage.statusPath);
    this.persistChain = Promise.resolve();
    this.registry = registry ?? new CollectorRegistry();
    this.taskRunner = taskRunner ?? new TaskRunner({
      registry: this.registry,
      logger,
      collectorConfig: config.collectors,
      onResult: onResult ?? ((result) => this.#handleResult(result)),
    });
    this.health = {
      state: 'starting',
      agentId: identity.agentId,
      lastHeartbeatAt: null,
      lastHeartbeatError: null,
      lastPollAt: null,
      lastPollError: null,
      lastTaskResult: null,
    };
  }

  async start() {
    this.health.state = 'running';
    await this.#persistHealth();
    const schedulerOptions = {
      initialRetryMs: this.config.retry.initialDelayMs,
      maximumRetryMs: this.config.retry.maximumDelayMs,
      logger: this.logger,
    };
    this.heartbeatScheduler = new HeartbeatScheduler({
      heartbeat: () => this.#heartbeat(),
      intervalMs: this.config.agent.heartbeatIntervalMs,
      ...schedulerOptions,
    });
    this.taskPollScheduler = new TaskPollScheduler({
      pollTasks: () => this.#pollTasks(),
      intervalMs: this.config.agent.pollIntervalMs,
      ...schedulerOptions,
    });
    this.heartbeatScheduler.start();
    this.taskPollScheduler.start();
    this.logger.info({ agentId: this.identity.agentId }, 'Agent runtime started');
  }

  async stop() {
    this.health.state = 'stopping';
    await Promise.all([
      this.heartbeatScheduler?.stop(),
      this.taskPollScheduler?.stop(),
    ]);
    this.health.state = 'stopped';
    await this.#persistHealth();
    this.logger.info('Agent runtime stopped');
  }

  getHealth() {
    return structuredClone(this.health);
  }

  async #heartbeat() {
    const payload = {
      agentId: this.identity.agentId,
      uptimeSeconds: Math.floor((Date.now() - this.startedAt) / 1000),
      processUptimeSeconds: Math.floor(process.uptime()),
      hostname: os.hostname(),
      lastSuccessfulHeartbeat: this.health.lastHeartbeatAt,
      currentQueueSize: 0,
      agentVersion: this.version,
    };
    try {
      await this.apiClient.sendHeartbeat(this.identity, payload);
      this.health.lastHeartbeatAt = new Date().toISOString();
      this.health.lastHeartbeatError = null;
      await this.#persistHealth();
      this.logger.debug({ heartbeat: payload }, 'Heartbeat accepted');
    } catch (error) {
      this.health.lastHeartbeatError = error.message;
      await this.#persistHealth();
      throw error;
    }
  }

  async #pollTasks() {
    try {
      const tasks = await this.apiClient.pollTasks(this.identity);
      this.health.lastPollAt = new Date().toISOString();
      this.health.lastPollError = null;
      await this.#persistHealth();
      if (tasks.length > 0) {
        this.logger.info({ taskCount: tasks.length }, 'Received collector tasks');
        await this.taskRunner.runAll(tasks);
      }
    } catch (error) {
      this.health.lastPollError = error.message;
      await this.#persistHealth();
      throw error;
    }
  }

  async #handleResult(result) {
    this.health.lastTaskResult = {
      taskId: result.taskId,
      collector: result.collector,
      status: result.status,
      finishedAt: result.finishedAt,
    };
    await this.#persistHealth();
    this.logger.info({ result }, 'Collector result ready');
  }

  #persistHealth() {
    const snapshot = {
      ...structuredClone(this.health),
      updatedAt: new Date().toISOString(),
      agentVersion: this.version,
    };
    this.persistChain = this.persistChain.then(() => writeStatus(this.statusPath, snapshot));
    return this.persistChain;
  }
}
