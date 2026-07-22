import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { CollectorRegistry } from '../core/collector-registry.js';
import { HeartbeatScheduler, TaskPollScheduler, UploadScheduler } from '../core/scheduler.js';
import { TaskRunner } from '../core/task-runner.js';
import { ResultUploader } from '../transport/result-uploader.js';

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
    resultStore,
    resultUploader,
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
    this.resultStore = resultStore;
    this.externalOnResult = onResult;
    this.registry = registry ?? new CollectorRegistry();
    const uploadConfig = config.collectors.upload;
    this.resultUploader = resultUploader ?? new ResultUploader({
      resultStore,
      apiClient,
      identity,
      logger,
      uploadConcurrency: uploadConfig.uploadConcurrency,
      maxPayloadWarningBytes: uploadConfig.maxPayloadWarningBytes,
    });
    this.taskRunner = taskRunner ?? new TaskRunner({
      registry: this.registry,
      logger,
      collectorConfig: config.collectors,
      onResult: (result) => this.#handleResult(result),
    });
    this.health = {
      state: 'starting',
      agentId: identity.agentId,
      lastHeartbeatAt: null,
      lastHeartbeatError: null,
      lastPollAt: null,
      lastPollError: null,
      lastTaskResult: null,
      queueDepth: 0,
      queueEvictedCount: 0,
      queueLastEvictedAt: null,
    };
  }

  async start() {
    this.health.state = 'running';
    await this.#refreshQueueHealth();
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
    this.uploadScheduler = new UploadScheduler({
      uploadResults: (signal) => this.#uploadResults(signal),
      intervalMs: this.config.collectors.upload.intervalMs,
      ...schedulerOptions,
    });
    this.heartbeatScheduler.start();
    this.taskPollScheduler.start();
    this.uploadScheduler.start();
    this.logger.info({ agentId: this.identity.agentId }, 'Agent runtime started');
  }

  async stop() {
    this.health.state = 'stopping';
    await Promise.all([
      this.heartbeatScheduler?.stop(),
      this.taskPollScheduler?.stop(),
      this.uploadScheduler?.stop(),
    ]);
    this.health.state = 'stopped';
    await this.#persistHealth();
    this.logger.info('Agent runtime stopped');
  }

  getHealth() {
    return structuredClone(this.health);
  }

  async #heartbeat() {
    await this.#refreshQueueHealth();
    const payload = {
      agentId: this.identity.agentId,
      uptimeSeconds: Math.floor((Date.now() - this.startedAt) / 1000),
      processUptimeSeconds: Math.floor(process.uptime()),
      hostname: os.hostname(),
      lastSuccessfulHeartbeat: this.health.lastHeartbeatAt,
      currentQueueSize: this.health.queueDepth,
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

  async #uploadResults(signal) {
    const summary = await this.resultUploader.drain({ signal });
    await this.#refreshQueueHealth();
    await this.#persistHealth();
    if (summary.attempted > 0) this.logger.debug({ upload: summary }, 'Result upload cycle completed');
  }

  async #handleResult(result) {
    if (!this.resultStore) throw new Error('Agent runtime requires a durable result store');
    const queued = await this.resultStore.enqueue(result);
    await this.#refreshQueueHealth();
    this.health.lastTaskResult = {
      taskId: result.taskId,
      collector: result.collector,
      status: result.status,
      finishedAt: result.finishedAt,
      queueItemId: queued.id,
    };
    await this.#persistHealth();
    this.logger.info({
      queueItemId: queued.id,
      collector: result.collector,
      status: result.status,
      retained: queued.retained,
    }, 'Collector result durably queued');
    await this.externalOnResult?.(result, queued);
  }

  async #refreshQueueHealth() {
    if (!this.resultStore) return;
    const stats = await this.resultStore.getStats();
    this.health.queueDepth = stats.pendingCount;
    this.health.queueEvictedCount = stats.evictedCount;
    this.health.queueLastEvictedAt = stats.lastEvictedAt;
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
