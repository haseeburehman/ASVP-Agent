import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { CollectorRegistry } from '../core/collector-registry.js';
import { HeartbeatScheduler, TaskPollScheduler, UploadScheduler } from '../core/scheduler.js';
import { TaskRunner } from '../core/task-runner.js';
import { ResultUploader } from '../transport/result-uploader.js';
import { TaskEnvelopeVerifier } from '../task/envelope-verifier.js';
import { TaskJournal } from '../task/task-journal.js';
import { TaskRateTracker } from '../task/rate-tracker.js';

const SHUTDOWN_GRACE_MS = 5000;

async function writeStatus(statusPath, status) {
  await mkdir(path.dirname(statusPath), { recursive: true, mode: 0o700 });
  const temporaryPath = `${statusPath}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(temporaryPath, `${JSON.stringify(status, null, 2)}\n`, { mode: 0o600 });
  if (process.platform === 'win32') await rm(statusPath, { force: true });
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
    taskEnvelopeVerifier,
    taskJournal,
    taskRateTracker,
    onResult,
    resultStore,
    resultUploader,
    integrityEvents = [],
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
    this.pendingIntegrityEvents = Array.isArray(integrityEvents) ? structuredClone(integrityEvents) : [];
    this.registry = registry ?? new CollectorRegistry();
    this.taskRateTracker = taskRateTracker ?? new TaskRateTracker(config.agent?.taskRateLimit);
    this.taskJournal = taskJournal ?? new TaskJournal({
      path: config.storage.taskJournalPath ?? 'var/task-journal.json',
      logger,
      cwd,
    });
    const uploadConfig = config.collectors.upload;
    this.authFailureThreshold = uploadConfig.authFailureThreshold ?? 5;
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
      taskJournal: this.taskJournal,
    });
    this.taskEnvelopeVerifier = taskEnvelopeVerifier ?? new TaskEnvelopeVerifier({
      identity,
      ledgerPath: config.storage.taskReplayLedgerPath,
      logger,
      cwd,
    });
    this.health = {
      state: 'starting',
      agentId: identity.agentId,
      tenantId: identity.tenantId,
      lastHeartbeatAt: null,
      lastHeartbeatError: null,
      lastPollAt: null,
      lastPollError: null,
      lastTaskResult: null,
      queueDepth: 0,
      queueEvictedCount: 0,
      queueLastEvictedAt: null,
      failedPermanentCount: 0,
      failedPermanentRetainUntil: null,
      consecutiveUploadAuthFailures: 0,
      authFailureThreshold: this.authFailureThreshold,
      healthState: 'healthy',
    };
  }

  async start() {
    const [replayClaims, resultQueueItems] = await Promise.all([
      this.taskEnvelopeVerifier.listReplayClaims?.() ?? [],
      this.resultStore?.listForStartupReconciliation?.() ?? [],
    ]);
    const abandonedTasks = await this.taskJournal.initialize({ resultQueueItems });
    const journalEntries = await this.taskJournal.listEntries();
    const journalTaskIds = new Set(journalEntries.map((entry) => entry.taskId));
    const replayTaskIds = new Set(replayClaims.map((claim) => claim.taskId).filter(Boolean));

    for (const task of abandonedTasks) {
      this.logger.warn({
        taskId: task.taskId,
        collectorName: task.collectorName,
        previousStatus: task.status,
        reconciledStatus: task.reconciledStatus,
        resultQueueItemId: task.resultQueueItemId,
        resultQueueState: task.resultQueueState,
        acceptedAt: task.acceptedAt,
        startedAt: task.startedAt ?? null,
      }, task.resultQueueItemId
        ? 'Reconciled abandoned task with its durable result; task will not be re-executed'
        : 'Recovered abandoned task from previous agent process; task will not be re-executed');
    }
    for (const claim of replayClaims) {
      if (!claim.taskId || journalTaskIds.has(claim.taskId)) continue;
      this.logger.warn({
        taskId: claim.taskId,
        collectorName: claim.collectorName ?? null,
        sequence: claim.sequence,
      }, 'Found durable replay claim without a task journal entry; task will not be re-executed');
    }
    for (const item of resultQueueItems) {
      if (journalTaskIds.has(item.taskId) || replayTaskIds.has(item.taskId)) continue;
      this.logger.warn({
        taskId: item.taskId,
        collectorName: item.collectorName,
        queueItemId: item.id,
        queueState: item.state,
        resultStatus: item.resultStatus,
      }, 'Found durable result without replay or journal state; result remains queued and task will not be re-executed');
    }
    this.logger.info({
      replayClaimCount: replayClaims.length,
      journalEntryCount: journalEntries.length,
      resultQueueItemCount: resultQueueItems.length,
      recoveredTaskCount: abandonedTasks.length,
    }, 'Startup task state reconciliation completed');
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
      pollTasks: (signal) => this.#pollTasks(signal),
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
    const schedulerShutdown = Promise.all([
      this.heartbeatScheduler?.stop(),
      this.taskPollScheduler?.stop(),
      this.uploadScheduler?.stop(),
    ]);
    let graceTimer;
    const graceful = await Promise.race([
      schedulerShutdown.then(() => true),
      new Promise((resolve) => { graceTimer = setTimeout(() => resolve(false), SHUTDOWN_GRACE_MS); }),
    ]);
    clearTimeout(graceTimer);
    if (!graceful) this.logger.warn({ gracePeriodMs: SHUTDOWN_GRACE_MS }, 'Agent shutdown grace period elapsed while operations were still stopping');
    this.health.state = 'stopped';
    await this.#persistHealth();
    this.logger.info('Agent runtime stopped');
  }

  getHealth() {
    return structuredClone(this.health);
  }

  async uploadResultsOnce({ signal } = {}) {
    return this.#uploadResults(signal);
  }

  async testConnection() {
    const startedAt = Date.now();
    await this.#heartbeat();
    return {
      ok: true,
      testedAt: this.health.lastHeartbeatAt,
      latencyMs: Date.now() - startedAt,
    };
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
      integrityEvents: this.pendingIntegrityEvents,
    };
    try {
      await this.apiClient.sendHeartbeat(this.identity, payload);
      this.health.lastHeartbeatAt = new Date().toISOString();
      this.health.lastHeartbeatError = null;
      this.pendingIntegrityEvents = [];
      await this.#persistHealth();
      this.logger.info({
        agentId: this.identity.agentId,
        currentQueueSize: payload.currentQueueSize,
        receivedAt: this.health.lastHeartbeatAt,
      }, 'Heartbeat accepted by management server');
    } catch (error) {
      this.health.lastHeartbeatError = error.message;
      await this.#persistHealth();
      throw error;
    }
  }

  async #pollTasks(signal) {
    try {
      const polledTasks = await this.apiClient.pollTasks(this.identity);
      const verifiedTasks = await this.taskEnvelopeVerifier.verifyAll(polledTasks);
      const rateDecision = this.taskRateTracker.admit(verifiedTasks);
      const tasks = rateDecision.accepted;
      for (const rejection of rateDecision.rejected) {
        this.logger.warn({
          taskId: rejection.task.taskId,
          collectorName: rejection.task.collectorName,
          reasonCode: rejection.reasonCode,
          reason: rejection.reason,
          maxExecutions: rateDecision.maxExecutions,
          windowMs: rateDecision.windowMs,
        }, 'Rejected task due to cumulative execution rate limit');
      }
      this.health.lastPollAt = new Date().toISOString();
      this.health.lastPollError = null;
      await this.#persistHealth();
      this.logger.info({
        agentId: this.identity.agentId,
        taskCount: tasks.length,
        rejectedTaskCount: polledTasks.length - tasks.length,
        invalidEnvelopeCount: polledTasks.length - verifiedTasks.length,
        rateLimitedTaskCount: rateDecision.rejected.length,
        receivedAt: this.health.lastPollAt,
      }, tasks.length > 0 ? 'Received collector tasks' : 'Task poll completed with no tasks');
      if (tasks.length > 0) await this.taskRunner.runAll(tasks, { signal });
    } catch (error) {
      this.health.lastPollError = error.message;
      await this.#persistHealth();
      throw error;
    }
  }

  async #uploadResults(signal) {
    const summary = await this.resultUploader.drain({ signal });
    if (summary.delivered > 0) {
      this.health.consecutiveUploadAuthFailures = 0;
      this.health.healthState = 'healthy';
    } else if (summary.authFailures > 0) {
      this.health.consecutiveUploadAuthFailures += summary.authFailures;
      if (this.health.consecutiveUploadAuthFailures >= this.authFailureThreshold) {
        this.health.healthState = 'authentication-degraded';
        this.logger.error({
          consecutiveUploadAuthFailures: this.health.consecutiveUploadAuthFailures,
          authFailureThreshold: this.authFailureThreshold,
        }, 'Result upload authentication is degraded; verify agent registration credentials');
      }
    }
    await this.#refreshQueueHealth();
    await this.#persistHealth();
    if (summary.attempted > 0) this.logger.debug({ upload: summary }, 'Result upload cycle completed');
    return summary;
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
    this.health.failedPermanentCount = stats.failedPermanentCount;
    this.health.failedPermanentRetainUntil = stats.failedPermanentRetainUntil;
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
