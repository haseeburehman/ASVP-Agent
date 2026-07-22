import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { HeartbeatScheduler } from '../core/scheduler.js';

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
  constructor({ config, identity, apiClient, logger, version, cwd = process.cwd() }) {
    this.config = config;
    this.identity = identity;
    this.apiClient = apiClient;
    this.logger = logger;
    this.version = version;
    this.startedAt = Date.now();
    this.statusPath = path.resolve(cwd, config.storage.statusPath);
    this.health = {
      state: 'starting',
      agentId: identity.agentId,
      lastHeartbeatAt: null,
      lastHeartbeatError: null,
    };
  }

  async start() {
    this.health.state = 'running';
    await this.#persistHealth();
    this.scheduler = new HeartbeatScheduler({
      heartbeat: () => this.#heartbeat(),
      intervalMs: this.config.agent.heartbeatIntervalMs,
      initialRetryMs: this.config.retry.initialDelayMs,
      maximumRetryMs: this.config.retry.maximumDelayMs,
      logger: this.logger,
    });
    this.scheduler.start();
    this.logger.info({ agentId: this.identity.agentId }, 'Agent runtime started; task polling is not implemented');
  }

  async stop() {
    this.health.state = 'stopping';
    await this.scheduler?.stop();
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

  #persistHealth() {
    return writeStatus(this.statusPath, {
      ...this.health,
      updatedAt: new Date().toISOString(),
      agentVersion: this.version,
    });
  }
}
