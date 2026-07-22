import os from 'node:os';
import { ApiClient, loadOrRegisterIdentity } from '../transport/api-client.js';
import { CredentialStore } from '../security/credentials.js';
import { ResultStore } from '../storage/result-store.js';
import { AgentRuntime } from './runtime.js';
import { createLogger, flushLogger } from '../utils/logger.js';

export class AgentLifecycle {
  constructor({ config, version, logger, apiClient, credentialStore, resultStore, cwd = process.cwd() }) {
    this.config = config;
    this.version = version;
    this.logger = logger ?? createLogger({ level: config.agent.logLevel });
    this.apiClient = apiClient ?? new ApiClient({ config });
    this.credentialStore = credentialStore ?? new CredentialStore({
      identityPath: config.storage.identityPath,
      logger: this.logger,
      cwd,
    });
    this.resultStore = resultStore ?? new ResultStore({
      queueDir: config.storage.queueDir,
      maxQueueSizeBytes: config.storage.maxQueueSizeBytes,
      maxQueueItems: config.storage.maxQueueItems,
      maxItemAgeMs: config.storage.maxItemAgeMs,
      logger: this.logger,
      cwd,
    });
    this.cwd = cwd;
    this.signalHandlers = new Map();
  }

  async start() {
    await this.credentialStore.initialize();
    const { identity, registered } = await loadOrRegisterIdentity({
      credentialStore: this.credentialStore,
      apiClient: this.apiClient,
      metadata: { hostname: os.hostname(), platform: process.platform, architecture: process.arch },
    });
    this.logger.info({ agentId: identity.agentId, registered }, registered ? 'Agent registered' : 'Loaded existing agent identity');

    await this.resultStore.initialize();
    const recoveredCount = await this.resultStore.requeueStaleInFlight();
    this.logger.info({ recoveredQueueItems: recoveredCount }, 'Result queue initialized and in-flight items recovered');

    this.runtime = new AgentRuntime({
      config: this.config,
      identity,
      apiClient: this.apiClient,
      logger: this.logger,
      version: this.version,
      resultStore: this.resultStore,
      cwd: this.cwd,
    });
    this.#installSignalHandlers();
    await this.runtime.start();
    return this.runtime.getHealth();
  }

  async stop(signal) {
    if (this.stopping) return this.stopping;
    this.stopping = (async () => {
      if (signal) this.logger.info({ signal }, 'Shutdown signal received');
      this.#removeSignalHandlers();
      await this.runtime?.stop();
      await flushLogger(this.logger);
    })();
    return this.stopping;
  }

  getHealth() {
    return this.runtime?.getHealth() ?? { state: 'not-started' };
  }

  #installSignalHandlers() {
    for (const signal of ['SIGINT', 'SIGTERM']) {
      const handler = () => {
        this.stop(signal).catch((error) => {
          this.logger.error({ err: error }, 'Graceful shutdown failed');
          process.exitCode = 1;
        });
      };
      this.signalHandlers.set(signal, handler);
      process.once(signal, handler);
    }
  }

  #removeSignalHandlers() {
    for (const [signal, handler] of this.signalHandlers) process.removeListener(signal, handler);
    this.signalHandlers.clear();
  }
}
