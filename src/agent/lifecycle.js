import os from 'node:os';
import { ApiClient, loadOrRegisterIdentity } from '../transport/api-client.js';
import { CredentialStore } from '../security/credentials.js';
import { IntegrityService } from '../security/integrity.js';
import { ResultStore } from '../storage/result-store.js';
import { AgentRuntime } from './runtime.js';
import { PLACEHOLDER_SERVER_URL } from '../enrollment/index.js';
import { createLogger, flushLogger } from '../utils/logger.js';

export class AgentLifecycle {
  constructor({ config, configPath, version, logger, apiClient, credentialStore, integrityService, resultStore, resultUploader, onResult, cwd = process.cwd() }) {
    this.config = config;
    this.version = version;
    this.logger = logger ?? createLogger({ level: config.agent.logLevel });
    this.apiClient = apiClient ?? new ApiClient({ config });
    this.credentialStore = credentialStore ?? new CredentialStore({
      identityPath: config.storage.identityPath,
      logger: this.logger,
      cwd,
    });
    this.integrityService = integrityService;
    this.configPath = configPath;
    this.resultStore = resultStore ?? new ResultStore({
      queueDir: config.storage.queueDir,
      maxQueueSizeBytes: config.storage.maxQueueSizeBytes,
      maxQueueItems: config.storage.maxQueueItems,
      maxItemAgeMs: config.storage.maxItemAgeMs,
      logger: this.logger,
      cwd,
    });
    this.resultUploader = resultUploader;
    this.onResult = onResult;
    this.cwd = cwd;
    this.signalHandlers = new Map();
  }

  async start() {
    await this.credentialStore.initialize();
    if (!this.integrityService && typeof this.credentialStore.loadIntegrityBaseline === 'function' && typeof this.credentialStore.saveIntegrityBaseline === 'function') {
      this.integrityService = new IntegrityService({ credentialStore: this.credentialStore, configPath: this.configPath,
        identityPath: this.config.storage.identityPath, logger: this.logger, cwd: this.cwd });
    }
    const integrityCheck = this.integrityService
      ? await this.integrityService.verifyOrEstablish(['binary', 'config', 'identity'])
      : { events: [] };
    const integrityEvents = integrityCheck.events;
    for (const integrityEvent of integrityEvents) this.logger.error({
      event: integrityEvent.type,
      target: integrityEvent.target,
      path: integrityEvent.path,
      expectedHash: integrityEvent.expectedHash,
      actualHash: integrityEvent.actualHash,
    }, 'SECURITY ALERT: agent integrity verification failed; continuing startup to preserve reporting and avoid denial of service');
    const metadata = {
      hostname: os.hostname(),
      platform: process.platform,
      architecture: process.arch,
      agentVersion: this.version,
      enrollmentToken: this.config.server.enrollmentToken,
      integrityEvents,
    };
    const existingIdentity = await this.credentialStore.loadIdentity();
    const hasCompleteIdentity = existingIdentity?.agentId && existingIdentity?.tenantId
      && existingIdentity?.authToken && existingIdentity?.encryptionKey
      && existingIdentity?.taskSigningKey && existingIdentity?.taskSigningKeyId;
    const configuredServerUrl = typeof this.config.server.url === 'string' ? this.config.server.url.trim().replace(/\/$/, '') : '';
    if (this.config.server.mode === 'http' && !hasCompleteIdentity
      && (!configuredServerUrl || configuredServerUrl === PLACEHOLDER_SERVER_URL)) {
      const message = 'Agent management server URL is not configured - run the enroll command or provide a valid server URL before starting the service';
      this.logger.error({ reasonCode: 'SERVER_URL_NOT_CONFIGURED' }, message);
      throw new Error(message);
    }
    const { identity, registered, validated } = await loadOrRegisterIdentity({
      credentialStore: this.credentialStore,
      apiClient: this.apiClient,
      metadata,
      existingIdentity,
      validateExisting: (existing) => this.apiClient.sendHeartbeat(existing, {
        agentId: existing.agentId,
        hostname: metadata.hostname,
        agentVersion: this.version,
        startupCredentialValidation: true,
        integrityEvents,
      }),
    });
    if (registered) await this.integrityService?.rebaseline(['identity'], 'normal-identity-write');
    this.logger.info({ agentId: identity.agentId, registered }, registered ? 'Agent registered' : 'Loaded existing agent identity');

    this.resultStore.setEncryptionKey(identity.encryptionKey);
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
      resultUploader: this.resultUploader,
      onResult: this.onResult,
      integrityEvents: registered || validated ? [] : integrityEvents,
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

  testConnection() {
    if (!this.runtime || this.runtime.getHealth().state !== 'running') {
      throw new Error('Agent must be running before testing the management-server connection');
    }
    return this.runtime.testConnection();
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
