import { randomUUID } from 'node:crypto';
import { generateEncryptionKey } from '../security/crypto.js';

export class ManagementHttpError extends Error {
  constructor(status, message = `Management server returned HTTP ${status}`) {
    super(message);
    this.name = 'ManagementHttpError';
    this.code = 'MANAGEMENT_HTTP_ERROR';
    this.status = status;
  }
}

export class MockManagementTransport {
  constructor({ tasks, uploadHandler } = {}) {
    this.tasks = tasks ?? [
      {
        taskId: 'mock-task-noop-001',
        collectorName: 'noop',
        params: { source: 'mock-management-transport' },
        scheduledAt: '2026-01-01T00:00:00.000Z',
      },
      {
        taskId: 'mock-task-network-scan-001',
        collectorName: 'network-scan',
        params: {},
        scheduledAt: '2026-01-01T00:00:01.000Z',
      },
    ];
    this.delivered = false;
    this.uploadHandler = uploadHandler;
    this.receivedUploads = [];
  }

  async register() {
    return {
      agentId: `mock-agent-${randomUUID()}`,
      authToken: `mock-token-${randomUUID()}`,
      encryptionKey: generateEncryptionKey(),
    };
  }

  async heartbeat() {
    return { accepted: true, receivedAt: new Date().toISOString() };
  }

  async pollTasks() {
    if (this.delivered) return [];
    this.delivered = true;
    return structuredClone(this.tasks);
  }

  async uploadResult(_pathname, payload, authToken, signal) {
    if (signal?.aborted) throw signal.reason ?? new DOMException('Upload aborted', 'AbortError');
    if (this.uploadHandler) return this.uploadHandler(payload, authToken, signal);
    this.receivedUploads.push(structuredClone(payload));
    return { accepted: true, queueItemId: payload.queueItemId, receivedAt: new Date().toISOString() };
  }
}

export class FetchManagementTransport {
  constructor({ baseUrl, requestTimeoutMs }) {
    this.baseUrl = baseUrl;
    this.requestTimeoutMs = requestTimeoutMs;
  }

  async #post(pathname, body, authToken, signal) {
    const headers = { 'content-type': 'application/json' };
    if (authToken) headers.authorization = `Bearer ${authToken}`;
    const response = await fetch(new URL(pathname, this.baseUrl), {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: signal
        ? AbortSignal.any([signal, AbortSignal.timeout(this.requestTimeoutMs)])
        : AbortSignal.timeout(this.requestTimeoutMs),
    });
    if (!response.ok) throw new ManagementHttpError(response.status);
    return response.json();
  }

  register(pathname, payload, previousAuthToken) {
    return this.#post(pathname, payload, previousAuthToken);
  }

  heartbeat(pathname, payload, authToken) {
    return this.#post(pathname, payload, authToken);
  }

  pollTasks(pathname, payload, authToken) {
    return this.#post(pathname, payload, authToken);
  }

  uploadResult(pathname, payload, authToken, signal) {
    return this.#post(pathname, payload, authToken, signal);
  }
}

export class ApiClient {
  constructor({ config, transport }) {
    this.config = config;
    this.transport = transport ?? (config.server.mode === 'mock'
      ? new MockManagementTransport()
      : new FetchManagementTransport({
        baseUrl: config.server.url,
        requestTimeoutMs: config.server.requestTimeoutMs,
      }));
  }

  register(metadata = {}, previousAuthToken) {
    return this.transport.register(this.config.server.registrationPath, metadata, previousAuthToken);
  }

  sendHeartbeat(identity, status) {
    return this.transport.heartbeat(this.config.server.heartbeatPath, status, identity.authToken);
  }

  uploadResult(identity, payload, { signal } = {}) {
    return this.transport.uploadResult(
      this.config.server.resultsPath,
      payload,
      identity.authToken,
      signal,
    );
  }

  async pollTasks(identity) {
    const response = await this.transport.pollTasks(
      this.config.server.tasksPath,
      { agentId: identity.agentId },
      identity.authToken,
    );
    const tasks = Array.isArray(response) ? response : response?.tasks;
    if (!Array.isArray(tasks)) throw new Error('Task poll response must contain an array of tasks');
    return tasks;
  }
}

export async function loadOrRegisterIdentity({ credentialStore, apiClient, force = false, metadata = {} }) {
  const existing = await credentialStore.loadIdentity();
  if (!force && existing?.agentId && existing?.authToken && existing?.encryptionKey) {
    return { identity: existing, registered: false };
  }

  const registrationMetadata = existing?.agentId
    ? { ...metadata, previousAgentId: existing.agentId }
    : metadata;
  const identity = await apiClient.register(registrationMetadata, existing?.authToken);
  if (!identity?.agentId || !identity?.authToken || !identity?.encryptionKey) {
    throw new Error('Registration response did not include agentId, authToken, and encryptionKey');
  }
  await credentialStore.saveIdentity(identity);
  return { identity, registered: true };
}
