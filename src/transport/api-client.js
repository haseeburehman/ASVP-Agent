import { randomUUID } from 'node:crypto';
import { generateEncryptionKey } from '../security/crypto.js';
import { deriveMachineFingerprint } from '../security/machine-fingerprint.js';

export class ManagementHttpError extends Error {
  constructor(status, message = `Management server returned HTTP ${status}`, serverCode) {
    super(message);
    this.name = 'ManagementHttpError';
    this.code = serverCode ?? 'MANAGEMENT_HTTP_ERROR';
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
    ];
    this.delivered = false;
    this.uploadHandler = uploadHandler;
    this.receivedUploads = [];
  }

  async register() {
    return {
      agentId: `mock-agent-${randomUUID()}`,
      tenantId: 'default',
      authToken: `mock-token-${randomUUID()}`,
      encryptionKey: generateEncryptionKey(),
      taskSigningKey: generateEncryptionKey(),
      taskSigningKeyId: `mock-task-key-${randomUUID()}`,
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
    const responseBody = await response.json().catch(() => null);
    if (!response.ok) throw new ManagementHttpError(response.status, responseBody?.error, responseBody?.code);
    return responseBody;
  }

  register(pathname, payload, previousAuthToken) {
    return this.#post(pathname, payload, previousAuthToken);
  }

  heartbeat(pathname, payload, authToken) {
    return this.#post(pathname, payload, authToken);
  }

  deregister(pathname, payload, authToken) {
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
  constructor({ config, transport, fingerprintProvider = deriveMachineFingerprint }) {
    this.config = config;
    this.fingerprintProvider = fingerprintProvider;
    this.transport = transport ?? (config.server.mode === 'mock'
      ? new MockManagementTransport()
      : new FetchManagementTransport({
        baseUrl: config.server.url,
        requestTimeoutMs: config.server.requestTimeoutMs,
      }));
  }

  async register(metadata = {}, previousAuthToken) {
    const machineFingerprint = await this.fingerprintProvider();
    return this.transport.register(this.config.server.registrationPath, { ...metadata, machineFingerprint }, previousAuthToken);
  }

  async sendHeartbeat(identity, status) {
    const machineFingerprint = await this.fingerprintProvider();
    return this.transport.heartbeat(this.config.server.heartbeatPath, { ...status, machineFingerprint }, identity.authToken);
  }

  async deregister(identity) {
    if (this.config.server.mode === 'mock') return { accepted: true, deregisteredAt: new Date().toISOString() };
    const machineFingerprint = await this.fingerprintProvider();
    return this.transport.deregister(
      this.config.server.deregistrationPath,
      { agentId: identity.agentId, machineFingerprint },
      identity.authToken,
    );
  }

  async uploadResult(identity, payload, { signal } = {}) {
    const machineFingerprint = await this.fingerprintProvider();
    return this.transport.uploadResult(
      this.config.server.resultsPath,
      { ...payload, machineFingerprint },
      identity.authToken,
      signal,
    );
  }

  async pollTasks(identity) {
    const machineFingerprint = await this.fingerprintProvider();
    const response = await this.transport.pollTasks(
      this.config.server.tasksPath,
      { agentId: identity.agentId, machineFingerprint },
      identity.authToken,
    );
    const tasks = Array.isArray(response) ? response : response?.tasks;
    if (!Array.isArray(tasks)) throw new Error('Task poll response must contain an array of tasks');
    return tasks;
  }
}

export async function loadOrRegisterIdentity({ credentialStore, apiClient, force = false, metadata = {}, validateExisting, existingIdentity }) {
  const existing = existingIdentity === undefined ? await credentialStore.loadIdentity() : existingIdentity;
  if (!force && existing?.agentId && existing?.tenantId && existing?.authToken && existing?.encryptionKey && existing?.taskSigningKey && existing?.taskSigningKeyId) {
    if (typeof validateExisting !== 'function') return { identity: existing, registered: false };
    try {
      await validateExisting(existing);
      return { identity: existing, registered: false, validated: true };
    } catch (error) {
      if (error?.code === 'IDENTITY_FINGERPRINT_MISMATCH') throw error;
      if (![401, 403].includes(Number(error?.status))) {
        return { identity: existing, registered: false, validationError: error };
      }
    }
  }

  const registrationMetadata = existing?.agentId
    ? { ...metadata, previousAgentId: existing.agentId }
    : metadata;
  const identity = await apiClient.register(registrationMetadata, existing?.authToken);
  if (!identity?.agentId || !identity?.tenantId || !identity?.authToken || !identity?.encryptionKey || !identity?.taskSigningKey || !identity?.taskSigningKeyId) {
    throw new Error('Registration response did not include agentId, tenantId, authToken, encryptionKey, taskSigningKey, and taskSigningKeyId');
  }
  await credentialStore.saveIdentity(identity);
  return { identity, registered: true };
}
