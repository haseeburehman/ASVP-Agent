import { randomUUID } from 'node:crypto';

export class MockManagementTransport {
  constructor({ tasks } = {}) {
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
  }

  async register() {
    return {
      agentId: `mock-agent-${randomUUID()}`,
      authToken: `mock-token-${randomUUID()}`,
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
}

export class FetchManagementTransport {
  constructor({ baseUrl, requestTimeoutMs }) {
    this.baseUrl = baseUrl;
    this.requestTimeoutMs = requestTimeoutMs;
  }

  async #post(pathname, body, authToken) {
    const headers = { 'content-type': 'application/json' };
    if (authToken) headers.authorization = `Bearer ${authToken}`;
    const response = await fetch(new URL(pathname, this.baseUrl), {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.requestTimeoutMs),
    });
    if (!response.ok) throw new Error(`Management server returned HTTP ${response.status}`);
    return response.json();
  }

  register(pathname, payload) {
    return this.#post(pathname, payload);
  }

  heartbeat(pathname, payload, authToken) {
    return this.#post(pathname, payload, authToken);
  }

  pollTasks(pathname, payload, authToken) {
    return this.#post(pathname, payload, authToken);
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

  register(metadata = {}) {
    return this.transport.register(this.config.server.registrationPath, metadata);
  }

  sendHeartbeat(identity, status) {
    return this.transport.heartbeat(this.config.server.heartbeatPath, status, identity.authToken);
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
  if (!force) {
    const existing = await credentialStore.loadIdentity();
    if (existing) return { identity: existing, registered: false };
  }

  const identity = await apiClient.register(metadata);
  if (!identity?.agentId || !identity?.authToken) {
    throw new Error('Registration response did not include agentId and authToken');
  }
  await credentialStore.saveIdentity(identity);
  return { identity, registered: true };
}
