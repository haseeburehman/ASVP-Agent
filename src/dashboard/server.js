import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { WebSocketServer, WebSocket } from 'ws';
import { AgentLifecycle } from '../agent/lifecycle.js';
import { readStatus } from '../agent/runtime.js';
import { parseOperatorCommand, runManualScan } from '../cli/commands.js';
import { loadConfig } from '../config/loader.js';
import { CollectorRegistry } from '../core/collector-registry.js';
import { CredentialStore } from '../security/credentials.js';
import { ApiClient, loadOrRegisterIdentity } from '../transport/api-client.js';
import { createLogger, flushLogger } from '../utils/logger.js';

const PAGE_PATH = new URL('./public/index.html', import.meta.url);
const DEFAULT_OVERRIDE_PATH = 'var/dashboard-config.json';
const LOOPBACK_ADDRESSES = new Set(['127.0.0.1', '::1', 'localhost']);

function tokenMatches(expected, provided) {
  if (typeof provided !== 'string') return false;
  const left = Buffer.from(expected);
  const right = Buffer.from(provided);
  return left.length === right.length && timingSafeEqual(left, right);
}

function requestToken(request) {
  const url = new URL(request.url, 'http://localhost');
  return request.headers['x-dashboard-token'] ?? url.searchParams.get('token');
}

async function atomicWriteConfig(filePath, config) {
  await mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const temporaryPath = `${filePath}.${process.pid}.tmp`;
  await writeFile(temporaryPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  await rename(temporaryPath, filePath);
  await chmod(filePath, 0o600).catch((error) => {
    if (process.platform !== 'win32') throw error;
  });
}

function editableConfig(config) {
  return {
    server: { mode: config.server.mode, url: config.server.url },
    networkScanAllowedCidrs: config.collectors['network-scan'].allowedCidrs,
    scaDepsScanPaths: config.collectors['sca-deps'].scanPaths,
  };
}

function applyEditableConfig(config, update) {
  const next = structuredClone(config);
  if (!['mock', 'http'].includes(update?.server?.mode)) throw new Error('server.mode must be "mock" or "http"');
  if (typeof update?.server?.url !== 'string' || !update.server.url.trim()) throw new Error('server.url is required');
  const serverUrl = update.server.url.trim().replace(/[\u200B-\u200D\uFEFF]/g, '');
  const localHttp = /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?(?:\/|$)/i.test(serverUrl);
  if (update.server.mode === 'http' && !serverUrl.toLowerCase().startsWith('https://') && !localHttp) {
    throw new Error('HTTP transport requires HTTPS, except for a localhost/127.0.0.1 development server');
  }
  if (!Array.isArray(update.networkScanAllowedCidrs) || !update.networkScanAllowedCidrs.every((value) => typeof value === 'string' && value.trim())) {
    throw new Error('network-scan allowedCidrs must be an array of non-empty strings');
  }
  if (!Array.isArray(update.scaDepsScanPaths) || !update.scaDepsScanPaths.every((value) => typeof value === 'string' && value.trim())) {
    throw new Error('sca-deps scanPaths must be an array of non-empty strings');
  }
  next.server.mode = update.server.mode;
  next.server.url = serverUrl;
  next.collectors['network-scan'].allowedCidrs = update.networkScanAllowedCidrs.map((value) => value.trim());
  next.collectors['tls-checks'].allowedCidrs = [...next.collectors['network-scan'].allowedCidrs];
  next.collectors['sca-deps'].scanPaths = update.scaDepsScanPaths.map((value) => value.trim());
  return next;
}

export class DashboardServer {
  constructor({
    config,
    logger,
    version,
    token = randomBytes(32).toString('base64url'),
    cwd = process.cwd(),
    overridePath = DEFAULT_OVERRIDE_PATH,
    lifecycleFactory,
    registry = new CollectorRegistry(),
    fetchImpl = fetch,
  }) {
    this.config = config;
    this.logger = logger;
    this.version = version;
    this.token = token;
    this.cwd = cwd;
    this.overridePath = path.resolve(cwd, overridePath);
    this.lifecycleFactory = lifecycleFactory ?? ((options) => new AgentLifecycle(options));
    this.registry = registry;
    this.fetchImpl = fetchImpl;
    this.clients = new Set();
    this.startedAt = Date.now();
  }

  async start({ startAgent = true } = {}) {
    const page = await readFile(PAGE_PATH, 'utf8');
    this.httpServer = createServer((request, response) => {
      if (!tokenMatches(this.token, requestToken(request))) {
        response.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' });
        response.end('Dashboard access token required');
        return;
      }
      const url = new URL(request.url, 'http://localhost');
      if (request.method !== 'GET' || url.pathname !== '/') {
        response.writeHead(404).end();
        return;
      }
      response.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src ws:; object-src 'none'; frame-ancestors 'none'",
      });
      response.end(page);
    });
    this.webSocketServer = new WebSocketServer({ noServer: true });
    this.httpServer.on('upgrade', (request, socket, head) => {
      const url = new URL(request.url, 'http://localhost');
      if (url.pathname !== '/ws' || !tokenMatches(this.token, requestToken(request))) {
        socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
        socket.destroy();
        return;
      }
      this.webSocketServer.handleUpgrade(request, socket, head, (client) => this.webSocketServer.emit('connection', client));
    });
    this.webSocketServer.on('connection', (client) => this.#attachClient(client));
    await new Promise((resolve, reject) => {
      this.httpServer.once('error', reject);
      this.httpServer.listen(this.config.dashboard.port, this.config.dashboard.bindAddress, resolve);
    });
    this.statusTimer = setInterval(() => this.broadcast({ type: 'snapshot', data: this.snapshot() }), 2000);
    this.statusTimer.unref();

    const address = this.httpServer.address();
    this.port = typeof address === 'object' ? address.port : this.config.dashboard.port;
    if (!LOOPBACK_ADDRESSES.has(this.config.dashboard.bindAddress)) {
      this.logger.warn({ bindAddress: this.config.dashboard.bindAddress, port: this.port }, 'SECURITY WARNING: dashboard is not bound to loopback and may expose full agent control to the network');
    }
    this.logger.info({ bindAddress: this.config.dashboard.bindAddress, port: this.port }, 'Local agent dashboard started');
    if (startAgent) await this.startAgent().catch((error) => this.logger.error({ err: error }, 'Agent failed to start; dashboard remains available for configuration'));
    return this;
  }

  async stop() {
    clearInterval(this.statusTimer);
    await this.stopAgent();
    for (const client of this.clients) client.close(1001, 'Dashboard shutting down');
    await new Promise((resolve) => this.webSocketServer?.close(resolve));
    await new Promise((resolve) => this.httpServer?.close(resolve));
  }

  async startAgent() {
    if (this.lifecycle?.getHealth().state === 'running') return this.lifecycle.getHealth();
    this.lifecycle = this.lifecycleFactory({
      config: this.config,
      version: this.version,
      logger: this.logger,
      cwd: this.cwd,
      onResult: (result) => this.broadcast({ type: 'result', data: result }),
    });
    const health = await this.lifecycle.start();
    this.broadcast({ type: 'snapshot', data: this.snapshot() });
    return health;
  }

  async stopAgent() {
    if (!this.lifecycle) return;
    await this.lifecycle.stop();
    this.broadcast({ type: 'snapshot', data: this.snapshot() });
  }

  async restartAgent() {
    await this.stopAgent();
    this.lifecycle = null;
    return this.startAgent();
  }

  snapshot() {
    const health = this.lifecycle?.getHealth() ?? { state: 'stopped' };
    const hasConnectionError = Boolean(health.lastHeartbeatError || health.lastPollError);
    const serverConnectionState = health.healthState === 'authentication-degraded'
      ? 'authentication-degraded'
      : this.config.server.mode === 'mock'
        ? 'mock'
        : health.state !== 'running'
          ? 'stopped'
          : hasConnectionError
            ? 'unreachable'
            : health.lastHeartbeatAt && health.lastPollAt
              ? 'connected'
              : 'connecting';
    const networkAuthorized = (this.config.collectors['network-scan'].allowedCidrs ?? []).length > 0;
    return {
      ...health,
      agentVersion: this.version,
      connectionMode: this.config.server.mode,
      serverUrl: this.config.server.url,
      serverConnectionState,
      lastHeartbeatSucceeded: Boolean(health.lastHeartbeatAt) && !health.lastHeartbeatError,
      lastPollSucceeded: Boolean(health.lastPollAt) && !health.lastPollError,
      uptimeSeconds: Math.floor((Date.now() - this.startedAt) / 1000),
      collectors: this.registry.list()
        .filter((definition) => definition.implemented)
        .map((definition) => ({
          name: definition.name,
          warning: ['network-scan', 'tls-checks'].includes(definition.name) && !networkAuthorized
            ? 'No targets currently authorized; configure network-scan allowedCidrs first'
            : null,
        })),
      taskCreation: {
        enabled: this.config.server.mode === 'http',
        reason: this.config.server.mode === 'http' ? null : 'Task creation requires a real connected server',
      },
      config: editableConfig(this.config),
    };
  }

  pushLog(record) {
    this.broadcast({ type: 'log', data: record });
  }

  broadcast(message) {
    const serialized = JSON.stringify(message);
    for (const client of this.clients) {
      if (client.readyState === WebSocket.OPEN) client.send(serialized);
    }
  }

  async executeOperatorCommand(input, signal) {
    const command = parseOperatorCommand(input);
    if (command.name === 'status') return { output: this.snapshot() };
    if (command.name === 'register') {
      await this.stopAgent();
      const credentialStore = await new CredentialStore({
        identityPath: this.config.storage.identityPath,
        logger: this.logger,
        cwd: this.cwd,
      }).initialize();
      const { identity } = await loadOrRegisterIdentity({
        credentialStore,
        apiClient: new ApiClient({ config: this.config }),
        force: true,
      });
      this.lifecycle = null;
      await this.startAgent();
      return { output: { agentId: identity.agentId, registered: true } };
    }
    const completed = await runManualScan({
      collectorName: command.collectorName,
      targets: command.targets,
      ports: command.ports,
      queue: command.queue,
      config: this.config,
      logger: this.logger,
      signal,
      resultStore: this.lifecycle?.resultStore,
      cwd: this.cwd,
    });
    this.broadcast({ type: 'result', data: completed.result });
    return { output: completed.result };
  }

  async testConnection() {
    if (!this.lifecycle) throw new Error('Agent must be running before testing the management-server connection');
    const result = await this.lifecycle.testConnection();
    this.broadcast({ type: 'snapshot', data: this.snapshot() });
    this.logger.info({
      serverUrl: this.config.server.url,
      latencyMs: result.latencyMs,
      testedAt: result.testedAt,
    }, 'Dashboard management-server connection test succeeded');
    return { ...result, serverUrl: this.config.server.url };
  }

  async createTask(input = {}) {
    if (this.config.server.mode !== 'http') {
      throw new Error('Task creation requires a real connected server');
    }
    if (!this.config.server.adminToken) {
      throw new Error('Dashboard server process is missing ADMIN_TOKEN for central task creation');
    }
    const health = this.lifecycle?.getHealth();
    if (!health?.agentId) throw new Error('The agent must be registered and running before creating a task');
    const collectorName = input.collectorName;
    const definition = this.registry.getDefinition(collectorName);
    if (!definition?.implemented) throw new Error(`Unknown or unavailable collector "${collectorName}"`);
    const params = {};
    if (['network-scan', 'tls-checks'].includes(collectorName)) {
      if ((this.config.collectors['network-scan'].allowedCidrs ?? []).length === 0) {
        throw new Error('No targets currently authorized; configure network-scan allowedCidrs first');
      }
      if (!Array.isArray(input.targets) || input.targets.length === 0) throw new Error(`${collectorName} requires at least one target`);
      params.targets = input.targets;
      if (input.ports != null) {
        if (!Array.isArray(input.ports) || input.ports.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) {
          throw new Error('ports must contain valid TCP port numbers');
        }
        params.ports = input.ports;
      }
    }
    const response = await this.fetchImpl(new URL('/api/admin/tasks', this.config.server.url), {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${this.config.server.adminToken}`,
      },
      body: JSON.stringify({ agentId: health.agentId, collectorName, params }),
      signal: AbortSignal.timeout(this.config.server.requestTimeoutMs),
    });
    if (!response.ok) {
      const detail = await response.text();
      throw new Error(`Central server task creation failed with HTTP ${response.status}${detail ? `: ${detail}` : ''}`);
    }
    const created = await response.json();
    if (typeof created.taskId !== 'string' || !created.taskId) throw new Error('Central server task response did not include taskId');
    const result = { taskId: created.taskId, agentId: health.agentId, collectorName, params };
    this.logger.info(result, 'Central-server task created from dashboard');
    return result;
  }

  async saveConfig(update) {
    const serverChanged = update?.server?.mode !== this.config.server.mode
      || update?.server?.url?.trim() !== this.config.server.url;
    const next = applyEditableConfig(this.config, update);
    await atomicWriteConfig(this.overridePath, next);
    this.config = await loadConfig({ configPath: this.overridePath, cwd: this.cwd });
    this.broadcast({ type: 'config', data: editableConfig(this.config), requiresRestart: true });
    return { overridePath: this.overridePath, config: editableConfig(this.config), serverChanged };
  }

  async #handleMessage(client, raw) {
    let message;
    try {
      message = JSON.parse(raw.toString());
      if (message.type === 'command') {
        const controller = new AbortController();
        const result = await this.executeOperatorCommand(message.command, controller.signal);
        client.send(JSON.stringify({ type: 'command-result', id: message.id ?? null, ok: true, ...result }));
      } else if (message.type === 'lifecycle') {
        if (message.action === 'start') await this.startAgent();
        else if (message.action === 'stop') await this.stopAgent();
        else if (message.action === 'restart') await this.restartAgent();
        else throw new Error(`Unknown lifecycle action "${message.action}"`);
        client.send(JSON.stringify({ type: 'lifecycle-result', id: message.id ?? null, ok: true, action: message.action }));
      } else if (message.type === 'config.save') {
        const saved = await this.saveConfig(message.config);
        client.send(JSON.stringify({ type: 'config-result', id: message.id ?? null, ok: true, ...saved }));
      } else if (message.type === 'task.create') {
        const created = await this.createTask(message.task);
        client.send(JSON.stringify({ type: 'task-result', id: message.id ?? null, ok: true, ...created }));
      } else if (message.type === 'connection.test') {
        const tested = await this.testConnection();
        client.send(JSON.stringify({ type: 'connection-result', id: message.id ?? null, ok: true, ...tested }));
      } else {
        throw new Error(`Unknown WebSocket message type "${message.type}"`);
      }
    } catch (error) {
      this.broadcast({ type: 'snapshot', data: this.snapshot() });
      const responseType = message?.type === 'task.create'
        ? 'task-result'
        : message?.type === 'connection.test'
          ? 'connection-result'
          : 'command-result';
      client.send(JSON.stringify({
        type: responseType,
        id: message?.id ?? null,
        ok: false,
        error: { message: error.message, code: error.code ?? null },
      }));
    }
  }

  #attachClient(client) {
    this.clients.add(client);
    client.send(JSON.stringify({ type: 'snapshot', data: this.snapshot() }));
    client.on('message', (raw) => this.#handleMessage(client, raw));
    client.on('close', () => this.clients.delete(client));
  }
}

export async function startDashboardCommand({ configPath } = {}) {
  const cwd = process.cwd();
  const config = await loadConfig({ configPath, cwd });
  const version = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8')).version;
  let dashboard;
  const logger = createLogger({ level: config.agent.logLevel, onLog: (record) => dashboard?.pushLog(record) });
  dashboard = new DashboardServer({ config, logger, version, cwd });
  await dashboard.start({ startAgent: true });
  const hostForUrl = config.dashboard.bindAddress === '0.0.0.0' ? '127.0.0.1' : config.dashboard.bindAddress;
  const url = `http://${hostForUrl}:${dashboard.port}/?token=${encodeURIComponent(dashboard.token)}`;
  process.stdout.write(`\nASVP dashboard access URL (shown once):\n${url}\n\n`);

  const shutdown = async (signal) => {
    logger.info({ signal }, 'Dashboard shutdown signal received');
    await dashboard.stop();
    await flushLogger(logger);
  };
  process.once('SIGINT', () => shutdown('SIGINT').catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }));
  process.once('SIGTERM', () => shutdown('SIGTERM').catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }));
  return dashboard;
}
