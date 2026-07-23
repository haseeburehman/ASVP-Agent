import { randomUUID } from 'node:crypto';
import { readFile, unlink } from 'node:fs/promises';
import path from 'node:path';
import { Command } from 'commander';
import { AgentLifecycle } from '../agent/lifecycle.js';
import { readStatus } from '../agent/runtime.js';
import { authorizeNetworkScan } from '../collectors/network-scan/authorization.js';
import { DEFAULT_TLS_PORTS } from '../collectors/tls-checks/index.js';
import { loadConfig } from '../config/loader.js';
import { CollectorRegistry } from '../core/collector-registry.js';
import { TaskRunner } from '../core/task-runner.js';
import { runEnrollment } from '../enrollment/index.js';
import { CredentialStore } from '../security/credentials.js';
import { ResultStore } from '../storage/result-store.js';
import { runServiceCommand } from '../service/index.js';
import { ApiClient, loadOrRegisterIdentity } from '../transport/api-client.js';
import { createLogger, flushLogger } from '../utils/logger.js';

async function getVersion() {
  const packagePath = new URL('../../package.json', import.meta.url);
  return JSON.parse(await readFile(packagePath, 'utf8')).version;
}

async function createContext(options) {
  const config = await loadConfig({ configPath: options.config });
  const logger = createLogger({ level: config.agent.logLevel });
  return { config, logger, version: await getVersion() };
}

const REMOTE_COLLECTORS = new Set(['network-scan', 'tls-checks']);

export function parseCommaSeparated(value, label) {
  const values = value.split(',').map((item) => item.trim()).filter(Boolean);
  if (values.length === 0) throw new Error(`${label} must contain at least one value`);
  return values;
}

export function parsePorts(value) {
  return parseCommaSeparated(value, '--ports').map((item) => {
    const port = Number(item);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`Invalid TCP port "${item}"`);
    return port;
  });
}

function addScanOptions(command) {
  return command
    .requiredOption('--collector <name>', 'registered collector name')
    .option('--target <targets>', 'comma-separated IP addresses or CIDRs')
    .option('--ports <ports>', 'comma-separated TCP ports', parsePorts)
    .option('--json', 'print the full normalized result as JSON')
    .option('--no-queue', 'do not persist the result in the durable queue');
}

function tokenizeCommand(input) {
  const tokens = [];
  const expression = /"([^"\\]*(?:\\.[^"\\]*)*)"|'([^']*)'|([^\s]+)/g;
  let match;
  while ((match = expression.exec(input.trim()))) tokens.push(match[1] ?? match[2] ?? match[3]);
  return tokens;
}

export function parseOperatorCommand(input) {
  const tokens = tokenizeCommand(input);
  const commandName = tokens.shift();
  if (!['scan', 'status', 'register'].includes(commandName)) throw new Error(`Unknown command "${commandName ?? ''}"`);
  if (commandName !== 'scan') {
    if (tokens.length > 0) throw new Error(`${commandName} does not accept arguments`);
    return { name: commandName };
  }
  if (tokens[0] && !tokens[0].startsWith('-')) tokens.unshift('--collector');
  const parser = addScanOptions(new Command())
    .exitOverride()
    .configureOutput({ writeErr() {} });
  parser.parse(['node', 'scan', ...tokens]);
  const options = parser.opts();
  return {
    name: 'scan',
    collectorName: options.collector,
    targets: options.target ? parseCommaSeparated(options.target, '--target') : undefined,
    ports: options.ports,
    queue: options.queue,
    json: options.json ?? false,
  };
}

function createResultStore(config, logger, cwd) {
  return new ResultStore({
    queueDir: config.storage.queueDir,
    maxQueueSizeBytes: config.storage.maxQueueSizeBytes,
    maxQueueItems: config.storage.maxQueueItems,
    maxItemAgeMs: config.storage.maxItemAgeMs,
    logger,
    cwd,
  });
}

export function formatScanSummary(result, queued) {
  const lines = [
    `Collector: ${result.collector}`,
    `Status: ${result.status}`,
    `Task ID: ${result.taskId}`,
  ];
  if (result.error) lines.push(`Error: ${result.error.message}`);
  if (result.collector === 'network-scan' && result.data) {
    const hosts = result.data.hosts ?? [];
    lines.push(`Hosts up: ${hosts.filter((host) => host.status === 'up').length}/${hosts.length}`);
    lines.push(`Open ports: ${hosts.reduce((count, host) => count + (host.openPorts?.length ?? 0), 0)}`);
  } else if (result.collector === 'os-info' && result.data) {
    lines.push(`OS: ${result.data.prettyName ?? result.data.os?.prettyName ?? 'unknown'}`);
    lines.push(`Version: ${result.data.version ?? result.data.os?.version ?? 'unknown'}`);
  } else if (result.collector === 'tls-checks' && result.data) {
    lines.push(`Endpoints checked: ${result.data.endpoints?.length ?? 0}`);
  }
  lines.push(queued ? `Queue item: ${queued.id}` : 'Queue: skipped (--no-queue)');
  return `${lines.join('\n')}\n`;
}

export async function runManualScan({
  collectorName,
  targets,
  ports,
  queue = true,
  config,
  logger,
  signal,
  registry = new CollectorRegistry(),
  resultStore,
  cwd = process.cwd(),
  taskId = `manual-${randomUUID()}`,
}) {
  if (!registry.has(collectorName)) throw new Error(`Unknown collector "${collectorName}"`);

  const remote = REMOTE_COLLECTORS.has(collectorName);
  if (remote && (!Array.isArray(targets) || targets.length === 0)) {
    throw new Error(`--target is required for collector "${collectorName}"`);
  }
  const params = remote ? {
    targets,
    ports: ports ?? (collectorName === 'tls-checks' ? [...DEFAULT_TLS_PORTS] : undefined),
  } : {};

  if (remote) {
    const authorization = authorizeNetworkScan({
      config: config.collectors[collectorName],
      taskParams: params,
    });
    if (!authorization.authorized || authorization.deniedTargets.length > 0) {
      const denied = authorization.deniedTargets.map((entry) => entry.target).filter(Boolean);
      const detail = denied.length > 0 ? ` (${denied.join(', ')})` : '';
      const error = new Error(`authorization denied: not in allowedCidrs${detail}: ${authorization.reason ?? authorization.deniedTargets[0]?.reason ?? 'target refused'}`);
      error.code = 'AUTHORIZATION_DENIED';
      throw error;
    }
  }

  let store = resultStore;
  if (queue && !store) store = createResultStore(config, logger, cwd);
  if (queue) await store.initialize();
  let queued = null;
  const runner = new TaskRunner({
    registry,
    logger,
    collectorConfig: config.collectors,
    onResult: async (result) => {
      if (queue) queued = await store.enqueue(result);
    },
  });
  const task = { taskId, collectorName, params, scheduledAt: new Date().toISOString() };
  const result = await runner.run(task, { signal });
  return { result, queued, task };
}

export function createProgram({ contextFactory = createContext } = {}) {
  const program = new Command();
  program
    .name('asvp-agent')
    .description('ASVP internal network agent')
    .option('-c, --config <path>', 'alternate configuration file');

  program.command('run')
    .description('run the agent in the foreground')
    .action(async (_, command) => {
      const { config } = command.optsWithGlobals();
      const context = await contextFactory({ config });
      if (context.config.dashboard.enabled) {
        await flushLogger(context.logger);
        const { startDashboardCommand } = await import('../dashboard/server.js');
        await startDashboardCommand({ configPath: config });
        return;
      }
      const lifecycle = new AgentLifecycle(context);
      await lifecycle.start();
    });

  program.command('enroll')
    .description('configure the management server for this installation')
    .option('--server-url <url>', 'management server HTTPS URL')
    .option('--enrollment-token <token>', 'optional short-lived enrollment token')
        .option('--input-file <path>', 'read URL and token from a temporary installer input file')
        .action(async (options, command) => {
          const { config: configPath } = command.optsWithGlobals();
          if (!configPath) throw new Error('enroll requires --config <path>');
          let serverUrl = options.serverUrl;
          let enrollmentToken = options.enrollmentToken;
          if (options.inputFile) {
            try {
              const [fileUrl, ...tokenLines] = (await readFile(options.inputFile, 'utf8')).split(/\r?\n/);
              serverUrl = fileUrl;
              enrollmentToken = tokenLines.join('').trim();
            } finally {
              await unlink(options.inputFile).catch(() => {});
            }
          }
          const result = await runEnrollment({ configPath, serverUrl, enrollmentToken });
      process.stdout.write(`Enrollment saved to ${result.configPath}\n`);
    });

  program.command('register')
    .description('force registration and replace the local identity')
    .action(async (_, command) => {
      const { config: configPath } = command.optsWithGlobals();
      const { config, logger } = await contextFactory({ config: configPath });
      try {
        const credentialStore = await new CredentialStore({
          identityPath: config.storage.identityPath,
          logger,
        }).initialize();
        const apiClient = new ApiClient({ config });
        const { identity } = await loadOrRegisterIdentity({
          credentialStore,
          apiClient,
          force: true,
          metadata: { enrollmentToken: config.server.enrollmentToken },
        });
        logger.info({ agentId: identity.agentId }, 'Agent registration replaced');
      } finally {
        await flushLogger(logger);
      }
    });

  program.command('status')
    .description('print persisted identity and heartbeat status')
    .action(async (_, command) => {
      const { config: configPath } = command.optsWithGlobals();
      const { config, logger, version } = await contextFactory({ config: configPath });
      try {
        const credentialStore = await new CredentialStore({
          identityPath: config.storage.identityPath,
          logger,
        }).initialize();
        const identity = await credentialStore.loadIdentity();
        const status = await readStatus(path.resolve(config.storage.statusPath));
        process.stdout.write(`${JSON.stringify({
          agentId: identity?.agentId ?? null,
          lastHeartbeatAt: status?.lastHeartbeatAt ?? null,
          lastPollAt: status?.lastPollAt ?? null,
          lastTaskResult: status?.lastTaskResult ?? null,
          queueDepth: status?.queueDepth ?? 0,
          queueEvictedCount: status?.queueEvictedCount ?? 0,
          queueLastEvictedAt: status?.queueLastEvictedAt ?? null,
          failedPermanentCount: status?.failedPermanentCount ?? 0,
          failedPermanentRetainUntil: status?.failedPermanentRetainUntil ?? null,
          consecutiveUploadAuthFailures: status?.consecutiveUploadAuthFailures ?? 0,
          authFailureThreshold: status?.authFailureThreshold ?? config.collectors.upload.authFailureThreshold,
          healthState: status?.healthState ?? 'unknown',
          state: status?.state ?? 'not-running-or-no-status',
          agentVersion: status?.agentVersion ?? version,
        }, null, 2)}\n`);
      } finally {
        await flushLogger(logger);
      }
    });

  addScanOptions(program.command('scan')
    .description('manually run one collector through the production task pipeline'))
    .action(async (options, command) => {
      const { config: configPath } = command.optsWithGlobals();
      const { config, logger } = await contextFactory({ config: configPath });
      const abortController = new AbortController();
      const handleSignal = () => abortController.abort(new Error('Manual scan interrupted'));
      process.once('SIGINT', handleSignal);
      process.once('SIGTERM', handleSignal);
      try {
        const { result, queued } = await runManualScan({
          collectorName: options.collector,
          targets: options.target ? parseCommaSeparated(options.target, '--target') : undefined,
          ports: options.ports,
          queue: options.queue,
          config,
          logger,
          signal: abortController.signal,
        });
        process.stdout.write(options.json
          ? `${JSON.stringify(result, null, 2)}\n`
          : formatScanSummary(result, queued));
        if (result.status !== 'success') process.exitCode = 1;
      } finally {
        process.removeListener('SIGINT', handleSignal);
        process.removeListener('SIGTERM', handleSignal);
        await flushLogger(logger);
      }
    });

  const diagnostics = program.command('diagnostics').description('run deployment diagnostics');
  diagnostics.command('credentials')
    .description('verify the active credential backend with a temporary write/read/delete round trip')
    .option('--require-keychain', 'fail unless the OS keychain backend is loaded and operational')
    .action(async (options, command) => {
      const { config: configPath } = command.optsWithGlobals();
      const { config, logger } = await contextFactory({ config: configPath });
      try {
        const credentialStore = await new CredentialStore({
          identityPath: config.storage.identityPath,
          logger,
        }).initialize();
        const result = await credentialStore.diagnoseBackend();
        process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
        if (options.requireKeychain && (result.backend !== 'keychain' || !result.operational)) process.exitCode = 1;
      } finally {
        await flushLogger(logger);
      }
    });

  const service = program.command('service').description('install, uninstall, or inspect the native OS service');
  for (const action of ['install', 'uninstall', 'status']) {
    service.command(action)
      .description(`${action} the ASVP agent native service`)
      .action(async (_, command) => {
        const { config: configPath } = command.optsWithGlobals();
        const result = await runServiceCommand(action, { configPath });
        process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      });
  }

  program.command('dashboard')
    .description('run the agent with the local operator dashboard')
    .action(async (_, command) => {
      const { config: configPath } = command.optsWithGlobals();
      const { startDashboardCommand } = await import('../dashboard/server.js');
      await startDashboardCommand({ configPath });
    });

  return program;
}
