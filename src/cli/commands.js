import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { Command } from 'commander';
import { AgentLifecycle } from '../agent/lifecycle.js';
import { readStatus } from '../agent/runtime.js';
import { loadConfig } from '../config/loader.js';
import { CredentialStore } from '../security/credentials.js';
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

export function createProgram() {
  const program = new Command();
  program
    .name('asvp-agent')
    .description('ASVP internal network agent')
    .option('-c, --config <path>', 'alternate configuration file');

  program.command('run')
    .description('run the agent in the foreground')
    .action(async (_, command) => {
      const { config } = command.optsWithGlobals();
      const context = await createContext({ config });
      const lifecycle = new AgentLifecycle(context);
      await lifecycle.start();
    });

  program.command('register')
    .description('force registration and replace the local identity')
    .action(async (_, command) => {
      const { config: configPath } = command.optsWithGlobals();
      const { config, logger } = await createContext({ config: configPath });
      try {
        const credentialStore = await new CredentialStore({
          identityPath: config.storage.identityPath,
          logger,
        }).initialize();
        const apiClient = new ApiClient({ config });
        const { identity } = await loadOrRegisterIdentity({ credentialStore, apiClient, force: true });
        logger.info({ agentId: identity.agentId }, 'Agent registration replaced');
      } finally {
        await flushLogger(logger);
      }
    });

  program.command('status')
    .description('print persisted identity and heartbeat status')
    .action(async (_, command) => {
      const { config: configPath } = command.optsWithGlobals();
      const { config, logger, version } = await createContext({ config: configPath });
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
          state: status?.state ?? 'not-running-or-no-status',
          agentVersion: status?.agentVersion ?? version,
        }, null, 2)}\n`);
      } finally {
        await flushLogger(logger);
      }
    });

  return program;
}
