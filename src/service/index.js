import { access } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { defaultConfigPath, loadConfig } from '../config/loader.js';
import { requireElevation } from './elevation.js';
import { CredentialStore } from '../security/credentials.js';
import { ApiClient } from '../transport/api-client.js';
import { resolveServicePaths } from './definitions.js';
import { createLinuxAdapter } from './linux.js';
import { createMacosAdapter } from './macos.js';
import { runCommand } from './process.js';
import { createWindowsAdapter } from './windows.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

export function detectServicePlatform(platform = process.platform) {
  if (platform === 'linux' || platform === 'win32' || platform === 'darwin') return platform;
  throw new Error(`Service installation is not supported on platform ${platform}`);
}

export async function promptConfirmation(message) {
  if (!input.isTTY) return false;
  const readline = createInterface({ input, output });
  try {
    const answer = await readline.question(`${message} Type "yes" to confirm: `);
    return answer.trim().toLowerCase() === 'yes';
  } finally {
    readline.close();
  }
}

function isWithin(parent, child) {
  const relative = path.relative(parent, child);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

export async function resolveServiceContext({ configPath, cwd = process.cwd(), nodePath = process.execPath, packaged = Boolean(process.pkg) } = {}) {
  const installRoot = packaged ? path.dirname(path.resolve(nodePath)) : projectRoot;
  const serviceDefaultConfigPath = packaged ? path.join(installRoot, 'config', 'default.json') : defaultConfigPath;
  const absoluteConfigPath = path.resolve(cwd, configPath ?? serviceDefaultConfigPath);
  await access(absoluteConfigPath);
  const config = await loadConfig({ configPath: absoluteConfigPath, cwd: installRoot });
  const paths = resolveServicePaths({ projectRoot, configPath: absoluteConfigPath, nodePath, packaged });
  const mutablePaths = [config.storage.identityPath, config.storage.statusPath, config.storage.queueDir]
    .map((value) => path.resolve(projectRoot, value));
  if (mutablePaths.some((value) => !isWithin(paths.varDirectory, value))) {
    throw new Error(`Service storage paths must remain under ${paths.varDirectory} so native sandbox permissions are complete`);
  }
  await Promise.all([paths.executablePath, ...paths.entryArguments, paths.configPath].map((value) => access(value)));
  return { config, paths };
}

export function createPlatformAdapter(platform, options) {
  if (platform === 'linux') return createLinuxAdapter(options);
  if (platform === 'win32') return createWindowsAdapter(options);
  if (platform === 'darwin') return createMacosAdapter(options);
  return detectServicePlatform(platform);
}

export async function deregisterBeforeUninstall({ config, paths, credentialStore, apiClient } = {}) {
  try {
    const store = credentialStore ?? await new CredentialStore({
      identityPath: config.storage.identityPath,
      cwd: paths.projectRoot,
      logger: { debug() {}, info() {}, warn() {}, error() {} },
    }).initialize();
    const identity = await store.loadIdentity();
    if (!identity?.agentId || !identity?.authToken) return { attempted: false, accepted: false, reason: 'No persisted agent identity was available' };
    const response = await (apiClient ?? new ApiClient({ config })).deregister(identity);
    return { attempted: true, accepted: response?.accepted === true, agentId: identity.agentId };
  } catch (error) {
    return { attempted: true, accepted: false, reason: error.message };
  }
}

export async function runServiceCommand(action, options = {}) {
  const platform = detectServicePlatform(options.platform);
  const runner = options.runner ?? runCommand;
  if (action === 'install' || action === 'uninstall') {
    await requireElevation({ platform, runCommand: runner, geteuid: options.geteuid });
  }
  const { config, paths } = await resolveServiceContext({
    configPath: options.configPath,
    cwd: options.cwd,
    nodePath: options.nodePath,
    packaged: options.packaged,
  });
  const adapter = createPlatformAdapter(platform, {
    paths,
    runner,
    confirm: options.confirm ?? promptConfirmation,
    fetchImpl: options.fetchImpl,
    architecture: options.architecture,
    fs: options.fs,
  });
  if (!['install', 'uninstall', 'status'].includes(action)) throw new Error(`Unknown service action ${action}`);
  const deregistration = action === 'uninstall'
    ? await deregisterBeforeUninstall({ config, paths, credentialStore: options.credentialStore, apiClient: options.apiClient })
    : null;
  const result = await adapter[action]();
  return deregistration ? { ...result, deregistration } : result;
}

export { projectRoot as serviceProjectRoot };
