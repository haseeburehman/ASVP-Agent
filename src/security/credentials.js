import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

const serviceName = 'asvp-internal-network-agent';
const accountName = 'agent-identity';

async function loadKeytar() {
  try {
    return (await import('keytar')).default;
  } catch {
    return null;
  }
}

async function writePrivateJson(filePath, value) {
  await mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const temporaryPath = `${filePath}.${process.pid}.tmp`;
  await writeFile(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await rename(temporaryPath, filePath);
}

export class CredentialStore {
  constructor({ identityPath, keychain, logger, cwd = process.cwd() }) {
    this.identityPath = path.resolve(cwd, identityPath);
    this.keychain = keychain;
    this.logger = logger;
  }

  async initialize() {
    if (this.keychain === undefined) this.keychain = await loadKeytar();
    if (!this.keychain) this.logger?.warn('OS keychain unavailable; using restricted identity file fallback');
    return this;
  }

  async loadIdentity() {
    if (this.keychain) {
      try {
        const serialized = await this.keychain.getPassword(serviceName, accountName);
        return serialized ? JSON.parse(serialized) : null;
      } catch (error) {
        this.logger?.warn({ err: error }, 'OS keychain read failed; using restricted identity file fallback');
        this.keychain = null;
      }
    }
    try {
      return JSON.parse(await readFile(this.identityPath, 'utf8'));
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw new Error(`Unable to read local agent identity: ${error.message}`, { cause: error });
    }
  }

  async saveIdentity(identity) {
    if (!identity?.agentId || !identity?.authToken) throw new Error('Cannot persist an incomplete agent identity');
    if (this.keychain) {
      try {
        await this.keychain.setPassword(serviceName, accountName, JSON.stringify(identity));
        return;
      } catch (error) {
        this.logger?.warn({ err: error }, 'OS keychain write failed; using restricted identity file fallback');
        this.keychain = null;
      }
    }
    await writePrivateJson(this.identityPath, identity);
  }

  async clearIdentity() {
    if (this.keychain) {
      try {
        await this.keychain.deletePassword(serviceName, accountName);
        return;
      } catch (error) {
        this.logger?.warn({ err: error }, 'OS keychain delete failed; clearing restricted identity file fallback');
        this.keychain = null;
      }
    }
    await rm(this.identityPath, { force: true });
  }
}
