import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

const serviceName = 'asvp-internal-network-agent';
const accountName = 'agent-identity';

let keytarLoadError = null;

async function loadKeytar() {
  try {
    keytarLoadError = null;
    return (await import('keytar')).default;
  } catch (error) {
    keytarLoadError = error;
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

  getBackend() {
    return this.keychain ? 'keychain' : 'restricted-file';
  }

  async diagnoseBackend() {
    if (!this.keychain) return {
      backend: 'restricted-file',
      nativeAddonLoaded: false,
      operational: false,
      ...(keytarLoadError ? { error: keytarLoadError.message } : {}),
    };
    const diagnosticAccount = `${accountName}-diagnostic-${process.pid}`;
    const marker = `asvp-keychain-diagnostic-${Date.now()}`;
    try {
      await this.keychain.setPassword(serviceName, diagnosticAccount, marker);
      const stored = await this.keychain.getPassword(serviceName, diagnosticAccount);
      await this.keychain.deletePassword(serviceName, diagnosticAccount);
      return { backend: 'keychain', nativeAddonLoaded: true, operational: stored === marker };
    } catch (error) {
      return {
        backend: 'keychain',
        nativeAddonLoaded: true,
        operational: false,
        error: error.message,
      };
    }
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
    if (!identity?.agentId || !identity?.authToken || !identity?.encryptionKey) {
      throw new Error('Cannot persist an incomplete agent identity');
    }
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
