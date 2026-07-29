import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import path from 'node:path';

async function sha256File(filePath) {
  await stat(filePath);
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.once('error', reject);
    stream.once('end', () => resolve(hash.digest('hex')));
  });
}

function mismatchEvent(kind, filePath, expectedHash, actualHash) {
  return {
    type: kind === 'binary' ? 'binary-integrity-mismatch' : 'config-integrity-mismatch',
    target: kind,
    path: filePath,
    expectedHash,
    actualHash,
    detectedAt: new Date().toISOString(),
  };
}

export class IntegrityService {
  constructor({ credentialStore, configPath, identityPath, executablePath, cwd = process.cwd(), hashFile = sha256File, logger } = {}) {
    this.credentialStore = credentialStore;
    this.logger = logger;
    this.hashFile = hashFile;
    this.paths = {
      binary: path.resolve(cwd, executablePath ?? (process.pkg ? process.execPath : process.argv[1])),
      config: configPath ? path.resolve(cwd, configPath) : null,
      identity: identityPath ? path.resolve(cwd, identityPath) : null,
    };
  }

  async currentHashes(kinds = ['binary', 'config', 'identity']) {
    const hashes = {};
    for (const kind of kinds) {
      const filePath = this.paths[kind];
      if (!filePath) continue;
      try { hashes[kind] = { path: filePath, sha256: await this.hashFile(filePath) }; }
      catch (error) { if (error.code !== 'ENOENT') throw new Error(`Unable to hash agent ${kind} file: ${error.message}`, { cause: error }); }
    }
    return hashes;
  }

  async rebaseline(kinds = ['binary', 'config', 'identity'], reason = 'explicit-rebaseline') {
    const previous = await this.credentialStore.loadIntegrityBaseline() ?? { schemaVersion: 1, hashes: {} };
    const hashes = await this.currentHashes(kinds);
    const baseline = { schemaVersion: 1, hashes: { ...(previous.hashes ?? {}), ...hashes }, establishedAt: new Date().toISOString(), reason };
    for (const kind of kinds) if (!hashes[kind]) delete baseline.hashes[kind];
    await this.credentialStore.saveIntegrityBaseline(baseline);
    this.logger?.info({ event: 'integrity-baseline-established', kinds, reason }, 'Agent integrity baseline established');
    return baseline;
  }

  async verifyOrEstablish(kinds = ['binary', 'config', 'identity']) {
    const baseline = await this.credentialStore.loadIntegrityBaseline();
    if (!baseline) return { baseline: await this.rebaseline(kinds, 'first-run'), events: [], established: true };
    const current = await this.currentHashes(kinds);
    const events = [];
    for (const kind of kinds) {
      const expected = baseline.hashes?.[kind];
      const actual = current[kind];
      if (!expected && actual) {
        baseline.hashes[kind] = actual;
        continue;
      }
      if (expected && (!actual || expected.sha256 !== actual.sha256)) {
        events.push(mismatchEvent(kind, actual?.path ?? expected.path, expected.sha256, actual?.sha256 ?? null));
      }
    }
    if (events.length === 0) await this.credentialStore.saveIntegrityBaseline({ ...baseline, hashes: { ...baseline.hashes, ...current } });
    return { baseline, events, established: false };
  }
}

export { sha256File };
