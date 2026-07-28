import { readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import systeminformation from 'systeminformation';

const MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024;
const DEFAULT_MAX_PATCHES = 100;

function abortedError() {
  const error = new Error('OS information collection was aborted');
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

function runCommand(executable, args, { signal, timeoutMs = 15000, spawnProcess = spawn } = {}) {
  if (signal?.aborted) return Promise.reject(abortedError());

  return new Promise((resolve, reject) => {
    const child = spawnProcess(executable, args, {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let settled = false;

    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', abortHandler);
      clearTimeout(timeout);
      callback(value);
    };
    const abortHandler = () => {
      child.kill();
      finish(reject, abortedError());
    };
    const timeout = setTimeout(() => {
      child.kill();
      const error = new Error(`Patch command exceeded its ${timeoutMs}ms deadline`);
      error.code = 'PATCH_COMMAND_TIMEOUT';
      finish(reject, error);
    }, timeoutMs);
    const append = (current, chunk) => {
      const next = current + chunk.toString('utf8');
      if (Buffer.byteLength(next) > MAX_COMMAND_OUTPUT_BYTES) {
        child.kill();
        finish(reject, new Error('Patch command output exceeded the 1 MiB safety limit'));
      }
      return next;
    };

    signal?.addEventListener('abort', abortHandler, { once: true });
    child.stdout?.on('data', (chunk) => { stdout = append(stdout, chunk); });
    child.stderr?.on('data', (chunk) => { stderr = append(stderr, chunk); });
    child.once('error', (error) => finish(reject, error));
    child.once('close', (code) => {
      if (code === 0) finish(resolve, stdout.trim());
      else finish(reject, new Error(`${executable} exited with code ${code}: ${stderr.trim() || 'no error output'}`));
    });
  });
}

function mostRecentInstallDate(items) {
  let mostRecent = null;
  let mostRecentTime = -Infinity;
  for (const item of items) {
    if (!item.installedAt) continue;
    const time = Date.parse(item.installedAt);
    if (!Number.isNaN(time) && time > mostRecentTime) {
      mostRecent = item.installedAt;
      mostRecentTime = time;
    }
  }
  return mostRecent;
}

function patchResult(items, source, reason = null, maxItems = DEFAULT_MAX_PATCHES) {
  if (!Array.isArray(items)) {
    return { items, source, reason, totalCount: null, mostRecentInstalledAt: null };
  }
  return {
    items: items.slice(-maxItems),
    source,
    reason,
    totalCount: items.length,
    mostRecentInstalledAt: mostRecentInstallDate(items),
  };
}

function unavailableClassification() {
  return { classification: null, classificationAvailable: false };
}

function parseDpkgUpdates(contents) {
  return contents
    .split(/\r?\n/)
    .filter((line) => /\supgrade\s/.test(line))
    .map((line) => {
      const [date, time, , packageName, previousVersion, installedVersion] = line.trim().split(/\s+/);
      return {
        identifier: packageName,
        installedAt: `${date}T${time}`,
        name: packageName,
        previousVersion,
        installedVersion,
        ...unavailableClassification(),
      };
    });
}

function parsePacmanUpdates(contents) {
  return contents
    .split(/\r?\n/)
    .filter((line) => /\[ALPM\] upgraded /.test(line))
    .map((line) => {
      const description = line.trim();
      const match = description.match(/^\[([^\]]+)] \[ALPM] upgraded (\S+)/);
      return {
        identifier: match?.[2] ?? null,
        installedAt: match?.[1] ?? null,
        description,
        ...unavailableClassification(),
      };
    });
}

async function collectLinuxPatches({ signal, commandTimeoutMs, maxItems, readTextFile, run }) {
  const attempts = [];
  for (const [filePath, parser, source] of [
    ['/var/log/dpkg.log', parseDpkgUpdates, 'dpkg-log'],
    ['/var/log/pacman.log', parsePacmanUpdates, 'pacman-log'],
  ]) {
    try {
      if (signal?.aborted) throw abortedError();
      return patchResult(parser(await readTextFile(filePath, 'utf8')), source, null, maxItems);
    } catch (error) {
      if (error.name === 'AbortError') throw error;
      attempts.push(`${source}: ${error.code ?? error.message}`);
    }
  }

  try {
    const output = await run('dnf', ['history', 'list', '--reverse'], { signal, timeoutMs: commandTimeoutMs });
    const items = output.split(/\r?\n/).filter(Boolean).map((description) => {
      const columns = description.split('|').map((value) => value.trim());
      return {
        identifier: columns.length > 1 ? columns[0] || null : null,
        installedAt: columns.length > 2 ? columns[2] || null : null,
        description,
        ...unavailableClassification(),
      };
    });
    return patchResult(items, 'dnf-history', null, maxItems);
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    attempts.push(`dnf-history: ${error.code ?? error.message}`);
  }

  return patchResult(
    null,
    null,
    `Unable to read supported package update history; logs may be missing or require elevated privileges (${attempts.join('; ')})`,
  );
}

async function collectWindowsPatches({ signal, commandTimeoutMs, maxItems, run }) {
  try {
    const script = 'Get-HotFix | Select-Object HotFixID,Description,InstalledOn | ConvertTo-Json -Compress';
    const output = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { signal, timeoutMs: commandTimeoutMs });
    const parsed = output ? JSON.parse(output) : [];
    const records = Array.isArray(parsed) ? parsed : [parsed];
    return patchResult(records.map((record) => ({
      identifier: record.HotFixID ?? null,
      installedAt: record.InstalledOn ?? null,
      classification: record.Description ?? null,
      classificationAvailable: Boolean(record.Description),
      hotfixId: record.HotFixID ?? null,
      description: record.Description ?? null,
      installedOn: record.InstalledOn ?? null,
    })), 'powershell-get-hotfix', null, maxItems);
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return patchResult(null, null, `Unable to query installed Windows hotfixes: ${error.message}`);
  }
}

async function collectMacOsPatches({ signal, commandTimeoutMs, maxItems, run }) {
  try {
    const output = await run('/usr/sbin/softwareupdate', ['--history'], { signal, timeoutMs: commandTimeoutMs });
    const items = output
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !/^Display Name\s+Version\s+Date$/i.test(line) && !/^-{3,}/.test(line))
      .map((description) => {
        const columns = description.split(/\s{2,}/);
        return {
          identifier: columns[0] || null,
          installedAt: columns.length >= 3 ? columns.at(-1) || null : null,
          description,
          ...unavailableClassification(),
        };
      });
    return patchResult(items, 'softwareupdate-history', null, maxItems);
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return patchResult(null, null, `Unable to query installed macOS updates: ${error.message}`);
  }
}

export async function collectInstalledPatches(platform, options = {}) {
  const dependencies = {
    signal: options.signal,
    commandTimeoutMs: options.commandTimeoutMs ?? 15000,
    maxItems: options.maxItems ?? DEFAULT_MAX_PATCHES,
    readTextFile: options.readTextFile ?? readFile,
    run: options.runCommand ?? runCommand,
  };

  if (platform === 'linux') return collectLinuxPatches(dependencies);
  if (platform === 'win32') return collectWindowsPatches(dependencies);
  if (platform === 'darwin') return collectMacOsPatches(dependencies);
  return patchResult(null, null, `Patch collection is unsupported on platform "${platform}"`);
}

function normalizePlatform(platform) {
  const value = platform?.toLowerCase();
  if (value === 'windows' || value === 'win32') return 'win32';
  if (value === 'macos' || value === 'osx' || value === 'darwin') return 'darwin';
  if (value === 'linux') return 'linux';
  return value || null;
}

function prettyName(osData, platform) {
  const distro = osData.distro?.trim();
  const release = osData.release?.trim();
  if (!distro) return release || platform || 'Unknown';
  if (platform === 'win32' || !release || distro.toLowerCase().includes(release.toLowerCase())) return distro;
  return `${distro} ${release}`;
}

export function createOsInfoCollector({
  systemInformation = systeminformation,
  patchChecker = collectInstalledPatches,
} = {}) {
  return {
    name: 'os-info',
    version: '1.0.0',
    async run(_params = {}, context = {}) {
      if (context.signal?.aborted) throw abortedError();
      const osData = await systemInformation.osInfo();
      if (context.signal?.aborted) throw abortedError();

      const platform = normalizePlatform(osData.platform);
      let patches;
      try {
        patches = await patchChecker(platform, {
          signal: context.signal,
          commandTimeoutMs: context.collectorConfig?.patchCheckTimeoutMs ?? 15000,
          maxItems: context.collectorConfig?.maxItems ?? DEFAULT_MAX_PATCHES,
        });
      } catch (error) {
        if (error.name === 'AbortError') throw error;
        patches = patchResult(null, null, `Patch sub-check failed: ${error.message}`);
      }

      return {
        prettyName: prettyName(osData, platform),
        version: osData.release || null,
        kernelRelease: osData.kernel || null,
        architecture: osData.arch || null,
        hostname: osData.hostname || null,
        platform,
        patches,
      };
    },
  };
}

export const osInfoCollector = createOsInfoCollector();
export default osInfoCollector;
