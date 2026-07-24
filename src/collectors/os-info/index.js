import { readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import systeminformation from 'systeminformation';

const MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024;

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

function patchResult(items, source, reason = null) {
  return { items, source, reason };
}

function parseDpkgUpdates(contents) {
  return contents
    .split(/\r?\n/)
    .filter((line) => /\supgrade\s/.test(line))
    .slice(-100)
    .map((line) => {
      const [timestamp, , packageName, previousVersion, installedVersion] = line.trim().split(/\s+/);
      return { installedAt: timestamp, name: packageName, previousVersion, installedVersion };
    });
}

function parsePacmanUpdates(contents) {
  return contents
    .split(/\r?\n/)
    .filter((line) => /\[ALPM\] upgraded /.test(line))
    .slice(-100)
    .map((line) => ({ description: line.trim() }));
}

async function collectLinuxPatches({ signal, commandTimeoutMs, readTextFile, run }) {
  const attempts = [];
  for (const [filePath, parser, source] of [
    ['/var/log/dpkg.log', parseDpkgUpdates, 'dpkg-log'],
    ['/var/log/pacman.log', parsePacmanUpdates, 'pacman-log'],
  ]) {
    try {
      if (signal?.aborted) throw abortedError();
      return patchResult(parser(await readTextFile(filePath, 'utf8')), source);
    } catch (error) {
      if (error.name === 'AbortError') throw error;
      attempts.push(`${source}: ${error.code ?? error.message}`);
    }
  }

  try {
    const output = await run('dnf', ['history', 'list', '--reverse'], { signal, timeoutMs: commandTimeoutMs });
    const items = output.split(/\r?\n/).filter(Boolean).slice(-100).map((description) => ({ description }));
    return patchResult(items, 'dnf-history');
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

async function collectWindowsPatches({ signal, commandTimeoutMs, run }) {
  try {
    const script = 'Get-HotFix | Select-Object HotFixID,Description,InstalledOn | ConvertTo-Json -Compress';
    const output = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { signal, timeoutMs: commandTimeoutMs });
    const parsed = output ? JSON.parse(output) : [];
    const records = Array.isArray(parsed) ? parsed : [parsed];
    return patchResult(records.map((record) => ({
      hotfixId: record.HotFixID ?? null,
      description: record.Description ?? null,
      installedOn: record.InstalledOn ?? null,
    })), 'powershell-get-hotfix');
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return patchResult(null, null, `Unable to query installed Windows hotfixes: ${error.message}`);
  }
}

async function collectMacOsPatches({ signal, commandTimeoutMs, run }) {
  try {
    const output = await run('/usr/sbin/softwareupdate', ['--history'], { signal, timeoutMs: commandTimeoutMs });
    const items = output
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !/^Display Name\s+Version\s+Date$/i.test(line) && !/^-{3,}/.test(line))
      .slice(-100)
      .map((description) => ({ description }));
    return patchResult(items, 'softwareupdate-history');
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return patchResult(null, null, `Unable to query installed macOS updates: ${error.message}`);
  }
}

export async function collectInstalledPatches(platform, options = {}) {
  const dependencies = {
    signal: options.signal,
    commandTimeoutMs: options.commandTimeoutMs ?? 15000,
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
