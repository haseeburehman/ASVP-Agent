import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import * as plist from 'plist';
import { createAbortError, runBoundedCommand } from '../shared/exec-utils.js';

const DEFAULT_MAX_ITEMS = 500;
const COMMAND_TIMEOUT_MS = 8000;

function sourceResult(items, source, reason = null, totalDetected = items?.length ?? 0) {
  return { items, source, reason, totalDetected, truncated: 0 };
}

function unavailableSource(source, error) {
  return sourceResult(null, source, `${source} enumeration failed: ${error.message}`, 0);
}

function appItem(name, version, binaryPath, source) {
  return {
    name: name || 'Unknown',
    version: version || null,
    serviceStatus: 'unknown',
    binaryPath: binaryPath || null,
    kind: 'application',
    source,
    correlated: false,
  };
}

function serviceItem(name, status, binaryPath, source, displayName = null) {
  return {
    name: displayName || name || 'Unknown',
    serviceName: name || null,
    version: null,
    serviceStatus: status,
    binaryPath: binaryPath || null,
    kind: 'service',
    source,
    correlated: false,
  };
}

function normalizeStatus(status) {
  const value = String(status ?? '').toLowerCase();
  if (['running', 'active'].includes(value)) return 'running';
  if (['stopped', 'inactive', 'failed', 'dead', 'exited'].includes(value)) return 'stopped';
  return 'unknown';
}

function parseDpkg(output) {
  return output.split(/\r?\n/).filter(Boolean).map((line) => {
    const [name, version] = line.split('\t');
    return appItem(name, version, null, 'dpkg');
  });
}

function parseRpm(output) {
  return output.split(/\r?\n/).filter(Boolean).map((line) => {
    const [name, version, architecture] = line.split('\t');
    return appItem(name, architecture ? `${version}.${architecture}` : version, null, 'rpm');
  });
}

async function collectLinuxApplications({ run, signal }) {
  try {
    const output = await run(
      'dpkg-query',
      ['-W', '-f=${binary:Package}\t${Version}\n'],
      { signal, timeoutMs: COMMAND_TIMEOUT_MS },
    );
    return sourceResult(parseDpkg(output), 'dpkg');
  } catch (dpkgError) {
    if (dpkgError.name === 'AbortError') throw dpkgError;
    try {
      const output = await run(
        'rpm',
        ['-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'],
        { signal, timeoutMs: COMMAND_TIMEOUT_MS },
      );
      return sourceResult(parseRpm(output), 'rpm');
    } catch (rpmError) {
      if (rpmError.name === 'AbortError') throw rpmError;
      return unavailableSource('dpkg/rpm', new Error(`dpkg: ${dpkgError.message}; rpm: ${rpmError.message}`));
    }
  }
}

async function collectLinuxServices({ run, signal }) {
  try {
    const output = await run(
      'systemctl',
      ['list-units', '--type=service', '--all', '--no-legend', '--no-pager', '--plain'],
      { signal, timeoutMs: COMMAND_TIMEOUT_MS },
    );
    const items = output.split(/\r?\n/).filter(Boolean).map((line) => {
      const [unit, , active, sub] = line.trim().split(/\s+/, 4);
      return serviceItem(unit?.replace(/\.service$/, ''), normalizeStatus(active === 'active' ? sub : active), null, 'systemctl');
    });
    return sourceResult(items, 'systemctl');
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return unavailableSource('systemctl', error);
  }
}

function parseJsonRecords(output) {
  if (!output) return [];
  const parsed = JSON.parse(output);
  return Array.isArray(parsed) ? parsed : [parsed];
}

function cleanWindowsExecutablePath(value) {
  if (!value) return null;
  const text = String(value).trim();
  const quoted = text.match(/^"([^"]+\.exe)"/i);
  if (quoted) return quoted[1];
  const unquoted = text.match(/^(.+?\.exe)(?:\s|,|$)/i);
  return unquoted?.[1] ?? null;
}

async function collectWindowsApplications({ run, signal }) {
  try {
    const script = [
      "$paths=@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');",
      'Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue',
      '| Where-Object {$_.DisplayName}',
      '| Select-Object DisplayName,DisplayVersion,InstallLocation,DisplayIcon',
      '| ConvertTo-Json -Compress',
    ].join(' ');
    const output = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      signal,
      timeoutMs: COMMAND_TIMEOUT_MS,
    });
    const items = parseJsonRecords(output).map((record) => appItem(
      record.DisplayName,
      record.DisplayVersion,
      cleanWindowsExecutablePath(record.DisplayIcon),
      'windows-uninstall-registry',
    ));
    return sourceResult(items, 'windows-uninstall-registry');
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return unavailableSource('windows-uninstall-registry', error);
  }
}

async function collectWindowsServices({ run, signal }) {
  try {
    const script = [
      '$paths=@{}; Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {$paths[$_.Name]=$_.PathName};',
      "Get-Service | Select-Object Name,DisplayName,@{Name='Status';Expression={$_.Status.ToString()}},@{Name='BinaryPathName';Expression={$paths[$_.Name]}} | ConvertTo-Json -Compress",
    ].join(' ');
    const output = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      signal,
      timeoutMs: COMMAND_TIMEOUT_MS,
    });
    const items = parseJsonRecords(output).map((record) => serviceItem(
      record.Name,
      normalizeStatus(record.Status),
      cleanWindowsExecutablePath(record.BinaryPathName),
      'powershell-get-service',
      record.DisplayName,
    ));
    return sourceResult(items, 'powershell-get-service');
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return unavailableSource('powershell-get-service', error);
  }
}

async function collectMacApplications({ readDirectory, readTextFile, signal, scanLimit }) {
  const bundles = [];
  const errors = [];
  for (const root of ['/Applications', '/System/Applications']) {
    try {
      const entries = await readDirectory(root, { withFileTypes: true });
      for (const entry of entries) {
        if ((entry.isDirectory?.() ?? true) && entry.name.endsWith('.app')) bundles.push(path.posix.join(root, entry.name));
      }
    } catch (error) {
      errors.push(`${root}: ${error.message}`);
    }
  }
  if (bundles.length === 0 && errors.length > 0) return unavailableSource('macos-app-bundles', new Error(errors.join('; ')));

  const items = [];
  for (const bundlePath of bundles.slice(0, scanLimit)) {
    if (signal?.aborted) throw createAbortError();
    const fallbackName = path.posix.basename(bundlePath, '.app');
    try {
      const metadata = plist.parse(await readTextFile(path.posix.join(bundlePath, 'Contents', 'Info.plist'), 'utf8')); 
      const executable = metadata.CFBundleExecutable
        ? path.posix.join(bundlePath, 'Contents', 'MacOS', metadata.CFBundleExecutable)
        : null;
      items.push(appItem(
        metadata.CFBundleDisplayName || metadata.CFBundleName || fallbackName,
        metadata.CFBundleShortVersionString || metadata.CFBundleVersion,
        executable,
        'macos-app-bundles',
      ));
    } catch (error) {
      errors.push(`${fallbackName}: ${error.message}`);
      items.push(appItem(fallbackName, null, null, 'macos-app-bundles'));
    }
  }
  return sourceResult(items, 'macos-app-bundles', errors.length ? errors.slice(0, 5).join('; ') : null, bundles.length);
}

async function collectMacServices({ run, signal }) {
  try {
    const output = await run('launchctl', ['list'], { signal, timeoutMs: COMMAND_TIMEOUT_MS });
    const items = output.split(/\r?\n/).slice(1).filter(Boolean).map((line) => {
      const [pid, status, label] = line.trim().split(/\s+/);
      return serviceItem(label, pid !== '-' && status === '0' ? 'running' : 'stopped', null, 'launchctl');
    });
    return sourceResult(items, 'launchctl');
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return unavailableSource('launchctl', error);
  }
}

function correlationKey(value) {
  return String(value ?? '')
    .toLowerCase()
    .replace(/\.(service|exe|app)$/g, '')
    .replace(/\b(server|service)\b/g, '')
    .replace(/[^a-z0-9]/g, '');
}

function correlate(applications, services) {
  if (!applications.items || !services.items) {
    return {
      attempted: false,
      successful: false,
      matchedCount: 0,
      reason: 'Application and service sources must both be available for correlation',
    };
  }
  const servicesByKey = new Map();
  for (const service of services.items) {
    for (const candidate of [service.serviceName, service.name]) {
      const key = correlationKey(candidate);
      if (key) servicesByKey.set(key, service);
    }
  }
  let matchedCount = 0;
  for (const application of applications.items) {
    const service = servicesByKey.get(correlationKey(application.name));
    if (!service) continue;
    application.correlated = true;
    application.serviceStatus = service.serviceStatus;
    service.correlated = true;
    matchedCount += 1;
  }
  return { attempted: true, successful: true, matchedCount, reason: null };
}

function capResults(applications, services, maxItems) {
  const appItems = applications.items ?? [];
  const serviceItems = services.items ?? [];
  let appLimit = Math.min(appItems.length, Math.ceil(maxItems / 2));
  let serviceLimit = Math.min(serviceItems.length, Math.floor(maxItems / 2));
  let remaining = maxItems - appLimit - serviceLimit;
  const extraApps = Math.min(remaining, appItems.length - appLimit);
  appLimit += extraApps;
  remaining -= extraApps;
  serviceLimit += Math.min(remaining, serviceItems.length - serviceLimit);

  if (applications.items) applications.items = appItems.slice(0, appLimit);
  if (services.items) services.items = serviceItems.slice(0, serviceLimit);
  applications.truncated = Math.max(0, applications.totalDetected - appLimit);
  services.truncated = Math.max(0, services.totalDetected - serviceLimit);

  return {
    maxItems,
    totalDetected: applications.totalDetected + services.totalDetected,
    returnedItems: appLimit + serviceLimit,
    truncated: applications.truncated + services.truncated,
  };
}

export function createAppsCollector({
  platform = process.platform,
  runCommand = runBoundedCommand,
  readDirectory = readdir,
  readTextFile = readFile,
} = {}) {
  return {
    name: 'apps',
    version: '1.0.0',
    async run(params = {}, context = {}) {
      if (context.signal?.aborted) throw createAbortError();
      const configuredMax = context.collectorConfig?.maxItems ?? params.maxItems ?? DEFAULT_MAX_ITEMS;
      const maxItems = Number.isInteger(configuredMax) && configuredMax > 0 ? configuredMax : DEFAULT_MAX_ITEMS;
      const dependencies = {
        run: runCommand,
        signal: context.signal,
        readDirectory,
        readTextFile,
        scanLimit: maxItems,
      };

      let applications;
      let services;
      if (platform === 'linux') {
        [applications, services] = await Promise.all([
          collectLinuxApplications(dependencies),
          collectLinuxServices(dependencies),
        ]);
      } else if (platform === 'win32') {
        [applications, services] = await Promise.all([
          collectWindowsApplications(dependencies),
          collectWindowsServices(dependencies),
        ]);
      } else if (platform === 'darwin') {
        [applications, services] = await Promise.all([
          collectMacApplications(dependencies),
          collectMacServices(dependencies),
        ]);
      } else {
        const error = new Error(`Unsupported platform "${platform}"`);
        applications = unavailableSource('applications', error);
        services = unavailableSource('services', error);
      }

      const correlation = correlate(applications, services);
      const summary = capResults(applications, services, maxItems);
      return { platform, summary, applications, services, correlation };
    },
  };
}

export const appsCollector = createAppsCollector();
export default appsCollector;
