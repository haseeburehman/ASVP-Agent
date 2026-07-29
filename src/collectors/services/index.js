import { createAbortError, runBoundedCommand } from '../shared/exec-utils.js';

const DEFAULT_MAX_ITEMS = 250;
const COMMAND_TIMEOUT_MS = 10000;
const COMMAND_OPTIONS = { timeoutMs: COMMAND_TIMEOUT_MS, maxOutputBytes: 2 * 1024 * 1024 };

function cleanString(value) {
  const text = value === null || value === undefined ? '' : String(value).trim();
  return text || null;
}

function availability(value, reason = null) { return { status: value == null ? 'unavailable' : 'available', reason: value == null ? reason : null }; }
function normalizeStartup(value) {
  const normalized = cleanString(value)?.toLowerCase();
  if (['auto', 'automatic', 'enabled', 'enabled-runtime'].includes(normalized)) return 'automatic';
  if (['manual', 'static', 'indirect', 'generated', 'transient'].includes(normalized)) return 'manual';
  if (['disabled', 'masked'].includes(normalized)) return 'disabled';
  return normalized ?? null;
}
function executablePath(value) {
  const text = cleanString(value); if (!text) return null;
  return text.match(/^"([^"]+)"/)?.[1] ?? text.match(/^\S+/)?.[0] ?? null;
}
function serviceItem({ name, displayName, status = 'running', startupType, binaryPath, runningUser, version, unavailableReason = 'The platform source did not expose this field' }) {
  const item = {
    name: cleanString(name) ?? 'Unknown',
    displayName: cleanString(displayName),
    status,
    startupType: normalizeStartup(startupType),
    binaryPath: executablePath(binaryPath),
    runningUser: cleanString(runningUser),
    version: cleanString(version),
  };
  item.fieldAvailability = {
    displayName: availability(item.displayName, unavailableReason), startupType: availability(item.startupType, unavailableReason),
    binaryPath: availability(item.binaryPath, unavailableReason), runningUser: availability(item.runningUser, unavailableReason),
    version: availability(item.version, 'Version was not cheaply attributable from the service enumeration source'),
  };
  return item;
}

function jsonRecords(output) {
  if (!cleanString(output)) return [];
  const parsed = JSON.parse(output);
  return Array.isArray(parsed) ? parsed : [parsed];
}

function parseWindows(output) {
  return jsonRecords(output).map((record) => serviceItem({
    name: record.Name,
    displayName: record.DisplayName,
    status: 'running',
    startupType: record.StartMode,
    binaryPath: record.PathName,
    runningUser: record.StartName,
    version: null,
  }));
}

function parseSystemdBlocks(output) {
  if (!cleanString(output)) return [];
  return output.split(/\r?\n\r?\n/).map((block) => Object.fromEntries(
    block.split(/\r?\n/).filter(Boolean).map((line) => {
      const separator = line.indexOf('=');
      return separator < 0 ? [line, ''] : [line.slice(0, separator), line.slice(separator + 1)];
    }),
  ));
}

function systemdBinaryPath(execStart) {
  const value = cleanString(execStart);
  if (!value) return null;
  return value.match(/(?:^|[;{]\s*)path=([^; }]+)/)?.[1] ?? null;
}

function parseLinux(output) {
  return parseSystemdBlocks(output)
    .filter((record) => record.ActiveState === 'active' && record.SubState === 'running')
    .map((record) => serviceItem({
      name: cleanString(record.Id)?.replace(/\.service$/, ''),
      displayName: record.Description,
      status: 'running',
      startupType: record.UnitFileState,
      binaryPath: systemdBinaryPath(record.ExecStart),
      runningUser: record.User,
      version: null,
    }));
}

function parseMacOS(output) {
  return output.split(/\r?\n/).slice(1).filter(Boolean).flatMap((line) => {
    const columns = line.trim().split(/\s+/);
    const pid = columns[0];
    const label = columns.slice(2).join(' ');
    if (!label || pid === '-' || !/^\d+$/.test(pid)) return [];
    return [serviceItem({
      name: label,
      displayName: label,
      status: 'running',
      startupType: null,
      binaryPath: null,
      runningUser: null,
      version: null,
      unavailableReason: 'launchctl list exposes only PID, exit status, and label',
    })];
  });
}

const WINDOWS_SCRIPT = [
  '$serviceStatus=@{};',
  "Get-Service -ErrorAction Stop | ForEach-Object {$serviceStatus[$_.Name]=@{DisplayName=$_.DisplayName;Status=$_.Status.ToString()}};",
  "Get-CimInstance Win32_Service -Filter \"State='Running'\" -ErrorAction Stop | ForEach-Object {",
  '$status=$serviceStatus[$_.Name];',
  '[pscustomobject]@{Name=$_.Name;DisplayName=if($status){$status.DisplayName}else{$_.DisplayName};Status=if($status){$status.Status}else{$_.State};StartMode=$_.StartMode;PathName=$_.PathName;StartName=$_.StartName}',
  '} | ConvertTo-Json -Compress',
].join(' ');

const PLATFORM_COMMANDS = {
  win32: {
    executable: 'powershell.exe',
    args: ['-NoProfile', '-NonInteractive', '-Command', WINDOWS_SCRIPT],
    source: 'Win32_Service/Get-Service',
    parse: parseWindows,
  },
  linux: {
    executable: 'systemctl',
    args: ['show', '--type=service', '--state=running', '--all', '--no-pager', '--property=Id,Description,ActiveState,SubState,UnitFileState,ExecStart,User'],
    source: 'systemctl',
    parse: parseLinux,
  },
  darwin: {
    executable: 'launchctl',
    args: ['list'],
    source: 'launchctl',
    parse: parseMacOS,
  },
};

function isPrivilegeError(error) {
  return /access (?:is )?denied|permission denied|not permitted|privilege|unauthorized|eacces|eperm/i.test(error?.message ?? '');
}

export function createServicesCollector({
  platform = process.platform,
  runCommand = runBoundedCommand,
} = {}) {
  return {
    name: 'services',
    version: '1.0.0',
    async run(params = {}, context = {}) {
      if (context.signal?.aborted) throw createAbortError('Services collection was aborted');
      const configuredMax = context.collectorConfig?.maxItems ?? params.maxItems ?? DEFAULT_MAX_ITEMS;
      const maxItems = Number.isInteger(configuredMax) && configuredMax > 0 ? configuredMax : DEFAULT_MAX_ITEMS;
      const command = PLATFORM_COMMANDS[platform];
      if (!command) {
        return {
          platform,
          source: null,
          services: null,
          summary: { maxItems, totalDetected: 0, returnedItems: 0, truncated: 0 },
          insufficientPrivilege: false,
          reason: `Running services inventory is unsupported on platform "${platform}"`,
        };
      }

      try {
        const output = await runCommand(command.executable, command.args, {
          ...COMMAND_OPTIONS,
          signal: context.signal,
        });
        if (context.signal?.aborted) throw createAbortError('Services collection was aborted');
        const allServices = command.parse(output).sort((left, right) => left.name.localeCompare(right.name));
        const services = allServices.slice(0, maxItems);
        return {
          platform,
          source: command.source,
          services,
          summary: {
            maxItems,
            totalDetected: allServices.length,
            returnedItems: services.length,
            truncated: allServices.length - services.length,
          },
          insufficientPrivilege: false,
          reason: null,
        };
      } catch (error) {
        if (error.name === 'AbortError' || context.signal?.aborted) {
          throw createAbortError('Services collection was aborted');
        }
        const insufficientPrivilege = isPrivilegeError(error);
        return {
          platform,
          source: command.source,
          services: null,
          summary: { maxItems, totalDetected: 0, returnedItems: 0, truncated: 0 },
          insufficientPrivilege,
          reason: insufficientPrivilege
            ? `Unable to enumerate running services due to insufficient privilege: ${error.message}`
            : `Unable to enumerate running services: ${error.message}`,
        };
      }
    },
  };
}

export const servicesCollector = createServicesCollector();
export default servicesCollector;
