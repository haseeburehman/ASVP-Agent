import { createAbortError, runBoundedCommand } from '../shared/exec-utils.js';

const COMMAND_TIMEOUT_MS = 8000;

const WINDOWS_SCRIPT = [
  "$result=[ordered]@{SecurityCenter=$null;Defender=$null;Preference=$null;Errors=@()};",
  "try {$result.SecurityCenter=@(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntivirusProduct -ErrorAction Stop | Select-Object displayName,productState,pathToSignedProductExe)} catch {$result.Errors+=('SecurityCenter2: '+$_.Exception.Message)};",
  "try {$result.Defender=Get-MpComputerStatus -ErrorAction Stop | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureVersion,AntivirusSignatureLastUpdated} catch {$result.Errors+=('Get-MpComputerStatus: '+$_.Exception.Message)};",
  "if ($null -eq $result.Defender) {try {$result.Preference=Get-MpPreference -ErrorAction Stop | Select-Object DisableRealtimeMonitoring} catch {$result.Errors+=('Get-MpPreference: '+$_.Exception.Message)}};",
  '$result | ConvertTo-Json -Compress -Depth 4',
].join(' ');

const LINUX_PRODUCTS = [
  { name: 'ClamAV', patterns: [/clamd/i, /clamav/i, /freshclam/i] },
  { name: 'Microsoft Defender for Endpoint', patterns: [/mdatp/i] },
  { name: 'CrowdStrike Falcon', patterns: [/falcon-sensor/i, /falconctl/i] },
  { name: 'SentinelOne', patterns: [/sentinelone/i, /sentinel-agent/i, /sentinelctl/i] },
  { name: 'Sophos', patterns: [/sophos/i, /sav-protect/i] },
  { name: 'ESET', patterns: [/esets/i, /eea/i, /eav/i] },
  { name: 'Trend Micro', patterns: [/ds_agent/i, /trendmicro/i] },
  { name: 'Trellix/McAfee', patterns: [/masvc/i, /mfetpd/i, /mcafee/i] },
  { name: 'Bitdefender', patterns: [/bdsec/i, /bitdefender/i] },
  { name: 'Elastic Endpoint', patterns: [/elastic-endpoint/i] },
];

function result(platform, status, products, checks, reason = null) {
  return { platform, status, products, checks, reason };
}

function parseJson(output) {
  return output ? JSON.parse(output) : null;
}

function windowsProduct(record) {
  const state = Number(record.productState ?? record.ProductState);
  const validState = Number.isInteger(state);
  return {
    name: record.displayName ?? record.DisplayName ?? 'Unknown antivirus',
    enabled: validState ? ((state >> 8) & 0xff) === 0x10 : null,
    upToDate: validState ? (state & 0xff) === 0 : null,
    version: null,
    source: 'SecurityCenter2',
  };
}

async function collectWindows({ run, signal }) {
  try {
    const output = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', WINDOWS_SCRIPT], {
      signal,
      timeoutMs: COMMAND_TIMEOUT_MS,
    });
    const data = parseJson(output) ?? {};
    const records = data.SecurityCenter == null
      ? []
      : (Array.isArray(data.SecurityCenter) ? data.SecurityCenter : [data.SecurityCenter]);
    const products = records.map(windowsProduct);

    if (data.Defender) {
      const defender = {
        name: 'Microsoft Defender Antivirus',
        enabled: data.Defender.AntivirusEnabled ?? data.Defender.antivirusEnabled ?? null,
        upToDate: data.Defender.AntivirusSignatureLastUpdated != null ? true : null,
        version: data.Defender.AntivirusSignatureVersion ?? null,
        lastDefinitionUpdateTime: data.Defender.AntivirusSignatureLastUpdated ?? null,
        realTimeProtectionEnabled: data.Defender.RealTimeProtectionEnabled ?? null,
        source: 'Get-MpComputerStatus',
      };
      const existing = products.find((item) => /defender/i.test(item.name));
      if (existing) Object.assign(existing, defender);
      else products.push(defender);
    } else if (data.Preference) {
      products.push({
        name: 'Microsoft Defender Antivirus',
        enabled: data.Preference.DisableRealtimeMonitoring == null
          ? null
          : !data.Preference.DisableRealtimeMonitoring,
        upToDate: null,
        version: null,
        source: 'Get-MpPreference',
      });
    }

    const checks = { securityCenter2: records.length > 0, defenderStatus: data.Defender != null, defenderPreference: data.Preference != null };
    if (products.some((item) => item.enabled === true)) return result('win32', 'protected', products, checks);
    if (products.length > 0 && products.every((item) => item.enabled === false)) return result('win32', 'unprotected', products, checks, 'Antivirus products were found but none report enabled protection');
    return result('win32', 'undetermined', products, checks, (data.Errors ?? []).join('; ') || 'No conclusive antivirus status was returned');
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return result('win32', 'undetermined', [], {}, `Windows antivirus checks failed: ${error.message}`);
  }
}

function detectLinuxProducts(text) {
  return LINUX_PRODUCTS.filter(({ patterns }) => patterns.some((pattern) => pattern.test(text))).map(({ name }) => ({
    name,
    enabled: true,
    upToDate: null,
    version: null,
    source: 'service/process-inventory',
  }));
}

async function collectLinux({ run, signal }) {
  const outputs = [];
  const checks = {};
  const errors = [];
  for (const [key, executable, args] of [
    ['services', 'systemctl', ['list-unit-files', '--type=service', '--no-legend', '--no-pager', '--plain']],
    ['processes', 'ps', ['-eo', 'comm=']],
  ]) {
    try {
      outputs.push(await run(executable, args, { signal, timeoutMs: COMMAND_TIMEOUT_MS }));
      checks[key] = true;
    } catch (error) {
      if (error.name === 'AbortError') throw error;
      checks[key] = false;
      errors.push(`${key}: ${error.message}`);
    }
  }
  const products = detectLinuxProducts(outputs.join('\n'));
  if (products.length > 0) return result('linux', 'protected', products, checks, errors.length ? errors.join('; ') : null);
  if (outputs.length > 0) return result('linux', 'unprotected', [], checks, 'No supported antivirus or EDR product was detected in available local inventories');
  return result('linux', 'undetermined', [], checks, `Unable to inspect local services or processes (${errors.join('; ')})`);
}

async function collectMacOs({ run, signal }) {
  const checks = { gatekeeper: null, xprotect: null };
  const products = [];
  const errors = [];
  try {
    const output = await run('/usr/sbin/spctl', ['--status'], { signal, timeoutMs: COMMAND_TIMEOUT_MS });
    checks.gatekeeper = /assessments enabled/i.test(output);
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    errors.push(`Gatekeeper: ${error.message}`);
  }
  try {
    const output = await run('/usr/sbin/pkgutil', ['--pkg-info', 'com.apple.pkg.XProtectPlistConfigData'], { signal, timeoutMs: COMMAND_TIMEOUT_MS });
    const version = output.match(/^version:\s*(.+)$/im)?.[1]?.trim() ?? null;
    checks.xprotect = true;
    products.push({ name: 'Apple XProtect', enabled: true, upToDate: null, version, source: 'pkgutil' });
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    errors.push(`XProtect: ${error.message}`);
  }
  if (checks.gatekeeper === true && checks.xprotect === true) return result('darwin', 'protected', products, checks);
  if (checks.gatekeeper === false && checks.xprotect === true) return result('darwin', 'unprotected', products, checks, 'Gatekeeper assessments are disabled');
  return result('darwin', 'undetermined', products, checks, errors.join('; ') || 'Built-in protection status was inconclusive');
}

export function createAntivirusStatusCollector({
  platform = process.platform,
  runCommand = runBoundedCommand,
} = {}) {
  return {
    name: 'antivirus-status',
    version: '1.0.0',
    async run(_params = {}, context = {}) {
      if (context.signal?.aborted) throw createAbortError('Antivirus status collection was aborted');
      const dependencies = { run: runCommand, signal: context.signal };
      if (platform === 'win32') return collectWindows(dependencies);
      if (platform === 'linux') return collectLinux(dependencies);
      if (platform === 'darwin') return collectMacOs(dependencies);
      return result(platform, 'undetermined', [], {}, `Unsupported platform "${platform}"`);
    },
  };
}

export const antivirusStatusCollector = createAntivirusStatusCollector();
export default antivirusStatusCollector;
