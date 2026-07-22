import { readFile } from 'node:fs/promises';
import path from 'node:path';
import fastGlob from 'fast-glob';
import { runBoundedCommand } from '../shared/exec-utils.js';

const SSH_DEFAULTS = Object.freeze({
  permitrootlogin: 'prohibit-password',
  passwordauthentication: 'yes',
});

function abortError() {
  const error = new Error('Compliance collection was aborted');
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

function checkAbort(signal) {
  if (signal?.aborted) throw abortError();
}

function checked(value, extra = {}) {
  return { status: 'checked', value, reason: null, ...extra };
}

function failed(reason, extra = {}) {
  return { status: 'check-failed', value: null, reason, ...extra };
}

function notApplicable(reason, extra = {}) {
  return { status: 'not-applicable', value: null, reason, ...extra };
}

function tokenize(line) {
  return line.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)?.map((token) => token.replace(/^['"]|['"]$/g, '')) ?? [];
}

function stripComment(line) {
  let quote = null;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if ((character === '"' || character === "'") && line[index - 1] !== '\\') {
      quote = quote === character ? null : quote ?? character;
    }
    if (character === '#' && !quote) return line.slice(0, index);
  }
  return line;
}

async function defaultGlob(pattern) {
  return fastGlob(pattern.replaceAll('\\', '/'), {
    absolute: true,
    onlyFiles: true,
    unique: true,
    followSymbolicLinks: false,
    dot: true,
  });
}

export async function parseSshdConfiguration(entryPath, options = {}) {
  const {
    readTextFile = readFile,
    expandGlob = defaultGlob,
    signal,
  } = options;
  const values = {
    permitrootlogin: null,
    passwordauthentication: null,
  };
  const warnings = [];
  const filesProcessed = [];
  const activeFiles = new Set();

  async function processFile(filePath, required) {
    checkAbort(signal);
    const absolutePath = path.resolve(filePath);
    if (activeFiles.has(absolutePath)) {
      warnings.push({ path: absolutePath, reason: 'Recursive Include cycle was ignored' });
      return;
    }
    let content;
    try {
      content = await readTextFile(absolutePath, 'utf8');
    } catch (error) {
      if (error.name === 'AbortError') throw error;
      if (required) throw new Error(`Unable to read SSH server configuration ${absolutePath}: ${error.message}`, { cause: error });
      warnings.push({ path: absolutePath, reason: `Unable to read included SSH configuration: ${error.message}` });
      return;
    }

    activeFiles.add(absolutePath);
    filesProcessed.push(absolutePath);
    let inConditionalMatch = false;
    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      checkAbort(signal);
      const tokens = tokenize(stripComment(lines[index]).trim());
      if (tokens.length === 0) continue;
      const directive = tokens[0].toLowerCase();
      if (directive === 'match') {
        inConditionalMatch = true;
        continue;
      }
      if (inConditionalMatch) continue;
      if (directive === 'include') {
        for (const includePattern of tokens.slice(1)) {
          const resolvedPattern = path.isAbsolute(includePattern)
            ? includePattern
            : path.resolve(path.dirname(absolutePath), includePattern);
          let matches;
          try {
            matches = await expandGlob(resolvedPattern);
          } catch (error) {
            warnings.push({ path: resolvedPattern, reason: `Unable to resolve SSH Include pattern: ${error.message}` });
            continue;
          }
          for (const includedPath of [...matches].sort((left, right) => left.localeCompare(right))) {
            await processFile(includedPath, false);
          }
        }
        continue;
      }
      if (Object.hasOwn(values, directive) && values[directive] === null && tokens[1]) {
        values[directive] = {
          value: tokens[1].toLowerCase(),
          file: absolutePath,
          line: index + 1,
        };
      }
    }
    activeFiles.delete(absolutePath);
  }

  await processFile(entryPath, true);

  const toResult = (directive) => {
    const explicit = values[directive];
    if (explicit) {
      return checked(explicit.value, {
        source: 'explicit',
        file: explicit.file,
        line: explicit.line,
      });
    }
    if (warnings.length > 0) {
      return failed('The directive was not found, but one or more Include files could not be evaluated; the compiled default cannot be reported safely', {
        source: null,
      });
    }
    return checked(SSH_DEFAULTS[directive], {
      source: 'compiled-default',
      file: null,
      line: null,
      note: 'Not explicitly configured; reporting the modern OpenSSH compiled default',
    });
  };

  return {
    permitRootLogin: toResult('permitrootlogin'),
    passwordAuthentication: toResult('passwordauthentication'),
    filesProcessed,
    warnings,
  };
}

async function collectSshChecks(platform, options) {
  const configPath = platform === 'win32'
    ? options.windowsSshConfigPath
    : options.unixSshConfigPath;
  try {
    return await parseSshdConfiguration(configPath, options);
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    const missing = error.cause?.code === 'ENOENT';
    const result = platform === 'win32' && missing
      ? notApplicable('Windows OpenSSH Server configuration was not found; OpenSSH Server is not installed or not configured')
      : failed(error.message);
    return {
      permitRootLogin: { ...result },
      passwordAuthentication: { ...result },
      filesProcessed: [],
      warnings: [],
    };
  }
}

export function parseUfwStatus(output) {
  const match = output.match(/^Status:\s*(active|inactive)/im);
  if (!match) throw new Error('ufw output did not contain an active/inactive status');
  const ruleLines = output.split(/\r?\n/).filter((line) => /\bALLOW\b|\bDENY\b|\bREJECT\b|\bLIMIT\b/i.test(line));
  return { subsystem: 'ufw', active: match[1].toLowerCase() === 'active', ruleCount: ruleLines.length, reason: null };
}

export function parseFirewalldStatus(output) {
  const state = output.trim().toLowerCase();
  if (!['running', 'not running'].includes(state)) throw new Error(`Unexpected firewalld state: ${output}`);
  return { subsystem: 'firewalld', active: state === 'running', ruleCount: null, reason: null };
}

export function parseNftablesRules(output) {
  const lines = output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const ruleCount = lines.filter((line) => !/^(table|chain)\b|^[{}]$|^type\b|^policy\b/i.test(line)).length;
  return { subsystem: 'nftables', active: ruleCount > 0, ruleCount, reason: null };
}

export function parseIptablesRules(output) {
  const lines = output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const nonAcceptPolicy = lines.some((line) => /^Chain\s+\S+\s+\(policy\s+(?!ACCEPT\b)/i.test(line));
  const ruleCount = lines.filter((line) => !/^Chain\s|^target\s|^pkts\s/i.test(line)).length;
  return { subsystem: 'iptables', active: nonAcceptPolicy || ruleCount > 0, ruleCount, reason: null };
}

async function collectLinuxFirewall({ runCommand, signal, timeoutMs }) {
  const attempts = [];
  for (const check of [
    ['ufw', ['status'], parseUfwStatus],
    ['firewall-cmd', ['--state'], parseFirewalldStatus],
    ['nft', ['list', 'ruleset'], parseNftablesRules],
    ['iptables', ['-L', '-n'], parseIptablesRules],
  ]) {
    const [command, args, parser] = check;
    try {
      const output = await runCommand(command, args, { signal, timeoutMs, maxOutputBytes: 2 * 1024 * 1024 });
      return { status: 'checked', ...parser(output) };
    } catch (error) {
      if (error.name === 'AbortError') throw error;
      attempts.push(`${command}: ${error.message}`);
    }
  }
  return {
    status: 'check-failed',
    subsystem: null,
    active: null,
    ruleCount: null,
    reason: `No supported firewall subsystem could be queried (${attempts.join('; ')})`,
  };
}

export function parseMacFirewallStatus(output) {
  const enabled = /State\s*=\s*1|enabled/i.test(output);
  const disabled = /State\s*=\s*0|disabled/i.test(output);
  if (!enabled && !disabled) throw new Error('socketfilterfw output did not contain a recognized global state');
  return { status: 'checked', subsystem: 'macos-application-firewall', active: enabled, ruleCount: null, reason: null };
}

async function collectMacFirewall({ runCommand, signal, timeoutMs }) {
  try {
    const output = await runCommand(
      '/usr/libexec/ApplicationFirewall/socketfilterfw',
      ['--getglobalstate'],
      { signal, timeoutMs, maxOutputBytes: 64 * 1024 },
    );
    return parseMacFirewallStatus(output);
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return { status: 'check-failed', subsystem: 'macos-application-firewall', active: null, ruleCount: null, reason: error.message };
  }
}

export function parseWindowsFirewallProfiles(output) {
  const parsed = JSON.parse(output);
  const records = Array.isArray(parsed) ? parsed : [parsed];
  const profiles = records.map((record) => ({ name: record.Name, enabled: Boolean(record.Enabled) }));
  return {
    status: 'checked',
    subsystem: 'windows-defender-firewall',
    active: profiles.length > 0 ? profiles.every((profile) => profile.enabled) : null,
    ruleCount: null,
    profiles,
    reason: null,
  };
}

async function collectWindowsFirewall({ runCommand, signal, timeoutMs }) {
  const script = 'Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress';
  try {
    const output = await runCommand('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      signal,
      timeoutMs,
      maxOutputBytes: 256 * 1024,
    });
    return parseWindowsFirewallProfiles(output);
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return { status: 'check-failed', subsystem: 'windows-defender-firewall', active: null, ruleCount: null, profiles: null, reason: error.message };
  }
}

export const UAC_LEVELS = Object.freeze([
  { level: 4, name: 'Always notify', EnableLUA: 1, ConsentPromptBehaviorAdmin: 2, PromptOnSecureDesktop: 1 },
  { level: 3, name: 'Notify only when apps try to make changes (default)', EnableLUA: 1, ConsentPromptBehaviorAdmin: 5, PromptOnSecureDesktop: 1 },
  { level: 2, name: 'Notify only when apps try to make changes (do not dim desktop)', EnableLUA: 1, ConsentPromptBehaviorAdmin: 5, PromptOnSecureDesktop: 0 },
  { level: 1, name: 'Never notify', EnableLUA: 1, ConsentPromptBehaviorAdmin: 0, PromptOnSecureDesktop: 0 },
]);

export function mapUacLevel(values) {
  const normalized = {
    EnableLUA: Number(values.EnableLUA),
    ConsentPromptBehaviorAdmin: Number(values.ConsentPromptBehaviorAdmin),
    PromptOnSecureDesktop: Number(values.PromptOnSecureDesktop),
  };
  if (normalized.EnableLUA === 0) {
    return checked({
      level: 1,
      name: 'Never notify',
      uacEnabled: false,
      registryValues: normalized,
    }, { source: 'windows-registry', note: 'EnableLUA=0 disables Admin Approval Mode and all related UAC policies' });
  }
  const match = UAC_LEVELS.find((level) => level.EnableLUA === normalized.EnableLUA
    && level.ConsentPromptBehaviorAdmin === normalized.ConsentPromptBehaviorAdmin
    && level.PromptOnSecureDesktop === normalized.PromptOnSecureDesktop);
  if (!match) {
    return checked({
      level: null,
      name: 'Custom policy combination',
      uacEnabled: normalized.EnableLUA === 1,
      registryValues: normalized,
    }, { source: 'windows-registry', note: 'The registry values do not match one of the four standard Control Panel slider presets' });
  }
  return checked({
    level: match.level,
    name: match.name,
    uacEnabled: true,
    registryValues: normalized,
  }, { source: 'windows-registry' });
}

async function collectWindowsUac({ runCommand, signal, timeoutMs }) {
  const script = [
    "$value=Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'",
    '$value | Select-Object ConsentPromptBehaviorAdmin,PromptOnSecureDesktop,EnableLUA | ConvertTo-Json -Compress',
  ].join('; ');
  try {
    const output = await runCommand('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      signal,
      timeoutMs,
      maxOutputBytes: 64 * 1024,
    });
    return mapUacLevel(JSON.parse(output));
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return failed(`Unable to read Windows UAC policy values: ${error.message}`);
  }
}

export function createComplianceChecksCollector({
  platform = process.platform,
  runCommand = runBoundedCommand,
  readTextFile = readFile,
  expandGlob = defaultGlob,
  unixSshConfigPath = '/etc/ssh/sshd_config',
  windowsSshConfigPath = 'C:\\ProgramData\\ssh\\sshd_config',
} = {}) {
  return {
    name: 'compliance-checks',
    version: '1.0.0',
    async run(_params = {}, context = {}) {
      const timeoutMs = context.collectorConfig?.commandTimeoutMs ?? 8000;
      const common = {
        runCommand,
        readTextFile,
        expandGlob,
        signal: context.signal,
        timeoutMs,
        unixSshConfigPath,
        windowsSshConfigPath,
      };
      checkAbort(context.signal);
      const sshPromise = collectSshChecks(platform, common);
      let firewallPromise;
      let uacPromise;
      if (platform === 'linux') {
        firewallPromise = collectLinuxFirewall(common);
        uacPromise = Promise.resolve(notApplicable('UAC applies only to Windows'));
      } else if (platform === 'darwin') {
        firewallPromise = collectMacFirewall(common);
        uacPromise = Promise.resolve(notApplicable('UAC applies only to Windows'));
      } else if (platform === 'win32') {
        firewallPromise = collectWindowsFirewall(common);
        uacPromise = collectWindowsUac(common);
      } else {
        firewallPromise = Promise.resolve(notApplicable(`Firewall check is not implemented for platform "${platform}"`, {
          subsystem: null,
          active: null,
          ruleCount: null,
        }));
        uacPromise = Promise.resolve(notApplicable('UAC applies only to Windows'));
      }
      const [ssh, firewall, uac] = await Promise.all([sshPromise, firewallPromise, uacPromise]);
      return { platform, ssh, firewall, uac };
    },
  };
}

export const complianceChecksCollector = createComplianceChecksCollector();
export default complianceChecksCollector;
