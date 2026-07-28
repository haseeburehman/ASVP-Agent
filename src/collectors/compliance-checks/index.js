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

const PART_TWO_MAX_OUTPUT_BYTES = 256 * 1024;

function privilegeFailure(error) {
  return error?.code === 'EACCES'
    || error?.code === 'EPERM'
    || /access (?:is )?denied|permission denied|not permitted|requires? (?:administrator|root)|insufficient privilege/i.test(error?.message ?? '');
}

function posture(value, source) {
  return { status: 'available', value, reasonCode: null, reason: null, source };
}

function postureFailure(error, source, subject) {
  const status = privilegeFailure(error) ? 'insufficient_privilege' : 'unavailable';
  return {
    status,
    value: null,
    reasonCode: status,
    reason: `${subject} is ${status === 'insufficient_privilege' ? 'not accessible with current privileges' : 'unavailable'}: ${error.message}`,
    source,
  };
}

async function fixedCommand(options, executable, args, parser, source, subject) {
  try {
    const output = await options.runCommand(executable, args, {
      signal: options.signal,
      timeoutMs: options.timeoutMs,
      maxOutputBytes: PART_TWO_MAX_OUTPUT_BYTES,
    });
    return posture(parser(output), source);
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return postureFailure(error, source, subject);
  }
}

async function fixedRead(options, filePath, parser, subject) {
  try {
    checkAbort(options.signal);
    const output = await options.readTextFile(filePath, 'utf8');
    if (Buffer.byteLength(output) > PART_TWO_MAX_OUTPUT_BYTES) {
      const error = new Error(`file exceeded the ${PART_TWO_MAX_OUTPUT_BYTES}-byte safety limit`);
      error.code = 'FILE_OUTPUT_LIMIT';
      throw error;
    }
    return posture(parser(output), filePath);
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return postureFailure(error, filePath, subject);
  }
}

function integer(value) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : null;
}

export function parseLoginDefs(output) {
  const values = {};
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(/^\s*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|PASS_MIN_LEN)\s+(\d+)/);
    if (match) values[match[1]] = integer(match[2]);
  }
  if (Object.keys(values).length === 0) throw new Error('login.defs contained no password policy values');
  return {
    maximumAgeDays: values.PASS_MAX_DAYS ?? null,
    minimumAgeDays: values.PASS_MIN_DAYS ?? null,
    warningAgeDays: values.PASS_WARN_AGE ?? null,
    minimumLength: values.PASS_MIN_LEN ?? null,
  };
}

export function parseWindowsPasswordPolicy(output) {
  const parsed = JSON.parse(output);
  if (parsed.minimumLength == null && parsed.complexityEnabled == null && parsed.maximumAgeDays == null) {
    throw new Error('local security policy contained no password policy values');
  }
  return parsed;
}

export function parsePamLockout(output) {
  const lines = output.split(/\r?\n/).map((item) => stripComment(item).trim());
  const faillockLine = lines.find((item) => /\bpam_faillock\.so\b/i.test(item));
  const tallyLine = lines.find((item) => /\bpam_tally2\.so\b/i.test(item));
  const line = faillockLine ?? tallyLine;
  if (!line) throw new Error('PAM authentication stack contained no pam_faillock or pam_tally2 rule');
  const moduleName = faillockLine ? 'pam_faillock' : 'pam_tally2';
  const option = (name) => {
    const match = line.match(new RegExp(`(?:^|\\s)${name}=(\\d+)(?=\\s|$)`, 'i'));
    return match ? integer(match[1]) : null;
  };
  return {
    lockoutEnabled: true,
    failureThreshold: option('deny'),
    failureWindowSeconds: moduleName === 'pam_faillock' ? option('fail_interval') : null,
    unlockAfterSeconds: option('unlock_time'),
    module: moduleName,
    configuredLine: line,
  };
}

export function parseMacLockoutPolicy(output) {
  const value = (names) => {
    for (const name of names) {
      const match = output.match(new RegExp(`(?:<key>\\s*${name}\\s*</key>\\s*<integer>|\\b${name}\\s*[=:]\\s*)(\\d+)`, 'i'));
      if (match) return integer(match[1]);
    }
    return null;
  };
  const failureThreshold = value(['maxFailedLoginAttempts', 'policyAttributeMaximumFailedAuthentications']);
  const resetMinutes = value(['minutesUntilFailedLoginReset', 'policyAttributeMinutesUntilFailedAuthenticationReset']);
  const unlockAfterSeconds = value(['autoEnableInSeconds', 'policyAttributeAutoEnableInSeconds']);
  if (failureThreshold == null) throw new Error('pwpolicy output contained no reliable account lockout keys');
  return {
    lockoutEnabled: failureThreshold > 0,
    failureThreshold,
    failureWindowSeconds: resetMinutes == null ? null : resetMinutes * 60,
    unlockAfterSeconds,
  };
}

export function parsePwQuality(output) {
  const values = {};
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(/^\s*(minlen|dcredit|ucredit|lcredit|ocredit)\s*=\s*(-?\d+)/i);
    if (match) values[match[1].toLowerCase()] = integer(match[2]);
  }
  return {
    minimumLength: values.minlen ?? null,
    digitCredit: values.dcredit ?? null,
    uppercaseCredit: values.ucredit ?? null,
    lowercaseCredit: values.lcredit ?? null,
    otherCredit: values.ocredit ?? null,
  };
}

function parseJson(output) {
  return JSON.parse(output);
}

function combinePostures(results, source, subject, value) {
  const privilege = results.find((result) => result.status === 'insufficient_privilege');
  if (privilege) return postureFailure(Object.assign(new Error(privilege.reason), { code: 'EACCES' }), source, subject);
  if (results.every((result) => result.status === 'unavailable')) {
    return { status: 'unavailable', value: null, reasonCode: 'unavailable', reason: `${subject} is unavailable: ${results.map((result) => result.reason).join('; ')}`, source };
  }
  return posture(value(results), source);
}

async function collectWindowsPartTwo(options) {
  const powerShell = (script, parser, source, subject) => fixedCommand(
    options,
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', script],
    parser,
    source,
    subject,
  );
  const screenScript = "$policy='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop';$user='HKCU:\\Control Panel\\Desktop';$p=if(Test-Path $policy){Get-ItemProperty $policy}else{Get-ItemProperty $user};[pscustomobject]@{enabled=$p.ScreenSaveActive -eq '1';passwordOnResume=$p.ScreenSaverIsSecure -eq '1';timeoutSeconds=[int]$p.ScreenSaveTimeOut;scope=if(Test-Path $policy){'machine-policy'}else{'service-account-user'}}|ConvertTo-Json -Compress";
  const passwordScript = "$f=Join-Path ([IO.Path]::GetTempPath()) ('asvp-secpol-'+[guid]::NewGuid()+'.inf');try{secedit.exe /export /cfg $f /areas SECURITYPOLICY|Out-Null;$v=@{};Get-Content $f|ForEach-Object{if($_ -match '^([^;][^=]+)=(.*)$'){$v[$matches[1].Trim()]=$matches[2].Trim()}};$threshold=if($null -eq $v.LockoutBadCount){$null}else{[int]$v.LockoutBadCount};$duration=if($null -eq $v.LockoutDuration){$null}else{[int]$v.LockoutDuration};$reset=if($null -eq $v.ResetLockoutCount){$null}else{[int]$v.ResetLockoutCount};[pscustomobject]@{minimumLength=[int]$v.MinimumPasswordLength;complexityEnabled=$v.PasswordComplexity -eq '1';maximumAgeDays=[int]$v.MaximumPasswordAge;minimumAgeDays=[int]$v.MinimumPasswordAge;historyLength=[int]$v.PasswordHistorySize;lockoutThreshold=$threshold;lockoutDurationMinutes=$duration;lockoutResetMinutes=$reset}|ConvertTo-Json -Compress}finally{Remove-Item $f -Force -ErrorAction SilentlyContinue}";
  const [screenLock, passwordPolicy, secureBoot, tpm, auditLogging] = await Promise.all([
    powerShell(screenScript, parseJson, 'Windows machine policy or service-account user policy', 'Screen-lock policy'),
    powerShell(passwordScript, parseWindowsPasswordPolicy, 'secedit local security policy export', 'Password policy'),
    powerShell('[pscustomobject]@{enabled=[bool](Confirm-SecureBootUEFI)}|ConvertTo-Json -Compress', parseJson, 'Confirm-SecureBootUEFI', 'Secure Boot status'),
    powerShell('Get-Tpm | Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,ManufacturerIdTxt,ManufacturerVersion | ConvertTo-Json -Compress', parseJson, 'Get-Tpm', 'TPM status'),
    fixedCommand(options, 'auditpol.exe', ['/get', '/category:*'], (output) => ({ configured: /Success|Failure/i.test(output), output }), 'auditpol /get /category:*', 'Audit policy'),
  ]);
  const lockoutValuesAvailable = passwordPolicy.status === 'available'
    && [passwordPolicy.value.lockoutThreshold, passwordPolicy.value.lockoutDurationMinutes, passwordPolicy.value.lockoutResetMinutes]
      .every((value) => Number.isFinite(value));
  const accountLockout = lockoutValuesAvailable
    ? posture({
      lockoutEnabled: passwordPolicy.value.lockoutThreshold > 0,
      failureThreshold: passwordPolicy.value.lockoutThreshold,
      failureWindowSeconds: passwordPolicy.value.lockoutResetMinutes * 60,
      unlockAfterSeconds: passwordPolicy.value.lockoutDurationMinutes * 60,
    }, passwordPolicy.source)
    : passwordPolicy.status === 'available'
      ? postureFailure(new Error('secedit output contained no complete account lockout policy'), passwordPolicy.source, 'Account lockout policy')
      : { ...passwordPolicy };
  return [screenLock, { ...passwordPolicy, accountLockout }, secureBoot, tpm, auditLogging];
}

async function collectLinuxPartTwo(options) {
  const screenResults = await Promise.all([
    fixedCommand(options, 'gsettings', ['get', 'org.gnome.desktop.session', 'idle-delay'], (output) => output.trim(), 'gsettings idle-delay', 'GNOME idle delay'),
    fixedCommand(options, 'gsettings', ['get', 'org.gnome.desktop.screensaver', 'lock-enabled'], (output) => output.trim() === 'true', 'gsettings lock-enabled', 'GNOME lock enabled'),
    fixedCommand(options, 'gsettings', ['get', 'org.gnome.desktop.screensaver', 'lock-delay'], (output) => output.trim(), 'gsettings lock-delay', 'GNOME lock delay'),
  ]);
  const passwordResults = await Promise.all([
    fixedRead(options, '/etc/login.defs', parseLoginDefs, 'Password age policy'),
    fixedRead(options, '/etc/security/pwquality.conf', parsePwQuality, 'PAM password quality policy'),
    fixedRead(options, '/etc/pam.d/common-password', (output) => ({ pwqualityEnabled: /pam_pwquality\.so/.test(output), configuredLine: output.split(/\r?\n/).find((line) => /pam_pwquality\.so/.test(line))?.trim() ?? null }), 'PAM password quality stack'),
  ]);
  const screenLock = combinePostures(screenResults, 'GNOME gsettings', 'Screen-lock policy', ([idle, enabled, delay]) => ({ idleDelay: idle.value, lockEnabled: enabled.value, lockDelay: delay.value }));
  const passwordPolicy = combinePostures(passwordResults, '/etc/login.defs and PAM password-quality configuration', 'Password policy', ([login, quality, pam]) => ({ loginDefaults: login.value, passwordQuality: quality.value, pam: pam.value }));
  const accountLockout = await fixedRead(options, '/etc/pam.d/common-auth', parsePamLockout, 'PAM account lockout policy');
  return Promise.all([
    screenLock,
    { ...passwordPolicy, accountLockout },
    fixedRead(options, '/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c', (output) => ({ enabled: output.charCodeAt(output.length - 1) === 1 }), 'Secure Boot status'),
    fixedRead(options, '/sys/class/tpm/tpm0/tpm_version_major', (output) => ({ present: true, versionMajor: integer(output.trim()) }), 'TPM status'),
    fixedCommand(options, 'systemctl', ['is-active', 'auditd.service'], (output) => ({ active: output.trim() === 'active' }), 'systemctl is-active auditd.service', 'Audit logging status'),
  ]);
}

async function collectMacPartTwo(options) {
  const screenResults = await Promise.all([
    fixedCommand(options, 'defaults', ['read', 'com.apple.screensaver', 'idleTime'], (output) => integer(output.trim()), 'defaults com.apple.screensaver idleTime', 'Screen-saver idle time'),
    fixedCommand(options, 'defaults', ['read', 'com.apple.screensaver', 'askForPassword'], (output) => integer(output.trim()) === 1, 'defaults com.apple.screensaver askForPassword', 'Password after sleep requirement'),
    fixedCommand(options, 'defaults', ['read', 'com.apple.screensaver', 'askForPasswordDelay'], (output) => integer(output.trim()), 'defaults com.apple.screensaver askForPasswordDelay', 'Password-after-sleep delay'),
  ]);
  const screenLock = combinePostures(screenResults, 'macOS screensaver defaults', 'Screen-lock policy', ([idle, required, delay]) => ({ idleTimeSeconds: idle.value, passwordOnResume: required.value, passwordDelaySeconds: delay.value }));
  const passwordPolicy = await fixedCommand(options, 'pwpolicy', ['-getaccountpolicies'], (output) => ({ configured: output.trim().length > 0, policy: output.trim() }), 'pwpolicy -getaccountpolicies', 'Password policy');
  const accountLockout = passwordPolicy.status === 'available'
    ? (() => {
      try {
        return posture(parseMacLockoutPolicy(passwordPolicy.value.policy), passwordPolicy.source);
      } catch (error) {
        return postureFailure(error, passwordPolicy.source, 'Account lockout policy');
      }
    })()
    : { ...passwordPolicy };
  return Promise.all([
    screenLock,
    { ...passwordPolicy, accountLockout },
    fixedCommand(options, 'system_profiler', ['SPiBridgeDataType', '-json'], (output) => {
      const data = parseJson(output);
      const text = JSON.stringify(data);
      const match = text.match(/Secure Boot[^:]*[":\s]+(Full Security|Medium Security|No Security|Enabled|Disabled)/i);
      if (!match) throw new Error('system profile did not expose a recognizable Secure Boot state');
      return { state: match[1], enabled: !/No Security|Disabled/i.test(match[1]) };
    }, 'system_profiler SPiBridgeDataType -json', 'Secure Boot status'),
    Promise.resolve({ status: 'unavailable', value: null, reasonCode: 'unavailable', reason: 'macOS hardware does not expose a standard TPM provider', source: null }),
    fixedCommand(options, 'launchctl', ['print', 'system/com.apple.auditd'], (output) => ({ loaded: /state\s*=\s*(running|waiting)/i.test(output) }), 'launchctl print system/com.apple.auditd', 'Audit logging status'),
  ]);
}

async function collectPartTwo(platform, options) {
  let values;
  if (platform === 'win32') values = await collectWindowsPartTwo(options);
  else if (platform === 'linux') values = await collectLinuxPartTwo(options);
  else if (platform === 'darwin') values = await collectMacPartTwo(options);
  else {
    const unavailable = (subject) => ({ status: 'unavailable', value: null, reasonCode: 'unavailable', reason: `${subject} is not implemented for platform "${platform}"`, source: null });
    values = ['Screen-lock policy', 'Password policy', 'Secure Boot status', 'TPM status', 'Audit logging status'].map(unavailable);
    values[1] = { ...values[1], accountLockout: unavailable('Account lockout policy') };
  }
  const [screenLock, passwordPolicy, secureBoot, tpm, auditLogging] = values;
  return { screenLock, passwordPolicy, secureBoot, tpm, auditLogging };
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
      const timeoutMs = context.collectorConfig?.commandTimeoutMs ?? 20000;
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
      const [ssh, firewall, uac, partTwo] = await Promise.all([
        sshPromise,
        firewallPromise,
        uacPromise,
        collectPartTwo(platform, common),
      ]);
      return { platform, ssh, firewall, uac, ...partTwo };
    },
  };
}

export const complianceChecksCollector = createComplianceChecksCollector();
export default complianceChecksCollector;
