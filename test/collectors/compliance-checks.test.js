import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import {
  createComplianceChecksCollector,
  mapUacLevel,
  parseFirewalldStatus,
  parseIptablesRules,
  parseMacFirewallStatus,
  parseMacLockoutPolicy,
  parseLoginDefs,
  parseNftablesRules,
  parsePamLockout,
  parseSshdConfiguration,
  parseUfwStatus,
  parseWindowsFirewallProfiles,
  parseWindowsPasswordPolicy,
  parsePwQuality,
  UAC_LEVELS,
} from '../../src/collectors/compliance-checks/index.js';

const fixtures = path.resolve('test/fixtures/compliance');

function fixturePath(name) {
  return path.join(fixtures, name, 'sshd_config');
}

test('SSH parser reads explicit settings from the main file', async () => {
  const result = await parseSshdConfiguration(fixturePath('explicit-main'));

  assert.equal(result.permitRootLogin.value, 'no');
  assert.equal(result.passwordAuthentication.value, 'no');
  assert.equal(result.permitRootLogin.source, 'explicit');
  assert.equal(result.permitRootLogin.line, 1);
});

test('SSH parser resolves settings found only in an included file', async () => {
  const result = await parseSshdConfiguration(fixturePath('include-only'));

  assert.equal(result.permitRootLogin.value, 'no');
  assert.equal(result.passwordAuthentication.value, 'no');
  assert.ok(result.permitRootLogin.file.endsWith(path.join('conf.d', '10-security.conf')));
  assert.equal(result.filesProcessed.length, 2);
});

test('SSH Include is processed in place and first match wins over conflicting main-file settings', async () => {
  const result = await parseSshdConfiguration(fixturePath('conflict'));

  assert.deepEqual({
    permitRootLogin: {
      value: result.permitRootLogin.value,
      source: result.permitRootLogin.source,
      file: path.basename(result.permitRootLogin.file),
      line: result.permitRootLogin.line,
    },
    passwordAuthentication: {
      value: result.passwordAuthentication.value,
      source: result.passwordAuthentication.source,
      file: path.basename(result.passwordAuthentication.file),
      line: result.passwordAuthentication.line,
    },
  }, {
    permitRootLogin: {
      value: 'prohibit-password',
      source: 'explicit',
      file: '10-first.conf',
      line: 1,
    },
    passwordAuthentication: {
      value: 'no',
      source: 'explicit',
      file: '10-first.conf',
      line: 2,
    },
  });
});

test('SSH parser reports modern compiled defaults when directives are absent', async () => {
  const result = await parseSshdConfiguration(fixturePath('defaults'));

  assert.equal(result.permitRootLogin.value, 'prohibit-password');
  assert.equal(result.passwordAuthentication.value, 'yes');
  assert.equal(result.permitRootLogin.source, 'compiled-default');
  assert.match(result.permitRootLogin.note, /Not explicitly configured/);
});

test('SSH Include glob files are processed in lexical order with first match wins', async () => {
  const result = await parseSshdConfiguration(fixturePath('glob-order'));

  assert.equal(result.permitRootLogin.value, 'no');
  assert.equal(result.passwordAuthentication.value, 'no');
  assert.ok(result.permitRootLogin.file.endsWith('10-first.conf'));
  assert.ok(result.filesProcessed[1].endsWith('10-first.conf'));
  assert.ok(result.filesProcessed[2].endsWith('20-second.conf'));
});

test('SSH unreadable base config reports per-field failure instead of defaults', async () => {
  const collector = createComplianceChecksCollector({
    platform: 'linux',
    unixSshConfigPath: '/missing/sshd_config',
    readTextFile: async () => {
      const error = new Error('permission denied');
      error.code = 'EACCES';
      throw error;
    },
    runCommand: async () => { throw new Error('firewall unavailable'); },
  });

  const result = await collector.run({}, { collectorConfig: {} });

  assert.equal(result.ssh.permitRootLogin.status, 'check-failed');
  assert.equal(result.ssh.permitRootLogin.value, null);
  assert.match(result.ssh.permitRootLogin.reason, /permission denied/);
});

test('firewall parsers normalize ufw, firewalld, nftables, and iptables output', () => {
  assert.deepEqual(parseUfwStatus('Status: active\n22/tcp ALLOW Anywhere'), {
    subsystem: 'ufw', active: true, ruleCount: 1, reason: null,
  });
  assert.deepEqual(parseFirewalldStatus('running'), {
    subsystem: 'firewalld', active: true, ruleCount: null, reason: null,
  });
  assert.deepEqual(parseNftablesRules('table inet filter {\n chain input {\n tcp dport 22 accept\n }\n}'), {
    subsystem: 'nftables', active: true, ruleCount: 1, reason: null,
  });
  assert.deepEqual(parseIptablesRules('Chain INPUT (policy DROP)\ntarget prot opt source destination'), {
    subsystem: 'iptables', active: true, ruleCount: 0, reason: null,
  });
});

test('Linux firewall detection follows ufw, firewalld, nftables, iptables order', async () => {
  const cases = [
    { selected: 'ufw', outputs: { ufw: 'Status: inactive' }, active: false },
    { selected: 'firewall-cmd', outputs: { 'firewall-cmd': 'running' }, active: true },
    { selected: 'nft', outputs: { nft: 'table inet filter {\n chain input {\n ip protocol tcp accept\n}\n}' }, active: true },
    { selected: 'iptables', outputs: { iptables: 'Chain INPUT (policy ACCEPT)\ntarget prot opt source destination' }, active: false },
  ];

  for (const testCase of cases) {
    const calls = [];
    const collector = createComplianceChecksCollector({
      platform: 'linux',
      readTextFile: async () => '# defaults',
      runCommand: async (command) => {
        calls.push(command);
        if (Object.hasOwn(testCase.outputs, command)) return testCase.outputs[command];
        throw new Error(`${command} unavailable`);
      },
    });
    const result = await collector.run({}, { collectorConfig: {} });
    assert.equal(result.firewall.active, testCase.active);
    assert.equal(calls.filter((command) => ['ufw', 'firewall-cmd', 'nft', 'iptables'].includes(command)).at(-1), testCase.selected);
  }
});

test('macOS firewall parser and fixed command report global state', async () => {
  assert.equal(parseMacFirewallStatus('Firewall is enabled. (State = 1)').active, true);
  const invocations = [];
  const collector = createComplianceChecksCollector({
    platform: 'darwin',
    readTextFile: async () => '# defaults',
    runCommand: async (command, args) => {
      invocations.push([command, args]);
      if (command === 'system_profiler') return '{}';
      return 'Firewall is disabled. (State = 0)';
    },
  });
  const result = await collector.run({}, { collectorConfig: {} });
  assert.ok(invocations.some((invocation) => invocation[0] === '/usr/libexec/ApplicationFirewall/socketfilterfw'
    && invocation[1].length === 1 && invocation[1][0] === '--getglobalstate'));
  assert.equal(result.firewall.active, false);
});

test('Windows firewall parser reports each profile independently', () => {
  const result = parseWindowsFirewallProfiles(JSON.stringify([
    { Name: 'Domain', Enabled: true },
    { Name: 'Private', Enabled: true },
    { Name: 'Public', Enabled: false },
  ]));

  assert.equal(result.active, false);
  assert.deepEqual(result.profiles, [
    { name: 'Domain', enabled: true },
    { name: 'Private', enabled: true },
    { name: 'Public', enabled: false },
  ]);
});

test('UAC mapping covers all four standard slider levels and disabled UAC', () => {
  for (const expected of UAC_LEVELS) {
    const result = mapUacLevel(expected);
    assert.equal(result.status, 'checked');
    assert.equal(result.value.level, expected.level);
    assert.equal(result.value.name, expected.name);
    assert.equal(result.value.uacEnabled, true);
  }

  const disabled = mapUacLevel({ EnableLUA: 0, ConsentPromptBehaviorAdmin: 0, PromptOnSecureDesktop: 0 });
  assert.equal(disabled.value.level, 1);
  assert.equal(disabled.value.name, 'Never notify');
  assert.equal(disabled.value.uacEnabled, false);
});

test('non-slider UAC policy combination is reported as custom rather than guessed', () => {
  const result = mapUacLevel({ EnableLUA: 1, ConsentPromptBehaviorAdmin: 1, PromptOnSecureDesktop: 1 });

  assert.equal(result.value.level, null);
  assert.equal(result.value.name, 'Custom policy combination');
});

test('Windows collector uses fixed PowerShell commands and degrades missing OpenSSH normally', async () => {
  const calls = [];
  const collector = createComplianceChecksCollector({
    platform: 'win32',
    readTextFile: async () => {
      const error = new Error('not found');
      error.code = 'ENOENT';
      throw error;
    },
    runCommand: async (command, args) => {
      calls.push([command, args]);
      const script = args.at(-1);
      if (script.includes('Get-NetFirewallProfile')) {
        return JSON.stringify([
          { Name: 'Domain', Enabled: true },
          { Name: 'Private', Enabled: true },
          { Name: 'Public', Enabled: true },
        ]);
      }
      if (script.includes('secedit.exe')) return JSON.stringify({ minimumLength: 14, complexityEnabled: true, maximumAgeDays: 90, lockoutThreshold: 5, lockoutDurationMinutes: 30, lockoutResetMinutes: 15 });
      if (script.includes('ScreenSaveActive')) return JSON.stringify({ enabled: true, passwordOnResume: true, timeoutSeconds: 900, scope: 'machine-policy' });
      return JSON.stringify({ ConsentPromptBehaviorAdmin: 5, PromptOnSecureDesktop: 1, EnableLUA: 1 });
    },
  });

  const result = await collector.run({}, { collectorConfig: {} });

  assert.equal(result.ssh.permitRootLogin.status, 'not-applicable');
  assert.equal(result.firewall.profiles.length, 3);
  assert.equal(result.uac.value.level, 3);
  const powerShellCalls = calls.filter(([command]) => command === 'powershell.exe');
  assert.ok(powerShellCalls.length >= 4);
  assert.ok(powerShellCalls.every(([, args]) => args[0] === '-NoProfile'
    && args[1] === '-NonInteractive'
    && args[2] === '-Command'));
  assert.equal(result.passwordPolicy.value.complexityEnabled, true);
  assert.equal(result.passwordPolicy.value.lockoutThreshold, 5);
  assert.deepEqual(result.passwordPolicy.accountLockout.value, {
    lockoutEnabled: true,
    failureThreshold: 5,
    failureWindowSeconds: 900,
    unlockAfterSeconds: 1800,
  });
  assert.equal(result.screenLock.value.scope, 'machine-policy');
  assert.ok(powerShellCalls.some(([, args]) => args.at(-1).includes('secedit.exe')));
  assert.ok(calls.some(([command, args]) => command === 'auditpol.exe'
    && args.length === 2 && args[0] === '/get' && args[1] === '/category:*'));
});

test('Part 2 password policy parsers normalize Windows and Linux values', () => {
  assert.deepEqual(parseLoginDefs('PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\nPASS_MIN_LEN 12'), {
    maximumAgeDays: 90,
    minimumAgeDays: 1,
    warningAgeDays: 7,
    minimumLength: 12,
  });
  assert.deepEqual(parseWindowsPasswordPolicy(JSON.stringify({
    minimumLength: 14,
    complexityEnabled: true,
    maximumAgeDays: 90,
    minimumAgeDays: 1,
    historyLength: 24,
  })), {
    minimumLength: 14,
    complexityEnabled: true,
    maximumAgeDays: 90,
    minimumAgeDays: 1,
    historyLength: 24,
  });
  assert.deepEqual(parsePwQuality('minlen = 14\ndcredit = -1\nucredit = -1'), {
    minimumLength: 14,
    digitCredit: -1,
    uppercaseCredit: -1,
    lowercaseCredit: null,
    otherCredit: null,
  });
});

test('Part B lockout parsers normalize PAM and macOS policy values', () => {
  assert.deepEqual(parsePamLockout('auth required pam_faillock.so preauth deny=4 fail_interval=900 unlock_time=600'), {
    lockoutEnabled: true,
    failureThreshold: 4,
    failureWindowSeconds: 900,
    unlockAfterSeconds: 600,
    module: 'pam_faillock',
    configuredLine: 'auth required pam_faillock.so preauth deny=4 fail_interval=900 unlock_time=600',
  });
  assert.deepEqual(parsePamLockout('auth required pam_tally2.so deny=3 unlock_time=1200'), {
    lockoutEnabled: true,
    failureThreshold: 3,
    failureWindowSeconds: null,
    unlockAfterSeconds: 1200,
    module: 'pam_tally2',
    configuredLine: 'auth required pam_tally2.so deny=3 unlock_time=1200',
  });
  assert.equal(parsePamLockout([
    'auth required pam_tally2.so deny=3',
    'auth required pam_faillock.so deny=5',
  ].join('\n')).module, 'pam_faillock');
  assert.deepEqual(parseMacLockoutPolicy('maxFailedLoginAttempts=5 minutesUntilFailedLoginReset=10 autoEnableInSeconds=1800'), {
    lockoutEnabled: true,
    failureThreshold: 5,
    failureWindowSeconds: 600,
    unlockAfterSeconds: 1800,
  });
  assert.throws(() => parseMacLockoutPolicy('policyCategoryPasswordContent = 1'), /no reliable account lockout keys/);
});

test('Linux Part 2 checks use only fixed bounded commands and reads', async () => {
  const commands = [];
  const reads = [];
  const collector = createComplianceChecksCollector({
    platform: 'linux',
    readTextFile: async (filePath) => {
      reads.push(filePath);
      if (filePath === '/etc/ssh/sshd_config') return '# defaults';
      if (filePath === '/etc/login.defs') return 'PASS_MAX_DAYS 90\nPASS_MIN_LEN 12';
      if (filePath === '/etc/security/pwquality.conf') return 'minlen = 14\ndcredit = -1';
      if (filePath === '/etc/pam.d/common-password') return 'password requisite pam_pwquality.so retry=3';
      if (filePath === '/etc/pam.d/common-auth') return 'auth required pam_faillock.so deny=4 fail_interval=900 unlock_time=600';
      if (filePath.includes('SecureBoot-')) return '\u0000\u0000\u0000\u0000\u0001';
      if (filePath === '/sys/class/tpm/tpm0/tpm_version_major') return '2';
      throw new Error(`unexpected read: ${filePath}`);
    },
    runCommand: async (command, args, options) => {
      commands.push([command, args, options]);
      if (command === 'ufw') return 'Status: inactive';
      if (command === 'gsettings') {
        if (args.at(-1) === 'lock-enabled') return 'true';
        return 'uint32 300';
      }
      if (command === 'systemctl') return 'active';
      throw new Error(`unexpected command: ${command}`);
    },
  });

  const result = await collector.run({}, { collectorConfig: { commandTimeoutMs: 1234 } });

  assert.equal(result.screenLock.status, 'available');
  assert.equal(result.screenLock.value.lockEnabled, true);
  assert.equal(result.passwordPolicy.value.loginDefaults.minimumLength, 12);
  assert.equal(result.passwordPolicy.value.passwordQuality.minimumLength, 14);
  assert.equal(result.passwordPolicy.value.pam.pwqualityEnabled, true);
  assert.equal(result.secureBoot.value.enabled, true);
  assert.equal(result.tpm.value.versionMajor, 2);
  assert.equal(result.auditLogging.value.active, true);
  assert.equal(result.passwordPolicy.accountLockout.value.failureThreshold, 4);
  assert.equal(result.passwordPolicy.accountLockout.value.failureWindowSeconds, 900);
  assert.equal(result.passwordPolicy.accountLockout.value.unlockAfterSeconds, 600);
  assert.deepEqual(reads.filter((item) => !item.endsWith('sshd_config')), [
    '/etc/login.defs',
    '/etc/security/pwquality.conf',
    '/etc/pam.d/common-password',
    '/etc/pam.d/common-auth',
    '/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c',
    '/sys/class/tpm/tpm0/tpm_version_major',
  ]);
  for (const [, , options] of commands) {
    assert.equal(options.timeoutMs, 1234);
    assert.ok(options.maxOutputBytes <= 2 * 1024 * 1024);
  }
});

test('Part 2 distinguishes insufficient privilege from unavailable', async () => {
  const collector = createComplianceChecksCollector({
    platform: 'linux',
    readTextFile: async (filePath) => {
      if (filePath === '/etc/ssh/sshd_config') return '# defaults';
      const error = new Error(filePath === '/etc/login.defs' ? 'permission denied' : 'not found');
      error.code = filePath === '/etc/login.defs' ? 'EACCES' : 'ENOENT';
      throw error;
    },
    runCommand: async (command) => {
      if (command === 'gsettings') {
        const error = new Error('permission denied');
        error.code = 'EACCES';
        throw error;
      }
      throw new Error('command not found');
    },
  });

  const result = await collector.run({}, { collectorConfig: {} });
  assert.equal(result.screenLock.status, 'insufficient_privilege');
  assert.equal(result.passwordPolicy.status, 'insufficient_privilege');
  assert.equal(result.secureBoot.status, 'unavailable');
  assert.equal(result.tpm.status, 'unavailable');
  assert.equal(result.auditLogging.status, 'unavailable');
});

test('Part B reports unavailable and insufficient privilege when PAM policy cannot be determined', async () => {
  for (const [code, expected] of [['ENOENT', 'unavailable'], ['EACCES', 'insufficient_privilege']]) {
    const collector = createComplianceChecksCollector({
      platform: 'linux',
      readTextFile: async (filePath) => {
        if (filePath === '/etc/ssh/sshd_config') return '# defaults';
        if (filePath === '/etc/login.defs') return 'PASS_MAX_DAYS 90';
        if (filePath === '/etc/security/pwquality.conf') return 'minlen = 14';
        if (filePath === '/etc/pam.d/common-password') return 'password requisite pam_pwquality.so';
        if (filePath.includes('SecureBoot-')) return '\u0000\u0000\u0000\u0000\u0001';
        if (filePath === '/sys/class/tpm/tpm0/tpm_version_major') return '2';
        const error = new Error(code === 'EACCES' ? 'permission denied' : 'not found');
        error.code = code;
        throw error;
      },
      runCommand: async (command) => command === 'ufw' ? 'Status: inactive' : 'active',
    });
    const result = await collector.run({}, { collectorConfig: {} });
    assert.equal(result.passwordPolicy.accountLockout.status, expected);
    assert.equal(result.passwordPolicy.accountLockout.value, null);
  }
});

test('macOS Part B reports unavailable instead of guessing absent pwpolicy keys', async () => {
  const collector = createComplianceChecksCollector({
    platform: 'darwin',
    readTextFile: async () => '# defaults',
    runCommand: async (command) => {
      if (command === 'pwpolicy') return 'policyCategoryPasswordContent = 1';
      if (command === 'system_profiler') return JSON.stringify({ secureBoot: 'Full Security' });
      if (command === '/usr/libexec/ApplicationFirewall/socketfilterfw') return 'Firewall is enabled. (State = 1)';
      return '1';
    },
  });
  const result = await collector.run({}, { collectorConfig: {} });
  assert.equal(result.passwordPolicy.status, 'available');
  assert.equal(result.passwordPolicy.accountLockout.status, 'unavailable');
  assert.match(result.passwordPolicy.accountLockout.reason, /no reliable account lockout keys/);
});

test('Part 2 rejects oversized fixed-file reads', async () => {
  const collector = createComplianceChecksCollector({
    platform: 'linux',
    readTextFile: async (filePath) => filePath === '/etc/ssh/sshd_config' ? '# defaults' : 'x'.repeat(300 * 1024),
    runCommand: async (command) => command === 'ufw' ? 'Status: inactive' : 'active',
  });
  const result = await collector.run({}, { collectorConfig: {} });
  assert.equal(result.passwordPolicy.status, 'unavailable');
  assert.match(result.passwordPolicy.reason, /safety limit/);
});

test('real compliance collector returns independent shaped checks on the development machine', async () => {
  const result = await createComplianceChecksCollector().run({}, {
    collectorConfig: { commandTimeoutMs: 8000 },
  });

  assert.ok(['linux', 'darwin', 'win32'].includes(result.platform));
  assert.ok(['checked', 'check-failed', 'not-applicable'].includes(result.ssh.permitRootLogin.status));
  assert.ok(['checked', 'check-failed', 'not-applicable'].includes(result.ssh.passwordAuthentication.status));
  assert.ok(['checked', 'check-failed', 'not-applicable'].includes(result.firewall.status));
  assert.ok(['checked', 'check-failed', 'not-applicable'].includes(result.uac.status));
  for (const name of ['screenLock', 'passwordPolicy', 'secureBoot', 'tpm', 'auditLogging']) {
    assert.ok(['available', 'unavailable', 'insufficient_privilege'].includes(result[name].status));
  }
  assert.ok(['available', 'unavailable', 'insufficient_privilege'].includes(result.passwordPolicy.accountLockout.status));
});
