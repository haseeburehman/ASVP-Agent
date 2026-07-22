import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import {
  createComplianceChecksCollector,
  mapUacLevel,
  parseFirewalldStatus,
  parseIptablesRules,
  parseMacFirewallStatus,
  parseNftablesRules,
  parseSshdConfiguration,
  parseUfwStatus,
  parseWindowsFirewallProfiles,
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
    assert.equal(calls.at(-1), testCase.selected);
  }
});

test('macOS firewall parser and fixed command report global state', async () => {
  assert.equal(parseMacFirewallStatus('Firewall is enabled. (State = 1)').active, true);
  let invocation;
  const collector = createComplianceChecksCollector({
    platform: 'darwin',
    readTextFile: async () => '# defaults',
    runCommand: async (command, args) => {
      invocation = [command, args];
      return 'Firewall is disabled. (State = 0)';
    },
  });
  const result = await collector.run({}, { collectorConfig: {} });
  assert.deepEqual(invocation, ['/usr/libexec/ApplicationFirewall/socketfilterfw', ['--getglobalstate']]);
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
      return JSON.stringify({ ConsentPromptBehaviorAdmin: 5, PromptOnSecureDesktop: 1, EnableLUA: 1 });
    },
  });

  const result = await collector.run({}, { collectorConfig: {} });

  assert.equal(result.ssh.permitRootLogin.status, 'not-applicable');
  assert.equal(result.firewall.profiles.length, 3);
  assert.equal(result.uac.value.level, 3);
  assert.ok(calls.every(([command, args]) => command === 'powershell.exe'
    && args[0] === '-NoProfile'
    && args[1] === '-NonInteractive'
    && args[2] === '-Command'));
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
});
