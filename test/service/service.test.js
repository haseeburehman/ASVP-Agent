import assert from 'node:assert/strict';
import test from 'node:test';
import { generateLaunchdPlist, generateSystemdUnit, generateWinSwXml, windowsWinSwAsset } from '../../src/service/definitions.js';
import { isElevated, requireElevation } from '../../src/service/elevation.js';
import { detectServicePlatform, runServiceCommand } from '../../src/service/index.js';

const posixPaths = {
  nodePath: '/usr/bin/node',
  binPath: '/opt/asvp-agent/bin/asvp-agent.js',
  configPath: '/etc/asvp-agent/config.json',
  workingDirectory: '/opt/asvp-agent',
  varDirectory: '/opt/asvp-agent/var',
};

test('systemd unit uses the foreground entry point, absolute config, hardening, and no capabilities', () => {
  const unit = generateSystemdUnit(posixPaths);
  assert.match(unit, /ExecStart="\/usr\/bin\/node" "\/opt\/asvp-agent\/bin\/asvp-agent\.js" "--config" "\/etc\/asvp-agent\/config\.json" "run"/);
  assert.match(unit, /WorkingDirectory="\/opt\/asvp-agent"/);
  assert.match(unit, /Restart=on-failure\nRestartSec=10s/);
  assert.match(unit, /StartLimitIntervalSec=300\nStartLimitBurst=5/);
  assert.match(unit, /ProtectSystem=strict/);
  assert.match(unit, /ProtectHome=true/);
  assert.match(unit, /NoNewPrivileges=true/);
  assert.match(unit, /ReadWritePaths="\/opt\/asvp-agent\/var"/);
  assert.match(unit, /CapabilityBoundingSet=\nAmbientCapabilities=/);
  assert.match(unit, /RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6/);
});

test('WinSW XML runs node under LocalService with restart backoff and rolling logs', () => {
  const xml = generateWinSwXml({
    nodePath: 'C:\\Program Files\\nodejs\\node.exe',
    binPath: 'C:\\Program Files\\ASVP\\bin\\asvp-agent.js',
    configPath: 'C:\\ProgramData\\ASVP\\config.json',
    workingDirectory: 'C:\\Program Files\\ASVP',
    logDirectory: 'C:\\Program Files\\ASVP\\var\\log\\winsw',
  });
  assert.match(xml, /<executable>C:\\Program Files\\nodejs\\node\.exe<\/executable>/);
  assert.match(xml, /&quot;C:\\Program Files\\ASVP\\bin\\asvp-agent\.js&quot; &quot;--config&quot; &quot;C:\\ProgramData\\ASVP\\config\.json&quot; &quot;run&quot;/);
  assert.match(xml, /<username>NT AUTHORITY\\LocalService<\/username>/);
  assert.match(xml, /<startmode>Automatic<\/startmode>/);
  assert.match(xml, /onfailure action="restart" delay="10 sec"/);
  assert.match(xml, /onfailure action="restart" delay="30 sec"/);
  assert.match(xml, /onfailure action="restart" delay="60 sec"/);
  assert.match(xml, /<log mode="roll-by-size-time">/);
  assert.equal(windowsWinSwAsset('x64').url, 'https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe');
  assert.equal(windowsWinSwAsset('arm64').asset, 'WinSW-x64.exe');
  assert.equal(windowsWinSwAsset('arm64').emulated, true);
  assert.throws(() => windowsWinSwAsset('ia32'), /supports Windows x64 and Windows ARM64/);
});

test('launchd plist is a system-daemon definition using one foreground entry point', () => {
  const plist = generateLaunchdPlist({
    ...posixPaths,
    stdoutPath: '/var/log/asvp-agent.log',
    stderrPath: '/var/log/asvp-agent.error.log',
  });
  assert.match(plist, /<string>com\.asvp\.agent<\/string>/);
  for (const value of ['/usr/bin/node', '/opt/asvp-agent/bin/asvp-agent.js', '--config', '/etc/asvp-agent/config.json', 'run']) {
    assert.match(plist, new RegExp(`<string>${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}<\\/string>`));
  }
  assert.match(plist, /<key>UserName<\/key>\s*<string>_www<\/string>/);
  assert.match(plist, /<key>RunAtLoad<\/key>\s*<true\/>/);
  assert.match(plist, /<key>KeepAlive<\/key>[\s\S]*<key>SuccessfulExit<\/key>\s*<false\/>/);
  assert.match(plist, /<key>ThrottleInterval<\/key>\s*<integer>10<\/integer>/);
  assert.match(plist, /<string>\/var\/log\/asvp-agent\.error\.log<\/string>/);
});

test('packaged service definitions invoke the standalone executable directly', () => {
  const packaged = {
    executablePath: '/opt/asvp-agent/asvp-agent',
    entryArguments: [],
    configPath: '/opt/asvp-agent/config/default.json',
    workingDirectory: '/opt/asvp-agent',
    varDirectory: '/opt/asvp-agent/var',
  };
  const unit = generateSystemdUnit(packaged);
  assert.match(unit, /ExecStart="\/opt\/asvp-agent\/asvp-agent" "--config" "\/opt\/asvp-agent\/config\/default\.json" "run"/);
  assert.doesNotMatch(unit, /node|bin\/asvp-agent\.js/);

  const xml = generateWinSwXml({
    ...packaged,
    executablePath: 'C:\\Program Files\\ASVP Agent\\asvp-agent.exe',
    configPath: 'C:\\Program Files\\ASVP Agent\\config\\default.json',
    workingDirectory: 'C:\\Program Files\\ASVP Agent',
    logDirectory: 'C:\\Program Files\\ASVP Agent\\var\\log\\winsw',
  });
  assert.match(xml, /<executable>C:\\Program Files\\ASVP Agent\\asvp-agent\.exe<\/executable>/);
  assert.doesNotMatch(xml, /bin\\asvp-agent\.js|node\.exe/);

  const plist = generateLaunchdPlist({
    ...packaged,
    stdoutPath: '/var/log/asvp-agent.log',
    stderrPath: '/var/log/asvp-agent.error.log',
  });
  assert.match(plist, /<string>\/opt\/asvp-agent\/asvp-agent<\/string>/);
  assert.doesNotMatch(plist, /bin\/asvp-agent\.js|\/usr\/bin\/node/);
});

test('platform detection supports exactly the three service targets', () => {
  assert.equal(detectServicePlatform('linux'), 'linux');
  assert.equal(detectServicePlatform('win32'), 'win32');
  assert.equal(detectServicePlatform('darwin'), 'darwin');
  assert.throws(() => detectServicePlatform('freebsd'), /not supported/);
});

test('elevation checks use root on Unix and Administrator probe on Windows', async () => {
  assert.equal(await isElevated({ platform: 'linux', geteuid: () => 0 }), true);
  assert.equal(await isElevated({ platform: 'darwin', geteuid: () => 501 }), false);
  assert.equal(await isElevated({ platform: 'win32', runCommand: async () => ({ code: 0 }) }), true);
  assert.equal(await isElevated({ platform: 'win32', runCommand: async () => ({ code: 2 }) }), false);
  await assert.rejects(
    requireElevation({ platform: 'win32', runCommand: async () => ({ code: 2 }) }),
    /Run as administrator/,
  );
  await assert.rejects(
    runServiceCommand('install', { platform: 'linux', geteuid: () => 1000, runner: async () => ({ code: 0 }) }),
    /require elevated privileges.*sudo/i,
  );
});
