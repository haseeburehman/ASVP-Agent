import path from 'node:path';

const xmlEscape = (value) => String(value)
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&apos;');

const plistEscape = xmlEscape;
const quoteSystemd = (value) => `"${String(value).replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
const quoteWindowsArgument = (value) => `"${String(value).replaceAll('"', '\\"')}"`;

function serviceCommand({ executablePath, entryArguments = [], configPath }) {
  return [executablePath, ...entryArguments, '--config', configPath, 'run'];
}

export function generateSystemdUnit({ executablePath, entryArguments, nodePath, binPath, configPath, workingDirectory, varDirectory, serviceUser = 'asvp-agent' }) {
  const command = serviceCommand({
    executablePath: executablePath ?? nodePath,
    entryArguments: entryArguments ?? (binPath ? [binPath] : []),
    configPath,
  });
  return `[Unit]
Description=ASVP Internal Network Scanning Agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=${serviceUser}
Group=${serviceUser}
WorkingDirectory=${quoteSystemd(workingDirectory)}
ExecStart=${command.map(quoteSystemd).join(' ')}
Restart=on-failure
RestartSec=10s
TimeoutStopSec=30s
KillSignal=SIGTERM
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelControlGroups=true
ProtectKernelModules=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictRealtime=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=${quoteSystemd(varDirectory)}
UMask=0077

[Install]
WantedBy=multi-user.target
`;
}

export function generateWinSwXml({ executablePath, entryArguments, nodePath, binPath, configPath, workingDirectory, logDirectory }) {
  const command = serviceCommand({
    executablePath: executablePath ?? nodePath,
    entryArguments: entryArguments ?? (binPath ? [binPath] : []),
    configPath,
  });
  const argumentsValue = command.slice(1).map(quoteWindowsArgument).join(' ');
  return `<?xml version="1.0" encoding="UTF-8"?>
<service>
  <id>asvp-agent</id>
  <name>ASVP Internal Network Scanning Agent</name>
  <description>Collects authorized internal asset and security posture data.</description>
  <executable>${xmlEscape(command[0])}</executable>
  <arguments>${xmlEscape(argumentsValue)}</arguments>
  <workingdirectory>${xmlEscape(workingDirectory)}</workingdirectory>
  <startmode>Automatic</startmode>
  <serviceaccount>
    <username>NT AUTHORITY\\LocalService</username>
    <allowservicelogon>true</allowservicelogon>
  </serviceaccount>
  <onfailure action="restart" delay="10 sec" />
  <onfailure action="restart" delay="30 sec" />
  <onfailure action="restart" delay="60 sec" />
  <resetfailure>1 hour</resetfailure>
  <stoptimeout>30 sec</stoptimeout>
  <logpath>${xmlEscape(logDirectory)}</logpath>
  <log mode="roll-by-size-time">
    <sizeThreshold>10240</sizeThreshold>
    <pattern>yyyyMMdd</pattern>
    <autoRollAtTime>00:00:00</autoRollAtTime>
    <zipOlderThanNumDays>7</zipOlderThanNumDays>
    <zipDateFormat>yyyyMM</zipDateFormat>
  </log>
</service>
`;
}

export function generateLaunchdPlist({ executablePath, entryArguments, nodePath, binPath, configPath, workingDirectory, stdoutPath, stderrPath, serviceUser = '_www' }) {
  const argument = (value) => `    <string>${plistEscape(value)}</string>`;
  const command = serviceCommand({
    executablePath: executablePath ?? nodePath,
    entryArguments: entryArguments ?? (binPath ? [binPath] : []),
    configPath,
  });
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.asvp.agent</string>
  <key>ProgramArguments</key>
  <array>
${command.map(argument).join('\n')}
  </array>
  <key>WorkingDirectory</key>
  <string>${plistEscape(workingDirectory)}</string>
  <key>UserName</key>
  <string>${plistEscape(serviceUser)}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>${plistEscape(stdoutPath)}</string>
  <key>StandardErrorPath</key>
  <string>${plistEscape(stderrPath)}</string>
  <key>Umask</key>
  <integer>63</integer>
</dict>
</plist>
`;
}

export function windowsWinSwAsset(architecture = process.arch) {
  if (!['x64', 'arm64'].includes(architecture)) {
    throw new Error(`Pinned WinSW v2.12.0 service installation supports Windows x64 and Windows ARM64 with x64 emulation; detected architecture: ${architecture}`);
  }
  const asset = 'WinSW-x64.exe';
  return {
    version: 'v2.12.0',
    asset,
    emulated: architecture === 'arm64',
    url: `https://github.com/winsw/winsw/releases/download/v2.12.0/${asset}`,
  };
}

export function resolveServicePaths({ projectRoot, configPath, nodePath = process.execPath, packaged = Boolean(process.pkg) }) {
  const root = packaged ? path.dirname(path.resolve(nodePath)) : path.resolve(projectRoot);
  return {
    projectRoot: root,
    executablePath: path.resolve(nodePath),
    entryArguments: packaged ? [] : [path.resolve(projectRoot, 'bin', 'asvp-agent.js')],
    configPath: path.resolve(configPath),
    varDirectory: path.resolve(root, 'var'),
    packaged,
  };
}
