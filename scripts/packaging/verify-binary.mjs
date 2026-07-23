import { access, mkdtemp, copyFile, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const metadata = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
const aliases = { win32: 'win', linux: 'linux', darwin: 'macos' };
const platform = process.env.PACKAGE_PLATFORM ?? aliases[process.platform];
const arch = process.env.PACKAGE_ARCH ?? process.arch;
if (aliases[process.platform] !== platform || process.arch !== arch) {
  throw new Error(`Cannot execute-test ${platform}-${arch} on ${aliases[process.platform]}-${process.arch}`);
}
const extension = platform === 'win' ? '.exe' : '';
const name = `asvp-agent-${metadata.version}-${platform}-${arch}${extension}`;
const builtDirectory = path.join(root, 'dist', `${platform}-${arch}`);
const sourceBinary = path.join(builtDirectory, name);
await access(sourceBinary);
const clean = await mkdtemp(path.join(os.tmpdir(), 'asvp-agent-package-'));
try {
  const binary = path.join(clean, platform === 'win' ? 'asvp-agent.exe' : 'asvp-agent');
  await copyFile(sourceBinary, binary);
  await mkdir(path.join(clean, 'config'));
  await mkdir(path.join(clean, 'public'));
  await copyFile(path.join(builtDirectory, 'config', 'default.json'), path.join(clean, 'config', 'default.json'));
  await copyFile(path.join(builtDirectory, 'public', 'index.html'), path.join(clean, 'public', 'index.html'));
  const run = (args, expectSuccess = true) => new Promise((resolve, reject) => {
    const child = spawn(binary, args, { cwd: clean, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code) => {
      process.stdout.write(stdout);
      process.stderr.write(stderr);
      if (expectSuccess && code !== 0) reject(new Error(`${name} ${args.join(' ')} exited with ${code}`));
      else resolve({ code, stdout, stderr });
    });
  });
  await run(['--help']);
  await run(['--config', path.join(clean, 'config', 'default.json'), 'scan', '--collector', 'os-info', '--no-queue']);
  const credentialArgs = ['--config', path.join(clean, 'config', 'default.json'), 'diagnostics', 'credentials'];
  if (process.env.REQUIRE_PACKAGED_KEYCHAIN === 'true') credentialArgs.push('--require-keychain');
  const diagnostic = await run(credentialArgs);
  const match = diagnostic.stdout.match(/\{\s*"backend"[\s\S]*?\n\}/g)?.at(-1);
  if (!match) throw new Error(`Credential diagnostic did not emit its JSON result: ${diagnostic.stdout}`);
  const parsed = JSON.parse(match);
  if (process.env.REQUIRE_PACKAGED_KEYCHAIN === 'true' && (parsed.backend !== 'keychain' || !parsed.operational)) {
    throw new Error(`Packaged keychain diagnostic failed: ${JSON.stringify(parsed)}`);
  }
  if (process.env.REQUIRE_PACKAGED_FALLBACK === 'true') {
    const fallbackConfigPath = path.join(clean, 'config', 'fallback-test.json');
    const fallbackConfig = JSON.parse(await readFile(path.join(clean, 'config', 'default.json'), 'utf8'));
    const identityPath = path.resolve(clean, 'var', 'fallback-identity.json');
    const statusPath = path.resolve(clean, 'var', 'fallback-status.json');
    const queueDirectory = path.resolve(clean, 'var', 'fallback-queue');
    fallbackConfig.server.mode = 'mock';
    fallbackConfig.storage.identityPath = identityPath;
    fallbackConfig.storage.statusPath = statusPath;
    fallbackConfig.storage.queueDir = queueDirectory;
    await writeFile(fallbackConfigPath, `${JSON.stringify(fallbackConfig, null, 2)}\n`);
    const registerResult = await run(['--config', fallbackConfigPath, 'register']);
    const registeredAgentId = registerResult.stdout.match(/"agentId"\s*:\s*"([^"]+)"/)?.[1];
    if (!registeredAgentId) {
      throw new Error(`Packaged fallback registration did not report its agentId: ${registerResult.stdout}`);
    }
    const statusResult = await run(['--config', fallbackConfigPath, 'status']);
    const statusAgentId = statusResult.stdout.match(/"agentId"\s*:\s*"([^"]+)"/)?.[1];
    if (statusAgentId !== registeredAgentId) {
      throw new Error(`Packaged fallback identity continuity failed: registered ${registeredAgentId}, status returned ${statusAgentId ?? 'null'}`);
    }
    const identity = JSON.parse(await readFile(identityPath, 'utf8'));
    if (!identity.agentId || !identity.authToken || !identity.encryptionKey) {
      throw new Error('Packaged restricted-file fallback persisted an incomplete identity');
    }
    if (process.platform !== 'win32') {
      const mode = (await stat(identityPath)).mode & 0o777;
      if (mode !== 0o600) throw new Error(`Packaged restricted-file fallback mode was ${mode.toString(8)}, expected 600`);
    }
    process.stdout.write(`Packaged restricted-file credential fallback round trip passed: register agentId=${registeredAgentId}; status agentId=${statusAgentId}; state=not-running-or-no-status; mode=0600.\n`);
  }
} finally {
  await rm(clean, { recursive: true, force: true });
}
