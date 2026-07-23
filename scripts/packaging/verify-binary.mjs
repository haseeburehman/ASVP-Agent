import { access, mkdtemp, copyFile, mkdir, readFile, rm } from 'node:fs/promises';
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
} finally {
  await rm(clean, { recursive: true, force: true });
}
