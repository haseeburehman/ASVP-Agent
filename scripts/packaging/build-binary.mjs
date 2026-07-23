import { mkdir, readFile, copyFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { buildAgentBundle } from './esbuild.config.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const metadata = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
const platformAliases = { win32: 'win', linux: 'linux', darwin: 'macos' };
const platform = process.env.PACKAGE_PLATFORM ?? platformAliases[process.platform];
const arch = process.env.PACKAGE_ARCH ?? process.arch;
if (!['win', 'linux', 'macos'].includes(platform)) throw new Error(`Unsupported package platform: ${platform}`);
if (!['x64', 'arm64'].includes(arch)) throw new Error(`Unsupported package architecture: ${arch}`);

const extension = platform === 'win' ? '.exe' : '';
const outputDirectory = path.join(root, 'dist', `${platform}-${arch}`);
const bundlePath = path.join(outputDirectory, 'asvp-agent.bundle.cjs');
const outputPath = path.join(outputDirectory, `asvp-agent-${metadata.version}-${platform}-${arch}${extension}`);
const pkgExecutable = path.join(root, 'node_modules', '@yao-pkg', 'pkg', 'lib-es5', 'bin.js');
await mkdir(path.join(outputDirectory, 'config'), { recursive: true });
await mkdir(path.join(outputDirectory, 'public'), { recursive: true });
await copyFile(path.join(root, 'config', 'default.json'), path.join(outputDirectory, 'config', 'default.json'));
await copyFile(path.join(root, 'src', 'dashboard', 'public', 'index.html'), path.join(outputDirectory, 'public', 'index.html'));

await buildAgentBundle({ root, outputPath: bundlePath, version: metadata.version });
await run(process.execPath, [bundlePath, '--help'], 'plain Node bundle help smoke test');
await run(process.execPath, [bundlePath, '--config', path.join(outputDirectory, 'config', 'default.json'), 'scan', '--collector', 'os-info', '--no-queue'], 'plain Node bundle collector smoke test');

await run(process.execPath, [
  pkgExecutable,
  bundlePath,
  '--config', path.join(root, 'package.json'),
  '--target', `node22-${platform}-${arch}`,
  '--output', outputPath,
  '--no-bytecode',
  '--public',
  '--public-packages', 'keytar,node-addon-api',
], '@yao-pkg/pkg');

process.stdout.write(`${outputPath}\n`);

function run(executable, args, label) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd: root, stdio: 'inherit' });
    child.once('error', reject);
    child.once('exit', (code) => code === 0 ? resolve() : reject(new Error(`${label} exited with code ${code}`)));
  });
}
