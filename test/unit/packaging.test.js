import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { discoverCollectorModules, verifyCollectorCoverage } from '../../scripts/packaging/esbuild.config.mjs';
import { preparePackagedConfig } from '../../scripts/packaging/prepare-config.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

test('packaging auto-discovers every registered collector module', async () => {
  const discovered = await discoverCollectorModules(root);
  const covered = verifyCollectorCoverage(discovered);
  assert.ok(covered.includes('users-groups'));
  assert.ok(covered.includes('antivirus-status'));
  assert.equal(covered.length, discovered.length);
});

test('packaged config bakes a validated server URL without modifying source', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-package-config-'));
  const sourcePath = path.join(directory, 'source.json');
  const destinationPath = path.join(directory, 'packaged.json');
  try {
    const source = { server: { mode: 'http', url: 'https://management.example.invalid' }, untouched: true };
    await writeFile(sourcePath, JSON.stringify(source));
    const result = await preparePackagedConfig({ sourcePath, destinationPath, defaultServerUrl: 'https://asvp.company.test/' });
    assert.deepEqual(result, { preconfigured: true, serverUrl: 'https://asvp.company.test' });
    assert.equal(JSON.parse(await readFile(destinationPath, 'utf8')).server.url, 'https://asvp.company.test');
    assert.equal(JSON.parse(await readFile(sourcePath, 'utf8')).server.url, 'https://management.example.invalid');
    await assert.rejects(preparePackagedConfig({ sourcePath, destinationPath, defaultServerUrl: 'http://evil.test' }), /must use HTTPS/);
    await assert.rejects(preparePackagedConfig({ sourcePath, destinationPath, defaultServerUrl: 'https://management.example.invalid' }), /placeholder/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('Windows uninstall deletes only the confirmed install tree while upgrades preserve config', async () => {
  const script = await readFile(path.join(root, 'scripts', 'packaging', 'windows', 'asvp-agent.iss'), 'utf8');
  assert.match(script, /DestName: "default\.json"; Flags: ignoreversion onlyifdoesntexist/);
  assert.match(script, /\[UninstallDelete\][\s\S]*Type: filesandordirs; Name: "\{app\}"/);
  assert.match(script, /Type "yes" to confirm/);
  assert.doesNotMatch(script, /\[UninstallDelete\][\s\S]*Name: "(?:\{autopf\}|[A-Z]:\\|\\\\)/i);
});

test('generic packaged config preserves enrollment placeholder', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-generic-config-'));
  const sourcePath = path.join(directory, 'source.json');
  const destinationPath = path.join(directory, 'packaged.json');
  try {
    await writeFile(sourcePath, JSON.stringify({ server: { mode: 'http', url: 'https://management.example.invalid' } }));
    const result = await preparePackagedConfig({ sourcePath, destinationPath });
    assert.equal(result.preconfigured, false);
    assert.equal(result.serverUrl, 'https://management.example.invalid');
  } finally { await rm(directory, { recursive: true, force: true }); }
});
