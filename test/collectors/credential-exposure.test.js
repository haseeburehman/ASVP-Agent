import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createCredentialExposureCollector, scanCredentialContent } from '../../src/collectors/credential-exposure/index.js';

async function withTempDirectory(callback) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-credential-exposure-'));
  try {
    await callback(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test('content scanning reports fixed rules without secret values or context', () => {
  const secrets = ['fixture-password-never-serialize', 'AKIAABCDEFGHIJKLMNOP', 'fixture-private-key-material'];
  const findings = scanCredentialContent([
    `password=${secrets[0]}`,
    `AWS_ACCESS_KEY_ID=${secrets[1]}`,
    '-----BEGIN PRIVATE KEY-----',
    secrets[2],
  ].join('\n'), 'project/.env');

  assert.deepEqual(findings.map(({ line, rule, confidence, type }) => ({ line, rule, confidence, type })), [
    { line: 1, rule: 'sensitive-key-name', confidence: 'medium', type: 'credential' },
    { line: 2, rule: 'aws-access-key-id', confidence: 'high', type: 'access_key' },
    { line: 3, rule: 'private-key-header', confidence: 'high', type: 'private_key' },
  ]);
  const serialized = JSON.stringify(findings);
  for (const secret of secrets) assert.equal(serialized.includes(secret), false);
  assert.ok(findings.every((finding) => Object.keys(finding).sort().join(',') === 'confidence,filePath,line,rule,type'));
});

test('collector is opt-in when scanPaths is empty', async () => {
  const result = await createCredentialExposureCollector().run({}, { collectorConfig: {} });
  assert.equal(result.status, 'unavailable');
  assert.deepEqual(result.findings, []);
  assert.match(result.reason, /No scanPaths are configured/);
  assert.equal(result.metadata.maxFindings, 200);
});

test('collector scans only allowlisted files and serializes no fixture secrets', async () => {
  await withTempDirectory(async (directory) => {
    const project = path.join(directory, 'project');
    await mkdir(project);
    const secrets = {
      password: 'fixture-password-001',
      token: 'fixture-token-002',
      aws: 'AKIA1234567890ABCDEF',
      ignored: 'fixture-secret-ignored',
    };
    await writeFile(path.join(project, '.env.production'), `password=${secrets.password}\nAWS=${secrets.aws}`);
    await writeFile(path.join(project, 'config.yaml'), `token: ${secrets.token}`);
    await writeFile(path.join(project, 'notes.txt'), `secret=${secrets.ignored}`);
    const collector = createCredentialExposureCollector({ cwd: directory, homeDirectory: path.join(directory, 'home') });

    const result = await collector.run({}, {
      collectorConfig: { scanPaths: ['project'], maxDepth: 6, maxFiles: 200, maxFindings: 200 },
    });

    assert.equal(result.status, 'available');
    assert.equal(result.summary.filesDiscovered, 2);
    assert.equal(result.findings.length, 3);
    assert.ok(result.findings.every((finding) => !path.isAbsolute(finding.filePath)));
    assert.deepEqual(new Set(result.findings.map((finding) => finding.filePath)), new Set(['.env.production', 'config.yaml']));
    assert.ok(result.findings.every((finding) => !finding.filePath.endsWith('notes.txt')));
    const serialized = JSON.stringify(result);
    for (const secret of Object.values(secrets)) assert.equal(serialized.includes(secret), false);
  });
});

test('collector enforces file and finding bounds', async () => {
  await withTempDirectory(async (directory) => {
    const project = path.join(directory, 'project');
    await mkdir(project);
    await writeFile(path.join(project, '.env'), 'password=one\ntoken=two');
    await writeFile(path.join(project, 'config.json'), '{"secret":"three"}');
    const collector = createCredentialExposureCollector({ cwd: directory, homeDirectory: path.join(directory, 'home') });
    const result = await collector.run({}, {
      collectorConfig: { scanPaths: ['project'], maxDepth: 0, maxFiles: 1, maxFindings: 1 },
    });
    assert.equal(result.summary.filesDiscovered, 1);
    assert.equal(result.summary.fileCapReached, true);
    assert.equal(result.summary.findings, 1);
    assert.equal(result.summary.findingCapReached, true);
  });
});

test('collector exposes insufficient privilege without leaking filesystem errors', async () => {
  await withTempDirectory(async (directory) => {
    const project = path.join(directory, 'project');
    await mkdir(project);
    await writeFile(path.join(project, '.env'), 'token=fixture-privileged-secret');
    const error = Object.assign(new Error('sensitive operating-system detail'), { code: 'EACCES' });
    const collector = createCredentialExposureCollector({
      cwd: directory,
      homeDirectory: path.join(directory, 'home'),
      readTextFile: async () => { throw error; },
    });
    const result = await collector.run({}, { collectorConfig: { scanPaths: ['project'] } });
    assert.equal(result.status, 'insufficient_privilege');
    assert.equal(result.traversalWarnings[0].status, 'insufficient_privilege');
    assert.equal(JSON.stringify(result).includes(error.message), false);
    assert.deepEqual(result.findings, []);
  });
});
