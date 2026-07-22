import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  createScaDepsCollector,
  discoverManifests,
  parseGoMod,
  parseNpmManifest,
  parsePipfileLock,
  parsePomXml,
  parseRequirements,
} from '../../src/collectors/sca-deps/index.js';

const fixtureRoot = path.resolve('test/fixtures/sca-project');

async function withTempDirectory(callback) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'asvp-sca-'));
  try {
    await callback(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test('npm parser prefers package-lock resolved versions', () => {
  const packageJson = JSON.stringify({
    dependencies: { express: '^4.18.0' },
    devDependencies: { eslint: '^9.0.0' },
  });
  const lock = JSON.stringify({
    packages: {
      'node_modules/express': { version: '4.21.2' },
      'node_modules/eslint': { version: '9.18.0' },
    },
  });

  const dependencies = parseNpmManifest(packageJson, lock, '/project/package.json');

  assert.deepEqual(dependencies.map(({ name, version }) => ({ name, version })), [
    { name: 'express', version: '4.21.2' },
    { name: 'eslint', version: '9.18.0' },
  ]);
  assert.ok(dependencies.every((item) => item.importStatus === 'declared'));
  assert.ok(dependencies.every((item) => item.manifestPath === '/project/package.json'));
});

test('pip parsers support requirements.txt and Pipfile.lock', () => {
  const requirements = parseRequirements('requests==2.32.3\nflask>=3.0\n# ignored\n-r other.txt');
  const lock = parsePipfileLock(JSON.stringify({
    default: { urllib3: { version: '==2.3.0' } },
    develop: { pytest: { version: '==8.3.4' } },
  }));

  assert.deepEqual(requirements.map(({ name, version }) => [name, version]), [
    ['requests', '==2.32.3'],
    ['flask', '>=3.0'],
  ]);
  assert.deepEqual(lock.map(({ name, version, scope }) => [name, version, scope]), [
    ['urllib3', '==2.3.0', 'runtime'],
    ['pytest', '==8.3.4', 'development'],
  ]);
});

test('Maven parser returns direct dependencies and resolves project properties', () => {
  const dependencies = parsePomXml(`
    <project>
      <properties><jackson.version>2.18.2</jackson.version></properties>
      <dependencies>
        <dependency>
          <groupId>com.fasterxml.jackson.core</groupId>
          <artifactId>jackson-databind</artifactId>
          <version>\${jackson.version}</version>
        </dependency>
      </dependencies>
      <dependencyManagement>
        <dependencies><dependency><groupId>ignored</groupId><artifactId>transitive</artifactId></dependency></dependencies>
      </dependencyManagement>
    </project>
  `);

  assert.equal(dependencies.length, 1);
  assert.equal(dependencies[0].name, 'com.fasterxml.jackson.core:jackson-databind');
  assert.equal(dependencies[0].version, '2.18.2');
});

test('Go parser supports block and single require directives with optional checksums', () => {
  const dependencies = parseGoMod(`
    module example.com/test
    require github.com/google/uuid v1.6.0
    require (
      golang.org/x/text v0.21.0
    )
  `, 'github.com/google/uuid v1.6.0 h1:checksum');

  assert.deepEqual(dependencies.map(({ name, version }) => [name, version]), [
    ['github.com/google/uuid', 'v1.6.0'],
    ['golang.org/x/text', 'v0.21.0'],
  ]);
  assert.equal(dependencies[0].checksum, 'h1:checksum');
  assert.equal(dependencies[1].checksum, null);
});

test('no configured scan paths safely returns an empty result', async () => {
  const result = await createScaDepsCollector().run({}, { collectorConfig: {} });

  assert.deepEqual(result.dependencies, []);
  assert.equal(result.summary.manifestsDiscovered, 0);
  assert.match(result.reason, /No scanPaths are configured/);
  assert.match(result.metadata.importStatusLimitation, /static analysis/);
});

test('traversal enforces maxDepth and skips dependency noise directories', async () => {
  const discovery = await discoverManifests({
    scanPaths: [fixtureRoot],
    maxDepth: 1,
    maxManifests: 100,
  });

  assert.ok(discovery.manifests.some((file) => file.endsWith(path.join('npm', 'package.json'))));
  assert.ok(!discovery.manifests.some((file) => file.includes(`vendor${path.sep}`)));
  assert.ok(!discovery.manifests.some((file) => file.includes(`deep${path.sep}one${path.sep}two`)));
});

test('traversal stops at maxManifests and reports the cap', async () => {
  const discovery = await discoverManifests({
    scanPaths: [fixtureRoot],
    maxDepth: 6,
    maxManifests: 2,
  });

  assert.equal(discovery.manifests.length, 2);
  assert.equal(discovery.capReached, true);
});

test('filesystem traversal responds to abort signals', async () => {
  const controller = new AbortController();
  controller.abort();

  await assert.rejects(
    discoverManifests({
      scanPaths: [fixtureRoot],
      maxDepth: 6,
      maxManifests: 100,
      signal: controller.signal,
    }),
    (error) => error.name === 'AbortError',
  );
});

test('malformed manifests are skipped with a reason without failing collection', async () => {
  await withTempDirectory(async (directory) => {
    await mkdir(path.join(directory, 'project'));
    await writeFile(path.join(directory, 'project', 'package.json'), '{not-json');
    await writeFile(path.join(directory, 'project', 'requirements.txt'), 'valid-package==1.0.0');
    const collector = createScaDepsCollector({ cwd: directory });

    const result = await collector.run({}, {
      collectorConfig: { scanPaths: ['project'], maxDepth: 2, maxManifests: 10 },
    });

    assert.equal(result.dependencies.length, 1);
    assert.equal(result.dependencies[0].name, 'valid-package');
    const malformed = result.manifests.find((manifest) => manifest.path.endsWith('package.json'));
    assert.equal(malformed.status, 'skipped');
    assert.match(malformed.reason, /Malformed package.json/);
  });
});

test('fixture project is collected end-to-end with declared-only status', async () => {
  const collector = createScaDepsCollector();
  const result = await collector.run({}, {
    collectorConfig: { scanPaths: [fixtureRoot], maxDepth: 6, maxManifests: 100 },
  });

  const names = new Set(result.dependencies.map((item) => item.name));
  for (const expected of [
    'express',
    'eslint',
    'requests',
    'flask',
    'urllib3',
    'pytest',
    'org.junit.jupiter:junit-jupiter',
    'github.com/google/uuid',
    'golang.org/x/text',
    'too-deep',
  ]) assert.ok(names.has(expected), `Expected fixture dependency ${expected}`);

  assert.ok(!names.has('must-not-be-scanned'));
  assert.equal(result.dependencies.filter((item) => item.name === 'express').length, 1);
  assert.ok(result.dependencies.find((item) => item.name === 'express').manifestPath.endsWith('package.json'));
  assert.ok(result.dependencies.every((item) => item.importStatus === 'declared'));
  assert.ok(result.dependencies.every((item) => path.isAbsolute(item.manifestPath)));
  assert.equal(result.reason, null);
  assert.equal(result.summary.capReached, false);
});
