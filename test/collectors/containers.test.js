import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createContainersCollector,
  LINUX_OS_COMMAND,
  LINUX_PACKAGES_COMMAND,
  WINDOWS_OS_COMMAND,
} from '../../src/collectors/containers/index.js';

function createMockClient(overrides = {}) {
  const running = [
    { Id: 'container-1', Image: 'ubuntu:24.04' },
    { Id: 'container-2', Image: 'alpine:3.20' },
    { Id: 'container-3', Image: 'debian:12' },
  ];
  return {
    async listRunningContainers() { return running; },
    async inspectContainer(containerId) {
      const source = running.find((item) => item.Id === containerId);
      return { Image: `sha256:${containerId}`, Platform: 'linux', Config: { Image: source.Image } };
    },
    async inspectImage() { return { Os: 'linux' }; },
    async execReadOnly(_containerId, command) {
      if (command === LINUX_OS_COMMAND) return 'PRETTY_NAME="Ubuntu 24.04 LTS"\nVERSION_ID="24.04"';
      if (command === LINUX_PACKAGES_COMMAND) {
        return 'dpkg\tlibc6\t2.39\ndpkg\topenssl\t3.0.13\ndpkg\tzlib1g\t1.3.1';
      }
      throw new Error('Unexpected command');
    },
    ...overrides,
  };
}

test('containers collector inspects running Docker containers through the mocked API', async () => {
  const collector = createContainersCollector({ client: createMockClient() });
  const result = await collector.run({}, {
    collectorConfig: { maxContainers: 2, maxPackagesPerContainer: 10 },
  });

  assert.equal(result.available, true);
  assert.equal(result.summary.totalRunning, 3);
  assert.equal(result.summary.inspected, 2);
  assert.equal(result.summary.truncated, 1);
  assert.equal(result.containers[0].containerId, 'container-1');
  assert.equal(result.containers[0].imageName, 'ubuntu:24.04');
  assert.equal(result.containers[0].internalOs.value, 'Ubuntu 24.04 LTS');
  assert.equal(result.containers[0].internalOs.reason, null);
  assert.equal(result.containers[0].sbom.packages.length, 3);
  assert.equal(result.containers[0].sbom.packages[0].name, 'libc6');
});

test('maxPackagesPerContainer caps package output and reports truncation', async () => {
  const collector = createContainersCollector({ client: createMockClient() });
  const result = await collector.run({}, {
    collectorConfig: { maxContainers: 1, maxPackagesPerContainer: 2 },
  });

  assert.equal(result.containers[0].sbom.totalDetected, 3);
  assert.equal(result.containers[0].sbom.packages.length, 2);
  assert.equal(result.containers[0].sbom.truncated, 1);
});

test('Docker unavailable is a successful empty collector result with a reason', async () => {
  const error = new Error('connect ENOENT /var/run/docker.sock');
  error.code = 'ENOENT';
  const collector = createContainersCollector({
    client: createMockClient({ async listRunningContainers() { throw error; } }),
  });

  const result = await collector.run({}, { collectorConfig: {} });

  assert.equal(result.available, false);
  assert.deepEqual(result.containers, []);
  assert.match(result.reason, /not installed, not running, or its local socket is unavailable/);
});

test('Docker socket permission denial is reported without throwing', async () => {
  const error = new Error('permission denied connecting to docker.sock');
  error.code = 'EACCES';
  const collector = createContainersCollector({
    client: createMockClient({ async listRunningContainers() { throw error; } }),
  });

  const result = await collector.run({}, { collectorConfig: {} });

  assert.equal(result.available, false);
  assert.match(result.reason, /lacks permission/);
});

test('exec failures degrade internal OS and package fields independently', async () => {
  const collector = createContainersCollector({
    client: createMockClient({
      async listRunningContainers() { return [{ Id: 'minimal', Image: 'distroless:latest' }]; },
      async inspectContainer() {
        return { Image: 'sha256:minimal', Platform: 'linux', Config: { Image: 'distroless:latest' } };
      },
      async execReadOnly(_id, command) {
        if (command === LINUX_OS_COMMAND) throw new Error('/bin/sh not found');
        throw new Error('no supported package manager');
      },
    }),
  });

  const result = await collector.run({}, {
    collectorConfig: { maxContainers: 1, maxPackagesPerContainer: 10 },
  });

  assert.equal(result.available, true);
  assert.equal(result.containers[0].internalOs.value, null);
  assert.match(result.containers[0].internalOs.reason, /\/bin\/sh not found/);
  assert.equal(result.containers[0].sbom.packages, null);
  assert.match(result.containers[0].sbom.reason, /no supported package manager/);
});

test('fixed inspection commands contain no task or container-derived input', () => {
  assert.deepEqual(LINUX_OS_COMMAND.slice(0, 2), ['/bin/sh', '-c']);
  assert.match(LINUX_OS_COMMAND[2], /\/etc\/os-release/);
  assert.deepEqual(LINUX_PACKAGES_COMMAND.slice(0, 2), ['/bin/sh', '-c']);
  assert.match(LINUX_PACKAGES_COMMAND[2], /dpkg-query/);
  assert.match(LINUX_PACKAGES_COMMAND[2], /rpm/);
  assert.match(LINUX_PACKAGES_COMMAND[2], /apk/);
  assert.deepEqual(WINDOWS_OS_COMMAND, ['cmd.exe', '/D', '/S', '/C', 'ver']);
});
