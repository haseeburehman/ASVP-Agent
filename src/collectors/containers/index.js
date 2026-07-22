import { Writable } from 'node:stream';
import Dockerode from 'dockerode';

const EXEC_OUTPUT_LIMIT_BYTES = 4 * 1024 * 1024;

export const LINUX_OS_COMMAND = [
  '/bin/sh',
  '-c',
  'if [ -r /etc/os-release ]; then cat /etc/os-release; elif [ -r /usr/lib/os-release ]; then cat /usr/lib/os-release; else exit 127; fi',
];

export const LINUX_PACKAGES_COMMAND = [
  '/bin/sh',
  '-c',
  "if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='dpkg\\t${binary:Package}\\t${Version}\\n'; elif command -v rpm >/dev/null 2>&1; then rpm -qa --qf 'rpm\\t%{NAME}\\t%{VERSION}-%{RELEASE}\\n'; elif command -v apk >/dev/null 2>&1; then apk info -v | while IFS= read -r p; do printf 'apk\\t%s\\n' \"$p\"; done; else exit 127; fi",
];

export const WINDOWS_OS_COMMAND = ['cmd.exe', '/D', '/S', '/C', 'ver'];

function abortError() {
  const error = new Error('Container inspection was aborted');
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

function checkAbort(signal) {
  if (signal?.aborted) throw abortError();
}

function field(value, source, reason = null) {
  return { value, source, reason };
}

function unavailableField(reason) {
  return field(null, null, reason);
}

function classifyDockerError(error) {
  const text = `${error.code ?? ''} ${error.message ?? ''}`.toLowerCase();
  if (error.statusCode === 403 || /eacces|eperm|permission denied|access is denied/.test(text)) {
    return `Docker is present but the agent lacks permission to access the Docker Engine API: ${error.message}`;
  }
  if (/enoent|econnrefused|enxio|not found|cannot find|is not running/.test(text)) {
    return `Docker Engine is not installed, not running, or its local socket is unavailable: ${error.message}`;
  }
  return `Docker Engine API is unavailable: ${error.message}`;
}

export class DockerEngineClient {
  constructor({ docker } = {}) {
    this.docker = docker ?? new Dockerode(
      process.platform === 'win32'
        ? { socketPath: '//./pipe/docker_engine' }
        : { socketPath: '/var/run/docker.sock' },
    );
  }

  listRunningContainers() {
    return this.docker.listContainers({ all: false });
  }

  inspectContainer(containerId) {
    return this.docker.getContainer(containerId).inspect();
  }

  inspectImage(imageReference) {
    return this.docker.getImage(imageReference).inspect();
  }

  async execReadOnly(containerId, command, { signal, maxOutputBytes = EXEC_OUTPUT_LIMIT_BYTES } = {}) {
    checkAbort(signal);
    const container = this.docker.getContainer(containerId);
    const exec = await container.exec({
      AttachStdout: true,
      AttachStderr: true,
      AttachStdin: false,
      Tty: false,
      Cmd: command,
    });
    const stream = await exec.start({ hijack: true, stdin: false });

    return new Promise((resolve, reject) => {
      const stdoutChunks = [];
      const stderrChunks = [];
      let bytes = 0;
      let settled = false;
      const finish = (callback, value) => {
        if (settled) return;
        settled = true;
        signal?.removeEventListener('abort', abortHandler);
        callback(value);
      };
      const append = (target, chunk) => {
        bytes += chunk.length;
        if (bytes > maxOutputBytes) {
          const error = new Error(`Container exec output exceeded the ${maxOutputBytes}-byte safety limit`);
          error.code = 'EXEC_OUTPUT_LIMIT';
          stream.destroy(error);
          finish(reject, error);
          return;
        }
        target.push(Buffer.from(chunk));
      };
      const stdout = new Writable({ write(chunk, _encoding, callback) { append(stdoutChunks, chunk); callback(); } });
      const stderr = new Writable({ write(chunk, _encoding, callback) { append(stderrChunks, chunk); callback(); } });
      const abortHandler = () => {
        stream.destroy();
        finish(reject, abortError());
      };

      signal?.addEventListener('abort', abortHandler, { once: true });
      this.docker.modem.demuxStream(stream, stdout, stderr);
      stream.once('error', (error) => finish(reject, error));
      stream.once('end', async () => {
        try {
          const details = await exec.inspect();
          const output = Buffer.concat(stdoutChunks).toString('utf8').trim();
          const errorOutput = Buffer.concat(stderrChunks).toString('utf8').trim();
          if (details.ExitCode !== 0) {
            const error = new Error(`Read-only container command exited with code ${details.ExitCode}: ${errorOutput || 'no error output'}`);
            error.code = 'CONTAINER_EXEC_FAILED';
            finish(reject, error);
          } else {
            finish(resolve, output);
          }
        } catch (error) {
          finish(reject, error);
        }
      });
    });
  }
}

function parseOsRelease(output) {
  const values = {};
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(/^([A-Z_]+)=(.*)$/);
    if (!match) continue;
    values[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
  }
  return values.PRETTY_NAME || values.VERSION || values.VERSION_ID || null;
}

function parseApkPackage(value) {
  const match = value.match(/^(.+?)-([0-9][A-Za-z0-9._+~-]*(?:-r\d+)?)$/);
  return match ? { name: match[1], version: match[2] } : { name: value, version: null };
}

export function parsePackageList(output) {
  const packages = [];
  for (const line of output.split(/\r?\n/)) {
    if (!line) continue;
    const [manager, nameOrRecord, version] = line.split('\t');
    if (manager === 'dpkg' || manager === 'rpm') {
      if (nameOrRecord) packages.push({ name: nameOrRecord, version: version || null, manager });
    } else if (manager === 'apk' && nameOrRecord) {
      packages.push({ ...parseApkPackage(nameOrRecord), manager });
    }
  }
  return packages;
}

async function collectInternalOs(client, containerId, containerPlatform, signal) {
  const command = containerPlatform === 'windows' ? WINDOWS_OS_COMMAND : LINUX_OS_COMMAND;
  try {
    const output = await client.execReadOnly(containerId, command, { signal });
    const version = containerPlatform === 'windows' ? output || null : parseOsRelease(output);
    if (!version) return unavailableField('The fixed OS-release command returned no recognizable version');
    return field(version, containerPlatform === 'windows' ? 'cmd-ver' : 'os-release');
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return unavailableField(`Unable to determine the internal OS version with the fixed read-only command: ${error.message}`);
  }
}

async function collectPackages(client, containerId, containerPlatform, maxPackages, signal) {
  if (containerPlatform === 'windows') {
    return {
      packages: null,
      source: null,
      reason: 'Windows container package inventory is not supported in this phase',
      totalDetected: 0,
      truncated: 0,
      format: 'best-effort-package-list',
    };
  }
  try {
    const output = await client.execReadOnly(containerId, LINUX_PACKAGES_COMMAND, { signal });
    const allPackages = parsePackageList(output);
    return {
      packages: allPackages.slice(0, maxPackages),
      source: allPackages[0]?.manager ?? 'container-package-manager',
      reason: allPackages.length === 0 ? 'No supported package-manager records were returned' : null,
      totalDetected: allPackages.length,
      truncated: Math.max(0, allPackages.length - maxPackages),
      format: 'best-effort-package-list',
    };
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return {
      packages: null,
      source: null,
      reason: `Unable to list packages with the fixed read-only command: ${error.message}`,
      totalDetected: 0,
      truncated: 0,
      format: 'best-effort-package-list',
    };
  }
}

async function inspectRunningContainer(client, container, maxPackages, signal) {
  checkAbort(signal);
  const containerId = container.Id;
  const imageName = container.Image || null;
  let containerDetails;
  let imageDetails;
  try {
    containerDetails = await client.inspectContainer(containerId);
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    const reason = `Unable to inspect container metadata: ${error.message}`;
    return {
      containerId,
      imageName,
      internalOs: unavailableField(reason),
      sbom: {
        packages: null,
        source: null,
        reason,
        totalDetected: 0,
        truncated: 0,
        format: 'best-effort-package-list',
      },
    };
  }

  checkAbort(signal);
  try {
    imageDetails = await client.inspectImage(containerDetails.Image || imageName);
  } catch {
    imageDetails = null;
  }
  const containerPlatform = String(imageDetails?.Os || containerDetails.Platform || 'linux').toLowerCase();
  const internalOs = await collectInternalOs(client, containerId, containerPlatform, signal);
  checkAbort(signal);
  const sbom = await collectPackages(client, containerId, containerPlatform, maxPackages, signal);
  return {
    containerId,
    imageName: containerDetails.Config?.Image || imageName,
    internalOs,
    sbom,
  };
}

export function createContainersCollector({ client } = {}) {
  return {
    name: 'containers',
    version: '1.0.0',
    async run(_params = {}, context = {}) {
      const config = context.collectorConfig ?? {};
      const maxContainers = Number.isInteger(config.maxContainers) && config.maxContainers > 0
        ? config.maxContainers
        : 20;
      const maxPackagesPerContainer = Number.isInteger(config.maxPackagesPerContainer)
        && config.maxPackagesPerContainer > 0
        ? config.maxPackagesPerContainer
        : 500;
      const dockerClient = client ?? new DockerEngineClient();
      const metadata = {
        engine: 'docker',
        runningContainersOnly: true,
        stoppedContainersExcluded: true,
        sbomFormat: 'best-effort-package-list-not-cyclonedx',
        readOnly: true,
        fixedCommands: {
          linuxOs: LINUX_OS_COMMAND,
          linuxPackages: LINUX_PACKAGES_COMMAND,
          windowsOs: WINDOWS_OS_COMMAND,
        },
      };

      let running;
      try {
        checkAbort(context.signal);
        running = await dockerClient.listRunningContainers();
      } catch (error) {
        if (error.name === 'AbortError') throw error;
        return {
          available: false,
          reason: classifyDockerError(error),
          metadata,
          summary: {
            totalRunning: 0,
            inspected: 0,
            truncated: 0,
            maxContainers,
            maxPackagesPerContainer,
          },
          containers: [],
        };
      }

      const selected = running.slice(0, maxContainers);
      const containers = [];
      for (const container of selected) {
        checkAbort(context.signal);
        containers.push(await inspectRunningContainer(
          dockerClient,
          container,
          maxPackagesPerContainer,
          context.signal,
        ));
      }

      return {
        available: true,
        reason: running.length === 0 ? 'Docker Engine is available, but no containers are currently running' : null,
        metadata,
        summary: {
          totalRunning: running.length,
          inspected: containers.length,
          truncated: Math.max(0, running.length - selected.length),
          maxContainers,
          maxPackagesPerContainer,
        },
        containers,
      };
    },
  };
}

export const containersCollector = createContainersCollector();
export default containersCollector;
