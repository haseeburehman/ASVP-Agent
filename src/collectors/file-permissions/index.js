import { lstat, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { createAbortError, runBoundedCommand } from '../shared/exec-utils.js';

export const UNIX_PERMISSION_PATHS = Object.freeze([
  '/etc/passwd',
  '/etc/shadow',
  '/etc/sudoers',
  '/tmp',
  '/var/tmp',
  '/var/www',
  '/srv/www',
]);

export const LINUX_EXECUTABLE_DIRECTORIES = Object.freeze([
  '/usr/bin',
  '/usr/sbin',
  '/bin',
  '/sbin',
]);

export const WINDOWS_ACL_PATHS = Object.freeze([
  'C:\\Windows\\Temp',
  'C:\\Windows\\System32',
]);

export const WINDOWS_ICACLS_COMMAND = Object.freeze({ executable: 'icacls.exe' });
export const COMMAND_TIMEOUT_MS = 5000;
export const MAX_COMMAND_OUTPUT_BYTES = 64 * 1024;
export const MAX_LINUX_CHILDREN = 4096;
export const MAX_PRIVILEGED_FILES = 1024;

const defaultFs = Object.freeze({ stat, lstat, readdir });

function abortIfNeeded(signal) {
  if (signal?.aborted) throw createAbortError('File permission collection was aborted');
}

function permissionFailure(error) {
  return ['EACCES', 'EPERM'].includes(error?.code)
    || /access (?:is )?denied|permission denied|operation not permitted|requires? (?:administrator|root)|insufficient privilege/i.test(error?.message ?? '');
}

function missingFailure(error) {
  return error?.code === 'ENOENT'
    || /cannot find|could not find|does not exist|no such file or directory/i.test(error?.message ?? '');
}

function failedPath(target, error, windows = false) {
  const status = missingFailure(error) ? 'not_present'
    : permissionFailure(error) ? 'insufficient_privilege' : 'unavailable';
  return {
    path: target,
    exists: status === 'not_present' ? false : null,
    mode: windows ? null : null,
    aclSummary: windows ? null : null,
    worldWritable: windows ? null : null,
    overlyPermissive: null,
    status,
    reason: status === 'not_present'
      ? 'Path is not present'
      : status === 'insufficient_privilege'
        ? `Permission metadata is not accessible with current privileges: ${error.message}`
        : `Permission metadata is unavailable: ${error.message}`,
  };
}

function unixPath(target, metadata) {
  const mode = metadata.mode & 0o7777;
  const worldWritable = (mode & 0o002) !== 0;
  const stickyTemporaryDirectory = ['/tmp', '/var/tmp'].includes(target) && (mode & 0o1000) !== 0;
  return {
    path: target,
    exists: true,
    mode: mode.toString(8).padStart(4, '0'),
    aclSummary: null,
    worldWritable,
    overlyPermissive: worldWritable && !stickyTemporaryDirectory,
    status: 'available',
    reason: null,
  };
}

async function inspectUnixPath(target, fsApi, signal) {
  try {
    const metadata = await fsApi.stat(target);
    abortIfNeeded(signal);
    return unixPath(target, metadata);
  } catch (error) {
    if (error?.name === 'AbortError') throw error;
    return failedPath(target, error);
  }
}

async function collectPrivilegedExecutables(fsApi, signal) {
  const files = [];
  let inspectedChildren = 0;
  let truncated = false;

  for (const directory of LINUX_EXECUTABLE_DIRECTORIES) {
    abortIfNeeded(signal);
    let entries;
    try {
      entries = await fsApi.readdir(directory, { withFileTypes: true });
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      continue;
    }

    for (const entry of entries) {
      if (inspectedChildren >= MAX_LINUX_CHILDREN || files.length >= MAX_PRIVILEGED_FILES) {
        truncated = true;
        break;
      }
      inspectedChildren += 1;
      const childPath = path.posix.join(directory, entry.name);
      try {
        const metadata = await fsApi.lstat(childPath);
        abortIfNeeded(signal);
        if (metadata.isSymbolicLink()) continue;
        if ((metadata.mode & 0o6000) !== 0) files.push(unixPath(childPath, metadata));
      } catch (error) {
        if (error?.name === 'AbortError') throw error;
        if (permissionFailure(error)) files.push(failedPath(childPath, error));
      }
    }
    if (truncated) break;
  }

  return { files, inspectedChildren, truncated };
}

function hasBroadFullControl(output) {
  return String(output).split(/\r?\n/).some((line) => (
    /(?:Everyone|\*S-1-1-0|BUILTIN\\Users|\*S-1-5-32-545)\s*:\s*(?:\([^)]*\))*\(F\)/i.test(line)
  ));
}

function windowsPath(target, output) {
  const aclSummary = String(output).trim();
  const overlyPermissive = hasBroadFullControl(aclSummary);
  return {
    path: target,
    exists: true,
    mode: null,
    aclSummary,
    worldWritable: null,
    overlyPermissive,
    status: 'available',
    reason: null,
  };
}

async function collectWindows(runCommand, signal) {
  return Promise.all(WINDOWS_ACL_PATHS.map(async (target) => {
    try {
      const output = await runCommand(WINDOWS_ICACLS_COMMAND.executable, [target], {
        signal,
        timeoutMs: COMMAND_TIMEOUT_MS,
        maxOutputBytes: MAX_COMMAND_OUTPUT_BYTES,
      });
      abortIfNeeded(signal);
      return windowsPath(target, output);
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      return failedPath(target, error, true);
    }
  }));
}

function wrapper(platform, paths, privilegedExecutables = []) {
  const fields = [...paths, ...privilegedExecutables];
  const insufficient = fields.some(({ status }) => status === 'insufficient_privilege');
  const available = fields.some(({ status }) => status === 'available');
  const status = insufficient ? 'insufficient_privilege' : available ? 'available' : 'unavailable';
  return {
    platform,
    status,
    reasonCode: status === 'available' ? null : status,
    reason: status === 'insufficient_privilege'
      ? 'One or more permission checks require additional privileges'
      : status === 'unavailable' ? 'No permission metadata was available' : null,
  };
}

export function createFilePermissionsCollector({
  platform = process.platform,
  fsApi = defaultFs,
  runCommand = runBoundedCommand,
} = {}) {
  return {
    name: 'file-permissions',
    version: '1.0.0',
    async run(_params = {}, context = {}) {
      const signal = context.signal;
      abortIfNeeded(signal);

      if (platform === 'win32') {
        const paths = await collectWindows(runCommand, signal);
        return { ...wrapper(platform, paths), paths, privilegedExecutables: [], scan: null };
      }

      if (platform === 'linux' || platform === 'darwin') {
        const paths = await Promise.all(UNIX_PERMISSION_PATHS.map((target) => inspectUnixPath(target, fsApi, signal)));
        if (platform === 'darwin') return { ...wrapper(platform, paths), paths, privilegedExecutables: [], scan: null };
        const scan = await collectPrivilegedExecutables(fsApi, signal);
        return {
          ...wrapper(platform, paths, scan.files),
          paths,
          privilegedExecutables: scan.files,
          scan: { inspectedChildren: scan.inspectedChildren, truncated: scan.truncated, hardCap: MAX_LINUX_CHILDREN },
        };
      }

      const reason = `File permission collection is unsupported on platform "${platform}"`;
      return {
        platform,
        status: 'unavailable',
        reasonCode: 'unavailable',
        reason,
        paths: [],
        privilegedExecutables: [],
        scan: null,
      };
    },
  };
}

export const filePermissionsCollector = createFilePermissionsCollector();
export default filePermissionsCollector;
