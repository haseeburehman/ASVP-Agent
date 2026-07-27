import { realpath } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const PERSONAL_DIRECTORIES = Object.freeze(['Documents', 'Desktop', 'Downloads', 'Pictures', 'Videos', 'Music']);
export const CREDENTIAL_DIRECTORY_NAMES = Object.freeze(['.ssh', '.aws', '.gnupg']);

function normalize(value, pathApi) {
  const resolved = pathApi.normalize(pathApi.resolve(value));
  const parsedRoot = pathApi.parse(resolved).root;
  const normalized = resolved === parsedRoot ? parsedRoot : resolved.replace(/[\\/]+$/, '');
  return process.platform === 'win32' ? normalized.toLowerCase() : normalized;
}

function isWithin(candidate, parent, pathApi) {
  const relative = pathApi.relative(parent, candidate);
  return relative === '' || (!relative.startsWith('..') && !pathApi.isAbsolute(relative));
}

function pathSegments(value) {
  return value.split(/[\\/]+/).filter(Boolean).map((segment) => process.platform === 'win32' ? segment.toLowerCase() : segment);
}

export async function validateScaScanPaths(scanPaths, {
  cwd = process.cwd(),
  homeDirectory = os.homedir(),
  identityPath,
  pathApi = path,
  resolveRealPath = realpath,
} = {}) {
  if (!Array.isArray(scanPaths)) return;
  const canonicalizePolicyDirectory = async (directory) => {
    try {
      return await resolveRealPath(pathApi.resolve(directory));
    } catch {
      return pathApi.resolve(directory);
    }
  };
  const canonicalHomeDirectory = await canonicalizePolicyDirectory(homeDirectory);
  const home = normalize(canonicalHomeDirectory, pathApi);
  const identityDirectory = identityPath
    ? normalize(await canonicalizePolicyDirectory(pathApi.dirname(pathApi.resolve(cwd, identityPath))), pathApi)
    : null;
  const personalDirectories = PERSONAL_DIRECTORIES.map((name) => normalize(pathApi.join(canonicalHomeDirectory, name), pathApi));
  const personalNames = new Set(PERSONAL_DIRECTORIES.map((name) => process.platform === 'win32' ? name.toLowerCase() : name));
  const credentialNames = new Set(CREDENTIAL_DIRECTORY_NAMES.map((name) => process.platform === 'win32' ? name.toLowerCase() : name));

  for (const configuredPath of scanPaths) {
    const unresolvedPath = pathApi.resolve(cwd, configuredPath);
    let canonicalPath;
    try {
      canonicalPath = await resolveRealPath(unresolvedPath);
    } catch (error) {
      throw new Error(`SCA scan path "${configuredPath}" cannot be resolved to a canonical path: ${error.message}`, { cause: error });
    }
    const absolutePath = normalize(canonicalPath, pathApi);
    const root = normalize(pathApi.parse(absolutePath).root, pathApi);
    let reason = null;
    if (absolutePath === root) reason = 'filesystem root paths are not allowed';
    else if (absolutePath === home) reason = 'the current user home directory is not allowed';
    else if (personalDirectories.some((directory) => isWithin(absolutePath, directory, pathApi))
      || (isWithin(absolutePath, home, pathApi) && pathSegments(absolutePath).some((segment) => personalNames.has(segment)))) reason = 'personal-data directories are not allowed';
    else if (identityDirectory && isWithin(absolutePath, identityDirectory, pathApi)) reason = 'the agent identity storage directory is not allowed';
    else if (pathSegments(absolutePath).some((segment) => credentialNames.has(segment))) reason = 'credential directories (.ssh, .aws, .gnupg) are not allowed';
    if (reason) throw new Error(`SCA scan path "${configuredPath}" is forbidden: ${reason}`);
  }
}
