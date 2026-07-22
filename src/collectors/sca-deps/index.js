import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { XMLParser } from 'fast-xml-parser';

const MANIFEST_NAMES = new Set([
  'package.json',
  'package-lock.json',
  'requirements.txt',
  'Pipfile.lock',
  'pom.xml',
  'go.mod',
  'go.sum',
]);
const NOISE_DIRECTORIES = new Set([
  'node_modules',
  '.git',
  'vendor',
  'site-packages',
  '__pycache__',
  '.venv',
  'venv',
  'dist',
  'build',
  'target',
]);
const IMPORT_STATUS_NOTE = 'Import status is "declared" because reliable used/unused detection requires ecosystem-specific static analysis, which is not performed.';

function abortError() {
  const error = new Error('Dependency manifest collection was aborted');
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

function checkAbort(signal) {
  if (signal?.aborted) throw abortError();
}

function dependency(ecosystem, name, version, manifestPath, extra = {}) {
  return {
    ecosystem,
    name,
    version: version == null ? null : String(version),
    importStatus: 'declared',
    manifestPath,
    ...extra,
  };
}

function parseJson(content, label) {
  try {
    return JSON.parse(content);
  } catch (error) {
    throw new Error(`Malformed ${label}: ${error.message}`, { cause: error });
  }
}

export function parseNpmManifest(packageContent, lockContent, manifestPath = 'package.json') {
  const manifest = parseJson(packageContent, 'package.json');
  const lock = lockContent ? parseJson(lockContent, 'package-lock.json') : null;
  const sections = [
    ['dependencies', 'runtime'],
    ['devDependencies', 'development'],
    ['optionalDependencies', 'optional'],
    ['peerDependencies', 'peer'],
  ];
  const seen = new Set();
  const results = [];
  for (const [section, scope] of sections) {
    for (const [name, declaredVersion] of Object.entries(manifest[section] ?? {})) {
      if (seen.has(name)) continue;
      seen.add(name);
      const resolvedVersion = lock?.packages?.[`node_modules/${name}`]?.version
        ?? lock?.dependencies?.[name]?.version
        ?? declaredVersion;
      results.push(dependency('npm', name, resolvedVersion, manifestPath, {
        scope,
        declaredVersion: String(declaredVersion),
        resolvedFromLockfile: Boolean(lock && resolvedVersion !== declaredVersion),
      }));
    }
  }
  return results;
}

export function parsePackageLock(content, manifestPath = 'package-lock.json') {
  const lock = parseJson(content, 'package-lock.json');
  const root = lock.packages?.[''] ?? lock;
  const declarations = {
    ...(root.dependencies ?? {}),
    ...(root.devDependencies ?? {}),
    ...(root.optionalDependencies ?? {}),
  };
  return Object.entries(declarations).map(([name, declaredVersion]) => dependency(
    'npm',
    name,
    lock.packages?.[`node_modules/${name}`]?.version ?? lock.dependencies?.[name]?.version ?? declaredVersion,
    manifestPath,
    { declaredVersion: String(declaredVersion), resolvedFromLockfile: true },
  ));
}

export function parseRequirements(content, manifestPath = 'requirements.txt') {
  const results = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    const withoutComment = line.split(/\s+#/, 1)[0].split(';', 1)[0].trim();
    const match = withoutComment.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)$/);
    if (!match) continue;
    results.push(dependency('pip', match[1], match[2] || null, manifestPath));
  }
  return results;
}

export function parsePipfileLock(content, manifestPath = 'Pipfile.lock') {
  const lock = parseJson(content, 'Pipfile.lock');
  const results = [];
  for (const [section, scope] of [['default', 'runtime'], ['develop', 'development']]) {
    for (const [name, record] of Object.entries(lock[section] ?? {})) {
      const version = typeof record === 'string' ? record : record?.version;
      results.push(dependency('pip', name, version ?? null, manifestPath, { scope }));
    }
  }
  return results;
}

function asArray(value) {
  if (value == null) return [];
  return Array.isArray(value) ? value : [value];
}

export function parsePomXml(content, manifestPath = 'pom.xml') {
  let project;
  try {
    project = new XMLParser({ ignoreAttributes: false, trimValues: true }).parse(content)?.project;
  } catch (error) {
    throw new Error(`Malformed pom.xml: ${error.message}`, { cause: error });
  }
  if (!project) throw new Error('Malformed pom.xml: missing project element');
  const properties = project.properties ?? {};
  return asArray(project.dependencies?.dependency).map((record) => {
    let version = record.version ?? null;
    const property = typeof version === 'string' && version.match(/^\$\{(.+)\}$/)?.[1];
    if (property && properties[property] != null) version = properties[property];
    return dependency('maven', `${record.groupId}:${record.artifactId}`, version, manifestPath, {
      groupId: record.groupId ?? null,
      artifactId: record.artifactId ?? null,
      scope: record.scope ?? 'compile',
    });
  });
}

function goChecksums(content = '') {
  const checksums = new Map();
  for (const line of content.split(/\r?\n/)) {
    const [name, version, checksum] = line.trim().split(/\s+/);
    if (name && version && checksum && !version.endsWith('/go.mod')) checksums.set(`${name}@${version}`, checksum);
  }
  return checksums;
}

export function parseGoMod(content, sumContent = '', manifestPath = 'go.mod') {
  const checksums = goChecksums(sumContent);
  const requirements = [];
  let inRequireBlock = false;
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.replace(/\/\/.*$/, '').trim();
    if (!line) continue;
    if (line === 'require (') {
      inRequireBlock = true;
      continue;
    }
    if (inRequireBlock && line === ')') {
      inRequireBlock = false;
      continue;
    }
    const match = inRequireBlock
      ? line.match(/^(\S+)\s+(\S+)/)
      : line.match(/^require\s+(\S+)\s+(\S+)/);
    if (match) requirements.push([match[1], match[2]]);
  }
  return requirements.map(([name, version]) => dependency('go', name, version, manifestPath, {
    checksum: checksums.get(`${name}@${version}`) ?? null,
  }));
}

export async function discoverManifests({
  scanPaths,
  maxDepth,
  maxManifests,
  signal,
  cwd = process.cwd(),
  fs = { readDirectory: readdir, statPath: stat },
}) {
  const manifests = [];
  const skipped = [];
  const queue = [];
  let capReached = false;

  for (const configuredPath of scanPaths) {
    checkAbort(signal);
    const absolutePath = path.resolve(cwd, configuredPath);
    try {
      const details = await fs.statPath(absolutePath);
      if (details.isFile()) {
        if (MANIFEST_NAMES.has(path.basename(absolutePath))) manifests.push(absolutePath);
        else skipped.push({ path: absolutePath, reason: 'Configured file is not a supported manifest' });
      } else if (details.isDirectory()) {
        queue.push({ directory: absolutePath, depth: 0 });
      }
    } catch (error) {
      skipped.push({ path: absolutePath, reason: `Unable to access scan path: ${error.message}` });
    }
    if (manifests.length >= maxManifests) {
      capReached = true;
      break;
    }
  }

  while (queue.length > 0 && manifests.length < maxManifests) {
    checkAbort(signal);
    const { directory, depth } = queue.shift();
    let entries;
    try {
      entries = await fs.readDirectory(directory, { withFileTypes: true });
    } catch (error) {
      skipped.push({ path: directory, reason: `Unable to read directory: ${error.message}` });
      continue;
    }
    for (const entry of entries) {
      checkAbort(signal);
      const entryPath = path.join(directory, entry.name);
      if (entry.isSymbolicLink?.()) continue;
      if (entry.isFile?.() && MANIFEST_NAMES.has(entry.name)) {
        manifests.push(entryPath);
        if (manifests.length >= maxManifests) {
          capReached = true;
          break;
        }
      } else if (entry.isDirectory?.() && depth < maxDepth && !NOISE_DIRECTORIES.has(entry.name.toLowerCase())) {
        queue.push({ directory: entryPath, depth: depth + 1 });
      }
    }
  }

  return { manifests, skipped, capReached };
}

async function readOptional(filePath, readTextFile) {
  try {
    return await readTextFile(filePath, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

async function parseDiscoveredManifests(manifestPaths, { readTextFile, signal }) {
  const pathSet = new Set(manifestPaths);
  const consumed = new Set();
  const dependencies = [];
  const manifests = [];

  const priority = { 'package.json': 0, 'package-lock.json': 1, 'go.mod': 0, 'go.sum': 1 };
  const orderedPaths = [...manifestPaths].sort((left, right) => {
    const directoryOrder = path.dirname(left).localeCompare(path.dirname(right));
    if (directoryOrder !== 0) return directoryOrder;
    return (priority[path.basename(left)] ?? 0) - (priority[path.basename(right)] ?? 0)
      || left.localeCompare(right);
  });

  for (const manifestPath of orderedPaths) {
    checkAbort(signal);
    if (consumed.has(manifestPath)) continue;
    const name = path.basename(manifestPath);
    const directory = path.dirname(manifestPath);
    let ecosystem;
    let parsed = [];
    try {
      const content = await readTextFile(manifestPath, 'utf8');
      if (name === 'package.json') {
        ecosystem = 'npm';
        const lockPath = path.join(directory, 'package-lock.json');
        const lockContent = pathSet.has(lockPath) ? await readOptional(lockPath, readTextFile) : null;
        if (lockContent != null) consumed.add(lockPath);
        parsed = parseNpmManifest(content, lockContent, manifestPath);
      } else if (name === 'package-lock.json') {
        ecosystem = 'npm';
        parsed = parsePackageLock(content, manifestPath);
      } else if (name === 'requirements.txt') {
        ecosystem = 'pip';
        parsed = parseRequirements(content, manifestPath);
      } else if (name === 'Pipfile.lock') {
        ecosystem = 'pip';
        parsed = parsePipfileLock(content, manifestPath);
      } else if (name === 'pom.xml') {
        ecosystem = 'maven';
        parsed = parsePomXml(content, manifestPath);
      } else if (name === 'go.mod') {
        ecosystem = 'go';
        const sumPath = path.join(directory, 'go.sum');
        const sumContent = pathSet.has(sumPath) ? await readOptional(sumPath, readTextFile) : null;
        if (sumContent != null) consumed.add(sumPath);
        parsed = parseGoMod(content, sumContent ?? '', manifestPath);
      } else if (name === 'go.sum') {
        ecosystem = 'go';
        manifests.push({ path: manifestPath, ecosystem, status: 'metadata-only', dependencyCount: 0, reason: 'go.sum is used only to enrich go.mod dependencies' });
        consumed.add(manifestPath);
        continue;
      }
      dependencies.push(...parsed);
      manifests.push({ path: manifestPath, ecosystem, status: 'parsed', dependencyCount: parsed.length, reason: null });
    } catch (error) {
      if (error.name === 'AbortError') throw error;
      manifests.push({ path: manifestPath, ecosystem: ecosystem ?? 'unknown', status: 'skipped', dependencyCount: 0, reason: error.message });
    }
    consumed.add(manifestPath);
  }

  return { dependencies, manifests };
}

export function createScaDepsCollector({
  readTextFile = readFile,
  readDirectory = readdir,
  statPath = stat,
  cwd = process.cwd(),
} = {}) {
  return {
    name: 'sca-deps',
    version: '1.0.0',
    async run(_params = {}, context = {}) {
      const config = context.collectorConfig ?? {};
      const scanPaths = Array.isArray(config.scanPaths) ? config.scanPaths.filter(Boolean) : [];
      const maxDepth = Number.isInteger(config.maxDepth) && config.maxDepth >= 0 ? config.maxDepth : 6;
      const maxManifests = Number.isInteger(config.maxManifests) && config.maxManifests > 0 ? config.maxManifests : 200;
      const metadata = {
        importStatusMethod: 'declared-manifest-only',
        importStatusLimitation: IMPORT_STATUS_NOTE,
        traversal: {
          scanPaths,
          maxDepth,
          maxManifests,
          skippedDirectoryNames: [...NOISE_DIRECTORIES],
          followsSymbolicLinks: false,
        },
      };

      if (scanPaths.length === 0) {
        return {
          metadata,
          reason: 'No scanPaths are configured; filesystem scanning was skipped for safety',
          summary: { manifestsDiscovered: 0, manifestsProcessed: 0, dependenciesFound: 0, capReached: false },
          dependencies: [],
          manifests: [],
          traversalWarnings: [],
        };
      }

      const discovery = await discoverManifests({
        scanPaths,
        maxDepth,
        maxManifests,
        signal: context.signal,
        cwd,
        fs: { readDirectory, statPath },
      });
      const parsed = await parseDiscoveredManifests(discovery.manifests, {
        readTextFile,
        signal: context.signal,
      });
      return {
        metadata,
        reason: null,
        summary: {
          manifestsDiscovered: discovery.manifests.length,
          manifestsProcessed: parsed.manifests.length,
          dependenciesFound: parsed.dependencies.length,
          capReached: discovery.capReached,
        },
        dependencies: parsed.dependencies,
        manifests: parsed.manifests,
        traversalWarnings: discovery.skipped,
      };
    },
  };
}

export const scaDepsCollector = createScaDepsCollector();
export default scaDepsCollector;
