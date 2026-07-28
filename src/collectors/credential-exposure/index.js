import { readFile, readdir, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { CREDENTIAL_DIRECTORY_NAMES, validateScaScanPaths } from '../../security/sca-scan-paths.js';

const ALLOWED_FILE_NAMES = new Set([
  '.env',
  'config.json',
  'appsettings.json',
  'config.yml',
  'config.yaml',
  'docker-compose.yml',
  'docker-compose.yaml',
  'web.config',
  '.npmrc',
  '.pypirc',
]);
const NOISE_DIRECTORIES = new Set([
  'node_modules', '.git', 'vendor', 'site-packages', '__pycache__', '.venv', 'venv',
  'dist', 'build', 'target', ...CREDENTIAL_DIRECTORY_NAMES,
]);
const RULES = Object.freeze([
  { name: 'private-key-header', confidence: 'high', type: 'private_key', pattern: /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/ },
  { name: 'aws-access-key-id', confidence: 'high', type: 'access_key', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'sensitive-key-name', confidence: 'medium', type: 'credential', pattern: /(?:^|["'\s{,])(?:password|api_key|secret|token)["']?\s*(?:=|:)\s*["']?\S+/i },
]);

function isAllowedFile(name) {
  const lowerName = name.toLowerCase();
  return ALLOWED_FILE_NAMES.has(lowerName) || lowerName.startsWith('.env.');
}

function abortError() {
  const error = new Error('Credential exposure collection was aborted');
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

function checkAbort(signal) {
  if (signal?.aborted) throw abortError();
}

function availabilityFor(error) {
  return ['EACCES', 'EPERM'].includes(error?.code) ? 'insufficient_privilege' : 'unavailable';
}

function relativeFilePath(filePath, roots) {
  const root = roots.find((candidate) => {
    const relative = path.relative(candidate, filePath);
    return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
  });
  return root ? path.relative(root, filePath) || path.basename(filePath) : path.basename(filePath);
}

export function scanCredentialContent(content, filePath) {
  const findings = [];
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    for (const rule of RULES) {
      if (rule.pattern.test(lines[index])) {
        findings.push({
          filePath,
          line: index + 1,
          rule: rule.name,
          confidence: rule.confidence,
          type: rule.type,
        });
      }
    }
  }
  return findings;
}

async function discoverFiles({ scanPaths, maxDepth, maxFiles, signal, fs }) {
  const files = [];
  const warnings = [];
  const queue = [];
  let capReached = false;

  for (const absolutePath of scanPaths) {
    checkAbort(signal);
    try {
      const details = await fs.statPath(absolutePath);
      if (details.isFile()) {
        if (isAllowedFile(path.basename(absolutePath))) files.push(absolutePath);
      } else if (details.isDirectory()) queue.push({ directory: absolutePath, depth: 0 });
    } catch (error) {
      warnings.push({ path: path.basename(absolutePath), status: availabilityFor(error) });
    }
    if (files.length >= maxFiles) {
      capReached = true;
      break;
    }
  }

  while (queue.length > 0 && files.length < maxFiles) {
    checkAbort(signal);
    const { directory, depth } = queue.shift();
    let entries;
    try {
      entries = await fs.readDirectory(directory, { withFileTypes: true });
    } catch (error) {
      warnings.push({ path: relativeFilePath(directory, scanPaths), status: availabilityFor(error) });
      continue;
    }
    for (const entry of entries) {
      checkAbort(signal);
      if (entry.isSymbolicLink?.()) continue;
      const entryPath = path.join(directory, entry.name);
      if (entry.isFile?.() && isAllowedFile(entry.name)) {
        files.push(entryPath);
        if (files.length >= maxFiles) {
          capReached = true;
          break;
        }
      } else if (entry.isDirectory?.() && depth < maxDepth && !NOISE_DIRECTORIES.has(entry.name.toLowerCase())) {
        queue.push({ directory: entryPath, depth: depth + 1 });
      }
    }
  }
  return { files, warnings, capReached };
}

export function createCredentialExposureCollector({
  readTextFile = readFile,
  readDirectory = readdir,
  statPath = stat,
  cwd = process.cwd(),
  homeDirectory,
  resolveRealPath = realpath,
} = {}) {
  return {
    name: 'credential-exposure',
    version: '1.0.0',
    async run(_params = {}, context = {}) {
      const config = context.collectorConfig ?? {};
      const scanPaths = Array.isArray(config.scanPaths) ? config.scanPaths.filter(Boolean) : [];
      await validateScaScanPaths(scanPaths, { cwd, homeDirectory, identityPath: config.identityPath, resolveRealPath });
      const approvedRoots = await Promise.all(scanPaths.map((configuredPath) => resolveRealPath(path.resolve(cwd, configuredPath))));
      const maxDepth = Number.isInteger(config.maxDepth) && config.maxDepth >= 0 ? config.maxDepth : 6;
      const maxFiles = Number.isInteger(config.maxFiles) && config.maxFiles > 0 ? config.maxFiles : 200;
      const maxFindings = Number.isInteger(config.maxFindings) && config.maxFindings > 0 ? config.maxFindings : 200;
      const metadata = { scanPaths, maxDepth, maxFiles, maxFindings, followsSymbolicLinks: false };

      if (scanPaths.length === 0) return {
        status: 'unavailable',
        reasonCode: 'unavailable',
        reason: 'No scanPaths are configured; credential exposure scanning was skipped for safety',
        source: 'approved-config-roots',
        metadata,
        summary: { filesDiscovered: 0, filesScanned: 0, findings: 0, fileCapReached: false, findingCapReached: false },
        findings: [],
        traversalWarnings: [],
      };

      const discovery = await discoverFiles({
        scanPaths: approvedRoots, maxDepth, maxFiles, signal: context.signal,
        fs: { readDirectory, statPath },
      });
      const findings = [];
      const warnings = [...discovery.warnings];
      let filesScanned = 0;
      let findingCapReached = false;
      for (const filePath of discovery.files) {
        checkAbort(context.signal);
        try {
          const content = await readTextFile(filePath, 'utf8');
          filesScanned += 1;
          for (const finding of scanCredentialContent(content, relativeFilePath(filePath, approvedRoots))) {
            if (findings.length >= maxFindings) {
              findingCapReached = true;
              break;
            }
            findings.push(finding);
          }
        } catch (error) {
          if (error.name === 'AbortError') throw error;
          warnings.push({ path: relativeFilePath(filePath, approvedRoots), status: availabilityFor(error) });
        }
        if (findingCapReached) break;
      }
      const status = warnings.some((warning) => warning.status === 'insufficient_privilege')
        ? 'insufficient_privilege'
        : (filesScanned === 0 && warnings.length > 0 ? 'unavailable' : 'available');
      return {
        status,
        reasonCode: status === 'available' ? null : status,
        reason: status === 'available' ? null : 'One or more configured locations could not be inspected',
        source: 'approved-config-roots',
        metadata,
        summary: {
          filesDiscovered: discovery.files.length,
          filesScanned,
          findings: findings.length,
          fileCapReached: discovery.capReached,
          findingCapReached,
        },
        findings,
        traversalWarnings: warnings,
      };
    },
  };
}

export const credentialExposureCollector = createCredentialExposureCollector();
export default credentialExposureCollector;
