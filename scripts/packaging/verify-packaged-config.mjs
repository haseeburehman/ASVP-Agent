import { readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { validateManagementServerUrl, PLACEHOLDER_SERVER_URL } from '../../src/enrollment/index.js';

export async function verifyPackagedConfig({ configPath, expectedServerUrl }) {
  const resolved = path.resolve(configPath);
  const config = JSON.parse(await readFile(resolved, 'utf8'));
  const actual = config?.server?.url;
  const generic = typeof actual !== 'string' || actual.replace(/\/$/, '') === PLACEHOLDER_SERVER_URL;
  let normalizedActual = actual ?? null;
  if (!generic) normalizedActual = validateManagementServerUrl(actual);

  const expected = expectedServerUrl?.trim()
    ? validateManagementServerUrl(expectedServerUrl.trim())
    : null;
  if (expected && (generic || normalizedActual !== expected)) {
    throw new Error(`ASVP_DEFAULT_SERVER_URL was set to ${expected}, but packaged config contains ${actual ?? 'no URL'}`);
  }
  const mode = generic ? 'GENERIC' : 'PRECONFIGURED';
  return { mode, preconfigured: !generic, serverUrl: normalizedActual, configPath: resolved };
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  const configPath = process.argv[2];
  if (!configPath) throw new Error('Usage: node verify-packaged-config.mjs <config-path>');
  const result = await verifyPackagedConfig({ configPath, expectedServerUrl: process.env.ASVP_DEFAULT_SERVER_URL });
  process.stdout.write(`ASVP PACKAGED CONFIG: ${result.mode}\nURL: ${result.serverUrl ?? 'none'}\nPATH: ${result.configPath}\n`);
}
