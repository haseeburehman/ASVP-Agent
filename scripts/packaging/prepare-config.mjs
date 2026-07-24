import { readFile, writeFile } from 'node:fs/promises';
import { validateManagementServerUrl } from '../../src/enrollment/index.js';

export async function preparePackagedConfig({ sourcePath, destinationPath, defaultServerUrl }) {
  const config = JSON.parse(await readFile(sourcePath, 'utf8'));
  let preconfigured = false;
  if (defaultServerUrl) {
    config.server.url = validateManagementServerUrl(defaultServerUrl);
    config.server.mode = 'http';
    preconfigured = true;
  }
  await writeFile(destinationPath, `${JSON.stringify(config, null, 2)}\n`);
  return { preconfigured, serverUrl: config.server.url };
}
