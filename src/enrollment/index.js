import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createInterface } from 'node:readline/promises';

export const PLACEHOLDER_SERVER_URL = 'https://management.example.invalid';

export function validateManagementServerUrl(value) {
  const input = typeof value === 'string' ? value.trim() : '';
  if (!input) throw new Error('Management server URL is required');
  if (input.replace(/\/$/, '') === PLACEHOLDER_SERVER_URL) {
    throw new Error(`Enter your real management server URL; ${PLACEHOLDER_SERVER_URL} is only a placeholder`);
  }

  let url;
  try {
    url = new URL(input);
  } catch {
    throw new Error('Management server URL must be a well-formed URL');
  }
  if (url.username || url.password) throw new Error('Management server URL must not contain credentials');
  if (url.hash) throw new Error('Management server URL must not contain a fragment');
  const loopbackHttp = url.protocol === 'http:' && (url.hostname === '127.0.0.1' || url.hostname === 'localhost');
  if (url.protocol !== 'https:' && !loopbackHttp) {
    throw new Error('Management server URL must use HTTPS (HTTP is allowed only for 127.0.0.1 or localhost testing)');
  }
  return input.replace(/\/$/, '');
}

export async function writeEnrollmentConfig({ configPath, serverUrl, enrollmentToken = null }) {
  if (!configPath) throw new Error('A configuration path is required for enrollment');
  const validatedUrl = validateManagementServerUrl(serverUrl);
  const resolved = path.resolve(configPath);
  let config;
  try {
    config = JSON.parse(await readFile(resolved, 'utf8'));
  } catch (error) {
    throw new Error(`Unable to load configuration from ${resolved}: ${error.message}`, { cause: error });
  }
  config.server = { ...(config.server ?? {}), mode: 'http', url: validatedUrl };
  const token = typeof enrollmentToken === 'string' ? enrollmentToken.trim() : '';
  config.server.enrollmentToken = token || null;

  await mkdir(path.dirname(resolved), { recursive: true });
  const temporary = `${resolved}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, resolved);
  await chmod(resolved, 0o600).catch(() => {});
  return { configPath: resolved, serverUrl: validatedUrl, enrollmentTokenConfigured: Boolean(token) };
}

export async function runEnrollment({ configPath, serverUrl, enrollmentToken, input = process.stdin, output = process.stdout }) {
  let url = serverUrl;
  let token = enrollmentToken;
  if (!url) {
    const prompts = createInterface({ input, output });
    try {
      url = await prompts.question('Management server URL: ');
      token = await prompts.question('Enrollment token (optional): ');
    } finally {
      prompts.close();
    }
  }
  return writeEnrollmentConfig({ configPath, serverUrl: url, enrollmentToken: token });
}
