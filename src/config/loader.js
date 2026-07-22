import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv';
import dotenv from 'dotenv';
import { configSchema } from './schema.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const defaultConfigPath = path.join(projectRoot, 'config', 'default.json');

const envMappings = {
  ASVP_SERVER_MODE: ['server', 'mode', String],
  ASVP_SERVER_URL: ['server', 'url', String],
  ASVP_REGISTRATION_PATH: ['server', 'registrationPath', String],
  ASVP_HEARTBEAT_PATH: ['server', 'heartbeatPath', String],
  ASVP_REQUEST_TIMEOUT_MS: ['server', 'requestTimeoutMs', Number],
  ASVP_HEARTBEAT_INTERVAL_MS: ['agent', 'heartbeatIntervalMs', Number],
  ASVP_LOG_LEVEL: ['agent', 'logLevel', String],
  ASVP_IDENTITY_PATH: ['storage', 'identityPath', String],
  ASVP_STATUS_PATH: ['storage', 'statusPath', String],
  ASVP_RETRY_INITIAL_DELAY_MS: ['retry', 'initialDelayMs', Number],
  ASVP_RETRY_MAXIMUM_DELAY_MS: ['retry', 'maximumDelayMs', Number],
};

function mergeObjects(base, overlay) {
  const result = structuredClone(base);
  for (const [key, value] of Object.entries(overlay)) {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      result[key] = mergeObjects(result[key] ?? {}, value);
    } else {
      result[key] = value;
    }
  }
  return result;
}

async function readJson(filePath) {
  try {
    return JSON.parse(await readFile(filePath, 'utf8'));
  } catch (error) {
    throw new Error(`Unable to load configuration from ${filePath}: ${error.message}`, { cause: error });
  }
}

function applyEnvironment(config, environment) {
  const result = structuredClone(config);
  for (const [name, [section, key, convert]] of Object.entries(envMappings)) {
    if (environment[name] === undefined || environment[name] === '') continue;
    if (!result[section]) result[section] = {};
    result[section][key] = convert(environment[name]);
  }
  return result;
}

function formatValidationErrors(errors = []) {
  return errors
    .map(({ instancePath, message, params }) => {
      const location = instancePath || `/${params?.missingProperty ?? 'config'}`;
      return `${location} ${message}`;
    })
    .join('; ');
}

export async function loadConfig(options = {}) {
  const {
    configPath,
    env = process.env,
    cwd = process.cwd(),
    loadDotEnv = true,
  } = options;

  if (loadDotEnv) dotenv.config({ path: path.join(cwd, '.env'), quiet: true });

  const defaults = await readJson(defaultConfigPath);
  const alternatePath = configPath ? path.resolve(cwd, configPath) : null;
  const fileConfig = alternatePath ? mergeObjects(defaults, await readJson(alternatePath)) : defaults;
  const config = applyEnvironment(fileConfig, env);

  const ajv = new Ajv({ allErrors: true });
  const validate = ajv.compile(configSchema);
  if (!validate(config)) {
    throw new Error(`Invalid agent configuration: ${formatValidationErrors(validate.errors)}`);
  }
  if (config.retry.maximumDelayMs < config.retry.initialDelayMs) {
    throw new Error('Invalid agent configuration: /retry/maximumDelayMs must be greater than or equal to initialDelayMs');
  }

  return config;
}

export { defaultConfigPath };
