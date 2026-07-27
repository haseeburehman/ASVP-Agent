import { Writable } from 'node:stream';
import pino from 'pino';

const redactPaths = [
  'authToken',
  'encryptionKey',
  'taskSigningKey',
  'enrollmentToken',
  'machineFingerprint',
  'adminToken',
  'config.server.adminToken',
  'config.server.enrollmentToken',
  'server.enrollmentToken',
  'token',
  'identity.authToken',
  'identity.encryptionKey',
  'identity.taskSigningKey',
  'identity.machineFingerprint',
  'identity.token',
  'config.authentication',
  'req.headers.authorization',
  'req.body.machineFingerprint',
  'request.body.machineFingerprint',
  'body.machineFingerprint',
  'headers.authorization',
];

function createLogHookStream(onLog) {
  return new Writable({
    write(chunk, _encoding, callback) {
      try {
        onLog(JSON.parse(chunk.toString()));
      } catch {
        // Pino emits complete JSON lines; malformed hook data is ignored rather than affecting logging.
      }
      callback();
    },
  });
}

export function createLogger(options = {}) {
  const loggerOptions = {
    level: options.level ?? 'info',
    redact: {
      paths: redactPaths,
      censor: '[REDACTED]',
    },
  };
  if (!options.onLog) return pino(loggerOptions, options.destination);
  const primary = options.destination ?? pino.destination(1);
  return pino(loggerOptions, pino.multistream([
    { stream: primary },
    { stream: createLogHookStream(options.onLog) },
  ]));
}

export async function flushLogger(logger) {
  if (typeof logger?.flush === 'function') logger.flush();
}
