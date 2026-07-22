import pino from 'pino';

const redactPaths = [
  'authToken',
  'token',
  'identity.authToken',
  'identity.token',
  'config.authentication',
  'req.headers.authorization',
  'headers.authorization',
];

export function createLogger(options = {}) {
  return pino({
    level: options.level ?? 'info',
    redact: {
      paths: redactPaths,
      censor: '[REDACTED]',
    },
  }, options.destination);
}

export async function flushLogger(logger) {
  if (typeof logger?.flush === 'function') logger.flush();
}
