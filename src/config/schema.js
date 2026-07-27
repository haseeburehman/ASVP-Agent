/**
 * JSON Schema for the core agent configuration.
 */
export const configSchema = {
  type: 'object',
  additionalProperties: true,
  required: ['server', 'agent', 'dashboard', 'storage', 'retry', 'collectors'],
  properties: {
    server: {
      type: 'object',
      additionalProperties: true,
      required: ['mode', 'url', 'registrationPath', 'heartbeatPath', 'deregistrationPath', 'tasksPath', 'resultsPath', 'requestTimeoutMs'],
      properties: {
        mode: { enum: ['mock', 'http'] },
        url: { type: 'string', minLength: 1 },
        registrationPath: { type: 'string', pattern: '^/' },
        heartbeatPath: { type: 'string', pattern: '^/' },
                deregistrationPath: { type: 'string', pattern: '^/' },
        tasksPath: { type: 'string', pattern: '^/' },
        resultsPath: { type: 'string', pattern: '^/' },
        adminToken: { type: ['string', 'null'], minLength: 1 },
        enrollmentToken: { type: ['string', 'null'], minLength: 1 },
        requestTimeoutMs: { type: 'integer', minimum: 1 },
      },
      allOf: [
        {
          if: { properties: { mode: { const: 'http' } }, required: ['mode'] },
          then: {
            properties: {
              url: {
                type: 'string',
                anyOf: [
                  { pattern: '^https://' },
                  { pattern: '^http://(127\\.0\\.0\\.1|localhost)(:[0-9]+)?(?:/|$)' },
                ],
              },
            },
          },
        },
      ],
    },
    agent: {
      type: 'object',
      additionalProperties: true,
      required: ['heartbeatIntervalMs', 'pollIntervalMs', 'logLevel', 'taskRateLimit'],
      properties: {
        heartbeatIntervalMs: { type: 'integer', minimum: 100 },
        pollIntervalMs: { type: 'integer', minimum: 100 },
        logLevel: { enum: ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'] },
        taskRateLimit: {
          type: 'object',
          additionalProperties: false,
          required: ['maxExecutions', 'windowMs'],
          properties: {
            maxExecutions: { type: 'integer', minimum: 1 },
            windowMs: { type: 'integer', minimum: 1000 },
          },
        },
      },
    },
    dashboard: {
      type: 'object',
      additionalProperties: false,
      required: ['enabled', 'port', 'bindAddress'],
      properties: {
        enabled: { type: 'boolean' },
        port: { type: 'integer', minimum: 1, maximum: 65535 },
        bindAddress: { enum: ['127.0.0.1', '::1', 'localhost'] },
      },
    },
    storage: {
      type: 'object',
      additionalProperties: true,
      required: [
        'identityPath',
        'statusPath',
        'taskReplayLedgerPath',
        'taskJournalPath',
        'queueDir',
        'maxQueueSizeBytes',
        'maxQueueItems',
        'maxItemAgeMs',
      ],
      properties: {
        identityPath: { type: 'string', minLength: 1 },
        statusPath: { type: 'string', minLength: 1 },
        taskReplayLedgerPath: { type: 'string', minLength: 1 },
        taskJournalPath: { type: 'string', minLength: 1 },
        queueDir: { type: 'string', minLength: 1 },
        maxQueueSizeBytes: { type: 'integer', minimum: 1 },
        maxQueueItems: { type: 'integer', minimum: 1 },
        maxItemAgeMs: { type: 'integer', minimum: 1 },
      },
    },
    retry: {
      type: 'object',
      additionalProperties: true,
      required: ['initialDelayMs', 'maximumDelayMs'],
      properties: {
        initialDelayMs: { type: 'integer', minimum: 100 },
        maximumDelayMs: { type: 'integer', minimum: 100 },
      },
    },
    collectors: {
      type: 'object',
      properties: {
        'process-summary': {
          type: 'object',
          required: ['timeoutMs', 'concurrency', 'maxItems'],
          properties: {
            timeoutMs: { type: 'integer', minimum: 1 },
            concurrency: { type: 'integer', minimum: 1 },
            maxItems: { type: 'integer', minimum: 1 },
          },
        },
        'network-config': {
          type: 'object',
          required: ['timeoutMs', 'concurrency', 'maxItems'],
          properties: {
            timeoutMs: { type: 'integer', minimum: 1 },
            concurrency: { type: 'integer', minimum: 1 },
            maxItems: { type: 'integer', minimum: 1 },
          },
        },
        'disk-security': {
          type: 'object',
          required: ['timeoutMs', 'concurrency', 'maxItems'],
          properties: {
            timeoutMs: { type: 'integer', minimum: 1 },
            concurrency: { type: 'integer', minimum: 1 },
            maxItems: { type: 'integer', minimum: 1 },
          },
        },
      },
      additionalProperties: {
        type: 'object',
        additionalProperties: true,
        properties: {
          timeoutMs: { type: 'integer', minimum: 1 },
          concurrency: { type: 'integer', minimum: 1 },
          maxItems: { type: 'integer', minimum: 1 },
          scanPaths: {
            type: 'array',
            items: { type: 'string', minLength: 1 },
            uniqueItems: true,
          },
          maxDepth: { type: 'integer', minimum: 0 },
          maxManifests: { type: 'integer', minimum: 1 },
          maxContainers: { type: 'integer', minimum: 1 },
          maxPackagesPerContainer: { type: 'integer', minimum: 1 },

          commandTimeoutMs: { type: 'integer', minimum: 1 },
                    patchCheckTimeoutMs: { type: 'integer', minimum: 1 },
          intervalMs: { type: 'integer', minimum: 100 },
          uploadConcurrency: { type: 'integer', minimum: 1 },
          maxPayloadWarningBytes: { type: 'integer', minimum: 1 },
          authFailureThreshold: { type: 'integer', minimum: 1 },
          rescanIntervalMs: { type: 'integer', minimum: 60000 },
        },
      },
    },
  },
};
