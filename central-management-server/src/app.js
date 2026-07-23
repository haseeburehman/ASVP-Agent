import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import express from 'express';
import { decodeResultEnvelope, generateAgentSecrets, hashToken } from './crypto.js';

function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function requireString(value, name) {
  if (typeof value !== 'string' || !value.trim()) throw httpError(400, `${name} must be a non-empty string`);
  return value.trim();
}

function requireObject(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw httpError(400, `${name} must be an object`);
  return value;
}

function tokenMatches(expected, supplied) {
  if (typeof supplied !== 'string') return false;
  const expectedHash = createHash('sha256').update(expected).digest();
  const suppliedHash = createHash('sha256').update(supplied).digest();
  return timingSafeEqual(expectedHash, suppliedHash);
}

function storedTokenMatches(storedHash, suppliedToken) {
  if (typeof suppliedToken !== 'string' || !/^[a-f0-9]{64}$/i.test(storedHash ?? '')) return false;
  const expected = Buffer.from(storedHash, 'hex');
  const supplied = createHash('sha256').update(suppliedToken).digest();
  return timingSafeEqual(expected, supplied);
}

function createAdminAuthenticator(adminToken) {
  return (request, _response, next) => {
    const match = /^Bearer\s+(.+)$/i.exec(request.headers.authorization ?? '');
    if (!match || !tokenMatches(adminToken, match[1])) return next(httpError(401, 'Unauthorized'));
    next();
  };
}

function createAdminRateLimiter({ maxRequests, windowMs, now }) {
  const clients = new Map();
  return (request, _response, next) => {
    const timestamp = now();
    const key = request.ip ?? request.socket.remoteAddress ?? 'unknown';
    const current = clients.get(key);
    const entry = !current || timestamp - current.windowStartedAt >= windowMs
      ? { count: 0, windowStartedAt: timestamp }
      : current;
    entry.count += 1;
    clients.set(key, entry);
    if (entry.count > maxRequests) return next(httpError(429, 'Too many admin requests'));
    next();
  };
}

function createAuthenticator(database) {
  const findAgent = database.prepare('SELECT * FROM agents WHERE auth_token_hash = ?');
  return (request, _response, next) => {
    const match = /^Bearer\s+(.+)$/i.exec(request.headers.authorization ?? '');
    if (!match) return next(httpError(401, 'Bearer authentication token required'));
    const agent = findAgent.get(hashToken(match[1]));
    if (!agent) return next(httpError(401, 'Invalid agent authentication token'));
    request.agent = agent;
    next();
  };
}

export function createApp({
  database,
  adminToken,
  adminRateLimit = { maxRequests: 60, windowMs: 60000 },
  logger = console,
  now = () => new Date(),
  rateNow = () => Date.now(),
}) {
  if (typeof adminToken !== 'string' || !adminToken) throw new Error('createApp requires a non-empty adminToken');
  const app = express();
  const authenticate = createAuthenticator(database);
  app.disable('x-powered-by');
  app.use(express.json({ limit: '25mb' }));
  app.use('/api/admin', createAdminRateLimiter({
    maxRequests: adminRateLimit.maxRequests,
    windowMs: adminRateLimit.windowMs,
    now: rateNow,
  }));
  app.use('/api/admin', createAdminAuthenticator(adminToken));

  const insertAgent = database.prepare(`
    INSERT INTO agents (id, hostname, auth_token_hash, encryption_key, registered_at, last_heartbeat_at, status)
    VALUES (?, ?, ?, ?, ?, NULL, 'registered')
  `);
  const findRegistrationAgent = database.prepare('SELECT id, auth_token_hash FROM agents WHERE id = ?');
  const rotateAgentCredentials = database.prepare(`
    UPDATE agents
    SET hostname = COALESCE(?, hostname), auth_token_hash = ?, encryption_key = ?, last_heartbeat_at = NULL, status = 'registered'
    WHERE id = ?
  `);
  const updateHeartbeat = database.prepare(`
    UPDATE agents SET hostname = ?, last_heartbeat_at = ?, status = 'online' WHERE id = ?
  `);
  const selectTasks = database.prepare(`
    SELECT * FROM tasks
    WHERE status = 'pending' AND (agent_id = ? OR agent_id IS NULL)
    ORDER BY created_at, id
  `);
  const dispatchTask = database.prepare(`UPDATE tasks SET status = 'dispatched', agent_id = ?, dispatched_at = ? WHERE id = ? AND status = 'pending'`);
  const dispatchPending = database.transaction((agentId, timestamp) => {
    const rows = selectTasks.all(agentId);
    const dispatched = [];
    for (const row of rows) {
      if (dispatchTask.run(agentId, timestamp, row.id).changes === 1) dispatched.push(row);
    }
    return dispatched;
  });
  const findResult = database.prepare('SELECT id FROM results WHERE id = ?');
  const insertResult = database.prepare(`
    INSERT INTO results (id, agent_id, task_id, collector, status, raw_data, received_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  const completeTask = database.prepare(`UPDATE tasks SET status = ? WHERE id = ? AND agent_id = ?`);
  const findTask = database.prepare('SELECT id FROM tasks WHERE id = ? AND agent_id = ?');
  const insertTask = database.prepare(`
    INSERT INTO tasks (id, agent_id, collector_name, params, status, created_at, dispatched_at)
    VALUES (?, ?, ?, ?, 'pending', ?, NULL)
  `);
  const findAgentById = database.prepare('SELECT id FROM agents WHERE id = ?');

  app.post('/api/agents/register', (request, response, next) => {
    try {
      const body = requireObject(request.body, 'request body');
      const hostname = body.hostname == null ? null : requireString(body.hostname, 'hostname');
      if (body.platform != null) requireString(body.platform, 'platform');
      if (body.architecture != null) requireString(body.architecture, 'architecture');
      const previousAgentId = body.previousAgentId == null ? null : requireString(body.previousAgentId, 'previousAgentId');
      const knownPreviousAgent = previousAgentId ? findRegistrationAgent.get(previousAgentId) : null;
      const previousBearer = /^Bearer\s+(.+)$/i.exec(request.headers.authorization ?? '')?.[1];
      const continuityAuthorized = Boolean(knownPreviousAgent)
        && storedTokenMatches(knownPreviousAgent.auth_token_hash, previousBearer);
      const agentId = continuityAuthorized ? previousAgentId : randomUUID();
      const { authToken, encryptionKey } = generateAgentSecrets();
      const registeredAt = now().toISOString();
      if (continuityAuthorized) {
        rotateAgentCredentials.run(hostname, hashToken(authToken), encryptionKey, agentId);
      } else {
        insertAgent.run(agentId, hostname, hashToken(authToken), encryptionKey, registeredAt);
      }
      logger.info({
        event: 'register', agentId, previousAgentId,
        continuity: continuityAuthorized
          ? 'reused-existing-agent'
          : knownPreviousAgent
            ? 'credential-mismatch-created-new'
            : previousAgentId
              ? 'previous-agent-not-found-created-new'
              : 'new-agent',
        hostname, platform: body.platform ?? null, architecture: body.architecture ?? null,
      });
      response.status(201).json({ agentId, authToken, encryptionKey });
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/agents/heartbeat', authenticate, (request, response, next) => {
    try {
      const body = requireObject(request.body, 'request body');
      const agentId = requireString(body.agentId, 'agentId');
      if (agentId !== request.agent.id) throw httpError(403, 'Heartbeat agentId does not match bearer token');
      const hostname = requireString(body.hostname, 'hostname');
      const timestamp = now().toISOString();
      updateHeartbeat.run(hostname, timestamp, agentId);
      logger.info({ event: 'heartbeat', agentId, hostname, uptimeSeconds: body.uptimeSeconds ?? null, queueSize: body.currentQueueSize ?? null, agentVersion: body.agentVersion ?? null });
      response.json({ accepted: true, receivedAt: timestamp });
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/agents/tasks/poll', authenticate, (request, response, next) => {
    try {
      const body = requireObject(request.body, 'request body');
      const agentId = requireString(body.agentId, 'agentId');
      if (agentId !== request.agent.id) throw httpError(403, 'Task poll agentId does not match bearer token');
      const timestamp = now().toISOString();
      const tasks = dispatchPending(agentId, timestamp).map((task) => ({
        taskId: task.id,
        collectorName: task.collector_name,
        params: JSON.parse(task.params),
        scheduledAt: task.created_at,
      }));
      logger.info({ event: 'poll', agentId, taskCount: tasks.length, taskIds: tasks.map((task) => task.taskId) });
      response.json(tasks);
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/agents/results', authenticate, async (request, response, next) => {
    try {
      const envelope = requireObject(request.body, 'request body');
      const queueItemId = requireString(envelope.queueItemId, 'queueItemId');
      const agentId = requireString(envelope.agentId, 'agentId');
      if (agentId !== request.agent.id) throw httpError(403, 'Result agentId does not match bearer token');
      if (envelope.schemaVersion !== 1) throw httpError(400, 'Unsupported result schemaVersion');
      for (const field of ['enqueuedAt', 'contentEncoding', 'encryption', 'iv', 'authTag', 'ciphertext']) requireString(envelope[field], field);

      if (findResult.get(queueItemId)) {
        logger.info({ event: 'result-duplicate', agentId, queueItemId });
        response.json({ accepted: true, queueItemId });
        return;
      }

      let decoded;
      try {
        decoded = await decodeResultEnvelope(envelope, request.agent.encryption_key);
      } catch (error) {
        throw httpError(400, `Unable to decrypt/decompress result: ${error.message}`);
      }
      const result = requireObject(decoded.result, 'decrypted result');
      const collector = requireString(result.collector, 'result.collector');
      const status = requireString(result.status, 'result.status');
      const reportedTaskId = result.taskId ?? null;
      const taskId = reportedTaskId && findTask.get(reportedTaskId, agentId) ? reportedTaskId : null;
      const receivedAt = now().toISOString();
      insertResult.run(queueItemId, agentId, taskId, collector, status, JSON.stringify(result), receivedAt);
      if (taskId) completeTask.run(status === 'success' ? 'completed' : 'failed', taskId, agentId);
      logger.info({
        event: 'result', agentId, queueItemId, taskId, reportedTaskId, collector, status,
        compressedSizeBytes: decoded.compressedSizeBytes,
        uncompressedSizeBytes: decoded.uncompressedSizeBytes,
      });
      response.json({ accepted: true, queueItemId });
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/admin/tasks', (request, response, next) => {
    try {
      const body = requireObject(request.body, 'request body');
      const collectorName = requireString(body.collectorName, 'collectorName');
      const params = body.params == null ? {} : requireObject(body.params, 'params');
      const agentId = body.agentId == null ? null : requireString(body.agentId, 'agentId');
      if (agentId && !findAgentById.get(agentId)) throw httpError(404, `Agent not found: ${agentId}`);
      const taskId = randomUUID();
      insertTask.run(taskId, agentId, collectorName, JSON.stringify(params), now().toISOString());
      logger.info({ event: 'admin-task-created', taskId, agentId, collectorName });
      response.status(201).json({ taskId });
    } catch (error) {
      next(error);
    }
  });

  app.use((error, _request, response, _next) => {
    const status = Number(error.status) || (error.type === 'entity.parse.failed' ? 400 : 500);
    if (status >= 500) logger.error({ event: 'server-error', error: error.message, stack: error.stack });
    response.status(status).json({ error: error.message });
  });

  return app;
}
