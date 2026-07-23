import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { decodeResultEnvelope, generateAgentSecrets, hashToken } from './crypto.js';
import { createDashboardSessions } from './dashboard-session.js';
import { computeFleetStatus } from './fleet-status.js';

const dashboardRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), 'public', 'dashboard');
function httpError(status, message) { const error = new Error(message); error.status = status; return error; }
function requireString(value, name) { if (typeof value !== 'string' || !value.trim()) throw httpError(400, `${name} must be a non-empty string`); return value.trim(); }
function requireObject(value, name) { if (!value || typeof value !== 'object' || Array.isArray(value)) throw httpError(400, `${name} must be an object`); return value; }
function tokenMatches(expected, supplied) {
  if (typeof supplied !== 'string') return false;
  return timingSafeEqual(createHash('sha256').update(expected).digest(), createHash('sha256').update(supplied).digest());
}
function storedTokenMatches(storedHash, suppliedToken) {
  if (typeof suppliedToken !== 'string' || !/^[a-f0-9]{64}$/i.test(storedHash ?? '')) return false;
  return timingSafeEqual(Buffer.from(storedHash, 'hex'), createHash('sha256').update(suppliedToken).digest());
}
function createAdminAuthenticator(adminToken) {
  return (request, _response, next) => {
    const match = /^Bearer\s+(.+)$/i.exec(request.headers.authorization ?? '');
    if (!match || !tokenMatches(adminToken, match[1])) return next(httpError(401, 'Unauthorized'));
    next();
  };
}
function createRateLimiter({ maxRequests, windowMs, now }) {
  const clients = new Map();
  return (request, _response, next) => {
    const timestamp = now();
    const key = request.ip ?? request.socket.remoteAddress ?? 'unknown';
    const current = clients.get(key);
    const entry = !current || timestamp - current.windowStartedAt >= windowMs ? { count: 0, windowStartedAt: timestamp } : current;
    entry.count += 1; clients.set(key, entry);
    if (entry.count > maxRequests) return next(httpError(429, 'Too many requests'));
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
    request.agent = agent; next();
  };
}
function parseJson(value, fallback) { try { return JSON.parse(value); } catch { return fallback; } }

export function createApp({
  database,
  adminToken,
  adminRateLimit = { maxRequests: 60, windowMs: 60000 },
  requireEnrollmentToken = false,
  expectedHeartbeatIntervalMs = 30000,
  secureDashboardCookie = false,
  logger = console,
  now = () => new Date(),
  rateNow = () => Date.now(),
}) {
  if (typeof adminToken !== 'string' || !adminToken) throw new Error('createApp requires a non-empty adminToken');
  const app = express();
  const authenticate = createAuthenticator(database);
  const dashboardSessions = createDashboardSessions({ adminToken, now: rateNow });
  const limiter = createRateLimiter({ ...adminRateLimit, now: rateNow });
  app.disable('x-powered-by');
  app.use(express.json({ limit: '25mb' }));
  app.use('/api/admin', limiter, createAdminAuthenticator(adminToken));

  const insertAgent = database.prepare(`INSERT INTO agents (id, hostname, auth_token_hash, encryption_key, registered_at, last_heartbeat_at, status, platform, architecture, last_poll_at) VALUES (?, ?, ?, ?, ?, NULL, 'registered', ?, ?, NULL)`);
  const findRegistrationAgent = database.prepare('SELECT id, auth_token_hash FROM agents WHERE id = ?');
  const rotateAgentCredentials = database.prepare(`UPDATE agents SET hostname = COALESCE(?, hostname), platform = COALESCE(?, platform), architecture = COALESCE(?, architecture), auth_token_hash = ?, encryption_key = ?, last_heartbeat_at = NULL, last_poll_at = NULL, status = 'registered' WHERE id = ?`);
  const updateHeartbeat = database.prepare(`UPDATE agents SET hostname = ?, last_heartbeat_at = ?, status = 'online' WHERE id = ?`);
  const updatePoll = database.prepare('UPDATE agents SET last_poll_at = ? WHERE id = ?');
  const insertEvent = database.prepare('INSERT INTO agent_events (agent_id, event_type, details, created_at) VALUES (?, ?, ?, ?)');
  const event = (agentId, type, details, timestamp = now().toISOString()) => insertEvent.run(agentId, type, JSON.stringify(details), timestamp);
  const selectTasks = database.prepare(`SELECT * FROM tasks WHERE status = 'pending' AND (agent_id = ? OR agent_id IS NULL) ORDER BY created_at, id`);
  const dispatchTask = database.prepare(`UPDATE tasks SET status = 'dispatched', agent_id = ?, dispatched_at = ? WHERE id = ? AND status = 'pending'`);
  const dispatchPending = database.transaction((agentId, timestamp) => {
    const dispatched = [];
    for (const row of selectTasks.all(agentId)) if (dispatchTask.run(agentId, timestamp, row.id).changes === 1) dispatched.push(row);
    return dispatched;
  });
  const findResult = database.prepare('SELECT id FROM results WHERE id = ?');
  const insertResult = database.prepare(`INSERT INTO results (id, agent_id, task_id, collector, status, raw_data, received_at) VALUES (?, ?, ?, ?, ?, ?, ?)`);
  const completeTask = database.prepare(`UPDATE tasks SET status = ? WHERE id = ? AND agent_id = ?`);
  const findTask = database.prepare('SELECT id FROM tasks WHERE id = ? AND agent_id = ?');
  const insertTask = database.prepare(`INSERT INTO tasks (id, agent_id, collector_name, params, status, created_at, dispatched_at) VALUES (?, ?, ?, ?, 'pending', ?, NULL)`);
  const findAgentById = database.prepare('SELECT id FROM agents WHERE id = ?');
  const insertEnrollmentToken = database.prepare('INSERT INTO enrollment_tokens (token_hash, created_at, expires_at, max_uses, use_count) VALUES (?, ?, ?, ?, 0)');
  const findUsableEnrollmentTokens = database.prepare(`SELECT token_hash FROM enrollment_tokens WHERE expires_at > ? AND (max_uses IS NULL OR use_count < max_uses)`);
  const consumeEnrollmentToken = database.prepare(`UPDATE enrollment_tokens SET use_count = use_count + 1 WHERE token_hash = ? AND expires_at > ? AND (max_uses IS NULL OR use_count < max_uses)`);
  function findEnrollmentTokenHash(suppliedToken, timestamp) {
    if (typeof suppliedToken !== 'string') return null;
    return findUsableEnrollmentTokens.all(timestamp)
      .find((row) => storedTokenMatches(row.token_hash, suppliedToken))?.token_hash ?? null;
  }

  const registerNew = database.transaction(({ hostname, platform, architecture, enrollmentToken }) => {
    const timestamp = now().toISOString();
    if (requireEnrollmentToken) {
      const tokenHash = findEnrollmentTokenHash(enrollmentToken, timestamp);
      if (!tokenHash || consumeEnrollmentToken.run(tokenHash, timestamp).changes !== 1) throw httpError(403, 'Valid enrollment token required');
    }
    const agentId = randomUUID();
    const secrets = generateAgentSecrets();
    insertAgent.run(agentId, hostname, hashToken(secrets.authToken), secrets.encryptionKey, timestamp, platform, architecture);
    event(agentId, 'register', { continuity: 'new-agent', hostname, platform, architecture }, timestamp);
    return { agentId, ...secrets };
  });

  app.post('/api/agents/register', (request, response, next) => {
    try {
      const body = requireObject(request.body, 'request body');
      const hostname = body.hostname == null ? null : requireString(body.hostname, 'hostname');
      const platform = body.platform == null ? null : requireString(body.platform, 'platform');
      const architecture = body.architecture == null ? null : requireString(body.architecture, 'architecture');
      const previousAgentId = body.previousAgentId == null ? null : requireString(body.previousAgentId, 'previousAgentId');
      const knownPreviousAgent = previousAgentId ? findRegistrationAgent.get(previousAgentId) : null;
      const previousBearer = /^Bearer\s+(.+)$/i.exec(request.headers.authorization ?? '')?.[1];
      const continuityAuthorized = Boolean(knownPreviousAgent) && storedTokenMatches(knownPreviousAgent.auth_token_hash, previousBearer);
      let identity;
      if (continuityAuthorized) {
        const secrets = generateAgentSecrets();
        rotateAgentCredentials.run(hostname, platform, architecture, hashToken(secrets.authToken), secrets.encryptionKey, previousAgentId);
        event(previousAgentId, 'register', { continuity: 'reused-existing-agent', hostname, platform, architecture });
        identity = { agentId: previousAgentId, ...secrets };
      } else {
        identity = registerNew({ hostname, platform, architecture, enrollmentToken: body.enrollmentToken });
      }
      logger.info({ event: 'register', agentId: identity.agentId, previousAgentId, continuity: continuityAuthorized ? 'reused-existing-agent' : 'new-agent', hostname, platform, architecture });
      response.status(201).json(identity);
    } catch (error) { next(error); }
  });

  app.post('/api/agents/heartbeat', authenticate, (request, response, next) => {
    try {
      const body = requireObject(request.body, 'request body');
      const agentId = requireString(body.agentId, 'agentId');
      if (agentId !== request.agent.id) throw httpError(403, 'Heartbeat agentId does not match bearer token');
      const hostname = requireString(body.hostname, 'hostname');
      const timestamp = now().toISOString();
      updateHeartbeat.run(hostname, timestamp, agentId);
      event(agentId, 'heartbeat', { hostname, uptimeSeconds: body.uptimeSeconds ?? null, queueSize: body.currentQueueSize ?? null, agentVersion: body.agentVersion ?? null }, timestamp);
      logger.info({ event: 'heartbeat', agentId, hostname });
      response.json({ accepted: true, receivedAt: timestamp });
    } catch (error) { next(error); }
  });

  app.post('/api/agents/tasks/poll', authenticate, (request, response, next) => {
    try {
      const body = requireObject(request.body, 'request body');
      const agentId = requireString(body.agentId, 'agentId');
      if (agentId !== request.agent.id) throw httpError(403, 'Task poll agentId does not match bearer token');
      const timestamp = now().toISOString();
      updatePoll.run(timestamp, agentId);
      const tasks = dispatchPending(agentId, timestamp).map((task) => ({ taskId: task.id, collectorName: task.collector_name, params: JSON.parse(task.params), scheduledAt: task.created_at }));
      event(agentId, 'poll', { taskCount: tasks.length, taskIds: tasks.map((task) => task.taskId) }, timestamp);
      logger.info({ event: 'poll', agentId, taskCount: tasks.length, taskIds: tasks.map((task) => task.taskId) });
      response.json(tasks);
    } catch (error) { next(error); }
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
        event(agentId, 'result-duplicate', { queueItemId });
        response.json({ accepted: true, queueItemId }); return;
      }
      let decoded;
      try { decoded = await decodeResultEnvelope(envelope, request.agent.encryption_key); }
      catch (error) { throw httpError(400, `Unable to decrypt/decompress result: ${error.message}`); }
      const result = requireObject(decoded.result, 'decrypted result');
      const collector = requireString(result.collector, 'result.collector');
      const status = requireString(result.status, 'result.status');
      const reportedTaskId = result.taskId ?? null;
      const taskId = reportedTaskId && findTask.get(reportedTaskId, agentId) ? reportedTaskId : null;
      const receivedAt = now().toISOString();
      insertResult.run(queueItemId, agentId, taskId, collector, status, JSON.stringify(result), receivedAt);
      if (taskId) completeTask.run(status === 'success' ? 'completed' : 'failed', taskId, agentId);
      event(agentId, 'result', { queueItemId, taskId, reportedTaskId, collector, status }, receivedAt);
      logger.info({ event: 'result', agentId, queueItemId, taskId, reportedTaskId, collector, status });
      response.json({ accepted: true, queueItemId });
    } catch (error) { next(error); }
  });

  app.post('/api/admin/tasks', (request, response, next) => {
    try {
      const body = requireObject(request.body, 'request body');
      const collectorName = requireString(body.collectorName, 'collectorName');
      const params = body.params == null ? {} : requireObject(body.params, 'params');
      const agentId = body.agentId == null ? null : requireString(body.agentId, 'agentId');
      if (agentId && !findAgentById.get(agentId)) throw httpError(404, `Agent not found: ${agentId}`);
      const taskId = randomUUID(); const timestamp = now().toISOString();
      insertTask.run(taskId, agentId, collectorName, JSON.stringify(params), timestamp);
      if (agentId) event(agentId, 'task-created', { taskId, collectorName }, timestamp);
      response.status(201).json({ taskId });
    } catch (error) { next(error); }
  });

  app.post('/api/admin/enrollment-tokens', (request, response, next) => {
    try {
      const body = request.body ?? {};
      const expiresInHours = body.expiresInHours ?? 24;
      const maxUses = body.maxUses ?? 1;
      if (typeof expiresInHours !== 'number' || expiresInHours <= 0 || expiresInHours > 168) throw httpError(400, 'expiresInHours must be between 0 and 168');
      if (maxUses !== null && (!Number.isInteger(maxUses) || maxUses < 1)) throw httpError(400, 'maxUses must be a positive integer or null');
      const token = randomBytes(18).toString('base64url');
      const createdAt = now(); const expiresAt = new Date(createdAt.getTime() + expiresInHours * 3600000);
      insertEnrollmentToken.run(hashToken(token), createdAt.toISOString(), expiresAt.toISOString(), maxUses);
      response.status(201).json({ token, expiresAt: expiresAt.toISOString(), maxUses });
    } catch (error) { next(error); }
  });

  const dashboardAuth = (request, _response, next) => dashboardSessions.valid(request) ? next() : next(httpError(401, 'Dashboard login required'));
  app.post('/api/dashboard/session', limiter, (request, response, next) => {
    try {
      const token = requireString(requireObject(request.body, 'request body').token, 'token');
      const session = dashboardSessions.create(token);
      if (!session) throw httpError(401, 'Invalid admin token');
      response.setHeader('Set-Cookie', `asvp_fleet_session=${session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secureDashboardCookie ? '; Secure' : ''}`);
      response.json({ authenticated: true });
    } catch (error) { next(error); }
  });
  app.delete('/api/dashboard/session', dashboardAuth, (request, response) => {
    dashboardSessions.destroy(request);
    response.setHeader('Set-Cookie', 'asvp_fleet_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    response.status(204).end();
  });
  app.get('/api/dashboard/fleet', dashboardAuth, (_request, response) => {
    const timestamp = now();
    const agents = database.prepare('SELECT id, hostname, platform, architecture, registered_at, last_heartbeat_at, last_poll_at FROM agents ORDER BY registered_at DESC').all().map((agent) => ({
      ...agent, status: computeFleetStatus(agent, { now: timestamp, expectedHeartbeatIntervalMs }).state,
    }));
    response.json({ generatedAt: timestamp.toISOString(), expectedHeartbeatIntervalMs, onlineThresholdMs: expectedHeartbeatIntervalMs * 2, agents });
  });
  app.get('/api/dashboard/agents/:agentId', dashboardAuth, (request, response, next) => {
    try {
      const agent = database.prepare('SELECT id, hostname, platform, architecture, registered_at, last_heartbeat_at, last_poll_at FROM agents WHERE id = ?').get(request.params.agentId);
      if (!agent) throw httpError(404, 'Agent not found');
      const tasks = database.prepare('SELECT id, collector_name, params, status, created_at, dispatched_at FROM tasks WHERE agent_id = ? ORDER BY created_at DESC').all(agent.id).map((row) => ({ ...row, params: parseJson(row.params, {}) }));
      const results = database.prepare('SELECT id, task_id, collector, status, raw_data, received_at FROM results WHERE agent_id = ? ORDER BY received_at DESC').all(agent.id).map((row) => ({ ...row, data: parseJson(row.raw_data, null), raw_data: undefined }));
      const events = database.prepare('SELECT id, event_type, details, created_at FROM agent_events WHERE agent_id = ? ORDER BY created_at DESC, id DESC LIMIT 200').all(agent.id).map((row) => ({ ...row, details: parseJson(row.details, {}) }));
      response.json({ agent: { ...agent, status: computeFleetStatus(agent, { now: now(), expectedHeartbeatIntervalMs }).state }, tasks, results, events });
    } catch (error) { next(error); }
  });

  app.use('/fleet/assets', express.static(dashboardRoot, { index: false }));
  const dashboardPage = (_request, response) => response.sendFile(path.join(dashboardRoot, 'index.html'));
  const dashboardPageAuth = (request, response, next) => dashboardSessions.valid(request) ? next() : response.redirect(302, '/login');
  app.get('/login', dashboardPage);
  app.get('/', (request, response) => response.redirect(302, dashboardSessions.valid(request) ? '/fleet' : '/login'));
  app.get('/fleet', dashboardPageAuth, dashboardPage);
  app.get('/fleet/agents/:agentId', dashboardPageAuth, dashboardPage);

  app.use((error, _request, response, _next) => {
    const status = Number(error.status) || (error.type === 'entity.parse.failed' ? 400 : 500);
    if (status >= 500) logger.error({ event: 'server-error', error: error.message, stack: error.stack });
    response.status(status).json({ error: error.message });
  });
  return app;
}
