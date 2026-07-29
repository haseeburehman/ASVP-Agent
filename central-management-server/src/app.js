import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { decodeResultEnvelope, generateAgentSecrets, hashToken } from './crypto.js';
import { createDashboardSessions } from './dashboard-session.js';
import { DEFAULT_TENANT_ID } from './database.js';
import { computeFleetStatus } from './fleet-status.js';
import { createNormalizationWorker } from './vulnerability/worker.js';
import { canonicalizeTaskParams, deriveTaskSigningKey, signTaskEnvelope } from '../../src/security/task-envelope.js';

const dashboardRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), 'public', 'dashboard');
export const BASELINE_COLLECTORS = Object.freeze(['os-info', 'apps', 'compliance-checks', 'users-groups', 'antivirus-status']);
function httpError(status, message, code) { const error = new Error(message); error.status = status; error.code = code; return error; }
function requireString(value, name) { if (typeof value !== 'string' || !value.trim()) throw httpError(400, `${name} must be a non-empty string`); return value.trim(); }
function requireObject(value, name) { if (!value || typeof value !== 'object' || Array.isArray(value)) throw httpError(400, `${name} must be an object`); return value; }
function requireMachineFingerprint(value) {
  const fingerprint = requireString(value, 'machineFingerprint');
  if (!/^[a-f0-9]{64}$/i.test(fingerprint)) throw httpError(400, 'machineFingerprint must be a SHA-256 hex string');
  return fingerprint.toLowerCase();
}
function fingerprintsMatch(expected, supplied) {
  return typeof expected === 'string' && /^[a-f0-9]{64}$/i.test(expected)
    && timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(supplied, 'hex'));
}
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
const INTEGRITY_EVENT_TYPES = new Set(['binary-integrity-mismatch', 'config-integrity-mismatch']);
function integrityEvents(value) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 10).flatMap((item) => {
    if (!item || typeof item !== 'object' || !INTEGRITY_EVENT_TYPES.has(item.type)) return [];
    return [{ type: item.type, details: {
      target: typeof item.target === 'string' ? item.target : null,
      path: typeof item.path === 'string' ? item.path : null,
      expectedHash: typeof item.expectedHash === 'string' ? item.expectedHash : null,
      actualHash: typeof item.actualHash === 'string' ? item.actualHash : null,
      detectedAt: typeof item.detectedAt === 'string' ? item.detectedAt : null,
    } }];
  });
}

export function createApp({
  database,
  adminToken,
  taskSigningSecret,
  taskSigningKeyId = 'v1',
  adminRateLimit = { maxRequests: 60, windowMs: 60000 },
  expectedHeartbeatIntervalMs = 30000,
  secureDashboardCookie = false,
  baselineRescanIntervalMs = 24 * 60 * 60 * 1000,
  baselineCollectors = BASELINE_COLLECTORS,
  requireEnrollmentToken = false,
  fleetHub = { broadcast() {} },
  dashboardSessions: suppliedDashboardSessions,
  logger = console,
  now = () => new Date(),
  rateNow = () => Date.now(),
  normalizationWorker: suppliedNormalizationWorker,
}) {
  if (typeof adminToken !== 'string' || !adminToken) throw new Error('createApp requires a non-empty adminToken');
  if (typeof taskSigningSecret !== 'string' || !taskSigningSecret) throw new Error('createApp requires a non-empty taskSigningSecret');
  if (typeof taskSigningKeyId !== 'string' || !taskSigningKeyId) throw new Error('createApp requires a non-empty taskSigningKeyId');
  const app = express();
  const authenticate = createAuthenticator(database);
  if (!Number.isInteger(baselineRescanIntervalMs) || baselineRescanIntervalMs < 60000) throw new Error('baselineRescanIntervalMs must be at least 60000');
  const dashboardSessions = suppliedDashboardSessions ?? createDashboardSessions({ adminToken, now: rateNow });
  const limiter = createRateLimiter({ ...adminRateLimit, now: rateNow });
  const knownFleetStates = new Map();
  const normalizationWorker = suppliedNormalizationWorker ?? createNormalizationWorker({ database, logger });
  normalizationWorker.enqueueMissing?.();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '25mb' }));
  app.use('/api/admin', limiter, createAdminAuthenticator(adminToken));

  const insertAgent = database.prepare(`INSERT INTO agents (id, tenant_id, hostname, auth_token_hash, encryption_key, registered_at, last_heartbeat_at, status, platform, architecture, last_poll_at, agent_version, deregistered_at, machine_fingerprint) VALUES (?, ?, ?, ?, ?, ?, NULL, 'registered', ?, ?, NULL, ?, NULL, ?)`);
  const findRegistrationAgent = database.prepare('SELECT id, tenant_id, auth_token_hash, encryption_key, machine_fingerprint FROM agents WHERE id = ?');
  const rotateAgentCredentials = database.prepare(`UPDATE agents SET hostname = COALESCE(?, hostname), platform = COALESCE(?, platform), architecture = COALESCE(?, architecture), agent_version = COALESCE(?, agent_version), auth_token_hash = ?, machine_fingerprint = COALESCE(machine_fingerprint, ?), last_heartbeat_at = NULL, last_poll_at = NULL, deregistered_at = NULL, status = 'registered' WHERE id = ? AND tenant_id = ?`);
  const updateHeartbeat = database.prepare(`UPDATE agents SET hostname = ?, last_heartbeat_at = ?, agent_version = COALESCE(?, agent_version), deregistered_at = NULL, status = 'online' WHERE id = ? AND tenant_id = ?`);
  const deregisterAgent = database.prepare(`UPDATE agents SET status = 'deregistered', deregistered_at = ? WHERE id = ? AND tenant_id = ?`);
  const updatePoll = database.prepare('UPDATE agents SET last_poll_at = ? WHERE id = ? AND tenant_id = ?');
  const findTaskSequence = database.prepare('SELECT task_sequence FROM agents WHERE id = ? AND tenant_id = ?');
  const updateTaskSequence = database.prepare('UPDATE agents SET task_sequence = ? WHERE id = ? AND tenant_id = ?');
  const insertEvent = database.prepare('INSERT INTO agent_events (tenant_id, agent_id, event_type, details, created_at) VALUES (?, ?, ?, ?, ?)');
  const event = (tenantId, agentId, type, details, timestamp = now().toISOString()) => insertEvent.run(tenantId, agentId, type, JSON.stringify(details), timestamp);
  const requireBoundFingerprint = (request, _response, next) => {
    try {
      const supplied = requireMachineFingerprint(requireObject(request.body, 'request body').machineFingerprint);
      if (fingerprintsMatch(request.agent.machine_fingerprint, supplied)) return next();
      const details = { route: request.path, method: request.method };
      event(request.agent.tenant_id, request.agent.id, 'identity-fingerprint-mismatch', details);
      logger.warn({ event: 'identity-fingerprint-mismatch', agentId: request.agent.id, tenantId: request.agent.tenant_id, ...details, message: 'Rejected authenticated agent request due to machine fingerprint mismatch' });
      return next(httpError(403, 'Machine fingerprint does not match registered agent identity', 'IDENTITY_FINGERPRINT_MISMATCH'));
    } catch (error) { return next(error); }
  };
  const selectTasks = database.prepare(`SELECT * FROM tasks WHERE tenant_id = ? AND status = 'pending' AND (agent_id = ? OR agent_id IS NULL) ORDER BY created_at, id`);
  const dispatchTask = database.prepare(`UPDATE tasks SET status = 'dispatched', agent_id = ?, dispatched_at = ? WHERE id = ? AND tenant_id = ? AND status = 'pending'`);
  const dispatchPending = database.transaction((tenantId, agentId, issuedAt) => {
    const dispatched = [];
    let sequence = findTaskSequence.get(agentId, tenantId).task_sequence;
    const signingKey = deriveTaskSigningKey(taskSigningSecret, agentId);
    const expiresAt = new Date(new Date(issuedAt).getTime() + 10 * 60 * 1000).toISOString();
    for (const row of selectTasks.all(tenantId, agentId)) {
      if (dispatchTask.run(agentId, issuedAt, row.id, tenantId).changes !== 1) continue;
      sequence += 1;
      const envelope = {
        taskId: row.id,
        agentId,
        tenantId,
        collectorName: row.collector_name,
        params: canonicalizeTaskParams(parseJson(row.params, {})),
        issuedAt,
        expiresAt,
        sequence,
        nonce: randomBytes(18).toString('base64url'),
        keyId: taskSigningKeyId,
      };
      dispatched.push({ ...envelope, signature: signTaskEnvelope(envelope, signingKey) });
    }
    if (dispatched.length) updateTaskSequence.run(sequence, agentId, tenantId);
    return dispatched;
  });
  const findResult = database.prepare('SELECT id FROM results WHERE id = ? AND tenant_id = ? AND agent_id = ?');
  const insertResult = database.prepare(`INSERT INTO results (id, tenant_id, agent_id, task_id, collector, status, raw_data, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
  const completeTask = database.prepare(`UPDATE tasks SET status = ? WHERE id = ? AND tenant_id = ? AND agent_id = ?`);
  const findTask = database.prepare('SELECT id FROM tasks WHERE id = ? AND tenant_id = ? AND agent_id = ?');
  const insertTask = database.prepare(`INSERT INTO tasks (id, tenant_id, agent_id, collector_name, params, status, created_at, dispatched_at) VALUES (?, ?, ?, ?, ?, 'pending', ?, NULL)`);
  const findAgentById = database.prepare('SELECT id, tenant_id FROM agents WHERE id = ?');
  const findTenantById = database.prepare("SELECT id FROM tenants WHERE id = ? AND status = 'active'");
  const findLatestBaselineTask = database.prepare('SELECT created_at FROM tasks WHERE tenant_id = ? AND agent_id = ? AND collector_name = ? ORDER BY created_at DESC LIMIT 1');
  function enqueueBaseline(tenantId, agentId, timestamp, force = false) {
    const scheduled = [];
    for (const collectorName of baselineCollectors) {
      const latest = findLatestBaselineTask.get(tenantId, agentId, collectorName);
      const due = force || !latest || new Date(timestamp).getTime() - new Date(latest.created_at).getTime() >= baselineRescanIntervalMs;
      if (!due) continue;
      const taskId = randomUUID();
      insertTask.run(taskId, tenantId, agentId, collectorName, '{}', timestamp);
      event(tenantId, agentId, 'task-created', { taskId, collectorName, source: 'baseline' }, timestamp);
      scheduled.push({ taskId, collectorName });
    }
    return scheduled;
  }
  const insertEnrollmentToken = database.prepare('INSERT INTO enrollment_tokens (token_hash, tenant_id, created_at, expires_at, max_uses, use_count) VALUES (?, ?, ?, ?, ?, 0)');
  const findUsableEnrollmentTokens = database.prepare(`SELECT token_hash, tenant_id FROM enrollment_tokens WHERE expires_at > ? AND (max_uses IS NULL OR use_count < max_uses)`);
  const consumeEnrollmentToken = database.prepare(`UPDATE enrollment_tokens SET use_count = use_count + 1 WHERE token_hash = ? AND tenant_id = ? AND expires_at > ? AND (max_uses IS NULL OR use_count < max_uses)`);
  function findEnrollmentToken(suppliedToken, timestamp) {
    if (typeof suppliedToken !== 'string') return null;
    return findUsableEnrollmentTokens.all(timestamp)
      .find((row) => storedTokenMatches(row.token_hash, suppliedToken)) ?? null;
  }

  const registerNew = database.transaction(({ hostname, platform, architecture, agentVersion, enrollmentToken, machineFingerprint }) => {
    const timestamp = now().toISOString();
    const suppliedEnrollmentToken = typeof enrollmentToken === 'string' && enrollmentToken.trim() !== '';
    const tokenRow = suppliedEnrollmentToken ? findEnrollmentToken(enrollmentToken, timestamp) : null;
    if (suppliedEnrollmentToken && (!tokenRow || consumeEnrollmentToken.run(tokenRow.token_hash, tokenRow.tenant_id, timestamp).changes !== 1)) {
      throw httpError(403, 'Valid enrollment token required');
    }
    if (!suppliedEnrollmentToken && requireEnrollmentToken) throw httpError(403, 'Valid enrollment token required');
    const tenantId = tokenRow?.tenant_id ?? DEFAULT_TENANT_ID;
    const agentId = randomUUID();
    const secrets = generateAgentSecrets();
    insertAgent.run(agentId, tenantId, hostname, hashToken(secrets.authToken), secrets.encryptionKey, timestamp, platform, architecture, agentVersion, machineFingerprint);
    event(tenantId, agentId, 'register', { continuity: 'new-agent', hostname, platform, architecture }, timestamp);
    const baselineTasks = enqueueBaseline(tenantId, agentId, timestamp, true);
    return {
      agentId,
      tenantId,
      ...secrets,
      taskSigningKey: deriveTaskSigningKey(taskSigningSecret, agentId),
      taskSigningKeyId,
      baselineTasks,
    };
  });

  app.post('/api/agents/register', (request, response, next) => {
    try {
      const body = requireObject(request.body, 'request body');
      const hostname = body.hostname == null ? null : requireString(body.hostname, 'hostname');
      const platform = body.platform == null ? null : requireString(body.platform, 'platform');
      const architecture = body.architecture == null ? null : requireString(body.architecture, 'architecture');
      const agentVersion = body.agentVersion == null ? null : requireString(body.agentVersion, 'agentVersion');
      const machineFingerprint = requireMachineFingerprint(body.machineFingerprint);
      const previousAgentId = body.previousAgentId == null ? null : requireString(body.previousAgentId, 'previousAgentId');
      const knownPreviousAgent = previousAgentId ? findRegistrationAgent.get(previousAgentId) : null;
      const previousBearer = /^Bearer\s+(.+)$/i.exec(request.headers.authorization ?? '')?.[1];
      const continuityAuthorized = Boolean(knownPreviousAgent) && storedTokenMatches(knownPreviousAgent.auth_token_hash, previousBearer);
      let identity;
      if (continuityAuthorized) {
        if (knownPreviousAgent.machine_fingerprint && !fingerprintsMatch(knownPreviousAgent.machine_fingerprint, machineFingerprint)) {
          event(knownPreviousAgent.tenant_id, previousAgentId, 'identity-fingerprint-mismatch', { route: request.path, method: request.method, operation: 'continuity-registration' });
          logger.warn({ event: 'identity-fingerprint-mismatch', agentId: previousAgentId, tenantId: knownPreviousAgent.tenant_id, route: request.path, method: request.method, operation: 'continuity-registration', message: 'Rejected continuity registration due to machine fingerprint mismatch' });
          throw httpError(403, 'Machine fingerprint does not match registered agent identity', 'IDENTITY_FINGERPRINT_MISMATCH');
        }
        const secrets = generateAgentSecrets();
        rotateAgentCredentials.run(hostname, platform, architecture, agentVersion, hashToken(secrets.authToken), machineFingerprint, previousAgentId, knownPreviousAgent.tenant_id);
        event(knownPreviousAgent.tenant_id, previousAgentId, 'register', { continuity: 'reused-existing-agent', hostname, platform, architecture });
        identity = {
          agentId: previousAgentId,
          tenantId: knownPreviousAgent.tenant_id,
          authToken: secrets.authToken,
          encryptionKey: knownPreviousAgent.encryption_key,
          taskSigningKey: deriveTaskSigningKey(taskSigningSecret, previousAgentId),
          taskSigningKeyId,
        };
      } else {
        identity = registerNew({ hostname, platform, architecture, agentVersion, enrollmentToken: body.enrollmentToken, machineFingerprint });
      }
      const baselineTasks = identity.baselineTasks ?? [];
      delete identity.baselineTasks;
      for (const integrityEvent of integrityEvents(body.integrityEvents)) {
        event(identity.tenantId, identity.agentId, integrityEvent.type, integrityEvent.details);
        logger.error({ event: integrityEvent.type, tenantId: identity.tenantId, agentId: identity.agentId, ...integrityEvent.details }, 'Agent reported an integrity mismatch during registration');
      }
      logger.info({ event: 'register', agentId: identity.agentId, previousAgentId, continuity: continuityAuthorized ? 'reused-existing-agent' : 'new-agent', hostname, platform, architecture, baselineTaskCount: baselineTasks.length });
      knownFleetStates.set(identity.agentId, 'never-connected');
      fleetHub.broadcast({ type: 'agent-registered', agentId: identity.agentId, hostname, platform, architecture, continuity: continuityAuthorized, baselineTaskCount: baselineTasks.length });
      response.status(201).json(identity);
    } catch (error) { next(error); }
  });

  app.post('/api/agents/deregister', authenticate, (request, response, next) => {
    try {
      const body = requireObject(request.body, 'request body');
      const agentId = requireString(body.agentId, 'agentId');
      if (agentId !== request.agent.id) throw httpError(403, 'Deregister agentId does not match bearer token');
      const timestamp = now().toISOString();
      deregisterAgent.run(timestamp, agentId, request.agent.tenant_id);
      event(request.agent.tenant_id, agentId, 'deregister', { reason: 'service-uninstall' }, timestamp);
      knownFleetStates.set(agentId, 'deregistered');
      fleetHub.broadcast({ type: 'status-transition', agentId, from: computeFleetStatus(request.agent, { now: now(), expectedHeartbeatIntervalMs }).state, to: 'deregistered', occurredAt: timestamp });
      response.json({ accepted: true, deregisteredAt: timestamp });
    } catch (error) { next(error); }
  });

  app.post('/api/agents/heartbeat', authenticate, requireBoundFingerprint, (request, response, next) => {
    try {
      const body = requireObject(request.body, 'request body');
      const agentId = requireString(body.agentId, 'agentId');
      if (agentId !== request.agent.id) throw httpError(403, 'Heartbeat agentId does not match bearer token');
      const hostname = requireString(body.hostname, 'hostname');
      const timestamp = now().toISOString();
      const previousStatus = computeFleetStatus(request.agent, { now: now(), expectedHeartbeatIntervalMs }).state;
      updateHeartbeat.run(hostname, timestamp, body.agentVersion ?? null, agentId, request.agent.tenant_id);
      event(request.agent.tenant_id, agentId, 'heartbeat', { hostname, uptimeSeconds: body.uptimeSeconds ?? null, queueSize: body.currentQueueSize ?? null, agentVersion: body.agentVersion ?? null }, timestamp);
      for (const integrityEvent of integrityEvents(body.integrityEvents)) {
        event(request.agent.tenant_id, agentId, integrityEvent.type, integrityEvent.details, timestamp);
        logger.error({ event: integrityEvent.type, tenantId: request.agent.tenant_id, agentId, ...integrityEvent.details }, 'Agent reported an integrity mismatch during heartbeat');
      }
      fleetHub.broadcast({ type: 'heartbeat', agentId, hostname, receivedAt: timestamp, queueSize: body.currentQueueSize ?? null, agentVersion: body.agentVersion ?? null });
      if (previousStatus !== 'online') fleetHub.broadcast({ type: 'status-transition', agentId, from: previousStatus, to: 'online', occurredAt: timestamp });
      knownFleetStates.set(agentId, 'online');
      logger.info({ event: 'heartbeat', agentId, hostname });
      response.json({ accepted: true, receivedAt: timestamp });
    } catch (error) { next(error); }
  });

  app.post('/api/agents/tasks/poll', authenticate, requireBoundFingerprint, (request, response, next) => {
    try {
      const body = requireObject(request.body, 'request body');
      const agentId = requireString(body.agentId, 'agentId');
      if (agentId !== request.agent.id) throw httpError(403, 'Task poll agentId does not match bearer token');
      const timestamp = now().toISOString();
      const tenantId = request.agent.tenant_id;
      updatePoll.run(timestamp, agentId, tenantId);
      const baselineTasks = enqueueBaseline(tenantId, agentId, timestamp);
      const tasks = dispatchPending(tenantId, agentId, timestamp);
      event(tenantId, agentId, 'poll', { taskCount: tasks.length, taskIds: tasks.map((task) => task.taskId) }, timestamp);
      logger.info({ event: 'poll', agentId, taskCount: tasks.length, taskIds: tasks.map((task) => task.taskId), baselineTaskCount: baselineTasks.length });
      response.json(tasks);
    } catch (error) { next(error); }
  });

  app.post('/api/agents/results', authenticate, requireBoundFingerprint, async (request, response, next) => {
    try {
      const envelope = requireObject(request.body, 'request body');
      const queueItemId = requireString(envelope.queueItemId, 'queueItemId');
      const agentId = requireString(envelope.agentId, 'agentId');
      if (agentId !== request.agent.id) throw httpError(403, 'Result agentId does not match bearer token');
      if (envelope.schemaVersion !== 1) throw httpError(400, 'Unsupported result schemaVersion');
      for (const field of ['enqueuedAt', 'contentEncoding', 'encryption', 'iv', 'authTag', 'ciphertext']) requireString(envelope[field], field);
      const tenantId = request.agent.tenant_id;
      if (findResult.get(queueItemId, tenantId, agentId)) {
        event(tenantId, agentId, 'result-duplicate', { queueItemId });
        response.json({ accepted: true, queueItemId }); return;
      }
      let decoded;
      try { decoded = await decodeResultEnvelope(envelope, request.agent.encryption_key); }
      catch (error) { throw httpError(400, `Unable to decrypt/decompress result: ${error.message}`); }
      const result = requireObject(decoded.result, 'decrypted result');
      const collector = requireString(result.collector, 'result.collector');
      const status = requireString(result.status, 'result.status');
      const reportedTaskId = result.taskId ?? null;
      const taskId = reportedTaskId && findTask.get(reportedTaskId, tenantId, agentId) ? reportedTaskId : null;
      const receivedAt = now().toISOString();
      insertResult.run(queueItemId, tenantId, agentId, taskId, collector, status, JSON.stringify(result), receivedAt);
      if (taskId) completeTask.run(status === 'success' ? 'completed' : 'failed', taskId, tenantId, agentId);
      event(tenantId, agentId, 'result', { queueItemId, taskId, reportedTaskId, collector, status }, receivedAt);
      const data = result.data && typeof result.data === 'object' ? result.data : null;
      fleetHub.broadcast({
        type: 'result-received',
        agentId,
        queueItemId,
        taskId,
        collector,
        status,
        receivedAt,
        summary: data ? {
          itemCount: Array.isArray(data) ? data.length : undefined,
          keys: Array.isArray(data) ? undefined : Object.keys(data).slice(0, 12),
        } : null,
      });
      logger.info({ event: 'result', agentId, queueItemId, taskId, reportedTaskId, collector, status });
      response.json({ accepted: true, queueItemId });
      normalizationWorker.enqueue({ resultId: queueItemId, tenantId, agentId });
    } catch (error) { next(error); }
  });

  app.post('/api/admin/tasks', (request, response, next) => {
    try {
      const body = requireObject(request.body, 'request body');
      const collectorName = requireString(body.collectorName, 'collectorName');
      const params = body.params == null ? {} : requireObject(body.params, 'params');
      const agentId = body.agentId == null ? null : requireString(body.agentId, 'agentId');
      const suppliedTenantId = body.tenantId == null ? null : requireString(body.tenantId, 'tenantId');
      const targetAgent = agentId ? findAgentById.get(agentId) : null;
      if (agentId && !targetAgent) throw httpError(404, `Agent not found: ${agentId}`);
      if (targetAgent && suppliedTenantId && suppliedTenantId !== targetAgent.tenant_id) throw httpError(400, 'tenantId does not match target agent tenant');
      const tenantId = targetAgent?.tenant_id ?? suppliedTenantId;
      if (!tenantId) throw httpError(400, 'tenantId is required for unassigned tasks');
      if (!findTenantById.get(tenantId)) throw httpError(404, `Active tenant not found: ${tenantId}`);
      const taskId = randomUUID(); const timestamp = now().toISOString();
      insertTask.run(taskId, tenantId, agentId, collectorName, JSON.stringify(params), timestamp);
      if (agentId) event(tenantId, agentId, 'task-created', { taskId, collectorName }, timestamp);
      response.status(201).json({ taskId, tenantId });
    } catch (error) { next(error); }
  });

  app.get('/api/admin/tenants/:tenantId/agents/:agentId/normalized-software', (request, response, next) => {
    try {
      const tenantId = requireString(request.params.tenantId, 'tenantId');
      const agentId = requireString(request.params.agentId, 'agentId');
      const agent = database.prepare('SELECT id FROM agents WHERE id = ? AND tenant_id = ?').get(agentId, tenantId);
      if (!agent) throw httpError(404, 'Agent not found in tenant');
      const software = database.prepare(`SELECT source_result_id, source_collector, raw_name, raw_version, vendor, product,
        normalized_version, cpe23_candidate, match_confidence, match_method, normalized_at
        FROM normalized_software WHERE tenant_id = ? AND agent_id = ? ORDER BY normalized_at DESC, source_result_id, ordinal`)
        .all(tenantId, agentId).map((row) => ({
          sourceResultId: row.source_result_id,
          sourceCollector: row.source_collector,
          rawName: row.raw_name,
          rawVersion: row.raw_version,
          vendor: row.vendor,
          product: row.product,
          version: row.normalized_version,
          cpe23Candidate: row.cpe23_candidate,
          matchConfidence: row.match_confidence,
          matchMethod: row.match_method,
          normalizedAt: row.normalized_at,
        }));
      response.json({ tenantId, agentId, software });
    } catch (error) { next(error); }
  });

  app.get('/api/admin/tenants/:tenantId/agents/:agentId/missing-patches', (request, response, next) => {
    try {
      const tenantId = requireString(request.params.tenantId, 'tenantId');
      const agentId = requireString(request.params.agentId, 'agentId');
      const agent = database.prepare('SELECT id FROM agents WHERE id = ? AND tenant_id = ?').get(agentId, tenantId);
      if (!agent) throw httpError(404, 'Agent not found in tenant');
      const patches = database.prepare(`SELECT source_result_id, advisory_id, severity, title, published_date, source,
        source_url, confidence, rationale, feed_fetched_at, matched_at FROM missing_patches
        WHERE tenant_id = ? AND agent_id = ? ORDER BY published_date DESC, advisory_id`)
        .all(tenantId, agentId).map((row) => ({
          sourceResultId: row.source_result_id, advisoryId: row.advisory_id, severity: row.severity,
          title: row.title, publishedDate: row.published_date, source: row.source, sourceUrl: row.source_url,
          confidence: row.confidence, rationale: row.rationale, feedFetchedAt: row.feed_fetched_at, matchedAt: row.matched_at,
        }));
      const feedCache = database.prepare(`SELECT feed_name, source_url, source_format, fetched_at, last_attempt_at, last_error,
        json_array_length(advisories_json) AS advisory_count FROM patch_feed_cache ORDER BY feed_name`).all().map((row) => ({
        feedName: row.feed_name, sourceUrl: row.source_url, sourceFormat: row.source_format,
        fetchedAt: row.fetched_at, lastAttemptAt: row.last_attempt_at, lastError: row.last_error,
        advisoryCount: row.advisory_count,
      }));
      response.json({ tenantId, agentId, assessment: 'advisory-based inference; not vendor confirmation', patches, feedCache });
    } catch (error) { next(error); }
  });

  app.post('/api/admin/enrollment-tokens', (request, response, next) => {
    try {
      const body = request.body ?? {};
      const expiresInHours = body.expiresInHours ?? 24;
      const maxUses = body.maxUses ?? 1;
      const tenantId = requireString(body.tenantId, 'tenantId');
      if (!findTenantById.get(tenantId)) throw httpError(404, `Active tenant not found: ${tenantId}`);
      if (typeof expiresInHours !== 'number' || expiresInHours <= 0 || expiresInHours > 168) throw httpError(400, 'expiresInHours must be between 0 and 168');
      if (maxUses !== null && (!Number.isInteger(maxUses) || maxUses < 1)) throw httpError(400, 'maxUses must be a positive integer or null');
      const token = randomBytes(18).toString('base64url');
      const createdAt = now(); const expiresAt = new Date(createdAt.getTime() + expiresInHours * 3600000);
      insertEnrollmentToken.run(hashToken(token), tenantId, createdAt.toISOString(), expiresAt.toISOString(), maxUses);
      response.status(201).json({ token, tenantId, expiresAt: expiresAt.toISOString(), maxUses });
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
    const agents = database.prepare('SELECT id, hostname, platform, architecture, agent_version, registered_at, last_heartbeat_at, last_poll_at, status, deregistered_at FROM agents ORDER BY registered_at DESC').all().map((agent) => ({
      ...agent, status: computeFleetStatus(agent, { now: timestamp, expectedHeartbeatIntervalMs }).state,
    }));
    response.json({ generatedAt: timestamp.toISOString(), expectedHeartbeatIntervalMs, onlineThresholdMs: expectedHeartbeatIntervalMs * 2, agents });
  });
  app.get('/api/dashboard/agents/:agentId', dashboardAuth, (request, response, next) => {
    try {
      const agent = database.prepare('SELECT id, hostname, platform, architecture, agent_version, registered_at, last_heartbeat_at, last_poll_at, status, deregistered_at FROM agents WHERE id = ?').get(request.params.agentId);
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

  app.locals.dashboardSessions = dashboardSessions;
  app.locals.normalizationWorker = normalizationWorker;
  app.locals.sweepFleetStatuses = () => {
    const timestamp = now();
    for (const agent of database.prepare('SELECT id, last_heartbeat_at, status, deregistered_at FROM agents').all()) {
      const state = computeFleetStatus(agent, { now: timestamp, expectedHeartbeatIntervalMs }).state;
      const previous = knownFleetStates.get(agent.id);
      if (previous && previous !== state) fleetHub.broadcast({ type: 'status-transition', agentId: agent.id, from: previous, to: state, occurredAt: timestamp.toISOString() });
      knownFleetStates.set(agent.id, state);
    }
  };

  app.use((error, _request, response, _next) => {
    const status = Number(error.status) || (error.type === 'entity.parse.failed' ? 400 : 500);
    if (status >= 500) logger.error({ event: 'server-error', error: error.message, stack: error.stack });
    response.status(status).json({ error: error.message, ...(error.code ? { code: error.code } : {}) });
  });
  return app;
}
