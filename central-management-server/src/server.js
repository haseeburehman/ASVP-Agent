import { randomBytes } from 'node:crypto';
import { createApp } from './app.js';
import { createDatabase } from './database.js';
import { createDashboardSessions } from './dashboard-session.js';
import { createFleetWebSocketHub } from './fleet-websocket.js';

const host = process.env.ASVP_SERVER_HOST ?? '127.0.0.1';
const port = Number(process.env.ASVP_SERVER_PORT ?? 8080);
const databasePath = process.env.ASVP_DATABASE_PATH ?? 'var/management.sqlite';
const configuredAdminToken = process.env.ADMIN_TOKEN;
const adminToken = configuredAdminToken || randomBytes(32).toString('base64url');
const requireEnrollmentToken = process.env.REQUIRE_ENROLLMENT_TOKEN === 'true';
const expectedHeartbeatIntervalMs = Number(process.env.EXPECTED_HEARTBEAT_INTERVAL_MS ?? 30000);
const baselineRescanIntervalMs = Number(process.env.BASELINE_RESCAN_INTERVAL_MS ?? 86400000);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('ASVP_SERVER_PORT must be a valid TCP port');
if (!Number.isInteger(expectedHeartbeatIntervalMs) || expectedHeartbeatIntervalMs < 100) throw new Error('EXPECTED_HEARTBEAT_INTERVAL_MS must be at least 100');
if (!Number.isInteger(baselineRescanIntervalMs) || baselineRescanIntervalMs < 60000) throw new Error('BASELINE_RESCAN_INTERVAL_MS must be at least 60000');

const database = createDatabase({ filename: databasePath });
const dashboardSessions = createDashboardSessions({ adminToken });
const fleetHub = createFleetWebSocketHub({ sessions: dashboardSessions, logger: console });
const app = createApp({
  database,
  adminToken,
  requireEnrollmentToken,
  expectedHeartbeatIntervalMs,
  baselineRescanIntervalMs,
  fleetHub,
  dashboardSessions,
  secureDashboardCookie: process.env.DASHBOARD_SECURE_COOKIE === 'true',
  logger: console,
});
const server = app.listen(port, host, () => {
  console.info({ event: 'server-started', host, port, databasePath, adminTokenSource: configuredAdminToken ? 'environment' : 'generated' });
  if (!configuredAdminToken) {
    console.info(`ASVP admin token (generated for this process; shown once): ${adminToken}`);
    console.warn('Set ADMIN_TOKEN to a persistent secret before any long-running deployment; generated tokens change on every restart.');
  }
  if (host !== '127.0.0.1' && host !== '::1' && host !== 'localhost') {
    console.warn('SECURITY WARNING: this minimal server is not hardened for non-loopback exposure.');
  }
});
fleetHub.attach(server);
const statusSweep = setInterval(() => app.locals.sweepFleetStatuses(), Math.min(expectedHeartbeatIntervalMs, 5000));
statusSweep.unref();

async function shutdown(signal) {
  console.info({ event: 'server-stopping', signal });
  clearInterval(statusSweep);
  await fleetHub.close();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  database.close();
}

process.once('SIGINT', () => shutdown('SIGINT').catch((error) => { console.error(error); process.exitCode = 1; }));
process.once('SIGTERM', () => shutdown('SIGTERM').catch((error) => { console.error(error); process.exitCode = 1; }));
