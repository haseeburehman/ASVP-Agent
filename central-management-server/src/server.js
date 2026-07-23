import { randomBytes } from 'node:crypto';
import { createApp } from './app.js';
import { createDatabase } from './database.js';

const host = process.env.ASVP_SERVER_HOST ?? '127.0.0.1';
const port = Number(process.env.ASVP_SERVER_PORT ?? 8080);
const databasePath = process.env.ASVP_DATABASE_PATH ?? 'var/management.sqlite';
const configuredAdminToken = process.env.ADMIN_TOKEN;
const adminToken = configuredAdminToken || randomBytes(32).toString('base64url');
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('ASVP_SERVER_PORT must be a valid TCP port');

const database = createDatabase({ filename: databasePath });
const app = createApp({ database, adminToken, logger: console });
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

async function shutdown(signal) {
  console.info({ event: 'server-stopping', signal });
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  database.close();
}

process.once('SIGINT', () => shutdown('SIGINT').catch((error) => { console.error(error); process.exitCode = 1; }));
process.once('SIGTERM', () => shutdown('SIGTERM').catch((error) => { console.error(error); process.exitCode = 1; }));
