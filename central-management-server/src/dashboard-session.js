import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

function hash(value) {
  return createHash('sha256').update(value).digest('hex');
}

function matches(expected, supplied) {
  if (typeof supplied !== 'string') return false;
  return timingSafeEqual(createHash('sha256').update(expected).digest(), createHash('sha256').update(supplied).digest());
}

function cookies(header = '') {
  return Object.fromEntries(header.split(';').map((part) => part.trim().split('=').map(decodeURIComponent)).filter(([key]) => key));
}

export function createDashboardSessions({ adminToken, now = () => Date.now(), ttlMs = 8 * 60 * 60 * 1000 }) {
  const sessions = new Map();
  function create(supplied) {
    if (!matches(adminToken, supplied)) return null;
    const id = randomBytes(32).toString('base64url');
    sessions.set(hash(id), now() + ttlMs);
    return id;
  }
  function valid(request) {
    const id = cookies(request.headers.cookie).asvp_fleet_session;
    if (!id) return false;
    const key = hash(id);
    const expiresAt = sessions.get(key);
    if (!expiresAt || expiresAt <= now()) {
      sessions.delete(key);
      return false;
    }
    return true;
  }
  function destroy(request) {
    const id = cookies(request.headers.cookie).asvp_fleet_session;
    if (id) sessions.delete(hash(id));
  }
  return { create, valid, destroy };
}
