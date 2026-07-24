export function computeFleetStatus(agent, { now = new Date(), expectedHeartbeatIntervalMs = 30000 } = {}) {
  const onlineThresholdMs = expectedHeartbeatIntervalMs * 2;
  if (agent.status === 'deregistered' || agent.deregistered_at) return { state: 'deregistered', heartbeatAgeMs: null, onlineThresholdMs };
  if (!agent.last_heartbeat_at) return { state: 'never-connected', heartbeatAgeMs: null, onlineThresholdMs };
  const heartbeatAgeMs = Math.max(0, now.getTime() - new Date(agent.last_heartbeat_at).getTime());
  return {
    state: heartbeatAgeMs <= onlineThresholdMs ? 'online' : 'stale',
    heartbeatAgeMs,
    onlineThresholdMs,
  };
}
