import { WebSocketServer, WebSocket } from 'ws';

export function createFleetWebSocketHub({ sessions, logger = console }) {
  const server = new WebSocketServer({ noServer: true });
  let httpServer;

  function onUpgrade(request, socket, head) {
    let pathname;
    try { pathname = new URL(request.url, 'http://localhost').pathname; } catch { socket.destroy(); return; }
    if (pathname !== '/api/dashboard/live') return;
    if (!sessions.valid(request)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    server.handleUpgrade(request, socket, head, (client) => server.emit('connection', client, request));
  }

  function attach(target) {
    httpServer = target;
    target.on('upgrade', onUpgrade);
  }

  function broadcast(message) {
    const payload = JSON.stringify({ ...message, sentAt: message.sentAt ?? new Date().toISOString() });
    for (const client of server.clients) if (client.readyState === WebSocket.OPEN) client.send(payload);
  }

  async function close() {
    if (httpServer) httpServer.off('upgrade', onUpgrade);
    for (const client of server.clients) client.close(1001, 'Server shutting down');
    await new Promise((resolve) => server.close(() => resolve()));
  }

  server.on('connection', (client) => {
    client.send(JSON.stringify({ type: 'connected', sentAt: new Date().toISOString() }));
  });
  server.on('error', (error) => logger.error({ event: 'fleet-websocket-error', error: error.message }));
  return { attach, broadcast, close, server };
}
