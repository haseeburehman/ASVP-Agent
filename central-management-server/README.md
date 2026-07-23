# ASVP Central Management Server

Minimal, production-shaped local management API for the ASVP internal network agent. It uses Express and SQLite (`better-sqlite3`) and binds to `127.0.0.1` by default.

## Start

From the agent repository root in PowerShell:

```powershell
npm.cmd --prefix .\central-management-server install
npm.cmd --prefix .\central-management-server start
```

Defaults:

```text
API:      http://127.0.0.1:8080
Database: central-management-server/var/management.sqlite
```

Optional environment variables:

```text
ASVP_SERVER_HOST
ASVP_SERVER_PORT
ASVP_DATABASE_PATH
ADMIN_TOKEN
```

`ADMIN_TOKEN` protects every `/api/admin/*` route. If omitted, startup generates a cryptographically random token and prints it once. That is convenient for a short local test, but a long-running deployment must set a persistent high-entropy `ADMIN_TOKEN`; otherwise dashboard task creation credentials change after every server restart.

## Verified agent API contract

### Registration

```http
POST /api/agents/register
Content-Type: application/json
```

The current `AgentLifecycle` sends:

```json
{
  "hostname": "WORKSTATION-01",
  "platform": "win32",
  "architecture": "x64"
}
```

Response:

```json
{
  "agentId": "uuid",
  "authToken": "opaque-random-token",
  "encryptionKey": "base64-encoded-32-byte-key"
}
```

The raw auth token is returned once and never stored by the server. SQLite stores its SHA-256 hash. The encryption key is stored because the server must decrypt result payloads.

### Heartbeat

```http
POST /api/agents/heartbeat
Authorization: Bearer <authToken>
Content-Type: application/json
```

Actual payload from `AgentRuntime`:

```json
{
  "agentId": "uuid",
  "uptimeSeconds": 120,
  "processUptimeSeconds": 124,
  "hostname": "WORKSTATION-01",
  "lastSuccessfulHeartbeat": "2026-07-22T12:00:00.000Z",
  "currentQueueSize": 2,
  "agentVersion": "0.1.0"
}
```

Response:

```json
{
  "accepted": true,
  "receivedAt": "2026-07-22T12:00:30.000Z"
}
```

### Task poll

```http
POST /api/agents/tasks/poll
Authorization: Bearer <authToken>
Content-Type: application/json
```

Request:

```json
{
  "agentId": "uuid"
}
```

Response is a JSON array:

```json
[
  {
    "taskId": "uuid",
    "collectorName": "os-info",
    "params": {},
    "scheduledAt": "2026-07-22T12:01:00.000Z"
  }
]
```

Returned tasks transition from `pending` to `dispatched` transactionally and are not returned by the next poll. A task created with `agentId: null` is claimed by the first polling agent; true fan-out broadcast replication is future work.

### Encrypted result upload

```http
POST /api/agents/results
Authorization: Bearer <authToken>
Content-Type: application/json
```

Request:

```json
{
  "schemaVersion": 1,
  "queueItemId": "uuid",
  "agentId": "uuid",
  "enqueuedAt": "2026-07-22T12:02:00.000Z",
  "contentEncoding": "gzip",
  "encryption": "aes-256-gcm",
  "iv": "base64",
  "authTag": "base64",
  "ciphertext": "base64",
  "uncompressedSizeBytes": 4096,
  "compressedSizeBytes": 900
}
```

The server decrypts AES-256-GCM using the registered key, verifies the authentication tag, gunzips the plaintext, parses the normalized collector result, and stores readable JSON.

Required acknowledgement:

```json
{
  "accepted": true,
  "queueItemId": "same-uploaded-uuid"
}
```

`queueItemId` is used as the result primary key, making repeated uploads idempotent.

## Create a task manually

This endpoint requires the server administrator bearer token and is rate-limited per source IP. Missing and incorrect tokens both return the same `{ "error": "Unauthorized" }` response.

PowerShell:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8080/api/admin/tasks `
  -Headers @{ Authorization = "Bearer $env:ADMIN_TOKEN" } `
  -ContentType application/json `
  -Body '{"agentId":null,"collectorName":"os-info","params":{}}'
```

Response:

```json
{
  "taskId": "uuid"
}
```

## Real local end-to-end run

Use two PowerShell windows.

### Terminal 1: server

```powershell
cd "C:\Users\hasee\Desktop\ASVP Internal Network scanning Agent"
$env:ADMIN_TOKEN = "replace-with-a-long-random-secret"
npm.cmd --prefix .\central-management-server start
```

Watch for `register`, `heartbeat`, `poll`, and `result` console events.

### Terminal 2: agent

```powershell
cd "C:\Users\hasee\Desktop\ASVP Internal Network scanning Agent"
node .\bin\asvp-agent.js --config .\central-management-server\agent-local-server.json run
```

This example uses separate identity/status/queue paths under `var/central-test/`, preventing old mock credentials or queue data from contaminating the test.

### Terminal 3 or another prompt: create task

```powershell
$env:ADMIN_TOKEN = "replace-with-the-same-server-admin-token"
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8080/api/admin/tasks `
  -Headers @{ Authorization = "Bearer $env:ADMIN_TOKEN" } `
  -ContentType application/json `
  -Body '{"agentId":null,"collectorName":"os-info","params":{}}'
```

Within the configured poll/upload intervals, the server console shows:

```text
admin-task-created
poll (taskCount: 1)
result (collector: os-info, status: success)
```

Stop agent and server with `Ctrl+C` in their respective windows.

## Test

```powershell
npm.cmd --prefix .\central-management-server test
```

The integration test runs the real agent lifecycle against an ephemeral Express server and verifies registration, heartbeat, task dispatch, real `os-info` execution, encrypted upload, decryption, gunzip, and readable SQLite storage.

## Before production deployment

This localhost server is not yet safe for network exposure. Production work includes:

- TLS termination with trusted certificates
- Administrator authentication and authorization
- Proper encryption-key wrapping/secret management instead of plaintext database keys
- Rate limiting and request body quotas per endpoint
- Stronger JSON schema validation
- Audit logging and log retention
- Database backup, migration, and retention policies
- Token rotation/revocation
- Multi-agent broadcast task expansion
- Task acknowledgement/retry semantics
- Monitoring, health/readiness endpoints, and metrics
- Running under a dedicated least-privilege service account
