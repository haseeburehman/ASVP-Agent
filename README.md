# ASVP Internal Network Agent

Phase 1 scaffold for a lightweight, cross-platform Node.js agent. This phase intentionally contains no collection or runtime implementation logic.

## Folder tree

```text
.
├── .env.example
├── .gitignore
├── README.md
├── package.json
├── bin/
│   └── asvp-agent.js
├── config/
│   └── default.json
├── docs/
│   └── architecture.md
├── scripts/
│   └── service/
│       └── README.md
├── src/
│   ├── index.js
│   ├── agent/
│   │   ├── lifecycle.js
│   │   └── runtime.js
│   ├── cli/
│   │   └── commands.js
│   ├── collectors/
│   │   ├── index.js
│   │   ├── apps/index.js
│   │   ├── compliance-checks/index.js
│   │   ├── containers/index.js
│   │   ├── network-scan/index.js
│   │   ├── os-info/index.js
│   │   ├── sca-deps/index.js
│   │   └── tls-checks/index.js
│   ├── config/
│   │   ├── loader.js
│   │   └── schema.js
│   ├── core/
│   │   ├── collector.js
│   │   ├── collector-registry.js
│   │   ├── scheduler.js
│   │   └── task-runner.js
│   ├── security/
│   │   ├── credentials.js
│   │   └── crypto.js
│   ├── storage/
│   │   └── result-store.js
│   ├── transport/
│   │   ├── api-client.js
│   │   └── result-uploader.js
│   └── utils/
│       └── logger.js
├── test/
│   ├── collectors/README.md
│   ├── integration/README.md
│   └── unit/README.md
└── var/
    ├── cache/.gitkeep
    └── log/.gitkeep
```

## Directory responsibilities

- `bin/`: executable shell only; delegates to the shared runtime.
- `config/`: non-secret configuration shape. Deployment overrides remain untracked.
- `docs/`: architecture and security decisions.
- `scripts/service/`: future `systemd`, Windows service-wrapper, and `launchd` assets.
- `src/agent/`: composition root and process lifecycle.
- `src/cli/`: interactive and administrative command definitions.
- `src/collectors/`: independently configurable built-in collector plugins.
- `src/config/`: loading and validation boundaries.
- `src/core/`: collector contract, registry, task execution, and scheduling.
- `src/security/`: credential access and payload cryptography boundaries.
- `src/storage/`: offline queue and local result lifecycle.
- `src/transport/`: management-server HTTPS API and uploads.
- `src/utils/`: narrowly shared infrastructure such as redacted logging.
- `test/`: unit, collector-contract, and integration test suites.
- `var/`: ignored local runtime state for development only.

## Recommended Phase 2 packages

`package.json` intentionally keeps `dependencies` and `devDependencies` empty. Standard JSON does not permit comments, so adding commented dependency entries would make the manifest invalid. Review these candidates before pinning compatible versions:

| Concern | Recommendation | Reasoning |
|---|---|---|
| CLI | `commander` | Mature command/subcommand parsing with a small API surface. |
| HTTP | Node.js built-in `fetch`/`undici` | Reuse Node 20's maintained HTTP stack; configure strict TLS and bounded timeouts. |
| Scheduling | `cron-parser` only if cron expressions are required | Polling and heartbeat loops can use built-in timers plus jitter; avoid a scheduler dependency initially. |
| Retry | `p-retry` | Bounded exponential backoff with explicit retry policy. |
| Validation | `ajv` | Fast JSON Schema validation for configuration, tasks, and collector output. |
| Logging | `pino` | Fast structured logging with configurable redaction. |
| Storage | `better-sqlite3` or filesystem records | SQLite provides durable queue transactions; assess native-addon packaging before choosing it over atomic files. |
| Encryption | Node.js built-in `node:crypto` | Use standard authenticated encryption such as AES-256-GCM; do not add custom crypto packages. |
| Compression | Built-in `node:zlib` | Supports gzip/Brotli without an external dependency. |
| Credential storage | `keytar` or platform adapters | Keychain/Credential Manager/libsecret support, but native packaging and Linux availability must be evaluated. |
| Service hosting | WinSW on Windows; native unit/plist files elsewhere | Prefer OS supervisors over an in-process daemon library. `node-windows` may be evaluated, but a separately maintained wrapper is easier to audit. |
| System inventory | `systeminformation` | Broad cross-platform read-only OS and hardware inventory; validate each API and command it invokes. |
| IP/CIDR handling | `ipaddr.js` | Reliable address parsing and allowlist/scope checks. |
| Port limiting | `p-limit` | Explicit concurrency bounds for network checks. |
| TLS inspection | Built-in `node:tls` and `node:crypto` | Direct certificate and protocol inspection without shelling out. |
| SBOM | CycloneDX npm tooling and/or `@cyclonedx/cyclonedx-library` | Standards-based CycloneDX output; exact package depends on whether manifests or installed environments are analyzed. |
| Tests | Node.js built-in test runner | Avoid adding a framework unless mocking/reporting needs justify one. |
| Lint/format | `eslint` and `prettier` | Consistent static analysis and formatting once source code is introduced. |
| Packaging | `@yao-pkg/pkg` or signed platform bundles | Evaluate native-module support, Node updates, code signing, and security patch workflow before selection. |

TLS itself requires no npm package: use Node's HTTPS/TLS implementation, certificate verification, optional private CA configuration, and optionally mutual TLS. Never disable verification as a fallback.

## Daemon and CLI approach

Build one runtime API with explicit `start`, `stop`, and one-shot task boundaries. The CLI remains a thin adapter: `run` starts the long-running foreground loop, while commands such as `collect` invoke bounded operations. Production service definitions execute `asvp-agent run`; the operating system owns daemonization, restart policy, logs, and signals. This keeps behavior identical across service and terminal execution and makes the runtime easy to test.

## Cross-platform service plan

- **Linux:** install a hardened `systemd` unit with a dedicated user, restricted writable paths, restart limits, and narrowly granted capabilities only if approved scanning modes need them.
- **Windows:** package a signed WinSW wrapper and XML definition that runs `asvp-agent run`; use Service Control Manager recovery policy and Windows-native credential protection.
- **macOS:** install a signed `launchd` system daemon plist that runs the same command and stores tokens in Keychain.
- **Common installer:** expose future `service install`, `service uninstall`, and `service status` commands backed by small platform adapters. Generate no init scripts dynamically at runtime, require elevation only for installation, and run the agent itself with least privilege.

See `docs/architecture.md` and `scripts/service/README.md` for the planned boundaries.

## Manual collector testing

The `scan` command creates a synthetic task and executes it through the same collector registry, timeout handling, authorization checks, and task runner used by polled tasks:

```sh
node ./bin/asvp-agent.js scan --collector os-info
node ./bin/asvp-agent.js scan --collector apps --json
node ./bin/asvp-agent.js scan --collector network-scan --target 10.0.0.10 --ports 22,80,443
```

On PowerShell systems that block `npm.ps1`, use `npm.cmd` for npm commands; direct `node` commands are unaffected.

Remote collectors require explicit targets and those targets must be contained by the corresponding local `allowedCidrs`. There is no authorization override. Results are durably queued by default; use `--no-queue` only for deliberate developer checks where persistence is not wanted. Press `Ctrl+C` to abort an in-progress manual scan.

## Result delivery

The default configuration uses real HTTPS transport (`server.mode: "http"`). Enroll before running the service instead of hand-editing JSON:

```sh
asvp-agent --config /path/to/config.json enroll
```

The command prompts for a required management URL and optional short-lived enrollment token. It accepts HTTPS, plus `http://127.0.0.1` or `http://localhost` for local testing, and explicitly rejects the `https://management.example.invalid` placeholder. Local development and CI can still explicitly select `server.mode: "mock"`. Enrollment changes only the server address/token; remote collectors retain their existing explicit target and `allowedCidrs` authorization checks.

Pending queue results are serialized, gzip-compressed, and encrypted with AES-256-GCM immediately before upload. The encryption key is provisioned during registration and stored with the auth token through the OS keychain or restricted-file fallback. The server must explicitly acknowledge an upload with `{ "accepted": true, "queueItemId": "..." }` before the local item is marked delivered. Transient failures return items to pending; permanent payload-rejection HTTP responses mark them failed-permanent.

## Local operator dashboard

The dashboard is disabled by default and normal `asvp-agent run` therefore opens no dashboard port. Set `dashboard.enabled` to `true` to start it with `run`, or use the dedicated command as an explicit one-run opt-in:

```sh
node ./bin/asvp-agent.js dashboard
```

It prints a one-time URL containing a freshly generated access token. The page and WebSocket both reject requests without that token. The dashboard uses plain HTTP because it binds to the same machine and the token protects against casual access by other local processes; it is not designed or supported as a remote management interface.

> **Security warning:** keep `dashboard.bindAddress` set to `127.0.0.1`. Setting it to `0.0.0.0` or another non-loopback address exposes lifecycle controls, registration, configuration, logs, and collector execution to the network. The agent emits a high-visibility warning whenever a non-loopback bind is configured.

Dashboard defaults:

```json
{
  "dashboard": {
    "enabled": false,
    "port": 4180,
    "bindAddress": "127.0.0.1"
  }
}
```

The **Apply & Restart Agent** action writes the complete validated merged configuration to `var/dashboard-config.json` with restrictive permissions. This dashboard-owned override avoids editing a deployment-managed source config. The running lifecycle is not hot-reloaded; the UI explicitly restarts it only after the write and validation succeed. Remote scan commands still pass through the same local CIDR authorization gate as CLI and server-polled tasks.

When connected to the real central server, the dashboard also provides:

- A clear connected/connecting/unreachable server indicator and configured URL
- Last heartbeat and poll success/failure indicators
- A one-shot **Test Connection** button using the normal authenticated heartbeat path
- A collector dropdown populated from `CollectorRegistry`
- Central task creation through the server's `/api/admin/tasks` endpoint
- Target/port inputs for `network-scan` and `tls-checks`
- Warnings and refusal when no remote targets are locally authorized

The task form is disabled in mock mode. In real mode, clicking **Create Task** assigns the task to this agent; its normal poll scheduler receives it, the normal task runner executes it, and the normal encrypted upload pipeline returns the result. No curl command is required.

Central-server admin routes require `ADMIN_TOKEN`. Start the central server and dashboard processes with the same persistent token. The dashboard config loader reads it from the process environment, keeps it server-side, redacts it from logs, and never sends it to browser JavaScript:

```powershell
$env:ADMIN_TOKEN = "replace-with-a-long-random-secret"
npm.cmd --prefix .\central-management-server start
```

In the dashboard process terminal:

```powershell
$env:ADMIN_TOKEN = "replace-with-the-same-long-random-secret"
node .\bin\asvp-agent.js --config .\config\local-dashboard.json dashboard
```

## Preconfigured zero-touch builds

Release packaging accepts `ASVP_DEFAULT_SERVER_URL`. When set, the build validates it with the same enrollment URL policy (HTTPS except loopback HTTP, no placeholder, credentials, fragments, or malformed URL) and writes it only into the target-specific `dist/<platform>-<arch>/config/default.json`; the source default remains generic. Invalid values fail packaging before an executable or installer is published.

```sh
ASVP_DEFAULT_SERVER_URL=https://asvp.company.com npm run package:binary
```

Windows installers compiled with that target config hide the enrollment page and install/start the service directly, including silent installs. Generic builds retain the enrollment wizard and do not start a service during a silent install without enrollment. Linux/macOS postinstall scripts likewise install the service immediately for a preconfigured config and print the enroll-then-install instructions for a generic placeholder build. `asvp-agent enroll` remains available to override a baked-in URL later.

GitHub release jobs read `ASVP_DEFAULT_SERVER_URL` from the repository variable or secret of that name. Configure one of those values before publishing a production tag.

## Download & Install

Versioned standalone binaries and native installers are published on the repository's **GitHub Releases** page. Standalone binary names follow `asvp-agent-<version>-<platform>-<arch>` and do not require Node.js or this source tree.

### Windows

Download the installer matching the machine architecture:

- `asvp-agent-<version>-windows-x64-setup.exe`
- `asvp-agent-<version>-windows-arm64-setup.exe`

Run the installer as Administrator. After choosing the install directory, the enrollment page requires the real management server URL and accepts an optional enrollment token. **Next** remains blocked for malformed/insecure URLs and the placeholder. Once files are installed, setup passes the values through a temporary input file to the packaged `enroll` command; that command validates and atomically updates the installed config, deletes the temporary input, and only then does setup install/start the service. Thus the first service launch already has the selected server. It installs under `C:\Program Files\ASVP Agent`. The x64 and ARM64 packages are separate because Windows PE executables are architecture-specific.

> **Windows ARM64 is experimental/best-effort.** GitHub's `windows-latest` runner is x64, and `@yao-pkg/pkg` can fail with `spawn UNKNOWN` while fetching or preparing its Windows ARM64 base binary. Upstream's open Node 22 tooling tracker documents unresolved cross-architecture packaging limitations. The ARM64 matrix entry is allowed to fail without blocking Windows x64, Linux x64, or either native macOS build. When an ARM64 artifact is produced, the agent executable is native ARM64; its pinned WinSW 2.12.0 service wrapper is x64 because WinSW does not publish an ARM64 asset, and therefore uses Windows-on-ARM x64 emulation. Do not treat ARM64 as production-qualified until its packaged keychain and service cycle pass on real Windows ARM64 hardware.

**Unsigned-build warning:** these installers and executables are not Authenticode-signed because no purchased code-signing certificate is configured. Microsoft Defender SmartScreen may show **Windows protected your PC**. Verify the artifact came from the expected GitHub Release, select **More info**, confirm the displayed filename, then choose **Run anyway** only if you trust it. Do not disable SmartScreen.

Credential storage remains Windows Credential Manager. A service runs as `Local Service`, so its Credential Manager scope is that service identity rather than the installing interactive user. If Credential Manager cannot be opened in that account, the existing restricted-file fallback writes beneath the service-protected `var` directory. Release CI runs `diagnostics credentials --require-keychain` from the packaged x64 executable; service-account scope must additionally be checked during the real service-install acceptance test.

### Linux x64

Download either package for the target package manager:

```sh
sudo apt install ./asvp-agent-<version>-linux-x64.deb
# or
sudo rpm -U ./asvp-agent-<version>-linux-x64.rpm
```

Package-manager scripts must not block unattended installs with prompts. Installation therefore prints the two explicit post-install commands; enroll first, then install the service:

```sh
sudo /opt/asvp-agent/asvp-agent --config /etc/asvp-agent/config.json enroll
sudo /opt/asvp-agent/asvp-agent --config /etc/asvp-agent/config.json service install
```

The `.deb` and `.rpm` are generic x64 packages rather than per-distribution builds. Test them against the exact supported distribution before production rollout.

### macOS

Download `asvp-agent-<version>-macos-x64.pkg` for Intel Macs or `asvp-agent-<version>-macos-arm64.pkg` for Apple silicon, then open it in Finder. The package installs under `/Library/Application Support/ASVP Agent` and prints the opt-in service command when installation completes.

**Unsigned/unnotarized warning:** the package is not signed with an Apple Developer certificate and is not notarized. Gatekeeper may refuse the first launch. Do not disable Gatekeeper globally. After verifying the package came from the expected GitHub Release:

1. Attempt to open the `.pkg` once.
2. Open **System Settings → Privacy & Security**.
3. Find the message that the ASVP package was blocked and select **Open Anyway**.
4. Authenticate as an administrator and confirm **Open**.

After installation, enroll first and then install the service:

```sh
sudo '/Library/Application Support/ASVP Agent/asvp-agent' --config '/Library/Application Support/ASVP Agent/config/default.json' enroll
sudo '/Library/Application Support/ASVP Agent/asvp-agent' --config '/Library/Application Support/ASVP Agent/config/default.json' service install
```

### Packaged credential verification

Every executable exposes an explicit deployment diagnostic:

```sh
asvp-agent diagnostics credentials --require-keychain
```

On Windows x64 and macOS, release CI loads the native `keytar` binding and performs a temporary OS-keychain write/read/delete round trip; `--require-keychain` exits nonzero if the process falls back or the keychain is not operational.

Linux GitHub runners are headless and have no PAM/desktop login session to create and unlock the Secret Service `login` collection or its default alias. Starting only a synthetic D-Bus session and `gnome-keyring-daemon` loads libsecret but does not reproduce a real user's keyring, causing `Object does not exist at path /org/freedesktop/secrets/collection/login`. Linux CI therefore does not claim OS-keychain verification. Instead it verifies the packaged restricted-file path end to end: mock registration persists an identity, `status` reloads it in a separate process, and the verifier requires mode `0600`. Linux Secret Service behavior remains a manual acceptance check on a real installation with a genuine logged-in user/keyring session.

## Central fleet dashboard

The central management server serves its fleet UI at `/fleet` (and `/`). Sign in with the same `ADMIN_TOKEN` used by admin API routes. Successful login exchanges that token for an opaque, eight-hour, `HttpOnly`, `SameSite=Strict` session cookie; browser JavaScript does not retain the admin token. Set `DASHBOARD_SECURE_COOKIE=true` behind production HTTPS so the cookie also has `Secure`.

The page has summary cards and a color-coded agent table: green **online**, yellow **never connected**, and red **stale**. It shows hostname, platform/architecture, agent ID, registration time, last heartbeat, and last poll. Selecting an agent opens registration data, its own complete task/result history, readable decrypted collector JSON, and the latest 200 register/heartbeat/poll/task/result events. The UI polls every five seconds, which keeps this initial single-process dashboard simple and reliable without adding WebSocket state.

Status is computed at read time. With the default expected heartbeat interval of 30 seconds, an agent is online when its last heartbeat is at most 60 seconds old (2× expected interval), stale after 60 seconds, and never connected when no heartbeat has ever arrived. Configure the expectation with `EXPECTED_HEARTBEAT_INTERVAL_MS`; the API returns both thresholds so the UI always explains the active values.

To require enrollment tokens for new registrations, set `REQUIRE_ENROLLMENT_TOKEN=true` (default is `false`). Create a token with the admin bearer credential:

```sh
curl -X POST http://127.0.0.1:8080/api/admin/enrollment-tokens \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"expiresInHours":24,"maxUses":1}'
```

Only a SHA-256 token hash is stored. Valid continuity re-registration using the existing agent credential does not consume a new enrollment token. Tokens reduce unauthorized registrations by someone who merely knows the server URL and bound the exposure by time/use count. They do **not** prove hardware/device identity, replace TLS or mTLS, resist endpoint compromise, or protect a token after it is stolen.

## Native service installation

The same foreground runtime can be installed under the current OS service manager:

```sh
asvp-agent service install
asvp-agent service status
asvp-agent service uninstall
```

From source:

```sh
node ./bin/asvp-agent.js service install
node ./bin/asvp-agent.js service status
node ./bin/asvp-agent.js service uninstall
```

Installation/removal requires root or Administrator. Source installations execute `node <absolute>/bin/asvp-agent.js --config <absolute-config> run`; packaged installations execute `<absolute>/asvp-agent --config <absolute-config> run` directly. Both reach the same `run` command and foreground lifecycle—the Node runtime embedded by `@yao-pkg/pkg` does not daemonize itself. Uninstall asks before deleting `var/` data or a created Linux account. See `scripts/service/README.md` for platform paths, accounts, logs, hardening, reboot verification, and required manual install testing.

## Release-build verification boundaries

GitHub Actions performs release-qualified builds on native Windows x64, Linux x64, macOS x64, and macOS ARM64 runners. All four execute the packaged binary and an `os-info` collector smoke test. Windows and macOS additionally require an OS-keychain round trip; Linux requires the packaged restricted-file identity round trip because its headless runner has no genuine login keyring. Windows ARM64 remains a non-blocking experimental cross-architecture build on the x64 `windows-latest` runner; a real Windows ARM64 machine must verify the executable, native `keytar` binding, WinSW-under-emulation service cycle, reboot persistence, and uninstall before that target is considered production-qualified.

## Open manual verification item

The development machine does not have `nmap` installed, so the `ssl-heartbleed` parser could not be compared with XML from a real local `nmap --script ssl-heartbleed` run. Existing fixture/parser tests pass, and the collector correctly reports `not-assessed` when nmap is absent. Before claiming production verification of that check, install a current nmap release in a controlled test environment, run it against the repository's local TLS test server, and compare the emitted `-oX -` XML with `parseHeartbleedXml()`.
