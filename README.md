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
