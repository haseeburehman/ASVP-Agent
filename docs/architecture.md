# Architecture plan

The agent will use a single application runtime with multiple thin hosts:

1. `bin/asvp-agent.js` starts the CLI.
2. CLI commands select one-shot collection or the long-running foreground loop.
3. A system service manager invokes that same foreground loop for daemon mode.
4. The runtime composes scheduling, transport, storage, security, and collector registry components.
5. Collectors implement one stable contract and do not directly own polling, persistence, authentication, or uploads.

This design avoids maintaining separate daemon and CLI implementations. It also keeps the process observable and lets `systemd`, Windows Service Control Manager, or `launchd` own restart policy, startup ordering, and shutdown signals.

The service layer is implemented under `src/service/`. `asvp-agent service install|uninstall|status` dispatches to native adapters, but every generated definition invokes the same `node <absolute-bin>/asvp-agent.js --config <absolute-config> run` foreground entry point. No service-manager behavior exists inside `AgentRuntime`.

## Collector boundary

Each collector will publish metadata, validate collector-specific options, report platform and privilege requirements, accept a bounded task and cancellation signal, and return a normalized result envelope. The registry will load an explicit allowlist of built-in plugins; arbitrary runtime package loading should not be enabled by default.

## Security boundary

Connections remain outbound-only. HTTPS certificate verification stays enabled. Tokens and key references belong in operating-system credential stores, not JSON or environment files for production. Results are persisted atomically, encrypted before durable caching, compressed before authenticated payload encryption/upload, and removed only after server acknowledgement.
