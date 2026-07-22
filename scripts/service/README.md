# Service installation assets

This directory is reserved for Phase 2 service definitions and installation helpers.

- **Linux:** ship a hardened `systemd` unit that runs the same CLI entry point in foreground mode under a dedicated, unprivileged account. Add narrowly scoped capabilities only when a collector genuinely requires them.
- **Windows:** use a service wrapper such as WinSW to host the same foreground process. Keep the wrapper configuration versioned and store credentials with Windows Credential Manager or DPAPI-backed storage.
- **macOS:** ship a signed `launchd` daemon property list that invokes the same foreground entry point under a dedicated account where practical. Store secrets in Keychain.

Installation and removal should be explicit CLI commands backed by platform adapters. The long-running Node.js application must not contain platform service-manager behavior; service managers should only supervise it.
