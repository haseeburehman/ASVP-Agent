# Native service installation

All platforms supervise the same foreground entry point:

```text
node <absolute-install-path>/bin/asvp-agent.js --config <absolute-config-path> run
```

The agent does not daemonize itself. `systemd`, Windows Service Control Manager through WinSW, or `launchd` owns background execution, restart behavior, startup, shutdown signals, and logs.

## Common commands

```sh
asvp-agent service install
asvp-agent service status
asvp-agent service uninstall
```

When invoking from source:

```sh
node ./bin/asvp-agent.js service install
node ./bin/asvp-agent.js service status
node ./bin/asvp-agent.js service uninstall
```

For a non-default configuration, the global option must precede `service`:

```sh
node ./bin/asvp-agent.js --config /absolute/path/config.json service install
```

The installer resolves and embeds the absolute config path. Identity, status, and queue paths must remain beneath the installation's `var/` directory so native ACL/sandbox rules cover all mutable sensitive data.

Installation and removal require root on Linux/macOS or an elevated Administrator terminal on Windows. Status does not require elevation. Uninstall always asks separately before deleting runtime data; Linux also asks before deleting the service account. In non-interactive contexts, destructive prompts default to “no.”

## Linux: systemd

Install the application under a system path such as `/opt/asvp-agent`; installation from `/home` or `/root` is refused because `ProtectHome=true` would make it inaccessible.

```sh
cd /opt/asvp-agent
sudo node ./bin/asvp-agent.js --config /etc/asvp-agent/config.json service install
sudo node ./bin/asvp-agent.js --config /etc/asvp-agent/config.json service uninstall
node ./bin/asvp-agent.js --config /etc/asvp-agent/config.json service status
```

Installed unit:

```text
/etc/systemd/system/asvp-agent.service
```

The installer creates `asvp-agent` with `useradd --system --no-create-home --shell /usr/sbin/nologin` only when absent. The unit uses `Restart=on-failure`, bounded start attempts, an empty capability set, and read-only system/home views. The agent needs no Linux capabilities: host discovery uses normal TCP `connect()`, not raw ICMP sockets, and therefore does not need `CAP_NET_RAW`.

Logs:

```sh
journalctl -u asvp-agent.service -f
journalctl -u asvp-agent.service --since today
```

Reboot verification:

```sh
sudo reboot
systemctl is-enabled asvp-agent.service
systemctl is-active asvp-agent.service
systemctl status asvp-agent.service --no-pager
```

Hardening rationale:

- `NoNewPrivileges=true`: prevents gaining privileges through exec.
- `ProtectSystem=strict`: makes the host filesystem read-only to the process.
- `ProtectHome=true`: hides user homes, reducing credential/data exposure.
- `ReadWritePaths=<install>/var`: permits writes only to agent runtime state.
- `PrivateTmp=true`: isolates temporary files.
- `PrivateDevices=true`: blocks unnecessary device access.
- Kernel/module/control-group protections: inventory collectors do not need to modify these facilities.
- Empty `CapabilityBoundingSet` and `AmbientCapabilities`: no privileged networking or system operation is required.
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`: allows local sockets and outbound IPv4/IPv6 only.

`ProtectHome=true` means SCA scan paths inside user homes are intentionally unavailable to the system service. Place service-scanned projects in an explicitly approved system-readable location or run that collector manually.

## Windows: SCM through WinSW

Supported installer architecture: Windows x64. WinSW `v2.12.0` is pinned and downloaded over HTTPS from its versioned GitHub release when the elevated installer runs. Unsupported architectures fail before download.

Open PowerShell with **Run as administrator**:

```powershell
cd "C:\Program Files\ASVP Agent"
node .\bin\asvp-agent.js --config "C:\ProgramData\ASVP\config.json" service install
node .\bin\asvp-agent.js --config "C:\ProgramData\ASVP\config.json" service status
node .\bin\asvp-agent.js --config "C:\ProgramData\ASVP\config.json" service uninstall
```

Generated assets:

```text
scripts\service\windows\asvp-agent-service.exe
scripts\service\windows\asvp-agent-service.xml
```

The interim account is built-in `NT AUTHORITY\LocalService`, not `LocalSystem`. It has substantially fewer local privileges and anonymous network credentials. Creating and lifecycle-managing a custom password-bearing Windows account safely requires installer-level password policy, LSA rights, and secret rotation, so it is deferred.

The installer grants LocalService read/execute access to the installation/config and modify access only to `var/`. WinSW registers automatic startup and three restart delays: 10, 30, and 60 seconds.

Credential Manager scope changes under a service account: LocalService cannot see credentials stored by the interactive installing user. `keytar` therefore uses the LocalService account context when available. If Credential Manager access is unavailable in that non-interactive context, the existing restricted-file fallback stores identity under `var/`, whose ACL grants LocalService access and denies ordinary users.

Logs:

```text
<install>\var\log\winsw\
```

WinSW creates rolling wrapper stdout/stderr logs there. Service state is also visible in Services (`services.msc`) and SCM tools:

```powershell
sc.exe query asvp-agent
node .\bin\asvp-agent.js service status
```

Reboot verification:

```powershell
Restart-Computer
sc.exe query asvp-agent
Get-Service asvp-agent
```

## macOS: launchd system daemon

Install under a system location such as `/Library/Application Support/ASVP Agent`; installation from `/Users` is refused because the system daemon account may not traverse user-home permissions.

```sh
cd "/Library/Application Support/ASVP Agent"
sudo node ./bin/asvp-agent.js --config "/Library/Application Support/ASVP Agent/config/default.json" service install
node ./bin/asvp-agent.js --config "/Library/Application Support/ASVP Agent/config/default.json" service status
sudo node ./bin/asvp-agent.js --config "/Library/Application Support/ASVP Agent/config/default.json" service uninstall
```

Installed plist:

```text
/Library/LaunchDaemons/com.asvp.agent.plist
```

The plist is owned by `root:wheel` with mode `0644`, uses `RunAtLoad`, and restarts only after unsuccessful exit through `KeepAlive.SuccessfulExit=false`, throttled by 10 seconds.

The interim service account is built-in `_www`. Safe creation of a dedicated hidden macOS account requires collision-free UID allocation and installer/MDM policy, which is outside this source-level installer. `_www` is low privilege but shared with the built-in web-service role; a packaged production installer should replace it with a dedicated `_asvpagent` account.

A system daemon does not use the interactive user's login Keychain. `keytar` attempts access in the daemon account context. If no usable keychain is available, the existing restricted-file fallback writes under `var/`, owned by `_www` with mode `0700` and item files `0600`.

Logs:

```text
/var/log/asvp-agent.log
/var/log/asvp-agent.error.log
```

Native state and unified-log inspection:

```sh
launchctl print system/com.asvp.agent
log show --last 1h --predicate 'process == "node"'
tail -f /var/log/asvp-agent.log /var/log/asvp-agent.error.log
```

Reboot verification:

```sh
sudo reboot
launchctl print system/com.asvp.agent
```

## Manual platform verification still required

Definition generation, platform dispatch, and elevation checks are unit tested. A real install/uninstall cycle was not run because it would create accounts, alter system ACLs, download/register WinSW, and modify machine service managers. Run the documented cycle on disposable Windows, Linux, and macOS test machines before production packaging and code signing.
