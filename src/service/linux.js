import { access, chmod, chown, copyFile, mkdir, rm, writeFile } from 'node:fs/promises';
import { generateSystemdUnit } from './definitions.js';

const UNIT_PATH = '/etc/systemd/system/asvp-agent.service';
const SERVICE_USER = 'asvp-agent';

export function createLinuxAdapter({ paths, runner, confirm, fs = { access, chmod, chown, copyFile, mkdir, rm, writeFile } }) {
  const unit = generateSystemdUnit({
    executablePath: paths.executablePath,
    entryArguments: paths.entryArguments,
    configPath: paths.configPath,
    workingDirectory: paths.projectRoot,
    varDirectory: paths.varDirectory,
    serviceUser: SERVICE_USER,
  });
  return {
    definition: unit,
    definitionPath: UNIT_PATH,
    async install() {
      if (paths.projectRoot === '/root' || paths.projectRoot.startsWith('/root/') || paths.projectRoot.startsWith('/home/')) {
        throw new Error('Install the agent under a system location such as /opt/asvp-agent before service installation; ProtectHome=true blocks service access to home directories');
      }
      const userExists = (await runner('id', ['-u', SERVICE_USER], { allowFailure: true })).code === 0;
      if (!userExists) await runner('useradd', ['--system', '--no-create-home', '--shell', '/usr/sbin/nologin', SERVICE_USER]);
      await fs.mkdir(paths.varDirectory, { recursive: true, mode: 0o700 });
      await runner('chown', ['root:' + SERVICE_USER, paths.projectRoot]);
      await runner('chmod', ['0750', paths.projectRoot]);
      await runner('chown', ['root:' + SERVICE_USER, paths.configPath]);
      await runner('chmod', ['0640', paths.configPath]);
      await runner('chown', ['-R', SERVICE_USER + ':' + SERVICE_USER, paths.varDirectory]);
      await runner('chmod', ['0700', paths.varDirectory]);
      await fs.writeFile(UNIT_PATH, unit, { mode: 0o644 });
      await fs.chmod(UNIT_PATH, 0o644);
      await runner('systemctl', ['daemon-reload']);
      await runner('systemctl', ['enable', '--now', 'asvp-agent.service']);
      return { installed: true, started: true, definitionPath: UNIT_PATH };
    },
    async uninstall() {
      await runner('systemctl', ['disable', '--now', 'asvp-agent.service'], { allowFailure: true });
      await fs.rm(UNIT_PATH, { force: true });
      await runner('systemctl', ['daemon-reload']);
      const removeData = await confirm(`Remove agent runtime data at ${paths.varDirectory}? This deletes identity and queued results.`);
      if (removeData) await fs.rm(paths.varDirectory, { recursive: true, force: true });
      const removeAccount = await confirm(`Remove the ${SERVICE_USER} system account?`);
      if (removeAccount) await runner('userdel', [SERVICE_USER], { allowFailure: true });
      return { installed: false, dataRemoved: removeData, accountRemoved: removeAccount };
    },
    async status() {
      const installed = (await runner('test', ['-f', UNIT_PATH], { allowFailure: true })).code === 0;
      const active = await runner('systemctl', ['is-active', 'asvp-agent.service'], { allowFailure: true });
      const native = await runner('systemctl', ['status', 'asvp-agent.service', '--no-pager'], { allowFailure: true });
      return { installed, running: active.stdout.trim() === 'active', nativeStatus: native.stdout || native.stderr };
    },
  };
}

export { UNIT_PATH as LINUX_UNIT_PATH, SERVICE_USER as LINUX_SERVICE_USER };
