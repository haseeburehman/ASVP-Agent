import { chmod, mkdir, rm, writeFile } from 'node:fs/promises';
import { generateLaunchdPlist } from './definitions.js';

const PLIST_PATH = '/Library/LaunchDaemons/com.asvp.agent.plist';
const LABEL = 'com.asvp.agent';
const SERVICE_USER = '_www';
const STDOUT_PATH = '/var/log/asvp-agent.log';
const STDERR_PATH = '/var/log/asvp-agent.error.log';

export function createMacosAdapter({ paths, runner, confirm, fs = { chmod, mkdir, rm, writeFile } }) {
  const definition = generateLaunchdPlist({
    executablePath: paths.executablePath,
    entryArguments: paths.entryArguments,
    configPath: paths.configPath,
    workingDirectory: paths.projectRoot,
    stdoutPath: STDOUT_PATH,
    stderrPath: STDERR_PATH,
    serviceUser: SERVICE_USER,
  });
  return {
    definition,
    definitionPath: PLIST_PATH,
    async install() {
      if (paths.projectRoot.startsWith('/Users/')) {
        throw new Error('Install the agent under a system location such as /Library/Application Support/ASVP Agent before launchd installation');
      }
      await fs.mkdir(paths.varDirectory, { recursive: true, mode: 0o700 });
      await runner('chown', ['root:' + SERVICE_USER, paths.projectRoot]);
      await runner('chmod', ['0750', paths.projectRoot]);
      await runner('chown', ['root:' + SERVICE_USER, paths.configPath]);
      await runner('chmod', ['0640', paths.configPath]);
      await runner('chown', ['-R', SERVICE_USER + ':wheel', paths.varDirectory]);
      await runner('chmod', ['0700', paths.varDirectory]);
      await runner('touch', [STDOUT_PATH, STDERR_PATH]);
      await runner('chown', [SERVICE_USER + ':wheel', STDOUT_PATH, STDERR_PATH]);
      await runner('chmod', ['0600', STDOUT_PATH, STDERR_PATH]);
      await fs.writeFile(PLIST_PATH, definition, { mode: 0o644 });
      await runner('chown', ['root:wheel', PLIST_PATH]);
      await fs.chmod(PLIST_PATH, 0o644);
      await runner('launchctl', ['bootout', `system/${LABEL}`], { allowFailure: true });
      await runner('launchctl', ['bootstrap', 'system', PLIST_PATH]);
      await runner('launchctl', ['enable', `system/${LABEL}`]);
      await runner('launchctl', ['kickstart', '-k', `system/${LABEL}`]);
      return { installed: true, started: true, definitionPath: PLIST_PATH };
    },
    async uninstall() {
      await runner('launchctl', ['bootout', `system/${LABEL}`], { allowFailure: true });
      await fs.rm(PLIST_PATH, { force: true });
      const removeData = await confirm(`Remove agent runtime data at ${paths.varDirectory}? This deletes identity and queued results.`);
      if (removeData) await fs.rm(paths.varDirectory, { recursive: true, force: true });
      return { installed: false, dataRemoved: removeData, accountRemoved: false };
    },
    async status() {
      const result = await runner('launchctl', ['print', `system/${LABEL}`], { allowFailure: true });
      const output = `${result.stdout}\n${result.stderr}`.trim();
      return { installed: result.code === 0, running: result.code === 0 && /state\s*=\s*running/i.test(output), nativeStatus: output };
    },
  };
}

export { PLIST_PATH as MACOS_PLIST_PATH, SERVICE_USER as MACOS_SERVICE_USER };
