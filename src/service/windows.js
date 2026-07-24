import { access, mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { generateWinSwXml, windowsWinSwAsset } from './definitions.js';

const LOCAL_SERVICE_SID = '*S-1-5-19';

export function createWindowsAdapter({ paths, runner, confirm, fetchImpl = fetch, architecture = process.arch, removeData = false, fs = { access, mkdir, rm, writeFile } }) {
  const serviceDirectory = path.join(paths.projectRoot, 'scripts', 'service', 'windows');
  const wrapperPath = path.join(serviceDirectory, 'asvp-agent-service.exe');
  const xmlPath = path.join(serviceDirectory, 'asvp-agent-service.xml');
  const logDirectory = path.join(paths.varDirectory, 'log', 'winsw');
  const asset = windowsWinSwAsset(architecture);
  const definition = generateWinSwXml({
    executablePath: paths.executablePath,
    entryArguments: paths.entryArguments,
    configPath: paths.configPath,
    workingDirectory: paths.projectRoot,
    logDirectory,
  });

  async function ensureWrapper() {
    try {
      await fs.access(wrapperPath);
      return;
    } catch {
      const response = await fetchImpl(asset.url, { headers: { 'user-agent': 'asvp-agent-service-installer' } });
      if (!response.ok) throw new Error(`Unable to download pinned WinSW ${asset.version} asset ${asset.asset}: HTTP ${response.status}`);
      await fs.writeFile(wrapperPath, Buffer.from(await response.arrayBuffer()), { mode: 0o755 });
    }
  }

  return {
    definition,
    definitionPath: xmlPath,
    wrapperPath,
    winSw: asset,
    async install() {
      await fs.mkdir(serviceDirectory, { recursive: true });
      await fs.mkdir(logDirectory, { recursive: true, mode: 0o700 });
      await ensureWrapper();
      await fs.writeFile(xmlPath, definition, 'utf8');
      await runner('icacls.exe', [paths.projectRoot, '/grant', `${LOCAL_SERVICE_SID}:(OI)(CI)RX`]);
      await runner('icacls.exe', [paths.configPath, '/grant', `${LOCAL_SERVICE_SID}:R`]);
      await runner('icacls.exe', [paths.varDirectory, '/inheritance:r', '/grant:r', `${LOCAL_SERVICE_SID}:(OI)(CI)M`, '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F']);
      await runner(wrapperPath, ['install']);
      await runner(wrapperPath, ['start']);
      return { installed: true, started: true, definitionPath: xmlPath, wrapperPath };
    },
    async uninstall() {
      try {
        await fs.access(wrapperPath);
        await runner(wrapperPath, ['stop'], { allowFailure: true, timeoutMs: 35000 });
        await runner(wrapperPath, ['uninstall'], { allowFailure: true, timeoutMs: 20000 });
      } catch {
        await runner('sc.exe', ['stop', 'asvp-agent'], { allowFailure: true, timeoutMs: 35000 });
        await runner('sc.exe', ['delete', 'asvp-agent'], { allowFailure: true, timeoutMs: 20000 });
      }
      const shouldRemoveData = removeData || await confirm(`Remove agent runtime data at ${paths.varDirectory}? This deletes identity and queued results.`);
      if (shouldRemoveData) await fs.rm(paths.varDirectory, { recursive: true, force: true });
      return { installed: false, dataRemoved: shouldRemoveData, accountRemoved: false };
    },
    async status() {
      try {
        await fs.access(wrapperPath);
        const result = await runner(wrapperPath, ['status'], { allowFailure: true });
        const output = `${result.stdout}\n${result.stderr}`.trim();
        return { installed: !/non[- ]existent|not installed/i.test(output), running: /started|running/i.test(output), nativeStatus: output };
      } catch {
        const result = await runner('sc.exe', ['query', 'asvp-agent'], { allowFailure: true });
        const output = `${result.stdout}\n${result.stderr}`.trim();
        return { installed: result.code === 0, running: /STATE\s*:\s*4\s+RUNNING/i.test(output), nativeStatus: output };
      }
    },
  };
}
