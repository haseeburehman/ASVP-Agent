export async function isElevated({ platform = process.platform, runCommand, geteuid = process.geteuid?.bind(process) } = {}) {
  if (platform === 'win32') {
    const result = await runCommand('net.exe', ['session'], { allowFailure: true });
    return result.code === 0;
  }
  if (platform === 'linux' || platform === 'darwin') return typeof geteuid === 'function' && geteuid() === 0;
  return false;
}

export async function requireElevation(options = {}) {
  if (await isElevated(options)) return;
  const platform = options.platform ?? process.platform;
  const guidance = platform === 'win32'
    ? 'Open PowerShell or Command Prompt with “Run as administrator”.'
    : 'Run the command through sudo or from a root shell.';
  throw new Error(`Service installation and removal require elevated privileges. ${guidance}`);
}
