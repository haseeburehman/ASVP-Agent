import { spawn } from 'node:child_process';

export function runCommand(command, args = [], options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      shell: false,
      windowsHide: true,
      stdio: options.inherit ? 'inherit' : ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const timeoutMs = options.timeoutMs ?? 60000;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      callback(value);
    };
    const timeout = setTimeout(() => {
      child.kill();
      const error = new Error(`${command} ${args.join(' ')} exceeded its ${timeoutMs}ms deadline`);
      error.code = 'SERVICE_COMMAND_TIMEOUT';
      if (options.allowFailure) finish(resolve, { code: null, stdout, stderr, timedOut: true });
      else finish(reject, error);
    }, timeoutMs);
    child.stdout?.on('data', (chunk) => { stdout += chunk; });
    child.stderr?.on('data', (chunk) => { stderr += chunk; });
    child.once('error', (error) => finish(reject, error));
    child.once('close', (code) => {
      const result = { code, stdout, stderr };
      if (code === 0 || options.allowFailure) finish(resolve, result);
      else finish(reject, new Error(`${command} ${args.join(' ')} failed with exit code ${code}: ${stderr.trim() || stdout.trim()}`));
    });
  });
}
