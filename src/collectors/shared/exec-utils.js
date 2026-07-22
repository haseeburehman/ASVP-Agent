import { spawn } from 'node:child_process';

export function createAbortError(message = 'Collector command was aborted') {
  const error = new Error(message);
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

export function runBoundedCommand(executable, args, options = {}) {
  const {
    signal,
    timeoutMs = 8000,
    maxOutputBytes = 2 * 1024 * 1024,
    spawnProcess = spawn,
  } = options;
  if (signal?.aborted) return Promise.reject(createAbortError());

  return new Promise((resolve, reject) => {
    const child = spawnProcess(executable, args, {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let settled = false;

    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      signal?.removeEventListener('abort', abortHandler);
      callback(value);
    };
    const stopWith = (error) => {
      child.kill();
      finish(reject, error);
    };
    const abortHandler = () => stopWith(createAbortError());
    const timeout = setTimeout(() => {
      const error = new Error(`${executable} exceeded its ${timeoutMs}ms deadline`);
      error.code = 'COMMAND_TIMEOUT';
      stopWith(error);
    }, timeoutMs);
    const append = (current, chunk) => {
      const next = current + chunk.toString('utf8');
      if (Buffer.byteLength(next) > maxOutputBytes) {
        const error = new Error(`${executable} output exceeded the ${maxOutputBytes}-byte safety limit`);
        error.code = 'COMMAND_OUTPUT_LIMIT';
        stopWith(error);
      }
      return next;
    };

    signal?.addEventListener('abort', abortHandler, { once: true });
    child.stdout?.on('data', (chunk) => { stdout = append(stdout, chunk); });
    child.stderr?.on('data', (chunk) => { stderr = append(stderr, chunk); });
    child.once('error', (error) => finish(reject, error));
    child.once('close', (code) => {
      if (code === 0) finish(resolve, stdout.trim());
      else finish(reject, new Error(`${executable} exited with code ${code}: ${stderr.trim() || 'no error output'}`));
    });
  });
}
