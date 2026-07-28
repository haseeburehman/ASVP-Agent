import { open } from 'node:fs/promises';
import { createAbortError, runBoundedCommand } from '../shared/exec-utils.js';

export const MAX_SYSCTL_BYTES = 64;
export const COMMAND_TIMEOUT_MS = 8000;
export const MAX_COMMAND_OUTPUT_BYTES = 32 * 1024;

export const LINUX_SYSCTLS = Object.freeze([
  Object.freeze({ name: 'kernel.kptr_restrict', path: '/proc/sys/kernel/kptr_restrict' }),
  Object.freeze({ name: 'kernel.dmesg_restrict', path: '/proc/sys/kernel/dmesg_restrict' }),
  Object.freeze({ name: 'kernel.yama.ptrace_scope', path: '/proc/sys/kernel/yama/ptrace_scope' }),
  Object.freeze({ name: 'net.ipv4.conf.all.accept_source_route', path: '/proc/sys/net/ipv4/conf/all/accept_source_route' }),
  Object.freeze({ name: 'net.ipv4.conf.all.accept_redirects', path: '/proc/sys/net/ipv4/conf/all/accept_redirects' }),
  Object.freeze({ name: 'kernel.randomize_va_space', path: '/proc/sys/kernel/randomize_va_space' }),
]);

export const WINDOWS_PROCESS_MITIGATION_COMMAND = Object.freeze({
  executable: 'powershell.exe',
  args: Object.freeze([
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-Command',
    'Get-ProcessMitigation -System | ConvertTo-Json -Depth 4 -Compress',
  ]),
});

function abortIfNeeded(signal) {
  if (signal?.aborted) throw createAbortError('Kernel hardening collection was aborted');
}

function field(status, value, source, reason = null) {
  return {
    status,
    reasonCode: ['unavailable', 'insufficient_privilege'].includes(status) ? status : null,
    reason,
    source,
    value,
  };
}

function unavailable(source, reason) {
  return field('unavailable', null, source, reason);
}

function sourceFailure(error, source, subject) {
  const privileged = ['EACCES', 'EPERM'].includes(error?.code)
    || /access (?:is )?denied|permission denied|not permitted|requires? (?:administrator|root)|insufficient privilege/i.test(error?.message ?? '');
  const status = privileged ? 'insufficient_privilege' : 'unavailable';
  return field(status, null, source, `${subject} is ${status === 'insufficient_privilege' ? 'not accessible with current privileges' : 'unavailable'}: ${error.message}`);
}

async function readBoundedFile(path, { signal } = {}) {
  abortIfNeeded(signal);
  const handle = await open(path, 'r');
  try {
    const buffer = Buffer.alloc(MAX_SYSCTL_BYTES);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    abortIfNeeded(signal);
    return buffer.subarray(0, bytesRead).toString('utf8');
  } finally {
    await handle.close();
  }
}

function normalizeSysctlValue(output) {
  const value = String(output ?? '').trim();
  return /^-?\d+$/.test(value) ? Number(value) : value;
}

function emptySysctls(reason) {
  return Object.fromEntries(LINUX_SYSCTLS.map(({ name }) => [
    name,
    unavailable(null, reason),
  ]));
}

async function collectLinux(readSource, signal) {
  const entries = await Promise.all(LINUX_SYSCTLS.map(async ({ name, path }) => {
    try {
      const output = await readSource(path, { signal, maxBytes: MAX_SYSCTL_BYTES });
      abortIfNeeded(signal);
      const value = normalizeSysctlValue(output);
      if (value === '') return [name, unavailable(path, 'The sysctl value was empty')];
      return [name, field('available', value, path)];
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      return [name, sourceFailure(error, path, 'This sysctl')];
    }
  }));
  return Object.fromEntries(entries);
}

function normalizeMitigations(output) {
  const text = String(output ?? '').trim();
  if (!text) throw new Error('Get-ProcessMitigation returned no output');
  return JSON.parse(text);
}

export function createKernelHardeningCollector({
  platform = process.platform,
  readSource = readBoundedFile,
  runCommand = runBoundedCommand,
} = {}) {
  return {
    name: 'kernel-hardening',
    version: '1.0.0',
    async run(_params = {}, context = {}) {
      const signal = context.signal;
      abortIfNeeded(signal);

      let sysctls;
      let processMitigations;
      if (platform === 'linux') {
        sysctls = await collectLinux(readSource, signal);
        processMitigations = unavailable(null, 'Windows process mitigations are unsupported on Linux');
      } else if (platform === 'win32') {
        sysctls = emptySysctls('Linux sysctls are unsupported on Windows');
        try {
          const output = await runCommand(
            WINDOWS_PROCESS_MITIGATION_COMMAND.executable,
            [...WINDOWS_PROCESS_MITIGATION_COMMAND.args],
            { signal, timeoutMs: COMMAND_TIMEOUT_MS, maxOutputBytes: MAX_COMMAND_OUTPUT_BYTES },
          );
          abortIfNeeded(signal);
          processMitigations = field(
            'available',
            normalizeMitigations(output),
            'Get-ProcessMitigation -System',
          );
        } catch (error) {
          if (error?.name === 'AbortError') throw error;
          processMitigations = sourceFailure(error, 'Get-ProcessMitigation -System', 'Windows process mitigations');
        }
      } else {
        const reason = platform === 'darwin'
          ? 'Kernel hardening fields are unsupported on macOS'
          : `Kernel hardening fields are unsupported on platform "${platform}"`;
        sysctls = emptySysctls(reason);
        processMitigations = unavailable(null, reason);
      }

      const fields = [...Object.values(sysctls), processMitigations];
      const availableCount = fields.filter(({ status }) => status === 'available').length;
      const insufficient = fields.some(({ status }) => status === 'insufficient_privilege');
      const status = availableCount > 0 ? 'available' : insufficient ? 'insufficient_privilege' : 'unavailable';
      return {
        platform,
        status,
        reasonCode: status === 'available' ? null : status,
        reason: status === 'available' ? null : status === 'insufficient_privilege'
          ? 'Kernel hardening fields require additional privileges'
          : 'No kernel hardening fields were available',
        sysctls,
        processMitigations,
      };
    },
  };
}

export const kernelHardeningCollector = createKernelHardeningCollector();
export default kernelHardeningCollector;
