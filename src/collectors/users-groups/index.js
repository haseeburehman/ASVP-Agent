import { readFile } from 'node:fs/promises';
import { createAbortError, runBoundedCommand } from '../shared/exec-utils.js';

const COMMAND_TIMEOUT_MS = 8000;

function sourceResult(items, source, reason = null) {
  return { items, source, reason };
}

function unavailableSource(source, error) {
  return sourceResult(null, source, `${source} enumeration failed: ${error.message}`);
}

function checkAborted(signal) {
  if (signal?.aborted) throw createAbortError('Users and groups collection was aborted');
}

function parseJsonRecords(output) {
  if (!output) return [];
  const parsed = JSON.parse(output);
  return Array.isArray(parsed) ? parsed : [parsed];
}

function parsePasswd(contents, passwordStatusByName) {
  return contents.split(/\r?\n/).filter(Boolean).map((line) => {
    const [name, , uid, gid, description, homeDirectory, shell] = line.split(':');
    const passwordStatus = passwordStatusByName?.get(name);
    return {
      name,
      uid: Number(uid),
      primaryGroupId: Number(gid),
      description: description || null,
      homeDirectory: homeDirectory || null,
      shell: shell || null,
      passwordLocked: passwordStatus?.locked ?? null,
      enabled: passwordStatus?.enabled ?? null,
      isAdministrator: false,
      lastLogin: null,
      passwordNeverExpires: passwordStatus?.neverExpires ?? null,
    };
  });
}

export function parsePasswdStatus(output) {
  const [name, status, , , maximumDays] = output.trim().split(/\s+/);
  if (!name || !status) throw new Error('passwd -S returned an incomplete status record');
  const normalizedStatus = status.toUpperCase();
  const locked = ['L', 'LK'].includes(normalizedStatus);
  const enabled = locked ? false : ['P', 'PS', 'NP'].includes(normalizedStatus) ? true : null;
  const maximum = Number(maximumDays);
  return {
    name,
    locked,
    enabled,
    neverExpires: maximumDays === '' || Number.isFinite(maximum) && (maximum < 0 || maximum >= 99999),
  };
}

async function collectPasswdStatuses(userNames, run, signal) {
  const records = await Promise.allSettled(userNames.map(async (name) => {
    const output = await run('passwd', ['-S', name], { signal, timeoutMs: COMMAND_TIMEOUT_MS });
    return parsePasswdStatus(output);
  }));
  const statuses = new Map();
  const failures = [];
  let privilegeFailures = 0;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (record.status === 'fulfilled') statuses.set(record.value.name, record.value);
    else {
      const message = record.reason.message;
      failures.push(`${userNames[index]}: ${message}`);
      if (/permission denied|may not view or modify password information|exited with code 1/i.test(message)) privilegeFailures += 1;
    }
  }
  const insufficientPrivilege = privilegeFailures > 0;
  return {
    statuses,
    status: failures.length === 0 ? 'available' : insufficientPrivilege ? 'insufficient_privilege' : 'unavailable',
    reasonCode: insufficientPrivilege ? 'insufficient_privilege' : failures.length > 0 ? 'command_unavailable' : null,
    reason: failures.length > 0 ? `Password status unavailable for ${failures.length} account(s): ${failures.join('; ')}` : null,
  };
}

function parseGroup(contents) {
  return contents.split(/\r?\n/).filter(Boolean).map((line) => {
    const [name, , gid, members = ''] = line.split(':');
    return {
      name,
      gid: Number(gid),
      members: members.split(',').filter(Boolean),
    };
  });
}

async function collectLinux({ readTextFile, run, signal }) {
  checkAborted(signal);
  const [passwdResult, groupResult] = await Promise.allSettled([
    readTextFile('/etc/passwd', 'utf8'),
    readTextFile('/etc/group', 'utf8'),
  ]);
  checkAborted(signal);

  const passwordState = passwdResult.status === 'fulfilled'
    ? await collectPasswdStatuses(
      passwdResult.value.split(/\r?\n/).filter(Boolean).map((line) => line.split(':', 1)[0]),
      run,
      signal,
    )
    : { statuses: null, status: 'unavailable', reasonCode: 'passwd_unavailable', reason: null };
  checkAborted(signal);

  const parsedGroups = groupResult.status === 'fulfilled' ? parseGroup(groupResult.value) : null;
  const parsedUsers = passwdResult.status === 'fulfilled' ? parsePasswd(passwdResult.value, passwordState.statuses) : null;
  const privilegedGroups = (parsedGroups ?? []).filter((group) => /^(admin|wheel|sudo)$/i.test(group.name));
  const privilegedNames = new Set(privilegedGroups.flatMap((group) => group.members));
  const privilegedGids = new Set(privilegedGroups.map((group) => group.gid));
  for (const user of parsedUsers ?? []) user.isAdministrator = privilegedNames.has(user.name) || privilegedGids.has(user.primaryGroupId) || user.uid === 0;
  const users = parsedUsers
    ? {
      ...sourceResult(parsedUsers, '/etc/passwd + passwd -S', passwordState.reason),
      accountStatus: passwordState.status,
      reasonCode: passwordState.reasonCode,
    }
    : {
      ...unavailableSource('/etc/passwd', passwdResult.reason),
      accountStatus: 'unavailable',
      reasonCode: 'passwd_unavailable',
    };
  const groups = parsedGroups ? sourceResult(parsedGroups, '/etc/group') : unavailableSource('/etc/group', groupResult.reason);
  return { users, groups, privilegedGroups: privilegedGroups.map((group) => group.name) };
}

async function collectWindows({ run, signal }) {
  const script = [
    "$users=@(Get-LocalUser | Select-Object Name,SID,Enabled,Description,LastLogon,PasswordRequired,PasswordExpires,@{Name='PasswordNeverExpires';Expression={$null -eq $_.PasswordExpires}});",
    "$groups=@(Get-LocalGroup | ForEach-Object {$g=$_; $members=@(Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue | Select-Object Name,SID,ObjectClass,PrincipalSource); [PSCustomObject]@{Name=$g.Name;SID=$g.SID.Value;Description=$g.Description;Members=$members}});",
    "[PSCustomObject]@{Users=$users;Groups=$groups} | ConvertTo-Json -Compress -Depth 5",
  ].join(' ');
  try {
    const output = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      signal,
      timeoutMs: COMMAND_TIMEOUT_MS,
    });
    const data = output ? JSON.parse(output) : { Users: [], Groups: [] };
    const administratorNames = new Set((data.Groups ?? []).filter((group) => /^(administrators|admin)$/i.test(group.Name)).flatMap((group) => (group.Members ?? []).map((member) => member.Name)));
        const users = (data.Users ?? []).map((user) => ({
      name: user.Name,
      sid: user.SID?.Value ?? user.SID ?? null,
      enabled: user.Enabled ?? null,
      description: user.Description || null,
      lastLogon: user.LastLogon || null,
      passwordRequired: user.PasswordRequired ?? null,
      passwordExpires: user.PasswordExpires || null,
      passwordNeverExpires: user.PasswordNeverExpires ?? null,
      isAdministrator: [...administratorNames].some((name) => name === user.Name || name.endsWith(`\\${user.Name}`)),
    }));
    const groups = (data.Groups ?? []).map((group) => ({
      name: group.Name,
      sid: group.SID || null,
      description: group.Description || null,
      members: (group.Members ?? []).map((member) => ({
        name: member.Name,
        sid: member.SID?.Value ?? member.SID ?? null,
        type: member.ObjectClass || null,
        principalSource: member.PrincipalSource || null,
      })),
    }));
    return {
      users: sourceResult(users, 'powershell-get-localuser'),
      groups: sourceResult(groups, 'powershell-get-localgroup'),
      privilegedGroups: groups.filter((group) => /^(administrators|admin)$/i.test(group.name)).map((group) => group.name),
    };
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return {
      users: unavailableSource('powershell-get-localuser', error),
      groups: unavailableSource('powershell-get-localgroup', error),
    };
  }
}

function parseDsclList(output, idKey) {
  return output.split(/\r?\n/).filter(Boolean).map((line) => {
    const match = line.match(/^(.*?)\s+(-?\d+)$/);
    return { name: match?.[1] ?? line.trim(), [idKey]: match ? Number(match[2]) : null };
  });
}

function parseDsclMemberships(output) {
  const memberships = new Map();
  for (const line of output.split(/\r?\n/).filter(Boolean)) {
    const [name, ...members] = line.trim().split(/\s+/);
    memberships.set(name, members);
  }
  return memberships;
}

async function collectMacOs({ run, signal }) {
  try {
    const [userOutput, groupOutput, membershipOutput] = await Promise.all([
      run('/usr/bin/dscl', ['.', '-list', '/Users', 'UniqueID'], { signal, timeoutMs: COMMAND_TIMEOUT_MS }),
      run('/usr/bin/dscl', ['.', '-list', '/Groups', 'PrimaryGroupID'], { signal, timeoutMs: COMMAND_TIMEOUT_MS }),
      run('/usr/bin/dscl', ['.', '-list', '/Groups', 'GroupMembership'], { signal, timeoutMs: COMMAND_TIMEOUT_MS }),
    ]);
    const memberships = parseDsclMemberships(membershipOutput);
    return {
      users: sourceResult(parseDsclList(userOutput, 'uid').map((user) => ({
        ...user,
        enabled: null,
        isAdministrator: ['admin', 'wheel'].some((group) => (memberships.get(group) ?? []).includes(user.name)) || user.uid === 0,
        lastLogin: null,
        passwordNeverExpires: null,
      })), 'dscl-local-users'),
      groups: sourceResult(parseDsclList(groupOutput, 'gid').map((group) => ({
        ...group,
        members: memberships.get(group.name) ?? [],
      })), 'dscl-local-groups'),
      privilegedGroups: ['admin', 'wheel'].filter((group) => memberships.has(group)),
    };
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return {
      users: unavailableSource('dscl-local-users', error),
      groups: unavailableSource('dscl-local-groups', error),
    };
  }
}

export function createUsersGroupsCollector({
  platform = process.platform,
  runCommand = runBoundedCommand,
  readTextFile = readFile,
} = {}) {
  return {
    name: 'users-groups',
    version: '1.0.0',
    async run(_params = {}, context = {}) {
      checkAborted(context.signal);
      const dependencies = { run: runCommand, readTextFile, signal: context.signal };
      let data;
      if (platform === 'linux') data = await collectLinux(dependencies);
      else if (platform === 'win32') data = await collectWindows(dependencies);
      else if (platform === 'darwin') data = await collectMacOs(dependencies);
      else {
        const error = new Error(`Unsupported platform "${platform}"`);
        data = {
          users: unavailableSource('local-users', error),
          groups: unavailableSource('local-groups', error),
        };
      }
      checkAborted(context.signal);
      return { platform, ...data };
    },
  };
}

export const usersGroupsCollector = createUsersGroupsCollector();
export default usersGroupsCollector;
