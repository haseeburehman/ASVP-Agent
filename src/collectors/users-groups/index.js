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

function parsePasswd(contents, shadowByName) {
  return contents.split(/\r?\n/).filter(Boolean).map((line) => {
    const [name, password, uid, gid, description, homeDirectory, shell] = line.split(':');
    const shadow = shadowByName?.get(name);
    const shadowPassword = shadow?.password;
    return {
      name,
      uid: Number(uid),
      primaryGroupId: Number(gid),
      description: description || null,
      homeDirectory: homeDirectory || null,
      shell: shell || null,
      passwordLocked: shadowPassword === undefined
        ? (['!', '*', '!!'].includes(password) ? true : null)
        : /^!|^\*/.test(shadowPassword),
      enabled: shadowPassword === undefined ? null : !/^!|^\*/.test(shadowPassword),
      isAdministrator: false,
      lastLogin: null,
      passwordNeverExpires: shadow ? shadow.maximumDays === '' || Number(shadow.maximumDays) >= 99999 : null,
    };
  });
}

function parseShadow(contents) {
  return new Map(contents.split(/\r?\n/).filter(Boolean).map((line) => {
    const [name, password, , , maximumDays] = line.split(':');
    return [name, { password, maximumDays }];
  }));
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

async function collectLinux({ readTextFile, signal }) {
  checkAborted(signal);
  const [passwdResult, groupResult, shadowResult] = await Promise.allSettled([
    readTextFile('/etc/passwd', 'utf8'),
    readTextFile('/etc/group', 'utf8'),
    readTextFile('/etc/shadow', 'utf8'),
  ]);
  checkAborted(signal);

  let shadowByName = null;
  let shadowReason = null;
  if (shadowResult.status === 'fulfilled') shadowByName = parseShadow(shadowResult.value);
  else shadowReason = `Password status unavailable: ${shadowResult.reason.message}`;

  const parsedGroups = groupResult.status === 'fulfilled' ? parseGroup(groupResult.value) : null;
  const parsedUsers = passwdResult.status === 'fulfilled' ? parsePasswd(passwdResult.value, shadowByName) : null;
  const privilegedGroups = (parsedGroups ?? []).filter((group) => /^(admin|wheel|sudo)$/i.test(group.name));
  const privilegedNames = new Set(privilegedGroups.flatMap((group) => group.members));
  const privilegedGids = new Set(privilegedGroups.map((group) => group.gid));
  for (const user of parsedUsers ?? []) user.isAdministrator = privilegedNames.has(user.name) || privilegedGids.has(user.primaryGroupId) || user.uid === 0;
  const users = parsedUsers ? sourceResult(parsedUsers, '/etc/passwd', shadowReason) : unavailableSource('/etc/passwd', passwdResult.reason);
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
