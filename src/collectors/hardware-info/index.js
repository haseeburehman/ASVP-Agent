import systeminformation from 'systeminformation';

function abortError() {
  const error = new Error('Hardware information collection was aborted');
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

function abortIfNeeded(signal) {
  if (signal?.aborted) throw abortError();
}

function privilegeFailure(error) {
  const text = `${error?.code ?? ''} ${error?.message ?? ''}`;
  return ['EACCES', 'EPERM'].includes(error?.code)
    || /access is denied|permission denied|not permitted|requires? elevation|administrator privileges|must be root|not authorized/i.test(text);
}

function available(value, source) {
  return { status: 'available', value, reasonCode: null, reason: null, source };
}

function failed(error, source, subject) {
  const status = privilegeFailure(error) ? 'insufficient_privilege' : 'unavailable';
  return {
    status,
    value: null,
    reasonCode: status,
    reason: `${subject} is ${status === 'insufficient_privilege' ? 'not accessible with current privileges' : 'unavailable'}: ${error?.message ?? String(error)}`,
    source,
  };
}

function nullable(value) {
  return value === undefined || value === '' ? null : value;
}

function number(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function normalizeCpu(cpu) {
  return {
    manufacturer: nullable(cpu.manufacturer),
    brand: nullable(cpu.brand),
    vendor: nullable(cpu.vendor),
    family: nullable(cpu.family),
    model: nullable(cpu.model),
    stepping: nullable(cpu.stepping),
    revision: nullable(cpu.revision),
    speedGHz: number(cpu.speed),
    speedMinGHz: number(cpu.speedMin),
    speedMaxGHz: number(cpu.speedMax),
    cores: number(cpu.cores),
    logicalCores: number(cpu.cores),
    physicalCores: number(cpu.physicalCores),
    performanceCores: number(cpu.performanceCores),
    efficiencyCores: number(cpu.efficiencyCores),
    processors: number(cpu.processors),
    socket: nullable(cpu.socket),
    cache: nullable(cpu.cache),
    flags: nullable(cpu.flags),
  };
}

function normalizeMemory(memory, layout) {
  return {
    totalBytes: number(memory.total),
    freeBytes: number(memory.free),
    usedBytes: number(memory.used),
    activeBytes: number(memory.active),
    availableBytes: number(memory.available),
    swapTotalBytes: number(memory.swaptotal),
    swapUsedBytes: number(memory.swapused),
    swapFreeBytes: number(memory.swapfree),
    moduleCount: Array.isArray(layout) ? layout.length : null,
    modulesAvailable: Array.isArray(layout),
    modules: (Array.isArray(layout) ? layout : []).map((module) => ({
      sizeBytes: number(module.size),
      bank: nullable(module.bank),
      type: nullable(module.type),
      ecc: typeof module.ecc === 'boolean' ? module.ecc : null,
      clockSpeedMHz: number(module.clockSpeed),
      formFactor: nullable(module.formFactor),
      manufacturer: nullable(module.manufacturer),
      partNumber: nullable(module.partNum),
      serialNumber: nullable(module.serialNum),
      voltageConfigured: number(module.voltageConfigured),
    })),
  };
}

function normalizeDisk(disk) {
  return {
    device: nullable(disk.device),
    type: nullable(disk.type),
    name: nullable(disk.name),
    model: nullable(disk.name),
    vendor: nullable(disk.vendor),
    sizeBytes: number(disk.size),
    bytesPerSector: number(disk.bytesPerSector),
    totalCylinders: number(disk.totalCylinders),
    totalHeads: number(disk.totalHeads),
    totalSectors: number(disk.totalSectors),
    totalTracks: number(disk.totalTracks),
    tracksPerCylinder: number(disk.tracksPerCylinder),
    sectorsPerTrack: number(disk.sectorsPerTrack),
    firmwareRevision: nullable(disk.firmwareRevision),
    serialNumber: nullable(disk.serialNum),
    interfaceType: nullable(disk.interfaceType),
    smartStatus: nullable(disk.smartStatus),
  };
}

function normalizeBios(bios) {
  return {
    vendor: nullable(bios.vendor),
    version: nullable(bios.version),
    releaseDate: nullable(bios.releaseDate),
    revision: nullable(bios.revision),
    serialNumber: nullable(bios.serial),
  };
}

function normalizeSystem(system) {
  return {
    manufacturer: nullable(system.manufacturer),
    model: nullable(system.model),
    version: nullable(system.version),
    serialNumber: nullable(system.serial),
    uuid: nullable(system.uuid),
    sku: nullable(system.sku),
  };
}

async function collect(call, normalize, source, subject, signal) {
  try {
    abortIfNeeded(signal);
    const value = await call();
    abortIfNeeded(signal);
    return available(normalize(value), source);
  } catch (error) {
    if (error?.name === 'AbortError') throw error;
    return failed(error, source, subject);
  }
}

function virtualization(cpu, system, platform) {
  const cpuValue = cpu.status === 'available' ? cpu.value.virtualization : null;
  const systemValue = system.status === 'available' ? system.value.virtual : null;
  const virtualHost = system.status === 'available' ? system.value.virtualHost : null;
  if (typeof systemValue === 'boolean' || typeof cpuValue === 'boolean' || virtualHost) {
    return available({
      isVirtual: typeof systemValue === 'boolean' ? systemValue : Boolean(virtualHost),
      hypervisorVendor: nullable(virtualHost),
      cpuVirtualization: typeof cpuValue === 'boolean' ? cpuValue : null,
    }, 'systeminformation.system+cpu');
  }

  const failure = [system, cpu].find((section) => section.status === 'insufficient_privilege')
    ?? [system, cpu].find((section) => section.status === 'unavailable');
  if (failure) {
    return {
      status: failure.status,
      value: null,
      reasonCode: failure.reasonCode,
      reason: `Virtualization information could not be derived: ${failure.reason}`,
      source: 'systeminformation.system+cpu',
    };
  }
  return failed(new Error(`no virtualization indicators were returned on platform "${platform}"`), 'systeminformation.system+cpu', 'Virtualization information');
}

export function createHardwareInfoCollector({
  systemInformation = systeminformation,
  platform = process.platform,
} = {}) {
  return {
    name: 'hardware-info',
    version: '1.0.0',
    async run(_params = {}, context = {}) {
      const signal = context.signal;
      abortIfNeeded(signal);
      const [rawCpu, memory, disks, bios, rawSystem] = await Promise.all([
        collect(() => systemInformation.cpu(), (value) => value, 'systeminformation.cpu', 'CPU information', signal),
        collect(
          () => Promise.all([systemInformation.mem(), systemInformation.memLayout()]),
          ([value, layout]) => normalizeMemory(value, layout),
          'systeminformation.mem+memLayout',
          'Memory information',
          signal,
        ),
        collect(() => systemInformation.diskLayout(), (value) => {
          const items = (Array.isArray(value) ? value : []).map(normalizeDisk);
          return { items, totalCount: items.length };
        }, 'systeminformation.diskLayout', 'Disk information', signal),
        collect(() => systemInformation.bios(), normalizeBios, 'systeminformation.bios', 'BIOS information', signal),
        collect(() => systemInformation.system(), (value) => value, 'systeminformation.system', 'System information', signal),
      ]);
      abortIfNeeded(signal);

      const cpu = rawCpu.status === 'available' ? available(normalizeCpu(rawCpu.value), rawCpu.source) : rawCpu;
      const system = rawSystem.status === 'available' ? available(normalizeSystem(rawSystem.value), rawSystem.source) : rawSystem;
      return {
        platform,
        cpu,
        memory,
        disks,
        bios,
        system,
        virtualization: virtualization(rawCpu, rawSystem, platform),
      };
    },
  };
}

export const hardwareInfoCollector = createHardwareInfoCollector();
export default hardwareInfoCollector;
