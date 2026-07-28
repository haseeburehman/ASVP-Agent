import assert from 'node:assert/strict';
import test from 'node:test';
import { executeCollector } from '../../src/core/collector.js';
import { builtInDefinitions } from '../../src/core/collector-registry.js';
import { configSchema } from '../../src/config/schema.js';
import hardwareInfoCollector, { createHardwareInfoCollector } from '../../src/collectors/hardware-info/index.js';

function mockedSystemInformation(overrides = {}) {
  return {
    async cpu() {
      return { manufacturer: 'CPU Co', brand: 'Fast CPU', speed: 3.2, cores: 8, physicalCores: 4, processors: 1, virtualization: true };
    },
    async mem() { return { total: 16000, free: 4000, used: 12000, active: 10000, available: 5000, swaptotal: 2000, swapused: 500, swapfree: 1500 }; },
    async memLayout() { return [{ size: 8000, bank: 'BANK 0', type: 'DDR5', manufacturer: 'RAM Co', partNum: 'PART-1', serialNum: 'RAM-SERIAL' }]; },
    async diskLayout() { return [{ device: '/dev/sda', type: 'SSD', name: 'Disk', vendor: 'Disk Co', size: 100000, serialNum: 'DISK-SERIAL', interfaceType: 'NVMe' }]; },
    async bios() { return { vendor: 'BIOS Co', version: '1.2.3', releaseDate: '2026-01-01', serial: 'BIOS-SERIAL' }; },
    async system() { return { manufacturer: 'System Co', model: 'Model 1', serial: 'SYSTEM-SERIAL', uuid: 'RAW-UUID', virtual: true, virtualHost: 'kvm' }; },
    ...overrides,
  };
}

function assertWrapper(section) {
  assert.deepEqual(Object.keys(section).sort(), ['reason', 'reasonCode', 'source', 'status', 'value']);
}

test('hardware-info normalizes all sections and preserves raw asset serials', async () => {
  const collector = createHardwareInfoCollector({ systemInformation: mockedSystemInformation(), platform: 'linux' });
  const result = await collector.run();

  assert.equal(result.platform, 'linux');
  for (const name of ['cpu', 'memory', 'disks', 'bios', 'system', 'virtualization']) assertWrapper(result[name]);
  assert.equal(result.cpu.value.speedGHz, 3.2);
  assert.equal(result.cpu.value.physicalCores, 4);
  assert.equal(result.cpu.value.logicalCores, 8);
  assert.equal(result.memory.value.totalBytes, 16000);
  assert.equal(result.memory.value.moduleCount, 1);
  assert.equal(result.memory.value.modulesAvailable, true);
  assert.equal(result.memory.value.modules[0].serialNumber, 'RAM-SERIAL');
  assert.equal(result.disks.value.totalCount, 1);
  assert.equal(result.disks.value.items[0].model, 'Disk');
  assert.equal(result.disks.value.items[0].serialNumber, 'DISK-SERIAL');
  assert.equal(result.bios.value.serialNumber, 'BIOS-SERIAL');
  assert.equal(result.system.value.serialNumber, 'SYSTEM-SERIAL');
  assert.equal(result.system.value.uuid, 'RAW-UUID');
  assert.deepEqual(result.virtualization.value, { isVirtual: true, hypervisorVendor: 'kvm', cpuVirtualization: true });
});

test('hardware-info isolates unavailable and insufficient privilege sections', async () => {
  const permissionError = Object.assign(new Error('permission denied'), { code: 'EACCES' });
  const collector = createHardwareInfoCollector({
    systemInformation: mockedSystemInformation({
      async diskLayout() { throw new Error('inventory missing'); },
      async bios() { throw permissionError; },
    }),
  });
  const result = await collector.run();

  assert.equal(result.cpu.status, 'available');
  assert.equal(result.disks.status, 'unavailable');
  assert.equal(result.disks.reasonCode, 'unavailable');
  assert.match(result.disks.reason, /inventory missing/);
  assert.equal(result.bios.status, 'insufficient_privilege');
  assert.equal(result.bios.reasonCode, 'insufficient_privilege');
  assert.match(result.bios.reason, /current privileges/);
});

test('hardware-info reports virtualization as unavailable when no indicator exists', async () => {
  const collector = createHardwareInfoCollector({
    platform: 'test-os',
    systemInformation: mockedSystemInformation({
      async cpu() { return { brand: 'CPU' }; },
      async system() { return { model: 'Machine' }; },
    }),
  });
  const result = await collector.run();
  assert.equal(result.virtualization.status, 'unavailable');
  assert.equal(result.virtualization.reasonCode, 'unavailable');
  assert.match(result.virtualization.reason, /no virtualization indicators/);
});

test('hardware-info preserves aborts', async () => {
  const controller = new AbortController();
  controller.abort();
  const collector = createHardwareInfoCollector({ systemInformation: mockedSystemInformation() });
  await assert.rejects(collector.run({}, { signal: controller.signal }), { name: 'AbortError', code: 'ABORT_ERR' });
});

test('hardware-info has explicit registry and config schema entries', () => {
  assert.deepEqual(builtInDefinitions['hardware-info'], {
    modulePath: '../collectors/hardware-info/index.js',
    implemented: true,
    timeoutMs: 20000,
    concurrency: 1,
  });
  assert.deepEqual(configSchema.properties.collectors.properties['hardware-info'].required, ['timeoutMs', 'concurrency']);
});

test('real hardware-info collector produces section wrappers', async () => {
  const result = await executeCollector({ collector: hardwareInfoCollector, params: {}, context: {}, timeoutMs: 20000 });
  assert.equal(result.collector, 'hardware-info');
  assert.equal(result.status, 'success');
  assert.equal(result.data.platform, process.platform);
  for (const name of ['cpu', 'memory', 'disks', 'bios', 'system', 'virtualization']) assertWrapper(result.data[name]);
});
