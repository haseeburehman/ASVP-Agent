const builtInDefinitions = {
  noop: {
    modulePath: '../collectors/noop/index.js',
    implemented: true,
    timeoutMs: 5000,
    concurrency: 2,
  },
  'os-info': {
    modulePath: '../collectors/os-info/index.js',
    implemented: true,
    timeoutMs: 25000,
    concurrency: 1,
  },
  apps: {
    modulePath: '../collectors/apps/index.js',
    implemented: true,
    timeoutMs: 20000,
    concurrency: 1,
  },
  'sca-deps': {
    modulePath: '../collectors/sca-deps/index.js',
    implemented: true,
    timeoutMs: 30000,
    concurrency: 1,
  },
  'credential-exposure': {
    modulePath: '../collectors/credential-exposure/index.js',
    implemented: true,
    timeoutMs: 30000,
    concurrency: 1,
  },
  containers: {
    modulePath: '../collectors/containers/index.js',
    implemented: true,
    timeoutMs: 60000,
    concurrency: 1,
  },
  'local-ports': {
    modulePath: '../collectors/local-ports/index.js',
    implemented: true,
    timeoutMs: 15000,
    concurrency: 1,
  },
  'compliance-checks': {
    modulePath: '../collectors/compliance-checks/index.js',
    implemented: true,
    timeoutMs: 45000,
    concurrency: 1,
  },
  'users-groups': {
    modulePath: '../collectors/users-groups/index.js',
    implemented: true,
    timeoutMs: 15000,
    concurrency: 1,
  },
  'antivirus-status': {
    modulePath: '../collectors/antivirus-status/index.js',
    implemented: true,
    timeoutMs: 20000,
    concurrency: 1,
  },
  'process-summary': {
    modulePath: '../collectors/process-summary/index.js',
    implemented: true,
    timeoutMs: 15000,
    concurrency: 1,
  },
  services: {
    modulePath: '../collectors/services/index.js',
    implemented: true,
    timeoutMs: 15000,
    concurrency: 1,
  },
  'network-config': {
    modulePath: '../collectors/network-config/index.js',
    implemented: true,
    timeoutMs: 15000,
    concurrency: 1,
  },
  'disk-security': {
    modulePath: '../collectors/disk-security/index.js',
    implemented: true,
    timeoutMs: 20000,
    concurrency: 1,
  },
  'hardware-info': {
    modulePath: '../collectors/hardware-info/index.js',
    implemented: true,
    timeoutMs: 20000,
    concurrency: 1,
  },
  'kernel-hardening': {
    modulePath: '../collectors/kernel-hardening/index.js',
    implemented: true,
    timeoutMs: 15000,
    concurrency: 1,
  },
  'file-permissions': {
    modulePath: '../collectors/file-permissions/index.js',
    implemented: true,
    timeoutMs: 15000,
    concurrency: 1,
  },
};

export class CollectorNotImplementedError extends Error {
  constructor(name, allowlisted) {
    super(allowlisted
      ? `Collector "${name}" is allowlisted but not implemented`
      : `Collector "${name}" is not registered or implemented`);
    this.name = 'CollectorNotImplementedError';
    this.code = 'COLLECTOR_NOT_IMPLEMENTED';
  }
}

export class CollectorRegistry {
  constructor({ definitions = builtInDefinitions, importer = (specifier) => import(specifier) } = {}) {
    this.definitions = definitions;
    this.importer = importer;
    this.loaded = new Map();
  }

  has(name) {
    return Object.hasOwn(this.definitions, name);
  }

  getDefinition(name) {
    return this.definitions[name] ?? null;
  }

  async get(name) {
    const definition = this.getDefinition(name);
    if (!definition?.implemented) throw new CollectorNotImplementedError(name, Boolean(definition));
    if (this.loaded.has(name)) return this.loaded.get(name);

    const moduleUrl = new URL(definition.modulePath, import.meta.url);
    const module = await this.importer(moduleUrl.href);
    const collector = module.default ?? module.collector ?? module[`${name}Collector`];
    if (!collector) throw new Error(`Collector module "${name}" does not export a collector`);
    this.loaded.set(name, collector);
    return collector;
  }

  list() {
    return Object.entries(this.definitions).map(([name, definition]) => ({ name, ...definition }));
  }
}

export { builtInDefinitions };
