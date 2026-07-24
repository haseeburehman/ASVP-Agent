import { access, readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { build } from 'esbuild';
import { builtInDefinitions } from '../../src/core/collector-registry.js';

export async function discoverCollectorModules(root) {
  const collectorsRoot = path.join(root, 'src', 'collectors');
  const entries = await readdir(collectorsRoot, { withFileTypes: true });
  const modules = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const modulePath = path.join(collectorsRoot, entry.name, 'index.js');
    try { await access(modulePath); } catch { continue; }
    modules.push({ name: entry.name, modulePath });
  }
  modules.sort((left, right) => left.name.localeCompare(right.name));
  return modules;
}

export function verifyCollectorCoverage(discovered) {
  const discoveredNames = new Set(discovered.map(({ name }) => name));
  const registeredNames = Object.entries(builtInDefinitions)
    .filter(([, definition]) => definition.implemented)
    .map(([name]) => name);
  const missingModules = registeredNames.filter((name) => !discoveredNames.has(name));
  const unregisteredModules = discovered.map(({ name }) => name).filter((name) => !Object.hasOwn(builtInDefinitions, name));
  if (missingModules.length || unregisteredModules.length) {
    throw new Error(`Collector packaging coverage mismatch: missing module(s) for registry=[${missingModules.join(', ')}]; unregistered module folder(s)=[${unregisteredModules.join(', ')}]`);
  }
  return registeredNames.sort();
}

function createCollectorImporter(discovered) {
  const branches = discovered.map(({ name }) => `  if (value.includes('/collectors/${name}/') || value === '../collectors/${name}/index.js') return import('../../src/collectors/${name}/index.js');`).join('\n');
  return `async (specifier) => {
  const value = String(specifier).replaceAll('\\\\', '/');
${branches}
  throw new Error(\`Packaged collector module is not bundled: \${value}\`);
}`;
}

function packagingTransforms({ version, collectorImporter }) {
  return {
    name: 'asvp-packaging-transforms',
    setup(buildApi) {
      buildApi.onLoad({ filter: /asvp-agent\.js$/ }, async ({ path: filePath }) => ({
        loader: 'js',
        contents: (await readFile(filePath, 'utf8')).replace(
          /try \{\s*await createProgram\(\)\.parseAsync\(process\.argv\);\s*\} catch \(error\) \{\s*process\.stderr\.write\(`asvp-agent: \$\{error\.message\}\\n`\);\s*process\.exitCode = 1;\s*\}/,
          `(async () => {\n  try {\n    await createProgram().parseAsync(process.argv);\n  } catch (error) {\n    process.stderr.write(\`asvp-agent: \${error.message}\\n\`);\n    process.exitCode = 1;\n  }\n})();`,
        ),
      }));
      buildApi.onLoad({ filter: /src[\\/]core[\\/]collector-registry\.js$/ }, async ({ path: filePath }) => ({
        loader: 'js',
        contents: (await readFile(filePath, 'utf8'))
          .replace('(specifier) => import(specifier)', collectorImporter)
          .replace('const moduleUrl = new URL(definition.modulePath, import.meta.url);', 'const moduleUrl = { href: definition.modulePath };'),
      }));
      buildApi.onLoad({ filter: /src[\\/]security[\\/]credentials\.js$/ }, async ({ path: filePath }) => ({ loader: 'js', contents: (await readFile(filePath, 'utf8')).replace("(await import('keytar')).default", "require('keytar')") }));
      buildApi.onLoad({ filter: /src[\\/]config[\\/]loader\.js$/ }, async ({ path: filePath }) => ({ loader: 'js', contents: (await readFile(filePath, 'utf8')).replace("const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');", "const projectRoot = globalThis.__ASVP_BUNDLE_ROOT__ ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');") }));
      buildApi.onLoad({ filter: /src[\\/]service[\\/]index\.js$/ }, async ({ path: filePath }) => ({ loader: 'js', contents: (await readFile(filePath, 'utf8')).replace("const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');", "const projectRoot = globalThis.__ASVP_BUNDLE_ROOT__ ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');") }));
      buildApi.onLoad({ filter: /src[\\/]cli[\\/]commands\.js$/ }, async ({ path: filePath }) => ({ loader: 'js', contents: (await readFile(filePath, 'utf8')).replace(/async function getVersion\(\) \{[\s\S]*?\n\}/, `async function getVersion() { return ${JSON.stringify(version)}; }`) }));
      buildApi.onLoad({ filter: /src[\\/]dashboard[\\/]server\.js$/ }, async ({ path: filePath }) => ({
        loader: 'js',
        contents: (await readFile(filePath, 'utf8'))
          .replace("const PAGE_PATH = new URL('./public/index.html', import.meta.url);", "const PAGE_PATH = path.join(globalThis.__ASVP_BUNDLE_ROOT__ ?? path.dirname(fileURLToPath(import.meta.url)), 'public', 'index.html');")
          .replace("const version = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8')).version;", `const version = ${JSON.stringify(version)};`)
          .replace("import path from 'node:path';", "import path from 'node:path';\nimport { fileURLToPath } from 'node:url';"),
      }));
      buildApi.onResolve({ filter: /^keytar$/ }, () => ({ path: 'keytar', external: true }));
      buildApi.onResolve({ filter: /^better-sqlite3$/ }, () => ({ path: 'better-sqlite3', external: true }));
      buildApi.onResolve({ filter: /^(ssh2|cpu-features)$/ }, ({ path: moduleName }) => ({ path: moduleName, namespace: 'unused-docker-ssh' }));
      buildApi.onLoad({ filter: /.*/, namespace: 'unused-docker-ssh' }, () => ({ loader: 'js', contents: 'module.exports = {};' }));
    },
  };
}

export async function buildAgentBundle({ root, outputPath, version }) {
  const discovered = await discoverCollectorModules(root);
  const registeredCollectors = verifyCollectorCoverage(discovered);
  await build({
    absWorkingDir: root,
    entryPoints: [path.join(root, 'bin', 'asvp-agent.js')],
    outfile: outputPath,
    bundle: true,
    platform: 'node',
    target: 'node22',
    format: 'cjs',
    sourcemap: false,
    legalComments: 'none',
    banner: { js: `globalThis.__ASVP_BUNDLE_ROOT__ = process.pkg ? require('node:path').dirname(process.execPath) : __dirname; // source root: ${normalizedPath(root)}` },
    plugins: [packagingTransforms({ version, collectorImporter: createCollectorImporter(discovered) })],
  });
  return { discovered, registeredCollectors };
}

function normalizedPath(value) { return value.replaceAll('\\', '/'); }
