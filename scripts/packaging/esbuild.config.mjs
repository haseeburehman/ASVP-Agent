import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { build } from 'esbuild';

const collectorImports = `async (specifier) => {
  const value = String(specifier).replaceAll('\\\\', '/');
  if (value.includes('/collectors/noop/')) return import('../../src/collectors/noop/index.js');
  if (value.includes('/collectors/os-info/')) return import('../../src/collectors/os-info/index.js');
  if (value.includes('/collectors/apps/')) return import('../../src/collectors/apps/index.js');
  if (value.includes('/collectors/sca-deps/')) return import('../../src/collectors/sca-deps/index.js');
  if (value.includes('/collectors/containers/')) return import('../../src/collectors/containers/index.js');
  if (value.includes('/collectors/network-scan/')) return import('../../src/collectors/network-scan/index.js');
  if (value.includes('/collectors/tls-checks/')) return import('../../src/collectors/tls-checks/index.js');
  if (value.includes('/collectors/compliance-checks/')) return import('../../src/collectors/compliance-checks/index.js');
  return import(specifier);
}`;

function packagingTransforms({ root, version }) {
  const normalizedRoot = root.replaceAll('\\', '/');
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
          .replace('(specifier) => import(specifier)', collectorImports)
          .replace('const moduleUrl = new URL(definition.modulePath, import.meta.url);', 'const moduleUrl = { href: definition.modulePath };'),
      }));
      buildApi.onLoad({ filter: /src[\\/]security[\\/]credentials\.js$/ }, async ({ path: filePath }) => ({
        loader: 'js',
        contents: (await readFile(filePath, 'utf8')).replace("(await import('keytar')).default", "require('keytar')"),
      }));
      buildApi.onLoad({ filter: /src[\\/]config[\\/]loader\.js$/ }, async ({ path: filePath }) => ({
        loader: 'js',
        contents: (await readFile(filePath, 'utf8')).replace(
          "const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');",
          'const projectRoot = globalThis.__ASVP_BUNDLE_ROOT__ ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), \'../..\');',
        ),
      }));
      buildApi.onLoad({ filter: /src[\\/]service[\\/]index\.js$/ }, async ({ path: filePath }) => ({
        loader: 'js',
        contents: (await readFile(filePath, 'utf8')).replace(
          "const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');",
          'const projectRoot = globalThis.__ASVP_BUNDLE_ROOT__ ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), \'../..\');',
        ),
      }));
      buildApi.onLoad({ filter: /src[\\/]cli[\\/]commands\.js$/ }, async ({ path: filePath }) => ({
        loader: 'js',
        contents: (await readFile(filePath, 'utf8')).replace(
          /async function getVersion\(\) \{[\s\S]*?\n\}/,
          `async function getVersion() { return ${JSON.stringify(version)}; }`,
        ),
      }));
      buildApi.onLoad({ filter: /src[\\/]dashboard[\\/]server\.js$/ }, async ({ path: filePath }) => ({
        loader: 'js',
        contents: (await readFile(filePath, 'utf8'))
          .replace("const PAGE_PATH = new URL('./public/index.html', import.meta.url);", "const PAGE_PATH = path.join(globalThis.__ASVP_BUNDLE_ROOT__ ?? path.dirname(fileURLToPath(import.meta.url)), 'public', 'index.html');")
          .replace("const version = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8')).version;", `const version = ${JSON.stringify(version)};`)
          .replace("import path from 'node:path';", "import path from 'node:path';\nimport { fileURLToPath } from 'node:url';"),
      }));
      buildApi.onResolve({ filter: /^keytar$/ }, () => ({ path: 'keytar', external: true }));
      buildApi.onResolve({ filter: /^better-sqlite3$/ }, () => ({ path: 'better-sqlite3', external: true }));
    },
  };
}

export async function buildAgentBundle({ root, outputPath, version }) {
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
    plugins: [packagingTransforms({ root, version })],
  });
}

function normalizedPath(value) {
  return value.replaceAll('\\', '/');
}
