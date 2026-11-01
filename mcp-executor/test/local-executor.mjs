// For the demonstration's test: the name "provared-mcp-executor" is taken
// to mean this folder's own files, through its package.json "exports",
// never a copy installed from npm. The same as local-library.mjs, for the
// executor: it holds in the test's own process and, through NODE_OPTIONS,
// in every program a test starts. Imported after local-library.mjs.

import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';

const root = new URL('../', import.meta.url);
const { exports: map } = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier !== 'provared-mcp-executor' && !specifier.startsWith('provared-mcp-executor/')) return nextResolve(specifier, context);
    const entry = map[specifier === 'provared-mcp-executor' ? '.' : `.${specifier.slice('provared-mcp-executor'.length)}`];
    const target = typeof entry === 'string' ? entry : entry?.default;
    if (!target) throw new Error(`The executor does not export "${specifier}".`);
    return { url: new URL(target, root).href, shortCircuit: true };
  },
});

const option = `--import=${import.meta.url}`;
const options = process.env.NODE_OPTIONS ?? '';
if (!options.includes(option)) process.env.NODE_OPTIONS = `${options} ${option}`.trim();
