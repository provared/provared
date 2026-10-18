// The tests run against this repository's own library, never a copy
// installed from npm, whatever node_modules holds: the name "provared" is
// taken to mean the repository's files, through its package.json
// "exports", read here. This holds in the test's own process and, through
// NODE_OPTIONS, in every program a test starts (the command). Nothing is
// written to disk. (The same as integrations/claude-code/test/local-library.mjs.)
//
// A test file imports this file first, and everything that names
// "provared" after it, with import(): the names in a file's own import
// lines are found before any of its code runs.

import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';

const root = new URL('../../', import.meta.url);
const { exports: map } = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier !== 'provared' && !specifier.startsWith('provared/')) return nextResolve(specifier, context);
    const entry = map[specifier === 'provared' ? '.' : `.${specifier.slice('provared'.length)}`];
    const target = typeof entry === 'string' ? entry : entry?.default;
    if (!target) throw new Error(`The library does not export "${specifier}".`);
    return { url: new URL(target, root).href, shortCircuit: true };
  },
});

// A file address has no spaces in it (they are written %20), so it needs no quotation marks here.
const option = `--import=${import.meta.url}`;
const options = process.env.NODE_OPTIONS ?? '';
if (!options.includes(option)) process.env.NODE_OPTIONS = `${options} ${option}`.trim();
