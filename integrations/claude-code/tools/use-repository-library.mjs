#!/usr/bin/env node
// For a copy of the repository: lets this recorder run on the repository's
// own library, with nothing installed. The recorder names its library
// "provared", as it is named when installed from npm; this writes
// node_modules/provared beside this folder's package.json as a few small
// files that only point at the repository's own: a package.json with the
// library's "exports", one line of JavaScript for each file it names, and
// one for the command-line checker.
//
//   node tools/use-repository-library.mjs
//
// Nothing is linked and nothing is copied: a link to the repository from
// inside it would be a loop, and some ways of deleting a folder follow a
// link and delete what it points at. Deleting node_modules/provared
// deletes only these small files. Installing the published package
// (npm install) puts the published library in their place. A folder that
// already holds an installed copy of the library is left as it is.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const recorderFolder = join(here, '..');
const repository = join(recorderFolder, '..', '..');
const target = join(recorderFolder, 'node_modules', 'provared');
const MARK = 'Stands for the library of the copy of the repository it sits in (tools/use-repository-library.mjs).';

const library = JSON.parse(readFileSync(join(repository, 'package.json'), 'utf8'));
if (library.name !== 'provared') throw new Error(`${repository} is not a copy of the Provared repository.`);

const existing = join(target, 'package.json');
if (existsSync(existing) && JSON.parse(readFileSync(existing, 'utf8')).description !== MARK) {
  console.log(`${target} holds an installed copy of the library, so it was left as it is.`);
  process.exit(0);
}

// One line for each file: the same names, pointing at the repository's own.
const pointTo = (file, from) => {
  let path = relative(dirname(join(target, file)), join(repository, from)).split(sep).join('/');
  if (!path.startsWith('.')) path = `./${path}`;
  return path;
};
const write = (file, text) => {
  mkdirSync(dirname(join(target, file)), { recursive: true });
  writeFileSync(join(target, file), text);
};

const exportsMap = {};
for (const [name, entry] of Object.entries(library.exports)) {
  const file = typeof entry === 'string' ? entry : entry.default;
  exportsMap[name] = file;
  if (file === './package.json') continue;
  write(file, `export * from '${pointTo(file, file)}';\n`);
}
write('bin/provared-check.mjs', `import '${pointTo('bin/provared-check.mjs', 'bin/provared-check.mjs')}';\n`);
write('package.json', JSON.stringify({ name: 'provared', version: library.version, description: MARK, private: true, type: 'module', exports: exportsMap }, null, 2) + '\n');
console.log(`${target} now stands for the library in ${repository} (version ${library.version}).`);
