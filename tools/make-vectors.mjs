// Write the shared test files in test-vectors/: records and values, each
// with the answer this library gives. Any other implementation of the
// format (such as the Python one in python/) must give the same answers.
//
//   node tools/make-vectors.mjs            every set
//   node tools/make-vectors.mjs slips ...  only the sets named
//
// The records are signed afresh each time, so remake a set only when its
// cases change. test/vectors.test.mjs checks that this library still gives
// every stored answer.

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CASES } from '../test/helpers/vectors.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'test-vectors');
mkdirSync(root, { recursive: true });
const wanted = process.argv.slice(2);
for (const name of wanted) {
  if (!Object.hasOwn(CASES, name)) {
    console.error(`There is no set named "${name}". The sets: ${Object.keys(CASES).join(', ')}.`);
    process.exit(2);
  }
}
for (const [name, make] of Object.entries(CASES)) {
  if (wanted.length > 0 && !wanted.includes(name)) continue;
  const set = await make();
  writeFileSync(join(root, `${name}.json`), JSON.stringify(set, null, 1) + '\n');
  console.log(`${name}.json: ${set.cases.length} cases`);
}
