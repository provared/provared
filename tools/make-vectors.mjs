// Write the shared test files in test-vectors/: records and values, each
// with the answer this library gives. Any other implementation of the
// format (such as the Python one in python/) must give the same answers.
//
//   node tools/make-vectors.mjs
//
// The records are signed afresh each time, so run it only when the cases
// change. test/vectors.test.mjs checks that this library still gives every
// stored answer.

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CASES } from '../test/helpers/vectors.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'test-vectors');
mkdirSync(root, { recursive: true });
for (const [name, make] of Object.entries(CASES)) {
  const set = await make();
  writeFileSync(join(root, `${name}.json`), JSON.stringify(set, null, 1) + '\n');
  console.log(`${name}.json: ${set.cases.length} cases`);
}
