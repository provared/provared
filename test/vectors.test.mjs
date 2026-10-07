// The shared test files in test-vectors/ (written by tools/make-vectors.mjs):
// this library must still give every stored answer. The Python library in
// python/ is checked against the same files.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { ANSWER } from './helpers/vectors.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'test-vectors');

for (const file of readdirSync(root).filter((f) => f.endsWith('.json')).sort()) {
  const set = JSON.parse(readFileSync(join(root, file), 'utf8'));
  test(`shared test file ${file}`, async () => {
    assert.ok(set.cases.length > 0);
    for (const c of set.cases) {
      const got = JSON.parse(JSON.stringify(await ANSWER[set.function](c)));
      assert.deepEqual(got, c.expected, `${file}: ${c.name}`);
    }
  });
}
