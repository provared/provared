// Two files are copies of the gateway's, so that a fix in one is made in
// both: files.mjs (key files, the slip, the book file) and the test's
// local-library.mjs. This test holds them the same, byte for byte.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const here = new URL('../', import.meta.url);
const gateway = new URL('../../gateway/', import.meta.url);

test('files.mjs and test/local-library.mjs are the gateway\'s, byte for byte', () => {
  for (const name of ['files.mjs', 'test/local-library.mjs']) {
    assert.equal(readFileSync(new URL(name, here), 'utf8'), readFileSync(new URL(name, gateway), 'utf8'), `${name} differs from gateway/${name}`);
  }
});
