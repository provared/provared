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

// sealer-client.mjs is the recorder's side of the central sealer's
// protocol, copied from the sealer's program (sealer/sealer.mjs): the
// labels, the proofs, the members a question may hold and connectSealer.
// Each declaration is held the same as the sealer's, byte for byte, and
// the copy may hold no other code: so the executor asks the sealer exactly
// as the sealer's own client does, and a change there is made here too.
const DECLARATIONS = [
  ['const LABELS = Object.freeze({', '\n});\n'],
  ['export const RECORDER_NAME = ', '\n'],
  ['const RANDOM = ', '\n'],
  ['export const MAX_BODY_BYTES = ', '\n'],
  ['const MEMBERS = Object.freeze({', '\n});\n'],
  ['export function isRandom(', '\n}\n'],
  ['export function sealerHmac(', '\n}\n'],
  ['function sameProof(', '\n}\n'],
  ['const sha256 = ', '\n'],
  ['export function connectSealer(', '\n}\n'],
];
/** One declaration of a file: from its first words, at the start of a line, to its end. */
function declaration(text, [head, end], name) {
  const from = text.indexOf(`\n${head}`);
  assert.notEqual(from, -1, `${name} has no declaration that starts "${head}"`);
  assert.equal(text.indexOf(`\n${head}`, from + 1), -1, `${name} has two declarations that start "${head}"`);
  const to = text.indexOf(end, from + 1);
  assert.notEqual(to, -1, `the declaration that starts "${head}" in ${name} has no end`);
  return text.slice(from + 1, to + end.length);
}

test('sealer-client.mjs holds the sealer\'s own client, each declaration byte for byte, and no other code', () => {
  const copy = readFileSync(new URL('sealer-client.mjs', here), 'utf8');
  const sealer = readFileSync(new URL('../sealer/sealer.mjs', here), 'utf8');
  let rest = copy;
  for (const d of DECLARATIONS) {
    const mine = declaration(copy, d, 'sealer-client.mjs');
    assert.equal(mine, declaration(sealer, d, 'sealer/sealer.mjs'), `the declaration that starts "${d[0]}" differs from the sealer's`);
    rest = rest.replace(mine, () => '');
  }
  // What is left: the two import lines, comments and blank lines.
  const imports = ["import nodeCrypto from 'node:crypto';", "import { toBase64url } from 'provared';"];
  const other = rest.split('\n').filter((line) => line !== '' && !imports.includes(line) && !/^(\/\/|\/\*\*| \*)/.test(line));
  assert.deepEqual(other, [], 'sealer-client.mjs holds code that is not the sealer\'s');
  for (const line of imports) assert.ok(rest.split('\n').includes(line), `sealer-client.mjs lacks the line: ${line}`);
});
