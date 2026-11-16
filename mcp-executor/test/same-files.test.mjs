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

const IMPORTS = ["import nodeCrypto from 'node:crypto';", "import { toBase64url } from 'provared';"];
/** The ends of a line other than the line feed: the carriage return, the line separator (U+2028) and the paragraph separator (U+2029). */
const OTHER_ENDS = ['\r', String.fromCharCode(0x2028), String.fromCharCode(0x2029)];

/**
 * The lines of the copy that are neither one of its ten declarations, one
 * of its two import lines, a blank line, nor a whole comment. A comment is
 * a line that begins "//"; a line that begins with the mark that opens a
 * block comment and ends with the first mark that closes one; or a block
 * that opens with that mark alone on a line and closes with " *" and a
 * slash alone on a line, every line between beginning " * " (or being
 * " *") and holding no closing mark. So nothing that runs can stand
 * after a comment mark, or between two. A line that holds another end of
 * line than the line feed (which would end a "//" comment early) is
 * counted too.
 */
function otherLines(copy) {
  let rest = copy;
  for (const d of DECLARATIONS) rest = rest.replace(declaration(copy, d, 'sealer-client.mjs'), () => '');
  const other = [];
  let block = false;
  for (const line of rest.split('\n')) {
    if (OTHER_ENDS.some((end) => line.includes(end))) other.push(line);
    else if (block) {
      if (line === ' */') block = false;
      else if (!/^ \*( |$)/.test(line) || line.includes('*/')) other.push(line);
    } else if (line === '/**') block = true;
    else if (line === '' || IMPORTS.includes(line) || line.startsWith('//')) continue;
    else if (line.startsWith('/**') && line.indexOf('*/') === line.length - 2) continue;
    else other.push(line);
  }
  if (block) other.push('(a block comment that does not end)');
  return other;
}

test('sealer-client.mjs holds the sealer\'s own client, each declaration byte for byte, and no other code', () => {
  const copy = readFileSync(new URL('sealer-client.mjs', here), 'utf8');
  const sealer = readFileSync(new URL('../sealer/sealer.mjs', here), 'utf8');
  for (const d of DECLARATIONS) {
    assert.equal(declaration(copy, d, 'sealer-client.mjs'), declaration(sealer, d, 'sealer/sealer.mjs'), `the declaration that starts "${d[0]}" differs from the sealer's`);
  }
  // What is left: the two import lines, comments and blank lines.
  assert.deepEqual(otherLines(copy), [], 'sealer-client.mjs holds code that is not the sealer\'s');
  for (const line of IMPORTS) assert.ok(copy.split('\n').includes(line), `sealer-client.mjs lacks the line: ${line}`);
});

test('the check that sealer-client.mjs holds no other code finds code behind a comment mark, between two, after an end of line that is no line feed, and in a third import (review 3.2, F4)', () => {
  const copy = readFileSync(new URL('sealer-client.mjs', here), 'utf8');
  assert.deepEqual(otherLines(copy), [], 'the copy as it is');
  // Each of these is put before a declaration of the copy, where code would run; each holds something that runs.
  const hidden = [
    '/** */ globalThis.provaredProbe = 1;',
    '/**/ globalThis.provaredProbe = 1;',
    '/* */ globalThis.provaredProbe = 1;',
    '/** a comment */ globalThis.provaredProbe = 1; /** and another */',
    ' * globalThis.provaredProbe = 1;',
    ' */ globalThis.provaredProbe = 1;',
    '/**\n */ globalThis.provaredProbe = 1;',
    '/**\n * a comment */ globalThis.provaredProbe = 1; /*\n */',
    '/**\nglobalThis.provaredProbe = 1;\n */',
    ...OTHER_ENDS.map((end) => `// a comment${end}globalThis.provaredProbe = 1;`),
    'globalThis.provaredProbe = 1;',
    "import './another-file.mjs';",
    '/**',
  ];
  for (const lines of hidden) {
    const changed = copy.replace('\nconst sha256 = ', () => `\n${lines}\nconst sha256 = `);
    assert.notEqual(changed, copy);
    assert.notDeepEqual(otherLines(changed), [], `not found: ${JSON.stringify(lines)}`);
  }
  // Comments in the forms the copy uses are let through.
  for (const lines of ['// a comment', '//', '/** A comment on one line. */', '/**\n * A comment\n *\n * on several lines.\n */']) {
    assert.deepEqual(otherLines(copy.replace('\nconst sha256 = ', () => `\n${lines}\nconst sha256 = `)), [], JSON.stringify(lines));
  }
});
