// Shared test cases for a central sealer's tree (format description,
// section 21.7): the leaf fingerprint of each line of a book, and the
// number of entries and top fingerprint of the tree built from leaf
// fingerprints alone, after each. A sealer that never sees the lines must
// reach the same top fingerprint as a checker that reads them.

import { leafFingerprint } from '../../src/index.js';
import { treeBuilder } from '../../src/tree.js';
import { answer, finish } from './vector-tools.mjs';

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const H = (text) => Uint8Array.from(Buffer.from(text, 'hex'));

/** How each kind of case is answered. */
export const ANSWER = {
  // "lines": the lines of a book, each without its line feed; or "leaves": leaf fingerprints, in hexadecimal.
  sealerTree: (c) =>
    answer(async () => {
      const leaves = [];
      if (Object.hasOwn(c, 'lines')) for (const line of c.lines) leaves.push(await leafFingerprint(line));
      else for (const leaf of c.leaves) leaves.push(H(leaf));
      const builder = treeBuilder();
      const after = [];
      for (const leaf of leaves) {
        await builder.addLeafHash(leaf);
        after.push({ size: after.length + 1, root: hex(await builder.root()) });
      }
      return { leaves: leaves.map(hex), after };
    }),
};

// A seeded source of bytes, so that the cases are the same each time they are made.
function randomSource(seed) {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s ^ (s >>> 15), 0x2c1b3c6d) + 0x297a2d39) >>> 0;
    s = (s ^ (s >>> 12)) >>> 0;
    return s & 0xff;
  };
}

function sealerTreeCases() {
  const next = randomSource(388);
  const leaf = (n = 32) => hex(Uint8Array.from({ length: n }, next));
  const line = (i) => JSON.stringify({ n: i, note: Array.from({ length: 1 + (next() % 30) }, () => String.fromCharCode(0x20 + (next() % 95))).join('') });
  const cases = [];
  cases.push({ name: 'one line', lines: ['{"slip":{"payload":"x"}}'] });
  cases.push({ name: 'a line with letters outside ASCII', lines: ['{"note":"café, Straße, 東京, 😀"}', '{"n":2}'] });
  for (let n = 2; n <= 33; n++) cases.push({ name: `${n} lines`, lines: Array.from({ length: n }, (_, i) => line(i)) });
  for (let n = 1; n <= 40; n++) cases.push({ name: `${n} leaf fingerprints`, leaves: Array.from({ length: n }, () => leaf()) });
  cases.push({ name: '300 leaf fingerprints', leaves: Array.from({ length: 300 }, () => leaf()) });
  cases.push({ name: 'no lines', lines: [] });
  cases.push({ name: 'an empty line', lines: ['{"n":1}', ''] });
  cases.push({ name: 'a line with its line feed', lines: ['{"n":1}\n'] });
  cases.push({ name: 'a line feed inside a line', lines: ['{"n":1}\n{"n":2}'] });
  cases.push({ name: 'a line with a lone surrogate', lines: ['{"n":"\ud800"}'] });
  cases.push({ name: 'a line that is not text', lines: [42] });
  cases.push({ name: 'a line of 43,691 three-byte letters: 131,073 bytes', lines: ['€'.repeat(43691)] });
  cases.push({ name: 'a leaf fingerprint of 31 bytes', leaves: [leaf(), leaf(31)] });
  cases.push({ name: 'a leaf fingerprint of 33 bytes', leaves: [leaf(33)] });
  cases.push({ name: 'an empty leaf fingerprint', leaves: [''] });
  return cases;
}

/** Each set of cases, by the name of its file. */
export const CASES = {
  'sealer-trees': async () => finish('A central sealer\'s tree (format description, section 21.7): the leaf fingerprint of each line, and the number of entries and top fingerprint after each leaf fingerprint taken in.', 'sealerTree', sealerTreeCases(), ANSWER),
};
