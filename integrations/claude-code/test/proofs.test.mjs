// The proofs the recorder shows a witness (proofs.mjs), made from the leaf
// hashes it keeps as a book grows, are exactly the library's: every audit
// path, and every consistency proof for every pair of sizes up to 48 lines,
// on a book read in pieces, and read again where it does not go on; which
// trees the recorder holds; and when a kept book's file is another version.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { statSync, utimesSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { inclusionPath, utf8, verifyConsistency, witnessProof } = await import('provared');
const { bookTree } = await import('../proofs.mjs');
const { proofTrees } = await import('../witnessed.mjs');
const { fileVersion } = await import('../recorder.mjs');
const { tempFolder } = await import('./world.mjs');

const same = (a, b) => a.length === b.length && a.every((x, i) => Buffer.from(x).equals(Buffer.from(b[i])));
const book = (n, tag = '') => `${Array.from({ length: n }, (_, i) => `{"line":${i},"text":"${tag}${'é€'.repeat(i % 4)}"}`).join('\n')}\n`;

test('every audit path and every consistency proof up to 48 lines is the library\'s, on a book read in pieces', async () => {
  const text = book(48);
  const tree = bookTree();
  // Read as the book grows: a few lines, then more, then the rest.
  for (const n of [1, 5, 17, 48]) await tree.extend(book(48).split('\n').slice(0, n).join('\n') + '\n');
  assert.equal(tree.size, 48);
  for (let n = 1; n <= 48; n++) {
    const leaves = text.split('\n').slice(0, n).map(utf8);
    for (let i = 0; i < n; i++) assert.ok(same(tree.path(i, n), await inclusionPath(leaves, i)), `path of ${i} in ${n}`);
    for (let m = 0; m <= n; m++) {
      const proof = tree.consistency(m, n);
      assert.ok(same(proof, await witnessProof(text, n, m)), `consistency ${m} to ${n}`);
      if (m > 0 && m < n) assert.equal(await verifyConsistency(m, n, tree.root(m), tree.root(n), proof), true);
    }
  }
});

test('an empty line is a leaf, as the library takes it, though no book holds one', async () => {
  const text = '{"a":1}\n\n{"c":3}\n{"d":4}\n';
  const tree = bookTree();
  await tree.extend(text);
  assert.equal(tree.size, 4);
  for (let n = 1; n <= 4; n++) {
    assert.ok(same(tree.path(0, n), await witnessProof(text, n, null)), `path in ${n}`);
    for (let m = 0; m <= n; m++) assert.ok(same(tree.consistency(m, n), await witnessProof(text, n, m)), `consistency ${m} to ${n}`);
  }
});

test('a book that does not go on from what was read is read again from its start', async () => {
  const tree = bookTree();
  await tree.extend(book(10, 'a'));
  await tree.extend(book(12, 'b'));
  assert.equal(tree.size, 12);
  assert.ok(same(tree.path(0, 12), await witnessProof(book(12, 'b'), 12, null)));
  assert.throws(() => tree.path(0, 13), RangeError);
  assert.throws(() => tree.consistency(13, 12), RangeError);
});

test('the trees held: a book the recorder holds keeps its tree only while it holds it; a kept book\'s tree, while its file is the same version, two at most', async () => {
  const text = { A: book(5, 'a'), B: book(7, 'b'), C: book(3, 'c') };
  const memory = (key) => ({ key, kind: 'memory', text: () => text[key], version: () => text[key].length });
  const versions = { F1: 'one', F2: 'one', F3: 'one' };
  const file = (key) => ({ key, kind: 'file', text: () => book(4, key), version: () => versions[key] });
  let now = [memory('A')];
  const trees = proofTrees(() => now);
  await trees.of(now[0]);
  assert.deepEqual(trees.keys(), ['A']);
  // A new book: the one before is held open beside it while a call allowed under it may come back.
  now = [memory('A'), memory('B')];
  await trees.of(now[1]);
  assert.deepEqual(trees.keys().sort(), ['A', 'B'], 'a book still held keeps its tree');
  // Kept, and no longer held: its tree is let go at the next use of a tree.
  now = [file('F1'), memory('B')];
  await trees.of(now[1]);
  assert.deepEqual(trees.keys(), ['B'], 'the tree of a book no longer held is let go');
  // Another new book, while the trees of kept books are made from their files: two of those at most.
  now = [file('F1'), file('F2'), file('F3'), memory('C')];
  for (const b of now) await trees.of(b);
  assert.deepEqual(trees.keys().sort(), ['C', 'F2', 'F3']);
  // A kept book whose file is another version is read again.
  const before = await trees.of(now[2]);
  versions.F3 = 'two';
  assert.notEqual(await trees.of(now[2]), before, 'a new tree for a file of another version');
  assert.ok(same((await trees.of(memory('C'))).path(0, 3), await witnessProof(text.C, 3, null)));
});

test('a kept book\'s file is read once while its version stays the same, also for uses at the same moment; read again once it changes', async () => {
  let reads = 0;
  let version = 'one';
  const kept = { key: 'F', kind: 'file', text: () => (reads++, book(9, 'k')), version: () => version };
  const trees = proofTrees(() => [kept]);
  const first = await trees.of(kept);
  assert.equal(reads, 1);
  // Two further uses, and two at the same moment: no further read.
  await trees.of(kept);
  await trees.of(kept);
  const both = await Promise.all([trees.of(kept), trees.of(kept)]);
  assert.equal(reads, 1, 'no further read of a kept book whose version is the same');
  assert.ok(both.every((t) => t === first));
  assert.ok(same(first.path(0, 9), await witnessProof(book(9, 'k'), 9, null)));
  // Another version of the file: read again, once.
  version = 'two';
  await trees.of(kept);
  await trees.of(kept);
  assert.equal(reads, 2);
  // Another version, asked for twice at the same moment before it is built: read once.
  version = 'three';
  await Promise.all([trees.of(kept), trees.of(kept)]);
  assert.equal(reads, 3);
  // A read that fails builds nothing, and is tried again at the next use.
  let failing = true;
  const flaky = { key: 'G', kind: 'file', text: () => { if (failing) throw new Error('held by another program'); reads++; return book(4, 'g'); }, version: () => 'one' };
  const others = proofTrees(() => [flaky]);
  await assert.rejects(others.of(flaky), /held by another program/);
  failing = false;
  assert.equal((await others.of(flaky)).size, 4);
});

test('a kept book changed in its middle, kept to the same size and given its old modification time, reads as another version', async () => {
  const folder = tempFolder('provared-fv-');
  const path = join(folder, 'book-1.jsonl');
  const at = new Date('2026-10-01T00:00:00Z');
  writeFileSync(path, book(6, 'a'));
  utimesSync(path, at, at);
  const before = fileVersion(path);
  // NTFS was seen not to move the change time for a change made within a moment of the one before.
  await new Promise((r) => setTimeout(r, 2000));
  writeFileSync(path, book(6, 'b'));
  utimesSync(path, at, at);
  assert.equal(statSync(path).mtimeMs, at.getTime(), 'the same modification time');
  assert.notEqual(fileVersion(path), before);
  assert.equal(fileVersion(join(folder, 'none.jsonl')), 'gone');
});
