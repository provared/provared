// Consistency proofs (RFC 9162, section 2.1.4): the library's are compared
// with a second implementation, written here from the RFC alone, for every
// pair of tree sizes up to 64 leaves, and changed proofs must fail.
//
// The second implementation makes a proof by the recursive definition of
// section 2.1.4.1, on the leaves' data, with its own Merkle Tree Hash
// (section 2.1.1). It checks a proof by following the same recursion back:
// it takes the values from the end of the proof, as SUBPROOF puts them
// there, and works out both roots. The library checks a proof with the
// steps of section 2.1.4.2, which are written differently.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';

import { consistencyProof, treeRoot, verifyConsistency } from '../src/tree.js';

const hash = (...parts) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};
const LEAF = Uint8Array.of(0);
const NODE = Uint8Array.of(1);

// Section 2.1.1: MTH({}) = HASH(); MTH({d0}) = HASH(0x00 || d0);
// MTH(D[n]) = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n])), k the largest power of two smaller than n.
function mth(data) {
  if (data.length === 0) return hash();
  if (data.length === 1) return hash(LEAF, data[0]);
  let k = 1;
  while (k * 2 < data.length) k *= 2;
  return hash(NODE, mth(data.slice(0, k)), mth(data.slice(k)));
}

// Section 2.1.4.1.
function subproof(m, data, b) {
  const n = data.length;
  if (m === n) return b ? [] : [mth(data)];
  let k = 1;
  while (k * 2 < n) k *= 2;
  if (m <= k) return [...subproof(m, data.slice(0, k), b), mth(data.slice(k))];
  return [...subproof(m - k, data.slice(k), false), mth(data.slice(0, k))];
}
const proofOf = (data, m) => subproof(m, data, true);

// The recursion of section 2.1.4.1 followed back: for a subtree of n
// leaves of which the first m belong to the earlier tree, the two roots.
function rootsFrom(m, n, b, proof, rootM) {
  if (m === n) {
    if (b) return { old: rootM, now: rootM };
    if (proof.length === 0) return null;
    const h = proof.pop();
    return { old: h, now: h };
  }
  if (proof.length === 0) return null;
  let k = 1;
  while (k * 2 < n) k *= 2;
  if (m <= k) {
    const right = proof.pop();
    const sub = rootsFrom(m, k, b, proof, rootM);
    return sub && { old: sub.old, now: hash(NODE, sub.now, right) };
  }
  const left = proof.pop();
  const sub = rootsFrom(m - k, n - k, false, proof, rootM);
  return sub && { old: hash(NODE, left, sub.old), now: hash(NODE, left, sub.now) };
}
function checkByRecursion(m, n, rootM, rootN, proof) {
  if (m === n) return proof.length === 0 && Buffer.from(rootM).equals(Buffer.from(rootN));
  const left = proof.slice();
  const roots = rootsFrom(m, n, true, left, rootM);
  return roots !== null && left.length === 0 && Buffer.from(roots.old).equals(Buffer.from(rootM)) && Buffer.from(roots.now).equals(Buffer.from(rootN));
}

const MOST = 64;
const data = Array.from({ length: MOST }, (_, i) => new TextEncoder().encode(`leaf ${i}`));
const roots = [hash(), ...data.map((_, i) => mth(data.slice(0, i + 1)))];

test('the library makes the same proof as the definition, for every pair m <= n up to 64 leaves', async () => {
  for (let n = 1; n <= MOST; n++) {
    assert.deepEqual(await treeRoot(data.slice(0, n)), roots[n], `the root of ${n}`);
    for (let m = 1; m <= n; m++) {
      const mine = await consistencyProof(data.slice(0, n), m);
      const theirs = proofOf(data.slice(0, n), m);
      assert.deepEqual(mine, theirs, `${m} to ${n}`);
    }
  }
});

test('every proof checks, in the library and by the recursion, and nothing else of those sizes does', async () => {
  for (let n = 1; n <= MOST; n++) {
    for (let m = 1; m <= n; m++) {
      const proof = proofOf(data.slice(0, n), m);
      assert.equal(await verifyConsistency(m, n, roots[m], roots[n], proof), true, `${m} to ${n}`);
      assert.equal(checkByRecursion(m, n, roots[m], roots[n], proof), true, `${m} to ${n}, by the recursion`);
      // The wrong roots.
      if (m < n) {
        assert.equal(await verifyConsistency(m, n, roots[m], roots[n - 1], proof), false, `${m} to ${n}, the wrong later root`);
        assert.equal(await verifyConsistency(m, n, roots[m - 1], roots[n], proof), false, `${m} to ${n}, the wrong earlier root`);
        assert.equal(await verifyConsistency(m, n, roots[n], roots[m], proof), false, `${m} to ${n}, the roots swapped`);
        // The wrong sizes, with the same proof.
        if (m + 1 < n) assert.equal(await verifyConsistency(m + 1, n, roots[m + 1], roots[n], proof), false, `${m} to ${n}, as from ${m + 1}`);
        if (n < MOST) assert.equal(await verifyConsistency(m, n + 1, roots[m], roots[n + 1], proof), false, `${m} to ${n}, as to ${n + 1}`);
      }
    }
  }
});

test('a changed proof fails, in the library and by the recursion', async () => {
  for (let n = 2; n <= MOST; n++) {
    for (let m = 1; m < n; m++) {
      const proof = proofOf(data.slice(0, n), m);
      const changes = [];
      for (let i = 0; i < proof.length; i++) {
        const flipped = proof.map((p) => p.slice());
        flipped[i][i % 32] ^= 1;
        changes.push([`value ${i} changed`, flipped]);
        changes.push([`value ${i} left out`, proof.filter((_, j) => j !== i)]);
      }
      changes.push(['a value added at the end', [...proof, roots[1]]]);
      changes.push(['a value added at the start', [roots[1], ...proof]]);
      changes.push(['the earlier root added at the start', [roots[m], ...proof]]);
      changes.push(['no values', []]);
      if (proof.length > 1) changes.push(['two values swapped', [proof[1], proof[0], ...proof.slice(2)]]);
      for (const [what, changed] of changes) {
        // Adding the earlier root at the start is exactly what step 2 of section 2.1.4.2 does for a power of two.
        const same = changed.length === proof.length && changed.every((p, i) => Buffer.from(p).equals(Buffer.from(proof[i])));
        if (same) continue;
        assert.equal(await verifyConsistency(m, n, roots[m], roots[n], changed), false, `${m} to ${n}: ${what}`);
        assert.equal(checkByRecursion(m, n, roots[m], roots[n], changed), false, `${m} to ${n}: ${what}, by the recursion`);
      }
    }
  }
});

test('a sound proof, with its own two roots, offered as a proof between other sizes: the two checkers agree, and the size steps refuse', async () => {
  // Without the size steps of section 2.1.4.2 ("if sn is 0, stop and fail" in the loop, and "sn is 0" at the end)
  // many of these would pass: the proof of 1 to 2 as one of 1 to 3, the proof of 7 to 8 as one of 3 to 4.
  const MOST_HERE = 20;
  for (let n = 2; n <= MOST_HERE; n++) {
    for (let m = 1; m < n; m++) {
      const proof = proofOf(data.slice(0, n), m);
      for (let n2 = 2; n2 <= MOST_HERE; n2++) {
        for (let m2 = 1; m2 < n2; m2++) {
          if (m2 === m && n2 === n) continue;
          // A root is any 32 bytes to a checker, so some of these are sound proofs between trees of other leaves: the
          // two checkers must agree on every one.
          assert.equal(await verifyConsistency(m2, n2, roots[m], roots[n], proof), checkByRecursion(m2, n2, roots[m], roots[n], proof), `${m} to ${n}, offered as ${m2} to ${n2}`);
        }
      }
    }
  }
  // These the steps refuse only by the sizes; they were found by trying the steps without those two checks.
  for (const [m, n, m2, n2] of [[1, 2, 1, 3], [1, 2, 1, 4], [3, 4, 3, 5], [7, 8, 3, 4], [7, 8, 5, 6], [7, 8, 6, 7], [7, 8, 9, 10], [6, 8, 6, 12], [5, 9, 5, 7]]) {
    assert.equal(await verifyConsistency(m2, n2, roots[m], roots[n], proofOf(data.slice(0, n), m)), false, `${m} to ${n}, offered as ${m2} to ${n2}`);
  }
});

test('the edges: m equal to n, m of 0, m a power of two, an empty proof', async () => {
  // m equal to n: an empty proof, and the two roots the same.
  assert.deepEqual(await consistencyProof(data.slice(0, 7), 7), []);
  assert.equal(await verifyConsistency(7, 7, roots[7], roots[7], []), true);
  assert.equal(await verifyConsistency(7, 7, roots[7], roots[6], []), false);
  assert.equal(await verifyConsistency(7, 7, roots[7], roots[7], [roots[7]]), false);
  // m of 0: an empty proof; the earlier root must be the root of the empty tree.
  assert.deepEqual(await consistencyProof(data.slice(0, 5), 0), []);
  assert.equal(await verifyConsistency(0, 5, hash(), roots[5], []), true);
  assert.equal(await verifyConsistency(0, 5, roots[1], roots[5], []), false);
  assert.equal(await verifyConsistency(0, 5, hash(), roots[5], [roots[5]]), false);
  assert.equal(await verifyConsistency(0, 0, hash(), hash(), []), true);
  // m a power of two: its proof does not hold its own root, which the steps put first.
  for (const m of [1, 2, 4, 8, 16, 32]) {
    const proof = await consistencyProof(data.slice(0, MOST), m);
    assert.ok(!proof.some((p) => Buffer.from(p).equals(Buffer.from(roots[m]))), `${m}`);
    assert.equal(await verifyConsistency(m, MOST, roots[m], roots[MOST], proof), true, `${m}`);
  }
  // m larger than n: without that rule the steps would take the proof of 3 to 4 as one of 7 to 3.
  assert.equal(await verifyConsistency(7, 3, roots[3], roots[4], await consistencyProof(data.slice(0, 4), 3)), false);
  for (let n = 2; n <= 16; n++) for (let m = 1; m < n; m++) {
    const proof = proofOf(data.slice(0, n), m);
    for (let a = 2; a <= 16; a++) for (let b = 1; b < a; b++) assert.equal(await verifyConsistency(a, b, roots[m], roots[n], proof), false, `${m} to ${n} as ${a} to ${b}`);
  }
  // An empty proof between two different sizes fails.
  assert.equal(await verifyConsistency(3, 5, roots[3], roots[5], []), false);
  assert.equal(await verifyConsistency(4, 8, roots[4], roots[8], []), false);
});

test('anything that is not a proof of those sizes gives false, and making one checks its sizes', async () => {
  const proof = await consistencyProof(data.slice(0, 10), 3);
  const cases = [
    [3.5, 10, roots[3], roots[10], proof],
    [-1, 10, roots[3], roots[10], proof],
    [11, 10, roots[3], roots[10], proof],
    [3, 2 ** 53, roots[3], roots[10], proof],
    ['3', 10, roots[3], roots[10], proof],
    [3, 10, roots[3].slice(0, 31), roots[10], proof],
    [3, 10, roots[3], 'x', proof],
    [3, 10, roots[3], roots[10], 'x'],
    [3, 10, roots[3], roots[10], [...proof.slice(0, -1), proof[proof.length - 1].slice(0, 31)]],
    [3, 10, roots[3], roots[10], [...proof.slice(0, -1), 5]],
  ];
  for (const [i, c] of cases.entries()) assert.equal(await verifyConsistency(...c), false, `case ${i}`);
  // A list with a gap is not a proof.
  const gapped = proof.slice();
  gapped.length += 1;
  assert.equal(await verifyConsistency(3, 10, roots[3], roots[10], gapped), false);
  await assert.rejects(consistencyProof(data.slice(0, 4), 5), RangeError);
  await assert.rejects(consistencyProof(data.slice(0, 4), -1), RangeError);
  await assert.rejects(consistencyProof(data.slice(0, 4), 1.5), RangeError);
  await assert.rejects(consistencyProof('x', 1), TypeError);
});

test('a large tree: sizes past 2 to the power 31 are not cut to 32 bits', async () => {
  // Only the steps that work on sizes are reached here: the proof is of the wrong length, and fails.
  assert.equal(await verifyConsistency(2 ** 32, 2 ** 32 + 1, roots[1], roots[2], [roots[1]]), false);
  assert.equal(await verifyConsistency(2 ** 31 + 1, 2 ** 32, roots[1], roots[2], [roots[1], roots[2]]), false);
});
