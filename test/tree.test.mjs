// The tree of fingerprints, against the well-known test values for the
// Merkle tree of RFC 6962, section 2.1.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { inclusionPath, leafHash, treeRoot, verifyInclusion } from '../src/tree.js';

const hex = (text) => new Uint8Array(Buffer.from(text, 'hex'));
const toHex = (bytes) => Buffer.from(bytes).toString('hex');

// The eight test leaves used with RFC 6962 trees, and the root of the tree
// over the first 1, 2, … 8 of them.
const LEAVES = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'].map(hex);
const ROOTS = [
  '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
  'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
  'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
  'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
  '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
  '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
  'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
  '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
];

test('the root of no leaves is the hash of nothing', async () => {
  assert.equal(toHex(await treeRoot([])), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('a leaf is hashed with a leading 0x00', async () => {
  assert.equal(toHex(await leafHash(hex(''))), ROOTS[0]);
  assert.equal(toHex(await leafHash(hex('00'))), '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7');
});

test('the roots of the test trees of 1 to 8 leaves', async () => {
  for (let n = 1; n <= 8; n++) {
    assert.equal(toHex(await treeRoot(LEAVES.slice(0, n))), ROOTS[n - 1], `tree of ${n}`);
  }
});

test('the audit path of the first leaf in the tree of 8', async () => {
  const path = await inclusionPath(LEAVES, 0);
  assert.deepEqual(path.map(toHex), [
    '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7',
    '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
    '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4',
  ]);
});

// Trees of every size up to 33, with leaves that differ from each other.
const manyLeaves = (n) => Array.from({ length: n }, (_, i) => new Uint8Array([i, i * 7, 0xab]));

test('every leaf of every tree up to 33 leaves has a path that checks', async () => {
  for (let n = 1; n <= 33; n++) {
    const leaves = manyLeaves(n);
    const root = await treeRoot(leaves);
    for (let i = 0; i < n; i++) {
      const path = await inclusionPath(leaves, i);
      assert.equal(await verifyInclusion(i, n, leaves[i], path, root), true, `leaf ${i} of ${n}`);
    }
  }
});

test('a path does not check for another leaf, place or root, nor when changed', async () => {
  for (const n of [2, 5, 8, 13]) {
    const leaves = manyLeaves(n);
    const root = await treeRoot(leaves);
    for (let i = 0; i < n; i++) {
      const path = await inclusionPath(leaves, i);
      const other = (i + 1) % n;
      assert.equal(await verifyInclusion(i, n, leaves[other], path, root), false, 'another leaf');
      assert.equal(await verifyInclusion(other, n, leaves[i], path, root), false, 'another place');
      assert.equal(await verifyInclusion(i, n, leaves[i], path, await treeRoot(manyLeaves(n + 1))), false, 'another root');
      assert.equal(await verifyInclusion(i, n, leaves[i], path.slice(1), root), false, 'a shorter path');
      assert.equal(await verifyInclusion(i, n, leaves[i], [...path, path[0]], root), false, 'a longer path');
      const changed = path.map((p) => p.slice());
      changed[0][0] ^= 1;
      assert.equal(await verifyInclusion(i, n, leaves[i], changed, root), false, 'a changed path');
    }
  }
});

test('the top fingerprint alone does not fix the size of the tree', async () => {
  // A known property of this tree: the first leaf of 5 has a path of the
  // same shape as the first leaf of 6. RFC 6962 therefore signs the size
  // beside the root. The format description, section 10, says the same.
  const leaves = manyLeaves(5);
  const root = await treeRoot(leaves);
  const path = await inclusionPath(leaves, 0);
  assert.equal(await verifyInclusion(0, 5, leaves[0], path, root), true);
  assert.equal(await verifyInclusion(0, 6, leaves[0], path, root), true);
  assert.equal(await verifyInclusion(0, 4, leaves[0], path, root), false);
  assert.equal(await verifyInclusion(0, 9, leaves[0], path, root), false);
});

test('a place outside the tree never checks', async () => {
  const leaves = manyLeaves(4);
  const root = await treeRoot(leaves);
  const path = await inclusionPath(leaves, 0);
  for (const index of [-1, 4, 5, 1.5, NaN, Infinity]) {
    assert.equal(await verifyInclusion(index, 4, leaves[0], path, root), false);
  }
  assert.equal(await verifyInclusion(0, 0, leaves[0], [], root), false);
  await assert.rejects(inclusionPath(leaves, 4), RangeError);
});

test('a node is not a leaf: the two are hashed differently', async () => {
  // The root of two leaves, offered as the data of a single leaf, gives a
  // different root. This is what the 0x00 and 0x01 prefixes are for.
  const two = manyLeaves(2);
  const root = await treeRoot(two);
  assert.notEqual(toHex(await treeRoot([root])), toHex(root));
});
