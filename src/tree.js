// The tree of fingerprints: a Merkle tree built exactly as RFC 6962
// (Certificate Transparency), section 2.1, sets out, with SHA-256.
//
//   leaf  = SHA-256(0x00 || data)
//   node  = SHA-256(0x01 || left || right)
//   a tree of n leaves splits at the largest power of two smaller than n
//
// The proof that one leaf is in the tree is the audit path of section
// 2.1.1. It is checked with the steps of RFC 9162, section 2.1.3.2.

import { concatBytes, equalBytes, sha256 } from './encoding.js';

const LEAF = new Uint8Array([0x00]);
const NODE = new Uint8Array([0x01]);

/** @param {Uint8Array} data @returns {Promise<Uint8Array>} */
export function leafHash(data) {
  return sha256(concatBytes(LEAF, data));
}

function nodeHash(left, right) {
  return sha256(concatBytes(NODE, left, right));
}

// Every level of the tree, from the leaf hashes up to the root. Pairing
// neighbours and carrying a last odd node up unchanged gives the same tree
// as the recursive definition in RFC 6962: the test vectors prove it.
async function levels(leafHashes) {
  const all = [leafHashes];
  let level = leafHashes;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i + 1 < level.length; i += 2) next.push(await nodeHash(level[i], level[i + 1]));
    if (level.length % 2 === 1) next.push(level[level.length - 1]);
    all.push(next);
    level = next;
  }
  return all;
}

/**
 * The root of the tree over the given leaves: the top fingerprint.
 * @param {Uint8Array[]} leaves the data of each leaf
 * @returns {Promise<Uint8Array>} 32 bytes; for no leaves, the hash of nothing, as RFC 6962 defines
 */
export async function treeRoot(leaves) {
  if (leaves.length === 0) return sha256(new Uint8Array(0));
  const hashes = [];
  for (const leaf of leaves) hashes.push(await leafHash(leaf));
  const all = await levels(hashes);
  return all[all.length - 1][0];
}

/**
 * Work out the root as the leaves arrive, one at a time, so that the root of
 * the first n leaves is at hand after each. It keeps one fingerprint for
 * each complete part of the tree and folds them together from the right.
 * This is the same tree as treeRoot gives: the tests compare the two at
 * every size.
 */
export function treeBuilder(from = []) {
  /** @type {{hash: Uint8Array, size: number}[]} */
  const parts = from.slice();
  return {
    /** A builder that carries on from here by itself: what is added to one is not added to the other. */
    fork() {
      return treeBuilder(parts);
    },
    /** @param {Uint8Array} leaf the data of the next leaf */
    async add(leaf) {
      let node = { hash: await leafHash(leaf), size: 1 };
      while (parts.length && parts[parts.length - 1].size === node.size) {
        const left = parts.pop();
        node = { hash: await nodeHash(left.hash, node.hash), size: left.size * 2 };
      }
      parts.push(node);
    },
    /** @returns {Promise<Uint8Array>} the root of the leaves added so far */
    async root() {
      if (parts.length === 0) return sha256(new Uint8Array(0));
      let hash = parts[parts.length - 1].hash;
      for (let i = parts.length - 2; i >= 0; i--) hash = await nodeHash(parts[i].hash, hash);
      return hash;
    },
  };
}

/**
 * The audit path for one leaf: the fingerprints needed to work out the root
 * from that leaf alone.
 * @param {Uint8Array[]} leaves
 * @param {number} index which leaf, counting from 0
 * @returns {Promise<Uint8Array[]>}
 */
export async function inclusionPath(leaves, index) {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) throw new RangeError('no such leaf');
  const hashes = [];
  for (const leaf of leaves) hashes.push(await leafHash(leaf));
  const all = await levels(hashes);
  const path = [];
  let at = index;
  for (let depth = 0; depth < all.length - 1; depth++) {
    const level = all[depth];
    if (at % 2 === 1) path.push(level[at - 1]);
    else if (at + 1 < level.length) path.push(level[at + 1]);
    // else: a last odd node, carried up with no neighbour at this level.
    at = Math.floor(at / 2);
  }
  return path;
}

/**
 * Check an audit path (RFC 9162, section 2.1.3.2).
 * @param {number} index which leaf, counting from 0
 * @param {number} size how many leaves the tree has
 * @param {Uint8Array} leaf the data of the leaf
 * @param {Uint8Array[]} path
 * @param {Uint8Array} root
 * @returns {Promise<boolean>}
 */
export async function verifyInclusion(index, size, leaf, path, root) {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = await leafHash(leaf);
  for (const p of path) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && equalBytes(r, root);
}
