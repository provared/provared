// The proofs a witness is shown (RFC 9162, section 2.1), made from a
// book's leaf hashes, kept as the book grows, so that no proof hashes the
// whole book again. The library's witnessProof makes the same proofs from
// the book's text, hashing every line each time: on a book near 100 MB that
// took about two seconds, and held the program up for half a second at a
// time, while a tool call's question waited (the independent review of step
// 7b). The tests compare these proofs with the library's for every pair of
// sizes up to 64 lines; a witness checks every proof it is shown, so a wrong
// one is refused, never taken.
//
// A leaf's hash is SHA-256 of 0x00 and the line's bytes (its text in UTF-8,
// without its line break); a node's, SHA-256 of 0x01 and its two children
// (RFC 9162, section 2.1.1). The hashes of every complete block of 2^j
// leaves, aligned on a multiple of 2^j, are kept, level by level; any other
// subtree's hash is worked out from at most two of them at each level.

import nodeCrypto from 'node:crypto';

const ZERO = Buffer.from([0]);
const ONE = Buffer.from([1]);
const leafHash = (bytes) => nodeCrypto.createHash('sha256').update(ZERO).update(bytes).digest();
const nodeHash = (left, right) => nodeCrypto.createHash('sha256').update(ONE).update(left).update(right).digest();

// The largest power of two below n (n at least 2), found by doubling, not with the bit operators, which hold 32 bits.
const split = (n) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};
const isPower = (n) => {
  let k = 1;
  while (k < n) k *= 2;
  return k === n;
};

/** Hashes of 32 bytes, kept in pieces of 32 KB, so that a book of 100,000 lines costs a few megabytes. */
function hashList() {
  const pieces = [];
  let length = 0;
  const PER = 1024;
  return {
    get length() { return length; },
    push(hash) {
      if (length % PER === 0) pieces.push(Buffer.alloc(PER * 32));
      hash.copy(pieces[pieces.length - 1], (length % PER) * 32);
      length++;
    },
    get(i) {
      const piece = pieces[Math.floor(i / PER)];
      const at = (i % PER) * 32;
      return piece.subarray(at, at + 32);
    },
  };
}

/**
 * The tree of a book, kept as it grows: extend it with the book's text as
 * it now stands, then ask for the audit path of a line, or the consistency
 * proof between two sizes.
 *
 * WHAT IT TRUSTS. The text handed to extend must go on from the text handed
 * before it: the lines already read are not read again. It checks only that
 * the text is not shorter, and that the last 64 characters already read are
 * the same; where either fails, it reads the text again from its start. A
 * text changed earlier than that, keeping those 64 characters, gives a tree
 * of the old lines and the new, and so wrong proofs. Checking more would
 * mean reading the whole text again at each extension, which is what this
 * tree is for avoiding. So a caller whose text could change in its middle
 * makes a new tree instead. The recorder does: a book it holds is its own
 * copy, which only grows, and a kept book's tree is thrown away whenever its
 * file's size, times or identity change (fileVersion, in recorder.mjs). A
 * wrong proof costs only availability: a witness checks every proof it is
 * shown, and refuses a wrong one.
 */
export function bookTree() {
  let levels = [hashList()];
  let read = 0;
  let tail = '';
  const add = (hash) => {
    levels[0].push(hash);
    for (let j = 0; levels[j].length % 2 === 0; j++) {
      if (!levels[j + 1]) levels.push(hashList());
      levels[j + 1].push(nodeHash(levels[j].get(levels[j].length - 2), levels[j].get(levels[j].length - 1)));
    }
  };
  // The hash of the subtree of the n leaves from leaf a.
  const mth = (a, n) => {
    if (n === 1) return levels[0].get(a);
    if (isPower(n) && a % n === 0) {
      let j = 0;
      for (let k = 1; k < n; k *= 2) j++;
      if (levels[j] && levels[j].length > a / n) return levels[j].get(a / n);
    }
    const k = split(n);
    return nodeHash(mth(a, k), mth(a + k, n - k));
  };
  // RFC 9162, section 2.1.3.1: the audit path of leaf m among the n leaves from leaf a.
  const path = (m, a, n) => {
    if (n === 1) return [];
    const k = split(n);
    return m < k ? [...path(m, a, k), mth(a + k, n - k)] : [...path(m - k, a + k, n - k), mth(a, k)];
  };
  // RFC 9162, section 2.1.4.1: SUBPROOF(m, D[a:a+n], b).
  const subproof = (m, a, n, b) => {
    if (m === n) return b ? [] : [mth(a, n)];
    const k = split(n);
    if (m <= k) return [...subproof(m, a, k, b), mth(a + k, n - k)];
    return [...subproof(m - k, a + k, n - k, false), mth(a, k)];
  };
  const copy = (hashes) => hashes.map((h) => new Uint8Array(h));
  const enough = (n) => {
    if (!Number.isSafeInteger(n) || n < 1 || n > levels[0].length) throw new RangeError('the book has no such number of entries');
  };
  return {
    /** How many lines are hashed. */
    get size() { return levels[0].length; },
    /**
     * Hash the lines the text gained since it was last read, a piece at a
     * time, giving way to other work between pieces.
     */
    async extend(text) {
      if (text.length < read || (read > 0 && text.slice(Math.max(0, read - 64), read) !== tail)) {
        levels = [hashList()];
        read = 0;
      }
      let since = 0;
      for (let end = text.indexOf('\n', read); end >= 0; end = text.indexOf('\n', read)) {
        // Every line is a leaf, as writeSeal and witnessProof take them (an empty one too, though no book holds one).
        add(leafHash(Buffer.from(text.slice(read, end), 'utf8')));
        since += end + 1 - read;
        read = end + 1;
        if (since > 1024 * 1024) {
          since = 0;
          await new Promise((r) => setImmediate(r));
        }
      }
      tail = text.slice(Math.max(0, read - 64), read);
    },
    /** The audit path of the line at place "index" in the tree of the first n lines (RFC 9162, section 2.1.3). */
    path(index, n) {
      enough(n);
      if (!Number.isSafeInteger(index) || index < 0 || index >= n) throw new RangeError('no such line');
      return copy(path(index, 0, n));
    },
    /** The consistency proof from the first m lines to the first n (RFC 9162, section 2.1.4); empty for m of 0 or m equal to n. */
    consistency(m, n) {
      enough(n);
      if (!Number.isSafeInteger(m) || m < 0 || m > n) throw new RangeError('no such earlier size');
      return m === 0 || m === n ? [] : copy(subproof(m, 0, n, true));
    },
    /** The top fingerprint of the first n lines. */
    root(n) {
      enough(n);
      return new Uint8Array(mth(0, n));
    },
  };
}
