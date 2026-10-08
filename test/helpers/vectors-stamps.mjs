// Shared test cases for the tree of fingerprints, DER, outside time-stamps,
// block time-stamps, the chain of block headers and the seal.
//
// Every key, time-stamp service, block and chain here is made up for the
// tests. Nothing is sent anywhere.

import { createHash, generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { blockFingerprint, blockStampItem, checkBlockStamp } from '../../src/blockstamp.js';
import { children, ecdsaToRaw, readElement, timeOf, validateDer } from '../../src/der.js';
import { concatBytes, fromBase64url, problemFrom, toBase64url, utf8 } from '../../src/encoding.js';
import { BITCOIN, answerFor, blocksInChain, checkHeaderChain, nextBits, readHeaderChain, startHeaderChain } from '../../src/headers.js';
import { generateKeySet, generateSealKeySet, writeSeal } from '../../src/index.js';
import { decodeStamps, keySetFingerprint, validateSealContent } from '../../src/seal.js';
import { checkStamp } from '../../src/timestamp.js';
import { inclusionPath, leafHash, treeBuilder, treeRoot, verifyInclusion } from '../../src/tree.js';
import { SHA256, blockStatement, header as madeUpHeader, joinAfter, joinBefore, makeBlockStamp, number, pendingStatement, start } from './blockstamp.mjs';
import { answer, finish } from './vector-tools.mjs';

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const H = (text) => Uint8Array.from(Buffer.from(text, 'hex'));
const b64 = (bytes) => toBase64url(bytes);

// A fixed sequence of random choices, so that the cases that rest on it are the same each time.
function randomSource(seed) {
  let s = seed >>> 0;
  const next = () => {
    s = (Math.imul(s, 1103515245) + 12345) >>> 0;
    return s / 2 ** 32;
  };
  return {
    next,
    int: (n) => Math.floor(next() * n),
    bytes: (n) => Uint8Array.from({ length: n }, () => Math.floor(next() * 256)),
    pick: (items) => items[Math.floor(next() * items.length)],
  };
}

/** A copy of some bytes, changed as a case says: one byte flipped, cut short, or more bytes after. */
function changed(bytes, change) {
  let out = Uint8Array.from(bytes);
  if (!change) return out;
  if (change.flip) out[change.flip[0]] ^= change.flip[1];
  if (change.cut !== undefined) out = out.subarray(0, change.cut);
  if (change.append) out = concatBytes(out, H(change.append));
  return out;
}

const bigOf = (text) => BigInt('0x' + text);

/** The rules of a chain, as a case writes them (whole numbers that may be large as hexadecimal). */
function rulesOf(r) {
  if (r === undefined) return undefined;
  const rules = { ...r, limit: bigOf(r.limit) };
  if (r.ease !== undefined) rules.ease = BigInt(r.ease);
  return rules;
}

/** What a chain of headers that has been read shows: the same in every implementation. */
function chainAnswer(chain, c) {
  const height = chain.height;
  const out = { height };
  if (height >= 0) {
    out.tip = chain.fingerprintAt(height);
    out.tipTime = chain.timeAt(height);
    out.size = chain.bytes().length;
    out.lastHash = hex(chain.hashAt(height));
  }
  if (c.lookups) out.found = c.lookups.map((fp) => chain.heightOf(fp));
  if (c.workAfter !== undefined) out.work = chain.workAfter(c.workAfter).toString(16);
  return out;
}

/** How each kind of case is answered. */
export const ANSWER = {
  // --- the tree ---
  leafHash: (c) => answer(async () => hex(await leafHash(H(c.leaf)))),
  treeRoot: (c) => answer(async () => hex(await treeRoot(c.leaves.map(H)))),
  treeBuilder: (c) =>
    answer(async () => {
      const builder = treeBuilder();
      const roots = [hex(await builder.root())];
      let fork = null;
      for (let i = 0; i < c.leaves.length; i++) {
        if (c.forkAt === i) fork = builder.fork();
        await builder.add(H(c.leaves[i]));
        roots.push(hex(await builder.root()));
      }
      if (c.forkAt === c.leaves.length) fork = builder.fork();
      const forkRoots = [];
      if (fork) {
        for (const leaf of c.forkLeaves) {
          await fork.add(H(leaf));
          forkRoots.push(hex(await fork.root()));
        }
      }
      return { roots, forkRoots, after: hex(await builder.root()) };
    }),
  inclusionPath: (c) => answer(async () => (await inclusionPath(c.leaves.map(H), c.index)).map(hex)),
  verifyInclusion: (c) => answer(() => verifyInclusion(c.index, c.size, H(c.leaf), c.path.map(H), H(c.root))),

  // --- DER ---
  readElement: (c) => answer(() => readElement(H(c.bytes), c.at, c.end)),
  children: (c) =>
    answer(() => {
      const bytes = H(c.bytes);
      return children(bytes, readElement(bytes, 0), c.most);
    }),
  validateDer: (c) =>
    answer(() => {
      const bytes = H(c.bytes);
      validateDer(bytes, readElement(bytes, 0));
      return true;
    }),
  timeOf: (c) =>
    answer(() => {
      const bytes = H(c.bytes);
      return timeOf(bytes, readElement(bytes, 0));
    }),
  ecdsaToRaw: (c) => answer(() => hex(ecdsaToRaw(H(c.der), c.size))),

  // --- time-stamps from a service ---
  checkStamp: (c) =>
    answer(() =>
      checkStamp(
        Object.hasOwn(c, 'tokenValue') ? c.tokenValue : changed(fromBase64url(c.token), c.change),
        Object.hasOwn(c, 'stampedValue') ? c.stampedValue : fromBase64url(c.stamped),
        c.options,
      ),
    ),

  // --- block time-stamps ---
  checkBlockStamp: (c) =>
    answer(() =>
      checkBlockStamp(
        Object.hasOwn(c, 'proofValue') ? c.proofValue : changed(H(c.proof), c.change),
        Object.hasOwn(c, 'headerValue') ? c.headerValue : changed(H(c.header), c.headerChange),
        Object.hasOwn(c, 'stampedValue') ? c.stampedValue : H(c.stamped),
        c.trusted,
      ),
    ),
  blockFingerprint: (c) => answer(() => blockFingerprint(H(c.header))),
  blockStampItem: (c) =>
    answer(() =>
      blockStampItem(Object.hasOwn(c, 'proofValue') ? c.proofValue : H(c.proof), Object.hasOwn(c, 'headerValue') ? c.headerValue : H(c.header)),
    ),

  // --- the seal ---
  validateSealContent: (c) =>
    answer(() => {
      validateSealContent(c.content);
      return true;
    }),
  decodeStamps: (c) =>
    answer(() =>
      decodeStamps(c.stamps).map((s) => (s.kind === 'service' ? { kind: s.kind, token: hex(s.token) } : { kind: s.kind, header: hex(s.header), proof: hex(s.proof) })),
    ),
  keySetFingerprint: (c) => answer(() => keySetFingerprint(c.keys)),

  // --- the chain of block headers ---
  nextBits: (c) => answer(() => nextBits(c.bits, c.firstTime, c.lastTime, rulesOf(c.rules))),
  readHeaderChain: (c) =>
    answer(async () => {
      const o = { now: c.now, partial: c.partial };
      if (c.rules) o.rules = rulesOf(c.rules);
      return chainAnswer(await readHeaderChain(changed(H(c.bytes), c.change), o), c);
    }),
  checkHeaderChain: (c) =>
    answer(async () => {
      const r = await checkHeaderChain(Object.hasOwn(c, 'bytesValue') ? c.bytesValue : changed(H(c.bytes), c.change), { now: c.now });
      return { height: r.height, tip: r.tip, tipWhen: r.tipWhen };
    }),
  // A chain of headers worked on step by step: added to, cut back, copied and taken on.
  headerChainSteps: (c) =>
    answer(async () => {
      const chains = [startHeaderChain(rulesOf(c.rules))];
      const out = [];
      for (const step of c.steps) {
        const chain = chains[step.chain ?? 0];
        let r;
        try {
          if (step.op === 'add') {
            await chain.add(Object.hasOwn(step, 'value') ? step.value : H(step.header), step.now);
            r = { height: chain.height };
          } else if (step.op === 'keepTo') {
            chain.keepTo(step.height);
            r = { height: chain.height };
          } else if (step.op === 'copy') {
            chains.push(chain.copy());
            r = { chains: chains.length };
          } else if (step.op === 'adopt') {
            chain.adopt(chains[step.from]);
            r = { height: chain.height };
          } else {
            r = chainAnswer(chain, step);
          }
          out.push({ ok: r });
        } catch (e) {
          out.push({ refused: problemFrom(e) });
        }
      }
      return out;
    }),
  answerFor: (c) =>
    answer(async () => {
      const chain = await readHeaderChain(H(c.bytes), { now: c.now, rules: rulesOf(c.rules) });
      const a = answerFor(chain);
      return { height: a.height, tip: a.tip, tipWhen: a.tipWhen, found: c.lookups.map((fp) => a.find(fp)) };
    }),
  blocksInChain: (c) =>
    answer(() => {
      const table = c.chain;
      const chain = { find: (fp) => (Object.hasOwn(table, fp) ? table[fp] : null) };
      return blocksInChain(c.result, chain);
    }),
};

const vectorSet = (about, fn, cases) => finish(about, fn, cases, ANSWER);

// =====================================================================
// The tree of fingerprints
// =====================================================================

const RFC_LEAVES = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'];

function leavesOf(rand, n, longest = 40) {
  return Array.from({ length: n }, () => hex(rand.bytes(rand.int(longest + 1))));
}

function treeRootCases() {
  const rand = randomSource(6962);
  const cases = [];
  for (let n = 0; n <= RFC_LEAVES.length; n++) cases.push({ name: `the first ${n} of the test leaves of RFC 6962`, leaves: RFC_LEAVES.slice(0, n) });
  for (let n = 0; n <= 70; n++) cases.push({ name: `${n} random leaves`, leaves: leavesOf(rand, n) });
  for (const n of [127, 128, 129, 255, 256, 257, 1000, 1023, 1024, 1025, 3000]) {
    cases.push({ name: `${n} short leaves`, leaves: Array.from({ length: n }, (_, i) => hex(new Uint8Array([i & 0xff, i >> 8]))) });
  }
  cases.push({ name: 'one long leaf', leaves: [hex(rand.bytes(5000))] });
  cases.push({ name: 'the same leaf four times', leaves: ['ab', 'ab', 'ab', 'ab'] });
  return cases;
}

function leafHashCases() {
  const rand = randomSource(1);
  return [...RFC_LEAVES, ...leavesOf(rand, 20, 100)].map((leaf, i) => ({ name: `leaf ${i}: ${leaf.slice(0, 16)}`, leaf }));
}

function treeBuilderCases() {
  const rand = randomSource(2016);
  const cases = [{ name: 'no leaves', leaves: [] }];
  for (let n = 1; n <= 40; n++) cases.push({ name: `${n} leaves`, leaves: leavesOf(rand, n, 12) });
  for (let i = 0; i < 30; i++) {
    const n = 1 + rand.int(30);
    const forkAt = rand.int(n + 1);
    cases.push({ name: `${n} leaves, split off after ${forkAt}`, leaves: leavesOf(rand, n, 12), forkAt, forkLeaves: leavesOf(rand, rand.int(20), 12) });
  }
  cases.push({ name: 'split off at the start', leaves: ['01', '02'], forkAt: 0, forkLeaves: ['01', '02'] });
  cases.push({ name: '300 leaves', leaves: Array.from({ length: 300 }, (_, i) => hex(new Uint8Array([i & 0xff]))) });
  return cases;
}

async function inclusionPathCases() {
  const rand = randomSource(9162);
  const cases = [];
  cases.push({ name: 'the first leaf of the eight test leaves', leaves: RFC_LEAVES, index: 0 });
  for (let n = 1; n <= 20; n++) {
    const leaves = leavesOf(rand, n, 6);
    for (let i = 0; i < n; i++) cases.push({ name: `leaf ${i} of ${n}`, leaves, index: i });
  }
  const leaves = leavesOf(rand, 5, 6);
  for (const index of [-1, 5, 6, 1.5, 2.0, '1', null, true, 1e300, -0, 2 ** 53]) {
    cases.push({ name: `a place ${JSON.stringify(index)} among 5 leaves`, leaves, index });
  }
  cases.push({ name: 'no leaves', leaves: [], index: 0 });
  cases.push({ name: 'leaf 700 of 1000', leaves: Array.from({ length: 1000 }, (_, i) => hex(new Uint8Array([i & 0xff, i >> 8]))), index: 700 });
  return cases;
}

async function verifyInclusionCases() {
  const rand = randomSource(1962);
  const cases = [];
  const add = (name, index, size, leaf, path, root) => cases.push({ name, index, size, leaf, path, root });
  for (let n = 1; n <= 33; n++) {
    const leaves = Array.from({ length: n }, (_, i) => hex(new Uint8Array([i, (i * 7) & 0xff, 0xab])));
    const bytes = leaves.map(H);
    const root = hex(await treeRoot(bytes));
    for (let i = 0; i < n; i++) {
      const path = (await inclusionPath(bytes, i)).map(hex);
      add(`leaf ${i} of ${n}`, i, n, leaves[i], path, root);
    }
  }
  for (const n of [1, 2, 3, 5, 8, 13, 21]) {
    const leaves = leavesOf(rand, n, 8);
    const bytes = leaves.map(H);
    const root = hex(await treeRoot(bytes));
    const otherRoot = hex(await treeRoot([...bytes, H('ff')]));
    for (let i = 0; i < n; i++) {
      const path = (await inclusionPath(bytes, i)).map(hex);
      const other = (i + 1) % n;
      add(`${n}: another leaf at ${i}`, i, n, leaves[other], path, root);
      add(`${n}: another place for ${i}`, other, n, leaves[i], path, root);
      add(`${n}: another root for ${i}`, i, n, leaves[i], path, otherRoot);
      add(`${n}: a shorter path for ${i}`, i, n, leaves[i], path.slice(1), root);
      add(`${n}: a longer path for ${i}`, i, n, leaves[i], [...path, path[0] ?? root], root);
      for (const size of [n - 1, n + 1, n + 2, 2 * n, 0]) add(`${n}: leaf ${i} said to be of a tree of ${size}`, i, size, leaves[i], path, root);
      if (path.length) {
        const flipped = [...path];
        flipped[path.length - 1] = hex(changed(H(path[path.length - 1]), { flip: [31, 1] }));
        add(`${n}: a changed path for ${i}`, i, n, leaves[i], flipped, root);
      }
      add(`${n}: a root cut short for ${i}`, i, n, leaves[i], path, root.slice(0, 62));
    }
  }
  const leaves = leavesOf(rand, 4, 4);
  const root = hex(await treeRoot(leaves.map(H)));
  const path = (await inclusionPath(leaves.map(H), 0)).map(hex);
  for (const index of [-1, 4, 5, 1.5, null, '0', true, 2 ** 53, 1e300, -0]) add(`a place ${JSON.stringify(index)}`, index, 4, leaves[0], path, root);
  for (const size of [1.5, null, '4', true, 2 ** 53, -1]) add(`a size ${JSON.stringify(size)}`, 0, size, leaves[0], path, root);
  add('a tree of none', 0, 0, leaves[0], [], root);
  add('a single leaf with no path', 0, 1, leaves[0], [], hex(await leafHash(H(leaves[0]))));
  add('a single leaf with a path', 0, 1, leaves[0], [root], hex(await leafHash(H(leaves[0]))));
  // The first leaf of 5 and of 6 have paths of the same shape.
  const five = Array.from({ length: 5 }, (_, i) => hex(new Uint8Array([i])));
  const fiveRoot = hex(await treeRoot(five.map(H)));
  const fivePath = (await inclusionPath(five.map(H), 0)).map(hex);
  for (const size of [4, 5, 6, 7, 8, 9]) add(`the first leaf of 5, said to be of ${size}`, 0, size, five[0], fivePath, fiveRoot);
  // Large trees: a few leaves of 100,000.
  const big = Array.from({ length: 100000 }, (_, i) => new Uint8Array([i & 0xff, (i >> 8) & 0xff, i >> 16]));
  const bigRoot = hex(await treeRoot(big));
  for (const i of [0, 1, 65535, 65536, 99998, 99999]) {
    const p = (await inclusionPath(big, i)).map(hex);
    add(`leaf ${i} of 100,000`, i, 100000, hex(big[i]), p, bigRoot);
    add(`leaf ${i} of 100,000, said to be of 100,001`, i, 100001, hex(big[i]), p, bigRoot);
  }
  return cases;
}

// =====================================================================
// DER
// =====================================================================

function der(tag, ...parts) {
  const content = concatBytes(...parts.map((p) => (p instanceof Uint8Array ? p : Uint8Array.from(p))));
  let length;
  if (content.length < 128) length = [content.length];
  else if (content.length < 256) length = [0x81, content.length];
  else length = [0x82, content.length >> 8, content.length & 0xff];
  return concatBytes(new Uint8Array([tag, ...length]), content);
}
const seq = (...parts) => der(0x30, ...parts);
const set = (...parts) => der(0x31, ...parts);
const oid = (h) => der(0x06, H(h));
const octets = (bytes) => der(0x04, bytes);
const NULL = H('0500');
const int = (n) => {
  let v = BigInt(n);
  const digits = [];
  do {
    digits.unshift(Number(v & 0xffn));
    v >>= 8n;
  } while (v > 0n);
  if (digits[0] & 0x80) digits.unshift(0);
  return der(0x02, new Uint8Array(digits));
};
/** A whole number from its bytes, most significant first, in its shortest positive form. */
const intBytes = (bytes) => {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  const digits = bytes.subarray(i);
  return der(0x02, digits[0] & 0x80 ? concatBytes(new Uint8Array([0]), digits) : digits);
};
const bitString = (bytes, unused = 0) => der(0x03, new Uint8Array([unused]), bytes);
const gtime = (text) => der(0x18, utf8(text));
const utime = (text) => der(0x17, utf8(text));
const gtimeOf = (ms) => gtime(new Date(ms).toISOString().slice(0, 19).replace(/[-:T]/g, '') + 'Z');

function readElementCases() {
  const cases = [];
  const add = (name, bytes, at, end) => cases.push({ name, bytes, ...(at === undefined ? { at: 0 } : { at }), ...(end === undefined ? {} : { end }) });
  add('empty', '');
  add('one byte', '30');
  add('an empty sequence', '3000');
  add('a sequence of one byte', '300105');
  add('a sequence cut short', '3001');
  add('a tag of the long form', '1f8100');
  add('a constructed tag of the long form', '3f00');
  add('a context tag of the long form', 'bf00');
  add('the indefinite length', '30800000');
  add('a length in five bytes', '3085000000000100');
  add('a length in one byte, not needed', '30817f' + '00'.repeat(127));
  add('a length in one byte', '308180' + '00'.repeat(128));
  add('a length in two bytes with a leading zero', '30820080' + '00'.repeat(128));
  add('a length in two bytes', '30820100' + '00'.repeat(256));
  add('a length in two bytes that is short enough for one', '308200ff' + '00'.repeat(255));
  add('a length in four bytes', '308400000100' + '00'.repeat(256));
  add('a length in four bytes, far too long', '3084ffffffff');
  add('a length in three bytes, too long', '3083010000');
  add('a length byte cut short', '3082ff');
  add('the long form with no length bytes', '3081');
  add('an element with bytes after it', '30000000');
  add('an element read from the middle', '0000300100', 2);
  add('an element read from the middle, cut by its end', '0000300100', 2, 4);
  add('an element that ends exactly at its end', '0000300100', 2, 5);
  add('an element at the last byte', '000030', 2);
  add('an element at the end', '0000', 2);
  add('a primitive integer', '020105');
  add('an octet string', '0403616263');
  add('a context tag', 'a0020500');
  add('tag 0xff', 'ff00');
  add('tag 0x00', '0000');
  const rand = randomSource(690);
  for (let i = 0; i < 300; i++) {
    const length = rand.int(10);
    const bytes = rand.bytes(length);
    if (length > 1 && rand.next() < 0.5) bytes[1] = rand.pick([0x00, 0x01, 0x02, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, length - 2]);
    add(`random ${i}`, hex(bytes));
  }
  return cases;
}

function childrenCases() {
  const cases = [];
  const add = (name, bytes, most) => cases.push({ name, bytes: hex(bytes), ...(most === undefined ? {} : { most }) });
  add('an empty sequence', seq());
  add('two items', seq(int(1), int(2)));
  add('two items, at most one', seq(int(1), int(2)), 1);
  add('two items, at most two', seq(int(1), int(2)), 2);
  add('thirty-two items', seq(...Array.from({ length: 32 }, () => NULL)));
  add('thirty-three items', seq(...Array.from({ length: 33 }, () => NULL)));
  add('an item longer than what holds it', H('30030203010203'));
  add('an item cut short inside', H('3003020201'));
  add('an item with a long tag', H('30031f0100'));
  add('nested items', seq(seq(int(1)), set(NULL, NULL), octets(H('00'))));
  add('a primitive element with content', octets(H('020101')));
  add('a set of items, at most zero', set(NULL), 0);
  const rand = randomSource(3);
  for (let i = 0; i < 150; i++) {
    const inner = rand.bytes(rand.int(14));
    for (let j = 0; j + 1 < inner.length; j += 2 + rand.int(3)) {
      inner[j] = rand.pick([0x02, 0x04, 0x05, 0x30, 0x31, 0xa0, 0x1f]);
      inner[j + 1] = rand.pick([0, 1, 2, 3, 0x80, 0x81]);
    }
    add(`random ${i}`, concatBytes(new Uint8Array([0x30, inner.length]), inner), rand.pick([undefined, 1, 2, 3, 32]));
  }
  return cases;
}

function nested(depth, inner = NULL) {
  let out = inner;
  for (let i = 0; i < depth; i++) out = seq(out);
  return out;
}

function validateDerCases() {
  const cases = [];
  const add = (name, bytes) => cases.push({ name, bytes: hex(bytes) });
  for (const [name, h] of [
    ['an integer', '020105'],
    ['an empty integer', '0200'],
    ['the integer 0', '020100'],
    ['the integer -1', '0201ff'],
    ['an integer with a needless zero', '0202007f'],
    ['an integer with a needed zero', '02020080'],
    ['an integer with a needless 0xff', '0202ff80'],
    ['an integer with a needed 0xff', '0202ff7f'],
    ['an integer of two zeros', '02020000'],
    ['an object identifier', '06032a0304'],
    ['an empty object identifier', '0600'],
    ['an object identifier cut short', '06022a83'],
    ['an object identifier with a needless 0x80 at its start', '0603802a03'],
    ['an object identifier with a needless 0x80 later', '06032a8001'],
    ['an object identifier with 0x80 inside a number', '06042a818001'],
    ['true', '0101ff'],
    ['false', '010100'],
    ['a truth value of 1', '010101'],
    ['an empty truth value', '0100'],
    ['a truth value of two bytes', '0102ff00'],
    ['null', '0500'],
    ['a null that is not empty', '050100'],
    ['a bit string', '030200ff'],
    ['a bit string with 7 bits unused', '030207ff'],
    ['a bit string with 8 bits unused', '030208ff'],
    ['an empty bit string', '0300'],
    ['a bit string of no bits', '030100'],
    ['an octet string', '0403000102'],
    ['a context tag, primitive', '8003000102'],
    ['a constructed context tag', 'a003020101'],
    ['a constructed context tag with a bad integer', 'a00402020001'],
    ['a constructed octet string', '2403020101'],
    ['a set', '3106020101020102'],
    ['a sequence whose item is longer than it', '30030202000102'],
    ['a sequence with an item cut short', '3004020301'],
    ['a sequence with a stray byte', '300302010100'],
    ['a sequence with a bad integer inside', '300402020001'],
    ['a sequence with a bad truth value inside', '3003010101'],
    ['an unknown primitive tag', '0c03616263'],
    ['an unknown constructed tag', '2c020500'],
    ['a long tag inside', '30031f0100'],
  ]) {
    add(name, H(h));
  }
  add('24 levels inside', nested(24));
  add('25 levels inside', nested(25));
  add('26 levels inside', nested(26));
  add('3,999 parts inside one', seq(...Array.from({ length: 3999 }, () => NULL)));
  add('4,000 parts inside one', seq(...Array.from({ length: 4000 }, () => NULL)));
  add('2,000 pairs', seq(...Array.from({ length: 2000 }, () => seq(NULL))));
  add('1,999 pairs and one', seq(...Array.from({ length: 1999 }, () => seq(NULL)), NULL));
  add('a bad integer after many parts', seq(...Array.from({ length: 50 }, () => int(5)), H('02020001')));
  // Random structures, some broken.
  const rand = randomSource(8825);
  const primitive = () =>
    rand.pick([
      () => int(rand.int(70000)),
      () => H(rand.pick(['0200', '0202007f', '0202ff80', '0201ff', '020180'])),
      () => oid(rand.pick(['2a864886f70d010702', '2b6570', '802a', '2a80', '2a83'])),
      () => H(rand.pick(['0101ff', '010100', '010101', '0100'])),
      () => H(rand.pick(['0500', '050100'])),
      () => H(rand.pick(['030100', '030207ff', '030208ff', '0300'])),
      () => octets(rand.bytes(rand.int(5))),
      () => der(0x80, rand.bytes(rand.int(3))),
    ])();
  const build = (depth) => {
    if (depth > 4 || rand.next() < 0.4) return primitive();
    const n = rand.int(4);
    return der(rand.pick([0x30, 0x31, 0xa0, 0xa3]), ...Array.from({ length: n }, () => build(depth + 1)));
  };
  for (let i = 0; i < 300; i++) {
    let bytes = build(0);
    if (rand.next() < 0.2 && bytes.length > 2) {
      bytes = Uint8Array.from(bytes);
      bytes[rand.int(bytes.length)] ^= 1 << rand.int(8);
    }
    add(`random ${i}`, bytes);
  }
  return cases;
}

function timeOfCases() {
  const cases = [];
  const add = (name, tag, text) => cases.push({ name, bytes: hex(concatBytes(new Uint8Array([tag, Buffer.from(text, 'latin1').length]), Uint8Array.from(Buffer.from(text, 'latin1')))) });
  for (const text of [
    '20261005120000Z',
    '20261005120000.5Z',
    '20261005120000.05Z',
    '20261005120000.999Z',
    '20261005120000.123456789Z',
    '20261005120000.1234567891Z',
    '20261005120000.50Z',
    '20261005120000.Z',
    '20261005120000.0Z',
    '20261005120000.29Z',
    '20261005120000.57Z',
    '20261005120000.001Z',
    '20261005120000',
    '20261005120000+0100',
    '20261005120000z',
    '2026100512000Z',
    '202610051200000Z',
    '20261305120000Z',
    '20260005120000Z',
    '20260230120000Z',
    '20240229120000Z',
    '20230229120000Z',
    '21000229120000Z',
    '20000229120000Z',
    '20260431120000Z',
    '20261000120000Z',
    '20261005240000Z',
    '20261005236000Z',
    '20261005235960Z',
    '20261005235959Z',
    '00000101000000Z',
    '00500101000000Z',
    '00990101000000Z',
    '00991231235959Z',
    '01000101000000Z',
    '09991231235959Z',
    '19700101000000Z',
    '19691231235959Z',
    '99991231235959Z',
    '99991231235959.999999999Z',
    '1970010100000²Z',
    '٢٠٢٦1005120000Z',
    '20261005120000Z\n',
    ' 20261005120000Z',
    '',
  ]) {
    add(`GeneralizedTime ${JSON.stringify(text)}`, 0x18, text);
  }
  for (const text of ['261005120000Z', '991231235959Z', '500101000000Z', '491231235959Z', '000101000000Z', '2610051200Z', '261005120000.5Z', '261305120000Z', '260230120000Z', '240229000000Z', '000229000000Z', '261005120000', '261005120060Z', '20261005120000Z']) {
    add(`UTCTime ${JSON.stringify(text)}`, 0x17, text);
  }
  add('an octet string', 0x04, '20261005120000Z');
  add('a sequence', 0x30, '20261005120000Z');
  return cases;
}

function ecdsaToRawCases() {
  const cases = [];
  const add = (name, bytes, size) => cases.push({ name, der: hex(bytes), size });
  const n32 = (fill) => new Uint8Array(32).fill(fill);
  for (const size of [32, 48]) {
    add(`small numbers, ${size}`, H('3006020105020107'), size);
    add(`numbers with a needed zero, ${size}`, seq(intBytes(n32(0xff)), intBytes(n32(0x80))), size);
    add(`numbers of 32 bytes, ${size}`, seq(intBytes(n32(0x7f)), intBytes(n32(0x01))), size);
    add(`a number of 48 bytes, ${size}`, seq(intBytes(new Uint8Array(48).fill(0x7f)), int(1)), size);
    add(`a number of 49 bytes, ${size}`, seq(intBytes(new Uint8Array(49).fill(0x7f)), int(1)), size);
    add(`a number of 33 bytes, ${size}`, seq(intBytes(new Uint8Array(33).fill(0x11)), int(1)), size);
    add(`zero, ${size}`, H('3006020100020100'), size);
  }
  for (const [name, h] of [
    ['negative', '3006020185020107'],
    ['not in its shortest form', '300702020005020107'],
    ['one number', '3003020105'],
    ['three numbers', '3009020105020107020109'],
    ['bytes left over', '300602010502010700'],
    ['an empty number', '30050200020107'],
    ['an octet string in place of a number', '3006040105020107'],
    ['not a sequence', '3106020105020107'],
    ['cut short', '30060201050201'],
    ['empty', ''],
    ['an empty sequence', '3000'],
    ['a long length', '308106020105020107'],
    ['a second number that is negative', '3006020105020187'],
    ['a second number with a needless zero', '300702010502020007'],
  ]) {
    add(name, H(h), 32);
  }
  const rand = randomSource(4);
  for (let i = 0; i < 100; i++) {
    const a = rand.bytes(1 + rand.int(34));
    const b = rand.bytes(1 + rand.int(34));
    add(`random ${i}`, seq(der(0x02, a), der(0x02, b)), rand.pick([32, 48]));
  }
  return cases;
}

// =====================================================================
// Time-stamps from a service (RFC 3161), made up here
// =====================================================================

const OID = {
  signedData: '2a864886f70d010702',
  data: '2a864886f70d010701',
  tstInfo: '2a864886f70d0109100104',
  contentType: '2a864886f70d010903',
  messageDigest: '2a864886f70d010904',
  signingTime: '2a864886f70d010905',
  signingCertificate: '2a864886f70d010910020c',
  signingCertificateV2: '2a864886f70d010910022f',
  sha1: '2b0e03021a',
  sha256: '608648016503040201',
  sha384: '608648016503040202',
  sha512: '608648016503040203',
  rsaEncryption: '2a864886f70d010101',
  rsaPss: '2a864886f70d01010a',
  sha256WithRsa: '2a864886f70d01010b',
  sha384WithRsa: '2a864886f70d01010c',
  sha512WithRsa: '2a864886f70d01010d',
  ecdsaWithSha256: '2a8648ce3d040302',
  ecdsaWithSha384: '2a8648ce3d040303',
  ecdsaWithSha512: '2a8648ce3d040304',
  ecPublicKey: '2a8648ce3d0201',
  p256: '2a8648ce3d030107',
  p384: '2b81040022',
  secp256k1: '2b8104000a',
  ed25519: '2b6570',
  dsa: '2a8648ce380401',
  commonName: '550403',
  policy: '2a0304',
  someExtension: '2a0305',
};
const HASH_OID = { 'SHA-1': OID.sha1, 'SHA-256': OID.sha256, 'SHA-384': OID.sha384, 'SHA-512': OID.sha512 };
const NODE_HASH = { 'SHA-1': 'sha1', 'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512' };
const RSA_WITH = { 'SHA-256': OID.sha256WithRsa, 'SHA-384': OID.sha384WithRsa, 'SHA-512': OID.sha512WithRsa };
const ECDSA_WITH = { 'SHA-256': OID.ecdsaWithSha256, 'SHA-384': OID.ecdsaWithSha384, 'SHA-512': OID.ecdsaWithSha512 };
const digest = (name, bytes) => new Uint8Array(createHash(NODE_HASH[name]).update(bytes).digest());
const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const WHEN = Date.parse('2026-10-05T12:00:00Z');
const STAMPED = digest('SHA-256', utf8('what was stamped'));
const NAME = seq(set(seq(oid(OID.commonName), der(0x0c, utf8('Made-up time-stamp service (for tests)')))));

function makeKey(kind) {
  let pair;
  if (kind === 'P-256' || kind === 'P-384') pair = generateKeyPairSync('ec', { namedCurve: kind });
  else if (kind === 'Ed25519') pair = generateKeyPairSync('ed25519');
  else {
    const [, bits, e] = /^RSA-(\d+)(?:-e(\d+))?$/.exec(kind);
    pair = generateKeyPairSync('rsa', { modulusLength: Number(bits), publicExponent: Number(e ?? 65537) });
  }
  const type = kind.startsWith('RSA') ? 'rsa' : kind === 'Ed25519' ? 'ed25519' : 'ec';
  return { type, kind, spki: new Uint8Array(pair.publicKey.export({ type: 'spki', format: 'der' })), jwk: pair.publicKey.export({ format: 'jwk' }), privateKey: pair.privateKey };
}

function signWith(key, hash, data) {
  if (key.type === 'ec') return new Uint8Array(nodeSign(NODE_HASH[hash], data, { key: key.privateKey, dsaEncoding: 'der' }));
  if (key.type === 'rsa') return new Uint8Array(nodeSign(NODE_HASH[hash], data, key.privateKey));
  return new Uint8Array(nodeSign(null, data, key.privateKey));
}

function signatureAlgorithm(key, hash) {
  if (key.type === 'rsa') return seq(oid(RSA_WITH[hash] ?? OID.sha256WithRsa), NULL);
  if (key.type === 'ec') return seq(oid(ECDSA_WITH[hash] ?? OID.ecdsaWithSha256));
  return seq(oid(OID.ed25519));
}

/** A certificate for a key. Its own signature is never checked by a time-stamp check, so it is made-up bytes. */
function certificate(key, o = {}) {
  const body = seq(
    ...(o.noVersion ? [] : [der(0xa0, int(2))]),
    int(o.serial ?? 1),
    signatureAlgorithm(key, 'SHA-256'),
    NAME,
    o.validity ?? seq(gtimeOf(o.notBefore ?? Date.parse('2026-01-01T00:00:00Z')), gtimeOf(o.notAfter ?? Date.parse('2036-01-01T00:00:00Z'))),
    NAME,
    o.spki ?? key.spki,
    ...(o.bodyExtra ?? []),
  );
  return seq(o.body ?? body, signatureAlgorithm(key, 'SHA-256'), bitString(H('0011223344556677')));
}

/**
 * A time-stamp, as a service writes one, with every part open to change.
 * "hash" is the signer's fingerprint method.
 */
function makeToken(key, o = {}) {
  const hash = o.hash ?? 'SHA-256';
  const cert = o.cert ?? certificate(key, o.certOptions);
  const statement =
    o.statement ??
    seq(
      int(o.version ?? 1),
      oid(OID.policy),
      seq(o.imprintAlgorithm ?? seq(oid(o.imprintOid ?? OID.sha256), NULL), octets(o.stamped ?? STAMPED)),
      int(o.serial ?? 1000),
      o.time ?? gtimeOf(o.when ?? WHEN),
      ...(o.tail ?? []),
    );
  const attributes = [
    seq(oid(OID.contentType), set(oid(OID.tstInfo))),
    seq(oid(OID.messageDigest), set(octets(digest(hash, statement)))),
    seq(oid(OID.signingCertificateV2), set(seq(seq(seq(octets(digest('SHA-256', o.namedCertificate ?? cert))))))),
  ];
  const signedAttributes = set(...(o.attributes ? o.attributes(attributes, { cert, statement, hash }) : attributes));
  let signature = o.sign ? o.sign(signedAttributes) : signWith(key, o.signHash ?? hash, signedAttributes);
  if (o.signature) signature = o.signature(signature);
  const signer = seq(
    o.signerVersion ?? int(1),
    o.signerName ?? seq(NAME, int(1)),
    o.signerDigestAlgorithm ?? seq(oid(HASH_OID[hash]), NULL),
    concatBytes(new Uint8Array([0xa0]), signedAttributes.subarray(1)),
    o.signatureAlgorithm ?? signatureAlgorithm(key, hash),
    octets(signature),
    ...(o.signerExtra ?? []),
  );
  const signedData = seq(
    o.signedDataVersion ?? int(3),
    o.digestAlgorithms ?? set(seq(oid(HASH_OID[hash]), NULL)),
    o.encapsulated ?? seq(oid(OID.tstInfo), der(0xa0, octets(statement))),
    ...(o.certificates === null ? [] : [der(0xa0, ...(o.certificates ?? [cert]))]),
    ...(o.beforeSigners ?? []),
    o.signerInfos ?? set(...Array(o.signerCount ?? 1).fill(signer)),
    ...(o.afterSigners ?? []),
  );
  const token = seq(o.outer ?? oid(OID.signedData), der(0xa0, signedData), ...(o.outerExtra ?? []));
  return o.bytes ? o.bytes(token) : token;
}

const authorityOf = (cert) => b64(digest('SHA-256', cert));

/** An RSA public key in the form of a certificate, from its two numbers, with every part open to change. */
function rsaSpki(n, e, o = {}) {
  const key = o.key ?? seq(o.modulus ?? intBytes(n), o.exponent ?? intBytes(e), ...(o.keyExtra ?? []));
  return seq(o.algorithm ?? seq(oid(OID.rsaEncryption), NULL), bitString(o.keyBytes ?? concatBytes(key, o.keyTail ?? new Uint8Array(0)), o.unused ?? 0));
}

/** The bytes of a PKCS #1 version 1.5 signature block for SHA-256, as an RSA key with exponent 1 would accept. */
function pkcs1Block(data, length) {
  const info = concatBytes(H('3031300d060960864801650304020105000420'), digest('SHA-256', data));
  return concatBytes(H('0001'), new Uint8Array(length - info.length - 3).fill(0xff), H('00'), info);
}

/** An ECDSA signature with its second number s replaced by n - s, the other of the two valid forms. */
function highS(signature) {
  const outer = readElement(signature, 0);
  const [r, s] = children(signature, outer);
  const sValue = bigOf(hex(signature.subarray(s.start, s.end)));
  const other = P256_ORDER - sValue;
  return seq(signature.subarray(r.from, r.end), int(other));
}

function compressedP256(spki) {
  const point = spki.subarray(spki.length - 65);
  const x = point.subarray(1, 33);
  const yOdd = point[64] & 1;
  return seq(seq(oid(OID.ecPublicKey), oid(OID.p256)), bitString(concatBytes(new Uint8Array([yOdd ? 0x03 : 0x02]), x)));
}

async function stampCases() {
  const cases = [];
  const keys = {
    p256: makeKey('P-256'),
    p384: makeKey('P-384'),
    ed: makeKey('Ed25519'),
    rsa: makeKey('RSA-2048'),
    rsa3072: makeKey('RSA-3072'),
    rsa1024: makeKey('RSA-1024'),
    rsaE3: makeKey('RSA-2048-e3'),
  };
  const add = (name, token, more = {}) => {
    const c = { name, token: b64(token) };
    if (Object.hasOwn(more, 'stampedValue')) c.stampedValue = more.stampedValue;
    else c.stamped = b64(more.stamped ?? STAMPED);
    if (Object.hasOwn(more, 'options')) c.options = more.options;
    if (more.change) c.change = more.change;
    cases.push(c);
  };
  // Each key has one certificate, so that "trusted" can name it.
  const certs = Object.fromEntries(Object.entries(keys).map(([k, key]) => [k, certificate(key)]));
  const token = (k, o = {}) => makeToken(keys[k], { cert: certs[k], ...o });
  const trustFor = (k) => ({ trusted: [authorityOf(certs[k])] });

  // --- sound time-stamps, with each signing method and fingerprint method ---
  add('ECDSA P-256 with SHA-256', token('p256'), { options: trustFor('p256') });
  add('ECDSA P-256 with SHA-384', token('p256', { hash: 'SHA-384' }), { options: trustFor('p256') });
  add('ECDSA P-256 with SHA-512', token('p256', { hash: 'SHA-512' }), { options: trustFor('p256') });
  add('ECDSA P-384 with SHA-384', token('p384', { hash: 'SHA-384' }), { options: trustFor('p384') });
  add('ECDSA P-384 with SHA-256', token('p384'), { options: trustFor('p384') });
  add('Ed25519', token('ed'), { options: trustFor('ed') });
  add('Ed25519 with SHA-512 named by the signer', token('ed', { hash: 'SHA-512' }), { options: trustFor('ed') });
  add('RSA 2048 with SHA-256', token('rsa'), { options: trustFor('rsa') });
  add('RSA 2048 with SHA-384', token('rsa', { hash: 'SHA-384' }), { options: trustFor('rsa') });
  add('RSA 2048 with SHA-512', token('rsa', { hash: 'SHA-512' }), { options: trustFor('rsa') });
  add('RSA 2048 named as plain RSA', token('rsa', { signatureAlgorithm: seq(oid(OID.rsaEncryption), NULL) }), { options: trustFor('rsa') });
  add('RSA 2048 named as plain RSA, with SHA-512', token('rsa', { hash: 'SHA-512', signatureAlgorithm: seq(oid(OID.rsaEncryption), NULL) }), { options: trustFor('rsa') });
  add('RSA 3072', token('rsa3072'), { options: trustFor('rsa3072') });
  add('RSA 2048 with exponent 3', token('rsaE3'), { options: trustFor('rsaE3') });
  add('RSA 1024: too small', token('rsa1024'), { options: trustFor('rsa1024') });

  // --- whom the checker trusts ---
  const sound = token('p256');
  for (const [name, options] of [
    ['no options', undefined],
    ['null options', null],
    ['options that are text', 'trusted'],
    ['options that are a list', [authorityOf(certs.p256)]],
    ['an empty object', {}],
    ['an empty list of trusted services', { trusted: [] }],
    ['trusted given as text', { trusted: authorityOf(certs.p256) }],
    ['another service trusted', { trusted: [authorityOf(certs.ed)] }],
    ['the service among others', { trusted: [5, null, authorityOf(certs.ed), authorityOf(certs.p256)] }],
    ['the service in capitals', { trusted: [authorityOf(certs.p256).toUpperCase()] }],
    ['the service inside a list', { trusted: [[authorityOf(certs.p256)]] }],
    ['the service trusted, ECDSA said to be missing', { trusted: [authorityOf(certs.p256)], without: ['ECDSA'] }],
    ['ECDSA said to be missing, as text', { trusted: [authorityOf(certs.p256)], without: 'ECDSA' }],
    ['ECDSA said to be missing, inside a list', { trusted: [authorityOf(certs.p256)], without: [['ECDSA']] }],
    ['ECDSA said to be missing, in small letters', { trusted: [authorityOf(certs.p256)], without: ['ecdsa'] }],
    ['other methods said to be missing', { trusted: [authorityOf(certs.p256)], without: ['RSA', 'Ed25519', null, 5] }],
  ]) {
    const c = { name: `trust: ${name}`, token: b64(sound), stamped: b64(STAMPED) };
    if (options !== undefined) c.options = options;
    cases.push(c);
  }
  add('RSA said to be missing', token('rsa'), { options: { trusted: [authorityOf(certs.rsa)], without: ['RSA'] } });
  add('Ed25519 said to be missing', token('ed'), { options: { trusted: [authorityOf(certs.ed)], without: ['Ed25519'] } });
  add('RSA 1024 said to be missing: its size is still judged', token('rsa1024'), { options: { without: ['RSA'] } });
  add('a broken ECDSA signature, ECDSA said to be missing', token('p256', { signature: (s) => s.subarray(0, 5) }), { options: { without: ['ECDSA'] } });

  // --- what was stamped ---
  add('made for something else', token('p256', { stamped: digest('SHA-256', utf8('something else')) }), { options: trustFor('p256') });
  add('the same bytes, said to be another fingerprint method', token('p256', { imprintOid: OID.sha512 }), { options: trustFor('p256') });
  add('a fingerprint of SHA-512', token('p256', { imprintOid: OID.sha512, stamped: digest('SHA-512', utf8('x')) }), { options: trustFor('p256'), stamped: digest('SHA-512', utf8('x')) });
  add('compared with 31 bytes', sound, { options: trustFor('p256'), stamped: STAMPED.subarray(0, 31) });
  add('compared with nothing', sound, { options: trustFor('p256'), stamped: new Uint8Array(0) });
  add('compared with null', sound, { options: trustFor('p256'), stampedValue: null });
  add('compared with text', sound, { options: trustFor('p256'), stampedValue: b64(STAMPED) });
  add('a stamped fingerprint of 33 bytes', token('p256', { stamped: concatBytes(STAMPED, H('00')) }), { options: trustFor('p256') });
  add('the fingerprint method with no parameters', token('p256', { imprintAlgorithm: seq(oid(OID.sha256)) }), { options: trustFor('p256') });
  add('the fingerprint method that is not a sequence', token('p256', { imprintAlgorithm: oid(OID.sha256) }), { options: trustFor('p256') });
  add('the fingerprint method with three parts', token('p256', { imprintAlgorithm: seq(oid(OID.sha256), NULL, NULL) }), { options: trustFor('p256') });

  // --- the statement ---
  const stmt = (more = {}) =>
    seq(
      ...(more.head ?? [int(more.version ?? 1), oid(OID.policy), seq(seq(oid(OID.sha256), NULL), octets(STAMPED)), int(1000), more.time ?? gtimeOf(WHEN)]),
      ...(more.tail ?? []),
    );
  const accuracy = (...parts) => seq(...parts);
  const extension = (critical) => der(0xa1, seq(oid(OID.someExtension), ...(critical === undefined ? [] : [H(critical ? '0101ff' : '010100')]), octets(NULL)));
  for (const [name, statement] of [
    ['version 2', stmt({ version: 2 })],
    ['version 0', stmt({ version: 0 })],
    ['no policy', seq(int(1), seq(seq(oid(OID.sha256), NULL), octets(STAMPED)), int(1000), gtimeOf(WHEN))],
    ['no serial number', seq(int(1), oid(OID.policy), seq(seq(oid(OID.sha256), NULL), octets(STAMPED)), gtimeOf(WHEN))],
    ['no time', seq(int(1), oid(OID.policy), seq(seq(oid(OID.sha256), NULL), octets(STAMPED)), int(1000))],
    ['a time as UTCTime', stmt({ time: utime('261005120000Z') })],
    ['a time with a fraction', stmt({ time: gtime('20261005120000.999Z') })],
    ['a time with a trailing zero in its fraction', stmt({ time: gtime('20261005120000.90Z') })],
    ['a time on a day that does not exist', stmt({ time: gtime('20261031120000Z') })],
    ['a time on 29 February 2028', stmt({ time: gtime('20280229120000Z') })],
    ['a time in the year 50', stmt({ time: gtime('00500101000000Z') })],
    ['accuracy of 300 seconds', stmt({ tail: [accuracy(int(300))] })],
    ['accuracy of 301 seconds', stmt({ tail: [accuracy(int(301))] })],
    ['accuracy of 0 seconds', stmt({ tail: [accuracy(int(0))] })],
    ['accuracy in milliseconds and microseconds only', stmt({ tail: [accuracy(der(0x80, H('03e7')), der(0x81, H('01')))] })],
    ['accuracy of 1 second and 500 milliseconds', stmt({ tail: [accuracy(int(1), der(0x80, H('01f4')))] })],
    ['accuracy that is empty', stmt({ tail: [accuracy()] })],
    ['accuracy given twice in seconds', stmt({ tail: [accuracy(int(1), int(400))] })],
    ['accuracy given twice in seconds, the second within', stmt({ tail: [accuracy(int(400), int(1))] })],
    ['accuracy of four parts', stmt({ tail: [accuracy(int(1), int(1), int(1), int(1))] })],
    ['accuracy of 2^31 - 1 seconds', stmt({ tail: [accuracy(H('02047fffffff'))] })],
    ['accuracy of five bytes', stmt({ tail: [accuracy(H('02050080000000'))] })],
    ['accuracy that is negative', stmt({ tail: [accuracy(H('0201ff'))] })],
    ['accuracy in an octet string', stmt({ tail: [accuracy(octets(H('01')))] })],
    ['accuracy with a constructed part', stmt({ tail: [accuracy(der(0xa0, int(1)))] })],
    ['ordering', stmt({ tail: [H('0101ff')] })],
    ['a number used once', stmt({ tail: [int(123456789)] })],
    ['the service named', stmt({ tail: [der(0xa0, der(0xa4, NAME))] })],
    ['every optional part, in order', stmt({ tail: [accuracy(int(1)), H('010100'), int(42), der(0xa0, der(0xa4, NAME)), extension()] })],
    ['a number used once before ordering', stmt({ tail: [int(42), H('0101ff')] })],
    ['accuracy after ordering', stmt({ tail: [H('0101ff'), accuracy(int(1))] })],
    ['accuracy given twice', stmt({ tail: [accuracy(int(1)), accuracy(int(1))] })],
    ['two extension lists', stmt({ tail: [extension(), extension()] })],
    ['an extension', stmt({ tail: [extension()] })],
    ['an extension marked as one that must be understood', stmt({ tail: [extension(true)] })],
    ['an extension marked as one that need not be understood', stmt({ tail: [extension(false)] })],
    ['two extensions, the second must be understood', stmt({ tail: [der(0xa1, seq(oid(OID.someExtension), octets(NULL)), seq(oid(OID.policy), H('0101ff'), octets(NULL)))] })],
    ['an extension that is not a sequence', stmt({ tail: [der(0xa1, octets(NULL))] })],
    ['an extension of four parts', stmt({ tail: [der(0xa1, seq(oid(OID.someExtension), H('0101ff'), octets(NULL), NULL))] })],
    ['an extension with a truth value in an odd place', stmt({ tail: [der(0xa1, seq(H('0101ff'), oid(OID.someExtension)))] })],
    ['17 extensions', stmt({ tail: [der(0xa1, ...Array.from({ length: 17 }, () => seq(oid(OID.someExtension), octets(NULL))))] })],
    ['a part of an unknown kind at the end', stmt({ tail: [octets(H('00'))] })],
    ['a [3] part at the end', stmt({ tail: [der(0xa3, NULL)] })],
    ['eleven parts', stmt({ tail: [accuracy(int(1)), H('010100'), int(42), der(0xa0, der(0xa4, NAME)), extension(), NULL] })],
    ['a statement that is not strict DER', stmt({ tail: [H('0202007f')] })],
    ['a statement with a bad truth value', stmt({ tail: [H('010101')] })],
    ['a statement that is a set', set(int(1))],
    ['a statement that is empty', new Uint8Array(0)],
    ['a statement of one byte', H('30')],
    ['a statement with a byte after it', concatBytes(stmt(), H('00'))],
    ['a statement that is an octet string', H('0400')],
  ]) {
    add(`statement: ${name}`, token('p256', { statement }), { options: trustFor('p256') });
  }

  // --- the certificate ---
  const certWith = (k, o) => certificate(keys[k], o);
  const withCert = (k, cert, more = {}) => token(k, { cert, ...more });
  for (const [name, cert] of [
    ['a certificate of the oldest kind', certWith('p256', { noVersion: true })],
    ['dates as UTCTime', certWith('p256', { validity: seq(utime('260101000000Z'), utime('360101000000Z')) })],
    ['dates as UTCTime in the last century', certWith('p256', { validity: seq(utime('990101000000Z'), utime('491231235959Z')) })],
    ['in force from the stated time', certWith('p256', { notBefore: WHEN })],
    ['in force until the stated time', certWith('p256', { notAfter: WHEN })],
    ['in force from a second after', certWith('p256', { notBefore: WHEN + 1000 })],
    ['in force until a second before', certWith('p256', { notAfter: WHEN - 1000 })],
    ['three dates', certWith('p256', { validity: seq(gtimeOf(WHEN - 1000), gtimeOf(WHEN + 1000), gtimeOf(WHEN + 2000)) })],
    ['one date', certWith('p256', { validity: seq(gtimeOf(WHEN - 1000)) })],
    ['dates that are octet strings', certWith('p256', { validity: seq(octets(H('00')), gtimeOf(WHEN)) })],
    ['a date that does not exist', certWith('p256', { validity: seq(gtime('20260230000000Z'), gtimeOf(WHEN)) })],
    ['dates in the wrong order', certWith('p256', { notBefore: WHEN + 1000, notAfter: WHEN - 1000 })],
    ['extensions after the key', certWith('p256', { bodyExtra: [der(0xa3, seq(seq(oid(OID.someExtension), octets(NULL))))] })],
    ['a body with no key', certWith('p256', { body: seq(der(0xa0, int(2)), int(1), seq(oid(OID.ecdsaWithSha256)), NAME, seq(gtimeOf(0), gtimeOf(WHEN * 2)), NAME) })],
    ['a body with no subject', certWith('p256', { body: seq(der(0xa0, int(2)), int(1), seq(oid(OID.ecdsaWithSha256)), NAME, seq(gtimeOf(0), gtimeOf(WHEN * 2))) })],
    ['a body that is a set', certWith('p256', { body: set(int(1)) })],
    ['a body with a serial number that is text', certWith('p256', { body: seq(der(0xa0, int(2)), der(0x0c, utf8('1')), seq(oid(OID.ecdsaWithSha256)), NAME, seq(gtimeOf(0), gtimeOf(WHEN * 2)), NAME, keys.p256.spki) })],
    ['a body with an issuer that is a set', certWith('p256', { body: seq(der(0xa0, int(2)), int(1), seq(oid(OID.ecdsaWithSha256)), set(), seq(gtimeOf(0), gtimeOf(WHEN * 2)), NAME, keys.p256.spki) })],
    ['a key that is not a sequence', certWith('p256', { spki: octets(H('00')) })],
    ['a key with no bits', certWith('p256', { spki: seq(seq(oid(OID.ecPublicKey), oid(OID.p256))) })],
    ['a key whose bits are an octet string', certWith('p256', { spki: seq(seq(oid(OID.ecPublicKey), oid(OID.p256)), octets(keys.p256.spki.subarray(26))) })],
    ['a key of an unknown kind', certWith('p256', { spki: seq(seq(oid(OID.dsa)), bitString(H('00'))) })],
    ['a key whose kind is not a sequence', certWith('p256', { spki: seq(oid(OID.ecPublicKey), bitString(H('00'))) })],
    ['a key on another curve', certWith('p256', { spki: seq(seq(oid(OID.ecPublicKey), oid(OID.secp256k1)), bitString(keys.p256.spki.subarray(26))) })],
    ['a key with no curve', certWith('p256', { spki: seq(seq(oid(OID.ecPublicKey)), bitString(keys.p256.spki.subarray(26))) })],
    ['a key with a curve given as null', certWith('p256', { spki: seq(seq(oid(OID.ecPublicKey), NULL), bitString(keys.p256.spki.subarray(26))) })],
    ['a key said to be P-384 that is P-256', certWith('p256', { spki: seq(seq(oid(OID.ecPublicKey), oid(OID.p384)), bitString(keys.p256.spki.subarray(26))) })],
    ['a key in its compressed form', certWith('p256', { spki: compressedP256(keys.p256.spki) })],
    ['a key that is not on the curve', certWith('p256', { spki: concatBytes(keys.p256.spki.subarray(0, keys.p256.spki.length - 1), new Uint8Array([keys.p256.spki.at(-1) ^ 1])) })],
    ['a key cut short', certWith('p256', { spki: seq(seq(oid(OID.ecPublicKey), oid(OID.p256)), bitString(keys.p256.spki.subarray(26, 60))) })],
    ['a key with a byte after its point', certWith('p256', { spki: seq(seq(oid(OID.ecPublicKey), oid(OID.p256)), bitString(concatBytes(keys.p256.spki.subarray(26), H('00')))) })],
    ['a key with unused bits', certWith('p256', { spki: seq(seq(oid(OID.ecPublicKey), oid(OID.p256)), bitString(keys.p256.spki.subarray(26), 1)) })],
    ['a key with three parts', certWith('p256', { spki: seq(seq(oid(OID.ecPublicKey), oid(OID.p256)), bitString(keys.p256.spki.subarray(26)), NULL) })],
  ]) {
    add(`certificate: ${name}`, withCert('p256', cert), { options: { trusted: [authorityOf(cert)] } });
  }
  // Ed25519 keys.
  const edPoint = keys.ed.spki.subarray(12);
  for (const [name, spki] of [
    ['an Ed25519 key with parameters', seq(seq(oid(OID.ed25519), NULL), bitString(edPoint))],
    ['an Ed25519 key of 31 bytes', seq(seq(oid(OID.ed25519)), bitString(edPoint.subarray(1)))],
    ['an Ed25519 key with unused bits', seq(seq(oid(OID.ed25519)), bitString(edPoint, 3))],
    ['an Ed25519 key that is another', seq(seq(oid(OID.ed25519)), bitString(makeKey('Ed25519').spki.subarray(12)))],
  ]) {
    const cert = certWith('ed', { spki });
    add(`certificate: ${name}`, withCert('ed', cert), { options: { trusted: [authorityOf(cert)] } });
  }
  // RSA keys: their size, and their form.
  const n = fromBase64url(keys.rsa.jwk.n);
  const e = fromBase64url(keys.rsa.jwk.e);
  const n1024 = fromBase64url(keys.rsa1024.jwk.n);
  for (const [name, spki, more] of [
    ['an RSA key written as it is made', rsaSpki(n, e)],
    ['an RSA key with no parameters', rsaSpki(n, e, { algorithm: seq(oid(OID.rsaEncryption)) })],
    ['an RSA key with parameters that are not null', rsaSpki(n, e, { algorithm: seq(oid(OID.rsaEncryption), oid(OID.sha256)) })],
    ['an RSA key said to be for RSA-PSS', rsaSpki(n, e, { algorithm: seq(oid(OID.rsaPss)) })],
    ['an RSA key with a byte after it', rsaSpki(n, e, { keyTail: H('00') })],
    ['an RSA key with a sequence after it', rsaSpki(n, e, { keyTail: seq() })],
    ['an RSA key with unused bits', rsaSpki(n, e, { unused: 3 })],
    ['an RSA key with a third number', rsaSpki(n, e, { keyExtra: [int(1)] })],
    ['an RSA key with one number', rsaSpki(n, e, { key: seq(intBytes(n)) })],
    ['an RSA key with numbers that are octet strings', rsaSpki(n, e, { key: seq(octets(n), intBytes(e)) })],
    ['an RSA key that is a set', rsaSpki(n, e, { key: set(intBytes(n), intBytes(e)) })],
    ['an RSA key that is empty', rsaSpki(n, e, { keyBytes: new Uint8Array(0) })],
    ['an RSA key that is one byte', rsaSpki(n, e, { keyBytes: H('30') })],
    ['an RSA key with a modulus with a needless zero', rsaSpki(n, e, { modulus: der(0x02, concatBytes(H('0000'), n)) })],
    ['an RSA key with a modulus with no sign byte', rsaSpki(n, e, { modulus: der(0x02, n) })],
    ['an RSA key with an exponent with a needless zero', rsaSpki(n, e, { exponent: der(0x02, concatBytes(H('00'), e)) })],
    ['an RSA key with an exponent of five bytes', rsaSpki(n, e, { exponent: int(2 ** 33 + 1) })],
    ['an RSA key with an exponent of four bytes', rsaSpki(n, e, { exponent: int(2 ** 31 + 1) })],
    ['an RSA key with an empty exponent', rsaSpki(n, e, { exponent: der(0x02, new Uint8Array(0)) })],
    ['an RSA key with an exponent of zero', rsaSpki(n, e, { exponent: int(0) })],
    ['an RSA key with an empty modulus', rsaSpki(n, e, { modulus: der(0x02, new Uint8Array(0)) })],
    ['an RSA key with an even exponent', rsaSpki(n, H('010000'))],
    ['an RSA key of 1,024 bits', rsaSpki(n1024, e)],
    ['an RSA key of 2,047 bits', rsaSpki(concatBytes(H('7f'), n.subarray(1)), e)],
    ['an RSA key of 8,192 bits', rsaSpki(new Uint8Array(1024).fill(0xff), e)],
    ['an RSA key of 8,193 bits', rsaSpki(concatBytes(H('01'), new Uint8Array(1024).fill(0xff)), e)],
  ]) {
    const cert = certWith('rsa', { spki });
    add(`certificate: ${name}`, withCert('rsa', cert, more), { options: { trusted: [authorityOf(cert)] } });
  }
  // An RSA key with the exponent 1, under which the signature block itself
  // is a signature, is not here: the JavaScript library counts such a
  // time-stamp as sound, and "cryptography" refuses to load the key (see
  // the report on the Python version). An exponent of 1 with any other
  // signature is refused by both.
  {
    const cert = certWith('rsa', { spki: rsaSpki(n, H('01')) });
    add('certificate: an RSA key with the exponent 1, and an ordinary signature', withCert('rsa', cert), { options: { trusted: [authorityOf(cert)] } });
    add('certificate: an RSA key with the exponent 1, and a signature block cut short', withCert('rsa', cert, { sign: (data) => pkcs1Block(data, n.length).subarray(1) }), { options: { trusted: [authorityOf(cert)] } });
  }
  // How the bits marked as unused at the end of a key are read: they are taken as zero.
  {
    let odd = makeKey('P-256');
    while (odd.spki.at(-1) % 2 === 0) odd = makeKey('P-256');
    let even = makeKey('P-256');
    while (even.spki.at(-1) % 2 === 1) even = makeKey('P-256');
    for (const [name, key] of [
      ['a P-256 key whose last bit is 1, marked as unused', odd],
      ['a P-256 key whose last bit is 0, marked as unused', even],
    ]) {
      const cert = certificate(key, { spki: seq(seq(oid(OID.ecPublicKey), oid(OID.p256)), bitString(key.spki.subarray(26), 1)) });
      add(`certificate: ${name}`, makeToken(key, { cert }), { options: { trusted: [authorityOf(cert)] } });
    }
    let zeros = makeKey('Ed25519');
    while ((zeros.spki.at(-1) & 7) !== 0) zeros = makeKey('Ed25519');
    let ones = makeKey('Ed25519');
    while ((ones.spki.at(-1) & 7) === 0) ones = makeKey('Ed25519');
    for (const [name, key] of [
      ['an Ed25519 key whose last three bits are 0, marked as unused', zeros],
      ['an Ed25519 key whose last three bits are not all 0, marked as unused', ones],
    ]) {
      const cert = certificate(key, { spki: seq(seq(oid(OID.ed25519)), bitString(key.spki.subarray(12), 3)) });
      add(`certificate: ${name}`, makeToken(key, { cert }), { options: { trusted: [authorityOf(cert)] } });
    }
    for (const [name, spki] of [
      ['an RSA key with a byte of zeros after it, three bits marked as unused', rsaSpki(n, e, { keyTail: H('00'), unused: 3 })],
      ['an RSA key with a byte of ones after it, seven bits marked as unused', rsaSpki(n, e, { keyTail: H('ff'), unused: 7 })],
      ['an RSA key with no parameters and a byte after it', rsaSpki(n, e, { algorithm: seq(oid(OID.rsaEncryption)), keyTail: H('0102') })],
      ['an RSA key with parameters that are a sequence', rsaSpki(n, e, { algorithm: seq(oid(OID.rsaEncryption), seq(int(1))) })],
    ]) {
      const cert = certWith('rsa', { spki });
      add(`certificate: ${name}`, withCert('rsa', cert), { options: { trusted: [authorityOf(cert)] } });
    }
    // The other forms of a point: hybrid, and the point at infinity.
    const point = keys.p256.spki.subarray(26);
    const hybrid = concatBytes(new Uint8Array([point[64] & 1 ? 0x07 : 0x06]), point.subarray(1));
    const wrongHybrid = concatBytes(new Uint8Array([point[64] & 1 ? 0x06 : 0x07]), point.subarray(1));
    for (const [name, bits] of [
      ['a P-256 key in its hybrid form', hybrid],
      ['a P-256 key in its hybrid form, with the wrong mark', wrongHybrid],
      ['a P-256 key that is the point at infinity', H('00')],
      ['a P-256 key in its compressed form, with the wrong mark', concatBytes(new Uint8Array([point[64] & 1 ? 0x02 : 0x03]), point.subarray(1, 33))],
      ['a P-256 key marked 0x05', concatBytes(H('05'), point.subarray(1))],
    ]) {
      const cert = certWith('p256', { spki: seq(seq(oid(OID.ecPublicKey), oid(OID.p256)), bitString(bits)) });
      add(`certificate: ${name}`, withCert('p256', cert), { options: { trusted: [authorityOf(cert)] } });
    }
    const explicit = certWith('p256', { spki: seq(seq(oid(OID.ecPublicKey), seq(int(1))), bitString(point)) });
    add('certificate: a P-256 key with its curve written out', withCert('p256', explicit), { options: { trusted: [authorityOf(explicit)] } });
  }
  // The signing method must match the key and the fingerprint method.
  for (const [name, k, more] of [
    ['an ECDSA key named with RSA', 'p256', { signatureAlgorithm: seq(oid(OID.sha256WithRsa), NULL) }],
    ['ECDSA with SHA-384 named, SHA-256 used', 'p256', { signatureAlgorithm: seq(oid(OID.ecdsaWithSha384)) }],
    ['ECDSA named with no fingerprint method', 'p256', { signatureAlgorithm: seq(oid(OID.ecPublicKey)) }],
    ['RSA with SHA-384 named, SHA-256 used', 'rsa', { signatureAlgorithm: seq(oid(OID.sha384WithRsa), NULL) }],
    ['RSA named as RSA-PSS', 'rsa', { signatureAlgorithm: seq(oid(OID.rsaPss)) }],
    ['RSA named with ECDSA', 'rsa', { signatureAlgorithm: seq(oid(OID.ecdsaWithSha256)) }],
    ['Ed25519 named with ECDSA', 'ed', { signatureAlgorithm: seq(oid(OID.ecdsaWithSha256)) }],
    ['Ed25519 named with parameters', 'ed', { signatureAlgorithm: seq(oid(OID.ed25519), NULL) }],
    ['a signing method that is not a sequence', 'p256', { signatureAlgorithm: oid(OID.ecdsaWithSha256) }],
    ['a signing method with three parts', 'p256', { signatureAlgorithm: seq(oid(OID.ecdsaWithSha256), NULL, NULL) }],
    ['a signing method that is empty', 'p256', { signatureAlgorithm: seq() }],
  ]) {
    add(`signing method: ${name}`, token(k, more), { options: trustFor(k) });
  }
  // The signature itself.
  for (const [name, k, signature] of [
    ['an ECDSA signature changed', 'p256', (s) => changed(s, { flip: [s.length - 1, 1] })],
    ['an ECDSA signature in its other valid form', 'p256', highS],
    ['an ECDSA signature side by side, not in DER', 'p256', (s) => ecdsaToRaw(s, 32)],
    ['an ECDSA signature with a byte after it', 'p256', (s) => concatBytes(s, H('00'))],
    ['an ECDSA signature that is empty', 'p256', () => new Uint8Array(0)],
    ['an ECDSA signature of zeros', 'p256', () => seq(int(0), int(0))],
    ['an ECDSA signature with numbers that are too large', 'p256', () => seq(intBytes(new Uint8Array(33).fill(0x11)), int(1))],
    ['an ECDSA signature whose first number is the order', 'p256', (s) => seq(int(P256_ORDER), readSeqItems(s)[1])],
    ['an Ed25519 signature changed', 'ed', (s) => changed(s, { flip: [10, 1] })],
    ['an Ed25519 signature cut short', 'ed', (s) => s.subarray(0, 63)],
    ['an Ed25519 signature with a byte after it', 'ed', (s) => concatBytes(s, H('00'))],
    ['an RSA signature changed', 'rsa', (s) => changed(s, { flip: [100, 1] })],
    ['an RSA signature cut short', 'rsa', (s) => s.subarray(1)],
    ['an RSA signature with a byte before it', 'rsa', (s) => concatBytes(H('00'), s)],
    ['an RSA signature that is empty', 'rsa', () => new Uint8Array(0)],
  ]) {
    add(`signature: ${name}`, token(k, { signature }), { options: trustFor(k) });
  }

  // --- the signed attributes ---
  const cv2 = (cert, hashName) =>
    seq(oid(OID.signingCertificateV2), set(seq(seq(seq(...(hashName ? [seq(oid(HASH_OID[hashName]), NULL)] : []), octets(digest(hashName ?? 'SHA-256', cert)))))));
  const cv1 = (cert) => seq(oid(OID.signingCertificate), set(seq(seq(seq(octets(digest('SHA-1', cert)))))));
  const otherCert = certificate(keys.ed);
  const p256Second = certificate(keys.p256, { serial: 2 });
  for (const [name, attributes, more] of [
    ['only the kind', (a) => [a[0]]],
    ['only the fingerprint', (a) => [a[1]]],
    ['no signing certificate', (a) => [a[0], a[1]]],
    ['the kind twice', (a) => [a[0], a[0], a[1], a[2]]],
    ['the fingerprint twice', (a) => [a[0], a[1], a[1], a[2]]],
    ['in another order', (a) => [a[2], a[1], a[0]]],
    ['the kind is data', (a) => [seq(oid(OID.contentType), set(oid(OID.data))), a[1], a[2]]],
    ['the kind given twice in one set', (a) => [seq(oid(OID.contentType), set(oid(OID.tstInfo), oid(OID.tstInfo))), a[1], a[2]]],
    ['the kind as an octet string', (a) => [seq(oid(OID.contentType), set(octets(H(OID.tstInfo)))), a[1], a[2]]],
    ['the kind with no value', (a) => [seq(oid(OID.contentType), set()), a[1], a[2]]],
    ['the fingerprint of something else', (a) => [a[0], seq(oid(OID.messageDigest), set(octets(digest('SHA-256', utf8('x'))))), a[2]]],
    ['the fingerprint as an object identifier', (a) => [a[0], seq(oid(OID.messageDigest), set(oid(OID.policy))), a[2]]],
    ['the fingerprint given twice in one set', (a) => [a[0], seq(oid(OID.messageDigest), set(...setValues(a[1]), ...setValues(a[1]))), a[2]]],
    ['a signing time beside them', (a) => [...a, seq(oid(OID.signingTime), set(utime('261005120000Z')))]],
    ['an unknown attribute with five values', (a) => [...a, seq(oid(OID.policy), set(NULL, NULL, NULL, NULL, NULL))]],
    ['an attribute with no value set', (a) => [...a, seq(oid(OID.policy))]],
    ['an attribute whose name is not an object identifier', (a) => [...a, seq(NULL, set(NULL))]],
    ['an attribute whose values are a sequence', (a) => [...a, seq(oid(OID.policy), seq(NULL))]],
    ['an attribute that is not a sequence', (a) => [...a, set(oid(OID.policy), set(NULL))]],
    ['an attribute with three parts', (a) => [...a, seq(oid(OID.policy), set(NULL), NULL)]],
    ['seventeen attributes', (a) => [...a, ...Array.from({ length: 14 }, () => seq(oid(OID.policy), set(NULL)))]],
    ['sixteen attributes', (a) => [...a, ...Array.from({ length: 13 }, () => seq(oid(OID.policy), set(NULL)))]],
    ['no attributes', () => []],
    ['the certificate named by SHA-1', (a, x) => [a[0], a[1], cv1(x.cert)]],
    ['the certificate named by SHA-512', (a, x) => [a[0], a[1], cv2(x.cert, 'SHA-512')]],
    ['the certificate named by SHA-384', (a, x) => [a[0], a[1], cv2(x.cert, 'SHA-384')]],
    ['the certificate named by SHA-256, written out', (a, x) => [a[0], a[1], cv2(x.cert, 'SHA-256')]],
    ['the certificate named by SHA-1, written out in the newer form', (a, x) => [a[0], a[1], seq(oid(OID.signingCertificateV2), set(seq(seq(seq(seq(oid(OID.sha1), NULL), octets(digest('SHA-1', x.cert)))))))]],
    ['the certificate named with a method that is not a sequence', (a, x) => [a[0], a[1], seq(oid(OID.signingCertificateV2), set(seq(seq(seq(oid(OID.sha256), octets(digest('SHA-256', x.cert)))))))]],
    ['both forms, the older wrong', (a) => [a[0], a[1], cv1(otherCert), a[2]]],
    ['both forms, the newer wrong', (a, x) => [a[0], a[1], cv2(otherCert), cv1(x.cert)]],
    ['both forms, the older after', (a, x) => [a[0], a[1], a[2], cv1(otherCert)]],
    ['the older form twice, the first right', (a, x) => [a[0], a[1], cv1(x.cert), cv1(otherCert)]],
    ['the older form twice, the second right', (a, x) => [a[0], a[1], cv1(otherCert), cv1(x.cert)]],
    ['the newer form twice, the second wrong', (a) => [a[0], a[1], a[2], cv2(otherCert)]],
    ['the newer form twice, the second right', (a) => [a[0], a[1], cv2(otherCert), a[2]]],
    ['the newer form with two values', (a) => [a[0], a[1], seq(oid(OID.signingCertificateV2), set(...setValues(a[2]), ...setValues(a[2])))]],
    ['the newer form with no value', (a) => [a[0], a[1], seq(oid(OID.signingCertificateV2), set())]],
    ['the newer form that is an octet string', (a, x) => [a[0], a[1], seq(oid(OID.signingCertificateV2), set(octets(digest('SHA-256', x.cert))))]],
    ['the newer form with an empty list', (a) => [a[0], a[1], seq(oid(OID.signingCertificateV2), set(seq(seq())))]],
    ['the newer form with no list', (a) => [a[0], a[1], seq(oid(OID.signingCertificateV2), set(seq()))]],
    ['the newer form with the fingerprint as an integer', (a) => [a[0], a[1], seq(oid(OID.signingCertificateV2), set(seq(seq(seq(int(5))))))]],
    ['the newer form naming two certificates, the first right', (a, x) => [a[0], a[1], seq(oid(OID.signingCertificateV2), set(seq(seq(seq(octets(digest('SHA-256', x.cert))), seq(octets(digest('SHA-256', otherCert)))))))]],
    ['the newer form naming two certificates, the second right', (a, x) => [a[0], a[1], seq(oid(OID.signingCertificateV2), set(seq(seq(seq(octets(digest('SHA-256', otherCert))), seq(octets(digest('SHA-256', x.cert)))))))]],
    ['the newer form with a policy list after', (a, x) => [a[0], a[1], seq(oid(OID.signingCertificateV2), set(seq(seq(seq(octets(digest('SHA-256', x.cert)))), seq())))]],
    ['the newer form with the issuer and number after', (a, x) => [a[0], a[1], seq(oid(OID.signingCertificateV2), set(seq(seq(seq(octets(digest('SHA-256', x.cert)), seq(seq(der(0xa4, NAME)), int(1)))))))]],
  ]) {
    add(`attributes: ${name}`, token('p256', { attributes, ...more }), { options: trustFor('p256') });
  }

  // --- the certificates that come with it ---
  for (const [name, more, trustCert] of [
    ['no certificates', { certificates: null }],
    ['an empty list of certificates', { certificates: [] }],
    ['only another certificate', { certificates: [otherCert] }],
    ['another certificate first', { certificates: [otherCert, certs.p256] }],
    ['the certificate twice', { certificates: [certs.p256, certs.p256] }],
    ['a second certificate for the same key, not named', { certificates: [p256Second] }],
    ['a second certificate for the same key, named', { certificates: [p256Second], namedCertificate: p256Second }, p256Second],
    ['a certificate of another kind first', { certificates: [der(0xa1, NULL), certs.p256] }],
    ['a certificate that is an octet string', { certificates: [octets(H('00')), certs.p256] }],
    ['eight certificates', { certificates: [...Array(7).fill(otherCert), certs.p256] }],
    ['nine certificates', { certificates: [...Array(8).fill(otherCert), certs.p256] }],
    ['a broken certificate that is not named', { certificates: [seq(int(1)), certs.p256] }],
    ['a certificate of four parts', { cert: seq(...readSeqItems(certs.p256), NULL) }],
    ['a list of withdrawn certificates', { beforeSigners: [der(0xa1, NULL)] }],
    ['two lists of withdrawn certificates', { beforeSigners: [der(0xa1, NULL), der(0xa1, NULL)] }],
    ['something else before the signers', { beforeSigners: [octets(H('00'))] }],
    ['something after the signers', { afterSigners: [NULL] }],
    ['the certificates after the withdrawn ones', { certificates: null, beforeSigners: [der(0xa1, NULL), der(0xa0, certs.p256)] }],
  ]) {
    add(`certificates: ${name}`, token('p256', more), { options: { trusted: [authorityOf(trustCert ?? certs.p256)] } });
  }

  // --- the signer ---
  for (const [name, more] of [
    ['version 3, named by its key', { signerVersion: int(3), signerName: der(0x80, H('0102030405')) }],
    ['version 3, named by issuer and number', { signerVersion: int(3) }],
    ['version 1, named by its key', { signerName: der(0x80, H('0102030405')) }],
    ['version 2', { signerVersion: int(2) }],
    ['a version that is not a number', { signerVersion: NULL }],
    ['no name', { signerName: octets(H('00')) }],
    ['the fingerprint method SHA-1', { signerDigestAlgorithm: seq(oid(OID.sha1), NULL), hash: 'SHA-256' }],
    ['the fingerprint method SHA-1, throughout', { hash: 'SHA-1', signHash: 'SHA-256', signatureAlgorithm: seq(oid(OID.ecdsaWithSha256)) }],
    ['the fingerprint method not a sequence', { signerDigestAlgorithm: oid(OID.sha256) }],
    ['the fingerprint method with no parameters', { signerDigestAlgorithm: seq(oid(OID.sha256)) }],
    ['unsigned attributes', { signerExtra: [der(0xa1, seq(oid(OID.policy), set(NULL)))] }],
    ['something else at the end', { signerExtra: [NULL] }],
    ['eight parts', { signerExtra: [der(0xa1, NULL), NULL] }],
    ['two signers', { signerCount: 2 }],
    ['no signers', { signerCount: 0 }],
    ['a signer that is a set', { signerInfos: set(set(int(1))) }],
    ['the signers as a sequence', { signerInfos: seq(seq(int(1))) }],
    ['a signer cut to its version', { signerInfos: set(seq(int(1))) }],
    ['a signer cut to its name', { signerInfos: set(seq(int(1), seq(NAME, int(1)))) }],
    ['a signer cut to its fingerprint method', { signerInfos: set(seq(int(1), seq(NAME, int(1)), seq(oid(OID.sha256), NULL))) }],
  ]) {
    add(`signer: ${name}`, token('p256', more), { options: trustFor('p256') });
  }

  // --- the wrapper and the signed data ---
  for (const [name, more] of [
    ['version 1 of the signed data', { signedDataVersion: int(1) }],
    ['version 4 of the signed data', { signedDataVersion: int(4) }],
    ['no fingerprint methods listed', { digestAlgorithms: set() }],
    ['two fingerprint methods listed', { digestAlgorithms: set(seq(oid(OID.sha256), NULL), seq(oid(OID.sha512))) }],
    ['a fingerprint method that is not a sequence', { digestAlgorithms: set(oid(OID.sha256)) }],
    ['the fingerprint methods as a sequence', { digestAlgorithms: seq(seq(oid(OID.sha256), NULL)) }],
    ['nine fingerprint methods', { digestAlgorithms: set(...Array(9).fill(seq(oid(OID.sha256)))) }],
    ['enclosed content of the wrong kind', { encapsulated: seq(oid(OID.data), der(0xa0, octets(H('00')))) }],
    ['enclosed content with no content', { encapsulated: seq(oid(OID.tstInfo)) }],
    ['enclosed content with three parts', { encapsulated: seq(oid(OID.tstInfo), der(0xa0, octets(H('00'))), NULL) }],
    ['enclosed content whose kind is not an object identifier', { encapsulated: seq(NULL, der(0xa0, octets(H('00')))) }],
    ['enclosed content not in [0]', { encapsulated: seq(oid(OID.tstInfo), der(0xa1, octets(H('00')))) }],
    ['enclosed content with two statements', { encapsulated: seq(oid(OID.tstInfo), der(0xa0, octets(H('00')), octets(H('00')))) }],
    ['enclosed content that is not an octet string', { encapsulated: seq(oid(OID.tstInfo), der(0xa0, seq())) }],
    ['enclosed content that is empty', { encapsulated: seq(oid(OID.tstInfo), der(0xa0)) }],
    ['the wrong kind of content', { outer: oid(OID.data) }],
    ['content of no kind', { outer: NULL }],
    ['a third part in the wrapper', { outerExtra: [NULL] }],
    ['a byte after the wrapper', { bytes: (t) => concatBytes(t, H('00')) }],
    ['the wrapper is a set', { bytes: (t) => concatBytes(H('31'), t.subarray(1)) }],
    ['the signed data not in [0]', { bytes: (t) => { const [kind, content] = readSeqItems(t); return seq(kind, der(0xa1, ...readSeqItems(content))); } }],
    ['the signed data twice', { bytes: (t) => { const [kind, content] = readSeqItems(t); return seq(kind, der(0xa0, ...readSeqItems(content), ...readSeqItems(content))); } }],
    ['the signed data that is a set', { bytes: (t) => { const [kind, content] = readSeqItems(t); return seq(kind, der(0xa0, set(...readSeqItems(readSeqItems(content)[0])))); } }],
    ['the signed data that is empty', { bytes: (t) => seq(readSeqItems(t)[0], der(0xa0)) }],
    ['only the kind of content', { bytes: (t) => seq(readSeqItems(t)[0]) }],
    ['a length in a needless long form inside', { bytes: (t) => { const [kind, content] = readSeqItems(t); return seq(kind, concatBytes(H('a08400'), new Uint8Array([content.length - 4 >> 16, (content.length - 4 >> 8) & 0xff, (content.length - 4) & 0xff]), content.subarray(4))); } }],
  ]) {
    add(`wrapper: ${name}`, token('p256', more), { options: trustFor('p256') });
  }

  // --- bytes that are not a time-stamp ---
  for (const [name, h] of [
    ['empty', ''],
    ['one byte', '30'],
    ['the indefinite form', '30800000'],
    ['a length not in its shortest form', '30810100'],
    ['a length far too long', '3084ffffffff'],
    ['a tag of the long form', '1f8100'],
    ['an empty sequence', '3000'],
    ['an octet string', '0400'],
    ['a sequence of one object identifier', '300b06092a864886f70d010702'],
  ]) {
    add(`bytes: ${name}`, H(h), { options: trustFor('p256') });
  }
  add('bytes: 12,288 bytes', concatBytes(H('30822ffc'), new Uint8Array(12284)), { options: trustFor('p256') });
  add('bytes: 12,289 bytes', concatBytes(H('30822ffd'), new Uint8Array(12285)), { options: trustFor('p256') });
  for (const [name, value] of [
    ['null', null],
    ['text', 'text'],
    ['a number', 42],
    ['an object', {}],
    ['a list of numbers', [48, 0]],
  ]) {
    cases.push({ name: `not bytes: ${name}`, tokenValue: value, stamped: b64(STAMPED), options: trustFor('p256') });
  }
  return cases;
}

/** The items of a constructed element, each as its whole bytes. */
function readSeqItems(bytes) {
  const outer = readElement(bytes, 0);
  return children(bytes, outer, 64).map((e) => bytes.subarray(e.from, e.end));
}
/** The values of an attribute: the items of its set. */
const setValues = (attribute) => readSeqItems(readSeqItems(attribute)[1]);

/** A time-stamp with every byte changed in turn. */
function flipCases(tokenBytes, stamped, options, every = 1, offset = 0, masks = [0x01]) {
  const token = b64(tokenBytes);
  const cases = [{ name: 'as made', token, stamped: b64(stamped), options }];
  for (let i = offset; i < tokenBytes.length; i += every) {
    for (const mask of masks) cases.push({ name: `byte ${i} changed by ${mask}`, token, stamped: b64(stamped), options, change: { flip: [i, mask] } });
  }
  return cases;
}

function cutCases(tokenBytes, stamped, options, every) {
  const token = b64(tokenBytes);
  const cases = [];
  for (let i = 0; i < tokenBytes.length; i += every) cases.push({ name: `cut to ${i} bytes`, token, stamped: b64(stamped), options, change: { cut: i } });
  cases.push({ name: 'a byte after it', token, stamped: b64(stamped), options, change: { append: '00' } });
  return cases;
}

function opensslCases() {
  const fixtures = JSON.parse(readFileSync(new URL('../fixtures/stamps.json', import.meta.url), 'utf8'));
  const cases = [];
  for (const s of fixtures.stamps) {
    const base = { token: s.token, stamped: s.stamped };
    cases.push({ name: `${s.about}: trusted`, ...base, options: { trusted: [s.authority] } });
    cases.push({ name: `${s.about}: not trusted`, ...base });
    cases.push({ name: `${s.about}: its method said to be missing`, ...base, options: { trusted: [s.authority], without: ['RSA', 'ECDSA'] } });
    cases.push({ name: `${s.about}: for something else`, token: s.token, stamped: b64(STAMPED), options: { trusted: [s.authority] } });
  }
  // Every second byte of the time-stamp with SHA-384 changed in turn.
  const p384 = fixtures.stamps.find((s) => /P-384/.test(s.about));
  for (const c of flipCases(fromBase64url(p384.token), fromBase64url(p384.stamped), { trusted: [p384.authority] }, 2)) cases.push({ ...c, name: `P-384: ${c.name}` });
  return cases;
}

// =====================================================================
// Block time-stamps
// =====================================================================

async function blockStampCases() {
  const cases = [];
  const stamped = digest('SHA-256', utf8('what was stamped'));
  const add = (name, proof, head, more = {}) => {
    const c = { name, proof: hex(proof), header: hex(head), stamped: hex(more.stamped ?? stamped) };
    if (Object.hasOwn(more, 'trusted')) c.trusted = more.trusted;
    for (const k of ['change', 'headerChange', 'proofValue', 'headerValue', 'stampedValue']) {
      if (Object.hasOwn(more, k)) c[k] = more[k];
    }
    for (const k of ['proofValue', 'headerValue', 'stampedValue']) {
      if (Object.hasOwn(more, k)) delete c[k.replace('Value', '')];
    }
    cases.push(c);
  };
  const s = await makeBlockStamp(stamped, WHEN, { height: 912345 });
  const pending = await makeBlockStamp(stamped, WHEN, { pending: true });
  const other = await makeBlockStamp(stamped, WHEN);
  add('a sound proof, its block named', s.proof, s.header, { trusted: [s.fingerprint] });
  add('a sound proof, its block named in capitals', s.proof, s.header, { trusted: [s.fingerprint.toUpperCase()] });
  add('a sound proof, its block named among others', s.proof, s.header, { trusted: [null, 5, other.fingerprint, s.fingerprint] });
  for (const [name, trusted] of [
    ['nothing named', undefined],
    ['an empty list', []],
    ['another block', [other.fingerprint]],
    ['text', 'everything'],
    ['the block as text, not in a list', s.fingerprint],
    ['things that are not text', [null, 5, [s.fingerprint], { a: s.fingerprint }]],
    ['the block with a space after it', [`${s.fingerprint} `]],
    ['the block cut short', [s.fingerprint.slice(1)]],
  ]) {
    add(`a sound proof, ${name}`, s.proof, s.header, trusted === undefined ? {} : { trusted });
  }
  add('a proof with a statement not yet complete beside the block', pending.proof, pending.header, { trusted: [pending.fingerprint] });
  add('a proof made for something else', s.proof, s.header, { trusted: [s.fingerprint], stamped: digest('SHA-256', utf8('something else')) });
  add('compared with 31 bytes', s.proof, s.header, { trusted: [s.fingerprint], stamped: stamped.subarray(0, 31) });
  add('compared with nothing given', s.proof, s.header, { trusted: [s.fingerprint], stampedValue: null });
  add('compared with text', s.proof, s.header, { trusted: [s.fingerprint], stampedValue: hex(stamped) });
  add('the header of another block', s.proof, other.header, { trusted: [other.fingerprint] });
  add('a header of 79 bytes', s.proof, s.header.subarray(0, 79), { trusted: [s.fingerprint] });
  add('a header of 81 bytes', s.proof, concatBytes(s.header, H('00')), { trusted: [s.fingerprint] });
  add('a header that is not bytes', s.proof, s.header, { headerValue: 'header', trusted: [s.fingerprint] });
  add('a header that is null', s.proof, s.header, { headerValue: null });
  add('a header that is a list', s.proof, s.header, { headerValue: Array.from(s.header) });
  add('a proof that is null', s.proof, s.header, { proofValue: null });
  add('a proof that is text', s.proof, s.header, { proofValue: 'proof' });
  add('a proof that is a list', s.proof, s.header, { proofValue: [0, 1] });
  add('a proof that is an object', s.proof, s.header, { proofValue: {} });
  add('an empty proof', new Uint8Array(0), s.header, { trusted: [s.fingerprint] });
  for (let length = 0; length < s.proof.length; length += 3) add(`cut to ${length} bytes`, s.proof, s.header, { trusted: [s.fingerprint], change: { cut: length } });
  add('a byte after its end', s.proof, s.header, { trusted: [s.fingerprint], change: { append: '00' } });
  add('another opening', s.proof, s.header, { trusted: [s.fingerprint], change: { flip: [1, 0x01] } });
  add('another version', s.proof, s.header, { trusted: [s.fingerprint], change: { flip: [31, 0x03] } });
  add('a first fingerprint that is not SHA-256', s.proof, s.header, { trusted: [s.fingerprint], change: { flip: [32, 0x0a] } });

  const head = madeUpHeader(stamped, WHEN);
  const headFp = await blockFingerprint(head);
  const direct = (...steps) => concatBytes(start(stamped), ...steps);
  const u = (...values) => new Uint8Array(values);
  for (const [name, proof] of [
    ['a statement about the stamped fingerprint itself', direct(blockStatement(7))],
    ['a statement of block 0', direct(blockStatement(0))],
    ['a statement of block 2^35 - 1', direct(blockStatement(2 ** 35 - 1))],
    ['a statement of block 2^35', direct(concatBytes(u(0x00), u(0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01), u(6), number(2 ** 35)))],
    ['a block number not in its shortest form', direct(concatBytes(u(0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01), u(2, 0x87, 0x00)))],
    ['a block number in six bytes', direct(concatBytes(u(0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01), u(6, 0x81, 0x81, 0x81, 0x81, 0x81, 0x01)))],
    ['a block statement with a byte after the number', direct(u(0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01, 0x02, 0x01, 0x01))],
    ['a block statement with no number', direct(u(0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01, 0x00))],
    ['a block statement that is cut short', direct(u(0x00, 0x05, 0x88, 0x96, 0x0d))],
    ['a statement of an unknown kind, then the block', direct(u(0xff, 0x00, 1, 2, 3, 4, 5, 6, 7, 8), number(3), utf8('xyz'), blockStatement(7))],
    ['a statement of an unknown kind only', direct(u(0x00, 1, 2, 3, 4, 5, 6, 7, 8), number(3), utf8('xyz'))],
    ['a statement of an unknown kind of 8,192 bytes', direct(u(0xff, 0x00, 1, 2, 3, 4, 5, 6, 7, 8), number(8192), new Uint8Array(8192), blockStatement(7))],
    ['a statement of an unknown kind of 8,193 bytes', direct(u(0x00, 1, 2, 3, 4, 5, 6, 7, 8), number(8193))],
    ['a pending statement, then the block', direct(u(0xff), pendingStatement('https://calendar.example'), blockStatement(9))],
    ['two block statements for the same value', direct(u(0xff), blockStatement(3), blockStatement(4))],
    ['many forks, the block last', direct(u(0xff), pendingStatement('a'), u(0xff), pendingStatement('b'), u(0xff), pendingStatement('c'), blockStatement(5))],
    ['a fork with nothing after', direct(u(0xff))],
    ['a fork of a step, then the block', direct(u(0xff), SHA256, blockStatement(1), blockStatement(2))],
    ['a step after the block', direct(u(0xff), blockStatement(2), SHA256, blockStatement(3))],
    ['a block statement about a value of 33 bytes', direct(joinAfter(u(1)), blockStatement(1))],
    ['steps the reader does not accept: 0x02', direct(u(0x02), blockStatement(1))],
    ['steps the reader does not accept: 0x03', direct(u(0x03), blockStatement(1))],
    ['steps the reader does not accept: 0x67', direct(u(0x67), blockStatement(1))],
    ['steps the reader does not accept: 0xf2', direct(u(0xf2), blockStatement(1))],
    ['steps the reader does not accept: 0xf3', direct(u(0xf3), blockStatement(1))],
    ['steps the reader does not accept: 0x55', direct(u(0x55), blockStatement(1))],
    ['a join with a length not in its shortest form', direct(u(0xf0, 0x81, 0x00, 0x00), blockStatement(1))],
    ['a join of nothing', direct(u(0xf0, 0x00), blockStatement(1))],
    ['a join before of nothing', direct(u(0xf1, 0x00), blockStatement(1))],
    ['a join of 4,064 bytes', direct(joinAfter(new Uint8Array(4064)), blockStatement(1))],
    ['a join of 4,065 bytes', direct(joinAfter(new Uint8Array(4065)), blockStatement(1))],
    ['a join of 4,090 bytes', direct(joinAfter(new Uint8Array(4090)), blockStatement(1))],
    ['a join of 4,097 bytes', direct(joinAfter(new Uint8Array(4097)), blockStatement(1))],
    ['a join whose length is cut short', direct(u(0xf0, 0x80))],
    ['a join longer than the proof', direct(u(0xf0, 0x10, 0x01))],
    ['255 steps in a row', direct(...Array(255).fill(SHA256), blockStatement(1))],
    ['256 steps in a row', direct(...Array(256).fill(SHA256), blockStatement(1))],
    ['254 steps, then forks', direct(...Array(254).fill(SHA256), u(0xff), SHA256, blockStatement(1), blockStatement(2))],
    ['255 steps, then forks', direct(...Array(255).fill(SHA256), u(0xff), SHA256, blockStatement(1), blockStatement(2))],
    ['joins growing past the limit', direct(joinBefore(new Uint8Array(4000)), SHA256, joinBefore(new Uint8Array(4000)), SHA256, joinBefore(new Uint8Array(4000)), SHA256, joinBefore(new Uint8Array(400)), blockStatement(1))],
    ['a number in five bytes', direct(u(0xf0, 0x80, 0x80, 0x80, 0x80, 0x01))],
    ['a number of more than five bytes', direct(u(0xf0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01))],
    ['a statement whose length is too large', direct(u(0x00, 1, 2, 3, 4, 5, 6, 7, 8, 0xff, 0xff, 0x03))],
  ]) {
    add(`steps: ${name}`, proof, head, { trusted: [headFp] });
  }
  // A proof longer than the format allows, and one exactly as long.
  const padTo = (length) => {
    const body = direct(u(0xff, 0x00, 1, 2, 3, 4, 5, 6, 7, 8), number(4000), new Uint8Array(4000), u(0xff, 0x00, 1, 2, 3, 4, 5, 6, 7, 8), number(4000), new Uint8Array(4000));
    const rest = length - body.length - 10 - 2 - 11;
    const proof = concatBytes(body, u(0xff, 0x00, 1, 2, 3, 4, 5, 6, 7, 8), number(rest), new Uint8Array(rest), blockStatement(7));
    if (proof.length !== length) throw new Error('the padded proof is not of the length wanted');
    return proof;
  };
  add('a proof of exactly 12,288 bytes', padTo(12288), head, { trusted: [headFp] });
  add('a proof of 12,289 bytes', padTo(12289), head, { trusted: [headFp] });
  // A header whose time is the largest a header can hold, and one whose time is 0.
  const late = Uint8Array.from(head);
  late.set([0xff, 0xff, 0xff, 0xff], 68);
  add('a header stating the latest time it can', direct(blockStatement(7)), late, { trusted: [await blockFingerprint(late)] });
  const early = Uint8Array.from(head);
  early.set([0, 0, 0, 0], 68);
  add('a header stating the time 0', direct(blockStatement(7)), early, { trusted: [await blockFingerprint(early)] });
  // Every byte of the header changed in turn.
  for (let at = 0; at < 80; at++) add(`header byte ${at} changed`, s.proof, s.header, { trusted: [s.fingerprint], headerChange: { flip: [at, 0x01] } });
  return cases;
}

async function blockFlipCases() {
  const stamped = digest('SHA-256', utf8('what was stamped'));
  const s = await makeBlockStamp(stamped, WHEN, { pending: true });
  const cases = [];
  for (let at = 0; at < s.proof.length; at++) {
    for (const mask of [0x01, 0x80]) cases.push({ name: `proof byte ${at} changed by ${mask}`, proof: hex(s.proof), header: hex(s.header), stamped: hex(stamped), trusted: [s.fingerprint], change: { flip: [at, mask] } });
  }
  return cases;
}

async function blockFingerprintCases() {
  const rand = randomSource(80);
  const cases = [];
  for (let i = 0; i < 30; i++) cases.push({ name: `a header of 80 bytes, ${i}`, header: hex(rand.bytes(80)) });
  for (const length of [0, 1, 79, 81, 200]) cases.push({ name: `${length} bytes`, header: hex(rand.bytes(length)) });
  cases.push({ name: 'the first block of the Bitcoin chain', header: BITCOIN.first });
  return cases;
}

async function blockStampItemCases() {
  const stamped = digest('SHA-256', utf8('what was stamped'));
  const s = await makeBlockStamp(stamped, WHEN);
  const cases = [];
  const add = (name, more) => cases.push({ name, proof: hex(s.proof), header: hex(s.header), ...more });
  add('a proof and its header', {});
  add('an empty proof', { proof: '' });
  add('a proof of one byte', { proof: '00' });
  add('a proof of 12,288 bytes', { proof: '00'.repeat(12288) });
  add('a proof of 12,289 bytes', { proof: '00'.repeat(12289) });
  add('a header of 79 bytes', { header: hex(s.header.subarray(1)) });
  add('a header of 81 bytes', { header: hex(s.header) + '00' });
  add('an empty header', { header: '' });
  for (const [name, value] of [['null', null], ['text', 'text'], ['a list', [1, 2]], ['an object', {}], ['a number', 5]]) {
    add(`a proof that is ${name}`, { proofValue: value });
    add(`a header that is ${name}`, { headerValue: value });
  }
  for (const c of cases) {
    if (Object.hasOwn(c, 'proofValue')) delete c.proof;
    if (Object.hasOwn(c, 'headerValue')) delete c.header;
  }
  return cases;
}

// =====================================================================
// The seal
// =====================================================================

async function sealContentCases() {
  const recorder = await generateSealKeySet();
  const agent = await generateKeySet();
  // One seal signed for real, so that its content is as a recorder writes it.
  const book = 'line one\nline two\nline three\n';
  const sealed = await writeSeal(book, { by: { keys: recorder.keys, name: 'Example recorder (invented)' }, when: WHEN }, recorder.privateKeys);
  const real = JSON.parse(Buffer.from(sealed.record.payload, 'base64url').toString('utf8'));
  const base = { type: 'provared.seal.v0', id: 'AAECAwQFBgcICQoLDA0ODw', by: { keys: recorder.keys, name: 'Example recorder (invented)' }, size: 3, root: b64(STAMPED), when: '2026-10-05T12:00:00Z' };
  const cases = [];
  const add = (name, content) => cases.push({ name, content });
  add('a seal as written', real);
  add('a seal', base);
  add('a seal with the seal before it', { ...base, previous: b64(STAMPED) });
  add('a seal of any type', { ...base, type: 'something else' });
  for (const name of Object.keys(base)) {
    const { [name]: _, ...rest } = base;
    add(`no "${name}"`, rest);
  }
  add('an unknown member', { ...base, extra: 1 });
  add('a member named __proto__', JSON.parse(JSON.stringify(base).replace('{', '{"__proto__":1,')));
  for (const [name, value] of [['null', null], ['a list', []], ['text', 'seal'], ['a number', 5]]) add(`content that is ${name}`, value);
  for (const [name, id] of [['too short', 'AAECAwQFBgcICQoLDA0ODg'.slice(0, 21)], ['too long', b64(new Uint8Array(17))], ['not base64url', '!AECAwQFBgcICQoLDA0ODw'], ['a number', 5], ['padded', 'AAECAwQFBgcICQoLDA0ODw==']]) add(`an id ${name}`, { ...base, id });
  for (const [name, by] of [
    ['null', null],
    ['a list', []],
    ['with no keys', { name: 'x' }],
    ['with no name', { keys: recorder.keys }],
    ['with something more', { keys: recorder.keys, name: 'x', more: 1 }],
    ['with an empty name', { keys: recorder.keys, name: '' }],
    ['with a name of 200 characters', { keys: recorder.keys, name: 'x'.repeat(200) }],
    ['with a name of 201 characters', { keys: recorder.keys, name: 'x'.repeat(201) }],
    ['with a name of 200 characters beyond the first plane', { keys: recorder.keys, name: '😀'.repeat(200) }],
    ['with a name of 201 characters beyond the first plane', { keys: recorder.keys, name: '😀'.repeat(201) }],
    ['with a name that is a number', { keys: recorder.keys, name: 5 }],
    ['with two keys', { keys: recorder.keys.slice(0, 2), name: 'x' }],
    ['with an agent\'s keys', { keys: agent.keys, name: 'x' }],
    ['with four keys', { keys: [...recorder.keys, recorder.keys[0]], name: 'x' }],
    ['with the keys in another order', { keys: [recorder.keys[1], recorder.keys[0], recorder.keys[2]], name: 'x' }],
    ['with an SLH-DSA key cut short', { keys: [recorder.keys[0], recorder.keys[1], { ...recorder.keys[2], pub: recorder.keys[2].pub.slice(0, 80) }], name: 'x' }],
    ['with an SLH-DSA key of another type', { keys: [recorder.keys[0], recorder.keys[1], { ...recorder.keys[2], kty: 'OKP' }], name: 'x' }],
    ['with an SLH-DSA key with a member more', { keys: [recorder.keys[0], recorder.keys[1], { ...recorder.keys[2], use: 'sig' }], name: 'x' }],
    ['with keys that are not a list', { keys: { 0: recorder.keys[0] }, name: 'x' }],
  ]) {
    add(`by ${name}`, { ...base, by });
  }
  for (const size of [0, 1, -1, 1.5, '3', null, true, 2 ** 53 - 1, 2 ** 53, 1e300]) add(`size ${JSON.stringify(size)}`, { ...base, size });
  for (const [name, root] of [['too short', b64(STAMPED).slice(1)], ['of 33 bytes', b64(new Uint8Array(33))], ['a number', 1], ['empty', '']]) add(`a root ${name}`, { ...base, root });
  for (const [name, previous] of [['too short', b64(STAMPED).slice(1)], ['null', null], ['empty', '']]) add(`a seal before it ${name}`, { ...base, previous });
  for (const when of ['2026-10-05T12:00:00.000Z', '2026-02-30T12:00:00Z', 'now', 5, null, '0000-01-01T00:00:00Z']) add(`a time ${JSON.stringify(when)}`, { ...base, when });
  return cases;
}

function sealStampCases() {
  const token = b64(H('3082000102030405060708090a0b0c0d0e0f'));
  const block = b64(new Uint8Array(80).fill(7));
  const proof = b64(new Uint8Array(100).fill(3));
  const cases = [];
  const add = (name, stamps) => cases.push({ name, stamps });
  add('one time-stamp from a service', [token]);
  add('one block time-stamp', [{ block, proof }]);
  add('four of both kinds', [token, { block, proof }, b64(H('00')), { block: b64(H('01')), proof }]);
  add('five', [token, b64(H('01')), b64(H('02')), b64(H('03')), b64(H('04'))]);
  add('none', []);
  add('not a list', token);
  add('an object', { 0: token });
  add('null', null);
  add('the same time-stamp twice', [token, token]);
  add('the same block time-stamp twice', [{ block, proof }, { block, proof }]);
  add('the same block time-stamp twice, written in another order', [{ block, proof }, { proof, block }]);
  add('a block and a proof swapped', [{ block, proof }, { block: proof, proof: block }]);
  add('a time-stamp that is null', [null]);
  add('a time-stamp that is a number', [42]);
  add('a time-stamp that is a list', [[token]]);
  add('a time-stamp that is empty', ['']);
  add('a time-stamp that is not base64url', ['not base64url!']);
  add('a time-stamp with padding', ['AA==']);
  add('a time-stamp with an impossible length', ['A']);
  add('a time-stamp with stray bits', ['AB']);
  add('a time-stamp beyond the first plane', ['😀😀']);
  add('a time-stamp of 16,384 characters', ['A'.repeat(16384)]);
  add('a time-stamp of 16,385 characters', ['A'.repeat(16385)]);
  add('a time-stamp of 8,192 characters beyond the first plane', ['😀'.repeat(8192)]);
  add('a time-stamp of 8,193 characters beyond the first plane', ['😀'.repeat(8193)]);
  add('a time-stamp of 20,000 characters', ['A'.repeat(20000)]);
  add('a block time-stamp with no proof', [{ block }]);
  add('a block time-stamp with no block', [{ proof }]);
  add('a block time-stamp with something more', [{ block, proof, extra: 'x' }]);
  add('a block time-stamp with an empty proof', [{ block, proof: '' }]);
  add('a block time-stamp with an empty block', [{ block: '', proof }]);
  add('a block time-stamp with a block that is a number', [{ block: 80, proof }]);
  add('a block time-stamp with a proof that is not base64url', [{ block, proof: 'not base64url!' }]);
  add('a block time-stamp with a block that is not base64url', [{ block: 'not base64url!', proof }]);
  add('a block time-stamp with a block of 1,366 characters', [{ block: 'A'.repeat(1366), proof }]);
  add('a block time-stamp with a block of 1,367 characters', [{ block: 'A'.repeat(1367), proof }]);
  add('a block time-stamp with a block of 1,368 characters', [{ block: 'A'.repeat(1368), proof }]);
  add('a block time-stamp with a block of 79 bytes', [{ block: b64(new Uint8Array(79)), proof }]);
  add('a block time-stamp with a proof of 16,385 characters', [{ block, proof: 'A'.repeat(16385) }]);
  add('a fault in the second, a fault in the first', [42, '']);
  add('a sound one, then a fault', [token, null]);
  add('a fault after the same one twice', [token, token, null]);
  return cases;
}

async function keySetFingerprintCases() {
  const recorder = await generateSealKeySet();
  const agent = await generateKeySet();
  const cases = [];
  const add = (name, keys) => cases.push({ name, keys });
  add('a recorder\'s key set', recorder.keys);
  add('an agent\'s key set', agent.keys);
  add('the same keys in another order', [recorder.keys[2], recorder.keys[0], recorder.keys[1]]);
  add('a key with its members in another order', [Object.fromEntries(Object.entries(recorder.keys[0]).reverse()), recorder.keys[1], recorder.keys[2]]);
  add('an empty list', []);
  add('an object', { a: 1 });
  add('text', 'keys');
  add('a number', 5);
  add('a negative number', [-1]);
  add('a fraction', [1.5]);
  add('true', [true]);
  add('null', [null]);
  add('nested nine deep', [[[[[[[[[1]]]]]]]]]);
  add('nested eight deep', [[[[[[[[1]]]]]]]]);
  add('names that sort by UTF-16', [{ '😀': 1, '￿': 2 }]);
  add('a lone surrogate', ['\ud800']);
  return cases;
}

// =====================================================================
// The chain of block headers
// =====================================================================

const sha256d = (b) => createHash('sha256').update(createHash('sha256').update(b).digest()).digest();
const writtenHash = (hash) => Buffer.from(hash).reverse().toString('hex');
const EASY = 0x207fffff;
const T0 = Math.floor(Date.parse('2025-10-05T09:00:00Z') / 1000);

/** A header that meets its target (or, with "fail", one that does not). */
function mine({ previous, time, bits = EASY, root = Buffer.alloc(32, 7), fail = false, version = 0x20000000 }) {
  const header = Buffer.alloc(80);
  header.writeInt32LE(version, 0);
  Buffer.from(previous).copy(header, 4);
  Buffer.from(root).copy(header, 36);
  header.writeUInt32LE(time >>> 0, 68);
  header.writeUInt32LE(bits >>> 0, 72);
  const exponent = bits >>> 24;
  const mantissa = BigInt(bits & 0x7fffff);
  const target = exponent <= 3 ? mantissa >> BigInt(8 * (3 - exponent)) : mantissa << BigInt(8 * (exponent - 3));
  for (let nonce = 0; nonce < 1e6; nonce++) {
    header.writeUInt32LE(nonce, 76);
    const meets = BigInt('0x' + writtenHash(sha256d(header))) <= target;
    if (meets !== fail) return new Uint8Array(header);
  }
  return new Uint8Array(header);
}

const FIRST = mine({ previous: Buffer.alloc(32), time: T0 });
const RULES = { first: hex(FIRST), limit: ((1n << 255n) - 1n).toString(16), interval: 2016, timespan: 1209600, retarget: false, known: [] };

function chainOf(n, { from = FIRST, start: t = T0, at = {}, step = 600 } = {}) {
  const headers = [from];
  for (let h = 1; h <= n; h++) {
    const previous = sha256d(headers[h - 1]);
    const plain = { previous, time: t + h * step, root: Buffer.alloc(32, h % 251) };
    headers.push(mine({ ...plain, ...(at[h] ? at[h]({ ...plain, headers }) : {}) }));
  }
  return headers;
}
const joined = (headers) => new Uint8Array(Buffer.concat(headers.map((h) => Buffer.from(h))));
const timeOfHeader = (h) => Buffer.from(h).readUInt32LE(68);
const bitsOfHeader = (h) => Buffer.from(h).readUInt32LE(72);

function nextBitsCases() {
  const cases = [];
  const add = (name, bits, firstTime, lastTime, rules) => cases.push({ name, bits, firstTime, lastTime, ...(rules ? { rules } : {}) });
  add('the first change of difficulty, at block 32,256', 0x1d00ffff, 1261130161, 1262152739);
  add('a change at block 967,680', 0x1702355e, 1788640367, 1789801627);
  add('never easier than the limit', 0x1d00ffff, 0, 10 * 1209600);
  add('at most four times harder', 0x1702355e, 0, 1);
  add('exactly a quarter', 0x1702355e, 0, 1209600 / 4);
  add('exactly four times', 0x1702355e, 0, 1209600 * 4);
  add('a run that went backwards', 0x1702355e, 1000, 0);
  add('a run of exactly two weeks', 0x1702355e, 0, 1209600);
  add('a negative target', 0x1d80ffff, 0, 1209600);
  add('a target of zero', 0x1d000000, 0, 1209600);
  add('a small exponent', 0x03123456, 0, 1209600);
  add('a smaller exponent', 0x02123456, 0, 1209600);
  add('an exponent of zero', 0x00123456, 0, 1209600);
  add('an exponent of one, harder', 0x01123456, 0, 1);
  add('a mantissa whose top bit would be set', 0x1c7fffff, 0, 1209600 * 2);
  add('a large exponent', 0x2100ffff, 0, 1209600);
  add('the easiest bits with the rules of a made-up chain', EASY, 0, 1000, RULES);
  add('a made-up chain that eases', 0x1f200000, 0, 4000, { ...RULES, timespan: 1000 });
  add('a made-up chain that hardens', 0x1f200000, 0, 100, { ...RULES, timespan: 1000 });
  add('a timespan that does not divide by four', 0x1f200000, 0, 3, { ...RULES, timespan: 7 });
  add('a timespan that does not divide by four, eased', 0x1f200000, 0, 1e6, { ...RULES, timespan: 7 });
  add('a fractional span', 0x1f200000, 0, 0.5, { ...RULES, timespan: 7 });
  add('times that are fractions', 0x1f200000, 0.25, 3.75, { ...RULES, timespan: 7 });
  add('a limit lower than the target', 0x1f200000, 0, 4000, { ...RULES, timespan: 1000, limit: (1n << 200n).toString(16) });
  const rand = randomSource(2016);
  for (let i = 0; i < 100; i++) {
    const exponent = 3 + rand.int(30);
    const bits = ((exponent << 24) | (rand.int(0x800000))) >>> 0;
    const span = rand.int(1209600 * 6);
    add(`random ${i}`, bits, 1700000000, 1700000000 + span);
  }
  return cases;
}

function readHeaderChainCases() {
  const cases = [];
  const add = (name, headers, more = {}) => {
    const now = more.now ?? (timeOfHeader(headers.at(-1)) + 3600) * 1000;
    cases.push({ name, bytes: hex(joined(headers)), now, rules: more.rules ?? RULES, ...(more.partial ? { partial: true } : {}), ...(more.change ? { change: more.change } : {}), ...(more.lookups ? { lookups: more.lookups } : {}), ...(more.workAfter !== undefined ? { workAfter: more.workAfter } : {}) });
  };
  const thirty = chainOf(30);
  add('a sound chain of 31 blocks', thirty, { lookups: [writtenHash(sha256d(thirty[12])), writtenHash(sha256d(thirty[0])), writtenHash(sha256d(thirty[30])), '0'.repeat(64), 'not a fingerprint', writtenHash(sha256d(thirty[12])).toUpperCase(), 5], workAfter: 10 });
  add('only the first block', [FIRST], { workAfter: -1 });
  add('the first block that is another', [mine({ previous: Buffer.alloc(32, 9), time: 1 })]);
  add('not whole headers', thirty, { change: { cut: 250 } });
  add('nothing at all', thirty, { change: { cut: 0 } });
  add('a byte after the last header', thirty, { change: { append: '00' } });
  add('a header that does not name the block before it', chainOf(12, { at: { 5: () => ({ previous: Buffer.alloc(32, 1) }) } }));
  add('a header that does not carry the work it claims', chainOf(12, { at: { 5: () => ({ fail: true }) } }));
  add('a header whose difficulty does not follow the rule', chainOf(12, { at: { 5: () => ({ bits: 0x2007ffff }) } }));
  add('a time not later than the middle of the eleven before', chainOf(14, { at: { 13: ({ headers }) => ({ time: timeOfHeader(headers[3]) }) } }));
  add('a time one second later than the middle of the eleven before', chainOf(14, { at: { 13: ({ headers }) => ({ time: timeOfHeader(headers[7]) + 1 }) } }));
  add('a time equal to the middle with few blocks before', chainOf(4, { at: { 3: ({ headers }) => ({ time: timeOfHeader(headers[1]) }) } }));
  add('a time before the block before, but after the middle', chainOf(14, { at: { 13: ({ headers }) => ({ time: timeOfHeader(headers[12]) - 1 }) } }));
  const five = chainOf(5);
  add('a time more than two hours ahead of the clock', five, { now: (timeOfHeader(five.at(-1)) - 3 * 3600) * 1000 });
  add('a time exactly two hours ahead of the clock', five, { now: (timeOfHeader(five.at(-1)) - 7200) * 1000 });
  add('a time two hours and a millisecond ahead of the clock', five, { now: (timeOfHeader(five.at(-1)) - 7200) * 1000 - 1 });
  add('a version below what the upgrades ask', chainOf(8, { at: { 6: () => ({ version: 3 }) } }), { rules: { ...RULES, versions: [[5, 4]] } });
  add('a version that is negative', chainOf(8, { at: { 6: () => ({ version: -1 }) } }), { rules: { ...RULES, versions: [[5, 4]] } });
  add('a version just high enough', chainOf(8, { at: { 6: () => ({ version: 4 }) } }), { rules: { ...RULES, versions: [[5, 4], [7, 2]] } });
  add('versions with no rule from that block', chainOf(8, { at: { 3: () => ({ version: 1 }) } }), { rules: { ...RULES, versions: [[5, 4]] } });
  const twenty = chainOf(20);
  add('a chain that holds a known block', twenty, { rules: { ...RULES, known: [[10, writtenHash(sha256d(twenty[10]))]] } });
  add('a chain whose block is not the one known', twenty, { rules: { ...RULES, known: [[10, writtenHash(sha256d(twenty[11]))]] } });
  add('a chain that ends before the last known block', twenty, { rules: { ...RULES, known: [[25, '0'.repeat(64)]] } });
  add('a chain that ends before the last known block, carried on', twenty, { rules: { ...RULES, known: [[25, '0'.repeat(64)]] }, partial: true });
  add('a chain that ends at the last known block', twenty, { rules: { ...RULES, known: [[3, writtenHash(sha256d(twenty[3]))], [20, writtenHash(sha256d(twenty[20]))]] } });
  add('a known block 0 that is right', twenty, { rules: { ...RULES, known: [[0, writtenHash(sha256d(twenty[0]))]] } });
  add('a known block 0 that is wrong', twenty, { rules: { ...RULES, known: [[0, '0'.repeat(64)]] } });
  // Where the difficulty changes.
  const retarget = { ...RULES, retarget: true, interval: 10, timespan: 1000 };
  const build = (bitsAt10, gap = 60) => {
    const headers = [FIRST];
    for (let h = 1; h <= 12; h++) {
      const bits = h < 10 ? EASY : h === 10 ? bitsAt10(headers) : bitsOfHeader(headers[10]);
      headers.push(mine({ previous: sha256d(headers[h - 1]), time: T0 + h * gap, bits }));
    }
    return headers;
  };
  const computed = (headers) => nextBits(EASY, timeOfHeader(headers[0]), timeOfHeader(headers[9]), { ...retarget, limit: bigOf(retarget.limit) });
  add('a change of difficulty, as computed', build(computed), { rules: retarget, workAfter: 0 });
  add('a change of difficulty, not as computed', build(() => EASY), { rules: retarget });
  add('a change of difficulty one step easier than computed', build((h) => computed(h) + 1), { rules: retarget });
  // After the last known block, no target may be more than four times easier than its.
  const hard = 0x1f200000;
  const first = mine({ previous: Buffer.alloc(32), time: T0, bits: hard });
  const easing = { ...RULES, first: hex(first), retarget: true, interval: 10, timespan: 1000 };
  const headers = [first];
  for (let h = 1; h <= 30; h++) {
    const prev = headers[h - 1];
    const bits = h % 10 === 0 ? nextBits(bitsOfHeader(prev), timeOfHeader(headers[h - 10]), timeOfHeader(prev), { ...easing, limit: bigOf(easing.limit) }) : bitsOfHeader(prev);
    const time = h <= 10 ? T0 + h * 100 : T0 + 1000 + (h - 10) * 1000;
    headers.push(mine({ previous: sha256d(prev), time, bits }));
  }
  const known = { ...easing, known: [[10, writtenHash(sha256d(headers[10]))]] };
  add('a target eased four times twice, to block 29', headers.slice(0, 30), { rules: known, workAfter: 5 });
  add('a target eased sixteen times by block 30', headers, { rules: known });
  add('a target eased sixteen times, with no known block', headers, { rules: easing, workAfter: 0 });
  add('a target eased sixteen times, with an ease of 16 allowed', headers, { rules: { ...known, ease: '16' } });
  add('a target eased sixteen times, with an ease of 15 allowed', headers, { rules: { ...known, ease: '15' } });
  // A first block whose bits stand for a target of zero, or a negative one.
  for (const [name, bits] of [['zero', 0x01000000], ['negative', 0x1d800001], ['above the limit', 0x21010000]]) {
    const odd = Buffer.from(FIRST);
    odd.writeUInt32LE(bits, 72);
    const next = Buffer.from(mine({ previous: sha256d(odd), time: T0 + 600 }));
    next.writeUInt32LE(bits, 72);
    add(`a target that is ${name}`, [odd, next], { rules: { ...RULES, first: odd.toString('hex') }, workAfter: -1 });
  }
  // A long chain, and every byte of one header changed in turn.
  const long = chainOf(2100, { step: 1 });
  add('a chain of 2,101 blocks a second apart', long, { workAfter: 1000 });
  const sixteen = chainOf(16);
  for (let at = 0; at < 80; at++) add(`byte ${at} of block 15 changed`, sixteen, { change: { flip: [15 * 80 + at, 1] } });
  for (let at = 0; at < 80; at += 7) add(`byte ${at} of block 0 changed`, sixteen, { change: { flip: [at, 0x80] } });
  return cases;
}

function checkHeaderChainCases() {
  const cases = [];
  const now = Date.parse('2026-10-08T00:00:00Z');
  cases.push({ name: 'only the first block of the Bitcoin chain', bytes: BITCOIN.first, now });
  cases.push({ name: 'the first block of the Bitcoin chain, changed', bytes: BITCOIN.first, now, change: { flip: [79, 1] } });
  cases.push({ name: 'a made-up first block', bytes: hex(FIRST), now });
  cases.push({ name: 'nothing', bytes: '', now });
  cases.push({ name: '79 bytes', bytes: BITCOIN.first.slice(2), now });
  cases.push({ name: 'the first block and half a header', bytes: BITCOIN.first + BITCOIN.first.slice(0, 80), now });
  cases.push({ name: 'the first block twice', bytes: BITCOIN.first + BITCOIN.first, now });
  // The real first block and the second block of the real chain.
  const second = '010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299';
  cases.push({ name: 'the first two blocks of the Bitcoin chain', bytes: BITCOIN.first + second, now });
  cases.push({ name: 'the first two blocks, the second changed', bytes: BITCOIN.first + second, now, change: { flip: [80 + 40, 1] } });
  cases.push({ name: 'the first two blocks, with the clock before the second', bytes: BITCOIN.first + second, now: 1231469665000 - 7201 * 1000 });
  for (const [name, value] of [['null', null], ['text', 'headers'], ['a list', [1, 2]]]) cases.push({ name: `not bytes: ${name}`, bytesValue: value, now });
  return cases;
}

function headerStepsCases() {
  const cases = [];
  const chain = chainOf(40);
  const now = (timeOfHeader(chain.at(-1)) + 3600) * 1000;
  const adds = (from, to, chainIndex = 0, list = chain) => Array.from({ length: to - from }, (_, i) => ({ op: 'add', header: hex(list[from + i]), now, ...(chainIndex ? { chain: chainIndex } : {}) }));
  const show = (more = {}) => ({ op: 'show', ...more });
  const fps = [writtenHash(sha256d(chain[5])), writtenHash(sha256d(chain[25])), writtenHash(sha256d(chain[39]))];
  cases.push({ name: 'added one at a time', rules: RULES, steps: [show(), ...adds(0, 40), show({ lookups: fps, workAfter: 0 })] });
  cases.push({ name: 'not bytes, then the wrong length', rules: RULES, steps: [{ op: 'add', value: null, now }, { op: 'add', header: hex(chain[0]).slice(2), now }, ...adds(0, 2), { op: 'add', value: 'text', now }, show()] });
  cases.push({ name: 'a header refused, then the right one', rules: RULES, steps: [...adds(0, 5), { op: 'add', header: hex(chain[6]), now }, ...adds(5, 8), show({ lookups: fps })] });
  cases.push({
    name: 'cut back and carried on',
    rules: RULES,
    steps: [...adds(0, 30), { op: 'keepTo', height: 20 }, show({ lookups: fps }), ...adds(21, 30), show({ lookups: fps }), { op: 'keepTo', height: 30 }, { op: 'keepTo', height: -1 }, { op: 'keepTo', height: 0 }, show()],
  });
  // A branch: a copy cut back and carried on with other headers, then taken on.
  const branch = chainOf(30, { at: { 25: () => ({ root: Buffer.alloc(32, 0xee) }) } });
  cases.push({
    name: 'a copy that takes another branch, and is taken on',
    rules: RULES,
    steps: [...adds(0, 30), { op: 'copy' }, { op: 'keepTo', height: 24, chain: 1 }, ...adds(25, 31, 1, branch), show({ chain: 1, lookups: fps }), show({ lookups: fps }), { op: 'adopt', from: 1 }, show({ lookups: fps, workAfter: 20 }), ...adds(31, 35), show()],
  });
  cases.push({ name: 'a copy of a chain that holds nothing', rules: RULES, steps: [{ op: 'copy' }, show({ chain: 1 }), ...adds(0, 3, 1), show({ chain: 1 }), show()] });
  // Taking on a chain that holds nothing leaves no room to add to: the JavaScript library throws there.
  cases.push({
    name: 'taking on a chain that holds nothing, then adding',
    rules: { ...RULES, known: [[0, writtenHash(sha256d(chain[0]))]] },
    steps: [{ op: 'copy' }, ...adds(0, 4), { op: 'adopt', from: 1 }, show(), ...adds(0, 2), show(), { op: 'adopt', from: 0, chain: 1 }, ...adds(0, 3, 1), show({ chain: 1 })],
  });
  cases.push({ name: 'a step on a chain that does not exist', rules: RULES, steps: [show({ chain: 3 }), { op: 'adopt', from: 5 }, ...adds(0, 1), show()] });
  // Growing past the room set aside at first (1,024 headers).
  const long = chainOf(1100, { step: 1 });
  const longNow = (timeOfHeader(long.at(-1)) + 3600) * 1000;
  cases.push({
    name: 'growing past 1,024 headers, cut back and grown again',
    rules: RULES,
    steps: [
      ...long.slice(0, 1050).map((h) => ({ op: 'add', header: hex(h), now: longNow })),
      { op: 'copy' },
      { op: 'keepTo', height: 500 },
      ...long.slice(501, 1101).map((h) => ({ op: 'add', header: hex(h), now: longNow })),
      show({ lookups: [writtenHash(sha256d(long[1024])), writtenHash(sha256d(long[1100]))] }),
      show({ chain: 1 }),
    ],
  });
  // A known block, the floor it sets, and cutting back below it.
  const hard = 0x1f200000;
  const first = mine({ previous: Buffer.alloc(32), time: T0, bits: hard });
  const easing = { ...RULES, first: hex(first), retarget: true, interval: 10, timespan: 1000 };
  const headers = [first];
  for (let h = 1; h <= 30; h++) {
    const prev = headers[h - 1];
    const bits = h % 10 === 0 ? nextBits(bitsOfHeader(prev), timeOfHeader(headers[h - 10]), timeOfHeader(prev), { ...easing, limit: bigOf(easing.limit) }) : bitsOfHeader(prev);
    const time = h <= 10 ? T0 + h * 100 : T0 + 1000 + (h - 10) * 1000;
    headers.push(mine({ previous: sha256d(prev), time, bits }));
  }
  const easeNow = (timeOfHeader(headers[30]) + 3600) * 1000;
  const known = { ...easing, known: [[10, writtenHash(sha256d(headers[10]))]] };
  const easeAdds = (from, to, c = 0) => headers.slice(from, to).map((h) => ({ op: 'add', header: hex(h), now: easeNow, ...(c ? { chain: c } : {}) }));
  cases.push({
    name: 'the floor set by the last known block, kept and lost',
    rules: known,
    steps: [...easeAdds(0, 31), show(), { op: 'keepTo', height: 9 }, ...easeAdds(10, 31), show(), { op: 'keepTo', height: 9 }, { op: 'copy' }, ...easeAdds(10, 31, 1), show({ chain: 1 }), { op: 'adopt', from: 1 }, show({ workAfter: 0 })],
  });
  return cases;
}

async function answerForCases() {
  const cases = [];
  const chain = chainOf(30);
  const now = (timeOfHeader(chain.at(-1)) + 3600) * 1000;
  cases.push({
    name: 'a chain of 31 blocks',
    bytes: hex(joined(chain)),
    now,
    rules: RULES,
    lookups: [writtenHash(sha256d(chain[24])), writtenHash(sha256d(chain[30])), writtenHash(sha256d(chain[0])), 'f'.repeat(64), null, 5, writtenHash(sha256d(chain[3])).toUpperCase()],
  });
  cases.push({ name: 'only the first block', bytes: hex(FIRST), now, rules: RULES, lookups: [writtenHash(sha256d(FIRST))] });
  return cases;
}

function blocksInChainCases() {
  const a = 'a'.repeat(64);
  const b = 'b'.repeat(64);
  const c = 'c'.repeat(64);
  const chain = { [a]: { height: 20, after: 6 }, [b]: { height: 30, after: 5 }, [c]: { height: 0, after: 100 } };
  const block = (authority, height = 912345) => ({ kind: 'block', authority, height });
  const cases = [];
  const add = (name, result) => cases.push({ name, result, chain });
  add('no entries', {});
  add('an empty list of entries', { entries: [] });
  add('entries with no stamps', { entries: [{}, { stamps: [] }] });
  add('a block in the chain with six after it', { entries: [{ stamps: [block(a)] }] });
  add('a block in the chain with five after it', { entries: [{ stamps: [block(b)] }] });
  add('a block not in the chain', { entries: [{ stamps: [block('d'.repeat(64))] }] });
  add('a time-stamp from a service', { entries: [{ stamps: [{ kind: 'service', authority: a }] }] });
  add('a block named twice', { entries: [{ stamps: [block(a), block(a, 1)] }, { stamps: [block(a)] }] });
  add('a block with no authority', { entries: [{ stamps: [{ kind: 'block', authority: null, height: 1 }] }] });
  add('a block with no number', { entries: [{ stamps: [{ kind: 'block', authority: c }] }] });
  add('blocks beside the book', { entries: [{ stamps: [block(b)] }], held: [{ stamps: [block(a), block(c)] }, {}] });
  add('many', { entries: [{ stamps: [block(c), block(b)] }, { stamps: [block(a), { kind: 'service', authority: 'x' }] }], held: [{ stamps: [block(c)] }] });
  return cases;
}

/** Each set of cases, by the name of its file. */
export const CASES = {
  'tree-leaves': async () => vectorSet('The fingerprint of one leaf of the tree (RFC 6962 section 2.1): SHA-256 of 0x00 and the leaf.', 'leafHash', leafHashCases()),
  'tree-roots': async () => vectorSet('The top fingerprint of a tree of leaves (RFC 6962 section 2.1; format description, section 10).', 'treeRoot', treeRootCases()),
  'tree-builder': async () => vectorSet('The top fingerprint worked out as the leaves arrive, and a builder split off part of the way.', 'treeBuilder', treeBuilderCases()),
  'tree-paths': async () => vectorSet('The audit path for one leaf (RFC 6962 section 2.1.1).', 'inclusionPath', await inclusionPathCases()),
  'tree-inclusion': async () => vectorSet('Checking an audit path (RFC 9162 section 2.1.3.2).', 'verifyInclusion', await verifyInclusionCases()),
  'der-elements': async () => vectorSet('Reading one DER element strictly (ITU-T X.690).', 'readElement', readElementCases()),
  'der-children': async () => vectorSet('Reading the items inside a DER element.', 'children', childrenCases()),
  'der-strict': async () => vectorSet('Refusing anything that is not strict DER, at every level.', 'validateDer', validateDerCases()),
  'der-times': async () => vectorSet('Reading a time in the two forms DER allows: milliseconds since 1970.', 'timeOf', timeOfCases()),
  'der-ecdsa': async () => vectorSet('An ECDSA signature from its DER form to the two numbers side by side.', 'ecdsaToRaw', ecdsaToRawCases()),
  stamps: async () => vectorSet('Checking a time-stamp from a service (RFC 3161; format description, section 21.2), made up here with every part changed in turn.', 'checkStamp', await stampCases()),
  'stamps-openssl': async () => vectorSet('Checking time-stamps made by the OpenSSL program (test/fixtures/stamps.json), as made and changed.', 'checkStamp', opensslCases()),
  'stamps-flips-ecdsa': async () => {
    const key = makeKey('P-256');
    const cert = certificate(key);
    const token = makeToken(key, { cert, tail: [seq(int(1)), H('010100'), int(77), der(0xa1, seq(oid(OID.someExtension), octets(NULL)))] });
    return vectorSet('A time-stamp signed with ECDSA P-256, with every byte changed in turn.', 'checkStamp', [...flipCases(token, STAMPED, { trusted: [authorityOf(cert)] }), ...cutCases(token, STAMPED, { trusted: [authorityOf(cert)] }, 7)]);
  },
  'stamps-flips-ed25519': async () => {
    const key = makeKey('Ed25519');
    const cert = certificate(key, { noVersion: true });
    const token = makeToken(key, { cert, signerVersion: int(3), signerName: der(0x80, H('0102030405060708')) });
    return vectorSet('A time-stamp signed with Ed25519, with every byte changed in turn.', 'checkStamp', flipCases(token, STAMPED, { trusted: [authorityOf(cert)] }, 1, 0, [0x01, 0x80]));
  },
  'stamps-flips-rsa': async () => {
    const key = makeKey('RSA-2048');
    const cert = certificate(key);
    const token = makeToken(key, { cert, hash: 'SHA-512' });
    return vectorSet('A time-stamp signed with RSA 2048 and SHA-512, with every second byte changed in turn.', 'checkStamp', flipCases(token, STAMPED, { trusted: [authorityOf(cert)] }, 2, 1));
  },
  'block-stamps': async () => vectorSet('Checking a block time-stamp (format description, section 21.4), made up here.', 'checkBlockStamp', await blockStampCases()),
  'block-stamps-flips': async () => vectorSet('A block time-stamp with every byte of its proof changed in turn.', 'checkBlockStamp', await blockFlipCases()),
  'block-fingerprints': async () => vectorSet('The fingerprint of a block: SHA-256 twice over its header, the bytes in reverse order, in hex.', 'blockFingerprint', await blockFingerprintCases()),
  'block-stamp-items': async () => vectorSet('A proof and its block header in the form they have beside a seal.', 'blockStampItem', await blockStampItemCases()),
  'seal-contents': async () => vectorSet("Confirming the members of a seal's content (format description, section 21.1).", 'validateSealContent', await sealContentCases()),
  'seal-stamps': async () => vectorSet('Confirming and decoding the time-stamps beside a seal or a cancellation (format description, section 21.2).', 'decodeStamps', sealStampCases()),
  'seal-key-sets': async () => vectorSet("The fingerprint of a recorder's key set (format description, section 21.1).", 'keySetFingerprint', await keySetFingerprintCases()),
  'header-bits': async () => vectorSet('The difficulty at the start of a run of blocks, from the run before it.', 'nextBits', nextBitsCases()),
  'header-chains': async () => vectorSet('Reading a chain of block headers by given rules, from a made-up first block.', 'readHeaderChain', readHeaderChainCases()),
  'header-checks': async () => vectorSet('Checking a chain of Bitcoin block headers held in a file, by the rules of the real chain.', 'checkHeaderChain', checkHeaderChainCases()),
  'header-steps': async () => vectorSet('A chain of block headers added to, cut back, copied and taken on, one step at a time.', 'headerChainSteps', headerStepsCases()),
  'header-answers': async () => vectorSet('What a check of a chain of headers gives, and finding a block in it.', 'answerFor', await answerForCases()),
  'header-blocks': async () => vectorSet('The blocks a check\'s block time-stamps lead to that a chain of headers holds with six blocks after them.', 'blocksInChain', blocksInChainCases()),
};
