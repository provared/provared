// Shared test cases for consistency proofs (RFC 9162, section 2.1.4) and
// for witness statements beside seals (format description, section 29).
//
// The books, Shows and checks before acting are answered as on a device
// without SLH-DSA (the seal's third signing method), as in vectors-book.mjs,
// so that an implementation that lacks SLH-DSA can be held to every answer.
// A statement then counts on its seal's first two signatures.

import { assembleSlip, checkBefore, checkBook, checkShow, countersign, entryLine, fingerprint, fromBase64url, generateKeySet, generateSealKeySet, makeShow, openWitness, prepareSlip, toBase64url, utf8, witnessProof, writeBook, writeDenial, writeSeal, writeStub, writeTerms, writeWitness } from '../../src/index.js';
import { ANSWER as STAMPS } from './vectors-stamps.mjs';
import { thumbprint } from '../../src/keys.js';
import { keySetFingerprint } from '../../src/seal.js';
import { consistencyProof, treeRoot, verifyConsistency } from '../../src/tree.js';
import { answer, finish } from './vector-tools.mjs';
import { START, makeWorld, withContent } from './world.mjs';

const SLH = 'SLH-DSA-SHA2-256s';
const withoutSlh = (options = {}) => ({ ...options, withoutMethods: [...(Array.isArray(options.withoutMethods) ? options.withoutMethods : []), SLH] });
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const H = (text) => Uint8Array.from(Buffer.from(text, 'hex'));
// Text is hexadecimal bytes; a list is read item by item; anything else is handed over as it is.
const bytesOf = (value) => (typeof value === 'string' ? H(value) : value);
const listOf = (value) => (Array.isArray(value) ? value.map(bytesOf) : value);

/** How each kind of case is answered. */
export const ANSWER = {
  // For each earlier size m: the proof, and whether it checks against the roots this library works out.
  consistencyProof: (c) =>
    answer(async () => {
      const leaves = listOf(c.leaves);
      const out = [];
      for (const m of c.ms) {
        const proof = await consistencyProof(leaves, m);
        const checks = await verifyConsistency(m, leaves.length, await treeRoot(leaves.slice(0, m)), await treeRoot(leaves), proof);
        out.push({ m, proof: proof.map(hex), checks });
      }
      return out;
    }),
  verifyConsistency: (c) => answer(() => verifyConsistency(c.m, c.n, bytesOf(c.rootM), bytesOf(c.rootN), listOf(c.proof))),
};

// --- consistency proofs ---

// The data of leaf i: three bytes, as in the cases of the audit path.
const leafData = (i) => hex(new Uint8Array([i & 0xff, (i * 7) & 0xff, 0xab]));

function consistencyCases() {
  const cases = [];
  for (let n = 1; n <= 64; n++) {
    const leaves = Array.from({ length: n }, (_, i) => leafData(i));
    cases.push({ name: `every earlier tree of a tree of ${n}`, leaves, ms: Array.from({ length: n + 1 }, (_, m) => m) });
  }
  const four = Array.from({ length: 4 }, (_, i) => leafData(i));
  for (const m of [5, -1, 1.5, '1', null, true, 2 ** 53]) cases.push({ name: `an earlier tree of ${JSON.stringify(m)} leaves, of a tree of 4`, leaves: four, ms: [m] });
  cases.push({ name: 'no leaves, and an earlier tree of none', leaves: [], ms: [0] });
  cases.push({ name: 'leaves that are not a list', leaves: 'ab', ms: [0] });
  // A large tree.
  const big = Array.from({ length: 1000 }, (_, i) => hex(new Uint8Array([i & 0xff, i >> 8])));
  cases.push({ name: 'a tree of 1,000, from earlier trees of several sizes', leaves: big, ms: [1, 2, 511, 512, 513, 999, 1000] });
  return cases;
}

async function consistencyCheckCases() {
  const cases = [];
  const add = (name, m, n, rootM, rootN, proof) => cases.push({ name, m, n, rootM, rootN, proof });
  const data = Array.from({ length: 33 }, (_, i) => H(leafData(i)));
  const roots = [];
  for (let n = 0; n <= 33; n++) roots.push(hex(await treeRoot(data.slice(0, n))));
  const flip = (h, at) => {
    const b = H(h);
    b[at % 32] ^= 1;
    return hex(b);
  };
  for (let n = 2; n <= 12; n++) {
    for (let m = 1; m < n; m++) {
      const proof = (await consistencyProof(data.slice(0, n), m)).map(hex);
      add(`${m} to ${n}`, m, n, roots[m], roots[n], proof);
      for (let i = 0; i < proof.length; i++) {
        add(`${m} to ${n}: value ${i} changed`, m, n, roots[m], roots[n], proof.map((p, j) => (j === i ? flip(p, i) : p)));
        add(`${m} to ${n}: value ${i} left out`, m, n, roots[m], roots[n], proof.filter((_, j) => j !== i));
      }
      add(`${m} to ${n}: a value added at the end`, m, n, roots[m], roots[n], [...proof, roots[1]]);
      add(`${m} to ${n}: the earlier root added at the start`, m, n, roots[m], roots[n], [roots[m], ...proof]);
      add(`${m} to ${n}: no values`, m, n, roots[m], roots[n], []);
      add(`${m} to ${n}: another later root`, m, n, roots[m], roots[n - 1], proof);
      add(`${m} to ${n}: another earlier root`, m, n, roots[m - 1] ?? roots[0], roots[n], proof);
      add(`${m} to ${n}: as from ${m + 1}`, m + 1, n, roots[m + 1], roots[n], proof);
      add(`${m} to ${n}: as to ${n + 1}`, m, n + 1, roots[m], roots[n + 1], proof);
    }
  }
  // A sound proof with its own roots, offered as a proof between other sizes: refused only by the size steps
  // of section 2.1.4.2 ("if sn is 0, stop and fail", and "sn is 0" at the end).
  for (const [m, n, m2, n2] of [[1, 2, 1, 3], [1, 2, 1, 4], [3, 4, 3, 5], [7, 8, 3, 4], [7, 8, 5, 6], [7, 8, 6, 7], [7, 8, 9, 10], [6, 8, 6, 12], [5, 9, 5, 7]]) {
    add(`the proof of ${m} to ${n}, with its roots, offered as one of ${m2} to ${n2}`, m2, n2, roots[m], roots[n], (await consistencyProof(data.slice(0, n), m)).map(hex));
  }
  // The edges.
  add('m equal to n, the same roots', 7, 7, roots[7], roots[7], []);
  add('m equal to n, other roots', 7, 7, roots[7], roots[6], []);
  add('m equal to n, a value given', 7, 7, roots[7], roots[7], [roots[7]]);
  add('m of 0, the root of the empty tree', 0, 5, roots[0], roots[5], []);
  add('m of 0, another earlier root', 0, 5, roots[1], roots[5], []);
  add('m of 0, a value given', 0, 5, roots[0], roots[5], [roots[5]]);
  add('both of 0', 0, 0, roots[0], roots[0], []);
  for (const m of [1, 2, 4, 8, 16, 32]) {
    add(`m of ${m}, a power of two, to 33`, m, 33, roots[m], roots[33], (await consistencyProof(data, m)).map(hex));
  }
  // What is not a proof of those sizes.
  const proof = (await consistencyProof(data.slice(0, 10), 3)).map(hex);
  for (const m of [3.5, -1, 11, '3', null, true]) add(`m of ${JSON.stringify(m)}`, m, 10, roots[3], roots[10], proof);
  for (const n of [2 ** 53, -1, '10', null]) add(`n of ${JSON.stringify(n)}`, 3, n, roots[3], roots[10], proof);
  add('m larger than n', 10, 3, roots[10], roots[3], proof);
  // Without the rule that m is not larger than n, the steps would pass this one.
  add('the proof of 3 to 4, with its roots, offered as one of 7 to 3', 7, 3, roots[3], roots[4], (await consistencyProof(data.slice(0, 4), 3)).map(hex));
  add('an earlier root of 31 bytes', 3, 10, roots[3].slice(0, 62), roots[10], proof);
  add('a later root that is not bytes', 3, 10, roots[3], 5, proof);
  add('a proof that is not a list', 3, 10, roots[3], roots[10], 5);
  add('a value of 31 bytes', 3, 10, roots[3], roots[10], [...proof.slice(0, -1), proof.at(-1).slice(0, 62)]);
  add('a value of 33 bytes', 3, 10, roots[3], roots[10], [...proof.slice(0, -1), proof.at(-1) + '00']);
  add('a value that is not bytes', 3, 10, roots[3], roots[10], [...proof.slice(0, -1), 5]);
  add('a value that is nothing', 3, 10, roots[3], roots[10], [...proof.slice(0, -1), null]);
  add('sizes past 2 to the power 32', 2 ** 32, 2 ** 32 + 1, roots[1], roots[2], [roots[1]]);
  return cases;
}

// --- witnesses ---

// A book of a slip, two stubs, a first seal (time-stamped, with the first
// witness's statement), a stub, a second seal (with no time-stamp, with
// both witnesses' statements) and a stub. The second witness also signs
// for the first seal later: that statement is not in the book, and is
// handed over beside it. Made once: signing a seal is slow.
let world;
function witnessWorld() {
  world ??= (async () => {
    const w = await makeWorld({ fields: { requires: [] } });
    await w.add({ value: 10 });
    await w.add({ value: 10 });
    const one = await generateKeySet();
    const two = await generateKeySet();
    const clock = () => Date.parse('2026-10-06T00:00:00Z');
    const first = await openWitness({ by: { keys: one.keys, name: 'First witness (invented)' }, signers: one.privateKeys, clock });
    const second = await openWitness({ by: { keys: two.keys, name: 'Second witness (invented)' }, signers: two.privateKeys, clock });
    const firstLine = utf8(w.book().split('\n')[0]);
    const sign = async (witness, entry, book, from) => {
      const size = book.split('\n').filter(Boolean).length;
      const r = await witness.witness(entry, await witnessProof(book, size, from), firstLine);
      if (r.refused) throw new Error(`a witness refused: ${r.refused.message}`);
      return r.statement;
    };
    const sealOne = await w.seal({ witnesses: async (sealed, book) => [await sign(first, { seal: sealed.record }, book, null)] });
    // The second witness sees the first seal only after it is in the book.
    const late = await sign(second, { seal: sealOne.record }, w.book().split('\n').slice(0, 3).join('\n') + '\n', null);
    await w.add({ value: 10 });
    const sealTwo = await w.seal({
      stamp: false,
      witnesses: async (sealed, book) => [await sign(first, { seal: sealed.record }, book, 3), await sign(second, { seal: sealed.record }, book, 3)],
    });
    await w.add({ value: 10 });
    const witnesses = { one: await keySetFingerprint(one.keys), two: await keySetFingerprint(two.keys) };
    const trust = { issuerKeys: [await thumbprint(w.passkey.key)], sealKeys: [await keySetFingerprint(w.recorder.keys)], witnesses: [witnesses.one, witnesses.two] };
    const lines = w.book().split('\n').filter(Boolean);
    return { w, one, two, sealOne, sealTwo, late, witnesses, trust, lines, text: w.book() };
  })();
  return world;
}

const book = (lines) => lines.join('\n') + '\n';
const withLine = (lines, at, line) => book(lines.map((l, i) => (i === at ? line : l)));

async function witnessBookCases() {
  const cases = [];
  const add = (name, text, options = {}) => cases.push({ name, text, options: withoutSlh(options) });
  const { w, one, two, sealOne, sealTwo, late, witnesses, trust, lines, text } = await witnessWorld();
  const { witnesses: _, ...noWitness } = trust;
  const { sealKeys: __, ...noRecorder } = trust;
  const at1 = 3;
  const at2 = 5;
  const entry1 = JSON.parse(lines[at1]);
  const entry2 = JSON.parse(lines[at2]);

  add('two seals witnessed, both witnesses named', text, trust);
  add('two seals witnessed, no witness named', text, noWitness);
  add('two seals witnessed, a witness named that signed for neither', text, { ...noWitness, witnesses: [toBase64url(new Uint8Array(32).fill(5))] });
  add('two seals witnessed, only the second witness named', text, { ...noWitness, witnesses: [witnesses.two] });
  add('two seals witnessed, the witnesses given as text', text, { ...noWitness, witnesses: witnesses.one });
  add('two seals witnessed, its recorder not named', text, noRecorder);
  add('two seals witnessed, on a device without ML-DSA-87', text, { ...trust, withoutMethods: ['ML-DSA-87'] });
  add('two seals witnessed, on a device without Ed25519', text, { ...trust, withoutMethods: ['Ed25519'] });

  // A statement that does not pass, on the seal's own line. The second seal is used: no seal after it covers its
  // line, so only its own entry is marked.
  const changed = withContent(entry2.witnesses[0], (c) => ({ ...c, when: '2026-10-06T00:00:01Z' }));
  const at = (statements) => withLine(lines, at2, entryLine({ ...entry2, witnesses: statements }));
  add('a statement changed after it was signed', at([changed, entry2.witnesses[1]]), trust);
  add('a statement for the first seal beside the second', at([late]), trust);
  add("the first seal's own statement beside the second: its unique number is in the book already", at([entry1.witnesses[0]]), trust);
  const seal2 = JSON.parse(Buffer.from(sealTwo.record.payload, 'base64url').toString());
  const seal1 = JSON.parse(Buffer.from(sealOne.record.payload, 'base64url').toString());
  const statement = (keys, name, when, id) => writeWitness({ id, seal: sealTwo.fingerprint, size: seal2.size, root: seal2.root, by: { keys: keys.keys, name }, when }, keys.privateKeys);
  const early = await statement(one, 'First witness (invented)', Date.parse(seal2.when) - 301000);
  const prompt = await statement(one, 'First witness (invented)', Date.parse(seal2.when) - 300000);
  add('a statement dated 301 seconds before its seal', at([early.record]), trust);
  const wrongSize = await writeWitness({ seal: sealTwo.fingerprint, size: seal2.size + 1, root: seal2.root, by: { keys: one.keys, name: 'First witness (invented)' }, when: Date.parse('2026-10-06T00:00:00Z') }, one.privateKeys);
  const wrongRoot = await writeWitness({ seal: sealTwo.fingerprint, size: seal2.size, root: seal1.root, by: { keys: one.keys, name: 'First witness (invented)' }, when: Date.parse('2026-10-06T00:00:00Z') }, one.privateKeys);
  add("a statement with the seal's fingerprint and another number of entries", at([wrongSize.record]), trust);
  add("a statement with the seal's fingerprint and another top fingerprint", at([wrongRoot.record]), trust);
  add('a seal line with "witness" in place of "witnesses"', withLine(lines, at2, entryLine({ seal: entry2.seal, witness: entry2.witnesses })), trust);
  add('two seals witnessed, no passkey named', text, (({ issuerKeys: _x, ...rest }) => rest)(trust));
  add('two seals witnessed, another passkey named: the first permission does not pass, and no statement counts', text, { ...trust, issuerKeys: [toBase64url(new Uint8Array(32).fill(5))] });
  add('a statement dated 300 seconds before its seal', at([prompt.record]), trust);
  add('the same witness twice beside one seal', at([entry2.witnesses[0], prompt.record]), trust);
  add('the same statement twice beside one seal', at([entry2.witnesses[0], entry2.witnesses[0]]), trust);
  add('five statements beside one seal', at(Array(5).fill(entry2.witnesses[0])), trust);
  add('no statements in the list', at([]), trust);
  add('statements that are not a list', withLine(lines, at2, entryLine({ ...entry2, witnesses: { 0: entry2.witnesses[0] } })), trust);
  add('a statement that is not a record', at([5]), trust);
  const denial = await writeDenial({ slip: w.slipFingerprint, action: 'supplies.order', source: 'rule', when: START }, w.agent.privateKeys);
  add('a denial in the place of a statement', at([denial.record]), trust);
  const stubId = JSON.parse(Buffer.from(JSON.parse(lines[1]).stub.payload, 'base64url').toString()).id;
  const sameId = await statement(two, 'Second witness (invented)', Date.parse('2026-10-06T00:00:00Z'), stubId);
  add('a statement that repeats the unique number of a stub', at([entry2.witnesses[0], sameId.record]), trust);
  add("a statement on the first seal's line changed: the second seal no longer fits", withLine(lines, at1, entryLine({ ...entry1, witnesses: [withContent(entry1.witnesses[0], (c) => ({ ...c, when: '2026-10-06T00:00:01Z' }))] })), trust);
  // A sound statement beside a seal that does not fit its book.
  add('a witnessed seal over an entry changed after it was made', withLine(lines, 1, lines[2]), trust);

  // Statements handed over beside the book, with a seal held elsewhere.
  add('a later statement for the first seal, handed over with it', text, { ...trust, seals: [{ seal: sealOne.record, witnesses: [late] }] });
  add('a later statement for the first seal, its witness alone named', text, { ...noWitness, witnesses: [witnesses.two], seals: [{ seal: sealOne.record, witnesses: [late] }] });
  add('the book cut back before the second seal, which is handed over with its statements', book(lines.slice(0, 5)), { ...trust, seals: [entry2] });
  add('a statement handed over that was changed', text, { ...trust, seals: [{ seal: sealOne.record, witnesses: [withContent(late, (c) => ({ ...c, when: '2026-10-06T00:00:01Z' }))] }] });
  add('a statement handed over for another seal', text, { ...trust, seals: [{ seal: sealOne.record, witnesses: [entry2.witnesses[1]] }] });
  add('statements handed over that are not a list', text, { ...trust, seals: [{ seal: sealOne.record, witnesses: late }] });
  add('a statement handed over, its recorder not named', text, { ...noRecorder, seals: [{ seal: sealOne.record, witnesses: [late] }] });
  add('a statement handed over, on a device without ML-DSA-87', text, { ...trust, withoutMethods: ['ML-DSA-87'], seals: [{ seal: sealOne.record, witnesses: [late] }] });
  add('a held seal that does not pass, with a statement', text, { ...trust, seals: [{ seal: { ...sealOne.record, payload: sealTwo.record.payload }, witnesses: [late] }] });
  return cases;
}

async function witnessShowCases() {
  const cases = [];
  const add = (name, show, options = {}) => cases.push({ name, show, options: withoutSlh(options) });
  const { trust, text } = await witnessWorld();
  const { witnesses: _, ...noWitness } = trust;
  const pages = await makeShow(text, [0, 1, 3]);
  add('a Show with a witnessed seal among its pages, not every page it covers: single pages cannot count', pages, trust);
  add('a Show of every page a witnessed seal covers, and the seal', await makeShow(text, [0, 1, 2, 3]), trust);
  add('a Show with a witnessed seal among its pages, no witness named', pages, noWitness);
  const under = await makeShow(text, [0, 4], { seal: 5 });
  add('a Show under a witnessed seal', under, trust);
  add('a Show under a witnessed seal, with its statements left out', { ...under, seal: { seal: under.seal.seal } }, trust);
  add('a Show under a seal with a statement that is not a list', { ...under, seal: { ...under.seal, witnesses: 'x' } }, trust);
  return cases;
}

async function witnessBeforeCases() {
  const cases = [];
  const { w, sealOne, late, trust, lines, text } = await witnessWorld();
  const proposal = { slip: w.slipFingerprint, action: 'supplies.order', amount: { unit: 'GBP', value: 1 }, with: 'supplier', when: START + 6 * 3600 * 1000 };
  const add = (name, book, options) => cases.push({ name, text: book, proposal, options: withoutSlh(options) });
  add('a book with witnessed seals', text, trust);
  add('a book with witnessed seals, on a device without ML-DSA-87', text, { ...trust, withoutMethods: ['ML-DSA-87'] });
  add('a book with a statement handed over beside it', text, { ...trust, seals: [{ seal: sealOne.record, witnesses: [late] }] });
  const entry1 = JSON.parse(lines[3]);
  const changed = withContent(entry1.witnesses[0], (c) => ({ ...c, when: '2026-10-06T00:00:01Z' }));
  add('a book whose statement was changed', withLine(lines, 3, entryLine({ ...entry1, witnesses: [changed] })), trust);
  return cases;
}

// --- the books of one permission (format description, section 21.6) ---

const recorderBy = (keys) => ({ keys: keys.keys, name: 'Example recorder (invented)' });

// Two books of one permission, sealed by one recorder and witnessed. Book 1: the slip, a stub, a seal, a stub, a
// seal (its last). Book 2: the slip, a stub, its first seal (book 2, naming the last seal of book 1), a stub, a seal.
// Made once: signing a seal is slow.
let chain;
function chainedWorld() {
  chain ??= (async () => {
    const w = await makeWorld({ fields: { requires: [] } });
    const recorder = await generateSealKeySet();
    const other = await generateSealKeySet();
    const one = await generateKeySet();
    const witness = await openWitness({ by: { keys: one.keys, name: 'Example witness (invented)' }, signers: one.privateKeys, clock: () => Date.parse('2026-10-06T00:00:00Z') });
    const slipLine = entryLine(w.entries[0]);
    const firstLine = utf8(slipLine);
    const lines = (text) => text.split('\n').filter(Boolean);
    const sealAndWitness = async (text, fields, from, keys = recorder) => {
      const sealed = await writeSeal(text, { by: recorderBy(keys), ...fields }, keys.privateKeys);
      const r = await witness.witness({ seal: sealed.record }, await witnessProof(text, lines(text).length, from), firstLine);
      if (!r.statement) throw new Error(`a witness refused: ${r.refused.message}`);
      return { sealed, statement: r.statement };
    };
    // Book 1.
    await w.add({ value: 10 });
    let text = w.book();
    const a1 = await sealAndWitness(text, { when: START + 2 * 3600 * 1000 }, null);
    text += entryLine({ seal: a1.sealed.record, witnesses: [a1.statement] }) + '\n';
    const stub2 = await w.add({ value: 10, when: START + 3 * 3600 * 1000 });
    text += entryLine(stub2.entry) + '\n';
    const a2 = await sealAndWitness(text, { previous: a1.sealed.fingerprint, when: START + 4 * 3600 * 1000 }, 2);
    const bookA = text + entryLine({ seal: a2.sealed.record, witnesses: [a2.statement] }) + '\n';
    // Book 2: the same permission on its first line, then the stubs that follow.
    // Its stubs form a chain of their own, from 0.
    w.after = null;
    const stub3 = await w.add({ value: 10, when: START + 5 * 3600 * 1000 });
    let textB = slipLine + '\n' + entryLine(stub3.entry) + '\n';
    const b1 = await sealAndWitness(textB, { book: 2, previous: a2.sealed.fingerprint, when: START + 6 * 3600 * 1000 }, null);
    textB += entryLine({ seal: b1.sealed.record, witnesses: [b1.statement] }) + '\n';
    const stub4 = await w.add({ value: 10, when: START + 7 * 3600 * 1000 });
    textB += entryLine(stub4.entry) + '\n';
    const b2 = await sealAndWitness(textB, { book: 2, previous: b1.sealed.fingerprint, when: START + 8 * 3600 * 1000 }, 2);
    const bookB = textB + entryLine({ seal: b2.sealed.record, witnesses: [b2.statement] }) + '\n';
    // A book 2 whose first seal is by other keys, and one dated before the last seal of book 1 (neither witnessed).
    const otherKeys = await writeSeal(slipLine + '\n' + entryLine(stub3.entry) + '\n', { by: recorderBy(other), book: 2, previous: a2.sealed.fingerprint, when: START + 6 * 3600 * 1000 }, other.privateKeys);
    const early = await writeSeal(slipLine + '\n' + entryLine(stub3.entry) + '\n', { by: recorderBy(recorder), book: 2, previous: a2.sealed.fingerprint, when: START + 3 * 3600 * 1000 }, recorder.privateKeys);
    const trust = {
      issuerKeys: [await thumbprint(w.passkey.key)],
      sealKeys: [await keySetFingerprint(recorder.keys), await keySetFingerprint(other.keys)],
      witnesses: [await keySetFingerprint(one.keys)],
    };
    return { w, one, recorder, slipLine, stub3, a1, a2, b1, b2, bookA, bookB, otherKeys, early, trust };
  })();
  return chain;
}

async function chainedBookCases() {
  const cases = [];
  const add = (name, text, options = {}) => cases.push({ name, text, options: withoutSlh(options) });
  const { w, one, slipLine, stub3, a1, a2, b1, bookA, bookB, otherKeys, early, trust } = await chainedWorld();
  const { issuerKeys: _i, ...noPasskey } = trust;
  const { sealKeys: _s, ...noRecorder } = trust;
  const linesB = bookB.split('\n').filter(Boolean);
  const linesA = bookA.split('\n').filter(Boolean);
  add('book 1 of a permission, witnessed', bookA, trust);
  add('book 2 of the same permission, witnessed: its first seal names the last seal of book 1', bookB, trust);
  add('book 2, no passkey named: no statement counts', bookB, noPasskey);
  add('book 2, no recorder named: no statement counts', bookB, noRecorder);
  add('book 2, with the last seal of book 1 handed over', bookB, { ...trust, seals: [{ seal: a2.sealed.record, witnesses: [a2.statement] }] });
  add('book 2, with an earlier seal of book 1 handed over', bookB, { ...trust, seals: [{ seal: a1.sealed.record }] });
  add('book 1, with the first seal of book 2 handed over', bookA, { ...trust, seals: [{ seal: b1.sealed.record, witnesses: [b1.statement] }] });
  add('book 1 cut back before its last seal, with the first seal of book 2 handed over', book(linesA.slice(0, 4)), { ...trust, seals: [{ seal: b1.sealed.record }] });
  add('book 1, with a seal of book 2 that names a seal of book 2 handed over', bookA, { ...trust, seals: [{ seal: JSON.parse(linesB[4]).seal }] });
  const otherBook = slipLine + '\n' + entryLine(stub3.entry) + '\n' + entryLine({ seal: otherKeys.record }) + '\n';
  add('book 2 sealed with other keys, with the last seal of book 1 handed over', otherBook, { ...trust, seals: [{ seal: a2.sealed.record }] });
  const earlyBook = slipLine + '\n' + entryLine(stub3.entry) + '\n' + entryLine({ seal: early.record }) + '\n';
  add('book 2 whose first seal is dated before the last seal of book 1, which is handed over', earlyBook, { ...trust, seals: [{ seal: a2.sealed.record }] });
  // A seal of another number later in the same book: the second seal of book 2 written as book 3.
  const asThree = await writeSeal(book(linesB.slice(0, 4)), { by: recorderBy((await chainedWorld()).recorder), book: 3, previous: b1.sealed.fingerprint, when: START + 8 * 3600 * 1000 }, (await chainedWorld()).recorder.privateKeys);
  add('a seal giving another book number than the seal before it in the book', book([...linesB.slice(0, 4), entryLine({ seal: asThree.record })]), trust);
  // A book whose seal is of book 2 but which holds a seal of book 1 first: the first seal says book 1.
  add('a seal of book 1 then a seal of book 2 in one book', book([...linesA.slice(0, 2), linesA[2], linesA[3], entryLine({ seal: JSON.parse(linesB[4]).seal })]), trust);
  // A book that does not start with a permission: a statement written for its seal by a witness the reader trusts
  // does not count, though the statement itself checks.
  const junk = await generateKeySet();
  const terms = await writeTerms({ by: { keys: junk.keys, name: 'Anything (invented)' }, accepts: ['supplies.order'], validFrom: '2026-10-01T00:00:00Z', validUntil: '2027-10-01T00:00:00Z' }, junk.privateKeys);
  const forgedText = entryLine({ terms: terms.record }) + '\n' + slipLine + '\n' + entryLine(stub3.entry) + '\n';
  const forgedSeal = await writeSeal(forgedText, { by: recorderBy((await chainedWorld()).recorder), when: START + 6 * 3600 * 1000 }, (await chainedWorld()).recorder.privateKeys);
  const content = JSON.parse(Buffer.from(forgedSeal.record.payload, 'base64url').toString());
  const forgedStatement = await writeWitness({ seal: forgedSeal.fingerprint, size: content.size, root: content.root, by: { keys: one.keys, name: 'Example witness (invented)' }, when: Date.parse('2026-10-06T00:00:00Z') }, one.privateKeys);
  add('a book that starts with terms, not a permission, with a statement from a trusted witness', forgedText + entryLine({ seal: forgedSeal.record, witnesses: [forgedStatement.record] }) + '\n', trust);
  void w;
  return cases;
}

async function chainedShowCases() {
  const cases = [];
  const add = (name, show, options = {}) => cases.push({ name, show, options: withoutSlh(options) });
  const { a1, bookB, trust } = await chainedWorld();
  add('a Show of book 2 with its first seal among the pages, not every page it covers', await makeShow(bookB, [0, 2]), trust);
  add('a Show of book 2, every page its first seal covers, and the seal', await makeShow(bookB, [0, 1, 2]), trust);
  add('a Show of book 2 under its last seal', await makeShow(bookB, [0, 1], { seal: 4 }), trust);
  // Pages that hold a seal of book 1 and then a seal of book 2: they cannot be of one book.
  const linesB = bookB.split('\n').filter(Boolean);
  const mixed = book([linesB[0], linesB[1], entryLine({ seal: a1.sealed.record }), linesB[3], linesB[4]]);
  add('pages holding a seal of book 1 and then one of book 2', await makeShow(mixed, [0, 2, 4]), trust);
  return cases;
}

function sealBookContents() {
  const fp = toBase64url(new Uint8Array(32).fill(1));
  const ED = { alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: toBase64url(new Uint8Array(32).fill(4)) };
  const ML = { alg: 'ML-DSA-87', kty: 'AKP', pub: toBase64url(new Uint8Array(2592).fill(5)) };
  const SL = { alg: 'SLH-DSA-SHA2-256s', kty: 'AKP', pub: toBase64url(new Uint8Array(64).fill(6)) };
  const base = { type: 'provared.seal.v0', id: 'AAECAwQFBgcICQoLDA0ODw', by: { keys: [ED, ML, SL], name: 'Example recorder (invented)' }, size: 3, root: fp, previous: fp, when: '2026-10-05T12:00:00Z' };
  const cases = [];
  const add = (name, content) => cases.push({ name, content });
  add('a seal of the first book: no number', base);
  add('a seal of the first book with no seal before it', (({ previous: _, ...rest }) => rest)(base));
  for (const [name, value] of [['2', 2], ['3', 3], ['the largest whole number', 2 ** 53 - 1], ['1', 1], ['0', 0], ['-1', -1], ['1.5', 1.5], ['2.5', 2.5], ['one more than the largest whole number', 2 ** 53], ['text', '2'], ['null', null], ['true', true], ['a list', [2]]]) {
    add(`book ${name}`, { ...base, book: value });
  }
  add('book 2 with no seal before it named', (({ previous: _, ...rest }) => ({ ...rest, book: 2 }))(base));
  add('a faulty seal before it and book: the seal before it is reported', { ...base, previous: 'x', book: 0 });
  add('a faulty book and time: the book is reported', { ...base, book: 0, when: 'x' });
  return cases;
}


// --- round two of the review: a book sealed again under another number, and renewals ---

// A book cut short and sealed again as "book 2": a seal held elsewhere of book 1 is not compared with it, and so
// gives no pass. And the other way: a held seal that gives a later number than the book handed over.
async function relabelCases() {
  const cases = [];
  const add = (name, text, options = {}) => cases.push({ name, text, options: withoutSlh(options) });
  const w = await makeWorld({ fields: { requires: [] } });
  for (let i = 0; i < 3; i++) await w.add({ value: 10 });
  const recorder = await generateSealKeySet();
  const seal = (text, fields) => writeSeal(text, { by: recorderBy(recorder), ...fields }, recorder.privateKeys);
  const t4 = w.book();
  const s1 = await seal(t4, { when: START + 5 * 3600 * 1000 });
  w.entries.push({ seal: s1.record });
  await w.add({ value: 150 });
  await w.add({ value: 10 });
  const t7 = w.book();
  const s1b = await seal(t7, { previous: s1.fingerprint, when: START + 9 * 3600 * 1000 });
  const trust = { issuerKeys: [await thumbprint(w.passkey.key)], sealKeys: [await keySetFingerprint(recorder.keys)] };
  const cut = t4 + entryLine({ seal: s1.record }) + '\n';
  add('a book cut back to its first seal, the later seal held elsewhere', cut, { ...trust, seals: [{ seal: s1b.record }] });
  const madeUp = toBase64url(new Uint8Array(32).fill(0x51));
  for (const [name, previous] of [['a made-up seal', madeUp], ['the seal held elsewhere', s1b.fingerprint], ['its own first seal', s1.fingerprint]]) {
    const relabel = await seal(t4, { book: 2, previous, when: START + 10 * 3600 * 1000 });
    add(`the same entries sealed again as book 2, naming ${name}, the later seal of book 1 held elsewhere`, t4 + entryLine({ seal: relabel.record }) + '\n', { ...trust, seals: [{ seal: s1b.record }] });
  }
  const later = await seal(t7, { book: 3, previous: s1.fingerprint, when: START + 9 * 3600 * 1000 });
  add('a book of the first number, with a held seal that says book 3', cut, { ...trust, seals: [{ seal: later.record }] });
  const earlier = await seal(t7, { book: 2, previous: s1.fingerprint, when: START + 9 * 3600 * 1000 });
  const asFour = await seal(t4, { book: 4, previous: madeUp, when: START + 10 * 3600 * 1000 });
  add('a book that says book 4, with a held seal that says book 2', t4 + entryLine({ seal: asFour.record }) + '\n', { ...trust, seals: [{ seal: earlier.record }] });
  return cases;
}

// A renewal written into a book: the first permission, then a second from the same passkey to the same agent, and
// two stubs under the second that pass its limit; sealed and witnessed. Made once.
let renewed;
function renewalWorld() {
  renewed ??= (async () => {
    const w = await makeWorld({ fields: { requires: [] } });
    const recorder = await generateSealKeySet();
    const one = await generateKeySet();
    const witness = await openWitness({ by: { keys: one.keys, name: 'Example witness (invented)' }, signers: one.privateKeys, clock: () => Date.parse('2026-10-06T00:00:00Z') });
    const prepared = await prepareSlip({ ...w.fields, purpose: 'Renewed.' });
    const slip2 = assembleSlip(prepared, await w.passkey.sign(prepared.challenge));
    const fp2 = await fingerprint(fromBase64url(slip2.payload));
    const stub = async (value, after, when) => {
      const x = await writeStub({ slip: fp2, action: 'supplies.order', amount: { unit: 'GBP', value }, with: 'supplier', after, when }, w.agent.privateKeys);
      return { entry: { stub: x.record, countersignature: await countersign(x.record, w.service.privateKeys, when + 60000) }, after: { seq: x.seq, fingerprint: x.fingerprint } };
    };
    const x1 = await stub(150, null, START + 3 * 3600 * 1000);
    const x2 = await stub(100, x1.after, START + 4 * 3600 * 1000);
    const text = writeBook([w.entries[0], { slip: slip2 }, x1.entry, x2.entry]);
    const sealed = await writeSeal(text, { by: recorderBy(recorder), when: START + 5 * 3600 * 1000 }, recorder.privateKeys);
    const r = await witness.witness({ seal: sealed.record }, await witnessProof(text, 4, null), utf8(text.split('\n')[0]));
    if (!r.statement) throw new Error(`a witness refused: ${r.refused.message}`);
    const book = text + entryLine({ seal: sealed.record, witnesses: [r.statement] }) + '\n';
    const trust = { issuerKeys: [await thumbprint(w.passkey.key)], sealKeys: [await keySetFingerprint(recorder.keys)], witnesses: [await keySetFingerprint(one.keys)] };
    const otherPasskey = await thumbprint((await makeWorld()).passkey.key);
    return { book, trust, otherPasskey };
  })();
  return renewed;
}

async function renewalBookCases() {
  const { book, trust, otherPasskey } = await renewalWorld();
  const add = (name, text, options) => ({ name, text, options: withoutSlh(options) });
  return [
    add('a renewal in the book, witnessed, the second permission over its limit', book, trust),
    add('a renewal in the book, another passkey named: the first permission does not pass, and no statement counts', book, { ...trust, issuerKeys: [otherPasskey] }),
  ];
}

async function renewalShowCases() {
  const { book, trust } = await renewalWorld();
  const add = async (name, pages) => ({ name, show: await makeShow(book, pages), options: withoutSlh(trust) });
  return [
    await add('the first permission and the seal: single pages cannot count', [0, 4]),
    await add('every page the seal covers, both permissions among them, and the seal', [0, 1, 2, 3, 4]),
    await add('the renewed permission and the seal, without page 0: the start is not shown, and no statement counts', [1, 4]),
  ];
}

// --- round three of the review: one person, two agents, one recorder ---

// One passkey gives permissions to agents X and Y, under one recorder and witnessed (as the gateway keeps them):
// X's book and Y's book, each honest; and a book that starts with Y's permission and then holds X's permission
// and X's first stub, which the witness signs as the first book of the person and agent Y. Made once.
let agents;
function twoAgentWorld() {
  agents ??= (async () => {
    const w = await makeWorld({ fields: { requires: [] } });
    await w.add({ value: 10 });
    await w.add({ value: 150 });
    await w.add({ value: 100 });
    const recorder = await generateSealKeySet();
    const one = await generateKeySet();
    const witness = await openWitness({ by: { keys: one.keys, name: 'Example witness (invented)' }, signers: one.privateKeys, clock: () => Date.parse('2026-10-06T00:00:00Z') });
    const agentY = await generateKeySet();
    const preparedY = await prepareSlip({ ...w.fields, agent: { name: 'Agent Y (invented)', keys: agentY.keys } });
    const slipY = assembleSlip(preparedY, await w.passkey.sign(preparedY.challenge));
    const fpY = await fingerprint(fromBase64url(slipY.payload));
    const stubY = await writeStub({ slip: fpY, action: 'supplies.order', amount: { unit: 'GBP', value: 5 }, with: 'supplier', after: null, when: START + 3600 * 1000 }, agentY.privateKeys);
    const entryY = { stub: stubY.record, countersignature: await countersign(stubY.record, w.service.privateKeys, START + 3600 * 1000 + 60000) };
    const second = await makeWorld({ fields: { requires: [] }, agent: w.agent, service: w.service });
    // The forged book is shown to a witness with the same keys that has not seen Y's own book: to it, the first book of
    // the person and agent Y.
    const fresh = await openWitness({ by: { keys: one.keys, name: 'Example witness (invented)' }, signers: one.privateKeys, clock: () => Date.parse('2026-10-06T00:00:00Z') });
    const witnessed = async (text, by = witness) => {
      const sealed = await writeSeal(text, { by: recorderBy(recorder), when: START + 6 * 3600 * 1000 }, recorder.privateKeys);
      const r = await by.witness({ seal: sealed.record }, await witnessProof(text, text.split('\n').filter(Boolean).length, null), utf8(text.split('\n')[0]));
      if (!r.statement) throw new Error(`a witness refused: ${r.refused.message}`);
      return text + entryLine({ seal: sealed.record, witnesses: [r.statement] }) + '\n';
    };
    const bookX = await witnessed(w.book());
    const bookY = await witnessed(writeBook([{ slip: slipY }, entryY]));
    const forged = await witnessed(writeBook([{ slip: slipY }, w.entries[0], w.entries[1], w.entries[2]]), fresh);
    const mixed = await witnessed(writeBook([second.entries[0], w.entries[0], w.entries[1], w.entries[2]]));
    // Y's permission, sealed and witnessed at entry 1; then X's permission and actions, sealed and witnessed again
    // (the review's fourth probe, case a). The first seal covers no other permission; the second does.
    const later = await openWitness({ by: { keys: one.keys, name: 'Example witness (invented)' }, signers: one.privateKeys, clock: () => Date.parse('2026-10-06T00:00:00Z') });
    const yOnly = writeBook([{ slip: slipY }]);
    const sY1 = await writeSeal(yOnly, { by: recorderBy(recorder), when: START }, recorder.privateKeys);
    const rY1 = await later.witness({ seal: sY1.record }, await witnessProof(yOnly, 1, null), utf8(yOnly.split('\n')[0]));
    const yThenX = yOnly + entryLine({ seal: sY1.record, witnesses: [rY1.statement] }) + '\n' + writeBook([w.entries[0], w.entries[1], w.entries[2]]);
    const sY2 = await writeSeal(yThenX, { by: recorderBy(recorder), previous: sY1.fingerprint, when: START + 6 * 3600 * 1000 }, recorder.privateKeys);
    const rY2 = await later.witness({ seal: sY2.record }, await witnessProof(yThenX, 5, 1), utf8(yOnly.split('\n')[0]));
    if (!rY1.statement || !rY2.statement) throw new Error('a witness refused');
    const laterBook = yThenX + entryLine({ seal: sY2.record, witnesses: [rY2.statement] }) + '\n';
    const trust = { issuerKeys: [await thumbprint(w.passkey.key)], sealKeys: [await keySetFingerprint(recorder.keys)], witnesses: [await keySetFingerprint(one.keys)] };
    const secondPasskey = await thumbprint(second.passkey.key);
    return { bookX, bookY, forged, mixed, laterBook, trust, secondPasskey };
  })();
  return agents;
}

async function twoAgentBookCases() {
  const { bookX, bookY, forged, mixed, laterBook, trust, secondPasskey } = await twoAgentWorld();
  const add = (name, text, options) => ({ name, text, options: withoutSlh(options) });
  return [
    add("agent X's own book, witnessed", bookX, trust),
    add("agent Y's own book, from the same passkey under the same recorder, witnessed", bookY, trust),
    add("a book that starts with Y's permission and then holds X's permission and stubs: not counted", forged, trust),
    add("a book that starts with a second passkey's permission for X and then holds X's first permission: not counted, both passkeys named", mixed, { ...trust, issuerKeys: [...trust.issuerKeys, secondPasskey] }),
    add("Y's permission witnessed at entry 1, then X's permission and actions witnessed again: the first seal counts, the second does not", laterBook, trust),
  ];
}

async function twoAgentShowCases() {
  const { bookX, forged, laterBook, trust } = await twoAgentWorld();
  const add = async (name, text, pages) => ({ name, show: await makeShow(text, pages), options: withoutSlh(trust) });
  return [
    await add("agent X's book, every page the seal covers, and the seal", bookX, [0, 1, 2, 3, 4]),
    await add("agent X's book, its first page and the seal: single pages cannot count", bookX, [0, 4]),
    await add("the book that starts with Y's permission, its first page and the seal", forged, [0, 4]),
    await add("the book that starts with Y's permission, every page and the seal", forged, [0, 1, 2, 3, 4]),
    await add("Y's permission and its seal at entry 1, from a book that goes on with X's permission", laterBook, [0, 1]),
  ];
}

/** Each set of cases, by the name of its file. */
export const CASES = {
  'tree-consistency': async () =>
    finish(
      'Consistency proofs (RFC 9162, section 2.1.4.1), for every earlier tree of trees of 1 to 64 leaves and some larger ones: the proof, and whether it checks (section 2.1.4.2) against the two roots. Leaves are written in hexadecimal.',
      'consistencyProof',
      consistencyCases(),
      ANSWER,
    ),
  'tree-consistency-checks': async () =>
    finish(
      'Checking a consistency proof (RFC 9162, section 2.1.4.2): sound proofs, changed ones, the edges and what is not a proof. Text is hexadecimal bytes.',
      'verifyConsistency',
      await consistencyCheckCases(),
      ANSWER,
    ),
  'seal-books': async () => finish("A seal's book number among the books of one permission (format description, section 21.6): confirming the members of a seal's content.", 'validateSealContent', sealBookContents(), STAMPS),
  'chained-books': async () => finish('Checking a book that is one of several of one permission (format description, sections 21.6 and 29), with seals of the books before and after handed over, on a device without SLH-DSA.', 'checkBook', [...(await chainedBookCases()), ...(await relabelCases())], { checkBook: async (c) => ({ ok: await checkBook(c.text, c.options) }) }),
  'chained-shows': async () => finish('Checking a Show of a book after the first of its permission (format description, sections 11, 21.6 and 29), on a device without SLH-DSA.', 'checkShow', await chainedShowCases(), { checkShow: async (c) => ({ ok: await checkShow(c.show, c.options) }) }),
  'renewal-books': async () => finish('Checking a book that holds a renewal: a second permission from the same passkey to the same agent (format description, section 29), on a device without SLH-DSA.', 'checkBook', await renewalBookCases(), { checkBook: async (c) => ({ ok: await checkBook(c.text, c.options) }) }),
  'renewal-shows': async () => finish('Checking a Show of a book that holds a renewal, with and without its page 0 (format description, sections 11 and 29), on a device without SLH-DSA.', 'checkShow', await renewalShowCases(), { checkShow: async (c) => ({ ok: await checkShow(c.show, c.options) }) }),
  'two-agent-books': async () => finish('Checking books of one person for two agents under one recorder, honest and forked (format description, section 29.2), on a device without SLH-DSA.', 'checkBook', await twoAgentBookCases(), { checkBook: async (c) => ({ ok: await checkBook(c.text, c.options) }) }),
  'two-agent-shows': async () => finish('Checking Shows of books of one person for two agents under one recorder (format description, sections 11 and 29.2), on a device without SLH-DSA.', 'checkShow', await twoAgentShowCases(), { checkShow: async (c) => ({ ok: await checkShow(c.show, c.options) }) }),
  'witness-books': async () => finish('Checking a whole book with witness statements beside its seals, or handed over beside it (format description, section 29), on a device without SLH-DSA.', 'checkBook', await witnessBookCases(), { checkBook: async (c) => ({ ok: await checkBook(c.text, c.options) }) }),
  'witness-shows': async () => finish('Checking a Show whose seals carry witness statements (format description, sections 11 and 29), on a device without SLH-DSA.', 'checkShow', await witnessShowCases(), { checkShow: async (c) => ({ ok: await checkShow(c.show, c.options) }) }),
  'witness-before': async () => finish('The check before acting over a book whose seals carry witness statements (format description, sections 20 and 29), on a device without SLH-DSA.', 'checkBefore', await witnessBeforeCases(), { checkBefore: async (c) => ({ ok: await checkBefore(c.text, c.proposal, c.options) }) }),
};

