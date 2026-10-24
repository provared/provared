// The central sealer (format description, section 21.7): a sealer that is
// sent only the leaf fingerprints of a book's lines signs the same seal
// that writeSeal signs over the book itself; a wrong fingerprint gives a
// seal the book refuses; a sealer carries on from its saved state, refuses
// to seal from an older one until it is brought up to date, never signs a
// size and top fingerprint handed to it, keeps books apart, and chains the
// first seal of a later book to the last seal of the book before. Signing a
// seal takes about a second and a half, so these tests seal sparingly.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  assembleSlip,
  checkBook,
  entryLine,
  fingerprint,
  fromBase64url,
  generateKeySet,
  prepareSlip,
  generateSealKeySet,
  keySetFingerprint,
  leafFingerprint,
  openRecorder,
  openSealer,
  signerFromKey,
  thumbprint,
  toBase64url,
  utf8,
  writeBook,
  writeSeal,
} from '../src/index.js';
import { treeBuilder, treeRoot } from '../src/tree.js';
import { START, makeWorld } from './helpers/world.mjs';

const NAME = 'Example central sealer (invented)';
const CLOCK = START + 6 * 3600 * 1000;
const linesOf = (text) => text.split('\n').filter(Boolean);
const leavesOf = (lines) => Promise.all(lines.map(leafFingerprint));
const b64 = (bytes) => toBase64url(bytes);
// The state as it would come back from a disk.
const saved = (state) => JSON.parse(JSON.stringify(state));

let recorderKeys;
async function recorder() {
  recorderKeys ??= await generateSealKeySet();
  return { keys: recorderKeys.keys, privateKeys: recorderKeys.privateKeys, by: { keys: recorderKeys.keys, name: NAME } };
}

async function sealerOf(more = {}) {
  const r = await recorder();
  return openSealer({ by: r.by, signers: r.privateKeys, clock: () => CLOCK, ...more });
}

// A seeded source of numbers, so that a failing case can be run again.
function randomSource(seed) {
  let s = seed >>> 0;
  return {
    int(n) {
      s = (Math.imul(s ^ (s >>> 15), 0x2c1b3c6d) + 0x297a2d39) >>> 0;
      s = (s ^ (s >>> 12)) >>> 0;
      return s % n;
    },
  };
}
const randomLine = (rand) => JSON.stringify({ note: Array.from({ length: 1 + rand.int(40) }, () => String.fromCharCode(0x20 + rand.int(95))).join(''), n: rand.int(1000) });

// The same seal: the same content and protected headers, and the same Ed25519 signature, which is deterministic.
function assertSameSeal(a, b, what) {
  assert.equal(a.payload, b.payload, `${what}: payload`);
  assert.deepEqual(
    a.signatures.map((s) => s.protected),
    b.signatures.map((s) => s.protected),
    `${what}: protected headers`,
  );
  assert.equal(a.signatures[0].signature, b.signatures[0].signature, `${what}: the Ed25519 signature`);
}

test('the leaf fingerprint of a line, and what is not a line', async () => {
  const line = '{"slip":{"payload":"x"}}';
  const expected = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([0, ...new TextEncoder().encode(line)])));
  assert.deepEqual(await leafFingerprint(line), expected);
  for (const [bad, why] of [
    ['', /must not be empty/],
    ['a\nb', /without its line feed/],
    ['\ud800', /well-formed Unicode/],
    ['x'.repeat(131073), /at most 131,072 bytes/],
    [42, /must be text/],
  ]) {
    await assert.rejects(leafFingerprint(bad), (e) => e.code === 'bad-field' && why.test(e.message));
  }
  assert.equal((await leafFingerprint('x'.repeat(131072))).length, 32);
});

test('random books: the sealer\'s seal is the seal writeSeal makes over the same book', async () => {
  const r = await recorder();
  const rand = randomSource(388);
  for (let round = 0; round < 2; round++) {
    const sealer = await sealerOf();
    let lines = Array.from({ length: 1 + rand.int(40) }, () => randomLine(rand));
    const first = b64(await leafFingerprint(lines[0]));
    // Sent in pieces of random length.
    let sent = 0;
    const send = async () => {
      while (sent < lines.length) {
        const n = 1 + rand.int(lines.length - sent);
        const answer = await sealer.extend(first, sent, await leavesOf(lines.slice(sent, sent + n)));
        assert.equal(answer.size, sent + n, JSON.stringify(answer.refused));
        sent += n;
      }
    };
    await send();
    let previous = null;
    for (let s = 0; s < 2; s++) {
      const id = toBase64url(new Uint8Array(16).fill(round * 2 + s + 1));
      const when = CLOCK - 60000 + s * 1000;
      const made = await sealer.seal(first, { previous, when, id });
      assert.ok(made.entry, JSON.stringify(made.refused));
      const direct = await writeSeal(lines.join('\n') + '\n', { by: r.by, previous: previous ?? undefined, when, id }, r.privateKeys);
      assertSameSeal(made.entry.seal, direct.record, `round ${round}, seal ${s}`);
      assert.equal(made.fingerprint, direct.fingerprint);
      assert.deepEqual(made.fingerprintBytes, direct.fingerprintBytes);
      assert.equal(made.line, entryLine({ seal: made.entry.seal }));
      // The seal's line, and more lines, join the book.
      previous = made.fingerprint;
      lines = [...lines, made.line, ...Array.from({ length: 1 + rand.int(10) }, () => randomLine(rand))];
      await send();
    }
  }
});

test('a sealer sent one wrong leaf signs a seal that the book refuses, through the stub writer\'s add and in a whole check', async () => {
  const w = await makeWorld();
  await w.add({ value: 10 });
  await w.add({ value: 20 });
  const text = w.book();
  const lines = linesOf(text);
  const r = await recorder();
  const trust = { issuerKeys: [await thumbprint(w.passkey.key)], sealKeys: [await keySetFingerprint(r.keys)] };
  const leaves = await leavesOf(lines);
  const first = b64(leaves[0]);
  const writer = () => openRecorder({ book: text, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys: trust.issuerKeys, now: () => CLOCK, options: { sealKeys: trust.sealKeys } });

  // One wrong leaf: the fingerprint of the second stub with one byte changed.
  const wrong = leaves.map((l) => l.slice());
  wrong[2][5] ^= 1;
  const misled = await sealerOf();
  assert.equal((await misled.extend(first, 0, wrong)).size, 3);
  const bad = await misled.seal(first, { previous: null });
  assert.ok(bad.entry);
  const refusing = await writer();
  await assert.rejects(refusing.add(bad.entry), (e) => e.code === 'record-not-sound');
  assert.equal(refusing.book(), text);
  const whole = await checkBook(text + bad.line + '\n', trust);
  assert.ok(whole.entries[3].problems.some((p) => p.code === 'seal-mismatch'));

  // The right leaves: the seal joins the book, and the book checks.
  const honest = await sealerOf();
  await honest.extend(first, 0, leaves);
  const good = await honest.seal(first, { previous: null });
  const taking = await writer();
  await taking.add(good.entry);
  const answer = await taking.check();
  assert.deepEqual(answer.problems, []);
  assert.equal(answer.summary.intact, true);
  assert.equal(taking.book(), text + good.line + '\n');
});

test('a sealer carries on from its saved state', async () => {
  const rand = randomSource(9162);
  const lines = Array.from({ length: 5 }, () => randomLine(rand));
  const first = b64(await leafFingerprint(lines[0]));
  const one = await sealerOf();
  await one.extend(first, 0, await leavesOf(lines));
  const s1 = await one.seal(first, { previous: null });
  // The state holds no private key, and is plain data.
  assert.ok(!JSON.stringify(s1.state).includes('"d"'));
  assert.equal(s1.state.type, 'provared.sealer-state.v0');

  // Opened again from the state it handed back with the seal: it carries on.
  const two = await sealerOf({ state: saved(s1.state) });
  assert.deepEqual(two.held(first), { first, number: 1, follows: null, size: 5, closed: false, latest: s1.fingerprint, sealed: 5 });
  assert.deepEqual(two.latest(first), { entry: s1.entry, line: s1.line, fingerprint: s1.fingerprint });
  const more = [s1.line, randomLine(rand), randomLine(rand)];
  assert.equal((await two.extend(first, 5, await leavesOf(more))).size, 8);
  const s2 = await two.seal(first, { previous: s1.fingerprint });
  assert.ok(s2.entry, JSON.stringify(s2.refused));
  const text = [...lines, ...more].join('\n') + '\n';
  const direct = await writeSeal(text, { by: (await recorder()).by, previous: s1.fingerprint, when: CLOCK, id: JSON.parse(Buffer.from(s2.entry.seal.payload, 'base64url')).id }, (await recorder()).privateKeys);
  assertSameSeal(s2.entry.seal, direct.record, 'after the restart');

  // A state that is not this sealer's, or changed, is refused when the sealer is opened.
  const other = await generateSealKeySet();
  await assert.rejects(openSealer({ by: { keys: other.keys, name: NAME }, signers: other.privateKeys, state: saved(s2.state) }), /another sealer/);
  // The tree at the latest seal is checked against the seal's top fingerprint. (The tree since covers no seal
  // yet: a change there gives a seal the book refuses, as a wrong leaf does.)
  const changedLatest = saved(s2.state);
  changedLatest.books[0].latest.parts[0] = b64(new Uint8Array(32));
  await assert.rejects(sealerOf({ state: changedLatest }), /do not give the seal's top fingerprint/);
  const changedSeal = saved(s2.state);
  const sig = fromBase64url(changedSeal.books[0].latest.entry.seal.signatures[1].signature);
  sig[7] ^= 1;
  changedSeal.books[0].latest.entry.seal.signatures[1].signature = b64(sig);
  await assert.rejects(sealerOf({ state: changedSeal }), (e) => e.code === 'signature-invalid');
  // A seal whose content is not in its one written form fails its check before any signature is looked at.
  const reordered = saved(s2.state);
  const content = JSON.parse(Buffer.from(reordered.books[0].latest.entry.seal.payload, 'base64url'));
  reordered.books[0].latest.entry.seal.payload = Buffer.from(JSON.stringify({ when: content.when, ...content })).toString('base64url');
  await assert.rejects(sealerOf({ state: reordered }), (e) => e.code === 'payload-not-canonical');
  const twice = saved(s2.state);
  twice.books.push(twice.books[0]);
  await assert.rejects(sealerOf({ state: twice }), /the same book is given twice/);
  await assert.rejects(sealerOf({ state: { ...saved(s2.state), type: 'x' } }));
  await assert.rejects(sealerOf({ state: 'x' }));
});

test('a sealer opened from an older state seals nothing until it is brought up to date from the seals in the book', async () => {
  const rand = randomSource(6962);
  const lines = Array.from({ length: 4 }, () => randomLine(rand));
  const first = b64(await leafFingerprint(lines[0]));
  const sealer = await sealerOf();
  await sealer.extend(first, 0, await leavesOf(lines));
  const s1 = await sealer.seal(first, { previous: null });
  const older = saved(s1.state);
  const between = [s1.line, randomLine(rand), randomLine(rand)];
  await sealer.extend(first, 4, await leavesOf(between));
  const s2 = await sealer.seal(first, { previous: s1.fingerprint });
  const after = [s2.line, randomLine(rand)];
  const book = [...lines, ...between, ...after];

  // Put back to the state of the first seal: it holds 4 lines and the first seal.
  const back = await sealerOf({ state: older });
  // Lines are taken only from the place it holds.
  const early = await back.extend(first, 8, await leavesOf(after));
  assert.equal(early.refused.code, 'out-of-step');
  assert.equal(early.size, 4);
  assert.equal((await back.extend(first, 4, await leavesOf([...between, ...after]))).size, 9);
  // The book names the second seal; the sealer holds the first as its latest: it signs nothing.
  const refused = await back.seal(first, { previous: s2.fingerprint });
  assert.equal(refused.refused.code, 'not-up-to-date');
  // Nor will it be told its own latest seal is the one before, by a caller that names the first seal.
  // (Signing then is the caller's word against the book; the book would refuse it: rule 3 of section 21.1.)

  // Brought up to date with lines that do not lead to the second seal: refused, and nothing changes.
  const wrongBetween = await leavesOf([s1.line, randomLine(rand), randomLine(rand)]);
  assert.equal((await back.update(first, s2.entry, wrongBetween)).refused.code, 'seal-mismatch');
  assert.equal((await back.update(first, s2.entry, (await leavesOf(between)).slice(1))).refused.code, 'bad-field');
  // An earlier or the same seal never moves it back.
  assert.equal((await back.update(first, s1.entry, [])).size, 9);
  assert.equal(back.held(first).latest, s1.fingerprint);
  // A seal not signed with its keys is not taken.
  const other = await generateSealKeySet();
  const foreign = await writeSeal(book.slice(0, 7).join('\n'), { by: { keys: other.keys, name: NAME }, previous: s1.fingerprint, when: CLOCK }, other.privateKeys);
  assert.equal((await back.update(first, { seal: foreign.record }, await leavesOf(between))).refused.code, 'sealer-not-expected');

  // Brought up to date: the second seal, and the lines from the first seal to it.
  const brought = await back.update(first, s2.entry, await leavesOf(between));
  assert.equal(brought.size, 7, JSON.stringify(brought.refused));
  assert.equal(back.held(first).latest, s2.fingerprint);
  // The lines it held past its latest seal were set aside: it carries on from the second seal.
  assert.equal((await back.extend(first, 7, await leavesOf(after))).size, 9);
  const s3 = await back.seal(first, { previous: s2.fingerprint });
  assert.ok(s3.entry, JSON.stringify(s3.refused));
  const r = await recorder();
  const check = await checkBook([...book, s3.line].join('\n') + '\n', { sealKeys: [await keySetFingerprint(r.keys)] });
  assert.deepEqual(check.problems, []);
  // Now moved on, the second seal is earlier than what it holds.
  assert.equal((await back.update(first, s2.entry, [])).refused.code, 'seal-mismatch');
});

test('a sealer never signs a size and top fingerprint handed to it, nor a line twice, nor a book it never took in', async () => {
  const rand = randomSource(1962);
  const lines = Array.from({ length: 3 }, () => randomLine(rand));
  const first = b64(await leafFingerprint(lines[0]));
  const sealer = await sealerOf();
  const unknown = await sealer.seal(first, { previous: null });
  assert.equal(unknown.refused.code, 'unknown-book');
  // The first line must be the one the book is known by.
  assert.equal((await sealer.extend(first, 0, await leavesOf(lines.slice(1)))).refused.code, 'bad-field');
  assert.equal((await sealer.extend(first, 1, await leavesOf(lines))).refused.code, 'out-of-step');
  await sealer.extend(first, 0, await leavesOf(lines));
  // A size or a top fingerprint is not something a seal request may hold.
  for (const more of [{ previous: null, size: 2 }, { previous: null, root: b64(new Uint8Array(32)) }, {}, null]) {
    assert.equal((await sealer.seal(first, more)).refused.code, 'bad-field', JSON.stringify(more));
  }
  // A place already taken is not taken again, with the same lines or others.
  const again = await sealer.extend(first, 1, await leavesOf(lines.slice(1)));
  assert.deepEqual(again, { refused: again.refused, size: 3 });
  assert.equal(again.refused.code, 'out-of-step');
  // Leaves that are not 32 bytes.
  assert.equal((await sealer.extend(first, 3, [new Uint8Array(31)])).refused.code, 'bad-field');
  assert.equal((await sealer.extend(first, 3, ['x'])).refused.code, 'bad-field');
  // The seal is over the three lines it took in.
  const s1 = await sealer.seal(first, { previous: null, when: CLOCK - 1000 });
  const content = JSON.parse(Buffer.from(s1.entry.seal.payload, 'base64url'));
  assert.equal(content.size, 3);
  assert.equal(content.root, b64(await treeRoot(lines.map(utf8))));
  // Nothing new since: no second seal at the same size.
  assert.equal((await sealer.seal(first, { previous: s1.fingerprint })).refused.code, 'nothing-new');
  // A date far from its own clock, or before the seal it names.
  await sealer.extend(first, 3, [await leafFingerprint(s1.line)]);
  assert.equal((await sealer.seal(first, { previous: s1.fingerprint, when: CLOCK + 301000 })).refused.code, 'bad-field');
  assert.equal((await sealer.seal(first, { previous: s1.fingerprint, when: CLOCK - 200000 })).refused.code, 'time-went-backwards');
  assert.equal((await sealer.seal(first, { previous: s1.fingerprint, when: 'soon' })).refused.code, 'bad-field');
  // A place is a whole number from 0.
  for (const at of [-1, 'x', 1.5]) assert.equal((await sealer.extend(first, at, [await leafFingerprint('{"y":1}')])).refused.code, 'bad-field', String(at));
});

test('two books are kept apart', async () => {
  const rand = randomSource(17);
  const a = Array.from({ length: 3 }, () => randomLine(rand));
  const b = Array.from({ length: 5 }, () => randomLine(rand));
  const fa = b64(await leafFingerprint(a[0]));
  const fb = b64(await leafFingerprint(b[0]));
  const sealer = await sealerOf();
  await sealer.extend(fa, 0, await leavesOf(a.slice(0, 2)));
  await sealer.extend(fb, 0, await leavesOf(b.slice(0, 4)));
  // Each book has its own place.
  assert.equal((await sealer.extend(fa, 4, await leavesOf(b.slice(4)))).refused.code, 'out-of-step');
  await sealer.extend(fa, 2, await leavesOf(a.slice(2)));
  await sealer.extend(fb, 4, await leavesOf(b.slice(4)));
  const sa = await sealer.seal(fa, { previous: null });
  const sb = await sealer.seal(fb, { previous: null });
  const r = await recorder();
  const trust = { sealKeys: [await keySetFingerprint(r.keys)] };
  assert.deepEqual((await checkBook([...a, sa.line].join('\n') + '\n', trust)).problems, []);
  assert.deepEqual((await checkBook([...b, sb.line].join('\n') + '\n', trust)).problems, []);
  // The seal of one book is no seal of the other.
  assert.ok((await checkBook([...a, sb.line].join('\n') + '\n', trust)).entries[3].problems.some((p) => p.code === 'seal-mismatch'));
  assert.equal(sealer.held(fa).latest, sa.fingerprint);
  assert.equal(sealer.held(fb).latest, sb.fingerprint);
  // A seal of one book does not bring the other up to date.
  assert.equal((await sealer.update(fa, sb.entry, [])).refused.code, 'bad-field');
  assert.equal((await sealer.update(fa, sb.entry, await leavesOf(b.slice(3)))).refused.code, 'seal-mismatch');
  assert.equal(sealer.state().books.length, 2);
});

test('the first seal of book 2 names the last seal of book 1, and book 1 is then closed', async () => {
  const w = await makeWorld();
  await w.add({ value: 10 });
  const book1 = linesOf(w.book());
  const r = await recorder();
  const sealer = await sealerOf();
  const first = b64(await leafFingerprint(book1[0]));
  await sealer.extend(first, 0, await leavesOf(book1));
  const last1 = await sealer.seal(first, { previous: null });

  // Book 2 starts with the same permission, so its first line is the same: its number keeps it apart.
  const ref2 = { first, number: 2 };
  assert.equal((await sealer.extend(ref2, 0, await leavesOf([book1[0]]))).refused.code, 'bad-field', 'a later book names the book it follows');
  assert.equal((await sealer.extend(ref2, 0, await leavesOf([book1[0]]), { follows: b64(new Uint8Array(32)) })).refused.code, 'unknown-book');
  assert.equal((await sealer.extend({ first, number: 3 }, 0, await leavesOf([book1[0]]), { follows: first })).refused.code, 'unknown-book');
  w.entries.splice(1);
  w.after = null;
  await w.add({ value: 10, when: START + 3 * 3600 * 1000 });
  const book2 = linesOf(w.book());
  assert.equal((await sealer.extend(ref2, 0, await leavesOf(book2), { follows: first })).size, 2);
  // Book 1 can still be sealed until book 2's first seal is signed; book 2's first seal names book 1's latest.
  assert.equal((await sealer.seal(ref2, { previous: null })).refused.code, 'not-up-to-date');
  const s2 = await sealer.seal(ref2, { previous: last1.fingerprint });
  assert.ok(s2.entry, JSON.stringify(s2.refused));
  const content = JSON.parse(Buffer.from(s2.entry.seal.payload, 'base64url'));
  assert.equal(content.book, 2);
  assert.equal(content.previous, last1.fingerprint);
  const direct = await writeSeal(writeBook(book2.map((l) => JSON.parse(l))), { by: r.by, previous: last1.fingerprint, book: 2, when: CLOCK, id: content.id }, r.privateKeys);
  assertSameSeal(s2.entry.seal, direct.record, 'book 2');
  // Book 1 is closed now, and no second book 2 may follow it.
  assert.equal((await sealer.extend(first, book1.length, [await leafFingerprint(last1.line)])).refused.code, 'book-closed');
  assert.equal(sealer.held(first).closed, true);
  // Both books check, each by itself.
  const trust = { issuerKeys: [await thumbprint(w.passkey.key)], sealKeys: [await keySetFingerprint(r.keys)] };
  assert.deepEqual((await checkBook([...book1, last1.line].join('\n') + '\n', trust)).problems, []);
  assert.deepEqual((await checkBook([...book2, s2.line].join('\n') + '\n', trust)).problems, []);
  // The state keeps the order of the books.
  const again = await sealerOf({ state: saved(s2.state) });
  assert.deepEqual(again.held(ref2), { first, number: 2, follows: first, size: 2, closed: false, latest: s2.fingerprint, sealed: 2 });
});

test('signers: a signer for another key is refused when the sealer is opened; one that never answers gives no seal, and nothing is kept', async () => {
  const r = await recorder();
  const other = await generateSealKeySet();
  await assert.rejects(openSealer({ by: r.by, signers: [other.privateKeys[0], r.privateKeys[1], r.privateKeys[2]].map((k, i) => signerFromKey(['Ed25519', 'ML-DSA-87', 'SLH-DSA-SHA2-256s'][i], k, [other.keys[0], r.keys[1], r.keys[2]][i])) }), (e) => e.code === 'bad-key');
  await assert.rejects(openSealer({ by: r.by, signers: r.privateKeys.slice(0, 2) }), /three private keys/);
  const silent = { key: r.keys[0], sign: () => new Promise(() => {}) };
  const sealer = await sealerOf({ signers: [silent, r.privateKeys[1], r.privateKeys[2]], signWithin: 200 });
  const first = b64(await leafFingerprint('{"a":1}'));
  await sealer.extend(first, 0, [await leafFingerprint('{"a":1}')]);
  const answer = await sealer.seal(first, { previous: null });
  assert.equal(answer.refused.code, 'check-failed');
  assert.match(answer.refused.message, /no answer within 200 milliseconds/);
  assert.equal(sealer.held(first).latest, null);
  assert.equal(sealer.latest(first), null);
});

test('the time-stamp hook: its stamp goes beside the seal; one that fails leaves the seal without it, and says so', async () => {
  const stampItem = b64(new Uint8Array(40).fill(7));
  let asked = null;
  const sealer = await sealerOf({ stamp: (bytes) => ((asked = bytes), stampItem) });
  const first = b64(await leafFingerprint('{"a":1}'));
  await sealer.extend(first, 0, [await leafFingerprint('{"a":1}')]);
  const made = await sealer.seal(first, { previous: null });
  assert.deepEqual(made.entry.stamps, [stampItem]);
  assert.deepEqual(asked, made.fingerprintBytes);
  assert.equal(made.line, entryLine({ seal: made.entry.seal, stamps: [stampItem] }));
  assert.deepEqual(made.state.books[0].latest.entry, made.entry);

  const failing = await sealerOf({ stamp: () => ({ not: 'a stamp' }) });
  await failing.extend(first, 0, [await leafFingerprint('{"a":1}')]);
  const bare = await failing.seal(first, { previous: null });
  assert.equal(bare.entry.stamps, undefined);
  assert.equal(bare.stampProblem.code, 'bad-field');
  assert.equal(failing.held(first).latest, bare.fingerprint);
});

// ---- After the first independent review (choices K33 onwards) ----

// One chain made once: book 1 of a first line P, sealed (L1); book 2 with the same first line, following it,
// sealed (S2), which closes book 1; book 3 the same way (S3). The state after each step, as from a disk.
let chainMade;
function chain() {
  chainMade ??= (async () => {
    const rand = randomSource(2027);
    const lines1 = Array.from({ length: 3 }, () => randomLine(rand));
    const P = b64(await leafFingerprint(lines1[0]));
    const s = await sealerOf();
    await s.extend(P, 0, await leavesOf(lines1));
    const L1 = await s.seal(P, { previous: null });
    const lines2 = [lines1[0], randomLine(rand)];
    await s.extend({ first: P, number: 2 }, 0, await leavesOf(lines2), { follows: P });
    const S2 = await s.seal({ first: P, number: 2 }, { previous: L1.fingerprint });
    const lines3 = [lines1[0], randomLine(rand)];
    await s.extend({ first: P, number: 3 }, 0, await leavesOf(lines3), { follows: P });
    const S3 = await s.seal({ first: P, number: 3 }, { previous: S2.fingerprint });
    return { P, lines1, lines2, lines3, L1, S2, S3, afterBook1: saved(L1.state), afterBook2: saved(S2.state), afterBook3: saved(S3.state) };
  })();
  return chainMade;
}

// A book with no seal, as a state holds it: at its first line, whose leaf fingerprint is "first".
const unsealed = (first, more = {}) => ({ first, number: 1, closed: false, ...more });
const fp = (n) => b64(new Uint8Array(32).fill(n));

test('a book whose first line the sealer holds starts only as the next book after the latest with that first line (S1)', async () => {
  const c = await chain();
  const s = await sealerOf({ state: saved(c.afterBook1) });
  // A throwaway book Q, sealed.
  const Q = new Uint8Array(32).fill(9);
  await s.extend(b64(Q), 0, [Q]);
  const sQ = await s.seal(b64(Q), { previous: null });
  assert.ok(sQ.entry);
  // "Book 2" of P after Q, with book 1 of P still open: refused, so no second history of P can be sealed.
  const forked = await s.extend({ first: c.P, number: 2 }, 0, await leavesOf(c.lines1.slice(0, 2)), { follows: b64(Q) });
  assert.equal(forked.refused.code, 'not-next-book');
  assert.equal(s.held({ first: c.P, number: 2 }), null);
  // The honest book 2 follows book 1 of P.
  assert.equal((await s.extend({ first: c.P, number: 2 }, 0, await leavesOf(c.lines2), { follows: c.P })).size, 2);
  // A book 2 between book 1 and a book 3 that the state holds: refused, not "closed".
  const gap = saved(c.afterBook3);
  gap.books = gap.books.filter((b) => b.number !== 2);
  const g = await sealerOf({ state: gap });
  assert.equal((await g.extend({ first: c.P, number: 2 }, 0, await leavesOf(c.lines2), { follows: c.P })).refused.code, 'not-next-book');
  // Nor is that book 2 brought in from its seal: a later book with the first line is held.
  assert.equal((await g.update({ first: c.P, number: 2 }, c.S2.entry, await leavesOf(c.lines2))).refused.code, 'book-closed');
  // So too where book 1, which its seal names, is not closed in that state: the later book held is enough.
  const gapOpen = saved(gap);
  gapOpen.books.find((b) => b.number === 1).closed = false;
  const go = await sealerOf({ state: gapOpen });
  const later3 = await go.update({ first: c.P, number: 2 }, c.S2.entry, await leavesOf(c.lines2));
  assert.equal(later3.refused.code, 'book-closed');
  assert.match(later3.refused.message, /holds a later book with this first line/);
  assert.equal(go.held(c.P).closed, false);
  // A first book of a first line held only as a later book.
  const later = saved(c.afterBook2);
  later.books = later.books.filter((b) => b.number !== 1);
  const l = await sealerOf({ state: later });
  assert.equal((await l.extend(c.P, 0, await leavesOf(c.lines1))).refused.code, 'not-next-book');
  // A book brought up to date must start with its own first line (a seal of Q is no seal of P).
  const other = await sealerOf();
  const named = await other.update(c.P, sQ.entry, [Q]);
  assert.equal(named.refused.code, 'bad-field');
  assert.match(named.refused.message, /known by its first line/);
});

test('one sealer serving several recorders: each book, and every book after it, is its own recorder\'s (S2)', async () => {
  const s = await sealerOf();
  const a = s.forRecorder('agent-a');
  const b = s.forRecorder('agent-b');
  assert.throws(() => s.forRecorder(''), (e) => e.code === 'bad-field');
  const rand = randomSource(42);
  const lines = Array.from({ length: 3 }, () => randomLine(rand));
  const F = b64(await leafFingerprint(lines[0]));
  const started = await a.extend(F, 0, await leavesOf(lines));
  assert.equal(started.state.books[0].recorder, 'agent-a', 'a book started hands back the state, with its recorder');
  const sa = await a.seal(F, { previous: null });
  // Another recorder, or the sealer's own calls, see nothing of it and can do nothing with it.
  for (const other of [b, s]) {
    assert.equal(other.held(F), null);
    assert.equal(other.latest(F), null);
    assert.equal((await other.extend(F, 3, [await leafFingerprint(sa.line)])).refused.code, 'other-recorder');
    assert.equal((await other.seal(F, { previous: sa.fingerprint })).refused.code, 'other-recorder');
    assert.equal((await other.update(F, sa.entry, [])).refused.code, 'other-recorder');
    // Nor start a book with its first line, nor a book after it.
    assert.equal((await other.extend({ first: F, number: 2 }, 0, [await leafFingerprint(lines[0])], { follows: F })).refused.code, 'other-recorder');
    const G = '{"g":1}';
    assert.equal((await other.extend({ first: b64(await leafFingerprint(G)), number: 2 }, 0, [await leafFingerprint(G)], { follows: F })).refused.code, 'other-recorder');
  }
  // Its own recorder carries on, and the state keeps the binding.
  assert.equal(a.held(F).latest, sa.fingerprint);
  const again = await sealerOf({ state: saved(sa.state) });
  assert.equal(again.held(F), null);
  assert.equal(again.forRecorder('agent-a').held(F).latest, sa.fingerprint);
  // Nor may another recorder start a book with its first line after a sealed book of its own.
  const G = '{"g":2}';
  const fg = b64(await leafFingerprint(G));
  await b.extend(fg, 0, [await leafFingerprint(G)]);
  assert.ok((await b.seal(fg, { previous: null })).entry);
  assert.equal((await b.extend({ first: F, number: 2 }, 0, [await leafFingerprint(lines[0])], { follows: fg })).refused.code, 'other-recorder');
  // Brought up to date by another recorder from a seal of a book whose first line it does not hold: refused too.
  const c = await chain();
  const x = (await sealerOf({ state: saved(c.afterBook1) })).forRecorder('agent-x');
  assert.equal((await x.update({ first: c.P, number: 2 }, c.S2.entry, await leavesOf(c.lines2))).refused.code, 'other-recorder');
  // And where the book before holds no seal it names, the first line held by another recorder is enough to refuse.
  const y = (await sealerOf({ state: { ...saved(c.afterBook1), books: [unsealed(c.P)] } })).forRecorder('agent-x');
  assert.equal((await y.update({ first: c.P, number: 2 }, c.S2.entry, await leavesOf(c.lines2))).refused.code, 'other-recorder');
  assert.equal(y.held(c.P), null);
});

// A second chain: book 1 of P sealed (X0, the state then), and book 2 of another first line R following it, sealed.
let renewalMade;
function renewal() {
  renewalMade ??= (async () => {
    const rand = randomSource(9999);
    const lines1 = Array.from({ length: 2 }, () => randomLine(rand));
    const P = b64(await leafFingerprint(lines1[0]));
    const s = await sealerOf();
    await s.extend(P, 0, await leavesOf(lines1));
    const L1 = await s.seal(P, { previous: null });
    const linesR = ['{"slip":"a stand-in for a renewed permission"}', randomLine(rand)];
    const R = b64(await leafFingerprint(linesR[0]));
    await s.extend({ first: R, number: 2 }, 0, await leavesOf(linesR), { follows: P });
    const SR = await s.seal({ first: R, number: 2 }, { previous: L1.fingerprint });
    return { P, R, lines1, linesR, L1, SR, X0: saved(L1.state) };
  })();
  return renewalMade;
}

test('a book brought up to date from its first seal closes the book before it (Md1)', async () => {
  const r = await renewal();
  const ref2 = { first: r.R, number: 2 };
  const leavesR = await leavesOf(r.linesR);
  // Put back to the state before book 2, and brought up to date with book 2's first seal.
  const back = await sealerOf({ state: saved(r.X0) });
  assert.equal((await back.update(ref2, r.SR.entry, leavesR)).size, 2);
  assert.equal(back.held(r.P).closed, true);
  assert.equal(back.held(ref2).follows, r.P);
  // Book 1 can no longer be extended or sealed, and no second book 2 follows it.
  assert.equal((await back.extend(r.P, 2, [await leafFingerprint(r.L1.line)])).refused.code, 'book-closed');
  const T = '{"slip":"a second book 2"}';
  assert.equal((await back.extend({ first: b64(await leafFingerprint(T)), number: 2 }, 0, [await leafFingerprint(T)], { follows: r.P })).refused.code, 'book-closed');
  // The book before closed already (in the state), or already followed by another book 2: refused.
  const closed = saved(r.X0);
  closed.books[0].closed = true;
  assert.equal((await (await sealerOf({ state: closed })).update(ref2, r.SR.entry, leavesR)).refused.code, 'book-closed');
  const taken = await sealerOf({ state: saved(r.X0) });
  assert.equal((await taken.extend({ first: b64(await leafFingerprint(T)), number: 2 }, 0, [await leafFingerprint(T)], { follows: r.P })).size, 1);
  assert.equal((await taken.update(ref2, r.SR.entry, leavesR)).refused.code, 'book-closed');
  // The book before is another recorder's: refused.
  const x = (await sealerOf({ state: saved(r.X0) })).forRecorder('agent-x');
  assert.equal((await x.update(ref2, r.SR.entry, leavesR)).refused.code, 'other-recorder');
  // A book of R held already: R's book 2 follows only R's book 1, not P's.
  const withR = saved(r.X0);
  withR.books.push(unsealed(r.R));
  assert.equal((await (await sealerOf({ state: withR })).update(ref2, r.SR.entry, leavesR)).refused.code, 'not-next-book');
  // Where the book named before is not held, every earlier book with R's first line is closed all the same.
  const onlyR = saved(r.X0);
  onlyR.books = [unsealed(r.R)];
  const o = await sealerOf({ state: onlyR });
  assert.equal((await o.update(ref2, r.SR.entry, leavesR)).size, 2);
  assert.equal(o.held(r.R).closed, true);
  assert.equal(o.held(ref2).follows, null);
  assert.equal((await o.extend(r.R, 1, [leavesR[1]])).refused.code, 'book-closed');
  // That state opens again.
  assert.equal((await sealerOf({ state: saved(o.state()) })).held(r.R).closed, true);
});

test('a later book started after a book that is behind is brought up to date only once that book is (Md1)', async () => {
  const rand = randomSource(4242);
  const lines1 = Array.from({ length: 2 }, () => randomLine(rand));
  const P = b64(await leafFingerprint(lines1[0]));
  const s = await sealerOf();
  await s.extend(P, 0, await leavesOf(lines1));
  const A = await s.seal(P, { previous: null });
  const stateA = saved(A.state);
  const between = [A.line, randomLine(rand)];
  await s.extend(P, 2, await leavesOf(between));
  const B = await s.seal(P, { previous: A.fingerprint });
  const ref2 = { first: P, number: 2 };
  const lines2 = [lines1[0], randomLine(rand)];
  await s.extend(ref2, 0, await leavesOf(lines2), { follows: P });
  const C = await s.seal(ref2, { previous: B.fingerprint });
  // Put back to the state of the first seal of book 1, and book 2 started again after it.
  const back = await sealerOf({ state: stateA });
  assert.equal((await back.extend(ref2, 0, await leavesOf(lines2), { follows: P })).size, 2);
  // Book 2's first seal names a later seal of book 1 than the sealer holds: book 1 first.
  const early = await back.update(ref2, C.entry, await leavesOf(lines2));
  assert.equal(early.refused.code, 'not-up-to-date');
  assert.equal(back.held(P).closed, false);
  assert.equal((await back.update(P, B.entry, await leavesOf(between))).size, 4);
  assert.equal((await back.update(ref2, C.entry, await leavesOf(lines2))).size, 2);
  assert.equal(back.held(P).closed, true);
  assert.equal(back.held(ref2).latest, C.fingerprint);
});

test('a book is kept at its latest seal, or with none at its first line, so a changed state cannot rewrite a sealed line (L2)', async () => {
  const c = await chain();
  const s = await sealerOf({ state: saved(c.afterBook1) });
  const more = await s.extend(c.P, 3, await leavesOf([c.L1.line, '{"x":1}']));
  assert.deepEqual(more, { size: 5 }, 'lines added to a book hand back no state');
  const st = saved(s.state());
  assert.equal(Object.hasOwn(st.books[0], 'size'), false);
  assert.equal(Object.hasOwn(st.books[0], 'parts'), false);
  const again = await sealerOf({ state: st });
  assert.equal(again.held(c.P).size, 3);
  assert.equal((await again.extend(c.P, 5, [await leafFingerprint('{"x":2}')])).refused.code, 'out-of-step');
  // A state that gives a book lines past its seal, or past its first line, is refused.
  for (const [book, member, value] of [[saved(c.afterBook1).books[0], 'size', 4], [saved(c.afterBook1).books[0], 'parts', [fp(1)]], [unsealed(fp(1)), 'size', 2], [unsealed(fp(1)), 'parts', [fp(1)]]]) {
    await assert.rejects(sealerOf({ state: { ...saved(c.afterBook1), books: [{ ...book, [member]: value }] } }), /holds a member that is not known/);
  }
  // A book with no seal: started again, the sealer holds its first line and asks for the rest.
  const fresh = await sealerOf();
  const lines = ['{"u":1}', '{"u":2}', '{"u":3}'];
  const U = b64(await leafFingerprint(lines[0]));
  const startedU = await fresh.extend(U, 0, await leavesOf(lines.slice(0, 2)));
  assert.deepEqual(startedU.state.books[0], unsealed(U));
  assert.deepEqual(await fresh.extend(U, 2, await leavesOf(lines.slice(2))), { size: 3 });
  assert.deepEqual(saved(fresh.state()).books[0], unsealed(U));
  const reopened = await sealerOf({ state: saved(fresh.state()) });
  assert.equal(reopened.held(U).size, 1);
  assert.equal((await reopened.extend(U, 1, await leavesOf(lines.slice(1)))).size, 3);
  const sU = await reopened.seal(U, { previous: null });
  assert.equal(JSON.parse(Buffer.from(sU.entry.seal.payload, 'base64url')).root, b64(await treeRoot(lines.map(utf8))));
});

test('what a state may hold, read strictly (Md2)', async () => {
  const c = await chain();
  const opens = (books, base = c.afterBook1) => sealerOf({ state: { ...saved(base), books } });
  const book1 = () => saved(c.afterBook1).books[0];
  // The parts at the latest seal must be those of a tree of that many lines.
  const shortParts = book1();
  shortParts.latest.parts = shortParts.latest.parts.slice(1);
  await assert.rejects(opens([shortParts]), /must be the 2 fingerprints of a tree of 3 leaves/);
  await assert.rejects(opens([unsealed(fp(1), { closed: 'no' })]), /true or false/);
  await assert.rejects(opens([unsealed(fp(1), { recorder: '' })]), (e) => e.code === 'bad-field' && /recorder/.test(e.message));
  // A seal of another book number; a first book that names a book it follows.
  await assert.rejects(opens([{ ...book1(), number: 2 }]), /a seal of another book number/);
  await assert.rejects(opens([{ ...book1(), follows: c.P }]), /is given for a first book/);
  // A later book with no seal must name the book it follows, which the state holds, with a seal, of the same recorder.
  await assert.rejects(opens([unsealed(fp(1), { number: 2 })]), /must name the book it follows/);
  await assert.rejects(opens([unsealed(fp(1), { number: 2, follows: fp(3) })]), /follows a book that this state does not hold/);
  await assert.rejects(opens([unsealed(fp(1)), unsealed(fp(2), { number: 2, follows: fp(1) })]), /follows a book that has no seal/);
  await assert.rejects(opens([book1(), unsealed(fp(2), { number: 2, follows: c.P, recorder: 'agent-x' })]), /follows a book of another recorder/);
  await assert.rejects(opens([book1(), unsealed(fp(2), { number: 2, follows: c.P }), unsealed(fp(4), { number: 2, follows: c.P })]), /two books follow the same book/);
  // Books of one first line belong to one recorder.
  const split = saved(c.afterBook2).books;
  delete split[1].follows;
  split[1].recorder = 'agent-x';
  await assert.rejects(opens(split), /belong to more than one recorder/);
  // At most 1,000 books.
  const many = Array.from({ length: 1000 }, (_, i) => unsealed(b64(new Uint8Array(32).fill(0).map((x, j) => (j < 2 ? (i >> (8 * j)) & 255 : 7)))));
  await assert.rejects(opens([...many, unsealed(fp(250))]), /at most 1,000 books/);
  const full = await opens(many);
  assert.equal((await full.extend(fp(250), 0, [new Uint8Array(32).fill(250)])).refused.code, 'too-large');
  assert.equal((await full.update(c.P, c.L1.entry, await leavesOf(c.lines1))).refused.code, 'too-large');
});

test('what a call may hold, and the rules of a chain of books, each held by a test (Md2)', async () => {
  const c = await chain();
  const s = await sealerOf();
  const one = new Uint8Array(32).fill(5);
  const first = b64(one);
  // At most 100,000 leaf fingerprints in one call; a new book starts with its first line; a book number is 1 or more.
  const tooMany = await s.extend(first, 0, new Array(100001).fill(one));
  assert.equal(tooMany.refused.code, 'bad-field');
  assert.equal((await s.extend(first, 0, [])).refused.code, 'bad-field');
  const zero = await s.extend({ first, number: 0 }, 0, [one]);
  assert.equal(zero.refused.code, 'bad-field');
  assert.match(zero.refused.message, /1 or more/);
  assert.match((await s.extend(first, 0, [one], { follows: fp(1) })).refused.message, /only a book after the first follows another/);
  // A later book follows a book with a seal, that is not closed, and that no other book follows.
  await s.extend(first, 0, [one]);
  const G = new Uint8Array(32).fill(6);
  assert.equal((await s.extend({ first: b64(G), number: 2 }, 0, [G], { follows: first })).refused.code, 'not-sealed');
  const closedState = saved(c.afterBook1);
  closedState.books[0].closed = true;
  const closed = await sealerOf({ state: closedState });
  assert.equal((await closed.extend({ first: b64(G), number: 2 }, 0, [G], { follows: c.P })).refused.code, 'book-closed');
  // A closed book is not sealed: with nothing new, the refusal is still that it is closed.
  assert.equal((await closed.seal(c.P, { previous: c.L1.fingerprint })).refused.code, 'book-closed');
  const open = await sealerOf({ state: saved(c.afterBook1) });
  assert.equal((await open.extend({ first: b64(G), number: 2 }, 0, [G], { follows: c.P })).size, 1);
  const H = new Uint8Array(32).fill(8);
  assert.equal((await open.extend({ first: b64(H), number: 2 }, 0, [H], { follows: c.P })).refused.code, 'book-closed');
  // A book carries on after the book it was started after, and no other.
  assert.match((await open.extend({ first: b64(G), number: 2 }, 1, [H], { follows: fp(3) })).refused.message, /is not the book this book was started after/);
  // A book holds at most 100,000 entries.
  const many = Array.from({ length: 100000 }, (_, i) => new Uint8Array(32).fill(0).map((x, j) => (j < 3 ? (i >> (8 * j)) & 255 : 11)));
  const full = await sealerOf();
  assert.equal((await full.extend(b64(many[0]), 0, many.slice(0, 99999))).size, 99999);
  assert.equal((await full.extend(b64(many[0]), 99999, [many[99999], one])).refused.code, 'too-large');
  assert.equal((await full.extend(b64(many[0]), 99999, [many[99999]])).size, 100000);
  assert.equal((await full.extend(b64(many[0]), 100000, [one])).refused.code, 'too-large');
  // Bringing up to date: a seal of the book's own number; never a closed book; the seal held already takes no lines.
  const mismatch = await (await sealerOf()).update({ first: c.P, number: 2 }, c.L1.entry, await leavesOf(c.lines1));
  assert.equal(mismatch.refused.code, 'seal-mismatch');
  assert.match(mismatch.refused.message, /is of book 1, not of book 2/);
  assert.equal((await (await sealerOf({ state: saved(c.afterBook2) })).update(c.P, c.L1.entry, [])).refused.code, 'book-closed');
  const same = await (await sealerOf({ state: saved(c.afterBook1) })).update(c.P, c.L1.entry, [one]);
  assert.equal(same.refused.code, 'bad-field');
  assert.match(same.refused.message, /holds this seal already/);
});

test('a sealer whose clock fails, or whose keys sign for another key set, gives no seal (Md2)', async () => {
  const lines = ['{"k":1}'];
  const first = b64(await leafFingerprint(lines[0]));
  const broken = await sealerOf({
    clock: () => {
      throw new Error('no clock');
    },
  });
  await broken.extend(first, 0, await leavesOf(lines));
  const noTime = await broken.seal(first, { previous: null });
  assert.equal(noTime.refused.code, 'check-failed');
  assert.match(noTime.refused.message, /clock did not give a time/);
  // Keys of the platform held for another key set: the sealer opens (they cannot be compared before signing), but
  // the seal they sign does not pass its own check, so it is neither kept nor given out.
  const other = await generateSealKeySet();
  const wrong = await sealerOf({ signers: other.privateKeys });
  await wrong.extend(first, 0, await leavesOf(lines));
  const bad = await wrong.seal(first, { previous: null });
  assert.equal(bad.refused.code, 'check-failed');
  assert.match(bad.refused.message, /does not pass its own check/);
  assert.equal(wrong.held(first).latest, null);
});

test('the tree builder copies the fingerprints it is handed and the parts it hands back', async () => {
  const leaf = new Uint8Array(32).fill(3);
  const builder = treeBuilder();
  await builder.addLeafHash(leaf);
  const root = b64(await builder.root());
  leaf[0] ^= 1;
  assert.equal(b64(await builder.root()), root);
  builder.parts()[0].hash[0] ^= 1;
  assert.equal(b64(await builder.root()), root);
});

// ---- After the second independent review (choices K45 onwards) ----

// Agent one's book: permission P, a stub, a renewed permission P2 from the same passkey, and a stub under P2 (as the
// review's probe builds it); and a permission of agent two's own, Q, for another agent.
let renewalBookMade;
function renewalBook() {
  renewalBookMade ??= (async () => {
    const w = await makeWorld();
    await w.add({ value: 10 });
    const prepared = await prepareSlip({ ...w.fields, purpose: 'Renewed: keep the office stocked.' });
    const slip2 = assembleSlip(prepared, await w.passkey.sign(prepared.challenge));
    const fp2 = await fingerprint(fromBase64url(slip2.payload));
    w.entries.push({ slip: slip2 });
    w.after = null;
    await w.add({ slip: fp2, value: 20 });
    const lines = linesOf(w.book());
    const w2 = await makeWorld();
    const q = linesOf(w2.book());
    return {
      lines,
      P: b64(await leafFingerprint(lines[0])),
      P2: b64(await leafFingerprint(lines[2])),
      agentOne: await keySetFingerprint(w.agent.keys),
      agentTwo: await keySetFingerprint(w2.agent.keys),
      agentTwoKeys: w2.agent,
      q,
      Q: b64(await leafFingerprint(q[0])),
    };
  })();
  return renewalBookMade;
}

test('a recorder named with its agents starts books only with their permissions, so never with a first line that is a permission for another recorder\'s agent (M1, L1)', async () => {
  const r = await renewalBook();
  const s = await sealerOf();
  const one = s.forRecorder('agent-one', { agents: [r.agentOne] });
  const two = s.forRecorder('agent-two', { agents: [r.agentTwo] });
  const leaves = await leavesOf(r.lines);
  // A book is started with its first line itself, the line the book is known by.
  assert.equal((await one.extend(r.P, 0, leaves)).refused.message.startsWith('line: a book is started with its first line itself'), true);
  const wrongLine = await one.extend(r.P, 0, leaves, { line: r.lines[1] });
  assert.equal(wrongLine.refused.code, 'bad-field');
  assert.match(wrongLine.refused.message, /not the line the book is known by/);
  assert.equal((await one.extend(r.P, 0, leaves, { line: r.lines[0] })).size, 4);
  const S1 = await one.seal(r.P, { previous: null });
  assert.ok(S1.entry, JSON.stringify(S1.refused));
  // Agent two cannot start a book from the renewed permission inside agent one's book.
  const squat = await two.extend(r.P2, 0, await leavesOf(r.lines.slice(2)), { line: r.lines[2] });
  assert.equal(squat.refused.code, 'other-recorder');
  assert.equal(two.held(r.P2), null);
  // Its own permission is its own.
  assert.equal((await two.extend(r.Q, 0, await leavesOf(r.q), { line: r.q[0] })).size, 1);
  // Agent one starts its next book with the renewed permission, as a recorder does after a renewal.
  const next = await one.extend({ first: r.P2, number: 2 }, 0, await leavesOf([r.lines[2]]), { follows: r.P, line: r.lines[2] });
  assert.equal(next.size, 1, JSON.stringify(next.refused));
  // A line that is not a permission, or a permission for an agent that its rules do not name, is not one to start with.
  const notSlip = '{"note":"not a permission"}';
  assert.equal((await one.extend(b64(await leafFingerprint(notSlip)), 0, [await leafFingerprint(notSlip)], { line: notSlip })).refused.code, 'slip-missing');
  const third = linesOf((await makeWorld()).book())[0];
  const T = b64(await leafFingerprint(third));
  assert.equal((await one.extend(T, 0, [await leafFingerprint(third)], { line: third })).refused.code, 'agent-not-allowed');
  // The rules stay with the recorder's name.
  assert.equal((await s.forRecorder('agent-one').extend(T, 0, [await leafFingerprint(third)], { line: third })).refused.code, 'agent-not-allowed');
  // A recorder with no list, and the sealer's own calls: a book only with its first line, and never for an agent a
  // recorder's list names; an agent no list names is free.
  const free = s.forRecorder('agent-free');
  assert.equal((await free.extend(T, 0, [await leafFingerprint(third)])).refused.message.startsWith('line: a book is started with its first line itself'), true);
  const twoAgain = linesOf((await makeWorld({ agent: r.agentTwoKeys })).book())[0];
  const T2 = b64(await leafFingerprint(twoAgain));
  assert.equal((await free.extend(T2, 0, [await leafFingerprint(twoAgain)], { line: twoAgain })).refused.code, 'other-recorder');
  assert.equal((await s.extend(T2, 0, [await leafFingerprint(twoAgain)], { line: twoAgain })).refused.code, 'other-recorder');
  assert.equal((await free.extend(T, 0, [await leafFingerprint(third)], { line: third })).size, 1);

  // After a state begun again with none, agent two cannot bring agent one's book in first (L1).
  const fresh = await sealerOf();
  const one2 = fresh.forRecorder('agent-one', { agents: [r.agentOne] });
  const two2 = fresh.forRecorder('agent-two', { agents: [r.agentTwo] });
  assert.equal((await two2.update(r.P, S1.entry, leaves, { line: r.lines[0] })).refused.code, 'other-recorder');
  assert.equal((await two2.update(r.P, S1.entry, leaves)).refused.message.startsWith('line: a book is started with its first line itself'), true);
  assert.equal((await one2.update(r.P, S1.entry, leaves, { line: r.lines[1] })).refused.code, 'bad-field');
  assert.equal((await one2.update(r.P, S1.entry, leaves, { line: r.lines[0] })).size, 4);
  assert.equal(two2.held(r.P), null);
});

test('a recorder\'s rules are read strictly and fixed by the first call that gives them; an agent belongs to one recorder', async () => {
  const s = await sealerOf();
  const [a, b] = [fp(1), fp(2)];
  s.forRecorder('x', { agents: [a], books: 3 });
  assert.doesNotThrow(() => s.forRecorder('x', { books: 3, agents: [a] }));
  assert.doesNotThrow(() => s.forRecorder('x'));
  assert.throws(() => s.forRecorder('x', { agents: [a], books: 4 }), /fixed by the first call/);
  assert.throws(() => s.forRecorder('y', { agents: [b, a] }), /an agent belongs to one recorder/);
  const many = Array.from({ length: 65 }, (_, i) => b64(new Uint8Array(32).fill(i)));
  for (const bad of [{ agents: [] }, { agents: many }, { agents: [b, b] }, { agents: ['x'] }, { agents: 'x' }, { books: 0 }, { books: 1001 }, { books: 1.5 }, { other: 1 }, null]) {
    assert.throws(() => s.forRecorder('z', bad), (e) => e.code === 'bad-field', JSON.stringify(bad));
  }
  // The refused call gave "y" no rules: it may still be given b.
  assert.doesNotThrow(() => s.forRecorder('y', { agents: [b] }));
});

test('a recorder holds at most the books its rules allow, and books with no seal can be released (M2)', async () => {
  const s = await sealerOf();
  const x = s.forRecorder('agent-x', { books: 3 });
  const y = s.forRecorder('agent-y');
  const L = (n) => new Uint8Array(32).fill(n);
  for (const n of [1, 2, 3]) assert.equal((await x.extend(b64(L(n)), 0, [L(n)])).size, 1);
  const fourth = await x.extend(b64(L(4)), 0, [L(4)]);
  assert.equal(fourth.refused.code, 'too-large');
  assert.match(fourth.refused.message, /holds 3 books, the most its rules allow/);
  // Another recorder is not held back by it.
  assert.equal((await y.extend(b64(L(5)), 0, [L(5)])).size, 1);
  // Nor is a book brought in with update past the limit.
  const elsewhere = await sealerOf();
  await elsewhere.extend(b64(L(6)), 0, [L(6)]);
  const s6 = await elsewhere.seal(b64(L(6)), { previous: null });
  assert.equal((await x.update(b64(L(6)), s6.entry, [L(6)])).refused.code, 'too-large');
  // Book 1 sealed; then the books with no seal of agent-x released: only those.
  const s1 = await x.seal(b64(L(1)), { previous: null });
  assert.ok(s1.entry);
  const done = await s.releaseUnsealed({ recorder: 'agent-x' });
  assert.deepEqual(done.released, [
    { first: b64(L(2)), number: 1, recorder: 'agent-x' },
    { first: b64(L(3)), number: 1, recorder: 'agent-x' },
  ]);
  assert.deepEqual(done.state.books.map((b) => b.first).sort(), [b64(L(1)), b64(L(5))].sort());
  assert.equal(x.held(b64(L(1))).latest, s1.fingerprint);
  assert.equal(y.held(b64(L(5))).size, 1);
  // The places are free again: in the limit, and as the next book after book 1.
  const ref2 = (n) => ({ first: b64(L(n)), number: 2 });
  assert.equal((await x.extend(ref2(7), 0, [L(7)], { follows: b64(L(1)) })).size, 1);
  assert.equal((await x.extend(ref2(8), 0, [L(8)], { follows: b64(L(1)) })).refused.code, 'book-closed');
  await s.releaseUnsealed({ recorder: 'agent-x' });
  assert.equal((await x.extend(ref2(8), 0, [L(8)], { follows: b64(L(1)) })).size, 1);
  // The sealer's own books alone (recorder null), or every recorder's.
  await s.extend(b64(L(9)), 0, [L(9)]);
  assert.deepEqual((await s.releaseUnsealed({ recorder: null })).released, [{ first: b64(L(9)), number: 1, recorder: null }]);
  const all = await s.releaseUnsealed();
  assert.deepEqual(all.released.map((b) => b.recorder).sort(), ['agent-x', 'agent-y']);
  assert.deepEqual(all.state.books.map((b) => b.first), [b64(L(1))]);
  assert.equal((await sealerOf({ state: saved(all.state) })).forRecorder('agent-x').held(b64(L(1))).latest, s1.fingerprint);
  await assert.rejects(s.releaseUnsealed({ recorder: '' }), (e) => e.code === 'bad-field');
  await assert.rejects(s.releaseUnsealed({ other: 1 }), (e) => e.code === 'bad-field');
});

test('a book left waiting after a book that another book now follows takes no seal (L2)', async () => {
  const P = '{"slip":"permission P"}';
  const Pf = b64(await leafFingerprint(P));
  const live = await sealerOf();
  await live.extend(Pf, 0, await leavesOf([P, '{"n":1}']));
  const S1 = await live.seal(Pf, { previous: null });
  const copy = saved(S1.state);
  const ref2 = { first: Pf, number: 2 };
  const b2 = [P, '{"n":2}'];
  await live.extend(ref2, 0, await leavesOf(b2), { follows: Pf });
  const T1 = await live.seal(ref2, { previous: S1.fingerprint });
  const b2more = [T1.line, '{"n":3}'];
  await live.extend(ref2, 2, await leavesOf(b2more));
  const T2 = await live.seal(ref2, { previous: T1.fingerprint });
  // Another history of the copy, in which a book X 2 followed book 1 and was sealed.
  const X = '{"slip":"another permission X"}';
  const refX = { first: b64(await leafFingerprint(X)), number: 2 };
  const other = await sealerOf({ state: saved(copy) });
  await other.extend(refX, 0, [await leafFingerprint(X)], { follows: Pf });
  const TX = await other.seal(refX, { previous: S1.fingerprint });
  assert.ok(TX.entry);
  // Put back to the copy: X waits after book 1; the real book 2 is brought in from its second seal, which closes book 1.
  const back = await sealerOf({ state: saved(copy) });
  assert.equal((await back.extend(refX, 0, [await leafFingerprint(X)], { follows: Pf })).size, 1);
  assert.equal((await back.update(ref2, T1.entry, await leavesOf(b2))).refused.code, 'book-closed');
  assert.equal((await back.update(ref2, T2.entry, await leavesOf([...b2, ...b2more]))).size, 4);
  assert.equal(back.held(Pf).closed, true);
  // X takes no first seal, signed here or brought in: two books 2 after book 1 are never both sealed.
  const sX = await back.seal(refX, { previous: S1.fingerprint });
  assert.equal(sX.refused.code, 'book-closed');
  assert.match(sX.refused.message, /can be released/);
  assert.equal((await back.update(refX, TX.entry, [await leafFingerprint(X)])).refused.code, 'book-closed');
  assert.equal(back.held(refX).latest, null);
  // Nothing was signed for it here: it is released.
  assert.deepEqual((await back.releaseUnsealed()).released, [{ first: refX.first, number: 2, recorder: null }]);
});

test('a saved latest seal, a seal entry handed over and a book reference hold only their own members (N8 to N10)', async () => {
  const c = await chain();
  const extra = saved(c.afterBook1);
  extra.books[0].latest.note = 1;
  await assert.rejects(sealerOf({ state: extra }), /holds a member that is not known/);
  const s = await sealerOf({ state: saved(c.afterBook1) });
  assert.equal((await s.update(c.P, { ...c.L1.entry, note: 1 }, [])).refused.code, 'bad-field');
  assert.equal((await s.update(c.P, c.L1.entry, [])).size, 3, 'the same entry, as it is, is taken');
  assert.equal((await s.extend({ first: c.P, number: 1, note: 1 }, 3, [new Uint8Array(32)])).refused.code, 'bad-field');
  assert.equal((await s.extend({ first: c.P, number: 1 }, 3, [new Uint8Array(32)])).size, 4, 'the same reference, as it is, is taken');
});

test('the options of extend and update are read strictly: a misspelt member is refused, never set aside (X8, X9)', async () => {
  const c = await chain();
  const s = await sealerOf({ state: saved(c.afterBook1) });
  const one = new Uint8Array(32).fill(7);
  for (const misspelt of [{ lines: c.lines1[0] }, { follow: c.P }, { line: undefined, note: 1 }]) {
    const refused = await s.extend(c.P, 3, [one], misspelt);
    assert.equal(refused.refused?.code, 'bad-field', JSON.stringify(Object.keys(misspelt)));
    assert.match(refused.refused.message, /more.*holds a member that is not known/);
  }
  assert.equal((await s.extend(c.P, 3, [one], {})).size, 4, 'with no misspelt member, the same lines are taken');
  const u = await sealerOf({ state: saved(c.afterBook1) });
  for (const misspelt of [{ lines: c.lines1[0] }, { follows: c.P }]) {
    const refused = await u.update(c.P, c.L1.entry, [], misspelt);
    assert.equal(refused.refused?.code, 'bad-field', JSON.stringify(Object.keys(misspelt)));
    assert.match(refused.refused.message, /more.*holds a member that is not known/);
  }
  assert.equal((await u.update(c.P, c.L1.entry, [], {})).size, 3, 'with no misspelt member, the same entry is taken');
});

// ---- After the fourth independent review (choices K67 onwards) ----

test('update keeps of an entry only the seal and its time-stamps, read for their form only, and refuses an entry longer than a line (Md1)', async () => {
  const c = await chain();
  const leaves = await leavesOf(c.lines1);
  const seal = c.L1.entry.seal;
  const fresh = () => sealerOf();
  // An entry far longer than a line of a book may be: refused before anything in it is read, and nothing is kept.
  const swollen = await fresh();
  const long = await swollen.update(c.P, { seal, stamps: Array.from({ length: 64 }, (_, i) => `${'A'.repeat(99999)}${'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'[i]}`), witnesses: [{ any: 'thing' }] }, leaves);
  assert.equal(long.refused?.code, 'too-large', JSON.stringify(long.refused));
  assert.equal(swollen.held(c.P), null);
  assert.deepEqual(saved(swollen.state()).books, []);
  // Witness statements alone can make an entry too long as well.
  const witnessed = await (await fresh()).update(c.P, { seal, witnesses: [{ any: 'x'.repeat(140000) }] }, leaves);
  assert.equal(witnessed.refused?.code, 'too-large');
  // A line's length is counted in bytes: 70,000 characters of two bytes each are too many.
  const wide = await (await fresh()).update(c.P, { seal, witnesses: [{ any: 'é'.repeat(70000) }] }, leaves);
  assert.equal(wide.refused?.code, 'too-large');
  // Time-stamps are read for their form only, by the rules a book reads their form by: at most four, each at most 12,288 bytes, in base64url, none twice.
  const five = ['AAAA', 'AAAB', 'AAAC', 'AAAD', 'AAAE'];
  for (const [stamps, code] of [[five, 'bad-field'], [['A'.repeat(20000)], 'bad-field'], [['!!!!'], 'bad-base64url'], [['AAAA', 'AAAA'], 'bad-field'], [[], 'bad-field'], ['AAAA', 'bad-field']]) {
    const s = await fresh();
    const got = await s.update(c.P, { seal, stamps }, leaves);
    assert.equal(got.refused?.code, code, JSON.stringify(stamps).slice(0, 40));
    assert.equal(s.held(c.P), null);
  }
  // A sound entry with time-stamps and witness statements: the seal and its time-stamps are kept, the statements not.
  const s = await fresh();
  const stamps = ['AAAA', b64(new Uint8Array(300).fill(9))];
  const handed = { seal, stamps, witnesses: [{ any: 'thing' }] };
  const taken = await s.update(c.P, handed, leaves);
  assert.equal(taken.size, 3, JSON.stringify(taken.refused));
  stamps.push('AAAB');
  handed.seal = null;
  const kept = taken.state.books[0].latest.entry;
  assert.deepEqual(Object.keys(kept).sort(), ['seal', 'stamps']);
  assert.deepEqual(kept, { seal, stamps: ['AAAA', b64(new Uint8Array(300).fill(9))] });
  assert.deepEqual(saved(s.state()).books[0].latest.entry, kept, 'nothing done to what was handed over changes what is kept');
  const held = s.latest(c.P);
  assert.equal(held.line, entryLine(kept));
  assert.equal(held.fingerprint, c.L1.fingerprint);
  // A saved state holds the seal and its time-stamps only, read in the same way.
  const st = saved(taken.state);
  assert.equal((await sealerOf({ state: st })).latest(c.P).line, entryLine(kept));
  const withStatements = saved(taken.state);
  withStatements.books[0].latest.entry.witnesses = [{ any: 'thing' }];
  await assert.rejects(sealerOf({ state: withStatements }), /holds a member that is not known/);
  const fiveSaved = saved(taken.state);
  fiveSaved.books[0].latest.entry.stamps = five;
  await assert.rejects(sealerOf({ state: fiveSaved }), (e) => e.code === 'bad-field');
  const longSaved = saved(taken.state);
  longSaved.books[0].latest.entry.stamps = ['A'.repeat(16384), 'B'.repeat(16384), 'C'.repeat(16384), 'D'.repeat(16384), 'E'.repeat(16384), 'F'.repeat(16384), 'G'.repeat(16384), 'H'.repeat(16384)];
  await assert.rejects(sealerOf({ state: longSaved }), (e) => e.code === 'too-large');
});

// ---- After the fifth independent review (choices K76 onwards) ----

test('update reads an entry once: a member that gives another value at one reading cannot be measured as one thing and kept as another (K76)', async () => {
  const c = await chain();
  const leaves = await leavesOf(c.lines1);
  const seal = c.L1.entry.seal;
  const honest = { seal, stamps: ['AAAA'] };
  const bad = {
    stamps: Array.from({ length: 4 }, (_, i) => 'A'.repeat(16000) + i).concat(Array.from({ length: 60 }, (_, i) => 'B'.repeat(100000) + i)),
    seal: { junk: 'x'.repeat(3000000) },
  };
  for (const member of ['stamps', 'seal']) {
    // The bad value at the first, the second or the third reading, and the honest one at every other.
    for (let k = 1; k <= 3; k++) {
      let n = 0;
      const e = member === 'seal' ? { stamps: honest.stamps } : { seal };
      Object.defineProperty(e, member, { enumerable: true, get: () => (++n === k ? bad[member] : honest[member]) });
      const s = await sealerOf();
      const got = await s.update(c.P, e, leaves);
      const what = `${member}, bad at reading ${k}`;
      assert.ok(n <= 1, `${what}: read ${n} times`);
      if (got.refused) {
        assert.equal(s.held(c.P), null, what);
        continue;
      }
      // Taken only with the honest value, and then what is kept is exactly that, and can be opened again.
      assert.equal(got.size, 3, what);
      assert.deepEqual(got.state.books[0].latest.entry, honest, what);
      assert.equal(s.latest(c.P).line, entryLine(honest), what);
      assert.equal((await sealerOf({ state: saved(got.state) })).latest(c.P).line, entryLine(honest), what);
    }
  }
  // A Proxy that gives a seal of no worth to every reading after the first is read once as well.
  let reads = 0;
  const proxy = new Proxy(honest, { get: (t, name) => (name === 'seal' && reads++ > 0 ? bad.seal : t[name]) });
  const s = await sealerOf();
  const got = await s.update(c.P, proxy, leaves);
  assert.equal(got.size, 3, JSON.stringify(got.refused));
  assert.deepEqual(got.state.books[0].latest.entry, honest);
  // A Proxy that lists a member it may not hold only after its members were first looked at: the copy's members are
  // looked at again, and the entry is refused, as one that held the member from the start is.
  let listed = 0;
  const growing = new Proxy({ ...honest }, {
    ownKeys: (t) => (++listed === 1 ? Reflect.ownKeys(t) : [...Reflect.ownKeys(t), 'note']),
    getOwnPropertyDescriptor: (t, name) => (name === 'note' ? { value: 'x', enumerable: true, configurable: true, writable: true } : Reflect.getOwnPropertyDescriptor(t, name)),
    get: (t, name) => (name === 'note' ? 'x' : t[name]),
  });
  const g = await sealerOf();
  const grown = await g.update(c.P, growing, leaves);
  assert.ok(listed >= 2, `its members were listed ${listed} times`);
  assert.equal(grown.refused?.code, 'bad-field', JSON.stringify(grown));
  assert.match(grown.refused.message, /^entry: holds a member that is not known/);
  assert.equal(g.held(c.P), null);
});
