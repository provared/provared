// Witnesses (format description, section 29): the witness program in the
// library (openWitness), what a checker makes of witness statements beside
// seals, the command-line checker, a checker that is carried on, and the
// stub writer. The shared test files (witness-*.json) hold the checker's
// answers for many more cases.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  assembleSlip,
  bookIdentity,
  checkBook,
  checkShow,
  countersign,
  fingerprint,
  fromBase64url,
  makeShow,
  prepareSlip,
  writeStub,
  entryLine,
  generateKeySet,
  generateSealKeySet,
  keySetFingerprint,
  openChecker,
  openRecorder,
  openWitness,
  signerFromKey,
  thumbprint,
  utf8,
  witnessProof,
  writeBook,
  writeSeal,
  writeTerms,
  writeWitness,
} from '../src/index.js';
import { trustOf } from '../page/render.js';
import { encodeContent } from '../src/jws.js';
import { tempFolder } from './helpers/temp.mjs';
import { START, makeWorld } from './helpers/world.mjs';

const SLH = 'SLH-DSA-SHA2-256s';
const NOW = Date.parse('2026-10-06T00:00:00Z');
const lineCount = (text) => text.split('\n').filter(Boolean).length;
const firstLineOf = (text) => utf8(text.split('\n')[0]);
// A signature with one byte changed: the right length, and base64url still.
const flipped = (b64) => {
  const bytes = Buffer.from(b64, 'base64url');
  bytes[10] ^= 1;
  return bytes.toString('base64url');
};

// A book with a slip and two stubs, a recorder, and two witnesses. Seals are
// made as needed: signing one takes about a second and a half.
async function setting() {
  const w = await makeWorld({ fields: { requires: [] } });
  await w.add({ value: 10 });
  await w.add({ value: 10 });
  w.recorder = await generateSealKeySet();
  const one = await generateKeySet();
  const by = { keys: one.keys, name: 'Example witness (invented)' };
  const recorderBy = { keys: w.recorder.keys, name: 'Example recorder (invented)' };
  const seal = (text, fields = {}) => writeSeal(text, { by: recorderBy, when: START + 5 * 3600 * 1000, ...fields }, fields.privateKeys ?? w.recorder.privateKeys);
  return { w, one, by, seal, recorderBy };
}

// Ask a witness to sign for a seal of a book, with the right proof for what it holds.
async function ask(witness, text, sealed, held = null, first = firstLineOf(text)) {
  return witness.witness({ seal: sealed.record }, await witnessProof(text, lineCount(text), held), first);
}

test('a witness signs for the first seal it sees of a book, then only for seals that extend it', async () => {
  const { w, one, by, seal } = await setting();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const book1 = w.book();
  const s1 = await seal(book1);
  const r1 = await ask(witness, book1, s1);
  assert.ok(r1.statement, JSON.stringify(r1.refused));
  // The state handed back already holds the seal, to be saved before the statement is given out.
  assert.equal(r1.state.books.length, 1);
  const identity = await bookIdentity(w.recorder.keys, firstLineOf(book1));
  assert.deepEqual(witness.latest(identity), { seal: s1.record, statement: r1.statement });
  assert.equal(witness.latest('another book'), null);

  // The same seal again: the same statement, and no second signature.
  const again = await ask(witness, book1, s1);
  assert.deepEqual(again.statement, r1.statement);

  // The book goes on, and the next seal extends the first.
  w.entries.push({ seal: s1.record, witnesses: [r1.statement] });
  await w.add({ value: 10 });
  const book2 = w.book();
  const s2 = await seal(book2, { previous: s1.fingerprint, when: START + 6 * 3600 * 1000 });
  const r2 = await ask(witness, book2, s2, 3);
  assert.ok(r2.statement, JSON.stringify(r2.refused));

  // Both statements check in the book, and count for a person who names the witness.
  w.entries.push({ seal: s2.record, witnesses: [r2.statement] });
  const trust = { issuerKeys: [await thumbprint(w.passkey.key)], sealKeys: [await keySetFingerprint(w.recorder.keys)], witnesses: [await keySetFingerprint(one.keys)] };
  const result = await checkBook(w.book(), trust);
  assert.deepEqual(result.problems, []);
  assert.equal(result.summary.intact, true);
  assert.deepEqual(result.summary.witnessed, { seal: 5, entries: 5, by: trust.witnesses, seals: [3, 5] });
  assert.ok(result.summary.limits.at(-1).startsWith('A witness you named as trusted signed for the seal at entry 5'));
  // Being witnessed excuses nothing, and is not needed: without the witness named, the record is just as intact.
  const { witnesses: _, ...noWitness } = trust;
  const plain = await checkBook(w.book(), noWitness);
  assert.equal(plain.summary.intact, true);
  assert.equal(plain.summary.witnessed, null);
});

test('a witness never signs two different seals of one book at one size, nor a seal that does not extend the one it holds', async () => {
  const { w, one, by, seal } = await setting();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const book1 = w.book();
  const s1 = await seal(book1);
  assert.ok((await ask(witness, book1, s1)).statement);
  w.entries.push({ seal: s1.record });
  await w.add({ value: 10 });
  const book2 = w.book();
  const s2 = await seal(book2, { previous: s1.fingerprint, when: START + 6 * 3600 * 1000 });
  const r2 = await ask(witness, book2, s2, 3);
  assert.ok(r2.statement);

  // A fork: a second history of the same length after the first seal.
  // (The witness weighs proofs, not what the lines say: a stub repeated stands for any other line.)
  const lines = book2.split('\n').filter(Boolean);
  const forkLines = [...lines.slice(0, 4), lines[2]];
  const forkBook = forkLines.join('\n') + '\n';
  const fork = await seal(forkBook, { previous: s1.fingerprint, when: START + 6 * 3600 * 1000 });
  assert.notEqual(fork.fingerprint, s2.fingerprint);
  const atSameSize = await ask(witness, forkBook, fork, 3);
  assert.equal(atSameSize.refused.code, 'seal-mismatch');

  // A longer history that does not extend the seal it holds: the proof cannot show it.
  const longer = [...forkLines, lines[4]].join('\n') + '\n';
  const notExtending = await seal(longer, { previous: s2.fingerprint, when: START + 7 * 3600 * 1000 });
  assert.equal((await ask(witness, longer, notExtending, 5)).refused.code, 'proof-invalid');
  // The right proof of the wrong tree is no better: a proof from the held size, over the real book, does not lead to this seal's root.
  assert.equal((await witness.witness({ seal: notExtending.record }, await witnessProof(book2 + entryLine({ seal: s2.record }) + '\n', 6, 5), firstLineOf(book2))).refused.code, 'proof-invalid');

  // A seal that names another seal than the one it holds.
  w.entries.push({ seal: s2.record });
  await w.add({ value: 10 });
  const book3 = w.book();
  const wrongPrevious = await seal(book3, { previous: s1.fingerprint, when: START + 7 * 3600 * 1000 });
  assert.equal((await ask(witness, book3, wrongPrevious, 5)).refused.code, 'seal-chain-broken');
  const dated = await seal(book3, { previous: s2.fingerprint, when: START + 5 * 3600 * 1000 - 1000 });
  assert.equal((await ask(witness, book3, dated, 5)).refused.code, 'time-went-backwards');
  const right = await seal(book3, { previous: s2.fingerprint, when: START + 7 * 3600 * 1000 });
  assert.ok((await ask(witness, book3, right, 5)).statement);
});

test('the books of one permission are one sequence to a witness: a new book starts from the last seal it holds, and the earlier book is closed', async () => {
  const { w, one, by, seal } = await setting();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const book1 = w.book();
  const s1 = await seal(book1);
  assert.ok((await ask(witness, book1, s1)).statement);
  // A new book that begins with the same permission, with no book number: it is book 1 again, and is refused.
  const second = writeBook([w.entries[0]]);
  const fresh = await seal(second);
  assert.equal((await ask(witness, second, fresh)).refused.code, 'seal-mismatch');
  // Book 2 whose first line is not the permission, offered with the permission as its first line: the audit path
  // does not lead to the seal, so it is refused, though it names the seal the witness holds.
  const stubFirst = writeBook([w.entries[1]]);
  const wrongStart = await seal(stubFirst, { book: 2, previous: s1.fingerprint, when: START + 6 * 3600 * 1000 });
  assert.equal((await witness.witness({ seal: wrongStart.record }, await witnessProof(stubFirst, 1, null), firstLineOf(book1))).refused.code, 'proof-invalid');
  // Book 2, whose first seal names the last seal of book 1: signed, with the audit path of its first line.
  const b2 = await seal(second, { book: 2, previous: s1.fingerprint, when: START + 6 * 3600 * 1000 });
  const r2 = await ask(witness, second, b2);
  assert.ok(r2.statement, JSON.stringify(r2.refused));
  // Book 1 is closed: a seal that extends it is refused now, though it extends the seal the witness held of it.
  w.entries.push({ seal: s1.record });
  await w.add({ value: 10 });
  const later1 = await seal(w.book(), { previous: s1.fingerprint, when: START + 7 * 3600 * 1000 });
  assert.equal((await ask(witness, w.book(), later1, 3)).refused.code, 'seal-mismatch');
  // A second book 2 (a fork across books) is refused, as is a book 3 that skips the book it holds.
  const fork = await seal(second, { book: 2, previous: s1.fingerprint, when: START + 6 * 3600 * 1000 + 1000 });
  assert.notEqual(fork.fingerprint, b2.fingerprint);
  assert.equal((await ask(witness, second, fork)).refused.code, 'seal-mismatch');
  const longerFork = writeBook([w.entries[0], w.entries[1]]);
  const fork2 = await seal(longerFork, { book: 2, previous: s1.fingerprint, when: START + 6 * 3600 * 1000 });
  assert.equal((await ask(witness, longerFork, fork2)).refused.code, 'seal-chain-broken');
  const skip = await seal(second, { book: 4, previous: b2.fingerprint, when: START + 8 * 3600 * 1000 });
  assert.equal((await ask(witness, second, skip)).refused.code, 'seal-chain-broken');
  // Book 3 that names a seal other than the latest the witness holds is refused; one that names it is signed.
  const wrong3 = await seal(second, { book: 3, previous: s1.fingerprint, when: START + 8 * 3600 * 1000 });
  assert.equal((await ask(witness, second, wrong3)).refused.code, 'seal-chain-broken');
  const right3 = await seal(second, { book: 3, previous: b2.fingerprint, when: START + 8 * 3600 * 1000 });
  assert.ok((await ask(witness, second, right3)).statement);
  // A book whose first line is not a permission is not a book a witness keeps.
  const notSlip = writeBook([w.entries[1]]);
  const s9 = await seal(notSlip);
  assert.equal((await ask(witness, notSlip, s9)).refused.code, 'slip-missing');
  // The same first line with a recorder's other keys is another book to the witness, which signs for it.
  const otherRecorder = await generateSealKeySet();
  const otherSeal = await seal(book1, { by: { keys: otherRecorder.keys, name: 'Another recorder (invented)' }, privateKeys: otherRecorder.privateKeys });
  assert.ok((await ask(witness, book1, otherSeal)).statement);
  assert.equal(witness.state().books.length, 2);
});

test('at first contact the first line must be the first entry of the sealed book', async () => {
  const { w, one, by, seal } = await setting();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const text = w.book();
  const s1 = await seal(text);
  // The line of a stub, said to be the first: not a permission.
  const wrong = utf8(text.split('\n')[1]);
  assert.equal((await ask(witness, text, s1, null, wrong)).refused.code, 'slip-missing');
  // Another permission, said to be the first line of this book: the proof does not lead there.
  const other = await makeWorld({ fields: { requires: [] } });
  assert.equal((await ask(witness, text, s1, null, firstLineOf(other.book()))).refused.code, 'proof-invalid');
  assert.equal((await witness.witness({ seal: s1.record }, [], firstLineOf(text))).refused.code, 'proof-invalid');
  assert.equal((await witness.witness({ seal: s1.record }, 'x', firstLineOf(text))).refused.code, 'proof-invalid');
  assert.equal((await witness.witness({ seal: s1.record }, [new Uint8Array(31)], firstLineOf(text))).refused.code, 'proof-invalid');
  assert.equal((await witness.witness({ seal: s1.record }, [], new Uint8Array(0))).refused.code, 'bad-field');
  assert.equal((await witness.witness({ seal: s1.record, note: 1 }, [], firstLineOf(text))).refused.code, 'bad-field');
  assert.equal(witness.state().books.length, 0);
  // The right line and proof.
  assert.ok((await ask(witness, text, s1)).statement);
});

test('a witness signs only for a seal whose three signatures it checked, dated no more than 300 seconds after its clock', async () => {
  const { w, one, by, seal } = await setting();
  const text = w.book();
  const s1 = await seal(text);
  const withoutSlh = await openWitness({ by, signers: one.privateKeys, clock: () => NOW, withoutMethods: [SLH] });
  assert.equal((await ask(withoutSlh, text, s1)).refused.code, 'check-failed');
  const early = await openWitness({ by, signers: one.privateKeys, clock: () => START + 5 * 3600 * 1000 - 301000 });
  assert.equal((await ask(early, text, s1)).refused.code, 'time-went-backwards');
  const justSo = await openWitness({ by, signers: one.privateKeys, clock: () => START + 5 * 3600 * 1000 - 300000 });
  assert.ok((await ask(justSo, text, s1)).statement);
  const broken = await openWitness({ by, signers: one.privateKeys, clock: () => { throw new Error('no clock'); } });
  assert.equal((await ask(broken, text, s1)).refused.code, 'check-failed');
  // A seal whose signature does not check.
  const bad = JSON.parse(JSON.stringify(s1.record));
  bad.signatures[0].signature = flipped(bad.signatures[0].signature);
  const plain = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  assert.equal((await plain.witness({ seal: bad }, await witnessProof(text, 3, null), firstLineOf(text))).refused.code, 'signature-invalid');
  assert.equal(plain.state().books.length, 0);
});

test('a signer that gives a signature that does not check: no statement, and nothing held', async () => {
  const { w, one, by, seal } = await setting();
  const text = w.book();
  const s1 = await seal(text);
  const other = await generateKeySet();
  // Signers for another key set: the signer interface refuses them, and nothing is held.
  const wrongSigners = [signerFromKey('Ed25519', other.privateKeys[0], other.keys[0]), signerFromKey('ML-DSA-87', other.privateKeys[1], other.keys[1])];
  const witness = await openWitness({ by, signers: wrongSigners, clock: () => NOW });
  assert.equal((await ask(witness, text, s1)).refused.code, 'check-failed');
  assert.equal(witness.state().books.length, 0);
  // Plain keys of another key set: the statement is made, does not check against "by", and is refused before it is kept.
  const wrongKeys = await openWitness({ by, signers: other.privateKeys, clock: () => NOW });
  assert.equal((await ask(wrongKeys, text, s1)).refused.code, 'check-failed');
  assert.equal(wrongKeys.state().books.length, 0);
});

test('opened from a saved state, a witness signs nothing until it is brought up to date and told so', async () => {
  const { w, one, by, seal } = await setting();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const book1 = w.book();
  const s1 = await seal(book1);
  const r1 = await ask(witness, book1, s1);
  const old = r1.state;
  w.entries.push({ seal: s1.record, witnesses: [r1.statement] });
  await w.add({ value: 10 });
  const book2 = w.book();
  const s2 = await seal(book2, { previous: s1.fingerprint, when: START + 6 * 3600 * 1000 });
  const r2 = await ask(witness, book2, s2, 3);
  // The state after the second seal was not saved: the witness is opened again from the state after the first.
  const restarted = await openWitness({ by, signers: one.privateKeys, clock: () => NOW, state: JSON.parse(JSON.stringify(old)) });
  // A fork of the second seal, which extends the first: refused, because the witness has not been brought up to date.
  const lines = book2.split('\n').filter(Boolean);
  const forkBook = [...lines.slice(0, 4), lines[2]].join('\n') + '\n';
  const fork = await seal(forkBook, { previous: s1.fingerprint, when: START + 6 * 3600 * 1000 });
  assert.equal((await ask(restarted, forkBook, fork, 3)).refused.code, 'witness-not-ready');
  assert.equal((await ask(restarted, book2, s2, 3)).refused.code, 'witness-not-ready');
  // Brought up to date from the book, which holds the second seal with this witness's statement.
  const entry2 = { seal: s2.record, witnesses: [r2.statement] };
  const updated = await restarted.update(entry2, await witnessProof(book2, 5, 3), firstLineOf(book2));
  assert.ok(updated.state, JSON.stringify(updated.refused));
  restarted.ready();
  assert.equal((await ask(restarted, forkBook, fork, 3)).refused.code, 'seal-mismatch');
  // And it goes on from there.
  w.entries.push(entry2);
  await w.add({ value: 10 });
  const book3 = w.book();
  const s3 = await seal(book3, { previous: s2.fingerprint, when: START + 7 * 3600 * 1000 });
  assert.ok((await ask(restarted, book3, s3, 5)).statement);
});

test('update takes only a seal that holds this witness\'s own statement, and that extends what it holds', async () => {
  const { w, one, by, seal } = await setting();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const book1 = w.book();
  const s1 = await seal(book1);
  const r1 = await ask(witness, book1, s1);
  const saved = r1.state;
  const restarted = await openWitness({ by, signers: one.privateKeys, clock: () => NOW, state: saved });
  // The seal it holds, with its own statement: nothing changes.
  assert.ok((await restarted.update({ seal: s1.record, witnesses: [r1.statement] }, [], firstLineOf(book1))).state);
  // A statement by another witness is not its own.
  const other = await generateKeySet();
  const foreign = await writeWitness({ seal: s1.fingerprint, size: 3, root: JSON.parse(Buffer.from(s1.record.payload, 'base64url').toString()).root, by: { keys: other.keys, name: 'Another witness (invented)' }, when: NOW }, other.privateKeys);
  w.entries.push({ seal: s1.record, witnesses: [r1.statement] });
  await w.add({ value: 10 });
  const book2 = w.book();
  const s2 = await seal(book2, { previous: s1.fingerprint, when: START + 6 * 3600 * 1000 });
  const signedByOther = await writeWitness({ seal: s2.fingerprint, size: 5, root: JSON.parse(Buffer.from(s2.record.payload, 'base64url').toString()).root, by: { keys: other.keys, name: 'Another witness (invented)' }, when: NOW }, other.privateKeys);
  void foreign;
  assert.equal((await restarted.update({ seal: s2.record, witnesses: [signedByOther.record] }, await witnessProof(book2, 5, 3), firstLineOf(book2))).refused.code, 'witness-invalid');
  assert.equal((await restarted.update({ seal: s2.record, witnesses: [] }, await witnessProof(book2, 5, 3), firstLineOf(book2))).refused.code, 'witness-invalid');
  // Its own statement for the second seal, made by the same keys elsewhere: taken, with the consistency proof.
  const own = await writeWitness({ seal: s2.fingerprint, size: 5, root: JSON.parse(Buffer.from(s2.record.payload, 'base64url').toString()).root, by, when: NOW }, one.privateKeys);
  assert.equal((await restarted.update({ seal: s2.record, witnesses: [own.record] }, [], firstLineOf(book2))).refused.code, 'proof-invalid');
  assert.ok((await restarted.update({ seal: s2.record, witnesses: [signedByOther.record, own.record] }, await witnessProof(book2, 5, 3), firstLineOf(book2))).state);
});

test('a saved state is checked when a witness is opened with it', async () => {
  const { w, one, by, seal } = await setting();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const text = w.book();
  const s1 = await seal(text);
  const { state } = await ask(witness, text, s1);
  const other = await generateKeySet();
  await assert.rejects(openWitness({ by: { keys: other.keys, name: 'Another witness (invented)' }, signers: other.privateKeys, state }), /another witness/);
  const changed = JSON.parse(JSON.stringify(state));
  changed.books[0].statement.signatures[0].signature = flipped(changed.books[0].statement.signatures[0].signature);
  await assert.rejects(openWitness({ by, signers: one.privateKeys, state: changed }));
  // The seal in the state with a signature changed: its content, and so its fingerprint and the statement, are the same.
  const badSeal = JSON.parse(JSON.stringify(state));
  badSeal.books[0].seal.signatures[0].signature = flipped(badSeal.books[0].seal.signatures[0].signature);
  await assert.rejects(openWitness({ by, signers: one.privateKeys, state: badSeal }), /does not pass its check/);
  const twice = { ...state, books: [state.books[0], state.books[0]] };
  await assert.rejects(openWitness({ by, signers: one.privateKeys, state: twice }), /the same person, agent and recorder are given twice/);
  await assert.rejects(openWitness({ by, signers: one.privateKeys, state: { ...state, type: 'x' } }));
  await assert.rejects(openWitness({ by, signers: one.privateKeys, state: 'x' }));
  // The state holds no private key.
  assert.ok(!JSON.stringify(state).includes('"d"'));
});

test('a checker that is carried on, and the stub writer, read witnessed seals as a whole check does', async () => {
  const { w, one, by, seal } = await setting();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const text = w.book();
  const s1 = await seal(text);
  const r1 = await ask(witness, text, s1);
  const options = { issuerKeys: [await thumbprint(w.passkey.key)], sealKeys: [await keySetFingerprint(w.recorder.keys)], witnesses: [await keySetFingerprint(one.keys)] };
  // The stub writer takes the witnessed seal into its book.
  const clock = START + 6 * 3600 * 1000;
  const writer = await openRecorder({ book: text, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys: options.issuerKeys, now: () => clock, options: { sealKeys: options.sealKeys, witnesses: options.witnesses } });
  await writer.add({ seal: s1.record, witnesses: [r1.statement] });
  const answer = await writer.check();
  assert.deepEqual(answer.problems, []);
  assert.deepEqual(answer.summary.witnessed?.seals, [3]);
  assert.deepEqual(answer, await checkBook(writer.book(), { issuerKeys: options.issuerKeys, sealKeys: options.sealKeys, witnesses: options.witnesses }));
  // A checker carried on, a line at a time.
  const carried = await openChecker('', options);
  for (const line of writer.book().split('\n').filter(Boolean)) await carried.add(line + '\n');
  assert.deepEqual(await carried.result(), await checkBook(writer.book(), options));
  // A statement that does not check, on a line handed to the stub writer: the line is not added.
  const changed = JSON.parse(JSON.stringify(r1.statement));
  changed.signatures[0].signature = flipped(changed.signatures[0].signature);
  const writer2 = await openRecorder({ book: text, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys: options.issuerKeys, now: () => clock, options: { sealKeys: options.sealKeys } });
  await assert.rejects(writer2.add({ seal: s1.record, witnesses: [changed] }));
  assert.equal(writer2.book(), text);
});

test('the command-line checker takes --witness, says how far a witness you trust reaches, and refuses a value that is not a fingerprint', async () => {
  const { w, one, by, seal } = await setting();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const text = w.book();
  const s1 = await seal(text);
  const r1 = await ask(witness, text, s1);
  w.entries.push({ seal: s1.record, witnesses: [r1.statement] });
  const dir = tempFolder();
  const file = join(dir, 'book.jsonl');
  writeFileSync(file, w.book());
  const cli = fileURLToPath(new URL('../bin/provared-check.mjs', import.meta.url));
  const run = (...args) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', cli, file, ...args], { encoding: 'utf8' });
  const issuer = await thumbprint(w.passkey.key);
  const sealer = await keySetFingerprint(w.recorder.keys);
  const fp = await keySetFingerprint(one.keys);
  const named = run('--issuer', issuer, '--sealer', sealer, '--witness', fp);
  assert.equal(named.status, 0, named.stdout + named.stderr);
  assert.match(named.stdout, /Witnessed by a witness you trust\? +yes: the seal at entry 3, which covers the first 3 entries \(1 of 1 seals witnessed\)/);
  assert.match(named.stdout, /WITNESSED by "Example witness \(invented\)" \(a label\), a witness you named as trusted/);
  const unnamed = run('--issuer', issuer, '--sealer', sealer);
  // Being witnessed is not needed for exit code 0.
  assert.equal(unnamed.status, 0);
  assert.match(unnamed.stdout, /Witnessed by a witness you trust\? +no \(you named no witness you trust, --witness\)/);
  assert.match(unnamed.stdout, /Witness statement, NOT COUNTED: from a witness you did not name as trusted/);
  const bad = run('--witness', 'not-a-fingerprint');
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /The value of --witness is not a fingerprint/);
  const json = JSON.parse(run('--issuer', issuer, '--sealer', sealer, '--witness', fp, '--json').stdout);
  assert.deepEqual(json.summary.witnessed, { seal: 3, entries: 3, by: [fp], seals: [3] });
});

test('a second history that starts from another first line is not witnessed for a reader who fixed the start (the review\'s probe)', async () => {
  const { w, one, by, seal } = await setting();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const trust = { issuerKeys: [await thumbprint(w.passkey.key)], sealKeys: [await keySetFingerprint(w.recorder.keys)], witnesses: [await keySetFingerprint(one.keys)] };
  // History A, witnessed.
  const a = w.book();
  const sA = await seal(a);
  const rA = await ask(witness, a, sA);
  assert.ok(rA.statement);
  // History B: a made-up first line (terms of an invented service), then the slip and a stub. The witness does not
  // keep a book whose first line is not a permission.
  const junk = await generateKeySet();
  const terms = await writeTerms({ by: { keys: junk.keys, name: 'Anything (invented)' }, accepts: ['supplies.order'], validFrom: '2026-10-01T00:00:00Z', validUntil: '2027-10-01T00:00:00Z' }, junk.privateKeys);
  const b = writeBook([{ terms: terms.record }, w.entries[0], w.entries[1]]);
  const sB = await seal(b);
  assert.equal((await ask(witness, b, sB)).refused.code, 'slip-missing');
  // A statement for B written directly with the witness's keys checks as a record, and does not count.
  const content = JSON.parse(Buffer.from(sB.record.payload, 'base64url').toString());
  const forged = await writeWitness({ seal: sB.fingerprint, size: content.size, root: content.root, by, when: NOW }, one.privateKeys);
  const result = await checkBook(b + entryLine({ seal: sB.record, witnesses: [forged.record] }) + '\n', trust);
  assert.equal(result.summary.witnessed, null);
  assert.equal(result.entries[3].witnesses[0].state, 'valid');
  assert.equal(result.entries[3].witnesses[0].counted, false);
  assert.ok(result.entries[3].notes.some((n) => n.includes('this book does not start with a permission')));
  // A, with its statement: counted only where both the passkey and the recorder are named, on the line and handed over alike.
  const bookA = a + entryLine({ seal: sA.record, witnesses: [rA.statement] }) + '\n';
  assert.deepEqual((await checkBook(bookA, trust)).summary.witnessed?.seals, [3]);
  const { issuerKeys: _i, ...noPasskey } = trust;
  const { sealKeys: _s, ...noRecorder } = trust;
  for (const options of [noPasskey, noRecorder]) {
    const r = await checkBook(bookA, options);
    assert.equal(r.summary.witnessed, null);
    assert.equal(r.entries[3].witnesses[0].counted, false);
  }
  const bare = a + entryLine({ seal: sA.record }) + '\n';
  const handed = { seals: [{ seal: sA.record, witnesses: [rA.statement] }] };
  assert.deepEqual((await checkBook(bare, { ...trust, ...handed })).summary.witnessed?.seals, [3]);
  assert.equal((await checkBook(bare, { ...noPasskey, ...handed })).summary.witnessed, null);
  assert.equal((await checkBook(bare, { ...noRecorder, ...handed })).summary.witnessed, null);
});

test('a statement with the right seal fingerprint but another number of entries or top fingerprint is refused, and a line with "witness" is unknown', async () => {
  const { w, one, by, seal } = await setting();
  const text = w.book();
  const s1 = await seal(text);
  const content = JSON.parse(Buffer.from(s1.record.payload, 'base64url').toString());
  const trust = { issuerKeys: [await thumbprint(w.passkey.key)], sealKeys: [await keySetFingerprint(w.recorder.keys)], witnesses: [await keySetFingerprint(one.keys)] };
  for (const change of [{ size: content.size + 1 }, { root: s1.fingerprint }]) {
    const statement = await writeWitness({ seal: s1.fingerprint, size: content.size, root: content.root, by, when: NOW, ...change }, one.privateKeys);
    const r = await checkBook(text + entryLine({ seal: s1.record, witnesses: [statement.record] }) + '\n', trust);
    assert.deepEqual(r.entries[3].problems.map((p) => p.code), ['witness-invalid'], JSON.stringify(change));
  }
  const good = await writeWitness({ seal: s1.fingerprint, size: content.size, root: content.root, by, when: NOW }, one.privateKeys);
  const r = await checkBook(text + entryLine({ seal: s1.record, witness: [good.record] }) + '\n', trust);
  assert.deepEqual(r.entries[3].problems.map((p) => p.code), ['unknown-entry']);
});

// A renewal: a second permission from the same passkey to the same agent, written into the book (as a recorder
// beside an agent renews), with stubs under it; the second permission's own stubs go over its limit.
async function renewal() {
  const s = await setting();
  const { w } = s;
  const prepared = await prepareSlip({ ...w.fields, purpose: 'Renewed.' });
  const slip2 = assembleSlip(prepared, await w.passkey.sign(prepared.challenge));
  const fp2 = await fingerprint(fromBase64url(slip2.payload));
  const stub = async (value, after, when) => {
    const x = await writeStub({ slip: fp2, action: 'supplies.order', amount: { unit: 'GBP', value }, with: 'supplier', after, when }, w.agent.privateKeys);
    return { entry: { stub: x.record, countersignature: await countersign(x.record, w.service.privateKeys, when + 60000) }, after: { seq: x.seq, fingerprint: x.fingerprint } };
  };
  const x1 = await stub(150, null, START + 3 * 3600 * 1000);
  const x2 = await stub(100, x1.after, START + 4 * 3600 * 1000);
  return { ...s, slip2, x1, x2 };
}

test('every permission one person gives one agent is one sequence to a witness: a book that starts with a renewal cannot fork the history', async () => {
  const { w, one, by, seal, slip2, x1, x2 } = await renewal();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const truth = writeBook([w.entries[0], { slip: slip2 }, x1.entry, x2.entry]);
  const sT = await seal(truth);
  assert.ok((await ask(witness, truth, sT)).statement);
  // A book that starts with the renewed permission, with the stub over its limit left out: the same sequence.
  const forged = writeBook([{ slip: slip2 }, x1.entry]);
  const sF = await seal(forged, { when: START + 5 * 3600 * 1000 + 1000 });
  assert.equal((await ask(witness, forged, sF)).refused.code, 'seal-mismatch');
  // As the next book of the sequence, naming the seal the witness holds, it follows on, as any new book.
  const next = await seal(forged, { book: 2, previous: sT.fingerprint, when: START + 6 * 3600 * 1000 });
  assert.ok((await ask(witness, forged, next)).statement);
  // A permission from the same passkey for another agent is another sequence.
  const otherAgent = await generateKeySet();
  const prepared = await prepareSlip({ ...w.fields, agent: { name: 'Another agent (invented)', keys: otherAgent.keys } });
  const slip3 = assembleSlip(prepared, await w.passkey.sign(prepared.challenge));
  const third = writeBook([{ slip: slip3 }]);
  assert.ok((await ask(witness, third, await seal(third))).statement);
  assert.equal(witness.state().books.length, 2);
  assert.notEqual(await bookIdentity(w.recorder.keys, firstLineOf(truth)), await bookIdentity(w.recorder.keys, firstLineOf(third)));
  assert.equal(await bookIdentity(w.recorder.keys, firstLineOf(truth)), await bookIdentity(w.recorder.keys, firstLineOf(forged)));
});

test('a first line given with its line feed, or holding more than the slip, gets words of its own', async () => {
  const { w, one, by, seal } = await setting();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const text = w.book();
  const s1 = await seal(text);
  const withFeed = utf8(text.split('\n')[0] + '\n');
  const r = await witness.witness({ seal: s1.record }, await witnessProof(text, 3, null), withFeed);
  assert.equal(r.refused.code, 'bad-field');
  assert.match(r.refused.message, /without its line feed/);
  // An entry that holds the slip and something more is not a permission.
  const more = writeBook([{ ...w.entries[0], note: 'x' }, w.entries[1]]);
  const s2 = await seal(more);
  const r2 = await ask(witness, more, s2);
  assert.equal(r2.refused.code, 'slip-missing');
  assert.match(r2.refused.message, /holds only a slip/);
});

test('a Show without page 0, whose first page is a later permission, is not witnessed; nor is a book whose first permission did not pass', async () => {
  const { w, one, by, seal, slip2, x1 } = await renewal();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const text = writeBook([w.entries[0], { slip: slip2 }, x1.entry]);
  const s = await seal(text);
  const r = await ask(witness, text, s);
  const book = text + entryLine({ seal: s.record, witnesses: [r.statement] }) + '\n';
  const trust = { issuerKeys: [await thumbprint(w.passkey.key)], sealKeys: [await keySetFingerprint(w.recorder.keys)], witnesses: [await keySetFingerprint(one.keys)] };
  assert.deepEqual((await checkBook(book, trust)).summary.witnessed?.seals, [3]);
  // A Show counts a statement only where its pages hold every entry the seal covers.
  assert.deepEqual((await checkShow(await makeShow(book, [0, 1, 2, 3]), trust)).summary.witnessed?.seals, [3]);
  const gap = await checkShow(await makeShow(book, [0, 3]), trust);
  assert.equal(gap.summary.witnessed, null);
  assert.ok(gap.entries.find((e) => e.kind === 'seal').notes.some((n) => n.includes('the pages do not hold every entry this seal covers')));
  // Pages 1 (the renewed permission, sound and signed by the named passkey) and the seal: the start is not shown.
  const without0 = await checkShow(await makeShow(book, [1, 3]), trust);
  assert.equal(without0.summary.witnessed, null);
  assert.equal(without0.entries.find((e) => e.kind === 'seal').witnesses[0].counted, false);
  // Another passkey named: the first permission does not pass here, and no statement counts.
  const other = await checkBook(book, { ...trust, issuerKeys: [await thumbprint((await makeWorld()).passkey.key)] });
  assert.equal(other.entries[3].witnesses[0].counted, false);
});

test("a book cut short and sealed again under another book number does not hide the cut from a seal held elsewhere (the review's probe)", async () => {
  const { w, seal } = await setting();
  await w.add({ value: 10 });
  const t4 = w.book();
  const s1 = await seal(t4, { when: START + 5 * 3600 * 1000 });
  w.entries.push({ seal: s1.record });
  await w.add({ value: 150 });
  await w.add({ value: 10 });
  const t7 = w.book();
  const s1b = await seal(t7, { previous: s1.fingerprint, when: START + 9 * 3600 * 1000 });
  const trust = { issuerKeys: [await thumbprint(w.passkey.key)], sealKeys: [await keySetFingerprint(w.recorder.keys)] };
  const held = { seals: [{ seal: s1b.record }] };
  // The cut is seen where the book keeps its number.
  const cut = t4 + entryLine({ seal: s1.record }) + '\n';
  assert.deepEqual((await checkBook(cut, { ...trust, ...held })).problems.map((p) => p.code), ['book-cut-short']);
  const dir = tempFolder();
  const heldFile = join(dir, 'held.json');
  writeFileSync(heldFile, JSON.stringify({ seal: s1b.record }));
  const cli = fileURLToPath(new URL('../bin/provared-check.mjs', import.meta.url));
  for (const previous of [s1.fingerprint.replace(/^./, (c) => (c === 'Q' ? 'R' : 'Q')), s1b.fingerprint, s1.fingerprint]) {
    const relabel = await seal(t4, { book: 2, previous, when: START + 10 * 3600 * 1000 });
    const text = t4 + entryLine({ seal: relabel.record }) + '\n';
    const r = await checkBook(text, { ...trust, ...held });
    assert.equal(r.held[0].used, false);
    assert.equal(r.held[0].inBook, null);
    // The record itself is intact; the page still gives no green answer, because the seal held was not compared.
    assert.equal(r.summary.intact, true);
    assert.equal(trustOf(r, { ...trust, ...held }).sure, false);
    assert.ok(r.held[0].notes.some((n) => n.includes('does not show whether book 1 was cut short') && n.includes('gives no pass')), JSON.stringify(r.held[0].notes));
    const file = join(dir, 'relabelled.jsonl');
    writeFileSync(file, text);
    const run = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', cli, file, '--issuer', trust.issuerKeys[0], '--sealer', trust.sealKeys[0], '--seal', heldFile], { encoding: 'utf8' });
    assert.equal(run.status, 1, run.stdout);
    assert.match(run.stdout, /Seals held elsewhere compared\? +NO: 1 of 1 handed over were not compared with the book/);
  }
  // The other way: the reader holds a seal that gives a later book number than the book handed over.
  const later = await seal(t7, { book: 3, previous: s1.fingerprint, when: START + 9 * 3600 * 1000 });
  const r = await checkBook(cut, { ...trust, seals: [{ seal: later.record }] });
  assert.equal(r.held[0].used, false);
  assert.ok(r.held[0].notes.some((n) => n.includes('a later book than this one')));
});

// One passkey, two agents, one recorder (as the gateway keeps them): a permission for each agent.
async function twoAgents() {
  const s = await setting();
  const { w } = s;
  const agentY = await generateKeySet();
  const preparedY = await prepareSlip({ ...w.fields, agent: { name: 'Agent Y (invented)', keys: agentY.keys } });
  const slipY = assembleSlip(preparedY, await w.passkey.sign(preparedY.challenge));
  const fpY = await fingerprint(fromBase64url(slipY.payload));
  const stubY = await writeStub({ slip: fpY, action: 'supplies.order', amount: { unit: 'GBP', value: 5 }, with: 'supplier', after: null, when: START + 3600 * 1000 }, agentY.privateKeys);
  const entryY = { stub: stubY.record, countersignature: await countersign(stubY.record, w.service.privateKeys, START + 3600 * 1000 + 60000) };
  return { ...s, slipY, entryY };
}

test("a fork through a second agent of the same person under the same recorder is not witnessed (the review's probe 5)", async () => {
  const { w, one, by, seal, slipY } = await twoAgents();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const trust = { issuerKeys: [await thumbprint(w.passkey.key)], sealKeys: [await keySetFingerprint(w.recorder.keys)], witnesses: [await keySetFingerprint(one.keys)] };
  // X's true book: its permission and two stubs, witnessed.
  const truth = w.book();
  const sT = await seal(truth);
  const rT = await ask(witness, truth, sT);
  assert.deepEqual((await checkBook(truth + entryLine({ seal: sT.record, witnesses: [rT.statement] }) + '\n', trust)).summary.witnessed?.seals, [3]);
  // A second book that starts with Y's permission, then X's permission and X's first stub only: the witness signs
  // it (the first book of the same person and agent Y, which it cannot tell from an honest one).
  const forged = writeBook([{ slip: slipY }, w.entries[0], w.entries[1]]);
  const sF = await seal(forged);
  const rF = await ask(witness, forged, sF);
  assert.ok(rF.statement);
  const forgedBook = forged + entryLine({ seal: sF.record, witnesses: [rF.statement] }) + '\n';
  const r = await checkBook(forgedBook, trust);
  assert.equal(r.summary.witnessed, null);
  assert.equal(r.entries[3].witnesses[0].counted, false);
  assert.ok(r.entries[3].notes.some((n) => n.includes('hold a permission from another passkey, or for another agent')));
  // Nor does a Show of its first page and the seal count.
  assert.equal((await checkShow(await makeShow(forgedBook, [0, 3]), trust)).summary.witnessed, null);
  assert.equal((await checkShow(await makeShow(forgedBook, [0, 1, 2, 3]), trust)).summary.witnessed, null);
  // A permission from a second passkey for X, at the start of a book that also holds X's first permission.
  const second = await makeWorld({ fields: { requires: [] }, agent: w.agent, service: w.service });
  const mixed = writeBook([second.entries[0], w.entries[0], w.entries[1]]);
  const sM = await seal(mixed);
  const rM = await ask(witness, mixed, sM);
  const both = { ...trust, issuerKeys: [...trust.issuerKeys, await thumbprint(second.passkey.key)] };
  const rMixed = await checkBook(mixed + entryLine({ seal: sM.record, witnesses: [rM.statement] }) + '\n', both);
  assert.equal(rMixed.summary.witnessed, null);
});

test('honest books are still witnessed: each agent its own book under one recorder (as the gateway keeps them), and a renewal by the same person', async () => {
  const { w, one, by, seal, slipY, entryY } = await twoAgents();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const trust = { issuerKeys: [await thumbprint(w.passkey.key)], sealKeys: [await keySetFingerprint(w.recorder.keys)], witnesses: [await keySetFingerprint(one.keys)] };
  for (const text of [w.book(), writeBook([{ slip: slipY }, entryY])]) {
    const s = await seal(text);
    const r = await ask(witness, text, s);
    assert.ok(r.statement);
    const size = text.split('\n').filter(Boolean).length;
    assert.deepEqual((await checkBook(text + entryLine({ seal: s.record, witnesses: [r.statement] }) + '\n', trust)).summary.witnessed?.seals, [size]);
  }
  assert.equal(witness.state().books.length, 2);
  // A renewal by the same person for the same agent, inside the book.
  const { w: w2, one: one2, by: by2, seal: seal2, slip2, x1 } = await renewal();
  const witness2 = await openWitness({ by: by2, signers: one2.privateKeys, clock: () => NOW });
  const text = writeBook([w2.entries[0], { slip: slip2 }, x1.entry]);
  const s = await seal2(text);
  const r = await ask(witness2, text, s);
  const trust2 = { issuerKeys: [await thumbprint(w2.passkey.key)], sealKeys: [await keySetFingerprint(w2.recorder.keys)], witnesses: [await keySetFingerprint(one2.keys)] };
  assert.deepEqual((await checkBook(text + entryLine({ seal: s.record, witnesses: [r.statement] }) + '\n', trust2)).summary.witnessed?.seals, [3]);
});

test('a permission on the first line that does not name a passkey key or an agent key set in a slip\'s forms is refused by the witness', async () => {
  const { w, one, by, seal } = await setting();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const real = JSON.parse(Buffer.from(w.entries[0].slip.payload, 'base64url').toString());
  for (const change of [{ issuer: { ...real.issuer, key: { kty: 'EC' } } }, { agent: { ...real.agent, keys: [real.agent.keys[0]] } }]) {
    const { payloadB64 } = encodeContent({ ...real, ...change });
    const record = { payload: payloadB64, signatures: [{ ...w.entries[0].slip.signatures[0] }] };
    const text = writeBook([{ slip: record }, w.entries[1]]);
    const s = await seal(text);
    const r = await ask(witness, text, s);
    assert.equal(r.refused.code, 'slip-unusable', JSON.stringify(change));
  }
});

test("a seal that covers only the first agent's permission counts, and a later seal that covers another agent's does not (the review's probe 6, case a)", async () => {
  const { w, one, by, seal, slipY } = await twoAgents();
  const witness = await openWitness({ by, signers: one.privateKeys, clock: () => NOW });
  const trust = { issuerKeys: [await thumbprint(w.passkey.key)], sealKeys: [await keySetFingerprint(w.recorder.keys)], witnesses: [await keySetFingerprint(one.keys)] };
  const yOnly = writeBook([{ slip: slipY }]);
  const s1 = await seal(yOnly, { when: START });
  const r1 = await ask(witness, yOnly, s1);
  const text = yOnly + entryLine({ seal: s1.record, witnesses: [r1.statement] }) + '\n' + writeBook([w.entries[0], w.entries[1], w.entries[2]]);
  const s2 = await seal(text, { previous: s1.fingerprint, when: START + 5 * 3600 * 1000 });
  const r2 = await witness.witness({ seal: s2.record }, await witnessProof(text, 5, 1), firstLineOf(yOnly));
  assert.ok(r1.statement && r2.statement);
  const book = text + entryLine({ seal: s2.record, witnesses: [r2.statement] }) + '\n';
  const r = await checkBook(book, trust);
  assert.equal(r.entries[1].witnesses[0].counted, true);
  assert.equal(r.entries[5].witnesses[0].counted, false);
  assert.deepEqual(r.summary.witnessed?.seals, [1]);
  // A Show of the first two pages counts the first seal, and says what single pages cannot show.
  const show = await checkShow(await makeShow(book, [0, 1]), trust);
  assert.deepEqual(show.summary.witnessed?.seals, [1]);
  assert.match(show.summary.limits.at(-1), /single pages of a book: they cannot show that a limit over the whole book was kept/);
  // The whole book's answer does not carry that sentence.
  assert.doesNotMatch(r.summary.limits.at(-1), /single pages/);
});
