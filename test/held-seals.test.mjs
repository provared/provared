// Seals held elsewhere, handed over beside the book (format description,
// section 21.5): the end of a book cut off after a seal someone else holds
// is shown; so is a book that holds another line where the seal stands.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { tempFolder } from './helpers/temp.mjs';

import { checkBefore, checkBook, checkShow, entryLine, fromBase64url, keySetFingerprint, makeShow, openChecker, openRecorder, thumbprint, toBase64url, writeBook, writeSeal } from '../src/index.js';
import { readHanded, trustOf } from '../page/render.js';
import { MAX_HELD_SEALS } from '../src/book.js';
import { START, makeWorld } from './helpers/world.mjs';

const SLH = 'SLH-DSA-SHA2-256s';

// A book of a slip, two stubs, a seal, a stub, a seal and a stub; the second seal is the one held elsewhere.
let made;
async function world() {
  made ??= (async () => {
    const w = await makeWorld({ fields: { requires: [] } });
    await w.add({ value: 10 });
    await w.add({ value: 10 });
    const first = await w.seal();
    await w.add({ value: 10 });
    const second = await w.seal();
    await w.add({ value: 10 });
    const trust = {
      issuerKeys: [await thumbprint(w.passkey.key)],
      sealKeys: [await keySetFingerprint(w.recorder.keys)],
      stampServices: [w.stampService.fingerprint],
    };
    const lines = w.book().split('\n').filter(Boolean);
    return { w, first, second, trust, lines, text: w.book() };
  })();
  return made;
}
const book = (lines) => lines.join('\n') + '\n';
const codes = (r) => r.problems.map((p) => p.code);
const copy = (value) => JSON.parse(JSON.stringify(value));

test('a seal held elsewhere that the book holds at its place: nothing else changes', async () => {
  const { second, trust, text } = await world();
  const without = await checkBook(text, trust);
  const r = await checkBook(text, { ...trust, seals: [second.entry] });
  assert.deepEqual(r.problems, []);
  assert.equal(r.summary.intact, true);
  assert.deepEqual(r.entries, without.entries);
  assert.deepEqual(r.summary, without.summary);
  assert.equal(r.held.length, 1);
  const h = r.held[0];
  assert.equal(h.kind, 'seal');
  assert.equal(h.used, true);
  assert.equal(h.place, 5);
  assert.equal(h.inBook, 5);
  assert.equal(h.fingerprint, second.fingerprint);
  assert.equal(h.sealer, trust.sealKeys[0]);
  assert.deepEqual(h.notes, []);
  assert.equal(h.stamps.length, 1);
  assert.equal(h.stamps[0].state, 'valid');
  assert.ok(h.stampedAt);
});

test('book-cut-short: the end of the book cut off after the seal held elsewhere, with the seal', async () => {
  const { second, trust, lines } = await world();
  // Cut back to the first seal: what is left checks as a book by itself.
  const cut = book(lines.slice(0, 4));
  assert.equal((await checkBook(cut, trust)).summary.intact, true);
  const r = await checkBook(cut, { ...trust, seals: [second.entry] });
  assert.deepEqual(codes(r), ['book-cut-short']);
  assert.match(r.problems[0].message, /^Seal 1 of those handed over beside the book stands at entry 5, but the book ends at entry 3\./);
  assert.equal(r.summary.problemFound, true);
  assert.equal(r.summary.intact, false);
  assert.equal(r.held[0].used, true);
  assert.equal(r.held[0].inBook, null);
  // Cut back to exactly the entries the seal covers, without the seal itself.
  const atEdge = await checkBook(book(lines.slice(0, 5)), { ...trust, seals: [second.entry] });
  assert.deepEqual(codes(atEdge), ['book-cut-short']);
});

test('seal-not-in-book: another seal in the place of the one held elsewhere', async () => {
  const { w, first, second, trust, lines } = await world();
  // The recorder seals the same entries again, with another date, and puts that seal in the place of the one held elsewhere.
  const again = await writeSeal(book(lines.slice(0, 5)), { by: { keys: w.recorder.keys, name: 'Example recorder (invented)' }, previous: first.fingerprint, when: second.when + 1000 }, w.recorder.privateKeys);
  const swapped = book([...lines.slice(0, 5), entryLine({ seal: again.record }), lines[6]]);
  assert.equal((await checkBook(swapped, trust)).problems.length, 0);
  assert.equal((await checkBook(swapped, trust)).entries.every((e) => e.problems.length === 0), true);
  const r = await checkBook(swapped, { ...trust, seals: [second.entry] });
  assert.deepEqual(codes(r), ['seal-not-in-book']);
  assert.match(r.problems[0].message, /stands at entry 5, but the book holds another line there/);
  // A stub in the place of the seal.
  const stubThere = await checkBook(book([...lines.slice(0, 5), lines[6]]), { ...trust, seals: [second.entry] });
  assert.deepEqual(codes(stubThere), ['seal-not-in-book']);
});

const SIGNED_AGAIN = 'The book holds this seal at entry 5 with the same content, but with other signatures than this copy. The same content fixes the same entries, so this is not a fault of the book. Only someone who holds the recorder\'s keys can sign a seal again.';

test('the same seal content signed again is the same seal: said, and not a fault of the book', async () => {
  const { w, second, trust, lines } = await world();
  const content = JSON.parse(Buffer.from(second.record.payload, 'base64url').toString());
  const resigned = await writeSeal(book(lines.slice(0, 5)), { id: content.id, by: content.by, previous: content.previous, when: Date.parse(content.when) }, w.recorder.privateKeys);
  assert.equal(resigned.fingerprint, second.fingerprint);
  assert.notEqual(resigned.record.signatures[1].signature, second.record.signatures[1].signature);
  const signedAgain = book([...lines.slice(0, 5), entryLine({ ...second.entry, seal: resigned.record }), lines[6]]);
  assert.equal((await checkBook(signedAgain, trust)).summary.intact, true);
  const r = await checkBook(signedAgain, { ...trust, seals: [second.entry] });
  assert.deepEqual(codes(r), []);
  assert.equal(r.held[0].inBook, 5);
  assert.deepEqual(r.held[0].notes, [SIGNED_AGAIN]);
});

test('a copy whose third signature was changed: the copy\'s fault where the device checks it, never the book\'s where it cannot', async () => {
  const { second, trust, text } = await world();
  const changed = copy(second.entry);
  const sig = fromBase64url(changed.seal.signatures[2].signature);
  sig[100] ^= 1;
  changed.seal.signatures[2].signature = toBase64url(sig);
  // With SLH-DSA: the copy does not pass its own check.
  const full = await checkBook(text, { ...trust, seals: [changed] });
  assert.deepEqual(codes(full), ['signature-invalid']);
  // Without it: the copy counts on its first two signatures, and the book holds the same seal.
  const part = await checkBook(text, { ...trust, seals: [changed], withoutMethods: [SLH] });
  assert.deepEqual(codes(part), []);
  assert.equal(part.held[0].used, true);
  assert.equal(part.held[0].inBook, 5);
  assert.ok(part.held[0].notes.includes(SIGNED_AGAIN));
});

test('a seal held elsewhere does not count on one of its first two signatures alone', async () => {
  const { second, trust, lines } = await world();
  const cut = book(lines.slice(0, 4));
  for (const lacking of ['Ed25519', 'ML-DSA-87']) {
    const r = await checkBook(cut, { ...trust, seals: [second.entry], withoutMethods: [lacking, SLH] });
    assert.deepEqual(codes(r), [], lacking);
    assert.equal(r.held[0].used, false, lacking);
  }
});

test('the check before acting excuses only the third signature of a held seal whose first two it checked', async () => {
  // A book of a permission alone, signed by a passkey: nothing in it needs Ed25519 or ML-DSA-87. Only the seal handed over does.
  const { first } = await world();
  const lone = await makeWorld({ fields: { requires: [] } });
  const issuerKeys = [await thumbprint(lone.passkey.key)];
  const proposal = { slip: lone.slipFingerprint, action: 'supplies.order', amount: { unit: 'GBP', value: 1 }, with: 'supplier', when: START + 3600 * 1000 };
  const allowed = await checkBefore(lone.book(), proposal, { issuerKeys, seals: [first.entry], withoutMethods: [SLH] });
  assert.equal(allowed.allowed, true);
  assert.deepEqual(allowed.notChecked, [SLH]);
  for (const lacking of ['Ed25519', 'ML-DSA-87']) {
    const refused = await checkBefore(lone.book(), proposal, { issuerKeys, seals: [first.entry], withoutMethods: [lacking, SLH] });
    assert.equal(refused.allowed, false, lacking);
    assert.deepEqual(refused.problems.map((p) => p.code), ['record-not-sound'], lacking);
  }
});

test('a checker that is carried on checks the seals handed over once, not at every answer', async () => {
  const { first, second, trust, text } = await world();
  const carried = await openChecker(text, { ...trust, seals: [first.entry, second.entry] });
  const once = await carried.result();
  const subtle = globalThis.crypto.subtle;
  const verify = subtle.verify;
  let calls = 0;
  subtle.verify = function (...args) {
    calls++;
    return verify.apply(this, args);
  };
  try {
    assert.deepEqual(await carried.result(), once);
    assert.equal(calls, 0);
  } finally {
    delete subtle.verify;
  }
  assert.equal(subtle.verify, verify);
});

test('a seal held elsewhere from a recorder not named is not used; one from a recorder other than those named fails its check', async () => {
  const { second, trust, lines } = await world();
  const cut = book(lines.slice(0, 4));
  const { sealKeys: _, ...unnamed } = trust;
  const r = await checkBook(cut, { ...unnamed, seals: [second.entry] });
  assert.deepEqual(codes(r), []);
  assert.equal(r.held[0].used, false);
  assert.ok(r.held[0].notes.some((n) => n.startsWith('It was not used: a seal handed over beside the book counts only where you named its recorder')));
  // From another recorder.
  const other = await makeWorld({ fields: { requires: [] } });
  await other.add({ value: 1 });
  const elsewhere = await other.seal();
  const r2 = await checkBook(cut, { ...trust, seals: [elsewhere.entry] });
  assert.deepEqual(codes(r2), ['sealer-not-expected']);
  assert.match(r2.problems[0].message, /^Seal 1 of those handed over beside the book did not pass its check, so it was not used\./);
  assert.equal(r2.held[0].used, false);
});

test('a seal held elsewhere that fails its own check is a problem with the whole check', async () => {
  const { second, trust, text } = await world();
  const changed = copy(second.entry);
  const sig = fromBase64url(changed.seal.signatures[0].signature);
  sig[3] ^= 1;
  changed.seal.signatures[0].signature = toBase64url(sig);
  const r = await checkBook(text, { ...trust, seals: [changed] });
  assert.deepEqual(codes(r), ['signature-invalid']);
  assert.equal(r.held[0].used, false);
  const badStamp = await checkBook(text, { ...trust, seals: [{ ...second.entry, stamps: ['AAAA'] }] });
  assert.deepEqual(codes(badStamp), ['stamp-bad-data']);
});

test('what is handed over must be a list of seal entries: at most 64, none twice; an empty list is none', async () => {
  const { second, trust, text } = await world();
  const plain = await checkBook(text, trust);
  assert.deepEqual(await checkBook(text, { ...trust, seals: [] }), plain);
  const many = await checkBook(text, { ...trust, seals: Array(MAX_HELD_SEALS + 1).fill(second.entry) });
  assert.deepEqual(codes(many), ['bad-field']);
  assert.equal(many.problems[0].message, 'seals: must be a list of 0 to 64 items.');
  assert.deepEqual(codes(await checkBook(text, { ...trust, seals: 'x' })), ['bad-field']);
  const twice = await checkBook(text, { ...trust, seals: [second.entry, second.entry] });
  assert.deepEqual(codes(twice), ['bad-field']);
  assert.match(twice.problems[0].message, /^Seal 2 of those handed over beside the book did not pass its check, so it was not used\. seals\[1\]: the same seal is handed over twice\.$/);
  assert.deepEqual(codes(await checkBook(text, { ...trust, seals: [5] })), ['bad-field']);
  assert.deepEqual(codes(await checkBook(text, { ...trust, seals: [{ ...second.entry, note: 'x' }] })), ['bad-field']);
  assert.deepEqual(codes(await checkBook(text, { ...trust, seals: [{ stub: second.entry.seal }] })), ['bad-field']);
  // A slip handed over as a seal.
  assert.deepEqual(codes(await checkBook(text, { ...trust, seals: [{ seal: JSON.parse(text.split('\n')[0]).slip }] })), ['bad-envelope']);
});

test('a copy with other time-stamps than the book: said, and its own are not used for the book', async () => {
  const { second, trust, text } = await world();
  const bare = { seal: second.entry.seal };
  const r = await checkBook(text, { ...trust, seals: [bare] });
  assert.deepEqual(codes(r), []);
  assert.equal(r.held[0].inBook, 5);
  assert.ok(r.held[0].notes.some((n) => n.startsWith('The book holds this seal at entry 5, with other time-stamps beside it than this copy.')));
  assert.deepEqual(r.entries, (await checkBook(text, trust)).entries);
});

test('the book holds the seal at its place, but an entry before it was changed: the book fails, and the copy says so', async () => {
  const { second, trust, lines } = await world();
  const changed = book([lines[0], lines[1], lines[2], lines[3], lines[2], lines[5], lines[6]]);
  const r = await checkBook(changed, { ...trust, seals: [second.entry] });
  assert.ok(r.entries[5].problems.some((p) => p.code === 'seal-mismatch'));
  assert.equal(r.held[0].inBook, 5);
  assert.ok(r.held[0].notes.includes('The book holds this seal at entry 5, but that entry did not pass its check.'));
});

test('on a device without SLH-DSA a seal held elsewhere is used on its first two signatures; without ML-DSA-87 it is not', async () => {
  const { second, trust, lines } = await world();
  const cut = book(lines.slice(0, 4));
  const r = await checkBook(cut, { ...trust, seals: [second.entry], withoutMethods: [SLH] });
  assert.deepEqual(codes(r), ['book-cut-short']);
  assert.ok(r.held[0].notes.includes(`This device could not check its third signature (${SLH}). It was used on the strength of its Ed25519 and ML-DSA-87 signatures, which were checked here.`));
  const r2 = await checkBook(cut, { ...trust, seals: [second.entry], withoutMethods: ['ML-DSA-87'] });
  assert.deepEqual(codes(r2), []);
  assert.equal(r2.held[0].used, false);
  assert.equal(r2.summary.fullyChecked, false);
  assert.ok(r2.summary.methodsMissing.includes('ML-DSA-87'));
});

test('a Show does not use seals held elsewhere, and says so; an empty list says nothing', async () => {
  const { second, trust, text } = await world();
  const show = await makeShow(text, [0, 1]);
  const r = await checkShow(show, { ...trust, seals: [second.entry] });
  assert.ok(r.notes.some((n) => n.startsWith('Seals held elsewhere were handed over beside this Show. They were not used')));
  assert.deepEqual(r.held, []);
  assert.deepEqual(await checkShow(show, { ...trust, seals: [] }), await checkShow(show, trust));
});

test('a checker that is carried on gives the whole check\'s answer with seals held elsewhere, after every line', async () => {
  const { second, trust, lines } = await world();
  const options = { ...trust, seals: [second.entry] };
  const carried = await openChecker('', options);
  for (let i = 0; i < lines.length; i++) {
    await carried.add(lines[i] + '\n');
    assert.deepEqual(await carried.result(), await checkBook(book(lines.slice(0, i + 1)), options), `after line ${i}`);
  }
});

test('the check before acting allows nothing where a seal held elsewhere shows the book cut short', async () => {
  const { w, second, trust, lines, text } = await world();
  const proposal = { slip: w.slipFingerprint, action: 'supplies.order', amount: { unit: 'GBP', value: 1 }, with: 'supplier', when: START + 6 * 3600 * 1000 };
  const sound = await checkBefore(text, proposal, { ...trust, seals: [second.entry] });
  assert.equal(sound.allowed, true);
  const cut = await checkBefore(book(lines.slice(0, 4)), proposal, { ...trust, seals: [second.entry] });
  assert.equal(cut.allowed, false);
  assert.deepEqual(cut.problems.map((p) => p.code), ['record-not-sound']);
  // On a device without SLH-DSA the check goes on and says so, as for a seal in the book.
  const without = await checkBefore(text, proposal, { ...trust, seals: [second.entry], withoutMethods: [SLH] });
  assert.equal(without.allowed, true);
  assert.deepEqual(without.notChecked, [SLH]);
});

test('the stub writer takes seals held elsewhere with its options, and refuses a book cut short', async () => {
  const { w, second, trust, lines, text } = await world();
  const clock = START + 6 * 3600 * 1000;
  const open = (b) => openRecorder({ book: b, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys: trust.issuerKeys, now: () => clock, options: { sealKeys: trust.sealKeys, stampServices: trust.stampServices, seals: [second.entry] } });
  const writer = await open(text);
  const answer = await writer.check();
  assert.equal(answer.held[0].used, true);
  assert.equal(answer.held[0].inBook, 5);
  assert.deepEqual(writer.cancellations(), []);
  await assert.rejects(open(book(lines.slice(0, 4))), /A problem was found in the record so far/);
});

test('a seal held elsewhere does not count against a book that holds it with its own place wrong', async () => {
  // The place is the one the seal states (its size), whatever order it is handed over in.
  const { first, second, trust, text } = await world();
  const r = await checkBook(text, { ...trust, seals: [second.entry, first.entry] });
  assert.deepEqual(codes(r), []);
  assert.deepEqual(r.held.map((h) => [h.place, h.inBook]), [[5, 5], [3, 3]]);
});

test('seals held elsewhere come after the cancellations handed over, and are numbered among themselves', async () => {
  const { second, trust, text } = await world();
  const other = await makeWorld({ fields: { requires: [] } });
  await other.add({ value: 1 });
  const elsewhere = await other.seal();
  const r = await checkBook(text, { ...trust, cancellations: [], seals: [second.entry, elsewhere.entry] });
  assert.deepEqual(r.held.map((h) => h.kind), ['seal', 'seal']);
  assert.match(r.problems[0].message, /^Seal 2 of those handed over/);
  void writeBook;
});

test('the command-line checker takes seals held elsewhere with --seal', async () => {
  const { second, trust, lines, text } = await world();
  const dir = tempFolder('provared-');
  const whole = join(dir, 'book.jsonl');
  const cut = join(dir, 'cut.jsonl');
  const held = join(dir, 'seal.json');
  writeFileSync(whole, text);
  writeFileSync(cut, book(lines.slice(0, 4)));
  writeFileSync(held, JSON.stringify(second.entry));
  const cli = join(fileURLToPath(new URL('..', import.meta.url)), 'bin', 'provared-check.mjs');
  const named = ['--issuer', trust.issuerKeys[0], '--sealer', trust.sealKeys[0], '--stamp-service', trust.stampServices[0]];
  const run = (file, ...more) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', cli, file, ...named, ...more], { encoding: 'utf8' });
  const sound = run(whole, '--seal', held);
  assert.equal(sound.status, 0);
  assert.match(sound.stdout, /Handed over beside the book, 1: SEAL HELD ELSEWHERE/);
  assert.match(sound.stdout, /In the book at that place: yes, at entry 5/);
  assert.equal(run(cut).status, 0);
  const short = run(cut, '--seal', held);
  assert.equal(short.status, 2);
  assert.match(short.stdout, /PROBLEM \[book-cut-short\]/);
  assert.match(short.stdout, /In the book at that place: NO/);
  assert.equal(run(whole, '--seal', join(dir, 'missing.json')).status, 2);
  assert.match(run(whole, '--help').stdout, /--seal +a JSON file of a seal held elsewhere/);
  assert.match(sound.stdout, /Seals held elsewhere compared\? +yes/);
  // No recorder named, and a book with no seal of its own: no pass, and a line says why.
  const unsealed = join(dir, 'unsealed.jsonl');
  writeFileSync(unsealed, book(lines.slice(0, 3)));
  const bare = (...more) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', cli, unsealed, '--issuer', trust.issuerKeys[0], ...more], { encoding: 'utf8' });
  assert.equal(bare().status, 0);
  const unnamed = bare('--seal', held);
  assert.equal(unnamed.status, 1);
  assert.match(unnamed.stdout, /Seals held elsewhere compared\? +NO: you named no recorder you expect \(--sealer\), so the seals handed over were not compared with the book\. This is not a pass\./);
  assert.match(unnamed.stdout, /Checked against keys you named\? +NO: you named the passkey you trust, but no recorder you expect \(--sealer\) for the seals handed over beside the book\. This is not a pass\./);
});

test('the stub writer keeps the book\'s seals, for a seal held elsewhere, when another party\'s entry joins its book', async () => {
  const { w, first, trust, lines } = await world();
  // A book up to the first seal, and one stub after it; the first seal is held elsewhere.
  const start = book(lines.slice(0, 5));
  const clock = START + 6 * 3600 * 1000;
  const writer = await openRecorder({ book: start, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys: trust.issuerKeys, now: () => clock, options: { sealKeys: trust.sealKeys, seals: [first.entry] } });
  // The recorder seals the book as it stands, and the seal joins the writer's book.
  const sealed = await writeSeal(start, { by: { keys: w.recorder.keys, name: 'Example recorder (invented)' }, previous: first.fingerprint, when: clock - 60000 }, w.recorder.privateKeys);
  await writer.add({ seal: sealed.record });
  const answer = await writer.check();
  assert.deepEqual(answer.problems, []);
  assert.deepEqual(answer.held.map((h) => [h.used, h.inBook]), [[true, 3]]);
  assert.deepEqual(answer, await checkBook(writer.book(), { issuerKeys: trust.issuerKeys, sealKeys: trust.sealKeys, seals: [first.entry] }));
});

test('a seal held elsewhere whose signatures this device cannot all check leaves the record not fully checked, even where it is not used', async () => {
  const { first, trust, lines } = await world();
  const { sealKeys: _, ...unnamed } = trust;
  // A book of the slip and its first two stubs, with no seal in it; the seal handed over is not used, its recorder not being named.
  const r = await checkBook(book(lines.slice(0, 3)), { ...unnamed, seals: [first.entry], withoutMethods: [SLH] });
  assert.deepEqual(r.problems, []);
  assert.equal(r.held[0].used, false);
  assert.equal(r.summary.fullyChecked, false);
  assert.deepEqual(r.summary.methodsMissing, [SLH]);
});

// The checking page: what it reads from the files chosen in its panel "What you were handed with the record", and when its answer is a pass.
const fileOf = (name, value) => ({ name, size: JSON.stringify(value).length, text: async () => JSON.stringify(value) });

test('the checking page hands over the seals chosen, at most 64, and says so', async () => {
  const { first, second } = await world();
  const { options, said } = await readHanded({ seals: [fileOf('a.json', first.entry), fileOf('b.json', second.entry)] });
  assert.deepEqual(options, { seals: [first.entry, second.entry] });
  assert.deepEqual(said, ['2 seals held elsewhere']);
  assert.deepEqual((await readHanded({ seals: [fileOf('a.json', first.entry)] })).said, ['one seal held elsewhere']);
  await assert.rejects(readHanded({ seals: Array(65).fill(fileOf('a.json', 5)) }), /At most 64 seals held elsewhere/);
  assert.equal((await readHanded({ seals: Array(64).fill(fileOf('a.json', 5)) })).options.seals.length, 64);
  await assert.rejects(readHanded({ seals: [{ name: 'x.json', size: 3, text: async () => 'not' }] }), /The file of a seal, x\.json, is not JSON/);
  assert.deepEqual(await readHanded({}), { options: {}, said: [] });
});

test('seals handed over with no recorder named: no pass on the page or the command line, and a plain line says why', async () => {
  const { second, trust, lines } = await world();
  const cut = book(lines.slice(0, 4));
  const { sealKeys: _, ...unnamed } = trust;
  // A book with no seal of its own: the first three entries.
  const short = book(lines.slice(0, 3));
  const r = await checkBook(short, { ...unnamed, seals: [second.entry] });
  assert.equal(r.summary.intact, true);
  assert.deepEqual(trustOf(r, { ...unnamed, seals: [second.entry] }), { issuerNamed: true, named: false, sure: false, heldUnused: true });
  assert.deepEqual(trustOf(r, unnamed), { issuerNamed: true, named: true, sure: true, heldUnused: false });
  assert.equal(trustOf(r, { ...trust, seals: [second.entry] }).heldUnused, false);
  void cut;
});

// A stand-in for the browser's document, enough for the page to write into (as test/review4.test.mjs does).
class Element {
  constructor() {
    this.children = [];
    this.textContent = '';
    this.className = '';
  }
  append(...nodes) {
    this.children.push(...nodes);
  }
  replaceChildren() {
    this.children = [];
  }
  words(out = []) {
    if (this.textContent) out.push(this.textContent);
    for (const c of this.children) c.words(out);
    return out;
  }
}

test('the checking page shows each seal handed over, and says when they were not compared', async () => {
  globalThis.document ??= { createElement: () => new Element() };
  const { renderResult } = await import('../page/render.js');
  const { second, trust, lines } = await world();
  const words = (result, options) => {
    const target = new Element();
    renderResult(target, result, { options });
    return target.words().join('\n');
  };
  const cut = book(lines.slice(0, 4));
  const shown = words(await checkBook(cut, { ...trust, seals: [second.entry] }), { ...trust, seals: [second.entry] });
  assert.match(shown, /Handed over beside the book, 1: a seal of the book held elsewhere/);
  assert.match(shown, /In the book at that place\nno/);
  assert.match(shown, /book-cut-short/);
  const { sealKeys: _, ...unnamed } = trust;
  const short = book(lines.slice(0, 3));
  const options = { ...unnamed, seals: [second.entry] };
  const unused = words(await checkBook(short, options), options);
  assert.match(unused, /The seals held elsewhere that you handed over were not compared with the book, because you named no recorder you expect/);
  assert.match(unused, /You were handed seals held elsewhere, and you named no recorder you expect, so those seals were not compared with the book/);
  assert.doesNotMatch(unused, /The record is intact\./);
  assert.match(words(await checkBook(short, unnamed), unnamed), /The record is intact\./);
});

test('answers asked for again, on a device without SLH-DSA, are each the whole check\'s answer', async () => {
  const { w, first, second, trust, lines, text } = await world();
  // Seals that leave notes on their items: one with other time-stamps than the book, one whose third signature this device cannot check.
  const options = { ...trust, seals: [{ seal: second.entry.seal }, first.entry], withoutMethods: [SLH] };
  const whole = await checkBook(text, options);
  assert.ok(whole.held.every((h) => h.notes.length > 0));
  const carried = await openChecker(text, options);
  assert.deepEqual(await carried.result(), whole);
  assert.deepEqual(await carried.result(), whole);
  assert.deepEqual(await carried.result(), whole);
  // A book cut short: the problems are given once at each answer.
  const cut = book(lines.slice(0, 4));
  const cutCarried = await openChecker(cut, options);
  const cutWhole = await checkBook(cut, options);
  assert.deepEqual(await cutCarried.result(), cutWhole);
  assert.deepEqual(await cutCarried.result(), cutWhole);
  // The stub writer, asked twice, and after an action.
  const clock = START + 6 * 3600 * 1000;
  const writer = await openRecorder({ book: text, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys: trust.issuerKeys, now: () => clock, options });
  const writerOptions = { issuerKeys: trust.issuerKeys, ...options };
  assert.deepEqual(await writer.check(), await checkBook(writer.book(), writerOptions));
  assert.deepEqual(await writer.check(), await checkBook(writer.book(), writerOptions));
  await writer.act({ action: 'supplies.order', amount: { unit: 'GBP', value: 1 }, with: 'supplier' }, async () => 'done');
  assert.deepEqual(await writer.check(), await checkBook(writer.book(), writerOptions));
  assert.deepEqual(await writer.check(), await checkBook(writer.book(), writerOptions));
});
