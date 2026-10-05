// What the tenth independent review found, in the stub writer, in what is
// shown as the time of a cancellation, in the seal of a Show and in a block
// time-stamp beside a later seal (4 October 2026). Each fault is fixed, or
// stated as a limit, and each is a test here.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { checkBook, checkShow, formatTime, generateSealKeySet, makeShow, openRecorder, thumbprint, toBase64url, writeSeal } from '../src/index.js';
import { makeStampService } from './helpers/stamp.mjs';
import { START, makeWorld } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const MINUTE = 60 * 1000;
const ORDER = 'supplies.order';
const CLI = fileURLToPath(new URL('../bin/provared-check.mjs', import.meta.url));

function codes(result) {
  const out = result.problems.map((p) => p.code);
  for (const e of result.entries) out.push(...e.problems.map((p) => p.code), ...e.breaches.map((b) => b.code));
  return out;
}
const breachesOf = (r) => r.entries.map((e) => e.breaches.map((b) => b.code));
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });

// --- the stub writer ---

test('finding 1: a cancellation the person signed stops the writer, whatever stands beside it', async () => {
  const shapes = {
    'stamps: undefined': (c) => ({ cancellation: c.record, stamps: undefined }),
    'stamps: null': (c) => ({ cancellation: c.record, stamps: null }),
    'stamps: [null]': (c) => ({ cancellation: c.record, stamps: [null] }),
    'stamps: [1.5]': (c) => ({ cancellation: c.record, stamps: [1.5] }),
    'stamps: [true]': (c) => ({ cancellation: c.record, stamps: [true] }),
    'stamps: [-1]': (c) => ({ cancellation: c.record, stamps: [-1] }),
    'stamps: text that is not well-formed': (c) => ({ cancellation: c.record, stamps: ['\ud800'] }),
    'stamps: bytes, not text': (c) => ({ cancellation: c.record, stamps: [new Uint8Array([1, 2, 3])] }),
    'stamps: nested too deep': (c) => ({ cancellation: c.record, stamps: [[[[[[[[['x']]]]]]]]] }),
    'stamps: longer than a line may be': (c) => ({ cancellation: c.record, stamps: ['A'.repeat(140000)] }),
    'stamps: not a time-stamp': (c) => ({ cancellation: c.record, stamps: ['AAAA'] }),
    'another member: undefined': (c) => ({ cancellation: c.record, note: undefined }),
    'another member: true': (c) => ({ cancellation: c.record, received: true }),
    'another member: a date': (c) => ({ cancellation: c.record, receivedAt: new Date(START) }),
    'another member: text': (c) => ({ cancellation: c.record, note: 'from the person' }),
  };
  for (const [name, shape] of Object.entries(shapes)) {
    const w = await makeWorld();
    const clock = START + HOUR;
    const issuerKeys = [await thumbprint(w.passkey.key)];
    const recorder = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock });
    let taken = 0;
    assert.equal((await recorder.act(order(10), async () => ++taken)).done, true, name);
    const cancel = await w.cancel({ when: clock });
    await assert.rejects(
      recorder.add(shape(cancel)),
      (e) => e.code === 'record-not-sound' && /The cancellation by itself was added to the book/.test(e.message) && /allows nothing more under that slip/.test(e.message),
      name,
    );
    const after = await recorder.act(order(10), async () => ++taken);
    assert.equal(after.done, false, name);
    assert.deepEqual(after.answer.breaches.map((b) => b.code), ['after-cancellation'], name);
    assert.equal(taken, 1, name);
    // The book holds the cancellation, by itself, and passes its check. So the stop outlives the writer.
    const book = await checkBook(recorder.book(), { issuerKeys });
    assert.equal(book.summary.problemFound, false, name);
    assert.equal(book.summary.counts.cancellations, 1, name);
    assert.deepEqual(recorder.cancellations(), [], name);
  }
});

test('finding 1: what is not a cancellation record at all is refused, and stops nothing', async () => {
  const w = await makeWorld();
  const clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const recorder = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock });
  const before = recorder.book();
  const cancel = await w.cancel({ when: clock });
  const other = await makeWorld();
  const forged = await w.cancel({ passkey: other.passkey, when: clock });
  for (const entry of [
    { cancellation: { ...cancel.record, note: 'x' } },
    { cancellation: { ...cancel.record, note: undefined } },
    { cancellation: null, stamps: undefined },
    { cancellation: forged.record, stamps: undefined },
    JSON.stringify(cancel.entry),
    [cancel.entry],
    cancel.record,
    null,
    undefined,
  ]) {
    await assert.rejects(recorder.add(entry), (e) => e.code === 'record-not-sound' && !/allows nothing more/.test(e.message) && !/was added to the book/.test(e.message));
  }
  assert.equal(recorder.book(), before);
  assert.deepEqual(recorder.cancellations(), []);
  assert.equal((await recorder.act(order(10), async () => null)).done, true);
});

test('finding 1: a cancellation of another slip, handed over with something that cannot be a line, is added by itself and does not stop the writer', async () => {
  const a = await makeWorld();
  const b = await makeWorld();
  const clock = START + HOUR;
  const issuerKeys = [await thumbprint(a.passkey.key), await thumbprint(b.passkey.key)];
  const recorder = await openRecorder({ book: a.book() + b.book(), slip: a.slipFingerprint, privateKeys: a.agent.privateKeys, issuerKeys, now: () => clock });
  const other = await b.cancel({ when: clock });
  await assert.rejects(recorder.add({ cancellation: other.record, stamps: undefined }), (e) => /The cancellation by itself was added to the book/.test(e.message) && !/allows nothing more/.test(e.message));
  assert.equal((await checkBook(recorder.book(), { issuerKeys })).summary.counts.cancellations, 1);
  assert.equal((await recorder.act(order(10), async () => null)).done, true);
});

test('finding 2: a cancellation the writer keeps is written into the book once the clock reaches its date, and can be read back until then', async () => {
  const w = await makeWorld();
  let clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const open = (book, options) => openRecorder({ book, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock, options });
  const recorder = await open(w.book());
  let taken = 0;
  assert.equal((await recorder.act(order(10), async () => ++taken)).done, true);
  // The person cancels. Their device's clock is ten minutes ahead of the writer's. A service time-stamps the cancellation.
  const cancel = await w.cancel({ when: clock + 10 * MINUTE, stampTime: clock + 10 * MINUTE + 5000 });
  const trust = { stampServices: [w.stampService.fingerprint] };
  const refused = await recorder.add(cancel.entry).catch((e) => e);
  assert.ok(refused.code === 'record-not-sound' && /dated ahead of the clock/.test(refused.message) && /allows nothing more under that slip/.test(refused.message));
  assert.equal((await recorder.act(order(10), async () => ++taken)).done, false);
  // The book does not hold it yet. The writer hands it back, whole, to be kept with the book: with its
  // time-stamp, and with the acknowledgement the writer signed for it.
  assert.equal((await checkBook(recorder.book(), { issuerKeys })).summary.counts.cancellations, 0);
  const handedBack = { ...cancel.entry, acknowledgements: [refused.acknowledgement] };
  assert.deepEqual(recorder.cancellations(), [handedBack]);
  // What is handed back is a copy.
  recorder.cancellations()[0].cancellation = null;
  assert.deepEqual(recorder.cancellations(), [handedBack]);
  // A writer opened again from the book alone knows nothing of it: a stated limit. Handed the copy, it is stopped.
  const forgetful = await open(recorder.book());
  assert.equal((await forgetful.before(order(10))).allowed, true);
  const told = await open(recorder.book(), { cancellations: recorder.cancellations() });
  assert.equal((await told.before(order(10))).allowed, false);
  assert.deepEqual(told.cancellations(), [handedBack]);

  // Twenty minutes later the cancellation is no longer dated ahead of the clock: the next call writes it into the book.
  clock += 20 * MINUTE;
  const later = await recorder.act(order(10), async () => ++taken);
  assert.equal(later.done, false);
  assert.deepEqual(later.answer.breaches.map((b) => b.code), ['after-cancellation']);
  const book = await checkBook(recorder.book(), { issuerKeys, ...trust });
  assert.equal(book.summary.problemFound, false);
  assert.equal(book.summary.counts.cancellations, 1);
  // It was written whole, with the person's time-stamp. (The writer's acknowledgement follows it.)
  assert.equal(book.entries.find((e) => e.kind === 'cancellation').stampedAt, formatTime(cancel.when + 5000));
  assert.deepEqual(recorder.cancellations(), []);
  // So the stop now outlives the writer.
  const again = await open(recorder.book());
  assert.equal((await again.act(order(10), async () => ++taken)).done, false);
  assert.equal(taken, 1);
});

test('finding 2: a cancellation the book already holds is not kept beside it as well', async () => {
  const w = await makeWorld();
  const clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const recorder = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock });
  const cancel = await w.cancel({ when: clock });
  await recorder.add(cancel.entry);
  await assert.rejects(recorder.add(cancel.entry), (e) => e.code === 'record-not-sound' && /allows nothing more under that slip/.test(e.message));
  assert.deepEqual(recorder.cancellations(), []);
  assert.equal((await checkBook(recorder.book(), { issuerKeys })).summary.counts.cancellations, 1);
});

// --- what is shown as the time of a cancellation ---

test('finding 3: a cancellation with no counted time-stamp of its own is not shown as cancelled at the time of a later seal', async () => {
  const w = await makeWorld();
  await w.add({ when: START }); // 1: a stub at 09:00
  await w.cancel({ when: START + HOUR }); // 2: the person cancels at 10:00; no time-stamp
  await w.seal({ when: START + 5 * HOUR }); // 3: a seal at 14:00, time-stamped by a service at 14:01
  const trust = { stampServices: [w.stampService.fingerprint] };
  const sealTime = formatTime(START + 5 * HOUR + MINUTE);
  const r = await checkBook(w.book(), trust);
  assert.deepEqual(codes(r), []);
  // The seal shows that the cancellation existed by 14:01. That is not the time it counts from: it has none.
  assert.equal(r.entries[2].stampedAt, undefined);
  assert.equal(r.entries[2].existedBy, sealTime);
  assert.ok(r.entries[2].notes.some((n) => /Only its place in the book says when it took effect/.test(n)));
  // The same as a page of a Show under the seal.
  const show = await checkShow(await makeShow(w.book(), [0, 1, 2], { seal: 3 }), trust);
  assert.equal(show.entries[2].stampedAt, undefined);
  assert.equal(show.entries[2].existedBy, sealTime);
  // And the command-line checker does not print a time it did not use.
  const dir = mkdtempSync(join(tmpdir(), 'provared-'));
  try {
    const file = join(dir, 'book.jsonl');
    writeFileSync(file, w.book());
    let out;
    try {
      out = execFileSync(process.execPath, ['--disable-warning=ExperimentalWarning', CLI, file, '--stamp-service', w.stampService.fingerprint], { encoding: 'utf8' });
    } catch (e) {
      out = e.stdout;
    }
    assert.match(out, /CANCELLATION/);
    assert.doesNotMatch(out, /Counts as cancelled at/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  // With a counted time-stamp of its own, a cancellation keeps that time, whatever a later seal shows.
  const v = await makeWorld();
  await v.add({ when: START });
  await v.cancel({ when: START + HOUR, stampTime: START + HOUR + 5000 });
  await v.seal({ when: START + 5 * HOUR });
  const own = await checkBook(v.book(), { stampServices: [v.stampService.fingerprint] });
  assert.equal(own.entries[2].stampedAt, formatTime(START + HOUR + 5000));
  assert.equal(own.entries[2].existedBy, sealTime);
});

test('suspected: a seal or a cancellation that did not pass its check shows no time of its own', async () => {
  // A second seal whose time-stamp is hours earlier than the first seal's.
  const w = await makeWorld();
  await w.add({ when: START });
  await w.seal({ when: START + 10 * MINUTE, stampTime: START + 3 * HOUR });
  await w.seal({ when: START + 20 * MINUTE, stampTime: START + 30 * MINUTE });
  const trust = { stampServices: [w.stampService.fingerprint] };
  const r = await checkBook(w.book(), trust);
  assert.deepEqual(r.entries[3].problems.map((p) => p.code), ['time-went-backwards']);
  assert.equal(r.entries[3].stampedAt, undefined);
  assert.equal(r.entries[2].stampedAt, formatTime(START + 3 * HOUR));
  // The seal of a Show that fails after its time-stamp was read.
  const show = await makeShow(w.book(), [0, 1, 2], { seal: 3 });
  const s = await checkShow(show, trust);
  assert.ok(s.entries.at(-1).problems.length > 0);
  assert.equal(s.entries.at(-1).stampedAt, undefined);
  assert.equal(s.summary.sealed, null);
});

test('suspected: a time-stamp is not held against a cancellation whose signature this device could not check', async () => {
  // The cancellation is dated an hour after the time-stamp that covers it.
  const w = await makeWorld();
  await w.add({ when: START });
  const cancel = await w.cancel({ when: START + 2 * HOUR, stampTime: START + HOUR });
  const trust = { stampServices: [w.stampService.fingerprint] };
  assert.deepEqual(codes(await checkBook(w.book(), trust)), ['dated-after-stamp']);
  // A device without the passkey's method cannot tell whose cancellation it is: it reports nothing against it, and gives no pass.
  const blind = await checkBook(w.book(), { ...trust, withoutMethods: ['ES256'] });
  assert.equal(blind.entries.at(-1).problems.length, 0);
  assert.equal(blind.entries.at(-1).stampedAt, undefined);
  assert.equal(blind.summary.intact, false);
  // The same for the person's own copy, handed over beside the book.
  w.entries.pop();
  const copy = await checkBook(w.book(), { ...trust, cancellations: [cancel.entry], withoutMethods: ['ES256'] });
  assert.deepEqual(copy.held[0].problems, []);
  assert.equal(copy.held[0].used, false);
  assert.equal(copy.summary.intact, false);
  assert.deepEqual((await checkBook(w.book(), { ...trust, cancellations: [cancel.entry] })).problems.map((p) => p.code), ['dated-after-stamp']);
});

// --- the seal that comes with a Show ---

test('finding 4: the seal that comes with a Show may not repeat a unique number of a page', async () => {
  const recorder = await generateSealKeySet();
  const service = await makeStampService();
  const trust = { stampServices: [service.fingerprint] };
  const by = { keys: recorder.keys, name: 'Example recorder (invented)' };
  const sealInto = async (w, fields) => {
    const sealed = await writeSeal(w.book(), { by, ...fields }, recorder.privateKeys);
    w.entries.push({ seal: sealed.record, stamps: [toBase64url(await service.stamp(sealed.fingerprintBytes, fields.when + MINUTE))] });
    return sealed;
  };
  // Two seals with one unique number.
  const w = await makeWorld();
  await w.add({ when: START });
  const ID = 'AAAAAAAAAAAAAAAAAAAAAA';
  const first = await sealInto(w, { id: ID, when: START + 10 * MINUTE });
  await w.add({ when: START + 20 * MINUTE });
  await sealInto(w, { id: ID, previous: first.fingerprint, when: START + 30 * MINUTE });
  const whole = await checkBook(w.book(), trust);
  assert.deepEqual(codes(whole), ['duplicate-id']);
  // Every entry before the second seal, under that seal: the same answer as the whole book.
  const under = await checkShow(await makeShow(w.book(), [0, 1, 2, 3], { seal: 4 }), trust);
  assert.deepEqual(codes(under), ['duplicate-id']);
  assert.equal(under.summary.intact, false);
  assert.equal(under.summary.sealed, null);
  // A stated limit: with the first seal left out of the pages, a Show cannot show it.
  assert.deepEqual(codes(await checkShow(await makeShow(w.book(), [0, 1, 3], { seal: 4 }), trust)), []);

  // The seal has the unique number of a stub before it.
  const v = await makeWorld();
  const STUB_ID = 'BBBBBBBBBBBBBBBBBBBBBA';
  await v.add({ when: START, id: STUB_ID });
  await sealInto(v, { id: STUB_ID, when: START + 10 * MINUTE });
  assert.deepEqual(codes(await checkBook(v.book(), trust)), ['duplicate-id']);
  assert.deepEqual(codes(await checkShow(await makeShow(v.book(), [0, 1], { seal: 2 }), trust)), ['duplicate-id']);
});

// --- a block time-stamp beside a later seal ---

test('finding 5: a block time-stamp that states a time before a service\'s time-stamp on an earlier seal is set aside', async () => {
  const at = (h, m = 0) => START - 9 * HOUR + h * HOUR + m * MINUTE; // START is 09:00
  const w = await makeWorld();
  await w.add({ when: at(8, 0), countersigned: false }); // 1: a stub dated 08:00
  await w.seal({ when: at(8, 1), stampTime: at(10, 0) }); // 2: the first seal, time-stamped by the service at 10:00
  await w.add({ when: at(8, 5), countersigned: false }); // 3: a stub dated 08:05, written after the first seal and its time-stamp
  // 4: the second seal, dated 09:56 (the recorder's clock is four minutes slow: within what is allowed). A block that
  // states 07:53 holds it ("existed by 09:53"); the service time-stamps it at 10:11.
  const second = await w.seal({ when: at(9, 56), stampTime: at(10, 11), blockTime: at(7, 53) });
  await w.cancel({ when: at(9, 54), stampTime: at(9, 54) + 5000 }); // 5: the person cancelled at 09:54
  const service = { stampServices: [w.stampService.fingerprint] };
  const both = { ...service, blocks: [second.block.fingerprint] };
  const setAside = /before the time a time-stamp service gave a seal that comes before this one/;

  // The second seal covers the first seal's line, time-stamp included, so it did not exist by 09:53. The block is set aside.
  // (Counted, it would show both stubs to have existed by 09:53, before the cancellation, and excuse them.)
  const r = await checkBook(w.book(), both);
  assert.deepEqual(r.entries.flatMap((e) => e.problems), []);
  assert.ok(r.entries[4].notes.some((n) => setAside.test(n)));
  assert.equal(r.entries[4].stampedAt, formatTime(at(10, 11)));
  assert.equal(r.entries[3].existedBy, formatTime(at(10, 11)));
  assert.deepEqual(r.summary.sealed, { entries: 4, when: formatTime(at(10, 11)), seal: 4, by: 'service' });
  // So no stub is excused: the answer is the one a reader gets who did not name the block.
  const plain = await checkBook(w.book(), service);
  assert.deepEqual(breachesOf(r), breachesOf(plain));
  assert.deepEqual(breachesOf(r), [[], ['after-cancellation'], [], ['after-cancellation'], [], []]);
  assert.ok(!plain.entries[4].notes.some((n) => setAside.test(n)));

  // The same in a Show under the second seal, with the first seal among the pages.
  const show = await checkShow(await makeShow(w.book(), [0, 1, 2, 3], { seal: 4 }), both);
  assert.deepEqual(codes(show), []);
  assert.ok(show.entries.at(-1).notes.some((n) => setAside.test(n)));
  assert.deepEqual(show.summary.sealed, { entries: 4, when: formatTime(at(10, 11)), seal: 4, by: 'service' });
  assert.equal(show.entries[3].existedBy, formatTime(at(10, 11)));

  // With the block alone beside the second seal, nothing gives that seal a time: only the first seal's time-stamp counts.
  second.entry.stamps = [second.block.item];
  const alone = await checkBook(w.book(), both);
  assert.deepEqual(alone.entries.flatMap((e) => e.problems), []);
  assert.ok(alone.entries[4].notes.some((n) => setAside.test(n)));
  assert.equal(alone.entries[4].stampedAt, undefined);
  assert.equal(alone.summary.sealed.seal, 2);
});

test('finding 5: a block time-stamp that states a time after an earlier seal\'s time-stamp counts as before', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  await w.seal({ when: START + 10 * MINUTE, stampTime: START + 11 * MINUTE });
  await w.add({ when: START + 20 * MINUTE });
  // The block states 09:40, so the entries existed by 11:40. The service time-stamps the seal at 15:00.
  const second = await w.seal({ when: START + 30 * MINUTE, stampTime: START + 6 * HOUR, blockTime: START + 40 * MINUTE });
  const r = await checkBook(w.book(), { stampServices: [w.stampService.fingerprint], blocks: [second.block.fingerprint] });
  assert.deepEqual(codes(r), []);
  assert.equal(r.entries[4].stampedAt, formatTime(START + 40 * MINUTE + 2 * HOUR));
  assert.equal(r.summary.sealed.by, 'block');
  assert.ok(!r.entries[4].notes.some((n) => /set aside/.test(n)));
});
