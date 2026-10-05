// What the eleventh independent review found, in the checker that can be
// carried on, in the stub writer that carries its book on, and in the tenth
// review's rule for block time-stamps (4 October 2026). Each fault is
// fixed, or stated as a limit, and each is a test here.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBook, checkShow, formatTime, makeShow, openChecker, openRecorder, thumbprint, toBase64url, fromBase64url } from '../src/index.js';
import { makeStampService } from './helpers/stamp.mjs';
import { START, makeWorld } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const MINUTE = 60 * 1000;
const ORDER = 'supplies.order';
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });

function codes(result) {
  const out = result.problems.map((p) => p.code);
  for (const e of result.entries) out.push(...e.problems.map((p) => p.code), ...e.breaches.map((b) => b.code));
  return out;
}

// --- the stub writer ---

test('finding 1: a clock that fails part of the way through a call leaves the writer\'s view of its book exact', async () => {
  // The clock fails on its first, second, ... reading inside the call. Whatever the call was doing, the
  // writer's view of its book is afterwards the view a whole check gives, and the writer goes on working.
  for (const kind of ['terms', 'refusal', 'cancellation', 'cancellation dated ahead', 'not an entry']) {
    for (let failAt = 1; failAt <= 5; failAt++) {
      const w = await makeWorld();
      const clock = START + HOUR;
      let readings = 0;
      let failing = Infinity;
      const now = () => {
        if (++readings === failing) throw new Error('the clock failed');
        return clock;
      };
      const issuerKeys = [await thumbprint(w.passkey.key)];
      const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now });
      assert.equal((await writer.act(order(10), async () => null)).done, true);
      let entry;
      if (kind === 'terms') entry = { terms: (await w.publishTerms()).record };
      else if (kind === 'refusal') entry = { refusal: (await w.refuse({ when: clock })).record };
      else if (kind === 'cancellation') entry = (await w.cancel({ when: clock })).entry;
      else if (kind === 'cancellation dated ahead') entry = (await w.cancel({ when: clock + 10 * MINUTE })).entry;
      else entry = { neither: 'this nor that' };
      readings = 0;
      failing = failAt;
      await writer.add(entry).catch(() => null);
      failing = Infinity;
      const what = `${kind}, the clock failing at reading ${failAt}`;
      const beside = writer.cancellations();
      const whole = await checkBook(writer.book(), beside.length ? { issuerKeys, cancellations: beside } : { issuerKeys });
      assert.deepEqual(await writer.check(), whole, what);
      assert.equal(whole.summary.problemFound, false, what);
      // A fresh writer, opened from the book and what is held beside it, allows what this one allows.
      const fresh = await openRecorder({ book: writer.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock, options: beside.length ? { cancellations: beside } : {} });
      assert.deepEqual(await writer.before(order(1)), await fresh.before(order(1)), what);
    }
  }
});

test('finding 4: a cancellation given when the writer is opened is written into the book once its date has come', async () => {
  const w = await makeWorld();
  let clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const open = (book, options) => openRecorder({ book, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock, options });
  const first = await open(w.book());
  assert.equal((await first.act(order(10), async () => null)).done, true);
  const cancel = await w.cancel({ when: clock + 10 * MINUTE, stampTime: clock + 10 * MINUTE + 5000 });
  const kept = await first.add(cancel.entry).catch((e) => e);
  assert.ok(kept.acknowledgement);
  // The agent's software stops and is started again an hour later, with the book and what the first writer held beside it.
  clock += HOUR;
  const again = await open(first.book(), { stampServices: [w.stampService.fingerprint], cancellations: first.cancellations() });
  // An action that was taken some other way is recorded. The cancellation is written into the book first, with
  // its time-stamp, and the acknowledgement the first writer signed follows it: the same one, not a second.
  await again.record(order(5));
  const book = await checkBook(again.book(), { issuerKeys, stampServices: [w.stampService.fingerprint] });
  assert.deepEqual(book.entries.map((e) => e.kind), ['slip', 'stub', 'cancellation', 'acknowledgement', 'stub']);
  assert.equal(book.summary.problemFound, false);
  assert.equal(book.entries[2].stampedAt, formatTime(cancel.when + 5000));
  assert.deepEqual(JSON.parse(again.book().split('\n')[3]).acknowledgement, kept.acknowledgement);
  // So a check of the book alone reports the stub that was written after it.
  assert.deepEqual(book.entries[4].breaches.map((b) => b.code), ['after-cancellation']);
});

test('finding 4: every cancellation of its slip that the writer is handed is kept, handed back, and written when its date comes', async () => {
  const w = await makeWorld();
  let clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock });
  const far = await w.cancel({ when: clock + 24 * HOUR });
  const near = await w.cancel({ when: clock + 10 * MINUTE });
  await assert.rejects(writer.add(far.entry), /allows nothing more under that slip/);
  await assert.rejects(writer.add(near.entry), /allows nothing more under that slip/);
  assert.deepEqual(writer.cancellations().map((c) => c.cancellation), [far.record, near.record]);
  // Ten minutes on, the nearer one is written into the book; the other is still held beside it.
  clock += 20 * MINUTE;
  assert.equal((await writer.act(order(1), async () => null)).done, false);
  assert.equal((await writer.check()).summary.counts.cancellations, 1);
  assert.deepEqual(writer.cancellations().map((c) => c.cancellation), [far.record]);
  // A day on, the other is written too.
  clock += 24 * HOUR;
  assert.equal((await writer.act(order(1), async () => null)).done, false);
  const book = await checkBook(writer.book(), { issuerKeys });
  assert.equal(book.summary.counts.cancellations, 2);
  assert.equal(book.summary.counts.acknowledgements, 2);
  assert.equal(book.summary.problemFound, false);
  assert.deepEqual(writer.cancellations(), []);
});

test('suspected: a cancellation kept without a time-stamp takes the time-stamp it is handed over with later', async () => {
  const w = await makeWorld();
  let clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock, options: {} });
  const cancel = await w.cancel({ when: clock + 10 * MINUTE });
  const bare = await writer.add({ cancellation: cancel.record }).catch((e) => e);
  const service = await makeStampService();
  const stamped = { cancellation: cancel.record, stamps: [toBase64url(await service.stamp(fromBase64url(cancel.fingerprint), cancel.when + 5000))] };
  const again = await writer.add(stamped).catch((e) => e);
  // One acknowledgement for one cancellation, and the fuller entry is the one held.
  assert.deepEqual(again.acknowledgement, bare.acknowledgement);
  assert.deepEqual(writer.cancellations(), [{ ...stamped, acknowledgements: [bare.acknowledgement] }]);
  clock += 20 * MINUTE;
  await writer.record(order(1));
  const book = await checkBook(writer.book(), { issuerKeys, stampServices: [service.fingerprint] });
  assert.equal(book.entries[1].kind, 'cancellation');
  assert.equal(book.entries[1].stampedAt, formatTime(cancel.when + 5000));
});

test('suspected: with sixteen cancellations given at opening, the person\'s cancellation of the writer\'s slip still stops it', async () => {
  const a = await makeWorld();
  const b = await makeWorld();
  const clock = START + HOUR;
  const issuerKeys = [await thumbprint(a.passkey.key), await thumbprint(b.passkey.key)];
  const many = [];
  for (let i = 0; i < 16; i++) many.push((await b.cancel({ when: START + i * 1000 })).entry);
  const writer = await openRecorder({ book: a.book() + b.book().split('\n')[0] + '\n', slip: a.slipFingerprint, privateKeys: a.agent.privateKeys, issuerKeys, now: () => clock + 24 * HOUR, options: { cancellations: many } });
  // (Those given at opening are written into the book at the first call, since their dates have come.)
  assert.equal((await writer.act(order(1), async () => null)).done, true);
  assert.equal((await writer.check()).summary.counts.cancellations, 16);
  // The person's cancellation of this writer's slip, dated ahead: there is no room to keep it beside the book,
  // and it stops the writer all the same.
  const cancel = await a.cancel({ when: clock + 48 * HOUR });
  await assert.rejects(writer.add(cancel.entry), /allows nothing more under that slip/);
  const refused = await writer.act(order(1), async () => null);
  assert.equal(refused.done, false);
  assert.deepEqual(refused.answer.breaches.map((x) => x.code), ['after-cancellation']);
  assert.equal((await writer.before(order(1))).allowed, false);
});

// --- options that are not plain data ---

test('finding 2: a carried checker reads its options as a whole check does, whatever kind of object they are', async () => {
  const w = await makeWorld({ cover: ['purpose'] });
  await w.add({ when: START });
  await w.add({ when: START + HOUR });
  const book = w.book();
  const stranger = 'A'.repeat(43);
  class Trust {
    get expectedSize() {
      return 7;
    }
  }
  class Disclosures {
    constructor(slip, list) {
      this[slip] = list;
    }
  }
  const cases = {
    'issuerKeys inherited': Object.create({ issuerKeys: [stranger] }),
    'expectedSize worked out when asked for': new Trust(),
    'disclosures that are an object of a class': { disclosures: new Disclosures(w.slipFingerprint, w.prepared.disclosures) },
    'disclosures with no prototype': { disclosures: Object.assign(Object.create(null), { [w.slipFingerprint]: w.prepared.disclosures }) },
    'cancellations inherited': Object.create({ cancellations: [(await w.cancel({ when: START + 2 * HOUR })).entry] }),
    'a list that is not a list': { issuerKeys: { 0: stranger, length: 1 } },
    'options that are not an object': 'trust me',
  };
  w.entries.pop();
  for (const [name, options] of Object.entries(cases)) {
    const whole = await checkBook(book, options);
    const lines = book.split('\n').filter(Boolean).map((l) => l + '\n');
    const checker = await openChecker(lines[0], options);
    await checker.add(lines.slice(1).join(''));
    assert.deepEqual(await checker.result(), whole, name);
  }
  // The first three are refused or reported by a whole check, so the comparison above is not empty.
  assert.deepEqual(codes(await checkBook(book, cases['issuerKeys inherited'])).slice(0, 1), ['issuer-not-expected']);
  assert.deepEqual((await checkBook(book, cases['expectedSize worked out when asked for'])).problems.map((p) => p.code), ['root-mismatch']);
  assert.deepEqual((await checkBook(book, cases['disclosures that are an object of a class'])).problems.map((p) => p.code), ['bad-field']);

  // What is plain data is fixed when the checker is opened, through and through; a member with a special name stays a member.
  const mine = { issuerKeys: [await thumbprint(w.passkey.key)], disclosures: { [w.slipFingerprint]: [...w.prepared.disclosures] } };
  const expected = await checkBook(book, structuredClone(mine));
  const checker = await openChecker(book.slice(0, book.indexOf('\n') + 1), mine);
  mine.issuerKeys[0] = stranger;
  mine.disclosures[w.slipFingerprint].length = 0;
  delete mine.disclosures;
  await checker.add(book.slice(book.indexOf('\n') + 1));
  assert.deepEqual(await checker.result(), expected);
});

test('finding 2: the stub writer reads its options as a whole check does', async () => {
  const w = await makeWorld();
  const clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const cancel = await w.cancel({ when: START + 10 * MINUTE });
  w.entries.pop();
  // The cancellations are inherited, not the options' own.
  const options = Object.create({ cancellations: [cancel.entry] });
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock, options });
  assert.deepEqual(writer.cancellations(), [cancel.entry]);
  assert.equal((await writer.act(order(1), async () => null)).done, false);
});

// --- a seal, the seals before it, and a Show ---

test('finding 3: a seal dated before a time-stamp that it covers is reported', async () => {
  // The first seal is time-stamped by the service at 10:00. The second seal covers that line, and is dated 09:10.
  const w = await makeWorld();
  await w.add({ when: START });
  await w.seal({ when: START + MINUTE, stampTime: START + HOUR });
  await w.seal({ when: START + 10 * MINUTE, stampTime: START + HOUR + 10 * MINUTE });
  const trust = { stampServices: [w.stampService.fingerprint] };
  const whole = await checkBook(w.book(), trust);
  assert.deepEqual(codes(whole), ['time-went-backwards']);
  assert.match(whole.entries[3].problems[0].message, /dated before the time that a time-stamp service gave a seal that comes before it/);
  assert.equal(whole.entries[3].stampedAt, undefined);
  assert.equal(whole.summary.sealed, null);
  // In a Show, with the first seal among the pages: the same.
  assert.deepEqual(codes(await checkShow(await makeShow(w.book(), [0, 1, 2], { seal: 3 }), trust)), ['time-went-backwards']);
  assert.deepEqual(codes(await checkShow(await makeShow(w.book(), [0, 2, 3]), { ...trust, expectedRoot: whole.root, expectedSize: 4 })), ['time-went-backwards']);
  // A stated limit: with the first seal left out of the pages, a Show cannot show it.
  assert.deepEqual(codes(await checkShow(await makeShow(w.book(), [0, 1], { seal: 3 }), trust)), []);
  // To a reader who trusts no time-stamp service nothing fixes the time, and nothing is reported.
  assert.deepEqual(codes(await checkBook(w.book())), []);
  // A seal dated up to 300 seconds before that time-stamp is within what clocks may differ by.
  const v = await makeWorld();
  await v.add({ when: START });
  await v.seal({ when: START + MINUTE, stampTime: START + HOUR });
  await v.seal({ when: START + HOUR - 299 * 1000, stampTime: START + HOUR + MINUTE });
  assert.deepEqual(codes(await checkBook(v.book(), { stampServices: [v.stampService.fingerprint] })), []);
});

test('finding 3, a stated limit: where a seal that settles a block time-stamp is left out of a Show, the Show can differ from the whole book', async () => {
  // The first seal is time-stamped by the service at 10:00. The second, dated 10:05, has only a block time-stamp,
  // in a block that states 06:30: far behind the true time.
  const w = await makeWorld();
  await w.add({ when: START });
  await w.seal({ when: START + MINUTE, stampTime: START + HOUR });
  await w.add({ when: START + HOUR + 2 * MINUTE });
  const second = await w.seal({ when: START + HOUR + 5 * MINUTE, stamp: false, blockTime: START - 150 * MINUTE });
  const trust = { stampServices: [w.stampService.fingerprint], blocks: [second.block.fingerprint] };
  // The whole book: the first seal's time-stamp settles it. The block is set aside, and the book passes.
  const whole = await checkBook(w.book(), trust);
  assert.deepEqual(codes(whole), []);
  assert.ok(whole.entries[4].notes.some((n) => /block time-stamp was set aside/.test(n)));
  assert.equal(whole.summary.sealed.seal, 2);
  // A Show with the first seal among its pages: the same.
  assert.deepEqual(codes(await checkShow(await makeShow(w.book(), [0, 1, 2, 3], { seal: 4 }), trust)), []);
  // A Show that leaves the first seal out: nothing settles it, and the seal reads as dated after its time-stamp.
  assert.deepEqual(codes(await checkShow(await makeShow(w.book(), [0, 1, 3], { seal: 4 }), trust)), ['dated-after-stamp']);
});
