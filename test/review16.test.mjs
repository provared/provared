// What the sixteenth independent review found, in the fixes of the
// fifteenth review (4 October 2026). Each fault is fixed and each is a
// test here.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBook, fromBase64url, openChecker, openRecorder, thumbprint, toBase64url } from '../src/index.js';
import { makeStampService } from './helpers/stamp.mjs';
import { START, makeWorld } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const MINUTE = 60 * 1000;
const ORDER = 'supplies.order';
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });

async function setUp() {
  const w = await makeWorld();
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const state = { clock: START + HOUR, fail: false };
  const now = () => {
    if (state.fail) throw new Error('the clock failed');
    return state.clock;
  };
  const service = await makeStampService();
  const trust = { stampServices: [service.fingerprint] };
  const open = (book = w.book(), cancellations = undefined) =>
    openRecorder({ book, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now, options: cancellations ? { ...trust, cancellations } : trust });
  const cancel = async (when) => {
    const c = await w.cancel({ when });
    w.entries.pop();
    return c;
  };
  const sameAsWhole = async (writer) => assert.deepEqual(await writer.check(), await checkBook(writer.book(), { issuerKeys, ...trust, cancellations: writer.cancellations() }));
  return { w, issuerKeys, state, service, trust, open, cancel, sameAsWhole };
}

// --- the stub writer ---

test('finding 1: an acknowledgement that waits is not cut off by cancellations kept after it', async () => {
  const s = await setUp();
  // A stub dated ten minutes ahead of the clock: the acknowledgement may not be dated before it, so it waits.
  await s.w.add({ when: s.state.clock + 10 * MINUTE });
  const writer = await s.open();
  const first = await s.cancel(s.state.clock);
  const { acknowledgement } = await writer.add(first.entry);
  const messages = [];
  for (let i = 0; i < 16; i++) messages.push((await writer.add((await s.cancel(s.state.clock + (20 + i) * MINUTE)).entry).catch((e) => e)).message);
  // Fifteen are kept beside the waiting acknowledgement; the sixteenth is not, and the error says so.
  assert.match(messages[14], /^The cancellation was not added/);
  assert.doesNotMatch(messages[14], /is not kept/);
  assert.match(messages[15], /is not kept/);
  const held = writer.cancellations();
  assert.equal(held.length, 16);
  assert.ok(held.some((c) => c.cancellation.payload === first.record.payload && c.acknowledgements[0].payload === acknowledgement.payload));
  await s.sameAsWhole(writer);
  // A writer opened again from what this one hands back gives the same acknowledgement.
  const again = await s.open(writer.book(), held);
  assert.deepEqual((await again.add(first.entry).catch((e) => e)).acknowledgement, acknowledgement);
});

test('finding 2: copies of other slips\' cancellations given at opening do not crowd out the writer\'s own', async () => {
  const s = await setUp();
  const other = await makeWorld();
  s.w.entries.push({ slip: other.slip });
  // The writer trusts the other person's passkey too, so that the other slip is no problem in its book.
  s.issuerKeys.push(await thumbprint(other.passkey.key));
  const others = [];
  for (let i = 0; i < 16; i++) {
    const c = await other.cancel({ when: s.state.clock + (30 + i) * MINUTE });
    other.entries.pop();
    others.push({ cancellation: c.record });
  }
  const writer = await s.open(s.w.book(), others);
  const own = await s.cancel(s.state.clock + 10 * MINUTE);
  const e = await writer.add(own.entry).catch((x) => x);
  assert.doesNotMatch(e.message, /is not kept/);
  const held = writer.cancellations();
  assert.equal(held.length, 16);
  assert.equal(held[0].cancellation.payload, own.record.payload);
  await s.sameAsWhole(writer);
  // A writer opened again from what this one hands back takes no action.
  const again = await s.open(writer.book(), held);
  assert.equal((await again.act(order(1), async () => null)).done, false);
  // The writer's own cancellation given at opening, last of sixteen, is not crowded out by one kept after it.
  const given = await s.cancel(s.state.clock + 12 * MINUTE);
  const third = await s.open(s.w.book(), [...others.slice(0, 15), { cancellation: given.record }]);
  await third.add(own.entry).catch(() => null);
  const payloads = third.cancellations().map((c) => c.cancellation.payload);
  assert.ok(payloads.includes(own.record.payload) && payloads.includes(given.record.payload));
  await s.sameAsWhole(third);
});

test('finding 3: what is handed to "add" is read once', async () => {
  for (const ahead of [false, true]) {
    for (const clockFails of [false, true]) {
      const s = await setUp();
      const writer = await s.open();
      const cancel = await s.cancel(s.state.clock + (ahead ? 10 * MINUTE : 0));
      let reads = 0;
      const entry = {
        get cancellation() {
          return reads++ === 0 ? cancel.record : { payload: 'e30', signatures: [] };
        },
      };
      s.state.fail = clockFails;
      await writer.add(entry).catch(() => null);
      s.state.fail = false;
      const where = `${ahead ? 'dated ahead' : 'dated now'}, ${clockFails ? 'the clock failing' : 'the clock working'}`;
      assert.equal(reads, 1, where);
      assert.equal((await writer.act(order(1), async () => null)).done, false, where);
      const held = writer.cancellations();
      const again = await s.open(writer.book(), held.length ? held : undefined);
      assert.equal((await again.act(order(1), async () => null)).done, false, where);
    }
  }
});

test('finding 7: a copy given as an object of a class is copied, and the caller\'s object is left as it was', async () => {
  const s = await setUp();
  const cancel = await s.cancel(s.state.clock + 10 * MINUTE);
  class Copy {
    constructor(record) {
      this.cancellation = record;
    }
  }
  const copy = Object.freeze(new Copy(cancel.record));
  const writer = await s.open(s.w.book(), [copy]);
  const e = await writer.add(cancel.entry).catch((x) => x);
  assert.ok(e.acknowledgement);
  assert.deepEqual(Object.keys(copy), ['cancellation']);
  assert.deepEqual(writer.cancellations()[0].acknowledgements, [e.acknowledgement]);
  s.state.clock += 20 * MINUTE;
  await writer.act(order(1), async () => null);
  assert.deepEqual((await checkBook(writer.book(), { issuerKeys: s.issuerKeys })).entries.map((x) => x.kind), ['slip', 'cancellation', 'acknowledgement']);
});

test('finding 8: the first acknowledgement of the agent\'s own is taken, and a copy never takes a second', async () => {
  const s = await setUp();
  const cancel = await s.w.cancel({ when: s.state.clock - 10 * MINUTE });
  const one = await s.w.acknowledge(cancel.fingerprint, { when: s.state.clock - 9 * MINUTE });
  const two = await s.w.acknowledge(cancel.fingerprint, { when: s.state.clock - 8 * MINUTE });
  // The book holds both: a writer opened from it hands back the first.
  const writer = await s.open();
  assert.deepEqual((await writer.add({ cancellation: cancel.record }).catch((e) => e)).acknowledgement, one.record);
  // A copy given at opening that holds another of the agent's own takes no second one.
  const opened = await s.open(s.w.book(), [{ cancellation: cancel.record, acknowledgements: [two.record] }]);
  await opened.add({ cancellation: cancel.record }).catch(() => null);
  assert.deepEqual(opened.cancellations()[0].acknowledgements, [two.record]);
});

test('finding 9: an empty list of cancellations is none at all, so what a writer holding none hands back can be handed in again', async () => {
  const s = await setUp();
  const writer = await s.open();
  assert.deepEqual(writer.cancellations(), []);
  const again = await s.open(writer.book(), writer.cancellations());
  assert.equal((await again.act(order(1), async () => null)).done, true);
  const r = await checkBook(again.book(), { issuerKeys: s.issuerKeys, cancellations: [] });
  assert.equal(r.summary.problemFound, false);
  assert.deepEqual(r.held, []);
});

test('of the time-stamps the writer counts, the earliest are kept', async () => {
  const s = await setUp();
  const writer = await s.open();
  const cancel = await s.cancel(s.state.clock + 10 * MINUTE);
  const stamp = async (after) => toBase64url(await s.service.stamp(fromBase64url(cancel.fingerprint), cancel.when + after));
  const later = [];
  for (let i = 1; i <= 4; i++) later.push(await stamp(i * MINUTE));
  await assert.rejects(writer.add({ cancellation: cancel.record, stamps: later }));
  const earliest = await stamp(5000);
  await assert.rejects(writer.add({ cancellation: cancel.record, stamps: [earliest] }));
  assert.deepEqual(writer.cancellations()[0].stamps, [earliest, ...later.slice(0, 3)]);
});

// --- the checker ---

test('finding 4: an option that cannot be read is read as a whole check reads it, and the stub writer refuses it', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const failing = () => {
    throw new Error('cannot be read');
  };
  for (const name of ['blocks', 'cancellations', 'vouchers', 'expectedRoot']) {
    const top = () => Object.defineProperty({ issuerKeys }, name, { get: failing, enumerable: true });
    const place = () => ({ issuerKeys, [name]: Object.defineProperty([1], 0, { get: failing, enumerable: true }) });
    for (const make of [top, place]) {
      const whole = await checkBook(w.book(), make());
      const carried = await (await openChecker(w.book(), make())).result();
      assert.deepEqual(carried, whole, name);
      // The stub writer opens only where a whole check finds no problem, and otherwise refuses on purpose: it never crashes.
      const opened = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => START + HOUR, options: make() }).then(
        () => 'opened',
        (e) => e.code,
      );
      assert.ok(opened === 'opened' || opened === 'bad-field' || opened === 'record-not-sound', `${name}: ${opened}`);
      if (whole.summary.problemFound) assert.notEqual(opened, 'opened', name);
    }
  }
});

test('finding 5: a list is read place by place, not through its own way of walking through itself', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const cancel = await w.cancel({ when: START + 2 * HOUR });
  w.entries.pop();
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const walksNowhere = (list) => Object.defineProperty(list, Symbol.iterator, { value: function* () {} });
  for (const options of [() => ({ issuerKeys, blocks: walksNowhere(['not a block']) }), () => ({ issuerKeys, cancellations: [{ cancellation: cancel.record, stamps: walksNowhere(['AAAA']) }] })]) {
    const whole = await checkBook(w.book(), options());
    const carried = await (await openChecker(w.book(), options())).result();
    assert.deepEqual(carried, whole);
    assert.equal(whole.summary.problemFound, true);
  }
});

test('finding 6: a very long list with no items in it costs little', async () => {
  const w = await makeWorld();
  const issuerKeys = [await thumbprint(w.passkey.key)];
  for (const name of ['cancellations', 'vouchers', 'blocks']) {
    const options = () => ({ issuerKeys, [name]: new Array(2 ** 32 - 1) });
    const started = Date.now();
    const whole = await checkBook(w.book(), options());
    const carried = await (await openChecker(w.book(), options())).result();
    assert.deepEqual(carried, whole, name);
    // A gap in the list of trusted organisations harms nothing: it is only looked in.
    assert.equal(whole.summary.problemFound, name !== 'vouchers', name);
    assert.ok(Date.now() - started < 5000, `${name}: ${Date.now() - started} ms`);
  }
});
