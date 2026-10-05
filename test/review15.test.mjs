// What the fifteenth independent review found, in the fixes of the
// fourteenth review (4 October 2026). Each fault is fixed and each is a
// test here. The review also found fixes of the fourteenth review that no
// test held in place; the tests marked "held in place" do so.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBook, entryLine, fromBase64url, openChecker, openRecorder, recordTools, thumbprint, toBase64url, writeAcknowledgement } from '../src/index.js';
import { makeStampService } from './helpers/stamp.mjs';
import { START, makeWorld } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const MINUTE = 60 * 1000;
const ORDER = 'supplies.order';
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });
const stampOf = async (service, cancel, after = 5000) => toBase64url(await service.stamp(fromBase64url(cancel.fingerprint), cancel.when + after));
const afterCancellation = (r) => r.entries.filter((e) => e.kind === 'stub' && e.breaches.some((b) => b.code === 'after-cancellation')).length;

// A world with a clock that can be made to fail, and a writer for its agent.
async function setUp({ fields, trusted = false } = {}) {
  const w = await makeWorld(fields ? { fields } : undefined);
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const state = { clock: START + HOUR, fail: false };
  const now = () => {
    if (state.fail) throw new Error('the clock failed');
    return state.clock;
  };
  const service = await makeStampService();
  const trust = trusted ? { stampServices: [service.fingerprint] } : {};
  const open = (book = w.book(), cancellations = undefined) =>
    openRecorder({ book, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now, options: cancellations ? { ...trust, cancellations } : trust });
  const cancel = async (when) => {
    const c = await w.cancel({ when });
    w.entries.pop();
    return c;
  };
  return { w, issuerKeys, state, service, trust, open, cancel };
}

// --- the stub writer ---

test('finding 1: a list with a gap beside a cancellation does not lose it, nor its sound time-stamp', async () => {
  for (const gap of ['in the time-stamps', 'in the acknowledgements']) {
    for (const clockFails of [true, false]) {
      const s = await setUp({ trusted: true });
      const writer = await s.open();
      const cancel = await s.cancel(s.state.clock);
      const stamp = await stampOf(s.service, cancel);
      // eslint-disable-next-line no-sparse-arrays
      const entry = gap === 'in the time-stamps' ? { cancellation: cancel.record, stamps: [, stamp] } : { cancellation: cancel.record, stamps: [stamp], acknowledgements: new Array(1) };
      const where = `${gap}, ${clockFails ? 'the clock failing' : 'the clock working'}`;
      s.state.fail = clockFails;
      const e = await writer.add(entry).catch((x) => x);
      s.state.fail = false;
      assert.ok(e instanceof Error, where);
      if (!clockFails) assert.ok(e.acknowledgement, where);
      const held = writer.cancellations();
      const r = await checkBook(writer.book(), { issuerKeys: s.issuerKeys, ...s.trust, cancellations: held.length ? held : undefined });
      assert.equal(r.summary.problemFound, false, where);
      const inBook = r.entries.find((x) => x.kind === 'cancellation');
      assert.equal(inBook ? 1 : held.length, 1, where);
      assert.equal(inBook ? inBook.stamps.length : held[0].stamps.length, 1, where);
      // A writer opened again from what this one hands back takes no action.
      const again = await s.open(writer.book(), held.length ? held : undefined);
      assert.equal((await again.act(order(1), async () => null)).done, false, where);
    }
  }
  // The root of it: a list with a gap is not JSON, and is not written as a line.
  assert.throws(() => entryLine({ refusal: [1, , 2] }), { code: 'payload-not-canonical' });
});

test('finding 2: a time-stamp the writer does not count does not keep out one it counts, handed over later', async () => {
  for (const route of ['the clock fails', 'dated ahead', 'kept without a time-stamp']) {
    const s = await setUp({ trusted: true });
    const other = await makeStampService();
    const writer = await s.open();
    assert.equal((await writer.act(order(1), async () => null)).done, true);
    const cancel = await s.cancel(route === 'the clock fails' ? s.state.clock - 2 * MINUTE : s.state.clock + 10 * MINUTE);
    if (route === 'kept without a time-stamp') await writer.add({ cancellation: cancel.record }).catch(() => null);
    s.state.fail = route === 'the clock fails';
    await assert.rejects(writer.add({ cancellation: cancel.record, stamps: [await stampOf(other, cancel)] }));
    s.state.fail = false;
    const counted = await stampOf(s.service, cancel);
    await writer.add({ cancellation: cancel.record, stamps: [counted] }).catch(() => null);
    if (route !== 'the clock fails') {
      assert.deepEqual(writer.cancellations()[0].stamps.length, 2, route);
      assert.equal(writer.cancellations()[0].stamps[0], counted, route);
      s.state.clock += 20 * MINUTE;
      await writer.act(order(1), async () => null);
    }
    const r = await checkBook(writer.book(), { issuerKeys: s.issuerKeys, ...s.trust });
    assert.equal(r.summary.problemFound, false, route);
    assert.equal(r.entries.find((x) => x.kind === 'cancellation').stamps.length, 2, route);
    // Dated before the stub, the cancellation now marks it; the time-stamp the writer does not count alone did not.
    if (route === 'the clock fails') assert.equal(afterCancellation(r), 1);
  }
});

test('finding 2: where a copy holds four time-stamps, one the writer counts takes the place of one it does not', async () => {
  const s = await setUp({ trusted: true });
  const other = await makeStampService();
  const writer = await s.open();
  const cancel = await s.cancel(s.state.clock + 10 * MINUTE);
  const four = [];
  for (let i = 1; i <= 4; i++) four.push(await stampOf(other, cancel, i * 1000));
  await assert.rejects(writer.add({ cancellation: cancel.record, stamps: four }));
  assert.equal(writer.cancellations()[0].stamps.length, 4);
  const counted = await stampOf(s.service, cancel);
  await assert.rejects(writer.add({ cancellation: cancel.record, stamps: [counted] }));
  assert.deepEqual(writer.cancellations()[0].stamps, [counted, ...four.slice(0, 3)]);
  assert.equal((await writer.check()).summary.problemFound, false);
});

test('finding 2: of the time-stamps handed over with a cancellation, the sound ones are kept', async () => {
  for (const clockFails of [true, false]) {
    const s = await setUp({ trusted: true });
    const writer = await s.open();
    const cancel = await s.cancel(s.state.clock + 10 * MINUTE);
    const stamp = await stampOf(s.service, cancel);
    s.state.fail = clockFails;
    await assert.rejects(writer.add({ cancellation: cancel.record, stamps: ['AAAA', stamp, stamp] }));
    s.state.fail = false;
    assert.deepEqual(writer.cancellations()[0].stamps, [stamp]);
  }
});

test('finding 3: a clock that fails keeps the acknowledgements handed over with a cancellation', async () => {
  const s = await setUp({ fields: { passes: 1 } });
  const p = await s.w.pass({ when: START });
  const cancel = await s.cancel(s.state.clock + 10 * MINUTE);
  const helper = (await writeAcknowledgement({ slip: s.w.slipFingerprint, cancellation: cancel.fingerprint, pass: p.fingerprint, when: s.state.clock }, p.helper.privateKeys)).record;
  const first = await s.open();
  const own = (await first.add({ cancellation: cancel.record, acknowledgements: [helper] }).catch((e) => e)).acknowledgement;
  const [copy] = first.cancellations();
  assert.deepEqual(copy.acknowledgements, [own, helper]);
  // A second writer, opened from the book alone, is handed that copy while its clock fails.
  const second = await s.open();
  s.state.fail = true;
  await assert.rejects(second.add(copy), /the clock failed/);
  s.state.fail = false;
  assert.deepEqual(second.cancellations()[0].acknowledgements, [own, helper]);
  assert.deepEqual((await second.add(copy).catch((e) => e)).acknowledgement, own);
  assert.equal((await second.check()).summary.problemFound, false);
});

test('finding 3: a copy never holds two acknowledgements of the writer\'s own agent, and the first is the one taken', async () => {
  const s = await setUp();
  const cancel = await s.cancel(s.state.clock + 10 * MINUTE);
  const sign = async (when) => (await writeAcknowledgement({ slip: s.w.slipFingerprint, cancellation: cancel.fingerprint, when }, s.w.agent.privateKeys)).record;
  const one = await sign(s.state.clock);
  const two = await sign(s.state.clock + MINUTE);
  const writer = await s.open();
  const e = await writer.add({ cancellation: cancel.record, acknowledgements: [one, two] }).catch((x) => x);
  assert.deepEqual(e.acknowledgement, one);
  assert.deepEqual(writer.cancellations()[0].acknowledgements, [one]);
  // Given when a writer is opened, too: the first.
  const opened = await s.open(s.w.book(), [{ cancellation: cancel.record, acknowledgements: [two, one] }]);
  assert.deepEqual((await opened.add({ cancellation: cancel.record }).catch((x) => x)).acknowledgement, two);
});

test('finding 3: the writer\'s own acknowledgement is found among more than four', async () => {
  const s = await setUp({ fields: { passes: 1 } });
  const cancel = await s.cancel(s.state.clock + 10 * MINUTE);
  const helpers = [];
  for (let i = 0; i < 4; i++) {
    const p = await s.w.pass({ when: START });
    helpers.push((await writeAcknowledgement({ slip: s.w.slipFingerprint, cancellation: cancel.fingerprint, pass: p.fingerprint, when: s.state.clock }, p.helper.privateKeys)).record);
  }
  const own = (await writeAcknowledgement({ slip: s.w.slipFingerprint, cancellation: cancel.fingerprint, when: s.state.clock }, s.w.agent.privateKeys)).record;
  const writer = await s.open();
  const e = await writer.add({ cancellation: cancel.record, acknowledgements: [...helpers, own] }).catch((x) => x);
  assert.deepEqual(e.acknowledgement, own);
  assert.deepEqual(writer.cancellations()[0].acknowledgements, [own, ...helpers.slice(0, 3)]);
});

test('finding 4: a copy given at opening is held as plain data, as it was checked', async () => {
  const s = await setUp({ trusted: true });
  const cancel = await s.cancel(s.state.clock + 10 * MINUTE);
  const stamp = await stampOf(s.service, cancel);
  const own = (await writeAcknowledgement({ slip: s.w.slipFingerprint, cancellation: cancel.fingerprint, when: s.state.clock }, s.w.agent.privateKeys)).record;
  for (const member of ['stamps', 'acknowledgements']) {
    const copy = Object.defineProperty({ cancellation: cancel.record }, member, { value: member === 'stamps' ? [stamp] : [own], enumerable: false });
    const writer = await s.open(s.w.book(), [copy]);
    const handed = writer.cancellations();
    assert.deepEqual(Object.keys(handed[0]), ['cancellation', member]);
    assert.deepEqual(await writer.check(), await checkBook(writer.book(), { issuerKeys: s.issuerKeys, ...s.trust, cancellations: handed }));
    if (member === 'acknowledgements') assert.deepEqual((await writer.add({ cancellation: cancel.record }).catch((x) => x)).acknowledgement, own);
  }
});

test('finding 6: the error says so where the cancellation is in the book after the call', async () => {
  const s = await setUp({ trusted: true });
  const writer = await s.open();
  const cancel = await s.cancel(s.state.clock + 400 * 1000);
  await assert.rejects(writer.add({ cancellation: cancel.record }), { code: 'record-not-sound' });
  s.state.clock += 500 * 1000;
  const e = await writer.add({ cancellation: cancel.record, stamps: [await stampOf(s.service, cancel)] }).catch((x) => x);
  assert.match(e.message, /already holds this cancellation.*written into the book in this call/);
  const r = await checkBook(writer.book(), { issuerKeys: s.issuerKeys, ...s.trust });
  assert.deepEqual(r.entries.map((x) => x.kind), ['slip', 'cancellation', 'acknowledgement']);
  assert.equal(r.entries[1].stamps.length, 1);
  // Handed over once more: the book already held it before the call.
  const again = await writer.add({ cancellation: cancel.record }).catch((x) => x);
  assert.match(again.message, /already holds this cancellation/);
  assert.doesNotMatch(again.message, /in this call/);
  assert.deepEqual(again.acknowledgement, e.acknowledgement);
});

test('finding 7: an acknowledgement that waits to be written is handed back, and written by a writer opened again', async () => {
  const s = await setUp();
  // A stub dated ten minutes ahead of the writer's clock: the acknowledgement may not be dated before it.
  await s.w.add({ when: s.state.clock + 10 * MINUTE });
  const writer = await s.open();
  const cancel = await s.cancel(s.state.clock);
  const { acknowledgement } = await writer.add(cancel.entry);
  assert.ok(acknowledgement);
  assert.equal((await writer.check()).summary.counts.acknowledgements, 0);
  const held = writer.cancellations();
  assert.deepEqual(held, [{ cancellation: cancel.record, acknowledgements: [acknowledgement] }]);
  assert.deepEqual(await writer.check(), await checkBook(writer.book(), { issuerKeys: s.issuerKeys, cancellations: held }));
  // A second writer, once the clock has come to the acknowledgement's date, writes the same one.
  s.state.clock += 20 * MINUTE;
  const again = await s.open(writer.book(), held);
  await again.act(order(1), async () => null);
  const r = await checkBook(again.book(), { issuerKeys: s.issuerKeys });
  assert.equal(r.summary.problemFound, false);
  assert.deepEqual(JSON.parse(again.book().trim().split('\n').at(-1)), { acknowledgement });
});

test('finding 8: a cancellation that cannot be kept while the clock fails: the error says so', async () => {
  const s = await setUp();
  const writer = await s.open();
  for (let i = 0; i < 16; i++) await writer.add((await s.cancel(s.state.clock + (10 + i) * MINUTE)).entry).catch(() => null);
  assert.equal(writer.cancellations().length, 16);
  s.state.fail = true;
  const e = await writer.add((await s.cancel(s.state.clock + 30 * MINUTE)).entry).catch((x) => x);
  s.state.fail = false;
  assert.match(e.message, /clock failed.*is not kept/);
  assert.match(e.cause.message, /the clock failed/);
});

test('held in place: acknowledgements of other agents go with a copy the writer already holds, or was given at opening, and never past four', async () => {
  const s = await setUp({ fields: { passes: 1 } });
  const cancel = await s.cancel(s.state.clock + 10 * MINUTE);
  const helpers = [];
  for (let i = 0; i < 4; i++) {
    const p = await s.w.pass({ when: START });
    helpers.push((await writeAcknowledgement({ slip: s.w.slipFingerprint, cancellation: cancel.fingerprint, pass: p.fingerprint, when: s.state.clock }, p.helper.privateKeys)).record);
  }
  // Kept by "add" first, then handed over again with a helper's acknowledgement.
  const writer = await s.open();
  const own = (await writer.add({ cancellation: cancel.record }).catch((e) => e)).acknowledgement;
  await writer.add({ cancellation: cancel.record, acknowledgements: [helpers[0]] }).catch(() => null);
  assert.deepEqual(writer.cancellations()[0].acknowledgements, [own, helpers[0]]);
  // Given at opening, then handed over with a helper's acknowledgement.
  const opened = await s.open(s.w.book(), [{ cancellation: cancel.record }]);
  await opened.add({ cancellation: cancel.record, acknowledgements: [helpers[0]] }).catch(() => null);
  assert.equal(opened.cancellations()[0].acknowledgements.length, 2);
  assert.ok(opened.cancellations()[0].acknowledgements.some((a) => a.payload === helpers[0].payload));
  // A copy that holds four: another agent's does not push it past four, and the last of the others gives way to the writer's own.
  const full = await s.open(s.w.book(), [{ cancellation: cancel.record, acknowledgements: helpers.slice(0, 3).concat(own) }]);
  await full.add({ cancellation: cancel.record, acknowledgements: [helpers[3]] }).catch(() => null);
  assert.deepEqual(full.cancellations()[0].acknowledgements, [...helpers.slice(0, 3), own]);
  const four = await s.open(s.w.book(), [{ cancellation: cancel.record, acknowledgements: helpers }]);
  const e = await four.add({ cancellation: cancel.record }).catch((x) => x);
  assert.deepEqual(four.cancellations()[0].acknowledgements, [...helpers.slice(0, 3), e.acknowledgement]);
});

test('held in place: a copy given at opening takes the time-stamp handed over later, whether or not the clock works', async () => {
  for (const clockFails of [true, false]) {
    const s = await setUp({ trusted: true });
    const cancel = await s.cancel(s.state.clock + 10 * MINUTE);
    const writer = await s.open(s.w.book(), [{ cancellation: cancel.record }]);
    const stamp = await stampOf(s.service, cancel);
    s.state.fail = clockFails;
    await assert.rejects(writer.add({ cancellation: cancel.record, stamps: [stamp] }));
    s.state.fail = false;
    assert.deepEqual(writer.cancellations()[0].stamps, [stamp]);
  }
});

// --- the checker ---

test('finding 5: options that a whole check does not read, or that have a gap, are read the same by a carried checker', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const cancel = await w.cancel({ when: START + 2 * HOUR });
  w.entries.pop();
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const unreadable = (enumerable) => Object.defineProperty({ cancellation: cancel.record }, 'note', {
    enumerable,
    get() {
      throw new Error('not to be read');
    },
  });
  for (const enumerable of [false, true]) {
    const options = () => ({ issuerKeys, cancellations: [unreadable(enumerable)] });
    const whole = await checkBook(w.book(), options());
    const carried = await (await openChecker(w.book(), options())).result();
    assert.deepEqual(carried, whole);
    assert.equal(whole.summary.problemFound, enumerable);
  }
  // The stub writer opens where the whole check finds no problem.
  await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => START + HOUR, options: { cancellations: [unreadable(false)] } });
  // eslint-disable-next-line no-sparse-arrays
  for (const options of [{ issuerKeys, blocks: new Array(1) }, { issuerKeys, blocks: ['a'.repeat(64), , 'b'.repeat(64)] }, { issuerKeys, cancellations: [{ cancellation: cancel.record, stamps: [, 'AAAA'] }] }]) {
    const whole = await checkBook(w.book(), options);
    const carried = await (await openChecker(w.book(), options)).result();
    assert.deepEqual(carried.problems.map((p) => p.code), ['bad-field']);
    assert.deepEqual(whole.problems.map((p) => p.code), ['bad-field']);
  }
});

// --- the connector for an agent's tools (held in place) ---

test('held in place: what a tool\'s "amount" gives, and what its "details" give, are each copied', async () => {
  for (const which of ['amount', 'details']) {
    const w = await makeWorld({ fields: { requires: [{ above: 20, action: ORDER, need: 'approval', unit: 'GBP' }] } });
    const issuerKeys = [await thumbprint(w.passkey.key)];
    const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => START + HOUR });
    let kept;
    let ran = 0;
    const spec = { action: ORDER, with: 'supplier', run: () => ++ran };
    if (which === 'amount') spec.amount = (o) => (kept = { unit: 'GBP', value: o.total });
    else {
      spec.amount = { unit: 'GBP', value: 45 };
      spec.details = () => (kept = [{ name: 'order', sha256: 'A'.repeat(43) }]);
    }
    spec.approve = async (request) => {
      // The tool changes what it gave, and has the person approve the changed action.
      if (which === 'amount') kept.value = 46;
      else kept[0].sha256 = 'E'.repeat(43);
      const changed = which === 'amount' ? { amount: { unit: 'GBP', value: 46 } } : { details: [{ name: 'order', sha256: 'E'.repeat(43) }] };
      return w.approve({ slip: w.slipFingerprint, ...request, ...changed, when: START + HOUR });
    };
    const tools = recordTools(writer, { placeOrder: spec });
    await assert.rejects(tools.placeOrder({ total: 45 }), { name: 'NotTaken' }, which);
    assert.equal(ran, 0, which);
  }
});

test('held in place: a tool\'s "run" is read once', async () => {
  const w = await makeWorld({ fields: { actions: [ORDER, 'provared.data.read'] } });
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => START + HOUR });
  let reads = 0;
  const spec = {
    action: 'provared.data.read',
    get run() {
      return reads++ === 0 ? () => 'the first' : () => 'another';
    },
  };
  const tools = recordTools(writer, { tool: spec });
  assert.equal(await tools.tool({ q: 1 }), 'the first');
  assert.equal(reads, 1);
});
