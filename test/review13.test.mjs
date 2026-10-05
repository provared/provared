// What the thirteenth independent review found, in the fixes of the
// eleventh and twelfth reviews (4 October 2026). Each fault is fixed, or
// stated as a limit, and each is a test here.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { argumentsFingerprint, checkBook, formatTime, fromBase64url, openChecker, openRecorder, recordTools, thumbprint, toBase64url } from '../src/index.js';
import { makeStampService } from './helpers/stamp.mjs';
import { START, makeWorld } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const MINUTE = 60 * 1000;
const ORDER = 'supplies.order';
const READ = 'provared.data.read';
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });
const whenOf = (record) => JSON.parse(Buffer.from(record.payload, 'base64url').toString()).when;
const kindsOf = async (writer) => (await writer.check()).entries.map((e) => e.kind).join(',');

// --- the stub writer ---

test('finding 1: the stub writer never dates its acknowledgement before a pass that its agent handed on', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  let clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock });
  // A pass dated 200 seconds ahead of the clock, as the writer allows, and the helper's stub under it.
  const p = await w.pass({ when: clock + 200 * 1000 });
  await writer.add({ pass: p.record });
  const h = await p.add({ when: clock + 200 * 1000 });
  await writer.add(h.entry);
  // Ten seconds later the person cancels.
  clock += 10 * 1000;
  const cancel = await w.cancel({ when: clock });
  w.entries.pop();
  const { acknowledgement } = await writer.add(cancel.entry);
  assert.equal(whenOf(acknowledgement), formatTime(START + HOUR + 200 * 1000));
  // The honest pass and the stub under it are not reported, with the person's copy and the acknowledgement.
  const before = writer.book().split('\n').filter(Boolean).slice(0, 3).join('\n') + '\n';
  const r = await checkBook(before, { issuerKeys, cancellations: [{ cancellation: cancel.record, acknowledgements: [acknowledgement] }] });
  assert.deepEqual(r.problems, []);
  assert.deepEqual(r.entries.map((e) => e.breaches.length), [0, 0, 0]);
  assert.equal(r.summary.withinSlips, true);
});

test('finding 3: a cancellation given when the writer was opened is handed back with the acknowledgement signed for it', async () => {
  const w = await makeWorld();
  let clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const cancel = await w.cancel({ when: clock + 10 * MINUTE });
  w.entries.pop();
  const open = (book, options) => openRecorder({ book, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock, options });
  const first = await open(w.book(), { cancellations: [cancel.entry] });
  const e1 = await first.add(cancel.entry).catch((e) => e);
  assert.ok(e1.acknowledgement);
  const handed = first.cancellations();
  assert.deepEqual(handed.map((c) => (c.acknowledgements ?? []).length), [1]);
  // A writer opened again with what was handed back hands back the same acknowledgement.
  clock += 2 * MINUTE;
  const again = await open(first.book(), { cancellations: handed });
  const e2 = await again.add(cancel.entry).catch((e) => e);
  assert.deepEqual(e2.acknowledgement, e1.acknowledgement);
});

test('finding 4: a cancellation given at opening takes the time-stamp it is handed over with later', async () => {
  const w = await makeWorld();
  let clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const cancel = await w.cancel({ when: clock + 10 * MINUTE });
  w.entries.pop();
  const service = await makeStampService();
  const stamped = { cancellation: cancel.record, stamps: [toBase64url(await service.stamp(fromBase64url(cancel.fingerprint), cancel.when + 5000))] };
  const trust = { stampServices: [service.fingerprint] };
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock, options: { ...trust, cancellations: [{ cancellation: cancel.record }] } });
  await assert.rejects(writer.add(stamped), { code: 'record-not-sound' });
  assert.deepEqual(writer.cancellations().map((c) => Object.hasOwn(c, 'stamps')), [true]);
  // Once its date has come it is written into the book, with the time-stamp.
  clock += 20 * MINUTE;
  assert.equal((await writer.act(order(1), async () => null)).done, false);
  const r = await checkBook(writer.book(), { issuerKeys, ...trust });
  const c = r.entries.find((e) => e.kind === 'cancellation');
  assert.equal(c.stamps.length, 1);
  assert.equal(c.stampedAt, formatTime(cancel.when + 5000));
});

test('finding 4: handed the form that "cancellations" gives back, the writer adds the cancellation with its time-stamps', async () => {
  const w = await makeWorld();
  let clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const service = await makeStampService();
  const trust = { stampServices: [service.fingerprint] };
  const cancel = await w.cancel({ when: clock });
  w.entries.pop();
  const form = { cancellation: cancel.record, stamps: [toBase64url(await service.stamp(fromBase64url(cancel.fingerprint), cancel.when + 5000))], acknowledgements: [] };
  clock += MINUTE;
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock, options: trust });
  const e = await writer.add(form).catch((x) => x);
  assert.equal(e.code, 'record-not-sound');
  assert.match(e.message, /with its time-stamps/);
  assert.ok(e.acknowledgement);
  const r = await checkBook(writer.book(), { issuerKeys, ...trust });
  assert.equal(r.summary.problemFound, false);
  assert.equal(r.entries.find((x) => x.kind === 'cancellation').stamps.length, 1);
});

test('finding 4: an acknowledgement of the writer\'s own agent that comes with a cancellation is the one it hands back', async () => {
  const w = await makeWorld();
  let clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const open = () => openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock });
  const cancel = await w.cancel({ when: clock + 10 * MINUTE });
  w.entries.pop();
  const first = await open();
  const e1 = await first.add(cancel.entry).catch((e) => e);
  const [form] = first.cancellations();
  assert.deepEqual(form.acknowledgements, [e1.acknowledgement]);
  // Another writer, opened from the book alone, is handed that form through "add".
  clock += 2 * MINUTE;
  const second = await open();
  const e2 = await second.add(form).catch((e) => e);
  assert.deepEqual(e2.acknowledgement, e1.acknowledgement);
});

test('finding 5: a clock that fails while the person\'s cancellation is handed over does not lose it', async () => {
  const w = await makeWorld();
  const clock = START + HOUR;
  let fail = false;
  const now = () => {
    if (fail) throw new Error('the clock failed');
    return clock;
  };
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now });
  const cancel = await w.cancel({ when: clock });
  fail = true;
  await assert.rejects(writer.add(cancel.entry), /the clock failed/);
  fail = false;
  // The writer holds it, and takes no action.
  assert.equal(writer.cancellations().length, 1);
  let ran = 0;
  const out = await writer.act(order(10), async () => ++ran);
  assert.equal(out.done, false);
  assert.equal(ran, 0);
  // It is in the book from the next call on.
  assert.equal((await writer.check()).summary.counts.cancellations, 1);
  assert.equal((await checkBook(writer.book(), { issuerKeys })).summary.problemFound, false);
});

test('finding 7: a clock that gives no time is a clock that failed', async () => {
  const w = await makeWorld();
  let clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock });
  const book = writer.book();
  for (const broken of [NaN, Infinity, undefined, '12']) {
    clock = broken;
    let ran = 0;
    await assert.rejects(writer.act(order(10), async () => ++ran, { when: START + 100 * HOUR }), { code: 'bad-field' });
    await assert.rejects(writer.record(order(1), { when: START + 120 * HOUR }), { code: 'bad-field' });
    assert.equal(ran, 0);
  }
  assert.equal(writer.book(), book);
});

test('finding 8: an acknowledgement that is dated ahead of the clock follows its cancellation into the book later', async () => {
  const w = await makeWorld();
  let clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock });
  // A stub dated 250 seconds ahead; the clock steps back 100 seconds; then the cancellation.
  await writer.act(order(10), async () => null, { when: clock + 250 * 1000 });
  clock -= 100 * 1000;
  const cancel = await w.cancel({ when: clock });
  const got = await writer.add(cancel.entry);
  assert.equal(whenOf(got.acknowledgement), formatTime(START + HOUR + 250 * 1000));
  assert.equal(await kindsOf(writer), 'slip,stub,cancellation');
  clock += 10 * MINUTE;
  assert.equal((await writer.act(order(1), async () => null)).done, false);
  assert.equal(await kindsOf(writer), 'slip,stub,cancellation,acknowledgement');
  assert.equal((await checkBook(writer.book(), { issuerKeys })).summary.problemFound, false);
});

test('a writer opened with the person\'s cancellation of its slip takes no action', async () => {
  const w = await makeWorld();
  const clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const cancel = await w.cancel({ when: clock + 10 * MINUTE });
  w.entries.pop();
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock, options: { cancellations: [cancel.entry] } });
  let ran = 0;
  assert.equal((await writer.act(order(1), async () => ++ran)).done, false);
  assert.equal(ran, 0);
});

// --- the connector for an agent's tools ---

test('finding 2: a tool\'s own function cannot change what the tool is recorded as', async () => {
  const w = await makeWorld({ fields: { actions: [ORDER, READ], limits: [{ action: ORDER, max: 20, unit: 'GBP' }] } });
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => START + HOUR });
  let ran = 0;
  const seen = [];
  const spec = {
    action: ORDER,
    with: 'supplier',
    amount: { unit: 'GBP', value: 15 },
    run() {
      ran++;
      seen.push(this);
      return 'ordered';
    },
    details(args) {
      seen.push(this);
      return [{ name: 'arguments', sha256: 'A'.repeat(43) }];
    },
  };
  const tools = recordTools(writer, { placeOrder: spec });
  assert.equal(await tools.placeOrder({ item: 'pens' }), 'ordered');
  // No function of the tool is handed its description.
  assert.deepEqual(seen, [undefined, undefined]);
  // The second order is over the limit, as the first was recorded as what it was.
  await assert.rejects(tools.placeOrder({ item: 'toner' }), { name: 'NotTaken' });
  assert.equal(ran, 1);
  const r = await checkBook(writer.book(), { issuerKeys });
  assert.deepEqual(r.entries.slice(1).map((e) => [e.content.action, e.content.amount.value]), [[ORDER, 15]]);
});

test('finding 10: 0 and -0 share a fingerprint, as RFC 8785 writes both as 0; bad arguments are refused through the promise', async () => {
  assert.equal(await argumentsFingerprint({ n: -0 }), await argumentsFingerprint({ n: 0 }));
  const promise = argumentsFingerprint([1, , 3]);
  assert.ok(promise instanceof Promise);
  await assert.rejects(promise, { code: 'bad-field' });
});

// --- the checker ---

test('finding 6: the words a stub is given do not depend on the order of the acknowledgements', async () => {
  const w = await makeWorld({ fields: { passes: 2 } });
  const cancel = await w.cancel({ when: START + HOUR });
  w.entries.pop();
  const agentAck = await w.acknowledge(cancel.fingerprint, { when: START + HOUR + MINUTE });
  w.entries.pop();
  // The pass is handed on after the agent acknowledged; the helper's stub is dated after the helper acknowledged too.
  const p = await w.pass({ when: START + 2 * HOUR });
  const helperAck = await w.acknowledge(cancel.fingerprint, { when: START + 2 * HOUR + MINUTE, pass: p.fingerprint, signer: p.helper.privateKeys });
  w.entries.pop();
  await p.add({ when: START + 3 * HOUR });
  const book = w.book();
  const a = await checkBook(book, { cancellations: [{ ...cancel.entry, acknowledgements: [agentAck.record, helperAck.record] }] });
  const b = await checkBook(book, { cancellations: [{ ...cancel.entry, acknowledgements: [helperAck.record, agentAck.record] }] });
  assert.deepEqual(a.problems, []);
  assert.deepEqual(a.entries, b.entries);
  assert.match(a.entries[2].breaches[0].message, /^This stub is dated after/);
});

test('finding 9: a member of the options that is not enumerable is read as a whole check reads it', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  await w.seal({ when: START + 10 * MINUTE });
  await w.add({ when: START + 3 * HOUR });
  const cancel = await w.cancel({ when: START + 2 * HOUR, stampTime: START + 2 * HOUR + 5000 });
  w.entries.pop();
  const copy = { cancellation: cancel.record };
  Object.defineProperty(copy, 'stamps', { value: cancel.entry.stamps, enumerable: false });
  const options = { stampServices: [w.stampService.fingerprint], cancellations: [copy] };
  const whole = await checkBook(w.book(), options);
  const carried = await (await openChecker(w.book(), options)).result();
  assert.deepEqual(carried, whole);
  assert.equal(whole.held[0].stampedAt, formatTime(START + 2 * HOUR + 5000));
});
