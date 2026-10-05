// What the seventeenth independent review found, in the fixes of the
// sixteenth review (4 October 2026). Each fault is fixed and each is a
// test here.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBook, checkShow, entryLine, makeShow, openChecker, openRecorder, thumbprint, writeAcknowledgement } from '../src/index.js';
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
  const open = (book = w.book(), cancellations = undefined) =>
    openRecorder({ book, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now, options: cancellations ? { cancellations } : {} });
  const cancel = async (when) => {
    const c = await w.cancel({ when });
    w.entries.pop();
    return c;
  };
  const sameAsWhole = async (writer) => assert.deepEqual(await writer.check(), await checkBook(writer.book(), { issuerKeys, cancellations: writer.cancellations() }));
  return { w, issuerKeys, state, open, cancel, sameAsWhole };
}

// --- the stub writer ---

test('finding 1: a cancellation wrapped in a Proxy stops the writer', async () => {
  for (const ahead of [false, true]) {
    for (const wrap of ['the record', 'its signatures']) {
      const s = await setUp();
      const writer = await s.open();
      const cancel = await s.cancel(s.state.clock + (ahead ? 10 * MINUTE : 0));
      const record = wrap === 'the record' ? new Proxy(cancel.record, {}) : { ...cancel.record, signatures: new Proxy(cancel.record.signatures, {}) };
      await writer.add({ cancellation: record }).catch(() => null);
      const where = `${wrap}, ${ahead ? 'dated ahead' : 'dated now'}`;
      assert.equal((await writer.act(order(1), async () => null)).done, false, where);
      const held = writer.cancellations();
      const again = await s.open(writer.book(), held.length ? held : undefined);
      assert.equal((await again.act(order(1), async () => null)).done, false, where);
    }
  }
});

test('finding 2: an acknowledgement that waits, carried by a copy given at opening, is not cut off', async () => {
  const s = await setUp();
  // A stub dated ten minutes ahead of the clock: the acknowledgement may not be dated before it, so it waits.
  await s.w.add({ when: s.state.clock + 10 * MINUTE });
  const first = await s.open();
  const cancel = await s.cancel(s.state.clock);
  const { acknowledgement } = await first.add(cancel.entry);
  const [carrying] = first.cancellations();
  assert.deepEqual(carrying.acknowledgements, [acknowledgement]);
  // A second writer is given that copy after fifteen copies of another slip's cancellations, and keeps one more of its own.
  const other = await makeWorld();
  s.issuerKeys.push(await thumbprint(other.passkey.key));
  const others = [];
  for (let i = 0; i < 15; i++) {
    const c = await other.cancel({ when: s.state.clock + (30 + i) * MINUTE });
    other.entries.pop();
    others.push({ cancellation: c.record });
  }
  const book = first.book().trimEnd().split('\n');
  book.splice(1, 0, entryLine({ slip: other.slip }));
  const second = await s.open(book.join('\n') + '\n', [...others, carrying]);
  await second.add((await s.cancel(s.state.clock + 20 * MINUTE)).entry).catch(() => null);
  const held = second.cancellations();
  assert.equal(held.length, 16);
  assert.ok(held.some((c) => c.cancellation.payload === cancel.record.payload && c.acknowledgements[0].payload === acknowledgement.payload));
  await s.sameAsWhole(second);
  // A writer opened again from what the second hands back gives the same acknowledgement.
  const third = await s.open(second.book(), held);
  assert.deepEqual((await third.add(cancel.entry).catch((e) => e)).acknowledgement, acknowledgement);
});

test('finding 2: a copy given at opening that carries a waiting acknowledgement takes up room', async () => {
  const s = await setUp();
  await s.w.add({ when: s.state.clock + 10 * MINUTE });
  const first = await s.open();
  const cancel = await s.cancel(s.state.clock);
  const { acknowledgement } = await first.add(cancel.entry);
  const [carrying] = first.cancellations();
  const second = await s.open(first.book(), [carrying]);
  const messages = [];
  for (let i = 0; i < 16; i++) messages.push((await second.add((await s.cancel(s.state.clock + (20 + i) * MINUTE)).entry).catch((e) => e)).message);
  assert.doesNotMatch(messages[14], /is not kept/);
  assert.match(messages[15], /is not kept/);
  assert.ok(second.cancellations().some((c) => c.cancellation.payload === cancel.record.payload && c.acknowledgements[0].payload === acknowledgement.payload));
});

test('finding 2: a copy of its own slip given at opening is never crowded out silently', async () => {
  const s = await setUp();
  const given = [];
  for (let i = 0; i < 16; i++) given.push({ cancellation: (await s.cancel(s.state.clock + (10 + i) * MINUTE)).record });
  const writer = await s.open(s.w.book(), given);
  const e = await writer.add((await s.cancel(s.state.clock + 40 * MINUTE)).entry).catch((x) => x);
  assert.match(e.message, /is not kept/);
  assert.deepEqual(writer.cancellations().map((c) => c.cancellation.payload).sort(), given.map((c) => c.cancellation.payload).sort());
});

test('an acknowledgement of the agent\'s own, handed over while the clock fails, is handed back and written later', async () => {
  const s = await setUp();
  const cancel = await s.w.cancel({ when: s.state.clock - 10 * MINUTE });
  const own = (await writeAcknowledgement({ slip: s.w.slipFingerprint, cancellation: cancel.fingerprint, when: s.state.clock - 9 * MINUTE }, s.w.agent.privateKeys)).record;
  const writer = await s.open();
  s.state.fail = true;
  await assert.rejects(writer.add({ cancellation: cancel.record, acknowledgements: [own] }), /the clock failed/);
  s.state.fail = false;
  assert.deepEqual(writer.cancellations(), [{ cancellation: cancel.record, acknowledgements: [own] }]);
  await s.sameAsWhole(writer);
  await writer.act(order(1), async () => null);
  assert.deepEqual(JSON.parse(writer.book().trimEnd().split('\n').at(-1)), { acknowledgement: own });
  assert.deepEqual(writer.cancellations(), []);
});

test('finding 3: a very long list of cancellations costs little when the writer is opened', async () => {
  const s = await setUp();
  const started = Date.now();
  await assert.rejects(s.open(s.w.book(), new Array(2 ** 28)), { code: 'record-not-sound' });
  assert.ok(Date.now() - started < 3000, `${Date.now() - started} ms`);
});

// --- the checker ---

test('finding 4: a whole check reads its options through the same copy as a carried checker', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  await w.add({ when: START });
  const cancel = await w.cancel({ when: START + 2 * HOUR });
  w.entries.pop();
  const own = (await writeAcknowledgement({ slip: w.slipFingerprint, cancellation: cancel.fingerprint, when: START + HOUR }, w.agent.privateKeys)).record;
  const issuer = await thumbprint(w.passkey.key);
  const walksNowhere = (list) => Object.defineProperty(list, Symbol.iterator, { value: function* () {} });
  const saysYes = (list) => Object.defineProperty(list, 'includes', { value: () => true });
  class Keys extends Array {
    includes() {
      return true;
    }
  }
  const shapes = {
    'a copy\'s acknowledgements that walk nowhere': () => ({ issuerKeys: [issuer], cancellations: [{ cancellation: cancel.record, acknowledgements: walksNowhere([own]) }] }),
    'disclosures that walk nowhere': () => ({ issuerKeys: [issuer], disclosures: { [w.slipFingerprint]: walksNowhere(['not a disclosure']) } }),
    'methods with their own "includes"': () => ({ issuerKeys: [issuer], withoutMethods: saysYes([]) }),
    'passkeys with their own "includes"': () => ({ issuerKeys: saysYes(['not this one']) }),
    'passkeys as a list of a class': () => ({ issuerKeys: Keys.from(['not this one']) }),
  };
  for (const [name, make] of Object.entries(shapes)) {
    const whole = await checkBook(w.book(), make());
    const carried = await (await openChecker(w.book(), make())).result();
    assert.deepEqual(carried, whole, name);
  }
  // A list that says yes to every passkey is read as the plain list it holds.
  assert.equal((await checkBook(w.book(), shapes['passkeys as a list of a class']())).summary.problemFound, true);
});

test('finding 5: an empty list of cancellations beside a Show is none', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const show = await makeShow(w.book(), [1]);
  const r = await checkShow(show, { cancellations: [] });
  assert.ok(!r.notes.some((n) => n.startsWith('Cancellations were handed over')));
});

test('finding 6: the list of trusted blocks holds at most 100,000', async () => {
  const w = await makeWorld();
  const block = 'a'.repeat(64);
  const at = async (n) => (await checkBook(w.book(), { blocks: new Array(n).fill(block) })).problems.map((p) => p.code);
  assert.deepEqual(await at(100000), []);
  assert.deepEqual(await at(100001), ['bad-field']);
});
