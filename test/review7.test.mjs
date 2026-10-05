// What the seventh independent review found, in how time-stamps are
// credited and in the stub writer (3 October 2026). Each fault is fixed,
// and each is a test here.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBook, checkShow, countersign, makeShow, thumbprint, toBase64url, fromBase64url, generateKeySet } from '../src/index.js';
import { START, makeWorld, openWriter } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const MINUTE = 60 * 1000;
const ORDER = 'supplies.order';

function codes(result) {
  const out = result.problems.map((p) => p.code);
  for (const e of result.entries) out.push(...e.problems.map((p) => p.code), ...e.breaches.map((b) => b.code));
  return out;
}
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });
const opened = async (w, more = {}) =>
  openWriter({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys: [await thumbprint(w.passkey.key)], ...more });

// --- time-stamps and dates ---

test('finding 1: a seal dated before a page it covers is reported in a Show, as in the whole book', async () => {
  const w = await makeWorld();
  await w.add({ when: START + 2 * HOUR });
  await w.seal({ when: START + HOUR, stampTime: START + 3 * HOUR });
  const trust = { stampServices: [w.stampService.fingerprint] };
  assert.deepEqual(codes(await checkBook(w.book(), trust)), ['time-went-backwards']);
  const show = await makeShow(w.book(), [0, 1], { seal: 2 });
  for (const options of [trust, {}]) {
    const r = await checkShow(show, options);
    assert.deepEqual(codes(r), ['time-went-backwards']);
    assert.equal(r.summary.intact, false);
  }
});

test('finding 7: an entry that failed its own check does not stand against a later seal, and one misdated entry does not excuse a seal from another', async () => {
  // A refusal dated hours after the time-stamp that covers it fails its check. The next seal is not blamed for it.
  const w = await makeWorld();
  await w.add({ when: START });
  await w.refuse({ when: START + 11 * HOUR });
  await w.seal({ when: START + 30 * MINUTE });
  await w.add({ when: START + 40 * MINUTE });
  await w.seal({ when: START + 45 * MINUTE });
  const r = await checkBook(w.book(), { stampServices: [w.stampService.fingerprint] });
  assert.deepEqual(codes(r), ['dated-after-stamp']);
  assert.deepEqual(r.entries[2].problems.map((p) => p.code), ['dated-after-stamp']);

  // A seal dated 10:00, time-stamped at 11:00, over a stub dated 10:30 and a refusal dated 12:00:
  // the refusal is dated after the time-stamp, which once excused the seal altogether. The seal is
  // still dated before the stub, and is reported. (A seal that fails its check credits no time-stamp,
  // so the refusal is not marked as well.)
  const v = await makeWorld();
  await v.add({ when: START + 90 * MINUTE });
  await v.refuse({ when: START + 3 * HOUR });
  await v.seal({ when: START + HOUR, stampTime: START + 2 * HOUR });
  const both = await checkBook(v.book(), { stampServices: [v.stampService.fingerprint] });
  assert.deepEqual(codes(both), ['time-went-backwards']);
  assert.equal(both.entries[3].kind, 'seal');
  assert.deepEqual(both.entries[3].problems.map((p) => p.code), ['time-went-backwards']);
});

test('finding 8: a time-stamp that this device cannot count raises no problem about dates', async () => {
  // A seal dated ten minutes after its own time-stamp.
  const w = await makeWorld();
  await w.add({ when: START });
  await w.seal({ when: START + 20 * MINUTE, stampTime: START + 10 * MINUTE });
  const trust = { stampServices: [w.stampService.fingerprint] };
  assert.ok(codes(await checkBook(w.book(), trust)).includes('dated-after-stamp'));
  const partial = await checkBook(w.book(), { ...trust, withoutMethods: ['SLH-DSA-SHA2-256s'] });
  assert.deepEqual(codes(partial), []);
  assert.equal(partial.summary.intact, false);
  assert.ok(partial.entries[2].notes.some((n) => /was not counted/.test(n)));
});

test('finding 9: where a service states the time, a block that states a time far behind does not make the seal fail', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  // The block states a time three hours before the seal's own date.
  const sealed = await w.seal({ when: START + 3 * HOUR, blockTime: START });
  const service = { stampServices: [w.stampService.fingerprint] };
  const blocks = { blocks: [sealed.block.fingerprint] };
  const both = await checkBook(w.book(), { ...service, ...blocks });
  assert.deepEqual(codes(both), []);
  assert.equal(both.summary.sealed.by, 'service');
  assert.deepEqual(codes(await checkBook(w.book(), service)), []);
  // With only the block named, nothing settles it, and the seal reads as dated after its time-stamp.
  assert.ok(codes(await checkBook(w.book(), blocks)).includes('dated-after-stamp'));
});

// --- the stub writer ---

test('finding 2: a cancellation that cannot be added still stops the stub writer, if the person signed it', async () => {
  for (const kind of ['dated ahead of the clock', 'a faulty time-stamp beside it']) {
    const w = await makeWorld();
    const recorder = await opened(w);
    const cancel = await w.cancel(kind === 'dated ahead of the clock' ? { when: START + 10 * HOUR } : { when: START + 30 * MINUTE, stampTime: START + 31 * MINUTE });
    if (kind !== 'dated ahead of the clock') {
      const other = await makeWorld();
      const foreign = await other.cancel();
      cancel.entry.stamps = [toBase64url(await w.stampService.stamp(fromBase64url(foreign.fingerprint), START + 31 * MINUTE))];
    }
    await assert.rejects(recorder.add(cancel.entry), (e) => e.code === 'record-not-sound' && /allows nothing more under that slip/.test(e.message), kind);
    let taken = false;
    const acted = await recorder.act(order(10), async () => (taken = true), { when: START + 40 * MINUTE });
    assert.equal(acted.done, false, kind);
    assert.equal(taken, false, kind);
    assert.deepEqual(acted.answer.breaches.map((b) => b.code), ['after-cancellation'], kind);
  }
  // A cancellation signed with another passkey stops nothing.
  const w = await makeWorld();
  const recorder = await opened(w);
  const other = await makeWorld();
  const forged = await w.cancel({ passkey: other.passkey, when: START + 10 * HOUR });
  await assert.rejects(recorder.add(forged.entry), (e) => e.code === 'record-not-sound' && !/allows nothing more/.test(e.message));
  assert.equal((await recorder.act(order(10), async () => null, { when: START + 40 * MINUTE })).done, true);
});

test('finding 3: the stub for an action is checked with the whole book before the action is taken', async () => {
  // Keys that are not the agent's: nothing is taken, and nothing is written.
  const w = await makeWorld();
  const stranger = await generateKeySet();
  const wrong = await opened(w, { privateKeys: stranger.privateKeys });
  let taken = 0;
  const refused = await wrong.act(order(10), async () => ++taken, { when: START });
  assert.equal(refused.done, false);
  assert.equal(taken, 0);
  assert.deepEqual(refused.answer.problems.map((p) => p.code), ['record-not-sound']);
  assert.equal(wrong.book(), w.book());

  // A stub of the writer's own chain that comes in through "add" moves its place on.
  const recorder = await opened(w);
  const outside = await w.add({ when: START });
  await recorder.add(outside.entry);
  const next = await recorder.act(order(10), async () => ++taken, { when: START + 10 * MINUTE });
  assert.equal(next.stub.seq, 1);

  // The other side is handed a copy of the stub: changing it changes nothing.
  const meddled = await recorder.act(order(10), async () => ++taken, {
    when: START + 20 * MINUTE,
    countersign: async (stub) => {
      const made = await countersign(stub, w.service.privateKeys, START + 21 * MINUTE);
      stub.signatures.length = 0;
      stub.payload = 'changed';
      return made;
    },
  });
  assert.equal(meddled.stub.countersignature.accepted, true);
  const r = await checkBook(recorder.book());
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.counts.stubs, 3);
});

test('finding 4: an approval that is not a record stops the action before it is taken', async () => {
  const w = await makeWorld();
  const recorder = await opened(w);
  for (const approval of [{ record: undefined }, { record: 'text' }, {}, { record: { payload: 'not base64url!' } }]) {
    let taken = false;
    const acted = await recorder.act(order(10), async () => (taken = true), { when: START, approval });
    assert.equal(acted.done, false, JSON.stringify(approval));
    assert.equal(taken, false);
  }
  assert.equal(recorder.book(), w.book());
});

test('finding 5: the stub writer writes nothing dated ahead of its clock', async () => {
  const w = await makeWorld();
  const recorder = await opened(w, { now: () => START + HOUR });
  let taken = false;
  const ahead = await recorder.act(order(10), async () => (taken = true), { when: START + 5 * 24 * HOUR });
  assert.equal(ahead.done, false);
  assert.equal(taken, false);
  assert.match(ahead.answer.problems[0].message, /ahead of the clock/);
  await assert.rejects(recorder.record(order(10), { when: START + 400 * 24 * HOUR }), (e) => e.code === 'record-not-sound' && /ahead of the clock/.test(e.message));
  assert.equal(recorder.book(), w.book());
});

test('finding 6: a call made after an action has ended is not mistaken for one made from inside it', async () => {
  const w = await makeWorld();
  const recorder = await opened(w);
  let late;
  const done = new Promise((resolve) => {
    recorder.act(
      order(10),
      async () => {
        // Something started inside the action that calls the writer after the action has ended.
        setTimeout(() => {
          late = recorder.record(order(1), { when: START + 10 * MINUTE });
          resolve();
        }, 20);
      },
      { when: START },
    );
  });
  await done;
  const stub = await late;
  assert.equal(stub.seq, 1);
  assert.equal((await checkBook(recorder.book())).summary.intact, true);
});

test('finding 10: the time given to the other side must be a real length of time, and an empty list of documents is the same as none', async () => {
  const w = await makeWorld();
  for (const countersignWithin of [Infinity, 0, -1, NaN, '30', 2 ** 31]) {
    await assert.rejects(opened(w, { countersignWithin }), (e) => e.code === 'bad-field', String(countersignWithin));
  }
  const recorder = await opened(w);
  const acted = await recorder.act({ ...order(10), details: [] }, async () => null, { when: START });
  assert.equal(acted.done, true);
  const written = await recorder.record({ ...order(10), details: [] }, { when: START + MINUTE });
  assert.equal(written.seq, 1);
  assert.equal((await checkBook(recorder.book())).summary.intact, true);
});
