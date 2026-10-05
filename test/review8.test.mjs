// What the eighth independent review found, in the stub writer and in which
// time-stamps give a record its time (3 October 2026). Each fault is fixed,
// and each is a test here.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBefore, checkBook, checkShow, countersign, formatTime, fromBase64url, makeShow, thumbprint, toBase64url, writeBook } from '../src/index.js';
import { makeBlockStamp } from './helpers/blockstamp.mjs';
import { START, makeWorld, openWriter } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const MINUTE = 60 * 1000;
const ORDER = 'supplies.order';

function codes(result) {
  const out = result.problems.map((p) => p.code);
  for (const e of result.entries) out.push(...e.problems.map((p) => p.code), ...e.breaches.map((b) => b.code));
  return out;
}
const breachesOf = (r) => r.entries.map((e) => e.breaches.map((b) => b.code));
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });
const opened = async (w, more = {}) =>
  openWriter({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys: [await thumbprint(w.passkey.key)], ...more });
const contentOf = (record) => JSON.parse(Buffer.from(record.payload, 'base64url').toString());

// --- which time-stamps give a record its time ---

test('finding 1: a later time-stamp put beside an earlier one does not move the time of a cancellation', async () => {
  const w = await makeWorld();
  await w.add({ when: START }); // entry 1: a stub at 09:00
  await w.seal({ when: START + 30 * MINUTE }); // entry 2: time-stamped at 09:31
  const cancel = await w.cancel({ when: START + HOUR }); // the person cancels at 10:00
  w.entries.pop();
  await w.add({ when: START + 26 * HOUR }); // entry 3: a stub a day after the cancellation
  await w.seal({ when: START + 26 * HOUR + 30 * MINUTE }); // entry 4
  const stamped = fromBase64url(cancel.fingerprint);
  const block = await makeBlockStamp(stamped, START + 90 * MINUTE); // a block that states 10:30 holds the cancellation
  const prompt = toBase64url(await w.stampService.stamp(stamped, START + HOUR + 5000));
  const late = toBase64url(await w.stampService.stamp(stamped, START + 50 * HOUR));
  const trust = { stampServices: [w.stampService.fingerprint], blocks: [block.fingerprint] };
  const onlyTheLaterStub = [[], [], [], ['after-cancellation'], [], []];

  // In the book. Whichever time-stamps stand beside it, the stub made a day later is reported.
  for (const stamps of [[block.item], [prompt, block.item], [late, block.item], [block.item, late]]) {
    const r = await checkBook(writeBook([...w.entries, { cancellation: cancel.record, stamps }]), trust);
    assert.deepEqual(breachesOf(r), onlyTheLaterStub, `${stamps.length} time-stamps`);
    assert.deepEqual(r.problems, []);
    // A block's loose time is not taken as earlier than the date the person signed.
    assert.equal(r.entries[5].stampedAt, formatTime(START + HOUR));
  }
  // With the late time-stamp alone, nothing shows that the cancellation existed earlier, and the reader is told.
  const alone = await checkBook(writeBook([...w.entries, { cancellation: cancel.record, stamps: [late] }]), trust);
  assert.deepEqual(breachesOf(alone), [[], [], [], [], [], []]);
  assert.ok(alone.entries[5].notes.some((n) => /more than 300 seconds after/.test(n)));

  // The person's own copy, beside a book that leaves the cancellation out.
  for (const stamps of [[block.item], [late, block.item]]) {
    const r = await checkBook(writeBook(w.entries), { ...trust, cancellations: [{ cancellation: cancel.record, stamps }] });
    assert.deepEqual(breachesOf(r), onlyTheLaterStub.slice(0, 5));
    assert.equal(r.held[0].stampedAt, formatTime(START + HOUR));
  }
});

test('finding 1: a block whose earliest time is after the person\'s own date counts from that earliest time', async () => {
  // The person cancels at 10:00; the block states 13:30, so the proof was made at 11:30 at the earliest.
  const w = await makeWorld();
  await w.add({ when: START });
  await w.seal({ when: START + 2 * HOUR, stampTime: START + 2 * HOUR + 20 * MINUTE }); // the stub is shown to have existed by 11:20
  const cancel = await w.cancel({ when: START + HOUR });
  const block = await makeBlockStamp(fromBase64url(cancel.fingerprint), START + 4 * HOUR + 30 * MINUTE);
  cancel.entry.stamps = [block.item];
  const r = await checkBook(w.book(), { stampServices: [w.stampService.fingerprint], blocks: [block.fingerprint] });
  assert.equal(r.entries[3].stampedAt, formatTime(START + 2 * HOUR + 30 * MINUTE));
  assert.deepEqual(codes(r), []);
});

test('finding 1: a seal whose block time-stamp and service time-stamp do not agree says so', async () => {
  // A seal dated 19:00, in a block that states 10:00; a service time-stamp of 19:01 is added later.
  const w = await makeWorld();
  await w.add({ when: START + 9 * HOUR });
  const sealed = await w.seal({ when: START + 10 * HOUR, stamp: false, blockTime: START + HOUR });
  const trust = { stampServices: [w.stampService.fingerprint], blocks: [sealed.block.fingerprint] };
  assert.ok(codes(await checkBook(w.book(), trust)).includes('dated-after-stamp'));
  sealed.entry.stamps = [toBase64url(await w.stampService.stamp(sealed.fingerprintBytes, START + 10 * HOUR + MINUTE)), sealed.block.item];
  const both = await checkBook(w.book(), trust);
  assert.deepEqual(codes(both), []);
  assert.ok(both.entries[2].notes.some((n) => /block time-stamp beside this seal states a time more than two hours before/.test(n)));
  // Where the two agree, nothing is said.
  const v = await makeWorld();
  await v.add({ when: START });
  const fine = await v.seal({ when: START + 30 * MINUTE, blockTime: START + HOUR });
  const agreed = await checkBook(v.book(), { stampServices: [v.stampService.fingerprint], blocks: [fine.block.fingerprint] });
  assert.ok(!agreed.entries[2].notes.some((n) => /do not agree|more than two hours before/.test(n)));
});

test('finding 9: a service\'s time-stamps cannot step backwards a little at a time', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const first = START + HOUR;
  await w.seal({ when: START + 30 * MINUTE, stampTime: first });
  // Each seal is dated within 300 seconds of the time-stamps it covers and of its own, so that only the time-stamps step back.
  await w.seal({ when: START + 56 * MINUTE, stampTime: first - 250 * 1000 });
  await w.seal({ when: START + 56 * MINUTE + 30 * 1000, stampTime: first - 500 * 1000 });
  const r = await checkBook(w.book(), { stampServices: [w.stampService.fingerprint] });
  assert.deepEqual(codes(r), ['time-went-backwards']);
  assert.deepEqual(r.entries[4].problems.map((p) => p.code), ['time-went-backwards']);
  assert.match(r.entries[4].problems[0].message, /earlier than the time-stamp of a seal before it/);
});

test('finding 5: a seal among the pages of a Show is held against the pages before it, as the whole book would be', async () => {
  // A stub dated 12:00, under a seal that was time-stamped at 09:31, and a second seal at 13:01.
  const w = await makeWorld();
  await w.add({ when: START + 3 * HOUR });
  await w.seal({ when: START + 30 * MINUTE });
  await w.seal({ when: START + 4 * HOUR });
  const trust = { stampServices: [w.stampService.fingerprint] };
  const whole = await checkBook(w.book(), trust);
  assert.deepEqual(codes(whole), ['dated-after-stamp']);

  // The first seal is among the pages: the Show fails as the whole book does.
  const withSeal = await checkShow(await makeShow(w.book(), [0, 1, 2], { seal: 3 }), trust);
  assert.deepEqual(codes(withSeal), ['dated-after-stamp']);
  // The finding is given for the seal page, which could not be compared with the entries before it
  // (the ninth review: single pages cannot show which of the two is at fault).
  assert.deepEqual(withSeal.entries[2].problems.map((p) => p.code), ['dated-after-stamp']);
  assert.deepEqual(withSeal.entries[1].problems, []);
  assert.equal(withSeal.summary.intact, false);
  // To a reader who trusts no time-stamp service, the first seal is dated before the stub it covers, in both.
  assert.deepEqual(codes(await checkBook(w.book())), ['time-went-backwards']);
  assert.deepEqual(codes(await checkShow(await makeShow(w.book(), [0, 1, 2], { seal: 3 }))), ['time-went-backwards']);

  // A stated limit: with the first seal left out of the pages, a Show cannot show it. Only the whole book can.
  const without = await checkShow(await makeShow(w.book(), [0, 1], { seal: 3 }), trust);
  assert.deepEqual(codes(without), []);
});

test('finding 5: in a Show, a seal is held against the seals among the pages that come before it', async () => {
  // The second seal's time-stamp is 400 seconds earlier than the first's. (Its own date is within 300 seconds of both.)
  const w = await makeWorld();
  await w.add({ when: START });
  await w.seal({ when: START + 30 * MINUTE, stampTime: START + 3 * HOUR });
  await w.seal({ when: START + 3 * HOUR - 200 * 1000, stampTime: START + 3 * HOUR - 400 * 1000 });
  const trust = { stampServices: [w.stampService.fingerprint] };
  assert.deepEqual(codes(await checkBook(w.book(), trust)), ['time-went-backwards']);
  const show = await checkShow(await makeShow(w.book(), [0, 1, 2], { seal: 3 }), trust);
  assert.deepEqual(codes(show), ['time-went-backwards']);
  assert.equal(show.entries.at(-1).kind, 'seal');
  assert.deepEqual(show.entries.at(-1).problems.map((p) => p.code), ['time-went-backwards']);
  assert.equal(show.summary.sealed, null);

  // The second seal is dated two minutes before the first.
  const v = await makeWorld();
  await v.add({ when: START });
  await v.seal({ when: START + 50 * MINUTE });
  await v.seal({ when: START + 48 * MINUTE });
  assert.deepEqual(codes(await checkBook(v.book(), trust)), ['time-went-backwards']);
  assert.deepEqual(codes(await checkShow(await makeShow(v.book(), [0, 2], { seal: 3 }))), ['time-went-backwards']);
});

// --- the check before acting ---

test('finding 8: the check before acting refuses an action that would add to a period a later-dated stub already overfills', async () => {
  // 100 GBP in any three hours. A helper's stub, dated 12:00, is 150 GBP by itself.
  const w = await makeWorld({ fields: { passes: 1, limits: [{ action: ORDER, max: 100, unit: 'GBP', per: 3 * 3600 }] } });
  const trust = { issuerKeys: [await thumbprint(w.passkey.key)] };
  const helper = await w.pass();
  await helper.add({ when: START + 3 * HOUR, value: 150, countersigned: false });
  assert.deepEqual(breachesOf(await checkBook(w.book(), trust)), [[], [], ['over-period-limit']]);
  // The agent proposes 1 GBP at 11:00: inside the three hours that end at the helper's stub.
  const answer = await checkBefore(w.book(), { slip: w.slipFingerprint, ...order(1), when: START + 2 * HOUR }, trust);
  assert.equal(answer.allowed, false);
  assert.deepEqual(answer.breaches.map((b) => b.code), ['over-period-limit']);
  // Written anyway, a checker reports nothing new: the finding stands with the later stub. This is
  // the one case where the check before acting refuses more than a checker reports.
  await w.add({ when: START + 2 * HOUR, value: 1, countersigned: false });
  assert.deepEqual(breachesOf(await checkBook(w.book(), trust)), [[], [], ['over-period-limit'], []]);
});

// --- the stub writer ---

test('finding 2: what the stub writer is handed is copied when it is handed over, and a later change changes nothing', async () => {
  const w = await makeWorld();
  const recorder = await opened(w);
  const soon = () => new Promise((resolve) => setImmediate(resolve));

  // The other side's own code adds a member to what it handed back, a moment later.
  const noted = (when) => async (stub) => {
    const made = await countersign(stub, w.service.privateKeys, when);
    setImmediate(() => {
      made.receivedAt = 'noted by the caller';
    });
    return made;
  };
  const first = await recorder.act(order(10), soon, { when: START, countersign: noted(START + 1000) });
  assert.deepEqual(first.stub.countersignature, { accepted: true, problem: null });

  // An object that answers one way when first read and another way afterwards.
  let reads = 0;
  const second = await recorder.act(order(10), soon, {
    when: START + MINUTE,
    countersign: async (stub) => {
      const made = await countersign(stub, w.service.privateKeys, START + MINUTE + 1000);
      const shifting = { signatures: made.signatures };
      Object.defineProperty(shifting, 'payload', { enumerable: true, get: () => (reads++ === 0 ? made.payload : first.stub.record.payload) });
      return shifting;
    },
  });
  assert.deepEqual(second.stub.countersignature, { accepted: true, problem: null });

  // The caller's own approval gains a member while the action runs.
  const approval = await w.approve({ slip: w.slipFingerprint, ...order(10), when: START + MINUTE });
  const third = await recorder.act(
    order(10),
    async () => {
      approval.record.usedAt = 'noted by the caller';
    },
    { when: START + 2 * MINUTE, approval, countersign: (stub) => countersign(stub, w.service.privateKeys, START + 2 * MINUTE + 1000) },
  );
  assert.equal(third.done, true);

  // The request is changed after the call was made, while the call waits its turn.
  const request = order(10);
  const waiting = recorder.act(request, soon, { when: START + 3 * MINUTE });
  request.amount.value = 1000;
  request.action = 'something.else';
  const fourth = await waiting;
  assert.equal(fourth.done, true);
  assert.deepEqual([contentOf(fourth.stub.record).action, contentOf(fourth.stub.record).amount.value], [ORDER, 10]);

  // "record": the same late change to what the other side handed back.
  const fifth = await recorder.record(order(10), { when: START + 4 * MINUTE, countersign: noted(START + 4 * MINUTE + 1000) });
  assert.deepEqual(fifth.countersignature, { accepted: true, problem: null });
  await soon();

  // What cannot be copied is not a record: the stub stands one-sided, and a request of that kind is refused.
  const sixth = await recorder.record(order(10), { when: START + 5 * MINUTE, countersign: async () => ({ payload: 'x', signatures: [], toJSON() {} }) });
  assert.equal(sixth.countersignature.problem.code, 'countersignature-invalid');
  await assert.rejects(recorder.act({ ...order(10), note() {} }, soon, { when: START + 6 * MINUTE }), (e) => e.code === 'bad-field');

  const r = await checkBook(recorder.book());
  assert.deepEqual(codes(r), []);
  assert.equal(r.summary.intact, true);
  assert.deepEqual([r.summary.counts.stubs, r.summary.counts.countersigned, r.summary.counts.approved], [6, 4, 1]);
});

test('finding 3: "record" hands the stub to the other side only once it has passed the check of the whole book', async () => {
  const w = await makeWorld();
  await w.add({ when: START + 30 * MINUTE });
  const recorder = await opened(w);
  const handed = [];
  const ask = (when) => async (stub) => {
    handed.push(contentOf(stub));
    return countersign(stub, w.service.privateKeys, when);
  };
  // Dated before the stub ahead of it: refused, and the other side was handed nothing.
  await assert.rejects(recorder.record(order(10), { when: START + 10 * MINUTE, countersign: ask(START + 11 * MINUTE) }), (e) => e.code === 'record-not-sound');
  assert.equal(handed.length, 0);
  const written = await recorder.record(order(10), { when: START + 40 * MINUTE, countersign: ask(START + 41 * MINUTE) });
  assert.deepEqual(written.countersignature, { accepted: true, problem: null });
  // The other side holds one signed stub for this place in the chain, not two.
  assert.deepEqual(handed.map((c) => c.seq), [1]);
  assert.equal((await checkBook(recorder.book())).summary.intact, true);
});

test('finding 4: "act" takes an action now: a date behind the clock is refused', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  // The clock is past the end of the slip.
  const late = Date.parse('2026-10-20T09:00:00Z');
  const recorder = await opened(w, { now: () => late });
  let taken = 0;
  const byTheClock = await recorder.act(order(10), async () => ++taken);
  assert.equal(byTheClock.done, false);
  assert.deepEqual(byTheClock.answer.breaches.map((b) => b.code), ['outside-valid-time']);
  // A date inside the slip, handed in, does not get the action taken.
  const back = await recorder.act(order(10), async () => ++taken, { when: START + HOUR });
  assert.equal(back.done, false);
  assert.match(back.answer.problems[0].message, /dated behind the clock/);
  assert.equal(taken, 0);
  assert.equal(recorder.book(), w.book());
  // 300 seconds between two clocks is allowed, and no more.
  const clock = START + 2 * HOUR;
  assert.equal((await (await opened(w, { now: () => clock })).act(order(10), async () => null, { when: clock - 300 * 1000 })).done, true);
  assert.equal((await (await opened(w, { now: () => clock })).act(order(10), async () => null, { when: clock - 301 * 1000 })).done, false);
  // "record" is for an action that was taken earlier, and still writes it.
  const written = await recorder.record(order(10), { when: START + HOUR });
  assert.equal(written.seq, 1);
});

test('finding 6: once the other side\'s time to countersign has run out, a later call that stems from that request is not refused', async () => {
  const w = await makeWorld();
  const recorder = await opened(w, { countersignWithin: 50 });
  let later;
  const first = await recorder.act(order(10), async () => null, {
    when: START,
    countersign: () => {
      // Something started by the request (a connection, a timer) calls the writer long after.
      later = new Promise((resolve) => {
        setTimeout(() => resolve(recorder.act(order(10), async () => null, { when: START + MINUTE })), 250);
      });
      return new Promise(() => {});
    },
  });
  assert.equal(first.done, true);
  assert.equal(first.stub.countersignature.problem.code, 'countersignature-missing');
  assert.equal((await later).done, true);
  // While the writer is still waiting for the other side, a call from inside the request is refused at once.
  const inner = [];
  await recorder.act(order(10), async () => null, {
    when: START + 2 * MINUTE,
    countersign: async () => {
      await recorder.record(order(1), { when: START + 2 * MINUTE }).catch((e) => inner.push(e.message));
      return null;
    },
  });
  assert.match(inner[0], /called from inside an action it is taking/);
  const r = await checkBook(recorder.book());
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.counts.stubs, 3);
});

test('finding 7: a countersignature dated more than 300 seconds ahead of the clock is left out, whatever date the action has', async () => {
  const w = await makeWorld();
  const clock = START + HOUR;
  const recorder = await opened(w, { now: () => clock });
  // The action is dated 299 seconds ahead of the clock, and the countersignature 299 seconds after that.
  const first = await recorder.act(order(10), async () => null, { when: clock + 299 * 1000, countersign: (stub) => countersign(stub, w.service.privateKeys, clock + 598 * 1000) });
  assert.equal(first.done, true);
  assert.equal(first.stub.countersignature.accepted, false);
  assert.match(first.stub.countersignature.problem.message, /dated ahead of the clock/);
  const second = await recorder.act(order(10), async () => null, { when: clock + 299 * 1000, countersign: (stub) => countersign(stub, w.service.privateKeys, clock + 300 * 1000) });
  assert.deepEqual(second.stub.countersignature, { accepted: true, problem: null });
  // Nothing in the book is dated more than 300 seconds ahead of the clock.
  const r = await checkBook(recorder.book());
  assert.equal(r.summary.intact, true);
  for (const e of r.entries.filter((x) => x.kind === 'stub')) {
    const times = [e.content.when, e.countersignature && e.countersignature.when].filter((t) => typeof t === 'string').map((t) => Date.parse(t));
    assert.ok(Math.max(...times) <= clock + 300 * 1000);
  }
});
