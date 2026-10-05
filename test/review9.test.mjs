// What the ninth independent review found, in the time of a cancellation,
// in seals in a Show and in the stub writer (3 October 2026). Each fault is
// fixed, or stated as a limit, and each is a test here.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBook, checkShow, countersign, formatTime, fromBase64url, keySetFingerprint, makeShow, openRecorder, thumbprint, toBase64url, writeBook } from '../src/index.js';
import { makeBlockStamp } from './helpers/blockstamp.mjs';
import { START, makeWorld, openWriter } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const MINUTE = 60 * 1000;
const DAY = 24 * HOUR;
const ORDER = 'supplies.order';

function codes(result) {
  const out = result.problems.map((p) => p.code);
  for (const e of result.entries) out.push(...e.problems.map((p) => p.code), ...e.breaches.map((b) => b.code));
  return out;
}
const breachesOf = (r) => r.entries.map((e) => e.breaches.map((b) => b.code));
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });

// --- the time of a cancellation ---

test('finding 1: a cancellation cannot be moved back in time by putting it into a block before the date it gives', async () => {
  // The person signs a cancellation dated three days ahead, and has it put into a block at once.
  const w = await makeWorld();
  const cancel = await w.cancel({ when: START + 3 * DAY });
  w.entries.pop();
  const stamped = fromBase64url(cancel.fingerprint);
  const block = await makeBlockStamp(stamped, START + 10 * MINUTE);
  // The agent works for two days. Each stub is sealed, and a service time-stamps the seal.
  await w.add({ when: START + DAY });
  await w.seal({ when: START + DAY + 30 * MINUTE });
  await w.add({ when: START + 2 * DAY });
  await w.seal({ when: START + 2 * DAY + 30 * MINUTE });
  // On the date the cancellation gives, the person has a service time-stamp it.
  const service = toBase64url(await w.stampService.stamp(stamped, START + 3 * DAY + 5000));
  const trust = { stampServices: [w.stampService.fingerprint], blocks: [block.fingerprint] };
  const setAside = /block time-stamp beside this cancellation states a time more than two hours before/;

  for (const stamps of [[service, block.item], [block.item, service]]) {
    // In the book, and as the person's own copy: the same answer.
    const inBook = await checkBook(writeBook([...w.entries, { cancellation: cancel.record, stamps }]), trust);
    assert.deepEqual(codes(inBook), []);
    assert.equal(inBook.entries.at(-1).stampedAt, formatTime(START + 3 * DAY));
    assert.ok(inBook.entries.at(-1).notes.some((n) => setAside.test(n)));
    const copy = await checkBook(writeBook(w.entries), { ...trust, cancellations: [{ cancellation: cancel.record, stamps }] });
    assert.deepEqual(codes(copy), []);
    assert.equal(copy.summary.withinSlips, true);
    assert.equal(copy.held[0].stampedAt, formatTime(START + 3 * DAY));
    assert.ok(copy.held[0].notes.some((n) => setAside.test(n)));
  }
  // With the block alone, nothing settles it: the cancellation is dated after its own time-stamp, and does not pass.
  const alone = await checkBook(writeBook([...w.entries, { cancellation: cancel.record, stamps: [block.item] }]), trust);
  assert.deepEqual(codes(alone), ['dated-after-stamp']);
});

test('finding 8: a late time-stamp beside a prompt one changes nothing, and only a late time is pointed out', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const cancel = await w.cancel({ when: START + HOUR, stampTime: START + HOUR + 5000 });
  const prompt = cancel.entry.stamps[0];
  const late = toBase64url(await w.stampService.stamp(fromBase64url(cancel.fingerprint), START + 50 * HOUR));
  const trust = { stampServices: [w.stampService.fingerprint] };
  const pointedOut = (r) => r.entries.at(-1).notes.some((n) => /more than 300 seconds after/.test(n));
  cancel.entry.stamps = [prompt, late];
  const both = await checkBook(w.book(), trust);
  assert.equal(both.entries.at(-1).stampedAt, formatTime(START + HOUR + 5000));
  assert.equal(pointedOut(both), false);
  cancel.entry.stamps = [late];
  const alone = await checkBook(w.book(), trust);
  assert.equal(alone.entries.at(-1).stampedAt, formatTime(START + 50 * HOUR));
  assert.equal(pointedOut(alone), true);
});

test('finding 9: a cancellation that the person kept back marks the stubs made meanwhile, and the copy says the book may never have been given it', async () => {
  const w = await makeWorld();
  const cancel = await w.cancel({ when: START, stampTime: START + 5000 });
  w.entries.pop();
  await w.add({ when: START + HOUR });
  await w.seal({ when: START + 2 * HOUR });
  const trust = { stampServices: [w.stampService.fingerprint] };
  assert.equal((await checkBook(w.book(), trust)).summary.withinSlips, true);
  const withCopy = await checkBook(w.book(), { ...trust, cancellations: [cancel.entry] });
  assert.deepEqual(breachesOf(withCopy), [[], ['after-cancellation'], []]);
  assert.ok(withCopy.held[0].notes.some((n) => /left it out, or was never given it/.test(n)));
});

// --- which time-stamps give a seal its time ---

test('finding 7: the earliest counted time-stamp of a seal shows when its entries existed, whichever kind it is', async () => {
  // A stub at 09:00. The seal is dated 09:05; a block that states 09:10 holds it; a service time-stamps it at 15:00.
  const w = await makeWorld();
  await w.add({ when: START });
  const sealed = await w.seal({ when: START + 5 * MINUTE, stampTime: START + 6 * HOUR, blockTime: START + 10 * MINUTE });
  // The person cancels at 12:00.
  await w.cancel({ when: START + 3 * HOUR, stampTime: START + 3 * HOUR + 5000 });
  const service = { stampServices: [w.stampService.fingerprint] };
  const both = await checkBook(w.book(), { ...service, blocks: [sealed.block.fingerprint] });
  // The block shows that the stub existed by 11:10, before the cancellation.
  assert.deepEqual(codes(both), []);
  assert.equal(both.entries[1].existedBy, formatTime(START + 10 * MINUTE + 2 * HOUR));
  assert.equal(both.summary.sealed.by, 'block');
  // To a reader who did not name the block, only the service's later time shows it: not before the cancellation.
  assert.deepEqual(breachesOf(await checkBook(w.book(), service)), [[], ['after-cancellation'], [], []]);
});

// --- seals in a Show ---

test('finding 2: in a Show, a seal that does not fit the book is the page marked, not the honest page before it', async () => {
  // An old book of the same recorder, sealed and time-stamped 30 days ago.
  const old = await makeWorld({ fields: { validFrom: '2026-09-01T08:00:00Z', validUntil: '2026-09-30T08:00:00Z' } });
  await old.add({ when: START - 30 * DAY });
  const oldSeal = await old.seal({ when: START - 30 * DAY + HOUR });
  const trust = { stampServices: [old.stampService.fingerprint], sealKeys: [await keySetFingerprint(old.recorder.keys)] };
  // Today's book: an honest stub, and the old seal put in at the place its size fits.
  const w = await makeWorld();
  await w.add({ when: START });
  w.entries.push(oldSeal.entry);
  const whole = await checkBook(w.book(), trust);
  assert.deepEqual(whole.entries[1].problems, []);
  assert.ok(whole.entries[2].problems.some((p) => p.code === 'seal-mismatch'));

  const show = await checkShow(await makeShow(w.book(), [0, 1, 2]), trust);
  assert.equal(show.summary.intact, false);
  assert.deepEqual(show.entries[1].problems, []);
  assert.equal(show.entries[1].verified, 'all');
  assert.deepEqual(show.entries[2].problems.map((p) => p.code), ['dated-after-stamp']);
  assert.match(show.entries[2].problems[0].message, /Either that page's date is not as it says, or this seal does not fit the entries before it/);
  assert.equal(show.entries[2].verified, 'none');
});

test('finding 5: in a Show, a seal is held to the chain of seals as far as the pages show it', async () => {
  const w = await makeWorld();
  await w.add({ when: START }); // 1
  const first = await w.seal({ when: START + 10 * MINUTE }); // 2: the first seal
  await w.add({ when: START + 20 * MINUTE }); // 3
  await w.seal({ when: START + 30 * MINUTE, previous: undefined }); // 4: says it is the first seal
  await w.add({ when: START + 40 * MINUTE }); // 5
  await w.seal({ when: START + 50 * MINUTE, previous: first.fingerprint }); // 6: names the first seal, passing over entry 4
  const whole = await checkBook(w.book());
  assert.deepEqual(codes(whole), ['seal-chain-broken', 'seal-chain-broken']);

  // Every entry before the last seal, under it; and every entry as pages.
  const under = await checkShow(await makeShow(w.book(), [0, 1, 2, 3, 4, 5], { seal: 6 }));
  assert.deepEqual(codes(under), ['seal-chain-broken', 'seal-chain-broken']);
  assert.deepEqual(under.entries.filter((e) => e.problems.length).map((e) => e.index), [4, 6]);
  const pages = await checkShow(await makeShow(w.book(), [0, 1, 2, 3, 4, 5, 6]), { expectedRoot: whole.root, expectedSize: 7 });
  assert.deepEqual(pages.entries.filter((e) => e.problems.length).map((e) => e.index), [4, 6]);
  // A stated limit: a Show that leaves the seals between out cannot show it.
  assert.deepEqual(codes(await checkShow(await makeShow(w.book(), [0, 1, 2], { seal: 6 }))), []);

  // A sound chain of seals passes, with every seal among the pages or only some.
  const v = await makeWorld();
  await v.add({ when: START });
  await v.seal({ when: START + 10 * MINUTE });
  await v.seal({ when: START + 20 * MINUTE });
  await v.seal({ when: START + 30 * MINUTE });
  assert.deepEqual(codes(await checkBook(v.book())), []);
  assert.deepEqual(codes(await checkShow(await makeShow(v.book(), [0, 1, 2, 3], { seal: 4 }))), []);
  assert.deepEqual(codes(await checkShow(await makeShow(v.book(), [0, 2], { seal: 4 }))), []);
  assert.deepEqual(codes(await checkShow(await makeShow(v.book(), [0, 2], { seal: 3 }))), []);
});

test('finding 6: a later time-stamp put beside the seal of a Show gains little: the pages are still held against the seal\'s own date', async () => {
  // A stub dated 09:09, under a seal dated 09:05 that a service time-stamped at 09:03.
  const w = await makeWorld();
  await w.add({ when: START + 9 * MINUTE, countersigned: false });
  const sealed = await w.seal({ when: START + 5 * MINUTE, stampTime: START + 3 * MINUTE });
  const trust = { stampServices: [w.stampService.fingerprint] };
  assert.deepEqual(codes(await checkBook(w.book(), trust)), ['dated-after-stamp']);
  const show = await makeShow(w.book(), [0, 1], { seal: 2 });
  assert.deepEqual(codes(await checkShow(show, trust)), ['dated-after-stamp']);
  // A stated limit: nothing fixes the time-stamps beside that seal. With a later one in their place the Show passes.
  show.seal.stamps = [toBase64url(await w.stampService.stamp(sealed.fingerprintBytes, START + 3 * HOUR))];
  assert.deepEqual(codes(await checkShow(show, trust)), []);

  // But a page dated more than 300 seconds after the seal's own date is reported, whatever stands beside the seal.
  const v = await makeWorld();
  await v.add({ when: START + 20 * MINUTE, countersigned: false });
  const early = await v.seal({ when: START + 5 * MINUTE, stampTime: START + 3 * MINUTE });
  const second = await makeShow(v.book(), [0, 1], { seal: 2 });
  second.seal.stamps = [toBase64url(await v.stampService.stamp(early.fingerprintBytes, START + 3 * HOUR))];
  assert.deepEqual(codes(await checkShow(second, { stampServices: [v.stampService.fingerprint] })), ['time-went-backwards']);
});

// --- the stub writer ---

test('finding 3: the stub writer writes no approval dated more than 300 seconds ahead of its clock', async () => {
  const w = await makeWorld({ fields: { requires: [{ need: 'approval', action: ORDER }] } });
  const clock = START + HOUR;
  const recorder = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys: [await thumbprint(w.passkey.key)], now: () => clock });
  // The action is dated 299 seconds ahead of the clock, and the approval 299 seconds after that.
  const ahead = await w.approve({ slip: w.slipFingerprint, ...order(10), when: clock + 598 * 1000 });
  let taken = 0;
  const refused = await recorder.act(order(10), async () => ++taken, { when: clock + 299 * 1000, approval: ahead, countersign: (stub) => countersign(stub, w.service.privateKeys, clock + 1000) });
  assert.equal(refused.done, false);
  assert.equal(taken, 0);
  assert.match(refused.answer.problems[0].message, /approval that goes with this action is dated ahead of the clock/);
  await assert.rejects(recorder.record(order(10), { when: clock + 300 * 1000, approval: ahead }), (e) => e.code === 'record-not-sound' && /ahead of the clock/.test(e.message));
  assert.equal(recorder.book(), w.book());
  // An approval dated within 300 seconds of the clock is written.
  const near = await w.approve({ slip: w.slipFingerprint, ...order(10), when: clock + 300 * 1000 });
  const done = await recorder.act(order(10), async () => ++taken, { when: clock + 299 * 1000, approval: near });
  assert.equal(done.done, true);
  assert.equal((await checkBook(recorder.book())).summary.intact, true);
});

test('finding 4: a cancellation of the writer\'s own slip stops it, however many others it was handed before', async () => {
  // One book that holds two slips, signed by two people. The writer serves the agent under the first.
  const a = await makeWorld();
  const b = await makeWorld();
  const clock = START + HOUR;
  const issuerKeys = [await thumbprint(a.passkey.key), await thumbprint(b.passkey.key)];
  const recorder = await openRecorder({ book: writeBook([{ slip: a.slip }, { slip: b.slip }]), slip: a.slipFingerprint, privateKeys: a.agent.privateKeys, issuerKeys, now: () => clock });
  let taken = 0;
  assert.equal((await recorder.act(order(10), async () => ++taken)).done, true);
  // Seventeen cancellations of the other slip, dated a day ahead: none can be added, and none stops this writer.
  for (let i = 0; i < 17; i++) {
    const other = await b.cancel({ when: clock + DAY + i * 1000 });
    await assert.rejects(recorder.add(other.entry), (e) => e.code === 'record-not-sound' && !/allows nothing more/.test(e.message));
  }
  assert.equal((await recorder.act(order(10), async () => ++taken)).done, true);
  // The first person cancels the first slip, dated ten minutes ahead: it cannot be added either, and it stops the writer.
  const cancel = await a.cancel({ when: clock + 10 * MINUTE });
  await assert.rejects(recorder.add(cancel.entry), (e) => /allows nothing more under that slip/.test(e.message));
  // Handed over a second time, it changes nothing.
  await assert.rejects(recorder.add(cancel.entry), (e) => /allows nothing more under that slip/.test(e.message));
  const after = await recorder.act(order(10), async () => ++taken);
  assert.equal(after.done, false);
  assert.deepEqual(after.answer.breaches.map((x) => x.code), ['after-cancellation']);
  assert.equal(taken, 2);
  assert.equal((await checkBook(recorder.book(), { issuerKeys })).summary.problemFound, false);

  // A writer opened with 16 cancellations of another slip still has room for the one that matters.
  const many = [];
  for (let i = 0; i < 16; i++) many.push((await b.cancel({ when: START + i * 1000 })).entry);
  const full = await openWriter({ book: writeBook([{ slip: a.slip }, { slip: b.slip }]), slip: a.slipFingerprint, privateKeys: a.agent.privateKeys, issuerKeys, options: { cancellations: many }, now: () => clock });
  await assert.rejects(full.add(cancel.entry), (e) => /allows nothing more under that slip/.test(e.message));
  const stopped = await full.act(order(10), async () => ++taken);
  assert.equal(stopped.done, false);
  assert.deepEqual(stopped.answer.breaches.map((x) => x.code), ['after-cancellation']);
});
