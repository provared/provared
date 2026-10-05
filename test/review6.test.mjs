// What the sixth independent review found, in the block time-stamp, the
// crediting of time-stamps and the stub writer (3 October 2026). Each fault
// is fixed, and each is a test here.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBlockStamp, blockFingerprint } from '../src/blockstamp.js';
import { sha256, utf8, concatBytes } from '../src/encoding.js';
import { checkBefore, checkBook, checkShow, countersign, entryLine, formatTime, makeShow, thumbprint, writeRefusal } from '../src/index.js';
import { blockStatement, header, makeBlockStamp, start } from './helpers/blockstamp.mjs';
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
const trusting = async (w) => ({ issuerKeys: [await thumbprint(w.passkey.key)] });
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });
const opened = async (w, more = {}) => openWriter({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, ...(await trusting(w)), ...more });
const blockStampFor = (record, time) => makeBlockStamp(new Uint8Array(Buffer.from(record.fingerprint, 'base64url')), time);

// --- the block time-stamp and time ---

test('finding 1: a block time-stamp on a cancellation counts from the earliest it allows, so no later stub escapes', async () => {
  // The agent's stub is dated 10:00 and sealed at 10:31. The person cancelled at 09:10; the block states 09:20.
  const w = await makeWorld();
  await w.add({ when: START + HOUR });
  await w.seal({ when: START + HOUR + 30 * MINUTE });
  const cancel = await w.cancel({ when: START + 10 * MINUTE });
  const proof = await blockStampFor(cancel, START + 20 * MINUTE);
  cancel.entry.stamps = [proof.item];
  const trust = { blocks: [proof.fingerprint], stampServices: [w.stampService.fingerprint] };
  const r = await checkBook(w.book(), trust);
  assert.deepEqual(breachesOf(r), [[], ['after-cancellation'], [], []]);
  // The time used is shown: two hours before the time the block states.
  // Two hours before the block's time is before the person's own date, so the person's own date is the time used.
  assert.equal(r.entries[3].stampedAt, formatTime(START + 10 * MINUTE));
  // The same where the person hands over their own copy instead.
  w.entries.pop();
  const held = await checkBook(w.book(), { ...trust, cancellations: [cancel.entry] });
  assert.deepEqual(breachesOf(held), [[], ['after-cancellation'], []]);
});

test('finding 11: a block that states a time just after the cancellation\'s own date is not called late', async () => {
  const w = await makeWorld();
  const cancel = await w.cancel({ when: START + 10 * MINUTE });
  const near = await blockStampFor(cancel, START + 11 * MINUTE);
  cancel.entry.stamps = [near.item];
  const r = await checkBook(w.book(), { blocks: [near.fingerprint] });
  assert.ok(!r.entries[1].notes.some((n) => /more than 300 seconds after/.test(n)));
  // One that states a time three hours later is.
  const far = await blockStampFor(cancel, START + 3 * HOUR + 11 * MINUTE);
  cancel.entry.stamps = [far.item];
  const late = await checkBook(w.book(), { blocks: [far.fingerprint] });
  assert.ok(late.entries[1].notes.some((n) => /more than 300 seconds after/.test(n)));
});

test('finding 5: a seal dated before an entry it covers is reported, unless a time-stamp settles that the entry is the one misdated', async () => {
  const build = async (seal) => {
    const w = await makeWorld();
    await w.add({ when: START + HOUR });
    const sealed = await w.seal({ when: START, ...seal });
    return { w, blocks: sealed.block ? [sealed.block.fingerprint] : [], stampServices: [w.stampService.fingerprint] };
  };
  // A block that states 09:10: it counts as "existed by 11:10", which settles nothing about a stub dated 10:00.
  const block = await build({ stamp: false, blockTime: START + 10 * MINUTE });
  assert.deepEqual(codes(await checkBook(block.w.book(), block)), ['time-went-backwards']);
  // A service time-stamp of 11:00: the same.
  const late = await build({ stampTime: START + 2 * HOUR });
  assert.deepEqual(codes(await checkBook(late.w.book(), late)), ['time-went-backwards']);
  // A service time-stamp of 09:01: the stub is dated after it, so the stub is the one marked.
  const early = await build({ stampTime: START + MINUTE });
  assert.deepEqual(codes(await checkBook(early.w.book(), early)), ['dated-after-stamp']);
});

test('finding 6: an entry is shown to have existed by the earliest time that any seal after it shows', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  // The first seal has a block time-stamp only (it counts as 11:40); the second a service's, of 09:46.
  const first = await w.seal({ when: START + 30 * MINUTE, stamp: false, blockTime: START + 40 * MINUTE });
  await w.seal({ when: START + 45 * MINUTE, stampTime: START + 46 * MINUTE });
  await w.cancel({ when: START + HOUR, stampTime: START + HOUR + 1000 });
  const trust = { stampServices: [w.stampService.fingerprint] };
  const without = await checkBook(w.book(), trust);
  const named = await checkBook(w.book(), { ...trust, blocks: [first.block.fingerprint] });
  // Naming a true block as trusted never turns an honest stub into one "after the cancellation".
  assert.deepEqual(breachesOf(without), [[], [], [], [], []]);
  assert.deepEqual(breachesOf(named), [[], [], [], [], []]);
  assert.deepEqual(codes(named), []);
  assert.equal(named.entries[1].existedBy, formatTime(START + 46 * MINUTE));
  // The first seal keeps the time of its own time-stamp.
  assert.equal(named.entries[2].stampedAt, formatTime(START + 40 * MINUTE + 2 * HOUR));
});

test('finding 15: where this device cannot check all three signatures of a seal, it says that the time-stamp was not counted', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  await w.seal({ when: START + 30 * MINUTE });
  const r = await checkBook(w.book(), { stampServices: [w.stampService.fingerprint], withoutMethods: ['SLH-DSA-SHA2-256s'] });
  assert.equal(r.summary.sealed, null);
  assert.ok(r.entries[2].notes.some((n) => /was not counted: this device could not check all three/.test(n)));
});

test('finding 12: a block\'s number may be any number of up to five bytes, and a header of any wrong length has one code', async () => {
  const stamped = await sha256(utf8('what was stamped'));
  const head = header(stamped, START);
  const proof = concatBytes(start(stamped), blockStatement(2 ** 33));
  assert.equal((await checkBlockStamp(proof, head, stamped, [await blockFingerprint(head)])).height, 2 ** 33);
  // In a book: 79 bytes and 81 bytes are both "stamp-bad-data".
  const w = await makeWorld();
  await w.add({ when: START });
  const sealed = await w.seal({ when: START + 30 * MINUTE, stamp: false, blockTime: START + HOUR });
  const lines = w.book().split('\n').filter(Boolean);
  const base64url = (bytes) => Buffer.from(bytes).toString('base64url');
  for (const wrong of [sealed.block.header.subarray(0, 79), concatBytes(sealed.block.header, new Uint8Array(1))]) {
    const book = lines.slice(0, 2).join('\n') + '\n' + entryLine({ seal: sealed.entry.seal, stamps: [{ block: base64url(wrong), proof: sealed.block.item.proof }] }) + '\n';
    assert.ok(codes(await checkBook(book)).includes('stamp-bad-data'));
  }
});

// --- passing on, and covered fields ---

test('finding 13: where two passes above a stub both set a limit within a period, the nearer pass gives the finding', async () => {
  const perDay = (max) => [{ action: ORDER, max, unit: 'GBP', per: 86400 }];
  const w = await makeWorld({ fields: { passes: 2 } });
  const first = await w.pass({ limits: perDay(50) });
  const second = await w.pass({ from: first.fingerprint, signer: first.helper.privateKeys, limits: perDay(40) });
  await second.add({ value: 60, when: START });
  const r = await checkBook(w.book());
  assert.deepEqual(breachesOf(r), [[], [], [], ['over-period-limit']]);
  assert.match(r.entries[3].breaches[0].message, /The pass's limit is 40 GBP/);
  const asked = await checkBefore(
    w.book().split('\n').slice(0, 3).join('\n') + '\n',
    { slip: w.slipFingerprint, pass: second.fingerprint, action: ORDER, amount: { unit: 'GBP', value: 60 }, with: 'supplier', when: START },
    await trusting(w),
  );
  assert.match(asked.breaches[0].message, /The pass's limit is 40 GBP/);
});

test('finding 10: disclosures on a page of a Show and disclosures handed over beside it are used together', async () => {
  const w = await makeWorld({ cover: ['issuer.name', 'purpose'] });
  const [nameOnly] = w.prepared.disclosures.filter((d) => Buffer.from(d, 'base64url').toString().includes('"name"'));
  const [purposeOnly] = w.prepared.disclosures.filter((d) => Buffer.from(d, 'base64url').toString().includes('"purpose"'));
  const show = await makeShow(w.book(), [0], { disclosures: { 0: [nameOnly] } });
  const both = await checkShow(show, { disclosures: { [w.slipFingerprint]: [purposeOnly, nameOnly] } });
  assert.deepEqual(codes(both), []);
  assert.equal(both.entries[0].content.purpose, 'Keep the office stocked with paper, pens and toner.');
  assert.equal(both.entries[0].content.issuer.name, 'Sam Example');
  // Rubbish handed over beside the Show is reported, not set aside.
  const rubbish = await checkShow(show, { disclosures: { [w.slipFingerprint]: ['bm90IGEgZGlzY2xvc3VyZQ'] } });
  assert.deepEqual(rubbish.problems.map((p) => p.code), ['cover-invalid']);
});

// --- the stub writer ---

test('finding 2: the stub writer refuses a countersignature, or an entry, dated ahead of the clock', async () => {
  const w = await makeWorld();
  const recorder = await opened(w, { now: () => START });
  const ahead = Date.parse('2036-01-01T00:00:00Z');
  const first = await recorder.act(order(10), async () => null, { when: START, countersign: (stub) => countersign(stub, w.service.privateKeys, ahead) });
  assert.equal(first.done, true);
  assert.equal(first.stub.countersignature.accepted, false);
  assert.match(first.stub.countersignature.problem.message, /dated ahead of the clock/);
  const refusal = await writeRefusal({ slip: w.slipFingerprint, by: { keys: w.service.keys, name: 'Example Stationery (invented)' }, action: ORDER, reason: 'over-limit', when: ahead }, w.service.privateKeys);
  await assert.rejects(recorder.add({ refusal: refusal.record }), (e) => e.code === 'record-not-sound' && /ahead of the clock/.test(e.message));
  const r = await checkBook(recorder.book());
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.counts.refusals, 0);
});

test('finding 3: the stub writer is not blocked by an other side that never answers, nor by a call from inside its own action', async () => {
  const w = await makeWorld();
  const recorder = await opened(w, { countersignWithin: 50 });
  const silent = await recorder.act(order(10), async () => 'done', { when: START, countersign: () => new Promise(() => {}) });
  assert.equal(silent.done, true);
  assert.deepEqual(silent.stub.countersignature, { accepted: false, problem: { code: 'countersignature-missing', message: 'Asking the other side for its countersignature failed, or took too long.' } });
  // A call to the writer from inside the action is refused at once, and the action's own error is passed on.
  await assert.rejects(
    recorder.act(order(10), async () => recorder.record(order(1), { when: START + HOUR }), { when: START + HOUR }),
    /called from inside an action it is taking/,
  );
  // The writer goes on working.
  const next = await recorder.act(order(10), async () => 'done', { when: START + 2 * HOUR });
  assert.equal(next.done, true);
  const r = await checkBook(recorder.book());
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.counts.stubs, 2);
});

test('finding 4: the stub writer works out an approval\'s fingerprint itself', async () => {
  const w = await makeWorld({ fields: { requires: [{ above: 50, action: ORDER, need: 'approval', unit: 'GBP' }] } });
  const recorder = await opened(w);
  const approval = await w.approve({ slip: w.slipFingerprint, ...order(60), when: START - MINUTE });
  // A wrong fingerprint handed over with the approval is not relied on.
  const acted = await recorder.act(order(60), async () => null, { when: START, approval: { record: approval.record, fingerprint: 'A'.repeat(43) } });
  assert.equal(acted.done, true);
  const r = await checkBook(recorder.book());
  assert.deepEqual(codes(r), []);
  assert.equal(r.summary.counts.approved, 1);
  // And none need be handed over at all.
  const fresh = await opened(w);
  assert.equal((await fresh.act(order(60), async () => null, { when: START, approval: { record: approval.record } })).done, true);
  assert.equal((await checkBook(fresh.book())).summary.intact, true);
});

test('finding 7: "record" writes nothing that would make the book fail its check', async () => {
  const w = await makeWorld();
  const recorder = await opened(w);
  await recorder.record(order(10), { when: START + HOUR });
  const before = recorder.book();
  // A clock set back: a stub dated before the one ahead of it.
  await assert.rejects(recorder.record(order(10), { when: START }), (e) => e.code === 'record-not-sound');
  assert.equal(recorder.book(), before);
  // The writer goes on from where it stood.
  const next = await recorder.record(order(10), { when: START + 2 * HOUR });
  assert.equal(next.seq, 1);
  assert.equal((await checkBook(recorder.book())).summary.intact, true);
});

test('finding 8: an action whose record would not fit a line of a book is not allowed', async () => {
  const w = await makeWorld();
  const proposal = { slip: w.slipFingerprint, ...order(1), when: START, approval: { payload: 'A'.repeat(125000), signatures: [] } };
  const answer = await checkBefore(w.book(), proposal, await trusting(w));
  assert.equal(answer.allowed, false);
  assert.deepEqual(answer.problems.map((p) => p.code), ['too-large']);
});

test('finding 9: where the slip asks for a countersignature, the stub writer acts only if it can ask for one', async () => {
  const w = await makeWorld({ fields: { requires: [{ need: 'countersignature' }] } });
  const recorder = await opened(w);
  let taken = false;
  const refused = await recorder.act(order(10), async () => (taken = true), { when: START });
  assert.equal(refused.done, false);
  assert.equal(taken, false);
  assert.deepEqual(refused.answer.breaches.map((b) => b.code), ['countersignature-missing']);
  const done = await recorder.act(order(10), async () => (taken = true), { when: START, countersign: (stub) => countersign(stub, w.service.privateKeys, START + 1000) });
  assert.equal(done.done, true);
  assert.equal((await checkBook(recorder.book())).summary.withinSlips, true);
});
