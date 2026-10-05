// The acknowledgement: the agent's side states that it was handed the
// person's cancellation of a slip, and when. Format description, section 26.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBook, checkShow, fingerprint, formatTime, generateKeySet, makeShow, openRecorder, thumbprint, utf8, writeAcknowledgement, writeBook } from '../src/index.js';
import { START, makeWorld, withContent } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const MINUTE = 60 * 1000;
const ORDER = 'supplies.order';
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });

function codes(result) {
  const out = result.problems.map((p) => p.code);
  for (const e of result.entries) out.push(...e.problems.map((p) => p.code), ...e.breaches.map((b) => b.code));
  return out;
}
const breachesOf = (r) => r.entries.map((e) => e.breaches.map((b) => b.code));
const acknowledgedWords = /dated after the agent's side acknowledged/;
// A fingerprint of nothing that is in any book here.
const NOWHERE = await fingerprint(utf8('not in the book'));

// --- in a book ---

test('an acknowledgement in a book: signed by the slip\'s agent, after the cancellation it names', async () => {
  const w = await makeWorld();
  await w.add({ when: START }); // 1
  const cancel = await w.cancel({ when: START + HOUR }); // 2
  const given = await w.acknowledge(cancel.fingerprint, { when: START + HOUR + MINUTE }); // 3
  const r = await checkBook(w.book());
  assert.deepEqual(codes(r), []);
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.counts.acknowledgements, 1);
  const e = r.entries[3];
  assert.equal(e.kind, 'acknowledgement');
  assert.equal(e.verified, 'all');
  assert.equal(e.fingerprint, given.fingerprint);
  assert.equal(e.cancellation, 2);
  assert.equal(e.slip, w.slipFingerprint);
  assert.deepEqual(e.signatures.map((s) => `${s.method} ${s.state}`), ['Ed25519 valid', 'ML-DSA-87 valid']);
  assert.deepEqual(Object.keys(e.content).sort(), ['cancellation', 'id', 'slip', 'type', 'when']);

  // As pages of a Show: with its slip and its cancellation among the pages it checks; without the cancellation it does not.
  const trust = { expectedRoot: r.root, expectedSize: 4 };
  assert.deepEqual(codes(await checkShow(await makeShow(w.book(), [0, 2, 3]), trust)), []);
  assert.deepEqual(codes(await checkShow(await makeShow(w.book(), [0, 3]), trust)), ['cancellation-not-found']);
  assert.deepEqual(codes(await checkShow(await makeShow(w.book(), [3]), trust)), ['slip-missing']);

  // A device that lacks one of the two methods confirms it in part, and gives no pass.
  const partly = await checkBook(w.book(), { withoutMethods: ['ML-DSA-87'] });
  assert.equal(partly.entries[3].verified, 'some');
  assert.equal(partly.summary.intact, false);
  assert.deepEqual(partly.summary.methodsMissing, ['ML-DSA-87']);
});

test('an acknowledgement that does not fit is refused, each way with its own code', async () => {
  const build = async (change) => {
    const w = await makeWorld({ fields: { passes: 1 } });
    await w.add({ when: START });
    const cancel = await w.cancel({ when: START + HOUR });
    await change(w, cancel);
    return checkBook(w.book());
  };
  const stranger = await generateKeySet();
  const cases = {
    // Signed with keys other than the agent's.
    'signature-invalid': (w, cancel) => w.acknowledge(cancel.fingerprint, { signer: stranger.privateKeys }),
    // The cancellation it names is not in the book.
    'cancellation-not-found': (w) => w.acknowledge('A'.repeat(43)),
    // Under a slip that is not in the book.
    'slip-missing': (w, cancel) => w.acknowledge(cancel.fingerprint, { slip: NOWHERE }),
    // From a helper under a pass that is not in the book.
    'pass-missing': (w, cancel) => w.acknowledge(cancel.fingerprint, { pass: NOWHERE }),
    // A member that is not known.
    'bad-field': async (w, cancel) => {
      const made = await w.acknowledge(cancel.fingerprint);
      w.entries.pop();
      w.entries.push({ acknowledgement: withContent(made.record, (c) => void (c.note = 'x')) });
    },
    // Another kind of record in its place.
    'payload-type-mismatch': async (w) => {
      const refusal = await w.refuse();
      w.entries.pop();
      w.entries.push({ acknowledgement: refusal.record });
    },
    // The unique number of another record.
    'duplicate-id': async (w, cancel) => {
      const first = await w.acknowledge(cancel.fingerprint);
      const id = JSON.parse(Buffer.from(first.record.payload, 'base64url').toString()).id;
      await w.acknowledge(cancel.fingerprint, { id });
    },
  };
  for (const [code, change] of Object.entries(cases)) {
    const r = await build(change);
    assert.ok(codes(r).includes(code), `${code}: got ${codes(r).join(', ')}`);
    assert.equal(r.summary.intact, false, code);
  }
  // Before its cancellation in the book; and naming a cancellation of another slip.
  const w = await makeWorld();
  const cancel = await w.cancel({ when: START + HOUR });
  w.entries.pop();
  await w.acknowledge(cancel.fingerprint);
  w.entries.push(cancel.entry);
  assert.deepEqual(codes(await checkBook(w.book())), ['cancellation-not-found']);
  const a = await makeWorld();
  const b = await makeWorld();
  const other = await b.cancel({ when: START + HOUR });
  const given = await a.acknowledge(other.fingerprint);
  const mixed = await checkBook(writeBook([{ slip: a.slip }, { slip: b.slip }, other.entry, given.entry]));
  assert.deepEqual(codes(mixed), ['cancellation-not-found']);
  // What a failed acknowledgement says is given no place among the counted findings.
  assert.equal(mixed.entries[3].verified, 'none');
});

test('a helper agent acknowledges with the keys its pass names', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  const pass = await w.pass({ when: START });
  const cancel = await w.cancel({ when: START + HOUR });
  await w.acknowledge(cancel.fingerprint, { pass: pass.fingerprint, signer: pass.helper.privateKeys, when: START + HOUR + MINUTE });
  const r = await checkBook(w.book());
  assert.deepEqual(codes(r), []);
  assert.equal(r.entries[3].pass, pass.fingerprint);
  // The agent's own keys do not fit an acknowledgement that names the pass, nor the helper's one that names none.
  const v = await makeWorld({ fields: { passes: 1 } });
  const vPass = await v.pass({ when: START });
  const vCancel = await v.cancel({ when: START + HOUR });
  await v.acknowledge(vCancel.fingerprint, { pass: vPass.fingerprint });
  await v.acknowledge(vCancel.fingerprint, { signer: vPass.helper.privateKeys });
  assert.deepEqual(codes(await checkBook(v.book())), ['signature-invalid', 'signature-invalid']);
  // A pass given under another slip.
  const other = await makeWorld({ fields: { passes: 1 } });
  const otherPass = await other.pass({ when: START });
  const x = await makeWorld({ fields: { passes: 1 } });
  const xCancel = await x.cancel({ when: START + HOUR });
  const wrong = await writeAcknowledgement({ slip: x.slipFingerprint, cancellation: xCancel.fingerprint, pass: otherPass.fingerprint, when: START + 2 * HOUR }, otherPass.helper.privateKeys);
  const r2 = await checkBook(writeBook([{ slip: x.slip }, { slip: other.slip }, other.entries[1], xCancel.entry, { acknowledgement: wrong.record }]));
  assert.deepEqual(codes(r2), ['pass-mismatch']);
});

// --- handed over with the person's own copy of a cancellation ---

test('with an acknowledgement, the person\'s own copy shows which stubs were made after the agent\'s side was told', async () => {
  // The agent acts at 09:00 and 10:00. The person cancels at 10:30; the agent's side acknowledges at 10:31.
  // The agent goes on: 11:00 and 12:00. The book leaves the cancellation and the acknowledgement out.
  const w = await makeWorld();
  await w.add({ when: START }); // 1
  await w.add({ when: START + HOUR }); // 2
  const cancel = await w.cancel({ when: START + 90 * MINUTE });
  w.entries.pop();
  const given = await w.acknowledge(cancel.fingerprint, { when: START + 91 * MINUTE });
  w.entries.pop();
  await w.add({ when: START + 2 * HOUR }); // 3
  await w.add({ when: START + 3 * HOUR }); // 4
  assert.equal((await checkBook(w.book())).summary.withinSlips, true);

  // The copy has no time-stamp. Without the acknowledgement, it cannot be placed in time, and no stub is marked.
  const bare = await checkBook(w.book(), { cancellations: [cancel.entry] });
  assert.deepEqual(breachesOf(bare), [[], [], [], [], []]);
  assert.ok(bare.held[0].notes.some((n) => /left it out, or was never given it/.test(n)));
  assert.deepEqual(bare.held[0].acknowledgements, []);

  // With it: the two stubs dated after the acknowledgement are reported, and the note says the agent's side was told.
  const told = await checkBook(w.book(), { cancellations: [{ ...cancel.entry, acknowledgements: [given.record] }] });
  assert.deepEqual(told.problems, []);
  assert.deepEqual(breachesOf(told), [[], [], [], ['after-cancellation'], ['after-cancellation']]);
  assert.match(told.entries[3].breaches[0].message, acknowledgedWords);
  assert.equal(told.summary.intact, true);
  assert.equal(told.summary.withinSlips, false);
  const held = told.held[0];
  assert.equal(held.used, true);
  assert.equal(held.acknowledgements.length, 1);
  assert.deepEqual(
    { by: held.acknowledgements[0].by, pass: held.acknowledgements[0].pass, state: held.acknowledgements[0].state, when: held.acknowledgements[0].when, inBook: held.acknowledgements[0].inBook },
    { by: 'agent', pass: null, state: 'valid', when: formatTime(START + 91 * MINUTE), inBook: null },
  );
  assert.ok(held.notes.some((n) => /though the agent's side acknowledged at 2026-10-05T10:31:00Z/.test(n)));
  assert.ok(!held.notes.some((n) => /was never given it/.test(n)));
});

test('with a time-stamp as well, the strict rule still marks every stub not shown to have existed in time, and the words tell the two cases apart', async () => {
  const w = await makeWorld();
  await w.add({ when: START }); // 1
  await w.seal({ when: START + 10 * MINUTE }); // 2: time-stamped at 09:11
  await w.add({ when: START + HOUR }); // 3: before the cancellation, and no seal covers it in time
  const cancel = await w.cancel({ when: START + 90 * MINUTE, stampTime: START + 90 * MINUTE + 5000 });
  w.entries.pop();
  const given = await w.acknowledge(cancel.fingerprint, { when: START + 2 * HOUR });
  w.entries.pop();
  await w.add({ when: START + 3 * HOUR }); // 4: after the agent's side was told
  const trust = { stampServices: [w.stampService.fingerprint] };
  const r = await checkBook(w.book(), { ...trust, cancellations: [{ ...cancel.entry, acknowledgements: [given.record] }] });
  assert.deepEqual(breachesOf(r), [[], [], [], ['after-cancellation'], ['after-cancellation']]);
  assert.match(r.entries[3].breaches[0].message, /not shown to have existed before the person cancelled/);
  assert.match(r.entries[4].breaches[0].message, acknowledgedWords);
});

test('a helper\'s acknowledgement speaks for the helper\'s chain only', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  const pass = await w.pass({ when: START }); // 1
  const cancel = await w.cancel({ when: START + HOUR });
  w.entries.pop();
  const given = await writeAcknowledgement({ slip: w.slipFingerprint, cancellation: cancel.fingerprint, pass: pass.fingerprint, when: START + HOUR + MINUTE }, pass.helper.privateKeys);
  await pass.add({ when: START + 2 * HOUR }); // 2: the helper, after it was told
  await w.add({ when: START + 2 * HOUR }); // 3: the slip's own agent, of which the acknowledgement says nothing
  const r = await checkBook(w.book(), { cancellations: [{ ...cancel.entry, acknowledgements: [given.record] }] });
  assert.deepEqual(breachesOf(r), [[], [], ['after-cancellation'], []]);
  assert.equal(r.held[0].acknowledgements[0].by, 'helper');
  assert.equal(r.held[0].acknowledgements[0].pass, pass.fingerprint);
});

test('an acknowledgement handed over that does not check is a problem with the whole check; the cancellation itself is still used', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  await w.add({ when: START });
  const cancel = await w.cancel({ when: START + HOUR });
  w.entries.pop();
  const good = (await w.acknowledge(cancel.fingerprint, { when: START + HOUR + MINUTE })).record;
  w.entries.pop();
  const other = await w.cancel({ when: START + 2 * HOUR });
  w.entries.pop();
  const forOther = (await w.acknowledge(other.fingerprint)).record;
  w.entries.pop();
  const stranger = await generateKeySet();
  const forged = (await writeAcknowledgement({ slip: w.slipFingerprint, cancellation: cancel.fingerprint, when: START + HOUR }, stranger.privateKeys)).record;
  const noPass = (await writeAcknowledgement({ slip: w.slipFingerprint, cancellation: cancel.fingerprint, pass: NOWHERE, when: START + HOUR }, stranger.privateKeys)).record;
  await w.add({ when: START + 3 * HOUR });
  // Each case: what is handed over, the code of the problem, and whether a sound acknowledgement among them still counts.
  const cases = [
    [[forOther], 'acknowledgement-mismatch', false],
    [[forged], 'signature-invalid', false],
    [[noPass], 'pass-missing', false],
    [[good, good], 'bad-field', true],
    [[good, forged], 'signature-invalid', true],
    [[good, good, good, good, good], 'bad-field', false],
    [[], 'bad-field', false],
    ['yes', 'bad-field', false],
    [[{ payload: 'AAAA', signatures: [] }], 'bad-signatures-layout', false],
  ];
  for (const [acknowledgements, code, counts] of cases) {
    const r = await checkBook(w.book(), { cancellations: [{ ...cancel.entry, acknowledgements }] });
    assert.deepEqual(r.problems.map((p) => p.code), [code], JSON.stringify(code));
    assert.match(r.problems[0].message, /^An acknowledgement handed over with cancellation 1 of those beside the book did not pass its check/);
    assert.equal(r.summary.intact, false);
    // The cancellation itself is still used: the agent's side cannot spoil the person's copy with a bad acknowledgement.
    assert.equal(r.held[0].used, true);
    assert.ok(r.held[0].notes.some((n) => /An acknowledgement handed over with it did not pass its check/.test(n)));
    // Nothing is reported because of the acknowledgement that failed. One that is sound still counts.
    assert.equal(r.held[0].acknowledgements.length, counts ? 1 : 0);
    assert.deepEqual(breachesOf(r), [[], [], counts ? ['after-cancellation'] : []]);
  }
  // With a time-stamp on the copy, the time-stamp rule goes on reporting, whatever the acknowledgement beside it is.
  const stamped = await w.cancel({ when: START + 2 * HOUR, stampTime: START + 2 * HOUR + 5000 });
  w.entries.pop();
  const spoiled = await checkBook(w.book(), { stampServices: [w.stampService.fingerprint], cancellations: [{ ...stamped.entry, acknowledgements: [forged] }] });
  assert.deepEqual(spoiled.problems.map((p) => p.code), ['acknowledgement-mismatch']);
  assert.deepEqual(breachesOf(spoiled), [[], ['after-cancellation'], ['after-cancellation']]);
  // A device that cannot check the acknowledgement does not use it, says so, and gives no pass.
  const blind = await checkBook(w.book(), { cancellations: [{ ...cancel.entry, acknowledgements: [good] }], withoutMethods: ['Ed25519', 'ML-DSA-87'] });
  assert.equal(blind.summary.intact, false);
  assert.equal(blind.held[0].acknowledgements[0].state, 'unavailable');
  assert.equal(blind.held[0].acknowledgements[0].when, null);
  assert.deepEqual(breachesOf(blind), [[], [], []]);
  const partly = await checkBook(w.book(), { cancellations: [{ ...cancel.entry, acknowledgements: [good] }], withoutMethods: ['ML-DSA-87'] });
  assert.equal(partly.held[0].acknowledgements[0].state, 'unavailable');
  assert.equal(partly.held[0].acknowledgements[0].when, null);
  assert.ok(partly.held[0].notes.some((n) => /could not check an acknowledgement/.test(n)));
  assert.equal(partly.summary.fullyChecked, false);
});

// --- the stub writer signs it ---

test('the stub writer acknowledges the person\'s cancellation of its slip, and the acknowledgement follows the cancellation into the book', async () => {
  const w = await makeWorld();
  let clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const open = (book, options) => openRecorder({ book, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock, options });
  const recorder = await open(w.book());
  assert.equal((await recorder.act(order(10), async () => null)).done, true);
  const cancel = await w.cancel({ when: clock });
  const { acknowledgement } = await recorder.add(cancel.entry);
  assert.ok(acknowledgement);
  const book = await checkBook(recorder.book(), { issuerKeys });
  assert.equal(book.summary.intact, true);
  assert.deepEqual(book.entries.map((e) => e.kind), ['slip', 'stub', 'cancellation', 'acknowledgement']);
  assert.equal(book.entries[3].content.when, formatTime(clock));
  assert.equal(book.entries[3].content.cancellation, cancel.fingerprint);
  // What was handed back is the record in the book, and checks beside the person's own copy.
  assert.deepEqual(JSON.parse(recorder.book().split('\n')[3]).acknowledgement, acknowledgement);
  const beside = await checkBook(recorder.book(), { issuerKeys, cancellations: [{ ...cancel.entry, acknowledgements: [acknowledgement] }] });
  assert.deepEqual(beside.problems, []);
  assert.equal(beside.held[0].acknowledgements[0].inBook, 3);
  // Handed over again, in this writer or in one opened again from the book: the same acknowledgement, and nothing more is written.
  const before = recorder.book();
  for (const writer of [recorder, await open(recorder.book())]) {
    const again = await writer.add(cancel.entry).catch((e) => e);
    assert.equal(again.code, 'record-not-sound');
    assert.deepEqual(again.acknowledgement, acknowledgement);
    assert.equal(writer.book(), before);
  }
  // A cancellation of another slip, or one signed with another passkey, is not acknowledged.
  const b = await makeWorld();
  const two = await openRecorder({ book: w.book().split('\n')[0] + '\n' + b.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys: [...issuerKeys, await thumbprint(b.passkey.key)], now: () => clock });
  assert.deepEqual(await two.add((await b.cancel({ when: clock })).entry), {});
  const forged = await w.cancel({ passkey: b.passkey, when: clock });
  const refused = await two.add(forged.entry).catch((e) => e);
  assert.equal(refused.code, 'record-not-sound');
  assert.equal(refused.acknowledgement, undefined);
});

test('a cancellation that the stub writer keeps, or adds by itself, is acknowledged all the same', async () => {
  const w = await makeWorld();
  let clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const recorder = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock });
  assert.equal((await recorder.act(order(10), async () => null)).done, true);
  // Dated ahead of the clock: kept beside the book, and acknowledged at once.
  const cancel = await w.cancel({ when: clock + 10 * MINUTE });
  const kept = await recorder.add(cancel.entry).catch((e) => e);
  assert.match(kept.message, /dated ahead of the clock/);
  assert.ok(kept.acknowledgement);
  const meanwhile = await checkBook(recorder.book(), { issuerKeys, cancellations: [{ ...cancel.entry, acknowledgements: [kept.acknowledgement] }] });
  assert.deepEqual(meanwhile.problems, []);
  assert.equal(meanwhile.summary.counts.cancellations, 0);
  assert.ok(meanwhile.held[0].notes.some((n) => /though the agent's side acknowledged at/.test(n)));
  // Once the clock has reached its date, the cancellation is written into the book, and the acknowledgement after it.
  clock += 20 * MINUTE;
  assert.equal((await recorder.act(order(10), async () => null)).done, false);
  const book = await checkBook(recorder.book(), { issuerKeys });
  assert.equal(book.summary.intact, true);
  assert.deepEqual(book.entries.map((e) => e.kind), ['slip', 'stub', 'cancellation', 'acknowledgement']);
  assert.deepEqual(JSON.parse(recorder.book().split('\n')[3]).acknowledgement, kept.acknowledgement);
  // It is dated when it was handed over, which is before the date the person's device gave.
  assert.equal(book.entries[3].content.when, formatTime(START + HOUR));

  // Handed over with something that cannot be a line: added by itself, and acknowledged.
  const v = await makeWorld();
  const writer = await openRecorder({ book: v.book(), slip: v.slipFingerprint, privateKeys: v.agent.privateKeys, issuerKeys: [await thumbprint(v.passkey.key)], now: () => clock });
  const vCancel = await v.cancel({ when: clock });
  const alone = await writer.add({ cancellation: vCancel.record, stamps: undefined }).catch((e) => e);
  assert.match(alone.message, /by itself was added to the book/);
  assert.ok(alone.acknowledgement);
  assert.deepEqual((await writer.check()).entries.map((e) => e.kind), ['slip', 'cancellation', 'acknowledgement']);
  assert.equal((await writer.check()).summary.intact, true);
});

test('a helper agent\'s stub writer acknowledges under its pass', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  const pass = await w.pass({ when: START });
  const clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const helper = await openRecorder({ book: w.book(), slip: w.slipFingerprint, pass: pass.fingerprint, privateKeys: pass.helper.privateKeys, issuerKeys, now: () => clock });
  const cancel = await w.cancel({ when: clock });
  const { acknowledgement } = await helper.add(cancel.entry);
  const book = await checkBook(helper.book(), { issuerKeys });
  assert.equal(book.summary.intact, true);
  assert.equal(book.entries.at(-1).kind, 'acknowledgement');
  assert.equal(book.entries.at(-1).pass, pass.fingerprint);
  assert.ok(acknowledgement);
  assert.equal((await helper.act(order(1), async () => null)).done, false);
});
