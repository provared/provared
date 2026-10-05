// What the twelfth independent review found, in the acknowledgement and in
// the connector for an agent's tools (4 October 2026). Each fault is fixed,
// or stated as a limit, and each is a test here.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { NotTaken, argumentsFingerprint, checkBook, checkShow, formatTime, generateKeySet, makeShow, openRecorder, recordTools, thumbprint, writeAcknowledgement } from '../src/index.js';
import { START, makeWorld } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const MINUTE = 60 * 1000;
const ORDER = 'supplies.order';
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });
const breachesOf = (r) => r.entries.map((e) => e.breaches.map((b) => b.code));
const whenOf = (record) => JSON.parse(Buffer.from(record.payload, 'base64url').toString()).when;

// --- the acknowledgement: the stub writer ---

test('finding 1: the stub writer never dates its acknowledgement before its own last stub', async () => {
  const w = await makeWorld();
  let clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock });
  // An action dated 200 seconds ahead of the clock, as the writer allows. Ten seconds later the person cancels.
  assert.equal((await writer.act(order(10), async () => null, { when: clock + 200 * 1000 })).done, true);
  clock += 10 * 1000;
  const cancel = await w.cancel({ when: clock });
  const { acknowledgement } = await writer.add(cancel.entry);
  assert.equal(whenOf(acknowledgement), formatTime(START + HOUR + 200 * 1000));
  // The honest stub is not reported, with the book alone or with the person's copy and the acknowledgement.
  assert.deepEqual(breachesOf(await checkBook(writer.book(), { issuerKeys })), [[], [], [], []]);
  const book = writer.book().split('\n').slice(0, 2).join('\n') + '\n';
  const beside = await checkBook(book, { issuerKeys, cancellations: [{ ...cancel.entry, acknowledgements: [acknowledgement] }] });
  assert.deepEqual(beside.problems, []);
  assert.deepEqual(breachesOf(beside), [[], []]);

  // The same where the clock steps back between the stub and the cancellation.
  const v = await makeWorld();
  let time = START + HOUR;
  const other = await openRecorder({ book: v.book(), slip: v.slipFingerprint, privateKeys: v.agent.privateKeys, issuerKeys: [await thumbprint(v.passkey.key)], now: () => time });
  assert.equal((await other.act(order(10), async () => null)).done, true);
  time -= 5000;
  const given = await other.add((await v.cancel({ when: time })).entry);
  assert.equal(whenOf(given.acknowledgement), formatTime(START + HOUR));
});

test('finding 6: a writer opened again hands back the acknowledgement that was signed, not a second one', async () => {
  const w = await makeWorld();
  let clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const open = (book, options) => openRecorder({ book, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock, options });
  const first = await open(w.book());
  const cancel = await w.cancel({ when: clock + 10 * MINUTE });
  const kept = await first.add(cancel.entry).catch((e) => e);
  // Started again two minutes later, with the book and what the first writer held; the person hands the cancellation over again.
  clock += 2 * MINUTE;
  const again = await open(first.book(), { cancellations: first.cancellations() });
  const second = await again.add(cancel.entry).catch((e) => e);
  assert.match(second.message, /allows nothing more under that slip/);
  assert.deepEqual(second.acknowledgement, kept.acknowledgement);
  // Once its date has come it is written into the book, with that one acknowledgement.
  clock += 20 * MINUTE;
  assert.equal((await again.act(order(1), async () => null)).done, false);
  const book = await checkBook(again.book(), { issuerKeys });
  assert.deepEqual(book.entries.map((e) => e.kind), ['slip', 'cancellation', 'acknowledgement']);
  assert.deepEqual(JSON.parse(again.book().split('\n')[2]).acknowledgement, kept.acknowledgement);
});

test('a design remark: a writer opened with keys that are not the agent\'s hands back no acknowledgement', async () => {
  const w = await makeWorld();
  const stranger = await generateKeySet();
  const clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: stranger.privateKeys, issuerKeys, now: () => clock });
  const cancel = await w.cancel({ when: clock });
  // The cancellation is added, and stops the writer. There is no acknowledgement: one signed with these keys would not check.
  assert.deepEqual(await writer.add(cancel.entry), { acknowledgement: undefined });
  assert.deepEqual((await writer.check()).entries.map((e) => e.kind), ['slip', 'cancellation']);
  assert.equal((await writer.check()).summary.intact, true);
  assert.equal((await writer.before(order(1))).allowed, false);
});

// --- the acknowledgement: the checker ---

test('finding 8: an acknowledgement does not pass once the cancellation it names has failed', async () => {
  // The cancellation is dated 12:00. A seal after it is time-stamped at 10:31: the cancellation is not dated as it says.
  const w = await makeWorld();
  await w.add({ when: START });
  const cancel = await w.cancel({ when: START + 3 * HOUR });
  await w.acknowledge(cancel.fingerprint, { when: START + HOUR });
  await w.seal({ when: START + 90 * MINUTE });
  const trust = { stampServices: [w.stampService.fingerprint] };
  const r = await checkBook(w.book(), trust);
  assert.deepEqual(r.entries[2].problems.map((p) => p.code), ['dated-after-stamp']);
  assert.deepEqual(r.entries[3].problems.map((p) => p.code), ['cancellation-not-found']);
  assert.match(r.entries[3].problems[0].message, /did not pass its own check/);
  assert.equal(r.entries[3].verified, 'none');
  assert.equal(r.entries[3].cancellation, undefined);
  // In a Show under that seal: the same.
  const show = await checkShow(await makeShow(w.book(), [0, 1, 2, 3], { seal: 4 }), trust);
  assert.deepEqual(show.entries[3].problems.map((p) => p.code), ['cancellation-not-found']);
  // To a reader who trusts no time-stamp service, nothing settles which date is wrong: the seal is where the two
  // meet, and the cancellation and its acknowledgement are left as they are.
  const untrusted = await checkBook(w.book());
  assert.deepEqual(untrusted.entries.map((e) => e.problems.map((p) => p.code)), [[], [], [], [], ['time-went-backwards']]);
  assert.equal(untrusted.entries[3].cancellation, 2);
});

test('finding 9: what a stub is told does not depend on the order in which copies are handed over', async () => {
  const w = await makeWorld();
  await w.add({ when: START }); // 1
  await w.seal({ when: START + 10 * MINUTE }); // 2: time-stamped at 09:11
  await w.add({ when: START + 3 * HOUR }); // 3
  await w.add({ when: START + 4 * HOUR }); // 4
  // Two cancellations that the book leaves out. One has the agent's acknowledgement, dated 12:30, and no time-stamp.
  const acknowledged = await w.cancel({ when: START + 2 * HOUR });
  w.entries.pop();
  const given = await w.acknowledge(acknowledged.fingerprint, { when: START + 3 * HOUR + 30 * MINUTE });
  w.entries.pop();
  // The other is time-stamped at 11:00.
  const stamped = await w.cancel({ when: START + 2 * HOUR, stampTime: START + 2 * HOUR + 5000 });
  w.entries.pop();
  const trust = { stampServices: [w.stampService.fingerprint] };
  const first = { ...acknowledged.entry, acknowledgements: [given.record] };
  const one = await checkBook(w.book(), { ...trust, cancellations: [first, stamped.entry] });
  const other = await checkBook(w.book(), { ...trust, cancellations: [stamped.entry, first] });
  assert.deepEqual(one.entries, other.entries);
  // Both stubs after the first seal are reported by the time-stamp rule, which rests on an outside time-stamp.
  assert.deepEqual(breachesOf(one), [[], [], [], ['after-cancellation'], ['after-cancellation']]);
  assert.match(one.entries[3].breaches[0].message, /not shown to have existed before the person cancelled/);
  assert.doesNotMatch(one.entries[3].breaches[0].message, /acknowledged/);
  // The one dated after the acknowledgement is told that as well, once.
  assert.match(one.entries[4].breaches[0].message, /not shown to have existed before the person cancelled.* It is also dated after the agent's side acknowledged the cancellation, by the agent's own dates\.$/);
  // Asked for again, the answer is the same: nothing piles up.
  assert.deepEqual((await checkBook(w.book(), { ...trust, cancellations: [first, stamped.entry] })).entries, one.entries);
});

test('finding 10: an acknowledgement is not given as confirmed where this device could not confirm the slip or the copy', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const cancel = await w.cancel({ when: START + HOUR });
  w.entries.pop();
  const given = await w.acknowledge(cancel.fingerprint, { when: START + HOUR + MINUTE });
  w.entries.pop();
  await w.add({ when: START + 2 * HOUR });
  const r = await checkBook(w.book(), { cancellations: [{ ...cancel.entry, acknowledgements: [given.record] }], withoutMethods: ['ES256'] });
  assert.equal(r.held[0].used, false);
  assert.equal(r.held[0].acknowledgements[0].state, 'unavailable');
  assert.equal(r.held[0].acknowledgements[0].when, null);
  assert.deepEqual(breachesOf(r), [[], [], []]);
  assert.equal(r.summary.intact, false);
});

test('a design remark: an agent that acknowledged a cancellation cannot go on through a helper', async () => {
  const w = await makeWorld({ fields: { passes: 2 } });
  const before = await w.pass({ when: START }); // 1: handed on before the agent was told
  const cancel = await w.cancel({ when: START + HOUR });
  w.entries.pop();
  const given = await w.acknowledge(cancel.fingerprint, { when: START + HOUR + MINUTE });
  w.entries.pop();
  const after = await w.pass({ when: START + 2 * HOUR }); // 2: handed on after the agent acknowledged
  const below = await w.pass({ from: after.fingerprint, signer: after.helper.privateKeys, when: START + 2 * HOUR + MINUTE }); // 3: handed on from that pass
  await before.add({ when: START + 3 * HOUR }); // 4: under the earlier pass
  await after.add({ when: START + 3 * HOUR }); // 5
  await w.add({ when: START + 3 * HOUR, pass: below.fingerprint, signer: below.helper.privateKeys, after: null }); // 6: under the pass below
  assert.equal((await checkBook(w.book())).summary.withinSlips, true);
  const r = await checkBook(w.book(), { cancellations: [{ ...cancel.entry, acknowledgements: [given.record] }] });
  assert.deepEqual(r.problems, []);
  assert.deepEqual(breachesOf(r), [[], [], ['after-cancellation'], ['after-cancellation'], [], ['after-cancellation'], ['after-cancellation']]);
  assert.match(r.entries[2].breaches[0].message, /This pass was handed on, or comes from a pass that was handed on, after the agent's side acknowledged/);
  assert.match(r.entries[5].breaches[0].message, /written under a pass that was handed on after the agent's side acknowledged/);
  // The helper that held its pass before the agent was told is not the one that acknowledged: nothing is said of it.
  assert.deepEqual(r.entries[4].breaches, []);
});

// --- the connector for an agent's tools ---

test('finding 2: a list with a gap in it, or with a named member, is not JSON, and has no fingerprint', async () => {
  const withName = Object.assign([1], { mode: 'delete-all' });
  for (const bad of [new Array(1), [1, , 3], withName, { a: [new Array(2)] }]) {
    await assert.rejects(async () => argumentsFingerprint(bad), (e) => e.code === 'bad-field');
  }
  assert.notEqual(await argumentsFingerprint([undefined].map(() => null)), await argumentsFingerprint([]));
  // A tool is not run with arguments that cannot be fingerprinted.
  const w = await makeWorld({ fields: { actions: [ORDER, 'provared.data.read'] } });
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys: [await thumbprint(w.passkey.key)], now: () => START + HOUR });
  let ran = 0;
  const tools = recordTools(writer, { look: { action: 'provared.data.read', run: () => ++ran } });
  await assert.rejects(tools.look(withName), (e) => e.code === 'bad-field');
  await assert.rejects(tools.look({ items: new Array(3) }), (e) => e.code === 'bad-field');
  assert.equal(ran, 0);
  assert.equal(await tools.look({ items: [null, null, null] }), 1);
});

test('findings 3 and 4: what a tool is, and what it is called with, cannot be changed after it is handed over', async () => {
  const w = await makeWorld({ fields: { actions: [ORDER, 'provared.data.read'], requires: [{ above: 40, action: ORDER, need: 'approval', unit: 'GBP' }] } });
  const clock = START + HOUR;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock });
  const amount = { unit: 'GBP', value: 150 };
  const seen = [];
  const stubs = [];
  const options = { onStub: (stub) => stubs.push(stub.seq) };
  const tools = recordTools(
    writer,
    {
      fixedPrice: { action: ORDER, with: 'supplier', amount, run: () => 'ordered', approve: (request) => w.approve({ slip: w.slipFingerprint, ...request, when: clock }) },
      meddling: {
        action: ORDER,
        with: 'supplier',
        // Every function a tool is described by tries to change the arguments.
        amount: (args) => {
          args.item = 'changed by amount';
          return { unit: 'GBP', value: 45 };
        },
        approve: async (request, args) => {
          args.item = 'changed by approve';
          request.amount.value = 1;
          return w.approve({ slip: w.slipFingerprint, action: ORDER, with: 'supplier', amount: { unit: 'GBP', value: 45 }, details: request.details, when: clock });
        },
        countersign: async (stub, args) => {
          args.item = 'changed by countersign';
          return null;
        },
        run: (args) => {
          seen.push(args.item);
          return 'ordered';
        },
      },
    },
    options,
  );
  // The caller changes the amount, and what is to be told of stubs, after the tools were handed over.
  amount.value = 1;
  options.onStub = () => {
    throw new Error('changed afterwards');
  };
  assert.equal(await tools.fixedPrice({ item: 'desk' }), 'ordered');
  assert.equal(await tools.meddling({ item: 'toner' }), 'ordered');
  assert.deepEqual(seen, ['toner']);
  assert.deepEqual(stubs, [0, 1]);
  const r = await checkBook(writer.book(), { issuerKeys });
  assert.equal(r.summary.intact, true);
  assert.deepEqual(r.entries.slice(1).map((e) => e.content.amount.value), [150, 45]);
  // The stub of the second call holds the fingerprint of what the tool was run with.
  assert.equal(r.entries[2].content.details[0].sha256, await argumentsFingerprint({ item: 'toner' }));
});

test('finding 5: the person is not asked to approve where the action could not be taken anyway', async () => {
  // The slip asks for the person's approval and for the other side's countersignature. The tool has no way to ask for the second.
  const w = await makeWorld({ fields: { requires: [{ need: 'approval', action: ORDER }, { need: 'countersignature', action: ORDER }] } });
  const clock = START + HOUR;
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys: [await thumbprint(w.passkey.key)], now: () => clock });
  let asked = 0;
  let ran = 0;
  const tools = recordTools(writer, {
    placeOrder: { action: ORDER, with: 'supplier', amount: () => ({ unit: 'GBP', value: 10 }), run: () => ++ran, approve: async () => void asked++ },
  });
  const refused = await tools.placeOrder({ item: 'pens' }).catch((e) => e);
  assert.ok(refused instanceof NotTaken);
  assert.deepEqual(refused.answer.breaches.map((b) => b.code).sort(), ['approval-missing', 'countersignature-missing']);
  assert.equal(asked, 0);
  assert.equal(ran, 0);
  // The stub writer's own answer says both, too.
  const answer = (await writer.act(order(10), async () => ++ran)).answer;
  assert.deepEqual(answer.breaches.map((b) => b.code).sort(), ['approval-missing', 'countersignature-missing']);
  assert.equal(await writeAcknowledgement({ slip: w.slipFingerprint, cancellation: w.slipFingerprint, when: clock }, w.agent.privateKeys).then(() => ran), 0);
});
