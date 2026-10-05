// A checker that is carried on: it reads a book once, keeps what it has
// worked out, and then takes more lines without reading the earlier ones
// again. Its answer must be the answer a whole check gives, at every length
// of the book. The stub writer carries its book on in this way.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBook, countersign, fromBase64url, keySetFingerprint, openChecker, openRecorder, thumbprint, toBase64url } from '../src/index.js';
import { answerOf, carryOn, forkCarried, promoteCarried, startCarried } from '../src/book.js';
import { START, makeWorld } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const MINUTE = 60 * 1000;
const ORDER = 'supplies.order';
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });
const linesOf = (book) => book.split('\n').filter(Boolean).map((l) => l + '\n');

// A book that holds every kind of entry, sound and unsound, in which later
// lines change what earlier ones show: a helper's stub dated earlier puts
// an earlier stub over a limit "in any period"; a seal's time-stamp covers
// the entries before it; a cancellation marks stubs that no seal covers.
let made;
async function variedBook() {
  if (made) return made;
  const w = await makeWorld({
    cover: ['purpose'],
    fields: {
      passes: 1,
      limits: [
        { action: ORDER, max: 400, unit: 'GBP' },
        { action: ORDER, max: 100, per: 7200, unit: 'GBP' },
        { action: ORDER, count: 6 },
      ],
      requires: [{ above: 80, action: ORDER, need: 'approval', unit: 'GBP' }],
    },
  });
  const terms = await w.publishTerms(); // 1
  await w.add({ value: 10, when: START, terms: terms.fingerprint }); // 2
  const vouching = await w.vouch({ kind: 'agent', keys: w.agent.keys, name: 'Office supplies agent' }); // 3
  await w.add({ value: 30, when: START + 10 * MINUTE, countersigned: false }); // 4
  const pass = await w.pass({ when: START + 15 * MINUTE }); // 5
  await pass.add({ value: 30, when: START + 20 * MINUTE }); // 6
  const sealed = await w.seal({ when: START + 40 * MINUTE, blockTime: START + 45 * MINUTE }); // 7
  await w.refuse({ when: START + 50 * MINUTE }); // 8
  await w.add({ value: 25, when: START + 60 * MINUTE }); // 9: 95 in its two hours, until the helper's next stub is read
  await pass.add({ value: 20, when: START + 30 * MINUTE }); // 10: dated earlier; entry 9 is now over the limit in its period
  await w.add({ value: 90, when: START + 3 * HOUR, approve: true }); // 11
  await w.add({ action: 'other.action', amount: undefined, when: START + 3 * HOUR + MINUTE }); // 12
  const cancelled = await w.cancel({ when: START + 4 * HOUR, stampTime: START + 4 * HOUR + 5000 }); // 13
  await w.acknowledge(cancelled.fingerprint, { when: START + 4 * HOUR + 30000 }); // 14: the agent's side says it was told
  await w.withdraw(vouching.fingerprint, { when: START + 4 * HOUR + MINUTE }); // 15
  await w.add({ value: 5, when: START + 5 * HOUR }); // 16: after the cancellation
  await w.seal({ when: START + 6 * HOUR }); // 17
  const lines = linesOf(w.book());
  lines.push('{"not":"an entry"}\n'); // 18
  lines.push('not a line at all\n'); // 19
  lines.push(lines[2]); // 20: a stub a second time
  // The person's own copy of a second cancellation, which the book leaves out, with the acknowledgement they were given.
  const held = await w.cancel({ when: START + 2 * HOUR, stampTime: START + 2 * HOUR + 5000 });
  held.entry.acknowledgements = [(await w.acknowledge(held.fingerprint, { when: START + 2 * HOUR + 30000 })).record];
  const options = {
    issuerKeys: [await thumbprint(w.passkey.key)],
    stampServices: [w.stampService.fingerprint],
    blocks: [sealed.block.fingerprint],
    sealKeys: [await keySetFingerprint(w.recorder.keys)],
    vouchers: [await keySetFingerprint(w.organisation.keys)],
    disclosures: { [w.slipFingerprint]: w.prepared.disclosures },
    cancellations: [held.entry],
  };
  made = { w, lines, options };
  return made;
}

test('a checker that is carried on gives the answer a whole check gives, at every length of the book', async () => {
  const { lines, options } = await variedBook();
  for (const trust of [options, {}]) {
    const checker = await openChecker('', trust);
    assert.deepEqual(await checker.result(), await checkBook('', trust));
    let text = '';
    for (const line of lines) {
      await checker.add(line);
      text += line;
      assert.deepEqual(await checker.result(), await checkBook(text, trust), `after ${linesOf(text).length} lines`);
    }
    // The book is the varied one it is meant to be: it has findings of many kinds.
    const whole = await checker.result();
    const found = new Set([...whole.problems, ...whole.entries.flatMap((e) => [...e.problems, ...e.breaches])].map((f) => f.code));
    for (const code of ['over-period-limit', 'action-not-allowed', 'after-cancellation', 'not-json', 'duplicate-id']) {
      assert.ok(found.has(code), code);
    }
    assert.equal(whole.size, lines.length);
  }
});

test('a checker opened part of the way through a book, and handed the rest in pieces, gives the same answer', async () => {
  const { lines, options } = await variedBook();
  const whole = await checkBook(lines.join(''), options);
  for (const [first, second] of [
    [1, 2],
    [7, 9],
    [10, 14],
    [17, lines.length],
  ]) {
    const checker = await openChecker(lines.slice(0, first).join(''), options);
    await checker.add(lines.slice(first, second).join(''));
    await checker.add(lines.slice(second).join(''));
    assert.deepEqual(await checker.result(), whole, `${first}, ${second}`);
  }
});

test('an answer is a copy: nothing done to it changes the checker', async () => {
  const { lines, options } = await variedBook();
  const checker = await openChecker(lines.slice(0, 5).join(''), options);
  const before = await checker.result();
  const spoiled = await checker.result();
  spoiled.entries[2].problems.push({ code: 'made-up', message: 'x' });
  spoiled.entries[2].content.action = 'something.else';
  spoiled.entries.length = 0;
  spoiled.summary.intact = true;
  assert.deepEqual(await checker.result(), before);
});

test('what a carried checker is handed must be whole lines, and a book with no line feed at its end cannot be added to', async () => {
  const { lines } = await variedBook();
  const text = lines.slice(0, 3).join('');
  // A missing line feed after the last line is allowed, as in a whole check.
  const open = await openChecker(text.slice(0, -1));
  assert.deepEqual(await open.result(), await checkBook(text.slice(0, -1)));
  await assert.rejects(open.add(lines[3]), RangeError);
  assert.deepEqual(await open.result(), await checkBook(text.slice(0, -1)));
  // Nothing at all, or something that is not text, adds nothing.
  const checker = await openChecker(text);
  await checker.add('');
  await checker.add(undefined);
  assert.deepEqual(await checker.result(), await checkBook(text));
  // An empty line is a line, as in a whole check.
  await checker.add('\n');
  assert.deepEqual(await checker.result(), await checkBook(text + '\n'));
});

test('a carried checker with no book, with an option that cannot be used, or with too many entries answers as a whole check does', async () => {
  const { lines } = await variedBook();
  assert.deepEqual(await (await openChecker()).result(), await checkBook(''));
  const bad = { blocks: ['not a block'] };
  const checker = await openChecker(lines[0], bad);
  await checker.add(lines[1]);
  assert.deepEqual(await checker.result(), await checkBook(lines[0] + lines[1], bad));
  assert.deepEqual((await checker.result()).problems.map((p) => p.code), ['bad-field']);
  // One entry too many: nothing is read, and no later line mends it.
  const full = await openChecker(lines[0]);
  const flood = 'x\n'.repeat(100000);
  await full.add(flood);
  const answer = await full.result();
  assert.deepEqual(answer.problems.map((p) => p.code), ['too-large']);
  assert.deepEqual(answer, await checkBook(lines[0] + flood));
  await full.add(lines[1]);
  assert.deepEqual((await full.result()).problems.map((p) => p.code), ['too-large']);
});

test('the options are fixed when a carried checker is opened', async () => {
  const { lines, options } = await variedBook();
  const mine = structuredClone(options);
  const checker = await openChecker(lines.slice(0, 8).join(''), mine);
  mine.stampServices.length = 0;
  mine.issuerKeys[0] = 'A'.repeat(43);
  delete mine.cancellations;
  await checker.add(lines.slice(8).join(''));
  assert.deepEqual(await checker.result(), await checkBook(lines.join(''), options));
});

// --- trying a stub (the stub writer's way) ---

test('trying a stub on a reader split off the book leaves the book\'s own reader exactly as it was', async () => {
  const { lines, options } = await variedBook();
  let text = '';
  const carried = startCarried(options);
  for (const line of lines) {
    const before = (await answerOf(carried)).result;
    const readable = line.startsWith('{');
    const isStub = readable && Object.hasOwn(JSON.parse(line), 'stub');
    // Split off, and read the next line there.
    const tried = forkCarried(carried);
    await carryOn(tried, line);
    const there = (await answerOf(tried)).result;
    if (isStub) assert.deepEqual(there, await checkBook(text + line, options), `the stub at entry ${before.size}`);
    // Only a stub may be tried: any other kind of entry is a problem there, and is not read.
    else if (readable) assert.deepEqual(there.entries.at(-1).problems.map((p) => p.code), ['check-failed']);
    else assert.ok(there.entries.at(-1).problems.length > 0);
    // The reader it was split from shows what it showed before.
    assert.deepEqual((await answerOf(carried)).result, before);
    // And carries on as if nothing had been tried.
    await carryOn(carried, line);
    text += line;
    assert.deepEqual((await answerOf(carried)).result, await checkBook(text, options));
  }
});

test('a reader that tried a stub can take the place of the book\'s own, and then reads any kind of entry', async () => {
  const { lines, options } = await variedBook();
  // Entries 0 to 8, then the stub at entry 9 tried on a split-off reader, which then reads the rest.
  const carried = startCarried(options);
  await carryOn(carried, lines.slice(0, 9).join(''));
  const tried = forkCarried(carried);
  await carryOn(tried, lines[9]);
  const next = promoteCarried(tried);
  await carryOn(next, lines.slice(10).join(''));
  assert.deepEqual((await answerOf(next)).result, await checkBook(lines.join(''), options));
});

test('trying a line of any kind on a reader split off whole leaves the book\'s own reader exactly as it was', async () => {
  const { lines, options } = await variedBook();
  let text = '';
  let carried = startCarried(options);
  for (const [n, line] of lines.entries()) {
    const before = (await answerOf(carried)).result;
    // Split off whole, read the next line there, ask for the answer, and throw the reader away.
    const tried = forkCarried(carried, true);
    await carryOn(tried, line);
    assert.deepEqual((await answerOf(tried)).result, await checkBook(text + line, options), `entry ${n}, tried`);
    assert.deepEqual((await answerOf(carried)).result, before, `entry ${n}: the reader it was split from`);
    // A second reader split off whole reads the line and takes the book's place: the book is carried on by such readers alone.
    const next = forkCarried(carried, true);
    await carryOn(next, line);
    carried = promoteCarried(next);
    text += line;
    assert.deepEqual((await answerOf(carried)).result, await checkBook(text, options), `entry ${n}, carried on`);
  }
});

// --- the stub writer carries its book on ---

test('the stub writer\'s view of its book is the view a whole check gives, after every call', async () => {
  const w = await makeWorld({
    fields: {
      passes: 1,
      limits: [
        { action: ORDER, max: 120, unit: 'GBP' },
        { action: ORDER, max: 60, per: 3600, unit: 'GBP' },
      ],
      requires: [{ above: 40, action: ORDER, need: 'approval', unit: 'GBP' }],
    },
  });
  const pass = await w.pass({ when: START });
  let clock = START + MINUTE;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const open = (more) => openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock, ...more });
  const agent = await open();
  const same = async (writer, what) => {
    const options = { issuerKeys, cancellations: writer.cancellations().length ? writer.cancellations() : undefined };
    if (options.cancellations === undefined) delete options.cancellations;
    assert.deepEqual(await writer.check(), await checkBook(writer.book(), options), what);
  };
  const sign = (stub) => countersign(stub, w.service.privateKeys, clock + 1000);
  let taken = 0;
  const act = async (writer, value, more = {}) => writer.act(order(value), async () => ++taken, more);

  await same(agent, 'opened');
  assert.equal((await act(agent, 10, { countersign: sign })).done, true);
  await same(agent, 'a countersigned action');
  clock += MINUTE;
  assert.equal((await act(agent, 20)).done, true);
  await same(agent, 'a one-sided action');
  // Outside the slip: not taken, nothing written.
  clock += MINUTE;
  assert.equal((await act(agent, 45)).done, false);
  assert.equal((await act(agent, 31)).done, false);
  await same(agent, 'two actions that were not allowed');
  // An action that fails: no stub.
  await assert.rejects(agent.act(order(5), async () => Promise.reject(new Error('the supplier did not answer'))), /did not answer/);
  await same(agent, 'an action that failed');
  // With the person's approval.
  clock += 2 * HOUR;
  const approval = await w.approve({ slip: w.slipFingerprint, ...order(50), when: clock });
  assert.equal((await act(agent, 50, { approval, countersign: sign })).done, true);
  await same(agent, 'an approved action');
  // A countersignature that does not check is left out.
  clock += MINUTE;
  const wrong = await act(agent, 5, { countersign: async () => ({ payload: 'AAAA', signatures: [] }) });
  assert.equal(wrong.done, true);
  assert.equal(wrong.stub.countersignature.accepted, false);
  await same(agent, 'a countersignature that did not check');
  // "record" writes what happened, inside the slip or not; a stub that would not fit is refused.
  clock += MINUTE;
  await agent.record(order(100));
  await same(agent, 'a recorded action outside the slip');
  await assert.rejects(agent.record(order(1), { when: clock - HOUR }), (e) => e.code === 'record-not-sound');
  await same(agent, 'a stub that was refused');
  // Entries that someone else made: a refusal, a seal that fits, a seal that does not, a cancellation dated ahead.
  const refusal = await w.refuse({ when: clock });
  await agent.add({ refusal: refusal.record });
  await same(agent, 'a refusal');
  w.entries.length = 0;
  w.entries.push(...linesOf(agent.book()).map((l) => JSON.parse(l)));
  const sealed = await w.seal({ when: clock + 1000, stamp: false });
  await agent.add(sealed.entry);
  await same(agent, 'a seal');
  await assert.rejects(agent.add(sealed.entry), (e) => e.code === 'record-not-sound');
  await same(agent, 'a seal that did not fit');
  clock += MINUTE;
  assert.equal((await act(agent, 1)).done, false); // the total is over the limit by now
  const cancel = await w.cancel({ when: clock + 10 * MINUTE });
  await assert.rejects(agent.add(cancel.entry), /allows nothing more under that slip/);
  await same(agent, 'a cancellation that is kept beside the book');
  assert.equal((await agent.before(order(1))).breaches.some((b) => b.code === 'after-cancellation'), true);
  clock += 20 * MINUTE;
  assert.equal((await act(agent, 1)).done, false);
  assert.equal((await agent.check()).summary.counts.cancellations, 1);
  await same(agent, 'the kept cancellation, written into the book');

  // A helper under a pass, in a chain of its own, from a book that another writer wrote.
  const v = await makeWorld({ fields: { passes: 1 } });
  const helperPass = await v.pass({ when: START });
  const helper = await openRecorder({ book: v.book(), slip: v.slipFingerprint, pass: helperPass.fingerprint, privateKeys: helperPass.helper.privateKeys, issuerKeys: [await thumbprint(v.passkey.key)], now: () => clock });
  assert.equal((await helper.act(order(10), async () => null)).done, true);
  assert.equal((await helper.act(order(10), async () => null)).done, true);
  assert.deepEqual(await helper.check(), await checkBook(helper.book(), { issuerKeys: [await thumbprint(v.passkey.key)] }));
  assert.equal((await helper.check()).summary.intact, true);
  assert.equal(pass.fingerprint.length, 43);
  assert.ok(taken >= 4);
});

test('the answer the stub writer hands out is a copy, and its calls wait for one another', async () => {
  const w = await makeWorld();
  const clock = START + MINUTE;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const writer = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock });
  const answer = await writer.check();
  answer.entries.length = 0;
  assert.equal((await writer.check()).entries.length, 1);
  // Asked for at the same moment: each call sees the book as the one before left it.
  const [first, between, second, after] = await Promise.all([
    writer.act(order(150), async () => 'first'),
    writer.check(),
    writer.act(order(150), async () => 'second'),
    writer.before(order(10)),
  ]);
  assert.equal(first.done, true);
  assert.equal(between.summary.counts.stubs, 1);
  assert.equal(second.done, false);
  assert.equal(after.allowed, true);
  assert.equal((await checkBook(writer.book(), { issuerKeys })).summary.withinSlips, true);
  assert.equal(fromBase64url(toBase64url(new Uint8Array([1]))).length, 1);
});
