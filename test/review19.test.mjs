// What the nineteenth independent review found, in the fixes of the
// eighteenth review (5 October 2026). Each fault is fixed and each is a
// test here.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fixedOptions } from '../src/book.js';
import { checkBefore, checkBook, fromBase64url, openChecker, openRecorder, thumbprint, toBase64url } from '../src/index.js';
import { makeStampService } from './helpers/stamp.mjs';
import { START, makeWorld } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const MINUTE = 60 * 1000;
const ORDER = 'supplies.order';
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });

async function setUp() {
  const w = await makeWorld();
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const clock = START + HOUR;
  const service = await makeStampService();
  const trust = { stampServices: [service.fingerprint] };
  const open = (book = w.book(), cancellations = undefined) =>
    openRecorder({ book, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock, options: cancellations ? { ...trust, cancellations } : trust });
  const cancel = async (when) => {
    const c = await w.cancel({ when });
    w.entries.pop();
    return c;
  };
  const stampFor = async (c, at) => toBase64url(await service.stamp(fromBase64url(c.fingerprint), at));
  const stoppedAfterReopen = async (writer) => {
    const held = writer.cancellations();
    const again = await open(writer.book(), held.length ? held : undefined);
    return (await again.act(order(1), async () => null)).done === false;
  };
  return { w, issuerKeys, clock, service, trust, open, cancel, stampFor, stoppedAfterReopen };
}

// --- the stub writer ---

test('finding 1: what is handed to "add" beside a cancellation cannot use memory or time out of proportion', async () => {
  const s = await setUp();
  const big = 'x'.repeat(20_000_000);
  // A list that, written out, fits a line by itself, named by 2,000 members.
  const list = Array(20_000).fill('a');
  const many = {};
  for (let i = 0; i < 2000; i++) many['m' + i] = list;
  for (const beside of [{ junk: Array(200).fill(big) }, many]) {
    const writer = await s.open();
    const c = await s.cancel(s.clock);
    const started = Date.now();
    await writer.add({ cancellation: c.record, ...beside }).catch(() => null);
    assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
    assert.equal((await writer.act(order(1), async () => null)).done, false);
    assert.ok(await s.stoppedAfterReopen(writer));
    assert.ok(writer.book().includes(c.record.payload), 'the cancellation is in the book');
  }
});

test('finding 1: a copy given at opening with too much beside its cancellation is refused at once', async () => {
  const s = await setUp();
  const c = await s.cancel(s.clock);
  const list = Array(20_000).fill('a');
  const copy = { cancellation: c.record };
  for (let i = 0; i < 2000; i++) copy['m' + i] = list;
  const started = Date.now();
  await assert.rejects(s.open(s.w.book(), [copy]), (e) => e.code === 'bad-field');
  assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
});

test('finding 1: "add" does not write out what cannot be an entry', async () => {
  const s = await setUp();
  const writer = await s.open();
  const revoked = Proxy.revocable({}, {});
  revoked.revoke();
  // A list that says it is as long as a list can be, and holds an item in every place.
  const endless = new Proxy([], { get: (t, k, r) => (k === 'length' ? 2 ** 32 - 1 : typeof k === 'string' && /^\d+$/.test(k) ? 'x' : Reflect.get(t, k, r)), has: () => true });
  const started = Date.now();
  for (const entry of [revoked.proxy, endless, 'text', null]) {
    await assert.rejects(writer.add(entry), (e) => e.code === 'record-not-sound');
  }
  assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
  // No place of a list is even read.
  let reads = 0;
  const counted = new Proxy(['a', 'b'], { get: (t, k, r) => (typeof k === 'string' && /^\d+$/.test(k) && reads++, Reflect.get(t, k, r)) });
  await assert.rejects(writer.add(counted), (e) => e.code === 'record-not-sound');
  assert.equal(reads, 0);
  assert.equal((await writer.act(order(1), async () => null)).done, true);
});

test('finding 2: a list whose length is not a number is not read as a list that holds it', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const thumb = await thumbprint(w.passkey.key);
  const lying = new Proxy([], { get: (t, k, r) => (k === 'length' ? thumb : Reflect.get(t, k, r)) });
  const book = w.book();
  const whole = await checkBook(book, { issuerKeys: lying });
  assert.ok(whole.entries[0].problems.some((p) => p.code === 'issuer-not-expected'));
  assert.deepEqual(await (await openChecker(book, { issuerKeys: lying })).result(), whole);
  assert.equal((await checkBefore(book, { slip: w.slipFingerprint, ...order(1), when: START + HOUR }, { issuerKeys: lying })).allowed, false);

  // In "add", a list of time-stamps whose length is a time-stamp puts nothing into the book.
  const s = await setUp();
  const writer = await s.open();
  const c = await s.cancel(s.clock - 10 * MINUTE);
  const stamp = await s.stampFor(c, c.when + MINUTE);
  const stamps = new Proxy([], { get: (t, k, r) => (k === 'length' ? stamp : Reflect.get(t, k, r)) });
  await writer.add({ cancellation: c.record, stamps }).catch(() => null);
  const line = writer.book().trimEnd().split('\n').find((l) => l.startsWith('{"cancellation"'));
  assert.equal(JSON.parse(line).stamps, undefined);
  assert.equal((await writer.act(order(1), async () => null)).done, false);
});

test('finding 3: an option for signing methods that cannot be read is a problem with the whole check, never a throw', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const options = () => ({
    issuerKeys,
    get withoutMethods() {
      throw new Error('not ready');
    },
  });
  const book = w.book();
  const whole = await checkBook(book, options());
  assert.deepEqual(whole.problems.map((p) => p.code), ['check-failed']);
  assert.deepEqual(await (await openChecker(book, options())).result(), whole);
});

test('finding 4: nothing deep in the options is kept as handed over, so a carried checker is fixed when opened', async () => {
  const s = await setUp();
  await s.w.add({ when: START });
  const c = await s.cancel(START + 30 * MINUTE);
  const record = structuredClone(c.record);
  const copy = { cancellation: record, stamps: [await s.stampFor(c, c.when + MINUTE)] };
  // The same copy, 15 levels down in another option.
  let deep = copy;
  for (let i = 0; i < 14; i++) deep = { a: deep };
  const options = { issuerKeys: s.issuerKeys, ...s.trust, vouchers: [deep], cancellations: [copy] };
  const book = s.w.book();
  const checker = await openChecker(book, options);
  const first = await checker.result();
  assert.deepEqual(first, await checkBook(book, options));
  record.signatures.length = 0;
  assert.deepEqual(await checker.result(), first);
});

test('finding 5: the passkeys the stub writer trusts are read as a whole check reads them, a Proxy among them', async () => {
  const s = await setUp();
  const writer = await openRecorder({ book: s.w.book(), slip: s.w.slipFingerprint, privateKeys: s.w.agent.privateKeys, issuerKeys: new Proxy([...s.issuerKeys], {}), now: () => s.clock });
  assert.equal((await writer.act(order(1), async () => null)).done, true);
});

// --- held by no test before ---

test('a gap at the end of a list in the options stays a gap', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const issuerKeys = [await thumbprint(w.passkey.key)];
  // eslint-disable-next-line no-sparse-arrays
  const options = { issuerKeys, blocks: ['a'.repeat(64), ,] };
  const whole = await checkBook(w.book(), options);
  assert.ok(whole.problems.some((p) => p.code === 'bad-field'));
  assert.deepEqual(await (await openChecker(w.book(), options)).result(), whole);
});

test('a fixed copy of the options handed in again is not copied again', () => {
  const fixed = fixedOptions({ issuerKeys: ['x'], blocks: [] });
  assert.equal(fixedOptions(fixed), fixed);
  assert.notEqual(fixedOptions({ ...fixed }), fixed);
});
