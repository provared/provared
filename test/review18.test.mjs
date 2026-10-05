// What the eighteenth independent review found, in the fixes of the
// seventeenth review (4 October 2026). Each fault is fixed and each is a
// test here.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBefore, checkBook, checkShow, fromBase64url, makeShow, openChecker, openRecorder, thumbprint, toBase64url } from '../src/index.js';
import { makeStampService } from './helpers/stamp.mjs';
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
  const service = await makeStampService();
  const trust = { stampServices: [service.fingerprint] };
  const open = (book = w.book(), cancellations = undefined) =>
    openRecorder({ book, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now, options: cancellations ? { ...trust, cancellations } : trust });
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
  return { w, issuerKeys, state, service, open, cancel, stampFor, stoppedAfterReopen };
}

// --- the options a checker is given ---

test('finding 1: options that share values are copied once, and cost no more than they hold', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const book = w.book();
  // Each level holds three references to the one below: no loop, but 3 to the power 20 ways down.
  let shared = { cancellation: 'x' };
  for (let i = 0; i < 20; i++) shared = { a: shared, b: shared, c: shared };
  const options = { issuerKeys, cancellations: [shared] };
  const started = Date.now();
  const whole = await checkBook(book, options);
  assert.deepEqual(await (await openChecker(book, options)).result(), whole);
  assert.equal(whole.summary.problemFound, true);
  await checkShow(await makeShow(book, [0]), options);
  assert.equal((await checkBefore(book, { slip: w.slipFingerprint, ...order(1), when: START + HOUR }, options)).allowed, false);
  assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
});

test('finding 1: options that hold themselves are copied once', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const book = w.book();
  for (const name of ['blocks', 'vouchers']) {
    const loop = [];
    loop.push(loop, loop, loop);
    const started = Date.now();
    const whole = await checkBook(book, { issuerKeys, [name]: loop });
    assert.deepEqual(await (await openChecker(book, { issuerKeys, [name]: loop })).result(), whole, name);
    assert.ok(Date.now() - started < 5000, `${name}: took ${Date.now() - started} ms`);
  }
});

test('finding 2: an option that cannot be looked into is a problem with the whole check, never a crash', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const book = w.book();
  const show = await makeShow(book, [1]);
  const revoked = () => {
    const r = Proxy.revocable([], {});
    r.revoke();
    return r.proxy;
  };
  for (const name of ['cancellations', 'stampServices', 'vouchers', 'withoutMethods', 'sealKeys']) {
    const options = () => ({ issuerKeys, [name]: revoked() });
    const whole = await checkBook(book, options());
    assert.deepEqual(
      whole.problems.map((p) => p.code),
      ['check-failed'],
      name,
    );
    assert.deepEqual(await (await openChecker(book, options())).result(), whole, name);
    assert.ok((await checkShow(show, options())).problems.some((p) => p.code === 'check-failed'), name);
    assert.equal((await checkBefore(book, { slip: w.slipFingerprint, ...order(1), when: START + HOUR }, options())).allowed, false, name);
    await assert.rejects(
      openRecorder({ book, slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => START + HOUR, options: { [name]: revoked() } }),
      (e) => e.code === 'bad-field',
      name,
    );
  }
  // A Proxy whose own traps fail or say too much is read as a whole check reads it, and answered.
  const lying = new Proxy({}, { ownKeys: () => ['x'], getOwnPropertyDescriptor: () => undefined });
  const noPrototype = new Proxy({}, { getPrototypeOf() { throw new Error('no prototype'); } });
  for (const value of [lying, noPrototype]) {
    for (const name of ['cancellations', 'blocks']) {
      const whole = await checkBook(book, { issuerKeys, [name]: value });
      assert.deepEqual(whole.problems.map((p) => p.code), ['bad-field'], name);
      assert.deepEqual(await (await openChecker(book, { issuerKeys, [name]: value })).result(), whole, name);
    }
  }
});

test('the check before acting reads its options once, for the book and the decision alike', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const trusted = [await thumbprint(w.passkey.key)];
  let reads = 0;
  const options = {
    get issuerKeys() {
      reads++;
      return reads === 1 ? trusted : ['someone else'];
    },
  };
  const answer = await checkBefore(w.book(), { slip: w.slipFingerprint, ...order(1), when: START + HOUR }, options);
  assert.equal(reads, 1);
  assert.equal(answer.allowed, true);
});

// --- the stub writer ---

test('what is handed to "add" is copied once, and refused if it holds more than a line could', async () => {
  const s = await setUp();
  const writer = await s.open();
  // Each of six levels holds 200 references to the one below: shallow
  // enough for a line, but written out, 200 to the power 6 values.
  let shared = 'x';
  for (let i = 0; i < 6; i++) {
    const next = {};
    for (let b = 0; b < 200; b++) next['m' + b] = shared;
    shared = next;
  }
  const loop = { payload: 'e30' };
  loop.signatures = [loop];
  const started = Date.now();
  for (const record of [shared, loop]) await assert.rejects(writer.add({ cancellation: record }), (e) => e.code === 'record-not-sound');
  assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
  assert.equal((await writer.act(order(1), async () => null)).done, true);
});

test('finding 3: a member read through a getter, beside a Proxy, is read once, and the writer stops', async () => {
  for (const clockFails of [false, true]) {
    for (const ahead of [false, true]) {
      const s = await setUp();
      const writer = await s.open();
      const c = await s.cancel(s.state.clock + (ahead ? 10 * MINUTE : 0));
      let reads = 0;
      const record = {
        get payload() {
          reads++;
          return reads === 1 ? c.record.payload : 'e30';
        },
        signatures: new Proxy(c.record.signatures, {}),
      };
      s.state.fail = clockFails;
      await writer.add({ cancellation: record }).catch(() => null);
      s.state.fail = false;
      const where = `${ahead ? 'dated ahead' : 'dated now'}, clock ${clockFails ? 'failing' : 'working'}`;
      assert.equal(reads, 1, where);
      assert.equal((await writer.act(order(1), async () => null)).done, false, where);
      assert.ok(await s.stoppedAfterReopen(writer), where);
    }
  }
});

test('finding 4: a sound time-stamp beside a faulty item, in a Proxy of the list, is kept', async () => {
  for (const faulty of ['a null item', 'a gap']) {
    for (const wrap of [false, true]) {
      const s = await setUp();
      const writer = await s.open();
      const c = await s.cancel(s.state.clock - 10 * MINUTE);
      const good = await s.stampFor(c, c.when + MINUTE);
      const list = faulty === 'a null item' ? [null, good] : [, good];
      await writer.add({ cancellation: c.record, stamps: wrap ? new Proxy(list, {}) : list }).catch(() => null);
      const line = writer.book().trimEnd().split('\n').find((l) => l.startsWith('{"cancellation"'));
      assert.deepEqual(JSON.parse(line).stamps, [good], `${faulty}, ${wrap ? 'in a Proxy' : 'plain'}`);
    }
  }
});

test('finding 5: an acknowledgement that waits, carried by a copy given at opening, is the last to give way', async () => {
  const s = await setUp();
  // A stub ahead of the clock: every acknowledgement waits.
  await s.w.add({ when: s.state.clock + 10 * MINUTE });
  const first = await s.open();
  const c0 = await s.cancel(s.state.clock);
  const { acknowledgement } = await first.add(c0.entry);
  const [carrying] = first.cancellations();
  const second = await s.open(first.book(), [carrying]);
  for (let i = 1; i <= 16; i++) await second.add((await s.cancel(s.state.clock + i * 1000)).entry).catch(() => null);
  const held = second.cancellations();
  assert.equal(held.length, 16);
  assert.ok(held.some((h) => h.cancellation.payload === c0.record.payload));
  const third = await s.open(second.book(), held);
  assert.deepEqual((await third.add(c0.entry).catch((e) => e)).acknowledgement, acknowledgement);
});

test('finding 6: a copy given at opening that cannot be read as plain data is refused', async () => {
  const s = await setUp();
  const c = await s.cancel(s.state.clock + 10 * MINUTE);
  const stamp = await s.stampFor(c, c.when + MINUTE);
  let reads = 0;
  class Copy {
    constructor() {
      this.cancellation = c.record;
      Object.defineProperty(this, 'stamps', {
        get() {
          if (reads++ === 0) throw new Error('not ready yet');
          return [stamp];
        },
        enumerable: true,
      });
    }
  }
  await assert.rejects(s.open(s.w.book(), [Object.freeze(new Copy())]), (e) => e.code === 'bad-field');
  // One that holds a function is refused in the same way.
  await assert.rejects(s.open(s.w.book(), [{ cancellation: c.record, stamps: [() => stamp] }]), (e) => e.code === 'bad-field');
});

// --- three fixes of the seventeenth review that no test held ---

const walksNowhere = (list) => Object.defineProperty(list, Symbol.iterator, { value: function* () {} });

test('a copy\'s acknowledgements are read place by place, whatever the list says of itself', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const c = await w.cancel({ when: START + 2 * HOUR });
  w.entries.pop();
  class Copy {
    constructor() {
      this.cancellation = c.record;
      this.acknowledgements = walksNowhere([{ payload: 'e30', signatures: [] }]);
    }
  }
  const r = await checkBook(w.book(), { issuerKeys, cancellations: [new Copy()] });
  assert.equal(r.summary.problemFound, true);
});

test('a page\'s disclosures are read place by place, whatever the list says of itself', async () => {
  const w = await makeWorld({ cover: ['purpose'] });
  await w.add({ when: START });
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const show = await makeShow(w.book(), [0]);
  show.pages[0].disclosures = walksNowhere(['not-a-disclosure']);
  const r = await checkShow(show, { issuerKeys });
  assert.ok(r.problems.some((p) => p.code === 'cover-invalid'));
});

test('a Show reads its options through the fixed copy: a list that says yes to every key trusts none', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  class Keys extends Array {
    includes() {
      return true;
    }
  }
  const r = await checkShow(await makeShow(w.book(), [0, 1]), { issuerKeys: Keys.from(['not this one']) });
  assert.ok(r.entries[0].problems.some((p) => p.code === 'issuer-not-expected'));
  assert.equal(r.summary.problemFound, true);
});
