// The stub writer beside an agent: ask first, act, write the receipt.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBook, countersign, openRecorder, thumbprint } from '../src/index.js';
import { START, makeWorld, openWriter } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const ORDER = 'supplies.order';

async function opened(w, more = {}) {
  // The tests use dates of their own, so the writer is given a clock that follows them.
  return openWriter({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys: [await thumbprint(w.passkey.key)], ...more });
}
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });

test('an allowed action is taken once, and its stub joins the chain', async () => {
  const w = await makeWorld();
  const recorder = await opened(w);
  let taken = 0;
  const first = await recorder.act(order(150), async () => ++taken, { when: START, countersign: (stub) => countersign(stub, w.service.privateKeys, START + 1000) });
  assert.equal(first.done, true);
  assert.equal(first.result, 1);
  assert.equal(first.stub.seq, 0);
  const second = await recorder.act(order(50), async () => ++taken, { when: START + HOUR });
  assert.equal(second.stub.seq, 1);
  const r = await checkBook(recorder.book());
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.withinSlips, true);
  assert.deepEqual(r.summary.counts.stubs, 2);
  assert.equal(r.entries[1].countersignature.state, 'valid');
  assert.equal(taken, 2);
});

test('an action that would be outside the slip is not taken, and nothing is written', async () => {
  const w = await makeWorld();
  const recorder = await opened(w);
  await recorder.act(order(150), async () => 'done', { when: START });
  const before = recorder.book();
  let taken = false;
  const refused = await recorder.act(order(51), async () => (taken = true), { when: START + HOUR });
  assert.equal(refused.done, false);
  assert.equal(taken, false);
  assert.deepEqual(refused.answer.breaches.map((b) => b.code), ['over-limit']);
  assert.equal(recorder.book(), before);
});

test('if taking the action fails, the error is passed on and no stub is written', async () => {
  const w = await makeWorld();
  const recorder = await opened(w);
  const before = recorder.book();
  await assert.rejects(
    recorder.act(
      order(10),
      async () => {
        throw new Error('the supplier did not answer');
      },
      { when: START },
    ),
    /did not answer/,
  );
  assert.equal(recorder.book(), before);
});

test('opened on a book that already holds stubs, the writer carries the chain on', async () => {
  const w = await makeWorld();
  await w.add({ value: 20 });
  await w.add({ value: 20 });
  const recorder = await opened(w);
  const next = await recorder.act(order(20), async () => null, { when: START + 2 * HOUR });
  assert.equal(next.stub.seq, 2);
  assert.equal((await checkBook(recorder.book())).summary.intact, true);
});

test('"record" writes what happened, even outside the slip: the record is of what happened', async () => {
  const w = await makeWorld();
  const recorder = await opened(w);
  await recorder.record(order(500), { when: START });
  const r = await checkBook(recorder.book());
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.withinSlips, false);
});

test('the writer will not open on a damaged book, or act for a passkey it was not told to trust', async () => {
  const w = await makeWorld();
  await w.add();
  await assert.rejects(opened(w, { book: w.book().replace(/\n$/, 'x\n') }), (e) => e.code === 'record-not-sound');
  const stranger = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys: ['A'.repeat(43)] }).catch((e) => e);
  assert.equal(stranger.code, 'record-not-sound');
});

test('a helper agent\'s writer acts under its pass, in its own chain', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  await w.add({ value: 10 });
  const pass = await w.pass({ limits: [{ action: ORDER, max: 30, unit: 'GBP' }] });
  const helper = await opened(w, { privateKeys: pass.helper.privateKeys, pass: pass.fingerprint });
  const first = await helper.act(order(20), async () => null, { when: START + HOUR });
  assert.equal(first.stub.seq, 0);
  const over = await helper.act(order(11), async () => null, { when: START + 2 * HOUR });
  assert.equal(over.done, false);
  const r = await checkBook(helper.book());
  assert.equal(r.summary.intact, true);
  assert.equal(r.entries.at(-1).pass, pass.fingerprint);
});

test('where the slip asks for approval, the writer takes the action only with the signed approval', async () => {
  const w = await makeWorld({ fields: { requires: [{ above: 50, action: ORDER, need: 'approval', unit: 'GBP' }] } });
  const recorder = await opened(w);
  const without = await recorder.act(order(60), async () => null, { when: START });
  assert.equal(without.done, false);
  assert.deepEqual(without.answer.breaches.map((b) => b.code), ['approval-missing']);
  const approval = await w.approve({ slip: w.slipFingerprint, ...order(60), when: START - 60000 });
  const withIt = await recorder.act(order(60), async () => null, { when: START, approval });
  assert.equal(withIt.done, true);
  const r = await checkBook(recorder.book());
  assert.equal(r.summary.withinSlips, true);
  assert.equal(r.summary.counts.approved, 1);
});
