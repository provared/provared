// Passing a slip on: an agent hands part of its permission to a helper
// agent, where the slip allows it.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBefore, checkBook, checkShow, generateKeySet, makeShow, prepareSlip, thumbprint } from '../src/index.js';
import { START, makeWorld, withContent } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const ORDER = 'supplies.order';

function codes(result) {
  const out = result.problems.map((p) => p.code);
  for (const e of result.entries) out.push(...e.problems.map((p) => p.code), ...e.breaches.map((b) => b.code));
  return out;
}
const breachesOf = (r) => r.entries.map((e) => e.breaches.map((b) => b.code));

test('a helper agent acts under a pass, in a chain of its own, within the slip', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  await w.add({ value: 50 });
  const pass = await w.pass();
  await pass.add({ value: 40, when: START + HOUR });
  await w.add({ value: 30, when: START + 2 * HOUR });
  await pass.add({ value: 20, when: START + 3 * HOUR });
  const r = await checkBook(w.book());
  assert.deepEqual(codes(r), []);
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.withinSlips, true);
  assert.equal(r.summary.counts.passes, 1);
  assert.equal(r.entries[2].kind, 'pass');
  // Each agent has its own numbering; the slip's total takes in both.
  assert.deepEqual(r.entries.filter((e) => e.kind === 'stub').map((e) => [e.content.seq, e.pass ? 'helper' : 'agent', e.running.total]), [
    [0, 'agent', '50'],
    [0, 'helper', '90'],
    [1, 'agent', '120'],
    [1, 'helper', '140'],
  ]);
});

test('the slip\'s limit holds for the agent and its helpers together', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  await w.add({ value: 150 });
  const pass = await w.pass();
  await pass.add({ value: 51, when: START + HOUR });
  const r = await checkBook(w.book());
  assert.deepEqual(breachesOf(r), [[], [], [], ['over-limit']]);
});

test('a pass may set narrower limits of its own, and the helper\'s stubs are compared with them', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  const pass = await w.pass({ limits: [{ action: ORDER, max: 30, unit: 'GBP' }], validUntil: '2026-10-06T08:00:00Z' });
  await pass.add({ value: 20 });
  await pass.add({ value: 20, when: START + HOUR });
  await pass.add({ value: 1, when: Date.parse('2026-10-06T09:00:00Z') });
  const r = await checkBook(w.book());
  assert.deepEqual(breachesOf(r), [[], [], [], ['over-limit'], ['outside-valid-time', 'over-limit']]);
  assert.match(r.entries[3].breaches[0].message, /The pass's limit is 30 GBP/);
});

test('a stub under a pass must be signed with the helper\'s keys, not the first agent\'s', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  const pass = await w.pass();
  await w.add({ pass: pass.fingerprint, after: null });
  assert.ok(codes(await checkBook(w.book())).includes('signature-invalid'));
  // And the helper cannot write into the first agent's chain.
  const w2 = await makeWorld({ fields: { passes: 1 } });
  const pass2 = await w2.pass();
  await w2.add({ signer: pass2.helper.privateKeys });
  assert.ok(codes(await checkBook(w2.book())).includes('signature-invalid'));
});

test('only the agent that holds the permission can pass it on', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  const stranger = await generateKeySet();
  await w.pass({ signer: stranger.privateKeys });
  assert.ok(codes(await checkBook(w.book())).includes('signature-invalid'));
});

test('where the slip does not allow passing on, the pass and every stub under it are outside the slip', async () => {
  const w = await makeWorld();
  const pass = await w.pass();
  await pass.add();
  const r = await checkBook(w.book());
  assert.equal(r.summary.intact, true);
  assert.deepEqual(breachesOf(r), [[], ['pass-not-allowed'], ['pass-not-allowed']]);
});

test('a permission may be passed on only as many times as the slip allows', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  const first = await w.pass();
  const second = await w.pass({ from: first.fingerprint, signer: first.helper.privateKeys });
  await second.add();
  const r = await checkBook(w.book());
  assert.deepEqual(breachesOf(r), [[], [], ['pass-not-allowed'], ['pass-not-allowed']]);

  const w2 = await makeWorld({ fields: { passes: 2 } });
  const a = await w2.pass();
  const b = await w2.pass({ from: a.fingerprint, signer: a.helper.privateKeys });
  await b.add();
  assert.deepEqual(codes(await checkBook(w2.book())), []);
  // The second pass must be signed by the first helper, not by the first agent.
  const w3 = await makeWorld({ fields: { passes: 2 } });
  const c = await w3.pass();
  await w3.pass({ from: c.fingerprint });
  assert.ok(codes(await checkBook(w3.book())).includes('signature-invalid'));
});

test('a pass cannot hand on what its writer does not hold', async () => {
  const w = await makeWorld({ fields: { passes: 2 } });
  await w.pass({ validUntil: '2027-01-01T00:00:00Z' });
  const narrow = await w.pass({ actions: [ORDER], validUntil: '2026-10-06T08:00:00Z' });
  await w.pass({ from: narrow.fingerprint, signer: narrow.helper.privateKeys, validUntil: '2026-10-07T08:00:00Z' });
  await w.pass({ when: Date.parse('2027-06-01T00:00:00Z') });
  const r = await checkBook(w.book());
  assert.deepEqual(breachesOf(r), [[], ['pass-wider'], [], ['pass-wider'], ['outside-valid-time']]);
});

test('the slip\'s conditions and its cancellation hold for a helper too', async () => {
  const w = await makeWorld({ fields: { passes: 1, requires: [{ need: 'countersignature' }] } });
  const pass = await w.pass();
  await pass.add({ countersigned: false });
  await w.cancel();
  await pass.add({ when: START + 2 * HOUR });
  await w.pass({ when: START + 2 * HOUR });
  const r = await checkBook(w.book());
  assert.deepEqual(breachesOf(r), [[], [], ['countersignature-missing'], [], ['after-cancellation'], ['after-cancellation']]);
});

test('a pass that is not as the format says is refused, and "passes" in a slip is from 1 to 10', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  const pass = await w.pass();
  for (const change of [
    (c) => void (c.actions = []),
    (c) => void (c.to = c.to.keys),
    (c) => void (c.to.keys = c.to.keys.slice(0, 1)),
    (c) => void (c.limits = [{ action: 'other', max: 1, unit: 'GBP' }]),
    (c) => void (c.validUntil = c.validFrom),
    (c) => void (c.from = 'short'),
    (c) => void (c.extra = 1),
  ]) {
    w.entries[1] = { pass: withContent(pass.record, change) };
    const r = await checkBook(w.book());
    assert.ok(codes(r).some((c) => c === 'bad-field' || c === 'bad-key'), codes(r).join(','));
  }
  for (const passes of [0, 11, -1, 1.5, '1', [1]]) {
    await assert.rejects(prepareSlip({ ...w.fields, passes }), (e) => e.code === 'bad-field', String(passes));
  }
});

test('the check before acting knows a helper\'s pass', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  const pass = await w.pass({ limits: [{ action: ORDER, max: 30, unit: 'GBP' }] });
  await pass.add({ value: 20 });
  const trust = { issuerKeys: [await thumbprint(w.passkey.key)] };
  const ask = (value, more = {}) =>
    checkBefore(w.book(), { slip: w.slipFingerprint, pass: pass.fingerprint, action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier', when: START + HOUR, ...more }, trust);
  assert.equal((await ask(10)).allowed, true);
  assert.deepEqual((await ask(11)).breaches.map((b) => b.code), ['over-limit']);
  assert.deepEqual((await ask(1, { pass: 'A'.repeat(43) })).problems.map((p) => p.code), ['pass-missing']);
});

test('a Show of a helper\'s stub needs its pass and its slip among the pages', async () => {
  const w = await makeWorld();
  const pass = await w.pass();
  await pass.add();
  const whole = await checkShow(await makeShow(w.book(), [0, 1, 2]));
  assert.deepEqual(whole.entries[2].breaches.map((b) => b.code), ['pass-not-allowed']);
  const without = await checkShow(await makeShow(w.book(), [0, 2]));
  assert.ok(codes(without).includes('pass-missing'));
});
