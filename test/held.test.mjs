// The person's own copy of a cancellation, handed over beside the book.
// Whoever keeps a book can leave a cancellation out, or put a later
// time-stamp in the place of the person's own. The person's copy settles both.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { checkBefore, checkBook, checkShow, fromBase64url, keySetFingerprint, makeShow, openRecorder, thumbprint, toBase64url } from '../src/index.js';
import { START, makeWorld } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const MINUTE = 60 * 1000;
const ORDER = 'supplies.order';

function codes(result) {
  const out = result.problems.map((p) => p.code);
  for (const e of result.entries) out.push(...e.problems.map((p) => p.code), ...e.breaches.map((b) => b.code));
  return out;
}
const breachesOf = (r) => r.entries.map((e) => e.breaches.map((b) => b.code));

// A book: a stub that is sealed and time-stamped, then a stub that is not.
// The person cancels at 10:00 and has the cancellation time-stamped; the
// cancellation is taken out of the book again, as its keeper might.
async function leftOut(change = {}) {
  const w = await makeWorld();
  await w.add({ when: START });
  await w.seal({ when: START + 10 * MINUTE });
  await w.add({ when: START + 30 * MINUTE });
  const cancel = await w.cancel({ when: START + HOUR, stampTime: START + HOUR + 1000, ...change });
  w.entries.pop();
  return { w, cancel, trust: { stampServices: [w.stampService.fingerprint] } };
}

test('a cancellation the keeper of the book left out counts when the person hands over their own copy', async () => {
  const { w, cancel, trust } = await leftOut();
  const without = await checkBook(w.book(), trust);
  assert.deepEqual(codes(without), []);
  assert.deepEqual(without.held, []);

  const r = await checkBook(w.book(), { ...trust, cancellations: [cancel.entry] });
  assert.deepEqual(r.problems, []);
  assert.equal(r.summary.intact, true);
  // The sealed stub existed before the cancellation. Nothing shows that the other did.
  assert.deepEqual(breachesOf(r), [[], [], [], ['after-cancellation']]);
  assert.match(r.entries[3].breaches[0].message, /own copy of the cancellation was handed over beside the book/);
  assert.equal(r.summary.withinSlips, false);
  assert.equal(r.summary.firstBreach, 3);
  const [held] = r.held;
  assert.equal(held.used, true);
  assert.equal(held.inBook, null);
  assert.equal(held.fingerprint, cancel.fingerprint);
  assert.equal(held.stampedAt, '2026-10-05T10:00:01Z');
  assert.ok(held.notes.some((n) => /The book does not hold this cancellation/.test(n)));
});

test('a time-stamp swapped for a later one in the book is overruled by the person\'s own copy', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const cancel = await w.cancel({ when: START + HOUR, stampTime: START + HOUR + 1000 });
  const trust = { stampServices: [w.stampService.fingerprint] };
  // The keeper seals the stub at 12:00, and swaps the time-stamp for one made at 13:00.
  w.entries.pop();
  await w.seal({ when: START + 3 * HOUR });
  const later = toBase64url(await w.stampService.stamp(fromBase64url(cancel.fingerprint), START + 4 * HOUR));
  w.entries.push({ cancellation: cancel.record, stamps: [later] });
  assert.deepEqual(codes(await checkBook(w.book(), trust)), []);

  const r = await checkBook(w.book(), { ...trust, cancellations: [cancel.entry] });
  assert.deepEqual(breachesOf(r), [[], ['after-cancellation'], [], []]);
  assert.equal(r.held[0].inBook, 3);
  assert.equal(r.held[0].stampedAt, '2026-10-05T10:00:01Z');
  assert.deepEqual(r.problems, []);
});

test('a copy with no time-stamp the reader trusts marks no stub, and still stops the agent', async () => {
  const { w, cancel, trust } = await leftOut();
  // The same copy, read by someone who does not trust its time-stamp service.
  const r = await checkBook(w.book(), { cancellations: [cancel.entry] });
  assert.deepEqual(codes(r), []);
  assert.equal(r.held[0].used, true);
  assert.equal(r.held[0].stampedAt, undefined);
  assert.ok(r.held[0].notes.some((n) => /cannot be placed in time/.test(n)));

  // The agent's software, handed the cancellation, takes no further action.
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const proposal = { slip: w.slipFingerprint, action: ORDER, amount: { unit: 'GBP', value: 1 }, with: 'supplier', when: START + 2 * HOUR };
  assert.equal((await checkBefore(w.book(), proposal, { ...trust, issuerKeys })).allowed, true);
  const answer = await checkBefore(w.book(), proposal, { ...trust, issuerKeys, cancellations: [cancel.entry] });
  assert.equal(answer.allowed, false);
  assert.deepEqual(answer.breaches.map((b) => b.code), ['after-cancellation']);
  const recorder = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => START + 2 * HOUR, options: { ...trust, cancellations: [cancel.entry] } });
  let taken = false;
  const acted = await recorder.act({ action: ORDER, amount: { unit: 'GBP', value: 1 }, with: 'supplier' }, async () => (taken = true), { when: START + 2 * HOUR });
  assert.equal(acted.done, false);
  assert.equal(taken, false);
});

test('a copy that does not pass its check is a problem, never dropped', async () => {
  const { w, cancel, trust } = await leftOut();
  const other = await makeWorld();
  const foreign = await other.cancel({ stampTime: START + HOUR });
  const forged = await w.cancel({ passkey: other.passkey });
  w.entries.pop();
  const cases = [
    [[forged.entry], 'cancellation-invalid'],
    // A cancellation of a slip that is not in this book.
    [[foreign.entry], 'slip-missing'],
    // A time-stamp made for another cancellation.
    [[{ cancellation: cancel.record, stamps: foreign.entry.stamps }], 'stamp-wrong-data'],
    [[cancel.entry, cancel.entry], 'bad-field'],
    [[{ cancellation: cancel.record, extra: 1 }], 'bad-field'],
    [[cancel.record], 'bad-field'],
    // An empty list is none at all: see test/review16.test.mjs.
    ['everything', 'bad-field'],
    [Array(17).fill(cancel.entry), 'bad-field'],
    [[null], 'bad-field'],
  ];
  for (const [i, [cancellations, expected]] of cases.entries()) {
    const r = await checkBook(w.book(), { ...trust, cancellations });
    assert.ok(r.problems.some((p) => p.code === expected), `case ${i}: ${r.problems.map((p) => p.code)}`);
    assert.equal(r.summary.intact, false, `case ${i}`);
    assert.equal(r.summary.problemFound, true, `case ${i}`);
  }
  // A copy that failed marks no stub.
  const r = await checkBook(w.book(), { ...trust, cancellations: [forged.entry] });
  assert.deepEqual(breachesOf(r), [[], [], [], []]);
  assert.equal(r.held[0].used, false);
});

test('a copy that this device cannot confirm is not used, and the check is not a pass', async () => {
  const { w, cancel, trust } = await leftOut();
  const r = await checkBook(w.book(), { ...trust, cancellations: [cancel.entry], withoutMethods: ['ES256'] });
  assert.equal(r.held[0].used, false);
  assert.equal(r.summary.intact, false);
  assert.equal(r.summary.withinSlips, false);
});

test('the copy of a cancellation that the book holds unchanged adds nothing and harms nothing', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  await w.seal({ when: START + 10 * MINUTE });
  const cancel = await w.cancel({ when: START + HOUR, stampTime: START + HOUR + 1000 });
  await w.add({ when: START + 2 * HOUR });
  const trust = { stampServices: [w.stampService.fingerprint] };
  const plain = await checkBook(w.book(), trust);
  const withCopy = await checkBook(w.book(), { ...trust, cancellations: [cancel.entry] });
  assert.deepEqual(breachesOf(withCopy), breachesOf(plain));
  assert.deepEqual(breachesOf(withCopy), [[], [], [], [], ['after-cancellation']]);
  assert.equal(withCopy.held[0].inBook, 3);
});

test('the command-line checker takes the person\'s copy, and a Show says that it cannot use one', async () => {
  const { w, cancel, trust } = await leftOut();
  const dir = mkdtempSync(join(tmpdir(), 'provared-'));
  const book = join(dir, 'book.jsonl');
  const copy = join(dir, 'cancellation.json');
  writeFileSync(book, w.book());
  writeFileSync(copy, JSON.stringify(cancel.entry));
  const cli = join(fileURLToPath(new URL('..', import.meta.url)), 'bin', 'provared-check.mjs');
  // Whom the person trusts: the passkey and, for a sealed book, the recorder.
  const named = ['--issuer', await thumbprint(w.passkey.key), ...(w.recorder ? ['--sealer', await keySetFingerprint(w.recorder.keys)] : [])];
  const run = (...more) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', cli, book, '--stamp-service', trust.stampServices[0], ...named, ...more], { encoding: 'utf8' });
  assert.equal(run().status, 0);
  const out = run('--cancellation', copy);
  assert.equal(out.status, 1);
  assert.match(out.stdout, /Handed over beside the book, 1: CANCELLATION/);
  assert.match(out.stdout, /In the book: NO/);
  assert.match(out.stdout, /OUTSIDE THE SLIP \[after-cancellation\]/);
  assert.equal(run('--cancellation', join(dir, 'missing.json')).status, 2);

  const show = await checkShow(await makeShow(w.book(), [0, 3]), { ...trust, cancellations: [cancel.entry] });
  assert.deepEqual(show.held, []);
  assert.ok(show.notes.some((n) => /were not used: single pages cannot show/.test(n)));
});
