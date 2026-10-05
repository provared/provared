// What the fifth independent review found, in the stub writer, the check
// before acting, what is shown, and places where the format description
// and the code parted (3 October 2026). Each fault is fixed, and each is a
// test here.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { label, shown } from '../page/render.js';
import { disclosureDigest } from '../src/cover.js';
import {
  assembleSlip,
  checkBefore,
  checkBook,
  checkSlip,
  countersign,
  fingerprint,
  fromBase64url,
  generateKeySet,
  thumbprint,
  toBase64url,
  writeRefusal,
} from '../src/index.js';
import { preparePasskeyRecord } from '../src/slip.js';
import { START, makeWorld, openWriter } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const ORDER = 'supplies.order';

function codes(result) {
  const out = result.problems.map((p) => p.code);
  for (const e of result.entries) out.push(...e.problems.map((p) => p.code), ...e.breaches.map((b) => b.code));
  return out;
}
const breachesOf = (r) => r.entries.map((e) => e.breaches.map((b) => b.code).sort());
const trusting = async (w) => ({ issuerKeys: [await thumbprint(w.passkey.key)] });
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });

async function opened(w, more = {}) {
  return openWriter({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, ...(await trusting(w)), ...more });
}

// Replace the world's slip with one of changed content, signed with the same passkey.
async function reslip(w, change) {
  const content = JSON.parse(Buffer.from(w.slip.payload, 'base64url').toString());
  change(content);
  const prepared = await preparePasskeyRecord('slip', content);
  const slip = assembleSlip(prepared, await w.passkey.sign(prepared.challenge));
  w.slip = slip;
  w.slipFingerprint = await fingerprint(fromBase64url(slip.payload));
  w.entries[0] = { slip };
  return w.slipFingerprint;
}

const CLI = join(fileURLToPath(new URL('..', import.meta.url)), 'bin', 'provared-check.mjs');
function cli(book, ...more) {
  const file = join(mkdtempSync(join(tmpdir(), 'provared-')), 'book.jsonl');
  writeFileSync(file, book);
  return spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', CLI, file, ...more], { encoding: 'utf8' });
}

// --- the stub writer ---

test('finding 1: two actions asked for at the same moment are taken one after the other', async () => {
  const w = await makeWorld();
  const recorder = await opened(w);
  let taken = 0;
  const both = await Promise.all([
    recorder.act(order(150), async () => ++taken, { when: START }),
    recorder.act(order(150), async () => ++taken, { when: START + 1000 }),
  ]);
  assert.deepEqual(both.map((b) => b.done), [true, false]);
  assert.deepEqual(both[1].answer.breaches.map((b) => b.code), ['over-limit']);
  assert.equal(taken, 1);
  const r = await checkBook(recorder.book());
  assert.deepEqual(codes(r), []);
  assert.equal(r.summary.counts.stubs, 1);
  // "record" waits its turn too: two receipts written at once keep the chain whole.
  await Promise.all([recorder.record(order(10), { when: START + 2000 }), recorder.record(order(10), { when: START + 3000 })]);
  const after = await checkBook(recorder.book());
  assert.equal(after.summary.intact, true);
  assert.deepEqual(after.entries.filter((e) => e.kind === 'stub').map((e) => e.content.seq), [0, 1, 2]);
});

test('finding 2: a countersignature that does not check is left out of the book, and the stub stands one-sided', async () => {
  const w = await makeWorld();
  const recorder = await opened(w);
  const stranger = await generateKeySet();
  const bad = await recorder.act(order(10), async () => 'done', { when: START, countersign: (stub) => countersign(stub, stranger.privateKeys, START + 1000) });
  assert.equal(bad.done, true);
  assert.deepEqual(bad.stub.countersignature, { accepted: false, problem: { code: 'countersignature-invalid', message: bad.stub.countersignature.problem.message } });
  // One made for another stub, and a service that cannot be reached.
  const other = await recorder.record(order(1), { when: START + 1000, countersign: () => countersign(bad.stub.record, w.service.privateKeys, START + 2000) });
  assert.equal(other.countersignature.problem.code, 'countersignature-wrong-stub');
  const failed = await recorder.record(order(1), {
    when: START + 2000,
    countersign: async () => {
      throw new Error('no answer');
    },
  });
  assert.deepEqual(failed.countersignature, { accepted: false, problem: { code: 'countersignature-missing', message: 'Asking the other side for its countersignature failed, or took too long.' } });
  const good = await recorder.act(order(10), async () => 'done', { when: START + HOUR, countersign: (stub) => countersign(stub, w.service.privateKeys, START + HOUR + 1000) });
  assert.deepEqual(good.stub.countersignature, { accepted: true, problem: null });
  const r = await checkBook(recorder.book());
  assert.equal(r.summary.intact, true);
  assert.deepEqual([r.summary.counts.countersigned, r.summary.counts.oneSided], [1, 3]);
});

test('finding 2: the stub writer adds an entry from someone else only if the book still passes its check', async () => {
  const w = await makeWorld();
  const recorder = await opened(w, { now: () => START + HOUR });
  await recorder.act(order(10), async () => null, { when: START + HOUR });
  const before = recorder.book();
  const stranger = await generateKeySet();
  const refusal = await writeRefusal(
    { slip: w.slipFingerprint, by: { keys: w.service.keys, name: 'Example Stationery (invented)' }, action: ORDER, reason: 'over-limit', when: START + HOUR },
    stranger.privateKeys,
  );
  await assert.rejects(recorder.add({ refusal: refusal.record }), (e) => e.code === 'record-not-sound');
  await assert.rejects(recorder.add({ anything: 1 }), (e) => e.code === 'record-not-sound');
  assert.equal(recorder.book(), before);
  const sound = await writeRefusal(
    { slip: w.slipFingerprint, by: { keys: w.service.keys, name: 'Example Stationery (invented)' }, action: ORDER, reason: 'over-limit', when: START + HOUR },
    w.service.privateKeys,
  );
  await recorder.add({ refusal: sound.record });
  assert.equal((await checkBook(recorder.book())).summary.counts.refusals, 1);
});

// --- the check before acting ---

test('finding 3: an action that could never be countersigned is not allowed where the slip asks for a countersignature', async () => {
  const w = await makeWorld({
    fields: {
      requires: [{ need: 'countersignature' }],
      with: [
        { id: 'supplier', name: 'Example Stationery (invented)', keys: (await generateKeySet()).keys },
        { id: 'courier', name: 'Example Courier (invented)' },
      ],
    },
  });
  const ask = async (more) => checkBefore(w.book(), { slip: w.slipFingerprint, action: ORDER, amount: { unit: 'GBP', value: 1 }, when: START, ...more }, await trusting(w));
  for (const more of [{}, { with: 'courier' }]) {
    const answer = await ask(more);
    assert.equal(answer.allowed, false);
    assert.deepEqual(answer.breaches.map((b) => b.code), ['countersignature-missing']);
  }
  const possible = await ask({ with: 'supplier' });
  assert.equal(possible.allowed, true);
  assert.deepEqual(possible.needs, ['countersignature']);
});

// --- what is shown ---

test('finding 4: a name cannot draw a line that looks like the checker\'s own, nor carry the checker\'s words', async () => {
  const blank = '⠀';
  const name = 'Sam' + blank.repeat(60) + 'Issuer\'s key thumbprint: ' + 'A'.repeat(43);
  const w = await makeWorld({
    fields: {
      purpose: 'Stock️ the office" (vouched for by "Trusted Body", key set AAAA) "',
      with: [{ id: 'supplier', name: 'Example   Stationery “Ltd”' }],
    },
  });
  await reslip(w, (c) => void (c.issuer.name = name));
  const out = cli(w.book()).stdout;
  assert.ok(!out.includes(blank) && !out.includes('️'));
  // The name is in quotation marks, each blank pattern is a visible mark, and the checker's own words follow the closing mark.
  assert.match(out, /Issuer:\s+"Sam�{60}Issuer's key thumbprint: A{43}" \(a label, not checked\)/);
  // A quotation mark inside a label is shown as an apostrophe, so the label cannot close its own quotation marks.
  assert.match(out, /Purpose:\s+"Stock� the office' \(vouched for by 'Trusted Body', key set AAAA\) '"/);
  assert.match(out, /With:\s+"Example Stationery 'Ltd'" \[supplier\]/);

  // The page: the same marks, runs of spaces folded, labels in quotation marks.
  assert.equal(shown('a' + blank + 'b️c  　d'), 'a�b�c d');
  assert.equal(label('Sam" (vouched for by “X”) "'), '"Sam\' (vouched for by \'X\') \'"');
});

// --- covered fields ---

test('finding 5: what a slip is does not depend on the disclosures handed over with it', async () => {
  // The signer covers the name with a value that a slip may not hold: 201 characters.
  const disclosure = Buffer.from(JSON.stringify(['c2FsdHNhbHRzYWx0c2FsdA', 'name', 'x'.repeat(201)])).toString('base64url');
  const digest = await disclosureDigest(disclosure);
  const w = await makeWorld();
  const fp = await reslip(w, (c) => void (delete c.issuer.name, (c.issuer._sd = [digest]), (c._sd_alg = 'sha-256')));
  await w.add({ slip: fp });
  const without = await checkBook(w.book());
  assert.equal(without.summary.intact, true);
  const withIt = await checkBook(w.book(), { disclosures: { [fp]: [disclosure] } });
  // The disclosure is refused, and said to be. The slip and its stub are checked as before.
  assert.deepEqual(withIt.problems.map((p) => p.code), ['bad-field']);
  assert.match(withIt.problems[0].message, /The disclosures handed over for the slip at entry 0 did not pass their check/);
  assert.deepEqual(withIt.entries.map((e) => e.problems), [[], []]);
  assert.deepEqual(withIt.entries[0].covered, ['issuer.name']);
  assert.equal(withIt.entries[1].compared, true);
  assert.equal(withIt.summary.firstBreach, null);
  // A problem with what was handed over is still a problem: the check is not a pass.
  assert.equal(withIt.summary.intact, false);
});

test('finding 8: only a fingerprint may stand in the place of a covered field', async () => {
  for (const [i, text] of ['', 'x', 'not a fingerprint at all !!', 'A'.repeat(44), 'A'.repeat(42) + 'B', 'A'.repeat(5000)].entries()) {
    const w = await makeWorld();
    await reslip(w, (c) => void (delete c.issuer.name, (c.issuer._sd = [text]), (c._sd_alg = 'sha-256')));
    assert.deepEqual((await checkSlip(w.slip)).problems.map((p) => p.code), ['cover-invalid'], `case ${i}`);
  }
});

test('finding 9: disclosures handed over in the wrong form are refused, not set aside', async () => {
  const w = await makeWorld({ cover: ['issuer.name'] });
  for (const [i, disclosures] of ['a text', 5, true, null, new Map([[w.slipFingerprint, w.prepared.disclosures]]), w.prepared.disclosures].entries()) {
    const r = await checkBook(w.book(), { disclosures });
    assert.deepEqual(r.problems.map((p) => p.code), ['bad-field'], `case ${i}`);
    assert.equal(r.summary.intact, false, `case ${i}`);
  }
  // A slip checked by itself, with no options at all, is not a failed check.
  assert.deepEqual((await checkSlip(w.slip, null)).problems, []);
});

// --- passing on ---

test('finding 6: a finding about a period is given once for a stub, whether the slip or the pass gave it', async () => {
  const perDay = { action: ORDER, max: 100, unit: 'GBP', per: 86400 };
  const w = await makeWorld({ fields: { passes: 1, limits: [perDay] } });
  const pass = await w.pass({ limits: [{ ...perDay, max: 50 }] });
  await pass.add({ value: 40, when: START });
  await pass.add({ value: 70, when: START + HOUR });
  const r = await checkBook(w.book());
  assert.deepEqual(breachesOf(r), [[], [], [], ['over-period-limit']]);
  const answer = await checkBefore(
    w.book().split('\n').slice(0, 3).join('\n') + '\n',
    { slip: w.slipFingerprint, pass: pass.fingerprint, action: ORDER, amount: { unit: 'GBP', value: 70 }, with: 'supplier', when: START + HOUR },
    await trusting(w),
  );
  assert.deepEqual(answer.breaches.map((b) => b.code), ['over-period-limit']);
});

test('finding 7: a pass too far down the row is refused, and the totals of a pass take in every pass below it', async () => {
  const w = await makeWorld({ fields: { passes: 3 } });
  const first = await w.pass({ limits: [{ action: ORDER, max: 30, unit: 'GBP' }] });
  const second = await w.pass({ from: first.fingerprint, signer: first.helper.privateKeys });
  const third = await w.pass({ from: second.fingerprint, signer: second.helper.privateKeys });
  await third.add({ value: 25, when: START });
  // The first helper then spends 10 itself: 35 under its limit of 30.
  await first.add({ value: 10, when: START + HOUR });
  const r = await checkBook(w.book());
  assert.deepEqual(breachesOf(r), [[], [], [], [], [], ['over-limit']]);
  const ask = await checkBefore(
    w.book().split('\n').slice(0, 5).join('\n') + '\n',
    { slip: w.slipFingerprint, pass: first.fingerprint, action: ORDER, amount: { unit: 'GBP', value: 10 }, with: 'supplier', when: START + HOUR },
    await trusting(w),
  );
  assert.deepEqual(ask.breaches.map((b) => b.code), ['over-limit']);

  // An eleventh pass in the row: refused, with whatever is written under it. (Ten is the most a slip can allow.)
  let last = third;
  for (let i = 4; i <= 11; i++) last = await w.pass({ from: last.fingerprint, signer: last.helper.privateKeys });
  await last.add({ value: 1, when: START + 2 * HOUR });
  const deep = await checkBook(w.book());
  assert.deepEqual(deep.entries.at(-2).problems.map((p) => p.code), ['pass-too-deep']);
  assert.deepEqual(deep.entries.at(-1).problems.map((p) => p.code), ['pass-missing']);
  assert.deepEqual(deep.entries.at(-3).problems, []);
  assert.equal(deep.summary.intact, false);
});

// --- the person's own copy of a cancellation ---

test('finding 11: the notes about the person\'s own copy say where the book holds it, and point out a late time-stamp', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const cancel = await w.cancel({ when: START + HOUR, stampTime: START + HOUR + 1000 });
  const trust = { stampServices: [w.stampService.fingerprint] };
  // The book holds the cancellation with a time-stamp that was made for something else.
  const other = await makeWorld();
  const foreign = await other.cancel();
  const wrong = toBase64url(await w.stampService.stamp(fromBase64url(foreign.fingerprint), START + 4 * HOUR));
  w.entries[2] = { cancellation: cancel.record, stamps: [wrong] };
  const r = await checkBook(w.book(), { ...trust, cancellations: [cancel.entry] });
  assert.equal(r.held[0].inBook, 2);
  assert.ok(r.held[0].notes.some((n) => /The book holds this cancellation at entry 2, but that entry did not pass its check/.test(n)));
  assert.ok(!r.held[0].notes.some((n) => /left it out/.test(n)));

  // A copy whose own time-stamp is hours after its date.
  const late = toBase64url(await w.stampService.stamp(fromBase64url(cancel.fingerprint), START + 5 * HOUR));
  w.entries.pop();
  const slow = await checkBook(w.book(), { ...trust, cancellations: [{ cancellation: cancel.record, stamps: [late] }] });
  assert.ok(slow.held[0].notes.some((n) => /states a time more than 300 seconds after the date the person's device gave/.test(n)));
});
