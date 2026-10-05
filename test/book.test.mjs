// A whole book, through the public interface: a sound record, what a sound
// record shows about the agent, and the named states.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBook, checkShow, makeShow, thumbprint, writeBook } from '../src/index.js';
import { START, makeWorld } from './helpers/world.mjs';

const codes = (list) => list.map((p) => p.code);

test('a sound book is intact, fully checked and within its slip', async () => {
  const w = await makeWorld();
  await w.add({ value: 45 });
  await w.add({ value: 30 });
  await w.add({ value: 80 });
  const r = await checkBook(w.book(), { issuerKeys: [await thumbprint(w.passkey.key)] });

  assert.deepEqual(r.problems, []);
  assert.equal(r.size, 4);
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.fullyChecked, true);
  assert.equal(r.summary.withinSlips, true);
  assert.equal(r.summary.firstBreach, null);
  assert.deepEqual(r.summary.counts, { slips: 1, stubs: 3, countersigned: 3, oneSided: 0, approved: 0, refusals: 0, terms: 0, seals: 0, cancellations: 0, acknowledgements: 0, vouchings: 0, passes: 0 });

  const [slip, first, , third] = r.entries;
  assert.equal(slip.kind, 'slip');
  assert.equal(slip.signature.state, 'valid');
  assert.equal(slip.signature.method, 'passkey (ES256)');
  assert.deepEqual(slip.notes, []);
  assert.equal(first.kind, 'stub');
  assert.deepEqual(first.signatures, [
    { method: 'Ed25519', state: 'valid' },
    { method: 'ML-DSA-87', state: 'valid' },
  ]);
  assert.equal(first.countersignature.state, 'valid');
  assert.deepEqual(third.running, { action: 'supplies.order', unit: 'GBP', total: '155', max: 200 });
});

test('the limits of what a record shows come with every result', async () => {
  const w = await makeWorld();
  const r = await checkBook(w.book());
  assert.ok(r.summary.limits.length >= 5);
  assert.match(r.summary.limits.join(' '), /not what was left out/);
});

test('with no expected issuer key, the result says the key was not compared', async () => {
  const w = await makeWorld();
  const r = await checkBook(w.book());
  assert.equal(r.summary.intact, true);
  assert.match(r.entries[0].notes.join(' '), /not compared with a key you already trust/);
});

test('a slip signed with each kind of passkey checks', async () => {
  for (const alg of ['ES256', 'RS256', 'Ed25519']) {
    const w = await makeWorld({ passkeyAlg: alg });
    await w.add();
    const r = await checkBook(w.book());
    assert.equal(r.summary.intact, true, alg);
    assert.equal(r.entries[0].signature.method, `passkey (${alg})`);
  }
});

test('the record shows exactly where the limit was passed', async () => {
  const w = await makeWorld();
  for (const value of [45, 30, 80, 25, 80]) await w.add({ value });
  const r = await checkBook(w.book());

  // The record itself is sound. What it shows is that the agent went over.
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.withinSlips, false);
  assert.equal(r.summary.firstBreach, 5);
  assert.deepEqual(codes(r.entries[4].breaches), []);
  assert.deepEqual(codes(r.entries[5].breaches), ['over-limit']);
  assert.deepEqual(r.entries[5].running, { action: 'supplies.order', unit: 'GBP', total: '260', max: 200 });
  assert.match(r.entries[5].breaches[0].message, /over by 60/);
});

test('a total exactly at the limit is within the slip', async () => {
  const w = await makeWorld();
  await w.add({ value: 120 });
  await w.add({ value: 80 });
  const r = await checkBook(w.book());
  assert.equal(r.summary.withinSlips, true);
});

test('a stub with no countersignature is one-sided, which is not a fault', async () => {
  const w = await makeWorld();
  await w.add({ countersigned: false });
  const r = await checkBook(w.book());
  assert.equal(r.summary.intact, true);
  assert.equal(r.entries[1].countersignature.state, 'absent');
  assert.deepEqual(r.summary.counts, { slips: 1, stubs: 1, countersigned: 0, oneSided: 1, approved: 0, refusals: 0, terms: 0, seals: 0, cancellations: 0, acknowledgements: 0, vouchings: 0, passes: 0 });
});

test('a stub with no other party needs no "with"', async () => {
  const w = await makeWorld();
  await w.add({ with: undefined, countersigned: false });
  const r = await checkBook(w.book());
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.withinSlips, true);
});

test('on a device with no ML-DSA the record is not reported as intact', async () => {
  const w = await makeWorld();
  await w.add();
  const r = await checkBook(w.book(), { withoutMethods: ['ML-DSA-87'] });
  // No problem was found, but "intact" is said only when every signature was checked.
  assert.equal(r.summary.problemFound, false);
  assert.equal(r.summary.intact, false);
  assert.equal(r.summary.fullyChecked, false);
  // Ed25519 was checked, so the stub still counts as evidence, in part.
  assert.equal(r.entries[1].verified, 'some');
  assert.equal(r.summary.withinSlips, true);
  assert.deepEqual(r.entries[1].signatures, [
    { method: 'Ed25519', state: 'valid' },
    { method: 'ML-DSA-87', state: 'unavailable' },
  ]);
  assert.equal(r.entries[1].countersignature.state, 'unavailable');
  assert.deepEqual(r.summary.methodsMissing, ['ML-DSA-87']);
});

test('a sound book names no missing method', async () => {
  const w = await makeWorld();
  await w.add();
  assert.deepEqual((await checkBook(w.book())).summary.methodsMissing, []);
});

test('a slip signed with a method the device lacks is not fully checked, and the method is named', async () => {
  const w = await makeWorld({ passkeyAlg: 'RS256' });
  await w.add({ value: 500 });
  const r = await checkBook(w.book(), { withoutMethods: ['RS256'] });
  assert.equal(r.summary.problemFound, false);
  assert.equal(r.summary.intact, false);
  assert.equal(r.summary.fullyChecked, false);
  assert.deepEqual(r.summary.methodsMissing, ['RS256']);
  assert.equal(r.entries[0].signature.state, 'unavailable');
  assert.equal(r.entries[0].verified, 'none');
  // The slip could not be confirmed, so the stub is not compared with it:
  // nothing is said either way about the limit.
  assert.deepEqual(r.entries[1].breaches, []);
  assert.equal(r.summary.withinSlips, false);
  assert.equal(r.summary.firstBreach, null);
});

test('a record forged with no key at all is never "intact", even on a device that can check nothing', async () => {
  // Every signature is empty. A device with neither method cannot tell.
  const w = await makeWorld({ passkeyAlg: 'Ed25519' });
  await w.add({ value: 500 });
  const empty = (record) => ({ ...record, signatures: record.signatures.map((s) => ({ ...s, signature: '' })) });
  const forged = writeBook([{ slip: empty(w.entries[0].slip) }, { stub: empty(w.entries[1].stub), countersignature: empty(w.entries[1].countersignature) }]);

  const here = await checkBook(forged);
  assert.equal(here.summary.problemFound, true);
  assert.equal(here.summary.intact, false);

  const blind = await checkBook(forged, { withoutMethods: ['Ed25519', 'ML-DSA-87'] });
  assert.equal(blind.summary.intact, false);
  assert.equal(blind.summary.fullyChecked, false);
  assert.equal(blind.summary.withinSlips, false);
  assert.deepEqual(blind.summary.methodsMissing, ['Ed25519', 'ML-DSA-87']);
  for (const e of blind.entries) {
    assert.equal(e.verified, 'none');
    assert.deepEqual(e.breaches, []);
  }
});

test('nothing checked is never "every signature checked"', async () => {
  for (const r of [await checkBook(''), await checkBook('x\n'.repeat(100001)), await checkShow('{}'), await checkShow('not json')]) {
    assert.equal(r.summary.fullyChecked, false);
    assert.equal(r.summary.intact, false);
    assert.equal(r.summary.withinSlips, false);
    assert.equal(r.summary.problemFound, true);
  }
});

test('a flood of line feeds is refused at once', async () => {
  const before = Date.now();
  const r = await checkBook('\n'.repeat(30000000));
  assert.deepEqual(r.problems.map((p) => p.code), ['too-large']);
  assert.equal(r.entries.length, 0);
  assert.ok(Date.now() - before < 5000);
});

test('a book is compared with the top fingerprint and the number of entries the checker trusts', async () => {
  const w = await makeWorld();
  await w.add();
  await w.add();
  const book = w.book();
  const { root } = await checkBook(book);
  assert.equal((await checkBook(book, { expectedRoot: root, expectedSize: 3 })).summary.intact, true);
  for (const options of [{ expectedRoot: 'A'.repeat(43) }, { expectedRoot: root, expectedSize: 4 }, { expectedSize: 2 }]) {
    const r = await checkBook(book, options);
    assert.deepEqual(r.problems.map((p) => p.code), ['root-mismatch']);
    assert.equal(r.summary.intact, false);
  }
});

test('a missing line feed after the last line changes nothing', async () => {
  const w = await makeWorld();
  await w.add();
  const withFeed = await checkBook(w.book());
  const without = await checkBook(w.book().slice(0, -1));
  assert.equal(without.summary.intact, true);
  assert.equal(without.root, withFeed.root);
  assert.equal(without.size, 2);
});

test('a Show shows a single stub that passes the limit by itself', async () => {
  const w = await makeWorld();
  await w.add({ value: 5000 });
  const r = await checkShow(await makeShow(w.book(), [0, 1]));
  assert.equal(r.summary.problemFound, false);
  assert.deepEqual(r.entries[1].breaches.map((b) => b.code), ['over-limit']);
  assert.equal(r.summary.withinSlips, false);
  assert.equal(r.summary.firstBreach, 1);
});

test('a Show compares the number of entries, when the checker trusts one', async () => {
  const w = await makeWorld();
  for (let i = 0; i < 4; i++) await w.add();
  const book = w.book();
  const show = await makeShow(book, [0]);
  const { root } = await checkBook(book);
  // The first page of 5 has a proof of the same shape as the first page of 6.
  const stretched = { ...show, size: 6 };
  assert.equal((await checkShow(stretched, { expectedRoot: root })).summary.problemFound, false);
  assert.match((await checkShow(stretched, { expectedRoot: root })).notes.join(' '), /number of entries was not compared/);
  assert.deepEqual((await checkShow(stretched, { expectedRoot: root, expectedSize: 5 })).problems.map((p) => p.code), ['root-mismatch']);
  assert.equal((await checkShow(show, { expectedRoot: root, expectedSize: 5 })).summary.intact, true);
});

test('a Show holds at most 64 pages', async () => {
  const w = await makeWorld();
  await w.add();
  await assert.rejects(makeShow(w.book(), []), RangeError);
  const show = await makeShow(w.book(), [0]);
  show.pages = Array.from({ length: 65 }, () => show.pages[0]);
  assert.equal((await checkShow(show)).summary.problemFound, true);
});

test('where an entry cannot be read, the result does not say every signature was checked', async () => {
  const w = await makeWorld();
  await w.add();
  await w.add();
  // The stubs without their slip: no key to check their signatures against.
  const r = await checkBook(w.book().split('\n').slice(1).join('\n'));
  assert.equal(r.summary.intact, false);
  assert.equal(r.summary.fullyChecked, false);
  assert.deepEqual(r.summary.methodsMissing, []);
  const garbage = await checkBook(w.book() + 'not a record\n');
  assert.equal(garbage.summary.fullyChecked, false);
});

test('a wrong signature is invalid even where the other method cannot be checked', async () => {
  const w = await makeWorld();
  const other = await makeWorld();
  await w.add({ signer: other.agent.privateKeys });
  const r = await checkBook(w.book(), { withoutMethods: ['ML-DSA-87'] });
  assert.equal(r.summary.intact, false);
  assert.deepEqual(codes(r.entries[1].problems), ['signature-invalid']);
});

test('two slips in one book each have their own chain and total', async () => {
  const a = await makeWorld();
  const b = await makeWorld();
  await a.add({ value: 150 });
  await b.add({ value: 150 });
  const text = a.book() + b.book();
  const r = await checkBook(text);
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.withinSlips, true);
  assert.deepEqual(r.summary.counts, { slips: 2, stubs: 2, countersigned: 2, oneSided: 0, approved: 0, refusals: 0, terms: 0, seals: 0, cancellations: 0, acknowledgements: 0, vouchings: 0, passes: 0 });
});

test('an empty book and a missing book are refused, not crashed on', async () => {
  for (const text of ['', undefined, null, 42]) {
    const r = await checkBook(text);
    assert.equal(r.summary.intact, false);
    assert.deepEqual(codes(r.problems), ['not-json']);
  }
});

test('the top fingerprint changes when any entry changes', async () => {
  const w = await makeWorld();
  await w.add();
  const before = (await checkBook(w.book())).root;
  await w.add();
  const after = (await checkBook(w.book())).root;
  assert.notEqual(before, after);
  assert.match(before, /^[A-Za-z0-9_-]{43}$/);
});

test('a Show proves that pages are in the book, and checks them', async () => {
  const w = await makeWorld();
  for (let i = 0; i < 6; i++) await w.add({ value: 10 });
  const book = w.book();
  const whole = await checkBook(book);

  const show = await makeShow(book, [0, 4]);
  assert.equal(show.root, whole.root);
  assert.equal(show.size, 7);
  const r = await checkShow(JSON.stringify(show), { expectedRoot: whole.root });
  assert.deepEqual(r.problems, []);
  assert.equal(r.summary.intact, true);
  assert.equal(r.entries.length, 2);
  assert.equal(r.entries[1].index, 4);
  assert.equal(r.entries[1].signatures[1].state, 'valid');
  assert.match(r.notes.join(' '), /cannot show whether the chain is whole/);
  // No running total: one page cannot show whether a limit was kept.
  assert.equal(r.entries[1].running, undefined);
});

test('a Show with no expected top fingerprint says it was not compared', async () => {
  const w = await makeWorld();
  await w.add();
  const r = await checkShow(await makeShow(w.book(), [0, 1]));
  assert.equal(r.summary.intact, true);
  assert.match(r.notes.join(' '), /not compared with a copy you already trust/);
});

test('a Show of a stub without its slip cannot check the stub', async () => {
  const w = await makeWorld();
  await w.add();
  const r = await checkShow(await makeShow(w.book(), [1]));
  assert.deepEqual(codes(r.entries[0].problems), ['slip-missing']);
});

test('stubs dated in order from the start of the test world', () => {
  assert.equal(new Date(START).toISOString(), '2026-10-05T09:00:00.000Z');
});
