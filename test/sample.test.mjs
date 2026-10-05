// The sample record in samples/ was written once. Today's code must still
// read it and find exactly what was found then. When the format is frozen,
// this is the test that keeps it frozen.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { checkBook, checkShow } from '../src/index.js';

const read = (name) => readFileSync(new URL(`../samples/${name}`, import.meta.url), 'utf8');
const book = read('office-supplies.jsonl');
const expected = JSON.parse(read('office-supplies.expected.json'));

test('the sample book checks, and shows what it showed when it was written', async () => {
  const r = await checkBook(book, { issuerKeys: [expected.issuerKey], sealKeys: expected.sealKeys, stampServices: expected.stampServices });
  assert.equal(r.size, expected.size);
  assert.deepEqual(r.summary.sealed, expected.sealed);
  assert.deepEqual(r.summary.sealed, { entries: 9, when: '2026-10-05T10:16:00Z', seal: 9, by: 'service' });
  assert.equal(r.root, expected.root);
  assert.deepEqual(r.entries.map((e) => e.fingerprint), expected.fingerprints);
  assert.deepEqual(r.entries.map((e) => e.breaches.map((b) => b.code)), expected.breaches);
  assert.deepEqual(r.entries.map((e) => (e.running ? e.running.total : null)), expected.running);
  const { intact, fullyChecked, withinSlips, firstBreach, counts } = r.summary;
  assert.deepEqual({ intact, fullyChecked, withinSlips, firstBreach, counts }, expected.summary);
  // With the issuer's key, the recorder's keys and the time-stamp service
  // given, nothing is left as a note.
  assert.deepEqual(r.entries.flatMap((e) => e.notes), []);
});

test('the sample is the demonstration: a sound record that shows the agent outside its slip four times', async () => {
  const r = await checkBook(book);
  assert.equal(r.summary.intact, true);
  assert.deepEqual(r.entries.map((e) => e.kind), ['slip', 'terms', 'stub', 'stub', 'stub', 'stub', 'stub', 'refusal', 'stub', 'seal']);
  assert.deepEqual(r.entries.map((e) => e.breaches.map((b) => b.code)), [
    [],
    [],
    [],
    [],
    [],
    ['countersignature-missing'],
    ['over-limit', 'approval-missing'],
    [],
    ['action-not-allowed', 'prohibited'],
    [],
  ]);
  assert.equal(r.summary.firstBreach, 5);
  // The order the person approved with the passkey.
  assert.equal(r.entries[4].approval.state, 'valid');
  assert.deepEqual(r.entries[4].needs, ['countersignature', 'approval']);
  assert.deepEqual(r.entries[6].running, { action: 'provared.order.place', unit: 'GBP', total: '230', max: 200 });
  assert.equal(r.entries[7].service, 'supplier');
  assert.deepEqual(r.summary.counts, { slips: 1, stubs: 6, countersigned: 3, oneSided: 3, approved: 1, refusals: 1, terms: 1, seals: 1, cancellations: 0, acknowledgements: 0, vouchings: 0, passes: 0 });
  // With no service named as trusted, the time-stamp counts for nothing.
  assert.equal(r.summary.sealed, null);
});

test('the sample Show checks against the sample book\'s top fingerprint', async () => {
  // The Show is of the book as it stood when it was sealed: nine entries.
  // It needs no copy of the top fingerprint: the seal and its time-stamp
  // come with it.
  const r = await checkShow(read('office-supplies.show.json'), { issuerKeys: [expected.issuerKey], sealKeys: expected.sealKeys, stampServices: expected.stampServices });
  assert.deepEqual(r.problems, []);
  assert.equal(r.summary.intact, true);
  assert.deepEqual(r.summary.sealed, expected.sealed);
  assert.deepEqual(r.entries.map((e) => e.index), [0, 1, 4, 9]);
  assert.deepEqual(r.entries.map((e) => e.fingerprint), [expected.fingerprints[0], expected.fingerprints[1], expected.fingerprints[4], expected.fingerprints[9]]);
  assert.equal(r.summary.withinSlips, true);
});

test('changing any one character of the sample book is noticed', async () => {
  // Change one character in the middle of each line in turn.
  const lines = book.split('\n').filter(Boolean);
  for (let i = 0; i < lines.length; i++) {
    const at = Math.floor(lines[i].length / 2);
    const swapped = lines[i][at] === 'A' ? 'B' : 'A';
    const changed = [...lines];
    changed[i] = lines[i].slice(0, at) + swapped + lines[i].slice(at + 1);
    const r = await checkBook(changed.join('\n') + '\n');
    assert.equal(r.summary.intact, false, `line ${i}`);
    assert.notEqual(r.root, expected.root);
  }
});
