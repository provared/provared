// The parts of the pages that can be tested without a browser.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readBlocks, readFingerprints, showTime, shown } from '../page/render.js';

test('a time from a record is shown in words', () => {
  assert.equal(showTime('2026-10-05T09:00:00Z'), '5 October 2026, 09:00:00 UTC');
  assert.equal(showTime('2027-01-31T23:59:59Z'), '31 January 2027, 23:59:59 UTC');
});

test('anything that is not a time in the one accepted form is shown as it is', () => {
  for (const text of ['2026-13-05T09:00:00Z', '2026-10-05', 'yesterday', '', '<b>x</b>']) {
    assert.equal(showTime(text), text);
  }
  assert.equal(showTime(undefined), 'undefined');
});

test('the page shows characters that cannot be seen as a mark, and leaves ordinary text alone', () => {
  assert.equal(shown('a\u200bb\u202ec\u2028d\u00ade\u{e0001}f\u0007g'), 'a\ufffdb\ufffdc\ufffdd\ufffde\ufffdf\ufffdg');
  assert.equal(shown('Zoë & Søren, 10 £ — naïve café\tok\nnext'), 'Zoë & Søren, 10 £ — naïve café\tok\nnext');
  assert.equal(shown('日本語 العربية עברית 😀'), '日本語 العربية עברית 😀');
});

test('a line in a trust box that is not a fingerprint is kept apart, never dropped', () => {
  const fingerprint = 'A'.repeat(43);
  assert.deepEqual(readFingerprints(`${fingerprint}\n  ${fingerprint}  \n\n`), { values: [fingerprint, fingerprint], bad: [] });
  assert.deepEqual(readFingerprints(`${fingerprint}\nnot one\n`), { values: [fingerprint], bad: ['not', 'one'] });
  // A block is named by 64 hex characters, as it is written wherever blocks are listed.
  const block = '00000000000000000001a2b3c4d5e6f7'.repeat(2);
  assert.deepEqual(readBlocks(`${block}\n${block.toUpperCase()}\n`), { values: [block, block.toUpperCase()], bad: [] });
  assert.deepEqual(readBlocks(`${block}\n${fingerprint}\n${block.slice(1)}`), { values: [block], bad: [fingerprint, block.slice(1)] });
  assert.deepEqual(readBlocks(''), { values: [], bad: [] });
});
