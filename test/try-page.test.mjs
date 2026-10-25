// The "try it" page's own logic (site/try/story.js), which runs the same in Node.js as in a browser.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBook } from '../src/check.js';
import { developmentRecorder, DEVELOPMENT_MARK } from '../src/dev.js';
import { sha256, toBase64url, utf8 } from '../src/encoding.js';
import { DEFAULT_LIMIT, ORDERS, choosePath, expectedFirstBreach, makeRecord, readLimit } from '../site/try/story.js';

const lib = { developmentRecorder, checkBook, sha256, utf8, toBase64url };

test('a browser with Ed25519 and ML-DSA-87 makes a record; any other steps through the sample, and says why', () => {
  assert.equal(choosePath({ ed25519: true, mldsa: true }).path, 'live');
  for (const has of [{ ed25519: true, mldsa: false }, { ed25519: false, mldsa: true }, { ed25519: false, mldsa: false }, {}, null]) {
    const chosen = choosePath(has);
    assert.equal(chosen.path, 'sample');
    assert.match(chosen.why, /not complete/);
  }
  assert.match(choosePath({ ed25519: true, mldsa: false }).why, /no built-in ML-DSA-87,/);
  assert.match(choosePath({ ed25519: false, mldsa: false }).why, /no built-in Ed25519 or ML-DSA-87,.*only the passkey's signature/);
});

test('the limit a visitor types is a whole number of GBP from 1 to 10,000, or nothing', () => {
  assert.equal(readLimit(' 200 '), 200);
  assert.equal(readLimit('1'), 1);
  assert.equal(readLimit('10000'), 10000);
  for (const text of ['', '0', '10001', '-5', '1.5', '1e3', 'abc', '200 GBP', '0x10']) assert.equal(readLimit(text), null, text);
});

test('the record made under each limit is intact, and the checker finds the first order over it', async () => {
  assert.equal(ORDERS.reduce((sum, o) => sum + o.value, 0), 230);
  for (const limit of [DEFAULT_LIMIT, 100, 230, 250, 1]) {
    const seen = [];
    const made = await makeRecord(lib, limit, (s) => seen.push(s.kind));
    const s = made.result.summary;
    assert.equal(s.intact, true, `limit ${limit}`);
    assert.equal(s.counts.stubs, ORDERS.length);
    assert.equal(s.firstBreach, expectedFirstBreach(limit), `limit ${limit}`);
    assert.deepEqual(seen, ['slip', 'stub', 'stub', 'stub', 'stub']);
    // The check before acting agrees with the checker, order by order.
    made.steps.forEach((step, i) => assert.equal(step.allowed, made.result.entries[i + 1].breaches.length === 0, `limit ${limit}, order ${i + 1}`));
    assert.ok(made.result.entries[0].content.issuer.name.endsWith(DEVELOPMENT_MARK));
  }
  assert.equal(expectedFirstBreach(200), 4);
  assert.equal(expectedFirstBreach(230), null);
});
