// The "try it" page's own logic (site/try/story.js), which runs the same in Node.js as in a browser.

import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBook } from '../src/check.js';
import { developmentRecorder, DEVELOPMENT_MARK } from '../src/dev.js';
import { sha256, toBase64url, utf8 } from '../src/encoding.js';
import { DEFAULT_LIMIT, ORDERS, choosePath, expectedFirstBreach, limitRefusal, makeRecord, pathText, readLimit } from '../site/try/story.js';

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

test('the words that differ by path are true only of the record that path shows', () => {
  const live = pathText('live');
  const sample = pathText('sample');
  assert.match(live.permissionNote, /a moment ago/);
  assert.match(live.permissionNote, /http:\/\/localhost, which is meant for development; a real permission names the page where the person signed, such as https:\/\/sign\.prova\.red/);
  assert.match(live.notDone.join(' '), /makes no seal/);
  assert.match(live.notDone.join(' '), /No other party countersigns/);
  assert.match(live.checkedBy, /stand-in passkey that this page made a moment ago/);
  assert.match(live.signedWith, /stand-in for a passkey/);
  assert.doesNotMatch(sample.permissionNote, /moment ago|\(development\)|http:\/\/localhost/);
  assert.match(sample.permissionNote, /in advance, on 5 October 2026/);
  assert.match(sample.notDone.join(' '), /has a seal, receipts countersigned by the invented supplier, and a time-stamp from a made-up time-stamp service/);
  assert.doesNotMatch(sample.notDone.join(' '), /no seal|No other party countersigns|Nothing here is time-stamped/);
  assert.match(sample.checkedBy, /keys that come with the sample/);
  assert.match(sample.signedWith, /software stand-in for a passkey, in advance/);
  for (const words of [live, sample]) assert.doesNotMatch([words.permissionNote, ...words.notDone].join(' '), /no browser has yet|No browser has the third/);
});

test('the sample path names only the browsers that were tried, and the refusal of a limit writes 10,000 with a comma', () => {
  for (const has of [{ ed25519: true, mldsa: false }, { ed25519: false, mldsa: false }]) assert.match(choosePath(has).why, /Chrome, Edge and Brave 155, tried on 13 October 2026, can make a new record here\.$/);
  assert.match(limitRefusal(), /from 1 to 10,000\./);
});

test('the try page leaves the heading of the top fingerprint to the renderer, which names the Seal only where there is one', () => {
  const render = readFileSync(new URL('../page/render.js', import.meta.url), 'utf8');
  const page = readFileSync(new URL('../site/try/try-page.js', import.meta.url), 'utf8');
  assert.ok(render.includes('topFingerprintHeading(result)'));
  assert.ok(!page.includes('the Seal'), 'the try page relabels the heading again; the renderer already heads it by what the record holds');
});

test('the renderer still names its list of entries as the try page folds it', () => {
  const render = readFileSync(new URL('../page/render.js', import.meta.url), 'utf8');
  const page = readFileSync(new URL('../site/try/try-page.js', import.meta.url), 'utf8');
  assert.ok(render.includes("'The entries'"), 'page/render.js no longer names its list of entries "The entries": change the try page with it');
  assert.ok(page.includes("h.textContent === 'The entries'"));
});

test('the start-up guard acts only on a script that fails, and the page clears its message once ready', () => {
  const wait = readFileSync(new URL('../site/try/wait.js', import.meta.url), 'utf8');
  const page = readFileSync(new URL('../site/try/try-page.js', import.meta.url), 'utf8');
  assert.ok(wait.includes("event.target.tagName === 'SCRIPT'"));
  assert.ok(page.includes("$('status').textContent = '';"));
});
