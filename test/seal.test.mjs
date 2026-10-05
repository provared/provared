// The Seal: whoever keeps a book signs its top fingerprint and its number of
// entries, and an outside time-stamp service states when. What this closes,
// and what it does not.
//
// Signing a seal takes about a second and a half (the third signature rests
// only on fingerprint functions, and is slow to make). So the tests share
// one sealed book where they can.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBook, checkShow, entryLine, generateSealKeySet, keySetFingerprint, makeShow, methodAvailable, toBase64url, utf8, writeSeal } from '../src/index.js';
import { treeBuilder, treeRoot } from '../src/tree.js';
import { makeStampService } from './helpers/stamp.mjs';
import { makeWorld, withContent } from './helpers/world.mjs';

function codes(result) {
  const out = result.problems.map((p) => p.code);
  for (const e of result.entries) out.push(...e.problems.map((p) => p.code), ...e.breaches.map((b) => b.code));
  return out;
}
const join = (lines) => lines.join('\n') + '\n';

// A slip, two stubs, a seal with a time-stamp, a third stub, a second seal
// with a time-stamp, a fourth stub that no seal covers.
const w = await makeWorld();
await w.add();
await w.add();
const first = await w.seal();
await w.add();
const second = await w.seal();
await w.add();
const lines = w.book().split('\n').filter(Boolean);
const trust = { stampServices: [w.stampService.fingerprint] };
const sealer = await keySetFingerprint(w.recorder.keys);

test('this device has the seal\'s third signing method', async () => {
  assert.equal(await methodAvailable('SLH-DSA-SHA2-256s'), true);
});

test('a sealed book: intact, and the time-stamp says how far it reaches and when', async () => {
  const r = await checkBook(w.book(), { ...trust, sealKeys: [sealer] });
  assert.deepEqual(codes(r), []);
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.withinSlips, true);
  assert.equal(r.summary.counts.seals, 2);
  // The second seal is entry 5. It covers the five entries before it.
  assert.deepEqual(r.summary.sealed, { entries: 5, when: r.entries[5].stampedAt, seal: 5, by: 'service' });
  assert.equal(r.entries[5].stampedAt, new Date(second.when + 60000).toISOString().slice(0, 19) + 'Z');
  assert.deepEqual(r.entries[3].signatures.map((s) => `${s.method} ${s.state}`), ['Ed25519 valid', 'ML-DSA-87 valid', 'SLH-DSA-SHA2-256s valid']);
  assert.equal(r.entries[3].sealer, sealer);
  assert.deepEqual(r.entries[3].notes, []);
  // Each entry says by when it is shown to have existed: the time of the first counted time-stamp on a seal
  // after it. The first seal is covered by the second. The second seal and the last stub are covered by none.
  assert.deepEqual(r.entries.map((e) => e.existedBy ?? null), [
    r.entries[3].stampedAt,
    r.entries[3].stampedAt,
    r.entries[3].stampedAt,
    r.entries[5].stampedAt,
    r.entries[5].stampedAt,
    null,
    null,
  ]);
  // Only a seal says "stampedAt": the time its own time-stamps give it.
  assert.deepEqual(r.entries.map((e) => (e.stampedAt === undefined ? null : e.kind)), [null, null, null, 'seal', null, 'seal', null]);
  assert.match(r.summary.limits.at(-1), /^An outside time-stamp covers the first 5 entries/);
});

test('a time-stamp from a service the checker did not name counts for nothing, and the result says so', async () => {
  for (const options of [{}, { stampServices: [] }, { stampServices: ['A'.repeat(43)] }]) {
    const r = await checkBook(w.book(), options);
    assert.deepEqual(codes(r), []);
    assert.equal(r.summary.intact, true);
    assert.equal(r.summary.sealed, null);
    assert.match(r.summary.limits.at(-1), /^Nothing here is time-stamped by an outside service that you named as trusted/);
    assert.ok(r.entries[3].notes.some((n) => n.includes(w.stampService.fingerprint)));
    assert.equal(r.entries[0].existedBy, undefined);
  }
});

test('with no expected recorder, the result says the seal\'s keys were not compared', async () => {
  const r = await checkBook(w.book(), trust);
  assert.ok(r.entries[3].notes.some((n) => /were not compared with keys you already trust/.test(n)));
});

test('the latest stubs before a seal can no longer be removed unnoticed', async () => {
  // Before seals, taking the last stub off a book left a book that checked.
  // Now the seal after it no longer fits.
  const r = await checkBook(join([lines[0], lines[1], ...lines.slice(3)]), trust);
  assert.ok(codes(r).includes('seal-mismatch'));
  assert.equal(r.summary.intact, false);
  assert.equal(r.summary.sealed, null);
});

test('any change to an entry before a seal is found by the seal', async () => {
  for (let i = 0; i < 3; i++) {
    const at = Math.floor(lines[i].length / 2);
    const changed = [...lines];
    changed[i] = lines[i].slice(0, at) + (lines[i][at] === 'A' ? 'B' : 'A') + lines[i].slice(at + 1);
    const r = await checkBook(join(changed), trust);
    assert.ok(r.entries[3].problems.some((p) => p.code === 'seal-mismatch'), `line ${i}`);
  }
});

test('what is still not closed: the last seal and everything after it can be removed', async () => {
  // The book cut back to its first seal checks. Only a copy of the later
  // top fingerprint, held by someone else, shows the loss.
  const cut = join(lines.slice(0, 4));
  const r = await checkBook(cut, trust);
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.sealed.entries, 3);
  const later = await checkBook(w.book(), trust);
  const withCopy = await checkBook(cut, { ...trust, expectedRoot: later.root, expectedSize: later.size });
  assert.ok(codes(withCopy).includes('root-mismatch'));
});

test('a stub that no seal covers is still checked, and is said not to be time-stamped', async () => {
  const r = await checkBook(w.book(), trust);
  assert.equal(r.entries[6].kind, 'stub');
  assert.deepEqual(r.entries[6].problems, []);
  assert.match(r.summary.limits.at(-1), /What came after is not time-stamped/);
});

test('a seal that is not signed by the keys it gives, or lacks a signature, is refused', async () => {
  const other = await generateSealKeySet();
  // The same seal content, signed by another recorder's keys.
  const forged = await writeSeal(join(lines.slice(0, 3)), { by: { keys: w.recorder.keys, name: 'Example recorder (invented)' }, when: first.when }, other.privateKeys);
  const r = await checkBook(join([...lines.slice(0, 3), entryLine({ seal: forged.record })]), trust);
  assert.ok(codes(r).includes('signature-invalid'));

  const entry = JSON.parse(lines[3]);
  const stripped = { ...entry, seal: { ...entry.seal, signatures: entry.seal.signatures.slice(0, 2) } };
  assert.ok(codes(await checkBook(join([...lines.slice(0, 3), entryLine(stripped)]), trust)).includes('bad-signatures-layout'));

  const twoKeys = { ...entry, seal: withContent(entry.seal, (c) => void (c.by.keys = c.by.keys.slice(0, 2))) };
  assert.ok(codes(await checkBook(join([...lines.slice(0, 3), entryLine(twoKeys)]), trust)).includes('bad-key'));
});

test('time-stamps beside a seal that are not as the format says are refused, not crashed on', async () => {
  const entry = JSON.parse(lines[3]);
  const token = entry.stamps[0];
  for (const stamps of [[], [token, token, token, token, token], 'token', [42], ['not base64url!'], ['A'.repeat(20000)], [null]]) {
    const r = await checkBook(join([...lines.slice(0, 3), JSON.stringify({ seal: entry.seal, stamps })]), trust);
    assert.equal(r.summary.problemFound, true, JSON.stringify(stamps).slice(0, 40));
    assert.equal(r.summary.intact, false);
  }
});

test('a seal with no time-stamp is sound, and its time is only the recorder\'s word', async () => {
  const entry = JSON.parse(lines[3]);
  const r = await checkBook(join([...lines.slice(0, 3), entryLine({ seal: entry.seal })]), trust);
  assert.deepEqual(codes(r), []);
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.sealed, null);
  assert.deepEqual(r.entries[3].stamps, []);
});

test('a seal dated well after its own time-stamp is refused; a small difference between clocks is allowed', async () => {
  const entry = JSON.parse(lines[3]);
  const service = w.stampService;
  const stampAt = async (ms) => [toBase64url(await service.stamp(first.fingerprintBytes, ms))];
  const check = async (ms) => codes(await checkBook(join([...lines.slice(0, 3), entryLine({ seal: entry.seal, stamps: await stampAt(ms) })]), trust));
  assert.deepEqual(await check(first.when - 299 * 1000), []);
  assert.deepEqual(await check(first.when - 301 * 1000), ['dated-after-stamp']);
});

test('on a device without the third method, or without the time-stamp service\'s method, nothing passes', async () => {
  const noSlh = await checkBook(w.book(), { ...trust, withoutMethods: ['SLH-DSA-SHA2-256s'] });
  assert.equal(noSlh.summary.problemFound, false);
  assert.equal(noSlh.summary.intact, false);
  assert.deepEqual(noSlh.summary.methodsMissing, ['SLH-DSA-SHA2-256s']);

  const noStampMethod = await checkBook(w.book(), { ...trust, withoutMethods: ['ECDSA'] });
  assert.equal(noStampMethod.summary.intact, false);
  assert.equal(noStampMethod.summary.sealed, null);
  assert.deepEqual(noStampMethod.summary.methodsMissing, ['the time-stamp service\'s method']);
});

test('a Show under a seal proves its pages existed at the time-stamp\'s time, with no copy of the top fingerprint', async () => {
  const show = await makeShow(w.book(), [0, 2], { seal: 3 });
  assert.equal(show.size, 3);
  const r = await checkShow(show, trust);
  assert.deepEqual(codes(r), []);
  assert.equal(r.summary.intact, true);
  assert.deepEqual(r.summary.sealed, { entries: 3, when: r.entries[2].stampedAt, seal: 3, by: 'service' });
  assert.deepEqual(r.entries.map((e) => e.kind), ['slip', 'stub', 'seal']);
  assert.ok(!r.notes.some((n) => /was not compared/.test(n)));

  // Without a trusted service, the Show says its top fingerprint rests on nothing.
  const untrusted = await checkShow(show);
  assert.equal(untrusted.summary.sealed, null);
  assert.ok(untrusted.notes.some((n) => /was not compared with a copy you already trust/.test(n)));
});

test('a Show cannot borrow a seal from another book, or from this book at another length', async () => {
  const show = await makeShow(w.book(), [0, 2], { seal: 3 });
  const otherLength = { ...show, seal: JSON.parse(lines[5]) };
  assert.ok(codes(await checkShow(otherLength, trust)).includes('seal-mismatch'));
  const noSeal = { ...show, seal: { stamps: JSON.parse(lines[3]).stamps } };
  assert.ok(codes(await checkShow(noSeal, trust)).includes('bad-field'));
  for (const hostile of [null, 42, 'seal', [], { seal: null }, { seal: {}, extra: 1 }]) {
    const r = await checkShow({ ...show, seal: hostile }, trust);
    assert.equal(r.summary.problemFound, true);
    assert.equal(r.summary.sealed, null);
  }
  await assert.rejects(makeShow(w.book(), [0], { seal: 2 }), RangeError);
  await assert.rejects(makeShow(w.book(), [0], { seal: 99 }), RangeError);
  await assert.rejects(makeShow(w.book(), [4], { seal: 3 }), Error);
});

test('a seal shown as an ordinary page is checked for its signatures and its time-stamp', async () => {
  const show = await makeShow(w.book(), [3]);
  const r = await checkShow(show, trust);
  assert.deepEqual(codes(r), []);
  assert.equal(r.entries[0].kind, 'seal');
  assert.equal(r.entries[0].stamps[0].state, 'valid');
});

test('the tree that grows leaf by leaf gives the same top fingerprint at every size', async () => {
  const leaves = Array.from({ length: 33 }, (_, i) => utf8(`leaf ${i}`));
  const builder = treeBuilder();
  for (let n = 0; n <= leaves.length; n++) {
    assert.deepEqual(await builder.root(), await treeRoot(leaves.slice(0, n)), `size ${n}`);
    if (n < leaves.length) await builder.add(leaves[n]);
  }
});

test('a time-stamp from a second service can sit beside the first, and either may be the trusted one', async () => {
  const entry = JSON.parse(lines[3]);
  const other = await makeStampService('RSA');
  const both = { seal: entry.seal, stamps: [entry.stamps[0], toBase64url(await other.stamp(first.fingerprintBytes, first.when + 120000))] };
  const book = join([...lines.slice(0, 3), entryLine(both)]);
  const onlyOther = await checkBook(book, { stampServices: [other.fingerprint] });
  assert.deepEqual(codes(onlyOther), []);
  assert.deepEqual(onlyOther.entries[3].stamps.map((s) => s.state), ['untrusted', 'valid']);
  assert.equal(onlyOther.summary.sealed.when, new Date(first.when + 120000).toISOString().slice(0, 19) + 'Z');
  // With both trusted, the earlier time is the one that counts.
  const bothTrusted = await checkBook(book, { stampServices: [other.fingerprint, w.stampService.fingerprint] });
  assert.equal(bothTrusted.summary.sealed.when, new Date(first.when + 60000).toISOString().slice(0, 19) + 'Z');
});
