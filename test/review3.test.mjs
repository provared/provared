// What the third independent review found, in the seal and the time-stamp
// (3 October 2026). Each fault is fixed, and each is a test here.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { readFingerprints } from '../page/render.js';
import { sha256, utf8 } from '../src/encoding.js';
import { checkBook, checkShow, countersign, entryLine, makeShow, toBase64url, writeSeal } from '../src/index.js';
import { checkStamp } from '../src/timestamp.js';
import { makeStampService, octets, oid, sequence } from './helpers/stamp.mjs';
import { START, makeWorld } from './helpers/world.mjs';

const WHEN = Date.parse('2026-10-05T12:00:00Z');
const stamped = await sha256(utf8('what was stamped'));
const code = (expected) => (e) => e.code === expected;
const NULL = new Uint8Array([0x05, 0x00]);

function codes(result) {
  const out = result.problems.map((p) => p.code);
  for (const e of result.entries) out.push(...e.problems.map((p) => p.code), ...e.breaches.map((b) => b.code));
  return out;
}
const join2 = (lines) => lines.join('\n') + '\n';

// A slip, two stubs and a seal with a time-stamp, shared where a test only reads.
const w = await makeWorld();
await w.add();
await w.add();
const sealed = await w.seal();
const lines = w.book().split('\n').filter(Boolean);
const trust = { stampServices: [w.stampService.fingerprint] };

// --- the time-stamp itself ---

test('finding 5: a time-stamp that is not strict DER, or not laid out as its standard sets out, is refused', async () => {
  const service = await makeStampService();
  const trusted = [service.fingerprint];
  const bad = [
    { signedDataVersion: new Uint8Array([0x02, 0x02, 0x00, 0x03]) }, // a version not in its shortest form
    { signedDataVersion: new Uint8Array([0x02, 0x01, 0x01]) }, // a version other than 3
    { digestAlgorithms: new Uint8Array([0x04, 0x02, 0xff]) }, // a part cut short
    { digestAlgorithms: octets(new Uint8Array(2)) }, // not a method
    { afterSigners: sequence() }, // something after the signer
    { signerExtra: sequence() }, // something unknown in the signer
    { signerName: octets(new Uint8Array(1)) }, // the signer not named as the standard sets out
    { signerVersion: new Uint8Array([0x02, 0x01, 0x03]) }, // version 3 with a version 1 name
    { statementExtra: octets(new Uint8Array(1)) }, // something unknown in the statement
    { statementExtra: new Uint8Array([0x06, 0x00]) }, // an empty object identifier
    { statementExtra: new Uint8Array([0x01, 0x01, 0x01]) }, // a truth value not written as DER allows
  ];
  for (const [i, change] of bad.entries()) {
    await assert.rejects(checkStamp(await service.stamp(stamped, WHEN, change), stamped, { trusted }), code('stamp-bad-data'), `case ${i}`);
  }
  // A signing method that names another fingerprint method than the signer does.
  const rsa = await makeStampService('RSA');
  const mixed = await rsa.stamp(stamped, WHEN, { signatureAlgorithm: sequence(oid('2a864886f70d01010c'), NULL) });
  await assert.rejects(checkStamp(mixed, stamped, { trusted: [rsa.fingerprint] }), code('stamp-invalid'));
});

test('finding 9: a time-stamp must say which certificate signed it, state its time closely, and carry no extension it insists on', async () => {
  const service = await makeStampService();
  const o = { trusted: [service.fingerprint] };
  await assert.rejects(checkStamp(await service.stamp(stamped, WHEN, { noSigningCertificate: true }), stamped, o), code('stamp-invalid'));
  await assert.rejects(checkStamp(await service.stamp(stamped, WHEN, { signingCertificate: await sha256(utf8('another')) }), stamped, o), code('stamp-invalid'));
  assert.equal((await checkStamp(await service.stamp(stamped, WHEN, { accuracy: 300 }), stamped, o)).state, 'valid');
  await assert.rejects(checkStamp(await service.stamp(stamped, WHEN, { accuracy: 301 }), stamped, o), code('stamp-invalid'));
  await assert.rejects(checkStamp(await service.stamp(stamped, WHEN, { accuracy: 3600 }), stamped, o), code('stamp-invalid'));
  assert.equal((await checkStamp(await service.stamp(stamped, WHEN, { extension: 'plain' }), stamped, o)).state, 'valid');
  await assert.rejects(checkStamp(await service.stamp(stamped, WHEN, { extension: 'critical' }), stamped, o), code('stamp-invalid'));
});

test('findings 7 and 9: the certificate that counts is the one the signed part names, wherever it sits', async () => {
  const service = await makeStampService();
  const o = { trusted: [service.fingerprint] };
  // A second certificate for the same key, put in front: the time-stamp is still the trusted service's.
  const inFront = await service.stamp(stamped, WHEN, { certificates: [service.secondCertificate, service.certificate] });
  assert.deepEqual(await checkStamp(inFront, stamped, o), { state: 'valid', when: '2026-10-05T12:00:00Z', time: WHEN, authority: service.fingerprint });
  // Shown under the second certificate alone, it is refused: that is not the one it names.
  const swapped = await service.stamp(stamped, WHEN, { certificates: [service.secondCertificate] });
  await assert.rejects(checkStamp(swapped, stamped, o), code('stamp-invalid'));
  // Made under the second certificate, it is the second certificate's, which the checker did not name.
  const second = await service.stamp(stamped, WHEN, { certificates: [service.secondCertificate], signingCertificate: await sha256(service.secondCertificate) });
  const r = await checkStamp(second, stamped, o);
  assert.equal(r.state, 'untrusted');
  assert.notEqual(r.authority, service.fingerprint);
});

test('finding 12: checking a time-stamp does not change it, and odd arguments are refused, not thrown on', async () => {
  const service = await makeStampService();
  const token = Buffer.from(await service.stamp(stamped, WHEN));
  const copy = Buffer.from(token);
  assert.equal((await checkStamp(token, stamped, { trusted: [service.fingerprint] })).state, 'valid');
  assert.ok(token.equals(copy));
  assert.equal((await checkStamp(token, stamped, { trusted: [service.fingerprint] })).state, 'valid');
  assert.equal((await checkStamp(token, stamped, null)).state, 'untrusted');
  await assert.rejects(checkStamp(token), code('stamp-bad-data'));
  await assert.rejects(checkStamp(token, 'fingerprint'), code('stamp-bad-data'));
  // Where the device cannot check the method, no time is given at all.
  assert.deepEqual(await checkStamp(token, stamped, { without: ['ECDSA'] }), { state: 'unavailable', when: null, time: NaN, authority: null });
});

// --- the seal, the book and the Show ---

test('finding 1: a Show under a seal reports a page dated after the time-stamp that covers it', async () => {
  const late = await makeWorld();
  await late.add({ when: START });
  // A stub dated a day after the seal that covers it will be time-stamped.
  await late.add({ when: START + 24 * 3600 * 1000 });
  await late.seal({ when: START + 1800 * 1000 });
  const o = { stampServices: [late.stampService.fingerprint] };
  // In the whole book the time-stamp settles which date is wrong: the stub's.
  const whole = await checkBook(late.book(), o);
  assert.deepEqual(codes(whole), ['dated-after-stamp']);
  assert.equal(whole.entries[2].problems[0].code, 'dated-after-stamp');
  // With no service trusted, nothing settles it: the seal is where the two dates meet.
  assert.deepEqual(codes(await checkBook(late.book())), ['time-went-backwards']);
  // The Show under that seal, which the review found said "intact".
  const r = await checkShow(await makeShow(late.book(), [0, 2], { seal: 3 }), o);
  assert.ok(codes(r).includes('dated-after-stamp'));
  assert.equal(r.summary.intact, false);
  assert.equal(r.summary.sealed, null);
});

test('finding 6: a countersignature dated after the seal that covers it is found', async () => {
  const v = await makeWorld();
  const stub = await v.add({ countersigned: false });
  stub.entry.countersignature = await countersign(stub.entry.stub, v.service.privateKeys, START + 365 * 24 * 3600 * 1000);
  await v.seal();
  const r = await checkBook(v.book(), { stampServices: [v.stampService.fingerprint] });
  assert.deepEqual(codes(r), ['dated-after-stamp']);
  assert.equal(r.entries[1].kind, 'stub');
  assert.equal(r.entries[1].problems.length, 1);
  assert.equal(r.summary.intact, false);
});

test('finding 6: a later seal cannot have been time-stamped before an earlier one', async () => {
  const v = await makeWorld();
  await v.add();
  const first = await v.seal();
  // The first seal's time-stamp states first.when + 60 seconds. This one states 330 seconds before that.
  await v.seal({ when: first.when, stampTime: first.when + 60000 - 330000 });
  const r = await checkBook(v.book(), { stampServices: [v.stampService.fingerprint] });
  assert.deepEqual(codes(r), ['time-went-backwards']);
  assert.equal(r.entries[3].problems[0].message, 'This seal\'s time-stamp is earlier than the time-stamp of a seal before it.');
});

test('finding 2: a seal shown as a single page is compared with its place, and says what could not be compared', async () => {
  // The first world's seal, put into another book of the same length before it.
  const other = await makeWorld();
  await other.add();
  await other.add();
  const borrowed = join2([...other.book().split('\n').filter(Boolean), lines[3]]);
  // The whole book finds it at once.
  assert.ok(codes(await checkBook(borrowed, trust)).includes('seal-mismatch'));
  // As a single page at the right place, it cannot be compared: the page says so, and nothing is credited.
  const page = await checkShow(await makeShow(borrowed, [0, 2, 3]), trust);
  assert.equal(page.summary.sealed, null);
  assert.ok(page.entries[2].notes.some((n) => /could not be compared with the entries before it/.test(n)));
  assert.equal(page.entries[1].existedBy, undefined);
  // At a place it does not fit, it is refused.
  const moved = join2([other.book().split('\n')[0], lines[3]]);
  assert.ok(codes(await checkShow(await makeShow(moved, [1]), trust)).includes('seal-mismatch'));
});

test('finding 4: a time-stamp from a service the checker did not name is not treated as a time', async () => {
  const stranger = await makeStampService();
  const entry = JSON.parse(lines[3]);
  // An hour before the seal's own date: from a trusted service this would be a problem.
  const early = toBase64url(await stranger.stamp(sealed.fingerprintBytes, sealed.when - 3600 * 1000));
  const book = join2([...lines.slice(0, 3), entryLine({ seal: entry.seal, stamps: [entry.stamps[0], early] })]);
  for (const options of [trust, {}]) {
    const r = await checkBook(book, options);
    assert.deepEqual(codes(r), []);
    assert.equal(r.summary.intact, true);
  }
  assert.ok(codes(await checkBook(book, { stampServices: [stranger.fingerprint] })).includes('dated-after-stamp'));
});

test('finding 11: a time-stamp is credited only when all three signatures of the seal were checked', async () => {
  const r = await checkBook(w.book(), { ...trust, withoutMethods: ['SLH-DSA-SHA2-256s'] });
  assert.equal(r.summary.problemFound, false);
  assert.equal(r.summary.sealed, null);
  assert.equal(r.entries[0].existedBy, undefined);
  assert.equal((await checkBook(w.book(), trust)).summary.sealed.entries, 3);
});

test('the same time-stamp twice beside one seal is refused', async () => {
  const entry = JSON.parse(lines[3]);
  const r = await checkBook(join2([...lines.slice(0, 3), JSON.stringify({ seal: entry.seal, stamps: [entry.stamps[0], entry.stamps[0]] })]), trust);
  assert.ok(codes(r).includes('bad-field'));
});

test('finding 8: time-stamps beside a seal whose own signatures fail are not checked', async () => {
  const entry = JSON.parse(lines[3]);
  const broken = { ...entry.seal, signatures: entry.seal.signatures.map((s) => ({ ...s, signature: 'AAAA' })) };
  const r = await checkBook(join2([...lines.slice(0, 3), entryLine({ seal: broken, stamps: entry.stamps })]), trust);
  assert.ok(codes(r).includes('signature-invalid'));
  assert.deepEqual(r.entries[3].stamps, []);
});

// --- what is shown ---

test('finding 3: a line that is not a fingerprint is reported, never dropped', () => {
  const good = 'A'.repeat(43);
  assert.deepEqual(readFingerprints(`${good}\n\n  ${good}  `), { values: [good, good], bad: [] });
  for (const wrong of [good + '.', good + '=', 'a'.repeat(64), good.slice(1), 'not-a-fingerprint']) {
    assert.deepEqual(readFingerprints(wrong), { values: [], bad: [wrong] }, wrong);
  }
  assert.deepEqual(readFingerprints(''), { values: [], bad: [] });
});

test('finding 10: a name padded with spaces cannot imitate a line of the checker', async () => {
  const v = await makeWorld();
  await v.add();
  await v.seal();
  v.entries.pop();
  const name = 'Example recorder' + ' '.repeat(100) + 'OUTSIDE TIME-STAMP: 2026-10-05T10:31:00Z, from a service you named as trusted';
  const fake = await writeSeal(v.book(), { by: { keys: v.recorder.keys, name }, when: START + 1800 * 1000 }, v.recorder.privateKeys);
  const dir = mkdtempSync(join(tmpdir(), 'provared-'));
  const file = join(dir, 'padded.jsonl');
  writeFileSync(file, v.book() + entryLine({ seal: fake.record }) + '\n');
  const cli = join(fileURLToPath(new URL('..', import.meta.url)), 'bin', 'provared-check.mjs');
  const out = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', cli, file], { encoding: 'utf8' }).stdout;
  // The name is shown in quotation marks, with its run of spaces folded into one.
  assert.match(out, /Recorder:\s+"Example recorder OUTSIDE TIME-STAMP: 2026-10-05T10:31:00Z, from a service you named as trusted" \(a label, not checked\)/);
  assert.doesNotMatch(out, /Example recorder {2,}/);
  assert.match(out, /No outside time-stamp: the time is only the recorder's own word\./);
});
