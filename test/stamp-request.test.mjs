// Asking a time-stamp service for a time-stamp (net/timestamp.js), against
// a service on this computer that the OpenSSL program answers for
// (helpers/tsa.mjs). No test reaches beyond this computer. Where there is
// no OpenSSL program, the tests that need it are skipped and say why.

import assert from 'node:assert/strict';
import http from 'node:http';
import { after, before, test } from 'node:test';
import { MAX_REPLY_BYTES, NONCE_BYTES, askForStamp, stampAddress, stampRequest, stampService } from '../net/timestamp.js';
import { decodeStamps } from '../src/seal.js';
import { fromBase64url } from '../src/encoding.js';
import { checkStamp } from '../src/timestamp.js';
import { NO_OPENSSL, findOpenssl, startTestTsa } from './helpers/tsa.mjs';

const skip = findOpenssl() ? false : NO_OPENSSL;
const fingerprint = () => globalThis.crypto.getRandomValues(new Uint8Array(32));
let tsa;

before(async () => {
  if (!skip) tsa = await startTestTsa();
});
after(async () => {
  await tsa?.close();
});

const refusedWith = (code, words) => (e) => {
  assert.equal(e.code, code, e.message);
  if (words) assert.match(e.message, words);
  return true;
};

test('the request is the one RFC 3161 sets out: version 1, SHA-256 with no parameters, the fingerprint, the number used once, the certificate asked for', () => {
  const fp = new Uint8Array(32).fill(0xab);
  const hex = (b) => Buffer.from(b).toString('hex');
  assert.equal(hex(stampRequest(fp, Uint8Array.of(0, 0, 1, 2))), `303b020101302f300b0609608648016503040201 0420${'ab'.repeat(32)} 02020102 0101ff`.replaceAll(' ', ''));
  // A first byte with its highest bit set is written after a zero byte, so the number stays positive (X.690, section 8.3).
  assert.equal(hex(stampRequest(fp, Uint8Array.of(0x80, 1)).subarray(-8)), '0203008001' + '0101ff');
  assert.throws(() => stampRequest(new Uint8Array(31), Uint8Array.of(1)), TypeError);
  assert.equal(NONCE_BYTES, 8);
});

test('a good answer gives the item of "stamps": the time-stamp in base64url, which the library checks for this fingerprint', { skip }, async () => {
  tsa.mode = 'good';
  const fp = fingerprint();
  const before = Date.now();
  const got = await askForStamp(fp, { address: tsa.address });
  assert.equal(got.authority, tsa.authority);
  assert.ok(Math.abs(got.time - before) < 60000);
  const [item] = decodeStamps([got.stamp]);
  assert.equal(item.kind, 'service');
  assert.equal((await checkStamp(fromBase64url(got.stamp), fp, { trusted: [tsa.authority] })).state, 'valid');
  // A number used once of 64 random bits, another for each request.
  const hook = stampService({ address: tsa.address });
  assert.equal(typeof (await hook(fp)), 'string');
  const [a, b] = tsa.queries.slice(-2).map((q) => Buffer.from(q).toString('hex'));
  assert.notEqual(a, b);
});

test('a service that refuses gives no time-stamp, and its status and reason are said', { skip }, async () => {
  tsa.mode = 'refuse';
  await assert.rejects(askForStamp(fingerprint(), { address: tsa.address }), refusedWith('stamp-not-given', /refused \(status 2\).*fingerprint method/));
});

test('a time-stamp with another number used once, or none, is not kept: it may answer another request', { skip }, async () => {
  tsa.mode = 'wrong-nonce';
  await assert.rejects(askForStamp(fingerprint(), { address: tsa.address }), refusedWith('stamp-wrong-data', /another number used once/));
  tsa.mode = 'no-nonce';
  await assert.rejects(askForStamp(fingerprint(), { address: tsa.address }), refusedWith('stamp-wrong-data', /does not carry the number used once/));
});

test('a time-stamp made for another fingerprint is not kept', { skip }, async () => {
  tsa.mode = 'wrong-imprint';
  await assert.rejects(askForStamp(fingerprint(), { address: tsa.address }), refusedWith('stamp-wrong-data', /made for something else/));
});

test('an answer larger than is read is refused, whether its length is given or not', { skip }, async () => {
  // A length given over the limit is refused before the body is read; a body with no length given, once it passes the limit.
  tsa.mode = 'big';
  await assert.rejects(askForStamp(fingerprint(), { address: tsa.address }), refusedWith('stamp-not-given', new RegExp(`is 20000 bytes, more than the ${MAX_REPLY_BYTES} bytes read`)));
  tsa.mode = 'big-unsized';
  await assert.rejects(askForStamp(fingerprint(), { address: tsa.address }), refusedWith('stamp-not-given', new RegExp(`longer than the ${MAX_REPLY_BYTES} bytes read`)));
});

test('a redirect is not followed: the request reaches no other address', { skip }, async () => {
  tsa.mode = 'redirect';
  await assert.rejects(askForStamp(fingerprint(), { address: tsa.address }), refusedWith('stamp-not-given', /redirect, which is not followed/));
  assert.equal(tsa.reachedElsewhere, 0);
});

test('a service slower than the time limit gives no time-stamp, and the request ends at the limit', { skip }, async () => {
  tsa.mode = 'slow';
  tsa.delay = 3000;
  const start = Date.now();
  await assert.rejects(askForStamp(fingerprint(), { address: tsa.address, timeout: 500 }), refusedWith('stamp-not-given', /within 500 milliseconds/));
  assert.ok(Date.now() - start < 2500, 'it did not wait for the answer');
  // Within the limit, the same answer is kept.
  tsa.delay = 200;
  assert.equal(typeof (await askForStamp(fingerprint(), { address: tsa.address, timeout: 5000 })).stamp, 'string');
});

test('an answer that is not 200, or not an answer of RFC 3161, gives no time-stamp', { skip }, async () => {
  tsa.mode = 'status-500';
  await assert.rejects(askForStamp(fingerprint(), { address: tsa.address }), refusedWith('stamp-not-given', /HTTP status 500/));
  tsa.mode = 'garbage';
  await assert.rejects(askForStamp(fingerprint(), { address: tsa.address }), refusedWith('stamp-bad-data'));
});

test('a time-stamp whose time is more than 300 seconds from this device\'s clock is not kept', { skip }, async () => {
  tsa.mode = 'good';
  for (const offset of [-301000, 301000]) {
    await assert.rejects(askForStamp(fingerprint(), { address: tsa.address, clock: () => Date.now() + offset }), refusedWith('stamp-not-given', /more than 300 seconds from this device's clock/), String(offset));
  }
  assert.equal(typeof (await askForStamp(fingerprint(), { address: tsa.address, clock: () => Date.now() + 200000 })).stamp, 'string');
});

test('a service that cannot be reached gives no time-stamp, said plainly', async () => {
  // A port that was free a moment ago, and that nothing listens on now.
  const s = http.createServer();
  await new Promise((done) => s.listen(0, '127.0.0.1', done));
  const port = s.address().port;
  await new Promise((done) => s.close(done));
  await assert.rejects(askForStamp(fingerprint(), { address: `http://127.0.0.1:${port}/`, timeout: 2000 }), refusedWith('stamp-not-given', /could not be reached/));
});

test('only an address on the web is taken, with no user name, password or fragment, and a time limit in range', () => {
  assert.equal(stampAddress('http://127.0.0.1:8080/tsa'), 'http://127.0.0.1:8080/tsa');
  for (const bad of ['', 'not an address', 'ftp://127.0.0.1/', 'file:///tsa', 'http://user:secret@127.0.0.1/', 'http://127.0.0.1/#part']) {
    assert.throws(() => stampAddress(bad), TypeError, bad);
  }
  assert.throws(() => stampService({}), TypeError);
  for (const timeout of [99, 60001, 1.5, '1000']) assert.throws(() => stampService({ address: 'http://127.0.0.1/', timeout }), TypeError, String(timeout));
});
