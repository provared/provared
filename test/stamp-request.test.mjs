// Asking a time-stamp service for a time-stamp (net/timestamp.js), against
// a service on this computer that the OpenSSL program answers for
// (helpers/tsa.mjs). No test reaches beyond this computer. Where there is
// no OpenSSL program, the tests that need it are skipped and say why.

import assert from 'node:assert/strict';
import http from 'node:http';
import { after, before, test } from 'node:test';
import { MAX_REPLY_BYTES, MAX_SHOWN_CHARACTERS, NONCE_BYTES, askForStamp, stampAddress, stampRequest, stampService } from '../net/timestamp.js';
import { decodeStamps } from '../src/seal.js';
import { fromBase64url } from '../src/encoding.js';
import { checkStamp } from '../src/timestamp.js';
import { makeStampService, sequence } from './helpers/stamp.mjs';
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
  // 320 seconds either way: the service's time can fall a second or two after the request, and its time is in whole seconds.
  for (const offset of [-320000, 320000]) {
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

test('only an address on the web is taken, with no user name, password, query or fragment, and a time limit in range', () => {
  assert.equal(stampAddress('http://127.0.0.1:8080/tsa'), 'http://127.0.0.1:8080/tsa');
  // A query may carry a key to the service, as a user name or password may: it is refused, not hidden (X311).
  for (const bad of ['', 'not an address', 'ftp://127.0.0.1/', 'file:///tsa', 'http://user:secret@127.0.0.1/', 'http://127.0.0.1/#part', 'http://127.0.0.1/tsa?key=secret', 'http://127.0.0.1/tsa?', 'http://127.0.0.1/tsa#']) {
    assert.throws(() => stampAddress(bad), TypeError, bad);
  }
  assert.throws(() => stampService({}), TypeError);
  for (const timeout of [99, 60001, 1.5, '1000']) assert.throws(() => stampService({ address: 'http://127.0.0.1/', timeout }), TypeError, String(timeout));
});

test('a time more than 300 seconds before the seal\'s own time, or before the time an earlier seal\'s time-stamp gave, is not kept', { skip }, async () => {
  tsa.mode = 'good';
  const now = Date.now();
  // The service's time is about now: a seal dated 320 seconds later would be dated after its time-stamp (section 21.2, rule 7).
  await assert.rejects(askForStamp(fingerprint(), { address: tsa.address, when: now + 320000 }), refusedWith('stamp-not-given', /more than 300 seconds before the seal's own time/));
  // A seal before it stamped 320 seconds later would put the times going backwards (section 21.3).
  await assert.rejects(askForStamp(fingerprint(), { address: tsa.address, after: now + 320000 }), refusedWith('stamp-not-given', /before the time a service's time-stamp gave the seal before/));
  // Within 300 seconds, kept; the hook of openSealer is given both as its "context".
  const hook = stampService({ address: tsa.address });
  assert.equal(typeof (await hook(fingerprint(), { when: now + 200000, after: now + 200000 })), 'string');
  assert.equal(typeof (await hook(fingerprint(), { when: now, after: null })), 'string');
  await assert.rejects(hook(fingerprint(), { when: now + 320000, after: null }), refusedWith('stamp-not-given', /the seal's own time/));
  for (const bad of ['1', Number.NaN, Number.POSITIVE_INFINITY]) {
    await assert.rejects(askForStamp(fingerprint(), { address: tsa.address, when: bad }), TypeError, String(bad));
    await assert.rejects(askForStamp(fingerprint(), { address: tsa.address, after: bad }), TypeError, String(bad));
  }
});

test('an answer with bytes left over after it gives no time-stamp', { skip }, async () => {
  tsa.mode = 'trailing';
  await assert.rejects(askForStamp(fingerprint(), { address: tsa.address }), refusedWith('stamp-not-given', /bytes left over after it/));
});

test('a time-stamp larger than the format allows is not kept, though the answer is within the size read', { skip }, async () => {
  tsa.mode = 'big-token';
  await assert.rejects(askForStamp(fingerprint(), { address: tsa.address }), refusedWith('stamp-not-given', /a time-stamp of 12302 bytes, more than the 12288 the format allows/));
});

test('status 1 ("granted with changes") gives the time-stamp, as status 0 does', { skip }, async () => {
  tsa.mode = 'status-1';
  const fp = fingerprint();
  const got = await askForStamp(fp, { address: tsa.address });
  assert.equal((await checkStamp(fromBase64url(got.stamp), fp, { trusted: [tsa.authority] })).state, 'valid');
});

test('a body sent slowly after its headers ends at the time limit: the limit holds for the whole answer', { skip }, async () => {
  tsa.mode = 'drip';
  tsa.delay = 3000;
  const start = Date.now();
  await assert.rejects(askForStamp(fingerprint(), { address: tsa.address, timeout: 500 }), refusedWith('stamp-not-given', /no whole answer within 500 milliseconds/));
  assert.ok(Date.now() - start < 2500, 'it did not wait for the rest of the body');
});

test('a compressed answer is read as it opens, and its size is counted opened', { skip }, async () => {
  tsa.mode = 'gzip';
  assert.equal(typeof (await askForStamp(fingerprint(), { address: tsa.address })).stamp, 'string');
  // A small body that opens to 100,000 bytes is stopped once what it opens to passes the size read.
  tsa.mode = 'gzip-bomb';
  await assert.rejects(askForStamp(fingerprint(), { address: tsa.address }), refusedWith('stamp-not-given', new RegExp(`longer than the ${MAX_REPLY_BYTES} bytes read`)));
});

test('a time-stamp signed with a method this device cannot check is not kept', { skip }, async () => {
  // A time-stamp signed with Ed25519, given as the answer, on a device made to lack Ed25519.
  const service = await makeStampService('Ed25519');
  const fp = fingerprint();
  tsa.mode = 'answer';
  tsa.answer = sequence(sequence(Uint8Array.of(0x02, 0x01, 0x00)), await service.stamp(fp, Date.now()));
  const subtle = globalThis.crypto.subtle;
  const importKey = subtle.importKey;
  subtle.importKey = function (format, data, algorithm, ...rest) {
    if ((algorithm?.name ?? algorithm) === 'Ed25519') return Promise.reject(new DOMException('Ed25519 is not built in here', 'NotSupportedError'));
    return importKey.call(this, format, data, algorithm, ...rest);
  };
  try {
    await assert.rejects(askForStamp(fp, { address: tsa.address }), refusedWith('stamp-not-given', /signs with a method this device cannot check/));
  } finally {
    subtle.importKey = importKey;
  }
});

test('what a service writes is shown with no control or format characters, and cut at 200 characters', { skip }, async () => {
  // A refusal (status 2) whose words turn the text round (U+202E), hide a character (U+200B), steer a terminal (ESC) and run long.
  const words = new TextEncoder().encode(`ok‮evil​x\u001b[31m${'A'.repeat(500)}`);
  tsa.mode = 'answer';
  tsa.answer = sequence(sequence(Uint8Array.of(0x02, 0x01, 0x02), sequence(Uint8Array.of(0x0c, 0x82, words.length >> 8, words.length & 0xff), words)));
  const e = await askForStamp(fingerprint(), { address: tsa.address }).catch((x) => x);
  assert.equal(e.code, 'stamp-not-given', e.message);
  assert.doesNotMatch(e.message, /[\p{Cc}\p{Cf}]/u);
  assert.match(e.message, /"ok evil x \[31mA+\.\.\.\.$/);
  const said = e.message.slice(e.message.indexOf('(status 2), ') + '(status 2), '.length);
  assert.equal(said.length, MAX_SHOWN_CHARACTERS + '....'.length);
});
