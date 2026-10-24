// The fixes that the audit of the Internet-Draft (24 October 2026) listed for
// version 0.6.0. Each refusal here fails without its fix. Where the library
// beneath (OpenSSL) would refuse the same bytes on its own, the test stands a
// yes-saying "verify" in its place, so that it shows the library deciding for
// itself, as the format description asks (section 3.8).

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readElement, setInOrder, timeOf, validateDer } from '../src/der.js';
import { concatBytes, fromBase64url, sha256, toBase64url, utf8 } from '../src/encoding.js';
import { badEd25519Signature, checkKey, onP256 } from '../src/keys.js';
import { generateKeySet, sign, verifySignature } from '../src/signatures.js';
import { checkStamp } from '../src/timestamp.js';
import { makePasskey } from './helpers/passkey.mjs';
import { makeStampService, oid, sequence, sorted } from './helpers/stamp.mjs';

const H = (text) => Uint8Array.from(Buffer.from(text, 'hex'));
const code = (expected) => (e) => e.code === expected;
const WHEN = Date.parse('2026-10-05T12:00:00Z');
const stamped = await sha256(utf8('what was stamped'));

// The order L of the Ed25519 base point (RFC 8032, section 5.1).
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const sOf = (signature) => {
  let s = 0n;
  for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(signature[i]);
  return s;
};
const withS = (signature, s) => {
  const out = Uint8Array.from(signature);
  for (let i = 32; i < 64; i++) {
    out[i] = Number(s & 0xffn);
    s >>= 8n;
  }
  return out;
};

/** Runs "work" with the device's "verify" saying yes to everything, then puts it back. */
async function withYesSayingVerify(work) {
  const subtle = globalThis.crypto.subtle;
  const original = subtle.verify;
  subtle.verify = async () => true;
  try {
    return await work();
  } finally {
    subtle.verify = original;
  }
}

test('a DER bit string whose unused bits are not zero is not strict DER', () => {
  const check = (hex) => validateDer(H(hex), readElement(H(hex), 0));
  // X.690, sections 8.6.2 and 11.2.1: the first byte counts the unused bits
  // of the last, 0 to 7; a string of no bits has none; the unused bits are zero.
  for (const bad of ['030201ff', '030207ff', '030101', '0303030004']) assert.throws(() => check(bad), code('stamp-bad-data'), bad);
  for (const good of ['030200ff', '030201fe', '03020780', '030100', '0303030008']) assert.doesNotThrow(() => check(good), good);
});

test('a P-256 key that is not a point on the curve is refused as bad-key, before any signature is tried', async () => {
  const genuine = (await makePasskey('ES256')).key;
  assert.equal(checkKey(genuine, ['ES256'], 'key'), 'ES256');
  // The base point of P-256 (FIPS 186-5, section D.1.2.3) is on the curve.
  const base = { ...genuine, x: toBase64url(H('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296')), y: toBase64url(H('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')) };
  assert.equal(checkKey(base, ['ES256'], 'key'), 'ES256');
  const changed = (text) => {
    const bytes = fromBase64url(text);
    bytes[31] ^= 1;
    return toBase64url(bytes);
  };
  const prime = toBase64url(H('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff'));
  for (const [name, key] of [
    ['y changed', { ...genuine, y: changed(genuine.y) }],
    ['x changed', { ...genuine, x: changed(genuine.x) }],
    ['filler bytes', { ...genuine, x: toBase64url(new Uint8Array(32).fill(1)), y: toBase64url(new Uint8Array(32).fill(2)) }],
    ['x equal to the prime', { ...genuine, x: prime }],
    ['y equal to the prime', { ...genuine, y: prime }],
  ]) {
    assert.throws(() => checkKey(key, ['ES256'], 'key'), (e) => e.code === 'bad-key' && /point on the curve/.test(e.message), name);
  }
  assert.equal(onP256(fromBase64url(genuine.x), fromBase64url(genuine.y)), true);
  assert.equal(onP256(fromBase64url(genuine.x), fromBase64url(changed(genuine.y))), false);
  // A second written form of one point, a half written as itself plus the
  // prime, is refused and not reduced: the point with x = 5, and the point
  // with y = 5 (its x found by solving the curve's equation), each as itself
  // and with that half written as 5 + p. Both halves of 5 + p fit 32 bytes.
  const five = toBase64url(H('0000000000000000000000000000000000000000000000000000000000000005'));
  const fivePlusP = toBase64url(H('ffffffff00000001000000000000000000000001000000000000000000000004'));
  const yOfX5 = toBase64url(H('459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc'));
  const xOfY5 = toBase64url(H('d7325d7646cd60d80a92738ceb345f844cffaf35841022cab176f692de8de1d7'));
  assert.equal(checkKey({ ...genuine, x: five, y: yOfX5 }, ['ES256'], 'key'), 'ES256');
  assert.equal(checkKey({ ...genuine, x: xOfY5, y: five }, ['ES256'], 'key'), 'ES256');
  for (const [name, key] of [
    ['x written as 5 plus the prime', { ...genuine, x: fivePlusP, y: yOfX5 }],
    ['y written as 5 plus the prime', { ...genuine, x: xOfY5, y: fivePlusP }],
  ]) {
    assert.throws(() => checkKey(key, ['ES256'], 'key'), (e) => e.code === 'bad-key' && /point on the curve/.test(e.message), name);
  }
});

test('an Ed25519 signature whose S is not below L is refused by the library itself, whatever the device would say', async () => {
  const { keys, privateKeys } = await generateKeySet();
  const message = utf8('a message');
  const genuine = await sign('Ed25519', privateKeys[0], message);
  assert.equal(await verifySignature(keys[0], genuine, message), 'valid');
  const raised = withS(genuine, sOf(genuine) + L);
  assert.equal(badEd25519Signature(genuine), false);
  assert.equal(badEd25519Signature(raised), true);
  assert.equal(badEd25519Signature(withS(genuine, L)), true);
  assert.equal(badEd25519Signature(withS(genuine, L - 1n)), false);
  // With "verify" saying yes to everything, only the library's own check can refuse.
  await withYesSayingVerify(async () => {
    assert.equal(await verifySignature(keys[0], genuine, message), 'valid');
    assert.equal(await verifySignature(keys[0], raised, message), 'invalid');
    assert.equal(await verifySignature(keys[0], withS(genuine, L), message), 'invalid');
    assert.equal(await verifySignature(keys[0], withS(genuine, sOf(genuine) | (1n << 255n)), message), 'invalid');
  });
  // On a device without Ed25519 it is not checked, as a signature with a weak R is not.
  assert.equal(await verifySignature(keys[0], raised, message, ['Ed25519']), 'unavailable');
});

test('a time-stamp signed with Ed25519 names SHA-512 as its fingerprint method, as RFC 8419 requires', async () => {
  const service = await makeStampService('Ed25519');
  const trusted = [service.fingerprint];
  const sound = await service.stamp(stamped, WHEN);
  assert.equal((await checkStamp(sound, stamped, { trusted })).state, 'valid');
  const sha256Named = await service.stamp(stamped, WHEN, { digestName: 'SHA-256' });
  await assert.rejects(checkStamp(sha256Named, stamped, { trusted }), code('stamp-invalid'));
  // The pairing of the signing method with the fingerprint method is judged
  // before the device's own methods are asked for, as for ECDSA and RSA: a
  // device without Ed25519 refuses it too, where a sound one is "unavailable".
  await assert.rejects(checkStamp(sha256Named, stamped, { trusted, without: ['Ed25519'] }), code('stamp-invalid'));
  assert.equal((await checkStamp(sound, stamped, { trusted, without: ['Ed25519'] })).state, 'unavailable');
});

test('a time-stamp that names the certificate that signed it twice in the same form is refused', async () => {
  const service = await makeStampService();
  const trusted = [service.fingerprint];
  // The helper's attributes are the kind, the fingerprint and the signing certificate, in that order.
  const twice = await service.stamp(stamped, WHEN, { attributes: (a) => [...a, a[2]] });
  await assert.rejects(checkStamp(twice, stamped, { trusted }), (e) => e.code === 'stamp-invalid' && /more than once/.test(e.message));
  const once = await service.stamp(stamped, WHEN);
  assert.equal((await checkStamp(once, stamped, { trusted })).state, 'valid');
});

test('an Ed25519 time-stamp whose S is not below L is refused by the library itself', async () => {
  const service = await makeStampService('Ed25519');
  const trusted = [service.fingerprint];
  const raised = await service.stamp(stamped, WHEN, { signature: (s) => withS(s, sOf(s) + L) });
  await withYesSayingVerify(async () => {
    assert.equal((await checkStamp(await service.stamp(stamped, WHEN), stamped, { trusted })).state, 'valid');
    await assert.rejects(checkStamp(raised, stamped, { trusted }), code('stamp-invalid'));
  });
});

test('a time-stamp\'s time is read to the millisecond, a finer fraction dropped (format description, section 21.2)', () => {
  // GeneralizedTime with a fraction, as a time-stamp may state its time.
  const read = (text) => {
    const bytes = concatBytes(new Uint8Array([0x18, text.length]), utf8(text));
    return timeOf(bytes, readElement(bytes, 0));
  };
  assert.equal(read('20261005120000Z'), WHEN);
  assert.equal(read('20261005120000.5Z'), WHEN + 500);
  assert.equal(read('20261005120000.123Z'), WHEN + 123);
  assert.equal(read('20261005120000.1239Z'), WHEN + 123);
  assert.equal(read('20261005120000.0009Z'), WHEN);
});

// --- added after the independent review of these fixes (24 October 2026) ---

test('a string written in parts, or a set out of DER order, is not strict DER', () => {
  const check = (hex) => validateDer(H(hex), readElement(H(hex), 0));
  // X.690, section 10.2: a string of bits, bytes or characters, or a time, is written in one piece.
  for (const bad of ['2308030200ff030200ff', '2406040101040102', '2c0a0c036162630c03646566', '3811180f32303236313030353132303030305a']) {
    assert.throws(() => check(bad), (e) => e.code === 'stamp-bad-data' && /written in parts/.test(e.message), bad);
  }
  // X.690, section 11.6: the items of a set in the order of their encodings, compared as bytes; equal items may stand side by side.
  for (const bad of ['3106020102020101', '310702020100020101', '310a30030201023003020101', '30083106020102020101']) {
    assert.throws(() => check(bad), (e) => e.code === 'stamp-bad-data' && /order DER requires/.test(e.message), bad);
  }
  // A sequence is not sorted, and a set under a tag that hides its kind cannot be told from one.
  for (const good of ['3106020101020102', '3106020101020101', '310702010102020100', '310a30030201013003020102', '3006020102020101', 'a006020102020101']) {
    assert.doesNotThrow(() => check(good), good);
  }
  assert.equal(setInOrder(H('020101020102'), [{ from: 0, end: 3 }, { from: 3, end: 6 }]), true);
  assert.equal(setInOrder(H('020102020101'), [{ from: 0, end: 3 }, { from: 3, end: 6 }]), false);
  assert.equal(setInOrder(H('020101020101'), [{ from: 0, end: 3 }, { from: 3, end: 6 }]), true);
  // Compared as bytes, the shorter padded with zeros: a shorter item is not for that reason the lesser.
  assert.equal(setInOrder(H('0201020005'), [{ from: 0, end: 2 }, { from: 2, end: 5 }]), false);
  assert.equal(setInOrder(H('0200050201'), [{ from: 0, end: 3 }, { from: 3, end: 5 }]), true);
});

test('the signed attributes and the certificates of a time-stamp are sets, and must be in DER order', async () => {
  const service = await makeStampService();
  const trusted = [service.fingerprint];
  // The helper's attributes are the kind, the fingerprint and the signing certificate, which is DER order as they stand.
  assert.equal((await checkStamp(await service.stamp(stamped, WHEN, { attributes: (a) => a }), stamped, { trusted })).state, 'valid');
  const reversed = await service.stamp(stamped, WHEN, { attributes: (a) => [a[2], a[1], a[0]] });
  await assert.rejects(checkStamp(reversed, stamped, { trusted }), (e) => e.code === 'stamp-bad-data' && /signed attributes are not in the order/.test(e.message));
  // Two certificates for one key: which comes first in DER order rests on their bytes (their lengths before their serial numbers), so it is computed.
  const [first, second] = sorted([service.certificate, service.secondCertificate]);
  const inOrder = await service.stamp(stamped, WHEN, { certificates: [first, second], keepOrder: true });
  assert.equal((await checkStamp(inOrder, stamped, { trusted })).state, 'valid');
  const outOfOrder = await service.stamp(stamped, WHEN, { certificates: [second, first], keepOrder: true });
  await assert.rejects(checkStamp(outOfOrder, stamped, { trusted }), (e) => e.code === 'stamp-bad-data' && /certificates are not in the order/.test(e.message));
  // Given in the other order without "keepOrder", the helper writes them as a service does.
  assert.equal((await checkStamp(await service.stamp(stamped, WHEN, { certificates: [service.certificate, service.secondCertificate] }), stamped, { trusted })).state, 'valid');
});

test('a time-stamp signed with Ed25519 gives its fingerprint method and its signing method no parameters, as RFC 8419 requires', async () => {
  const service = await makeStampService('Ed25519');
  const trusted = [service.fingerprint];
  const NULL = new Uint8Array([0x05, 0x00]);
  const sha512 = '608648016503040203';
  assert.equal((await checkStamp(await service.stamp(stamped, WHEN), stamped, { trusted })).state, 'valid');
  const digestParameters = await service.stamp(stamped, WHEN, { digestAlgorithm: sequence(oid(sha512), NULL) });
  await assert.rejects(checkStamp(digestParameters, stamped, { trusted }), (e) => e.code === 'stamp-invalid' && /gives the method parameters, which RFC 8419/.test(e.message));
  const signingParameters = await service.stamp(stamped, WHEN, { signatureAlgorithm: sequence(oid('2b6570'), NULL) });
  await assert.rejects(checkStamp(signingParameters, stamped, { trusted }), (e) => e.code === 'stamp-invalid' && /signing method parameters, which RFC 8419/.test(e.message));
  // Naming another method is refused in words that name the cause.
  const sha256Named = await service.stamp(stamped, WHEN, { digestName: 'SHA-256' });
  await assert.rejects(checkStamp(sha256Named, stamped, { trusted }), (e) => e.code === 'stamp-invalid' && /fingerprint method other than SHA-512/.test(e.message));
  // The list of fingerprint methods in the signed data is read for its form only.
  assert.equal((await checkStamp(await service.stamp(stamped, WHEN, { digestAlgorithms: sequence(oid(sha512), NULL) }), stamped, { trusted })).state, 'valid');
  // For the other signing methods the parameters stay NULL, as the OpenSSL program writes them.
  const ecdsa = await makeStampService('ECDSA');
  assert.equal((await checkStamp(await ecdsa.stamp(stamped, WHEN), stamped, { trusted: [ecdsa.fingerprint] })).state, 'valid');
});
