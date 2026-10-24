// The fixes that the audit of the Internet-Draft (24 October 2026) listed for
// version 0.6.0. Each refusal here fails without its fix. Where the library
// beneath (OpenSSL) would refuse the same bytes on its own, the test stands a
// yes-saying "verify" in its place, so that it shows the library deciding for
// itself, as the format description asks (section 3.8).

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readElement, timeOf, validateDer } from '../src/der.js';
import { concatBytes, fromBase64url, sha256, toBase64url, utf8 } from '../src/encoding.js';
import { badEd25519Signature, checkKey, onP256 } from '../src/keys.js';
import { generateKeySet, sign, verifySignature } from '../src/signatures.js';
import { checkStamp } from '../src/timestamp.js';
import { makePasskey } from './helpers/passkey.mjs';
import { makeStampService } from './helpers/stamp.mjs';

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
