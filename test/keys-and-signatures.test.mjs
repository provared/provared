// Keys, thumbprints and signatures, against the worked examples in the
// standards.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { Refusal, fromBase64url, toBase64url, utf8 } from '../src/encoding.js';
import { checkKey, checkKeySet, thumbprint } from '../src/keys.js';
import { generateKeySet, methodAvailable, sign, verifySignature } from '../src/signatures.js';

const hex = (text) => new Uint8Array(Buffer.from(text, 'hex'));
const badKey = (fn) => assert.throws(fn, (e) => e instanceof Refusal && e.code === 'bad-key');

// RFC 8032, section 7.1, TEST 1: an empty message.
const RFC8032_PUBLIC = hex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
const RFC8032_SIGNATURE = hex(
  'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' + '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
);
const ed25519Key = { alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: toBase64url(RFC8032_PUBLIC) };

// RFC 9964, appendix A.1, figure 5: an ML-DSA-87 key and a signed message.
const rfc9964 = JSON.parse(readFileSync(new URL('./fixtures/rfc9964-ml-dsa-87.json', import.meta.url), 'utf8'));
const mlDsaKey = { alg: 'ML-DSA-87', kty: 'AKP', pub: rfc9964.jwk.pub };

test('this device has both methods of a key set built in', async () => {
  assert.equal(await methodAvailable('Ed25519'), true);
  assert.equal(await methodAvailable('ML-DSA-87'), true);
  assert.equal(await methodAvailable('No-Such-Method'), false);
});

test('Ed25519: the first test vector of RFC 8032 checks', async () => {
  assert.equal(await verifySignature(ed25519Key, RFC8032_SIGNATURE, new Uint8Array(0)), 'valid');
  assert.equal(await verifySignature(ed25519Key, RFC8032_SIGNATURE, utf8('x')), 'invalid');
  const changed = RFC8032_SIGNATURE.slice();
  changed[10] ^= 1;
  assert.equal(await verifySignature(ed25519Key, changed, new Uint8Array(0)), 'invalid');
});

test('Ed25519: the signed example of RFC 8037, appendix A.4, checks', async () => {
  // The key of appendix A.1 is the key of RFC 8032 test 1.
  assert.equal(ed25519Key.x, '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo');
  const input = utf8('eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc');
  const signature = fromBase64url('hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg');
  assert.equal(await verifySignature(ed25519Key, signature, input), 'valid');
});

test('thumbprint: the Ed25519 example of RFC 8037, appendix A.3', async () => {
  assert.equal(await thumbprint(ed25519Key), 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
});

test('ML-DSA-87: the signed example of RFC 9964, appendix A.1, checks', async () => {
  const [header, payload, signature] = rfc9964.jws.split('.');
  const input = utf8(header + '.' + payload);
  assert.equal(await verifySignature(mlDsaKey, fromBase64url(signature), input), 'valid');
  assert.equal(await verifySignature(mlDsaKey, fromBase64url(signature), utf8(header + '.' + payload + 'x')), 'invalid');
});

test('thumbprint: the ML-DSA-87 example of RFC 9964 (members alg, kty, pub)', async () => {
  assert.equal(await thumbprint(mlDsaKey), rfc9964.jwk.kid);
});

test('thumbprint: an EC key and an RSA key use the members RFC 7638 section 3.2 names', async () => {
  const sha = async (text) => toBase64url(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(text))));
  const ec = { alg: 'ES256', crv: 'P-256', kty: 'EC', x: 'A'.repeat(43), y: 'B'.repeat(43) };
  assert.equal(await thumbprint(ec), await sha(`{"crv":"P-256","kty":"EC","x":"${ec.x}","y":"${ec.y}"}`));
  const rsa = { alg: 'RS256', e: 'AQAB', kty: 'RSA', n: 'x'.repeat(342) };
  assert.equal(await thumbprint(rsa), await sha(`{"e":"AQAB","kty":"RSA","n":"${rsa.n}"}`));
});

test('a method this device is told it lacks is "unavailable", never "valid"', async () => {
  assert.equal(await verifySignature(ed25519Key, RFC8032_SIGNATURE, new Uint8Array(0), ['Ed25519']), 'unavailable');
});

test('a key the device refuses to load is "invalid", not "unavailable"', async () => {
  // x and y are 32 bytes each, but not a point on the curve.
  const off = { alg: 'ES256', crv: 'P-256', kty: 'EC', x: toBase64url(new Uint8Array(32).fill(1)), y: toBase64url(new Uint8Array(32).fill(2)) };
  assert.equal(await verifySignature(off, new Uint8Array(64), utf8('x')), 'invalid');
});

test('a new key set signs, and each signature checks only with its own key', async () => {
  const a = await generateKeySet();
  const b = await generateKeySet();
  checkKeySet(a.keys, 'a');
  const data = utf8('some bytes');
  for (let i = 0; i < 2; i++) {
    const alg = a.keys[i].alg;
    const signature = await sign(alg, a.privateKeys[i], data);
    assert.equal(await verifySignature(a.keys[i], signature, data), 'valid');
    assert.equal(await verifySignature(b.keys[i], signature, data), 'invalid');
  }
  assert.equal((await sign('Ed25519', a.privateKeys[0], data)).length, 64);
  // FIPS 204, table 2.
  assert.equal((await sign('ML-DSA-87', a.privateKeys[1], data)).length, 4627);
});

test('the private keys of a new key set cannot be exported', async () => {
  const a = await generateKeySet();
  for (const key of a.privateKeys) {
    assert.equal(key.extractable, false);
    await assert.rejects(crypto.subtle.exportKey('jwk', key));
  }
});

test('a key must be exactly one of the accepted shapes', () => {
  assert.equal(checkKey(ed25519Key, ['Ed25519'], 'k'), 'Ed25519');
  assert.equal(checkKey(mlDsaKey, ['ML-DSA-87'], 'k'), 'ML-DSA-87');
  badKey(() => checkKey(ed25519Key, ['ML-DSA-87'], 'k')); // not allowed in this place
  badKey(() => checkKey({ ...ed25519Key, kid: 'x' }, ['Ed25519'], 'k')); // an extra member
  badKey(() => checkKey({ ...ed25519Key, d: 'secret' }, ['Ed25519'], 'k')); // a private key
  badKey(() => checkKey({ crv: 'Ed25519', kty: 'OKP', x: ed25519Key.x }, ['Ed25519'], 'k')); // no alg
  badKey(() => checkKey({ ...ed25519Key, crv: 'Ed448' }, ['Ed25519'], 'k'));
  badKey(() => checkKey({ ...ed25519Key, x: ed25519Key.x.slice(2) }, ['Ed25519'], 'k'));
  badKey(() => checkKey({ ...ed25519Key, x: 42 }, ['Ed25519'], 'k'));
  badKey(() => checkKey({ ...mlDsaKey, pub: mlDsaKey.pub.slice(4) }, ['ML-DSA-87'], 'k'));
  badKey(() => checkKey({ ...mlDsaKey, alg: 'ML-DSA-44' }, ['ML-DSA-87', 'ML-DSA-44'], 'k'));
  badKey(() => checkKey({ alg: 'RS256', e: 'AQAB', kty: 'RSA', n: toBase64url(new Uint8Array(128).fill(255)) }, ['RS256'], 'k')); // 1,024 bits
  badKey(() => checkKey({ alg: 'RS256', e: 'Aw', kty: 'RSA', n: toBase64url(new Uint8Array(256).fill(255)) }, ['RS256'], 'k')); // e = 3
  // The size is counted in bits: 256 bytes that begin 0x01 are 2,041 bits.
  const bits2041 = new Uint8Array(256).fill(255);
  bits2041[0] = 0x01;
  badKey(() => checkKey({ alg: 'RS256', e: 'AQAB', kty: 'RSA', n: toBase64url(bits2041) }, ['RS256'], 'k'));
  assert.equal(checkKey({ alg: 'RS256', e: 'AQAB', kty: 'RSA', n: toBase64url(new Uint8Array(256).fill(255)) }, ['RS256'], 'k'), 'RS256'); // 2,048 bits
  assert.equal(checkKey({ alg: 'RS256', e: 'AQAB', kty: 'RSA', n: toBase64url(new Uint8Array(1024).fill(255)) }, ['RS256'], 'k'), 'RS256'); // 8,192 bits
  badKey(() => checkKey({ alg: 'RS256', e: 'AQAB', kty: 'RSA', n: toBase64url(new Uint8Array(1025).fill(255)) }, ['RS256'], 'k'));
  badKey(() => checkKey({ alg: 'toString', kty: 'OKP' }, ['toString'], 'k'));
  for (const notAKey of [null, undefined, 'key', 42, [], [ed25519Key]]) badKey(() => checkKey(notAKey, ['Ed25519'], 'k'));
});

test('a key set is exactly Ed25519, then ML-DSA-87', () => {
  checkKeySet([ed25519Key, mlDsaKey], 'set');
  badKey(() => checkKeySet([mlDsaKey, ed25519Key], 'set'));
  badKey(() => checkKeySet([ed25519Key], 'set'));
  badKey(() => checkKeySet([ed25519Key, ed25519Key], 'set'));
  badKey(() => checkKeySet([ed25519Key, mlDsaKey, mlDsaKey], 'set'));
  badKey(() => checkKeySet({ 0: ed25519Key, 1: mlDsaKey, length: 2 }, 'set'));
});
