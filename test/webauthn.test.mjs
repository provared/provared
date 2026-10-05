// The passkey check, piece by piece: the strict reading of an ECDSA
// signature, and each step of checking a passkey's answer.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Refusal, utf8 } from '../src/encoding.js';
import { checkAssertion, ecdsaDerToRaw } from '../src/webauthn.js';
import { ecdsaRawToDer, makePasskey } from './helpers/passkey.mjs';

const hex = (text) => new Uint8Array(Buffer.from(text.replace(/\s/g, ''), 'hex'));
const refused = (promiseOrFn, code) =>
  typeof promiseOrFn === 'function'
    ? assert.throws(promiseOrFn, (e) => e instanceof Refusal && e.code === code)
    : assert.rejects(promiseOrFn, (e) => e instanceof Refusal && e.code === code);

test('an ECDSA signature in DER form is read into two numbers of 32 bytes', () => {
  const r = new Uint8Array(32).fill(0x11);
  const s = new Uint8Array(32).fill(0x22);
  const raw = new Uint8Array([...r, ...s]);
  assert.deepEqual(ecdsaDerToRaw(ecdsaRawToDer(raw)), raw);

  // A number whose first bit is set carries a leading zero in DER.
  const high = new Uint8Array(64).fill(0xff);
  const der = ecdsaRawToDer(high);
  assert.equal(der.length, 72);
  assert.deepEqual(ecdsaDerToRaw(der), high);

  // A small number is shorter in DER and is padded back to 32 bytes.
  const small = new Uint8Array(64);
  small[31] = 5;
  small[63] = 7;
  assert.deepEqual([...ecdsaRawToDer(small)], [0x30, 6, 2, 1, 5, 2, 1, 7]);
  assert.deepEqual(ecdsaDerToRaw(hex('3006 0201 05 0201 07')), small);
});

test('an ECDSA signature that is not strictly encoded is refused', () => {
  const bad = [
    '', // nothing
    '3006 0201 05 0201', // cut short
    '3006 0201 05 0201 07 00', // a byte left over
    '3007 0201 05 0201 07 00', // a byte left over, inside the sequence
    '3106 0201 05 0201 07', // not a sequence
    '3006 0301 05 0201 07', // not a whole number
    '3006 0201 05 0301 07',
    '3007 0202 0005 0201 07', // a leading zero that is not needed
    '3006 0201 85 0201 07', // a negative number
    '3006 0200 0201 07 00', // a number of no bytes
    '3081 06 0201 05 0201 07', // a long-form length
    '3005 0201 05 0201 07', // a wrong length
    '3008 0201 05 0203 000007', // a leading zero that is not needed, twice
    '30 26 0222 0001' + '11'.repeat(32) + ' 0201 07', // a number of more than 32 bytes
    '3003 0201 05', // only one number
  ];
  for (const text of bad) refused(() => ecdsaDerToRaw(hex(text)), 'passkey-bad-data');
});

const signedBytes = utf8('the bytes to sign');

async function answer(alg, change) {
  const passkey = await makePasskey(alg);
  const challenge = new Uint8Array(await crypto.subtle.digest('SHA-256', signedBytes));
  const a = await passkey.sign(challenge, change);
  return { key: passkey.key, rpId: passkey.rpId, origin: passkey.origin, signedBytes, ...a };
}

test('a sound passkey answer checks, for each signing method', async () => {
  for (const alg of ['ES256', 'RS256', 'Ed25519']) {
    assert.equal(await checkAssertion(await answer(alg)), 'valid', alg);
  }
});

test('extension data is allowed only when the flags say it is there', async () => {
  const extra = new Uint8Array([0xa0]);
  assert.equal(await checkAssertion(await answer('ES256', { flags: 0x85, extra })), 'valid');
  await refused(checkAssertion(await answer('ES256', { flags: 0x05, extra })), 'passkey-bad-data');
});

test('the flags for a synced passkey do not change the result', async () => {
  // 0x1d: user present, user verified, backup eligible, backed up.
  assert.equal(await checkAssertion(await answer('ES256', { flags: 0x1d })), 'valid');
});

test('each failed step has its own code', async () => {
  await refused(checkAssertion(await answer('ES256', { type: 'webauthn.create' })), 'passkey-wrong-type');
  await refused(checkAssertion(await answer('ES256', { challenge: new Uint8Array(32) })), 'passkey-challenge-mismatch');
  await refused(checkAssertion(await answer('ES256', { origin: 'http://localhost:9999' })), 'passkey-origin-mismatch');
  await refused(checkAssertion(await answer('ES256', { crossOrigin: true })), 'passkey-origin-mismatch');
  await refused(checkAssertion(await answer('ES256', { rpId: 'example.org' })), 'passkey-rpid-mismatch');
  await refused(checkAssertion(await answer('ES256', { flags: 0x04 })), 'passkey-user-not-present');
  await refused(checkAssertion(await answer('ES256', { flags: 0x01 })), 'passkey-user-not-verified');
  await refused(checkAssertion(await answer('ES256', { flags: 0x45 })), 'passkey-bad-data');
  await refused(checkAssertion(await answer('ES256', { clientDataText: 'not json' })), 'passkey-bad-data');
  await refused(checkAssertion(await answer('ES256', { clientDataText: '[]' })), 'passkey-bad-data');
  await refused(checkAssertion(await answer('ES256', { clientDataText: 'null' })), 'passkey-bad-data');
});

test('authenticator data that is cut short is refused', async () => {
  const a = await answer('ES256');
  await refused(checkAssertion({ ...a, authenticatorData: a.authenticatorData.subarray(0, 36) }), 'passkey-bad-data');
  await refused(checkAssertion({ ...a, authenticatorData: new Uint8Array(0) }), 'passkey-bad-data');
});

test('a signature over other authenticator data, or by another passkey, is invalid', async () => {
  // The flags are changed after signing: from "not verified" to "verified".
  const a = await answer('ES256', { flags: 0x01 });
  const forged = a.authenticatorData.slice();
  forged[32] = 0x05;
  await refused(checkAssertion({ ...a, authenticatorData: forged }), 'signature-invalid');

  const other = await makePasskey('ES256');
  await refused(checkAssertion({ ...(await answer('ES256')), key: other.key }), 'signature-invalid');
  for (const alg of ['RS256', 'Ed25519']) {
    const b = await answer(alg);
    const changed = b.signature.slice();
    changed[5] ^= 1;
    await refused(checkAssertion({ ...b, signature: changed }), 'signature-invalid');
  }
});

test('where the device lacks the passkey\'s method, the answer is "unavailable", after every other step has passed', async () => {
  const a = await answer('Ed25519');
  assert.equal(await checkAssertion(a, ['Ed25519']), 'unavailable');
  await refused(checkAssertion({ ...a, origin: 'https://elsewhere.example' }, ['Ed25519']), 'passkey-origin-mismatch');
});
