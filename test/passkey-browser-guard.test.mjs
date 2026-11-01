// The browser part (src/passkey-browser.js), with a stand-in for the
// browser's passkey interface: a passkey with no identifier is refused
// before the device is asked, except where the caller asks the device to
// offer a choice (signChallengeWithChosenPasskey); there, and only there,
// the device is asked with no list of passkeys, and the identifier of the
// one chosen comes back.
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { PasskeyError, signChallengeWithChosenPasskey, signChallengeWithPasskey } from '../src/passkey-browser.js';
import { toBase64url } from '../src/encoding.js';

const asked = [];
const saved = {};
const NAMES = ['isSecureContext', 'navigator', 'PublicKeyCredential'];

before(() => {
  for (const name of NAMES) saved[name] = Object.getOwnPropertyDescriptor(globalThis, name);
  const answer = { rawId: new Uint8Array([7, 7, 7]).buffer, response: { authenticatorData: new Uint8Array([1]).buffer, clientDataJSON: new Uint8Array([2]).buffer, signature: new Uint8Array([3]).buffer } };
  Object.defineProperty(globalThis, 'isSecureContext', { value: true, configurable: true, writable: true });
  Object.defineProperty(globalThis, 'PublicKeyCredential', { value: function PublicKeyCredential() {}, configurable: true, writable: true });
  Object.defineProperty(globalThis, 'navigator', { value: { credentials: { get: async (options) => { asked.push(options); return answer; } } }, configurable: true, writable: true });
});
after(() => {
  for (const name of NAMES) {
    if (saved[name]) Object.defineProperty(globalThis, name, saved[name]);
    else delete globalThis[name];
  }
});

const challenge = new Uint8Array(32).fill(9);
const key = { alg: 'ES256', crv: 'P-256', kty: 'EC', x: 'x', y: 'y' };

test('a passkey with no identifier is refused before the device is asked', async () => {
  asked.length = 0;
  for (const passkey of [{ key, rpId: 'sign.prova.red' }, { key, rpId: 'sign.prova.red', credentialId: '' }, { key, rpId: 'sign.prova.red', credentialId: 7 }, null]) {
    await assert.rejects(signChallengeWithPasskey(challenge, passkey), (e) => e instanceof PasskeyError && e.code === 'cancelled' && /No passkey was named/.test(e.message), JSON.stringify(passkey));
  }
  assert.equal(asked.length, 0, 'the device was never asked');
});

test('a named passkey is asked for by its identifier alone', async () => {
  asked.length = 0;
  const got = await signChallengeWithPasskey(challenge, { key, rpId: 'sign.prova.red', credentialId: toBase64url(new Uint8Array([5, 6])) });
  assert.equal(asked.length, 1);
  assert.equal(asked[0].publicKey.rpId, 'sign.prova.red');
  assert.equal(asked[0].publicKey.userVerification, 'required');
  assert.deepEqual([...new Uint8Array(asked[0].publicKey.allowCredentials[0].id)], [5, 6]);
  assert.equal(asked[0].publicKey.allowCredentials.length, 1);
  assert.equal(got.credentialId, toBase64url(new Uint8Array([7, 7, 7])));
});

test('only the chosen way asks the device to offer every passkey it holds for the website', async () => {
  asked.length = 0;
  const got = await signChallengeWithChosenPasskey(challenge, 'sign.prova.red');
  assert.equal(asked.length, 1);
  assert.equal(asked[0].publicKey.rpId, 'sign.prova.red');
  assert.equal(Object.hasOwn(asked[0].publicKey, 'allowCredentials'), false);
  assert.equal(got.credentialId, toBase64url(new Uint8Array([7, 7, 7])));
});
