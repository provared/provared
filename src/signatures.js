// Checking and making signatures with the cryptography built into the
// browser or Node.js (Web Crypto). No outside code.
//
// Methods:
//   Ed25519    RFC 8032
//   ML-DSA-87  FIPS 204, plain method, empty context (RFC 9964 section 5)
//   ES256      ECDSA with P-256 and SHA-256 (FIPS 186-5), passkeys only
//   RS256      RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017), passkeys only
//   SLH-DSA-SHA2-256s  FIPS 205, plain method, empty context; seals only
//
// SLH-DSA is not yet in Web Crypto anywhere. Node.js has it in its own
// cryptography module, which is asked for here without an import, so that
// this file still loads in a browser. In a browser the method is reported as
// not built in, which is never a pass.

import { importPublicKey } from './keys.js';

const SLH = 'SLH-DSA-SHA2-256s';
const nodeCrypto = globalThis.process && typeof globalThis.process.getBuiltinModule === 'function' ? globalThis.process.getBuiltinModule('node:crypto') : null;

function slhKey(pub) {
  return nodeCrypto.createPublicKey({ key: { kty: 'AKP', alg: SLH, pub }, format: 'jwk' });
}

/** @typedef {'valid'|'invalid'|'unavailable'} SignatureState */

const VERIFY_PARAMS = {
  Ed25519: { name: 'Ed25519' },
  'ML-DSA-87': { name: 'ML-DSA-87' },
  ES256: { name: 'ECDSA', hash: 'SHA-256' },
  RS256: { name: 'RSASSA-PKCS1-v1_5' },
};

// Whether this device has a method built in. Ed25519 and ML-DSA are newer
// additions to Web Crypto, so they are probed once by making a key. ES256 and
// RS256 have been in Web Crypto from the start.
const available = new Map();

/**
 * @param {string} alg
 * @returns {Promise<boolean>} whether this device can check signatures made with this method
 */
export function methodAvailable(alg) {
  if (alg === 'ES256' || alg === 'RS256') return Promise.resolve(true);
  if (alg === SLH && !available.has(alg)) {
    let has = false;
    try {
      // An all-zero key is a key of the right shape: loading it shows whether the method is there.
      slhKey('A'.repeat(86));
      has = true;
    } catch {
      has = false;
    }
    available.set(alg, Promise.resolve(has));
  }
  if (!available.has(alg)) {
    const subtle = globalThis.crypto && globalThis.crypto.subtle;
    const probe = subtle
      ? Promise.resolve()
          .then(() => subtle.generateKey({ name: alg }, false, ['sign', 'verify']))
          .then(() => true, () => false)
      : Promise.resolve(false);
    available.set(alg, probe);
  }
  return available.get(alg);
}

/**
 * Check one signature.
 *
 * "unavailable" means this device has no built-in support for the method. It
 * is never treated as a pass. On a device that has the method, any failure,
 * including a key the device refuses to load, is "invalid".
 *
 * @param {any} jwk a public key that has passed checkKey
 * @param {Uint8Array} signature
 * @param {Uint8Array} data the bytes that were signed
 * @param {string[]} [without] methods to treat as not built in, to see how a
 *   check behaves on a device without them; it can only withhold a pass
 * @returns {Promise<SignatureState>}
 */
export async function verifySignature(jwk, signature, data, without = []) {
  if (jwk.alg === SLH) {
    if (without.includes(SLH) || !(await methodAvailable(SLH))) return 'unavailable';
    try {
      return nodeCrypto.verify(null, data, slhKey(jwk.pub), signature) ? 'valid' : 'invalid';
    } catch {
      return 'invalid';
    }
  }
  if (!Object.hasOwn(VERIFY_PARAMS, jwk.alg)) return 'invalid';
  const params = VERIFY_PARAMS[jwk.alg];
  if (without.includes(jwk.alg) || !(await methodAvailable(jwk.alg))) return 'unavailable';
  try {
    const key = await importPublicKey(jwk);
    return (await globalThis.crypto.subtle.verify(params, key, signature, data)) ? 'valid' : 'invalid';
  } catch {
    return 'invalid';
  }
}

/**
 * Sign with one private key of a key set.
 * @param {string} alg 'Ed25519', 'ML-DSA-87' or, for a seal, 'SLH-DSA-SHA2-256s'
 * @param {any} privateKey
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
export async function sign(alg, privateKey, data) {
  if (alg === SLH) return new Uint8Array(nodeCrypto.sign(null, data, privateKey));
  return new Uint8Array(await globalThis.crypto.subtle.sign({ name: alg }, privateKey, data));
}

/**
 * Make a new key set for a recorder, which signs seals: an Ed25519 key, an
 * ML-DSA-87 key and an SLH-DSA-SHA2-256s key. It needs Node.js: no browser
 * has the third method.
 * @returns {Promise<{keys: object[], privateKeys: any[]}>}
 */
export async function generateSealKeySet() {
  if (!(await methodAvailable(SLH))) throw new Error('SLH-DSA is not built into this device.');
  const two = await generateKeySet();
  const slh = nodeCrypto.generateKeyPairSync('slh-dsa-sha2-256s');
  const { pub } = slh.publicKey.export({ format: 'jwk' });
  return { keys: [...two.keys, { alg: SLH, kty: 'AKP', pub }], privateKeys: [...two.privateKeys, slh.privateKey] };
}

/**
 * Make a new key set for an agent or a service: an Ed25519 key and an
 * ML-DSA-87 key. The private halves cannot be exported from the returned
 * objects; they stay in the memory of this process.
 * @returns {Promise<{keys: object[], privateKeys: CryptoKey[]}>} the public key set, and the private keys in the same order
 */
export async function generateKeySet() {
  const subtle = globalThis.crypto.subtle;
  const ed = await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  const ml = await subtle.generateKey({ name: 'ML-DSA-87' }, false, ['sign', 'verify']);
  const edJwk = await subtle.exportKey('jwk', ed.publicKey);
  const mlJwk = await subtle.exportKey('jwk', ml.publicKey);
  return {
    keys: [
      { alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: edJwk.x },
      { alg: 'ML-DSA-87', kty: 'AKP', pub: mlJwk.pub },
    ],
    privateKeys: [ed.privateKey, ml.privateKey],
  };
}
