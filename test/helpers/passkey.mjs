// A software stand-in for a passkey, for tests and for the sample record.
// It builds the same three values a real passkey returns (authenticator
// data, client data, signature), in the forms the Web Authentication
// standard sets out. It is not a passkey: its private key is an ordinary key
// in this process's memory.

import { concatBytes, sha256, toBase64url, utf8 } from '../../src/encoding.js';

const subtle = globalThis.crypto.subtle;

/** Two numbers of 32 bytes each, side by side, to the ASN.1 DER form a passkey returns. */
export function ecdsaRawToDer(raw) {
  const part = (bytes) => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    let digits = bytes.subarray(start);
    if (digits[0] & 0x80) digits = concatBytes(new Uint8Array([0]), digits);
    return concatBytes(new Uint8Array([0x02, digits.length]), digits);
  };
  const body = concatBytes(part(raw.subarray(0, 32)), part(raw.subarray(32)));
  return concatBytes(new Uint8Array([0x30, body.length]), body);
}

const KINDS = {
  ES256: {
    generate: { name: 'ECDSA', namedCurve: 'P-256' },
    sign: { name: 'ECDSA', hash: 'SHA-256' },
    jwk: (j) => ({ alg: 'ES256', crv: 'P-256', kty: 'EC', x: j.x, y: j.y }),
  },
  RS256: {
    generate: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    sign: { name: 'RSASSA-PKCS1-v1_5' },
    jwk: (j) => ({ alg: 'RS256', e: j.e, kty: 'RSA', n: j.n }),
  },
  Ed25519: {
    generate: { name: 'Ed25519' },
    sign: { name: 'Ed25519' },
    jwk: (j) => ({ alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: j.x }),
  },
};

/**
 * @param {'ES256'|'RS256'|'Ed25519'} [alg]
 * @param {{rpId?: string, origin?: string}} [site]
 */
export async function makePasskey(alg = 'ES256', { rpId = 'localhost', origin = 'http://localhost:8787' } = {}) {
  const kind = KINDS[alg];
  const pair = await subtle.generateKey(kind.generate, false, ['sign', 'verify']);
  const key = kind.jwk(await subtle.exportKey('jwk', pair.publicKey));
  return {
    key,
    rpId,
    origin,
    /**
     * Answer a request to sign. "change" overrides a part, to build the
     * records a checker must refuse.
     */
    async sign(challenge, change = {}) {
      const clientDataJSON = utf8(
        change.clientDataText ??
          JSON.stringify({
            type: change.type ?? 'webauthn.get',
            challenge: toBase64url(change.challenge ?? challenge),
            origin: change.origin ?? origin,
            crossOrigin: change.crossOrigin ?? false,
          }),
      );
      // Flags 0x05: user present and user verified.
      const authenticatorData = concatBytes(
        await sha256(utf8(change.rpId ?? rpId)),
        new Uint8Array([change.flags ?? 0x05, 0, 0, 0, 1]),
        change.extra ?? new Uint8Array(0),
      );
      const signed = concatBytes(change.signedAuthenticatorData ?? authenticatorData, await sha256(clientDataJSON));
      let signature = new Uint8Array(await subtle.sign(kind.sign, pair.privateKey, signed));
      if (alg === 'ES256') signature = ecdsaRawToDer(signature);
      if (change.signature) signature = change.signature(signature);
      return { authenticatorData, clientDataJSON, signature };
    },
  };
}
