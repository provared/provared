// A made-up time-stamp service, for tests, the sample record and the
// demonstration. It writes time-stamps in the layout of RFC 3161, signed
// with a key of its own, and a certificate for that key which it signs
// itself. It is not a time-stamp service: it states whatever time it is
// told, and nobody outside this process vouches for it.

import { concatBytes, sha256, toBase64url, utf8 } from '../../src/encoding.js';
import { ecdsaRawToDer } from './passkey.mjs';

const subtle = globalThis.crypto.subtle;

// --- writing DER ---

export function der(tag, ...parts) {
  const content = concatBytes(...parts);
  let length;
  if (content.length < 128) length = [content.length];
  else if (content.length < 256) length = [0x81, content.length];
  else length = [0x82, content.length >> 8, content.length & 0xff];
  return concatBytes(new Uint8Array([tag, ...length]), content);
}
const hex = (text) => new Uint8Array(text.match(/../g).map((h) => parseInt(h, 16)));
export const oid = (h) => der(0x06, hex(h));
export const integer = (n) => {
  const digits = [];
  do {
    digits.unshift(n & 0xff);
    n = Math.floor(n / 256);
  } while (n > 0);
  if (digits[0] & 0x80) digits.unshift(0);
  return der(0x02, new Uint8Array(digits));
};
export const sequence = (...parts) => der(0x30, ...parts);
const set = (...parts) => der(0x31, ...parts);
export const octets = (bytes) => der(0x04, bytes);
const generalizedTime = (ms) => der(0x18, utf8(new Date(ms).toISOString().slice(0, 19).replace(/[-:T]/g, '') + 'Z'));
const NULL = new Uint8Array([0x05, 0x00]);
const TRUE = new Uint8Array([0x01, 0x01, 0xff]);

// A set is written with its items in the order of their bytes.
function sorted(items) {
  return [...items].sort((a, b) => {
    for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
    return a.length - b.length;
  });
}

const OID = {
  signedData: '2a864886f70d010702',
  tstInfo: '2a864886f70d0109100104',
  contentType: '2a864886f70d010903',
  messageDigest: '2a864886f70d010904',
  signingCertificateV2: '2a864886f70d010910022f',
  sha256: '608648016503040201',
  ecdsaWithSha256: '2a8648ce3d040302',
  sha256WithRsa: '2a864886f70d01010b',
  ed25519: '2b6570',
  commonName: '550403',
  policy: '2a0304',
  someExtension: '2a0305',
};

const METHODS = {
  ECDSA: {
    generate: { name: 'ECDSA', namedCurve: 'P-256' },
    sign: { name: 'ECDSA', hash: 'SHA-256' },
    algorithm: sequence(oid(OID.ecdsaWithSha256)),
    finish: ecdsaRawToDer,
  },
  RSA: {
    generate: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    sign: { name: 'RSASSA-PKCS1-v1_5' },
    algorithm: sequence(oid(OID.sha256WithRsa), NULL),
    finish: (s) => s,
  },
  Ed25519: {
    generate: { name: 'Ed25519' },
    sign: { name: 'Ed25519' },
    algorithm: sequence(oid(OID.ed25519)),
    finish: (s) => s,
  },
};

/**
 * Make a time-stamp service.
 * @param {'ECDSA'|'RSA'|'Ed25519'} [method]
 * @param {object} [o]
 * @param {number} [o.notBefore] when its certificate begins, in milliseconds
 * @param {number} [o.notAfter] when its certificate ends
 * @returns {Promise<{fingerprint: string, certificate: Uint8Array, secondCertificate: Uint8Array, stamp: Function}>}
 *   "fingerprint" is what a checker is told in order to trust this service.
 *   "secondCertificate" is another certificate for the same key.
 */
export async function makeStampService(method = 'ECDSA', o = {}) {
  const m = METHODS[method];
  const pair = await subtle.generateKey(m.generate, false, ['sign', 'verify']);
  const spki = new Uint8Array(await subtle.exportKey('spki', pair.publicKey));
  const signWith = async (bytes) => m.finish(new Uint8Array(await subtle.sign(m.sign, pair.privateKey, bytes)));

  const name = sequence(set(sequence(oid(OID.commonName), der(0x0c, utf8('Made-up time-stamp service (for tests)')))));
  const serial = integer(1);
  const certificateWith = async (number) => {
    const body = sequence(
      der(0xa0, integer(2)),
      integer(number),
      m.algorithm,
      name,
      sequence(generalizedTime(o.notBefore ?? Date.parse('2026-01-01T00:00:00Z')), generalizedTime(o.notAfter ?? Date.parse('2036-01-01T00:00:00Z'))),
      name,
      spki,
    );
    return sequence(body, m.algorithm, der(0x03, new Uint8Array([0]), await signWith(body)));
  };
  const certificate = await certificateWith(1);

  return {
    certificate,
    secondCertificate: await certificateWith(2),
    fingerprint: toBase64url(await sha256(certificate)),
    /**
     * State that a fingerprint existed at a time.
     * @param {Uint8Array} fingerprintBytes the 32 bytes to stamp
     * @param {number} when the time to state, in milliseconds
     * @param {object} [change] overrides, to build the time-stamps a checker must refuse
     * @returns {Promise<Uint8Array>} the time-stamp
     */
    async stamp(fingerprintBytes, when, change = {}) {
      const statement =
        change.statement ??
        sequence(
          integer(change.version ?? 1),
          oid(OID.policy),
          sequence(sequence(oid(change.hash ?? OID.sha256), NULL), octets(fingerprintBytes)),
          integer(change.serial ?? 1000),
          generalizedTime(when),
          // How exact the time is, in seconds.
          ...(change.accuracy === undefined ? [] : [sequence(integer(change.accuracy))]),
          // An extension, which may say that it must be understood.
          ...(change.extension === undefined
            ? []
            : [der(0xa1, sequence(oid(OID.someExtension), ...(change.extension === 'critical' ? [TRUE] : []), octets(NULL)))]),
          ...(change.statementExtra ? [change.statementExtra] : []),
        );
      const attributes = [
        sequence(oid(OID.contentType), set(oid(change.kind ?? OID.tstInfo))),
        sequence(oid(OID.messageDigest), set(octets(change.digest ?? (await sha256(statement))))),
      ];
      // Which certificate signed: its SHA-256 fingerprint, as RFC 3161 asks.
      if (!change.noSigningCertificate) {
        const named = change.signingCertificate ?? (await sha256(certificate));
        attributes.push(sequence(oid(OID.signingCertificateV2), set(sequence(sequence(sequence(octets(named)))))));
      }
      const signedAttributes = set(...(change.attributes ? change.attributes(attributes) : sorted(attributes)));
      let signature = await signWith(signedAttributes);
      if (change.signature) signature = change.signature(signature);
      const signer = sequence(
        change.signerVersion ?? integer(1),
        change.signerName ?? sequence(name, serial),
        sequence(oid(OID.sha256), NULL),
        // The same bytes, with the tag that marks them as the signer's attributes.
        concatBytes(new Uint8Array([0xa0]), signedAttributes.subarray(1)),
        change.signatureAlgorithm ?? m.algorithm,
        octets(signature),
        ...(change.signerExtra ? [change.signerExtra] : []),
      );
      const certificates = change.certificates ?? [change.certificate ?? certificate];
      const signedData = sequence(
        change.signedDataVersion ?? integer(3),
        set(change.digestAlgorithms ?? sequence(oid(OID.sha256), NULL)),
        sequence(oid(OID.tstInfo), der(0xa0, octets(change.enclosed ?? statement))),
        ...(change.noCertificate ? [] : [der(0xa0, ...certificates)]),
        set(signer),
        ...(change.afterSigners ? [change.afterSigners] : []),
      );
      const token = sequence(oid(OID.signedData), der(0xa0, signedData));
      return change.bytes ? change.bytes(token) : token;
    },
  };
}
