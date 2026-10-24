// The shared test files: how each case is answered, and how the cases are
// made. tools/make-vectors.mjs writes them to test-vectors/;
// test/vectors.test.mjs checks that this library still gives every answer.

import { checkSlip, assembleSlip, generateKeySet } from '../../src/index.js';
import { coverMembers } from '../../src/cover.js';
import { DOCUMENT_NAMES, httpRequestBase, httpRequestFingerprint, httpResponseBase, httpResponseFingerprint, identifierFingerprint } from '../../src/documents.js';
import { concatBytes, countCharacters, fromBase64url, parseCanonical, parseTime, sha256, toBase64url, utf8 } from '../../src/encoding.js';
import { encodeContent, parseRecord, protectedHeaders, signingInput } from '../../src/jws.js';
import { PASSKEY_METHODS, checkKey, thumbprint } from '../../src/keys.js';
import { sign, verifySignature } from '../../src/signatures.js';
import { checkOriginForTests } from '../../src/slip.js';
import { validateCountersignatureContent, validateStubContent } from '../../src/stub.js';
import { ecdsaDerToRaw } from '../../src/webauthn.js';
import { makePasskey } from './passkey.mjs';
import { answer, finish } from './vector-tools.mjs';
import * as book from './vectors-book.mjs';
import * as recorder from './vectors-recorder.mjs';
import * as records from './vectors-records.mjs';
import * as stamps from './vectors-stamps.mjs';
import * as witness from './vectors-witness.mjs';
import * as sealer from './vectors-sealer.mjs';

const hex = (bytes) => Buffer.from(bytes).toString('hex');

/** How each kind of case is answered. The same names are used in every implementation. */
export const ANSWER = {
  ...stamps.ANSWER,
  ...records.ANSWER,
  ...book.ANSWER,
  ...recorder.ANSWER,
  ...witness.ANSWER,
  ...sealer.ANSWER,
  parseCanonical: (c) => answer(() => parseCanonical(c.text)),
  fromBase64url: (c) => answer(() => hex(fromBase64url(c.text))),
  parseTime: async (c) => ({ ok: Number.isNaN(parseTime(c.text)) ? null : parseTime(c.text) }),
  countCharacters: async (c) => ({ ok: countCharacters(c.text) }),
  checkKey: (c) =>
    answer(async () => {
      const alg = checkKey(c.key, c.allowed, 'key');
      return { alg, thumbprint: await thumbprint(c.key) };
    }),
  ecdsaDerToRaw: (c) => answer(() => hex(ecdsaDerToRaw(Uint8Array.from(Buffer.from(c.der, 'hex'))))),
  // The key (32 bytes), the signature and the message are hexadecimal. The key
  // is checked first, as a checker checks it before any signature under it.
  checkEd25519Signature: (c) =>
    answer(async () => {
      const H = (text) => Uint8Array.from(Buffer.from(text, 'hex'));
      const key = { alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: toBase64url(H(c.key)) };
      checkKey(key, ['Ed25519'], 'key');
      return verifySignature(key, H(c.signature), H(c.message), c.without);
    }),
  parseRecord: (c) =>
    answer(async () => {
      const p = await parseRecord(c.record, c.kind);
      return { kind: p.kind, fingerprint: p.fingerprint, content: p.content, signatures: p.signatures.length };
    }),
  validateStubContent: (c) =>
    answer(() => {
      validateStubContent(c.content);
      return true;
    }),
  documentFingerprint: (c) =>
    answer(async () => {
      if (c.kind === 'names') return DOCUMENT_NAMES;
      if (c.kind === 'identifier') return { fingerprint: await identifierFingerprint(c.input) };
      let r = c.input;
      if (r !== null && typeof r === 'object' && !Array.isArray(r)) {
        r = { ...r };
        if (Object.hasOwn(r, 'bodyHex')) r.body = Uint8Array.from(Buffer.from(r.bodyHex, 'hex'));
        if (Object.hasOwn(r, 'bodyText')) r.body = r.bodyText;
        delete r.bodyHex;
        delete r.bodyText;
      }
      if (c.kind === 'request') return { base: await httpRequestBase(r), fingerprint: await httpRequestFingerprint(r) };
      return { base: await httpResponseBase(r), fingerprint: await httpResponseFingerprint(r) };
    }),
  validateCountersignatureContent: (c) =>
    answer(() => {
      validateCountersignatureContent(c.content);
      return true;
    }),
  checkSlip: async (c) => ({ ok: await checkSlip(c.record, c.options, c.disclosures) }),
  // Whether a text is a page address in its plain form: the address the URL
  // Standard gives back for it, with nothing after the host and the port.
  // A slip's issuer.origin and issuer.rpId, by the slip's own rule.
  checkOrigin: (c) =>
    answer(() => {
      checkOriginForTests(c.text, c.rpId);
      return true;
    }),
};

const set = (about, fn, cases) => finish(about, fn, cases, ANSWER);

// --- values ---

function encodingCases() {
  const texts = [
    ['an object', '{"a":1,"b":[2,"x"]}'],
    ['members out of order', '{"b":1,"a":2}'],
    ['a space', '{"a": 1}'],
    ['a repeated name', '{"a":1,"a":1}'],
    ['a fraction', '{"a":1.5}'],
    ['a whole number written with a point', '{"a":1.0}'],
    ['an exponent', '{"a":1e2}'],
    ['minus zero', '{"a":-0}'],
    ['a negative number', '{"a":-1}'],
    ['the largest number', '{"a":9007199254740991}'],
    ['one more than the largest number', '{"a":9007199254740992}'],
    ['a very long number', '{"a":123456789012345678901234567890}'],
    ['true', '{"a":true}'],
    ['null', '{"a":null}'],
    ['NaN', '{"a":NaN}'],
    ['not JSON', '{"a":'],
    ['empty text', ''],
    ['a byte order mark', '﻿{}'],
    ['a lone surrogate written as an escape', '{"a":"\\ud800"}'],
    ['a pair written as escapes', '{"a":"\\ud83d\\ude00"}'],
    ['a pair written as itself', '{"a":"😀"}'],
    ['an escape that need not be one', '{"a":"\\u0041"}'],
    ['a control character escaped', '{"a":"\\u0001"}'],
    ['a control character escaped in capitals', '{"a":"\\u001F"}'],
    ['a solidus escaped', '{"a":"\\/"}'],
    ['delete written as itself', '{"a":"\u007f"}'],
    ['line separator written as itself', '{"a":" "}'],
    ['names sorted by UTF-16, not by code point', '{"😀":1,"￿":2}'],
    ['names sorted by code point', '{"￿":1,"😀":2}'],
    ['names that are numbers', '{"10":1,"2":2,"a":3}'],
    ['nesting of depth 8', '[[[[[[[[1]]]]]]]]'],
    ['nesting of depth 7', '[[[[[[[1]]]]]]]'],
    ['nesting of depth 2000', '['.repeat(2000) + ']'.repeat(2000)],
    ['a list at the top', '[1,2]'],
    ['a string at the top', '"a"'],
    ['a member named __proto__', '{"__proto__":1}'],
    ['trailing text', '{} '],
  ];
  return texts.map(([name, text]) => ({ name, text }));
}

function base64urlCases() {
  return [
    ['empty', ''],
    ['one byte', 'AA'],
    ['two bytes', 'AAE'],
    ['three bytes', 'AAEC'],
    ['an impossible length', 'A'],
    ['padding', 'AA=='],
    ['stray bits', 'AB'],
    ['a plus sign', 'a+b_'],
    ['a character outside ASCII', 'AAAé'],
    ['an astral character', 'AAA😀'],
    ['all the alphabet', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'],
  ].map(([name, text]) => ({ name, text }));
}

function timeCases() {
  return [
    '2026-10-05T09:00:00Z',
    '0000-01-01T00:00:00Z',
    '9999-12-31T23:59:59Z',
    '2024-02-29T00:00:00Z',
    '2026-02-29T00:00:00Z',
    '2026-04-31T00:00:00Z',
    '2026-01-01T24:00:00Z',
    '2026-12-31T23:59:60Z',
    '2026-13-01T00:00:00Z',
    '2026-00-10T00:00:00Z',
    '2026-10-05T09:00:00.000Z',
    '2026-10-05T09:00:00+00:00',
    '2026-10-05 09:00:00Z',
    '2026-10-05T09:00Z',
    '٢٠٢٦-10-05T09:00:00Z',
    '2026-10-05T09:00:00Z\n',
    '1900-03-01T00:00:00Z',
    '1969-12-31T23:59:59Z',
  ].map((text) => ({ name: JSON.stringify(text), text }));
}

function countCases() {
  return [
    ['empty', ''],
    ['ASCII', 'abc'],
    ['an accent', 'é'],
    ['an astral character', '😀'],
    ['a lone first half', '\ud83d'],
    ['a lone second half', '\ude00'],
    ['a combining mark', 'é'],
  ].map(([name, text]) => ({ name, text }));
}

// --- Ed25519 signatures ---

// The twelve cases of the paper "Taming the many EdDSAs" (Chalkias,
// Garillot, Kondi and Nikolaenko, 2020; https://eprint.iacr.org/2020/1244),
// as its authors published them under the Apache License 2.0: what each
// tests, then the message, the public key A and the signature (R, then S),
// each in hexadecimal. "Mixed order" means a point of large order with a
// small-order part. The format's rules decide each one (format description,
// section 3.8): a small-order or non-canonical A is refused as a key; a
// small-order or non-canonical R, or an S not below L, is invalid; a
// mixed-order key is checked without the cofactor.
const TAMING_CASES = [
  ['small-order A and small-order R, S of 0', '8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000'],
  ['small-order A, mixed-order R', '9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa', 'f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04'],
  ['mixed-order A, small-order R', 'aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab', 'f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e'],
  ['mixed-order A and R, accepted with or without the cofactor', '9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79', 'cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d', '9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009'],
  ['mixed-order A and R, accepted only with the cofactor', 'e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c', 'cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d', '160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09'],
  ['mixed-order A, accepted only with the cofactor and with k not reduced before multiplying', 'e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c', 'cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d', '21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405'],
  ['S above L', '85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40', '442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623', 'e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514'],
  ['S far above L, with the top bit set', '85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40', '442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623', '8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22'],
  ['R not in canonical form, reduced for the hash', '9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41', 'f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43', 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f'],
  ['R not in canonical form, not reduced for the hash', '9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41', 'f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43', 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908'],
  ['A not in canonical form, reduced for the hash', 'e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b', 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04'],
  ['A not in canonical form, not reduced for the hash', '39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f', 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04'],
];

async function ed25519Cases() {
  const agent = await generateKeySet();
  const key = agent.keys[0];
  const message = utf8('a message signed for the shared test files');
  const genuine = await sign('Ed25519', agent.privateKeys[0], message);
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
  const neutral = new Uint8Array(32);
  neutral[0] = 1;
  const cases = TAMING_CASES.map(([name, m, a, signature]) => ({ name: `the paper: ${name}`, key: a, signature, message: m }));
  const own = (name, signature, more = {}) => cases.push({ name, key: hex(fromBase64url(key.x)), signature: hex(signature), message: hex(message), ...more });
  own('a genuine signature', genuine);
  own('a genuine signature, Ed25519 said to be missing', genuine, { without: ['Ed25519'] });
  own('a genuine signature over another message', genuine, { message: hex(utf8('another message')) });
  own('S raised by L: the same number modulo L, written a second way', withS(genuine, sOf(genuine) + L));
  own('S equal to L', withS(genuine, L));
  own('S of L minus 1, under a genuine R', withS(genuine, L - 1n));
  own('S with its top bit set', withS(genuine, sOf(genuine) | (1n << 255n)));
  own('R replaced by the neutral point', concatBytes(neutral, genuine.subarray(32)));
  own('63 bytes', genuine.subarray(0, 63));
  own('65 bytes', concatBytes(genuine, new Uint8Array(1)));
  return cases;
}

// --- keys ---

// The Ed25519 public keys under which anyone can sign (the points of small
// order), and keys written in more than one way (y not below p).
const WEAK_ED25519 = [
  ['the neutral point', '0100000000000000000000000000000000000000000000000000000000000000'],
  ['the neutral point, with the sign bit', '0100000000000000000000000000000000000000000000000000000000000080'],
  ['a point of order 2', 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'],
  ['a point of order 4', '0000000000000000000000000000000000000000000000000000000000000000'],
  ['the other point of order 4', '0000000000000000000000000000000000000000000000000000000000000080'],
  ['a point of order 8', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'],
  ['another point of order 8', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa'],
  ['a third point of order 8', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'],
  ['a fourth point of order 8', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85'],
  ['y equal to p', 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'],
  ['y of p + 1, the neutral point written again', 'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'],
  ['y of 2^255 - 1', 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'],
];

// Points of P-256 with a small half: x = 5 and its y; y = 5 and its x (found
// by solving the curve's equation); and 5 + p, the second written form of 5.
const P256_X5 = ['0000000000000000000000000000000000000000000000000000000000000005', '459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc'];
const P256_Y5 = ['d7325d7646cd60d80a92738ceb345f844cffaf35841022cab176f692de8de1d7', '0000000000000000000000000000000000000000000000000000000000000005'];
const P256_PLUS_5 = 'ffffffff00000001000000000000000000000001000000000000000000000004';

/** A copy of some bytes with the last byte changed by one. */
const changedLastByte = (bytes) => {
  const out = Uint8Array.from(bytes);
  out[out.length - 1] ^= 1;
  return out;
};

async function keyCases() {
  const agent = await generateKeySet();
  const es = (await makePasskey('ES256')).key;
  const rs = (await makePasskey('RS256')).key;
  const ed = (await makePasskey('Ed25519')).key;
  const [edAgent, ml] = agent.keys;
  const slhPub = toBase64url(new Uint8Array(64));
  const all = ['Ed25519', 'ML-DSA-87', 'SLH-DSA-SHA2-256s', ...PASSKEY_METHODS];
  const cases = [
    ['an Ed25519 key', edAgent, ['Ed25519']],
    ['an ML-DSA-87 key', ml, ['ML-DSA-87']],
    ['an SLH-DSA key', { alg: 'SLH-DSA-SHA2-256s', kty: 'AKP', pub: slhPub }, ['SLH-DSA-SHA2-256s']],
    ['an ES256 passkey', es, PASSKEY_METHODS],
    ['an RS256 passkey', rs, PASSKEY_METHODS],
    ['an Ed25519 passkey', ed, PASSKEY_METHODS],
    ['a method not allowed here', ml, PASSKEY_METHODS],
    ['an unknown method', { ...edAgent, alg: 'EdDSA' }, all],
    ['no method', { kty: 'OKP', crv: 'Ed25519', x: edAgent.x }, all],
    ['a list', [edAgent], all],
    ['null', null, all],
    ['an extra member', { ...edAgent, kid: 'a' }, all],
    ['a private part', { ...edAgent, d: 'AAAA' }, all],
    ['a member that is not text', { ...edAgent, crv: 1 }, all],
    ['the wrong curve', { ...edAgent, crv: 'Ed448' }, all],
    ['the wrong key type', { ...edAgent, kty: 'EC' }, all],
    ['a short Ed25519 key', { ...edAgent, x: toBase64url(new Uint8Array(31)) }, all],
    ['an Ed25519 key that is not base64url', { ...edAgent, x: edAgent.x + '=' }, all],
    ['a short ML-DSA-87 key', { ...ml, pub: toBase64url(new Uint8Array(1952)) }, all],
    ['an ML-DSA-87 key of the wrong type', { ...ml, kty: 'OKP' }, all],
    ['a short SLH-DSA key', { alg: 'SLH-DSA-SHA2-256s', kty: 'AKP', pub: toBase64url(new Uint8Array(32)) }, all],
    ['a P-256 key with a short half', { ...es, y: toBase64url(new Uint8Array(31)) }, all],
    ['a P-256 key that is not on the curve: y changed', { ...es, y: toBase64url(changedLastByte(fromBase64url(es.y))) }, all],
    ['a P-256 key that is not on the curve: x changed', { ...es, x: toBase64url(changedLastByte(fromBase64url(es.x))) }, all],
    ['a P-256 key whose halves are not a point', { ...es, x: toBase64url(new Uint8Array(32).fill(1)), y: toBase64url(new Uint8Array(32).fill(2)) }, all],
    ['a P-256 key with x equal to the prime of the curve', { ...es, x: toBase64url(Buffer.from('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff', 'hex')) }, all],
    ['a P-256 key with y equal to the prime of the curve', { ...es, y: toBase64url(Buffer.from('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff', 'hex')) }, all],
    ['the base point of P-256', { ...es, x: toBase64url(Buffer.from('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296', 'hex')), y: toBase64url(Buffer.from('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5', 'hex')) }, all],
    // Two points with a small half, and the same points with that half written as itself plus the prime: a second written form of one point, which is refused, not reduced.
    ['the point of P-256 with x equal to 5', { ...es, x: toBase64url(Buffer.from(P256_X5[0], 'hex')), y: toBase64url(Buffer.from(P256_X5[1], 'hex')) }, all],
    ['a P-256 key with x written as 5 plus the prime', { ...es, x: toBase64url(Buffer.from(P256_PLUS_5, 'hex')), y: toBase64url(Buffer.from(P256_X5[1], 'hex')) }, all],
    ['the point of P-256 with y equal to 5', { ...es, x: toBase64url(Buffer.from(P256_Y5[0], 'hex')), y: toBase64url(Buffer.from(P256_Y5[1], 'hex')) }, all],
    ['a P-256 key with y written as 5 plus the prime', { ...es, x: toBase64url(Buffer.from(P256_Y5[0], 'hex')), y: toBase64url(Buffer.from(P256_PLUS_5, 'hex')) }, all],
    ['an EC key on another curve', { ...es, crv: 'P-384' }, all],
    ['an RSA key with another exponent', { ...rs, e: 'Aw' }, all],
    ['an RSA key of 1,024 bits', { ...rs, n: toBase64url(fromBase64url(rs.n).subarray(0, 128)) }, all],
    ['an RSA key with a leading zero', { ...rs, n: toBase64url(new Uint8Array([0, ...fromBase64url(rs.n)])) }, all],
    ['an RSA key of 8,193 bits', { ...rs, n: toBase64url(new Uint8Array([1, ...new Uint8Array(1024).fill(255)])) }, all],
    ['an RSA key of 8,192 bits', { ...rs, n: toBase64url(new Uint8Array(1024).fill(255)) }, all],
    ...WEAK_ED25519.map(([name, h]) => [`a weak Ed25519 key: ${name}`, { ...edAgent, x: toBase64url(Buffer.from(h, 'hex')) }, all]),
    ...WEAK_ED25519.map(([name, h]) => [`a weak Ed25519 passkey: ${name}`, { ...ed, x: toBase64url(Buffer.from(h, 'hex')) }, PASSKEY_METHODS]),
  ];
  return cases.map(([name, key, allowed]) => ({ name, key, allowed }));
}

function derCases() {
  const r = '01'.repeat(32);
  const high = '80' + '01'.repeat(31);
  const int = (h) => '02' + (h.length / 2).toString(16).padStart(2, '0') + h;
  const seq = (body) => '30' + (body.length / 2).toString(16).padStart(2, '0') + body;
  return [
    ['two numbers', seq(int(r) + int(r))],
    ['a number with its high bit set, padded', seq(int('00' + high) + int(r))],
    ['a number with its high bit set, not padded', seq(int(high) + int(r))],
    ['a padded number that need not be', seq(int('00' + r) + int(r))],
    ['short numbers', seq(int('01') + int('02'))],
    ['a number of 33 bytes', seq(int('01' + r) + int(r))],
    ['bytes left over', seq(int(r) + int(r) + '00')],
    ['a wrong length', '30ff' + int(r) + int(r)],
    ['not a sequence', '31' + seq(int(r) + int(r)).slice(2)],
    ['an empty number', seq('0200' + int(r))],
    ['too short', '3006020101020101'.slice(0, 12)],
  ].map(([name, der]) => ({ name, der }));
}

// --- records ---

async function signedSlip(passkey, content, assertion = {}) {
  const { payloadB64 } = encodeContent(content);
  const [protectedB64] = protectedHeaders('slip');
  const challenge = await sha256(signingInput(protectedB64, payloadB64));
  return assembleSlip({ payloadB64, protectedB64 }, await passkey.sign(challenge, assertion));
}

async function baseSlip(alg = 'ES256', site = {}) {
  const passkey = await makePasskey(alg, site);
  const agent = await generateKeySet();
  const service = await generateKeySet();
  const content = {
    type: 'provared.slip.v0',
    id: toBase64url(new Uint8Array(16).fill(7)),
    issuer: { name: 'Sam Example', key: passkey.key, rpId: passkey.rpId, origin: passkey.origin },
    agent: { name: 'Office supplies agent', keys: agent.keys },
    actions: ['supplies.order', 'provared.message.send'],
    limits: [
      { action: 'supplies.order', max: 200, unit: 'GBP' },
      { action: 'supplies.order', count: 5, per: 86400 },
    ],
    requires: [{ need: 'approval', action: 'supplies.order', above: 100, unit: 'GBP' }],
    never: ['destroys', 'deceive'],
    with: [{ id: 'supplier', name: 'Example Stationery (invented)', keys: service.keys }],
    validFrom: '2026-10-05T08:00:00Z',
    validUntil: '2026-10-12T08:00:00Z',
    purpose: 'Keep the office stocked with paper, pens and toner.',
  };
  return { passkey, content, agent, service };
}

const ORIGINS = [
  ['a port', 'https://sign.example.org:8443', 'example.org'],
  ['port 0', 'https://sign.example.org:0', 'example.org'],
  ['the default port', 'https://sign.example.org:443', 'example.org'],
  ['a port with a leading zero', 'https://sign.example.org:08443', 'example.org'],
  ['a port too large', 'https://sign.example.org:65536', 'example.org'],
  ['an empty port', 'https://sign.example.org:', 'example.org'],
  ['a path', 'https://sign.example.org/', 'example.org'],
  ['a query', 'https://sign.example.org?a', 'example.org'],
  ['capitals', 'https://Sign.example.org', 'example.org'],
  ['a capital scheme', 'HTTPS://sign.example.org', 'example.org'],
  ['user information', 'https://u@sign.example.org', 'example.org'],
  ['plain http', 'http://sign.example.org', 'example.org'],
  ['http on localhost', 'http://localhost', 'localhost'],
  ['http on localhost with a port', 'http://localhost:8787', 'localhost'],
  ['ws', 'ws://sign.example.org', 'example.org'],
  ['ftp', 'ftp://sign.example.org', 'example.org'],
  ['a scheme that is not special', 'foo://sign.example.org', 'example.org'],
  ['no scheme', 'sign.example.org', 'example.org'],
  ['not an address', 'not an address', 'example.org'],
  ['the website itself', 'https://example.org', 'example.org'],
  ['another website', 'https://example.com', 'example.org'],
  ['a website that only ends the same way', 'https://badexample.org', 'example.org'],
  ['a final dot', 'https://example.org.', 'example.org'],
  ['an empty label', 'https://a..example.org', 'example.org'],
  ['a leading dot', 'https://.example.org', 'example.org'],
  ['an underscore', 'https://a_b.example.org', 'example.org'],
  ['punctuation', 'https://a!b$c&d(e)f*g+h,i;j=k~l.example.org', 'example.org'],
  ['quotation marks and braces', 'https://a"b{c}d`e\'f.example.org', 'example.org'],
  ['a space', 'https://a b.example.org', 'example.org'],
  ['a percent sign', 'https://a%41.example.org', 'example.org'],
  ['an encoded name', 'https://xn--bcher-kva.example.org', 'example.org'],
  ['an encoded emoji', 'https://xn--ls8h.example.org', 'example.org'],
  ['an encoded sharp s', 'https://xn--zca.example.org', 'example.org'],
  ['an encoded name that decodes to ASCII', 'https://xn--ss-.example.org', 'example.org'],
  ['an encoded name that does not decode', 'https://xn--a.example.org', 'example.org'],
  ['an empty encoded name', 'https://xn--.example.org', 'example.org'],
  ['an encoded name in capitals', 'https://xn--Bcher-kva.example.org', 'example.org'],
  ['an address of four numbers', 'https://192.0.2.1', '192.0.2.1'],
  ['an address of three numbers', 'https://192.0.2', '192.0.2'],
  ['an address with a leading zero', 'https://192.0.2.01', '192.0.2.01'],
  ['an address with a number too large', 'https://256.0.2.1', '256.0.2.1'],
  ['an address in hexadecimal', 'https://0xc0.0.2.1', 'example.org'],
  ['a name ending in a number', 'https://a.1', 'a.1'],
  ['a name ending in hexadecimal', 'https://a.0x', 'a.0x'],
  ['a name beginning with a number', 'https://09.example.org', 'example.org'],
  ['IPv6', 'https://[::1]', 'example.org'],
  ['a website name in capitals', 'https://sign.example.org', 'Example.org'],
  ['a website name with an underscore', 'https://sign.ex_ample.org', 'ex_ample.org'],
  ['a website name ending with a hyphen', 'https://sign.example-', 'example-'],
  ['a long address', 'https://' + 'a'.repeat(290) + '.example.org', 'example.org'],
];

async function slipCases() {
  const cases = [];
  const add = (name, record, options, disclosures) => cases.push({ name, record, ...(options ? { options } : {}), ...(disclosures ? { disclosures } : {}) });

  const site = { rpId: 'example.org', origin: 'https://sign.example.org' };
  const es = await baseSlip('ES256', site);
  const good = await signedSlip(es.passkey, es.content);
  const issuerKey = await thumbprint(es.passkey.key);
  add('a sound slip, signed with ES256', good);
  add('a sound slip, with the passkey trusted', good, { issuerKeys: [issuerKey] });
  add('a sound slip, with another passkey trusted', good, { issuerKeys: [toBase64url(new Uint8Array(32))] });
  add('a sound slip, on a device without ES256', good, { withoutMethods: ['ES256'] });
  for (const alg of ['RS256', 'Ed25519']) {
    const w = await baseSlip(alg, site);
    add(`a sound slip, signed with ${alg}`, await signedSlip(w.passkey, w.content));
  }
  const local = await baseSlip('ES256');
  add('a sound slip, signed on localhost', await signedSlip(local.passkey, local.content));

  // The passkey's answer.
  const assertions = [
    ['an answer made to create a passkey', { type: 'webauthn.create' }],
    ['an answer for another challenge', { challenge: new Uint8Array(32) }],
    ['an answer from another page', { origin: 'https://other.example.org' }],
    ['an answer across origins', { crossOrigin: true }],
    ['an answer for another website', { rpId: 'example.com' }],
    ['no person present', { flags: 0x04 }],
    ['the person not verified', { flags: 0x01 }],
    ['data that belongs to creating a passkey', { flags: 0x45 }],
    ['bytes left over', { extra: new Uint8Array([1, 2]) }],
    ['extension bytes, as marked', { flags: 0x85, extra: new Uint8Array([0xa0]) }],
    ['client data that is not JSON', { clientDataText: 'not json' }],
    ['client data that is NaN', { clientDataText: 'NaN' }],
    ['client data that is a list', { clientDataText: '[]' }],
    ['client data whose type is not text', { clientDataText: '{"type":1}' }],
    ['client data nested deeply', { clientDataText: '{"type":"webauthn.get","x":' + '['.repeat(3000) + ']'.repeat(3000) + '}' }],
    ['a signature over other bytes', { signedAuthenticatorData: new Uint8Array(37) }],
    ['a signature with a changed byte', { signature: (s) => { const t = new Uint8Array(s); t[t.length - 1] ^= 1; return t; } }],
    ['a signature not in its shortest form', { signature: (s) => Uint8Array.from([0x30, s[1] + 1, 0x02, s[3] + 1, 0x00, ...s.subarray(4)]) }],
    ['a signature cut short', { signature: (s) => s.subarray(0, s.length - 1) }],
  ];
  for (const [name, change] of assertions) add(name, await signedSlip(es.passkey, es.content, change));

  // The envelope.
  const [sig] = good.signatures;
  const stubLabel = toBase64url(utf8('{"typ":"vnd.provared.stub.v0+json","alg":"Ed25519"}'));
  const envelopes = [
    ['an extra member', { ...good, extra: 1 }],
    ['a payload that is not text', { ...good, payload: 1 }],
    ['signatures that are not a list', { ...good, signatures: sig }],
    ['no signature', { ...good, signatures: [] }],
    ['two signatures', { ...good, signatures: [sig, sig] }],
    ['the label of a stub', { ...good, signatures: [{ ...sig, protected: stubLabel }] }],
    ['an unknown label', { ...good, signatures: [{ ...sig, protected: toBase64url(utf8('{"alg":"none"}')) }] }],
    ['a label that is not base64url', { ...good, signatures: [{ ...sig, protected: sig.protected + '=' }] }],
    ['a label that is not UTF-8', { ...good, signatures: [{ ...sig, protected: toBase64url(new Uint8Array([0xff])) }] }],
    ['a signature entry without its header', { ...good, signatures: [{ protected: sig.protected, signature: sig.signature }] }],
    ['a header with a member missing', { ...good, signatures: [{ ...sig, header: { authenticatorData: sig.header.authenticatorData } }] }],
    ['passkey values that are not base64url', { ...good, signatures: [{ ...sig, header: { ...sig.header, clientDataJSON: '!' } }] }],
    ['a payload that is not base64url', { ...good, payload: good.payload + '!' }],
    ['a changed payload', { ...good, payload: encodeContent({ ...es.content, purpose: 'Something else.' }).payloadB64 }],
    ['a payload with a space', { ...good, payload: toBase64url(utf8('{ "type":"provared.slip.v0"}')) }],
    ['a payload that is a list', { ...good, payload: toBase64url(utf8('[]')) }],
    ['a payload of another type', { ...good, payload: toBase64url(utf8('{"type":"provared.stub.v0"}')) }],
    ['a record too large', { ...good, signatures: [{ ...sig, signature: 'A'.repeat(70000) }] }],
    ['not an object', [good]],
  ];
  for (const [name, record] of envelopes) add(name, record);

  // The content.
  const c = es.content;
  const contents = [
    ['a member missing', (() => { const { purpose, ...rest } = c; return rest; })()],
    ['an unknown member', { ...c, colour: 'red' }],
    ['an id too short', { ...c, id: 'AAAA' }],
    ['passes of 0', { ...c, passes: 0 }],
    ['passes of 10', { ...c, passes: 10 }],
    ['passes of 11', { ...c, passes: 11 }],
    ['an issuer name of 201 characters', { ...c, issuer: { ...c.issuer, name: 'a'.repeat(201) } }],
    ['an issuer name of 200 astral characters', { ...c, issuer: { ...c.issuer, name: '😀'.repeat(200) } }],
    ['an issuer name of 201 astral characters', { ...c, issuer: { ...c.issuer, name: '😀'.repeat(201) } }],
    ['an empty issuer name', { ...c, issuer: { ...c.issuer, name: '' } }],
    ['an issuer key of an agent kind', { ...c, issuer: { ...c.issuer, key: c.agent.keys[1] } }],
    ['an issuer with an extra member', { ...c, issuer: { ...c.issuer, email: 'a' } }],
    ['agent keys in the wrong order', { ...c, agent: { ...c.agent, keys: [c.agent.keys[1], c.agent.keys[0]] } }],
    ['one agent key', { ...c, agent: { ...c.agent, keys: [c.agent.keys[0]] } }],
    ['agent software', { ...c, agent: { ...c.agent, software: [{ name: 'agent.py', sha256: toBase64url(new Uint8Array(32)) }] } }],
    ['empty agent software', { ...c, agent: { ...c.agent, software: [] } }],
    ['no actions', { ...c, actions: [], limits: [], requires: [] }],
    ['a repeated action', { ...c, actions: ['supplies.order', 'supplies.order'] }],
    ['an unknown reserved action', { ...c, actions: ['supplies.order', 'provared.money.send'] }],
    ['an action with a capital', { ...c, actions: ['Supplies.order'], limits: [], requires: [] }],
    ['an action of 65 characters', { ...c, actions: ['a'.repeat(65)], limits: [], requires: [] }],
    ['a limit on an action not allowed', { ...c, limits: [{ action: 'other', max: 1, unit: 'GBP' }] }],
    ['a limit with two kinds', { ...c, limits: [{ action: 'supplies.order', max: 1, each: 1, unit: 'GBP' }] }],
    ['a count with a unit', { ...c, limits: [{ action: 'supplies.order', count: 1, unit: 'GBP' }] }],
    ['a count of 0', { ...c, limits: [{ action: 'supplies.order', count: 0 }] }],
    ['a total without a unit', { ...c, limits: [{ action: 'supplies.order', max: 1 }] }],
    ['a period on each action', { ...c, limits: [{ action: 'supplies.order', each: 1, unit: 'GBP', per: 60 }] }],
    ['a period of 367 days', { ...c, limits: [{ action: 'supplies.order', max: 1, unit: 'GBP', per: 367 * 86400 }] }],
    ['a period of 0', { ...c, limits: [{ action: 'supplies.order', max: 1, unit: 'GBP', per: 0 }] }],
    ['the same limit twice', { ...c, limits: [{ action: 'supplies.order', max: 1, unit: 'GBP' }, { action: 'supplies.order', max: 2, unit: 'GBP' }] }],
    ['two totals, one with a period', { ...c, limits: [{ action: 'supplies.order', max: 1, unit: 'GBP' }, { action: 'supplies.order', max: 2, unit: 'GBP', per: 60 }] }],
    ['two units for one action', { ...c, limits: [{ action: 'supplies.order', max: 1, unit: 'GBP' }, { action: 'supplies.order', each: 2, unit: 'EUR' }] }],
    ['a unit with a space', { ...c, limits: [{ action: 'supplies.order', max: 1, unit: 'G P' }] }],
    ['a unit of 17 characters', { ...c, limits: [{ action: 'supplies.order', max: 1, unit: 'a'.repeat(17) }] }],
    ['a total that is text', { ...c, limits: [{ action: 'supplies.order', max: 'x', unit: 'GBP' }] }],
    ['a condition of an unknown kind', { ...c, requires: [{ need: 'blessing' }] }],
    ['a condition on an action not allowed', { ...c, requires: [{ need: 'approval', action: 'other' }] }],
    ['a condition with an amount and no unit', { ...c, requires: [{ need: 'approval', action: 'supplies.order', above: 1 }] }],
    ['a condition with an amount and no action', { ...c, requires: [{ need: 'approval', above: 1, unit: 'GBP' }] }],
    ['a condition in another unit', { ...c, requires: [{ need: 'approval', action: 'supplies.order', above: 1, unit: 'EUR' }] }],
    ['the same condition twice', { ...c, requires: [{ need: 'countersignature' }, { need: 'countersignature' }] }],
    ['a condition for every action and one for an action', { ...c, requires: [{ need: 'countersignature' }, { need: 'countersignature', action: 'supplies.order' }] }],
    ['an unknown prohibition', { ...c, never: ['steal'] }],
    ['a repeated prohibition', { ...c, never: ['deceive', 'deceive'] }],
    ['a prohibition of what is allowed', { ...c, never: ['sends'] }],
    ['17 prohibitions', { ...c, never: Array(17).fill('deceive') }],
    ['a service with a repeated id', { ...c, with: [c.with[0], c.with[0]] }],
    ['a service without keys', { ...c, with: [{ id: 'supplier', name: 'Supplier' }] }],
    ['a service with a bad id', { ...c, with: [{ id: 'Supplier', name: 'Supplier' }] }],
    ['a time with a fraction', { ...c, validFrom: '2026-10-05T08:00:00.000Z' }],
    ['30 February', { ...c, validFrom: '2026-02-30T08:00:00Z' }],
    ['an end before the start', { ...c, validUntil: '2026-10-05T07:59:59Z' }],
    ['an end at the start', { ...c, validUntil: c.validFrom }],
    ['a purpose of 1,001 characters', { ...c, purpose: 'a'.repeat(1001) }],
    ['a purpose with a lone surrogate', { ...c, purpose: 'a\ud800' }],
    ['a member named __proto__', { ...c, __proto__: 1 }],
  ];
  for (const [name, content] of contents) {
    // A member named __proto__ is written by assigning it as a member of its own.
    if (name === 'a member named __proto__') Object.defineProperty(content, '__proto__', { value: 1, enumerable: true, writable: true, configurable: true });
    let record;
    try {
      record = await signedSlip(es.passkey, content);
    } catch {
      continue; // content the canonical form cannot write
    }
    add(name, record);
  }

  for (const [name, origin, rpId] of ORIGINS) {
    const content = { ...c, issuer: { ...c.issuer, origin, rpId } };
    add(`the address: ${name}`, await signedSlip(es.passkey, content, { origin, rpId }));
  }

  // Covered fields.
  const coverIn = async (fieldsToCover) => {
    let content = { ...c };
    const disclosures = [];
    const hide = async (object, names) => {
      const made = await coverMembers(object, names);
      disclosures.push(...made.disclosures);
      return made.object;
    };
    if (fieldsToCover.includes('issuer.name')) content.issuer = await hide(content.issuer, ['name']);
    if (fieldsToCover.includes('agent.name')) content.agent = await hide(content.agent, ['name']);
    if (fieldsToCover.includes('with.name')) content.with = await Promise.all(content.with.map((s) => hide(s, ['name'])));
    if (fieldsToCover.includes('purpose')) content = await hide(content, ['purpose']);
    content._sd_alg = 'sha-256';
    return { content, disclosures };
  };
  const covered = await coverIn(['issuer.name', 'agent.name', 'with.name', 'purpose']);
  const coveredSlip = await signedSlip(es.passkey, covered.content);
  const fp = toBase64url(await sha256(fromBase64url(coveredSlip.payload)));
  add('covered fields, none revealed', coveredSlip);
  add('covered fields, all revealed beside it', coveredSlip, { disclosures: { [fp]: covered.disclosures } });
  add('covered fields, two revealed with it', coveredSlip, undefined, covered.disclosures.slice(0, 2));
  add('covered fields, one with it and one beside it', coveredSlip, { disclosures: { [fp]: [covered.disclosures[1]] } }, [covered.disclosures[0]]);
  add('covered fields, the same one both ways', coveredSlip, { disclosures: { [fp]: [covered.disclosures[0]] } }, [covered.disclosures[0]]);
  add('covered fields, a disclosure handed over twice', coveredSlip, undefined, [covered.disclosures[0], covered.disclosures[0]]);
  add('covered fields, a disclosure of another record', coveredSlip, undefined, [toBase64url(utf8('["c2FsdA","name","x"]'))]);
  add('covered fields, a disclosure not in the canonical form', coveredSlip, undefined, [toBase64url(utf8('["c2FsdA", "name", "x"]'))]);
  add('covered fields, a disclosure that is not text', coveredSlip, undefined, [1]);
  add('covered fields, disclosures that are not a list', coveredSlip, undefined, 'abc');
  add('covered fields, disclosures for another slip beside it', coveredSlip, { disclosures: { [toBase64url(new Uint8Array(32))]: covered.disclosures } });
  const { _sd_alg, ...unnamed } = covered.content;
  add('covered fields, without the fingerprint method', await signedSlip(es.passkey, unnamed));
  add('covered fields, another fingerprint method', await signedSlip(es.passkey, { ...covered.content, _sd_alg: 'sha-512' }));
  add('no covered field, with the fingerprint method', await signedSlip(es.passkey, { ...c, _sd_alg: 'sha-256' }));
  add('covered fields, a decoy fingerprint', await signedSlip(es.passkey, { ...covered.content, issuer: { ...covered.content.issuer, _sd: [...covered.content.issuer._sd, toBase64url(new Uint8Array(32))] } }));
  add('covered fields, the name also given', await signedSlip(es.passkey, { ...covered.content, issuer: { ...covered.content.issuer, name: 'Sam' } }));
  add('covered fields, an action covered', await signedSlip(es.passkey, { ...covered.content, actions: [{ '...': toBase64url(new Uint8Array(32)) }, 'provared.message.send'] }));
  add('covered fields, a limit covered', await signedSlip(es.passkey, { ...covered.content, limits: [{ ...c.limits[0], _sd: [toBase64url(new Uint8Array(32))] }] }));
  add('covered fields, a fingerprint that is not one', await signedSlip(es.passkey, { ...covered.content, issuer: { ...covered.content.issuer, _sd: ['abc'] } }));
  add('covered fields, the same fingerprint twice', await signedSlip(es.passkey, { ...covered.content, agent: { ...covered.content.agent, _sd: covered.content.issuer._sd } }));
  return cases;
}

async function recordCases() {
  const w = await baseSlip('ES256');
  const slip = await signedSlip(w.passkey, w.content);
  return [
    { name: 'a slip read as a slip', record: slip, kind: 'slip' },
    { name: 'a slip read as a stub', record: slip, kind: 'stub' },
    { name: 'a slip read as an approval', record: slip, kind: 'approval' },
  ];
}

function stubContents() {
  const fp = toBase64url(new Uint8Array(32).fill(1));
  const id = toBase64url(new Uint8Array(16).fill(2));
  const base = { type: 'provared.stub.v0', id, slip: fp, seq: 0, action: 'supplies.order', when: '2026-10-05T09:00:00Z' };
  return [
    ['the least a stub holds', base],
    ['every member', { ...base, seq: 1, previous: fp, amount: { unit: 'GBP', value: 30 }, with: 'supplier', details: [{ name: 'order.pdf', sha256: fp }], approval: fp, terms: fp, pass: fp }],
    ['a first stub naming one before it', { ...base, previous: fp }],
    ['a later stub naming none before it', { ...base, seq: 1 }],
    ['an unknown member', { ...base, colour: 'red' }],
    ['a negative number', { ...base, seq: -1 }],
    ['an amount without a unit', { ...base, amount: { value: 1 } }],
    ['an amount with an extra member', { ...base, amount: { unit: 'GBP', value: 1, tax: 0 } }],
    ['terms without a service', { ...base, terms: fp }],
    ['no documents', { ...base, details: [] }],
    ['33 documents', { ...base, details: Array(33).fill({ name: 'a', sha256: fp }) }],
    ['a document fingerprint too short', { ...base, details: [{ name: 'a', sha256: id }] }],
    ['an unknown reserved action', { ...base, action: 'provared.money.send' }],
    ['a shared action', { ...base, action: 'provared.order.place' }],
    ['a service with a capital', { ...base, with: 'Supplier' }],
    ['a time with an offset', { ...base, when: '2026-10-05T09:00:00+01:00' }],
    ['a list', [base]],
    // The reserved document names (format description, section 27).
    ...['provared.arguments', 'provared.http-request', 'provared.http-response', 'provared.trace-id', 'provared.request-id', 'provared.event-id', 'provared.error'].map((name) => [
      `the reserved document name ${name}`,
      { ...base, details: [{ name, sha256: fp }] },
    ]),
    ['a reserved document name not on the list', { ...base, details: [{ name: 'order.pdf', sha256: fp }, { name: 'provared.invoice', sha256: fp }] }],
    ['the reserved prefix alone as a document name', { ...base, details: [{ name: 'provared.', sha256: fp }] }],
    ['a reserved document name with a capital', { ...base, details: [{ name: 'provared.Event-id', sha256: fp }] }],
    ['a reserved document name with a space after it', { ...base, details: [{ name: 'provared.event-id ', sha256: fp }] }],
    ['a document name that begins with the prefix in capitals', { ...base, details: [{ name: 'Provared.invoice', sha256: fp }] }],
    ['a document name that holds the prefix later', { ...base, details: [{ name: 'my provared.invoice', sha256: fp }] }],
    ['a reserved document name twice', { ...base, details: [{ name: 'provared.event-id', sha256: fp }, { name: 'provared.event-id', sha256: id + 'AAAAAAAAAAAAAAAAAAAAA' }] }],
    // Only the three identifiers may be named more than once.
    ...['provared.trace-id', 'provared.request-id', 'provared.event-id'].map((name) => [`${name} three times`, { ...base, details: [{ name, sha256: fp }, { name, sha256: fp }, { name, sha256: fp }] }]),
    ...['provared.arguments', 'provared.http-request', 'provared.http-response', 'provared.error'].map((name) => [
      `${name} twice`,
      { ...base, details: [{ name, sha256: fp }, { name: 'order.pdf', sha256: fp }, { name, sha256: fp }] },
    ]),
    ['every reserved name once, and the identifiers twice', { ...base, details: ['provared.arguments', 'provared.http-request', 'provared.http-response', 'provared.error', 'provared.trace-id', 'provared.request-id', 'provared.event-id', 'provared.trace-id', 'provared.request-id', 'provared.event-id'].map((name) => ({ name, sha256: fp })) }],
    ['a label named twice', { ...base, details: [{ name: 'order.pdf', sha256: fp }, { name: 'order.pdf', sha256: fp }] }],
    ['the old name "arguments" beside the reserved one', { ...base, details: [{ name: 'arguments', sha256: fp }, { name: 'provared.arguments', sha256: fp }] }],
    ['an unknown reserved document name with a bad fingerprint', { ...base, details: [{ name: 'provared.x', sha256: 'short' }] }],
  ].map(([name, content]) => ({ name, content }));
}

// The reserved document names and the fingerprints they stand for (format
// description, section 27). A body is written in hexadecimal ("bodyHex");
// "names" asks for the list of reserved names and their words.
function documentCases() {
  const hello = Buffer.from('{"hello": "world"}').toString('hex');
  const request = (name, r) => ({ name, kind: 'request', input: r });
  const response = (name, r) => ({ name, kind: 'response', input: r });
  const identifier = (name, id) => ({ name, kind: 'identifier', input: id });
  return [
    { name: 'the reserved document names and their words', kind: 'names' },
    // The test request of RFC 9421, appendix B.2, with its body, whose Content-Digest RFC 9530 gives.
    request('a POST with a body, as in RFC 9421, appendix B.2', { method: 'POST', url: 'https://example.com/foo?param=Value&Pet=dog', bodyHex: hello }),
    request('a GET with no body', { method: 'GET', url: 'https://example.com/' }),
    request('an empty body is a body', { method: 'POST', url: 'https://example.com/', bodyHex: '' }),
    request('an address with a port', { method: 'GET', url: 'https://example.com:8443/a' }),
    request('an address with its default port', { method: 'GET', url: 'https://example.com:443/a' }),
    request('an address with a query', { method: 'GET', url: 'https://example.com/a?b=c&d=e' }),
    request('an address with an empty query', { method: 'GET', url: 'https://example.com/a?' }),
    request('an address with a space written as %20', { method: 'GET', url: 'https://example.com/a%20b' }),
    request('the same address with %2f in place of %2F', { method: 'GET', url: 'https://example.com/a%2fb' }),
    request('the same address with %2F', { method: 'GET', url: 'https://example.com/a%2Fb' }),
    request('the host in capitals', { method: 'GET', url: 'https://EXAMPLE.com/a' }),
    request('plain http', { method: 'GET', url: 'http://localhost:8080/x' }),
    request('a method in small letters, kept as given', { method: 'get', url: 'https://example.com/' }),
    request('a method of its own', { method: 'X-REPORT', url: 'https://example.com/' }),
    request('an address with a fragment', { method: 'GET', url: 'https://example.com/a#b' }),
    request('an address with a space', { method: 'GET', url: 'https://example.com/a b' }),
    request('an address with a letter outside ASCII', { method: 'GET', url: 'https://example.com/café' }),
    request('an address with a line feed', { method: 'GET', url: 'https://example.com/a\n' }),
    request('a relative address', { method: 'GET', url: '/foo' }),
    request('an address with the scheme in capitals', { method: 'GET', url: 'HTTPS://example.com/' }),
    request('another scheme', { method: 'GET', url: 'ftp://example.com/' }),
    request('an address that is not text', { method: 'GET', url: 5 }),
    request('a method with a space', { method: 'GET X', url: 'https://example.com/' }),
    request('an empty method', { method: '', url: 'https://example.com/' }),
    request('no method', { url: 'https://example.com/' }),
    request('a body that is text', { method: 'POST', url: 'https://example.com/', bodyText: 'hello' }),
    request('a body of null is no body', { method: 'POST', url: 'https://example.com/', body: null }),
    request('a body that is a number', { method: 'POST', url: 'https://example.com/', body: 5 }),
    { name: 'a request that is not an object', kind: 'request', input: 'GET /' },
    response('a 200 answer with a body', { status: 200, bodyHex: hello }),
    response('a 204 answer with no body', { status: 204 }),
    response('a 200 answer with an empty body', { status: 200, bodyHex: '' }),
    response('the lowest status', { status: 100 }),
    response('the highest status', { status: 599 }),
    response('a status below 100', { status: 99 }),
    response('a status above 599', { status: 600 }),
    response('a status written as text', { status: '200' }),
    response('a status with a fraction', { status: 200.5 }),
    response('no status', {}),
    response('a status of true', { status: true }),
    response('a 404 answer whose body is null', { status: 404, body: null }),    identifier('a trace-id', '4bf92f3577b34da6a3ce929d0e0e4736'),
    identifier('an identifier a platform gave', 'toolu_01AbCdEf'),
    identifier('an error text with a line feed and a letter outside ASCII', 'Tool failed:\nfichier introuvable é \u{1F600}'),
    identifier('one character', 'x'),
    identifier('an empty identifier', ''),
    identifier('a lone surrogate', 'a\ud800b'),
    identifier('a number', 42),
  ];
}

function countersignatureContents() {
  const fp = toBase64url(new Uint8Array(32).fill(1));
  const base = { type: 'provared.countersignature.v0', stub: fp, when: '2026-10-05T09:00:00Z' };
  return [
    ['a countersignature', base],
    ['no stub', { type: base.type, when: base.when }],
    ['an extra member', { ...base, note: 'x' }],
    ['a bad time', { ...base, when: 'yesterday' }],
  ].map(([name, content]) => ({ name, content }));
}

function originCases() {
  // A fixed sequence of random choices, so that the file is the same each time.
  let seed = 20261008;
  const next = () => {
    seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
    return seed / 2 ** 32;
  };
  const pick = (items) => items[Math.floor(next() * items.length)];
  const schemes = ['https', 'http', 'wss', 'ws', 'ftp', 'file', 'foo', 'HTTPS', 'Http', 'blob:https', 'data'];
  const characters = 'abcz019-._!"$&\'()*+,;=`{}~ABZ%@#/:?[]\\ ^|<>éßİK。．\u0000\t';
  const labels = ['example', 'org', 'sign', 'a', 'xn--bcher-kva', 'xn--zca', 'xn--ss-', 'xn--a', 'xn--', 'xn--ls8h', 'xn--55qx5d', 'xn--1ch', '0', '09', '255', '256', '0x1f', '0x', '1e3', 'localhost', ''];
  const ipv6 = ['[::1]', '[::]', '[0:0:0:0:0:0:0:1]', '[2001:db8::1]', '[2001:DB8::1]', '[2001:db8:0:0:1:0:0:1]', '[2001:db8::1:0:0:1]', '[1:0:0:2:0:0:0:3]', '[1::2:0:0:0:3]', '[::ffff:192.0.2.1]', '[::ffff:c000:201]', '[1:2:3:4:5:6:7:8]', '[1:2:3:4:5:6:7::]', '[1:2:3:4:5:6::8]', '[::1%25eth0]', '[0001::1]', '[1::0:1]'];
  const cases = new Set([
    'https://example.org', 'https://sign.example.org', 'https://sign.example.org:8443', 'http://localhost', 'http://localhost:8787',
    'http://localhost:80', 'https://example.org:443', 'https://xn--bcher-kva.example', 'https://sign.xn--bcher-kva.example',
    'https://-a.example.org', 'https://a-.example.org', 'https://a--b.example.org', 'https://' + 'a'.repeat(63) + '.example.org',
    'https://' + 'a'.repeat(64) + '.example.org', 'https://example.123', 'https://123.example.org', 'https://192.0.2.1',
    'https://example.org.', 'https://.example.org', 'https://a..example.org', 'https://example.org:0', 'https://example.org:65535',
    'https://example.org:65536', 'https://example.org:080', 'https://Example.org', 'https://a_b.example.org',
  ]);
  for (let i = 0; i < 4000; i++) {
    let host;
    const shape = next();
    if (shape < 0.1) host = pick(ipv6);
    else if (shape < 0.25) host = Array.from({ length: 4 }, () => pick(['0', '1', '9', '10', '99', '192', '255', '256', '01', '0x10'])).slice(0, 2 + Math.floor(next() * 4)).join('.');
    else if (shape < 0.6) host = Array.from({ length: 1 + Math.floor(next() * 4) }, () => pick(labels)).join('.');
    else {
      host = '';
      const n = 1 + Math.floor(next() * 12);
      for (let j = 0; j < n; j++) host += next() < 0.7 ? pick('abcz019.-') : characters[Math.floor(next() * characters.length)];
    }
    let port = '';
    const p = next();
    if (p < 0.15) port = ':' + pick(['0', '80', '443', '21', '8443', '08443', '65535', '65536', '', '1a', '99999']);
    let tail = '';
    if (next() < 0.08) tail = pick(['/', '/x', '?a', '#a', ' ', '\n', '.']);
    let user = next() < 0.04 ? pick(['u@', 'u:p@', '@']) : '';
    cases.add(`${pick(schemes)}://${user}${host}${port}${tail}`);
  }
  // The website name: mostly the end of the address's own host, so that the
  // rule's other parts are reached; sometimes one that does not fit.
  const rpIdFor = (text, i) => {
    const host = /^[A-Za-z]+:\/\/([^:/?#]*)/.exec(text);
    const labels = host ? host[1].split('.').filter(Boolean) : [];
    if (i % 5 === 4 || labels.length === 0) return 'example.org';
    return labels.slice(-(1 + (i % 2))).join('.');
  };
  return [...cases].map((text, i) => ({ name: JSON.stringify(text), text, rpId: rpIdFor(text, i) }));
}

/** Each set of cases, by the name of its file. */
export const CASES = {
  'canonical-json': () => set('Reading JSON that must be in the canonical form (format description, section 3.4).', 'parseCanonical', encodingCases()),
  base64url: () => set('Reading base64url strictly (format description, section 3.3).', 'fromBase64url', base64urlCases()),
  times: () => set('Reading a time (format description, section 3.6): milliseconds since 1970, or null.', 'parseTime', timeCases()),
  characters: () => set('Counting the characters of a text, as Unicode code points.', 'countCharacters', countCases()),
  keys: async () => set('Confirming the shape of a public key, and its thumbprint (format description, section 3.8).', 'checkKey', await keyCases()),
  'ecdsa-der': () => set("Reading a passkey's ES256 signature from its DER form (format description, section 4.4).", 'ecdsaDerToRaw', derCases()),
  'ed25519-signatures': async () =>
    set(
      'Checking an Ed25519 signature under a key (format description, section 3.8): the cases of the paper "Taming the many EdDSAs" (Chalkias, Garillot, Kondi and Nikolaenko, 2020), and cases made here, each with the answer the format\'s rules give, so that the rules are pinned and not the library beneath.',
      'checkEd25519Signature',
      await ed25519Cases(),
    ),
  records: async () => set('Reading the envelope of a record as a given kind (format description, sections 3.1 to 3.5).', 'parseRecord', await recordCases()),
  'stub-contents': () => set("Confirming the members of a stub's content (format description, section 5.1).", 'validateStubContent', stubContents()),
  'http-fingerprints': () =>
    set(
      'The reserved document names, and the texts their fingerprints are made from (format description, section 27): an HTTP request or answer written as the signature base of RFC 9421, section 2.5, and an identifier exactly as given. A body is written in hexadecimal.',
      'documentFingerprint',
      documentCases(),
    ),
  'countersignature-contents': () => set("Confirming the members of a countersignature's content (format description, section 6).", 'validateCountersignatureContent', countersignatureContents()),
  origins: () => set('Whether a slip\'s "issuer.origin" is a page address as the format allows, on the website its "issuer.rpId" names (format description, section 4.1).', 'checkOrigin', originCases()),
  slips: async () => set('Checking one slip (format description, section 4.4), with what the checker is told to trust.', 'checkSlip', await slipCases()),
  ...stamps.CASES,
  ...records.CASES,
  ...book.CASES,
  ...recorder.CASES,
  ...witness.CASES,
  ...sealer.CASES,
};
