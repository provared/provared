// How a command knows that it is talking to the executor before it sends
// the administrator's secret (DESIGN.md, X138).
//
// The commands "seal", "acknowledge" and "status" ask a running executor
// over plain HTTP at the address the settings name. Whatever listens there
// would be handed the secret. So the command first sends a challenge, 32
// random bytes it has just made, to POST /provared/hello, with no secret.
// The executor answers with two signatures, by the two keys of its own key
// set (Ed25519 and ML-DSA-87, the keys it countersigns with), over this
// text and nothing else:
//
//   provared-mcp-executor hello v1\n<challenge>\n<address>\n<port>\n
//
// <challenge> is the 43 characters of base64url the command sent; <address>
// and <port> are where the executor received the request. The command
// checks both signatures against the public keys in the executor's key
// file, which it reads itself, and checks that the address and port are
// the ones it connected to, so that an answer fetched from the executor by
// a program in the middle does not pass. Only then does it send the secret,
// on the same connection.
//
// The text can never be what a signature on a record covers: every record
// is signed over two runs of base64url joined by a full stop (format
// description, section 3), and this text holds spaces and line feeds. So
// the address cannot be used to have the executor sign a countersignature.
// No primitive is new: the signatures are made by the library's signers for
// the key file, and checked with the same Web Crypto methods the library
// uses.
//
// The command needs the executor's public keys and no private key
// (X166). It takes them from the executor's key file, of which it uses the
// public parts alone, or from a file of the public keys alone, which
// "keys --public-keys <file>" writes and "--public-keys <file>" names: the
// form of a key file, {"about": …, "keys": [Ed25519, ML-DSA-87]}, with no
// private part in it.

import { readFileSync } from 'node:fs';
import { fromBase64url, toBase64url, utf8 } from 'provared';

/** The first line of the text the executor signs. */
export const HELLO = 'provared-mcp-executor hello v1';
/** A challenge: 32 bytes in base64url. */
export const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const METHODS = ['Ed25519', 'ML-DSA-87'];

/** An address as both ends write it: an IPv4 address reached over IPv6 is the IPv4 address. */
export function plainAddress(address) {
  return typeof address === 'string' ? address.replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/i, '') : '';
}

/** What the file of the executor's public keys says about itself. */
export const PUBLIC_KEYS_ABOUT = 'The public keys of the executor: what "status", "seal" and "acknowledge" check a running executor\'s signatures against (--public-keys). It holds no private key and is no secret. Keep it where only the administrator can change it.';

/** The public part of a key in a key file, with nothing else of it; null where it is not a key of that method. */
function publicPart(jwk, alg) {
  if (jwk === null || typeof jwk !== 'object') return null;
  if (alg === 'Ed25519') return jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && typeof jwk.x === 'string' ? { alg, crv: 'Ed25519', kty: 'OKP', x: jwk.x } : null;
  return jwk.kty === 'AKP' && jwk.alg === alg && typeof jwk.pub === 'string' ? { alg, kty: 'AKP', pub: jwk.pub } : null;
}

/**
 * The executor's two public keys, read from a file: the executor's own key
 * file, or a file of its public keys alone (X166). Only the public parts
 * are taken, and no private key is loaded, so a file with none will do.
 * Throws, in plain words, where the file cannot be read or holds no usable
 * keys: each key must be one that a signature can be checked with.
 * @param {string} path
 * @returns {Promise<object[]>} the public keys (Ed25519, then ML-DSA-87)
 */
export async function readPublicKeys(path) {
  let jwks;
  try {
    jwks = JSON.parse(readFileSync(path, 'utf8').replace(/^﻿/, ''))?.keys;
  } catch (e) {
    throw new Error(`The key file ${path} could not be read (${e.code ?? 'it is not JSON'}).`);
  }
  const keys = Array.isArray(jwks) && jwks.length === METHODS.length ? METHODS.map((alg, i) => publicPart(jwks[i], alg)) : [null];
  let usable = keys.every((key) => key !== null);
  try {
    if (usable) for (const key of keys) await globalThis.crypto.subtle.importKey('jwk', key, { name: key.alg }, false, ['verify']);
  } catch {
    usable = false;
  }
  if (!usable) throw new Error(`The file ${path} holds no usable keys of the executor. It must hold the executor's two public keys, ${METHODS.join(' and then ')}: the file that "provared-mcp-executor keys --public-keys <file>" writes, or the executor's own key file.`);
  return keys;
}

function helloBytes(challenge, address, port) {
  return utf8(`${HELLO}\n${challenge}\n${plainAddress(address)}\n${port}\n`);
}

/**
 * The executor's answer to a challenge: its two signatures, in base64url,
 * in the order of its key set.
 * @param {{sign: (data: Uint8Array) => Promise<Uint8Array>}[]} signers the executor's private keys, as its key file gives them
 * @param {string} challenge 43 characters of base64url
 * @param {string} address where the request was received
 * @param {number} port
 */
export async function identify(signers, challenge, address, port) {
  if (!CHALLENGE.test(challenge)) throw new Error('The challenge must be 32 bytes in base64url.');
  const bytes = helloBytes(challenge, address, port);
  const signatures = [];
  for (const signer of signers) signatures.push(toBase64url(await signer.sign(bytes)));
  return signatures;
}

/**
 * Whether an answer is the executor's: both signatures check under the
 * executor's public keys, over the challenge the command sent and the
 * address and port it connected to.
 * @param {object[]} keys the executor's public keys (Ed25519, then ML-DSA-87)
 * @param {string} challenge
 * @param {string} address
 * @param {number} port
 * @param {any} signatures what the listener answered
 */
export async function checkIdentity(keys, challenge, address, port, signatures) {
  if (!Array.isArray(keys) || keys.length !== METHODS.length || !Array.isArray(signatures) || signatures.length !== METHODS.length) return false;
  const bytes = helloBytes(challenge, address, port);
  try {
    for (const [i, alg] of METHODS.entries()) {
      if (keys[i]?.alg !== alg || typeof signatures[i] !== 'string') return false;
      const key = await globalThis.crypto.subtle.importKey('jwk', keys[i], { name: alg }, false, ['verify']);
      if (!(await globalThis.crypto.subtle.verify({ name: alg }, key, fromBase64url(signatures[i]), bytes))) return false;
    }
    return true;
  } catch {
    return false;
  }
}
