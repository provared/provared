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
