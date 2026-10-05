// Made-up block time-stamps, for tests. A proof is written in the layout of
// the open format (version 1 of its proof file), and leads to a block
// header that is made up here: no block of any real chain is involved, and
// nothing is sent anywhere.

import { blockFingerprint } from '../../src/blockstamp.js';
import { concatBytes, sha256, toBase64url, utf8 } from '../../src/encoding.js';

const MAGIC = concatBytes(new Uint8Array([0x00]), utf8('OpenTimestamps'), new Uint8Array([0x00, 0x00]), utf8('Proof'), new Uint8Array([0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]));
const BLOCK_MARK = new Uint8Array([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]);
const PENDING_MARK = new Uint8Array([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);

/** A whole number as the format writes it. */
export function number(n) {
  const out = [];
  do {
    const low = n % 128;
    n = Math.floor(n / 128);
    out.push(n > 0 ? low | 0x80 : low);
  } while (n > 0);
  return new Uint8Array(out);
}
const bytes = (...values) => new Uint8Array(values);
const random = (length) => globalThis.crypto.getRandomValues(new Uint8Array(length));
const withLength = (data) => concatBytes(number(data.length), data);
export const joinAfter = (data) => concatBytes(bytes(0xf0), withLength(data));
export const joinBefore = (data) => concatBytes(bytes(0xf1), withLength(data));
export const SHA256 = bytes(0x08);
export const blockStatement = (height) => concatBytes(bytes(0x00), BLOCK_MARK, withLength(number(height)));
export const pendingStatement = (text) => concatBytes(bytes(0x00), PENDING_MARK, withLength(withLength(utf8(text))));
/** The start of a proof file for a fingerprint. */
export const start = (fingerprintBytes) => concatBytes(MAGIC, bytes(0x01, 0x08), fingerprintBytes);

/** A made-up block header that holds a Merkle root and states a time. */
export function header(root, timeMs) {
  const seconds = Math.floor(timeMs / 1000);
  const out = new Uint8Array(80);
  out.set([0x00, 0x00, 0x00, 0x20], 0);
  out.set(random(32), 4);
  out.set(root, 36);
  out.set([seconds & 0xff, (seconds >>> 8) & 0xff, (seconds >>> 16) & 0xff, (seconds >>> 24) & 0xff], 68);
  out.set(random(8), 72);
  return out;
}

/**
 * Make a block time-stamp for a fingerprint: a proof of a few steps, and a
 * made-up block that states the time given.
 *
 * @param {Uint8Array} fingerprintBytes what is stamped
 * @param {number} timeMs the time the made-up block states
 * @param {object} [change]
 * @param {boolean} [change.pending] also hold a statement that the proof is not yet complete, as a real one may
 * @param {number} [change.height] the block's number, as the proof states it
 * @returns {Promise<{proof: Uint8Array, header: Uint8Array, item: {block: string, proof: string}, fingerprint: string}>}
 */
export async function makeBlockStamp(fingerprintBytes, timeMs, change = {}) {
  // The steps a real proof takes: join a random value, hash, then go up a
  // tree by joining a neighbour on one side or the other and hashing twice.
  const nonce = random(16);
  const left = random(32);
  const right = random(32);
  let value = await sha256(concatBytes(fingerprintBytes, nonce));
  const steps = [joinAfter(nonce), SHA256];
  const branch = change.pending ? [bytes(0xff), pendingStatement('https://calendar.example')] : [];
  value = await sha256(await sha256(concatBytes(left, value)));
  steps.push(...branch, joinBefore(left), SHA256, SHA256);
  value = await sha256(await sha256(concatBytes(value, right)));
  steps.push(joinAfter(right), SHA256, SHA256);
  const proof = concatBytes(start(fingerprintBytes), ...steps, blockStatement(change.height ?? 912345));
  const head = header(value, timeMs);
  return { proof, header: head, item: { block: toBase64url(head), proof: toBase64url(proof) }, fingerprint: await blockFingerprint(head) };
}
