// The Seal: whoever keeps a book signs its top fingerprint and its number of
// entries, and an outside time-stamp service states when that was.
// Format description, section 21.

import { Refusal, fingerprint, formatTime, fromBase64url, randomId, toBase64url, utf8 } from './encoding.js';
import * as f from './fields.js';
import { KINDS, encodeContent, protectedHeaders, signingInput, withinSize } from './jws.js';
import { SEAL_METHODS, checkSealKeySet } from './keys.js';
import { sign } from './signatures.js';
import { MAX_STAMP_BYTES } from './timestamp.js';
import { treeRoot } from './tree.js';

/** The most time-stamps one seal may carry. */
export const MAX_STAMPS = 4;

/**
 * How far a clock may differ, in milliseconds. A seal may be dated up to this
 * much after its time-stamp, and an entry up to this much after the
 * time-stamp that covers it, before the checker reports it.
 */
export const CLOCK_ALLOWANCE_MS = 300 * 1000;

/**
 * Confirm every member of a seal's content.
 * @param {any} c
 */
export function validateSealContent(c) {
  f.members(c, ['by', 'id', 'root', 'size', 'type', 'when'], ['previous'], 'seal');
  f.id(c.id, 'id');
  f.members(c.by, ['keys', 'name'], [], 'by');
  f.label(c.by.name, 'by.name');
  checkSealKeySet(c.by.keys, 'by.keys');
  f.wholeNumber(c.size, 'size');
  if (c.size < 1) throw f.fail('size', 'must be 1 or more.');
  f.fingerprintText(c.root, 'root');
  if (Object.hasOwn(c, 'previous')) f.fingerprintText(c.previous, 'previous');
  f.time(c.when, 'when');
}

/**
 * Confirm the time-stamps that sit beside a seal or a cancellation in an
 * entry, and decode them. A time-stamp from a service is text: the
 * service's answer in base64url. A block time-stamp is an object: the
 * proof and the header of its block, each in base64url.
 * @param {any} stamps
 * @returns {({kind: 'service', token: Uint8Array}|{kind: 'block', proof: Uint8Array, header: Uint8Array})[]}
 */
export function decodeStamps(stamps) {
  f.list(stamps, 1, MAX_STAMPS, 'stamps');
  const seen = new Set();
  const items = [];
  // Every place in the list is read by its number, a gap included, so that a gap is refused as an empty
  // place, not skipped; a list's own way of walking through itself is not used.
  for (let i = 0; i < stamps.length; i++) {
    const s = stamps[i];
    const path = `stamps[${i}]`;
    const decode = (text, most, what) => {
      if (typeof text !== 'string' || text.length === 0 || text.length > Math.ceil((most * 4) / 3)) throw f.fail(path, what);
      try {
        return fromBase64url(text);
      } catch {
        throw new Refusal('bad-base64url', 'A time-stamp is not base64url.');
      }
    };
    let item;
    let key;
    if (s !== null && typeof s === 'object' && !Array.isArray(s)) {
      f.members(s, ['block', 'proof'], [], path);
      item = {
        kind: 'block',
        header: decode(s.block, 1024, 'must hold a block header of 80 bytes, in base64url.'),
        proof: decode(s.proof, MAX_STAMP_BYTES, 'must hold a proof in base64url, of at most 12,288 bytes.'),
      };
      key = `${s.block} ${s.proof}`;
    } else {
      item = { kind: 'service', token: decode(s, MAX_STAMP_BYTES, 'must be a time-stamp in base64url, of at most 12,288 bytes.') };
      key = s;
    }
    if (seen.has(key)) throw f.fail('stamps', 'the same time-stamp is given twice.');
    seen.add(key);
    items.push(item);
  }
  return items;
}

/**
 * The fingerprint of a recorder's key set: how a person checking says which
 * recorder they expect. It is the fingerprint of the list of keys, written
 * in the canonical form.
 * @param {object[]} keys a key set that has passed its check
 * @returns {Promise<string>}
 */
export async function keySetFingerprint(keys) {
  return fingerprint(encodeContent(keys).contentBytes);
}

/**
 * Seal a book as it stands: sign its top fingerprint and its number of
 * entries. The seal is then added to the book as its next entry, with any
 * time-stamps beside it.
 *
 * @param {string} book the book so far
 * @param {object} fields
 * @param {{keys: object[], name: string}} fields.by the recorder's public key set and its name (a label)
 * @param {string} [fields.previous] the fingerprint of the seal before this one in the book, if there is one
 * @param {number|Date} [fields.when] defaults to now
 * @param {any[]} privateKeys the recorder's private keys, in the order of the key set
 * @returns {Promise<{record: object, fingerprint: string, fingerprintBytes: Uint8Array}>}
 *   "fingerprintBytes" is what a time-stamp service is asked to stamp
 */
export async function writeSeal(book, fields, privateKeys) {
  const lines = book.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  const content = {
    type: KINDS.seal.type,
    id: fields.id ?? randomId(),
    by: fields.by,
    size: lines.length,
    root: toBase64url(await treeRoot(lines.map(utf8))),
    when: formatTime(fields.when ?? Date.now()),
  };
  if (fields.previous) content.previous = fields.previous;
  validateSealContent(content);
  const { contentBytes, payloadB64 } = encodeContent(content);
  const headers = protectedHeaders('seal');
  const signatures = [];
  for (let i = 0; i < SEAL_METHODS.length; i++) {
    const signature = await sign(SEAL_METHODS[i], privateKeys[i], signingInput(headers[i], payloadB64));
    signatures.push({ protected: headers[i], signature: toBase64url(signature) });
  }
  const name = await fingerprint(contentBytes);
  return { record: withinSize({ payload: payloadB64, signatures }), fingerprint: name, fingerprintBytes: fromBase64url(name) };
}
