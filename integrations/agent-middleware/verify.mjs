// Checks the signature on a record of the project "Agent Middleware" (AMW):
// a permit, or a receipt, in the envelope form AMW publishes.
//
// This file was written from AMW's published test data alone (the files
// under test/vectors/, read as data) and from the published standards: RFC
// 8032 for Ed25519 and FIPS 186 with RFC 5480 for ECDSA on P-256. No AMW
// program was read or run. So the rules below are the rules that give
// every expected answer in that data, and nothing more: where AMW's own
// verifier does something the data does not show, this file may differ,
// and the README says so.
//
// An AMW record is the gateway's own signed statement. Checking its
// signature shows that the key named signed exactly this text, and nothing
// else: not that the gateway told the truth, not that no other record was
// left out, and not that any person agreed to anything. The judgement
// against a Provared permission is in judge.mjs.

import { createPublicKey, verify as cryptoVerify } from 'node:crypto';

/** The six answers, AMW's own words for them, as its published test data uses them. */
export const STATUSES = ['verified', 'invalid', 'mismatch', 'unknown_key', 'malformed', 'unsupported'];

/** The one canonical form of AMW's receipt contract that this reader accepts. */
export const CANONICAL_FORM = 'awi-canonical-json/1';

/** The one signing method AMW's permit and receipt contracts accept. */
export const SIGNING_METHOD = 'Ed25519';

/** A key with one of these statuses may still be used to check a signature. Any other status ("disabled", or a word this reader does not know) may not. */
export const USABLE_KEY_STATUSES = ['active', 'retired'];

// The order of the Ed25519 group: a signature's second half, S, must be
// below it (RFC 8032, section 5.1.7), or the same signature has more than
// one valid encoding.
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

const ENVELOPE_ID = { receipt: 'receipt_id', permit: 'permit_id' };

const isText = (v) => typeof v === 'string';
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// Strict base64: only the one spelling of the bytes is accepted, with its
// padding. "AAAA" is 3 bytes; "!!!!" is nothing.
function fromBase64(text) {
  if (!isText(text) || text.length === 0 || text.length % 4 !== 0) return null;
  const bytes = Buffer.from(text, 'base64');
  return bytes.toString('base64') === text ? bytes : null;
}

function fromBase64url(text) {
  if (!isText(text) || text.length === 0) return null;
  const bytes = Buffer.from(text, 'base64url');
  return bytes.toString('base64url') === text ? bytes : null;
}

// The id is given back only for a record that verified: the envelope's id
// is not signed, and the signed content's is shown only once the signature
// fits. A record that failed is known by its place in what was handed over.
function answer(kind, status, reason, more = {}) {
  const out = { kind, status, reason, id: null, key: null, content: null, ...more };
  if (status !== 'verified') out.id = null;
  return out;
}

// True where some object in the JSON text names one member twice. JSON.parse
// keeps the last of them silently, so two readers could take two meanings
// from one signed text. The text has already been read by JSON.parse, so it
// is well-formed JSON here; member names are compared as JSON.parse reads
// them ("a" and "\u0061" are one name).
function hasRepeatedName(text) {
  const stack = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '{') stack.push({ names: new Set(), expectName: true });
    else if (ch === '[') stack.push(null);
    else if (ch === '}' || ch === ']') stack.pop();
    else if (ch === ',') {
      const top = stack[stack.length - 1];
      if (top) top.expectName = true;
    } else if (ch === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const top = stack[stack.length - 1];
      if (top && top.expectName) {
        const name = JSON.parse(text.slice(i, j + 1));
        if (top.names.has(name)) return true;
        top.names.add(name);
        top.expectName = false;
      }
      i = j;
    }
  }
  return false;
}

/**
 * The list of AMW keys, as the published file gives it: {"keys": [...]}, or
 * the list itself. Each key has "kid", "alg", "status", and the public key
 * as "public_key_b64" (standard base64) or "jwk", or both.
 * @param {unknown} keys
 * @returns {object[]}
 */
export function readKeys(keys) {
  const list = isObject(keys) && Object.hasOwn(keys, 'keys') ? keys.keys : keys;
  if (!Array.isArray(list)) throw new TypeError('The AMW keys must be a list, or an object holding one as "keys".');
  for (const entry of list) {
    if (!isObject(entry) || !isText(entry.kid)) throw new TypeError('Each AMW key must be an object with a text "kid".');
  }
  return list;
}

// The public key of one entry, in a form Node.js can check with. A raw
// Ed25519 key of exactly 32 bytes in "public_key_b64" is used if present;
// otherwise the JSON Web Key. (From the published data: a raw key of the
// wrong length is set aside for the JSON Web Key; a raw key of the right
// length is used even where the JSON Web Key differs.)
function keyMaterial(entry) {
  if (entry.alg === SIGNING_METHOD) {
    let raw = fromBase64(entry.public_key_b64);
    if (!raw || raw.length !== 32) {
      const jwk = entry.jwk;
      raw = isObject(jwk) && jwk.kty === 'OKP' && jwk.crv === SIGNING_METHOD ? fromBase64url(jwk.x) : null;
      if (!raw || raw.length !== 32) return null;
    }
    return { method: SIGNING_METHOD, publicKey: createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') }, format: 'jwk' }) };
  }
  if (entry.alg === 'ECDSA-P256-SHA256') {
    const der = fromBase64(entry.public_key_b64);
    if (!der) return null;
    let publicKey;
    try {
      publicKey = createPublicKey({ key: der, format: 'der', type: 'spki' });
    } catch {
      return null;
    }
    if (publicKey.asymmetricKeyType !== 'ec' || publicKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return null;
    return { method: 'ECDSA-P256-SHA256', publicKey };
  }
  return { method: isText(entry.alg) ? entry.alg : null, publicKey: null };
}

/**
 * Check one AMW record: the signature in its envelope, against the key its
 * content names, and the envelope against the content.
 *
 * The answer's "status" is one of STATUSES, in this order of precedence
 * (the first that applies):
 *
 * - "malformed": not an envelope: no id, "kid", "signing_input" or
 *   "signature" as text; "signing_input" not well-formed Unicode text, not
 *   a JSON object, or naming one member twice in one object; the content's
 *   "kid" present and not text; "signature" not strict base64, or not of
 *   the length the key's method needs;
 * - "unknown_key": the key named is not in the list, or its status allows
 *   no use (anything but "active" or "retired"), or its public key cannot
 *   be read;
 * - "unsupported": the key's method is one this reader cannot check;
 * - "invalid": the signature does not fit the key over the exact bytes of
 *   "signing_input";
 * - "unsupported": the signature fits, but the key's own method is not
 *   Ed25519 (a P-256 key), or the content names a signing method other than
 *   Ed25519, or a canonical form other than awi-canonical-json/1, so the
 *   record is outside the contract;
 * - "mismatch": the signature fits, but the envelope's id, "kid", "alg" or
 *   "canonicalization" differs from what the content says;
 * - "verified".
 *
 * The key is found by the "kid" in the signed content where it has one,
 * else by the envelope's; an envelope "kid" that differs from the content's
 * is a mismatch. The content and the id are given back only when the
 * record is verified: what a record that failed says is not shown as fact,
 * and its envelope id is not signed.
 *
 * @param {unknown} bundle the AMW envelope: {receipt_id or permit_id, kid, alg, canonicalization?, signing_input, signature}
 * @param {unknown} keys the published key list (see readKeys)
 * @param {'receipt'|'permit'} [kind]
 * @returns {{kind: string, status: string, reason: string, id: string|null, key: {kid: string, alg: string|null, status: string|null}|null, content: object|null}}
 */
export function verifyRecord(bundle, keys, kind = 'receipt') {
  if (!Object.hasOwn(ENVELOPE_ID, kind)) throw new TypeError('kind must be "receipt" or "permit".');
  const list = readKeys(keys);
  const idName = ENVELOPE_ID[kind];

  if (!isObject(bundle)) return answer(kind, 'malformed', 'The record is not an object.');
  const id = isText(bundle[idName]) && bundle[idName].length > 0 ? bundle[idName] : null;
  if (id === null) return answer(kind, 'malformed', `The envelope has no "${idName}".`);
  if (!isText(bundle.kid) || bundle.kid.length === 0) return answer(kind, 'malformed', 'The envelope has no "kid".', { id });
  if (!isText(bundle.signing_input)) return answer(kind, 'malformed', 'The envelope has no "signing_input" text.', { id });
  if (!isText(bundle.signature)) return answer(kind, 'malformed', 'The envelope has no "signature" text.', { id });
  if (Object.hasOwn(bundle, 'alg') && !isText(bundle.alg)) return answer(kind, 'malformed', 'The envelope\'s "alg" is not text.', { id });
  if (Object.hasOwn(bundle, 'canonicalization') && !isText(bundle.canonicalization)) return answer(kind, 'malformed', 'The envelope\'s "canonicalization" is not text.', { id });
  // A text with a lone surrogate is not Unicode text: it has no one UTF-8
  // form, and two texts that differ only there are signed as the same bytes.
  if (!bundle.signing_input.isWellFormed()) return answer(kind, 'malformed', 'The "signing_input" is not well-formed Unicode text.', { id });

  let content;
  try {
    content = JSON.parse(bundle.signing_input);
  } catch {
    return answer(kind, 'malformed', 'The "signing_input" is not JSON.', { id });
  }
  if (!isObject(content)) return answer(kind, 'malformed', 'The "signing_input" is not a JSON object.', { id });
  if (hasRepeatedName(bundle.signing_input)) return answer(kind, 'malformed', 'The "signing_input" names one member twice in one object.', { id });
  if (Object.hasOwn(content, 'kid') && !isText(content.kid)) return answer(kind, 'malformed', 'The signed content\'s "kid" is not text.', { id });

  const signature = fromBase64(bundle.signature);
  if (!signature) return answer(kind, 'malformed', 'The "signature" is not strict base64.', { id });

  const kid = Object.hasOwn(content, 'kid') ? content.kid : bundle.kid;
  const entry = list.find((k) => k.kid === kid);
  if (!entry) return answer(kind, 'unknown_key', 'The key the record names is not in the key list.', { id });
  const key = { kid: entry.kid, alg: isText(entry.alg) ? entry.alg : null, status: isText(entry.status) ? entry.status : null };
  if (!USABLE_KEY_STATUSES.includes(entry.status)) {
    return answer(kind, 'unknown_key', `The key the record names has the status "${key.status === null ? '' : key.status.replace(/[^a-z0-9_-]/gi, '?')}", which allows no use.`, { id, key });
  }
  const material = keyMaterial(entry);
  if (!material) return answer(kind, 'unknown_key', 'The public key of the key the record names cannot be read.', { id, key });
  if (!material.publicKey) return answer(kind, 'unsupported', 'The key\'s signing method is not one this reader can check.', { id, key });

  const data = Buffer.from(bundle.signing_input, 'utf8');
  let fits;
  if (material.method === SIGNING_METHOD) {
    if (signature.length !== 64) return answer(kind, 'malformed', 'An Ed25519 signature is 64 bytes.', { id, key });
    // S below L (RFC 8032, section 5.1.7); S is the second half, little-endian.
    const S = BigInt('0x' + Buffer.from(signature.subarray(32)).reverse().toString('hex'));
    fits = S < L && cryptoVerify(null, data, material.publicKey, signature);
  } else {
    try {
      fits = cryptoVerify('sha256', data, { key: material.publicKey, dsaEncoding: 'der' }, signature);
    } catch {
      return answer(kind, 'malformed', 'The signature is not in the form the key\'s method needs.', { id, key });
    }
  }
  if (!fits) return answer(kind, 'invalid', 'The signature does not fit the key over the signed text.', { id, key });

  // The signature fits. Is the record within the contract this reader knows?
  // The key's own method comes first: a P-256 key is outside the contract
  // whatever method the content or the envelope names, so a P-256 signature
  // over content that says "Ed25519" is not verified.
  if (material.method !== SIGNING_METHOD) return answer(kind, 'unsupported', 'The key named signs with a method other than Ed25519, the one method of the contract.', { id, key });
  if (content.alg !== SIGNING_METHOD) return answer(kind, 'unsupported', 'The content names a signing method other than Ed25519.', { id, key });
  const contentForm = Object.hasOwn(content, 'canonicalization') ? content.canonicalization : CANONICAL_FORM;
  if (contentForm !== CANONICAL_FORM) return answer(kind, 'unsupported', 'The content names a canonical form other than awi-canonical-json/1.', { id, key });

  // Does the envelope say what the content says?
  if (content[idName] !== id) return answer(kind, 'mismatch', `The envelope's "${idName}" is not the one in the signed content.`, { id, key });
  if (bundle.kid !== kid) return answer(kind, 'mismatch', 'The envelope\'s "kid" is not the one in the signed content.', { id, key });
  if (Object.hasOwn(bundle, 'alg') && bundle.alg !== content.alg) return answer(kind, 'mismatch', 'The envelope\'s "alg" is not the one in the signed content.', { id, key });
  if (Object.hasOwn(bundle, 'canonicalization') && bundle.canonicalization !== contentForm) {
    return answer(kind, 'mismatch', 'The envelope\'s "canonicalization" is not the one the signed content was written in.', { id, key });
  }

  return answer(kind, 'verified', 'The signature fits the key named, over the signed text, and the envelope says what the content says.', { id, key, content });
}
