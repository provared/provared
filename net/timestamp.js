// Asking a time-stamp service for a time-stamp over a seal's fingerprint
// (RFC 3161, sections 2.4 and 3.4): the second file in this package that
// makes a network request. The library (src/) never does. A program that
// seals hands the function stampService gives to the library's openSealer
// as its "stamp", or calls askForStamp itself.
//
// Only the service whose address the caller gives is asked; none is named
// here or anywhere in this package. What is sent is the request of RFC
// 3161, section 2.4.1: the seal's fingerprint (SHA-256, 32 bytes), a
// random number used once, and a request for the service's certificate.
// The service sees that fingerprint, this device's address and the time it
// was asked; nothing else. The answer is read up to a limit and within a
// time limit, a redirect is not followed, and what comes back is checked by
// the library's own checkStamp before it is handed on: a service can refuse
// or fall silent, but cannot have a time-stamp kept that is laid out
// wrongly, made for something else, or signed with a key that does not fit
// its certificate.

import { TAG, children, contentOf, expect, readElement, wholeOf } from '../src/der.js';
import { Refusal, equalBytes, toBase64url } from '../src/encoding.js';
import { MAX_STAMP_BYTES, checkStamp } from '../src/timestamp.js';

/** How long one request may take, unless the caller says otherwise, and the least and the most it may say: milliseconds. */
export const STAMP_TIMEOUT_MS = 10000;
export const STAMP_TIMEOUT_MIN_MS = 100;
export const STAMP_TIMEOUT_MAX_MS = 60000;
/** The largest answer read: a time-stamp of the largest size the format allows, and room for the status beside it. */
export const MAX_REPLY_BYTES = MAX_STAMP_BYTES + 256;
/** The furthest the time a time-stamp states may be from this device's clock, in milliseconds. */
export const STAMP_CLOCK_GAP_MS = 300000;
/** How many random bytes the number used once holds: 64 bits, as RFC 3161, section 2.4.1, gives as its example. */
export const NONCE_BYTES = 8;

// SHA-256, named with no parameters, as RFC 5754, section 2, says a writer MUST.
const SHA256 = Uint8Array.of(0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01);
const CERT_REQ_TRUE = Uint8Array.of(0x01, 0x01, 0xff);
// The statuses of RFC 3161, section 2.4.2, and the reasons of a refusal (PKIFailureInfo), by their bit.
const STATUS = ['granted', 'granted with changes', 'refused', 'waiting', 'a warning that its certificate is about to be withdrawn', 'its certificate was withdrawn'];
const FAILURE = { 0: 'the fingerprint method is not one it takes', 2: 'the request was not allowed or not supported', 5: 'the request was not laid out as it expects', 14: 'its source of time is not available', 15: 'the policy asked for is not one it takes', 16: 'an extension asked for is not one it takes', 17: 'more information asked for is not available', 25: 'it failed in itself' };

/** No time-stamp was given that could be kept: the service could not be reached, refused, or answered in a way that cannot be used. */
const notGiven = (message) => new Refusal('stamp-not-given', message);

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

// One DER element. Every element here is short: its length fits in one byte.
function element(tag, content) {
  if (content.length > 127) throw new Error('An element of a time-stamp request is longer than this writer writes.');
  return concat(Uint8Array.of(tag, content.length), content);
}

// A whole number that is not negative, from its bytes, most significant first, in its shortest form (X.690, section 8.3).
function positiveInteger(bytes) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  const digits = bytes.subarray(i);
  return element(TAG.INTEGER, digits[0] & 0x80 ? concat(Uint8Array.of(0), digits) : digits);
}

/**
 * The request of RFC 3161, section 2.4.1 ("TimeStampReq"), in DER: version
 * 1, the fingerprint as what is to be stamped, the number used once, and
 * the service's certificate asked for. No policy and no extension.
 * @param {Uint8Array} fingerprintBytes the 32 bytes of a seal's fingerprint
 * @param {Uint8Array} nonce the bytes of the number used once, most significant first
 * @returns {Uint8Array}
 */
export function stampRequest(fingerprintBytes, nonce) {
  if (!(fingerprintBytes instanceof Uint8Array) || fingerprintBytes.length !== 32) throw new TypeError('A seal\'s fingerprint is 32 bytes.');
  if (!(nonce instanceof Uint8Array) || nonce.length < 1 || nonce.length > 32) throw new TypeError('A number used once is 1 to 32 bytes.');
  const imprint = element(TAG.SEQUENCE, concat(SHA256, element(TAG.OCTET_STRING, fingerprintBytes)));
  return element(TAG.SEQUENCE, concat(element(TAG.INTEGER, Uint8Array.of(1)), imprint, positiveInteger(nonce), CERT_REQ_TRUE));
}

/**
 * The address of a time-stamp service, read: an address on the web
 * (http: or https:) with no user name, password or fragment.
 * @param {string} address
 * @returns {string} the address, written in full
 */
export function stampAddress(address) {
  let url;
  try {
    url = new URL(address);
  } catch {
    throw new TypeError('The address of a time-stamp service must be a whole address, such as http://<host>/<path>.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new TypeError('The address of a time-stamp service must begin http:// or https://.');
  if (url.username !== '' || url.password !== '') throw new TypeError('The address of a time-stamp service must hold no user name or password.');
  if (url.hash !== '') throw new TypeError('The address of a time-stamp service must hold no fragment (#).');
  return url.href;
}

function readTimeout(timeout) {
  if (!Number.isInteger(timeout) || timeout < STAMP_TIMEOUT_MIN_MS || timeout > STAMP_TIMEOUT_MAX_MS) {
    throw new TypeError(`The time limit of a request for a time-stamp must be a whole number of milliseconds from ${STAMP_TIMEOUT_MIN_MS} to ${STAMP_TIMEOUT_MAX_MS}.`);
  }
  return timeout;
}

// Text a service wrote, made safe to show: no characters that steer a terminal, and not too long.
const shown = (text) => {
  const plain = text.replace(/[\p{Cc}\p{Zl}\p{Zp}]/gu, ' ').trim();
  return plain.length > 200 ? `${plain.slice(0, 200)}...` : plain;
};

// The answer of RFC 3161, section 2.4.2 ("TimeStampResp"): the status, and the time-stamp where it was granted.
function readResponse(bytes) {
  const top = expect(readElement(bytes, 0), TAG.SEQUENCE, 'the answer');
  if (top.end !== bytes.length) throw notGiven('The time-stamp service\'s answer has bytes left over after it.');
  const parts = children(bytes, top, 2);
  const info = children(bytes, expect(parts[0], TAG.SEQUENCE, 'the status of the answer'), 3);
  const status = contentOf(bytes, expect(info[0], TAG.INTEGER, 'the status of the answer'));
  if (status.length !== 1 || status[0] >= STATUS.length) throw notGiven('The time-stamp service\'s answer gives a status that RFC 3161 does not name.');
  const words = [];
  const reasons = [];
  for (const part of info.slice(1)) {
    if (part.tag === TAG.SEQUENCE) {
      for (const text of children(bytes, part, 8)) if (text.tag === 0x0c) words.push(shown(new TextDecoder().decode(contentOf(bytes, text))));
    } else if (part.tag === TAG.BIT_STRING) {
      const b = contentOf(bytes, part);
      for (let bit = 0; bit < (b.length - 1) * 8; bit++) {
        if (b[1 + (bit >> 3)] & (0x80 >> (bit & 7))) reasons.push(FAILURE[bit] ?? `reason ${bit}`);
      }
    }
  }
  if (status[0] === 0 || status[0] === 1) {
    if (parts.length !== 2) throw notGiven('The time-stamp service says it granted a time-stamp, and its answer holds none.');
    return { token: new Uint8Array(wholeOf(bytes, expect(parts[1], TAG.SEQUENCE, 'the time-stamp'))) };
  }
  const said = [words.length ? `"${words.join(' ')}"` : '', reasons.join('; ')].filter(Boolean).join(': ');
  throw notGiven(`The time-stamp service gave no time-stamp: ${STATUS[status[0]]} (status ${status[0]})${said ? `, ${said}` : ''}.`);
}

// The number used once that the statement of a time-stamp carries, as its whole element, or null. The time-stamp
// has passed checkStamp, so its layout is known to be the one RFC 3161 sets out.
function nonceOf(token) {
  const outer = children(token, readElement(token, 0), 2);
  const signedData = children(token, children(token, outer[1], 1)[0], 6);
  const enclosed = children(token, signedData[2], 2);
  const statementBytes = contentOf(token, children(token, enclosed[1], 1)[0]);
  const parts = children(statementBytes, readElement(statementBytes, 0), 10);
  // After the time: how exact it is, whether stamps are ordered, then the number used once (RFC 3161, section 2.4.2).
  let i = 5;
  if (parts[i] && parts[i].tag === TAG.SEQUENCE) i++;
  if (parts[i] && parts[i].tag === TAG.BOOLEAN) i++;
  return parts[i] && parts[i].tag === TAG.INTEGER ? wholeOf(statementBytes, parts[i]) : null;
}

// The body of an answer, read piece by piece up to the limit and no further.
async function readBody(response, most) {
  const declared = response.headers.get('content-length');
  if (declared !== null && Number(declared) > most) {
    await response.body?.cancel().catch(() => {});
    throw notGiven(`The time-stamp service's answer is ${declared} bytes, more than the ${most} bytes read.`);
  }
  if (!response.body) return new Uint8Array(0);
  const pieces = [];
  let size = 0;
  const reader = response.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > most) {
      await reader.cancel().catch(() => {});
      throw notGiven(`The time-stamp service's answer is longer than the ${most} bytes read.`);
    }
    pieces.push(value);
  }
  return concat(...pieces);
}

/**
 * Ask a time-stamp service for a time-stamp over a seal's fingerprint, and
 * check what it gives before handing it on.
 *
 * @param {Uint8Array} fingerprintBytes the 32 bytes of the seal's fingerprint
 * @param {object} o
 * @param {string} o.address the service's address; none is named by this package
 * @param {number} [o.timeout] how long the whole request, the reading of the answer included, may take (10 seconds)
 * @param {() => number} [o.clock] this device's clock, in milliseconds
 * @returns {Promise<{stamp: string, when: string, time: number, authority: string}>}
 *   "stamp" is the item of "stamps" the format sets out (section 21.2): the
 *   time-stamp in base64url. "when" and "time" are the time it states, as
 *   checkStamp gives them; "authority" is the fingerprint of the certificate
 *   that signed it, which a person checking names to trust the service.
 * @throws {Refusal} "stamp-not-given", or the code of checkStamp ("stamp-bad-data", "stamp-wrong-data", "stamp-invalid")
 */
export async function askForStamp(fingerprintBytes, { address, timeout = STAMP_TIMEOUT_MS, clock = Date.now } = {}) {
  const where = stampAddress(address);
  const limit = readTimeout(timeout);
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const request = stampRequest(fingerprintBytes, nonce);
  const asked = clock();
  let bytes;
  try {
    // A redirect is not followed: the request goes to the address given and nowhere else, whatever answers there says.
    const response = await fetch(where, {
      method: 'POST',
      headers: { 'content-type': 'application/timestamp-query', accept: 'application/timestamp-reply' },
      body: request,
      redirect: 'error',
      signal: AbortSignal.timeout(limit),
    });
    if (response.status !== 200) {
      await response.body?.cancel().catch(() => {});
      throw notGiven(`The time-stamp service at ${where} answered with the HTTP status ${response.status}, and gave no time-stamp.`);
    }
    bytes = await readBody(response, MAX_REPLY_BYTES);
  } catch (e) {
    if (e instanceof Refusal) throw e;
    if (e?.name === 'TimeoutError' || e?.name === 'AbortError') throw notGiven(`The time-stamp service at ${where} gave no whole answer within ${limit} milliseconds.`);
    const why = e?.cause?.message ?? e?.message ?? String(e);
    throw notGiven(`The time-stamp service at ${where} could not be reached, or answered with a redirect, which is not followed (${shown(String(why))}).`);
  }
  const answered = clock();
  const { token } = readResponse(bytes);
  if (token.length > MAX_STAMP_BYTES) throw notGiven(`The time-stamp service gave a time-stamp of ${token.length} bytes, more than the ${MAX_STAMP_BYTES} the format allows.`);
  // Laid out as RFC 3161 and RFC 5652 set out, made for this fingerprint, and signed with the key of the certificate it carries.
  const checked = await checkStamp(token, fingerprintBytes);
  if (checked.state === 'unavailable') throw notGiven('The time-stamp service signs with a method this device cannot check, so its time-stamp was not kept.');
  const sent = positiveInteger(nonce);
  const carried = nonceOf(token);
  if (carried === null || !equalBytes(carried, sent)) {
    throw new Refusal('stamp-wrong-data', carried === null ? 'The time-stamp service\'s time-stamp does not carry the number used once that was sent, so it may answer another request.' : 'The time-stamp service\'s time-stamp carries another number used once than the one sent: it answers another request.');
  }
  // A time far from this device's clock would put the book at odds with itself under a checker who trusts the service:
  // the seal dated more than 300 seconds after it, or a later seal more than 300 seconds before it (section 21.1, rule 4; section 21.2, rule 7).
  if (checked.time < asked - STAMP_CLOCK_GAP_MS || checked.time > answered + STAMP_CLOCK_GAP_MS) {
    throw notGiven(`The time-stamp service states the time ${checked.when}, more than ${STAMP_CLOCK_GAP_MS / 1000} seconds from this device's clock, so its time-stamp was not kept.`);
  }
  return { stamp: toBase64url(token), when: checked.when, time: checked.time, authority: checked.authority };
}

/**
 * The "stamp" of the library's openSealer, for one service: a function that
 * asks it for a time-stamp over a seal's fingerprint and gives the item of
 * "stamps". The address and the time limit are read here, once.
 * @param {{address: string, timeout?: number, clock?: () => number}} o
 * @returns {(fingerprintBytes: Uint8Array) => Promise<string>}
 */
export function stampService({ address, timeout = STAMP_TIMEOUT_MS, clock = Date.now } = {}) {
  const where = stampAddress(address);
  const limit = readTimeout(timeout);
  return async (fingerprintBytes) => (await askForStamp(fingerprintBytes, { address: where, timeout: limit, clock })).stamp;
}
