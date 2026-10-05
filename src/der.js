// A small, strict reader for DER, the byte layout that time-stamps and
// certificates use (ITU-T X.690). It reads; it never writes. Anything not in
// the one form DER allows is refused.

import { Refusal } from './encoding.js';

export function badStamp(why) {
  return new Refusal('stamp-bad-data', `A time-stamp is not laid out as its standard sets out: ${why}`);
}

/** The tags this reader meets. */
export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30,
  SET: 0x31,
  CONTEXT_0: 0xa0,
  CONTEXT_1: 0xa1,
  CONTEXT_3: 0xa3,
};

/**
 * Read the element that begins at "at".
 * @param {Uint8Array} bytes
 * @param {number} at
 * @param {number} [end] the element must lie before this
 * @returns {{tag: number, from: number, start: number, end: number}} "from" is the first byte of the element, "start" and "end" bound its content
 */
export function readElement(bytes, at, end = bytes.length) {
  if (at + 2 > end) throw badStamp('it is cut short.');
  const tag = bytes[at];
  if ((tag & 0x1f) === 0x1f) throw badStamp('it holds a tag of a kind that is not used here.');
  let length = bytes[at + 1];
  let start = at + 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    // Never the indefinite form, and never more than four bytes of length.
    if (count === 0 || count > 4) throw badStamp('it holds a length in a form that is not allowed.');
    if (start + count > end) throw badStamp('it is cut short.');
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[start + i];
    if (bytes[start] === 0 || length < 128) throw badStamp('it holds a length that is not in its shortest form.');
    start += count;
  }
  if (length > end - start) throw badStamp('a part is longer than what holds it.');
  return { tag, from: at, start, end: start + length };
}

/**
 * The elements inside a constructed element, in order.
 * @param {Uint8Array} bytes
 * @param {{start: number, end: number}} parent
 * @param {number} [most] refuse more children than this
 */
export function children(bytes, parent, most = 32) {
  const out = [];
  let at = parent.start;
  while (at < parent.end) {
    if (out.length >= most) throw badStamp('a part holds too many items.');
    const child = readElement(bytes, at, parent.end);
    out.push(child);
    at = child.end;
  }
  return out;
}

/** Confirm an element's tag, and hand the element back. */
export function expect(element, tag, what) {
  if (!element || element.tag !== tag) throw badStamp(`${what} is missing or of the wrong kind.`);
  return element;
}

/** The content bytes of an element. */
export function contentOf(bytes, element) {
  return bytes.subarray(element.start, element.end);
}

/** The whole element, tag and length included. */
export function wholeOf(bytes, element) {
  return bytes.subarray(element.from, element.end);
}

/** The content of an element as lower-case hexadecimal: how object identifiers are compared here. */
export function hexOf(bytes, element) {
  let out = '';
  for (let i = element.start; i < element.end; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

/**
 * A time, from the two forms DER allows: "YYMMDDHHMMSSZ" (UTCTime) and
 * "YYYYMMDDHHMMSS[.f]Z" (GeneralizedTime).
 * @returns {number} milliseconds
 */
export function timeOf(bytes, element) {
  let text = '';
  for (let i = element.start; i < element.end; i++) text += String.fromCharCode(bytes[i]);
  let m;
  if (element.tag === TAG.UTC_TIME) {
    m = /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(text);
    if (m) m[1] = (Number(m[1]) < 50 ? '20' : '19') + m[1];
  } else if (element.tag === TAG.GENERALIZED_TIME) {
    m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(?:\.(\d{1,9}))?Z$/.exec(text);
    // DER allows no trailing zero in the fraction.
    if (m && m[7] && m[7].endsWith('0')) m = null;
  }
  if (!m) throw badStamp('a time is not written in the form DER allows.');
  const [, y, mo, d, h, mi, s] = m.map(Number);
  const ms = Date.UTC(y, mo - 1, d, h, mi, s) + (m[7] ? Math.floor(Number('0.' + m[7]) * 1000) : 0);
  const check = new Date(ms);
  if (check.getUTCFullYear() !== y || check.getUTCMonth() !== mo - 1 || check.getUTCDate() !== d || h > 23 || mi > 59 || s > 59) {
    throw badStamp('a time names a moment that does not exist.');
  }
  return ms;
}

/**
 * An ECDSA signature from its DER form (two whole numbers) to the two
 * numbers side by side, each of "size" bytes, as Web Crypto wants them.
 * @param {Uint8Array} der
 * @param {number} size 32 for P-256, 48 for P-384
 */
export function ecdsaToRaw(der, size) {
  const outer = expect(readElement(der, 0), TAG.SEQUENCE, 'the signature');
  if (outer.end !== der.length) throw badStamp('a signature has bytes left over.');
  const parts = children(der, outer, 2);
  if (parts.length !== 2) throw badStamp('a signature does not hold two numbers.');
  const out = new Uint8Array(size * 2);
  parts.forEach((part, i) => {
    expect(part, TAG.INTEGER, 'a number of the signature');
    let digits = contentOf(der, part);
    if (digits.length === 0 || digits[0] & 0x80) throw badStamp('a signature holds a number that is not positive.');
    if (digits.length > 1 && digits[0] === 0 && !(digits[1] & 0x80)) throw badStamp('a signature holds a number not in its shortest form.');
    if (digits[0] === 0) digits = digits.subarray(1);
    if (digits.length > size) throw badStamp('a signature holds a number that is too large.');
    out.set(digits, i * size + (size - digits.length));
  });
  return out;
}

/**
 * Walk a whole element and everything inside it, and refuse anything that
 * is not strict DER: a constructed part whose items do not fill it exactly,
 * a whole number or an object identifier that is not in its shortest form,
 * a truth value that is not written in the one way DER allows. Parts this
 * checker does not otherwise read are still read here, so that two checkers
 * cannot disagree about whether a time-stamp is well formed.
 * @param {Uint8Array} bytes
 * @param {{tag: number, start: number, end: number}} element
 */
export function validateDer(bytes, element) {
  let budget = 4000;
  const walk = (e, depth) => {
    if (--budget < 0 || depth > 24) throw badStamp('it holds too many parts, or parts nested too deeply.');
    const length = e.end - e.start;
    if (e.tag & 0x20) {
      let at = e.start;
      while (at < e.end) {
        const child = readElement(bytes, at, e.end);
        walk(child, depth + 1);
        at = child.end;
      }
      return;
    }
    const first = bytes[e.start];
    const second = bytes[e.start + 1];
    if (e.tag === TAG.INTEGER) {
      if (length === 0) throw badStamp('a whole number is empty.');
      if (length > 1 && ((first === 0x00 && !(second & 0x80)) || (first === 0xff && second & 0x80))) {
        throw badStamp('a whole number is not in its shortest form.');
      }
    } else if (e.tag === TAG.OID) {
      if (length === 0 || bytes[e.end - 1] & 0x80) throw badStamp('an object identifier is empty or cut short.');
      for (let i = e.start; i < e.end; i++) {
        if (bytes[i] === 0x80 && (i === e.start || !(bytes[i - 1] & 0x80))) throw badStamp('an object identifier is not in its shortest form.');
      }
    } else if (e.tag === TAG.BOOLEAN) {
      if (length !== 1 || (first !== 0x00 && first !== 0xff)) throw badStamp('a truth value is not written as DER allows.');
    } else if (e.tag === TAG.NULL) {
      if (length !== 0) throw badStamp('an empty value is not empty.');
    } else if (e.tag === TAG.BIT_STRING) {
      if (length === 0 || first > 7) throw badStamp('a string of bits is not written as DER allows.');
    }
  };
  walk(element, 0);
}
