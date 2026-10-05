// Base64url, the canonical form and times.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Refusal, canonicalJson, fromBase64url, parseCanonical, parseTime, toBase64url, utf8 } from '../src/encoding.js';

const refused = (fn, code) =>
  assert.throws(fn, (e) => e instanceof Refusal && e.code === code, `expected a refusal with code ${code}`);

test('base64url round trip, for every length up to 64 bytes', () => {
  for (let n = 0; n <= 64; n++) {
    const bytes = new Uint8Array(n).map((_, i) => (i * 37 + n) & 0xff);
    const text = toBase64url(bytes);
    assert.equal(text, Buffer.from(bytes).toString('base64url'));
    assert.deepEqual(fromBase64url(text), bytes);
  }
});

test('base64url: the examples of RFC 4648 section 10', () => {
  const pairs = [['', ''], ['f', 'Zg'], ['fo', 'Zm8'], ['foo', 'Zm9v'], ['foob', 'Zm9vYg'], ['fooba', 'Zm9vYmE'], ['foobar', 'Zm9vYmFy']];
  for (const [plain, coded] of pairs) {
    assert.equal(toBase64url(utf8(plain)), coded);
    assert.deepEqual(fromBase64url(coded), utf8(plain));
  }
});

test('base64url refuses padding, other alphabets, impossible lengths and stray bits', () => {
  refused(() => fromBase64url('Zg=='), 'bad-base64url');
  refused(() => fromBase64url('Zm9v+'), 'bad-base64url');
  refused(() => fromBase64url('Zm9v/w'), 'bad-base64url');
  refused(() => fromBase64url('Z'), 'bad-base64url');
  refused(() => fromBase64url('Zm9vY'), 'bad-base64url');
  refused(() => fromBase64url('Zm 9v'), 'bad-base64url');
  refused(() => fromBase64url('Zm9v\n'), 'bad-base64url');
  refused(() => fromBase64url('Zmé'), 'bad-base64url');
  // "Zh" decodes to the same byte as "Zg" in a lax decoder: stray bits.
  refused(() => fromBase64url('Zh'), 'bad-base64url');
  refused(() => fromBase64url('Zm9'), 'bad-base64url');
  refused(() => fromBase64url(42), 'bad-base64url');
  refused(() => fromBase64url(undefined), 'bad-base64url');
});

test('the canonical form sorts members as RFC 8785 section 3.2.3 shows', () => {
  const value = {
    '€': 'Euro Sign',
    '\r': 'Carriage Return',
    'דּ': 'Hebrew Letter Dalet With Dagesh',
    1: 'One',
    '😀': 'Emoji: Grinning Face',
    '\u0080': 'Control',
    'ö': 'Latin Small Letter O With Diaeresis',
  };
  const order = JSON.parse('[' + canonicalJson(value).slice(1, -1).split(/,(?=")/).map((m) => m.slice(0, m.indexOf(':'))).join(',') + ']');
  assert.deepEqual(order, ['\r', '1', '\u0080', 'ö', '€', '😀', 'דּ']);
});

test('the canonical form has no spaces and writes strings as RFC 8785 section 3.2.2.2 sets out', () => {
  assert.equal(canonicalJson({ b: [1, 'x', { d: 0, c: '' }], a: 'é"\\\n\u0001' }), '{"a":"é\\"\\\\\\n\\u0001","b":[1,"x",{"c":"","d":0}]}');
  assert.equal(canonicalJson({}), '{}');
  assert.equal(canonicalJson([]), '[]');
  assert.equal(canonicalJson(9007199254740991), '9007199254740991');
});

test('the canonical form refuses what the format does not allow', () => {
  for (const value of [1.5, -1, -0, 9007199254740992, NaN, Infinity, null, true, false, undefined, 10n, () => 1, '\ud800', { a: '\udc00' }]) {
    refused(() => canonicalJson(value), 'payload-not-canonical');
  }
  let deep = 'x';
  for (let i = 0; i < 9; i++) deep = [deep];
  refused(() => canonicalJson(deep), 'payload-not-canonical');
});

test('reading canonical text refuses anything that is not byte for byte canonical', () => {
  assert.deepEqual(parseCanonical('{"a":1,"b":["x"]}'), { a: 1, b: ['x'] });
  const notCanonical = [
    '{"b":1,"a":2}', // members out of order
    '{"a":1,"a":2}', // a repeated name
    '{"a":1,"a":1}',
    '{"a": 1}', // a space
    '{"a":1}\n',
    ' {"a":1}',
    '{"a":1.0}', // unusual number forms
    '{"a":1e2}',
    '{"a":-0}',
    '{"a":01}',
    '{"a":-1}',
    '{"a":1.5}',
    '{"a":null}',
    '{"a":true}',
    '{"a":"\\u0041"}', // an escape that is not needed
    '{"a":"\\/"}',
    '{"a":"\\ud800"}', // half a character
    '﻿{"a":1}', // a byte order mark
    'not json',
    '',
  ];
  for (const text of notCanonical) refused(() => parseCanonical(text), 'payload-not-canonical');
});

test('very deep nesting is refused, not crashed on', () => {
  const deep = '['.repeat(200000) + ']'.repeat(200000);
  refused(() => parseCanonical(deep), 'payload-not-canonical');
  refused(() => parseCanonical(deep, 'line-not-canonical'), 'line-not-canonical');
});

test('a line that is not JSON at all is named as such', () => {
  refused(() => parseCanonical('hello', 'line-not-canonical'), 'not-json');
});

test('times: one form only', () => {
  assert.equal(parseTime('2026-10-05T09:00:00Z'), Date.UTC(2026, 9, 5, 9, 0, 0));
  for (const text of [
    '2026-10-05T09:00:00',
    '2026-10-05T09:00:00.000Z',
    '2026-10-05T09:00:00+00:00',
    '2026-10-05t09:00:00Z',
    '2026-10-05 09:00:00Z',
    '2026-02-30T09:00:00Z',
    '2026-13-01T09:00:00Z',
    '2026-10-05T24:00:00Z',
    '2026-10-05T09:60:00Z',
    '26-10-05T09:00:00Z',
    '',
    42,
    null,
  ]) {
    assert.ok(Number.isNaN(parseTime(text)), String(text));
  }
});
