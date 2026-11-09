// The connection line (line.mjs): its format, what it carries, and what is
// refused, each with one sentence that names no value from the line.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCryptoCore } from '@microtoll/crypto-core';
import { FIELDS, LINE_PREFIX, LINE_VERSION, checkConnection, decodeLine, encodeLine, sameConnection } from 'provared-connect';
import { NAMESPACE } from '../entry.mjs';

const cc = createCryptoCore({ namespace: NAMESPACE });
const fresh = () => ({
  server: 'wss://app.example/ws', origin: 'https://app.example', namespace: NAMESPACE, objectId: crypto.randomUUID(),
  kObject: cc.toBase64Url(cc.generateSymmetricKey()), appendCapabilitySecret: cc.toBase64Url(cc.randomBytes(32)),
});
const SENTENCE = /^[A-Z][^\n]*\.$/;

test('the line: the prefix, the version, then base64url of the JSON with exactly the connection\'s fields', () => {
  const c = fresh();
  const line = encodeLine(c);
  assert.equal(LINE_PREFIX, 'provared-connect:');
  assert.equal(LINE_VERSION, 1);
  assert.ok(line.startsWith('provared-connect:1:'));
  const body = line.slice('provared-connect:1:'.length);
  assert.match(body, /^[A-Za-z0-9_-]+$/, 'base64url, no padding');
  assert.deepEqual(JSON.parse(Buffer.from(body, 'base64url').toString('utf8')), { version: 1, ...c });
  assert.ok(!line.includes('\n') && !line.includes(' '));
  assert.ok(line.length < 500, `${line.length} characters`);
  // The same fields the connection file holds: "about" and "version" added, nothing else.
  const back = decodeLine(line);
  assert.deepEqual(Object.keys(back), ['about', 'version', ...FIELDS]);
  assert.equal(back.version, 1);
  assert.match(back.about, /never share it/);
  for (const k of FIELDS) assert.equal(back[k], c[k]);
  assert.ok(sameConnection(c, back));
  // Spaces around it, as a paste may leave, are no matter.
  assert.ok(sameConnection(c, decodeLine(`  ${line}\n`)));
  // Written from a file's connection, with "about" and "version", the line is the same.
  assert.equal(encodeLine(back), line);
});

test('a line is refused with one sentence that says what to do and names no value from it', () => {
  const c = fresh();
  const line = encodeLine(c);
  const body = line.slice('provared-connect:1:'.length);
  const refused = (text, code = 'bad-line') => {
    let e = null;
    try { decodeLine(text); } catch (x) { e = x; }
    assert.ok(e, `accepted: ${String(text).slice(0, 40)}`);
    assert.equal(e.code, code);
    assert.match(e.message, SENTENCE);
    assert.ok(!e.message.includes(c.kObject) && !e.message.includes(c.appendCapabilitySecret) && !e.message.includes(c.objectId) && !e.message.includes(body.slice(0, 12)), 'no value from the line');
    return e.message;
  };
  // Not a line at all, or half of one.
  assert.match(refused(''), /copy the whole line/);
  assert.match(refused(undefined), /copy the whole line/);
  assert.match(refused('hello'), /copy the whole line/);
  refused(line.slice(0, -1)); // the last character lost
  refused(line.slice(0, 60)); // cut short
  refused(`${line}=`); // padding, or a stray character
  refused(line.slice(1)); // the first character lost
  refused('provared-connect:');
  refused('provared-connect:1:');
  refused('provared-connect::abc');
  refused('provared-connect:x:abc');
  refused(`provared-connect:1:${Buffer.from('not json').toString('base64url')}`);
  refused(`provared-connect:1:${Buffer.from('[]').toString('base64url')}`);
  refused(`provared-connect:1:${Buffer.from('{"version":2}').toString('base64url')}`);
  // A newer version of the format.
  assert.match(refused(`provared-connect:2:${body}`, 'newer-line'), /newer version/);
  // The fields, each.
  const withBody = (o) => `provared-connect:1:${Buffer.from(JSON.stringify({ version: 1, ...o })).toString('base64url')}`;
  for (const k of FIELDS) {
    const missing = { ...c }; delete missing[k];
    assert.match(refused(withBody(missing)), new RegExp(`has no "${k}"`));
    assert.match(refused(withBody({ ...c, [k]: '' })), new RegExp(`has no "${k}"`));
    assert.match(refused(withBody({ ...c, [k]: 5 })), new RegExp(`has no "${k}"`));
  }
  assert.match(refused(withBody({ ...c, extra: 'x' })), /does not know/);
  assert.match(refused(withBody({ ...c, server: 'https://app.example/ws' })), /WebSocket/);
  assert.match(refused(withBody({ ...c, server: 'not an address' })), /"server"/);
  assert.match(refused(withBody({ ...c, origin: 'https://app.example/page' })), /"origin"/);
  assert.match(refused(withBody({ ...c, origin: 'wss://app.example' })), /"origin"/);
  assert.match(refused(withBody({ ...c, namespace: 'has space' })), /"namespace"/);
  assert.match(refused(withBody({ ...c, objectId: 'not-a-uuid' })), /"objectId"/);
  assert.match(refused(withBody({ ...c, kObject: 'short' })), /"kObject"/);
  assert.match(refused(withBody({ ...c, kObject: `${c.kObject}=` })), /"kObject"/);
  assert.match(refused(withBody({ ...c, appendCapabilitySecret: 'has space in it and more' })), /"appendCapabilitySecret"/);
});

test('checkConnection reads a connection file\'s object the same way, and encodeLine refuses what it refuses', () => {
  const c = fresh();
  const checked = checkConnection({ about: 'old words', version: 1, ...c });
  assert.deepEqual(Object.keys(checked), ['about', 'version', ...FIELDS]);
  assert.throws(() => checkConnection(null), { code: 'bad-connection' });
  assert.throws(() => checkConnection({ ...c, objectId: 'x' }), { code: 'bad-connection', message: /"objectId"/ });
  assert.throws(() => encodeLine({ ...c, kObject: '' }), { code: 'bad-connection' });
  assert.ok(!sameConnection(c, { ...c, kObject: cc.toBase64Url(cc.generateSymmetricKey()) }), 'a new key is another connection');
  assert.ok(!sameConnection(c, null));
});
