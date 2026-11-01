// The wire layer on its own: lines split across chunks, strict reading of a
// message, repeated names.

import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { CODES, foldName, idKey, isId, readLines, readMessage, repeatedName } from '../jsonrpc.mjs';

function collect(chunks, limit) {
  const stream = new PassThrough();
  const lines = [];
  const tooLong = [];
  let ended = false;
  readLines(stream, { onLine: (l) => lines.push(l.toString('utf8')), onTooLong: (n) => tooLong.push(n), onEnd: () => (ended = true), ...(limit ? { limit } : {}) });
  for (const c of chunks) stream.write(Buffer.isBuffer(c) ? c : Buffer.from(c));
  stream.end();
  return new Promise((done) => setImmediate(() => done({ lines, tooLong, ended })));
}

test('lines are whole whatever the chunks, a carriage return before the line feed is dropped, and a last line without a line feed counts', async () => {
  let r = await collect(['{"a":1}\n{"b":', '2}\r\n', '{"c":3}']);
  assert.deepEqual(r.lines, ['{"a":1}', '{"b":2}', '{"c":3}']);
  assert.equal(r.ended, true);
  r = await collect(['\n\n{"a":1}\n']);
  assert.deepEqual(r.lines, ['', '', '{"a":1}']);
  // A line split inside a multi-byte character.
  const bytes = Buffer.from('{"s":"é"}\n');
  r = await collect([bytes.subarray(0, 6), bytes.subarray(6)]);
  assert.deepEqual(r.lines, ['{"s":"é"}']);
});

test('a line over the limit is reported once and dropped to its end; the next line is read', async () => {
  const r = await collect(['{"pad":"', 'x'.repeat(40), '"}\n{"ok":1}\n'], 30);
  assert.deepEqual(r.lines, ['{"ok":1}']);
  assert.equal(r.tooLong.length, 1);
  assert.ok(r.tooLong[0] > 30);
});

test('readMessage: requests, notifications and responses are told apart, and what cannot be read strictly is refused', () => {
  const read = (v) => readMessage(Buffer.isBuffer(v) ? v : Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)));
  assert.equal(read({ jsonrpc: '2.0', id: 1, method: 'ping' }).kind, 'request');
  assert.equal(read({ jsonrpc: '2.0', id: 'a', method: 'ping', params: {} }).kind, 'request');
  assert.equal(read({ jsonrpc: '2.0', method: 'notifications/initialized' }).kind, 'notification');
  assert.equal(read({ jsonrpc: '2.0', id: 1, result: {} }).kind, 'response');
  assert.equal(read({ jsonrpc: '2.0', id: 1, error: { code: 1, message: 'x' } }).kind, 'response');
  assert.equal(read('nope').refused.code, CODES.parse);
  assert.equal(read(Buffer.from([0xff, 0xfe])).refused.code, CODES.parse);
  assert.equal(read([{ jsonrpc: '2.0', id: 1, method: 'ping' }]).refused.code, CODES.invalidRequest);
  assert.equal(read('"text"').refused.code, CODES.invalidRequest);
  assert.equal(read({ jsonrpc: '1.0', id: 1, method: 'ping' }).refused.code, CODES.invalidRequest);
  assert.equal(read({ jsonrpc: '2.0', id: null, method: 'ping' }).refused.code, CODES.invalidRequest);
  assert.equal(read({ jsonrpc: '2.0', id: 1.5, method: 'ping' }).refused.code, CODES.invalidRequest);
  assert.equal(read({ jsonrpc: '2.0', id: true, method: 'ping' }).refused.code, CODES.invalidRequest);
  assert.equal(read({ jsonrpc: '2.0', id: 1, method: 7 }).refused.code, CODES.invalidRequest);
  assert.equal(read({ jsonrpc: '2.0', id: 1, method: 'ping', params: [] }).refused.code, CODES.invalidRequest);
  assert.equal(read({ jsonrpc: '2.0', id: 1, method: 'ping', result: {} }).refused.code, CODES.invalidRequest);
  assert.equal(read({ jsonrpc: '2.0', result: {} }).refused.code, CODES.invalidRequest, 'a response needs an id');
  assert.equal(read({ jsonrpc: '2.0', id: 1, result: {}, error: {} }).refused.code, CODES.invalidRequest);
  assert.equal(read({ jsonrpc: '2.0', id: 1 }).refused.code, CODES.invalidRequest);
  const twice = read('{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}');
  assert.equal(twice.refused.code, CODES.invalidRequest);
  const deep = read('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"x":{"a":1,"a":2}}}}');
  assert.equal(deep.refused.code, CODES.invalidRequest);
  // The id is given back where it could be read, so that the refusal can name it.
  assert.equal(read({ jsonrpc: '1.0', id: 'k', method: 'ping' }).id, 'k');
  assert.equal(read([1]).id, null);
});

test('repeated names: exact by default, folded on request; ids', () => {
  assert.equal(repeatedName('{"a":1,"b":{"a":2}}'), null);
  assert.equal(repeatedName('{"a":1,"a":2}'), 'a');
  assert.equal(repeatedName('[{"a":1},{"a":2}]'), null);
  assert.equal(repeatedName('{"a":{"b":1},"c":{"b":2}}'), null);
  assert.equal(repeatedName('{"a\\"b":1,"a\\"b":2}'), 'a"b');
  assert.equal(repeatedName('{"total":1,"TOTAL":2}'), null);
  assert.equal(repeatedName('{"total":1,"TOTAL":2}', true), 'TOTAL');
  assert.equal(repeatedName('{"k":1,"K":2}', true), 'K', 'the Kelvin sign and k');
  assert.equal(foldName('İ'), 'i');
  assert.equal(isId('x'), true);
  assert.equal(isId(0), true);
  assert.equal(isId(1.5), false);
  assert.equal(isId(null), false);
  assert.notEqual(idKey(1), idKey('1'));
});
