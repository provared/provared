// A message nested very deeply does not end the executor (DESIGN.md,
// X250). In the first build of 0.4.2 the check for names that differ only
// in capitals wrote the params out afresh, which calls itself once for
// each level of nesting: one line of 10 KB, 5,000 levels deep, overflowed
// the stack where the lines are read and ended the executor on stdio. The
// text is now walked as it came. These tests send 200,000 levels, on stdio
// and over HTTP. Nothing leaves this computer.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { test } from 'node:test';

const { checkBook } = await import('provared');
const { CODES, foldedInParams, readMessage } = await import('../jsonrpc.mjs');
const { httpWorld, post, call } = await import('./http-world.mjs');
const { until, world } = await import('./world.mjs');

const DEPTH = 200000;
const stubsOf = (checked) => checked.entries.filter((e) => e.kind === 'stub');
/** The text of a value nested "depth" lists deep, with "inner" at the bottom. */
const nested = (inner, depth = DEPTH) => `${'['.repeat(depth)}${inner}${']'.repeat(depth)}`;
const ping = (id, inner) => `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"method":"ping","params":{"a":${nested(inner)}}}`;
const echo = (id, inner) => `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"method":"tools/call","params":{"name":"echo","arguments":{"a":${nested(inner)}}}}`;

test('readMessage: 200,000 levels of nesting are read without an error, and two names that differ only in capitals are still found at the bottom', () => {
  const read = (text, more) => readMessage(Buffer.from(text), more);
  assert.equal(read(ping(1, '1')).kind, 'request');
  assert.equal(read(ping(1, '{"x":1,"y":{"x":2}}')).kind, 'request');
  const refused = read(ping(7, '{"total":1,"TOTAL":2}'));
  assert.equal(refused.refused?.code, CODES.invalidRequest);
  assert.equal(refused.id, 7);
  assert.equal(read(ping(7, '{"total":1,"total":2}')).refused?.code, CODES.invalidRequest, 'a name given twice exactly');
  assert.equal(read(ping(7, '9007199254740993')).refused?.code, CODES.invalidRequest, 'a number two readers hold differently');
  assert.equal(read(ping(1, '{"total":1,"TOTAL":2}'), { strictNumbers: false }).kind, 'request', 'a line of the server is not read for it');
  // The walk looks inside "params" alone, at every depth of it.
  assert.equal(foldedInParams('{"jsonrpc":"2.0","id":1,"result":{"a":1,"A":2}}'), null);
  assert.equal(foldedInParams('{"jsonrpc":"2.0","id":1,"method":"m","params":{"a":[{"b":{"k":1,"K":2}}]}}'), 'K');
  assert.equal(foldedInParams('{"jsonrpc":"2.0","id":1,"method":"m","params":{"a":{"k":1},"b":{"K":2},"c":[{"k":1},{"K":2}]}}'), null, 'the same name in two objects');
  assert.equal(foldedInParams('{"jsonrpc":"2.0","id":1,"method":"m","params":{"a\\"A":1,"A\\"a":2}}'), 'A"a', 'a name with an escape in it');
});

test('readMessage: a refusal for a name given twice, or for a number two readers hold differently, names the request where its id can be found', () => {
  const id = (text) => readMessage(Buffer.from(text)).id;
  assert.equal(id('{"jsonrpc":"2.0","id":7,"method":"ping","method":"tools/call"}'), 7);
  assert.equal(id('{"jsonrpc":"2.0","id":"k","method":"tools/call","params":{"arguments":{"x":{"a":1,"a":2}}}}'), 'k');
  assert.equal(id('{"jsonrpc":"2.0","method":"tools/call","params":{"n":9007199254740993},"id":"last"}'), 'last');
  assert.equal(id('{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}'), null, 'two ids: neither is taken');
  assert.equal(id('{"jsonrpc":"2.0","id":9007199254740993,"method":"ping"}'), null, 'an id two readers hold differently is not answered under');
  assert.equal(id('{"jsonrpc":"2.0","id":null,"method":"ping","method":"x"}'), null);
  assert.equal(id('{"jsonrpc":"2.0","id":{"a":1,"a":2},"method":"ping"}'), null);
  assert.equal(id('{"jsonrpc":"2.0","method":"notifications/x","params":{"a":1,"a":2}}'), null, 'a notification has none');
});

test('stdio: a line nested 200,000 levels deep is passed on, refused or answered with an error, and the executor goes on', async () => {
  const w = await world();
  const answer = (id) => until(() => w.client.others.find((m) => m.id === id), { timeout: 20000 });
  try {
    // A request that is not a call goes on to the server as it came.
    w.client.raw(`${ping('deep-ping', '1')}\n`);
    assert.deepEqual((await answer('deep-ping')).result, {});
    // Two names that differ only in capitals, at the bottom: refused, under the request's id.
    w.client.raw(`${ping('deep-names', '{"total":1,"TOTAL":2}')}\n`);
    assert.equal((await answer('deep-names')).error.code, CODES.invalidRequest);
    // A name given twice exactly, at the bottom: the older refusal, now under the request's id too.
    w.client.raw(`${ping('deep-twice', '{"total":1,"total":2}')}\n`);
    assert.equal((await answer('deep-twice')).error.code, CODES.invalidRequest);
    // A call whose arguments cannot be fingerprinted at that depth is answered with an error and not sent.
    w.client.raw(`${echo('deep-call', '1')}\n`);
    assert.equal((await answer('deep-call')).error.code, CODES.notRecorded);
    // The executor is still there, and so is the server.
    const after = await w.client.call('echo', { a: 1 });
    assert.equal(after.result?.isError, undefined, JSON.stringify(after));
    assert.deepEqual(w.fakeSeen().map((e) => e.seen?.method), ['ping', 'tools/call'], 'the server was sent the ping and the one call that was checked');
    assert.equal(stubsOf(await checkBook(w.executor.writer.book(), { issuerKeys: w.settings.agent.issuerKeys })).length, 1);
  } finally {
    await w.close();
  }
});

test('HTTP: a body nested 200,000 levels deep is passed on or refused, and the executor goes on', async () => {
  const w = await httpWorld();
  try {
    const passed = await post(w, 'alpha', null, { raw: ping(1, '1') });
    assert.equal(passed.status, 200, passed.body.slice(0, 200));
    assert.deepEqual(passed.json.result, {});
    const names = await post(w, 'alpha', null, { raw: ping(2, '{"total":1,"TOTAL":2}') });
    assert.equal(names.status, 400);
    assert.equal(names.json.error.code, CODES.invalidRequest);
    assert.equal(names.json.id, 2);
    const twice = await post(w, 'alpha', null, { raw: ping(3, '{"total":1,"total":2}') });
    assert.equal(twice.status, 400);
    assert.equal(twice.json.id, 3, 'the older refusal names the request too');
    const deepCall = await post(w, 'alpha', null, { raw: echo(4, '1') });
    assert.notEqual(deepCall.status, 200, 'a call whose arguments cannot be fingerprinted at that depth is not sent');
    const after = await call(w, 'alpha', 'echo', { a: 1 });
    assert.equal(after.status, 200, after.body);
    assert.equal(w.upstream.ran.length, 1, 'the upstream ran the one call that was checked');
    assert.equal(stubsOf(await checkBook(w.executor.agent('alpha').writer.book(), { issuerKeys: w.settings.agents.alpha.issuerKeys })).length, 1);
  } finally {
    await w.close();
  }
});
