// A message nested very deeply does not end the executor, whoever sent it
// (DESIGN.md, X250). Much that walks a value calls itself once for each
// level of nesting, and overflows the stack on a value deep enough: the
// writing of a value as text, the fingerprint of a result, the filtering
// of a list of tools. So a message nested more than MAX_DEPTH levels deep
// is not read: the agent's is refused, and the server's is a line the
// executor cannot read. These tests send 200,000 levels each way, on stdio
// and over HTTP. Nothing leaves this computer.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { test } from 'node:test';

const { checkBook, identifierFingerprint } = await import('provared');
const { RESULT_DOCUMENT, UNREADABLE_ANSWER } = await import('../executor.mjs');
const { CODES, MAX_DEPTH, deeperThan, foldedInParams, readMessage } = await import('../jsonrpc.mjs');
const { httpWorld, post, call, request } = await import('./http-world.mjs');
const { TOOLS, until, world } = await import('./world.mjs');

const DEPTH = 200000;
const stubsOf = (checked) => checked.entries.filter((e) => e.kind === 'stub');
const docs = (stub) => Object.fromEntries(stub.content.details.map((d) => [d.name, d.sha256]));
/** The text of a value nested "depth" lists deep, with "inner" at the bottom. */
const nested = (inner, depth = DEPTH) => `${'['.repeat(depth)}${inner}${']'.repeat(depth)}`;
/** A ping whose params hold such a value: the message, its params and the lists are depth + 2 levels in all. */
const ping = (id, inner, depth) => `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"method":"ping","params":{"a":${nested(inner, depth)}}}`;
const echo = (id, inner, depth) => `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"method":"tools/call","params":{"name":"echo","arguments":{"a":${nested(inner, depth)}}}}`;

test('readMessage: a message nested more than MAX_DEPTH levels deep is refused under its id, the agent\'s and the server\'s alike; one within it is read, to the bottom', () => {
  const read = (text, more) => readMessage(Buffer.from(text), more);
  for (const more of [{}, { strictNumbers: false }]) {
    const refused = read(ping(7, '1'), more);
    assert.equal(refused.refused?.code, CODES.invalidRequest);
    assert.match(refused.refused.message, /nested more than 256 levels deep/);
    assert.equal(refused.id, 7);
    // The message and its params are two levels: the lists may be MAX_DEPTH - 2, and no more.
    assert.equal(read(ping(1, '1', MAX_DEPTH - 2), more).kind, 'request');
    assert.equal(read(ping(1, '1', MAX_DEPTH - 1), more).refused?.code, CODES.invalidRequest);
    assert.equal(read(`{"jsonrpc":"2.0","id":1,"result":${nested('1', MAX_DEPTH - 1)}}`, more).kind, 'response');
    assert.equal(read(`{"jsonrpc":"2.0","id":1,"result":${nested('1', MAX_DEPTH)}}`, more).refused?.code, CODES.invalidRequest);
  }
  // Brackets inside a text are not levels.
  assert.equal(read(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":${JSON.stringify('['.repeat(DEPTH))}}}`).kind, 'request');
  assert.equal(deeperThan('{"a":"[[[[\\"[["}', 1), false);
  assert.equal(deeperThan('{"a":[]}', 1), true);
  assert.equal(deeperThan('{"a":[]}', 2), false);
  // Within the limit, two names that differ only in capitals are found at the bottom, and the same name in two objects is not taken for them.
  const within = MAX_DEPTH - 4;
  assert.equal(read(ping(1, '{"x":1,"y":{"x":2}}', within)).kind, 'request');
  assert.equal(read(ping(7, '{"total":1,"TOTAL":2}', within)).refused?.code, CODES.invalidRequest);
  assert.equal(read(ping(7, '{"total":1,"TOTAL":2}', within), { strictNumbers: false }).kind, 'request', 'a line of the server is not read for it');
  // The walk for such names looks inside "params" alone, at every depth of it, and calls nothing that calls itself.
  assert.equal(foldedInParams(ping(1, '{"total":1,"TOTAL":2}')), 'TOTAL', '200,000 levels down');
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

test('stdio: the agent\'s lines nested 200,000 levels deep are refused, a cancellation among them, and the executor goes on', async () => {
  const w = await world();
  const answer = (id) => until(() => w.client.others.find((m) => m.id === id), { timeout: 20000 });
  const book = () => checkBook(w.executor.writer.book(), { issuerKeys: w.settings.agent.issuerKeys });
  try {
    for (const [id, line] of [['deep-ping', ping('deep-ping', '1')], ['deep-call', echo('deep-call', '1')], ['deep-names', ping('deep-names', '{"total":1,"TOTAL":2}')], ['deep-twice', ping('deep-twice', '{"total":1,"total":2}')]]) {
      w.client.raw(`${line}\n`);
      assert.equal((await answer(id)).error.code, CODES.invalidRequest, id);
    }
    // A cancellation of a call in flight, nested as deeply: it is not written afresh for the server, and the call goes on.
    w.client.raw(`${JSON.stringify({ jsonrpc: '2.0', id: 'slow-1', method: 'tools/call', params: { name: 'slow', arguments: { ms: 600 } } })}\n`);
    await until(() => w.fakeSeen().some((e) => e.seen?.method === 'tools/call'));
    w.client.raw(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"slow-1","x":${nested('1')}}}\n`);
    assert.equal((await until(() => w.client.others.find((m) => m.id === null && m.error))).error.code, CODES.invalidRequest);
    assert.equal((await answer('slow-1')).result?.content[0].text, 'Done, slowly.');
    // A call nested 50 levels deep is within the limit, and within what the library fingerprints (64 levels): taken, and receipted with its result.
    w.client.raw(`${echo('within', '1', 50)}\n`);
    assert.equal((await answer('within')).result?.isError, undefined);
    assert.deepEqual(w.fakeSeen().filter((e) => e.seen).map((e) => e.seen.method), ['tools/call', 'tools/call'], 'the server was sent the two calls that were checked, and nothing else');
    const stubs = stubsOf(await book());
    assert.equal(stubs.length, 2);
    for (const stub of stubs) assert.ok(docs(stub)[RESULT_DOCUMENT]);
  } finally {
    await w.close();
  }
});

test('stdio: the server\'s answers nested 200,000 levels deep (a result, an error, a list of tools, a notification) do not end the executor: a call\'s receipt says its answer could not be read', async () => {
  const w = await world({ config: { tools: { ...TOOLS, deep: { action: 'tool.run' }, deeperror: { action: 'tool.run' }, deepnote: { action: 'tool.run' } } }, env: { FAKE_DEEP_LIST: { value: String(DEPTH) } } });
  const unreadable = await identifierFingerprint(UNREADABLE_ANSWER);
  try {
    const result = await w.client.call('deep', { depth: DEPTH });
    assert.equal(result.result?.content[0].text, 'deep', 'the line is handed to the agent as it was');
    const error = await w.client.call('deeperror', { depth: DEPTH });
    assert.equal(error.error?.message, 'deep');
    const list = await w.client.request('tools/list', {});
    assert.deepEqual(list.result.tools.map((t) => t.name), ['echo', 'hidden'], 'a list the executor cannot read is handed on as it was, as any such answer is');
    const noted = await w.client.call('deepnote', { depth: DEPTH });
    assert.equal(noted.result?.content[0].text, 'After a deep notification.');
    assert.ok(w.client.others.some((m) => m.method === 'notifications/message'), 'the notification is handed on as it was');
    // Within the limit, a result is read and fingerprinted.
    const within = await w.client.call('deep', { depth: 50 });
    assert.equal(within.result?.content[0].text, 'deep');
    assert.equal((await w.client.call('echo', { a: 1 })).result?.isError, undefined, 'the executor is still there');
    assert.deepEqual(w.logs.filter((e) => e.event === 'server-line-not-read').map((e) => e.matched ?? null), ['call', 'call', 'list', null]);
    const stubs = stubsOf(await checkBook(w.executor.writer.book(), { issuerKeys: w.settings.agent.issuerKeys }));
    assert.deepEqual(stubs.map((s) => (docs(s)[RESULT_DOCUMENT] ? 'result' : docs(s)['provared.error'] === unreadable ? 'unreadable' : 'other')), ['unreadable', 'unreadable', 'result', 'result', 'result']);
  } finally {
    await w.close();
  }
});

test('HTTP: the agent\'s bodies nested 200,000 levels deep are refused, and the upstream\'s answers nested as deeply do not end the executor: a call\'s receipt says its answer could not be read', async () => {
  const w = await httpWorld();
  const unreadable = await identifierFingerprint(UNREADABLE_ANSWER);
  try {
    for (const [id, body] of [[1, ping(1, '1')], [2, echo(2, '1')], [3, ping(3, '{"total":1,"TOTAL":2}')], [4, ping(4, '{"total":1,"total":2}')]]) {
      const refused = await post(w, 'alpha', null, { raw: body });
      assert.equal(refused.status, 400, `request ${id}`);
      assert.equal(refused.json.error.code, CODES.invalidRequest);
      assert.equal(refused.json.id, id, 'the refusal names the request');
    }
    assert.equal(w.upstream.seen.length, 0, 'none reached the upstream');
    // The upstream's answers: a result and an error as a JSON body, a result as an event, and a list of tools each way.
    for (const how of ['deep-result', 'deep-error', 'deep-result-sse']) assert.equal((await call(w, 'alpha', 'odd', { how, depth: DEPTH })).status, 200, how);
    w.upstream.deepList(DEPTH);
    for (const params of [{}, { sse: true }]) {
      const list = await request(w, 'alpha', 'tools/list', params);
      assert.equal(list.status, 200);
      assert.ok(list.body.includes('"hidden"'), 'a list the executor cannot read is handed on as it was');
    }
    // Within the limit, a result is read and fingerprinted; and the executor is still there.
    assert.equal((await call(w, 'alpha', 'odd', { how: 'deep-result', depth: 50 })).status, 200);
    assert.equal((await call(w, 'alpha', 'echo', { a: 1 })).status, 200);
    const stubs = stubsOf(await checkBook(w.executor.agent('alpha').writer.book(), { issuerKeys: w.settings.agents.alpha.issuerKeys }));
    assert.deepEqual(stubs.map((s) => (docs(s)[RESULT_DOCUMENT] ? 'result' : docs(s)['provared.error'] === unreadable ? 'unreadable' : 'other')), ['unreadable', 'unreadable', 'unreadable', 'result', 'result']);
  } finally {
    await w.close();
  }
});
