// Member names that differ only in capitals (DESIGN.md, X241). A tool
// server whose JSON reader ignores capitals takes "Method" for "method" and
// "Name" for "name", the later one winning. The executor reads names
// exactly, so a message with both was one message to the executor and
// another to such a server: a tool the executor never checked was run, or
// another tool than the receipt names. These tests send such messages on
// every transport, in front of a made-up server that reads names that way
// (FAKE_FOLD in fake-server.mjs, foldNames() in fake-http-server.mjs), and
// read the server's own record of what it ran. Nothing leaves this computer.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { checkBook, identifierFingerprint } = await import('provared');
const { CALL_META, RESULT_DOCUMENT, UNREADABLE_ANSWER } = await import('../executor.mjs');
const { CODES, misspelt, readMessage } = await import('../jsonrpc.mjs');
const { httpWorld, openHttpWorld, post, call } = await import('./http-world.mjs');
const { FAKE_SERVER, TOOLS, world } = await import('./world.mjs');

const stubsOf = (checked) => checked.entries.filter((e) => e.kind === 'stub');
const docs = (stub) => Object.fromEntries(stub.content.details.map((d) => [d.name, d.sha256]));
const ORDER = { name: 'order', arguments: { total: 999999 } };
const LONG_S = 'ſ';
const KELVIN = 'K';

/**
 * Messages that a reader that ignores capitals reads as a call of "order"
 * for 999,999, and that the executor, reading names exactly, read as
 * something else. Each is made for an id. The first three are the review's
 * probes.
 */
const TWO_READINGS = [
  ['a ping to the executor, a tools/call to the server ("Method")', (id) => ({ jsonrpc: '2.0', id, method: 'ping', Method: 'tools/call', params: ORDER })],
  ['a call of echo to the executor, of order to the server ("Name", "Arguments")', (id) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'echo', Name: 'order', arguments: {}, Arguments: { total: 999999 } } })],
  ['a notification to the executor, a request to the server ("Method", "ID")', (id) => ({ jsonrpc: '2.0', method: 'notifications/initialized', Method: 'tools/call', ID: id, params: ORDER })],
  ['"METHOD" before "method"', (id) => ({ jsonrpc: '2.0', id, METHOD: 'ping', method: 'ping', mEthod: 'tools/call', params: ORDER })],
  ['a second "Params"', (id) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'echo' }, Params: ORDER })],
  ['a second params with the long s', (id) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'echo' }, [`param${LONG_S}`]: ORDER })],
  ['a response to the executor, a request to the server', (id) => ({ jsonrpc: '2.0', id, result: {}, Method: 'tools/call', Params: ORDER })],
  ['"NAME" after "name", and no second arguments', (id) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'echo', arguments: { total: 999999 }, NAME: 'order' } })],
  ['a second arguments with the long s', (id) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'order', arguments: { total: 1 }, [`argument${LONG_S}`]: { total: 999999 } } })],
  ['"Arguments" beside "arguments": the amount the executor checked is not the one the server acts on', (id) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'order', arguments: { total: 1 }, Arguments: { total: 999999 } } })],
  ['"Arguments" alone: the executor saw no arguments', (id) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'echo', Arguments: { total: 999999 }, Name: 'order' } })],
];

test('readMessage: a member at the top level other than the six of JSON-RPC is refused, from the agent and from the server', () => {
  for (const strictNumbers of [true, false]) {
    const read = (v) => readMessage(Buffer.from(JSON.stringify(v)), { strictNumbers });
    for (const extra of ['Method', 'METHOD', 'Id', 'ID', 'Params', `param${LONG_S}`, 'Result', `re${LONG_S}ult`, 'Error', 'JSONRPC', `j${LONG_S}onrpc`, 'Jsonrpc', '_meta', 'other', '__proto__']) {
      for (const base of [{ jsonrpc: '2.0', id: 1, method: 'ping' }, { jsonrpc: '2.0', method: 'notifications/initialized' }, { jsonrpc: '2.0', id: 1, result: {} }, { jsonrpc: '2.0', id: 1, error: { code: 1, message: 'x' } }]) {
        const got = readMessage(Buffer.from(`${JSON.stringify(base).slice(0, -1)},${JSON.stringify(extra)}:"tools/call"}`), { strictNumbers });
        assert.equal(got.refused?.code, CODES.invalidRequest, `${extra} beside ${Object.keys(base).join(', ')}`);
        assert.equal(got.kind, undefined);
      }
    }
    // The refusal names the request, where its id is written exactly.
    assert.equal(read({ jsonrpc: '2.0', id: 'k', method: 'ping', Method: 'tools/call' }).id, 'k');
    assert.equal(read({ jsonrpc: '2.0', ID: 'k', method: 'ping' }).id, null);
    // The six, as written, are read as before.
    assert.equal(read({ jsonrpc: '2.0', id: 1, method: 'ping', params: {} }).kind, 'request');
    assert.equal(read({ jsonrpc: '2.0', method: 'notifications/initialized' }).kind, 'notification');
    assert.equal(read({ jsonrpc: '2.0', id: 1, result: {} }).kind, 'response');
    assert.equal(read({ jsonrpc: '2.0', id: 1, error: { code: 1, message: 'x' } }).kind, 'response');
  }
});

test('readMessage: the agent\'s params with two names in one object that differ only in capitals are refused, at any depth; the server\'s are not read for it', () => {
  const read = (params, method = 'tools/call', more = {}) => readMessage(Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 7, method, params })), more);
  const refused = [
    { name: 'echo', Name: 'order' },
    { name: 'echo', arguments: {}, ARGUMENTS: {} },
    { name: 'echo', arguments: {}, [`argument${LONG_S}`]: {} },
    { name: 'echo', _meta: {}, _META: {} },
    { name: 'echo', arguments: { total: 1, Total: 2 } },
    { name: 'echo', arguments: { a: { b: [{ k: 1, [KELVIN]: 2 }] } } },
    { name: 'echo', arguments: { 'straße': 1, STRASSE: 2 } },
    { name: 'echo', _meta: { progressToken: 1, ProgressToken: 2 } },
    { name: 'echo', _meta: { [CALL_META]: 'a', [CALL_META.toUpperCase()]: 'b' } },
  ];
  for (const params of refused) {
    const got = read(params);
    assert.equal(got.refused?.code, CODES.invalidRequest, JSON.stringify(params));
    assert.equal(got.id, 7, 'the refusal names the request');
    assert.equal(read(params, 'tools/call', { strictNumbers: false }).kind, 'request', 'a line of the server is not read for it');
  }
  // In every method, not only a tool call.
  assert.equal(read({ uri: 'a', URI: 'b' }, 'resources/read').refused?.code, CODES.invalidRequest);
  assert.equal(read({ requestId: 1, RequestId: 2 }, 'notifications/cancelled').refused?.code, CODES.invalidRequest);
  // A name the executor reads, written in other capitals with the exact one absent.
  for (const params of [{ Name: 'order' }, { name: 'echo', Arguments: {} }, { name: 'echo', [`argument${LONG_S}`]: {} }, { name: 'echo', _Meta: {} }, { name: 'echo', _META: {} }]) {
    assert.equal(read(params).refused?.code, CODES.invalidRequest, JSON.stringify(params));
  }
  assert.equal(read({ RequestId: 1 }, 'notifications/cancelled').refused?.code, CODES.invalidRequest);
  // The same name in two objects, and names that differ in more than capitals, are read.
  assert.equal(read({ name: 'echo', arguments: { name: 'x', Arguments: 1, a: { A: 1 }, b: [{ a: 1 }, { A: 2 }], total: 1, totals: 2 } }).kind, 'request');
  assert.equal(read({ Name: 'x' }, 'resources/read').kind, 'request', 'the executor reads no name in the params of another method');
  assert.equal(misspelt({ name: 1, other: 2 }, ['name']), null);
  assert.equal(misspelt({ name: 1, NAME: 2 }, ['name']), 'NAME');
  assert.equal(misspelt({ [KELVIN]: 1 }, ['k']), KELVIN);
});

/** What the made-up program ran, by its own record: the tools' names. */
const ranByProgram = (log) => (existsSync(log) ? readFileSync(log, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((e) => Object.hasOwn(e, 'ran')) : []);

test('stdio: no message with two readings reaches a server that ignores capitals, and no receipt names a tool the server did not run', async () => {
  const w = await world({ env: { FAKE_FOLD: { value: '1' } } });
  try {
    let id = 100;
    for (const [, make] of TWO_READINGS) w.client.send(make(id++));
    // The _meta names of the executor's own, in other capitals.
    w.client.send({ jsonrpc: '2.0', id: id++, method: 'tools/call', params: { name: 'order', arguments: { total: 999999 }, _meta: { [CALL_META.toUpperCase()]: 'the-agent-s-own' } } });
    w.client.send({ jsonrpc: '2.0', id: id++, method: 'tools/call', params: { name: 'order', arguments: { total: 999999 }, _meta: { Traceparent: 'x' } } });
    const answer = await w.client.call('echo', { a: 1 });
    assert.equal(answer.result.isError, undefined, JSON.stringify(answer));
    const refusals = w.client.others.filter((m) => m.error?.code === CODES.invalidRequest);
    assert.equal(refusals.length, TWO_READINGS.length + 2, 'each is refused as a message the executor does not read');
    assert.equal(w.client.others.length, refusals.length, 'and nothing else is answered');
    assert.deepEqual(ranByProgram(w.fakeLog).map((e) => e.ran), ['echo'], 'the server ran the one call the executor checked');
    assert.equal(w.fakeSeen().filter((e) => e.seen).length, 1, 'and saw no other message');
    const stubs = stubsOf(await checkBook(w.executor.writer.book(), { issuerKeys: w.settings.agent.issuerKeys }));
    assert.deepEqual(stubs.map((s) => s.content.action), ['provared.data.read']);
  } finally {
    await w.close();
  }
});

test('stdio: an answer of the server with a second result or id in other capitals is not read as a result, and a list with such names is not shown', async () => {
  const w = await world({ config: { tools: { ...TOOLS, capresult: { action: 'tool.run' }, capid: { action: 'tool.run' } } }, env: { FAKE_CAPITAL_LIST: { value: '1' } } });
  try {
    for (const tool of ['capresult', 'capid']) await w.client.call(tool, {});
    const stubs = stubsOf(await checkBook(w.executor.writer.book(), { issuerKeys: w.settings.agent.issuerKeys }));
    assert.equal(stubs.length, 2);
    for (const stub of stubs) {
      assert.equal(docs(stub)['provared.error'], await identifierFingerprint(UNREADABLE_ANSWER), 'the receipt says the answer could not be read');
      assert.equal(docs(stub)[RESULT_DOCUMENT], undefined, 'and names no result');
    }
    const list = await w.client.request('tools/list', {});
    assert.deepEqual(list.result.tools.map((t) => t.name), ['echo'], 'a tool with a second name in other capitals is not shown');
    assert.deepEqual(Object.keys(list.result), ['tools'], 'and a second list is left out');
    assert.equal(w.logs.find((e) => e.event === 'tools-hidden')?.hidden, 2);
  } finally {
    await w.close();
  }
});

test('HTTP, in front of an upstream: no message with two readings reaches a server that ignores capitals', async () => {
  const w = await httpWorld();
  try {
    w.upstream.foldNames();
    let id = 100;
    for (const [what, make] of TWO_READINGS) {
      const answer = await post(w, 'alpha', make(id++));
      assert.equal(answer.status, 400, what);
      assert.equal(answer.json.error.code, CODES.invalidRequest, what);
    }
    const meta = await post(w, 'alpha', { jsonrpc: '2.0', id: id++, method: 'tools/call', params: { name: 'order', arguments: { total: 999999 }, _meta: { [CALL_META.toUpperCase()]: 'the-agent-s-own' } } });
    assert.equal(meta.json.error.code, CODES.invalidRequest);
    const answer = await call(w, 'alpha', 'echo', { a: 1 });
    assert.equal(answer.status, 200, answer.body);
    assert.deepEqual(w.upstream.ran.map((r) => r.name), ['echo'], 'the server ran the one call the executor checked');
    assert.equal(w.upstream.seen.filter((s) => s.method === 'POST').length, 1, 'and saw no other message');
    const stubs = stubsOf(await checkBook(w.executor.agent('alpha').writer.book(), { issuerKeys: w.settings.agents.alpha.issuerKeys }));
    assert.deepEqual(stubs.map((s) => s.content.action), ['provared.data.read']);
    // An answer of the upstream with a second result or id in other capitals.
    for (const how of ['capital-result', 'capital-id']) await call(w, 'alpha', 'odd', { how });
    const after = stubsOf(await checkBook(w.executor.agent('alpha').writer.book(), { issuerKeys: w.settings.agents.alpha.issuerKeys })).slice(1);
    assert.equal(after.length, 2);
    for (const stub of after) {
      assert.equal(docs(stub)['provared.error'], await identifierFingerprint(UNREADABLE_ANSWER), 'the receipt says the answer could not be read');
      assert.equal(docs(stub)[RESULT_DOCUMENT], undefined);
    }
  } finally {
    await w.close();
  }
});

test('HTTP, in front of a local program: no message with two readings reaches a program that ignores capitals', async () => {
  const w = await httpWorld({ open: false });
  delete w.settings.upstream;
  w.fakeLog = join(w.folder, 'fake.log');
  w.settings.server = { command: process.execPath, args: [FAKE_SERVER], env: { FAKE_LOG: { value: w.fakeLog }, FAKE_FOLD: { value: '1' } } };
  w.settings.tools = { echo: { action: 'provared.data.read' }, order: { action: 'supplies.order', amount: { unit: 'GBP', pointer: '/total' } }, capresult: { action: 'tool.run' }, capid: { action: 'tool.run' } };
  await openHttpWorld(w, { serverStderr: null });
  try {
    const begun = await post(w, 'alpha', { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } } });
    assert.equal(begun.status, 200, begun.body);
    const headers = { 'mcp-session-id': begun.headers.get('mcp-session-id'), 'mcp-protocol-version': '2025-11-25' };
    let id = 100;
    for (const [what, make] of TWO_READINGS) {
      const answer = await post(w, 'alpha', make(id++), { headers });
      assert.equal(answer.status, 400, what);
      assert.equal(answer.json.error.code, CODES.invalidRequest, what);
    }
    const meta = await post(w, 'alpha', { jsonrpc: '2.0', id: id++, method: 'tools/call', params: { name: 'order', arguments: { total: 999999 }, _meta: { [CALL_META.toUpperCase()]: 'the-agent-s-own' } } }, { headers });
    assert.equal(meta.json.error.code, CODES.invalidRequest);
    const answer = await post(w, 'alpha', { jsonrpc: '2.0', id: id++, method: 'tools/call', params: { name: 'echo', arguments: { a: 1 } } }, { headers });
    assert.equal(answer.status, 200, answer.body);
    assert.deepEqual(ranByProgram(w.fakeLog).map((e) => e.ran), ['echo'], 'the program ran the one call the executor checked');
    const book = () => checkBook(w.executor.agent('alpha').writer.book(), { issuerKeys: w.settings.agents.alpha.issuerKeys });
    assert.deepEqual(stubsOf(await book()).map((s) => s.content.action), ['provared.data.read']);
    // An answer of the program with a second result or id in other capitals.
    for (const tool of ['capresult', 'capid']) await post(w, 'alpha', { jsonrpc: '2.0', id: id++, method: 'tools/call', params: { name: tool, arguments: {} } }, { headers });
    const after = stubsOf(await book()).slice(1);
    assert.equal(after.length, 2);
    for (const stub of after) {
      assert.equal(docs(stub)['provared.error'], await identifierFingerprint(UNREADABLE_ANSWER), 'the receipt says the answer could not be read');
      assert.equal(docs(stub)[RESULT_DOCUMENT], undefined);
    }
  } finally {
    await w.close();
  }
});
