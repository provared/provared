// A list of tools that the executor is to filter and cannot read is not
// handed to the agent (DESIGN.md, X250). With "hideUnlisted" the executor
// leaves out of the server's answer to tools/list the tools that have no
// rule. Where it cannot read that answer (nested too deeply, a member named
// twice, no "tools" in the result, another id), handing it on as it was
// would show the agent the tools it is to hide: the agent's request is
// answered with an error under its id instead, and the log says so.
// Nothing leaves this computer.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { gzipSync } from 'node:zlib';

const { checkBook, identifierFingerprint } = await import('provared');
const { LIST_NOT_READ, UNREADABLE_ANSWER } = await import('../executor.mjs');
const { CODES } = await import('../jsonrpc.mjs');
const { httpWorld, openHttpWorld, post, call, request } = await import('./http-world.mjs');
const { FAKE_SERVER, until, world } = await import('./world.mjs');

const DEPTH = 200000;

for (const [how, env] of [['nested 200,000 levels deep', { FAKE_DEEP_LIST: { value: String(DEPTH) } }], ['with a member named twice', { FAKE_ODD_LIST: { value: 'twice' } }], ['with no "tools" in its result, and the tools under "Tools"', { FAKE_ODD_LIST: { value: 'capital-only' } }]]) {
  test(`HTTP, in front of a local program: a list of tools ${how} is not handed on, and an answer nested as deeply does not end the executor`, async () => {
    const w = await httpWorld({ open: false });
    delete w.settings.upstream;
    w.settings.server = { command: process.execPath, args: [FAKE_SERVER], env };
    w.settings.tools = { echo: { action: 'provared.data.read' }, deep: { action: 'tool.run' }, deeperror: { action: 'tool.run' } };
    await openHttpWorld(w, { serverStderr: null });
    try {
      const begun = await post(w, 'alpha', { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } } });
      const headers = { 'mcp-session-id': begun.headers.get('mcp-session-id'), 'mcp-protocol-version': '2025-11-25' };
      const list = await post(w, 'alpha', { jsonrpc: '2.0', id: 'list-1', method: 'tools/list' }, { headers });
      assert.equal(list.status, 200, list.body.slice(0, 200));
      assert.equal(list.json.id, 'list-1');
      assert.equal(list.json.error?.code, CODES.internal);
      assert.equal(list.json.error.message, LIST_NOT_READ);
      assert.ok(!list.body.includes('hidden'), 'nothing the agent was sent names the tool with no rule');
      assert.equal(w.logs.filter((e) => e.event === 'tools-list-not-read').length, 1);
      // The agent's own body nested as deeply is refused, and the program's result and error nested as deeply are answers the executor cannot read.
      const deepBody = await post(w, 'alpha', null, { headers, raw: `{"jsonrpc":"2.0","id":2,"method":"ping","params":{"a":${'['.repeat(DEPTH)}1${']'.repeat(DEPTH)}}}` });
      assert.equal(deepBody.status, 400);
      assert.equal(deepBody.json.id, 2);
      for (const [id, tool] of [[3, 'deep'], [4, 'deeperror']]) assert.equal((await post(w, 'alpha', { jsonrpc: '2.0', id, method: 'tools/call', params: { name: tool, arguments: { depth: DEPTH } } }, { headers })).status, 200, tool);
      assert.equal((await post(w, 'alpha', { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'echo', arguments: {} } }, { headers })).status, 200, 'the executor goes on');
      const stubs = (await checkBook(w.executor.agent('alpha').writer.book(), { issuerKeys: w.settings.agents.alpha.issuerKeys })).entries.filter((e) => e.kind === 'stub');
      const unreadable = await identifierFingerprint(UNREADABLE_ANSWER);
      assert.deepEqual(stubs.map((s) => s.content.details.find((d) => d.name === 'provared.error')?.sha256 === unreadable), [true, true, false]);
    } finally {
      await w.close();
    }
  });
}

for (const [how, env] of [['nested 200,000 levels deep', { FAKE_DEEP_LIST: { value: String(DEPTH) } }], ['with a member named twice', { FAKE_ODD_LIST: { value: 'twice' } }], ['with no "tools" in its result, and the tools under "Tools"', { FAKE_ODD_LIST: { value: 'capital-only' } }]]) {
  test(`stdio: a list of tools ${how} is not handed on: the agent is answered with an error under its id`, async () => {
    const w = await world({ env });
    try {
      const list = await w.client.request('tools/list', {}, { id: 'list-1' });
      assert.equal(list.id, 'list-1');
      assert.equal(list.error?.code, CODES.internal, JSON.stringify(list).slice(0, 200));
      assert.equal(list.error.message, LIST_NOT_READ);
      assert.equal(list.result, undefined);
      assert.ok(!w.client.rawText.includes('hidden'), 'nothing the agent was sent names the tool with no rule');
      assert.equal(w.logs.filter((e) => e.event === 'tools-list-not-read').length, 1);
      assert.equal((await w.client.call('echo', { a: 1 })).result?.isError, undefined, 'the executor goes on');
    } finally {
      await w.close();
    }
  });
}

test('stdio: the server\'s own error to tools/list goes on as it is; and where the settings do not filter the list, an answer the executor cannot read is handed on as before', async () => {
  const refusing = await world({ env: { FAKE_ODD_LIST: { value: 'error' } } });
  try {
    assert.equal((await refusing.client.request('tools/list', {})).error?.code, -32601);
    assert.equal(refusing.logs.filter((e) => e.event === 'tools-list-not-read').length, 0);
  } finally {
    await refusing.close();
  }
  const unfiltered = await world({ config: { hideUnlisted: false }, env: { FAKE_ODD_LIST: { value: 'twice' } } });
  try {
    const list = await unfiltered.client.request('tools/list', {});
    assert.deepEqual(list.result?.tools.map((t) => t.name), ['echo', 'hidden']);
  } finally {
    await unfiltered.close();
  }
});

test('HTTP: a list of tools the executor cannot read is not handed on, as a JSON body or as an event stream: the agent is answered with an error under its id', async () => {
  const w = await httpWorld();
  try {
    for (const [how, set] of [['deep', (u) => u.deepList(DEPTH)], ['twice', (u) => u.oddList('twice')], ['capital-only', (u) => u.oddList('capital-only')], ['other-id', (u) => u.oddList('other-id')]]) {
      w.upstream.deepList(0);
      w.upstream.oddList(null);
      set(w.upstream);
      const asJson = await request(w, 'alpha', 'tools/list', {}, { id: `json-${how}` });
      assert.equal(asJson.status, 200, how);
      assert.equal(asJson.json.id, `json-${how}`, how);
      assert.equal(asJson.json.error?.code, CODES.internal, how);
      assert.equal(asJson.json.error.message, LIST_NOT_READ);
      assert.ok(!asJson.body.includes('hidden'), `${how}: nothing the agent was sent names the tool with no rule`);
      if (how === 'other-id') continue; // an event under another id is no answer to the request, and is handed on as any event that is not
      const asEvents = await request(w, 'alpha', 'tools/list', { sse: true }, { id: `sse-${how}` });
      assert.equal(asEvents.status, 200, how);
      assert.match(asEvents.type, /^text\/event-stream/);
      assert.ok(asEvents.body.includes(`"id":"sse-${how}"`) && asEvents.body.includes(String(CODES.internal)), `${how}: ${asEvents.body.slice(0, 200)}`);
      assert.ok(!asEvents.body.includes('hidden'), how);
    }
    assert.equal(w.logs.filter((e) => e.event === 'tools-list-not-read').length, 7);
    // The upstream's own error goes on as it is, and a list the executor can read is filtered as before.
    w.upstream.deepList(0);
    w.upstream.oddList('error');
    assert.equal((await request(w, 'alpha', 'tools/list', {})).json.error?.code, -32601);
    w.upstream.oddList(null);
    const usual = await request(w, 'alpha', 'tools/list', {});
    assert.ok(usual.json.result.tools.length > 0 && usual.json.result.tools.every((t) => t.name !== 'hidden'));
    assert.equal((await call(w, 'alpha', 'echo', { a: 1 })).status, 200, 'the executor goes on');
  } finally {
    await w.close();
  }
});

// What stays (X250): the executor answers for a list only where it can match the answer to the request. These hold the limit as it is, and are not a promise.
for (const how of ['id-twice', 'no-id', 'null-id', 'batch', 'bom']) {
  test(`stdio: a list of tools on a line the executor cannot match to the request (${how}) is handed on as it was, and the request is not answered`, async () => {
    const w = await world({ env: { FAKE_ODD_LIST: { value: how } } });
    try {
      const answer = w.client.request('tools/list', {}, { id: 'list-1', timeout: 1500 }).then(() => 'answered', () => 'not answered');
      await until(() => w.client.rawText.includes('hidden'));
      assert.equal(await answer, 'not answered');
      assert.equal(w.logs.filter((e) => e.event === 'tools-list-not-read').length, 0);
      assert.equal((await w.client.call('echo', { a: 1 })).result?.isError, undefined, 'the executor goes on');
    } finally {
      await w.close();
    }
  });
}

test('HTTP: a list of tools in an event the executor cannot match to the request (no id, another id, a list of messages) is handed on as it was', async () => {
  const w = await httpWorld();
  const tools = '{"tools":[{"name":"echo"},{"name":"hidden"}]}';
  try {
    for (const [how, data] of [['no id', () => `{"jsonrpc":"2.0","result":${tools}}`], ['another id', () => `{"jsonrpc":"2.0","id":"someone-else","result":${tools}}`], ['a list of messages', (id) => `[{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":${tools}}]`]]) {
      w.upstream.rawList({ status: 200, headers: { 'content-type': 'text/event-stream' }, body: (id) => `data: ${data(id)}\n\n` });
      const got = await request(w, 'alpha', 'tools/list', {}, { id: 'mine' });
      assert.equal(got.status, 200, how);
      assert.match(got.type, /^text\/event-stream/, how);
      assert.ok(got.body.includes('hidden') && !got.body.includes('"mine"'), `${how}: ${got.body.slice(0, 200)}`);
    }
    assert.equal(w.logs.filter((e) => e.event === 'tools-list-not-read').length, 0);
  } finally {
    await w.close();
  }
});

// X260. An upstream may refuse a request it could not read, or a session it does not know, with a 4xx and a JSON-RPC error under a null id.
const JSON_HEADERS = { 'content-type': 'application/json' };
const refusal = (id, error) => `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"error":${JSON.stringify(error)}}`;

test('HTTP: the upstream\'s own refusal of tools/list under a null id, or under another, is handed on as it is, with its status', async () => {
  const w = await httpWorld();
  try {
    for (const [status, body] of [
      [400, refusal(null, { code: -32600, message: 'Bad Request: the server could not read the request.' })],
      [404, refusal(null, { code: -32001, message: 'Session not found' })],
      [200, ' {"error": {"code": -32000, "message": "Busy", "data": {"retryAfter": 5}}, "id": "someone-else", "jsonrpc": "2.0"}\n'],
    ]) {
      w.upstream.rawList({ status, headers: JSON_HEADERS, body });
      const got = await request(w, 'alpha', 'tools/list', {}, { id: `mine-${status}` });
      assert.equal(got.status, status);
      assert.equal(got.body, body, 'the upstream\'s own words, unchanged');
      assert.equal(got.type, 'application/json');
      assert.equal(got.headers.get('content-length'), String(Buffer.byteLength(body)));
    }
    assert.equal(w.logs.filter((e) => e.event === 'tools-list-not-read').length, 0);
  } finally {
    await w.close();
  }
});

test('HTTP: an answer to tools/list that is not an error answer and nothing more is still not handed on, whatever its id and status', async () => {
  const w = await httpWorld();
  const error = { code: -32600, message: 'no' };
  const tools = '{"tools":[{"name":"echo"},{"name":"hidden"}]}';
  const cases = [
    ['a result beside the error', 400, `{"jsonrpc":"2.0","id":null,"error":${JSON.stringify(error)},"result":${tools}}`],
    ['a result under another spelling beside the error', 400, `{"jsonrpc":"2.0","id":null,"error":${JSON.stringify(error)},"Result":${tools}}`],
    ['a list beside the error', 400, `{"jsonrpc":"2.0","id":null,"error":${JSON.stringify(error)},"tools":[{"name":"hidden"}]}`],
    ['a result under a null id', 404, `{"jsonrpc":"2.0","id":null,"result":${tools}}`],
    ['the error given twice', 400, `{"jsonrpc":"2.0","id":null,"error":${JSON.stringify(error)},"error":{"code":1,"message":"hidden"}}`],
    ['a member given twice inside the error', 400, `{"jsonrpc":"2.0","id":null,"error":{"code":1,"message":"no","data":{"a":"hidden","a":2}}}`],
    ['a batch', 400, `[${refusal(null, { code: 1, message: 'hidden' })}]`],
    ['a byte order mark', 400, `﻿${refusal(null, { code: 1, message: 'hidden' })}`],
    ['an error that is text', 400, '{"jsonrpc":"2.0","id":null,"error":"hidden"}'],
    ['an error with no code', 400, '{"jsonrpc":"2.0","id":null,"error":{"message":"hidden"}}'],
    ['an id that is an object', 400, `{"jsonrpc":"2.0","id":{"result":${tools}},"error":${JSON.stringify(error)}}`],
    ['no "jsonrpc"', 400, '{"id":null,"error":{"code":1,"message":"hidden"}}'],
    ['a "jsonrpc" that is not 2.0', 400, '{"jsonrpc":"1.0","id":null,"error":{"code":1,"message":"hidden"}}'],
    ['an error nested 300 levels deep', 400, refusal(null, { code: 1, message: 'no', data: JSON.parse(`${'['.repeat(300)}"hidden"${']'.repeat(300)}`) })],
  ];
  try {
    for (const [how, status, body] of cases) {
      w.upstream.rawList({ status, headers: JSON_HEADERS, body });
      const got = await request(w, 'alpha', 'tools/list', {}, { id: 'mine' });
      assert.equal(got.status, status, how);
      assert.equal(got.json?.id, 'mine', how);
      assert.equal(got.json.error?.code, CODES.internal, how);
      assert.equal(got.json.error.message, LIST_NOT_READ, how);
      assert.equal(got.json.result, undefined, how);
      assert.ok(!got.body.includes('hidden'), `${how}: nothing the agent was sent names the tool with no rule`);
    }
    assert.equal(w.logs.filter((e) => e.event === 'tools-list-not-read').length, cases.length);
  } finally {
    await w.close();
  }
});

test('HTTP: the executor\'s own error in place of the upstream\'s answer is sent as JSON, with its own length, and not under the upstream\'s content type, encoding or word on caching', async () => {
  const w = await httpWorld();
  const listUnder = (id) => `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"tools":[{"name":"echo"},{"name":"hidden"}]}}`;
  try {
    for (const [how, answer] of [
      ['a page, 200', { status: 200, headers: { 'content-type': 'text/html; charset=iso-8859-1', 'cache-control': 'public, max-age=3600' }, body: '<html><body>hidden</body></html>' }],
      ['a page, 502', { status: 502, headers: { 'content-type': 'text/html', 'cache-control': 'public, max-age=3600' }, body: '<html><body>Bad gateway: hidden</body></html>' }],
      ['a compressed list, which the executor did not ask for', { status: 200, headers: { 'content-type': 'application/json', 'content-encoding': 'gzip', 'cache-control': 'max-age=60' }, body: (id) => gzipSync(listUnder(id)) }],
    ]) {
      w.upstream.rawList(answer);
      const got = await request(w, 'alpha', 'tools/list', {}, { id: 'mine' });
      assert.equal(got.status, answer.status, how);
      assert.equal(got.type, 'application/json; charset=utf-8', how);
      assert.equal(got.headers.get('content-length'), String(Buffer.byteLength(got.body)), how);
      assert.equal(got.headers.get('content-encoding'), null, how);
      assert.equal(got.headers.get('cache-control'), 'no-store', how);
      assert.deepEqual(got.json, { jsonrpc: '2.0', id: 'mine', error: { code: CODES.internal, message: LIST_NOT_READ } }, how);
    }
    // What is handed on keeps the upstream's content type and its word on caching, as before.
    w.upstream.rawList({ status: 200, headers: { 'content-type': 'application/json', 'cache-control': 'max-age=60' }, body: listUnder });
    const usual = await request(w, 'alpha', 'tools/list', {}, { id: 'mine' });
    assert.equal(usual.type, 'application/json');
    assert.equal(usual.headers.get('cache-control'), 'max-age=60');
    assert.deepEqual(usual.json.result.tools.map((t) => t.name), ['echo']);
  } finally {
    await w.close();
  }
});
