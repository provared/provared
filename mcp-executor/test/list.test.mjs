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

const { LIST_NOT_READ } = await import('../executor.mjs');
const { CODES } = await import('../jsonrpc.mjs');
const { httpWorld, call, request } = await import('./http-world.mjs');
const { world } = await import('./world.mjs');

const DEPTH = 200000;

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
