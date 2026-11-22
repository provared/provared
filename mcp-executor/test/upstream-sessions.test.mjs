// Sessions in front of an upstream HTTP server (F3 and F4 of the check
// against the MCP SDK's advisories of October 2026): a call in flight is
// held by its session and its id, as in front of a local program, since a
// request's id is unique only within its session; and a session begun
// under one connection made through OAuth is not used under another.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { test } from 'node:test';

const { checkBook } = await import('provared');
const { httpWorld, post } = await import('./http-world.mjs');
const { oauthWorld, connect, bearer } = await import('./oauth-world.mjs');
const { until } = await import('./world.mjs');

const LEGACY = '2025-11-25';
const init = async (w, agent) => (await post(w, agent, { jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: LEGACY, capabilities: {}, clientInfo: { name: 'test', version: '1' } } })).headers.get('mcp-session-id');
const under = (session) => ({ 'mcp-session-id': session, 'mcp-protocol-version': LEGACY });
const callIn = (w, agent, session, id, name, args) => post(w, agent, { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }, { headers: under(session) });

test('F3: two sessions of one agent in front of an upstream each have their own ids: the same id in flight in both is taken, and a cancellation under one does not cut the other\'s call', async () => {
  const w = await httpWorld({ config: { timeout: 10000 } });
  try {
    const a1 = await init(w, 'alpha');
    const a2 = await init(w, 'alpha');
    assert.ok(a1 && a2 && a1 !== a2);
    // A slow call under id 9 in the first session.
    const first = callIn(w, 'alpha', a1, 9, 'slow', { ms: 1500, tag: 'session-a1' });
    await until(() => w.executor.agent('alpha').calls() === 1, { timeout: 5000 });
    await until(() => w.upstream.ran.some((r) => r.args.tag === 'session-a1'), { timeout: 5000 });
    // The same id in the second session, while the first is in flight: taken and answered.
    const second = await callIn(w, 'alpha', a2, 9, 'echo', { x: 2 });
    assert.equal(second.status, 200);
    assert.equal(second.json.id, 9);
    assert.equal(second.json.error, undefined, JSON.stringify(second.json));
    assert.deepEqual(second.json.result.structuredContent.args, { x: 2 });
    // A cancellation under the second session naming id 9: not the first session's call.
    const cancelled = await post(w, 'alpha', { jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 9 } }, { headers: under(a2) });
    assert.ok(cancelled.status < 300);
    const done = await first;
    assert.equal(done.status, 200);
    assert.equal(done.json.result.content[0].text, 'Done, slowly. session-a1', 'the first session\'s call ran to its end');
    const stubs = (await checkBook(w.executor.agent('alpha').writer.book(), { issuerKeys: w.settings.agents.alpha.issuerKeys })).entries.filter((e) => e.kind === 'stub');
    assert.equal(stubs.length, 2);
    assert.ok(stubs.every((s) => !s.content.details.some((d) => d.name === 'provared.error')), 'neither receipt says the call failed');
    // A cancellation under the call's own session still cuts it.
    const third = callIn(w, 'alpha', a1, 10, 'slow', { ms: 3000, tag: 'cut' });
    await until(() => w.upstream.ran.some((r) => r.args.tag === 'cut'), { timeout: 5000 });
    await post(w, 'alpha', { jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 10 } }, { headers: under(a1) });
    const cut = await third;
    assert.match(JSON.stringify(cut.json ?? cut.body), /cancelled/);
  } finally {
    await w.close();
  }
});

test('F4: a session an upstream opened under one connection made through OAuth is not used under the next connection of the same agent', async () => {
  const w = await oauthWorld();
  try {
    const c1 = await connect(w);
    const initialize = { jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: LEGACY, capabilities: {}, clientInfo: { name: 'test', version: '1' } } };
    const session = (await post(w, bearer(c1.access), initialize)).headers.get('mcp-session-id');
    assert.ok(session);
    assert.equal((await post(w, bearer(c1.access), { jsonrpc: '2.0', id: 1, method: 'ping' }, { headers: under(session) })).status, 200, 'its own connection may use it');
    const c2 = await connect(w);
    const ran = w.upstream.ran.length;
    const carried = await post(w, bearer(c2.access), { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { x: 1 } } }, { headers: under(session) });
    assert.equal(carried.status, 404);
    assert.equal(w.upstream.ran.length, ran, 'nothing reached the upstream');
    assert.ok(w.logs.some((e) => e.event === 'refused' && e.code === 'session-not-found'));
    // The session is forgotten: not even the agent's later connections can use it; a new one is begun.
    assert.equal((await post(w, bearer(c2.access), { jsonrpc: '2.0', id: 3, method: 'ping' }, { headers: under(session) })).status, 404);
    const fresh = (await post(w, bearer(c2.access), initialize)).headers.get('mcp-session-id');
    assert.equal((await post(w, bearer(c2.access), { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'echo', arguments: { x: 1 } } }, { headers: under(fresh) })).status, 200);
  } finally {
    await w.close();
  }
});
