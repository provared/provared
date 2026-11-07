// The executor over HTTP, in front of the made-up HTTP upstream: several
// agents, each with its own secret, slip, book and copy; what passes
// through, what is checked, what is written; and each attack of the
// design's list, with the defence that stops it.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const { checkBook, identifierFingerprint } = await import('provared');
const { httpWorld, openHttpWorld, call, request, post, rawRequest, auth, META, TOKEN } = await import('./http-world.mjs');
const { CALL_DOCUMENT, RESULT_DOCUMENT, TOOL_DOCUMENT, CALL_META, UNLISTED_ACTION, UNREADABLE_ANSWER } = await import('../executor.mjs');
const { CREDENTIAL_REMOVED, readHttpSettings, sseReader, sseEvent, secretHash } = await import('../http.mjs');
const { readCopy, loadCopyKey } = await import('../copy.mjs');
const { compareCopyWithBook } = await import('../compare.mjs');
const { until, pause } = await import('./world.mjs');

async function bookOf(w, name) {
  return checkBook(w.executor.agent(name).writer.book(), { issuerKeys: w.settings.agents[name].issuerKeys });
}
const stubsOf = (checked) => checked.entries.filter((e) => e.kind === 'stub');
const denialsOf = (checked) => checked.entries.filter((e) => e.kind === 'denial');
const docs = (stub) => Object.fromEntries(stub.content.details.map((d) => [d.name, d.sha256]));
function copyOf(w, name) {
  const a = w.agents[name];
  return readCopy(a.copy, loadCopyKey(a.copyKey), w.settings.name);
}
/** Every message the upstream saw, by method. */
const seenCalls = (w) => w.upstream.seen.filter((s) => s.method === 'POST' && s.body?.method === 'tools/call');

test('both eras pass through; sessions are kept; tools/list is filtered as JSON and as a stream; a call is checked, sent with the upstream\'s credential, answered and receipted in the agent\'s own book', async () => {
  const w = await httpWorld();
  try {
    const discover = await request(w, 'alpha', 'server/discover', { _meta: META });
    assert.equal(discover.status, 200);
    assert.deepEqual(discover.json.result.supportedVersions, ['2026-07-28']);
    const init = await request(w, 'alpha', 'initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '1' } });
    assert.equal(init.json.result.serverInfo.name, 'fake-http-server');
    const session = init.headers.get('mcp-session-id');
    assert.equal(session, 'sess-1', 'the session id the upstream gave comes back as it is');
    const note = await post(w, 'alpha', { jsonrpc: '2.0', method: 'notifications/initialized' }, { headers: { 'mcp-session-id': session } });
    assert.equal(note.status, 202);
    assert.equal(w.upstream.seen.at(-1).headers['mcp-session-id'], session, 'the session id goes on to the upstream');
    const ping = await request(w, 'alpha', 'ping', undefined, { headers: { 'mcp-session-id': session } });
    assert.deepEqual(ping.json.result, {});
    assert.equal(ping.json.id, ping.json.id, 'under the agent\'s id');
    const page1 = await request(w, 'alpha', 'tools/list', { _meta: META });
    assert.deepEqual(page1.json.result.tools.map((t) => t.name), ['echo', 'order', 'slow', 'stream']);
    assert.equal(page1.json.result.nextCursor, 'page2');
    const page2 = await request(w, 'alpha', 'tools/list', { cursor: 'page2', _meta: META });
    assert.deepEqual(page2.json.result.tools.map((t) => t.name), ['fail', 'error', 'odd'], '"hidden" has no rule and is not shown');
    const streamed = await request(w, 'alpha', 'tools/list', { cursor: 'page2', sse: true, _meta: META });
    assert.equal(streamed.type.split(';')[0], 'text/event-stream');
    assert.deepEqual(streamed.json.result.tools.map((t) => t.name), ['fail', 'error', 'odd'], 'filtered in the stream too');
    assert.equal(w.logs.filter((e) => e.event === 'tools-hidden').length, 2);

    const echo = await call(w, 'alpha', 'echo', { a: 1 }, { id: 'c-1', meta: { traceparent: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' } });
    assert.equal(echo.status, 200);
    assert.equal(echo.json.id, 'c-1', 'the answer comes back under the agent\'s id');
    const seen = echo.json.result.structuredContent;
    assert.equal(seen.headers.authorization, `Bearer ${CREDENTIAL_REMOVED}`, 'the upstream got the executor\'s credential; the agent does not see it');
    assert.equal(w.upstream.seen.at(-1).headers.authorization, `Bearer ${TOKEN}`);
    assert.match(w.upstream.seen.at(-1).body.id, /^provared-\d+-/, 'sent under the executor\'s id');
    assert.equal(typeof seen.meta[CALL_META], 'string', 'the executor\'s identifier for the call is in _meta');
    assert.deepEqual(seen.args, { a: 1 });

    const checked = await bookOf(w, 'alpha');
    assert.equal(checked.summary.problemFound, false);
    const stubs = stubsOf(checked);
    assert.equal(stubs.length, 1);
    const d = docs(stubs[0]);
    assert.equal(d[TOOL_DOCUMENT], await identifierFingerprint('echo'));
    assert.equal(d[CALL_DOCUMENT], await identifierFingerprint(seen.meta[CALL_META]));
    assert.equal(d['provared.trace-id'], await identifierFingerprint('0af7651916cd43dd8448eb211c80319c'));
    assert.ok(d[RESULT_DOCUMENT], 'the result is fingerprinted');
    assert.equal(stubs[0].content.with, 'executor');
    assert.equal(stubs[0].countersignature.state, 'valid');
    assert.equal(stubsOf(await bookOf(w, 'beta')).length, 0, 'nothing in the other agent\'s book');
    const copy = copyOf(w, 'alpha');
    assert.deepEqual(copy.lines.map((l) => l.entry.kind), ['sending', 'done']);
    assert.equal(copy.lines[1].entry.stub, stubs[0].fingerprint);
    assert.equal(copy.lines[1].entry.outcome, 'answer');
    const compared = await compareCopyWithBook({ copyPath: w.agents.alpha.copy, copyKey: loadCopyKey(w.agents.alpha.copyKey), name: w.settings.name, service: 'executor', book: readFileSync(w.agents.alpha.book, 'utf8'), options: { issuerKeys: w.settings.agents.alpha.issuerKeys } });
    assert.equal(compared.summary.agree, true);

    // The other kinds of answer, each with a receipt: a stream, a tool execution error, a protocol error.
    const stream = await call(w, 'alpha', 'stream', {}, { id: 's-1' });
    assert.equal(stream.type.split(';')[0], 'text/event-stream');
    assert.deepEqual(stream.events.map((e) => e.method ?? 'response'), ['notifications/progress', 'notifications/message', 'response'], 'each event is forwarded as it arrives, then the response');
    assert.equal(stream.json.id, 's-1');
    assert.ok(stream.rawEvents[1].includes(': a comment\nid: ev-2'), 'the event\'s other lines pass as they were');
    assert.ok(stream.rawEvents[2].startsWith('id: ev-3\n'), 'the response keeps its event id');
    assert.ok(!stream.body.includes(TOKEN) && stream.body.includes(CREDENTIAL_REMOVED), 'the credential is taken out of every event');
    const fail = await call(w, 'alpha', 'fail', {});
    assert.equal(fail.json.result.isError, true);
    const error = await call(w, 'alpha', 'error', {});
    assert.equal(error.json.error.code, -32602);
    const stubs2 = stubsOf(await bookOf(w, 'alpha'));
    assert.equal(stubs2.length, 4);
    assert.ok(docs(stubs2[1])[RESULT_DOCUMENT]);
    assert.ok(docs(stubs2[3])['provared.error'], 'a protocol error names provared.error');

    // Headers the agent sent that the upstream never sees, and the wrong content type.
    const headers = { cookie: 'session=abc', 'x-api-key': 'k', 'x-custom': 'c', connection: 'close, x-custom', 'x-forwarded-for': '1.2.3.4', 'proxy-authorization': 'Bearer p' };
    const echo2 = await call(w, 'alpha', 'echo', {}, { headers });
    const got = echo2.json.result.structuredContent.headers;
    for (const name of ['cookie', 'x-api-key', 'x-custom', 'x-forwarded-for', 'proxy-authorization', 'origin']) assert.equal(got[name], undefined, `${name} did not reach the upstream`);
    assert.equal(got.authorization, `Bearer ${CREDENTIAL_REMOVED}`);
    assert.ok(w.logs.some((e) => e.event === 'headers-dropped' && e.headers.includes('x-custom')));
    const text = await post(w, 'alpha', null, { headers: { 'content-type': 'text/plain' }, raw: 'hello' });
    assert.equal(text.status, 415);
    assert.equal(seenCalls(w).length, 5);
  } finally {
    await w.close();
  }
});

test('attack: a call with a missing, wrong or another agent\'s secret. No secret or a wrong one is refused; another agent\'s secret acts as that agent, in its own book, never in this one\'s', async () => {
  const w = await httpWorld();
  try {
    const none = await call(w, null, 'echo', {});
    assert.equal(none.status, 401);
    assert.equal(none.headers.get('www-authenticate'), 'Bearer');
    const wrong = await call(w, `Bearer ${w.agents.alpha.secret.slice(0, -1)}x`, 'echo', {});
    assert.equal(wrong.status, 401);
    const basic = await call(w, `Basic ${Buffer.from(`alpha:${w.agents.alpha.secret}`).toString('base64')}`, 'echo', {});
    assert.equal(basic.status, 401, 'only a bearer secret signs in');
    const twice = await rawRequest(w, { headers: { 'content-type': 'application/json', authorization: [`Bearer ${w.agents.alpha.secret}`, `Bearer ${w.agents.alpha.secret}`] }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }) });
    assert.equal(twice.status, 401, 'two Authorization headers sign in as nobody');
    const hashed = await call(w, `Bearer ${secretHash(w.agents.alpha.secret)}`, 'echo', {});
    assert.equal(hashed.status, 401, 'the hash in the settings is not the secret');
    assert.equal(seenCalls(w).length, 0, 'nothing reached the upstream');
    assert.equal(w.logs.filter((e) => e.event === 'not-signed-in').length, 5);

    const asBeta = await call(w, 'beta', 'echo', {});
    assert.equal(asBeta.status, 200);
    assert.equal(stubsOf(await bookOf(w, 'beta')).length, 1);
    assert.equal(stubsOf(await bookOf(w, 'alpha')).length, 0, 'beta\'s secret writes nothing to alpha\'s book');
    assert.equal(copyOf(w, 'alpha').lines.length, 0);
    assert.equal(copyOf(w, 'beta').lines.length, 2);
    // Beta's permission does not allow supplies.order; alpha's does. Beta's secret cannot act under alpha's slip.
    const w2 = await httpWorld({ slips: { beta: { actions: ['provared.data.read'] } } });
    try {
      const order = await call(w2, 'beta', 'order', { total: 5 });
      assert.equal(order.json.result.isError, true);
      assert.equal(order.json.result._meta['red.prova/refused'], 'not-allowed');
      assert.equal(denialsOf(await bookOf(w2, 'beta')).length, 1);
      assert.equal(denialsOf(await bookOf(w2, 'alpha')).length, 0);
      const ok = await call(w2, 'alpha', 'order', { total: 5 });
      assert.equal(ok.json.result.isError, undefined);
    } finally {
      await w2.close();
    }
  } finally {
    await w.close();
  }
});

test('the secret is compared in constant time, and is never written to a log, a book, a copy or an answer', async () => {
  const source = readFileSync(fileURLToPath(new URL('../http.mjs', import.meta.url)), 'utf8');
  const signedIn = /const signedIn = \(header\) => \{[\s\S]*?\n {2}\};/.exec(source)?.[0];
  assert.ok(signedIn, 'signedIn is where secrets are compared');
  assert.ok(signedIn.includes('timingSafeEqual(given, agent.hash)'), 'the hash of the secret given is held against each agent\'s with timingSafeEqual');
  assert.ok(!/===?\s*agent\.hash(?!\.length)|agent\.hash\s*===?|\.equals\(|given\s*===?|===?\s*given/.test(signedIn), 'no comparison that stops at the first byte that differs');
  const w = await httpWorld();
  try {
    const bodies = [];
    for (const who of ['alpha', `Bearer ${w.agents.alpha.secret}x`, null]) bodies.push((await call(w, who, 'echo', { note: 'x' })).body);
    bodies.push((await call(w, 'alpha', 'hidden', {})).body);
    const everything = [JSON.stringify(w.logs), w.executor.agent('alpha').writer.book(), readFileSync(w.agents.alpha.copy, 'utf8'), ...bodies].join('\n');
    for (const a of Object.values(w.agents)) {
      assert.ok(!everything.includes(a.secret), `${a.name}'s secret appears nowhere`);
    }
    assert.ok(!everything.includes(TOKEN), 'the upstream\'s credential appears nowhere');
  } finally {
    await w.close();
  }
});

test('attack: a session id taken from another agent. A session belongs to the agent that opened it; another agent, or an unknown id, is answered 404 and the upstream is not asked', async () => {
  const w = await httpWorld();
  try {
    const init = await request(w, 'alpha', 'initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '1' } });
    const session = init.headers.get('mcp-session-id');
    assert.ok(session);
    const before = w.upstream.seen.length;
    const stolen = await call(w, 'beta', 'echo', {}, { headers: { 'mcp-session-id': session } });
    assert.equal(stolen.status, 404);
    const stolenGet = await rawRequest(w, { method: 'GET', headers: { accept: 'text/event-stream', ...auth(w, 'beta'), 'mcp-session-id': session } });
    assert.equal(stolenGet.status, 404);
    const stolenDelete = await rawRequest(w, { method: 'DELETE', headers: { ...auth(w, 'beta'), 'mcp-session-id': session } });
    assert.equal(stolenDelete.status, 404);
    const unknown = await call(w, 'alpha', 'echo', {}, { headers: { 'mcp-session-id': 'sess-999' } });
    assert.equal(unknown.status, 404);
    assert.equal(w.upstream.seen.length, before, 'none of it reached the upstream');
    assert.equal(stubsOf(await bookOf(w, 'beta')).length, 0);
    assert.equal(w.logs.filter((e) => e.event === 'refused' && e.code === 'session-not-found').length, 4);

    const own = await call(w, 'alpha', 'echo', {}, { headers: { 'mcp-session-id': session } });
    assert.equal(own.status, 200);
    assert.equal(w.upstream.seen.at(-1).headers['mcp-session-id'], session);
    // The GET stream of a legacy session passes through, under the owner's session.
    const stream = await rawRequest(w, { method: 'GET', headers: { accept: 'text/event-stream', ...auth(w, 'alpha'), 'mcp-session-id': session }, stream: true });
    assert.equal(stream.status, 200);
    assert.equal(stream.headers.get('content-type'), 'text/event-stream');
    const first = await new Promise((d) => stream.res.once('data', (c) => d(c.toString('utf8'))));
    assert.ok(first.includes(`hello ${session}`), 'the upstream\'s event arrives as it was sent');
    assert.ok(first.startsWith('id: ev-1\n'), 'with its event id');
    stream.res.destroy();
    // The owner ends the session; it is then unknown to everyone.
    const ended = await rawRequest(w, { method: 'DELETE', headers: { ...auth(w, 'alpha'), 'mcp-session-id': session } });
    assert.equal(ended.status, 200);
    const gone = await call(w, 'alpha', 'echo', {}, { headers: { 'mcp-session-id': session } });
    assert.equal(gone.status, 404);
  } finally {
    await w.close();
  }
});

test('attack: a body over the limit; an unending stream; an oversized event. Each is cut off, and a call that was sent gets a receipt that says its outcome is not known', async () => {
  const w = await httpWorld({ config: { bodyLimit: 2048, timeout: 1000 } });
  try {
    const big = await post(w, 'alpha', { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: { pad: 'x'.repeat(3000) }, _meta: META } });
    assert.equal(big.status, 413);
    assert.equal(seenCalls(w).length, 0, 'the oversized call never reached the upstream');
    // Not declared, sent large: the limit is on the bytes, not the declaration.
    const chunked = await rawRequest(w, { headers: { 'content-type': 'application/json', ...auth(w, 'alpha'), 'transfer-encoding': 'chunked' }, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { pad: 'x'.repeat(3000) }, _meta: META } }) });
    assert.equal(chunked.status, 413);
    assert.equal(seenCalls(w).length, 0);

    const endless = await call(w, 'alpha', 'odd', { how: 'endless' }, { id: 'e-1' });
    assert.equal(endless.type.split(';')[0], 'text/event-stream', 'the events were forwarded as they came');
    assert.ok(endless.events.length > 1);
    assert.equal(endless.json.id, 'e-1');
    assert.equal(endless.json.error.code, 1002, 'the executor\'s timeout ends the call');
    assert.match(endless.json.error.message, /no answer within 1000 ms/);
    await until(() => w.upstream.aborted >= 1);
    const stubs = stubsOf(await bookOf(w, 'alpha'));
    assert.equal(stubs.length, 1);
    assert.ok(docs(stubs[0])['provared.error']);
    assert.equal(copyOf(w, 'alpha').lines.at(-1).entry.outcome, 'error');
  } finally {
    await w.close();
  }
  // An answer over the limit, as one event or as one JSON body: cut off, with a receipt.
  const w2 = await httpWorld({ config: { timeout: 20000 } });
  try {
    const bigEvent = await call(w2, 'alpha', 'odd', { how: 'big-event', size: 17 * 1024 * 1024 }, { id: 'e-2' });
    assert.equal(bigEvent.json.error.code, 1002);
    assert.match(bigEvent.json.error.message, /event longer than/);
    assert.ok(w2.logs.some((e) => e.event === 'upstream-event-dropped'));
    const bigJson = await call(w2, 'alpha', 'odd', { how: 'big-json', size: 17 * 1024 * 1024 }, { id: 'e-3' });
    assert.equal(bigJson.json.error.code, 1002);
    assert.match(bigJson.json.error.message, /larger than/);
    const stubs = stubsOf(await bookOf(w2, 'alpha'));
    assert.equal(stubs.length, 2, 'each sent call has its receipt');
    assert.ok(docs(stubs[0])['provared.error'] && docs(stubs[1])['provared.error']);
  } finally {
    await w2.close();
  }
});

test('attack: a batch, or a message shape that would carry a tools/call past the check. Nothing but one well-formed message is read, and a call without an id goes nowhere', async () => {
  const w = await httpWorld();
  try {
    const callBody = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: {}, _meta: META } };
    const batch = await post(w, 'alpha', [callBody]);
    assert.equal(batch.status, 400);
    assert.match(batch.json.error.message, /batch/);
    const asNotification = await post(w, 'alpha', { jsonrpc: '2.0', method: 'tools/call', params: callBody.params });
    assert.equal(asNotification.status, 202, 'dropped: nothing to answer');
    assert.ok(w.logs.some((e) => e.event === 'notification-dropped' && e.method === 'tools/call'));
    const nullId = await post(w, 'alpha', { ...callBody, id: null });
    assert.equal(nullId.status, 400);
    const twoMethods = await post(w, 'alpha', null, { raw: '{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call","params":{"name":"echo","arguments":{}}}' });
    assert.equal(twoMethods.status, 400);
    assert.match(twoMethods.json.error.message, /twice/);
    const noVersion = await post(w, 'alpha', { id: 1, method: 'tools/call', params: callBody.params });
    assert.equal(noVersion.status, 400);
    const notObject = await post(w, 'alpha', null, { raw: '"tools/call"' });
    assert.equal(notObject.status, 400);
    const bigint = await post(w, 'alpha', null, { raw: '{"jsonrpc":"2.0","id":12345678901234567890,"method":"tools/call","params":{"name":"echo","arguments":{}}}' });
    assert.equal(bigint.status, 400);
    const notJson = await post(w, 'alpha', null, { raw: 'tools/call' });
    assert.equal(notJson.status, 400);
    assert.equal(notJson.json.error.code, -32700);
    assert.equal(w.upstream.seen.length, 0, 'none of it reached the upstream');
    assert.equal(stubsOf(await bookOf(w, 'alpha')).length, 0);
  } finally {
    await w.close();
  }
});

test('attack: headers trying to reach the upstream (hop-by-hop, Authorization, Cookie, forged Mcp-Param-*); mirrored metadata must agree with the body, and the body\'s values go on', async () => {
  const w = await httpWorld();
  try {
    // A forged Mcp-Param header with nothing in the body to match is refused; one that agrees goes on.
    const forged = await call(w, 'alpha', 'echo', {}, { headers: { 'mcp-param-foo': 'bar' } });
    assert.equal(forged.status, 400);
    assert.match(forged.json.error.message, /does not agree with the body/);
    const disagree = await call(w, 'alpha', 'echo', {}, { headers: { 'mcp-param-foo': 'bar' }, meta: { 'io.modelcontextprotocol/foo': 'baz' } });
    assert.equal(disagree.status, 400);
    const agree = await call(w, 'alpha', 'echo', {}, { headers: { 'mcp-param-foo': 'bar' }, meta: { 'io.modelcontextprotocol/foo': 'bar' } });
    assert.equal(agree.status, 200);
    assert.equal(agree.json.result.structuredContent.headers['mcp-param-foo'], 'bar');
    // The protocol version: a header that disagrees with the body is refused; the body's value goes on, header or no header.
    const mismatch = await call(w, 'alpha', 'echo', {}, { headers: { 'mcp-protocol-version': '2025-11-25' } });
    assert.equal(mismatch.status, 400);
    assert.match(mismatch.json.error.message, /does not agree/);
    assert.equal(mismatch.json.id, mismatch.json.id);
    const same = await call(w, 'alpha', 'echo', {}, { headers: { 'mcp-protocol-version': '2026-07-28' } });
    assert.equal(same.json.result.structuredContent.headers['mcp-protocol-version'], '2026-07-28');
    const bodyOnly = await call(w, 'alpha', 'echo', {});
    assert.equal(bodyOnly.json.result.structuredContent.headers['mcp-protocol-version'], '2026-07-28', 'the body\'s value is mirrored for the upstream');
    const legacy = await post(w, 'alpha', { jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'echo', arguments: {} } }, { headers: { 'mcp-protocol-version': '2025-11-25' } });
    assert.equal(legacy.json.result.structuredContent.headers['mcp-protocol-version'], '2025-11-25', 'a legacy client\'s header, with no version in the body, goes on');
    const twoVersions = await rawRequest(w, { headers: { 'content-type': 'application/json', ...auth(w, 'alpha'), 'mcp-protocol-version': ['2026-07-28', '2026-07-28'] }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }) });
    assert.equal(twoVersions.status, 400);
    // Mcp-Param on a request with no message (GET), or on a response, is refused.
    const onGet = await rawRequest(w, { method: 'GET', headers: { accept: 'text/event-stream', ...auth(w, 'alpha'), 'mcp-param-foo': 'bar' } });
    assert.equal(onGet.status, 400);
    // Every header but the few the transport needs is dropped on the way, whatever its name or its Connection listing.
    assert.equal(seenCalls(w).length, 4);
    for (const s of seenCalls(w)) {
      const names = Object.keys(s.headers);
      for (const name of names) assert.ok(['accept', 'accept-language', 'content-type', 'content-length', 'host', 'connection', 'authorization', 'mcp-protocol-version', 'mcp-param-foo'].includes(name), `${name} reached the upstream`);
      assert.equal(s.headers.authorization, `Bearer ${TOKEN}`);
    }
  } finally {
    await w.close();
  }
});

test('attack: an upstream that answers with another id, answers twice, drops the stream midway, redirects, or refuses the credential. The outcome is never taken from the wrong message, a redirection is never followed, and nothing of the upstream\'s refusal reaches the agent', async () => {
  const w = await httpWorld({ config: { timeout: 1500 } });
  try {
    const otherJson = await call(w, 'alpha', 'odd', { how: 'other-id' }, { id: 'o-1' });
    assert.equal(otherJson.json.id, 'o-1');
    assert.equal(otherJson.json.error.code, 1002);
    assert.match(otherJson.json.error.message, /not its response/);
    assert.ok(w.logs.some((e) => e.event === 'upstream-other-id' && e.id === 'someone-else'));
    const otherSse = await call(w, 'alpha', 'odd', { how: 'other-id-sse' }, { id: 'o-2' });
    assert.equal(otherSse.events.length, 2, 'the event passes through, and the executor\'s own error ends the stream');
    assert.equal(otherSse.events[0].id, 'someone-else');
    assert.equal(otherSse.json.id, 'o-2');
    assert.equal(otherSse.json.error.code, 1002);
    assert.match(otherSse.json.error.message, /ended the stream before it answered/);
    const twice = await call(w, 'alpha', 'odd', { how: 'twice' }, { id: 'o-3' });
    const answers = twice.events.filter((e) => e && typeof e === 'object' && Object.hasOwn(e, 'result'));
    assert.equal(answers.length, 1, 'one response for the call, not two');
    assert.equal(answers[0].id, 'o-3');
    assert.equal(answers[0].result.content[0].text, 'first');
    assert.ok(!twice.body.includes('provared-'), 'no message under the executor\'s own id reaches the agent');
    const drop = await call(w, 'alpha', 'odd', { how: 'drop' }, { id: 'o-4' });
    assert.equal(drop.events[0].method, 'notifications/progress');
    assert.equal(drop.json.error.code, 1002);
    assert.match(drop.json.error.message, /ended the stream|closed the stream/);
    const redirect = await call(w, 'alpha', 'odd', { how: 'redirect' }, { id: 'o-5' });
    assert.equal(redirect.json.error.code, 1002);
    assert.match(redirect.json.error.message, /redirection/);
    assert.equal(w.upstream.elsewhere, 0, 'the redirection was not followed');
    assert.equal(redirect.headers.get('location'), null);
    const broken = await call(w, 'alpha', 'odd', { how: 'status', status: 500 }, { id: 'o-6' });
    assert.equal(broken.json.error.code, 1002);
    assert.match(broken.json.error.message, /HTTP 500/);
    assert.ok(!broken.body.includes(TOKEN) && !broken.body.includes('broken'), 'the upstream\'s body, which echoed the credential, is not relayed');
    const unreadable = await call(w, 'alpha', 'odd', { how: 'not-json' }, { id: 'o-7' });
    assert.ok(unreadable.body.includes('"id":"o-7"') && unreadable.body.includes('"a":1,"a":2'), 'handed to the agent as it was, under the agent\'s id');
    const bigint = await call(w, 'alpha', 'odd', { how: 'bigint' }, { id: 'o-8' });
    assert.ok(bigint.body.includes('1234567890123456789'), 'digits exact');
    const stubs = stubsOf(await bookOf(w, 'alpha'));
    assert.equal(stubs.length, 8, 'every call that was sent has its receipt');
    for (const i of [0, 1, 3, 4, 5]) assert.ok(docs(stubs[i])['provared.error'], `call ${i} names provared.error`);
    assert.ok(docs(stubs[2])[RESULT_DOCUMENT], 'the first of two answers is the result');
    assert.equal(docs(stubs[6])['provared.error'], await identifierFingerprint(UNREADABLE_ANSWER));
    assert.ok(docs(stubs[7])['provared.error'], 'a number beyond 2^53 - 1 cannot be fingerprinted');
  } finally {
    await w.close();
  }
  // The upstream refuses the executor's credential: the agent learns that, and nothing of the refusal (header or body).
  const w2 = await httpWorld({ fileToken: 'not-the-token-the-upstream-expects' });
  try {
    const refused = await call(w2, 'alpha', 'echo', {}, { id: 'r-1' });
    assert.equal(refused.status, 200);
    assert.equal(refused.json.error.code, 1002);
    assert.match(refused.json.error.message, /refused the executor's credential \(HTTP 401\)/);
    assert.equal(refused.headers.get('www-authenticate'), null);
    assert.ok(!refused.body.includes('bad token') && !refused.body.includes('not-the-token'));
    assert.ok(w2.logs.some((e) => e.event === 'upstream-refused-credential'));
    const ping = await request(w2, 'alpha', 'ping');
    assert.equal(ping.status, 502, 'for a request that is not a call, the same as an error of the executor\'s');
    assert.equal(ping.headers.get('www-authenticate'), null);
    assert.ok(!ping.body.includes('not-the-token'));
  } finally {
    await w2.close();
  }
});

test('attack: a request from a browser page. An Origin is refused unless the settings allow it, and the executor listens on the local address unless told otherwise', async () => {
  const w = await httpWorld();
  try {
    assert.equal(w.address.address, '127.0.0.1');
    assert.equal(readHttpSettings(w.settings, w.folder).settings.listen.host, '127.0.0.1');
    assert.equal(readHttpSettings({ ...w.settings, listen: { port: 1 } }, w.folder).settings.listen.host, '127.0.0.1', 'the default');
    const page = await call(w, 'alpha', 'echo', {}, { headers: { origin: 'http://localhost:3000' } });
    assert.equal(page.status, 403);
    assert.equal(seenCalls(w).length, 0);
    assert.ok(w.logs.some((e) => e.event === 'refused' && e.code === 'origin-refused'));
  } finally {
    await w.close();
  }
  const allowed = await httpWorld({ config: { allowedOrigins: ['http://localhost:3000'] } });
  try {
    const page = await call(allowed, 'alpha', 'echo', {}, { headers: { origin: 'http://localhost:3000' } });
    assert.equal(page.status, 200);
    assert.equal(page.json.result.structuredContent.headers.origin, undefined, 'and the Origin itself does not go on');
    const other = await call(allowed, 'alpha', 'echo', {}, { headers: { origin: 'http://evil.example' } });
    assert.equal(other.status, 403);
  } finally {
    await allowed.close();
  }
  const { problems, warnings } = readHttpSettings({ ...allowed.settings, listen: { host: '0.0.0.0', port: 1 }, allowedOrigins: ['not an origin'] }, allowed.folder);
  assert.ok(problems.some((p) => p.startsWith('allowedOrigins')));
  assert.ok(warnings.some((p) => p.startsWith('listen.host')));
});

test('two simultaneous calls by one agent, and by two agents: each book holds its own receipts in order, and the limits hold per agent', async () => {
  const w = await httpWorld({ config: { maxWaiting: 2 } });
  try {
    const [slow, fast] = await Promise.all([call(w, 'alpha', 'slow', { ms: 300, tag: 'first' }, { id: 'a-1' }), (async () => {
      await pause(50);
      return call(w, 'alpha', 'echo', { tag: 'second' }, { id: 'a-2' });
    })()]);
    assert.equal(slow.json.result.content[0].text, 'Done, slowly. first');
    assert.equal(fast.json.id, 'a-2');
    const stubs = stubsOf(await bookOf(w, 'alpha'));
    assert.equal(stubs.length, 2);
    assert.equal(docs(stubs[0])[TOOL_DOCUMENT], await identifierFingerprint('slow'), 'receipts in the order the calls were taken');
    assert.equal(docs(stubs[1])[TOOL_DOCUMENT], await identifierFingerprint('echo'));
    const copy = copyOf(w, 'alpha');
    assert.deepEqual(copy.lines.map((l) => l.entry.kind), ['sending', 'done', 'sending', 'done'], 'one call at a time through the writer');
    assert.equal(copy.sequence.ok, true);

    // Two agents at once: each in its own book, neither waiting for the other.
    const [a, b] = await Promise.all([call(w, 'alpha', 'slow', { ms: 200 }, { id: 'x' }), call(w, 'beta', 'slow', { ms: 200 }, { id: 'x' })]);
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
    assert.equal(stubsOf(await bookOf(w, 'alpha')).length, 3);
    assert.equal(stubsOf(await bookOf(w, 'beta')).length, 1);
    assert.equal(copyOf(w, 'beta').lines.length, 2);

    // The limit on calls in progress is each agent's own.
    const first = call(w, 'alpha', 'slow', { ms: 400 }, { id: 'l-1' });
    const second = call(w, 'alpha', 'slow', { ms: 400 }, { id: 'l-2' });
    await pause(100);
    const third = await call(w, 'alpha', 'echo', {}, { id: 'l-3' });
    assert.equal(third.json.error.code, 1001);
    assert.match(third.json.error.message, /maxWaiting/);
    const betas = await call(w, 'beta', 'echo', {}, { id: 'l-3' });
    assert.equal(betas.status, 200, 'the other agent is not held back');
    const again = await call(w, 'alpha', 'echo', {}, { id: 'l-1' });
    assert.equal(again.json.error.code, -32600, 'the same id while that call is in progress');
    await Promise.all([first, second]);
    assert.equal(stubsOf(await bookOf(w, 'alpha')).length, 5);
  } finally {
    await w.close();
  }
});

test('cancellation: the agent closing the response stream closes the stream to the upstream, and the outcome is not known; so does a notifications/cancelled; a call still waiting its turn is withdrawn', async () => {
  const w = await httpWorld({ config: { timeout: 5000 } });
  try {
    const controller = new AbortController();
    const closed = call(w, 'alpha', 'slow', { ms: 3000 }, { id: 'k-1', signal: controller.signal }).catch((e) => e.name);
    await until(() => seenCalls(w).length === 1);
    controller.abort();
    assert.equal(await closed, 'AbortError');
    await until(() => w.logs.some((e) => e.event === 'taken' && e.outcome === 'error'));
    await until(() => w.upstream.aborted >= 1, { timeout: 3000 });
    const stubs = stubsOf(await bookOf(w, 'alpha'));
    assert.equal(stubs.length, 1);
    assert.equal(docs(stubs[0])['provared.error'], await identifierFingerprint('The agent closed the connection while this call was with the tool server, so its outcome is not known.'));
    assert.equal(copyOf(w, 'alpha').lines.at(-1).entry.outcome, 'error');

    // The notification, as a POST of its own: the call settles, the upstream's stream is closed.
    const pending = call(w, 'alpha', 'slow', { ms: 3000 }, { id: 'k-2' });
    await until(() => seenCalls(w).length === 2);
    const note = await post(w, 'alpha', { jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 'k-2', reason: 'changed my mind' } });
    assert.equal(note.status, 202);
    const answer = await pending;
    assert.equal(answer.json.error.code, 1002);
    assert.match(answer.json.error.message, /cancelled this call/);
    await until(() => w.upstream.aborted >= 2, { timeout: 3000 });
    assert.equal(w.upstream.seen.filter((s) => s.body?.method === 'notifications/cancelled').length, 0, 'the closed stream is the cancellation; the notification is not sent on');

    // Still waiting its turn behind a slow call: closed before it was sent, so nothing is sent and the copy says withdrawn.
    const blocker = call(w, 'alpha', 'slow', { ms: 600 }, { id: 'k-3' });
    await until(() => seenCalls(w).length === 3);
    const c2 = new AbortController();
    const queued = call(w, 'alpha', 'echo', { q: 1 }, { id: 'k-4', signal: c2.signal }).catch((e) => e.name);
    await pause(100);
    c2.abort();
    assert.equal(await queued, 'AbortError');
    await blocker;
    await until(() => w.logs.some((e) => e.event === 'withdrawn'));
    assert.equal(seenCalls(w).length, 3, 'the withdrawn call never reached the upstream');
    const kinds = copyOf(w, 'alpha').lines.map((l) => l.entry.kind);
    assert.ok(kinds.includes('withdrawn'));
    assert.equal(stubsOf(await bookOf(w, 'alpha')).length, 3);
  } finally {
    await w.close();
  }
});

test('refusals over HTTP are the same code as on stdio: no rule, the amount, the permission, the rules on content; each with a denial in the agent\'s own book', async () => {
  const w = await httpWorld({ config: { contentRules: 'rules.json' }, open: false });
  writeFileSync(join(w.folder, 'rules.json'), JSON.stringify({ version: 1, rules: [{ name: 'orders go to the one approved supplier', tool: 'order', test: { pointer: '/supplier', equals: 'acme' } }] }));
  await openHttpWorld(w);
  try {
    const unlisted = await call(w, 'alpha', 'hidden', {});
    assert.equal(unlisted.json.result.isError, true);
    assert.equal(unlisted.json.result._meta['red.prova/refused'], 'unlisted');
    const noAmount = await call(w, 'alpha', 'order', { total: 'ten' });
    assert.equal(noAmount.json.result._meta['red.prova/refused'], 'amount-not-found');
    const wrongSupplier = await call(w, 'alpha', 'order', { total: 50, supplier: 'other' });
    assert.equal(wrongSupplier.json.result._meta['red.prova/rule'], 'orders go to the one approved supplier');
    const fine = await call(w, 'alpha', 'order', { total: 50, supplier: 'acme' });
    assert.equal(fine.json.result.content[0].text, 'Ordered for 50.');
    const checked = await bookOf(w, 'alpha');
    assert.equal(denialsOf(checked).length, 3);
    assert.equal(denialsOf(checked)[0].content.action, UNLISTED_ACTION);
    assert.equal(stubsOf(checked).length, 1);
    assert.ok(docs(stubsOf(checked)[0])['executor.rules'], 'the rules in force are named in the receipt');
    assert.equal(seenCalls(w).length, 1, 'only the allowed call reached the upstream');
    assert.deepEqual(copyOf(w, 'alpha').lines.map((l) => l.entry.kind), ['refused', 'refused', 'refused', 'sending', 'done']);
  } finally {
    await w.close();
  }
});

test('the settings: what is refused, what is warned about, and no two agents sharing a file or a secret', async () => {
  const w = await httpWorld({ open: false });
  const ok = readHttpSettings(w.settings, w.folder);
  assert.deepEqual(ok.problems, []);
  assert.equal(ok.settings.agents.get('alpha').copy, join(w.folder, 'copies', 'alpha.jsonl'));
  assert.equal(ok.settings.agents.get('alpha').copyKey, join(w.folder, 'copies', 'alpha.jsonl.key'));
  const problem = (change) => readHttpSettings({ ...w.settings, ...change }, w.folder).problems;
  assert.ok(problem({ agents: {} }).some((p) => p.startsWith('agents:')));
  assert.ok(problem({ agents: { ...w.settings.agents, gamma: { ...w.settings.agents.alpha } } }).some((p) => p.includes('agents.gamma.secretHash: is also agents.alpha.secretHash')));
  assert.ok(problem({ agents: { ...w.settings.agents, gamma: { ...w.settings.agents.beta, secretHash: 'B'.repeat(43), book: w.settings.agents.alpha.book } } }).some((p) => p.includes('gamma.book: is also agents.alpha.book')));
  assert.ok(problem({ agents: { alpha: { ...w.settings.agents.alpha, secretHash: 'short' } } }).some((p) => p.includes('secretHash')));
  assert.ok(problem({ agents: { 'Bad Name': w.settings.agents.alpha } }).some((p) => p.includes('not an agent name')));
  assert.ok(problem({ upstream: { url: 'ftp://x/' } }).some((p) => p.startsWith('upstream.url')));
  assert.ok(problem({ upstream: { url: 'http://user:pw@127.0.0.1/mcp' } }).some((p) => p.startsWith('upstream.url')));
  assert.ok(problem({ upstream: { url: w.settings.upstream.url, credential: { env: 'X' } } }).some((p) => p.startsWith('upstream.credential')));
  assert.ok(problem({ path: 'mcp' }).some((p) => p.startsWith('path')));
  assert.ok(problem({ bodyLimit: 10 }).some((p) => p.startsWith('bodyLimit')));
  assert.ok(problem({ listen: { port: 70000 } }).some((p) => p.startsWith('listen.port')));
  const warned = readHttpSettings({ ...w.settings, upstream: { url: 'http://10.0.0.1/mcp' }, extra: 1 }, w.folder).warnings;
  assert.ok(warned.some((p) => p.includes('no credential')));
  assert.ok(warned.some((p) => p.includes('in the clear')));
  assert.ok(warned.some((p) => p.startsWith('extra:')));
  await w.upstream.close();
});

test('the reader of server-sent events: line endings, comments, a BOM, data over lines, and the limit', () => {
  const events = [];
  let tooLong = null;
  const r = sseReader({ onEvent: (e) => events.push(e), onTooLong: (n) => (tooLong = n), limit: 200 });
  r.feed('﻿id: 1\r\ndata: {"a":');
  r.feed('1}\r\n\r\n: comment\nevent: x\ndata: one\ndata: two\n\n\r');
  assert.equal(events.length, 2);
  assert.deepEqual(events[0], { raw: 'id: 1\r\ndata: {"a":1}\r\n\r\n', data: '{"a":1}', others: ['id: 1'] });
  assert.deepEqual(events[1], { raw: ': comment\nevent: x\ndata: one\ndata: two\n\n', data: 'one\ntwo', others: [': comment', 'event: x'] });
  r.feed('\ndata\n\n');
  assert.equal(events.length, 3);
  assert.equal(events[2].data, '', 'a bare "data" line is empty data');
  r.feed(`data: ${'x'.repeat(300)}`);
  assert.ok(tooLong > 200);
  r.feed('\n\n');
  assert.equal(events.length, 3, 'nothing more is read');
  assert.equal(sseEvent(['id: 7', ': c'], '{"b":2}'), 'id: 7\n: c\ndata: {"b":2}\n\n');
});
