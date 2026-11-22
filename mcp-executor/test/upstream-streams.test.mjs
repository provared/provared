// The upstream's own requests, in front of an upstream with no sessions,
// with more than one agent: whose they are. A request the upstream sends on
// an agent's call stream is that agent's alone to answer; a stream of the
// upstream's messages that is tied to no request and no session (a GET
// without an Mcp-Session-Id) is not opened, since what comes on it is no
// one agent's.
import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { test } from 'node:test';

const { httpWorld, post, rawRequest, auth, beginSession, META } = await import('./http-world.mjs');
const { CODES } = await import('../jsonrpc.mjs');

/** A GET of the stream of server messages, as an agent: {status, headers, res}, the body still to be read. */
function openStream(w, agent, headers = {}) {
  return rawRequest(w, { method: 'GET', headers: { accept: 'text/event-stream', ...auth(w, agent), ...headers }, stream: true });
}

/** Read "res" until what has come satisfies "enough"; gives the text so far. */
function readUntil(res, enough, timeout = 5000) {
  return new Promise((done, failed) => {
    let text = '';
    const timer = setTimeout(() => failed(new Error(`not seen in time; had: ${text.slice(0, 300)}`)), timeout);
    const take = (c) => {
      text += c.toString('utf8');
      if (!enough(text)) return;
      clearTimeout(timer);
      res.off('data', take);
      done(text);
    };
    res.on('data', take);
    res.on('end', () => {
      clearTimeout(timer);
      if (enough(text)) done(text);
      else failed(new Error(`the stream ended; had: ${text.slice(0, 300)}`));
    });
  });
}

/** The messages in the events of "text". */
function messagesIn(text) {
  return text
    .split(/\r?\n\r?\n/)
    .map((b) => b.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.replace(/^data: ?/, '')).join('\n'))
    .filter((d) => d !== '')
    .map((d) => JSON.parse(d));
}

const answer = (id, account) => ({ jsonrpc: '2.0', id, result: { action: 'accept', content: { account } } });

test('upstream streams: with more than one agent, a GET without a session id is not opened (405) and the upstream is not asked; with one agent it is, and its requests are that agent\'s to answer, once', async () => {
  const w = await httpWorld();
  try {
    w.upstream.askOnStream();
    for (const agent of ['alpha', 'beta']) {
      const s = await openStream(w, agent);
      s.res.resume();
      assert.equal(s.status, 405, `${agent}'s stream`);
      assert.match(s.headers.get('allow') ?? '', /POST/);
    }
    assert.ok(!w.upstream.seen.some((s) => s.method === 'GET'), 'the upstream was not asked for a stream');
    assert.ok(w.logs.some((e) => e.event === 'refused' && e.code === 'stream-not-tied'));
  } finally {
    await w.close();
  }
  const one = await httpWorld({ agents: ['alpha'] });
  try {
    one.upstream.askOnStream();
    const s = await openStream(one, 'alpha');
    assert.equal(s.status, 200);
    const text = await readUntil(s.res, (t) => t.includes('roots/list'));
    const asked = messagesIn(text).find((m) => m.method === 'roots/list');
    assert.equal((await post(one, 'alpha', answer(asked.id, 'alpha'))).status, 202);
    assert.equal(one.upstream.answers.length, 1);
    // Answered once: the same id again is not the answer to a request of the upstream's.
    const again = await post(one, 'alpha', answer(asked.id, 'alpha'));
    assert.equal(again.status, 400);
    assert.equal(one.upstream.answers.length, 1);
    s.res.destroy();
  } finally {
    await one.close();
  }
});

test('upstream streams: the upstream\'s request on one agent\'s call stream reaches only that agent; another agent\'s answer under its id is refused (400) and not sent on; the agent\'s own is', async () => {
  const w = await httpWorld();
  try {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 'asking', method: 'tools/call', params: { name: 'odd', arguments: { how: 'ask' }, _meta: META } });
    const s = await rawRequest(w, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...auth(w, 'alpha') }, body, stream: true });
    assert.equal(s.status, 200);
    let text = await readUntil(s.res, (t) => t.includes('elicitation/create'));
    const asked = messagesIn(text).find((m) => m.method === 'elicitation/create');
    assert.ok(asked && asked.id !== undefined);
    // Beta, under the same id: refused, and nothing goes to the upstream.
    const before = w.upstream.seen.length;
    const theirs = await post(w, 'beta', answer(asked.id, 'beta'));
    assert.equal(theirs.status, 400);
    assert.equal(theirs.json.error.code, CODES.invalidRequest);
    assert.equal(w.upstream.seen.length, before, 'beta\'s answer was not sent on');
    assert.ok(w.logs.some((e) => e.event === 'refused' && e.code === 'response-not-asked'));
    // Alpha's own: sent on, and the call is answered with it.
    assert.equal((await post(w, 'alpha', answer(asked.id, 'alpha'))).status, 202);
    text += await readUntil(s.res, (t) => t.includes('answered:'));
    const result = messagesIn(text).find((m) => m.id === 'asking');
    assert.match(result.result.content[0].text, /"account":"alpha"/);
    // Answered once: again, refused.
    assert.equal((await post(w, 'alpha', answer(asked.id, 'alpha'))).status, 400);
  } finally {
    await w.close();
  }
});

test('upstream streams: under sessions, the upstream\'s request is answered under the session it came on; the same agent\'s answer under another of its sessions is refused (400) and not sent on', async () => {
  const w = await httpWorld();
  try {
    const [s1, s2] = [await beginSession(w, 'alpha'), await beginSession(w, 'alpha')];
    const under = (session) => ({ 'mcp-session-id': session, 'mcp-protocol-version': '2025-11-25' });
    const body = JSON.stringify({ jsonrpc: '2.0', id: 'asking', method: 'tools/call', params: { name: 'odd', arguments: { how: 'ask' } } });
    const s = await rawRequest(w, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...auth(w, 'alpha'), ...under(s1) }, body, stream: true });
    assert.equal(s.status, 200);
    let text = await readUntil(s.res, (t) => t.includes('elicitation/create'));
    const asked = messagesIn(text).find((m) => m.method === 'elicitation/create');
    const before = w.upstream.seen.length;
    const elsewhere = await post(w, 'alpha', answer(asked.id, 'other-session'), { headers: under(s2) });
    assert.equal(elsewhere.status, 400);
    assert.equal(w.upstream.seen.length, before, 'not sent on');
    assert.equal((await post(w, 'alpha', answer(asked.id, 'alpha'), { headers: under(s1) })).status, 202);
    text += await readUntil(s.res, (t) => t.includes('answered:'));
    assert.match(messagesIn(text).find((m) => m.id === 'asking').result.content[0].text, /"account":"alpha"/);
  } finally {
    await w.close();
  }
});
