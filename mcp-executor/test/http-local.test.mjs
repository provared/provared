// The HTTP executor in front of a local program (DESIGN.md, section 10.1):
// the tool server is a program the executor starts, one for each MCP
// session, and speaks to over its standard input and output, as the stdio
// executor does. Everything goes through the executor's public interface:
// its settings, and HTTP requests to the address it listens on. The program
// is the tests' made-up server (fake-server.mjs). Nothing leaves this
// computer.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook, identifierFingerprint } = await import('provared');
const { EXECUTOR_STOPPED, SERVER_ENDED } = await import('../executor.mjs');
const { checkHttpConfig, openHttpExecutor, readHttpSettings } = await import('../http.mjs');
const { SESSIONS_MAX, SESSION_IDLE } = await import('../local.mjs');
const { CODES } = await import('../jsonrpc.mjs');
const { TOKEN, httpWorld, openHttpWorld, post, rawRequest, auth } = await import('./http-world.mjs');
const { oauthWorld, reopen, connect, token, json, bearer } = await import('./oauth-world.mjs');
const { FAKE_SERVER, tempFolder, until } = await import('./world.mjs');

const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));
/** The rules: "ask" is mapped to an action that the tests' permission does not allow, unless a test says otherwise. */
const TOOLS = { echo: { action: 'provared.data.read' }, slow: { action: 'slow.work' }, crash: { action: 'tool.run' }, ask: { action: 'not.in.the.permission' } };
const stubsOf = (checked) => checked.entries.filter((e) => e.kind === 'stub');
const docs = (stub) => Object.fromEntries(stub.content.details.map((d) => [d.name, d.sha256]));

/** Turn a world's settings from an upstream HTTP server to the made-up program: its credential comes from a file, as the upstream's did. */
function makeLocal(w, { server = {}, config = {} } = {}) {
  delete w.settings.upstream;
  w.fakeLog = join(w.folder, 'fake.log');
  w.settings.server = { command: process.execPath, args: [FAKE_SERVER], env: { FAKE_TOKEN: { file: 'secrets/upstream' }, FAKE_LOG: { value: w.fakeLog } }, ...server };
  w.settings.tools = TOOLS;
  Object.assign(w.settings, config);
  return w;
}

/** A world whose executor stands in front of the made-up program, the agents signing in with their secrets. */
async function localWorld({ agents = ['alpha', 'beta'], server, config, open = true } = {}) {
  const w = makeLocal(await httpWorld({ agents, open: false }), { server, config });
  if (open) await openHttpWorld(w, { serverStderr: null });
  return w;
}

/** What the made-up program saw, in every session: each message, in order. */
const seenByProgram = (w) => (existsSync(w.fakeLog) ? readFileSync(w.fakeLog, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
const bookOf = (w, name) => checkBook(w.executor.agent(name).writer.book(), { issuerKeys: w.settings.agents[name].issuerKeys });
const events = (w, event) => w.logs.filter((e) => e.event === event);

const initialize = (id = 1) => ({ jsonrpc: '2.0', id, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } } });
const under = (session) => ({ 'mcp-session-id': session, 'mcp-protocol-version': '2025-11-25' });
/** Begin a session as an agent: {answer, session}. */
async function begin(w, agent) {
  const answer = await post(w, agent, initialize());
  return { answer, session: answer.headers.get('mcp-session-id') };
}
const ask = (w, agent, session, message) => post(w, agent, message, { headers: under(session) });
const callIn = (w, agent, session, name, args, id = 2) => ask(w, agent, session, { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });

test('a full call to a local program, by an agent\'s secret: a session is begun, the list is filtered, the call is checked, receipted, countersigned and copied, the program holds the credential, and the session\'s end ends the program', async () => {
  const w = await localWorld();
  try {
    assert.equal(w.executor.programs(), 0, 'no program runs until a session is begun');
    const { answer, session } = await begin(w, 'alpha');
    assert.equal(answer.status, 200, answer.body);
    assert.equal(answer.json.id, 1, 'the answer comes back under the agent\'s id');
    assert.equal(answer.json.result.serverInfo.name, 'fake-server');
    assert.match(session, /^[A-Za-z0-9_-]{43}$/, 'the session id is 32 random bytes in base64url');
    assert.equal(w.executor.programs(), 1);
    assert.equal(w.executor.agent('alpha').sessions(), 1);
    assert.equal((await ask(w, 'alpha', session, { jsonrpc: '2.0', method: 'notifications/initialized' })).status, 202, 'a notification is answered 202');

    const list = await ask(w, 'alpha', session, { jsonrpc: '2.0', id: 'list-1', method: 'tools/list' });
    assert.equal(list.status, 200);
    assert.match(list.type, /^application\/json/, 'one JSON body');
    assert.equal(list.json.id, 'list-1');
    assert.deepEqual(list.json.result.tools.map((t) => t.name).sort(), ['crash', 'echo', 'slow'], 'the tools with no rule are hidden, as on stdio');

    const echo = await callIn(w, 'alpha', session, 'echo', { a: 1 }, 7);
    assert.equal(echo.status, 200, echo.body);
    assert.equal(echo.json.id, 7);
    assert.deepEqual(echo.json.result.structuredContent.args, { a: 1 });
    assert.equal(echo.json.result.structuredContent.token, TOKEN, 'the program was started with its credential, read from the file');
    assert.equal(echo.json.result.structuredContent.agentSecret, null);
    assert.ok(!echo.body.includes(w.agents.alpha.secret));
    const seen = seenByProgram(w).filter((s) => s.seen?.method === 'tools/call');
    assert.equal(seen.length, 1);
    assert.notEqual(seen[0].seen.id, 7, 'the program is sent the executor\'s own id, not the agent\'s');

    const book = await bookOf(w, 'alpha');
    assert.ok(book.summary.intact && book.summary.withinSlips && !book.summary.problemFound);
    assert.equal(stubsOf(book).length, 1);
    assert.equal(stubsOf(book)[0].countersignature?.state, 'valid', 'the receipt is countersigned');
    assert.ok(docs(stubsOf(book)[0])['provared.tool-result']);
    assert.equal(stubsOf(await bookOf(w, 'beta')).length, 0, 'nothing is written in another agent\'s book');
    const copy = readFileSync(w.agents.alpha.copy, 'utf8');
    assert.ok(copy.includes('"sending"') && copy.includes('"done"'), 'the executor\'s copy holds the call');

    // A call the permission does not allow is refused before anything reaches the program.
    const refused = await callIn(w, 'alpha', session, 'ask', {}, 8);
    assert.equal(refused.json.result.isError, true);
    assert.equal(refused.json.result._meta['red.prova/refused'], 'not-allowed');
    assert.equal(seenByProgram(w).filter((s) => s.seen?.method === 'tools/call').length, 1, 'the refused call did not reach the program');

    const ended = await rawRequest(w, { method: 'DELETE', headers: { ...auth(w, 'alpha'), ...under(session) } });
    assert.equal(ended.status, 204);
    assert.equal((await callIn(w, 'alpha', session, 'echo', {}, 9)).status, 404, 'an ended session is not known');
    await until(() => w.executor.programs() === 0);
    assert.ok(seenByProgram(w).some((s) => s.stdinEnded), 'the program was ended by closing its input');
    assert.equal(events(w, 'session-ended').at(-1).why, 'ended-by-agent');
  } finally {
    await w.close();
  }
});

test('a message with no session, and a session misused: each is refused, and nothing is started', async () => {
  const w = await localWorld();
  try {
    const none = await post(w, 'alpha', { jsonrpc: '2.0', id: 1, method: 'tools/list' });
    assert.equal(none.status, 400);
    assert.match(none.json.error.message, /begin one with "initialize"/);
    assert.equal((await post(w, 'alpha', { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: {} } })).status, 400, 'a call with no session is not sent anywhere');
    assert.equal((await rawRequest(w, { method: 'GET', headers: { ...auth(w, 'alpha'), accept: 'text/event-stream' } })).status, 400);
    assert.equal((await rawRequest(w, { method: 'DELETE', headers: auth(w, 'alpha') })).status, 400);
    assert.equal(w.executor.programs(), 0);
    assert.equal(stubsOf(await bookOf(w, 'alpha')).length, 0);

    const { session } = await begin(w, 'alpha');
    const again = await ask(w, 'alpha', session, initialize(3));
    assert.equal(again.status, 400, 'a session is not begun under a session');
    assert.equal(w.executor.programs(), 1);
    assert.equal((await post(w, null, initialize())).status, 401, 'nobody begins a session without signing in');
    assert.equal(w.executor.programs(), 1);
  } finally {
    await w.close();
  }
});

test('two agents at once: each has a program of its own, gets its own results, and cannot use the other\'s session; two sessions of one agent may use the same id at once', async () => {
  const w = await localWorld();
  try {
    const [a, b] = await Promise.all([begin(w, 'alpha'), begin(w, 'beta')]);
    assert.notEqual(a.session, b.session);
    assert.equal(w.executor.programs(), 2, 'one program for each session');

    // Both call at once, under the same id, the slower one first.
    const [slowA, fastB, echoA, echoB] = await Promise.all([
      callIn(w, 'alpha', a.session, 'slow', { ms: 400, tag: 'for-alpha' }, 5),
      callIn(w, 'beta', b.session, 'slow', { ms: 50, tag: 'for-beta' }, 5),
      callIn(w, 'alpha', a.session, 'echo', { who: 'alpha' }, 6),
      callIn(w, 'beta', b.session, 'echo', { who: 'beta' }, 6),
    ]);
    assert.equal(slowA.json.result.content[0].text, 'Done, slowly. for-alpha');
    assert.equal(fastB.json.result.content[0].text, 'Done, slowly. for-beta');
    assert.deepEqual(echoA.json.result.structuredContent.args, { who: 'alpha' });
    assert.deepEqual(echoB.json.result.structuredContent.args, { who: 'beta' });
    for (const r of [slowA, echoA]) assert.ok(!r.body.includes('beta'), 'nothing of beta\'s reaches alpha');
    for (const r of [fastB, echoB]) assert.ok(!r.body.includes('alpha'), 'nothing of alpha\'s reaches beta');
    assert.equal(stubsOf(await bookOf(w, 'alpha')).length, 2);
    assert.equal(stubsOf(await bookOf(w, 'beta')).length, 2);

    // Another agent's session is no session: no call, no stream, no end.
    const stolen = await callIn(w, 'beta', a.session, 'echo', { who: 'beta' }, 9);
    assert.equal(stolen.status, 404);
    assert.equal((await rawRequest(w, { method: 'GET', headers: { ...auth(w, 'beta'), ...under(a.session), accept: 'text/event-stream' } })).status, 404);
    assert.equal((await rawRequest(w, { method: 'DELETE', headers: { ...auth(w, 'beta'), ...under(a.session) } })).status, 404);
    assert.equal(w.executor.programs(), 2, 'alpha\'s session still stands');
    assert.equal(stubsOf(await bookOf(w, 'beta')).length, 2, 'and nothing was written for the attempt');

    // Two sessions of one agent: the same id at once, each answered with its own.
    const a2 = await begin(w, 'alpha');
    const [one, two] = await Promise.all([callIn(w, 'alpha', a.session, 'slow', { ms: 200, tag: 'first' }, 30), callIn(w, 'alpha', a2.session, 'slow', { ms: 200, tag: 'second' }, 30)]);
    assert.equal(one.json.result?.content[0].text, 'Done, slowly. first', one.body);
    assert.equal(two.json.result?.content[0].text, 'Done, slowly. second', two.body);
  } finally {
    await w.close();
  }
});

test('the program\'s own request goes on its session\'s stream, and the agent\'s answer goes back to that program alone', async () => {
  const w = await localWorld({ config: { tools: { ...TOOLS, ask: { action: 'provared.data.read' } } } });
  try {
    const a = await begin(w, 'alpha');
    const b = await begin(w, 'beta');
    const open = async (agent, session) => {
      const s = await rawRequest(w, { method: 'GET', headers: { ...auth(w, agent), ...under(session), accept: 'text/event-stream' }, stream: true });
      assert.equal(s.status, 200);
      assert.match(s.headers.get('content-type'), /^text\/event-stream/);
      s.text = '';
      s.res.setEncoding('utf8').on('data', (d) => {
        s.text += d;
      });
      return s;
    };
    const streamA = await open('alpha', a.session);
    const streamB = await open('beta', b.session);
    const asking = callIn(w, 'beta', b.session, 'ask', {}, 4);
    await until(() => streamB.text.includes('sampling/createMessage'));
    const asked = JSON.parse(/data: (.*)/.exec(streamB.text)[1]);
    assert.equal(asked.method, 'sampling/createMessage');
    const replied = await ask(w, 'beta', b.session, { jsonrpc: '2.0', id: asked.id, result: { said: 'beta-only' } });
    assert.equal(replied.status, 202, 'a response is answered 202');
    const done = await asking;
    assert.equal(done.json.result.content[0].text, 'The client said: {"said":"beta-only"}');
    assert.equal(streamA.text, '', 'alpha\'s stream carried nothing of beta\'s program');
    assert.ok(!streamB.text.includes('"result"'), 'no response is sent on the stream');

    // A later stream takes the place of the earlier one.
    const later = await open('beta', b.session);
    await until(() => streamB.res.complete || streamB.res.destroyed);
    for (const s of [streamA, later]) s.res.destroy();
  } finally {
    await w.close();
  }
});

test('a program that ends in the middle of a call: the agent is told, the receipt is the one a stdio executor writes, the session is over, and a new one starts a new program', async () => {
  const w = await localWorld();
  try {
    const { session } = await begin(w, 'alpha');
    const other = await begin(w, 'beta');
    const crashed = await callIn(w, 'alpha', session, 'crash', {}, 3);
    assert.equal(crashed.status, 200);
    assert.equal(crashed.json.error.code, CODES.noAnswer);
    assert.equal(crashed.json.error.message, SERVER_ENDED);
    const book = await bookOf(w, 'alpha');
    assert.equal(stubsOf(book).length, 1, 'the call has its receipt');
    assert.equal(stubsOf(book)[0].countersignature?.state, 'valid');
    assert.equal(docs(stubsOf(book)[0])['provared.error'], await identifierFingerprint(SERVER_ENDED), 'the receipt names the same text as on stdio');
    assert.equal(crashed.json.error.data['red.prova/stub'], stubsOf(book)[0].fingerprint);
    assert.ok(book.summary.intact && !book.summary.problemFound);

    await until(() => w.executor.agent('alpha').sessions() === 0);
    assert.equal((await callIn(w, 'alpha', session, 'echo', {}, 4)).status, 404, 'the session ended with its program');
    assert.equal((await callIn(w, 'beta', other.session, 'echo', { still: 'here' }, 4)).status, 200, 'another agent\'s program is not touched');
    const fresh = await begin(w, 'alpha');
    assert.equal((await callIn(w, 'alpha', fresh.session, 'echo', { again: true }, 5)).json.result.structuredContent.args.again, true);
  } finally {
    await w.close();
  }
});

test('a program that will not start: a program that is not there stops the executor\'s start; one that ends at once, or cannot be run, begins no session and is said so', async () => {
  const missing = await localWorld({ server: { command: './no-such-program' }, open: false });
  await assert.rejects(openHttpExecutor(missing.settings, { root: missing.folder, log: () => {} }), /server\.command: .*no-such-program was not found/);
  await missing.upstream.close();
  const check = await checkHttpConfig(missing.settings, missing.folder);
  assert.ok(check.problems.some((p) => /server\.command/.test(p)), '"check" names it too');

  const ends = await localWorld({ server: { args: ['-e', 'process.exit(7)'] } });
  try {
    const { answer, session } = await begin(ends, 'alpha');
    assert.equal(answer.status, 502);
    assert.equal(answer.json.error.code, CODES.noAnswer);
    assert.match(answer.json.error.message, /ended before it answered "initialize", so no session was begun/);
    assert.equal(session, null, 'no session id is given');
    assert.equal(ends.executor.agent('alpha').sessions(), 0);
    await until(() => ends.executor.programs() === 0);
    assert.equal(events(ends, 'server-ended').at(-1).code, 7);
  } finally {
    await ends.close();
  }

  // A file that is there and is not a program: it cannot be run.
  const notRun = await localWorld({ server: { command: './not-a-program.txt', args: [] }, open: false });
  writeFileSync(join(notRun.folder, 'not-a-program.txt'), 'not a program\n', { mode: 0o644 });
  await openHttpWorld(notRun, { serverStderr: null });
  try {
    const { answer, session } = await begin(notRun, 'alpha');
    assert.equal(answer.status, 502, answer.body);
    assert.match(answer.json.error.message, /no session was begun/);
    assert.equal(session, null);
    await until(() => notRun.executor.programs() === 0);
    assert.equal(notRun.executor.agent('alpha').sessions(), 0);
    assert.equal(stubsOf(await bookOf(notRun, 'alpha')).length, 0);
  } finally {
    await notRun.close();
  }

  // A program that never answers "initialize": the executor's timeout, and no session.
  const silent = await localWorld({ server: { args: ['-e', 'setInterval(() => {}, 1000); process.stdin.on("end", () => process.exit(0)).resume()'] }, config: { timeout: 1000 } });
  try {
    const { answer, session } = await begin(silent, 'alpha');
    assert.equal(answer.status, 504);
    assert.equal(session, null);
    await until(() => silent.executor.programs() === 0);
  } finally {
    await silent.close();
  }
});

test('the limit on how many: at most "sessions.max" for each agent, the one quiet longest making room and a busy one never', async () => {
  const w = await localWorld({ config: { sessions: { max: 2 }, timeout: 5000 } });
  try {
    const first = await begin(w, 'alpha');
    const second = await begin(w, 'alpha');
    assert.equal((await callIn(w, 'alpha', first.session, 'echo', {}, 2)).status, 200, 'the first is used after the second began, so the second is now the one quiet longest');
    // Another agent's sessions are not counted with alpha's.
    const beta = await begin(w, 'beta');
    assert.equal(beta.answer.status, 200);
    const third = await begin(w, 'alpha');
    assert.equal(third.answer.status, 200, third.answer.body);
    assert.equal(w.executor.agent('alpha').sessions(), 2, 'never more than the most');
    assert.equal((await callIn(w, 'alpha', second.session, 'echo', {}, 3)).status, 404, 'the one quiet longest made room');
    assert.equal((await callIn(w, 'alpha', first.session, 'echo', {}, 4)).status, 200);
    assert.equal(events(w, 'session-ended').filter((e) => e.why === 'made-room').length, 1);

    // Both of alpha's sessions busy: a third is refused, and neither is ended.
    const busy = [callIn(w, 'alpha', first.session, 'slow', { ms: 1000, tag: 'one' }, 5), callIn(w, 'alpha', third.session, 'slow', { ms: 1000, tag: 'two' }, 5)];
    await until(() => w.executor.agent('alpha').calls() === 2);
    const fourth = await begin(w, 'alpha');
    assert.equal(fourth.answer.status, 503);
    assert.match(fourth.answer.json.error.message, /already has 2 sessions/);
    assert.equal(fourth.session, null);
    const [one, two] = await Promise.all(busy);
    assert.equal(one.json.result?.content[0].text, 'Done, slowly. one', one.body);
    assert.equal(two.json.result?.content[0].text, 'Done, slowly. two', two.body);
    assert.equal(w.executor.agent('alpha').sessions(), 2, 'neither busy session was ended');
    // With nothing in flight, a new one is begun again.
    assert.equal((await begin(w, 'alpha')).answer.status, 200);
    assert.equal(w.executor.agent('beta').sessions(), 1, 'another agent\'s session never makes room');
  } finally {
    await w.close();
  }
});

test('many programs at once: what each says on its standard error is handed on, and Node.js is given nothing to warn about', async () => {
  const w = await localWorld({ config: { sessions: { max: 12 } }, open: false });
  const said = new PassThrough();
  let text = '';
  said.setEncoding('utf8').on('data', (d) => {
    text += d;
  });
  const warnings = [];
  const onWarning = (warning) => warnings.push(warning.name);
  process.on('warning', onWarning);
  await openHttpWorld(w, { serverStderr: said });
  try {
    const begun = await Promise.all(Array.from({ length: 12 }, () => begin(w, 'alpha')));
    assert.ok(begun.every((b) => b.answer.status === 200));
    assert.equal(w.executor.programs(), 12);
    await until(() => text.split('fake-server: started').length - 1 === 12);
    assert.deepEqual(warnings.filter((name) => name === 'MaxListenersExceededWarning'), [], 'no warning of too many listeners on the one place they all write to');
  } finally {
    process.off('warning', onWarning);
    await w.close();
  }
});

test('the limit on how long: a session is ended, with its program, "sessions.idle" after the agent\'s last message; one with a call in flight is not, however long the call', async () => {
  const w = await localWorld({ config: { sessions: { idle: 1500 }, timeout: 8000 } });
  try {
    const { session } = await begin(w, 'alpha');
    // The call takes longer than the idle limit, and is answered all the same.
    const long = await callIn(w, 'alpha', session, 'slow', { ms: 2500, tag: 'long' }, 2);
    assert.equal(long.json.result?.content[0].text, 'Done, slowly. long', long.body);
    assert.equal(w.executor.agent('alpha').sessions(), 1);
    assert.equal(events(w, 'session-ended').length, 0);
    // Left alone, the session is ended, and its program with it.
    await until(() => w.executor.programs() === 0, { timeout: 8000 });
    assert.equal(w.executor.agent('alpha').sessions(), 0);
    assert.equal(events(w, 'session-ended').at(-1).why, 'idle');
    assert.equal((await callIn(w, 'alpha', session, 'echo', {}, 3)).status, 404);
    assert.ok(seenByProgram(w).some((s) => s.stdinEnded));
  } finally {
    await w.close();
  }
});

test('a call the program never answers is cancelled at the executor\'s timeout, and one the agent cancels is cancelled under the executor\'s id, each with its receipt; a request it never answers is answered 504', async () => {
  const w = await localWorld({ config: { timeout: 1000 } });
  try {
    const { session } = await begin(w, 'alpha');
    const never = await callIn(w, 'alpha', session, 'slow', { never: true }, 2);
    assert.equal(never.json.error.code, CODES.noAnswer);
    assert.match(never.json.error.message, /gave no answer within 1000 ms/);
    const sent = seenByProgram(w).filter((s) => s.seen?.method === 'tools/call').at(-1).seen.id;
    assert.ok(seenByProgram(w).some((s) => s.seen?.method === 'notifications/cancelled' && s.seen.params.requestId === sent), 'the program is told, under the executor\'s id');

    const slow = callIn(w, 'alpha', session, 'slow', { ms: 600 }, 3);
    await until(() => seenByProgram(w).filter((s) => s.seen?.method === 'tools/call').length === 2);
    const cancel = await ask(w, 'alpha', session, { jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 3 } });
    assert.equal(cancel.status, 202);
    const cancelled = await slow;
    assert.match(cancelled.json.error.message, /The agent cancelled this call/);
    const second = seenByProgram(w).filter((s) => s.seen?.method === 'tools/call').at(-1).seen.id;
    await until(() => seenByProgram(w).some((s) => s.seen?.method === 'notifications/cancelled' && s.seen.params.requestId === second));
    assert.ok(!seenByProgram(w).some((s) => s.seen?.method === 'notifications/cancelled' && s.seen.params.requestId === 3), 'never under the agent\'s id');
    assert.equal(stubsOf(await bookOf(w, 'alpha')).length, 2);

    const unanswered = await ask(w, 'alpha', session, { jsonrpc: '2.0', id: 4, method: 'never' });
    assert.equal(unanswered.status, 504);
    assert.equal(unanswered.json.id, 4);
    assert.equal((await callIn(w, 'alpha', session, 'echo', { ok: 1 }, 5)).status, 200, 'the session goes on');
  } finally {
    await w.close();
  }
});

test('the executor\'s stop: a call with a program is receipted as the executor\'s stop, and every program is ended', async () => {
  const w = await localWorld();
  const { session } = await begin(w, 'alpha');
  await begin(w, 'beta');
  const slow = callIn(w, 'alpha', session, 'slow', { ms: 20000 }, 2);
  await until(() => seenByProgram(w).some((s) => s.seen?.method === 'tools/call'));
  assert.equal(w.executor.programs(), 2);
  const closing = w.executor.close();
  const answer = await slow;
  assert.equal(answer.json.error.message, EXECUTOR_STOPPED);
  await closing;
  await w.upstream.close();
  assert.equal(w.executor.programs(), 0, 'no program outlives the executor');
  const book = await checkBook(readFileSync(w.agents.alpha.book, 'utf8'), { issuerKeys: w.settings.agents.alpha.issuerKeys });
  assert.equal(docs(stubsOf(book)[0])['provared.error'], await identifierFingerprint(EXECUTOR_STOPPED));
});

test('through the OAuth front door to a local program: a call under an access token is receipted in the connection\'s book; the session outlives the token and ends with the connection', async () => {
  const w = makeLocal(await oauthWorld({ open: false }));
  w.more.serverStderr = null;
  await reopen(w);
  try {
    const first = await connect(w);
    assert.equal(w.executor.programs(), 0, 'signing in starts no program');
    const { answer, session } = await begin(w, bearer(first.access));
    assert.equal(answer.status, 200, answer.body);
    assert.ok(session);
    const echo = await callIn(w, bearer(first.access), session, 'echo', { through: 'the front door' }, 2);
    assert.equal(echo.status, 200, echo.body);
    assert.equal(echo.json.result.structuredContent.token, TOKEN);
    assert.ok(!JSON.stringify(seenByProgram(w)).includes(first.access), 'the access token does not reach the program');
    const book = await bookOf(w, 'conn');
    assert.equal(stubsOf(book).length, 1, 'the call is receipted in the connection\'s own book');
    assert.equal(stubsOf(book)[0].countersignature?.state, 'valid');
    assert.equal(stubsOf(await bookOf(w, 'alpha')).length, 0);

    // The agent with a secret cannot use the connection's session.
    assert.equal((await callIn(w, 'alpha', session, 'echo', {}, 3)).status, 404);

    // A refreshed token of the same connection goes on with the same session, and the same program.
    const refreshed = json(await token(w, { grant_type: 'refresh_token', refresh_token: first.refresh, client_id: w.docs.client, resource: first.discovered.resource }));
    assert.ok(refreshed.access_token);
    assert.equal((await callIn(w, bearer(refreshed.access_token), session, 'echo', { n: 2 }, 4)).status, 200);
    assert.equal(w.executor.programs(), 1);

    // A new approval of the agent ends the connection before, and with it the session and its program.
    const next = await connect(w);
    await until(() => w.executor.programs() === 0);
    assert.equal(events(w, 'session-ended').at(-1).why, 'connection-ended');
    assert.equal((await callIn(w, bearer(next.access), session, 'echo', {}, 5)).status, 404, 'the new connection cannot use the old one\'s session');
    const again = await begin(w, bearer(next.access));
    assert.equal((await callIn(w, bearer(next.access), again.session, 'echo', { n: 3 }, 6)).status, 200);
    assert.equal(stubsOf(await bookOf(w, 'conn')).length, 3);
  } finally {
    await w.close();
  }
});

test('the settings: "upstream" or "server", never both; "server" is read as the stdio executor reads it; the limits have their defaults and their bounds; "check" describes the program', async () => {
  const w = await localWorld({ open: false });
  await w.upstream.close();
  const read = (change) => readHttpSettings({ ...w.settings, ...change }, w.folder);
  const good = read({});
  assert.deepEqual(good.problems, []);
  assert.deepEqual(good.settings.sessions, { max: SESSIONS_MAX, idle: SESSION_IDLE });
  assert.equal(good.settings.shutdownWait, 5000);
  assert.equal(good.settings.server.cwd, w.folder, 'the program runs in the settings\' folder unless they say otherwise');
  assert.equal(good.settings.upstream, undefined);

  assert.match(read({ upstream: { url: 'http://127.0.0.1:9/mcp' } }).problems.join('\n'), /upstream: is given beside "server".*never both/);
  const neither = { ...w.settings };
  delete neither.server;
  assert.match(readHttpSettings(neither, w.folder).problems.join('\n'), /upstream: must be an object.*"server" in its place/);
  assert.match(read({ server: { command: '' } }).problems.join('\n'), /server\.command: must be the program to start/);
  assert.match(read({ server: { command: 'node', env: { A: { file: 'x', value: 'y' } } } }).problems.join('\n'), /server\.env\.A: must say where its value is read from/);
  for (const sessions of [{ max: 0 }, { max: 257 }, { max: 1.5 }, { idle: 999 }, { idle: 86400001 }, 'many']) assert.match(read({ sessions }).problems.join('\n'), /sessions/, JSON.stringify(sessions));
  assert.match(read({ shutdownWait: 5 }).problems.join('\n'), /shutdownWait/);
  // Over HTTP it is not the agent's client that sets the executor's environment.
  const fromEnv = read({ server: { command: process.execPath, env: { A: { env: 'PATH' } } } });
  assert.ok(fromEnv.warnings.some((x) => /server\.env\.A: .*whoever starts the executor sets/.test(x)));
  // Without "server", the limits are not settings.
  assert.ok(readHttpSettings({ ...neither, upstream: { url: 'http://127.0.0.1:9/mcp' }, sessions: { max: 2 } }, w.folder).warnings.some((x) => /^sessions: not a setting without "server"/.test(x)));

  const check = await checkHttpConfig(w.settings, w.folder);
  assert.deepEqual(check.problems, []);
  assert.equal(check.program, process.execPath);
  assert.deepEqual(check.credentials, ['FAKE_TOKEN', 'FAKE_LOG']);
  assert.deepEqual(check.sessions, { max: SESSIONS_MAX, idle: SESSION_IDLE });
  assert.equal(check.upstream, undefined);
  const noFile = await checkHttpConfig({ ...w.settings, server: { ...w.settings.server, env: { FAKE_TOKEN: { file: 'secrets/not-there' } } } }, w.folder);
  assert.ok(noFile.problems.some((p) => /server\.env\.FAKE_TOKEN/.test(p)), 'a credential file that is not there is a problem');
  await assert.rejects(openHttpExecutor({ ...w.settings, server: { ...w.settings.server, env: { FAKE_TOKEN: { file: 'secrets/not-there' } } } }, { root: w.folder, log: () => {} }), /server\.env\.FAKE_TOKEN/);
});

test('init --http --demo: writes settings that run the demonstration\'s made-up server as the local program, with the OAuth sign-in, its rules and its made-up credential; overwrites nothing; and the settings run', async () => {
  const folder = tempFolder();
  const run = (args) => spawnSync(process.execPath, [BIN, ...args], { cwd: folder, encoding: 'utf8', windowsHide: true, timeout: 90000 });
  const alone = run(['init', '--demo']);
  assert.equal(alone.status, 2);
  assert.match(alone.stderr, /--demo only with --http/);
  assert.ok(!existsSync(join(folder, 'executor-http.json')));

  const r = run(['init', '--http', '--demo']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /made-up server/);
  const config = JSON.parse(readFileSync(join(folder, 'executor-http.json'), 'utf8'));
  assert.equal(config.upstream, undefined);
  assert.equal(config.server.command, process.execPath);
  assert.deepEqual(config.server.args, [fileURLToPath(new URL('../demo/server.mjs', import.meta.url))]);
  assert.deepEqual(config.server.env, { DEMO_TOKEN: { file: 'demo-token' } });
  assert.deepEqual(Object.keys(config.tools), ['echo', 'add']);
  assert.equal(config.agents['connection-1'].oauth, true);
  assert.equal(readFileSync(join(folder, 'content-rules.json'), 'utf8'), readFileSync(new URL('../demo/content-rules.json', import.meta.url), 'utf8'));
  assert.match(readFileSync(join(folder, 'demo-token'), 'utf8'), /^[0-9a-f]{32}\n$/);
  if (process.platform !== 'win32') assert.equal(statSync(join(folder, 'demo-token')).mode & 0o777, 0o600);
  const again = run(['init', '--http', '--demo']);
  assert.equal(again.status, 2);
  assert.match(again.stderr, /Nothing was written/);

  // What is left to put in is named by "check": the public address, the client and the passkey's thumbprint, and no more of the settings.
  const check = run(['check', '--config', 'executor-http.json']);
  assert.equal(check.status, 1);
  const problems = JSON.parse(check.stdout).problems.join('\n');
  assert.match(problems, /oauth\.issuer/);
  assert.match(problems, /issuerKeys/);
  assert.doesNotMatch(problems, /^(server|upstream|sessions|shutdownWait)[.:]/m);

  // The same program and credential under the tests' own agent (a secret in place of the sign-in, the tests' stand-in for a passkey): the made-up server answers behind the executor.
  const w = await httpWorld({ agents: ['alpha'], open: false });
  delete w.settings.upstream;
  w.settings.server = { ...config.server, cwd: folder, env: { DEMO_TOKEN: { file: join(folder, 'demo-token') } } };
  w.settings.tools = { echo: { action: 'provared.data.read' }, add: { action: 'tool.run' } };
  await openHttpWorld(w, { serverStderr: null });
  try {
    const { answer, session } = await begin(w, 'alpha');
    assert.equal(answer.json.result.serverInfo.name, 'provared-demo-server');
    const sum = await callIn(w, 'alpha', session, 'add', { a: 2, b: 3 }, 2);
    assert.equal(sum.status, 200, sum.body);
    assert.match(JSON.stringify(sum.json.result), /5/);
    assert.equal(stubsOf(await bookOf(w, 'alpha')).length, 1);
  } finally {
    await w.close();
  }
});
