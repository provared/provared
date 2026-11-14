// The HTTP executor in front of a local program (DESIGN.md, section 10.1),
// when the program or the agent misbehaves: a program that will not end,
// that does not read, that writes without pause; an agent that goes away,
// that floods the executor with sessions, that sends a version the executor
// does not serve. Each test is one finding of the review of the local
// program (X242 to X247), or one fault that the review put into the code
// and that no test caught. Everything goes through the executor's public
// interface, but for two tests of local.mjs alone. The program is the
// tests' made-up server (fake-server.mjs). Nothing leaves this computer.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { existsSync, readFileSync } from 'node:fs';
import http from 'node:http';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';

const { checkBook, identifierFingerprint } = await import('provared');
const { SERVER_ENDED, UNREADABLE_ANSWER } = await import('../executor.mjs');
const { BACKLOG_LIMIT, LOCAL_VERSIONS } = await import('../http.mjs');
const { CLOSE_MARGIN, FLOOD_PER_SECOND, FLOOD_SECONDS, openLocalSessions } = await import('../local.mjs');
const { CODES } = await import('../jsonrpc.mjs');
const { httpWorld, openHttpWorld, post, rawRequest, auth } = await import('./http-world.mjs');
const { FAKE_SERVER, until, pause, world } = await import('./world.mjs');

const TOOLS = { echo: { action: 'provared.data.read' }, slow: { action: 'slow.work' }, flood: { action: 'tool.run' }, stray: { action: 'tool.run' }, loud: { action: 'tool.run' }, mutter: { action: 'tool.run' }, garbage: { action: 'tool.run' } };
const stubsOf = (checked) => checked.entries.filter((e) => e.kind === 'stub');
const docs = (stub) => Object.fromEntries(stub.content.details.map((d) => [d.name, d.sha256]));
const POSIX = process.platform !== 'win32';

/** A world whose executor stands in front of the made-up program. "env" is added to the program's environment, as text. */
async function localWorld({ env = {}, config = {}, more = { serverStderr: null } } = {}) {
  const w = await httpWorld({ open: false });
  delete w.settings.upstream;
  w.fakeLog = join(w.folder, 'fake.log');
  w.settings.server = { command: process.execPath, args: [FAKE_SERVER], env: { FAKE_LOG: { value: w.fakeLog }, ...Object.fromEntries(Object.entries(env).map(([k, v]) => [k, { value: String(v) }])) } };
  w.settings.tools = TOOLS;
  Object.assign(w.settings, config);
  await openHttpWorld(w, more);
  return w;
}

const seenByProgram = (w) => (existsSync(w.fakeLog) ? readFileSync(w.fakeLog, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
const bookOf = (w, name) => checkBook(w.executor.agent(name).writer.book(), { issuerKeys: w.settings.agents[name].issuerKeys });
const events = (w, event) => w.logs.filter((e) => e.event === event);
const initialize = (id = 1, version = '2025-11-25') => ({ jsonrpc: '2.0', id, method: 'initialize', params: { protocolVersion: version, capabilities: {}, clientInfo: { name: 'test', version: '1' } } });
const under = (session, version = '2025-11-25') => ({ 'mcp-session-id': session, ...(version ? { 'mcp-protocol-version': version } : {}) });
async function begin(w, agent, more = {}) {
  const answer = await post(w, agent, initialize(), more);
  return { answer, session: answer.headers.get('mcp-session-id') };
}
const ask = (w, agent, session, message, more = {}) => post(w, agent, message, { headers: under(session), ...more });
const callIn = (w, agent, session, name, args, id = 2) => ask(w, agent, session, { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });
const ping = (w, agent, session, id = 50) => ask(w, agent, session, { jsonrpc: '2.0', id, method: 'ping' });
const endSession = (w, agent, session) => rawRequest(w, { method: 'DELETE', headers: { ...auth(w, agent), ...under(session) } });
/** Open the stream of a session's program's own messages; "text" gathers what comes. */
async function openStream(w, agent, session) {
  const s = await rawRequest(w, { method: 'GET', headers: { ...auth(w, agent), ...under(session), accept: 'text/event-stream' }, stream: true });
  assert.equal(s.status, 200);
  s.text = '';
  s.res.setEncoding('utf8').on('data', (d) => {
    s.text += d;
  });
  s.over = () => s.res.complete || s.res.destroyed;
  return s;
}
/** The most programs running at any moment while "work" is done, looked at every few milliseconds. */
async function mostPrograms(w, work) {
  let most = 0;
  const look = setInterval(() => {
    most = Math.max(most, w.executor.programs());
  }, 2);
  try {
    await work(() => {
      most = Math.max(most, w.executor.programs());
    });
  } finally {
    clearInterval(look);
  }
  return most;
}

test('a program that does not end when its input closes is ended by force after "shutdownWait"', async () => {
  const w = await localWorld({ env: { FAKE_LINGER: 60000 }, config: { shutdownWait: 300 } });
  try {
    const { session } = await begin(w, 'alpha');
    assert.equal((await endSession(w, 'alpha', session)).status, 204);
    assert.equal(w.executor.programs(), 1, 'the program is given "shutdownWait" to end of itself');
    await until(() => w.executor.programs() === 0, { timeout: 3000 });
    assert.deepEqual(events(w, 'server-killed').map((e) => e.signal), ['SIGTERM']);
  } finally {
    await w.close();
  }
});

test('a program that takes no notice of SIGTERM is sent SIGKILL after a second wait, and the executor\'s stop finishes', async () => {
  const w = await localWorld({ env: { FAKE_IGNORE_TERM: 1 }, config: { shutdownWait: 300 } });
  let closed = false;
  try {
    const { session } = await begin(w, 'alpha');
    await begin(w, 'beta');
    assert.equal((await endSession(w, 'alpha', session)).status, 204);
    await until(() => w.executor.programs() === 1, { timeout: 4000 });
    if (POSIX) {
      assert.deepEqual(events(w, 'server-killed').map((e) => e.signal), ['SIGTERM', 'SIGKILL'], 'first the signal a program may ignore, then the one it cannot');
      assert.equal(events(w, 'server-ended').at(-1).signal, 'SIGKILL');
      assert.ok(seenByProgram(w).some((e) => e.sigterm), 'the program was sent SIGTERM, and took no notice');
    }
    // The stop: beta's program takes no notice either.
    const stopped = await Promise.race([w.executor.close().then(() => 'finished'), pause(5000).then(() => 'still waiting')]);
    closed = true;
    assert.equal(stopped, 'finished');
    assert.equal(w.executor.programs(), 0, 'no program outlives the executor');
  } finally {
    if (!closed) await w.executor.close();
    await w.upstream.close();
  }
});

test('local.mjs: the stop finishes even where a program cannot be ended, and says so', async () => {
  // A program that nothing ends: a stand-in for one the system will not let go.
  const child = () => Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), kill: () => true });
  const logs = [];
  const local = openLocalSessions({ settings: { server: { resolved: 'x', args: [] }, sessions: { max: 2, idle: 60000 }, shutdownWait: 100, timeout: 1000 }, env: {}, credentialNames: [], log: (e) => logs.push(e), serverStderr: null, spawnProgram: child });
  assert.ok((await local.begin('alpha', null)).session);
  const started = Date.now();
  await local.close();
  const took = Date.now() - started;
  assert.ok(took >= 200 && took < 200 + CLOSE_MARGIN + 1500, `the two waits and a little more: ${took} ms`);
  assert.deepEqual(logs.filter((e) => e.event === 'server-killed').map((e) => e.signal), ['SIGTERM', 'SIGKILL']);
  assert.equal(logs.find((e) => e.event === 'servers-not-ended')?.programs, 1);
  assert.deepEqual(await local.begin('alpha', null), { refused: 'stopping' }, 'no program is started after the stop');
});

test('local.mjs: a session used under another connection than the one it was begun under is ended', async () => {
  const logs = [];
  const local = openLocalSessions({ settings: { server: { resolved: process.execPath, args: [FAKE_SERVER] }, sessions: { max: 2, idle: 60000 }, shutdownWait: 1000, timeout: 1000 }, env: process.env, credentialNames: [], log: (e) => logs.push(e), serverStderr: null });
  try {
    const { session } = await local.begin('alpha', 'connection-1');
    assert.equal(local.owned(session.id, 'alpha', 'connection-1'), session);
    assert.equal(local.owned(session.id, 'beta', 'connection-1'), null, 'another agent');
    assert.equal(local.count('alpha'), 1, 'and the session is not ended for it');
    assert.equal(local.owned(session.id, 'alpha', 'connection-2'), null, 'another connection of the same agent');
    assert.equal(local.owned(session.id, 'alpha', null), null);
    assert.equal(local.count('alpha'), 0);
    assert.equal(logs.find((e) => e.event === 'session-ended')?.why, 'another-connection');
    assert.equal(local.owned(session.id, 'alpha', 'connection-1'), null, 'and its own connection cannot use it after');
  } finally {
    await local.close();
  }
});

test('"sessions.max" bounds the programs an agent has running: a new session waits until the one that made room has gone', async () => {
  // Each program stays for a while after its session has ended.
  const w = await localWorld({ env: { FAKE_LINGER: 400 }, config: { sessions: { max: 2 }, shutdownWait: 5000 } });
  try {
    const most = await mostPrograms(w, async (look) => {
      for (let i = 0; i < 6; i++) {
        const { answer } = await begin(w, 'alpha');
        assert.equal(answer.status, 200, answer.body);
        look();
      }
    });
    assert.equal(most, 2, 'never more programs than "sessions.max"');
    assert.equal(w.executor.agent('alpha').sessions(), 2);
    assert.equal(events(w, 'session-ended').filter((e) => e.why === 'made-room').length, 4);
    // A session that the agent ends counts until its program has gone.
    const { session } = await begin(w, 'beta');
    await begin(w, 'beta');
    assert.equal((await endSession(w, 'beta', session)).status, 204);
    const again = await mostPrograms(w, async () => {
      assert.equal((await begin(w, 'beta')).answer.status, 200);
    });
    assert.equal(again, 4, 'two of each agent');
  } finally {
    await w.close();
  }
});

test('"sessions.max" counts a program whose "initialize" is not answered yet, and room that is not made in time is refused', async () => {
  const w = await localWorld({ env: { FAKE_LINGER: 60000 }, config: { sessions: { max: 2 }, shutdownWait: 300 } });
  try {
    const most = await mostPrograms(w, async () => {
      const answers = await Promise.all([1, 2, 3, 4].map(() => begin(w, 'alpha')));
      assert.deepEqual(answers.map((a) => a.answer.status).sort(), [200, 200, 503, 503], 'four at once: two are begun, and two find every session busy');
    });
    assert.equal(most, 2);
  } finally {
    await w.close();
  }
  // A program that cannot be ended in time: the wait for room has an end.
  const logs = [];
  const child = () => Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), kill: () => true });
  const local = openLocalSessions({ settings: { server: { resolved: 'x', args: [] }, sessions: { max: 1, idle: 60000 }, shutdownWait: 100, timeout: 1000 }, env: {}, credentialNames: [], log: (e) => logs.push(e), serverStderr: null, spawnProgram: child });
  const { session } = await local.begin('alpha', null);
  assert.deepEqual(await local.begin('alpha', null), { refused: 'too-many' }, 'a session whose first message is not yet in hand makes no room');
  assert.equal(local.count('alpha'), 1, 'and is not ended');
  local.enter(session);
  local.leave(session);
  assert.deepEqual(await local.begin('alpha', null), { refused: 'too-many' }, 'it made room, and its program did not go within the two waits');
  assert.equal(logs.find((e) => e.event === 'session-ended')?.why, 'made-room');
  assert.equal(local.programs('alpha'), 1);
  await local.close();
});

test('an agent that goes away while room is made for its new session is given none', async () => {
  const w = await localWorld({ env: { FAKE_LINGER: 800 }, config: { sessions: { max: 1 }, shutdownWait: 5000 } });
  try {
    await begin(w, 'alpha');
    const gone = new AbortController();
    const asked = begin(w, 'alpha', { signal: gone.signal }).catch(() => null);
    await until(() => events(w, 'session-ended').some((e) => e.why === 'made-room'));
    gone.abort();
    await asked;
    await until(() => events(w, 'server-started').length === 2, { timeout: 3000 });
    await until(() => w.executor.programs() === 0, { timeout: 3000 });
    assert.equal(w.executor.agent('alpha').sessions(), 0, 'no session is left that no one can name');
    assert.equal(events(w, 'session-ended').at(-1).why, 'not-begun');
  } finally {
    await w.close();
  }
});

test('local.mjs: one read of a program\'s output at a time, with everything else that waits taken in between', async () => {
  const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), kill: () => true });
  const local = openLocalSessions({ settings: { server: { resolved: 'x', args: [] }, sessions: { max: 1, idle: 60000 }, shutdownWait: 100, timeout: 1000 }, env: {}, credentialNames: [], log: () => {}, serverStderr: null, spawnProgram: () => child });
  const { session } = await local.begin('alpha', null);
  const got = [];
  session.toStream = (text) => got.push(text) > 0;
  // Five reads' worth of the program's output, waiting at once.
  for (let i = 0; i < 5; i++) child.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/message', params: { n: i } })}\n`);
  const turns = [];
  for (let turn = 0; turn < 8 && got.length < 5; turn++) {
    turns.push(got.length);
    await new Promise((d) => setImmediate(d));
  }
  assert.equal(got.length, 5, 'every message is read in the end');
  assert.ok(turns.length >= 4, `the five reads were spread over the turns of the event loop: ${turns.join(', ')}`);
  child.emit('exit', 0, null);
  await local.close();
});

test('stdio: a program that takes no notice of SIGTERM is sent SIGKILL after a second wait, at the client\'s end and at the executor\'s stop', async () => {
  for (const how of ['the client ends', 'the executor is stopped']) {
    const w = await world({ env: { FAKE_IGNORE_TERM: { value: '1' } }, config: { shutdownWait: 300 } });
    assert.equal((await w.client.call('echo', {})).result.isError, undefined);
    const ending = how === 'the client ends' ? w.close() : w.executor.close();
    assert.equal(await Promise.race([ending.then(() => 'finished'), pause(5000).then(() => 'still waiting')]), 'finished', how);
    if (POSIX && how === 'the client ends') assert.deepEqual(w.logs.filter((e) => e.event === 'server-killed').map((e) => e.signal), ['SIGTERM', 'SIGKILL']);
    if (how !== 'the client ends') await w.close();
  }
});

for (const kind of ['request', 'notification']) {
  test(`a program that is not reading: what waits to be written to it is bounded, and a ${kind} past the bound is refused, not held`, async () => {
    const w = await localWorld({ env: { FAKE_INIT: 'deaf' }, config: { timeout: 3000 } });
    try {
      const { session } = await begin(w, 'alpha');
      // One mebibyte at a time to just under the bound, and then half as much again: more than the bound now waits, whatever little the program's pipe took.
      const mebibyte = 1024 * 1024;
      const fill = BACKLOG_LIMIT / mebibyte - 1;
      for (let i = 0; i <= fill; i++) {
        const sent = await ask(w, 'alpha', session, { jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: 'p', progress: i, message: 'x'.repeat(i < fill ? mebibyte : 1.5 * mebibyte) } });
        assert.equal(sent.status, 202, `notification ${i}: ${sent.body}`);
      }
      const started = Date.now();
      const refused = kind === 'request' ? await ping(w, 'alpha', session) : await ask(w, 'alpha', session, { jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: 'p', progress: fill } });
      assert.equal(refused.status, 503, refused.body);
      assert.match(refused.json.error.message, /not reading/);
      assert.ok(Date.now() - started < 2000, 'refused at once, not at the timeout');
      assert.equal(events(w, 'server-not-reading').length, 1);
      assert.equal(events(w, 'session-ended').at(-1).why, 'not-reading');
      assert.equal((await ping(w, 'alpha', session)).status, 404, 'the session is over');
      await until(() => w.executor.programs() === 0, { timeout: 3000 });
    } finally {
      await w.close();
    }
  });
}

test('a program that writes without pause: another agent is served meanwhile, what is dropped is logged at most once a second, and the session is ended', async () => {
  const w = await localWorld({ config: { timeout: 30000 } });
  try {
    const a = await begin(w, 'alpha');
    const b = await begin(w, 'beta');
    const flooding = callIn(w, 'alpha', a.session, 'flood', {});
    await until(() => events(w, 'server-message-dropped').length > 0);
    const started = Date.now();
    let slowest = 0;
    let id = 100;
    while (!events(w, 'session-ended').some((e) => e.why === 'flooding')) {
      assert.ok(Date.now() - started < 15000, 'the session of the flooding program is ended');
      const asked = Date.now();
      assert.equal((await ping(w, 'beta', b.session, id++)).status, 200);
      slowest = Math.max(slowest, Date.now() - asked);
      await pause(50);
    }
    assert.ok(slowest < 1500, `another agent's ping took at most ${slowest} ms`);
    const answer = await flooding;
    assert.equal(answer.json.error.message, SERVER_ENDED, 'the call that was with the program is answered and receipted as for any program that ends');
    await until(() => w.executor.programs() === 1, { timeout: 3000 });
    const lines = events(w, 'server-message-dropped');
    const seconds = Math.ceil((Date.now() - started) / 1000) + 2;
    assert.ok(lines.length <= seconds, `${lines.length} lines of the log in ${seconds} seconds`);
    assert.ok(lines.reduce((sum, e) => sum + e.count, 0) > FLOOD_PER_SECOND * FLOOD_SECONDS, 'each line counts what was dropped since the last');
    assert.equal(events(w, 'server-flooding').length, 1);
    assert.equal((await ping(w, 'beta', b.session, id++)).status, 200, 'the other agent\'s session goes on');
    assert.equal(docs(stubsOf(await bookOf(w, 'alpha'))[0])['provared.error'], await identifierFingerprint(SERVER_ENDED));
  } finally {
    await w.close();
  }
});

test('a program that writes much, and then stops, is not ended: every message reaches the stream', async () => {
  const w = await localWorld({ config: { timeout: 30000 } });
  try {
    const { session } = await begin(w, 'alpha');
    const stream = await openStream(w, 'alpha', session);
    const answer = await callIn(w, 'alpha', session, 'flood', { count: 3000 });
    assert.equal(answer.json.result?.content[0].text, 'Flooded.', answer.body);
    await until(() => stream.text.split('notifications/message').length - 1 === 3000);
    assert.equal(events(w, 'session-ended').length, 0);
    stream.res.destroy();
  } finally {
    await w.close();
  }
});

test('an "initialize" whose body arrives while the executor is stopping starts no program', async () => {
  const w = await localWorld({ env: { FAKE_LINGER: 600 } });
  await begin(w, 'alpha');
  const u = new URL(w.url);
  const body = JSON.stringify(initialize(9));
  const req = http.request({ host: u.hostname, port: u.port, path: u.pathname, method: 'POST', agent: false, headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...auth(w, 'beta'), 'content-length': Buffer.byteLength(body) } });
  const answered = new Promise((done) => {
    req.on('response', (res) => {
      res.resume();
      res.on('end', () => done(res.statusCode));
    });
    req.on('error', (e) => done(e.code));
  });
  // The headers and half the body: the executor has taken the request, and waits for the rest.
  req.write(body.slice(0, 20));
  await pause(150);
  // The stop begins, and waits for alpha's program, which stays a while.
  const closing = w.executor.close();
  await pause(150);
  req.end(body.slice(20));
  assert.equal(await answered, 503);
  await closing;
  await w.upstream.close();
  assert.equal(w.executor.programs(), 0, 'no program outlives the executor');
  assert.equal(events(w, 'server-started').length, 1, 'only alpha\'s program was ever started');
});

test('a request\'s method sent with no id is refused with 400 and does not reach the program', async () => {
  const w = await localWorld();
  try {
    const { session } = await begin(w, 'alpha');
    for (const method of ['tools/call', 'ping', 'tools/list']) {
      const answer = await ask(w, 'alpha', session, { jsonrpc: '2.0', method, params: { name: 'echo', arguments: {} } });
      assert.equal(answer.status, 400, method);
      assert.equal(answer.json.error.code, CODES.invalidRequest);
    }
    assert.equal(events(w, 'notification-dropped').length, 3);
    // A notification of the protocol's own is sent on, and answered 202.
    assert.equal((await ask(w, 'alpha', session, { jsonrpc: '2.0', method: 'notifications/initialized' })).status, 202);
    assert.equal((await ping(w, 'alpha', session)).status, 200);
    assert.deepEqual(seenByProgram(w).map((e) => e.seen?.method).filter(Boolean), ['initialize', 'notifications/initialized', 'ping']);
    assert.equal(stubsOf(await bookOf(w, 'alpha')).length, 0);
  } finally {
    await w.close();
  }
});

test('a program that answers "initialize" with an error: the agent is given the error and no session, and the program is ended', async () => {
  const w = await localWorld({ env: { FAKE_INIT: 'error' } });
  try {
    const { answer, session } = await begin(w, 'alpha');
    assert.equal(answer.status, 200, answer.body);
    assert.equal(answer.json.error.code, -32602, 'the program\'s own error, under the agent\'s id');
    assert.equal(answer.json.id, 1);
    assert.equal(session, null, 'no session id is given');
    assert.equal(w.executor.agent('alpha').sessions(), 0);
    assert.equal(events(w, 'session-ended').at(-1).why, 'not-begun');
    await until(() => w.executor.programs() === 0, { timeout: 3000 });
  } finally {
    await w.close();
  }
});

test('an answer to a call that cannot be read settles the call at once, with its receipt', async () => {
  const w = await localWorld({ config: { timeout: 10000 } });
  try {
    const { session } = await begin(w, 'alpha');
    const started = Date.now();
    const answer = await callIn(w, 'alpha', session, 'garbage', {});
    assert.equal(answer.status, 200, answer.body);
    assert.ok(Date.now() - started < 5000, 'not at the timeout');
    const [stub] = stubsOf(await bookOf(w, 'alpha'));
    assert.equal(docs(stub)['provared.error'], await identifierFingerprint(UNREADABLE_ANSWER));
  } finally {
    await w.close();
  }
});

test('an open stream does not keep its session from the idle limit, and a session\'s end closes its stream', async () => {
  const w = await localWorld({ config: { sessions: { idle: 1000 } } });
  try {
    const idle = await begin(w, 'alpha');
    const idleStream = await openStream(w, 'alpha', idle.session);
    await until(idleStream.over, { timeout: 4000 });
    assert.equal(events(w, 'session-ended').at(-1).why, 'idle');
    assert.equal((await ping(w, 'alpha', idle.session)).status, 404);
    // Ended by the agent: the stream is closed with the session.
    const ended = await begin(w, 'beta');
    const endedStream = await openStream(w, 'beta', ended.session);
    assert.equal((await endSession(w, 'beta', ended.session)).status, 204);
    await until(endedStream.over, { timeout: 800 });
    assert.equal(events(w, 'session-ended').at(-1).why, 'ended-by-agent');
  } finally {
    await w.close();
  }
});

test('an agent that goes away before its request is answered is forgotten: its session is not begun, or is not held busy', async () => {
  // Before "initialize" is answered: the program is ended at once, not at the timeout.
  const never = await localWorld({ env: { FAKE_INIT: 'never' }, config: { timeout: 10000 } });
  try {
    const gone = new AbortController();
    const asked = begin(never, 'alpha', { signal: gone.signal }).catch(() => null);
    await until(() => never.executor.programs() === 1);
    gone.abort();
    await asked;
    await until(() => never.executor.programs() === 0, { timeout: 3000 });
    assert.equal(events(never, 'session-ended').at(-1).why, 'not-begun');
  } finally {
    await never.close();
  }
  // Before another request is answered: the session is no longer busy, so it can make room.
  const w = await localWorld({ config: { sessions: { max: 1 }, timeout: 10000 } });
  try {
    const { session } = await begin(w, 'alpha');
    const gone = new AbortController();
    const asked = ask(w, 'alpha', session, { jsonrpc: '2.0', id: 7, method: 'never' }, { signal: gone.signal }).catch(() => null);
    await until(() => seenByProgram(w).some((e) => e.seen?.method === 'never'));
    gone.abort();
    await asked;
    await pause(100);
    const next = await begin(w, 'alpha');
    assert.equal(next.answer.status, 200, next.answer.body);
    assert.equal(events(w, 'session-ended').at(-1).why, 'made-room');
  } finally {
    await w.close();
  }
});

test('an answer of the program to nothing in flight goes to no agent, and not on the stream', async () => {
  const w = await localWorld();
  try {
    const { session } = await begin(w, 'alpha');
    const stream = await openStream(w, 'alpha', session);
    const answer = await callIn(w, 'alpha', session, 'stray', {});
    assert.equal(answer.json.result?.content[0].text, 'Strayed.', answer.body);
    await until(() => stream.text.includes('after the stray answer'));
    assert.ok(!stream.text.includes('an answer to nothing'), 'no response is sent on the stream');
    assert.equal(events(w, 'late-answer-dropped').length, 1);
    stream.res.destroy();
  } finally {
    await w.close();
  }
});

test('a program\'s standard error is read where it goes nowhere, and is written on in whole lines where it goes somewhere', async () => {
  const nowhere = await localWorld({ config: { timeout: 5000 } });
  try {
    const { session } = await begin(nowhere, 'alpha');
    const answer = await callIn(nowhere, 'alpha', session, 'loud', { kib: 1024 });
    assert.equal(answer.json.result?.content[0].text, 'Loud.', 'a program that writes much on its standard error is not held up');
  } finally {
    await nowhere.close();
  }
  const said = [];
  const stderr = new PassThrough();
  stderr.on('data', (d) => said.push(d.toString('utf8')));
  const w = await localWorld({ more: { serverStderr: stderr } });
  try {
    const { session } = await begin(w, 'alpha');
    assert.equal((await callIn(w, 'alpha', session, 'mutter', {})).status, 200);
    assert.equal((await endSession(w, 'alpha', session)).status, 204);
    await until(() => w.executor.programs() === 0, { timeout: 3000 });
    await until(() => said.join('').includes('half a line'));
    assert.ok(said.every((piece) => piece.endsWith('\n')), 'each piece written on ends with a line feed, so that it never runs into a line of the executor\'s own');
    assert.ok(said.join('').endsWith('half a line\n'));
  } finally {
    await w.close();
  }
});

test('MCP-Protocol-Version: a request that names a version the executor does not serve is answered 400; one that names none is taken', async () => {
  const w = await localWorld();
  try {
    for (const version of ['not-a-version', '2099-01-01', '2026-07-28', '2024-11-05', '']) {
      const refused = await post(w, 'alpha', initialize(), { headers: { 'mcp-protocol-version': version } });
      assert.equal(refused.status, 400, `initialize under ${JSON.stringify(version)}`);
      assert.equal(refused.json.error.code, CODES.invalidRequest);
    }
    assert.equal(w.executor.programs(), 0, 'and no program is started for it');
    const { answer, session } = await begin(w, 'alpha');
    assert.equal(answer.status, 200, 'no header: taken');
    for (const version of LOCAL_VERSIONS) assert.equal((await ask(w, 'alpha', session, { jsonrpc: '2.0', id: 3, method: 'ping' }, { headers: under(session, version) })).status, 200, version);
    assert.equal((await ask(w, 'alpha', session, { jsonrpc: '2.0', id: 3, method: 'ping' }, { headers: under(session, null) })).status, 200, 'no header: taken');
    for (const version of ['not-a-version', '2099-01-01', '2026-07-28', '2024-11-05']) {
      assert.equal((await ask(w, 'alpha', session, { jsonrpc: '2.0', id: 4, method: 'ping' }, { headers: under(session, version) })).status, 400, version);
      assert.equal((await post(w, 'alpha', { jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'echo', arguments: {} } }, { headers: under(session, version) })).status, 400, `a call under ${version}`);
      assert.equal((await rawRequest(w, { method: 'GET', headers: { ...auth(w, 'alpha'), ...under(session, version), accept: 'text/event-stream' } })).status, 400);
      assert.equal((await rawRequest(w, { method: 'DELETE', headers: { ...auth(w, 'alpha'), ...under(session, version) } })).status, 400);
    }
    assert.equal(events(w, 'refused').filter((e) => e.code === 'protocol-version').length, 5 + 16);
    assert.equal(w.executor.agent('alpha').sessions(), 1, 'a refused DELETE ended nothing');
    // The version a session's program answered "initialize" with may be named in that session, and in no other.
    const old = await post(w, 'beta', initialize(1, '2024-11-05'));
    assert.equal(old.json.result.protocolVersion, '2024-11-05');
    const oldSession = old.headers.get('mcp-session-id');
    assert.equal((await ask(w, 'beta', oldSession, { jsonrpc: '2.0', id: 2, method: 'ping' }, { headers: under(oldSession, '2024-11-05') })).status, 200);
    assert.equal((await ask(w, 'alpha', session, { jsonrpc: '2.0', id: 9, method: 'ping' }, { headers: under(session, '2024-11-05') })).status, 400);
  } finally {
    await w.close();
  }
});

test('a request the program never answers is cancelled at the timeout, under the executor\'s id; "initialize" is not', async () => {
  const w = await localWorld({ config: { timeout: 1000 } });
  try {
    const { session } = await begin(w, 'alpha');
    const answer = await ask(w, 'alpha', session, { jsonrpc: '2.0', id: 7, method: 'never' });
    assert.equal(answer.status, 504);
    await until(() => seenByProgram(w).some((e) => e.seen?.method === 'notifications/cancelled'));
    const seen = seenByProgram(w).map((e) => e.seen).filter(Boolean);
    const asked = seen.find((m) => m.method === 'never');
    assert.notEqual(asked.id, 7, 'the program knows the request by the executor\'s id');
    assert.equal(seen.find((m) => m.method === 'notifications/cancelled').params.requestId, asked.id);
  } finally {
    await w.close();
  }
  const never = await localWorld({ env: { FAKE_INIT: 'never' }, config: { timeout: 1000 } });
  try {
    assert.equal((await begin(never, 'alpha')).answer.status, 504);
    await until(() => never.executor.programs() === 0, { timeout: 3000 });
    assert.ok(!seenByProgram(never).some((e) => e.seen?.method === 'notifications/cancelled'));
  } finally {
    await never.close();
  }
});
