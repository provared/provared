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
import { fileURLToPath } from 'node:url';

const { checkBook, identifierFingerprint } = await import('provared');
const { KILL_WAIT, SERVER_ENDED, UNREADABLE_ANSWER } = await import('../executor.mjs');
const { BACKLOG_LIMIT, LOCAL_VERSIONS } = await import('../http.mjs');
const { CLOSE_MARGIN, FLOOD_PER_SECOND, FLOOD_SECONDS, STDERR_BACKLOG, STDERR_LINE, STDERR_PER_SECOND, openLocalSessions } = await import('../local.mjs');
const { CODES } = await import('../jsonrpc.mjs');
const { httpWorld, openHttpWorld, post, rawRequest, auth } = await import('./http-world.mjs');
const { FAKE_SERVER, until, pause, world, openWorld } = await import('./world.mjs');

const LAUNCHER = fileURLToPath(new URL('./launcher.mjs', import.meta.url));

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

const seenByProgram = (w) => (existsSync(w.fakeLog) ? ((text) => text.slice(0, text.lastIndexOf('\n') + 1))(readFileSync(w.fakeLog, 'utf8')).split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
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
    const w = await localWorld({ env: { FAKE_INIT: 'deaf' }, config: { timeout: 3000, shutdownWait: 500 } });
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

test('a program busy with a call when the bound is passed is given shutdownWait: the session ends, and the call it was working on is still answered (X363)', async () => {
  const w = await localWorld({ config: { timeout: 15000, shutdownWait: 8000, tools: { ...TOOLS, work: { action: 'tool.run' } } } });
  try {
    const { session } = await begin(w, 'alpha');
    // The program works for 4 seconds and reads nothing meanwhile.
    const working = callIn(w, 'alpha', session, 'work', { ms: 4000 });
    await until(() => seenByProgram(w).some((m) => m.seen?.params?.name === 'work'));
    const mebibyte = 1024 * 1024;
    const fill = BACKLOG_LIMIT / mebibyte - 1;
    for (let i = 0; i <= fill; i++) {
      const sent = await ask(w, 'alpha', session, { jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: 'p', progress: i, message: 'x'.repeat(i < fill ? mebibyte : 1.5 * mebibyte) } });
      assert.equal(sent.status, 202, `notification ${i}: ${sent.body}`);
    }
    const refused = await ping(w, 'alpha', session);
    assert.equal(refused.status, 503, refused.body);
    assert.equal(events(w, 'session-ended').at(-1).why, 'not-reading');
    assert.equal(events(w, 'server-killed').length, 0, 'not ended by force at once');
    const answer = await working;
    assert.equal(answer.json.result?.content[0].text, 'Worked.', answer.body);
  } finally {
    await w.close();
  }
});

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
    // With no session: any message but the "initialize" that begins one (X287, and the test after this one).
    for (const version of ['not-a-version', '2099-01-01', '2026-07-28', '2024-11-05', '']) {
      const refused = await post(w, 'alpha', { jsonrpc: '2.0', id: 1, method: 'ping' }, { headers: { 'mcp-protocol-version': version } });
      assert.equal(refused.status, 400, `a ping with no session under ${JSON.stringify(version)}`);
      assert.equal(refused.json.error.code, CODES.invalidRequest);
      assert.match(refused.json.error.message, /^The MCP-Protocol-Version header names a version the executor does not serve/);
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

test('MCP-Protocol-Version on the "initialize" that begins a session: with no session id it is taken whatever version the header names, and the version the program answers with is the session\'s; every other request keeps the rule', async () => {
  const w = await localWorld();
  const versionRefusals = () => events(w, 'refused').filter((e) => e.code === 'protocol-version');
  try {
    // A client that names the newest revision on its opening "initialize": taken. The version is agreed inside "initialize", and the program answered 2025-11-25.
    const begun = await post(w, 'alpha', initialize(1, '2025-11-25'), { headers: { 'mcp-protocol-version': '2026-07-28' } });
    assert.equal(begun.status, 200, JSON.stringify(begun.json));
    assert.equal(begun.json.result.protocolVersion, '2025-11-25');
    const session = begun.headers.get('mcp-session-id');
    assert.ok(session, 'a session was begun');
    assert.equal(w.executor.programs(), 1);
    assert.equal(versionRefusals().length, 0);
    // In that session the header is held to the rule again: 2026-07-28 is not what the program answered, so it is refused; the version it answered is taken.
    assert.equal((await ask(w, 'alpha', session, { jsonrpc: '2.0', id: 2, method: 'ping' }, { headers: under(session, '2026-07-28') })).status, 400);
    assert.equal((await callIn(w, 'alpha', session, 'echo', {})).status, 200);
    assert.equal((await post(w, 'alpha', { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo', arguments: {} } }, { headers: under(session, '2026-07-28') })).status, 400);
    assert.equal(versionRefusals().length, 2);
    // Any other value on the opening "initialize" is taken too: the header settles nothing there.
    for (const version of ['2099-01-01', 'not-a-version', '']) {
      const other = await post(w, 'beta', initialize(1, '2025-06-18'), { headers: { 'mcp-protocol-version': version } });
      assert.equal(other.status, 200, JSON.stringify(version));
      assert.equal(other.json.result.protocolVersion, '2025-06-18');
      assert.equal((await endSession(w, 'beta', other.headers.get('mcp-session-id'))).status, 204);
    }
    // Where the program answers 2026-07-28, that is the session's version, and a later request may name it (X247).
    const newest = await post(w, 'beta', initialize(1, '2026-07-28'), { headers: { 'mcp-protocol-version': '2026-07-28' } });
    assert.equal(newest.json.result.protocolVersion, '2026-07-28');
    const newestSession = newest.headers.get('mcp-session-id');
    assert.equal((await ask(w, 'beta', newestSession, { jsonrpc: '2.0', id: 2, method: 'ping' }, { headers: under(newestSession, '2026-07-28') })).status, 200);
    assert.equal(versionRefusals().length, 2, 'none of these was refused for its header');
    // Every other request keeps the rule. With no session id: a request that is not "initialize", and a notification.
    const before = versionRefusals().length;
    assert.equal((await post(w, 'alpha', { jsonrpc: '2.0', id: 4, method: 'tools/list' }, { headers: { 'mcp-protocol-version': '2026-07-28' } })).status, 400);
    assert.equal((await post(w, 'alpha', { jsonrpc: '2.0', method: 'notifications/initialized' }, { headers: { 'mcp-protocol-version': '2026-07-28' } })).status, 400);
    assert.equal((await post(w, 'alpha', { jsonrpc: '2.0', method: 'initialize' }, { headers: { 'mcp-protocol-version': '2026-07-28' } })).status, 400, 'an "initialize" with no id is a notification, and begins nothing');
    // An "initialize" that names a session is refused for its header, as before; under a version that is served, for naming a session.
    const named = await post(w, 'alpha', initialize(5), { headers: under(session, '2026-07-28') });
    assert.equal(named.status, 400);
    assert.match(named.json.error.message, /^The MCP-Protocol-Version header names a version/);
    assert.match((await post(w, 'alpha', initialize(6), { headers: under(session) })).json.error.message, /this one names a session/);
    assert.equal(versionRefusals().length, before + 4);
    // Two programs run: the first session's and the last one's. The three sessions that were ended have none, and no refusal started one.
    await until(() => w.executor.programs() === 2, { timeout: 3000 });
    // For a POST with no session id the check now comes once the message has been read, so the checks of the body come before it; under a session it is still the first.
    const notJson = await rawRequest(w, { headers: { 'content-type': 'text/plain', ...auth(w, 'alpha'), 'mcp-protocol-version': '2026-07-28' }, body: 'x' });
    assert.equal(notJson.status, 415);
    const notAMessage = await rawRequest(w, { headers: { 'content-type': 'application/json', ...auth(w, 'alpha'), 'mcp-protocol-version': '2026-07-28' }, body: '[]' });
    assert.equal(notAMessage.status, 400);
    assert.equal(versionRefusals().length, before + 4, 'refused for the body, not for the header');
    const inSession = await rawRequest(w, { headers: { 'content-type': 'text/plain', ...auth(w, 'alpha'), ...under(session, '2026-07-28') }, body: 'x' });
    assert.equal(inSession.status, 400);
    assert.equal(versionRefusals().length, before + 5);
    // The check that waited comes before the mirrored headers: a message that also has a header that disagrees with it is refused for its version.
    const mirrored = await post(w, 'alpha', { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'echo', arguments: {} } }, { headers: { 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/list' } });
    assert.equal(mirrored.status, 400);
    assert.match(mirrored.json.error.message, /^The MCP-Protocol-Version header names a version/);
    assert.equal(versionRefusals().length, before + 6);
    // A GET or a DELETE with no session id is no "initialize": it is refused for its version at once, not for naming no session.
    for (const method of ['GET', 'DELETE']) {
      const none = await rawRequest(w, { method, headers: { ...auth(w, 'alpha'), 'mcp-protocol-version': '2026-07-28', ...(method === 'GET' ? { accept: 'text/event-stream' } : {}) } });
      assert.equal(none.status, 400, method);
      assert.match(none.body, /The MCP-Protocol-Version header names a version/, method);
      assert.deepEqual({ version: versionRefusals().at(-1).version, session: versionRefusals().at(-1).session }, { version: '2026-07-28', session: false }, method);
    }
    assert.equal(versionRefusals().length, before + 8);
  } finally {
    await w.close();
  }
});

test('the log line of a request refused for its MCP-Protocol-Version names the version, where it is written as a revision is, and says whether a session id came with it; nothing else of the request', async () => {
  const w = await localWorld();
  try {
    const { session } = await begin(w, 'alpha');
    const last = () => events(w, 'refused').filter((e) => e.code === 'protocol-version').at(-1);
    const ping = { jsonrpc: '2.0', id: 'an-id-not-for-the-log', method: 'ping', params: { secret: 'not-for-the-log' } };
    // A revision's form: named. With no session id, and with one.
    assert.equal((await post(w, 'alpha', ping, { headers: { 'mcp-protocol-version': '2026-07-28' } })).status, 400);
    assert.deepEqual({ version: last().version, session: last().session }, { version: '2026-07-28', session: false });
    assert.equal((await post(w, 'alpha', ping, { headers: under(session, '2099-01-01') })).status, 400);
    assert.deepEqual({ version: last().version, session: last().session }, { version: '2099-01-01', session: true });
    // The line holds the event, the code, the agent's name as every line of an agent's does, and these two; nothing of the body, and not the session's id.
    assert.deepEqual(Object.keys(last()).sort(), ['agent', 'code', 'event', 'session', 'version']);
    assert.equal(JSON.stringify(last()).includes(session), false);
    assert.equal(JSON.stringify(events(w, 'refused')).includes('not-for-the-log'), false);
    // Any other value is written as "other": what a client sends there is not put in the log.
    const odd = ['not-a-version', '', '2026-7-28', '2026-07-28x', 'x2026-07-28', '20260728', '{"event":"oauth-approved"}', 'x'.repeat(300)];
    for (const version of odd) {
      assert.equal((await post(w, 'alpha', ping, { headers: { 'mcp-session-id': session, 'mcp-protocol-version': version } })).status, 400, JSON.stringify(version));
      assert.deepEqual({ version: last().version, session: last().session }, { version: 'other', session: true }, JSON.stringify(version));
    }
    assert.equal(events(w, 'refused').filter((e) => e.code === 'protocol-version').length, 2 + odd.length);
    // A GET and a DELETE are logged in the same way.
    assert.equal((await rawRequest(w, { method: 'GET', headers: { ...auth(w, 'alpha'), ...under(session, '2026-07-28'), accept: 'text/event-stream' } })).status, 400);
    assert.deepEqual({ version: last().version, session: last().session }, { version: '2026-07-28', session: true });
  } finally {
    await w.close();
  }
});

test('a request the program never answers is cancelled at the timeout, under the executor\'s id; "initialize" is not', async () => {
  // The timeout leaves a program time to start on a busy computer: the session must be begun before the request that is never answered.
  const w = await localWorld({ config: { timeout: 4000 } });
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
    await until(() => never.executor.programs() === 0, { timeout: 10000 });
    assert.ok(!seenByProgram(never).some((e) => e.seen?.method === 'notifications/cancelled'));
  } finally {
    await never.close();
  }
});

test('a program that writes much, answers and ends at once: its exit does not overtake its last lines, and the answer reaches the agent with its receipt (X251)', async () => {
  const w = await localWorld({ config: { tools: { ...TOOLS, chatty: { action: 'tool.run' } }, timeout: 20000 } });
  try {
    // The counts at which the re-check lost answers on Linux: all of them at 1,500, some at each of the others.
    const counts = [1500, 1500, 1500, 1500, 3000, 3000, 6000, 12000];
    for (const [i, count] of counts.entries()) {
      const { session } = await begin(w, 'alpha');
      const answer = await callIn(w, 'alpha', session, 'chatty', { count });
      assert.equal(answer.json.result?.content[0].text, 'Chatty.', `session ${i}, ${count} notifications: ${answer.body.slice(0, 200)}`);
    }
    const stubs = stubsOf(await bookOf(w, 'alpha'));
    assert.equal(stubs.length, counts.length);
    for (const stub of stubs) assert.ok(docs(stub)['provared.tool-result'], 'the receipt names the result, not a program that ended before it answered');
    assert.equal(events(w, 'late-answer-dropped').length, 0);
  } finally {
    await w.close();
  }
  // The same on stdio.
  const stdio = await world({ config: { tools: { chatty: { action: 'tool.run' } }, timeout: 20000 } });
  const answer = await stdio.client.call('chatty', { count: 3000 });
  assert.equal(answer.result?.content[0].text, 'Chatty.', JSON.stringify(answer).slice(0, 200));
  await stdio.close();
});

test('the stop reaches what a program started: a server behind a launcher that passes no signal on is ended with it, and counts until it has gone (X252)', { skip: POSIX ? false : 'Windows has no process groups: there the one process the executor started is ended, as the README says' }, async () => {
  // A process that has ended but is not yet reaped (a zombie) has gone: where nothing reaps orphans, as in a container
  // with no init, a server whose launcher has ended stays a zombie, and a signal 0 to it still succeeds.
  const alive = (pid) => {
    try {
      process.kill(pid, 0);
    } catch {
      return false;
    }
    try {
      const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
      return stat.slice(stat.lastIndexOf(')') + 2, stat.lastIndexOf(')') + 3) !== 'Z';
    } catch {
      return true;
    }
  };
  const pidsOf = (file) => (existsSync(file) ? readFileSync(file, 'utf8').split('\n').filter(Boolean).map(Number) : []);
  // The real server stays when its input closes, and ends at SIGTERM; the launcher passes no signal on.
  const w = await httpWorld({ open: false });
  delete w.settings.upstream;
  const pids = join(w.folder, 'pids');
  w.settings.server = { command: process.execPath, args: [LAUNCHER, FAKE_SERVER], env: { FAKE_LINGER: { value: '600000' }, LAUNCHER_PIDS: { value: pids } } };
  w.settings.tools = TOOLS;
  Object.assign(w.settings, { sessions: { max: 2 }, shutdownWait: 300 });
  await openHttpWorld(w, { serverStderr: null });
  try {
    const most = await mostPrograms(w, async () => {
      for (let i = 0; i < 5; i++) assert.equal((await begin(w, 'alpha')).answer.status, 200);
    });
    assert.equal(most, 2);
    assert.equal(pidsOf(pids).length, 5);
    assert.equal(pidsOf(pids).filter(alive).length, 2, 'the real servers of the three sessions that made room have gone');
  } finally {
    await w.close();
  }
  await until(() => pidsOf(pids).filter(alive).length === 0, { timeout: 3000 });
  // A launcher that ends by itself and leaves its server running: what is left in its group is ended, and counts as the program until it has gone.
  const left = await httpWorld({ open: false });
  delete left.settings.upstream;
  const leftPids = join(left.folder, 'pids');
  left.settings.server = { command: process.execPath, args: [LAUNCHER, FAKE_SERVER], env: { FAKE_LINGER: { value: '600000' }, LAUNCHER_PIDS: { value: leftPids }, LAUNCHER_LEAVES: { value: '700' } } };
  left.settings.tools = TOOLS;
  Object.assign(left.settings, { shutdownWait: 300 });
  await openHttpWorld(left, { serverStderr: null });
  try {
    assert.equal((await begin(left, 'alpha')).answer.status, 200);
    await until(() => left.logs.some((e) => e.event === 'server-group-left'), { timeout: 6000 });
    await until(() => left.executor.programs() === 0, { timeout: 6000 });
    assert.equal(pidsOf(leftPids).filter(alive).length, 0, 'the server the launcher left behind has gone');
  } finally {
    await left.close();
  }
  // The same on stdio, at the client's end.
  const stdio = await world({ open: false, config: { shutdownWait: 300 } });
  const stdioPids = join(stdio.folder, 'pids');
  stdio.settings.server = { command: process.execPath, args: [LAUNCHER, FAKE_SERVER], env: { FAKE_LINGER: { value: '600000' }, LAUNCHER_PIDS: { value: stdioPids } } };
  await openWorld(stdio);
  assert.equal((await stdio.client.call('echo', {})).result?.isError, undefined);
  assert.equal(pidsOf(stdioPids).filter(alive).length, 1);
  await stdio.close();
  await until(() => pidsOf(stdioPids).filter(alive).length === 0, { timeout: 3000 });
});

/** A stand-in for a program, for the tests of local.mjs alone: nothing ends it, and a test writes its output. */
const standIn = () => Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), kill: () => true });
/** The sessions of a stand-in program, with the clock in the test's hands. */
async function clocked(t, settings = {}) {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'] });
  const child = standIn();
  const logs = [];
  const local = openLocalSessions({ settings: { server: { resolved: 'x', args: [] }, sessions: { max: 1, idle: 3600000 }, shutdownWait: 100, timeout: 1000, ...settings }, env: {}, credentialNames: [], log: (e) => logs.push(e), serverStderr: null, spawnProgram: () => child });
  const { session } = await local.begin('alpha', null);
  /** Write "count" lines of the program's output at once, and let them be read. */
  const write = async (count, line = { jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info' } }) => {
    child.stdout.write(`${JSON.stringify(line)}\n`.repeat(count));
    for (let turn = 0; turn < 3; turn++) await new Promise((d) => setImmediate(d));
  };
  return { child, logs, local, session, write, tick: (ms) => t.mock.timers.tick(ms) };
}

test('local.mjs: once the stop has begun (noMore), before the sessions are closed, a new session starts no program (X246; review 3.7f re-check, N3)', async () => {
  let spawned = 0;
  const local = openLocalSessions({ settings: { server: { resolved: 'x', args: [] }, sessions: { max: 2, idle: 3600000 }, shutdownWait: 100, timeout: 1000 }, env: {}, credentialNames: [], log: () => {}, serverStderr: null, spawnProgram: () => (spawned++, standIn()) });
  // The time in which the stop waits for calls in flight: "close" has not run yet.
  local.noMore();
  assert.deepEqual(await local.begin('alpha', null), { refused: 'stopping' });
  assert.equal(spawned, 0, 'no program was started');
  await local.close();
});

test('local.mjs, the flood rule by the clock: more than 1,000 messages in each of 5 seconds running ends the session; an honest program below that, evenly or in bursts, is not ended (X245)', async (t) => {
  // 1,001 in each of five seconds running.
  const flood = await clocked(t);
  for (let second = 0; second < FLOOD_SECONDS; second++) {
    assert.equal(flood.session.ended, null, `second ${second}`);
    await flood.write(FLOOD_PER_SECOND + 1);
    flood.tick(1000);
  }
  assert.equal(flood.session.ended, 'flooding');
  assert.equal(flood.logs.filter((e) => e.event === 'server-flooding').length, 1);
  t.mock.timers.reset();

  // 1,000 a second, evenly, for 12 seconds: at the limit, and not over it.
  const even = await clocked(t);
  for (let second = 0; second < 12; second++) {
    await even.write(FLOOD_PER_SECOND);
    even.tick(1000);
  }
  assert.equal(even.session.ended, null);
  t.mock.timers.reset();

  // 1,001 at once every 1.9 seconds, for 40 seconds: about 527 a second, and in every other second none at all.
  const bursts = await clocked(t);
  for (let burst = 0; burst < 21; burst++) {
    await bursts.write(FLOOD_PER_SECOND + 1);
    bursts.tick(1900);
  }
  assert.equal(bursts.session.ended, null);
  t.mock.timers.reset();

  // Four seconds over the limit, one second with nothing, four more over it: the quiet second breaks the run.
  const broken = await clocked(t);
  for (const pause of [1000, 1000, 1000, 2000, 1000, 1000, 1000, 2000]) {
    await broken.write(FLOOD_PER_SECOND + 1);
    broken.tick(pause);
  }
  assert.equal(broken.session.ended, null);
  // And a second with a few messages, under the limit, breaks it as well.
  for (const count of [FLOOD_PER_SECOND + 1, FLOOD_PER_SECOND + 1, FLOOD_PER_SECOND + 1, 5, FLOOD_PER_SECOND + 1, FLOOD_PER_SECOND + 1]) {
    await broken.write(count);
    broken.tick(1000);
  }
  assert.equal(broken.session.ended, null);
});

test('local.mjs, the flood rule counts every message that answers nothing in flight: an answer to no request, and a message that reaches an open stream, as much as one that is dropped (X245)', async (t) => {
  const answers = await clocked(t);
  for (let second = 0; second < FLOOD_SECONDS; second++) {
    await answers.write(FLOOD_PER_SECOND + 1, { jsonrpc: '2.0', id: 'nobody', result: {} });
    answers.tick(1000);
  }
  assert.equal(answers.session.ended, 'flooding', 'answers to nothing in flight');
  t.mock.timers.reset();

  const streamed = await clocked(t);
  let delivered = 0;
  streamed.session.toStream = () => {
    delivered += 1;
    return true;
  };
  for (let second = 0; second < FLOOD_SECONDS; second++) {
    await streamed.write(FLOOD_PER_SECOND + 1);
    streamed.tick(1000);
  }
  assert.equal(streamed.session.ended, 'flooding', 'messages that reach an open stream');
  assert.ok(delivered > FLOOD_PER_SECOND * (FLOOD_SECONDS - 1), 'and they were delivered until then');
});

test('local.mjs: the second wait, before SIGKILL, is "shutdownWait" again and at most 5 seconds (X242)', async (t) => {
  const long = await clocked(t, { shutdownWait: 20000 });
  const signals = () => long.logs.filter((e) => e.event === 'server-killed').map((e) => e.signal);
  long.local.end(long.session, 'ended-by-agent');
  long.tick(19999);
  assert.deepEqual(signals(), []);
  long.tick(1);
  assert.deepEqual(signals(), ['SIGTERM']);
  long.tick(KILL_WAIT - 1);
  assert.deepEqual(signals(), ['SIGTERM']);
  long.tick(1);
  assert.deepEqual(signals(), ['SIGTERM', 'SIGKILL'], '5 seconds after SIGTERM, not 20');
  t.mock.timers.reset();

  const short = await clocked(t, { shutdownWait: 300 });
  short.local.end(short.session, 'ended-by-agent');
  short.tick(300);
  short.tick(299);
  assert.deepEqual(short.logs.filter((e) => e.event === 'server-killed').map((e) => e.signal), ['SIGTERM']);
  short.tick(1);
  assert.deepEqual(short.logs.filter((e) => e.event === 'server-killed').map((e) => e.signal), ['SIGTERM', 'SIGKILL'], '"shutdownWait" again, where it is shorter');
});

test('a program that floods its standard error has no more than 256 KiB of it written on in each second; the rest is dropped and counted (X353)', async () => {
  let bytes = 0;
  const stderr = new PassThrough();
  stderr.on('data', (d) => (bytes += d.length));
  const w = await localWorld({ config: { tools: { ...TOOLS, floodErr: { action: 'tool.run' } } }, more: { serverStderr: stderr } });
  try {
    const { session } = await begin(w, 'alpha');
    const began = Date.now();
    assert.equal((await callIn(w, 'alpha', session, 'floodErr', { mib: 4 })).json.result?.content[0].text, 'Flooded.');
    await until(() => events(w, 'server-stderr-dropped').length > 0);
    const seconds = Math.floor((Date.now() - began) / 1000) + 2;
    assert.ok(bytes <= seconds * STDERR_PER_SECOND, `${bytes} bytes written on in about ${seconds} seconds' worth`);
    assert.ok(bytes > 0, 'the first lines are written on');
    assert.ok(events(w, 'server-stderr-dropped').every((e) => e.count > 0 && e.agent === 'alpha'));
  } finally {
    await w.close();
  }
});

test('where more than 1 MiB already waits to be written to the executor\'s standard error, a program\'s lines are dropped, not held (X353)', async () => {
  // A place that has taken nothing for a long while: what waits there is already over the bound.
  const stuck = { writableLength: STDERR_BACKLOG + 1, written: 0, write() { this.written += 1; return false; } };
  const w = await localWorld({ config: { tools: { ...TOOLS, longerr: { action: 'tool.run' } } }, more: { serverStderr: stuck } });
  try {
    const { session } = await begin(w, 'alpha');
    assert.equal((await callIn(w, 'alpha', session, 'longerr', {})).json.result?.content[0].text, 'Long.');
    await until(() => events(w, 'server-stderr-dropped').length > 0 || stuck.written > 0);
    assert.equal(stuck.written, 0);
  } finally {
    await w.close();
  }
});

test('a line of a program\'s standard error longer than 64 KiB is dropped, and the log says so; the lines after it are written on', async () => {
  const said = [];
  const stderr = new PassThrough();
  stderr.on('data', (d) => said.push(d.toString('utf8')));
  const w = await localWorld({ config: { tools: { ...TOOLS, longerr: { action: 'tool.run' } } }, more: { serverStderr: stderr } });
  try {
    const { session } = await begin(w, 'alpha');
    assert.equal((await callIn(w, 'alpha', session, 'longerr', {})).json.result?.content[0].text, 'Long.');
    await until(() => said.join('').includes('after the long line\n'));
    assert.ok(said.every((piece) => piece.length <= STDERR_LINE + 1), 'no piece written on is longer than the limit');
    assert.ok(!said.join('').includes('LLLL'));
    assert.equal(events(w, 'server-stderr-line-dropped').length, 1);
  } finally {
    await w.close();
  }
});
