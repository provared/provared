// The command for the HTTP executor: "http" as a real process, stopped in
// the middle of a call and started again; "secret"; and "check", "keys" and
// "compare --agent" on the HTTP settings.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook, identifierFingerprint } = await import('provared');
const { httpWorld, call, request, rawRequest, auth } = await import('./http-world.mjs');
const { EXECUTOR_STOPPED, OUTCOME_UNKNOWN, WRITTEN_LATE_DOCUMENT } = await import('../executor.mjs');
const { secretHash } = await import('../http.mjs');
const { until } = await import('./world.mjs');

const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));
const WRAPPER = fileURLToPath(new URL('./signal-wrapper.mjs', import.meta.url));

const children = new Set();
function start(args, cwd) {
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', BIN, ...args], { cwd, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  children.add(child);
  child.on('exit', () => children.delete(child));
  child.stdin.end();
  return child;
}
process.on('exit', () => {
  for (const c of children) {
    try {
      c.kill();
    } catch {
      // Already gone.
    }
  }
});
function run(args, { cwd } = {}) {
  return new Promise((done) => {
    const child = start(args, cwd);
    const out = [];
    const err = [];
    child.stdout.on('data', (c) => out.push(c));
    child.stderr.on('data', (c) => err.push(c));
    child.on('exit', (code) => done({ code, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }));
  });
}
/** A port nobody listens on right now. */
function freePort() {
  return new Promise((done) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => done(port));
    });
  });
}
/** End a child for good (on Windows, kill is final), and wait for it. */
function kill(child) {
  return new Promise((done) => {
    if (child.exitCode !== null) return done();
    child.on('exit', () => done());
    child.kill();
  });
}

test('http: a real process in front of the upstream; stopped in the middle of a call, the next start writes the receipt from the copy, and compare agrees', async () => {
  const w = await httpWorld({ open: false, agents: ['alpha'] });
  const port = await freePort();
  w.settings.listen = { host: '127.0.0.1', port };
  w.settings.timeout = 30000;
  writeFileSync(w.configPath, JSON.stringify(w.settings));
  w.url = `http://127.0.0.1:${port}/mcp`;
  const logsOf = (child) => {
    const lines = [];
    child.stderr.on('data', (c) => lines.push(c.toString('utf8')));
    return () => lines.join('').split('\n').filter(Boolean).map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return { raw: l };
      }
    });
  };
  const waitListening = async () => until(async () => {
    try {
      return (await request(w, 'alpha', 'ping')).status === 200;
    } catch {
      return false;
    }
  }, { timeout: 15000, every: 100 });

  let child = start(['http', '--config', w.configPath], w.folder);
  let logs = logsOf(child);
  try {
    await waitListening();
    assert.ok(logs().some((e) => e.event === 'listening' && e.address === '127.0.0.1' && e.port === port));
    const echo = await call(w, 'alpha', 'echo', { n: 1 });
    assert.equal(echo.status, 200);
    // A slow call, in flight when the executor is stopped for good.
    const pending = call(w, 'alpha', 'slow', { ms: 20000 }, { id: 'lost' }).catch((e) => e.message);
    await until(() => existsSync(w.agents.alpha.copy) && readFileSync(w.agents.alpha.copy, 'utf8').split('\n').filter((l) => l.includes('"kind":"sending"')).length === 2, { timeout: 10000 });
    await kill(child);
    const failed = await pending;
    assert.equal(typeof failed, 'string', 'the agent\'s request ended with an error');
    const book1 = await checkBook(readFileSync(w.agents.alpha.book, 'utf8'), { issuerKeys: w.settings.agents.alpha.issuerKeys });
    assert.equal(book1.entries.filter((e) => e.kind === 'stub').length, 1, 'the slow call has no receipt yet');

    // Started again: the receipt is written from the copy before anything is served.
    child = start(['http', '--config', w.configPath], w.folder);
    logs = logsOf(child);
    await waitListening();
    const late = logs().find((e) => e.event === 'receipt-written-late');
    assert.ok(late, 'the log says so');
    assert.equal(late.agent, 'alpha');
    const book2 = await checkBook(readFileSync(w.agents.alpha.book, 'utf8'), { issuerKeys: w.settings.agents.alpha.issuerKeys });
    assert.equal(book2.summary.problemFound, false);
    const stubs = book2.entries.filter((e) => e.kind === 'stub');
    assert.equal(stubs.length, 2);
    const d = Object.fromEntries(stubs[1].content.details.map((x) => [x.name, x.sha256]));
    assert.equal(d['provared.error'], await identifierFingerprint(OUTCOME_UNKNOWN));
    assert.ok(d[WRITTEN_LATE_DOCUMENT]);
    assert.equal(d['provared.tool-name'], await identifierFingerprint('slow'));
    assert.equal(stubs[1].countersignature.state, 'valid');
    const again = await call(w, 'alpha', 'echo', { n: 2 });
    assert.equal(again.status, 200);
    // The slow call may or may not have reached the upstream before the stop: that is what "outcome not known" means.
    assert.ok([2, 3].includes(w.upstream.seen.filter((s) => s.body?.method === 'tools/call').length));
    assert.ok(!logs().some((e) => JSON.stringify(e).includes(w.agents.alpha.secret)), 'the secret is in no log line');
  } finally {
    await kill(child);
  }
  const compared = await run(['compare', '--config', w.configPath, '--agent', 'alpha'], { cwd: w.folder });
  assert.equal(compared.code, 0, compared.stderr);
  const result = JSON.parse(compared.stdout);
  assert.equal(result.summary.agree, true);
  assert.equal(result.summary.matched, 3, 'the two echoes, and the slow call written late');
  const noAgent = await run(['compare', '--config', w.configPath], { cwd: w.folder });
  assert.equal(noAgent.code, 2);
  assert.match(noAgent.stderr, /--agent <name>/);
  await w.upstream.close();
});

test('secret prints a secret and its hash; check and keys read the HTTP settings', async () => {
  const w = await httpWorld({ open: false, agents: ['alpha', 'beta'] });
  try {
    const secret = await run(['secret']);
    assert.equal(secret.code, 0);
    const [, value] = /The secret[^\n]*\n {2}([A-Za-z0-9_-]{43})\n/.exec(secret.stdout) ?? [];
    const [, hash] = /Its hash[^\n]*\n {2}([A-Za-z0-9_-]{43})\n/.exec(secret.stdout) ?? [];
    assert.ok(value && hash);
    assert.equal(hash, secretHash(value));

    const check = await run(['check', '--config', w.configPath], { cwd: w.folder });
    assert.equal(check.code, 0, check.stderr);
    const report = JSON.parse(check.stdout);
    assert.deepEqual(report.problems, []);
    assert.deepEqual(Object.keys(report.agents), ['alpha', 'beta']);
    assert.equal(report.credential, true);
    assert.equal(report.listen.host, '127.0.0.1');
    assert.equal(report.upstream, w.upstream.url);
    assert.equal(report.agents.alpha.unfinished, 0);
    assert.ok(report.tools.some((t) => t.tool === 'order' && t.amount.pointer === '/total'));
    assert.ok(!existsSync(w.agents.alpha.copyKey), 'check writes nothing');

    // keys: the executor's and each agent's, made once, and the entries for each permission.
    const fresh = { ...w.settings, executor: { keys: 'keys/new-executor.jwk' }, agents: { alpha: { ...w.settings.agents.alpha, keys: 'keys/new-alpha.jwk' }, beta: { ...w.settings.agents.beta, keys: 'keys/new-beta.jwk' } } };
    writeFileSync(join(w.folder, 'fresh.json'), JSON.stringify(fresh));
    const keys = await run(['keys', '--config', 'fresh.json'], { cwd: w.folder });
    assert.equal(keys.code, 0, keys.stderr);
    const printed = JSON.parse(keys.stdout);
    assert.deepEqual(Object.keys(printed), ['alpha', 'beta']);
    assert.equal(printed.alpha.with.id, 'executor');
    assert.deepEqual(printed.alpha.with.keys, printed.beta.with.keys, 'one executor for both');
    assert.notDeepEqual(printed.alpha.agent.keys, printed.beta.agent.keys, 'each agent its own keys');
    assert.equal(printed.alpha.agent.name, 'alpha, through The test HTTP executor');
    assert.deepEqual(printed.alpha.requires, [{ need: 'countersignature' }]);
    const again = JSON.parse((await run(['keys', '--config', 'fresh.json'], { cwd: w.folder })).stdout);
    assert.deepEqual(again, printed, 'made once');

    const bad = await run(['check', '--config', 'fresh.json'], { cwd: w.folder });
    assert.equal(bad.code, 1);
    assert.match(JSON.parse(bad.stdout).problems[0], /names other agent keys/);
    const broken = { ...w.settings, agents: { alpha: { ...w.settings.agents.alpha, secretHash: 'nope' } } };
    writeFileSync(join(w.folder, 'broken.json'), JSON.stringify(broken));
    const broke = await run(['check', '--config', 'broken.json'], { cwd: w.folder });
    assert.equal(broke.code, 1);
    assert.ok(JSON.parse(broke.stdout).problems.some((p) => p.startsWith('agents.alpha.secretHash')));
  } finally {
    await w.upstream.close();
  }
});

test('http: the wrong path, a method the endpoint does not take, and no settings', async () => {
  const w = await httpWorld({ agents: ['alpha'] });
  try {
    w.url = w.url.replace('/mcp', '/other');
    const wrong = await rawRequest(w, { headers: { 'content-type': 'application/json', ...auth(w, 'alpha') }, body: '{}' });
    assert.equal(wrong.status, 404);
    w.url = w.url.replace('/other', '/mcp');
    const put = await rawRequest(w, { method: 'PUT', headers: { ...auth(w, 'alpha') }, body: '{}' });
    assert.equal(put.status, 405);
    assert.equal(put.headers.get('allow'), 'POST, GET, DELETE');
    const head = await rawRequest(w, { method: 'OPTIONS', headers: { ...auth(w, 'alpha') } });
    assert.equal(head.status, 405);
  } finally {
    await w.close();
  }
  const none = await run(['http']);
  assert.equal(none.code, 2);
  assert.match(none.stderr, /--config/);
});

test('http: SIGINT with a call in flight. The call is settled as the executor\'s stop, its receipt written and the agent answered, and the process ends with code 0', async () => {
  const w = await httpWorld({ open: false, agents: ['alpha'] });
  const port = await freePort();
  w.settings.listen = { host: '127.0.0.1', port };
  w.settings.timeout = 30000;
  writeFileSync(w.configPath, JSON.stringify(w.settings));
  w.url = `http://127.0.0.1:${port}/mcp`;
  // Through the wrapper, with an IPC channel: Windows delivers no signal to a child, so there the test sends the signal's name and the wrapper raises it; elsewhere the real signal is sent.
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', WRAPPER, 'http', '--config', w.configPath], { cwd: w.folder, stdio: ['pipe', 'pipe', 'pipe', 'ipc'], windowsHide: true });
  children.add(child);
  child.on('exit', () => children.delete(child));
  child.stdin.end();
  const err = [];
  child.stderr.on('data', (c) => err.push(c));
  const exited = new Promise((done) => child.on('exit', (code) => done(code)));
  try {
    await until(async () => {
      try {
        return (await request(w, 'alpha', 'ping')).status === 200;
      } catch {
        return false;
      }
    }, { timeout: 15000, every: 100 });
    const pending = call(w, 'alpha', 'slow', { ms: 20000 }, { id: 'stopped' });
    await until(() => w.upstream.seen.some((s) => s.body?.params?.name === 'slow'));
    if (process.platform === 'win32') child.send('SIGINT');
    else child.kill('SIGINT');
    const answer = await pending;
    assert.equal(answer.status, 200);
    assert.equal(answer.json.id, 'stopped');
    assert.equal(answer.json.error.code, 1002);
    assert.equal(answer.json.error.message, EXECUTOR_STOPPED);
    assert.equal(await exited, 0, Buffer.concat(err).toString('utf8'));
    const book = await checkBook(readFileSync(w.agents.alpha.book, 'utf8'), { issuerKeys: w.settings.agents.alpha.issuerKeys });
    const stubs = book.entries.filter((e) => e.kind === 'stub');
    assert.equal(stubs.length, 1);
    const d = Object.fromEntries(stubs[0].content.details.map((x) => [x.name, x.sha256]));
    assert.equal(d['provared.error'], await identifierFingerprint(EXECUTOR_STOPPED));
    assert.equal(d[WRITTEN_LATE_DOCUMENT], undefined, 'written at the stop, not at the next start');
    assert.ok(w.upstream.aborted >= 1, 'the stream to the upstream was closed');
  } finally {
    await kill(child);
    await w.upstream.close();
  }
});
