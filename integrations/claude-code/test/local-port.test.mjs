// The recorder's own routes on its local port (all but the feed's, which
// prove each request with the feed's token) answer a program on this
// computer, not a web page. A request that names an Origin, says through
// Sec-Fetch-Site that it comes from a page, or names any Host but
// 127.0.0.1:<port>, is refused, and a POST whose body is not
// application/json is refused too, before anything is read or written.
// Every test works in a temporary folder and on a port of its own.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createServer, request } from 'node:http';
import { connect, createServer as createNetServer } from 'node:net';
import { join } from 'node:path';
import { test } from 'node:test';

const { thumbprint } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { VERSION, readTrusted, startService } = await import('../recorder.mjs');
const { feedReader } = await import('../feed.mjs');
const { runCommand, runHook, signSlip, status, tempFolder, world } = await import('./world.mjs');

/** A promise, or a failure once "ms" have passed without it. */
const within = (promise, ms, what) => Promise.race([promise, new Promise((resolve, reject) => setTimeout(() => reject(new Error(`${what}: not within ${ms} ms`)), ms).unref())]);

// The development stand-in for a passkey signs at http://localhost: the recorder is told to take records signed there.
const LOCAL = { signingOrigins: ['http://localhost'] };

/** One request, with exactly the headers given (Host among them), answered within 10 seconds. */
function ask(port, method, path, body, headers) {
  return new Promise((resolve, reject) => {
    const bytes = body === undefined ? null : Buffer.from(body);
    const req = request({ host: '127.0.0.1', port, path, method, headers: { ...headers, ...(bytes ? { 'Content-Length': bytes.length } : {}) } }, (res) => {
      let out = '';
      res.on('data', (d) => (out += d));
      res.on('end', () => resolve({ code: res.statusCode, body: out }));
    });
    req.on('error', reject);
    req.setTimeout(10000, () => req.destroy(new Error('no answer within 10 seconds')));
    req.end(bytes ?? undefined);
  });
}

const own = (port) => ({ Host: `127.0.0.1:${port}`, 'Content-Type': 'application/json' });
// Each differs from the recorder's own clients' request in one thing only; "browser" is a web page's request as a browser sends it.
const strangers = (port) => ({
  origin: [{ ...own(port), Origin: 'https://some-website.example' }, 403],
  'a null origin': [{ ...own(port), Origin: 'null' }, 403],
  'sec-fetch-site': [{ ...own(port), 'Sec-Fetch-Site': 'cross-site' }, 403],
  'sec-fetch-site same-origin': [{ ...own(port), 'Sec-Fetch-Site': 'same-origin' }, 403],
  'sec-fetch-site same-site': [{ ...own(port), 'Sec-Fetch-Site': 'same-site' }, 403],
  'sec-fetch-site anything else': [{ ...own(port), 'Sec-Fetch-Site': 'nonesuch' }, 403],
  host: [{ ...own(port), Host: `rebound.some-website.example:${port}` }, 403],
  'host without the port': [{ ...own(port), Host: '127.0.0.1' }, 403],
  'host localhost': [{ ...own(port), Host: `localhost:${port}` }, 403],
  'text/plain': [{ ...own(port), 'Content-Type': 'text/plain;charset=UTF-8' }, 415],
  'a type that only names application/json': [{ ...own(port), 'Content-Type': 'text/plain;x=application/json' }, 415],
  'a type that begins with application/json': [{ ...own(port), 'Content-Type': 'application/jsonx' }, 415],
  'no content type': [{ Host: `127.0.0.1:${port}` }, 415],
  browser: [{ Host: `127.0.0.1:${port}`, Origin: 'https://some-website.example', 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'no-cors', 'Content-Type': 'text/plain;charset=UTF-8' }, 403],
});

/** Every file in the folder and what it holds. */
function snapshot(folder) {
  const all = {};
  for (const name of readdirSync(folder).sort()) {
    const path = join(folder, name);
    all[name] = statSync(path).isFile() ? readFileSync(path, 'utf8') : 'a folder';
  }
  return all;
}

test('a web page\'s request to any of the recorder\'s own routes is refused, and nothing is written or taken', async () => {
  const w = await world([]);
  const service = await startService({ folder: w.folder, port: 0, ...LOCAL });
  try {
    const port = service.port;
    const stranger = await developmentPasskey();
    const T = await thumbprint(stranger.key);
    const theirs = await signSlip({ agentKeys: w.agent.keys, passkey: stranger, purpose: 'A stranger\'s permission.' });
    const routes = {
      '/admit': { slip: theirs, thumbprint: T, take: true },
      '/renew': { slip: theirs, newPasskey: true },
      '/before': { action: 'provared.code.run', toolUseId: 'toolu_page' },
      '/record': { action: 'provared.code.run', toolUseId: 'toolu_page', details: [{ name: 'Bash', sha256: 'A'.repeat(43) }] },
      '/seal': {},
      '/new-book': {},
      '/stop': {},
    };
    const before = { files: snapshot(w.folder), trusted: readTrusted(w.folder), status: await status(port) };
    for (const [path, body] of Object.entries(routes)) {
      for (const [what, [headers, code]] of Object.entries(strangers(port))) {
        const r = await ask(port, 'POST', path, JSON.stringify(body), headers);
        assert.equal(r.code, code, `POST ${path} with ${what}: ${r.body}`);
        assert.ok(JSON.parse(r.body).error, `POST ${path} with ${what} says why`);
      }
    }
    for (const [what, [headers, code]] of Object.entries(strangers(port))) {
      if (code === 415) continue;
      const r = await ask(port, 'GET', '/status', undefined, headers);
      assert.equal(r.code, 403, `GET /status with ${what}`);
      assert.equal(JSON.parse(r.body).folder, undefined, `GET /status with ${what} tells nothing`);
    }
    // Still running; the passkeys trusted, the permission in force, the book and every other file as they were.
    const after = await status(port);
    assert.deepEqual(readTrusted(w.folder), before.trusted, 'no passkey is trusted that was not');
    assert.equal(readTrusted(w.folder).includes(T), false);
    assert.equal(after.slip, before.status.slip, 'the permission in force is unchanged');
    assert.equal(after.issuer, before.status.issuer);
    assert.equal(after.entries, before.status.entries, 'nothing is written into the book');
    assert.equal(after.recordedSinceStart, 0);
    assert.deepEqual(snapshot(w.folder), before.files, 'no file is written');
  } finally {
    await service.close();
  }
});

test('the recorder\'s own clients are answered: the hook, the commands, and a program\'s fetch', async () => {
  const w = await world([]);
  const service = await startService({ folder: w.folder, port: 0, ...LOCAL });
  try {
    const port = service.port;
    // A program's own request as Node.js sends it (no Origin, Host 127.0.0.1:<port>); a charset after application/json is taken.
    const asked = await fetch(`http://127.0.0.1:${port}/before`, { method: 'POST', headers: { 'Content-Type': 'application/json; charset=utf-8' }, body: JSON.stringify({ action: 'provared.code.read' }), signal: AbortSignal.timeout(10000) });
    assert.equal(asked.status, 200);
    assert.equal((await asked.json()).allowed, true);
    // The media type is read before the first ";", trimmed and in any case.
    assert.equal((await ask(port, 'POST', '/before', JSON.stringify({ action: 'provared.code.read' }), { Host: `127.0.0.1:${port}`, 'Content-Type': ' Application/JSON ; charset=utf-8' })).code, 200);
    // A request a person types by hand says Sec-Fetch-Site: none, if anything.
    assert.equal((await ask(port, 'GET', '/status', undefined, { Host: `127.0.0.1:${port}`, 'Sec-Fetch-Site': 'none' })).code, 200);
    // The hook, before and after a call.
    const call = { tool_use_id: 'toolu_local' };
    const pre = await runHook(port, 'PreToolUse', 'Bash', { command: 'npm test' }, { more: call });
    assert.equal(pre.code, 0);
    assert.equal(pre.out, '', 'allowed: the hook says nothing');
    const post = await runHook(port, 'PostToolUse', 'Bash', { command: 'npm test' }, { more: call });
    assert.equal(post.code, 0);
    assert.equal((await status(port)).recordedSinceStart, 1, 'the hook\'s call is recorded');
    // The commands.
    const shown = await runCommand(['status'], { folder: w.folder, port });
    assert.equal(shown.code, 0, shown.err);
    const sealed = await runCommand(['seal'], { folder: w.folder, port });
    assert.equal(sealed.code, 0, sealed.err);
    const made = await runCommand(['new-book'], { folder: w.folder, port });
    assert.equal(made.code, 0, made.err);
    const next = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, purpose: 'The next permission.' });
    const file = join(tempFolder('provared-cc-port-'), 'next.json');
    writeFileSync(file, JSON.stringify(next));
    const first = (await status(port)).slip;
    const renewed = await runCommand(['renew', file], { folder: w.folder, port });
    assert.equal(renewed.code, 0, renewed.err);
    assert.notEqual((await status(port)).slip, first, 'the next permission is in force');
    const stopped = await runCommand(['stop'], { folder: w.folder, port });
    assert.equal(stopped.code, 0, stopped.err);
    // The recorder lets go of its port a moment after it answers.
    let gone = false;
    for (const until = Date.now() + 5000; !gone && Date.now() < until;) {
      gone = await fetch(`http://127.0.0.1:${port}/status`, { signal: AbortSignal.timeout(1000) }).then(() => false, () => true);
      if (!gone) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(gone, 'the recorder stopped');
  } finally {
    await service.close().catch(() => {});
  }
});

/** A request's head only, with a body of 1000 bytes declared and never sent: its answer, or null where none comes within 5 seconds. */
function headOnly(port, method, path, headers) {
  return new Promise((resolve) => {
    const req = request({ host: '127.0.0.1', port, path, method, headers: { ...headers, 'Content-Length': 1000 } }, (res) => {
      let out = '';
      res.on('data', (d) => (out += d));
      res.on('end', () => {
        clearTimeout(timer);
        req.destroy();
        resolve({ code: res.statusCode, body: out });
      });
    });
    const timer = setTimeout(() => {
      req.destroy();
      resolve(null);
    }, 5000);
    req.on('error', () => {});
    req.flushHeaders();
  });
}

test('a web page\'s POST is refused before its body is read: answered at once, with a body declared and never sent', async () => {
  const w = await world([]);
  const service = await startService({ folder: w.folder, port: 0, ...LOCAL });
  try {
    const port = service.port;
    const before = snapshot(w.folder);
    const asked = [];
    for (const path of ['/admit', '/renew', '/before', '/record', '/seal', '/new-book', '/stop', '/hand-over']) {
      for (const [what, [headers, code]] of Object.entries(strangers(port))) {
        // The feed's route asks for no Content-Type: its body is proved with the feed's token.
        if (path === '/hand-over' && code === 415) continue;
        asked.push(headOnly(port, 'POST', path, headers).then((r) => [path, what, code, r]));
      }
    }
    for (const [path, what, code, r] of await Promise.all(asked)) {
      assert.ok(r, `POST ${path} with ${what}: answered before its body is sent`);
      assert.equal(r.code, code, `POST ${path} with ${what}: ${r.body}`);
    }
    const after = await status(port);
    assert.equal(after.recordedSinceStart, 0);
    assert.deepEqual(snapshot(w.folder), before, 'no file is written');
  } finally {
    await service.close();
  }
});

test('the feed\'s four routes refuse a web page\'s request too, and give it no session and no proof; the feed\'s own reader is answered', async () => {
  const w = await world([]);
  const service = await startService({ folder: w.folder, port: 0, ...LOCAL });
  try {
    const port = service.port;
    const random = () => randomBytes(32).toString('base64url');
    const feedHeaders = { 'Provared-Feed-Hello': random(), 'Provared-Feed-Session': random(), 'Provared-Feed-Nonce': random(), 'Provared-Feed-Proof': random() };
    for (const [method, path] of [['GET', '/hello'], ['GET', '/books'], ['GET', '/lines?from=0&wait=0'], ['POST', '/hand-over']]) {
      for (const [what, [headers, code]] of Object.entries(strangers(port))) {
        if (code === 415) continue;
        const r = await ask(port, method, path, method === 'POST' ? '{}' : undefined, { ...headers, ...feedHeaders });
        assert.equal(r.code, 403, `${method} ${path} with ${what}: ${r.body}`);
        const said = JSON.parse(r.body);
        assert.ok(said.error, `${method} ${path} with ${what} says why`);
        assert.equal(said.session, undefined, `${method} ${path} with ${what}: no session`);
        assert.equal(said.proof, undefined, `${method} ${path} with ${what}: no proof`);
      }
    }
    assert.equal((await status(port)).feed.conversations, 0, 'no conversation is kept');
    // The feed's own reader, as the uploader asks: Host 127.0.0.1:<port>, no Origin.
    const reader = feedReader({ address: `http://127.0.0.1:${port}`, token: readFileSync(join(w.folder, 'feed-token'), 'utf8').trim() });
    const books = await reader.get('/books');
    assert.equal(books.code, 200);
    assert.equal(books.proved, true);
    assert.equal((await reader.post('/hand-over', { kind: 'nothing' })).proved, true);
  } finally {
    await service.close();
  }
});

test('a call whose request came before the port closed (close(), or POST /stop) is still answered, and recorded', async () => {
  for (const how of ['close()', 'POST /stop']) {
    const w = await world([]);
    const service = await startService({ folder: w.folder, port: 0, ...LOCAL });
    const port = service.port;
    const lines = () => readFileSync(join(w.folder, 'book.jsonl'), 'utf8').split('\n').filter(Boolean).length;
    const before = lines();
    const sock = connect(port, '127.0.0.1');
    let out = '';
    sock.on('data', (d) => (out += d));
    sock.on('error', () => {});
    const ended = new Promise((r) => sock.on('close', r));
    try {
      await within(new Promise((r) => sock.on('connect', r)), 5000, 'connected');
      // All of the request's head but its end, before the port closes.
      sock.write(`POST /record HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Type: application/json\r\n`);
      await new Promise((r) => setTimeout(r, 100));
      const closing = how === 'close()' ? service.close() : null;
      if (!closing) assert.equal((await ask(port, 'POST', '/stop', '{}', own(port))).code, 200);
      await new Promise((r) => setTimeout(r, 300));
      const body = JSON.stringify({ action: 'provared.code.run', details: [{ name: 'Bash', sha256: 'A'.repeat(43) }] });
      sock.write(`Content-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
      await within(ended, 5000, `the answer after ${how}`);
      assert.match(out, /^HTTP\/1\.1 200 /, `after ${how}: ${out}`);
      assert.equal(lines(), before + 1, `after ${how}: the call is in the book`);
      if (closing) await within(closing, 5000, 'the port closed');
    } finally {
      sock.destroy();
      await service.close().catch(() => {});
    }
  }
});

test('on port 80, the recorder takes the Host its own clients send there: 127.0.0.1, with the port left out', async (t) => {
  // Port 80 may be in use, or not open to this user: then there is nothing to try here.
  const free = await within(new Promise((resolve) => {
    const probe = createNetServer();
    probe.once('error', (e) => resolve(e.code ?? e.message));
    probe.listen(80, '127.0.0.1', () => probe.close(() => resolve(true)));
  }), 5000, 'port 80 tried');
  if (free !== true) return t.skip(`port 80 cannot be taken on this computer (${free})`);
  const w = await world([]);
  const service = await startService({ folder: w.folder, port: 80, ...LOCAL });
  try {
    const r = await fetch('http://127.0.0.1/status', { signal: AbortSignal.timeout(10000) });
    assert.equal(r.status, 200, 'a program\'s fetch, which sends Host: 127.0.0.1');
    for (const host of ['127.0.0.1', '127.0.0.1:80']) assert.equal((await ask(80, 'GET', '/status', undefined, { Host: host })).code, 200, host);
    for (const host of ['localhost', 'rebound.some-website.example', '127.0.0.1:8080']) assert.equal((await ask(80, 'GET', '/status', undefined, { Host: host })).code, 403, host);
    const pre = await runHook(80, 'PreToolUse', 'Read', { file_path: 'README.md' });
    assert.equal(pre.code, 0);
    assert.equal(pre.out, '', 'the hook is answered: allowed');
    const reader = feedReader({ address: 'http://127.0.0.1', token: readFileSync(join(w.folder, 'feed-token'), 'utf8').trim() });
    assert.equal((await reader.get('/books')).code, 200, 'the feed\'s reader is answered');
  } finally {
    await service.close();
  }
});

test('"ensure" says so where the recorder that answers is not this version, with how to restart it, and stops nothing', async () => {
  const w = await world([]);
  for (const [given, words] of [[undefined, /The recorder that is running is an earlier version, which does not give its version/], ['0.1.0', /The recorder that is running is version 0\.1\.0/]]) {
    const asked = [];
    const earlier = createServer((req, res) => {
      asked.push(`${req.method} ${req.url}`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ slip: 'earlier', entries: 1, ...(given ? { version: given } : {}) }));
    });
    await new Promise((r) => earlier.listen(0, '127.0.0.1', r));
    try {
      const r = await runCommand(['ensure'], { folder: w.folder, port: earlier.address().port });
      assert.equal(r.code, 0, r.err);
      assert.match(r.err, words);
      assert.ok(r.err.includes(`not ${VERSION}, the one installed here`), r.err);
      assert.match(r.err, /keeps the code it started with until it is restarted/);
      assert.match(r.err, / stop; .* ensure/);
      assert.deepEqual(asked, ['GET /status'], 'asked its status, and not told to stop');
    } finally {
      earlier.closeAllConnections();
      await new Promise((r) => earlier.close(r));
    }
  }
  // This version answering: its status gives the version, and "ensure" says nothing.
  const service = await startService({ folder: w.folder, port: 0, ...LOCAL });
  try {
    assert.equal(VERSION, JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version);
    assert.equal((await status(service.port)).version, VERSION);
    const r = await runCommand(['ensure'], { folder: w.folder, port: service.port });
    assert.equal(r.code, 0, r.err);
    assert.equal(`${r.out}${r.err}`.trim(), '', 'nothing to say');
  } finally {
    await service.close();
  }
});
