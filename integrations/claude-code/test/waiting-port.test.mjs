// The port's one owner (port.mjs): the waiting recorder (waiting.mjs)
// answers behind the same checks as the full recorder (0.1.1's, in
// test/local-port.test.mjs). A request that names an Origin, says through
// Sec-Fetch-Site that it comes from a page, or names any Host but
// 127.0.0.1:<port>, is refused, and a POST whose body is not
// application/json is refused too, before anything is read or written.
// Every test works in a temporary folder and on a port of its own.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { request } from 'node:http';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { test } from 'node:test';

const { thumbprint } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { VERSION } = await import('../recorder.mjs');
const { feedReader } = await import('../feed.mjs');
const { startWaiting } = await import('../waiting.mjs');
const { freshWorld, runHook, signSlip, status } = await import('./world.mjs');

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
// The same table as test/local-port.test.mjs: each differs from the recorder's own clients' request in one thing only.
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

test('the waiting recorder refuses a web page\'s request to any route, /admit, /renew and /stop among them, and the folder is unchanged', async () => {
  const w = await freshWorld();
  const waiting = await startWaiting({ folder: w.folder, port: 0 });
  try {
    const port = waiting.port;
    const stranger = await developmentPasskey();
    const T = await thumbprint(stranger.key);
    const theirs = await signSlip({ agentKeys: w.agent.keys, passkey: stranger, purpose: 'A stranger\'s permission.' });
    const routes = {
      '/admit': { fingerprint: 'F'.repeat(43), thumbprint: T, take: true },
      '/renew': { slip: theirs, newPasskey: true },
      '/before': { action: 'provared.code.run', toolUseId: 'toolu_page' },
      '/record': { action: 'provared.code.run', toolUseId: 'toolu_page', details: [{ name: 'Bash', sha256: 'A'.repeat(43) }] },
      '/seal': {},
      '/new-book': {},
      '/stop': {},
    };
    const before = snapshot(w.folder);
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
    // Still waiting, and every file as it was.
    assert.equal((await status(port)).waiting, true, 'still running, and waiting');
    assert.deepEqual(snapshot(w.folder), before, 'no file is written');
  } finally {
    await waiting.close();
  }
});

test('the waiting recorder refuses a web page\'s POST before its body is read: answered at once, with a body declared and never sent', async () => {
  const w = await freshWorld();
  const waiting = await startWaiting({ folder: w.folder, port: 0 });
  try {
    const port = waiting.port;
    const before = snapshot(w.folder);
    const asked = [];
    for (const path of ['/admit', '/renew', '/before', '/record', '/seal', '/new-book', '/stop', '/hand-over']) {
      for (const [what, [headers, code]] of Object.entries(strangers(port))) {
        if (path === '/hand-over' && code === 415) continue;
        asked.push(headOnly(port, 'POST', path, headers).then((r) => [path, what, code, r]));
      }
    }
    for (const [path, what, code, r] of await Promise.all(asked)) {
      assert.ok(r, `POST ${path} with ${what}: answered before its body is sent`);
      assert.equal(r.code, code, `POST ${path} with ${what}: ${r.body}`);
    }
    assert.equal((await status(port)).waiting, true);
    assert.deepEqual(snapshot(w.folder), before, 'no file is written');
  } finally {
    await waiting.close();
  }
});

test('the waiting recorder\'s feed refuses a web page\'s request too, and gives it no session; the feed\'s own reader is answered, and lists no book', async () => {
  const w = await freshWorld();
  const waiting = await startWaiting({ folder: w.folder, port: 0 });
  try {
    const port = waiting.port;
    const random = () => randomBytes(32).toString('base64url');
    const feedHeaders = { 'Provared-Feed-Hello': random(), 'Provared-Feed-Session': random(), 'Provared-Feed-Nonce': random(), 'Provared-Feed-Proof': random() };
    for (const [method, path] of [['GET', '/hello'], ['GET', '/books'], ['GET', '/lines?from=0&wait=0'], ['POST', '/hand-over']]) {
      for (const [what, [headers, code]] of Object.entries(strangers(port))) {
        if (code === 415) continue;
        const r = await ask(port, method, path, method === 'POST' ? '{}' : undefined, { ...headers, ...feedHeaders });
        assert.equal(r.code, 403, `${method} ${path} with ${what}: ${r.body}`);
        const said = JSON.parse(r.body);
        assert.equal(said.session, undefined, `${method} ${path} with ${what}: no session`);
        assert.equal(said.proof, undefined, `${method} ${path} with ${what}: no proof`);
      }
    }
    assert.equal((await status(port)).feed.conversations, 0, 'no conversation is kept');
    // The token file is made at this start, so the uploader's one line works.
    const reader = feedReader({ address: `http://127.0.0.1:${port}`, token: readFileSync(join(w.folder, 'feed-token'), 'utf8').trim() });
    const books = await reader.get('/books');
    assert.equal(books.code, 200);
    assert.equal(books.proved, true);
    assert.deepEqual(books.body.books, [], 'the waiting recorder holds no book');
  } finally {
    await waiting.close();
  }
});

test('the waiting recorder\'s own clients are answered: its status, the hook (refused), and POST /stop, which lets go of the port', async () => {
  const w = await freshWorld();
  const waiting = await startWaiting({ folder: w.folder, port: 0 });
  const port = waiting.port;
  try {
    const shown = await status(port);
    assert.equal(shown.waiting, true);
    assert.equal(shown.version, VERSION);
    assert.match(shown.agentKeySet, /^[A-Za-z0-9_-]{43}$/);
    assert.match(shown.sealer, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(shown.waitingPermissions, 0);
    assert.equal(shown.folder, w.folder);
    assert.equal(shown.slip, undefined, 'no permission is named');
    const pre = await runHook(port, 'PreToolUse', 'Bash', { command: 'npm test' });
    assert.equal(pre.decision.permissionDecision, 'deny');
    assert.match(pre.decision.permissionDecisionReason, /no-permission-yet/);
    for (const path of ['/record', '/seal', '/renew', '/new-book']) {
      const r = await ask(port, 'POST', path, '{}', own(port));
      assert.equal(r.code, 409, path);
      assert.equal(JSON.parse(r.body).code, 'no-permission-yet', path);
    }
    assert.equal((await ask(port, 'POST', '/stop', '{}', own(port))).code, 200);
    let gone = false;
    for (const until = performance.now() + 5000; !gone && performance.now() < until;) {
      gone = await fetch(`http://127.0.0.1:${port}/status`, { signal: AbortSignal.timeout(1000) }).then(() => false, () => true);
      if (!gone) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(gone, 'the waiting recorder stopped');
  } finally {
    await waiting.close();
  }
});
