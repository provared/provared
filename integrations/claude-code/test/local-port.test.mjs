// The recorder's own routes on its local port (all but the feed's, which
// prove each request with the feed's token) answer a program on this
// computer, not a web page. A request that names an Origin, says through
// Sec-Fetch-Site that it comes from a page, or names any Host but
// 127.0.0.1:<port>, is refused, and a POST whose body is not
// application/json is refused too, before anything is read or written.
// Every test works in a temporary folder and on a port of its own.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { join } from 'node:path';
import { test } from 'node:test';

const { thumbprint } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { readTrusted, startService } = await import('../recorder.mjs');
const { runCommand, runHook, signSlip, status, tempFolder, world } = await import('./world.mjs');

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
  host: [{ ...own(port), Host: `rebound.some-website.example:${port}` }, 403],
  'host without the port': [{ ...own(port), Host: '127.0.0.1' }, 403],
  'host localhost': [{ ...own(port), Host: `localhost:${port}` }, 403],
  'text/plain': [{ ...own(port), 'Content-Type': 'text/plain;charset=UTF-8' }, 415],
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
    for (const [what, [headers]] of Object.entries(strangers(port))) {
      if (what === 'text/plain' || what === 'no content type') continue;
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
