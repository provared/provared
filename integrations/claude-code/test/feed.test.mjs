// The feed (feed.mjs): the book's lines for a reader on this computer,
// such as the application's uploader, on the recorder's own port, so that
// no other program opens a book file. Every test works in a temporary
// folder and on a port of its own.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFileSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { FEED_LABELS, FEED_MAX_BUSY, FEED_MAX_BYTES, FEED_MAX_LINES, FEED_MAX_SESSIONS, FEED_MAX_WAITING, createFeed, diskIndex, feedHmac, feedReader, identityOf, sameProof } = await import('../feed.mjs');
const { bookSaver, saveBook, startService } = await import('../recorder.mjs');
const { runCommand, runHook, freePort, status, stopService, tempFolder, world } = await import('./world.mjs');

const sha = (text) => createHash('sha256').update(text).digest('base64url');
const read = (folder, name) => readFileSync(join(folder, name), 'utf8');
const lines = (text) => text.split('\n').filter(Boolean);
const tokenOf = (folder) => read(folder, 'feed-token').trim();
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

/** A question to the feed, in a conversation of its own, with the folder's token unless another is given. */
async function ask(port, path, { token, folder } = {}) {
  return feedReader({ address: `http://127.0.0.1:${port}`, token: token ?? tokenOf(folder) }).get(path);
}

/** A conversation opened by hand: the session, its key, and the headers of a proved question. */
async function opened(port, token) {
  const mine = createHash('sha256').update(String(Math.random())).digest('base64url');
  const hello = await (await fetch(`http://127.0.0.1:${port}/hello`, { headers: { 'Provared-Feed-Hello': mine } })).json();
  const key = feedHmac(Buffer.from(token), FEED_LABELS.key, mine, hello.session);
  const nonce = () => createHash('sha256').update(String(Math.random())).digest('base64url');
  return {
    mine, hello, key,
    headers(path, n = nonce(), k = key) {
      return { 'Provared-Feed-Session': hello.session, 'Provared-Feed-Hello': mine, 'Provared-Feed-Nonce': n, 'Provared-Feed-Proof': feedHmac(k, FEED_LABELS.question, hello.session, n, `GET ${path}`).toString('base64url') };
    },
  };
}

/** A service on a world, with some stubs written through the hook. */
async function running(stubs = 3, more = {}) {
  const w = await world([]);
  const service = await startService({ folder: w.folder, port: 0, ...more });
  for (let i = 0; i < stubs; i++) assert.equal((await runHook(service.port, 'PostToolUse', 'Bash', { command: `npm run s${i}` })).code, 0);
  return { ...w, service, port: service.port, get: (path, o = {}) => ask(service.port, path, { folder: w.folder, ...o }) };
}

const fileIdentity = (path) => identityOf(statSync(path, { bigint: true }));

test('the token is written at the first start, readable by the owner only, and kept across starts', async () => {
  const w = await running(0);
  try {
    const token = tokenOf(w.folder);
    assert.match(token, /^[A-Za-z0-9_-]{43}$/);
    if (process.platform !== 'win32') assert.equal(statSync(join(w.folder, 'feed-token')).mode & 0o077, 0, 'no one but the owner may read it');
    assert.equal((await status(w.port)).feed.token, join(w.folder, 'feed-token'));
  } finally {
    await w.service.close();
  }
  const again = await startService({ folder: w.folder, port: 0 });
  try {
    assert.equal(tokenOf(w.folder), tokenOf(w.folder));
    assert.equal((await ask(again.port, '/books', { folder: w.folder })).code, 200, 'the same token works after a restart');
  } finally {
    await again.close();
  }
});

test('the recorder proves it knows the token before anything is asked, and the token never travels', async () => {
  const w = await running(1);
  try {
    const token = tokenOf(w.folder);
    const c = await opened(w.port, token);
    assert.equal(sameProof(c.hello.proof, feedHmac(Buffer.from(token), FEED_LABELS.recorder, c.mine, c.hello.session)), true, 'the recorder\'s proof over both numbers');
    assert.equal(sameProof(c.hello.proof, feedHmac(Buffer.from('W'.repeat(43)), FEED_LABELS.recorder, c.mine, c.hello.session)), false, 'which another token does not give');
    assert.ok(!JSON.stringify(c.hello).includes(token));
    // A reader with another token does not take the recorder's word, and asks nothing.
    await assert.rejects(() => ask(w.port, '/books', { token: 'W'.repeat(43) }), (e) => e.code === 'not-the-recorder');
    // A hello that is not a random number of 32 bytes.
    for (const given of [undefined, 'short', `${c.mine}A`]) {
      const r = await fetch(`http://127.0.0.1:${w.port}/hello`, { headers: given === undefined ? {} : { 'Provared-Feed-Hello': given } });
      assert.equal(r.status, 400);
    }
  } finally {
    await w.service.close();
  }
});

test('a question without the reader\'s proof, with a proof made with another token, for another question, or asked twice: refused, and nothing of the book is said', async () => {
  const w = await running(2);
  try {
    const token = tokenOf(w.folder);
    const c = await opened(w.port, token);
    const get = (path, headers) => fetch(`http://127.0.0.1:${w.port}${path}`, { headers });
    const wrongKey = feedHmac(Buffer.from('W'.repeat(43)), FEED_LABELS.key, c.mine, c.hello.session);
    for (const path of ['/books', '/lines?from=0&wait=0']) {
      const tries = [
        ['no headers', {}],
        ['no proof', { ...c.headers(path), 'Provared-Feed-Proof': '' }],
        ['another token', c.headers(path, undefined, wrongKey)],
        ['the proof of another question', { ...c.headers(path), 'Provared-Feed-Proof': c.headers('/lines?from=1&wait=0')['Provared-Feed-Proof'] }],
        ['a session the feed never opened', { ...c.headers(path), 'Provared-Feed-Session': 'S'.repeat(43) }],
        ['a proof a character short', (() => { const h = c.headers(path); return { ...h, 'Provared-Feed-Proof': h['Provared-Feed-Proof'].slice(0, -1) }; })()],
      ];
      for (const [what, headers] of tries) {
        const r = await get(path, headers);
        assert.equal(r.status, 401, `${what} on ${path}`);
        const body = await r.json();
        assert.ok(!('lines' in body) && !('books' in body), what);
      }
    }
    // A proved question is answered, once.
    const headers = c.headers('/books');
    assert.equal((await get('/books', headers)).status, 200);
    assert.equal((await get('/books', headers)).status, 401, 'the same question again');
    // The feed answers GET only.
    assert.equal((await fetch(`http://127.0.0.1:${w.port}/lines`, { method: 'POST', body: '{}' })).status, 405);
  } finally {
    await w.service.close();
  }
});

test('each answer carries the recorder\'s proof over the question\'s number, its code and every byte; another conversation\'s key does not check it', async () => {
  const w = await running(1);
  try {
    const token = tokenOf(w.folder);
    const c = await opened(w.port, token);
    const nonce = createHash('sha256').update('one').digest('base64url');
    const r = await fetch(`http://127.0.0.1:${w.port}/books`, { headers: c.headers('/books', nonce) });
    const bytes = Buffer.from(await r.arrayBuffer());
    const proof = r.headers.get('provared-feed-proof');
    assert.equal(sameProof(proof, feedHmac(c.key, FEED_LABELS.answer, c.hello.session, nonce, '200', bytes)), true);
    assert.equal(sameProof(proof, feedHmac(c.key, FEED_LABELS.answer, c.hello.session, nonce, '200', Buffer.concat([bytes, Buffer.from(' ')]))), false, 'a byte more');
    assert.equal(sameProof(proof, feedHmac(c.key, FEED_LABELS.answer, c.hello.session, nonce.replace(/^./, 'x'), '200', bytes)), false, 'another question');
    const other = await opened(w.port, token);
    assert.equal(sameProof(proof, feedHmac(other.key, FEED_LABELS.answer, c.hello.session, nonce, '200', bytes)), false, 'another conversation');
    // The reader checks it.
    assert.equal((await ask(w.port, '/books', { folder: w.folder })).proved, true);
  } finally {
    await w.service.close();
  }
});

test('at most 16 proved conversations: the one used longest ago gives way, and its reader opens another', async () => {
  const w = await running(1);
  try {
    const token = tokenOf(w.folder);
    const get = (c, path) => fetch(`http://127.0.0.1:${w.port}${path}`, { headers: c.headers(path) });
    const first = await opened(w.port, token);
    assert.equal((await get(first, '/books')).status, 200);
    // A hello keeps nothing: only a conversation that has carried a proved question is kept.
    assert.equal((await status(w.port)).feed.conversations, 1);
    const second = await opened(w.port, token);
    assert.equal((await get(second, '/books')).status, 200);
    for (let i = 0; i < FEED_MAX_SESSIONS - 2; i++) assert.equal((await get(await opened(w.port, token), '/books')).status, 200);
    assert.equal((await status(w.port)).feed.conversations, FEED_MAX_SESSIONS);
    // The first is used again; then a 17th is proved, and the one used longest ago (the second) gives way.
    assert.equal((await get(first, '/books')).status, 200);
    assert.equal((await get(await opened(w.port, token), '/books')).status, 200);
    assert.equal((await status(w.port)).feed.conversations, FEED_MAX_SESSIONS);
    assert.equal((await get(first, '/books')).status, 200, 'the one in use goes on');
    const r = await get(second, '/books');
    assert.equal(r.status, 401);
    assert.equal((await r.json()).renew, true, 'the one used longest ago gave way, and cannot be begun again');
    const reader = feedReader({ address: `http://127.0.0.1:${w.port}`, token });
    assert.equal((await reader.get('/books')).proved, true);
  } finally {
    await w.service.close();
  }
});

test('after a restart, no conversation of the recorder before is taken: its reader opens another', async () => {
  const w = await running(1);
  let c;
  try {
    c = await opened(w.port, tokenOf(w.folder));
    assert.equal((await fetch(`http://127.0.0.1:${w.port}/books`, { headers: c.headers('/books') })).status, 200);
  } finally {
    await w.service.close();
  }
  const again = await startService({ folder: w.folder, port: 0 });
  try {
    // A conversation begun with the recorder before, not yet proved there, nor kept: refused all the same.
    const unproved = await opened(again.port, tokenOf(w.folder));
    const before = await opened(w.port, tokenOf(w.folder)).catch(() => null);
    assert.equal(before, null, 'the recorder before is gone');
    for (const [what, s] of [['kept before', c], ['opened again here', unproved]]) {
      const headers = { ...s.headers('/books'), 'Provared-Feed-Session': s === c ? c.hello.session : unproved.hello.session };
      const r = await fetch(`http://127.0.0.1:${again.port}/books`, { headers });
      assert.equal(r.status, s === c ? 401 : 200, what);
    }
  } finally {
    await again.close();
  }
});

test('a program without the token, opening conversations without end, keeps nothing and pushes out no conversation in use', async () => {
  const w = await running(1);
  try {
    const token = tokenOf(w.folder);
    const mine = await opened(w.port, token);
    const get = (path) => fetch(`http://127.0.0.1:${w.port}${path}`, { headers: mine.headers(path) });
    assert.equal((await get('/books')).status, 200);
    // 2,000 hellos from a program that does not hold the token, many at once.
    await Promise.all(Array.from({ length: 20 }, async () => {
      for (let i = 0; i < 100; i++) await (await fetch(`http://127.0.0.1:${w.port}/hello`, { headers: { 'Provared-Feed-Hello': createHash('sha256').update(`${Math.random()}`).digest('base64url') } })).arrayBuffer();
    }));
    assert.equal((await status(w.port)).feed.conversations, 1, 'none of them kept');
    assert.equal((await get('/books')).status, 200, 'the conversation in use goes on, with no new hello');
    // A question with a made-up proof, in conversations it opened, keeps nothing either.
    for (let i = 0; i < 50; i++) {
      const c = await opened(w.port, 'W'.repeat(43));
      assert.equal((await fetch(`http://127.0.0.1:${w.port}/books`, { headers: c.headers('/books') })).status, 401);
    }
    assert.equal((await status(w.port)).feed.conversations, 1);
    assert.equal((await get('/books')).status, 200);
  } finally {
    await w.service.close();
  }
});

test('a conversation must begin within 10 minutes of its hello, ends after 10 minutes unused, and ends at its last question; an ended one cannot be begun again', async () => {
  let clock = Date.now();
  const f = await unitFeed({ memory: (folder) => [{ key: 1, path: join(folder, 'book.jsonl'), text: () => '{"slip":1}\n', inForce: true }], now: () => clock, sessionQuestions: 3 });
  try {
    const ask = (c, path = '/books') => fetch(`${f.address}${path}`, { headers: c.headers(path) });
    const renewed = async (r) => r.status === 401 && (await r.json()).renew === true;
    // Late: a hello 11 minutes before its first question.
    const late = await opened(f.port, f.token);
    clock += 11 * 60 * 1000;
    assert.equal(await renewed(await ask(late)), true, 'too long after its hello');
    // Idle: proved, then unused for 11 minutes.
    const idle = await opened(f.port, f.token);
    assert.equal((await ask(idle)).status, 200);
    clock += 11 * 60 * 1000;
    assert.equal(await renewed(await ask(idle)), true, 'ended after 10 minutes unused');
    // Its questions run out: three, then it ends.
    const short = await opened(f.port, f.token);
    for (let i = 0; i < 3; i++) assert.equal((await ask(short)).status, 200);
    assert.equal(await renewed(await ask(short)), true, 'ended at its last question');
    assert.equal(await renewed(await ask(short)), true, 'and not begun again from its hello');
  } finally {
    await f.close();
  }
});

// Another way of writing the same 32 bytes: the last base64url character carries two bits no byte uses.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const respelled = (s) => s.slice(0, -1) + ALPHABET[(ALPHABET.indexOf(s.at(-1)) & ~3) | ((ALPHABET.indexOf(s.at(-1)) + 1) & 3)];

test('a session, a reader\'s number, a number used once or a proof written another way for the same bytes is refused: an ended conversation cannot be begun again under another spelling', async () => {
  const f = await unitFeed({ memory: (folder) => [{ key: 1, path: join(folder, 'book.jsonl'), text: () => '{"slip":1}\n', inForce: true }], sessionQuestions: 3 });
  try {
    const ask = (headers, path = '/books') => fetch(`${f.address}${path}`, { headers });
    const c = await opened(f.port, f.token);
    assert.notEqual(respelled(c.hello.session), c.hello.session);
    assert.ok(Buffer.from(respelled(c.hello.session), 'base64url').equals(Buffer.from(c.hello.session, 'base64url')), 'the same bytes');
    for (let i = 0; i < 3; i++) assert.equal((await ask(c.headers('/books'))).status, 200);
    assert.equal((await ask(c.headers('/books'))).status, 401, 'its questions are used up: ended');
    // With the token, the ended conversation under another spelling of its number, with a key made for that spelling.
    const other = respelled(c.hello.session);
    const key = feedHmac(Buffer.from(f.token), FEED_LABELS.key, c.mine, other);
    const n = createHash('sha256').update('n').digest('base64url');
    const headers = { 'Provared-Feed-Session': other, 'Provared-Feed-Hello': c.mine, 'Provared-Feed-Nonce': n, 'Provared-Feed-Proof': feedHmac(key, FEED_LABELS.question, other, n, 'GET /books').toString('base64url') };
    const r = await ask(headers);
    assert.equal(r.status, 401, 'not begun again');
    // A question of a conversation in use, with its number used once, or its proof, written another way.
    const d = await opened(f.port, f.token);
    const seen = d.headers('/books');
    assert.equal((await ask(seen)).status, 200);
    assert.equal((await ask({ ...seen, 'Provared-Feed-Nonce': respelled(seen['Provared-Feed-Nonce']) })).status, 401, 'the number used once, written another way');
    assert.equal((await ask({ ...d.headers('/books'), 'Provared-Feed-Proof': respelled(d.headers('/books')['Provared-Feed-Proof']) })).status, 401, 'a proof written another way');
    // A hello whose number is written another way.
    const mine = createHash('sha256').update('m').digest('base64url');
    const h = await fetch(`${f.address}/hello`, { headers: { 'Provared-Feed-Hello': respelled(mine) } });
    assert.equal(h.status, mine === respelled(mine) ? 200 : 400);
  } finally {
    await f.close();
  }
});

test('a hello dated ahead of the clock (the clock set back) is not taken', async () => {
  let clock = Date.now();
  const f = await unitFeed({ memory: (folder) => [{ key: 1, path: join(folder, 'book.jsonl'), text: () => '{"slip":1}\n', inForce: true }], now: () => clock });
  try {
    const c = await opened(f.port, f.token);
    clock -= 60 * 60 * 1000;
    const r = await fetch(`${f.address}/books`, { headers: c.headers('/books') });
    assert.equal(r.status, 401);
    assert.equal((await r.json()).renew, true);
    const fresh = await opened(f.port, f.token);
    assert.equal((await fetch(`${f.address}/books`, { headers: fresh.headers('/books') })).status, 200, 'a hello made after the clock went back is taken');
  } finally {
    await f.close();
  }
});

test('a question that has waited is answered in its turn, never told to ask again, however busy the feed is', async () => {
  const folder = tempFolder();
  // A kept book on disk, large enough that finding its lines takes several pieces, and holds the feed's one answer meanwhile.
  writeFileSync(join(folder, 'book-1.jsonl'), Array.from({ length: 12000 }, (_, i) => `{"a":"${String(i).padEnd(3000, 'x')}"}\n`).join(''));
  let text = '{"slip":1}\n';
  const f = await unitFeed({ folder, memory: (dir) => [{ key: 1, path: join(dir, 'book.jsonl'), text: () => text, inForce: true }], maxBusy: 1 });
  try {
    const waiting = f.get('/lines?from=1&wait=20');
    while (f.feed.status().waiting === 0) await pause(5);
    const slow = f.get('/lines?book=book-1.jsonl&wait=0');
    while (f.feed.status().busy === 0) await new Promise((r) => setImmediate(r));
    // While the one answer allowed is being made, the waiting question is woken.
    text += '{"a":1}\n';
    f.feed.changed();
    const woken = await waiting;
    assert.equal(woken.code, 200, `told ${woken.code}`);
    assert.deepEqual(woken.body.lines, ['{"a":1}']);
    assert.equal((await slow).code, 200);
  } finally {
    await f.close();
  }
});

test('the service listens on 127.0.0.1 only', async () => {
  const w = await running(0);
  try {
    const port = w.port;
    const { createConnection } = await import('node:net');
    // Another address of this computer, where there is one, is not answered.
    const { networkInterfaces } = await import('node:os');
    const other = Object.values(networkInterfaces()).flat().find((a) => a && a.family === 'IPv4' && !a.internal);
    if (other) {
      const refused = await new Promise((resolve) => {
        const s = createConnection({ host: other.address, port });
        s.once('connect', () => { s.destroy(); resolve(false); });
        s.once('error', () => resolve(true));
      });
      assert.equal(refused, true, `nothing answers on ${other.address}`);
    }
    const s6 = await new Promise((resolve) => {
      const s = createConnection({ host: '::1', port });
      s.once('connect', () => { s.destroy(); resolve(false); });
      s.once('error', () => resolve(true));
    });
    assert.equal(s6, true, 'nothing answers on ::1');
  } finally {
    await w.service.close();
  }
});

test('the lines of the book in force from a place on, with where each is, the line before, the size and the last line', async () => {
  const w = await running(4);
  try {
    const book = read(w.folder, 'book.jsonl');
    const all = lines(book);
    const r = await w.get('/lines?from=2&wait=0');
    assert.equal(r.code, 200);
    assert.deepEqual(r.body.lines, all.slice(2));
    assert.equal(r.body.size, all.length);
    assert.equal(r.body.from, 2);
    assert.equal(r.body.inForce, true);
    assert.equal(r.body.book, 'book.jsonl');
    assert.equal(r.body.id, fileIdentity(join(w.folder, 'book.jsonl')), 'the identity is the file\'s, as the uploader reckons it');
    assert.equal(r.body.last, sha(all.at(-1)));
    assert.equal(r.body.bytes, Buffer.byteLength(book));
    // Where each line is in the file, in bytes.
    const bytes = Buffer.from(book);
    r.body.lines.forEach((line, i) => {
      assert.equal(bytes.subarray(r.body.starts[i], r.body.ends[i]).toString(), `${line}\n`);
    });
    assert.deepEqual(r.body.previous, { fingerprint: sha(all[1]), start: r.body.starts[0] - Buffer.byteLength(all[1]) - 1, end: r.body.starts[0] });
    // From 0, no line before; past the end, nothing, at once.
    assert.equal((await w.get('/lines?from=0&wait=0')).body.previous, null);
    const past = await w.get(`/lines?from=${all.length + 3}`);
    assert.deepEqual(past.body.lines, []);
    assert.equal(past.body.size, all.length);
    // At most "max" lines; with 0, only the line before, the size and the last, and no waiting.
    assert.deepEqual((await w.get('/lines?from=2&max=1&wait=0')).body.lines, all.slice(2, 3));
    const none = await w.get(`/lines?from=${all.length}&max=0`);
    assert.deepEqual(none.body.lines, []);
    assert.equal(none.body.previous.fingerprint, sha(all.at(-1)));
    // The same by identity and by name.
    assert.deepEqual((await w.get(`/lines?id=${encodeURIComponent(r.body.id)}&from=2&wait=0`)).body.lines, all.slice(2));
    assert.deepEqual((await w.get('/lines?book=book.jsonl&from=2&wait=0')).body.lines, all.slice(2));
    // The listing.
    const books = (await w.get('/books')).body.books;
    assert.deepEqual(books, [{ book: 'book.jsonl', number: null, id: r.body.id, inForce: true, bytes: Buffer.byteLength(book) }]);
  } finally {
    await w.service.close();
  }
});

test('what the feed is asked is read strictly', async () => {
  const w = await running(1);
  try {
    for (const path of ['/lines?from=-1', '/lines?from=01', '/lines?from=1.5', '/lines?from=2147483648', '/lines?wait=26', '/lines?wait=x', '/lines?max=501', '/lines?max=-1', '/lines?from=0&from=1', '/lines?other=1', '/lines?book=../x.jsonl', '/lines?book=book-0.jsonl', '/lines?id=a&book=book.jsonl']) {
      assert.equal((await w.get(path)).code, 400, path);
    }
    assert.equal((await w.get('/lines?id=no-such&wait=0')).code, 404);
    assert.equal((await w.get('/lines?book=book-7.jsonl&wait=0')).code, 404);
  } finally {
    await w.service.close();
  }
});

test('at most 500 lines in one answer', async () => {
  const w = await world([]);
  // A book of 520 lines: the slip and 519 stubs written by the recorder itself.
  const service = await startService({ folder: w.folder, port: 0 });
  try {
    for (let i = 0; i < 519; i++) await fetch(`http://127.0.0.1:${service.port}/record`, { method: 'POST', body: JSON.stringify({ action: 'provared.code.read', details: [{ name: 'Read', sha256: sha(String(i)) }] }) });
    const r = await ask(service.port, '/lines?from=0&wait=0', { folder: w.folder });
    assert.equal(r.body.lines.length, FEED_MAX_LINES);
    assert.equal(r.body.size, 520);
    const rest = await ask(service.port, `/lines?from=${FEED_MAX_LINES}&wait=0`, { folder: w.folder });
    assert.equal(rest.body.lines.length, 20);
    assert.deepEqual([...r.body.lines, ...rest.body.lines], lines(read(w.folder, 'book.jsonl')));
  } finally {
    await service.close();
  }
});

test('a reader at the end waits for the next line, and is answered as soon as it is written; with nothing new, empty when the wait ends', async () => {
  const w = await running(1);
  try {
    const size = (await w.get('/lines?wait=0')).body.size;
    const started = Date.now();
    const waiting = w.get(`/lines?from=${size}&wait=20`);
    await pause(300);
    assert.equal((await status(w.port)).feed.waiting, 1);
    await runHook(w.port, 'PostToolUse', 'Bash', { command: 'npm test' });
    const r = await waiting;
    assert.equal(r.body.lines.length, 1);
    assert.ok(Date.now() - started < 15000, 'answered when the line was written, not when the wait ended');
    assert.equal(r.body.lines[0], lines(read(w.folder, 'book.jsonl')).at(-1));
    const empty = await w.get(`/lines?from=${size + 1}&wait=1`);
    assert.deepEqual(empty.body.lines, []);
    assert.equal((await status(w.port)).feed.waiting, 0);
  } finally {
    await w.service.close();
  }
});

test('at most 8 readers wait at once; one more is told to ask again, at once', async () => {
  const w = await running(1);
  try {
    const size = (await w.get('/lines?wait=0')).body.size;
    const waiting = Array.from({ length: FEED_MAX_WAITING }, () => w.get(`/lines?from=${size}&wait=20`));
    await pause(300);
    assert.equal((await status(w.port)).feed.waiting, FEED_MAX_WAITING);
    const started = Date.now();
    const one = await w.get(`/lines?from=${size}&wait=20`);
    assert.equal(one.code, 429);
    assert.ok(Date.now() - started < 5000);
    // A request that does not wait is still answered.
    assert.equal((await w.get(`/lines?from=${size}&wait=0`)).code, 200);
    await runHook(w.port, 'PostToolUse', 'Bash', { command: 'npm test' });
    for (const r of await Promise.all(waiting)) assert.equal(r.body.lines.length, 1);
    assert.equal((await w.get(`/lines?from=${size + 1}&wait=1`)).code, 200, 'once they have been answered, a reader may wait again');
  } finally {
    await w.service.close();
  }
});

test('a reader that goes away while waiting no longer counts', async () => {
  const w = await running(1);
  try {
    const size = (await w.get('/lines?wait=0')).body.size;
    const gone = new AbortController();
    const c = await opened(w.port, tokenOf(w.folder));
    const path = `/lines?from=${size}&wait=20`;
    const asked = fetch(`http://127.0.0.1:${w.port}${path}`, { headers: c.headers(path), signal: gone.signal }).catch(() => null);
    await pause(300);
    assert.equal((await status(w.port)).feed.waiting, 1);
    gone.abort();
    await asked;
    await pause(300);
    assert.equal((await status(w.port)).feed.waiting, 0);
  } finally {
    await w.service.close();
  }
});

test('stopping the service answers every waiting reader at once', async () => {
  const w = await running(1);
  const size = (await w.get('/lines?wait=0')).body.size;
  const waiting = w.get(`/lines?from=${size}&wait=25`);
  await pause(300);
  const started = Date.now();
  await w.service.close();
  const r = await waiting;
  assert.deepEqual(r.body.lines, []);
  assert.ok(Date.now() - started < 5000, 'the close did not wait for the 25 seconds');
});

test('a new book: the book kept keeps its identity, and a reader by identity goes on in it; the new book is listed after it', async () => {
  const w = await running(2);
  try {
    const first = await w.get('/lines?wait=0');
    const id = first.body.id;
    const size = first.body.size;
    // A reader waiting at the end of the book in force is answered by the switch.
    const waiting = w.get(`/lines?id=${encodeURIComponent(id)}&from=${size}&wait=20`);
    await pause(200);
    await w.service.newBook();
    // Woken by the seal, written into book.jsonl before it is kept.
    const woken = await waiting;
    assert.equal(woken.body.lines.length, 1, 'the seal');
    assert.ok(woken.body.lines[0].startsWith('{"seal":'));
    const r = await w.get(`/lines?id=${encodeURIComponent(id)}&from=${size}&wait=0`);
    assert.equal(r.body.book, 'book-1.jsonl');
    assert.equal(r.body.inForce, false);
    assert.equal(r.body.id, id, 'the same book, under its kept name');
    assert.deepEqual(r.body.lines, woken.body.lines);
    assert.equal(fileIdentity(join(w.folder, 'book-1.jsonl')), id);
    const books = (await w.get('/books')).body.books;
    assert.deepEqual(books.map((b) => [b.book, b.number, b.inForce]), [['book-1.jsonl', 1, false], ['book.jsonl', null, true]]);
    assert.notEqual(books[1].id, id, 'the new book is a new file');
    assert.deepEqual((await w.get('/lines?wait=0')).body.lines, lines(read(w.folder, 'book.jsonl')));
  } finally {
    await w.service.close();
  }
});

test('a late stub and the seal again of a kept book reach a reader waiting on it', async () => {
  const w = await running(1);
  try {
    // A call allowed under the book before the switch, and recorded after it.
    assert.equal((await runHook(w.port, 'PreToolUse', 'Bash', { command: 'long' }, { more: { tool_use_id: 'long' } })).out, '');
    const id = (await w.get('/lines?wait=0')).body.id;
    await w.service.newBook();
    const kept = await w.get(`/lines?id=${encodeURIComponent(id)}&wait=0`);
    const waiting = w.get(`/lines?id=${encodeURIComponent(id)}&from=${kept.body.size}&wait=20`);
    await pause(200);
    assert.equal((await runHook(w.port, 'PostToolUse', 'Bash', { command: 'long' }, { more: { tool_use_id: 'long' } })).code, 0);
    const r = await waiting;
    assert.ok(r.body.lines.length >= 1);
    const all = await w.get(`/lines?id=${encodeURIComponent(id)}&wait=0`);
    assert.deepEqual(all.body.lines, lines(read(w.folder, 'book-1.jsonl')));
    assert.deepEqual(all.body.lines.slice(-2).map((l) => Object.keys(JSON.parse(l))[0]), ['stub', 'seal'], 'the late stub, then the seal again');
  } finally {
    await w.service.close();
  }
});

test('a kept book sealed again when the recorder starts reaches a reader; a kept book no longer held is read from its file', async () => {
  const w = await running(1);
  let id;
  try {
    id = (await w.get('/lines?wait=0')).body.id;
    await w.service.newBook();
  } finally {
    await w.service.close();
  }
  // The kept book as a stop leaves it after a late stub and before the seal again: it does not end with a seal.
  const keptPath = join(w.folder, 'book-1.jsonl');
  const before = lines(read(w.folder, 'book-1.jsonl')).slice(0, -1);
  writeFileSync(keptPath, before.map((l) => `${l}\n`).join(''));
  const again = await startService({ folder: w.folder, port: 0 });
  try {
    const r = await ask(again.port, `/lines?id=${encodeURIComponent(id)}&from=${before.length}&wait=0`, { folder: w.folder });
    assert.equal(r.code, 200);
    assert.equal(r.body.book, 'book-1.jsonl');
    assert.deepEqual(r.body.lines, lines(read(w.folder, 'book-1.jsonl')).slice(before.length));
    assert.ok(r.body.lines.at(-1).startsWith('{"seal":'), 'sealed again at the start');
  } finally {
    await again.close();
  }
});

test('a token file that holds no token is left as it is, and the feed refuses every request and says why', async () => {
  const w = await world([]);
  writeFileSync(join(w.folder, 'feed-token'), 'not a token\n');
  const service = await startService({ folder: w.folder, port: 0 });
  try {
    for (const path of ['/hello', '/books']) {
      const r = await fetch(`http://127.0.0.1:${service.port}${path}`, { headers: { 'Provared-Feed-Hello': 'H'.repeat(43) } });
      assert.equal(r.status, 503);
      assert.match((await r.json()).error, /does not hold a token/);
    }
    assert.match((await status(service.port)).feed.problem, /does not hold a token/);
    assert.equal(read(w.folder, 'feed-token'), 'not a token\n');
    // The recorder itself goes on.
    assert.equal((await runHook(service.port, 'PostToolUse', 'Bash', { command: 'npm test' })).code, 0);
  } finally {
    await service.close();
  }
});

test('a line still being written in a kept book on disk is not a line until its line break', async () => {
  const w = await running(1);
  let id;
  try {
    id = (await w.get('/lines?wait=0')).body.id;
    await w.service.newBook();
  } finally {
    await w.service.close();
  }
  const again = await startService({ folder: w.folder, port: 0 });
  try {
    const get = (path) => ask(again.port, path, { folder: w.folder });
    const kept = join(w.folder, 'book-1.jsonl');
    const size = (await get(`/lines?id=${encodeURIComponent(id)}&wait=0`)).body.size;
    appendFileSync(kept, '{"half":');
    assert.equal((await get(`/lines?id=${encodeURIComponent(id)}&wait=0`)).body.size, size);
    appendFileSync(kept, '1}\r\n\n\r\n');
    const r = await get(`/lines?id=${encodeURIComponent(id)}&from=${size}&wait=0`);
    assert.deepEqual(r.body.lines, ['{"half":1}'], 'a carriage return, an empty line and a line that is only a carriage return are set aside, as the uploader and the checker set them aside');
    const bytes = readFileSync(kept);
    assert.equal(bytes.subarray(r.body.starts[0], r.body.ends[0]).toString(), '{"half":1}\r\n');
  } finally {
    await again.close();
  }
});

test('a new book whose file is not written yet is listed with no identity, never with the identity of the book kept before it', async () => {
  const { createFeed } = await import('../feed.mjs');
  const { mkdtempSync, renameSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const folder = mkdtempSync(join(tmpdir(), 'provared-cc-feed-'));
  const token = { token: 'A'.repeat(43), problem: null, path: join(folder, 'feed-token') };
  let first = '{"slip":1}\n{"stub":1}\n';
  const second = '{"slip":1}\n';
  writeFileSync(join(folder, 'book.jsonl'), first);
  let held = [{ key: 1, path: join(folder, 'book.jsonl'), text: () => first, inForce: true }];
  const feed = createFeed({ folder, token, memory: () => held });
  const { createServer } = await import('node:http');
  const server = createServer((req, res) => feed.handle(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const books = async () => (await ask(server.address().port, '/books', { token: token.token })).body.books;
    const id = (await books())[0].id;
    assert.ok(id);
    // The switch, as the recorder makes it: the book kept under its number, and a new book in force whose file could not be written yet.
    first += '{"seal":1}\n';
    writeFileSync(join(folder, 'book.jsonl'), first);
    renameSync(join(folder, 'book.jsonl'), join(folder, 'book-1.jsonl'));
    held = [{ key: 2, path: join(folder, 'book.jsonl'), text: () => second, inForce: true }, { key: 1, path: join(folder, 'book-1.jsonl'), text: () => first, inForce: false }];
    const after = await books();
    assert.deepEqual(after.map((b) => [b.book, b.id, b.inForce]), [['book-1.jsonl', id, false], ['book.jsonl', null, true]]);
    // Asked by that identity, it is the kept book.
    const r = await ask(server.address().port, `/lines?id=${encodeURIComponent(id)}&wait=0`, { token: token.token });
    assert.equal(r.body.book, 'book-1.jsonl');
    assert.equal(r.body.size, 3);
  } finally {
    feed.close();
    await new Promise((r) => server.close(r));
  }
});

test('on Windows, the feed answers while another program holds book.jsonl open with no sharing', { skip: process.platform !== 'win32' && 'needs Windows' }, async () => {
  const w = await running(3);
  const book = join(w.folder, 'book.jsonl');
  // PowerShell opens the file with no sharing, says so, and holds it until its input ends.
  const holder = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `$f = [System.IO.File]::Open('${book.replace(/'/g, "''")}', 'Open', 'ReadWrite', 'None'); [Console]::Out.WriteLine('held'); [Console]::In.ReadLine() | Out-Null; $f.Close()`], { stdio: ['pipe', 'pipe', 'inherit'] });
  try {
    await new Promise((resolve, reject) => {
      holder.stdout.on('data', (d) => { if (String(d).includes('held')) resolve(); });
      holder.once('exit', () => reject(new Error('PowerShell did not hold the file')));
    });
    assert.throws(() => readFileSync(book), /EBUSY|EPERM|EACCES/, 'the file cannot be read by another program meanwhile');
    const r = await w.get('/lines?wait=0');
    assert.equal(r.code, 200);
    assert.equal(r.body.size, 4);
    assert.ok(r.body.id, 'the identity, from the last look at the file');
  } finally {
    holder.stdin.end('\n');
    await new Promise((r) => holder.once('exit', r));
    await w.service.close();
  }
});

test('the command "start" runs the feed on the recorder\'s own port, with the token in its folder', async () => {
  const w = await world([]);
  const port = await freePort();
  const child = runCommand(['start'], { folder: w.folder, port });
  try {
    let ok = null;
    for (let i = 0; i < 80 && !ok; i++) {
      await pause(250);
      try { ok = await status(port); } catch { /* not yet */ }
    }
    assert.ok(ok);
    assert.equal((await ask(port, '/lines?wait=0', { folder: w.folder })).body.size, 1);
  } finally {
    await stopService(port);
    await child;
  }
});

// --- after the review of 18 October 2026 ---

/** A feed on a folder with books given in memory, served on a port of its own, and a reader of it. */
async function unitFeed({ memory = () => [], folder = tempFolder('provared-cc-feed-'), ...more } = {}) {
  const token = { token: 'U'.repeat(43), problem: null, path: join(folder, 'feed-token') };
  const feed = createFeed({ folder, token, memory: () => memory(folder), ...more });
  const { createServer } = await import('node:http');
  const server = createServer((req, res) => feed.handle(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const address = `http://127.0.0.1:${port}`;
  const reader = feedReader({ address, token: token.token });
  return { folder, feed, port, address, token: token.token, get: (path) => reader.get(path), close: async () => { feed.close(); await new Promise((r) => server.close(r)); } };
}

/** Another program holding a file open with no sharing, for some seconds (Windows). */
function hold(path, seconds) {
  const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `$f = [System.IO.File]::Open('${path.replace(/'/g, "''")}', 'Open', 'Read', 'None'); [Console]::Out.WriteLine('held'); Start-Sleep -Seconds ${seconds}; $f.Close()`], { stdio: ['ignore', 'pipe', 'inherit'] });
  const done = new Promise((r) => child.once('exit', r));
  const held = new Promise((ok, no) => {
    child.stdout.on('data', (d) => { if (String(d).includes('held')) ok(); });
    child.once('exit', () => no(new Error('PowerShell did not hold the file')));
  });
  return { held, done };
}

test('a save waits while another program reads the book for a moment, and never replaces the file because it could not be read', () => {
  const folder = tempFolder();
  const path = join(folder, 'book.jsonl');
  saveBook(folder, 'one\n');
  const id = fileIdentity(path);
  let tries = 0;
  const busyAtFirst = (p, e) => {
    if (tries++ < 2) throw Object.assign(new Error('the file is busy'), { code: 'EBUSY' });
    return readFileSync(p, e);
  };
  saveBook(folder, 'one\ntwo\n', path, { read: busyAtFirst });
  assert.equal(tries, 3, 'read again while it was busy');
  assert.equal(read(folder, 'book.jsonl'), 'one\ntwo\n');
  assert.equal(fileIdentity(path), id, 'appended to, not replaced');
  // A read that fails for another reason: the save fails, and the file is left as it is.
  const failing = () => { throw Object.assign(new Error('the disk failed'), { code: 'EIO' }); };
  assert.throws(() => saveBook(folder, 'one\ntwo\nthree\n', path, { read: failing }), /the disk failed/);
  assert.equal(read(folder, 'book.jsonl'), 'one\ntwo\n');
  assert.equal(fileIdentity(path), id);
});

test('adding to the book waits while another program holds it for a moment, in a whole save and in the saver that follows the file', () => {
  const folder = tempFolder();
  const path = join(folder, 'book.jsonl');
  saveBook(folder, 'one\n');
  const id = fileIdentity(path);
  const busyTwice = () => {
    let tries = 0;
    const append = (p, t) => {
      if (tries++ < 2) throw Object.assign(new Error('the file is busy'), { code: 'EBUSY' });
      appendFileSync(p, t);
    };
    return { append, tries: () => tries };
  };
  const whole = busyTwice();
  saveBook(folder, 'one\ntwo\n', path, { append: whole.append });
  assert.equal(whole.tries(), 3, 'tried again while busy (saveBook)');
  assert.equal(read(folder, 'book.jsonl'), 'one\ntwo\n');
  const follows = busyTwice();
  const save = bookSaver(folder, { path, saved: 'one\ntwo\n', append: follows.append });
  save('one\ntwo\nthree\n');
  assert.equal(follows.tries(), 3, 'tried again while busy (bookSaver)');
  assert.equal(read(folder, 'book.jsonl'), 'one\ntwo\nthree\n');
  assert.equal(fileIdentity(path), id, 'added to, never replaced');
});

test('on Windows, a receipt written while another program holds book.jsonl for 3 seconds: written once the lock ends, and the book keeps its identity', { skip: process.platform !== 'win32' && 'needs Windows' }, async () => {
  const w = await running(2);
  try {
    const path = join(w.folder, 'book.jsonl');
    const id = fileIdentity(path);
    const lock = hold(path, 3);
    await lock.held;
    const r = await runHook(w.port, 'PostToolUse', 'Bash', { command: 'npm test' });
    await lock.done;
    assert.equal(r.code, 0, 'the receipt was written');
    assert.equal(fileIdentity(path), id, 'the same file');
    assert.equal(lines(read(w.folder, 'book.jsonl')).length, 4);
    const feed = await w.get(`/lines?id=${encodeURIComponent(id)}&wait=0`);
    assert.deepEqual(feed.body.lines, lines(read(w.folder, 'book.jsonl')));
  } finally {
    await w.service.close();
  }
});

test('on Windows, a receipt whose save failed (the file held for longer than the recorder waits) is not given out by the feed until it is in the file', { skip: process.platform !== 'win32' && 'needs Windows' }, async () => {
  const w = await running(1);
  try {
    const path = join(w.folder, 'book.jsonl');
    const lock = hold(path, 13);
    await lock.held;
    const r = await runHook(w.port, 'PostToolUse', 'Bash', { command: 'npm test' });
    assert.notEqual(r.code, 0, 'the hook was told');
    assert.match(r.err, /is not yet in the book file: the stub is signed and held by the recorder/, 'and told truly: the stub is held, and written with the next save');
    assert.doesNotMatch(r.err, /was not written/);
    const during = await w.get('/lines?wait=0');
    assert.equal(during.body.size, 2, 'the slip and the first receipt: the one not yet in the file is not given');
    assert.equal((await status(w.port)).recordedSinceStart, 2, 'the held receipt is in the book, and counted as recorded');
    await lock.done;
    assert.equal((await runHook(w.port, 'PostToolUse', 'Bash', { command: 'npm run more' })).code, 0);
    assert.equal((await status(w.port)).recordedSinceStart, 3);
    const after = await w.get('/lines?wait=0');
    assert.equal(after.body.size, 4);
    assert.deepEqual(after.body.lines, lines(read(w.folder, 'book.jsonl')));
  } finally {
    await w.service.close();
  }
});

test('a book in memory is given only as far as it is written to its file', async () => {
  let text = '{"slip":1}\n{"a":1}\n{"a":2}\n';
  let saved = '{"slip":1}\n{"a":1}\n'.length;
  const f = await unitFeed({ memory: (folder) => [{ key: 1, path: join(folder, 'book.jsonl'), text: () => text, saved: () => saved, inForce: true }] });
  try {
    const r = await f.get('/lines?wait=0');
    assert.deepEqual(r.body.lines, ['{"slip":1}', '{"a":1}']);
    saved = text.length;
    assert.deepEqual((await f.get('/lines?from=2&wait=0')).body.lines, ['{"a":2}']);
    text += '{"a":3}\n';
    assert.equal((await f.get('/lines?wait=0')).body.size, 3);
  } finally {
    await f.close();
  }
});

test('in memory as on disk, a carriage return before a line break and an empty line are set aside', async () => {
  const text = '{"slip":1}\r\n\n{"a":1}\n\r\n{"a":2}\n';
  const f = await unitFeed({ memory: (folder) => [{ key: 1, path: join(folder, 'book.jsonl'), text: () => text, inForce: true }] });
  try {
    const r = await f.get('/lines?wait=0');
    assert.deepEqual(r.body.lines, ['{"slip":1}', '{"a":1}', '{"a":2}']);
    assert.equal(r.body.size, 3);
    const bytes = Buffer.from(text);
    assert.equal(bytes.subarray(r.body.starts[0], r.body.ends[0]).toString(), '{"slip":1}\r\n');
    assert.equal(bytes.subarray(r.body.starts[2], r.body.ends[2]).toString(), '{"a":2}\n');
  } finally {
    await f.close();
  }
});

test('an answer holds at most 4 MiB of lines, but always one', async () => {
  const big = (i) => `{"a":"${String(i).padEnd(20000, 'x')}"}`;
  const text = Array.from({ length: 400 }, (_, i) => `${big(i)}\n`).join('');
  const f = await unitFeed({ memory: (folder) => [{ key: 1, path: join(folder, 'book.jsonl'), text: () => text, inForce: true }] });
  try {
    const r = await f.get('/lines?wait=0');
    assert.ok(r.body.lines.length < 400, `${r.body.lines.length} lines`);
    assert.ok(r.body.ends.at(-1) - r.body.starts[0] <= FEED_MAX_BYTES + Buffer.byteLength(big(0)) + 1);
    const huge = `{"a":"${'y'.repeat(FEED_MAX_BYTES + 10)}"}\n`;
    const g = await unitFeed({ memory: (folder) => [{ key: 1, path: join(folder, 'book.jsonl'), text: () => huge, inForce: true }] });
    try {
      assert.equal((await g.get('/lines?wait=0')).body.lines.length, 1, 'one line longer than 4 MiB still goes');
    } finally {
      await g.close();
    }
  } finally {
    await f.close();
  }
});

test('a kept book on disk is read whole, in pieces, and only while it is the file named by its identity', async () => {
  const folder = tempFolder();
  const path = join(folder, 'book-1.jsonl');
  const line = (i) => `{"a":"${String(i).padEnd(1000, 'x')}"}\n`;
  writeFileSync(path, Array.from({ length: 6000 }, (_, i) => line(i)).join(''));
  const id = fileIdentity(path);
  const ix = await diskIndex(path, id);
  assert.equal(ix.bs.length, 6000, 'every line of a book of about 6 MB');
  assert.equal(await diskIndex(path, 'another:file:1'), null, 'not read as another file');
  const f = await unitFeed({ folder });
  try {
    const r = await f.get('/lines?book=book-1.jsonl&from=5999&wait=0');
    assert.equal(r.body.size, 6000);
    assert.equal(r.body.lines[0], line(5999).trim());
  } finally {
    await f.close();
  }
});

test('a kept book on disk of exactly 4 MiB that ends part way through a line: once the line ends, it is given whole', async () => {
  const folder = tempFolder();
  const path = join(folder, 'book-1.jsonl');
  const PIECE = 4 * 1024 * 1024;
  const first = `{"slip":"${'a'.repeat(1000)}"}\n`;
  const partial = `{"stub":"${'b'.repeat(PIECE - first.length - 9)}`;
  writeFileSync(path, first + partial);
  assert.equal(Buffer.byteLength(first + partial), PIECE);
  const f = await unitFeed({ folder });
  try {
    assert.equal((await f.get('/lines?book=book-1.jsonl&wait=0')).body.size, 1);
    appendFileSync(path, 'bbbbbbbbbb"}\n');
    const r = await f.get('/lines?book=book-1.jsonl&from=1&wait=0');
    assert.equal(r.body.size, 2);
    assert.equal(r.body.starts[0], Buffer.byteLength(first));
    assert.equal(r.body.lines[0], `${partial}bbbbbbbbbb"}`);
  } finally {
    await f.close();
  }
});

test('many questions at once: at most 16 are taken on, the rest are told to ask again at once, and the hook is answered meanwhile', async () => {
  const w = await running(30);
  try {
    // A kept book large enough that finding its lines takes several pieces, so that each answer
    // holds the feed for a while on a fast computer too, and the questions pile up.
    writeFileSync(join(w.folder, 'book-1.jsonl'), Array.from({ length: 12000 }, (_, i) => `{"a":"${String(i).padEnd(3000, 'x')}"}\n`).join(''));
    const reader = feedReader({ address: `http://127.0.0.1:${w.port}`, token: tokenOf(w.folder) });
    await reader.get('/books');
    const flood = Array.from({ length: 200 }, () => reader.get('/lines?book=book-1.jsonl&wait=0').then((r) => r.code));
    const started = Date.now();
    assert.equal((await runHook(w.port, 'PreToolUse', 'Bash', { command: 'npm test' })).out, '', 'the hook is answered');
    const hookTook = Date.now() - started;
    const codes = await Promise.all(flood);
    assert.ok(codes.filter((c) => c === 429).length > 0, 'some told to ask again');
    assert.ok(codes.filter((c) => c === 200).length >= FEED_MAX_BUSY, 'at least 16 answered');
    assert.ok(codes.every((c) => c === 200 || c === 429));
    assert.ok(hookTook < 10000, `the hook took ${hookTook} ms`);
  } finally {
    await w.service.close();
  }
});
