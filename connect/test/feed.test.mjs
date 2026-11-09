// The uploader through the recorder's feed (--feed), with a stand-in for
// the feed and one for the server, on no network: it asks the recorder for
// the lines of its books and opens no book file. The stand-in keeps books
// as the recorder beside Claude Code keeps them: the one in force, and the
// ones kept before it, each named by its file's identity, which a rename
// keeps; a switch seals the book in force, keeps it under the next number
// with the same identity, and begins a new one (with a new identity) with
// the permission in force.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import fs, { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmdirSync, statSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { spawn } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCryptoCore } from '@microtoll/crypto-core';
import { DEFAULT_FEED, DEFAULT_FEED_TOKEN, createUploader, feedClient, identityOf, readCommandLine } from '../upload.mjs';
import { NAMESPACE, openEntry } from '../entry.mjs';

const cc = createCryptoCore({ namespace: NAMESPACE });
const quiet = { info() {}, error() {} };
const sha = (text) => createHash('sha256').update(text).digest('base64url');
const here = dirname(fileURLToPath(import.meta.url));

/** As in upload.test.mjs: the server's append, with its rules. */
function standIn() {
  const parts = [];
  const server = { parts, crashAfter: Infinity, sent: 0 };
  const fail = (reason, extra) => Object.assign(new Error(reason), { reason, serverMessage: { type: 'provared-append-failed', reason, ...extra } });
  server.append = async (msg) => {
    const part = msg.part === undefined ? 0 : msg.part;
    if (part > parts.length) throw fail('part-gap', { parts: parts.length });
    const list = parts[part] || [];
    if (msg.seq !== list.length) throw fail(msg.seq < list.length ? 'conflict' : 'gap', { part, next: list.length });
    list.push(msg.sealed);
    parts[part] = list;
    server.sent++;
    if (server.sent > server.crashAfter) { server.crashAfter = Infinity; throw new Error('the connection closed'); }
    return { type: 'provared-append-ok', part, seq: msg.seq };
  };
  return server;
}

/**
 * A stand-in for the recorder's feed: books as lists of lines, each with
 * an identity, answered as the recorder answers (feed.mjs): where each line
 * is in the file, the line before, the size and the last line. "asked"
 * counts the questions.
 */
function feedStandIn({ identities = true } = {}) {
  let made = 0;
  const newId = () => (identities ? `9:${++made}:1` : null);
  const books = [{ book: 'book.jsonl', number: null, id: newId(), lines: [] }];
  // The places of lines that an empty line comes before (in the book in force), as a hand edit might leave.
  // batch: at most this many lines in one answer; afterLines: called with each answer given.
  const f = { books, asked: 0, gaps: new Set(), batch: 500, afterLines: () => {} };
  const inForce = () => books.at(-1);
  const bytesOf = (lines) => lines.reduce((n, l) => n + Buffer.byteLength(l) + 1, 0);
  f.add = (...lines) => { inForce().lines.push(...lines); };
  /** A kept book put in the folder by someone (a copy, say), before the book in force. */
  f.addKept = (number, lines, id = newId()) => { books.splice(books.length - 1, 0, { book: `book-${number}.jsonl`, number, id, lines: [...lines] }); };
  /** A kept book moved out of the folder. */
  f.remove = (name) => { books.splice(books.findIndex((b) => b.book === name), 1); };
  f.late = (number, ...lines) => { books.find((b) => b.number === number).lines.push(...lines); };
  /** The recorder's switch: a seal into the book in force, kept under the next number, a new book with the permission. */
  f.switchBook = (first = ['{"slip":"in force"}']) => {
    const old = inForce();
    const number = Math.max(0, ...books.filter((b) => b.number).map((b) => b.number)) + 1;
    old.lines.push(`{"seal":${number}}`);
    Object.assign(old, { book: `book-${number}.jsonl`, number });
    books.push({ book: 'book.jsonl', number: null, id: newId(), lines: [...first] });
  };
  const listing = () => books.map((b) => ({ book: b.book, number: b.number, id: b.id, inForce: b === inForce(), bytes: bytesOf(b.lines) }));
  f.client = {
    origin: 'http://127.0.0.1:1',
    async books() { f.asked++; return { books: listing(), version: 0 }; },
    async lines({ id, book, from, max = 500 }) {
      f.asked++;
      const b = id ? books.find((x) => x.id === id) : books.find((x) => x.book === book);
      if (!b) return { missing: true, books: listing() };
      const starts = [];
      let at = 0;
      b.lines.forEach((l, i) => { if (b === inForce() && f.gaps.has(i)) at += 1; starts.push(at); at += Buffer.byteLength(l) + 1; });
      const pick = b.lines.slice(from, from + Math.min(max, f.batch));
      const before = from > 0 && from <= b.lines.length ? { fingerprint: sha(b.lines[from - 1]), start: starts[from - 1], end: starts[from - 1] + Buffer.byteLength(b.lines[from - 1]) + 1 } : null;
      const answer = {
        book: b.book, id: b.id, inForce: b === inForce(), from, lines: pick,
        starts: pick.map((_, i) => starts[from + i]), ends: pick.map((l, i) => starts[from + i] + Buffer.byteLength(l) + 1),
        previous: before, size: b.lines.length, bytes: at, last: b.lines.length ? sha(b.lines.at(-1)) : null, books: listing(), version: 0,
      };
      f.afterLines(answer);
      return answer;
    },
  };
  return f;
}

async function setUp(feedOptions) {
  const dir = mkdtempSync(join(tmpdir(), 'provared-app-feed-'));
  const kObject = cc.generateSymmetricKey();
  const connection = { server: 'ws://nowhere', origin: 'http://nowhere', namespace: NAMESPACE, objectId: crypto.randomUUID(), kObject: cc.toBase64Url(kObject), appendCapabilitySecret: cc.toBase64Url(cc.randomBytes(32)) };
  const server = standIn();
  const key = await cc.importSymmetricKey(kObject);
  const book = join(dir, 'book.jsonl');
  const feed = feedStandIn(feedOptions);
  const uploader = (more = {}) => createUploader({ connection, book, log: quiet, append: server.append, feed: feed.client, ...more });
  const opened = async () => {
    const out = [];
    for (let p = 0; p < server.parts.length; p++) out.push(await Promise.all(server.parts[p].map((s, seq) => openEntry(cc, key, connection.objectId, seq, cc.fromBase64Url(s), p))));
    return out;
  };
  return { dir, book, server, feed, key, connection, uploader, opened };
}

const lines = (prefix, n, from = 0) => Array.from({ length: n }, (_, i) => `{"${prefix}":${from + i}}`);
const state = (t) => JSON.parse(readFileSync(`${t.book}.uploaded.json`, 'utf8'));

test('through the feed: exactly the lines the book holds, in order; nothing new, nothing sent; no file in the folder but the state', async () => {
  const t = await setUp();
  t.feed.add(...lines('a', 3));
  const u = t.uploader();
  assert.equal(await u.sync(), 3);
  t.feed.add(...lines('a', 2, 3));
  assert.equal(await u.sync(), 5);
  assert.deepEqual(await t.opened(), [lines('a', 5)]);
  const before = t.server.sent;
  await u.sync();
  assert.equal(t.server.sent, before);
  assert.equal(existsSync(t.book), false, 'no book file was ever there');
  const s = state(t);
  assert.equal(s.parts[0].id, t.feed.books[0].id);
  assert.equal(s.parts[0].sha, sha(lines('a', 5).map((l) => `${l}\n`).join('')), 'the fingerprint of every byte sent, as for a file');
});

test('a switch while the uploader runs: the kept book, with its seal, in its part; the new book as the next part', async () => {
  const t = await setUp();
  t.feed.add(...lines('old', 3));
  const u = t.uploader();
  await u.sync();
  t.feed.switchBook(['{"slip":"in force"}', '{"new":0}']);
  assert.equal(await u.sync(), 2);
  assert.deepEqual(await t.opened(), [[...lines('old', 3), '{"seal":1}'], ['{"slip":"in force"}', '{"new":0}']]);
  assert.deepEqual(u.parts(), [{ file: 'book-1.jsonl', count: 4 }, { file: 'book.jsonl', count: 2 }]);
});

test('a switch with only the permission line sent: the new book, which begins with that same line, is still the next part', async () => {
  const t = await setUp();
  t.feed.add('{"slip":"in force"}');
  const u = t.uploader();
  await u.sync();
  t.feed.switchBook();
  t.feed.add('{"new":0}');
  await u.sync();
  assert.deepEqual(await t.opened(), [['{"slip":"in force"}', '{"seal":1}'], ['{"slip":"in force"}', '{"new":0}']]);
});

test('two switches while the uploader is stopped: every kept book in order, then the book in force', async () => {
  const t = await setUp();
  t.feed.add(...lines('one', 2));
  await t.uploader().sync();
  t.feed.switchBook(['{"slip":"in force"}', '{"two":0}']);
  t.feed.switchBook(['{"slip":"in force"}', '{"three":0}']);
  const u = t.uploader();
  await u.sync();
  assert.deepEqual(await t.opened(), [
    [...lines('one', 2), '{"seal":1}'],
    ['{"slip":"in force"}', '{"two":0}', '{"seal":2}'],
    ['{"slip":"in force"}', '{"three":0}'],
  ]);
  assert.deepEqual(u.parts().map((p) => p.file), ['book-1.jsonl', 'book-2.jsonl', 'book.jsonl']);
});

test('a switch, a stop after the new book\'s first line was sent and before it was remembered, and two more switches while stopped: every book in order', async () => {
  const t = await setUp();
  t.feed.add(...lines('one', 2));
  await t.uploader().sync();
  t.feed.switchBook(['{"slip":"in force"}', '{"two":0}']);
  // The seal goes, and the first line of the new book reaches the server, whose answer is lost.
  t.server.crashAfter = t.server.sent + 1;
  await assert.rejects(() => t.uploader().sync());
  assert.equal(state(t).parts.at(-1).count, 0, 'the new part has no line remembered');
  t.feed.switchBook(['{"slip":"in force"}', '{"three":0}']);
  t.feed.switchBook(['{"slip":"in force"}', '{"four":0}']);
  await t.uploader().sync();
  await t.uploader().sync();
  assert.deepEqual(await t.opened(), [
    [...lines('one', 2), '{"seal":1}'],
    ['{"slip":"in force"}', '{"two":0}', '{"seal":2}'],
    ['{"slip":"in force"}', '{"three":0}', '{"seal":3}'],
    ['{"slip":"in force"}', '{"four":0}'],
  ]);
});

test('a late receipt and the seal again in a kept book reach its part, while the uploader runs and after a restart', async () => {
  const t = await setUp();
  t.feed.add(...lines('old', 2));
  const u = t.uploader();
  await u.sync();
  t.feed.switchBook();
  await u.sync();
  t.feed.late(1, '{"late":0}', '{"seal":"again"}');
  t.feed.add('{"new":0}');
  await u.sync();
  assert.deepEqual((await t.opened())[0], [...lines('old', 2), '{"seal":1}', '{"late":0}', '{"seal":"again"}']);
  // Stopped; the recorder seals the kept book again at its next start.
  t.feed.late(1, '{"seal":"at the start"}');
  await t.uploader().sync();
  assert.equal((await t.opened())[0].at(-1), '{"seal":"at the start"}');
  assert.deepEqual((await t.opened())[1], ['{"slip":"in force"}', '{"new":0}']);
});

test('the books kept before the connection began are not uploaded', async () => {
  const t = await setUp();
  t.feed.add(...lines('earlier', 2));
  t.feed.switchBook(['{"slip":"in force"}', '{"now":0}']);
  const u = t.uploader();
  await u.sync();
  assert.deepEqual(await t.opened(), [['{"slip":"in force"}', '{"now":0}']]);
  assert.deepEqual(state(t).older.map((o) => o.file), ['book-1.jsonl']);
});

test('stopped at every point, before a switch and after it, it goes on without a gap or a repeat', async () => {
  const expected = [[...lines('a', 4), '{"seal":1}', '{"late":0}'], ['{"slip":"in force"}', ...lines('b', 3)]];
  // Stopped after k lines of the first round (before the switch), and after j of the next (after it).
  for (let k = 0; k <= 4; k++) {
    for (let j = 0; j <= 7; j++) {
      const t = await setUp();
      t.feed.add(...lines('a', 4));
      t.server.crashAfter = k;
      try { await t.uploader().sync(); } catch { /* stopped there */ }
      t.feed.switchBook(['{"slip":"in force"}', ...lines('b', 3)]);
      t.feed.late(1, '{"late":0}');
      t.server.crashAfter = t.server.sent + j;
      try { await t.uploader().sync(); } catch { /* stopped there */ }
      for (let round = 0; round < 3; round++) await t.uploader().sync();
      assert.deepEqual(await t.opened(), expected, `stopped after ${k} lines, then after ${j} more`);
    }
  }
});

test('a state that cannot be read stops the uploader and says so: it never begins again from the first line, and the file is left as it was', async () => {
  for (const kept of ['', '{"version":3,"par', '{"something":"else"}']) {
    const t = await setUp();
    t.feed.add(...lines('a', 3));
    await t.uploader().sync();
    writeFileSync(`${t.book}.uploaded.json`, kept);
    t.feed.add('{"more":0}');
    await assert.rejects(() => t.uploader().sync(), (e) => e.reason === 'state-unreadable' && /cannot be read/.test(e.message) && e.message.includes(`${t.book}.uploaded.json`));
    assert.equal(t.server.sent, 3, 'nothing more is sent');
    assert.equal(readFileSync(`${t.book}.uploaded.json`, 'utf8'), kept);
  }
});

test('a part whose file is not text is a state that cannot be read, not a fault at every round', async () => {
  const t = await setUp();
  t.feed.add(...lines('a', 2));
  writeFileSync(`${t.book}.uploaded.json`, JSON.stringify({ version: 3, parts: [{ file: 5, id: null, count: 1, last: 'x', start: 0, bytes: 8 }], older: [] }));
  await assert.rejects(() => t.uploader().sync(), (e) => e.reason === 'state-unreadable');
  assert.equal(t.server.sent, 0);
});

test('no state at all is a first start: everything is sent, and the state is written whole, with no temporary file left', async () => {
  const t = await setUp();
  t.feed.add(...lines('a', 3));
  await t.uploader().sync();
  assert.equal(t.server.sent, 3);
  assert.equal(state(t).parts[0].count, 3);
  assert.equal(existsSync(`${t.book}.uploaded.json.tmp`), false);
});

test('a part that names a book and has no line yet: the book the recorder kept under that identity is that part', async () => {
  const t = await setUp();
  t.feed.add(...lines('a', 2));
  t.feed.switchBook(['{"slip":"in force"}', '{"b":0}']);
  writeFileSync(`${t.book}.uploaded.json`, JSON.stringify({ version: 3, parts: [{ file: 'book.jsonl', id: t.feed.books[0].id, count: 0, last: null, start: 0, bytes: 0 }], older: [] }));
  await t.uploader().sync();
  await t.uploader().sync();
  assert.deepEqual(await t.opened(), [[...lines('a', 2), '{"seal":1}'], ['{"slip":"in force"}', '{"b":0}']]);
});

test('a book in force with another identity, and no kept book that is or holds the part: refused, nothing sent', async () => {
  const t = await setUp();
  t.feed.add(...lines('a', 3));
  const u = t.uploader();
  await u.sync();
  // The book in force is a new file (a program rewrote it), and nothing was kept.
  t.feed.books[0].id = '9:77:1';
  t.feed.add('{"more":0}');
  await assert.rejects(() => t.uploader().sync(), /is not the book the 3 lines already uploaded were read from/);
  assert.equal(t.server.sent, 3);
});

test('a book that no longer holds the lines sent, in that order: refused', async () => {
  const t = await setUp();
  t.feed.add(...lines('a', 3));
  await t.uploader().sync();
  t.feed.books[0].lines[2] = '{"changed":2}';
  t.feed.add('{"more":0}');
  await assert.rejects(() => t.uploader().sync(), /no longer holds the 3 lines/);
  // An earlier line changed, the last one as it was: the fingerprint of every byte sent shows it when the uploader starts.
  const t2 = await setUp();
  t2.feed.add(...lines('a', 3));
  await t2.uploader().sync();
  t2.feed.books[0].lines[0] = '{"A":0}';
  t2.feed.add('{"more":0}');
  await assert.rejects(() => t2.uploader().sync(), /no longer holds/);
  assert.equal(t2.server.sent, 3);
  // A part kept by an earlier version has no such fingerprint: the line before the next one must still be the last one sent.
  const t3 = await setUp();
  t3.feed.add(...lines('a', 3));
  await t3.uploader().sync();
  const kept = state(t3);
  delete kept.parts[0].sha;
  writeFileSync(`${t3.book}.uploaded.json`, JSON.stringify(kept));
  t3.feed.books[0].lines[2] = '{"changed":2}';
  t3.feed.add('{"more":0}');
  await assert.rejects(() => t3.uploader().sync(), /no longer holds the 3 lines/);
  assert.equal(t3.server.sent, 3);
});

test('where the bytes of the book are not its lines alone (an empty line between two), the fingerprint of every byte is set aside, and every line still goes', async () => {
  const t = await setUp();
  t.feed.add(...lines('a', 2));
  const u = t.uploader();
  await u.sync();
  assert.ok(state(t).parts[0].sha);
  t.feed.gaps.add(2);
  t.feed.add('{"a":2}');
  await u.sync();
  assert.deepEqual(await t.opened(), [lines('a', 3)]);
  assert.equal(state(t).parts[0].sha, undefined);
  assert.equal(state(t).parts[0].count, 3);
});

test('on a file system that gives no identity, books are known by name and by what they hold', async () => {
  const t = await setUp({ identities: false });
  t.feed.add(...lines('old', 2));
  const u = t.uploader();
  await u.sync();
  t.feed.switchBook(['{"slip":"in force"}', '{"new":0}']);
  await u.sync();
  assert.deepEqual(await t.opened(), [[...lines('old', 2), '{"seal":1}'], ['{"slip":"in force"}', '{"new":0}']]);
});

test('a part sent from the file (--book) goes on through the feed, without a gap or a repeat, and the file way can take it back', async () => {
  const t = await setUp();
  const first = lines('f', 3);
  writeFileSync(t.book, first.map((l) => `${l}\n`).join(''));
  // From the file, the old way.
  await createUploader({ connection: t.connection, book: t.book, log: quiet, append: t.server.append }).sync();
  const fromFile = state(t).parts[0];
  // The feed names the same file by the same identity, as the recorder reckons it.
  t.feed.books[0].id = identityOf(statSync(t.book, { bigint: true }));
  t.feed.books[0].lines.push(...first, '{"f":3}');
  appendFileSync(t.book, '{"f":3}\n');
  assert.equal(fromFile.id, t.feed.books[0].id);
  await t.uploader().sync();
  assert.deepEqual(await t.opened(), [[...first, '{"f":3}']]);
  const s = state(t).parts[0];
  assert.equal(s.count, 4);
  assert.equal(s.sha, sha(readFileSync(t.book)), 'the fingerprint went on, and is the file\'s');
  // Back to the file: it checks the fingerprint against the file when it starts, and goes on.
  appendFileSync(t.book, '{"f":4}\n');
  await createUploader({ connection: t.connection, book: t.book, log: quiet, append: t.server.append }).sync();
  assert.equal((await t.opened())[0].at(-1), '{"f":4}');
});

test('a feed that asks nothing of the file system: the uploader makes only the questions it needs once all is sent', async () => {
  const t = await setUp();
  t.feed.add(...lines('a', 2));
  const u = t.uploader();
  await u.sync();
  t.feed.asked = 0;
  await u.sync();
  assert.ok(t.feed.asked <= 2, `${t.feed.asked} questions for a round with nothing new`);
});

test('--same-book is for --book: refused with a feed', () => {
  assert.throws(() => createUploader({ connection: {}, book: 'x', feed: {}, sameBook: true, log: quiet, append: () => {} }), /--same-book is for --book/);
});

// --- after the review of 18 October 2026 ---

test('every answer must go on from the last line sent, not only the first of a round', async () => {
  const t = await setUp();
  t.feed.batch = 100;
  t.feed.add(...lines('a', 250));
  // After the second answer, its last line is changed for another of the same length.
  let changed = false;
  t.feed.afterLines = (a) => { if (a.from === 100 && !changed) { changed = true; t.feed.books[0].lines[199] = '{"b":199}'; } };
  await assert.rejects(() => t.uploader().sync(), /no longer holds the 200 lines/);
  assert.equal(t.server.sent, 200, 'nothing after the line that changed');
});

test('an answer whose first line starts before the line before it ended is refused', async () => {
  const t = await setUp();
  t.feed.add(...lines('a', 3));
  await t.uploader().sync();
  t.feed.add('{"a":3}');
  t.feed.afterLines = (a) => { if (a.from === 3 && a.lines.length > 0) a.starts[0] -= 1; };
  await assert.rejects(() => t.uploader().sync(), /no longer holds the 3 lines/);
  assert.equal(t.server.sent, 3);
});

test('the line before must be at the place where the last line sent ended, for a part with no fingerprint of every byte', async () => {
  const t = await setUp();
  t.feed.add(...lines('a', 3));
  await t.uploader().sync();
  const kept = state(t);
  delete kept.parts[0].sha;
  writeFileSync(`${t.book}.uploaded.json`, JSON.stringify(kept));
  // An empty line put in before line 1: the lines sent are all there, a byte further on.
  t.feed.gaps.add(1);
  t.feed.add('{"more":0}');
  await assert.rejects(() => t.uploader().sync(), /no longer holds the 3 lines/);
  assert.equal(t.server.sent, 3);
});

test('the line before must have the fingerprint of the last line sent, even where its place is the same', async () => {
  const t = await setUp();
  t.feed.add(...lines('a', 3));
  await t.uploader().sync();
  const kept = state(t);
  delete kept.parts[0].sha;
  writeFileSync(`${t.book}.uploaded.json`, JSON.stringify(kept));
  t.feed.books[0].lines[2] = '{"b":2}';
  t.feed.add('{"more":0}');
  await assert.rejects(() => t.uploader().sync(), /no longer holds the 3 lines/);
  assert.equal(t.server.sent, 3);
});

test('with no identities, a kept book that holds the last line sent at another place is not the part\'s book', async () => {
  const t = await setUp({ identities: false });
  t.feed.add('{"a":0}', '{"a":1}');
  const u = t.uploader();
  await u.sync();
  t.feed.switchBook(['{"slip":"in force"}', '{"new":0}']);
  // Kept after it, so tried first: the same last line, but after a longer first one.
  t.feed.addKept(2, ['{"zz":"a longer first line"}', '{"a":1}']);
  await u.sync();
  await u.sync();
  assert.deepEqual((await t.opened())[0], ['{"a":0}', '{"a":1}', '{"seal":1}']);
});

test('with no identities, a copy of the start of the book in force, kept beside it, is not taken for the part', async () => {
  const t = await setUp({ identities: false });
  t.feed.add(...lines('a', 3));
  const u = t.uploader();
  await u.sync();
  t.feed.addKept(5, lines('a', 3));
  t.feed.add('{"a":3}');
  await u.sync();
  assert.deepEqual(await t.opened(), [lines('a', 4)]);
  assert.deepEqual(u.parts().map((p) => p.file), ['book.jsonl']);
});

test('a copy of a kept book, put beside it under another name, is set aside and not sent as a part', async () => {
  const t = await setUp();
  t.feed.add(...lines('a', 3));
  const u = t.uploader();
  await u.sync();
  t.feed.switchBook(['{"slip":"in force"}', '{"b":0}']);
  t.feed.addKept(2, t.feed.books[0].lines);
  await u.sync();
  await u.sync();
  assert.deepEqual(await t.opened(), [[...lines('a', 3), '{"seal":1}'], ['{"slip":"in force"}', '{"b":0}']]);
  assert.ok(state(t).older.some((o) => o.file === 'book-2.jsonl'), 'set aside');
});

test('a kept book\'s name that now holds another book (with another identity) is not followed for its part', async () => {
  const t = await setUp();
  t.feed.add(...lines('a', 2));
  const u = t.uploader();
  await u.sync();
  t.feed.switchBook(['{"slip":"in force"}', '{"b":0}']);
  await u.sync();
  const keptLines = [...t.feed.books[0].lines];
  // The person moved book-1.jsonl away, and a new file under that name begins as it did, with more after.
  t.feed.remove('book-1.jsonl');
  t.feed.addKept(1, [...keptLines, '{"other":0}']);
  await u.sync();
  assert.deepEqual((await t.opened())[0], keptLines, 'nothing of the other book went into the part');
});

// --- the feed's client, and the command line ---

test('the feed\'s client takes only the recorder\'s address, 127.0.0.1, and a token in its form', () => {
  const token = 'A'.repeat(43);
  for (const address of ['https://127.0.0.1:8794', 'http://example.org:8794', 'http://10.0.0.1:8794', 'http://localhost:8794', 'http://[::1]:8794', 'http://127.0.0.2:8794', 'http://127.0.0.1:8794/lines', 'http://u@127.0.0.1:8794', 'not an address']) {
    assert.throws(() => feedClient({ address, token }), /address|this computer/, address);
  }
  assert.throws(() => feedClient({ address: 'http://127.0.0.1:8794', token: 'short' }), /does not hold a token/);
  assert.equal(feedClient({ address: 'http://127.0.0.1:8794', token }).origin, 'http://127.0.0.1:8794');
});

const LABELS = { recorder: 'provared feed v1: the recorder knows the token', key: 'provared feed v1: the key of a conversation', question: 'provared feed v1: a question', answer: 'provared feed v1: an answer' };
const mac = (key, label, ...parts) => { const h = createHmac('sha256', key); h.update(label); for (const p of parts) { h.update('\n'); h.update(p); } return h.digest(); };

/**
 * A stand-in for the recorder's feed that speaks its conversation (as
 * feed.mjs does), knowing the token it is given; "answer" says what each
 * question gets. Every question it is sent is kept in "seen".
 */
// Another way of writing the same 32 bytes: the last base64url character carries two bits no byte uses.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const respelled = (s) => s.slice(0, -1) + ALPHABET[(ALPHABET.indexOf(s.at(-1)) & ~3) | ((ALPHABET.indexOf(s.at(-1)) + 1) & 3)];

async function speaking(token, answer, { tamper = false, unproved = false, respellSession = false, respellProof = false } = {}) {
  const seen = [];
  const talks = new Map();
  const server = createServer(async (req, res) => {
    seen.push({ url: req.url, headers: req.headers });
    if (req.url === '/hello') {
      const theirs = req.headers['provared-feed-hello'];
      const plainSession = createHash('sha256').update(String(Math.random())).digest('base64url');
      // respellSession: the session written another way, with its proof made over that text.
      const session = respellSession ? respelled(plainSession) : plainSession;
      talks.set(session, mac(Buffer.from(token), LABELS.key, theirs, session));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ session, proof: mac(Buffer.from(token), LABELS.recorder, theirs, session).toString('base64url') }));
    }
    const session = req.headers['provared-feed-session'];
    const nonce = req.headers['provared-feed-nonce'];
    const key = talks.get(session);
    const given = Buffer.from(req.headers['provared-feed-proof'] ?? '', 'base64url');
    if (!key || !given.equals(mac(key, LABELS.question, session, nonce, `GET ${req.url}`))) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end('{"error":"no"}');
    }
    const { code, body } = answer(req.url);
    const bytes = Buffer.from(JSON.stringify(body));
    const made = mac(key, LABELS.answer, session, nonce, String(code), bytes).toString('base64url');
    // respellProof: the right proof, written another way.
    const proof = respellProof ? respelled(made) : made;
    res.writeHead(code, { 'Content-Type': 'application/json', ...(unproved ? {} : { 'Provared-Feed-Proof': proof }) });
    res.end(tamper ? Buffer.from(JSON.stringify({ ...body, lines: (body.lines ?? []).map(() => '{"changed":1}') })) : bytes);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, seen, address: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

const oneLine = { book: 'book.jsonl', id: 'y', inForce: true, from: 0, lines: ['{"a":1}'], starts: [0], ends: [8], previous: null, size: 1, bytes: 8, last: null, books: [], version: 0 };

test('the token never travels: the client and the recorder each prove they know it, and each answer is proved', async () => {
  const token = 'B'.repeat(43);
  const s = await speaking(token, () => ({ code: 200, body: oneLine }));
  try {
    const client = feedClient({ address: s.address, token });
    assert.deepEqual((await client.lines({ id: 'y', from: 0 })).lines, ['{"a":1}']);
    assert.ok(s.seen.length >= 2);
    for (const q of s.seen) assert.ok(!JSON.stringify(q).includes(token), 'the token is in no question');
  } finally {
    await s.close();
  }
});

test('a program that listens on the address and does not know the token is told nothing, and nothing it says is sent', async () => {
  // The reviewer's case: while the recorder is stopped, another program listens on its address.
  const t = await setUp();
  const impostor = await speaking('I'.repeat(43), (url) => (url.startsWith('/books')
    ? { code: 200, body: { books: [{ book: 'book.jsonl', number: null, id: '1:2:3', inForce: true, bytes: 40 }], version: 0 } }
    : { code: 200, body: { ...oneLine, id: '1:2:3', lines: ['{"slip":"made up"}'], ends: [19] } }));
  try {
    const u = t.uploader({ feed: feedClient({ address: impostor.address, token: 'B'.repeat(43) }) });
    await assert.rejects(() => u.sync(), (e) => e.reason === 'feed-refused' && /did not prove that it knows the token/.test(e.message));
    assert.equal(t.server.sent, 0, 'nothing sent to the server');
    assert.deepEqual(impostor.seen.map((q) => q.url), ['/hello'], 'nothing asked of it after its proof failed');
    for (const q of impostor.seen) assert.ok(!JSON.stringify(q).includes('B'.repeat(43)));
  } finally {
    await impostor.close();
  }
});

test('a session or a proof from the recorder written another way for the same bytes is not taken', async () => {
  const token = 'G'.repeat(43);
  const s1 = await speaking(token, () => ({ code: 200, body: oneLine }), { respellSession: true });
  try {
    await assert.rejects(() => feedClient({ address: s1.address, token }).lines({ id: 'y', from: 0 }), (e) => e.reason === 'feed-refused');
  } finally {
    await s1.close();
  }
  const s2 = await speaking(token, () => ({ code: 200, body: oneLine }), { respellProof: true });
  try {
    await assert.rejects(() => feedClient({ address: s2.address, token }).lines({ id: 'y', from: 0 }), (e) => e.reason === 'feed-error' && /does not carry the recorder's proof/.test(e.message));
  } finally {
    await s2.close();
  }
  // Written in the one way, the same stand-in is taken.
  const s3 = await speaking(token, () => ({ code: 200, body: oneLine }));
  try {
    assert.deepEqual((await feedClient({ address: s3.address, token }).lines({ id: 'y', from: 0 })).lines, ['{"a":1}']);
  } finally {
    await s3.close();
  }
});

test('an answer other than 200 (404, 429, 503) without the recorder\'s proof is not used either', async () => {
  const token = 'F'.repeat(43);
  for (const [code, body] of [[404, { error: 'no such book', books: [] }], [429, { error: 'busy' }], [503, { error: 'off' }]]) {
    const s = await speaking(token, () => ({ code, body }), { unproved: true });
    try {
      await assert.rejects(() => feedClient({ address: s.address, token }).lines({ id: 'x', from: 0 }), (e) => e.reason === 'feed-error' && /does not carry the recorder's proof/.test(e.message), String(code));
    } finally {
      await s.close();
    }
  }
});

test('an answer that gives a line before where nothing has been sent is refused', async () => {
  const t = await setUp();
  t.feed.add(...lines('a', 2));
  t.feed.afterLines = (a) => { if (a.from === 0) a.previous = { fingerprint: sha('{"made":"up"}'), start: 0, end: 14 }; };
  await assert.rejects(() => t.uploader().sync(), /no longer holds the 0 lines/);
  assert.equal(t.server.sent, 0);
});

test('a conversation the recorder gives up is opened again once; given up again, the feed is taken as busy, not as refusing', async () => {
  const token = 'E'.repeat(43);
  const asked = [];
  const server = createServer((req, res) => {
    asked.push(req.url);
    res.writeHead(req.url === '/hello' ? 200 : 401, { 'Content-Type': 'application/json' });
    if (req.url !== '/hello') return res.end('{"error":"no such conversation","renew":true}');
    const theirs = req.headers['provared-feed-hello'];
    const session = createHash('sha256').update(String(Math.random())).digest('base64url');
    res.end(JSON.stringify({ session, proof: mac(Buffer.from(token), LABELS.recorder, theirs, session).toString('base64url') }));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    await assert.rejects(() => feedClient({ address: `http://127.0.0.1:${server.address().port}`, token }).books(), (e) => e.reason === 'feed-busy');
    assert.deepEqual(asked, ['/hello', '/books', '/hello', '/books']);
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test('the recorder\'s proof, given to one reader, cannot be handed again to another: it is over that reader\'s own random number', async () => {
  const token = 'D'.repeat(43);
  // A genuine answer to one hello, as another program could have seen it pass.
  const theirs = createHash('sha256').update('an earlier reader').digest('base64url');
  const session = createHash('sha256').update('its session').digest('base64url');
  const seen = { session, proof: mac(Buffer.from(token), LABELS.recorder, theirs, session).toString('base64url') };
  const asked = [];
  const replaying = createServer((req, res) => {
    asked.push(req.url);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(seen));
  });
  await new Promise((r) => replaying.listen(0, '127.0.0.1', r));
  try {
    await assert.rejects(() => feedClient({ address: `http://127.0.0.1:${replaying.address().port}`, token }).books(), (e) => e.reason === 'feed-refused');
    assert.deepEqual(asked, ['/hello'], 'nothing asked after the hello');
  } finally {
    await new Promise((r) => replaying.close(r));
  }
});

test('the feed\'s client: an answer without the recorder\'s proof, or changed after it, is not used; a busy feed, a refused proof, an answer in another form and a feed not running each say so', async () => {
  const token = 'C'.repeat(43);
  for (const how of [{ unproved: true }, { tamper: true }]) {
    const s = await speaking(token, () => ({ code: 200, body: oneLine }), how);
    try {
      await assert.rejects(() => feedClient({ address: s.address, token }).lines({ id: 'y', from: 0 }), (e) => e.reason === 'feed-error' && /does not carry the recorder's proof/.test(e.message), JSON.stringify(how));
    } finally {
      await s.close();
    }
  }
  let reply = { code: 429, body: { error: 'busy' } };
  const s = await speaking(token, () => reply);
  try {
    const client = feedClient({ address: s.address, token });
    await assert.rejects(() => client.lines({ id: 'x', from: 0 }), (e) => e.reason === 'feed-busy');
    reply = { code: 200, body: { books: 'not a list' } };
    await assert.rejects(() => client.books(), (e) => e.reason === 'feed-error');
    reply = { code: 200, body: oneLine };
    await assert.rejects(() => client.lines({ id: 'x', from: 0 }), (e) => e.reason === 'feed-error', 'an answer for another book');
    await assert.rejects(() => client.lines({ id: 'y', from: 3 }), (e) => e.reason === 'feed-error', 'an answer for another place');
    assert.deepEqual((await client.lines({ id: 'y', from: 0 })).lines, ['{"a":1}']);
    reply = { code: 200, body: { ...oneLine, lines: ['{"a":1}\n{"b":2}'] } };
    await assert.rejects(() => client.lines({ id: 'y', from: 0 }), (e) => e.reason === 'feed-error', 'a line with a line break inside');
  } finally {
    await s.close();
  }
  // A recorder that knows the token but refuses the client's proof (the client's own key is wrong): refused for good.
  const refusing = await speaking(token, () => ({ code: 200, body: oneLine }));
  const wrongKey = feedClient({ address: refusing.address, token, fetchImpl: (url, o) => fetch(url, { ...o, headers: { ...o.headers, ...(o.headers['Provared-Feed-Proof'] ? { 'Provared-Feed-Proof': 'P'.repeat(43) } : {}) } }) });
  try {
    await assert.rejects(() => wrongKey.books(), (e) => e.reason === 'feed-refused' && /refused this uploader's proof/.test(e.message));
  } finally {
    await refusing.close();
  }
  const gone = feedClient({ address: s.address, token });
  await assert.rejects(() => gone.books(), (e) => e.reason === 'feed-unreachable');
});

test('the command line: --feed with --feed-token keeps the uploader\'s files beside the token, as --book names them for book.jsonl', () => {
  const folder = join(tmpdir(), 'recorder');
  const said = readCommandLine(['--connection', 'c.json', '--feed', 'http://127.0.0.1:8794', '--feed-token', join(folder, 'feed-token')]);
  assert.equal(said.base, join(folder, 'book.jsonl'));
  assert.equal(said.base, readCommandLine(['--connection', 'c.json', '--book', join(folder, 'book.jsonl')]).base, 'the same state, lock and process number as the file way');
  assert.match(readCommandLine(['--feed', 'http://127.0.0.1:8794']).error, /both --feed/);
  assert.match(readCommandLine(['--feed', 'http://127.0.0.1:8794', '--feed-token', 't', '--book', 'b']).error, /not both/);
  assert.match(readCommandLine(['--feed', 'http://127.0.0.1:8794', '--feed-token', 't', '--same-book']).error, /--same-book is for --book/);
  // Nothing named: the recorder beside Claude Code, where it is.
  const bare = readCommandLine([]);
  assert.equal(bare.error, undefined);
  assert.equal(bare.feedAddress, DEFAULT_FEED);
  assert.equal(bare.feedToken, DEFAULT_FEED_TOKEN);
  assert.equal(bare.base, join(dirname(DEFAULT_FEED_TOKEN), 'book.jsonl'));
  assert.match(readCommandLine(['--feed-token', 't']).error, /both --feed/);
});

test('the command: a refused token stops it at once, with nothing sent to the server; --book says it is the fragile way', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'provared-app-feed-cli-'));
  const connection = join(dir, 'connection.json');
  writeFileSync(connection, JSON.stringify({ server: 'ws://127.0.0.1:1', origin: 'http://nowhere', namespace: NAMESPACE, objectId: crypto.randomUUID(), kObject: cc.toBase64Url(cc.generateSymmetricKey()), appendCapabilitySecret: cc.toBase64Url(cc.randomBytes(32)) }));
  writeFileSync(join(dir, 'feed-token'), `${'C'.repeat(43)}\n`);
  const server = createServer((req, res) => { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end('{"error":"the feed needs the token"}'); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const upload = join(here, '..', 'upload.mjs');
    // Ended after 20 seconds where it has not ended by itself.
    const run = (args) => new Promise((resolve) => {
      const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', upload, ...args]);
      let err = '';
      const timer = setTimeout(() => child.kill(), 20000);
      child.stderr.on('data', (d) => { err += d; });
      child.on('close', (code) => { clearTimeout(timer); resolve({ code, err }); });
    });
    const r = await run(['--connection', connection, '--feed', `http://127.0.0.1:${server.address().port}`, '--feed-token', join(dir, 'feed-token'), '--once']);
    assert.equal(r.code, 1);
    assert.match(r.err, /feed-refused/);
    // The watcher too stops for good, at once, and is not tried again every 30 seconds.
    const started = Date.now();
    const w = await run(['--connection', connection, '--feed', `http://127.0.0.1:${server.address().port}`, '--feed-token', join(dir, 'feed-token')]);
    assert.equal(w.code, 1);
    assert.ok(Date.now() - started < 20000, 'it stopped');
    assert.equal(existsSync(join(dir, 'book.jsonl.uploader.lock')), false, 'its lock, beside the token, is given back');
    const b = await run(['--connection', connection, '--book', join(dir, 'book.jsonl'), '--once']);
    assert.match(b.err, /the fragile way/);
  } finally {
    await new Promise((r) => server.close(r));
  }
});

// --- the same fault in the file way ---

test('the file way: stopped after the server took the first line and before the state was written, then a switch: the kept file is still the first part', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'provared-app-feed-file-'));
  const book = join(dir, 'book.jsonl');
  const kObject = cc.generateSymmetricKey();
  const connection = { server: 'ws://nowhere', origin: 'http://nowhere', namespace: NAMESPACE, objectId: crypto.randomUUID(), kObject: cc.toBase64Url(kObject), appendCapabilitySecret: cc.toBase64Url(cc.randomBytes(32)) };
  const server = standIn();
  const key = await cc.importSymmetricKey(kObject);
  writeFileSync(book, lines('a', 3).map((l) => `${l}\n`).join(''));
  server.crashAfter = 0;
  await assert.rejects(() => createUploader({ connection, book, log: quiet, append: server.append }).sync());
  // The recorder's switch.
  appendFileSync(book, '{"seal":1}\n');
  const { renameSync } = await import('node:fs');
  renameSync(book, join(dir, 'book-1.jsonl'));
  writeFileSync(book, '{"slip":"in force"}\n{"b":0}\n');
  for (let i = 0; i < 2; i++) await createUploader({ connection, book, log: quiet, append: server.append }).sync();
  const opened = [];
  for (let p = 0; p < server.parts.length; p++) opened.push(await Promise.all(server.parts[p].map((s, seq) => openEntry(cc, key, connection.objectId, seq, cc.fromBase64Url(s), p))));
  assert.deepEqual(opened, [[...lines('a', 3), '{"seal":1}'], ['{"slip":"in force"}', '{"b":0}']]);
});

// --- the state beside the book: holds, failed saves, shapes, conflicts ---

/** A stand-in for each way of reading a book, with the same few things: add lines, make an uploader. */
const ways = {
  async feed() {
    const t = await setUp();
    return { ...t, stateFile: `${t.book}.uploaded.json`, add: (...l) => t.feed.add(...l) };
  },
  async book() {
    const t = await setUp();
    writeFileSync(t.book, '');
    return { ...t, stateFile: `${t.book}.uploaded.json`, add: (...l) => appendFileSync(t.book, l.map((x) => `${x}\n`).join('')), uploader: (more = {}) => t.uploader({ feed: null, ...more }) };
  },
};
const eachWay = (name, f) => { for (const way of Object.keys(ways)) test(`${name} (--${way})`, async () => f(await ways[way]())); };
const onDisk = (t) => JSON.parse(readFileSync(t.stateFile, 'utf8')).parts.map((p) => p.count);

/** For the length of f, a stand-in for a function of node:fs, which the uploader sees too: stub(real, ...what it was given). */
async function standingIn(name, stub, f) {
  const real = fs[name];
  fs[name] = (...given) => stub(real, ...given);
  syncBuiltinESMExports();
  try { return await f(); } finally { fs[name] = real; syncBuiltinESMExports(); }
}
const refused = (code) => Object.assign(new Error(`${code}: held by another program`), { code });
/** Reads of the state fail with code, the first "times" of them. */
const heldFor = (t, times, code = 'EBUSY') => {
  let n = 0;
  return (real, path, ...rest) => { if (path === t.stateFile && n++ < times) throw refused(code); return real(path, ...rest); };
};

eachWay('a brief hold on a good state at a start is waited out: the state is read, and the new line goes', async (t) => {
  t.add(...lines('a', 3));
  await t.uploader().sync();
  t.add('{"b":0}');
  for (const code of ['EBUSY', 'EPERM', 'EACCES']) await standingIn('readFileSync', heldFor(t, 2, code), () => t.uploader().sync());
  assert.equal(t.server.sent, 4);
  assert.deepEqual(onDisk(t), [4]);
});

eachWay('a hold at a start that outlasts the tries fails for now, with the code; the next round goes on from the right place', async (t) => {
  t.add(...lines('a', 3));
  await t.uploader().sync();
  t.add('{"b":0}');
  const kept = readFileSync(t.stateFile, 'utf8');
  const u = t.uploader();
  await standingIn('readFileSync', heldFor(t, Infinity), () => assert.rejects(() => u.sync(), (e) => e.reason === 'state-not-read' && e.message.includes('EBUSY') && e.message.includes(t.stateFile)));
  assert.equal(t.server.sent, 3, 'nothing is sent');
  assert.equal(readFileSync(t.stateFile, 'utf8'), kept, 'the file is left as it was');
  await u.sync();
  assert.equal(t.server.sent, 4);
  assert.deepEqual(onDisk(t), [4]);
});

eachWay('a directory at the state\'s path is a read that fails, not bad content: nothing is sent, and nothing is begun again', async (t) => {
  mkdirSync(t.stateFile);
  t.add(...lines('a', 3));
  const u = t.uploader();
  await assert.rejects(() => u.sync(), (e) => e.reason === 'state-not-read' && e.message.includes('EISDIR'));
  assert.equal(t.server.sent, 0);
  rmdirSync(t.stateFile);
  await u.sync();
  assert.equal(t.server.sent, 3);
});

eachWay('a hold while a run is under way stops nothing: the run holds the position', async (t) => {
  t.add(...lines('a', 3));
  const u = t.uploader();
  await u.sync();
  t.add('{"b":0}');
  await standingIn('readFileSync', heldFor(t, Infinity), () => u.sync());
  assert.equal(t.server.sent, 4);
  assert.deepEqual(onDisk(t), [4]);
});

eachWay('a state garbled while a run is under way is written over with the run\'s position, and the run says so', async (t) => {
  const said = [];
  t.add(...lines('a', 3));
  const u = t.uploader({ log: { info() {}, error: (words) => said.push(words) } });
  await u.sync();
  let sent = 3;
  for (const kept of ['{"version":3,"par', '{"version":3,"parts":[{"count":"3"}],"older":[]}']) {
    said.length = 0;
    writeFileSync(t.stateFile, kept);
    t.add(`{"b":${sent}}`);
    await u.sync();
    sent++;
    assert.equal(t.server.sent, sent);
    assert.deepEqual(onDisk(t), [sent]);
    assert.equal(said.length, 1);
    assert.match(said[0], /was garbled while this uploader ran; it was written over/);
  }
});

eachWay('a state read and found ahead of the run still stops it: another uploader is at work', async (t) => {
  t.add(...lines('a', 3));
  const u = t.uploader();
  await u.sync();
  const s = JSON.parse(readFileSync(t.stateFile, 'utf8'));
  s.parts[0].count = 9;
  writeFileSync(t.stateFile, JSON.stringify(s));
  t.add('{"b":0}');
  await assert.rejects(() => u.sync(), (e) => e.code === 'another-uploader');
  assert.deepEqual(onDisk(t), [9]);
});

for (const after of ['the same run', 'a restart']) {
  eachWay(`a save that fails on two lines running: the second line is not sent, the disk stays one behind, and ${after} goes on`, async (t) => {
    t.add(...lines('a', 3));
    const u = t.uploader();
    await u.sync();
    mkdirSync(`${t.stateFile}.tmp`);
    t.add('{"b":0}', '{"b":1}');
    await assert.rejects(() => u.sync(), (e) => e.reason === 'state-not-saved' && e.message.includes(t.stateFile));
    assert.equal(t.server.sent, 4, 'one line, and no more after the failed save');
    t.add('{"b":2}');
    await assert.rejects(() => u.sync(), (e) => e.reason === 'state-not-saved');
    assert.equal(t.server.sent, 4, 'the next round sends nothing while the save fails');
    assert.deepEqual(onDisk(t), [3]);
    rmdirSync(`${t.stateFile}.tmp`);
    await (after === 'a restart' ? t.uploader() : u).sync();
    assert.equal(t.server.sent, 6);
    assert.deepEqual(onDisk(t), [6]);
    assert.deepEqual(await t.opened(), [[...lines('a', 3), '{"b":0}', '{"b":1}', '{"b":2}']]);
  });
}

eachWay('a round with nothing new still makes a save that failed', async (t) => {
  t.add(...lines('a', 3));
  const u = t.uploader();
  await u.sync();
  mkdirSync(`${t.stateFile}.tmp`);
  t.add('{"b":0}');
  await assert.rejects(() => u.sync(), (e) => e.reason === 'state-not-saved');
  assert.deepEqual(onDisk(t), [3]);
  rmdirSync(`${t.stateFile}.tmp`);
  await u.sync();
  assert.equal(t.server.sent, 4);
  assert.deepEqual(onDisk(t), [4]);
});

test('a save that failed is made first, even while the recorder cannot be reached', async () => {
  const t = await ways.feed();
  let away = false;
  const client = { ...t.feed.client, books: async () => { if (away) throw Object.assign(new Error('not reached'), { reason: 'feed-unreachable' }); return t.feed.client.books(); } };
  t.add(...lines('a', 3));
  const u = t.uploader({ feed: client });
  await u.sync();
  mkdirSync(`${t.stateFile}.tmp`);
  t.add('{"b":0}');
  await assert.rejects(() => u.sync(), (e) => e.reason === 'state-not-saved');
  rmdirSync(`${t.stateFile}.tmp`);
  away = true;
  await assert.rejects(() => u.sync(), (e) => e.reason === 'feed-unreachable');
  assert.deepEqual(onDisk(t), [4]);
});

eachWay('the first save, made before any line, fails: no line is sent until it is made', async (t) => {
  mkdirSync(`${t.stateFile}.tmp`);
  t.add(...lines('a', 3));
  const u = t.uploader();
  for (let round = 0; round < 2; round++) {
    await assert.rejects(() => u.sync(), (e) => e.reason === 'state-not-saved');
    assert.equal(t.server.sent, 0);
  }
  rmdirSync(`${t.stateFile}.tmp`);
  await u.sync();
  assert.equal(t.server.sent, 3);
});

eachWay('a rename refused while a scanner holds the file is tried again a few times: a brief hold costs nothing, a long one fails the round', async (t) => {
  let calls = 0;
  let refusals = 2;
  const scanner = (real, ...given) => { calls++; if (refusals-- > 0) throw refused('EPERM'); return real(...given); };
  t.add(...lines('a', 3));
  const u = t.uploader();
  await u.sync();
  t.add('{"b":0}');
  await standingIn('renameSync', scanner, () => u.sync());
  assert.equal(calls, 3);
  assert.deepEqual(onDisk(t), [4]);
  calls = 0;
  refusals = Infinity;
  t.add('{"b":1}', '{"b":2}');
  await standingIn('renameSync', scanner, () => assert.rejects(() => u.sync(), (e) => e.reason === 'state-not-saved' && e.message.includes('EPERM')));
  assert.equal(calls, 5, 'the tries are bounded');
  assert.equal(t.server.sent, 5);
  assert.deepEqual(onDisk(t), [4]);
});

eachWay('a malformed state stops with state-unreadable, sends nothing and is left as it was', async (t) => {
  t.add(...lines('a', 3));
  await t.uploader().sync();
  t.add('{"b":0}');
  const good = JSON.parse(readFileSync(t.stateFile, 'utf8')).parts[0];
  const v3 = (parts, older = []) => JSON.stringify({ version: 3, parts, older });
  const shapes = [
    v3([]), v3([null]), v3([7]), v3([[]]), v3([{}]), v3(['book.jsonl']),
    v3([{ ...good, count: '3' }]), v3([{ ...good, count: -1 }]), v3([{ ...good, count: 2.5 }]), v3([{ ...good, count: undefined }]),
    v3([{ ...good, bytes: '24' }]), v3([{ ...good, bytes: 1.5 }]), v3([{ ...good, bytes: -1 }]),
    v3([{ ...good, start: '16' }]), v3([{ ...good, start: 1.5 }]), v3([{ ...good, start: -1 }]),
    v3([good, null]), v3([good], [null]), v3([good], [7]), v3([good], [[]]), v3([good], null),
    JSON.stringify({ version: 3, parts: [good] }),
    JSON.stringify({ version: 2, parts: [] }), JSON.stringify({ version: 2, parts: [null] }), JSON.stringify({ version: 2, parts: [{ ...good, count: '3' }] }),
    JSON.stringify({ version: 9, count: 3, last: good.last }), JSON.stringify({ version: 3, count: 3, last: good.last }),
    '{"count":-1}', '{"count":2.5}', '{"count":"3"}',
    'null', '[]', '3', '"x"', '﻿', '﻿﻿{"count":3}',
  ];
  for (const kept of shapes) {
    writeFileSync(t.stateFile, kept);
    await assert.rejects(() => t.uploader().sync(), (e) => e.reason === 'state-unreadable', kept);
    assert.equal(t.server.sent, 3, kept);
    assert.equal(readFileSync(t.stateFile, 'utf8'), kept);
  }
});

for (const way of Object.keys(ways)) {
  test(`every legal form of the state goes on from where it was, with a byte order mark or without (--${way})`, async () => {
    const forms = {
      'version 3': (p) => ({ version: 3, parts: [p], older: [] }),
      'version 3 with the stage-0 mark': (p) => ({ version: 3, parts: [p], older: [], stage0: true }),
      'version 2': ({ id, ...p }) => ({ version: 2, parts: [p] }),
      'version 2 with no place': ({ file, count, last }) => ({ version: 2, parts: [{ file, count, last }] }),
      'stage-0': ({ count, last }) => ({ count, last }),
    };
    for (const [name, form] of Object.entries(forms)) {
      for (const mark of ['', '﻿']) {
        const t = await ways[way]();
        t.add(...lines('a', 3));
        await t.uploader().sync();
        t.add('{"b":0}');
        writeFileSync(t.stateFile, `${mark}${JSON.stringify(form(JSON.parse(readFileSync(t.stateFile, 'utf8')).parts[0]))}`);
        for (let round = 0; round < 2; round++) await t.uploader().sync();
        assert.equal(t.server.sent, 4, name);
        assert.deepEqual(onDisk(t), [4], name);
      }
    }
    const first = await ways[way]();
    first.add(...lines('a', 3));
    await first.uploader().sync();
    assert.equal(first.server.sent, 3, 'no file: a first start');
  });
}

eachWay('a conflict says how many lines the server holds of the part and how many the state says, and that nothing is lost', async (t) => {
  t.add(...lines('a', 2));
  const u = t.uploader();
  await u.sync();
  const copy = readFileSync(t.stateFile);
  t.add(...lines('a', 3, 2));
  await u.sync();
  writeFileSync(t.stateFile, copy);
  await assert.rejects(() => t.uploader().sync(), (e) => {
    assert.equal(e.reason, 'conflict');
    assert.match(e.message, /the server holds 5 lines of part 0, and the state beside the book says 2, so this uploader stops/);
    assert.match(e.message, /Nothing is lost: the book stays on this computer/);
    return true;
  });
  assert.equal(t.server.sent, 5);
  // A refusal in a race for the place names no count: it still says what it means.
  const race = async () => { throw Object.assign(new Error('conflict'), { reason: 'conflict', serverMessage: { type: 'provared-append-failed', reason: 'conflict', detail: 'a line arrived at that place first' } }); };
  await assert.rejects(() => t.uploader({ append: race }).sync(), (e) => e.reason === 'conflict' && /already has a line at place 2 of part 0, and the state beside the book says 2/.test(e.message) && /Nothing is lost/.test(e.message));
});

test('a conflict in a later part names that part', async () => {
  const t = await ways.feed();
  t.add(...lines('a', 2));
  const u = t.uploader();
  await u.sync();
  t.feed.switchBook();
  await u.sync();
  const copy = readFileSync(t.stateFile);
  t.add(...lines('b', 3));
  await u.sync();
  writeFileSync(t.stateFile, copy);
  await assert.rejects(() => t.uploader().sync(), (e) => e.reason === 'conflict' && /the server holds 4 lines of part 1, and the state beside the book says 1, so this uploader stops/.test(e.message));
});

// --- the same, through the command ---

const upload = join(here, '..', 'upload.mjs');
/** Runs the command; ended after 20 seconds where it has not ended by itself, or one second after saying "until". */
const command = (args, until = null) => new Promise((resolve) => {
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', upload, ...args]);
  let err = '';
  let ended = false;
  const end = () => { ended = true; child.kill(); };
  const timer = setTimeout(end, 20000);
  child.stderr.on('data', (d) => { err += d; if (until && until.test(err)) { clearTimeout(timer); setTimeout(end, 1000); until = null; } });
  child.on('close', (code) => { clearTimeout(timer); resolve({ code, err, ended }); });
});
/** A folder with a connection file and a line of a book, as the command is given them; the server is not there. */
function commandFolder() {
  const dir = mkdtempSync(join(tmpdir(), 'provared-app-state-cli-'));
  const connection = join(dir, 'connection.json');
  writeFileSync(connection, JSON.stringify({ server: 'ws://127.0.0.1:1', origin: 'http://nowhere', namespace: NAMESPACE, objectId: crypto.randomUUID(), kObject: cc.toBase64Url(cc.generateSymmetricKey()), appendCapabilitySecret: cc.toBase64Url(cc.randomBytes(32)) }));
  writeFileSync(join(dir, 'feed-token'), `${'C'.repeat(43)}\n`);
  const book = join(dir, 'book.jsonl');
  writeFileSync(book, '{"a":0}\n');
  return { dir, connection, book, stateFile: `${book}.uploaded.json`, lock: `${book}.uploader.lock`, pid: `${book}.uploader.pid` };
}
const listing = { books: [{ book: 'book.jsonl', number: null, id: '9:1:1', inForce: true, bytes: 8 }], version: 0 };

for (const way of ['book', 'feed']) {
  test(`the command, --${way}: a garbled state stops --once and a long run, with exit code 1, the words, and the lock given back`, async () => {
    const s = await speaking('C'.repeat(43), (url) => (url.startsWith('/books') ? { code: 200, body: listing } : { code: 400, body: { error: 'no' } }));
    try {
      const f = commandFolder();
      writeFileSync(f.stateFile, '{"version":3,"par');
      const how = way === 'book' ? ['--book', f.book] : ['--feed', s.address, '--feed-token', join(f.dir, 'feed-token')];
      for (const more of [['--once'], []]) {
        const r = await command(['--connection', f.connection, ...how, ...more]);
        assert.equal(r.ended, false, 'it stopped by itself');
        // On Windows, a process that ends while the feed's connection is closing can crash after its exit handlers have run, in place of exit code 1 (a known fault, not of this test).
        const crashed = process.platform === 'win32' && r.code === 0xC0000409 && r.err.includes('UV_HANDLE_CLOSING');
        assert.ok(r.code === 1 || crashed, r.err);
        assert.match(r.err, /state-unreadable: the state kept beside the book/);
        assert.ok(r.err.includes(f.stateFile));
        assert.equal(existsSync(f.lock), false, 'its lock is given back');
        assert.equal(existsSync(f.pid), false);
        assert.equal(readFileSync(f.stateFile, 'utf8'), '{"version":3,"par');
      }
    } finally {
      await s.close();
    }
  });
}

test('the command: a state that cannot be opened fails --once with the code and gives the lock back; a long run does not stop for it', async () => {
  const f = commandFolder();
  mkdirSync(f.stateFile);
  const how = ['--connection', f.connection, '--book', f.book];
  const once = await command([...how, '--once']);
  assert.equal(once.code, 1, once.err);
  assert.match(once.err, /state-not-read: .*\(EISDIR\)/);
  assert.equal(existsSync(f.lock), false, 'its lock is given back');
  const run = await command(how, /state-not-read/);
  assert.equal(run.ended, true, 'it was still running, to try again');
  assert.match(run.err, /state-not-read: .*\(EISDIR\)/);
});
