// The uploader beside the recorder (upload.mjs), with a stand-in
// for the server on no network: how it follows a recorder that starts a new
// book file. The recorder beside Claude Code seals book.jsonl, renames it
// book-<n>.jsonl in the same folder, and starts book.jsonl again; a call
// allowed under the old file and finished after the switch is written into
// the kept file, which is then sealed again. Each step is done here to
// files in a folder of the test's own, as the recorder does it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createCryptoCore } from '@microtoll/crypto-core';
import { createUploader, holds, linesFrom, lockBook } from '../upload.mjs';
import { NAMESPACE, openEntry, sealEntry } from '../entry.mjs';

const cc = createCryptoCore({ namespace: NAMESPACE });
const quiet = { info() {}, error() {} };

/**
 * A stand-in for the server's append, with its rules: a place is the next
 * free one of its part ("conflict" or "gap" otherwise, naming the next
 * free place), and a part is begun only straight after the last one
 * ("part-gap"). crashAfter: the number of lines after which one more is
 * stored and the answer is lost, as when the uploader stops in between.
 */
function standIn() {
  const parts = [];
  const server = { parts, crashAfter: Infinity, sent: 0 };
  const fail = (reason, extra) => Object.assign(new Error(reason), { reason, serverMessage: { type: 'provared-append-failed', reason, ...extra } });
  server.append = async (msg) => {
    assert.equal(msg.type, 'provared-append');
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

/** A book, the connection to it, a stand-in server, and a folder that holds the recorder's files. */
async function setUp() {
  const dir = mkdtempSync(join(tmpdir(), 'provared-app-upload-'));
  const kObject = cc.generateSymmetricKey();
  const connection = { server: 'ws://nowhere', origin: 'http://nowhere', namespace: NAMESPACE, objectId: crypto.randomUUID(), kObject: cc.toBase64Url(kObject), appendCapabilitySecret: cc.toBase64Url(cc.randomBytes(32)) };
  const server = standIn();
  const key = await cc.importSymmetricKey(kObject);
  const book = join(dir, 'book.jsonl');
  const uploader = (more = {}) => createUploader({ connection, book, log: quiet, append: server.append, ...more });
  /** What the server holds, opened as the page opens it: one list of lines for each part. */
  const opened = async () => {
    const out = [];
    for (let p = 0; p < server.parts.length; p++) {
      out.push(await Promise.all(server.parts[p].map((s, seq) => openEntry(cc, key, connection.objectId, seq, cc.fromBase64Url(s), p))));
    }
    return out;
  };
  return { dir, book, server, key, connection, uploader, opened, file: (name) => join(dir, name) };
}

const lines = (prefix, n, from = 0) => Array.from({ length: n }, (_, i) => `{"${prefix}":${from + i}}`);
const write = (path, list) => writeFileSync(path, list.map((l) => `${l}\n`).join(''));
const add = (path, list) => appendFileSync(path, list.map((l) => `${l}\n`).join(''));

/** The recorder's switch, as it makes it: a seal added to book.jsonl, the file kept as book-<n>.jsonl, a new book.jsonl. */
function switchBook(t, n, first = lines('new', 1)) {
  add(t.book, [`{"seal":${n}}`]);
  renameSync(t.book, t.file(`book-${n}.jsonl`));
  if (first) write(t.book, first);
}

test('a sealed line of one part does not open as the same place of another part', async () => {
  const key = await cc.importSymmetricKey(cc.generateSymmetricKey());
  const id = crypto.randomUUID();
  const zero = await sealEntry(cc, key, id, 3, '{"a":1}');
  const one = await sealEntry(cc, key, id, 3, '{"a":1}', 1);
  assert.equal(await openEntry(cc, key, id, 3, zero), '{"a":1}');
  assert.equal(await openEntry(cc, key, id, 3, one, 1), '{"a":1}');
  await assert.rejects(() => openEntry(cc, key, id, 3, one));
  await assert.rejects(() => openEntry(cc, key, id, 3, zero, 1));
  await assert.rejects(() => openEntry(cc, key, id, 3, one, 2));
});

test('the lines of a file are read with where each is, an empty line and a carriage return set aside, a line still being written left for later', () => {
  const dir = mkdtempSync(join(tmpdir(), 'provared-app-lines-'));
  const path = join(dir, 'book.jsonl');
  writeFileSync(path, 'a\r\n\nbé\nc');
  const got = [...linesFrom(path)];
  assert.deepEqual(got.map((l) => l.text), ['a', 'bé']);
  assert.deepEqual(got.map((l) => [l.start, l.end]), [[0, 3], [4, 8]]);
  assert.deepEqual([...linesFrom(path, 8)], [], 'the line with no line break yet is not read');
  const sha = (x) => createHash('sha256').update(x).digest('base64url');
  assert.ok(holds(path, { count: 2, last: sha('bé'), start: 4, bytes: 8 }));
  assert.equal(holds(path, { count: 2, last: sha('a'), start: 4, bytes: 8 }), null);
  // A part kept by an earlier version knows only the count and the last fingerprint: the file is read to find it.
  assert.deepEqual(holds(path, { count: 2, last: sha('bé') }), { count: 2, last: sha('bé'), start: 4, bytes: 8 });
});

test('a switch: the kept file is found by what it holds, its seal uploaded into its part, the new book file uploaded as the next part', async () => {
  const t = await setUp();
  write(t.book, lines('old', 3));
  const u = t.uploader();
  assert.equal(await u.sync(), 3);
  switchBook(t, 1, lines('new', 2));
  assert.equal(await u.sync(), 2);
  assert.deepEqual(await t.opened(), [[...lines('old', 3), '{"seal":1}'], lines('new', 2)]);
  assert.deepEqual(u.parts(), [{ file: 'book-1.jsonl', count: 4 }, { file: 'book.jsonl', count: 2 }]);
  // Nothing new: nothing sent.
  const before = t.server.sent;
  await u.sync();
  assert.equal(t.server.sent, before);
});

test('late lines: a call allowed under the old file and finished after the switch, and the seal after it, go into its part', async () => {
  const t = await setUp();
  write(t.book, lines('old', 2));
  const u = t.uploader();
  await u.sync();
  switchBook(t, 1, lines('new', 1));
  await u.sync();
  // The late receipt, then the seal again, in the kept file; a new receipt in the book in force.
  add(t.file('book-1.jsonl'), ['{"late":0}', '{"seal":"again"}']);
  add(t.book, lines('new', 1, 1));
  await u.sync();
  assert.deepEqual(await t.opened(), [[...lines('old', 2), '{"seal":1}', '{"late":0}', '{"seal":"again"}'], lines('new', 2)]);
  // Followed for as long as it runs: a line much later still goes in.
  add(t.file('book-1.jsonl'), ['{"later":0}']);
  await u.sync();
  assert.equal((await t.opened())[0].at(-1), '{"later":0}');
});

test('a restart between the recorder keeping the old file and writing the new one, and between sending a line and remembering it', async () => {
  const t = await setUp();
  write(t.book, lines('old', 2));
  await t.uploader().sync();
  // The old file is kept, and there is no book file yet.
  switchBook(t, 1, null);
  assert.equal(existsSync(t.book), false);
  await t.uploader().sync();
  assert.deepEqual(t.uploader().parts(), [{ file: 'book-1.jsonl', count: 3 }, { file: 'book.jsonl', count: 0 }]);
  // The new book file is written; the uploader stops after the server took its second line and before it remembered it.
  write(t.book, lines('new', 3));
  t.server.crashAfter = t.server.sent + 1;
  await assert.rejects(() => t.uploader().sync(), /the connection closed/);
  assert.equal(JSON.parse(readFileSync(`${t.book}.uploaded.json`, 'utf8')).parts[1].count, 1);
  // Started again: the line already on the server is not sent twice.
  assert.equal(await t.uploader().sync(), 3);
  assert.deepEqual(await t.opened(), [[...lines('old', 2), '{"seal":1}'], lines('new', 3)]);
});

test('a state file kept by the uploader before parts carries on, and its first switch is followed', async () => {
  const t = await setUp();
  write(t.book, lines('old', 3));
  await t.uploader().sync();
  // The form the earlier version kept: a count and the last line's fingerprint.
  const s = JSON.parse(readFileSync(`${t.book}.uploaded.json`, 'utf8'));
  writeFileSync(`${t.book}.uploaded.json`, JSON.stringify({ count: s.parts[0].count, last: s.parts[0].last }));
  add(t.book, lines('old', 1, 3));
  assert.equal(await t.uploader().sync(), 4);
  switchBook(t, 1, lines('new', 1));
  assert.equal(await t.uploader().sync(), 1);
  assert.deepEqual(await t.opened(), [[...lines('old', 4), '{"seal":1}'], lines('new', 1)]);
});

test('a gap in the numbers, files kept before the connection, and two switches while the uploader was stopped', async () => {
  const t = await setUp();
  // The recorder's earlier record, kept before this book was connected: not uploaded.
  write(t.file('book-1.jsonl'), lines('before', 2));
  write(t.book, lines('a', 2));
  await t.uploader().sync();
  // The next kept file is numbered 3 (2 was moved away by the person).
  switchBook(t, 3, lines('b', 2));
  await t.uploader().sync();
  assert.deepEqual(t.uploader().parts().map((p) => p.file), ['book-3.jsonl', 'book.jsonl']);
  // Stopped; the recorder switches twice; started again.
  switchBook(t, 4, lines('c', 1));
  switchBook(t, 5, lines('d', 1));
  await t.uploader().sync();
  assert.deepEqual(await t.opened(), [
    [...lines('a', 2), '{"seal":3}'],
    [...lines('b', 2), '{"seal":4}'],
    [...lines('c', 1), '{"seal":5}'],
    lines('d', 1),
  ]);
  assert.deepEqual(t.uploader().parts().map((p) => p.file), ['book-3.jsonl', 'book-4.jsonl', 'book-5.jsonl', 'book.jsonl']);
});

test('a switch again before the new book file had any line on the server: the file kept since comes first', async () => {
  const t = await setUp();
  write(t.book, lines('a', 1));
  await t.uploader().sync();
  switchBook(t, 1, null);
  await t.uploader().sync();
  // The new book is begun and kept again while the uploader is stopped, before any of it was sent.
  write(t.book, lines('b', 1));
  switchBook(t, 2, lines('c', 1));
  await t.uploader().sync();
  assert.deepEqual(await t.opened(), [[...lines('a', 1), '{"seal":1}'], [...lines('b', 1), '{"seal":2}'], lines('c', 1)]);
});

test('a book file that holds none of the parts, with no kept file that does, is refused, and nothing is sent', async () => {
  const t = await setUp();
  write(t.book, lines('a', 3));
  write(t.file('book-1.jsonl'), lines('unrelated', 3));
  const u = t.uploader();
  await u.sync();
  const sent = t.server.sent;
  write(t.book, lines('rewritten', 4));
  await assert.rejects(() => u.sync(), /no longer holds the 3 lines already uploaded/);
  await assert.rejects(() => t.uploader().sync(), /no longer holds/);
  assert.equal(t.server.sent, sent);
  assert.equal(t.server.parts.length, 1);
});

test('a kept file changed after it was uploaded is no longer followed; the book in force goes on', async () => {
  const t = await setUp();
  const said = [];
  write(t.book, lines('a', 2));
  const u = createUploader({ connection: t.connection, book: t.book, log: { info() {}, error: (m) => said.push(m) }, append: t.server.append });
  await u.sync();
  switchBook(t, 1, lines('b', 1));
  await u.sync();
  write(t.file('book-1.jsonl'), lines('changed', 5));
  add(t.book, lines('b', 1, 1));
  await u.sync();
  await u.sync();
  assert.deepEqual(await t.opened(), [[...lines('a', 2), '{"seal":1}'], lines('b', 2)]);
  assert.equal(said.filter((m) => /no longer holds/.test(m)).length, 1, 'said once');
});

test('the stand-in keeps the server\'s rule: a part is begun only straight after the last one', async () => {
  const t = await setUp();
  const sealed = cc.toBase64Url(await sealEntry(cc, t.key, t.connection.objectId, 0, '{"x":1}', 2));
  await assert.rejects(() => t.server.append({ type: 'provared-append', part: 2, seq: 0, sealed }), (e) => e.reason === 'part-gap');
});

const SLIP = '{"slip":{"payload":"the-permission-in-force"}}';

test('a new book file that begins with the same bytes as the old is seen as new: by its identity, and on a file system without one, by preferring a kept file not yet seen that holds what was sent', async () => {
  for (const identities of [true, false]) {
    const t = await setUp();
    write(t.book, [SLIP]);
    const u = t.uploader({ identities });
    await u.sync();
    // Only the permission was sent; the recorder writes a receipt, seals, and starts a new book with the same permission.
    add(t.book, ['{"stub":"old"}']);
    switchBook(t, 1, [SLIP, '{"stub":"new"}']);
    await u.sync();
    assert.deepEqual(await t.opened(), [[SLIP, '{"stub":"old"}', '{"seal":1}'], [SLIP, '{"stub":"new"}']], `identities: ${identities}`);
  }
});

test('one open file for a whole round: a switch between two batches leaves the new file out of the old part', async () => {
  const t = await setUp();
  write(t.book, lines('x', 520));
  // During the first batch, the recorder switches.
  const append = t.server.append;
  let done = false;
  t.server.append = async (msg) => {
    const r = await append(msg);
    if (!done && msg.seq === 10) { done = true; switchBook(t, 1, lines('y', 600)); }
    return r;
  };
  const u = createUploader({ connection: t.connection, book: t.book, log: quiet, append: (m) => t.server.append(m) });
  await u.sync();
  await u.sync();
  const got = await t.opened();
  assert.deepEqual(got[0], [...lines('x', 520), '{"seal":1}']);
  assert.deepEqual(got[1], lines('y', 600));
});

test('a kept file\'s name used again: the earlier part is no longer read from it, and the name goes to the part it now holds, with and without identities', async () => {
  for (const identities of [true, false]) {
    const t = await setUp();
    write(t.book, lines('a', 2));
    const u = t.uploader({ identities });
    await u.sync();
    switchBook(t, 1, lines('b', 1));
    await u.sync();
    assert.deepEqual(u.parts().map((p) => p.file), ['book-1.jsonl', 'book.jsonl']);
    // The person moves book-1 away; the recorder's next kept file takes the name again.
    mkdirSync(t.file('archive'));
    renameSync(t.file('book-1.jsonl'), join(t.file('archive'), 'book-1.jsonl'));
    switchBook(t, 1, lines('c', 1));
    await u.sync();
    assert.deepEqual(u.parts().map((p) => p.file), [null, 'book-1.jsonl', 'book.jsonl'], `identities: ${identities}`);
    assert.deepEqual(await t.opened(), [[...lines('a', 2), '{"seal":1}'], [...lines('b', 1), '{"seal":1}'], lines('c', 1)], `identities: ${identities}`);
  }
});

test('without identities, the newest kept file that holds what was sent is taken, and an empty kept file never becomes a part', async () => {
  const t = await setUp();
  write(t.book, lines('a', 2));
  const u = t.uploader({ identities: false });
  await u.sync();
  // A copy of the old file under a lower number, the real kept file (with its seal) under a higher one, and an empty kept file after it.
  writeFileSync(t.file('book-1.jsonl'), readFileSync(t.book));
  add(t.book, ['{"seal":"real"}']);
  renameSync(t.book, t.file('book-2.jsonl'));
  writeFileSync(t.file('book-3.jsonl'), '');
  write(t.book, lines('b', 1));
  await u.sync();
  assert.deepEqual(await t.opened(), [[...lines('a', 2), '{"seal":"real"}'], lines('b', 1)]);
  assert.deepEqual(u.parts().map((p) => p.file), ['book-2.jsonl', 'book.jsonl']);
  // While the new part has no line on the server, an empty kept file is not put before it either.
  const s = await setUp();
  write(s.book, lines('a', 1));
  await s.uploader().sync();
  switchBook(s, 1, null);
  await s.uploader().sync();
  writeFileSync(s.file('book-2.jsonl'), '');
  write(s.book, lines('b', 1));
  await s.uploader().sync();
  assert.deepEqual(s.uploader().parts().map((p) => p.file), ['book-1.jsonl', 'book.jsonl']);
});

test('the last line sent must end with its line break where it was: a carriage return in its place is not the same file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'provared-app-lines-'));
  const path = join(dir, 'book.jsonl');
  writeFileSync(path, 'a\nb\n');
  const sha = (x) => createHash('sha256').update(x).digest('base64url');
  const part = { count: 2, last: sha('b'), start: 2, bytes: 4 };
  assert.ok(holds(path, part));
  writeFileSync(path, 'a\nb\r');
  assert.equal(holds(path, part), null);
});

test('"already on the server" is taken only for the first line of a round, and only where the server says the next free place is just after it', async () => {
  // The server already holds three lines the uploader has not remembered: not one line, so not taken.
  const t = await setUp();
  write(t.book, lines('a', 3));
  await t.uploader({ stateFile: `${t.book}.other.json` }).sync();
  await assert.rejects(() => t.uploader().sync(), (e) => e.reason === 'conflict');
  assert.deepEqual(t.uploader().parts(), [{ file: 'book.jsonl', count: 0 }], 'no line is marked as sent without being sent');
  // The first line of the round was on the server; then someone else adds the second before it is sent.
  const s = await setUp();
  write(s.book, lines('a', 1));
  await s.uploader({ stateFile: `${s.book}.other.json` }).sync();
  add(s.book, lines('a', 1, 1));
  const append = s.server.append;
  s.server.append = async (msg) => {
    try { return await append(msg); } catch (e) {
      if (msg.seq === 0) await append({ ...msg, seq: 1 });
      throw e;
    }
  };
  await assert.rejects(() => s.uploader({ append: (m) => s.server.append(m) }).sync(), (e) => e.reason === 'conflict');
});

test('against a server from before parts (it sets the part aside and names none), the first line of a new part stops the uploader, and nothing is written into part 0', async () => {
  const t = await setUp();
  const held = [];
  const fail = (reason, next) => Object.assign(new Error(reason), { reason, serverMessage: { type: 'provared-append-failed', reason, next } });
  const old = async (msg) => {
    if (msg.seq !== held.length) throw fail(msg.seq < held.length ? 'conflict' : 'gap', held.length);
    held.push(msg.sealed);
    return { type: 'provared-append-ok', seq: msg.seq };
  };
  // Part 0 with one line: the place the server says is next is the one after line 0 of part 1.
  write(t.book, lines('a', 1));
  await t.uploader({ append: old }).sync();
  switchBook(t, 1, lines('b', 2));
  await assert.rejects(() => t.uploader({ append: old }).sync(), /does not keep parts/);
  assert.equal(held.length, 2, 'part 0 and its seal; nothing of part 1');
  assert.deepEqual(t.uploader().parts().map((p) => p.count), [2, 0]);
  // The narrow case: part 0 holds exactly one line, so the next free place
  // that server names is the one just after line 0 of part 1. Its answer
  // names no part, and is not taken as line 0 of part 1.
  const s = await setUp();
  held.length = 0;
  write(s.book, lines('a', 1));
  await s.uploader({ append: old }).sync();
  renameSync(s.book, s.file('book-1.jsonl'));
  write(s.book, lines('b', 2));
  await assert.rejects(() => s.uploader({ append: old }).sync(), /does not keep parts/);
  assert.equal(held.length, 1, 'nothing of part 1 went into part 0');
  assert.deepEqual(s.uploader().parts().map((p) => p.count), [1, 0]);
});

test('one uploader at a time: a second, --once included, refuses while one runs; a lock left by a stopped process is taken over', () => {
  const t = mkdtempSync(join(tmpdir(), 'provared-app-lock-'));
  const book = join(t, 'book.jsonl');
  writeFileSync(book, '');
  const release = lockBook(book);
  assert.throws(() => lockBook(book), (e) => e.code === 'another-uploader');
  const connection = join(t, 'connection.json');
  writeFileSync(connection, JSON.stringify({ server: 'ws://127.0.0.1:9', origin: 'http://127.0.0.1:9', namespace: NAMESPACE, objectId: crypto.randomUUID(), kObject: cc.toBase64Url(cc.randomBytes(32)), appendCapabilitySecret: cc.toBase64Url(cc.randomBytes(32)) }));
  const run = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', fileURLToPath(new URL('../upload.mjs', import.meta.url)), '--connection', connection, '--book', book, '--once'], { encoding: 'utf8' });
  assert.equal(run.status, 1);
  assert.match(run.stderr, /another uploader \(process \d+\) is sending this book/);
  release();
  // A process that has stopped left its lock: it is taken over.
  const gone = spawnSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], { encoding: 'utf8' }).stdout;
  writeFileSync(`${book}.uploader.lock`, gone);
  const again = lockBook(book);
  assert.equal(readFileSync(`${book}.uploader.lock`, 'utf8'), String(process.pid));
  again();
  assert.equal(existsSync(`${book}.uploader.lock`), false);
});

test('the state is written forward only: an uploader whose state is behind the one on disk stops rather than write it back', async () => {
  const t = await setUp();
  write(t.book, lines('a', 1));
  const a = t.uploader();
  const b = t.uploader();
  await a.sync();
  b.parts(); // b reads the state now: one line sent
  add(t.book, lines('a', 2, 1));
  await a.sync(); // a sends two more
  // The recorder switches; b, behind, would write its part 0 back with one line.
  switchBook(t, 1, lines('b', 1));
  await assert.rejects(() => b.sync(), (e) => e.code === 'another-uploader');
  assert.equal(JSON.parse(readFileSync(`${t.book}.uploaded.json`, 'utf8')).parts[0].count, 3);
});

const sha = (x) => createHash('sha256').update(x).digest('base64url');

test('without identities, a copy of the book in force under a kept name (whole, or cut in the middle of a line) is not taken as the part\'s own file', async () => {
  for (const cut of [false, true]) {
    const t = await setUp();
    write(t.book, lines('a', 2));
    const u = t.uploader({ identities: false });
    await u.sync();
    // A backup tool leaves a copy beside the book under a name the recorder uses; the agent writes on.
    const whole = readFileSync(t.book);
    add(t.book, lines('a', 1, 2));
    writeFileSync(t.file('book-7.jsonl'), cut ? readFileSync(t.book).subarray(0, whole.length + 3) : whole);
    await u.sync();
    add(t.book, lines('a', 1, 3));
    await u.sync();
    assert.deepEqual(await t.opened(), [lines('a', 4)], `cut: ${cut}`);
    assert.deepEqual(u.parts().map((p) => p.file), ['book.jsonl'], `cut: ${cut}`);
  }
});

test('the stage-0 uploader meeting its first switch only when this version starts: the file kept before this run is found, where the book file does not hold the part', async () => {
  const t = await setUp();
  write(t.book, lines('a', 3));
  await t.uploader().sync();
  // As the stage-0 uploader left it: { count, last }, no identity.
  writeFileSync(`${t.book}.uploaded.json`, JSON.stringify({ count: 3, last: sha(lines('a', 3)[2]) }));
  // The recorder switched while that uploader was stopped (it would have stopped for good).
  switchBook(t, 1, lines('b', 1));
  await t.uploader().sync();
  assert.deepEqual(await t.opened(), [[...lines('a', 3), '{"seal":1}'], lines('b', 1)]);
  // A book kept before the connection that also begins with the same lines is never taken in this way
  // once the book file itself holds the part (the second review's N1 and N2, in review-parts-2).
});

test('a book file rewritten under a new identity stops the uploader with what to do; --same-book takes it on where it holds every line sent, and only there', async () => {
  const t = await setUp();
  write(t.book, lines('a', 2));
  await t.uploader().sync();
  // Saved by writing a new file and renaming it over the book, as some editors and backup tools do.
  write(`${t.book}.new`, lines('a', 3));
  renameSync(`${t.book}.new`, t.book);
  await assert.rejects(() => t.uploader().sync(), /it has a new identity.*some editors and backup tools.*run the uploader once with --same-book/s);
  assert.equal(await t.uploader({ sameBook: true }).sync(), 3);
  assert.deepEqual(await t.opened(), [lines('a', 3)]);
  // Rewritten again, now without the lines already sent: --same-book still refuses.
  write(`${t.book}.new`, lines('z', 4));
  renameSync(`${t.book}.new`, t.book);
  await assert.rejects(() => t.uploader({ sameBook: true }).sync(), /does not hold every line already uploaded/);
  assert.deepEqual(await t.opened(), [lines('a', 3)]);
});

test('--same-book compares every byte sent, by the fingerprint kept of them: an earlier line changed to another of the same length is refused', async () => {
  const t = await setUp();
  write(t.book, ['{"stub":"a"}', '{"stub":"b"}', '{"stub":"c"}']);
  await t.uploader().sync();
  assert.match(JSON.parse(readFileSync(`${t.book}.uploaded.json`, 'utf8')).parts[0].sha, /^[A-Za-z0-9_-]{43}$/);
  // The second line changed, the last line sent at the same byte place.
  write(`${t.book}.new`, ['{"stub":"a"}', '{"stub":"X"}', '{"stub":"c"}', '{"stub":"d"}']);
  renameSync(`${t.book}.new`, t.book);
  await assert.rejects(() => t.uploader({ sameBook: true }).sync(), /--same-book would refuse it: this file does not hold every line already uploaded/);
  assert.deepEqual(await t.opened(), [['{"stub":"a"}', '{"stub":"b"}', '{"stub":"c"}']]);
  // The same change made in place (the same file): seen when the uploader next starts, by the same fingerprint.
  const s = await setUp();
  write(s.book, ['{"stub":"a"}', '{"stub":"b"}']);
  await s.uploader().sync();
  write(s.book, ['{"stub":"X"}', '{"stub":"b"}', '{"stub":"c"}']);
  await assert.rejects(() => s.uploader().sync(), /no longer holds the 2 lines already uploaded/);
  assert.deepEqual(await s.opened(), [['{"stub":"a"}', '{"stub":"b"}']]);
});

test('--same-book is refused where the only line sent is the permission: every new book begins with it, so the program\'s own advice would lose the kept book', async () => {
  const t = await setUp();
  write(t.book, [SLIP]);
  await t.uploader().sync();
  // A real switch, with the kept book moved away before the uploader looked.
  add(t.book, ['{"stub":"old-1"}']);
  switchBook(t, 1, [SLIP, '{"stub":"new-1"}']);
  mkdirSync(t.file('away'));
  renameSync(t.file('book-1.jsonl'), join(t.file('away'), 'book-1.jsonl'));
  await assert.rejects(() => t.uploader().sync(), (e) => /--same-book cannot be used here: the only line sent is the permission/.test(e.message) && !/run the uploader once with --same-book/.test(e.message));
  await assert.rejects(() => t.uploader({ sameBook: true }).sync(), /the only line sent is the permission, and every new book begins with that same line/);
  assert.deepEqual(await t.opened(), [[SLIP]], 'nothing of the new book went into the old part');
  // Put back, the kept book is found, and all of it arrives.
  renameSync(join(t.file('away'), 'book-1.jsonl'), t.file('book-1.jsonl'));
  await t.uploader().sync();
  assert.deepEqual(await t.opened(), [[SLIP, '{"stub":"old-1"}', '{"seal":1}'], [SLIP, '{"stub":"new-1"}']]);
});

test('--same-book cannot be used for a state kept by an earlier version (no fingerprint of every byte sent), and says so', async () => {
  const t = await setUp();
  write(t.book, lines('a', 2));
  await t.uploader().sync();
  writeFileSync(`${t.book}.uploaded.json`, JSON.stringify({ count: 2, last: sha(lines('a', 2)[1]) }));
  // Sends one more line under this version: the part still has no fingerprint, since its first bytes were not sent by it.
  add(t.book, lines('a', 1, 2));
  await t.uploader().sync();
  assert.equal(JSON.parse(readFileSync(`${t.book}.uploaded.json`, 'utf8')).parts[0].sha, undefined);
  write(`${t.book}.new`, lines('a', 4));
  renameSync(`${t.book}.new`, t.book);
  await assert.rejects(() => t.uploader({ sameBook: true }).sync(), /--same-book cannot be used here: the state beside the book was kept by an earlier version/);
});
