// The feed: the book's lines, for a reader on this computer (the
// application's uploader), on the recorder's own port. The reader asks the
// recorder, and never opens a book file: two programs touching one file
// was fragile on Windows (on 11 October 2026 a reader holding book.jsonl
// open made the recorder's rename of it fail, and seven receipts were
// lost).
//
//   GET /hello                      the start of a conversation (below)
//   GET /books                      the books, oldest first, the one in force last
//   GET /lines?from=<n>             the lines of the book in force from place n on
//   GET /lines?id=<id>&from=<n>     the lines of the book with that identity
//   GET /lines?book=<name>&from=<n> the lines of the book of that name (book.jsonl, book-<n>.jsonl)
//     &wait=<seconds>               where the book holds no line at place n yet, wait up to this
//                                   long (0 to 25; 25 where it is not given) for anything to change
//     &max=<lines>                  at most this many lines (0 to 500; 500 where it is not given):
//                                   0 asks only for the line before place n, the size and the last
//
// THE TOKEN NEVER TRAVELS. The recorder writes a token into its folder at
// its first start (feed-token). A reader that holds it opens a
// conversation: it sends a random number of its own (Provared-Feed-Hello);
// the recorder answers with a random number of its own (the session) and
// HMAC-SHA-256, keyed by the token, over both: the recorder's proof that it
// knows the token. Only then does the reader trust anything it is told.
// Both sides then work out the conversation's key, HMAC-SHA-256 keyed by
// the token over both numbers under another label. Each question carries
// the session, a random number used once (Provared-Feed-Nonce), and an
// HMAC under that key over the question (Provared-Feed-Proof): the reader's
// proof that it knows the token; it carries the reader's own number again
// (Provared-Feed-Hello), because the hello keeps nothing (below), and the
// recorder works the conversation out again from it at the first proved
// question. Each answer carries an HMAC under the same
// key over the question's number, the answer's code and every byte of the
// answer: so an answer is the recorder's, and is the answer to that
// question. Every proof is compared in constant time. So a program that
// listens on the recorder's address while the recorder is stopped learns
// nothing, and nothing it says is taken; a program that cannot read the
// recorder's folder cannot read the book through the feed.
//
// A book is named by its identity: the volume, the number the file system
// gives its file, and the file's creation time, which a rename keeps. So the
// book in force keeps its identity when the recorder keeps it as
// book-<n>.jsonl, and a reader that asks by identity goes on reading the
// same book, wherever it now is. The application's uploader reckons a
// file's identity in the same way, so a book it read as a file before is
// the same book through the feed. Where the file system gives no number,
// the identity is null and a book is named by its file name only.
//
// Lines are counted as the uploader and the checker count them: the text
// between two line breaks, without a carriage return before the break; an
// empty line is passed over; a line with no line break yet is not a line.
// Byte places are those of the file. The books the recorder holds open
// (the one in force, and a kept one that a call allowed under it may still
// come back to) are read from the recorder's own copy in memory, but only
// as far as the recorder has written it to the file; a kept book it no
// longer writes is read from its file, a piece at a time, and the file is
// closed again before anything else is done.
//
// One answer is made at a time, with a pause between two so that the
// hook's questions are answered in between, and at most a few are taken
// on at once: one more is told to ask again (429). So the hook waits for at
// most the making of one answer, and, besides, for the reading of whatever
// questions arrive meanwhile: each refused or answered question still costs
// the recorder about a thousandth of a second to read and check, so very
// many at once (thousands, from one program) do hold the hook up, in
// proportion to their number.

import nodeCrypto from 'node:crypto';
import { closeSync, fstatSync, openSync, readdirSync, readFileSync, readSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const FEED_TOKEN = 'feed-token';
/** At most this many lines in one answer, and at most this many bytes of them (but always one line). */
export const FEED_MAX_LINES = 500;
export const FEED_MAX_BYTES = 4 * 1024 * 1024;
/** The longest a request waits for something new, in seconds. */
export const FEED_MAX_WAIT = 25;
/** At most this many requests wait at once; one more is answered at once with "429". */
export const FEED_MAX_WAITING = 8;
/** At most this many answers are taken on (being made, or waiting their turn to be made); one more is answered at once with "429". */
export const FEED_MAX_BUSY = 16;
/**
 * At most this many conversations are kept at once, each from its first
 * proved question (the one used longest ago gives way); each is ended after
 * this long unused. A hello keeps nothing.
 */
export const FEED_MAX_SESSIONS = 16;
export const FEED_SESSION_IDLE_MS = 10 * 60 * 1000;
/** A conversation must have its first proved question within this long of its hello. */
export const FEED_HELLO_MS = 10 * 60 * 1000;
/** A conversation takes at most this many questions; then the reader opens another. */
export const FEED_SESSION_QUESTIONS = 100000;

// The labels of the HMACs: each proof is of one kind only. The last is the
// recorder's own, for the number it gives a conversation, and no reader needs it.
export const FEED_LABELS = Object.freeze({
  recorder: 'provared feed v1: the recorder knows the token',
  key: 'provared feed v1: the key of a conversation',
  question: 'provared feed v1: a question',
  answer: 'provared feed v1: an answer',
  session: 'provared feed v1: the recorder\'s number for a conversation',
});

const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const RANDOM = /^[A-Za-z0-9_-]{43}$/;
/**
 * Whether a value is 32 bytes written in base64url in the one way they can
 * be written. The last of the 43 characters carries two bits that no byte
 * uses, so each 32 bytes could be written four ways; a value whose bytes,
 * written again, do not give back the same text is refused, so that one
 * session, number used once or proof cannot be given under another
 * spelling (and a conversation that has ended be begun again).
 */
export function isRandom(value) {
  return typeof value === 'string' && RANDOM.test(value) && Buffer.from(value, 'base64url').toString('base64url') === value;
}
// eslint-disable-next-line security/detect-unsafe-regex -- the number has at most nine digits, so the text it can match is short and bounded.
const BOOK_NAME = /^book(?:-[1-9][0-9]{0,8})?\.jsonl$/;
const KEPT_NAME = /^book-([1-9][0-9]{0,8})\.jsonl$/;
const PIECE = 4 * 1024 * 1024;
// The highest place a reader may ask for: more than any book holds.
const HIGHEST_PLACE = 2 ** 31 - 1;

const sha256 = (text) => nodeCrypto.createHash('sha256').update(text).digest('base64url');

/** HMAC-SHA-256 under a key, over a label and parts, each after a line break. */
export function feedHmac(key, label, ...parts) {
  const h = nodeCrypto.createHmac('sha256', key);
  h.update(label);
  for (const p of parts) {
    h.update('\n');
    h.update(p);
  }
  return h.digest();
}

/** Whether a proof given in base64url is the one expected, compared in constant time. */
export function sameProof(given, expected) {
  if (!isRandom(given)) return false;
  const bytes = Buffer.from(given, 'base64url');
  return bytes.length === expected.length && nodeCrypto.timingSafeEqual(bytes, expected);
}

/**
 * The feed's token, from the folder: made at the first start (32 random
 * bytes, in base64url), and read as it is after that. A file that does not
 * hold a token in that form is not replaced (it may be the person's), and
 * the feed then refuses every request and says why.
 * @returns {{path: string, token: string|null, problem: string|null}}
 */
export function feedToken(folder) {
  const path = join(folder, FEED_TOKEN);
  const made = nodeCrypto.randomBytes(32).toString('base64url');
  try {
    // "wx": made only where there is none, so that two starts at once cannot write two tokens.
    writeFileSync(path, `${made}\n`, { flag: 'wx', mode: 0o600 });
    return { path, token: made, problem: null };
  } catch (e) {
    if (e.code !== 'EEXIST') return { path, token: null, problem: `the token file ${path} could not be written: ${e.message}` };
  }
  let text = '';
  try {
    text = readFileSync(path, 'utf8').trim();
  } catch (e) {
    return { path, token: null, problem: `the token file ${path} could not be read: ${e.message}` };
  }
  if (!TOKEN.test(text)) return { path, token: null, problem: `the token file ${path} does not hold a token (43 letters, digits, "-" and "_"), so the feed refuses every request. Move it out of the folder, and the recorder makes a new one at its next start.` };
  return { path, token: text, problem: null };
}

/**
 * A file's identity, reckoned as the application's uploader reckons it
 * (connector/upload.mjs, identityOf): the volume, the number the file
 * system gives the file, and its creation time. null where the file system
 * gives no number.
 */
export function identityOf(stat) {
  if (!stat || stat.ino === undefined || stat.ino === 0n || stat.ino === 0) return null;
  return `${stat.dev}:${stat.ino}:${stat.birthtimeNs ?? stat.birthtimeMs}`;
}

function lookAt(path) {
  try {
    const st = statSync(path, { bigint: true });
    return { id: identityOf(st), size: Number(st.size) };
  } catch {
    return null;
  }
}

/**
 * Where the lines of a book the recorder holds in memory are, found once
 * each, as far as "limit" (the characters the recorder has written to the
 * file): where each line's text starts and ends (as characters), and where
 * the line starts and where the next one starts (as bytes, the places in
 * the file). The text only grows; where it does not go on from what was
 * read (the recorder opened the book again), it is read again from its
 * start.
 */
export function memoryIndex() {
  const ix = {};
  const reset = () => Object.assign(ix, { seen: 0, bytes: 0, tail: '', cs: [], ce: [], bs: [], be: [] });
  reset();
  ix.extend = (text, limit = text.length) => {
    if (text.length < ix.seen || text.slice(Math.max(0, ix.seen - 64), ix.seen) !== ix.tail) reset();
    let at = ix.seen;
    for (let end = text.indexOf('\n', at); end >= 0 && end < limit; end = text.indexOf('\n', at)) {
      const length = Buffer.byteLength(text.slice(at, end + 1));
      const textEnd = end > at && text.charCodeAt(end - 1) === 13 ? end - 1 : end;
      if (textEnd > at) {
        ix.cs.push(at);
        ix.ce.push(textEnd);
        ix.bs.push(ix.bytes);
        ix.be.push(ix.bytes + length);
      }
      ix.bytes += length;
      at = end + 1;
    }
    ix.seen = at;
    ix.tail = text.slice(Math.max(0, at - 64), at);
  };
  return ix;
}

/**
 * Where the lines of a file are, found by reading it from where the index
 * last stopped (always the start of a line, or of a line not yet ended), a
 * piece of 4 MiB at a time, with the file closed and a pause between
 * pieces. null where the file is not there, or is another file than the
 * one named by "id".
 */
export async function diskIndex(path, id, ix = { scanned: 0, bs: [], be: [] }) {
  let lineStart = ix.scanned;
  let at = ix.scanned;
  let before = -1; // the byte before the piece's first one, where it is in the same line
  const stop = () => {
    // A line not yet ended is read again from its start next time.
    ix.scanned = lineStart;
    return ix;
  };
  for (;;) {
    let fd;
    try { fd = openSync(path, 'r'); } catch { return null; }
    let piece;
    let got = 0;
    let size;
    try {
      const st = fstatSync(fd, { bigint: true });
      if (identityOf(st) !== id) return null;
      size = Number(st.size);
      if (at >= size) return stop();
      piece = Buffer.alloc(Math.min(PIECE, size - at));
      got = readSync(fd, piece, 0, piece.length, at);
    } finally {
      closeSync(fd);
    }
    if (got === 0) return stop();
    for (let i = piece.indexOf(10); i !== -1 && i < got; i = piece.indexOf(10, i + 1)) {
      const lineEnd = at + i + 1;
      let textBytes = lineEnd - 1 - lineStart;
      const returnBefore = i > 0 ? piece[i - 1] === 13 : before === 13;
      if (textBytes > 0 && returnBefore) textBytes--;
      if (textBytes > 0) {
        ix.bs.push(lineStart);
        ix.be.push(lineEnd);
      }
      lineStart = lineEnd;
    }
    before = piece[got - 1];
    at += got;
    if (at >= size) return stop();
    await new Promise((r) => setImmediate(r));
  }
}

function lineFromBytes(buf) {
  let text = buf.toString('utf8');
  if (text.endsWith('\n')) text = text.slice(0, -1);
  if (text.endsWith('\r')) text = text.slice(0, -1);
  return text;
}

/**
 * The feed of one recorder's folder.
 * @param {{folder: string, memory: () => {key: number, path: string, text: () => string, saved?: () => number, inForce: boolean}[], token: {token: string|null, problem: string|null, path: string}, now?: () => number}} o
 *   memory: the books the recorder holds open, asked each time; key names one book for as long as
 *   the recorder holds it, wherever its file now is; saved gives how many characters of its text the
 *   recorder has written to the file (all of it where not given); now, sessionQuestions and maxBusy are
 *   for the tests (the clock, FEED_SESSION_QUESTIONS and FEED_MAX_BUSY by default)
 */
export function createFeed({ folder, memory, token, now = Date.now, sessionQuestions = FEED_SESSION_QUESTIONS, maxBusy = FEED_MAX_BUSY }) {
  let version = 0;
  let waiting = new Set();
  let closed = false;
  // By the recorder's own book (its key), not by its file's name, which the book in force gives up when it is kept.
  const memoryIndexes = new Map();
  const diskIndexes = new Map();
  const ids = new Map();
  const sessions = new Map();
  // One answer is made at a time; "busy" counts those taken on.
  let busy = 0;
  let turn = Promise.resolve();
  const oneAtATime = (work) => {
    const run = turn.then(work);
    // A pause after each answer, so that whatever else waits (the hook's questions) is answered in between.
    turn = run.then(() => new Promise((r) => setImmediate(r)), () => new Promise((r) => setImmediate(r)));
    return run;
  };

  /** Something was written, or a book was kept: every waiting request is answered. */
  function changed() {
    version++;
    const all = waiting;
    waiting = new Set();
    for (const wake of all) wake();
  }

  function indexFor(m) {
    let ix = memoryIndexes.get(m.key);
    if (!ix) memoryIndexes.set(m.key, (ix = memoryIndex()));
    const text = m.text();
    ix.extend(text, Math.min(text.length, m.saved ? m.saved() : text.length));
    return ix;
  }

  /** The books, oldest first, the one in force last: {book, number, id, inForce, bytes, held}. */
  function listing() {
    const held = new Map(memory().map((m) => [m.path, m]));
    const keys = new Set([...held.values()].map((m) => m.key));
    for (const key of memoryIndexes.keys()) if (!keys.has(key)) memoryIndexes.delete(key);
    for (const key of ids.keys()) if (!keys.has(key)) ids.delete(key);
    let names = [];
    try { names = readdirSync(folder); } catch { /* no folder */ }
    const kept = names.flatMap((name) => {
      const m = KEPT_NAME.exec(name);
      return m ? [{ book: name, number: Number(m[1]) }] : [];
    }).sort((a, b) => a.number - b.number);
    const inForce = [...held.values()].some((m) => m.inForce);
    const all = [...kept, ...(inForce ? [{ book: 'book.jsonl', number: null }] : [])];
    return all.flatMap((b) => {
      const path = join(folder, b.book);
      const m = held.get(path);
      const seen = lookAt(path);
      if (m) {
        // The identity of the file it is written to: kept from the last look where the file cannot be looked at now.
        if (seen) ids.set(m.key, seen.id);
        return [{ book: b.book, number: b.number, id: ids.get(m.key) ?? null, inForce: m.inForce, bytes: indexFor(m).bytes, held: m }];
      }
      if (!seen) return [];
      return [{ book: b.book, number: b.number, id: seen.id, inForce: false, bytes: seen.size, held: null }];
    });
  }
  const publicEntry = ({ held, ...rest }) => rest;

  /**
   * A way to read one book: {count, bytes, bs, be, lines(from, to)}; bs
   * and be are where each line starts, and where the next one starts, in
   * bytes. null where it cannot be read now.
   */
  async function source(entry) {
    if (entry.held) {
      const ix = indexFor(entry.held);
      const text = entry.held.text();
      return {
        count: ix.cs.length, bytes: ix.bytes, bs: ix.bs, be: ix.be,
        lines: (from, to) => Array.from({ length: to - from }, (_, i) => ({ text: text.slice(ix.cs[from + i], ix.ce[from + i]), start: ix.bs[from + i], end: ix.be[from + i] })),
      };
    }
    const path = join(folder, entry.book);
    const key = `${path}\n${entry.id}`;
    const seen = lookAt(path);
    if (!seen || seen.id !== entry.id) return null;
    let ix = diskIndexes.get(key);
    // A file shorter than what was read of it is read again from its start; a longer one from where it was left.
    if (!ix || seen.size < ix.scanned) ix = await diskIndex(path, entry.id);
    else if (seen.size > ix.scanned) ix = await diskIndex(path, entry.id, ix);
    if (!ix) return null;
    diskIndexes.delete(key);
    diskIndexes.set(key, ix);
    if (diskIndexes.size > 16) diskIndexes.delete(diskIndexes.keys().next().value);
    return {
      count: ix.bs.length, bytes: ix.be.length ? ix.be.at(-1) : 0, bs: ix.bs, be: ix.be,
      lines: (from, to) => {
        const start = ix.bs[from];
        const buf = Buffer.alloc(ix.be[to - 1] - start);
        const fd = openSync(path, 'r');
        try {
          if (identityOf(fstatSync(fd, { bigint: true })) !== entry.id) throw new Error('the book changed while it was read');
          readSync(fd, buf, 0, buf.length, start);
        } finally {
          closeSync(fd);
        }
        return Array.from({ length: to - from }, (_, i) => ({ text: lineFromBytes(buf.subarray(ix.bs[from + i] - start, ix.be[from + i] - start)), start: ix.bs[from + i], end: ix.be[from + i] }));
      },
    };
  }

  function answer(entry, src, from, list, max) {
    let lines = [];
    if (from < src.count && max > 0) {
      // At most "max" lines and FEED_MAX_BYTES bytes, and always one line.
      let to = from + 1;
      while (to < src.count && to - from < max && src.be[to] - src.bs[from] <= FEED_MAX_BYTES) to++;
      lines = src.lines(from, to);
    }
    const before = from > 0 && from <= src.count ? src.lines(from - 1, from)[0] : null;
    const last = src.count > 0 ? src.lines(src.count - 1, src.count)[0] : null;
    return {
      book: entry.book,
      id: entry.id,
      inForce: entry.inForce,
      from,
      lines: lines.map((l) => l.text),
      starts: lines.map((l) => l.start),
      ends: lines.map((l) => l.end),
      previous: before ? { fingerprint: sha256(before.text), start: before.start, end: before.end } : null,
      size: src.count,
      bytes: src.bytes,
      last: last ? sha256(last.text) : null,
      books: list.map(publicEntry),
      version,
    };
  }

  function find(list, { id, book }) {
    if (id !== undefined) return list.find((b) => b.id !== null && b.id === id) ?? null;
    if (book !== undefined) return list.find((b) => b.book === book) ?? null;
    return list.find((b) => b.inForce) ?? null;
  }

  /** An answer with no proof: before a conversation is open, or where it could not be. */
  const plain = (res, code, body, more = {}) => {
    if (res.writableEnded || res.destroyed) return true;
    res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...more });
    res.end(JSON.stringify(body));
    return true;
  };

  /** An answer in a conversation: with the recorder's proof over the question's number, its code and every byte. */
  const proved = (res, talk, code, body, more = {}) => {
    if (res.writableEnded || res.destroyed) return true;
    const bytes = Buffer.from(JSON.stringify(body));
    const proof = feedHmac(talk.key, FEED_LABELS.answer, talk.session, talk.nonce, String(code), bytes).toString('base64url');
    res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Provared-Feed-Proof': proof, ...more });
    res.end(bytes);
    return true;
  };

  // THE HELLO STORES NOTHING. The recorder's number for a conversation (the
  // session) is the time of the hello and an HMAC over that time and the
  // reader's number, under a secret only this running recorder holds; so a
  // program without the token can ask for as many hellos as it likes and
  // nothing is kept, and nothing it does can push out a conversation in use.
  // A conversation is kept only from its first question that carries the
  // reader's proof (which needs the token), and must begin within
  // FEED_HELLO_MS of its hello. Only conversations so proved compete for the
  // FEED_MAX_SESSIONS places, the one used longest ago giving way; one also
  // ends after FEED_SESSION_IDLE_MS unused, or after its questions run out.
  // An ended conversation is remembered (only while its hello could still
  // be taken), so that it cannot be begun again and its questions asked
  // again.
  const secret = nodeCrypto.randomBytes(32);
  const ended = new Map();
  const sessionNumber = (theirs, time) => {
    const t = Buffer.alloc(8);
    t.writeBigUInt64BE(BigInt(time));
    return Buffer.concat([t, feedHmac(secret, FEED_LABELS.session, theirs, t).subarray(0, 24)]).toString('base64url');
  };
  const endConversation = (session) => {
    sessions.delete(session);
    ended.set(session, now());
  };

  function hello(req, res) {
    const theirs = req.headers['provared-feed-hello'];
    if (!isRandom(theirs)) return plain(res, 400, { error: 'a conversation begins with a random number of 32 bytes, in base64url, in Provared-Feed-Hello' });
    const session = sessionNumber(theirs, now());
    return plain(res, 200, { session, proof: feedHmac(Buffer.from(token.token), FEED_LABELS.recorder, theirs, session).toString('base64url') });
  }

  /**
   * The conversation a question belongs to, checked: {session, nonce, key},
   * or an answer already sent. Nothing is kept for a question whose proof
   * does not check.
   */
  function conversation(req, res) {
    const session = req.headers['provared-feed-session'];
    const theirs = req.headers['provared-feed-hello'];
    const nonce = req.headers['provared-feed-nonce'];
    const given = req.headers['provared-feed-proof'];
    const time = now();
    for (const [s, at] of ended) if (time - at > FEED_HELLO_MS) ended.delete(s);
    const unknown = () => {
      plain(res, 401, { error: 'the feed knows no such conversation: begin one with GET /hello', renew: true });
      return null;
    };
    if (!isRandom(session)) return unknown();
    let v = sessions.get(session);
    if (v && time - v.used > FEED_SESSION_IDLE_MS) {
      endConversation(session);
      return unknown();
    }
    let key = v?.key;
    if (!v) {
      // Not yet kept: one this recorder began, from this reader's number, recently, and not ended.
      if (ended.has(session) || !isRandom(theirs)) return unknown();
      const begun = Number(Buffer.from(session, 'base64url').readBigUInt64BE(0));
      if (!(time - begun >= 0 && time - begun <= FEED_HELLO_MS) || !sameProof(session, Buffer.from(sessionNumber(theirs, begun), 'base64url'))) return unknown();
      key = feedHmac(Buffer.from(token.token), FEED_LABELS.key, theirs, session);
    }
    if (!isRandom(nonce) || !sameProof(given, feedHmac(key, FEED_LABELS.question, session, nonce, `${req.method} ${req.url}`))) {
      plain(res, 401, { error: `the question does not carry the proof that its reader knows the token in the recorder's folder (${FEED_TOKEN})` }, { 'WWW-Authenticate': 'Provared-Feed' });
      return null;
    }
    if (!v) {
      // Proved: kept from now on. Only proved conversations give way to one another.
      while (sessions.size >= FEED_MAX_SESSIONS) endConversation(sessions.keys().next().value);
      v = { key, used: time, nonces: new Set() };
      sessions.set(session, v);
    }
    if (v.nonces.has(nonce)) {
      plain(res, 401, { error: 'this question was asked before: each is asked once' });
      return null;
    }
    if (v.nonces.size >= sessionQuestions) {
      endConversation(session);
      plain(res, 401, { error: 'the conversation has taken all the questions it may: begin another with GET /hello', renew: true });
      return null;
    }
    v.nonces.add(nonce);
    v.used = time;
    // The one used last goes to the end, so that the one used longest ago gives way first.
    sessions.delete(session);
    sessions.set(session, v);
    return { session, nonce, key };
  }

  /**
   * Answer a request if it is the feed's; gives back whether it was.
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   */
  async function handle(req, res) {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname !== '/hello' && url.pathname !== '/books' && url.pathname !== '/lines') return false;
    if (req.method !== 'GET') return plain(res, 405, { error: 'the feed answers GET only' });
    if (token.problem || !token.token) return plain(res, 503, { error: `the feed is off: ${token.problem ?? 'it has no token'}` });
    if (url.pathname === '/hello') return hello(req, res);
    const talk = conversation(req, res);
    if (!talk) return true;
    const send = (code, body, more) => proved(res, talk, code, body, more);

    const known = url.pathname === '/books' ? [] : ['from', 'id', 'book', 'wait', 'max'];
    for (const name of new Set(url.searchParams.keys())) {
      if (!known.includes(name)) return send(400, { error: `the feed does not know "${name}"${known.length ? `; it takes ${known.join(', ')}` : ''}` });
      if (url.searchParams.getAll(name).length > 1) return send(400, { error: `"${name}" is given more than once` });
    }
    // "always": a question that has waited is answered in its turn, however busy the feed is (at most FEED_MAX_WAITING of them).
    const take = async (work, always = false) => {
      if (busy >= maxBusy && !always) return send(429, { error: `${maxBusy} answers are being made already; ask again in a moment` }, { 'Retry-After': '1' });
      busy++;
      try {
        return await oneAtATime(work);
      } finally {
        busy--;
      }
    };
    if (url.pathname === '/books') return take(() => send(200, { books: listing().map(publicEntry), version }));

    const whole = (name, fallback, highest) => {
      const text = url.searchParams.get(name);
      if (text === null) return fallback;
      if (!/^(0|[1-9][0-9]{0,9})$/.test(text) || Number(text) > highest) return undefined;
      return Number(text);
    };
    const from = whole('from', 0, HIGHEST_PLACE);
    const wait = whole('wait', FEED_MAX_WAIT, FEED_MAX_WAIT);
    const max = whole('max', FEED_MAX_LINES, FEED_MAX_LINES);
    if (from === undefined) return send(400, { error: `"from" must be a whole number from 0 to ${HIGHEST_PLACE}` });
    if (wait === undefined) return send(400, { error: `"wait" must be a whole number of seconds from 0 to ${FEED_MAX_WAIT}` });
    if (max === undefined) return send(400, { error: `"max" must be a whole number from 0 to ${FEED_MAX_LINES}` });
    const which = {};
    if (url.searchParams.has('id')) {
      which.id = url.searchParams.get('id');
      if (url.searchParams.has('book')) return send(400, { error: 'name a book by "id" or by "book", not both' });
    } else if (url.searchParams.has('book')) {
      which.book = url.searchParams.get('book');
      if (!BOOK_NAME.test(which.book)) return send(400, { error: '"book" must be book.jsonl or book-<n>.jsonl' });
    }

    // Look, and answer at once unless the question must wait; the answer is made in its turn.
    const attempt = (mayWait, always = false) => take(async () => {
      const list = listing();
      const entry = find(list, which);
      const src = entry ? await source(entry) : null;
      if (!entry) return send(404, { error: 'the recorder holds no such book', books: list.map(publicEntry), version });
      if (!src) return send(404, { error: 'the book could not be read now', books: list.map(publicEntry), version });
      if (mayWait && from === src.count && wait > 0 && max > 0 && !closed) return 'wait';
      return send(200, answer(entry, src, from, list, max));
    }, always);
    const first = await attempt(true);
    if (first !== 'wait') return true;
    if (waiting.size >= FEED_MAX_WAITING) {
      return send(429, { error: `${FEED_MAX_WAITING} readers are waiting already; ask again in a few seconds` }, { 'Retry-After': '5' });
    }
    // Until anything is written or a book is kept, the wait ends, or the reader goes.
    await new Promise((resolve) => {
      const timer = setTimeout(done, wait * 1000);
      function done() {
        clearTimeout(timer);
        waiting.delete(done);
        res.off('close', done);
        resolve();
      }
      waiting.add(done);
      res.on('close', done);
    });
    if (res.destroyed || res.writableEnded) return true;
    await attempt(false, true);
    return true;
  }

  return {
    handle,
    changed,
    /** Every waiting request is answered, and none waits after this. */
    close() {
      closed = true;
      changed();
    },
    status: () => ({ token: token.path, waiting: waiting.size, busy, conversations: sessions.size, ...(token.problem ? { problem: token.problem } : {}) }),
  };
}

/**
 * A reader of a recorder's feed, for the tests and for any program on this
 * computer that holds the token (the application's uploader has its own,
 * which works in the same way): it opens a conversation, takes no answer
 * before the recorder has proved that it knows the token, proves each
 * question, and checks the recorder's proof on each answer.
 * @param {{address: string, token: string, fetchImpl?: typeof fetch}} o
 * @returns {{get: (path: string) => Promise<{code: number, body: object}>, hello: () => Promise<void>}}
 */
export function feedReader({ address, token, fetchImpl = globalThis.fetch }) {
  const tokenKey = Buffer.from(token);
  let talk = null;
  async function hello() {
    const mine = nodeCrypto.randomBytes(32).toString('base64url');
    const r = await fetchImpl(new URL('/hello', address), { headers: { 'Provared-Feed-Hello': mine } });
    const body = await r.json();
    if (r.status !== 200) throw Object.assign(new Error(body.error ?? `the feed answered ${r.status}`), { code: r.status });
    if (!isRandom(body.session) || !sameProof(body.proof, feedHmac(tokenKey, FEED_LABELS.recorder, mine, body.session))) {
      throw Object.assign(new Error('the program at that address did not prove that it knows the token'), { code: 'not-the-recorder' });
    }
    talk = { mine, session: body.session, key: feedHmac(tokenKey, FEED_LABELS.key, mine, body.session) };
  }
  async function get(path, renewed = false) {
    if (!talk) await hello();
    const nonce = nodeCrypto.randomBytes(32).toString('base64url');
    const proof = feedHmac(talk.key, FEED_LABELS.question, talk.session, nonce, `GET ${path}`).toString('base64url');
    const r = await fetchImpl(new URL(path, address), { headers: { 'Provared-Feed-Session': talk.session, 'Provared-Feed-Hello': talk.mine, 'Provared-Feed-Nonce': nonce, 'Provared-Feed-Proof': proof } });
    const bytes = Buffer.from(await r.arrayBuffer());
    if (r.status === 401) {
      const body = JSON.parse(bytes.toString());
      if (body.renew && !renewed) {
        talk = null;
        return get(path, true);
      }
      return { code: 401, body, proved: false };
    }
    const ok = sameProof(r.headers.get('provared-feed-proof'), feedHmac(talk.key, FEED_LABELS.answer, talk.session, nonce, String(r.status), bytes));
    if (!ok) throw Object.assign(new Error('an answer of the feed does not carry the recorder\'s proof'), { code: 'not-proved' });
    return { code: r.status, body: JSON.parse(bytes.toString()), proved: true };
  }
  return { get, hello };
}
