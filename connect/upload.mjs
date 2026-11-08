#!/usr/bin/env node
// The uploader beside a Provared recorder: it takes each new line of the
// recorder's book, seals it under the book's key and sends it to the
// application's server, which cannot read it.
//
//   npx provared-connect --connection <file> --feed <address> --feed-token <file> [--once | --ensure]
//   npx provared-connect --connection <file> --book <file> [--once | --ensure] [--same-book]
//
// THROUGH THE RECORDER'S FEED (--feed). The recorder beside Claude Code
// answers on its own port (http://127.0.0.1:8794) with the lines of its
// books, to whoever gives the token it writes into its folder (feed-token).
// With --feed the uploader asks the recorder, and never opens a book file:
// the recorder alone touches them. It asks from its own counts; where
// nothing is new, the recorder holds the question for up to 25 seconds and
// answers as soon as anything is written, so a new line goes out at once.
// The recorder names each book by its file's identity (as below), so the
// uploader goes on in the same book when the recorder keeps it as
// book-<n>.jsonl, and takes the new book as the next part. Its own files
// (the state, the lock, the process number and the log) are kept beside
// the token file, under the names the --book way gives them for the
// recorder's book.jsonl, so an uploader that read the file before goes on
// through the feed with the same state, without a gap or a repeat, and the
// two ways cannot run at once on one book. --same-book is for --book only.
//
// THE FILE (--book) is the fragile way, for a recorder that offers no
// feed: two programs touching one file. On Windows a program that holds a
// file open can make another's rename or writing of it fail; on 11 October
// 2026 this uploader's reading made the recorder's rename of the book fail,
// and seven receipts were lost (the recorder has appended since). The rest
// of this note is about that way.
//
// --same-book: the book file has a new identity (a program saved it by
// writing a new file and renaming it), and the person says it is the same
// book; it is taken on only where it begins with every byte already sent
// (by the fingerprint kept of them), and those bytes hold more than
// permission lines.
//
// RECORDS HANDED TO THE RECORDER (--feed only; handover.mjs). The
// renewals and cancellations the person signed, which the application keeps
// with the book, sealed, are opened with the book's key and handed to the
// recorder through its feed (POST /hand-over); the recorder checks each
// itself, and takes it or refuses it. What it took arrives in the book, and
// goes to the server as every line does; what it refused or held is said in
// a sealed note of outcomes for the page. Handed over as soon as the book's
// content changes, and once a minute besides.
//
// --once uploads what is new and stops (through the feed, it also hands
// over what is due once, and uploads what that added). --ensure starts the uploader in the
// background unless one is already running for that book (it keeps its
// process number in <book>.uploader.pid and its counts and reasons in
// <book>.uploader.log), so that a session-start hook can call it each time.
// One uploader at a time for a book: each run holds <book>.uploader.lock
// while it runs, and a second one, --once included, refuses.
//
// The connection file is made by the application's page ("Connect a
// recorder"). It holds the key to one book: keep it beside the recorder's
// own keys and never share it.
//
// A NEW BOOK FILE. A recorder may start a new book file now and then: the
// recorder beside Claude Code seals book.jsonl at 90,000 entries (or on its
// command new-book), renames it book-<n>.jsonl in the same folder, and
// starts book.jsonl again with the permission in force. A call allowed
// under the old file that finishes after the switch is still written into
// the kept file, which is then sealed again. So the application's book is
// kept in parts, numbered from 0 here and in the server's messages (part 0
// is "part 1" on the page): part 0 is the first file this uploader
// followed, part 1 the next, and so on.
//
// HOW A FILE IS KNOWN. Each part keeps the identity of its file (the volume,
// the file number the operating system gives it, and its creation time),
// which a rename keeps and a new file does not have. So a new book.jsonl
// is seen as new even where it begins with the same bytes as the old one,
// as every new book does: it begins with the permission in force. Where
// book.jsonl is not the file the part in force was read from, the uploader
// looks for that file among the kept ones (by its identity first, then, on
// a file system that gives no identity, by what it holds: the last line
// sent, with its fingerprint, at the place it was, preferring a kept file
// not yet seen), sends what that file holds beyond what was sent, and then
// sends book.jsonl as the next part. Every kept file it has sent goes on
// being followed, for as long as it runs, for lines added at its end. A
// book file that holds none of the parts, with no kept file that does, is
// refused, as before, and nothing more is sent.
//
// Within one round each file is read through one open handle, so a switch
// in the middle of a round cannot mix the new file into the old part: the
// handle goes on reading the old file, under its kept name.
//
// Beside the book file this program keeps <book>.uploaded.json: for each
// part, the file it was read from and its identity, how many lines are on
// the server, the fingerprint of the last one and where that line is in
// the file; and the identities of the files kept before this connection
// began, which belong to the recorder's earlier record and are not sent.
// A restart goes on where the last run stopped. The state is only ever
// written forward: where the file on disk is ahead of what this run holds
// (another uploader), it stops. A save that fails is made again before
// anything more is sent, so the file is at most one line behind the server.
//
// It prints counts and reasons, never a line of the book or a key.

import { appendFileSync, closeSync, existsSync, fstatSync, fsyncSync, openSync, readdirSync, readFileSync, readSync, renameSync, statSync, unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { basename, dirname, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { createCryptoCore } from '@microtoll/crypto-core';
import { authenticateConnection, createEphemeralIdentity, sendAndAwait } from '@microtoll/identity';
import { sealEntry } from './entry.mjs';
import { HAND_OVER_AGAIN_MS, bookSide, createHandover } from './handover.mjs';
import { checkConnection } from './line.mjs';
import { homedir } from 'node:os';

/** The recorder beside Claude Code, where it is unless another is named: its folder, its feed and the token in that folder. */
export const DEFAULT_FOLDER = process.env.PROVARED_CLAUDE_CODE_DIR || join(homedir(), '.provared', 'claude-code');
export const DEFAULT_FEED = `http://127.0.0.1:${process.env.PROVARED_CLAUDE_CODE_PORT || 8794}`;
export const DEFAULT_FEED_TOKEN = join(DEFAULT_FOLDER, 'feed-token');

const POLL_MS = 2000;
const RETRY_MS = 30000;
// A read or a rename of the state that fails is tried this many times, this
// far apart, in all: a scanner or a backup holds a file for moments.
const STATE_TRIES = 5;
const STATE_WAIT_MS = 200;
const pause = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
const CHUNK = 4 * 1024 * 1024;
const BATCH = 500;

function sha256(text) {
  return createHash('sha256').update(text).digest('base64url');
}

const escaped = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** The connection file, read as the command reads it (line.mjs: checkConnection), so the two agree on what a connection is. */
export function readConnection(path) {
  let parsed;
  try { parsed = JSON.parse(readFileSync(path, 'utf8')); } catch (e) { throw new Error(`the connection file ${path} could not be read: ${e.message}`); }
  try { return checkConnection(parsed); } catch (e) { throw new Error(`the connection file ${path} is not a connection: ${e.message}`); }
}

// --- files and their identity ---

/**
 * A file's identity: its volume, the number the file system gives it, and
 * its creation time. A rename keeps all three; a new file under the same
 * name has a new number. (On Windows a new file made under a name just
 * freed may be given the old one's creation time; its number still
 * differs.) null where the file system gives no number.
 */
export function identityOf(stat) {
  if (!stat || stat.ino === undefined || stat.ino === 0n || stat.ino === 0) return null;
  return `${stat.dev}:${stat.ino}:${stat.birthtimeNs ?? stat.birthtimeMs}`;
}

/** An open file: { fd, id, size, stat(), close() }, or null where it is not there. */
function openFile(path, idOf = identityOf) {
  let fd;
  try { fd = openSync(path, 'r'); } catch { return null; }
  const f = { fd, close: () => { try { closeSync(fd); } catch { /* closed */ } } };
  f.stat = () => { const st = fstatSync(fd, { bigint: true }); f.id = idOf(st); f.size = Number(st.size); return f; };
  return f.stat();
}

/** The identity and size of a file, without keeping it open; null where it is not there. */
function look(path, idOf = identityOf) {
  try { const st = statSync(path, { bigint: true }); return { id: idOf(st), size: Number(st.size) }; } catch { return null; }
}

/**
 * The whole lines of an open file from a byte onwards, each as
 * { text, start, end }: its text without the line break (and without a
 * carriage return before it), where it starts and where the next line
 * starts. An empty line is passed over, as the checker passes it over. A
 * line still being written has no line break yet, and is left for the next
 * round. The file is read in pieces of 4 MiB, so a long book is never held
 * whole.
 */
function* linesOfFd(fd, from, size) {
  let at = from;
  let carry = Buffer.alloc(0);
  while (at < size) {
    const piece = Buffer.alloc(Math.min(CHUNK, size - at));
    const got = readSync(fd, piece, 0, piece.length, at);
    if (got === 0) break;
    const bufStart = at - carry.length;
    const buf = carry.length ? Buffer.concat([carry, piece.subarray(0, got)]) : piece.subarray(0, got);
    at += got;
    let lineStart = 0;
    for (let i = buf.indexOf(10); i !== -1; i = buf.indexOf(10, lineStart)) {
      let text = buf.toString('utf8', lineStart, i);
      if (text.endsWith('\r')) text = text.slice(0, -1);
      if (text.length > 0) yield { text, start: bufStart + lineStart, end: bufStart + i + 1 };
      lineStart = i + 1;
    }
    carry = Buffer.from(buf.subarray(lineStart));
  }
}

/** The whole lines of a file by its name (for tests and for reading once). */
export function* linesFrom(path, from = 0) {
  const f = openFile(path);
  if (!f) return;
  try { yield* linesOfFd(f.fd, from, f.size); } finally { f.close(); }
}

/**
 * Whether an open file holds a part's lines as uploaded: its last line
 * sent, with the same fingerprint, ending in a line break, at the same
 * place in the file. Returns the part with where that line is
 * ({ ...part, start, bytes }), or null. A part uploaded by an earlier
 * version of this program knows only how many lines it had and the
 * fingerprint of the last: the file is then read from its start, once, to
 * find that line.
 */
function holdsFd(f, part) {
  if (part.count === 0) return { ...part, start: 0, bytes: 0 };
  if (Number.isInteger(part.bytes) && Number.isInteger(part.start) && part.bytes > part.start) {
    if (f.size < part.bytes) return null;
    const buf = Buffer.alloc(part.bytes - part.start);
    readSync(f.fd, buf, 0, buf.length, part.start);
    if (buf[buf.length - 1] !== 10) return null;
    let text = buf.toString('utf8', 0, buf.length - 1);
    if (text.endsWith('\r')) text = text.slice(0, -1);
    return sha256(text) === part.last ? part : null;
  }
  let n = 0;
  for (const line of linesOfFd(f.fd, 0, f.size)) {
    n++;
    if (n === part.count) return sha256(line.text) === part.last ? { ...part, start: line.start, bytes: line.end } : null;
  }
  return null;
}

/**
 * Whether one file, not empty, is a byte-for-byte start of another: a copy
 * taken earlier of a file that has grown since (even one taken while a
 * line was being written). Read in pieces, so neither is held whole.
 */
export function prefixOf(shorter, longer) {
  const a = openFile(shorter);
  if (!a) return false;
  const b = openFile(longer);
  if (!b) { a.close(); return false; }
  try {
    if (a.size === 0 || a.size > b.size) return false;
    const pa = Buffer.alloc(Math.min(CHUNK, Math.max(a.size, 1)));
    const pb = Buffer.alloc(pa.length);
    for (let at = 0; at < a.size; at += pa.length) {
      const n = Math.min(pa.length, a.size - at);
      readSync(a.fd, pa, 0, n, at);
      readSync(b.fd, pb, 0, n, at);
      if (!pa.subarray(0, n).equals(pb.subarray(0, n))) return false;
    }
    return true;
  } finally { a.close(); b.close(); }
}

/** Adds the bytes of an open file from one place to another to a SHA-256 under way. */
function hashRange(fd, from, to, hasher) {
  const piece = Buffer.alloc(Math.min(CHUNK, Math.max(to - from, 1)));
  for (let at = from; at < to; at += piece.length) {
    const n = readSync(fd, piece, 0, Math.min(piece.length, to - at), at);
    if (n === 0) break;
    hasher.update(piece.subarray(0, n));
  }
  return hasher;
}

/**
 * The SHA-256 of a file's first bytes (base64url), or null where the file
 * is shorter or not there.
 */
export function startFingerprint(path, bytes) {
  const f = openFile(path);
  if (!f) return null;
  try { return f.size < bytes ? null : hashRange(f.fd, 0, bytes, createHash('sha256')).digest('base64url'); } finally { f.close(); }
}

/** Whether every line in a file's first bytes is a permission (a slip's line). */
function permissionsOnly(path, bytes) {
  const f = openFile(path);
  if (!f) return false;
  try {
    for (const line of linesOfFd(f.fd, 0, Math.min(bytes, f.size))) if (!line.text.startsWith('{"slip":')) return false;
    return true;
  } finally { f.close(); }
}

/** holds, by the file's name. */
export function holds(path, part) {
  const f = openFile(path);
  if (!f) return null;
  try { return holdsFd(f, part); } finally { f.close(); }
}

// --- the recorder's feed ---

const whole = (x) => Number.isInteger(x) && x >= 0;
const feedError = (words, reason) => Object.assign(new Error(words), { reason });

/** Whether an answer of the feed for a book has the shape this uploader reads. */
function feedAnswerFits(a) {
  if (!a || typeof a !== 'object' || !Array.isArray(a.lines) || !Array.isArray(a.starts) || !Array.isArray(a.ends)) return false;
  if (a.starts.length !== a.lines.length || a.ends.length !== a.lines.length) return false;
  if (!a.lines.every((l) => typeof l === 'string' && l.length > 0 && !l.includes('\n'))) return false;
  if (!a.starts.every(whole) || !a.ends.every(whole) || !whole(a.size) || !whole(a.from) || typeof a.book !== 'string') return false;
  if (!(a.id === null || typeof a.id === 'string')) return false;
  if (a.previous !== null && !(a.previous && typeof a.previous.fingerprint === 'string' && whole(a.previous.start) && whole(a.previous.end))) return false;
  return a.lines.every((_, i) => a.starts[i] < a.ends[i] && (i === 0 || a.starts[i] >= a.ends[i - 1]));
}

/** Whether a listing of the feed has the shape this uploader reads. */
function feedListingFits(l) {
  return Boolean(l) && Array.isArray(l.books) && l.books.every((b) => b && typeof b.book === 'string' && (b.id === null || typeof b.id === 'string') && typeof b.inForce === 'boolean' && whole(b.bytes) && (b.number === null || whole(b.number)))
    && l.books.filter((b) => b.inForce).length <= 1;
}

// The labels of the four HMACs, as the recorder's feed has them (feed.mjs, FEED_LABELS).
const FEED_LABELS = Object.freeze({
  recorder: 'provared feed v1: the recorder knows the token',
  key: 'provared feed v1: the key of a conversation',
  question: 'provared feed v1: a question',
  questionWithBody: 'provared feed v1: a question with a body',
  answer: 'provared feed v1: an answer',
});
const RANDOM = /^[A-Za-z0-9_-]{43}$/;
/** Whether a value is 32 bytes in base64url, written in the one way they can be (as the recorder's feed reads them). */
function isRandom(value) {
  return typeof value === 'string' && RANDOM.test(value) && Buffer.from(value, 'base64url').toString('base64url') === value;
}

/** HMAC-SHA-256 under a key, over a label and parts, each after a line break, as the recorder makes it. */
function feedHmac(key, label, ...parts) {
  const h = createHmac('sha256', key);
  h.update(label);
  for (const p of parts) { h.update('\n'); h.update(p); }
  return h.digest();
}

/** Whether a proof given in base64url is the one expected, compared in constant time. */
function sameProof(given, expected) {
  if (!isRandom(given)) return false;
  const bytes = Buffer.from(given, 'base64url');
  return bytes.length === expected.length && timingSafeEqual(bytes, expected);
}

/**
 * A client of a recorder's feed: GET /books and GET /lines. The token
 * never travels. The client opens a conversation with a random number of
 * its own (GET /hello); the recorder answers with a random number of its
 * own and an HMAC-SHA-256 over both, keyed by the token: until that proof
 * checks, nothing is asked and nothing it says is taken. Both sides then
 * hold the conversation's key (an HMAC over both numbers, keyed by the
 * token, under another label); each question carries a random number used
 * once and an HMAC over the question under that key (the client's proof),
 * and each answer must carry an HMAC under that key over the question's
 * number, the answer's code and every byte of the answer (the recorder's),
 * or it is not used. Every proof is compared in constant time. The feed is
 * the recorder's, on 127.0.0.1, where the recorder listens: no other
 * address is taken, not even "localhost", which may lead to another
 * program on the other address of this computer.
 *
 * Errors carry a reason: "feed-refused" (the program at the address did
 * not prove that it knows the token, or refused this client's proof),
 * which a person must look into; "feed-unreachable", "feed-busy",
 * "feed-off" and "feed-error", which may pass.
 * @param {{address: string, token: string, fetchImpl?: typeof fetch}} o
 */
export function feedClient({ address, token, fetchImpl = globalThis.fetch }) {
  let base;
  try { base = new URL(address); } catch { throw new Error(`the feed's address (${address}) is not an address; give it as http://127.0.0.1:<port>`); }
  if (base.protocol !== 'http:' || base.hostname !== '127.0.0.1' || base.pathname !== '/' || base.search || base.hash || base.username || base.password) {
    throw new Error(`the feed is the recorder's, on this computer, where it listens: give its address as http://127.0.0.1:<port>, not ${address}`);
  }
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) throw new Error('the feed token file does not hold a token (43 letters, digits, "-" and "_"): give the file feed-token from the recorder\'s folder');
  const tokenKey = Buffer.from(token);
  let talk = null;
  const reach = async (path, headers, wait, body = null) => {
    try {
      const how = body === null ? {} : { method: 'POST', body, headers: { ...headers, 'Content-Type': 'application/json' } };
      return await fetchImpl(new URL(path, base), { headers, signal: AbortSignal.timeout((wait + 30) * 1000), ...how });
    } catch (e) {
      throw feedError(`the recorder's feed at ${base.origin} did not answer (${e.cause?.code || e.name || 'no answer'}): is the recorder running?`, 'feed-unreachable');
    }
  };
  const readJson = (bytes) => { try { return JSON.parse(bytes.toString('utf8')); } catch { return {}; } };

  async function hello() {
    const mine = randomBytes(32).toString('base64url');
    const response = await reach('/hello', { 'Provared-Feed-Hello': mine }, 0);
    const body = readJson(Buffer.from(await response.arrayBuffer()));
    if (response.status === 503) throw feedError(`the recorder's feed is off: ${typeof body.error === 'string' ? body.error.slice(0, 300) : 503}`, 'feed-off');
    if (response.status !== 200 || !isRandom(body.session) || !sameProof(body.proof, feedHmac(tokenKey, FEED_LABELS.recorder, mine, body.session))) {
      throw feedError(`the program at ${base.origin} did not prove that it knows the token in the feed token file: either it is not the recorder (another program on this computer may listen there while the recorder is stopped), or the token file is not this recorder's. Nothing was asked of it, and nothing it said is used`, 'feed-refused');
    }
    talk = { mine, session: body.session, key: feedHmac(tokenKey, FEED_LABELS.key, mine, body.session) };
  }

  // A question with a body (POST /hand-over) is proved over every byte of the body as well, under a label of its own.
  async function get(path, wait, renewed = false, sending = null) {
    if (!talk) await hello();
    const nonce = randomBytes(32).toString('base64url');
    const proof = sending === null
      ? feedHmac(talk.key, FEED_LABELS.question, talk.session, nonce, `GET ${path}`)
      : feedHmac(talk.key, FEED_LABELS.questionWithBody, talk.session, nonce, `POST ${path}`, sending);
    // The uploader's own number goes with each question: the recorder keeps nothing from the hello.
    const headers = { 'Provared-Feed-Session': talk.session, 'Provared-Feed-Hello': talk.mine, 'Provared-Feed-Nonce': nonce, 'Provared-Feed-Proof': proof.toString('base64url') };
    const response = await reach(path, headers, wait, sending);
    const bytes = Buffer.from(await response.arrayBuffer());
    if (response.status === 401) {
      const body = readJson(bytes);
      // A conversation the recorder no longer holds (it restarted, or gave it up): another is opened, once.
      if (body.renew === true && !renewed) { talk = null; return get(path, wait, true, sending); }
      // Given up again before its question: another program may be opening conversations without end.
      // Taken as a busy feed, and tried again later; the uploader does not stop for good on it.
      if (body.renew === true) { talk = null; throw feedError('the recorder gave up this uploader\'s conversation again before its question was answered (another program may be opening conversations); tried again later', 'feed-busy'); }
      throw feedError(`the recorder's feed refused this uploader's proof: ${typeof body.error === 'string' ? body.error.slice(0, 300) : 401}. Give the file feed-token from the recorder's folder`, 'feed-refused');
    }
    if (!sameProof(response.headers.get('provared-feed-proof'), feedHmac(talk.key, FEED_LABELS.answer, talk.session, nonce, String(response.status), bytes))) {
      talk = null;
      throw feedError(`an answer from ${base.origin} does not carry the recorder's proof over it; it is not used`, 'feed-error');
    }
    const body = readJson(bytes);
    const said = typeof body?.error === 'string' ? body.error.slice(0, 300) : `it answered ${response.status}`;
    if (response.status === 429) throw feedError(`the recorder's feed is busy: ${said}`, 'feed-busy');
    if (response.status === 503) throw feedError(`the recorder's feed is off: ${said}`, 'feed-off');
    if (response.status === 404) {
      if (!feedListingFits(body)) throw feedError(`the recorder's feed answered in a form this uploader does not read (${said})`, 'feed-error');
      return { missing: true, books: body.books };
    }
    if (!response.ok) throw feedError(`the recorder's feed answered ${response.status}: ${said}`, 'feed-error');
    return body;
  }
  return {
    origin: base.origin,
    async books() {
      const l = await get('/books', 0);
      if (!feedListingFits(l)) throw feedError('the recorder\'s feed gave a list of books in a form this uploader does not read', 'feed-error');
      return l;
    },
    /**
     * Hands the recorder a record the person signed ({ kind: 'renewal', slip }
     * or { kind: 'cancellation', cancellation }). Resolves with the
     * recorder's answer: { outcome, code?, thumbprint?, message, ... }.
     */
    async handOver(record) {
      const a = await get('/hand-over', 30, false, Buffer.from(JSON.stringify(record)));
      if (a.missing || !a || typeof a !== 'object' || typeof a.outcome !== 'string') throw feedError('the recorder answered a record handed over in a form this uploader does not read', 'feed-error');
      return a;
    },
    /** The lines of one book, named by its identity or, with none, by its name, from a place on. */
    async lines({ id, book, from, wait = 0, max }) {
      const which = id ? `id=${encodeURIComponent(id)}` : `book=${encodeURIComponent(book)}`;
      const a = await get(`/lines?${which}&from=${from}&wait=${wait}${max === undefined ? '' : `&max=${max}`}`, wait);
      if (a.missing) return a;
      if (!feedAnswerFits(a) || a.from !== from || (id && a.id !== id) || (!id && a.book !== book)) throw feedError('the recorder\'s feed answered in a form this uploader does not read, or for another book or place than the one asked', 'feed-error');
      return a;
    },
  };
}

// --- what is kept beside the book ---

const isObject = (x) => typeof x === 'object' && x !== null && !Array.isArray(x);
const partFits = (p) => isObject(p) && (p.file === undefined || p.file === null || typeof p.file === 'string') && whole(p.count) && (p.bytes === undefined || whole(p.bytes)) && (p.start === undefined || whole(p.start));
const partsFit = (parts) => Array.isArray(parts) && parts.length > 0 && parts.every(partFits);
const fresh = (file) => ({ file, id: null, count: 0, last: null, start: 0, bytes: 0 });

/**
 * The saved state, in the form of this version:
 *   { version: 3, parts: [{ file, id, count, last, start, bytes, sha }], older }
 * file is the name of the file a part is read from, in the book's folder
 * (the book's own name for the last part, the part in force), or null once
 * that file is not known; id is that file's identity (identityOf); sha is
 * the SHA-256 of every byte of the file sent so far (up to bytes), built
 * as lines are sent, for a part this version began (one from an earlier
 * version's state has none, and --same-book cannot be used for it); older
 * lists the files kept before this connection began, as { file, id };
 * stage0 marks a state read from the stage-0 uploader's form, until its
 * first switch. The forms of earlier versions are read: { count, last } is
 * one part. Each part is an object with a whole count, and whole bytes and
 * start where it has them; each entry of older is an object. Anything else
 * is state-unreadable, so that a malformed file stops with words and does
 * not fail at every round.
 */
function readState(stateFile, tries = STATE_TRIES) {
  // No file: nothing has been sent from here. A file that cannot be read is
  // not the same thing: lines may be on the server, so this run must not
  // begin again from the first line as if none were (this happened once,
  // at a start after the computer restarted: the uploader then stopped at
  // every start with nothing but "conflict", for five days). Only what the
  // file holds can stop the uploader for good; a file that cannot be opened
  // now (another program holding it) says nothing of what it holds, so that
  // is tried again, here and then at a later round.
  const unreadable = () => Object.assign(new Error(`the state kept beside the book (${stateFile}) cannot be read, so this uploader does not know how much of the book is on the server, and sends nothing. Put a good copy back, at most one line behind the server; see "If the uploader's state is lost" in the README`), { reason: 'state-unreadable' });
  let text;
  for (let left = tries; text === undefined; left--) {
    try { text = readFileSync(stateFile, 'utf8'); } catch (e) {
      if (e.code === 'ENOENT') return null;
      if (left <= 1) throw Object.assign(new Error(`the state kept beside the book (${stateFile}) could not be read just now (${e.code}); it may be whole, and nothing is sent this round`), { reason: 'state-not-read' });
      pause(STATE_WAIT_MS);
    }
  }
  // A byte order mark, as some editors and copying tools leave.
  if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
  let s;
  try { s = JSON.parse(text); } catch { throw unreadable(); }
  if (!isObject(s)) throw unreadable();
  if (s.version === 3 && partsFit(s.parts) && Array.isArray(s.older) && s.older.every(isObject)) return s;
  if (s.version === 2 && partsFit(s.parts)) return { version: 3, parts: s.parts.map((p) => ({ id: null, ...p })), older: null };
  // The stage-0 uploader's form: its first switch may be met only when this
  // version starts, so a file kept before this run may still be its part's.
  if (s.version === undefined && whole(s.count)) return { version: 3, parts: [{ file: null, id: null, count: s.count, last: s.last ?? null }], older: null, stage0: true };
  throw unreadable();
}

/**
 * The server's refusal of a place already taken, in words: how many lines it
 * holds of the part, where its answer says so for this part (a refusal in a
 * race for the place does not), and how many the state says.
 */
function conflictStop(e, index, seq, forThisPart) {
  const next = forThisPart ? e.serverMessage.next : undefined;
  const held = whole(next) ? `the server holds ${next} line${next === 1 ? '' : 's'} of part ${index}` : `the server already has a line at place ${seq} of part ${index}`;
  return Object.assign(new Error(`${held}, and the state beside the book says ${seq}, so this uploader stops. Nothing is lost: the book stays on this computer. See "If the uploader's state is lost" in the README`), { reason: 'conflict', serverMessage: e.serverMessage });
}

/**
 * createUploader({ connection, book, log }) -> { sync, close, parts }
 *   connection  the object from the connection file
 *   book        the path of the book file
 *   sync()      uploads every line not yet on the server, in every part;
 *               resolves with the count of lines on the server in the part
 *               in force
 *   parts()     what is kept beside the book, for each part: { file, count }
 *   append      for tests: (message) => the server's answer, in place of the connection
 *   identities  false: act as on a file system that gives files no
 *               number (for tests): files are then known by name and by
 *               what they hold
 *   sameBook    true (--same-book): the person says the book file, under a
 *               new identity, is the same book (rewritten by a program that
 *               saves by writing a new file and renaming it); it is taken
 *               on, only where it begins with every byte already sent (by
 *               the part's sha) and those bytes hold more than
 *               permission lines
 *   feed        a client of the recorder's feed (feedClient): the lines are
 *               asked of the recorder, and no book file is opened; "book"
 *               then only names the files kept beside it (the state)
 *   sync({ wait }) through the feed: where nothing is new in the book in
 *               force, the recorder may hold the question this many
 *               seconds (0 to 25) for something new
 */
export function createUploader({ connection, book, log = console, stateFile = `${book}.uploaded.json`, WebSocketImpl = globalThis.WebSocket, append = null, identities = true, sameBook = false, feed = null }) {
  if (feed && sameBook) throw new Error('--same-book is for --book: through the feed, the recorder names its books itself');
  const idOf = identities ? identityOf : () => null;
  const opened = (path) => openFile(path, idOf);
  const looked = (path) => look(path, idOf);
  const cc = createCryptoCore({ namespace: connection.namespace });
  const folder = dirname(book);
  const bookName = basename(book);
  const ext = extname(bookName);
  const stem = ext ? bookName.slice(0, -ext.length) : bookName;
  const keptName = new RegExp(`^${escaped(stem)}-([1-9][0-9]{0,8})${escaped(ext)}$`);
  let socket = null;
  let keyPromise = null;
  let busy = null;
  let state = null;
  // A save of the state that failed: the disk is behind this run. Nothing is
  // sent until it has worked, so the disk is never more than the one line
  // behind that the server allows for.
  let unsaved = false;
  // A kept file that went missing or was changed is said once, not every round.
  const said = new Set();
  // For each part, the SHA-256 under way of the bytes sent so far, and how
  // many bytes it covers. Kept in memory; its digest is the part's sha.
  const hashers = new Map();
  const sayOnce = (what, words, level = 'info') => { if (!said.has(what)) { said.add(what); log[level](`provared-connect: ${words}`); } };

  /** The state, written forward only: where the file on disk is ahead of this run, another uploader is at work. */
  function remember() {
    unsaved = true;
    // This run holds the true position, and the lock keeps other uploaders
    // out, so a file that cannot be read now stops nothing: it is one read,
    // not retried, and the file is written over. Only a file that was read
    // and found ahead stops this run.
    let onDisk = null;
    let garbled = false;
    try { onDisk = readState(stateFile, 1); } catch (e) { garbled = e.reason === 'state-unreadable'; }
    if (onDisk && onDisk.parts.some((p, i) => !state.parts[i] ? p.count > 0 : p.count > state.parts[i].count)) {
      throw Object.assign(new Error(`the state kept beside the book (${stateFile}) is ahead of this uploader: another uploader is sending this book; this one stops`), { code: 'another-uploader' });
    }
    // Written whole, forced to the disk, then put in place, so that a stop
    // half way through, or a power cut, leaves the state before or after,
    // never a part of it.
    try {
      const fd = openSync(`${stateFile}.tmp`, 'w');
      try {
        writeFileSync(fd, JSON.stringify(state));
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      putInPlace();
    } catch (e) {
      throw Object.assign(new Error(`the state kept beside the book (${stateFile}) could not be saved (${e.code}), so it may be a line behind the server; nothing more is sent until it is saved`), { reason: 'state-not-saved' });
    }
    unsaved = false;
    if (garbled) log.error(`provared-connect: the state kept beside the book (${stateFile}) was garbled while this uploader ran; it was written over with the position this run holds`);
  }

  /** On Windows a rename fails with EPERM while a scanner holds the file, so it is tried a few times. */
  function putInPlace() {
    for (let left = STATE_TRIES; ; left--) {
      try { renameSync(`${stateFile}.tmp`, stateFile); return; } catch (e) {
        if (left <= 1 || !['EPERM', 'EBUSY', 'EACCES'].includes(e.code)) throw e;
        pause(STATE_WAIT_MS);
      }
    }
  }

  /** At the start of a round, new lines or none: a save that failed is made first, or the round ends here. */
  function savePending() {
    if (unsaved) remember();
  }

  /** The kept files in the book's folder, by number: { number, file, id, size }. */
  function keptFiles() {
    let names = [];
    try { names = readdirSync(folder); } catch { /* no folder yet */ }
    return names.flatMap((file) => {
      const m = keptName.exec(file);
      if (!m) return [];
      const seen = looked(join(folder, file));
      return seen ? [{ number: Number(m[1]), file, ...seen }] : [];
    }).sort((a, b) => a.number - b.number);
  }

  const pathOf = (index) => (index === state.parts.length - 1 ? book : join(folder, state.parts[index].file));

  function load() {
    if (state) return state;
    state = readState(stateFile) || { version: 3, parts: [fresh(bookName)], older: null };
    // The last part is the one in force, read from the book file itself.
    state.parts[state.parts.length - 1].file = bookName;
    // A connection begun before any switch it saw: the files kept before it
    // belong to the recorder's earlier record, and are not uploaded here.
    // This is written down at once, before any line is sent: otherwise a
    // stop after the server took the first line, and before the state was
    // first written, followed by a switch, made the next run count the
    // kept file as one kept before the connection began, and send the new
    // book file into the old part.
    if (state.older === null) {
      state.older = keptFiles().map((k) => ({ file: k.file, id: k.id }));
      remember();
    }
    return state;
  }

  /**
   * Whether a kept file is one this connection has not seen: not the file
   * of any part, nor one kept before the connection began. By identity;
   * where the file system gives none, by name.
   */
  function unseen(k) {
    const known = [...state.parts, ...state.older];
    if (k.id) return !known.some((p) => p.id === k.id);
    return !known.some((p) => p.file === k.file);
  }
  const isOlder = (k) => state.older.some((o) => (k.id ? o.id === k.id : o.file === k.file));

  async function connect() {
    if (socket && socket.readyState === 1) return socket;
    const identity = await createEphemeralIdentity(cc);
    const ws = new WebSocketImpl(connection.server);
    await new Promise((resolve, reject) => {
      ws.addEventListener('open', resolve, { once: true });
      ws.addEventListener('error', () => reject(new Error('could not reach the server')), { once: true });
    });
    await authenticateConnection(cc, ws, identity.routing, connection.origin);
    ws.addEventListener('close', () => { if (socket === ws) socket = null; });
    socket = ws;
    return ws;
  }

  async function send(message) {
    if (append) return append(message);
    return sendAndAwait(await connect(), message, 'provared-append-ok', 'provared-append-failed');
  }

  async function key() {
    if (!keyPromise) keyPromise = cc.importSymmetricKey(cc.fromBase64Url(connection.kObject));
    return keyPromise;
  }

  /**
   * Uploads the lines an open file holds beyond those already sent of a
   * part, a batch at a time, all through the one handle; returns how many
   * were sent. The part's place in the file must have been confirmed first
   * (holdsFd), with the same handle.
   */
  async function upload(index, f) {
    const k = await key();
    let sent = 0;
    for (;;) {
      // The handle is the same file throughout; it is asked how long it is now.
      f.stat();
      if (state.parts[index].id && f.id && f.id !== state.parts[index].id) throw new Error(`the file read for part ${index} changed under the uploader`);
      const batch = [];
      let size = 0;
      for (const line of linesOfFd(f.fd, state.parts[index].bytes, f.size)) {
        batch.push(line);
        size += line.end - line.start;
        if (batch.length >= BATCH || size >= CHUNK) break;
      }
      if (batch.length === 0) return sent;
      for (const line of batch) {
        const part = state.parts[index];
        const seq = part.count;
        const sealed = await sealEntry(cc, k, connection.objectId, seq, line.text, index);
        // A server from before parts names no part in its answers, and keeps
        // every line in part 0: its answers count for part 0 only.
        const ofThisPart = (m) => Boolean(m) && (m.part === undefined ? index === 0 : m.part === index);
        let reply;
        try {
          reply = await send({
            type: 'provared-append', objectId: connection.objectId, appendCapabilitySecret: connection.appendCapabilitySecret, part: index, seq, sealed: cc.toBase64Url(sealed),
          });
        } catch (e) {
          // Sent last time, but not remembered (the program stopped in
          // between): only for the first line of a round, only where the
          // server says the next free place is the one after it, and only in
          // an answer for this part.
          if (e.reason === 'conflict' && ofThisPart(e.serverMessage) && e.serverMessage.next === seq + 1 && sent === 0) {
            log.info(`provared-connect: line ${seq} of part ${index} was already on the server`);
          } else {
            if (e.reason === 'conflict' && index > 0 && e.serverMessage && e.serverMessage.part === undefined) {
              throw Object.assign(new Error(`the server does not keep parts (it is from before them): deploy the server first; nothing more is uploaded`), { reason: 'conflict' });
            }
            if (e.reason === 'conflict') throw conflictStop(e, index, seq, ofThisPart(e.serverMessage));
            throw e;
          }
        }
        // (A server from before parts never answers "ok" for the first line of
        // a new part: it holds lines of part 0 already, so place 0 is taken.)
        if (reply && reply.part !== undefined && reply.part !== index) throw Object.assign(new Error(`the server answered for part ${reply.part ?? '(none)'} where part ${index} was sent; nothing more is uploaded`), { reason: 'conflict' });
        const h = hashers.get(index);
        let sha = part.sha;
        if (h) { hashRange(f.fd, h.bytes, line.end, h.hasher); h.bytes = line.end; sha = h.hasher.copy().digest('base64url'); }
        state.parts[index] = { ...part, id: part.id || f.id, count: seq + 1, last: sha256(line.text), start: line.start, bytes: line.end, ...(sha ? { sha } : {}) };
        remember();
        sent++;
      }
    }
  }

  /** Opens a part's file, confirms it holds what was sent, and sends what is new; returns how many lines. */
  async function send1(index, path) {
    const f = opened(path);
    if (!f) return 0;
    try {
      const held = holdsFd(f, state.parts[index]);
      if (!held) return -1;
      state.parts[index] = { ...held, id: held.id || f.id };
      if (!fingerprintFrom(index, f)) return -1;
      return await upload(index, f);
    } finally { f.close(); }
  }

  /**
   * The SHA-256 of every byte sent of a part, under way, from the open file
   * that holds it. A part with no line sent begins one; a part with a
   * fingerprint kept has it built again from the file once in a run, and
   * where the file's first bytes no longer give it, the file does not hold
   * what was sent (false). A part from an earlier version's state, with
   * none, goes on without one.
   */
  function fingerprintFrom(index, f) {
    const part = state.parts[index];
    const h = hashers.get(index);
    if (h && h.bytes === part.bytes) return true;
    if (part.count === 0) { hashers.set(index, { hasher: createHash('sha256'), bytes: 0 }); return true; }
    if (!part.sha) { hashers.delete(index); return true; }
    const hasher = hashRange(f.fd, 0, part.bytes, createHash('sha256'));
    if (hasher.copy().digest('base64url') !== part.sha) return false;
    hashers.set(index, { hasher, bytes: part.bytes });
    return true;
  }

  /**
   * Whether a kept file is one the recorder kept since this connection
   * began, to be sent as a part: not yet seen, not empty (an empty part is
   * one the server does not go on from; a kept book always begins with its
   * permission), and not a copy of a part already sent (one that holds
   * what a part sent, under another name or identity). A copy is set aside
   * for good, and said once.
   */
  function newKept(k) {
    if (!unseen(k) || isOlder(k) || k.size === 0) return false;
    const f = opened(join(folder, k.file));
    if (!f) return false;
    try {
      // A copy holds what a part sent, or is a start of a part's own file
      // (a copy taken before the part grew).
      const path = join(folder, k.file);
      let copyOf = state.parts.findIndex((p) => p.count > 0 && holdsFd(f, p));
      if (copyOf < 0) copyOf = state.parts.findIndex((p, i) => p.count > 0 && p.file && p.file !== k.file && prefixOf(path, i === state.parts.length - 1 ? book : join(folder, p.file)));
      if (copyOf < 0) return true;
      state.older.push({ file: k.file, id: f.id });
      sayOnce(`copy:${k.file}:${f.id}`, `${k.file} holds what part ${copyOf} already sent: a copy, set aside`);
      return false;
    } finally { f.close(); }
  }

  /**
   * The part in force has moved to a kept file (found). That file becomes
   * that part's file, and the book file is the next part. Any other file
   * the recorder kept while this program was not running is put before the
   * book file by keptSince, at the start of the next round, which follows
   * at once.
   */
  function switchTo(found) {
    const last = state.parts.length - 1;
    state.parts[last] = { ...state.parts[last], file: found.file, id: state.parts[last].id || found.id };
    state.parts.push(fresh(bookName));
    delete state.stage0;
    remember();
    log.info(`provared-connect: the recorder kept part ${last} as ${found.file} and started a new book file; the book file goes on as part ${state.parts.length - 1}`);
  }

  /**
   * Where the part in force is now, when the book file is not its file:
   * a kept file with its identity; else, a kept file that is no part's
   * and holds what was sent (one kept since this connection began first,
   * the newest number first). null where none is.
   */
  function findMoved(part, bookHolds) {
    const kept = keptFiles();
    if (part.id) {
      const same = kept.find((k) => k.id === part.id);
      if (same) return same;
    }
    // By what it holds: a kept file that is no part's. A file kept before
    // this connection began is the recorder's earlier record, and is tried
    // only for the stage-0 uploader's state, which may meet its first
    // switch only when this version starts, and only where the book file
    // itself does not hold the part (an earlier book may begin with the
    // same permission line).
    const isPart = (k) => state.parts.some((p) => (k.id && p.id ? p.id === k.id : p.file === k.file));
    const allowOlder = Boolean(state.stage0) && !bookHolds;
    const candidates = kept.filter((k) => !isPart(k) && (allowOlder || !isOlder(k))).sort((a, b) => (isOlder(a) - isOlder(b)) || (b.number - a.number));
    for (const k of candidates) {
      const path = join(folder, k.file);
      const f = opened(path);
      if (!f) continue;
      let held;
      try { held = holdsFd(f, part); } finally { f.close(); }
      if (!held) continue;
      // Where the book file holds the part too, a kept file that is a start
      // of the book file is a copy taken earlier (the book only grows), not
      // the part's own file: the recorder's kept file goes on past where the
      // new book does (with its seal, at least).
      if (bookHolds && prefixOf(path, book)) continue;
      return { ...k, id: f.id };
    }
    return null;
  }

  /**
   * A part in force that has no line on the server yet comes after any
   * file the recorder has kept since: a kept file not yet seen was kept
   * after the last switch this program saw (the recorder switched again
   * before this program sent the new book's first line). Such files
   * become parts, in order of their numbers, before it.
   */
  function keptSince() {
    const last = state.parts.length - 1;
    if (state.parts[last].count > 0) return;
    const setAside = state.older.length;
    const later = keptFiles().filter((k) => newKept(k));
    if (later.length === 0) { if (state.older.length !== setAside) remember(); return; }
    hashers.clear();
    const inForce = state.parts.pop();
    for (const k of later) state.parts.push({ ...fresh(k.file), id: k.id });
    state.parts.push(inForce);
    remember();
    log.info(`provared-connect: ${later.length} file(s) the recorder kept come before the book file, as parts ${last} to ${state.parts.length - 2}`);
  }

  /**
   * A part before the one in force: its kept file is followed, for lines
   * added at its end. Where its name now holds another file (the person
   * moved the kept file away, and the recorder used its number again),
   * known by its identity or, with none, by not holding what was sent, the
   * part is no longer read from that name: its file is not known. This
   * runs before the part in force is looked for, so a name used again can
   * be taken by the part it now holds.
   */
  async function follow(index) {
    const part = state.parts[index];
    if (!part.file) return 0;
    let path = join(folder, part.file);
    let seen = looked(path);
    if (part.id && (!seen || (seen.id && seen.id !== part.id))) {
      // Not under that name, or another file now has it: looked for by its identity.
      const moved = keptFiles().find((k) => k.id === part.id);
      if (!moved) {
        sayOnce(`gone:${index}`, `the file of part ${index} (${part.file}) is not in the folder; it is not followed while it is not there`);
        if (seen) { state.parts[index] = { ...part, file: null }; remember(); }
        return 0;
      }
      part.file = moved.file;
      path = join(folder, part.file);
      seen = moved;
    }
    if (!seen) { sayOnce(`gone:${index}`, `${part.file} (part ${index}) is not in the folder; it is not followed while it is not there`); return 0; }
    if (Number.isInteger(part.bytes) && seen.size === part.bytes) return 0;
    const sent = await send1(index, path);
    if (sent < 0) {
      sayOnce(`changed:${index}`, `${part.file} no longer holds the ${part.count} lines of part ${index} already uploaded; nothing more is uploaded into part ${index}`, 'error');
      state.parts[index] = { ...state.parts[index], file: null };
      remember();
      return 0;
    }
    return sent;
  }

  async function syncOnce() {
    savePending();
    load();
    let sent = 0;
    // The parts before the one in force first, in order: a late line of a
    // kept file goes to the server before the new book's lines, and a part
    // has its first line before the part after it begins. They are followed
    // before the files kept since are looked for, so that a kept name now
    // holding another file is first let go by its earlier part, and then
    // taken as the new file it is; and again after, for those just taken.
    for (let i = 0; i < state.parts.length - 1; i++) sent += await follow(i);
    keptSince();
    for (let i = 0; i < state.parts.length - 1; i++) sent += await follow(i);
    const last = state.parts.length - 1;
    const part = state.parts[last];
    const seen = looked(book);
    if (part.count > 0) {
      // The book file is the part in force's own file only where its
      // identity is the one kept; otherwise (a new file, or none, or a
      // part from before identities were kept) the part is looked for
      // among the kept files first.
      const same = seen && part.id && seen.id === part.id;
      if (!same) {
        const bookHolds = seen ? Boolean(holds(book, part)) : false;
        const moved = findMoved(part, bookHolds);
        if (moved) { switchTo(moved); return syncOnce(); }
        if (!seen) return part.count;
        if (part.id && seen.id) {
          // A new file under the book's name, and the old one nowhere beside
          // it: taking the new one on would put its lines into the old part
          // (every new book begins with the same permission), so it is
          // refused, unless the person says it is the same book (--same-book)
          // and it begins with every byte already sent, by the fingerprint
          // kept of them, and those bytes hold more than permission lines.
          const sameBytes = Boolean(part.sha) && startFingerprint(book, part.bytes) === part.sha;
          const onlyPermission = sameBytes && permissionsOnly(book, part.bytes);
          if (sameBook && sameBytes && !onlyPermission) {
            state.parts[last] = { ...part, id: seen.id };
            hashers.delete(last);
            remember();
            log.info(`provared-connect: the book file has a new identity, and begins with every byte of the ${part.count} lines already uploaded: taken as the same book, as asked`);
          } else {
            let advice;
            if (!part.sha) advice = '--same-book cannot be used here: the state beside the book was kept by an earlier version of this uploader, which kept no fingerprint of every byte sent';
            else if (onlyPermission) advice = '--same-book cannot be used here: the only line sent is the permission, and every new book begins with that same line, so this file cannot be told from a new book';
            else if (sameBytes) advice = 'If you are sure it is the same book, run the uploader once with --same-book: this file begins with every byte already uploaded';
            else advice = '--same-book would refuse it: this file does not hold every line already uploaded';
            throw new Error(`the book at ${book} is not the file the ${part.count} lines already uploaded were read from (it has a new identity), and no file kept beside it is or holds them; nothing more is uploaded. A program that saves by writing a new file and renaming it over the old one (some editors and backup tools) does this; so does the recorder starting a new book file whose kept file was then moved away: if so, put that file back beside the book. ${advice}`);
          }
        }
      }
    }
    if (!seen) return part.count;
    const n = await send1(last, book);
    if (n < 0) throw new Error(`the book at ${book} no longer holds the ${part.count} lines already uploaded in that order, and no file kept beside it does; nothing more is uploaded`);
    sent += n;
    if (sent > 0) log.info(`provared-connect: ${sent} new line(s); ${state.parts[last].count} on the server in part ${last}`);
    return state.parts[last].count;
  }

  // --- through the recorder's feed ---
  //
  // The same rules as for files, with the recorder's word in place of the
  // file system's: the recorder lists its books oldest first (the kept ones
  // by number, the one in force last), each with its file's identity and
  // size, and answers for one book from a place on with its lines, where
  // each is in the file, and the line before. A part is the recorder's book
  // with its identity; a book with none (a file system that gives files no
  // number) is known by its name and by what it holds, as files are.

  const keptOf = (listing) => listing.books.filter((b) => !b.inForce).map((b) => ({ number: b.number, file: b.book, id: b.id, size: b.bytes }));
  const inForceOf = (listing) => {
    const b = listing.books.find((x) => x.inForce);
    return b ? { number: null, file: b.book, id: b.id, size: b.bytes } : null;
  };
  // How a book is asked for: by its identity, or with none by its name.
  const ref = (entry) => (entry.id ? { id: entry.id } : { book: entry.file });

  function loadFeed(listing) {
    if (!state) {
      state = readState(stateFile) || { version: 3, parts: [fresh(bookName)], older: null };
      state.parts[state.parts.length - 1].file = bookName;
    }
    // A connection begun before any switch it saw: the books kept before it
    // are not uploaded here. Written down at once, as for files (load).
    if (state.older === null) {
      state.older = keptOf(listing).map((k) => ({ file: k.file, id: k.id }));
      remember();
    }
    return state;
  }

  /** The line at place n of a book, as the feed gives it ({fingerprint, start, end}), or null where it holds fewer. */
  async function lineOf(entry, n) {
    const a = await feed.lines({ ...ref(entry), from: n + 1, max: 0 });
    return a.missing ? null : a.previous;
  }

  /** Whether a book holds a part's lines as uploaded: its last line sent, with the same fingerprint, at the same place. */
  async function holdsIn(entry, part) {
    if (part.count === 0) return true;
    const p = await lineOf(entry, part.count - 1);
    return Boolean(p) && p.fingerprint === part.last && (!Number.isInteger(part.bytes) || p.end === part.bytes);
  }

  /** Whether one book is a start of another: the other holds its last line, at the same place. */
  async function startOf(shorter, longer) {
    const a = await feed.lines({ ...ref(shorter), from: 0, max: 0 });
    if (a.missing || a.size === 0) return false;
    const p = await lineOf(longer, a.size - 1);
    return Boolean(p) && p.fingerprint === a.last && p.end === a.bytes;
  }

  /**
   * The SHA-256 under way of every byte sent of a part, as for a file
   * (fingerprintFrom), built from the lines the feed gives: once in a run,
   * from the part's first line, and compared with the fingerprint kept. A
   * stretch of the book that is not its lines, each with one line break
   * and nothing between (an empty line, a carriage return: the recorder
   * writes neither), cannot be built from lines: the fingerprint is then
   * set aside for that part ('dropped'), as for a part from an earlier
   * version.
   */
  async function feedFingerprint(index, entry) {
    const part = state.parts[index];
    const h = hashers.get(index);
    if (h && h.bytes === part.bytes) return true;
    if (part.count === 0) { hashers.set(index, { hasher: createHash('sha256'), bytes: 0 }); return true; }
    if (!part.sha) { hashers.delete(index); return true; }
    const hasher = createHash('sha256');
    let at = 0;
    let n = 0;
    while (n < part.count) {
      const a = await feed.lines({ ...ref(entry), from: n });
      if (a.missing || a.lines.length === 0) return false;
      for (let i = 0; i < a.lines.length && n < part.count; i++, n++) {
        if (a.starts[i] !== at || a.ends[i] !== at + Buffer.byteLength(a.lines[i]) + 1) return dropFingerprint(index, 'its bytes are not its lines alone');
        hasher.update(`${a.lines[i]}\n`);
        at = a.ends[i];
      }
    }
    if (at !== part.bytes || hasher.copy().digest('base64url') !== part.sha) return false;
    hashers.set(index, { hasher, bytes: at });
    return true;
  }

  function dropFingerprint(index, why) {
    hashers.delete(index);
    const { sha: _set, ...rest } = state.parts[index];
    state.parts[index] = rest;
    remember();
    sayOnce(`unfingerprinted:${index}`, `the fingerprint of every byte sent of part ${index} is set aside (${why}); --same-book cannot be used for it`);
    return 'dropped';
  }

  /**
   * Uploads the lines a book holds beyond those already sent of a part, a
   * batch at a time; returns how many were sent, or -1 where the book does
   * not hold what was sent. The first question may wait (wait seconds) for
   * something new.
   */
  async function sendFeed(index, entry, wait = 0) {
    const k = await key();
    let sent = 0;
    let first = true;
    for (;;) {
      const part = state.parts[index];
      const a = await feed.lines({ ...ref(entry), from: part.count, wait: first && sent === 0 ? wait : 0 });
      if (a.missing) return sent;
      // Every answer, not only the first of a round, must go on from the last
      // line sent: the line before the place asked for has its fingerprint,
      // at its place in bytes, and the first line given starts after it.
      if (part.count > 0) {
        const p = a.previous;
        if (!p || p.fingerprint !== part.last || (Number.isInteger(part.bytes) && p.end !== part.bytes)) return -1;
        if (a.starts.length > 0 && a.starts[0] < p.end) return -1;
        // A part kept by an earlier version knows only its count and last fingerprint: the feed says where that line is.
        if (!Number.isInteger(part.bytes) || !Number.isInteger(part.start)) state.parts[index] = { ...part, start: p.start, bytes: p.end };
      } else if (a.previous !== null) return -1;
      if (first) {
        first = false;
        if ((await feedFingerprint(index, entry)) === false) return -1;
      }
      if (a.lines.length === 0) return sent;
      for (let i = 0; i < a.lines.length; i++) {
        const part = state.parts[index];
        const seq = part.count;
        const line = { text: a.lines[i], start: a.starts[i], end: a.ends[i] };
        const sealed = await sealEntry(cc, k, connection.objectId, seq, line.text, index);
        const ofThisPart = (m) => Boolean(m) && (m.part === undefined ? index === 0 : m.part === index);
        let reply;
        try {
          reply = await send({
            type: 'provared-append', objectId: connection.objectId, appendCapabilitySecret: connection.appendCapabilitySecret, part: index, seq, sealed: cc.toBase64Url(sealed),
          });
        } catch (e) {
          // As for a file: sent last time and not remembered, only for the first line of a round.
          if (e.reason === 'conflict' && ofThisPart(e.serverMessage) && e.serverMessage.next === seq + 1 && sent === 0) {
            log.info(`provared-connect: line ${seq} of part ${index} was already on the server`);
          } else {
            if (e.reason === 'conflict' && index > 0 && e.serverMessage && e.serverMessage.part === undefined) {
              throw Object.assign(new Error('the server does not keep parts (it is from before them): deploy the server first; nothing more is uploaded'), { reason: 'conflict' });
            }
            if (e.reason === 'conflict') throw conflictStop(e, index, seq, ofThisPart(e.serverMessage));
            throw e;
          }
        }
        if (reply && reply.part !== undefined && reply.part !== index) throw Object.assign(new Error(`the server answered for part ${reply.part ?? '(none)'} where part ${index} was sent; nothing more is uploaded`), { reason: 'conflict' });
        // The fingerprint of every byte sent goes on where the bytes are this line and its line break, straight after the last.
        const h = hashers.get(index);
        let sha = part.sha;
        if (h) {
          if (line.start === h.bytes && line.end === line.start + Buffer.byteLength(line.text) + 1) {
            h.hasher.update(`${line.text}\n`);
            h.bytes = line.end;
            sha = h.hasher.copy().digest('base64url');
          } else {
            dropFingerprint(index, 'its bytes are not its lines alone');
            sha = undefined;
          }
        }
        const { sha: _old, ...rest } = state.parts[index];
        state.parts[index] = { ...rest, id: rest.id || entry.id || a.id, count: seq + 1, last: sha256(line.text), start: line.start, bytes: line.end, ...(sha ? { sha } : {}) };
        remember();
        sent++;
      }
    }
  }

  /** As follow, through the feed: a part before the one in force, followed for lines added at the end of its book. */
  async function followFeed(index, listing) {
    const part = state.parts[index];
    if (!part.file) return 0;
    const kept = keptOf(listing);
    const k = part.id ? kept.find((x) => x.id === part.id) : kept.find((x) => x.file === part.file);
    if (!k) {
      sayOnce(`gone:${index}`, `the book of part ${index} (${part.file}) is not among those the recorder offers; it is not followed while it is not there`);
      // Its name now holds another book: the part is no longer read from that name.
      if (part.id && kept.some((x) => x.file === part.file)) { state.parts[index] = { ...part, file: null }; remember(); }
      return 0;
    }
    part.file = k.file;
    if (Number.isInteger(part.bytes) && k.size === part.bytes) return 0;
    const sent = await sendFeed(index, k);
    if (sent < 0) {
      sayOnce(`changed:${index}`, `${part.file} no longer holds the ${part.count} lines of part ${index} already uploaded; nothing more is uploaded into part ${index}`, 'error');
      state.parts[index] = { ...state.parts[index], file: null };
      remember();
      return 0;
    }
    return sent;
  }

  /** As newKept, through the feed: a kept book not yet seen, not empty, and not a copy of a part already sent. */
  async function newKeptFeed(k, listing) {
    if (!unseen(k) || isOlder(k) || k.size === 0) return false;
    const last = state.parts.length - 1;
    const bookOf = (p, i) => (i === last ? inForceOf(listing) : keptOf(listing).find((x) => (p.id ? x.id === p.id : x.file === p.file)));
    let copyOf = -1;
    for (let i = 0; i < state.parts.length && copyOf < 0; i++) if (state.parts[i].count > 0 && (await holdsIn(k, state.parts[i]))) copyOf = i;
    for (let i = 0; i < state.parts.length && copyOf < 0; i++) {
      const own = state.parts[i].count > 0 && state.parts[i].file && state.parts[i].file !== k.file ? bookOf(state.parts[i], i) : null;
      if (own && (await startOf(k, own))) copyOf = i;
    }
    if (copyOf < 0) return true;
    state.older.push({ file: k.file, id: k.id });
    sayOnce(`copy:${k.file}:${k.id}`, `${k.file} holds what part ${copyOf} already sent: a copy, set aside`);
    return false;
  }

  /** As keptSince, through the feed. */
  async function keptSinceFeed(listing) {
    const last = state.parts.length - 1;
    if (state.parts[last].count > 0) return;
    const setAside = state.older.length;
    const later = [];
    for (const k of keptOf(listing)) if (await newKeptFeed(k, listing)) later.push(k);
    if (later.length === 0) { if (state.older.length !== setAside) remember(); return; }
    hashers.clear();
    const inForce = state.parts.pop();
    for (const k of later) state.parts.push({ ...fresh(k.file), id: k.id });
    state.parts.push(inForce);
    remember();
    log.info(`provared-connect: ${later.length} book(s) the recorder kept come before the book in force, as parts ${last} to ${state.parts.length - 2}`);
  }

  /** As findMoved, through the feed: where the part in force is now, when the book in force is not its book. */
  async function findMovedFeed(part, bookHolds, listing, inForce) {
    const kept = keptOf(listing);
    if (part.id) {
      const same = kept.find((k) => k.id === part.id);
      if (same) return same;
    }
    const isPart = (k) => state.parts.some((p) => (k.id && p.id ? p.id === k.id : p.file === k.file));
    const allowOlder = Boolean(state.stage0) && !bookHolds;
    const candidates = kept.filter((k) => !isPart(k) && (allowOlder || !isOlder(k))).sort((a, b) => (isOlder(a) - isOlder(b)) || (b.number - a.number));
    for (const k of candidates) {
      if (!(await holdsIn(k, part))) continue;
      // A kept book that is a start of the book in force is a copy taken earlier, not the part's own.
      if (bookHolds && inForce && (await startOf(k, inForce))) continue;
      return k;
    }
    return null;
  }

  async function syncFeedOnce(wait) {
    savePending();
    const listing = await feed.books();
    loadFeed(listing);
    let sent = 0;
    for (let i = 0; i < state.parts.length - 1; i++) sent += await followFeed(i, listing);
    await keptSinceFeed(listing);
    for (let i = 0; i < state.parts.length - 1; i++) sent += await followFeed(i, listing);
    const last = state.parts.length - 1;
    const part = state.parts[last];
    const inForce = inForceOf(listing);
    if (part.count === 0 && part.id && (!inForce || inForce.id !== part.id)) {
      // A part that names a book and has no line sent yet: where the recorder
      // kept that book, it is that part's; otherwise nothing was sent from it,
      // and the part is the book in force's.
      const kept = keptOf(listing).find((k) => k.id === part.id);
      if (kept) { switchTo(kept); return syncFeedOnce(0); }
      state.parts[last] = { ...part, id: null };
    }
    if (part.count > 0) {
      // The book in force is the part in force's own only where its identity is the one kept.
      const same = inForce && part.id && inForce.id === part.id;
      if (!same) {
        const bookHolds = inForce ? await holdsIn(inForce, part) : false;
        const moved = await findMovedFeed(part, bookHolds, listing, inForce);
        if (moved) { switchTo(moved); return syncFeedOnce(0); }
        if (!inForce) return part.count;
        if (part.id && inForce.id) {
          throw new Error(`the book in force that the recorder offers is not the book the ${part.count} lines already uploaded were read from (it has another identity), and no book the recorder kept is or holds them; nothing more is uploaded. If the recorder started a new book and its kept file was moved out of its folder, put that file back`);
        }
        if (!bookHolds) throw new Error(`the book in force that the recorder offers no longer holds the ${part.count} lines already uploaded in that order, and no book it kept does; nothing more is uploaded`);
      }
    }
    if (!inForce) return part.count;
    const n = await sendFeed(last, inForce, sent === 0 ? wait : 0);
    if (n < 0) throw new Error(`the book in force that the recorder offers no longer holds the ${state.parts[last].count} lines already uploaded in that order, and no book it kept does; nothing more is uploaded`);
    sent += n;
    if (sent > 0) log.info(`provared-connect: ${sent} new line(s); ${state.parts[last].count} on the server in part ${last}`);
    return state.parts[last].count;
  }

  function sync({ wait = 0 } = {}) {
    if (!busy) busy = (feed ? syncFeedOnce(Math.max(0, Math.min(25, wait))) : syncOnce()).finally(() => { busy = null; });
    return busy;
  }

  function parts() {
    // Through the feed, nothing in the recorder's folder but the state is looked at.
    if (feed) return (state ?? readState(stateFile) ?? { parts: [fresh(bookName)] }).parts.map((p) => ({ file: p.file, count: p.count }));
    load();
    return state.parts.map((p) => ({ file: p.file, count: p.count }));
  }

  function close() {
    if (socket) { try { socket.close(); } catch { /* gone */ } socket = null; }
  }

  return Object.freeze({ sync, close, connect, parts, key });
}

// --- one uploader at a time for a book ---

function running(pidFile) {
  if (!existsSync(pidFile)) return false;
  const pid = Number(readFileSync(pidFile, 'utf8').trim());
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch { return false; }
}

/**
 * Takes the lock of a book for this process: <book>.uploader.lock holds its
 * process number. A lock left by a process that is no longer running is
 * taken over. Returns a function that gives it back, or throws where
 * another uploader holds it.
 */
export function lockBook(book) {
  const lockFile = `${book}.uploader.lock`;
  for (let tries = 0; tries < 2; tries++) {
    try {
      const fd = openSync(lockFile, 'wx');
      writeSync(fd, String(process.pid));
      closeSync(fd);
      return () => { try { if (readFileSync(lockFile, 'utf8').trim() === String(process.pid)) unlinkSync(lockFile); } catch { /* gone */ } };
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      if (running(lockFile)) throw Object.assign(new Error(`another uploader (process ${readFileSync(lockFile, 'utf8').trim()}) is sending this book; this one does not start`), { code: 'another-uploader' });
      // Left by a process that stopped: taken over.
      try { unlinkSync(lockFile); } catch { /* taken by another meanwhile */ }
    }
  }
  throw Object.assign(new Error('another uploader took the lock of this book first; this one does not start'), { code: 'another-uploader' });
}

export const USAGE = `usage: npx provared-connect <line> [--feed <address> --feed-token <file> | --book <file>]
       npx provared-connect --connection <file> [--feed <address> --feed-token <file> | --book <file>] [--once | --ensure | --same-book]
The line is copied from the book's page on the application. With neither --feed nor --book, the recorder beside
Claude Code is taken: its feed at ${DEFAULT_FEED} and its token in ${DEFAULT_FEED_TOKEN}.`;

/**
 * What the command line asks: the connection file, and either the feed
 * (its address and token file) or the book file. Through the feed, the
 * uploader's own files are named as the --book way names them for the
 * recorder's book.jsonl in the folder that holds the token file, which is
 * the recorder's: so the state, the lock and the process number are the
 * ones an uploader with --book on that book keeps, and are shared.
 */
export function readCommandLine(argv) {
  const value = (name) => {
    const i = argv.indexOf(name);
    return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : null;
  };
  const connection = value('--connection') ?? 'provared-app-connection.json';
  let feedAddress = value('--feed');
  let feedToken = value('--feed-token');
  const book = value('--book');
  if (!feedAddress && !feedToken && !argv.includes('--feed') && !argv.includes('--feed-token') && !argv.includes('--book')) {
    // Neither named: the recorder beside Claude Code, where it is.
    feedAddress = DEFAULT_FEED;
    feedToken = DEFAULT_FEED_TOKEN;
  }
  if (feedAddress || feedToken || argv.includes('--feed') || argv.includes('--feed-token')) {
    if (!feedAddress || !feedToken) return { error: 'give both --feed <address> and --feed-token <file>' };
    if (argv.includes('--book')) return { error: 'give --feed or --book, not both: through the feed, the uploader opens no book file' };
    if (argv.includes('--same-book')) return { error: '--same-book is for --book: through the feed, the recorder names its books itself' };
    return { connection, feedAddress, feedToken, base: join(dirname(feedToken), 'book.jsonl') };
  }
  if (!book) return { error: 'give --feed <address> with --feed-token <file>, or --book <file>' };
  return { connection, book, base: book };
}

/**
 * The uploader as a program, from its command line (the arguments after the
 * program's name). Gives back the exit code, or null where it runs on.
 */
export async function main(argv = process.argv.slice(2)) {
  const said = readCommandLine(argv);
  if (said.error) { console.error(`provared-connect: ${said.error}\n${USAGE}`); return 2; }
  const { base } = said;
  const pidFile = `${base}.uploader.pid`;
  if (argv.includes('--ensure')) return ensure(said, pidFile);
  const connection = readConnection(said.connection);
  let feed = null;
  if (said.feedAddress) {
    let token;
    try { token = readFileSync(said.feedToken, 'utf8').trim(); } catch (e) { console.error(`provared-connect: the feed token file ${said.feedToken} could not be read: ${e.message}`); return 1; }
    try { feed = feedClient({ address: said.feedAddress, token }); } catch (e) { console.error(`provared-connect: ${e.message}`); return 2; }
  } else {
    console.error("provared-connect: reading the book file (--book) is the fragile way: on Windows, a program that holds the file open can make the recorder's writing of it fail. Where the recorder offers a feed, use --feed http://127.0.0.1:8794 --feed-token <the recorder's folder>/feed-token instead.");
  }
  let unlock;
  try { unlock = lockBook(base); } catch (e) { console.error(`provared-connect: ${e.message}`); return 1; }
  process.on('exit', unlock);
  const uploader = createUploader({ connection, book: base, sameBook: argv.includes('--same-book'), feed });
  const once = argv.includes('--once');
  // true: done; 'again': failed for now (the server restarting, the network
  // down, the recorder stopped or busy); false: refused for good.
  const attempt = async (wait = 0) => {
    try { await uploader.sync({ wait }); } catch (e) {
      const meaning = e.reason === 'gap' || e.reason === 'part-gap' ? ' (the state beside the book is ahead of what the server holds, so this uploader stops; nothing is lost, because the book stays on this computer)' : '';
      console.error(`provared-connect: ${e.reason || e.code || 'error'}: ${e.message}${meaning}`);
      if (e.reason === 'conflict' || e.reason === 'gap' || e.reason === 'part-gap' || e.reason === 'forbidden' || e.reason === 'feed-refused' || e.reason === 'state-unreadable' || e.code === 'another-uploader' || /no longer holds|is not the file|is not the book/.test(e.message)) return false;
      uploader.close();
      return 'again';
    }
    return true;
  };
  // Records handed to the recorder: through the feed only.
  let handover = null;
  let side = null;
  if (feed) {
    side = bookSide({ cc: createCryptoCore({ namespace: connection.namespace }), connection, connect: uploader.connect, key: uploader.key });
    handover = createHandover({ feed, readKept: side.readKept, putOutcomes: side.putOutcomes, log: console });
  }
  const handOverOnce = async () => {
    try { await handover.round(); } catch (e) { console.error(`provared-connect: records kept with the book could not be handed to the recorder now: ${e.reason || e.code || 'error'}: ${e.message}`); }
  };
  if (once) {
    let ok = await attempt();
    if (ok === true && handover) { await handOverOnce(); ok = await attempt(); }
    uploader.close();
    return ok === true ? 0 : 1;
  }
  if (running(pidFile)) { console.error(`provared-connect: one is already running for ${base}`); return 1; }
  writeFileSync(pidFile, String(process.pid));
  const forget = () => { try { if (readFileSync(pidFile, 'utf8').trim() === String(process.pid)) unlinkSync(pidFile); } catch { /* gone */ } };
  process.on('exit', forget);
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => process.exit(0));
  if (feed) {
    console.log(`provared-connect: following the books of the recorder at ${feed.origin}; press Ctrl and C to stop.`);
    // Beside the rounds of lines: a hand-over as soon as the book's content
    // changes (the engine says so to whoever watches its shelf), and once a
    // minute besides.
    let wake = null;
    (async () => {
      for (;;) {
        await handOverOnce();
        try { await side.watch(() => { if (wake) wake(); }); } catch { /* watched again at the next round */ }
        await new Promise((r) => { const t = setTimeout(r, HAND_OVER_AGAIN_MS); wake = () => { clearTimeout(t); wake = null; r(); }; });
      }
    })();
    // One round after another: a round that finds nothing new waits up to
    // 25 seconds at the recorder for something new. A round that failed for
    // now is tried again 30 seconds later.
    for (;;) {
      const alive = await attempt(25);
      if (alive === false) return 1;
      if (alive === 'again') await new Promise((r) => setTimeout(r, RETRY_MS));
    }
  }
  console.log(`provared-connect: watching ${base} and the files the recorder keeps beside it; press Ctrl and C to stop.`);
  let alive = await attempt();
  if (alive === false) return 1;
  // Every two seconds the book file and each kept file are looked at; a
  // kept file whose size has not changed is not read. A round that failed
  // for now is tried again 30 seconds later.
  let retryAt = alive === 'again' ? Date.now() + RETRY_MS : 0;
  let turn = false;
  setInterval(async () => {
    if (turn || Date.now() < retryAt) return;
    turn = true;
    try {
      alive = await attempt();
      if (alive === false) process.exit(1);
      retryAt = alive === 'again' ? Date.now() + RETRY_MS : 0;
    } finally { turn = false; }
  }, POLL_MS);
  return null;
}

/**
 * Starts the uploader in the background unless one runs for this book, and
 * waits up to ten seconds for it to be running. The command line of the
 * program started names the connection file, never what it holds; its
 * output goes to <book>.uploader.log beside the book. 0 once it runs,
 * 1 where it did not start.
 */
export async function ensure(said, pidFile = `${said.base}.uploader.pid`) {
  if (running(pidFile)) return 0;
  const logFile = `${said.base}.uploader.log`;
  appendFileSync(logFile, `${new Date().toISOString()} starting\n`);
  const out = openSync(logFile, 'a');
  const how = said.feedAddress ? ['--feed', said.feedAddress, '--feed-token', said.feedToken] : ['--book', said.book];
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', fileURLToPath(new URL('./bin.mjs', import.meta.url)), '--connection', said.connection, ...how],
    { detached: true, stdio: ['ignore', out, out], windowsHide: true });
  child.unref();
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 250));
    if (running(pidFile)) return 0;
  }
  console.error(`provared-connect: it did not start; see ${logFile}`);
  return 1;
}

/** Whether the uploader whose process number <book>.uploader.pid holds is running. */
export function uploaderRunning(pidFile) { return running(pidFile); }

if (process.argv[1] && process.argv[1].replace(/\\/g, '/').endsWith('/upload.mjs')) {
  main().then((code) => { if (code !== null) process.exit(code); }, (e) => { console.error(`provared-connect: ${e.message}`); process.exit(2); });
}
