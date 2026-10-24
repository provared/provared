#!/usr/bin/env node
// A witness for seals, run as a small service on this computer (format
// description, section 29). For each recorder, person and agent it holds
// the latest seal it has signed for, and it signs a statement for a new
// seal only where the new seal extends that one, in the same book or as
// the first seal of the next book. The library's witness (openWitness)
// decides and signs; this program keeps what it holds on the disk, and
// answers on a port.
//
//   provared-witness init [--name <label>] [--recorder <fingerprint>]... [--port <n>]
//                                      make the witness's keys and tokens if they are missing, and name the
//                                      recorders it serves (by the fingerprint of their key sets)
//   provared-witness start [--ready] [--port <n>]
//                                      run the witness in this terminal; --ready says, at this start, that its
//                                      folder was not put back to an older copy (see "ready")
//   provared-witness status            what the running witness holds
//   provared-witness ready             tell the running witness that its folder was not put back: it signs from then
//   provared-witness update <book> [--seal <file>]...
//                                      hand the running witness, from a copy, the statements it signed for the
//                                      seals of a book: it takes the latest of them as what it holds
//   provared-witness forget <sequence> stop holding a sequence (it then signs whatever it is next shown for it)
//   provared-witness stop              stop the running witness
//
// The folder (PROVARED_WITNESS_DIR, or ~/.provared/witness) holds:
//   witness-keys.jwk   the witness's two private keys, Ed25519 and ML-DSA-87 (never share)
//   witness-token      the token a recorder must hold to ask the witness to sign (give it to the recorder alone)
//   operator-token     the token of the operator's commands: status, ready, update, forget, stop (never share)
//   witness.json       its settings: its name, the recorders it serves, its port, its limits
//   journal.jsonl      every statement it gave out, every seal it was brought up to date with, and every sequence
//                      it was told to forget, one to a line, in order, since its last checkpoint: only added to,
//                      and made sure to be on the disk before each answer
//   state.json         what it holds, as the library's witness hands it back, with the journal lines it reflects:
//                      replaced whole, and made sure to be on the disk before each answer
//   checkpoint.json    what it held when it last began its journal again (every 256 lines, by default): the
//                      latest seal of each sequence with its statement, which is all it needs to refuse a fork
//   journal-mark.json  the segment and the number of journal lines last saved, apart from the state: so that, with
//                      state.json lost, a journal emptied or cut short since is seen at the start
//
// WHAT IT SAVES BEFORE IT GIVES ANYTHING OUT. For each new statement: the
// journal line, then the state, then the journal mark, each made sure to be
// on the disk (fsync); only then is the statement given out. What it says it holds (/latest,
// status) is what was last saved, never what the library's witness holds in
// memory. If anything cannot be saved, it gives out nothing more, by any
// route, until it is started again.
//
// AT EVERY START, the first included, it takes again every journal line that
// its state does not yet reflect, and then signs nothing ("witness-not-ready")
// until its operator says that its folder was not put back to an older copy
// ("ready", or "start --ready"). It cannot tell that by itself: a folder put
// back, journal and all, looks like any other. Before saying so, the operator
// can hand it the statements a recorder holds ("update"), from the recorder's
// books and the statements kept beside them.
//
// WHO MAY ASK. Only a program that holds the witness's token (a recorder) may
// ask it to sign, or ask what it holds; only one that holds the operator's
// token may use the operator's commands. Neither token ever travels: a
// program asks for a conversation (GET /hello, with a random number of its
// own), the witness proves that it knows the token, and each question then
// carries an HMAC-SHA-256 (RFC 2104) over itself, its body included, under a
// key both sides work out from the token; each answer carries one over its
// code and every byte. A conversation takes one question. It signs only for
// seals of the recorders its operator named, and starts a new sequence only
// from a permission whose passkey signature the library's checker passes.
//
// It listens on 127.0.0.1 only. A program on this computer that can read the
// witness's folder can do whatever the witness can: so run it under another
// user account than the agent's, or on another computer reached through a
// tunnel, for its statements to mean more than that the recorder's own side
// kept to the rules.

import nodeCrypto from 'node:crypto';
import { closeSync, existsSync, fstatSync, fsyncSync, ftruncateSync, mkdirSync, openSync, readFileSync, readSync, realpathSync, renameSync, unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { createServer } from 'node:http';
import { homedir } from 'node:os';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bookIdentity, checkSlip, fingerprint, formatTime, fromBase64url, keySetFingerprint, openWitness, toBase64url, utf8, witnessProof } from 'provared';
import { feedHmac, isRandom, sameProof } from './feed.mjs';

const subtle = globalThis.crypto.subtle;

export const DEFAULT_WITNESS_FOLDER = process.env.PROVARED_WITNESS_DIR || join(homedir(), '.provared', 'witness');
export const DEFAULT_WITNESS_PORT = 8796;
/** The largest body a question may have: a seal (about 52,000 bytes), a first line (at most 131,072 characters), a proof, and for "update" up to four statements. */
export const WITNESS_MAX_BODY = 1024 * 1024;
/** At most this many questions that sign or bring the witness up to date are taken on at once (one is answered at a time); one more is answered at once with 429. */
export const WITNESS_MAX_WAITING = 8;
/** A conversation must have its question within this long of its hello. */
export const WITNESS_HELLO_MS = 2 * 60 * 1000;
/** At most this many conversations that had their question are remembered (so that none is used twice); one more question is answered with 429 until the oldest are forgotten. */
export const WITNESS_MAX_REMEMBERED = 10000;
/** By default: at most this many new statements in any hour, and at most this many sequences held. */
export const DEFAULT_STATEMENTS_PER_HOUR = 120;
export const DEFAULT_MAX_SEQUENCES = 64;
/** By default the journal is begun again after this many lines, with a checkpoint of what the witness holds. */
export const DEFAULT_JOURNAL_LINES = 256;
/** The longest a line of a book may be (the format description, section 9), and so the first line handed over. */
const MAX_LINE = 131072;
const FINGERPRINT = /^[A-Za-z0-9_-]{43}$/;
const SERVICE_STATE = 'provared.witness-service-state.v1';
const CHECKPOINT_TYPE = 'provared.witness-checkpoint.v1';
const MARK_TYPE = 'provared.witness-journal-mark.v1';
/**
 * The advice for starting a new witness in a folder: every file in which a
 * witness keeps its keys and what it signed goes out together; leaving one
 * behind gives the new witness the old one's journal, state, checkpoint or
 * mark. The tokens, the settings and the lock may stay.
 */
const NEW_WITNESS = 'To start a new witness here, move all of these out of the folder together, and then run init: witness-keys.jwk, journal.jsonl, state.json, checkpoint.json and journal-mark.json (each that is there). witness-token, operator-token and witness.json may stay; the recorders must then be given the new witness with add-witness.';
const ROLES = ['recorder', 'operator'];

// The labels of the HMACs: each proof is of one kind only. The last is the
// witness's own, for the number it gives a conversation, and no one else needs it.
export const WITNESS_LABELS = Object.freeze({
  witness: 'provared witness v1: the witness knows the token',
  key: 'provared witness v1: the key of a conversation',
  question: 'provared witness v1: a question',
  answer: 'provared witness v1: an answer',
  session: 'provared witness v1: the witness\'s number for a conversation',
});

const SELF = realpathSync(fileURLToPath(import.meta.url));
const RUN = SELF.split(sep).includes('node_modules') ? 'provared-witness' : `node ${SELF.includes(' ') ? `"${SELF}"` : SELF}`;

export const witnessFiles = (folder) => ({
  keys: join(folder, 'witness-keys.jwk'),
  token: join(folder, 'witness-token'),
  operator: join(folder, 'operator-token'),
  settings: join(folder, 'witness.json'),
  journal: join(folder, 'journal.jsonl'),
  state: join(folder, 'state.json'),
  checkpoint: join(folder, 'checkpoint.json'),
  mark: join(folder, 'journal-mark.json'),
});

const sha256 = (bytes) => nodeCrypto.createHash('sha256').update(bytes).digest('base64url');

// --- files that are made sure to be on the disk ---

// On Windows, writing to a file, or renaming one, is refused while another
// program (a virus scanner, a backup tool) holds it open; each is tried again
// for up to ten seconds, as the recorder does.
const BUSY = ['EPERM', 'EBUSY', 'EACCES'];
export function untilFree(step, ms = 10000) {
  const pause = new Int32Array(new SharedArrayBuffer(4));
  const deadline = Date.now() + ms;
  for (let wait = 10; ; wait = Math.min(wait * 2, 200)) {
    try {
      return step();
    } catch (e) {
      if (!BUSY.includes(e.code) || Date.now() >= deadline) throw e;
      Atomics.wait(pause, 0, 0, wait);
    }
  }
}

function writeAll(fd, text) {
  const bytes = Buffer.from(text);
  for (let at = 0; at < bytes.length;) at += writeSync(fd, bytes, at, bytes.length - at);
}

/** Add text to the end of a file, and make sure it is on the disk (fsync) before this returns. */
export function appendDurably(path, text, mode = 0o600) {
  const fd = untilFree(() => openSync(path, 'a', mode));
  try {
    writeAll(fd, text);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Replace a file whole: a temporary file is written and made sure to be on
 * the disk, then put in the file's place. Where the system allows it (not
 * on Windows, which cannot open a folder to do so), the folder is made sure
 * to hold the new name too.
 */
export function replaceDurably(path, text, mode = 0o600) {
  const temporary = `${path}.tmp`;
  try {
    const fd = untilFree(() => openSync(temporary, 'w', mode));
    try {
      writeAll(fd, text);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    untilFree(() => renameSync(temporary, path));
  } catch (e) {
    try { unlinkSync(temporary); } catch { /* nothing to remove */ }
    throw e;
  }
  if (process.platform !== 'win32') {
    let fd;
    try {
      fd = openSync(dirname(path), 'r');
      fsyncSync(fd);
    } catch {
      // Some systems do not allow it; the file itself is on the disk.
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
  }
}

/** The first line of a file, without its line break, read a piece at a time; null where the file has none. */
export function firstLineOfFile(path) {
  const fd = untilFree(() => openSync(path, 'r'));
  try {
    const pieces = [];
    let total = 0;
    for (;;) {
      const piece = Buffer.alloc(65536);
      const got = readSync(fd, piece, 0, piece.length, total);
      if (got === 0) return null;
      const end = piece.subarray(0, got).indexOf(10);
      if (end >= 0) {
        pieces.push(piece.subarray(0, end));
        let line = Buffer.concat(pieces).toString('utf8');
        if (line.endsWith('\r')) line = line.slice(0, -1);
        return line;
      }
      pieces.push(piece.subarray(0, got));
      total += got;
      if (total > 4 * MAX_LINE) return null;
    }
  } finally {
    closeSync(fd);
  }
}

// --- the witness's keys and tokens ---

async function newWebKey(alg) {
  const pair = await subtle.generateKey({ name: alg }, true, ['sign', 'verify']);
  return subtle.exportKey('jwk', pair.privateKey);
}

function publicOf(jwk) {
  if (jwk?.kty === 'OKP' && jwk.crv === 'Ed25519') return { alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: jwk.x };
  if (jwk?.kty === 'AKP' && jwk.alg === 'ML-DSA-87') return { alg: 'ML-DSA-87', kty: 'AKP', pub: jwk.pub };
  throw new Error('a key in the file is of a kind a witness does not keep.');
}

/** The witness's public key set, and its private keys. */
export async function loadWitnessKeys(folder) {
  const path = witnessFiles(folder).keys;
  let jwks;
  try {
    jwks = JSON.parse(readFileSync(path, 'utf8')).keys;
  } catch (e) {
    throw new Error(`The witness's key file ${path} could not be read as a key file (${e.code ?? 'not JSON'}).`);
  }
  if (!Array.isArray(jwks) || jwks.length !== 2) throw new Error(`The witness's key file ${path} must hold two keys: Ed25519, then ML-DSA-87.`);
  const keys = jwks.map(publicOf);
  if (keys[0].alg !== 'Ed25519' || keys[1].alg !== 'ML-DSA-87') throw new Error(`The keys in ${path} must be Ed25519, then ML-DSA-87.`);
  const privateKeys = [];
  for (const [i, jwk] of jwks.entries()) privateKeys.push(await subtle.importKey('jwk', jwk, { name: keys[i].alg }, false, ['sign']));
  return { keys, privateKeys };
}

// A token: 32 random bytes in base64url, made only where there is none.
function makeToken(path) {
  try {
    writeFileSync(path, `${nodeCrypto.randomBytes(32).toString('base64url')}\n`, { flag: 'wx', mode: 0o600 });
  } catch (e) {
    if (e.code !== 'EEXIST') throw e;
  }
}

/** A token read from its file: 43 letters, digits, "-" and "_", as made. */
export function readToken(path) {
  let text;
  try {
    text = readFileSync(path, 'utf8').trim();
  } catch (e) {
    throw new Error(`The token file ${path} could not be read (${e.code ?? e.message}).`);
  }
  if (!isRandom(text)) throw new Error(`The file ${path} does not hold a token: 43 letters, digits, "-" and "_".`);
  return text;
}

// --- settings ---

/** The witness's settings, from witness.json, checked. */
export function readSettings(folder) {
  const path = witnessFiles(folder).settings;
  let value = {};
  if (existsSync(path)) {
    try {
      value = JSON.parse(readFileSync(path, 'utf8').replace(/^﻿/, ''));
    } catch {
      throw new Error(`${path} is not JSON.`);
    }
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${path} does not hold one JSON object.`);
  const name = value.name ?? 'A witness on this computer';
  if (typeof name !== 'string' || name.length < 1 || name.length > 100 || /[\u0000-\u001f\u007f]/.test(name)) {
    throw new Error(`"name" in ${path} must be a short label: 1 to 100 characters, with no control characters.`);
  }
  const recorders = value.recorders ?? [];
  if (!Array.isArray(recorders) || recorders.length > 256 || !recorders.every((r) => typeof r === 'string' && FINGERPRINT.test(r))) {
    throw new Error(`"recorders" in ${path} must be a list of the fingerprints of recorders' key sets, each 43 letters, digits, "-" and "_".`);
  }
  const whole = (key, fallback, lowest, highest) => {
    const v = value[key] ?? fallback;
    if (!Number.isInteger(v) || v < lowest || v > highest) throw new Error(`"${key}" in ${path} must be a whole number from ${lowest} to ${highest}.`);
    return v;
  };
  return {
    path,
    name,
    recorders: [...new Set(recorders)],
    port: value.port === undefined ? null : whole('port', 0, 1, 65535),
    statementsPerHour: whole('statementsPerHour', DEFAULT_STATEMENTS_PER_HOUR, 1, 100000),
    maxSequences: whole('maxSequences', DEFAULT_MAX_SEQUENCES, 1, 100000),
    journalLines: whole('journalLines', DEFAULT_JOURNAL_LINES, 1, 100000),
  };
}

/**
 * Make what a witness needs where it is missing (its keys, its two tokens,
 * an empty journal), and add to its settings. A folder that holds a journal
 * but no keys is refused: new keys would be another witness, and the
 * journal is the old one's. The keys and the journal are made together, so
 * that a witness whose journal has gone is noticed (startWitness).
 * @param {{folder?: string, name?: string, recorders?: string[], port?: number}} o
 * @returns {Promise<{fingerprint: string, made: boolean, settings: object, files: object}>}
 */
export async function initWitness({ folder = DEFAULT_WITNESS_FOLDER, name, recorders = [], port } = {}) {
  const f = witnessFiles(folder);
  mkdirSync(folder, { recursive: true, mode: 0o700 });
  for (const r of recorders) if (!FINGERPRINT.test(r)) throw new Error(`"${r}" is not the fingerprint of a recorder's key set: 43 letters, digits, "-" and "_".`);
  const before = readSettings(folder);
  let made = false;
  if (!existsSync(f.keys)) {
    // What a witness keeps of what it signed, left without its keys: new keys would be another witness with the old
    // one's journal, state, checkpoint or mark (an old mark would also stop the new witness's every start).
    const left = [f.journal, f.state, f.checkpoint, f.mark].filter((p) => existsSync(p));
    if (left.length > 0) throw new Error(`${left.map((p) => basename(p)).join(', ')} ${left.length === 1 ? 'is' : 'are'} there, but the witness's keys are not. New keys would be another witness, with what the old one kept. ${NEW_WITNESS}`);
    const jwks = [await newWebKey('Ed25519'), await newWebKey('ML-DSA-87')];
    writeFileSync(f.keys, JSON.stringify({ about: 'The private keys of a witness for seals. Never share this file.', keys: jwks }), { mode: 0o600, flag: 'wx' });
    // The journal, made with the keys: empty, and made sure to be on the disk.
    writeFileSync(f.journal, '', { mode: 0o600, flag: 'wx' });
    appendDurably(f.journal, '');
    made = true;
  }
  makeToken(f.token);
  makeToken(f.operator);
  const settings = {
    about: 'The settings of a witness for seals: its name (a label), the fingerprints of the key sets of the recorders it serves, and its port.',
    name: name ?? before.name,
    recorders: [...new Set([...before.recorders, ...recorders])],
    ...(port !== undefined ? { port } : before.port !== null ? { port: before.port } : {}),
    ...(before.statementsPerHour !== DEFAULT_STATEMENTS_PER_HOUR ? { statementsPerHour: before.statementsPerHour } : {}),
    ...(before.maxSequences !== DEFAULT_MAX_SEQUENCES ? { maxSequences: before.maxSequences } : {}),
    ...(before.journalLines !== DEFAULT_JOURNAL_LINES ? { journalLines: before.journalLines } : {}),
  };
  replaceDurably(f.settings, JSON.stringify(settings, null, 2) + '\n');
  const checked = readSettings(folder);
  const { keys } = await loadWitnessKeys(folder);
  return { fingerprint: await keySetFingerprint(keys), made, settings: checked, files: f };
}

// --- talking to a witness ---

/**
 * A program that asks a witness: it opens a conversation for each question,
 * takes nothing before the witness has proved that it knows the token,
 * proves its question, body included, and checks the witness's proof on the
 * answer.
 * @param {{address: string, token: string, role?: 'recorder'|'operator', timeoutMs?: number, fetchImpl?: typeof fetch, signal?: AbortSignal}} o
 * @returns {{ask: (method: 'GET'|'POST', path: string, body?: any) => Promise<{code: number, body: any}>}}
 *   ask throws, with "code", where nothing can be believed: "unreachable", "not-the-witness" (the hello's
 *   proof did not check: another program listens there, or the token is not the witness's), "not-proved"
 */
export function witnessClient({ address, token, role = 'recorder', timeoutMs = 10000, fetchImpl = globalThis.fetch, signal }) {
  const tokenKey = Buffer.from(token);
  const within = () => (signal ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs));
  const fail = (code, message) => Object.assign(new Error(message), { code });
  async function ask(method, path, body) {
    const mine = nodeCrypto.randomBytes(32).toString('base64url');
    let r;
    try {
      r = await fetchImpl(new URL('/hello', address), { headers: { 'Provared-Witness-Hello': mine, 'Provared-Witness-Role': role }, signal: within() });
    } catch (e) {
      throw fail('unreachable', `nothing answered at ${address} (${e.cause?.code ?? e.name})`);
    }
    let hello = null;
    try { hello = await r.json(); } catch { /* not JSON */ }
    if (r.status !== 200 || !hello || !isRandom(hello.session) || !sameProof(hello.proof, feedHmac(tokenKey, WITNESS_LABELS.witness, role, mine, hello.session))) {
      throw fail('not-the-witness', `the program at ${address} did not prove that it knows the token (the token may not be this witness's, or another program listens there)`);
    }
    const key = feedHmac(tokenKey, WITNESS_LABELS.key, role, mine, hello.session);
    const bytes = body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body));
    const proof = feedHmac(key, WITNESS_LABELS.question, `${method} ${path}`, sha256(bytes)).toString('base64url');
    const headers = { 'Provared-Witness-Session': hello.session, 'Provared-Witness-Hello': mine, 'Provared-Witness-Role': role, 'Provared-Witness-Proof': proof };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let answer;
    try {
      r = await fetchImpl(new URL(path, address), { method, headers, body: body === undefined ? undefined : bytes, signal: within() });
      answer = Buffer.from(await r.arrayBuffer());
    } catch (e) {
      throw fail('unreachable', `the witness at ${address} gave no answer (${e.cause?.code ?? e.name})`);
    }
    if (!sameProof(r.headers.get('provared-witness-proof'), feedHmac(key, WITNESS_LABELS.answer, String(r.status), answer))) {
      // What an answer without the proof says is not believed; it is shown, cut short and with no control characters, to help find out why.
      let said = '';
      try { said = String(JSON.parse(answer.toString('utf8')).error ?? '').slice(0, 200).replace(/[\u0000-\u001f\u007f-\u009f]/g, ' '); } catch { /* not JSON */ }
      throw fail('not-proved', `an answer from ${address} (${r.status}) does not carry the witness's proof${said ? ` (it said, unproved: "${said}")` : ''}`);
    }
    try {
      return { code: r.status, body: JSON.parse(answer.toString('utf8')) };
    } catch {
      throw fail('not-proved', `an answer from ${address} is not JSON`);
    }
  }
  return { ask };
}

// --- the service ---

// Whether a process with this number is running.
const alive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === 'EPERM';
  }
};

/**
 * One witness at a time on a folder: two would each hold, in memory, what
 * they signed, and could sign a fork between them. The lock is a file made
 * only where there is none, naming the process. A lock left by a process
 * that is no longer running is taken over under a second file, made only
 * where there is none (witness.lock.takeover): only the start that made it
 * replaces the lock, and only where the lock still holds what that start
 * found, so two starts that find the same stale lock cannot both take it.
 * Gives back the way to let the lock go.
 */
function lockFolder(folder) {
  const path = join(folder, 'witness.lock');
  const takeover = `${path}.takeover`;
  const mine = JSON.stringify({ pid: process.pid, started: new Date().toISOString(), at: nodeCrypto.randomBytes(8).toString('hex') });
  const make = () => {
    try {
      writeFileSync(path, mine, { flag: 'wx', mode: 0o600 });
      return true;
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      return false;
    }
  };
  const look = () => {
    try {
      return readFileSync(path, 'utf8');
    } catch (e) {
      if (e.code === 'ENOENT') return null;
      throw e;
    }
  };
  let held = false;
  const release = () => {
    if (!held) return;
    held = false;
    try {
      if (look() === mine) unlinkSync(path);
    } catch { /* gone already */ }
  };
  const pause = new Int32Array(new SharedArrayBuffer(4));
  for (let tries = 0; tries < 10; tries++) {
    if (make()) {
      held = true;
      return release;
    }
    const found = look();
    if (found === null) continue;
    let other = null;
    try { other = JSON.parse(found); } catch { /* being written by another start */ }
    if (!other || !Number.isInteger(other.pid)) {
      Atomics.wait(pause, 0, 0, 50);
      continue;
    }
    if (alive(other.pid)) {
      throw new Error(`Another witness runs on this folder (process ${other.pid}, started ${other.started}): two would each hold what they signed, and could sign a fork between them, so this one does not start. If no witness runs, the number has been given to another program since: move ${path} out of the folder.`);
    }
    // Left by a process that has ended: taken over, under the second file.
    try {
      writeFileSync(takeover, mine, { flag: 'wx', mode: 0o600 });
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      throw new Error(`Another start is taking over the lock of this folder (${takeover}), so this one does not start. If none is, a start stopped while it took it over: move that file out of the folder.`);
    }
    try {
      if (look() === found) {
        unlinkSync(path);
        if (make()) {
          held = true;
          return release;
        }
      }
    } finally {
      try { unlinkSync(takeover); } catch { /* removed already */ }
    }
  }
  throw new Error(`The lock ${path} could not be taken. Look at the folder before you go on.`);
}

// A journal line begins with its segment and its number, so that a line
// already reflected in what the witness kept is known without being read
// any further.
const JOURNAL_LINE = /^\{"seg":([1-9][0-9]{0,8}),"n":([1-9][0-9]{0,8}),"kind":"(witness|update|forget)",/;
const KINDS = ['witness', 'update', 'forget'];

/**
 * Read the journal a piece at a time, line by line: it is never held as one
 * text. Each line names its segment (see "checkpoints", below) and its
 * number in that segment. A line of the segment the base reflects, numbered
 * at or below what the base reflects, is checked only by its beginning;
 * every later line is read whole and checked, to be taken again. Lines of an
 * earlier segment are what a checkpoint already holds (a stop came after the
 * checkpoint was written and before the journal was begun again). A last line
 * with no line break is one a stop cut off while it was written: the witness
 * answers only once a line is on the disk, and gives out only what is on the
 * disk, so no statement was given out for it; it is taken off the journal.
 * @returns {{lines: number, earlier: number, later: object[]}} lines: the number of lines of the base's segment;
 *   earlier: the number of lines of earlier segments; later: the lines to take again, read
 */
function readJournal(path, base, notes) {
  const fd = untilFree(() => openSync(path, 'r+'));
  const out = { lines: 0, earlier: 0, later: [] };
  try {
    const size = fstatSync(fd).size;
    const piece = Buffer.alloc(1024 * 1024);
    let carry = Buffer.alloc(0);
    let offset = 0;
    let lineStart = 0;
    let seen = 0;
    const take = (bytes) => {
      seen++;
      const head = bytes.subarray(0, 64).toString('latin1');
      const m = JOURNAL_LINE.exec(head);
      if (!m) throw new Error(`Line ${seen} of the journal is not a line this witness writes: the journal was changed, so the witness does not start. Look at it before you go on.`);
      const seg = Number(m[1]);
      const n = Number(m[2]);
      if (seg < base.segment) {
        if (out.lines > 0) throw new Error(`Line ${seen} of the journal is of an earlier segment than the line before it: the journal was changed, so the witness does not start.`);
        out.earlier++;
        return;
      }
      if (seg > base.segment) {
        throw new Error(`Line ${seen} of the journal follows checkpoint ${seg - 1}, and what the witness kept goes only as far as checkpoint ${base.segment - 1}: what it kept is older than its journal (a file was lost or put back), so it does not start. Look at the folder before you go on.`);
      }
      if (n !== out.lines + 1) throw new Error(`Line ${seen} of the journal is numbered ${n} where ${out.lines + 1} was due: lines were taken out, added or moved, so the witness does not start. Look at it before you go on.`);
      out.lines++;
      if (n <= base.journal) return;
      let r;
      try {
        r = JSON.parse(bytes.toString('utf8'));
      } catch {
        throw new Error(`Line ${seen} of the journal is not JSON: the journal was changed, so the witness does not start. Look at it before you go on.`);
      }
      const sound = r && typeof r === 'object' && KINDS.includes(r.kind) && (r.kind === 'forget'
        ? r.sequence && ['agent', 'passkey', 'recorder'].every((k) => typeof r.sequence[k] === 'string' && FINGERPRINT.test(r.sequence[k]))
        : r.entry && typeof r.entry === 'object' && Array.isArray(r.entry.witnesses) && Array.isArray(r.proof) && typeof r.first === 'string');
      if (!sound) throw new Error(`Line ${seen} of the journal is not a line this witness writes: the journal was changed, so the witness does not start. Look at it before you go on.`);
      out.later.push(r);
    };
    while (offset < size) {
      const got = readSync(fd, piece, 0, Math.min(piece.length, size - offset), offset);
      if (got === 0) break;
      offset += got;
      let chunk = Buffer.concat([carry, piece.subarray(0, got)]);
      let from = 0;
      for (let end = chunk.indexOf(10, from); end >= 0; end = chunk.indexOf(10, from)) {
        take(chunk.subarray(from, end));
        lineStart += end - from + 1;
        from = end + 1;
      }
      carry = Buffer.from(chunk.subarray(from));
      chunk = null;
      if (carry.length > 4 * MAX_LINE + 65536) throw new Error(`Line ${seen + 1} of the journal is longer than any line this witness writes: the journal was changed, so the witness does not start.`);
    }
    if (carry.length > 0) {
      notes.push(`The journal's last line (${carry.length} bytes) had no line break: a stop while it was written. The witness answers only once a line is on the disk, and gives out only what is on the disk, so no statement was given out for it: it was taken off the journal.`);
      ftruncateSync(fd, lineStart);
      fsyncSync(fd);
    }
  } finally {
    closeSync(fd);
  }
  return out;
}

/** A state or a checkpoint, read and checked; null where there is none. */
function readKept(path, type, what) {
  if (!existsSync(path)) return null;
  let value;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    value = null;
  }
  const sound = value && value.type === type && Number.isInteger(value.segment) && value.segment >= 1
    && (type !== SERVICE_STATE || (Number.isInteger(value.journal) && value.journal >= 0)) && value.witness && typeof value.witness === 'object';
  if (!sound) throw new Error(`${path} is not ${what} this witness writes, so it does not start. Move it out of the folder, and the witness rebuilds what it holds from its checkpoint and its journal.`);
  return value;
}

/**
 * The journal's mark, read and checked; null where there is none (a witness
 * made before it was kept). It is written after the state, and is never
 * more than the journal held when it was written: so a segment, or a number
 * of lines, beyond what the start finds means lines were lost.
 */
function readMark(path) {
  if (!existsSync(path)) return null;
  let value;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    value = null;
  }
  const sound = value && value.type === MARK_TYPE && Number.isSafeInteger(value.segment) && value.segment >= 1 && Number.isSafeInteger(value.lines) && value.lines >= 0;
  if (!sound) throw new Error(`${path} is not a journal mark this witness writes, so it does not start. Look at the folder before you go on: with the mark moved out, a journal cut short is no longer seen where the state is lost too.`);
  return value;
}

/**
 * Start a witness on a folder made by initWitness, on 127.0.0.1.
 *
 * WHAT IT KEEPS. Its journal (journal.jsonl) has a line for each statement
 * it gave out, each seal it was brought up to date with, and each sequence
 * its operator told it to forget, in order, in segments. Its state
 * (state.json) is what it holds, with the segment and the number of journal
 * lines it reflects, replaced after each line; then its journal mark
 * (journal-mark.json), the same segment and number of lines kept apart from
 * the state, so that a journal emptied or cut short is seen at a start even
 * where the state is lost. Every journalLines lines (256
 * by default) it writes a checkpoint (checkpoint.json: what it holds, the
 * latest seal of each sequence and its statement, which is all it needs to
 * refuse a fork) and begins the journal again, so that the journal stays
 * small: the earlier lines are dropped. Each is made sure to be on the disk
 * before anything is given out.
 *
 * WHAT IT GIVES OUT. Only what is on the disk: a statement is answered once
 * its journal line and the state are saved, and /latest answers from what
 * was last saved, never from what the library's witness holds in memory. If
 * anything cannot be saved, it gives out nothing more, by any route, until
 * it is started again.
 *
 * AT EVERY START, the first included, it signs nothing until its operator
 * says that its folder was not put back to an older copy (ready, or
 * start --ready): a folder put back is not something it can see.
 *
 * @param {object} o
 * @param {string} [o.folder]
 * @param {number} [o.port] 0 takes any free port; by default the setting, or PROVARED_WITNESS_PORT, or 8796
 * @param {boolean} [o.ready] the operator's word, at this start, that the folder was not put back to an older copy
 * @param {() => number} [o.clock] the time the library's witness dates its statements by (Date.now), for tests
 * @param {(step: string) => Promise<void>|void} [o.faults] called at "signing", "journal" (before a journal line is
 *   written), "journaled", "saved", "checkpointed" and "rotated",
 *   for tests
 * @param {{statementsPerHour?: number, maxSequences?: number, journalLines?: number}} [o.limits] in place of the
 *   settings, for tests
 * @returns {Promise<{port: number, close: () => Promise<void>, status: () => Promise<object>}>}
 */
export async function startWitness({ folder = DEFAULT_WITNESS_FOLDER, port, ready: told = false, clock = Date.now, faults = () => {}, limits = {}, withoutMethods = [] } = {}) {
  const f = witnessFiles(folder);
  if (!existsSync(f.keys)) throw new Error(`There are no witness keys at ${f.keys}. Make them first: ${RUN} init --recorder <the fingerprint of the recorder's key set>`);
  if (!existsSync(f.journal)) {
    throw new Error(`The witness's keys are there, but its journal (${f.journal}) is not. Without it the witness would have forgotten every seal it signed for, and could be made to sign a second history, so it does not start. Put the journal back. ${NEW_WITNESS}`);
  }
  const settings = readSettings(folder);
  if (settings.recorders.length === 0) throw new Error(`The witness serves no recorder yet. Name one by the fingerprint of its key set: ${RUN} init --recorder <fingerprint>`);
  const release = lockFolder(folder);
  process.once('exit', release);
  try {
    return await run();
  } catch (e) {
    release();
    process.off('exit', release);
    throw e;
  }

  async function run() {
    const statementsPerHour = limits.statementsPerHour ?? settings.statementsPerHour;
    const maxSequences = limits.maxSequences ?? settings.maxSequences;
    const journalLines = limits.journalLines ?? settings.journalLines;
    const tokens = { recorder: readToken(f.token), operator: readToken(f.operator) };
    const { keys, privateKeys } = await loadWitnessKeys(folder);
    const by = { keys, name: settings.name };
    const me = await keySetFingerprint(keys);
    const notes = [];
    const sealContent = (record) => JSON.parse(Buffer.from(record.payload, 'base64url').toString('utf8'));
    // A sequence, as the library knows it (bookIdentity): the fingerprint of {agent, passkey, recorder} in the canonical form.
    const identityOf = (agent, passkey, recorder) => fingerprint(utf8(JSON.stringify({ agent, passkey, recorder })));
    const identityOfBook = async (b) => identityOf(b.agent, b.passkey, await keySetFingerprint(sealContent(b.seal).by.keys));

    // What it kept: the newer of its state and its checkpoint, or nothing.
    const state = readKept(f.state, SERVICE_STATE, 'a state');
    const checkpoint = readKept(f.checkpoint, CHECKPOINT_TYPE, 'a checkpoint');
    const mark = readMark(f.mark);
    const empty = (await openWitness({ by, signers: privateKeys, clock, withoutMethods })).state();
    let base;
    if (state && (!checkpoint || state.segment >= checkpoint.segment)) base = { segment: state.segment, journal: state.journal, witness: state.witness };
    else if (checkpoint) {
      base = { segment: checkpoint.segment, journal: 0, witness: checkpoint.witness };
      notes.push(state ? 'Its state was older than its checkpoint: it was rebuilt from the checkpoint and the journal.' : 'Its state was not there: it was rebuilt from the checkpoint and the journal.');
    } else base = { segment: 1, journal: 0, witness: empty };
    const read = readJournal(f.journal, base, notes);
    if (read.earlier > 0 && read.lines > 0) throw new Error('The journal holds lines of two segments: the journal was changed, so the witness does not start.');
    if (base.journal > read.lines) {
      throw new Error(`${f.state} reflects ${base.journal} lines of the journal's segment ${base.segment}, and the journal holds ${read.lines}: lines were taken out of the journal, so the witness does not start. Look at the folder before you go on.`);
    }
    // The mark: kept apart from the state, so that a journal emptied or cut short is seen where the state is lost.
    if (mark && (mark.segment > base.segment || (mark.segment === base.segment && mark.lines > read.lines))) {
      throw new Error(`${f.mark} says that ${mark.lines} lines of the journal's segment ${mark.segment} were saved, and the start finds ${mark.segment > base.segment ? `nothing kept beyond segment ${base.segment}` : `${read.lines}`}: lines were taken out of the journal, or what the witness kept is older than it, so the witness does not start. Look at the folder before you go on.`);
    }
    if (!state && !checkpoint && read.lines > 0) notes.push('Its state was not there: it was rebuilt from the journal.');
    // Opened always from a state (empty for a new witness), so that the library's witness signs nothing until it is told it may.
    let witness;
    try {
      witness = await openWitness({ by, signers: privateKeys, clock, withoutMethods, state: base.witness });
    } catch (e) {
      throw new Error(`What the witness kept could not be taken: ${e.message} It does not start.`);
    }
    // Forget a sequence: the library's witness opened again from what it holds, less that sequence.
    const without = async (sequence) => {
      const now = witness.state();
      const kept = [];
      for (const b of now.books) if ((await identityOfBook(b)) !== sequence) kept.push(b);
      return openWitness({ by, signers: privateKeys, clock, withoutMethods, state: { ...now, books: kept } });
    };
    for (const r of read.later) {
      if (r.kind === 'forget') {
        witness = await without(await identityOf(r.sequence.agent, r.sequence.passkey, r.sequence.recorder));
        continue;
      }
      const taken = await witness.update(r.entry, r.proof.map((p) => (typeof p === 'string' ? fromBase64url(p) : null)), utf8(r.first));
      if (taken.refused) throw new Error(`Line ${r.n} of the journal could not be taken again (${taken.refused.code}: ${taken.refused.message}). The journal does not follow on from what the witness kept, so it does not start.`);
    }
    let segment = base.segment;
    let count = read.lines;
    // The state, then the mark: the mark never says more than the journal holds, so it is written after the line.
    const saveState = () => {
      replaceDurably(f.state, JSON.stringify({ about: 'What a witness for seals holds, as the library hands it back, with the journal segment and the number of its lines it reflects.', type: SERVICE_STATE, segment, journal: count, witness: witness.state() }));
      replaceDurably(f.mark, JSON.stringify({ about: 'How far the journal of a witness for seals went when it last saved: its segment and its number of lines. Kept apart from the state, so that a journal emptied or cut short is seen where the state is lost.', type: MARK_TYPE, segment, lines: count }));
    };
    // A checkpoint, and the journal begun again: each step whole, in this order, so that a stop between any two
    // leaves a folder from which the next start takes what it holds.
    const rotate = async () => {
      const next = segment + 1;
      const holds = witness.state();
      replaceDurably(f.checkpoint, JSON.stringify({ about: 'What a witness for seals held when it began its journal again: the latest seal of each sequence, with its statement.', type: CHECKPOINT_TYPE, segment: next, witness: holds }));
      await faults('checkpointed');
      replaceDurably(f.state, JSON.stringify({ about: 'What a witness for seals holds, as the library hands it back, with the journal segment and the number of its lines it reflects.', type: SERVICE_STATE, segment: next, journal: 0, witness: holds }));
      replaceDurably(f.journal, '');
      segment = next;
      count = 0;
      await faults('rotated');
    };
    if (read.earlier > 0) {
      // A stop came after a checkpoint was written and before the journal was begun again: it is begun again now.
      replaceDurably(f.journal, '');
      notes.push('A checkpoint had been written and the journal not yet begun again: it was begun again.');
    }
    saveState();

    // What it gives out: only what is saved on the disk, by sequence.
    const saved = new Map();
    for (const b of witness.state().books) saved.set(await identityOfBook(b), { seal: b.seal, statement: b.statement });
    // How many sequences it holds: counted from what it kept, and then as each is taken or forgotten.
    let sequencesHeld = saved.size;
    // At every start, the first included, it signs nothing until its operator says it may.
    let ready = false;
    if (told) {
      witness.ready();
      ready = true;
      notes.push('Started with --ready: the operator said, at this start, that its folder was not put back to an older copy.');
    }
    /** Why it gives out nothing more, once what it holds could not be kept on the disk. */
    let broken = null;
    const stopped = () => [503, { error: `This witness gives out nothing more: ${broken}`, code: 'witness-stopped' }];
    const failed = (e) => {
      broken = `what it holds could not be kept on the disk (${e.message}), so it gave out nothing for the question it was answering, and it answers nothing more but its status until it is started again`;
      return stopped();
    };
    const signedAt = [];

    // A question that changes what it holds: one at a time, at most WITNESS_MAX_WAITING taken on.
    let taken = 0;
    let turn = Promise.resolve();
    const oneAtATime = (work) => {
      if (taken >= WITNESS_MAX_WAITING) return null;
      taken++;
      const step = turn.then(work).finally(() => { taken--; });
      turn = step.catch(() => {});
      return step;
    };

    /** The body of a question that hands over a seal, read: or why not. */
    async function readQuestion(body, withStatements) {
      if (!body || typeof body !== 'object' || Array.isArray(body)) return { error: 'the body must be one JSON object: {"entry", "proof", "first"}' };
      const extra = Object.keys(body).filter((k) => !['entry', 'proof', 'first'].includes(k));
      if (extra.length) return { error: `the body holds what this witness does not take: ${extra.join(', ')}` };
      const { entry, proof, first } = body;
      const allowed = withStatements ? ['seal', 'witnesses'] : ['seal'];
      if (!entry || typeof entry !== 'object' || Array.isArray(entry) || !Object.hasOwn(entry, 'seal') || !Object.keys(entry).every((k) => allowed.includes(k))) {
        return { error: withStatements ? '"entry" must be a seal\'s entry, {"seal", "witnesses"}, with a statement of this witness' : '"entry" must be {"seal": the seal record}' };
      }
      if (withStatements && !Array.isArray(entry.witnesses)) return { error: '"entry.witnesses" must be a list of statements' };
      if (!Array.isArray(proof) || proof.length > 64 || !proof.every((p) => isRandom(p))) return { error: '"proof" must be a list of at most 64 values, each 32 bytes in base64url' };
      if (typeof first !== 'string' || first.length < 1 || first.length > MAX_LINE || /[\r\n]/.test(first)) return { error: '"first" must be the book\'s first line, without its line break' };
      let recorderKeys;
      try {
        recorderKeys = sealContent(entry.seal).by.keys;
        return { entry, proof: proof.map(fromBase64url), first, firstBytes: utf8(first), recorderKeys, recorder: await keySetFingerprint(recorderKeys) };
      } catch {
        return { error: '"entry.seal" is not a seal record whose recorder can be read' };
      }
    }
    const notServed = [403, { error: 'This witness does not serve the recorder that signed the seal: its operator did not name the fingerprint of that recorder\'s key set.', code: 'recorder-not-served' }];

    // A journal line, made sure to be on the disk; then the state; then, every journalLines lines, a checkpoint.
    const keep = async (line) => {
      await faults('journal');
      appendDurably(f.journal, `${JSON.stringify({ seg: segment, n: count + 1, ...line })}\n`);
      count++;
      await faults('journaled');
      saveState();
      await faults('saved');
    };

    async function sign(body) {
      if (broken) return stopped();
      const q = await readQuestion(body, false);
      if (q.error) return [400, { error: q.error }];
      if (!settings.recorders.includes(q.recorder)) return notServed;
      let identity = null;
      try { identity = await bookIdentity(q.recorderKeys, q.firstBytes); } catch { /* the library says why */ }
      const before = identity ? witness.latest(identity) : null;
      const same = before && before.seal.payload === q.entry.seal.payload;
      if (identity && !before) {
        if (heldCount() >= maxSequences) return [503, { error: `This witness holds the most sequences it keeps (${maxSequences}), so it starts no new one.`, code: 'witness-full' }];
        // A new sequence starts only from a permission that passes the library's check, its passkey's signature included.
        const slip = await checkSlip(JSON.parse(q.first).slip, { withoutMethods });
        if (slip.problems.length > 0) return [409, { refused: { code: slip.problems[0].code, message: `The permission on the book's first line does not pass its check, so this witness starts no sequence for it. ${slip.problems[0].message}` } }];
        if (slip.signature.state !== 'valid') return [409, { refused: { code: 'check-failed', message: 'This witness could not check the passkey\'s signature on the permission on the book\'s first line, so it starts no sequence for it.' } }];
      }
      const now = Date.now();
      while (signedAt.length && signedAt[0] <= now - 3600000) signedAt.shift();
      if (!same && signedAt.length >= statementsPerHour) {
        return [429, { error: `This witness gives at most ${statementsPerHour} new statements in any hour; ask again later.`, code: 'witness-busy' }, { 'Retry-After': '60' }];
      }
      await faults('signing');
      const r = await witness.witness(q.entry, q.proof, q.firstBytes);
      if (r.refused) return [409, { refused: r.refused }];
      if (same && before.statement.payload === r.statement.payload) return [200, { statement: r.statement }];
      // Kept before it is given out: the journal line, then the state and the mark, each made sure to be on the disk.
      try {
        await keep({ kind: 'witness', at: formatTime(Date.now()), entry: { seal: q.entry.seal, witnesses: [r.statement] }, proof: body.proof, first: q.first });
      } catch (e) {
        return failed(e);
      }
      saved.set(identity, { seal: q.entry.seal, statement: r.statement });
      signedAt.push(now);
      if (!before) sequencesHeld++;
      await rotateIfDue();
      return [200, { statement: r.statement }];
    }

    // The statement just given is on the disk whatever happens here: a checkpoint that cannot be written stops the
    // witness from giving out anything more, as any save that fails does.
    async function rotateIfDue() {
      if (count < journalLines) return;
      try {
        await rotate();
      } catch (e) {
        failed(e);
      }
    }

    async function bringUpToDate(body) {
      if (broken) return stopped();
      const q = await readQuestion(body, true);
      if (q.error) return [400, { error: q.error }];
      if (!settings.recorders.includes(q.recorder)) return notServed;
      let identity = null;
      try { identity = await bookIdentity(q.recorderKeys, q.firstBytes); } catch { /* the library says why */ }
      const before = identity ? witness.latest(identity) : null;
      if (identity && !before && heldCount() >= maxSequences) {
        return [503, { error: `This witness holds the most sequences it keeps (${maxSequences}), so it starts no new one.`, code: 'witness-full' }];
      }
      const r = await witness.update(q.entry, q.proof, q.firstBytes);
      if (r.refused) return [409, { refused: r.refused }];
      const after = identity ? witness.latest(identity) : null;
      if (!after) return [500, { error: 'The witness took the seal but holds nothing for it: it is not up to date. Start it again.' }];
      if (before && before.seal.payload === after.seal.payload) return [200, { taken: false }];
      try {
        await keep({ kind: 'update', at: formatTime(Date.now()), entry: { seal: after.seal, witnesses: [after.statement] }, proof: body.proof, first: q.first });
      } catch (e) {
        return failed(e);
      }
      saved.set(identity, { seal: after.seal, statement: after.statement });
      if (!before) sequencesHeld++;
      await rotateIfDue();
      return [200, { taken: true }];
    }

    // The operator's: forget a sequence. The witness then signs, for that recorder, person and agent, whatever
    // seal it is shown first, as it did before it held any: forgetting a sequence a recorder still uses lets that
    // recorder have a second history witnessed. The statements it gave out stay as they are.
    async function forget(body) {
      if (broken) return stopped();
      const sequence = body?.sequence;
      if (!body || typeof body !== 'object' || Object.keys(body).some((k) => k !== 'sequence') || typeof sequence !== 'string' || !FINGERPRINT.test(sequence)) {
        return [400, { error: 'the body must be {"sequence": the fingerprint of a sequence, as status gives it}' }];
      }
      let held = null;
      for (const b of witness.state().books) {
        if ((await identityOfBook(b)) === sequence) {
          held = b;
          break;
        }
      }
      if (!held) return [404, { error: 'This witness holds no such sequence.' }];
      const next = await without(sequence);
      if (ready) next.ready();
      const recorder = await keySetFingerprint(sealContent(held.seal).by.keys);
      try {
        appendDurably(f.journal, `${JSON.stringify({ seg: segment, n: count + 1, kind: 'forget', at: formatTime(Date.now()), sequence: { agent: held.agent, passkey: held.passkey, recorder } })}\n`);
        count++;
        witness = next;
        saveState();
      } catch (e) {
        return failed(e);
      }
      saved.delete(sequence);
      sequencesHeld--;
      await rotateIfDue();
      return [200, { forgotten: sequence }];
    }
    const heldCount = () => sequencesHeld;

    async function statusOf() {
      const sequences = [];
      for (const [sequence, b] of saved) {
        const c = sealContent(b.seal);
        const held = witness.state().books.find((x) => x.seal.payload === b.seal.payload);
        sequences.push({
          sequence,
          recorder: await keySetFingerprint(c.by.keys),
          passkey: held?.passkey ?? null,
          agent: held?.agent ?? null,
          book: c.book ?? 1,
          entries: c.size,
          seal: await fingerprint(fromBase64url(b.seal.payload)),
          sealedAt: c.when,
        });
      }
      const now = Date.now();
      return {
        ready: ready && !broken,
        ...(ready ? {} : { notReady: `At every start it signs nothing until its operator says that its folder was not put back to an older copy: ${RUN} ready` }),
        ...(broken ? { problem: broken } : {}),
        notes,
        witness: { name: by.name, fingerprint: me },
        recorders: settings.recorders,
        sequences,
        journal: { segment, lines: count, beginsAgainAt: journalLines },
        statementsInTheLastHour: signedAt.filter((t) => t > now - 3600000).length,
        limits: { statementsPerHour, maxSequences, journalLines },
        folder,
      };
    }

    // Conversations. The witness's number for one (the session) is the time
    // of the hello and an HMAC over that time, the role and the asker's
    // number, under a secret only this running witness holds: a hello keeps
    // nothing. A session takes one question; the sessions used are remembered
    // only while their hello could still be taken.
    const secret = nodeCrypto.randomBytes(32);
    const used = new Map();
    const sessionNumber = (role, theirs, time) => {
      const t = Buffer.alloc(8);
      t.writeBigUInt64BE(BigInt(time));
      return Buffer.concat([t, feedHmac(secret, WITNESS_LABELS.session, role, theirs, t).subarray(0, 24)]).toString('base64url');
    };
    const plain = (res, code, body, more = {}) => {
      if (res.writableEnded || res.destroyed) return;
      res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...more });
      res.end(JSON.stringify(body));
    };
    const proved = (res, key, code, body, more = {}) => {
      if (res.writableEnded || res.destroyed) return;
      const bytes = Buffer.from(JSON.stringify(body));
      res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Provared-Witness-Proof': feedHmac(key, WITNESS_LABELS.answer, String(code), bytes).toString('base64url'), ...more });
      res.end(bytes);
    };

    /** The conversation a question belongs to, checked: {role, key}; or null, with the answer sent. */
    function conversation(req, res, bytes) {
      const role = req.headers['provared-witness-role'];
      const session = req.headers['provared-witness-session'];
      const theirs = req.headers['provared-witness-hello'];
      const now = Date.now();
      for (const [s, at] of used) {
        if (now - at <= WITNESS_HELLO_MS) break;
        used.delete(s);
      }
      if (!ROLES.includes(role) || !isRandom(session) || !isRandom(theirs)) {
        plain(res, 401, { error: 'a question belongs to a conversation: begin one with GET /hello' });
        return null;
      }
      const begun = Number(Buffer.from(session, 'base64url').readBigUInt64BE(0));
      if (!(now - begun >= 0 && now - begun <= WITNESS_HELLO_MS) || !sameProof(session, Buffer.from(sessionNumber(role, theirs, begun), 'base64url'))) {
        plain(res, 401, { error: 'the witness knows no such conversation: begin one with GET /hello' });
        return null;
      }
      if (used.has(session)) {
        plain(res, 401, { error: 'a conversation takes one question, and this one has had its question: begin another with GET /hello' });
        return null;
      }
      const key = feedHmac(Buffer.from(tokens[role]), WITNESS_LABELS.key, role, theirs, session);
      if (!sameProof(req.headers['provared-witness-proof'], feedHmac(key, WITNESS_LABELS.question, `${req.method} ${req.url}`, sha256(bytes)))) {
        plain(res, 401, { error: `the question does not carry the proof that its sender holds the ${role === 'operator' ? 'operator\'s' : 'witness\'s'} token` });
        return null;
      }
      if (used.size >= WITNESS_MAX_REMEMBERED) {
        plain(res, 429, { error: 'too many questions in the last two minutes; ask again in a moment' }, { 'Retry-After': '30' });
        return null;
      }
      used.set(session, now);
      return { role, key };
    }

    const PATHS = { '/about': 'GET', '/latest': 'GET', '/witness': 'POST', '/status': 'GET', '/ready': 'POST', '/update': 'POST', '/forget': 'POST', '/stop': 'POST' };
    const OPERATOR_ONLY = ['/status', '/ready', '/update', '/forget', '/stop'];

    const server = createServer(async (req, res) => {
      try {
        const url = new URL(req.url, 'http://127.0.0.1');
        if (url.pathname === '/hello') {
          if (req.method !== 'GET') return plain(res, 405, { error: 'a hello is GET /hello' });
          const role = req.headers['provared-witness-role'];
          const theirs = req.headers['provared-witness-hello'];
          if (!ROLES.includes(role)) return plain(res, 400, { error: 'say who asks, in Provared-Witness-Role: recorder or operator' });
          if (!isRandom(theirs)) return plain(res, 400, { error: 'a conversation begins with a random number of 32 bytes, in base64url, in Provared-Witness-Hello' });
          const session = sessionNumber(role, theirs, Date.now());
          return plain(res, 200, { session, proof: feedHmac(Buffer.from(tokens[role]), WITNESS_LABELS.witness, role, theirs, session).toString('base64url') });
        }
        if (!Object.hasOwn(PATHS, url.pathname)) return plain(res, 404, { error: 'not found' });
        if (req.method !== PATHS[url.pathname]) return plain(res, 405, { error: `${url.pathname} takes ${PATHS[url.pathname]} only` });
        const parts = [];
        let size = 0;
        for await (const chunk of req) {
          size += chunk.length;
          if (size > WITNESS_MAX_BODY) {
            plain(res, 413, { error: `a question's body may be at most ${WITNESS_MAX_BODY} bytes` }, { Connection: 'close' });
            req.destroy();
            return undefined;
          }
          parts.push(chunk);
        }
        const bytes = Buffer.concat(parts);
        const talk = conversation(req, res, bytes);
        if (!talk) return undefined;
        const send = (code, body, more) => proved(res, talk.key, code, body, more);
        if (OPERATOR_ONLY.includes(url.pathname) && talk.role !== 'operator') return send(403, { error: `${url.pathname} is one of the operator's commands, and takes the operator's token` });
        let body;
        if (req.method === 'POST') {
          try {
            body = bytes.length ? JSON.parse(bytes.toString('utf8')) : {};
          } catch {
            return send(400, { error: 'the body is not JSON' });
          }
        }
        if (url.pathname === '/about') return send(200, { witness: { by, fingerprint: me }, ready: ready && !broken });
        if (url.pathname === '/latest') {
          const sequence = url.searchParams.get('sequence');
          if ([...url.searchParams.keys()].some((k) => k !== 'sequence') || !FINGERPRINT.test(sequence ?? '')) {
            return send(400, { error: '/latest takes "sequence": the fingerprint of a recorder, person and agent, as bookIdentity gives it' });
          }
          // Only what is saved on the disk; nothing at all once a save has failed.
          if (broken) return send(...stopped());
          return send(200, { latest: saved.get(sequence) ?? null, ready });
        }
        if (url.pathname === '/status') return send(200, await statusOf());
        if (url.pathname === '/ready') {
          if (broken) return send(...stopped());
          witness.ready();
          ready = true;
          return send(200, { ready: true });
        }
        if (url.pathname === '/stop') {
          send(200, { stopped: true });
          setTimeout(() => server.close(), 50);
          return undefined;
        }
        const work = { '/witness': sign, '/update': bringUpToDate, '/forget': forget }[url.pathname];
        const step = oneAtATime(() => work(body));
        if (!step) return send(429, { error: `${WITNESS_MAX_WAITING} questions are being answered already; ask again in a moment`, code: 'witness-busy' }, { 'Retry-After': '1' });
        const [code, answer, more] = await step;
        return send(code, answer, more);
      } catch (e) {
        return plain(res, 500, { error: e.message });
      }
    });
    server.requestTimeout = 30000;
    server.headersTimeout = 10000;
    server.maxConnections = 64;
    const listenOn = port ?? (process.env.PROVARED_WITNESS_PORT ? Number(process.env.PROVARED_WITNESS_PORT) : settings.port ?? DEFAULT_WITNESS_PORT);
    await new Promise((done, fail) => {
      server.once('error', fail);
      server.listen(listenOn, '127.0.0.1', done);
    });
    // The folder is let go once the witness has stopped, however it was stopped.
    server.on('close', () => {
      release();
      process.off('exit', release);
    });
    return {
      port: server.address().port,
      fingerprint: me,
      status: statusOf,
      close: () => new Promise((done) => {
        server.close(() => done());
        server.closeAllConnections();
      }),
    };
  }
}

// --- the commands ---

/** The port of the running witness, as the commands find it: --port, then PROVARED_WITNESS_PORT, then the setting, then 8796. */
function portOf(folder, given) {
  if (given !== undefined) return given;
  if (process.env.PROVARED_WITNESS_PORT) return Number(process.env.PROVARED_WITNESS_PORT);
  return readSettings(folder).port ?? DEFAULT_WITNESS_PORT;
}

function operator(folder, port) {
  return witnessClient({ address: `http://127.0.0.1:${port}`, token: readToken(witnessFiles(folder).operator), role: 'operator', timeoutMs: 60000 });
}

/**
 * Hand the running witness, from a copy, the statements it signed for the
 * seals of a book: those on the seals' lines, and those in files handed
 * over beside the book ({"seal", "witnesses"}, as a checker takes them). It
 * takes, in order, each seal it does not yet hold, where the seal extends
 * the one it holds.
 */
export async function updateFrom({ folder = DEFAULT_WITNESS_FOLDER, port, book, sealFiles = [] }) {
  const text = readFileSync(book, 'utf8');
  const lines = text.split('\n');
  if (lines.at(-1) === '') lines.pop();
  const first = (lines[0] ?? '').replace(/\r$/, '');
  const me = await keySetFingerprint((await loadWitnessKeys(folder)).keys);
  const handed = new Map();
  for (const file of sealFiles) {
    const value = JSON.parse(readFileSync(file, 'utf8'));
    if (!value?.seal?.payload || !Array.isArray(value.witnesses)) throw new Error(`${file} is not a seal handed over beside a book: {"seal", "witnesses"}.`);
    handed.set(value.seal.payload, [...(handed.get(value.seal.payload) ?? []), ...value.witnesses]);
  }
  const ownStatement = async (list) => {
    for (const s of list) {
      try {
        if ((await keySetFingerprint(JSON.parse(Buffer.from(s.payload, 'base64url').toString('utf8')).by.keys)) === me) return s;
      } catch { /* not a statement that can be read */ }
    }
    return null;
  };
  const found = [];
  for (const line of lines) {
    if (!line.startsWith('{"seal":')) continue;
    let value;
    try { value = JSON.parse(line.replace(/\r$/, '')); } catch { continue; }
    const statement = await ownStatement([...(value.witnesses ?? []), ...(handed.get(value.seal?.payload) ?? [])]);
    if (!statement) continue;
    const c = JSON.parse(Buffer.from(value.seal.payload, 'base64url').toString('utf8'));
    found.push({ seal: value.seal, statement, number: c.book ?? 1, size: c.size, keys: c.by.keys });
  }
  if (found.length === 0) return { found: 0, taken: 0, refused: null };
  const client = operator(folder, portOf(folder, port));
  const sequence = await bookIdentity(found[0].keys, utf8(first));
  const latest = await client.ask('GET', `/latest?sequence=${sequence}`);
  if (latest.code !== 200) throw new Error(latest.body.error ?? `the witness answered ${latest.code}`);
  let held = latest.body.latest ? JSON.parse(Buffer.from(latest.body.latest.seal.payload, 'base64url').toString('utf8')) : null;
  let taken = 0;
  for (const s of found) {
    if (held && (s.number < (held.book ?? 1) || (s.number === (held.book ?? 1) && s.size <= held.size))) continue;
    const from = held && (held.book ?? 1) === s.number ? held.size : null;
    const proof = (await witnessProof(text, s.size, from)).map(toBase64url);
    const r = await client.ask('POST', '/update', { entry: { seal: s.seal, witnesses: [s.statement] }, proof, first });
    if (r.code !== 200) return { found: found.length, taken, refused: r.body.refused ?? { code: String(r.code), message: r.body.error } };
    if (r.body.taken) taken++;
    held = { book: s.number === 1 ? undefined : s.number, size: s.size };
  }
  return { found: found.length, taken, refused: null };
}

const USAGE = `Usage: ${RUN} <command>

  init [--name <label>] [--recorder <fingerprint>]... [--port <n>]
                make the witness's keys and tokens if they are missing, and name the recorders
                it serves, by the fingerprint of each recorder's key set ("provared-claude-code
                status" prints it, as "sealer")
  start [--ready] [--port <n>]
                run the witness in this terminal; --ready says, at this start, that its folder
                was not put back to an older copy
  status        what the running witness holds
  ready         tell the running witness that its folder was not put back to an older copy:
                at every start it signs nothing until you do
  update <book> [--seal <file>]...
                hand the running witness, from a copy, the statements it signed for the seals
                of a book (on their lines, and in the files handed over beside it)
  forget <sequence>
                stop holding a sequence ("status" names each): the witness then signs, for that
                recorder, person and agent, whatever seal it is next shown, so forget only a
                sequence no recorder you serve still uses
  stop          stop the running witness

The folder is ${DEFAULT_WITNESS_FOLDER} (PROVARED_WITNESS_DIR names another).`;

async function main(argv) {
  const [command, ...rest] = argv;
  const folder = DEFAULT_WITNESS_FOLDER;
  const values = (name) => rest.flatMap((a, i) => (a === name && i + 1 < rest.length ? [rest[i + 1]] : []));
  const portGiven = values('--port').length ? Number(values('--port')[0]) : undefined;
  if (portGiven !== undefined && !(Number.isInteger(portGiven) && portGiven >= 1 && portGiven <= 65535)) {
    console.error('The value of --port is not a port: a whole number from 1 to 65535.');
    return 2;
  }
  if (command === 'init') {
    const name = values('--name')[0];
    const made = await initWitness({ folder, name, recorders: values('--recorder'), port: portGiven });
    console.log(made.made ? `A witness was made in ${folder}: its keys, its tokens and its journal.` : `The witness in ${folder} is as it was; its settings were brought up to date.`);
    console.log(`  The fingerprint of its key set: ${made.fingerprint}`);
    console.log(`  It serves the recorders: ${made.settings.recorders.length ? made.settings.recorders.join(', ') : '(none yet: name one with --recorder)'}`);
    console.log(`  A recorder asks it with the token in ${made.files.token}: give that file to the recorder alone (provared-claude-code add-witness). Never share ${made.files.keys} or ${made.files.operator}.`);
    return 0;
  }
  if (command === 'start') {
    const service = await startWitness({ folder, port: portGiven, ready: rest.includes('--ready') });
    const s = await service.status();
    console.log(`The witness "${s.witness.name}" is running on http://127.0.0.1:${service.port}`);
    console.log(`  The fingerprint of its key set: ${s.witness.fingerprint}. It holds ${s.sequences.length} sequences; its journal has ${s.journal.lines} lines in segment ${s.journal.segment}.`);
    for (const note of s.notes) console.log(`  ${note}`);
    if (!s.ready) console.log(`  It signs nothing until you say that its folder was not put back to an older copy. Check that (hand it what a recorder holds with "${RUN} update", if you wish), then: ${RUN} ready`);
    console.log('  Press Ctrl and C to stop.');
    return null;
  }
  if (command === 'status' || command === 'ready' || command === 'stop') {
    const r = await operator(folder, portOf(folder, portGiven)).ask(command === 'status' ? 'GET' : 'POST', `/${command}`, command === 'status' ? undefined : {});
    if (r.code !== 200) {
      console.error(r.body.error ?? `The witness answered ${r.code}.`);
      return 1;
    }
    if (command === 'status') console.log(JSON.stringify(r.body, null, 2));
    if (command === 'ready') console.log('The witness takes your word that it is up to date, and signs again.');
    if (command === 'stop') console.log('Stopped.');
    return 0;
  }
  if (command === 'forget') {
    const sequence = rest.find((a, i) => !a.startsWith('-') && rest[i - 1] !== '--port');
    if (!sequence || !FINGERPRINT.test(sequence)) {
      console.error('Name the sequence to forget by its fingerprint, as "status" gives it ("sequence"): 43 letters, digits, "-" and "_".');
      return 2;
    }
    const r = await operator(folder, portOf(folder, portGiven)).ask('POST', '/forget', { sequence });
    if (r.code !== 200) {
      console.error(r.body.error ?? `The witness answered ${r.code}.`);
      return 1;
    }
    console.log(`The witness holds sequence ${sequence} no more. It now signs, for that recorder, person and agent, whatever seal it is next shown; the statements it gave out before stay as they are.`);
    return 0;
  }
  if (command === 'update') {
    const book = rest.find((a, i) => !a.startsWith('-') && rest[i - 1] !== '--seal' && rest[i - 1] !== '--port');
    if (!book) {
      console.log(USAGE);
      return 2;
    }
    const done = await updateFrom({ folder, port: portGiven, book: resolve(book), sealFiles: values('--seal').map((p) => resolve(p)) });
    if (done.found === 0) {
      console.log('The book, and the files handed over beside it, hold no statement of this witness.');
      return 1;
    }
    console.log(`Of the ${done.found} seals with a statement of this witness, it took ${done.taken} as later than what it held.`);
    if (done.refused) {
      console.error(`Then it refused one: [${done.refused.code}] ${done.refused.message}`);
      return 1;
    }
    return 0;
  }
  console.log(USAGE);
  return 2;
}

let invoked = '';
try { invoked = process.argv[1] ? realpathSync(process.argv[1]) : ''; } catch { /* not a file */ }
if (invoked === SELF) {
  process.removeAllListeners('warning');
  main(process.argv.slice(2)).then((code) => {
    if (code !== null) process.exitCode = code;
  }, (e) => {
    console.error(e.message);
    process.exitCode = 1;
  });
}
