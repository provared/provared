#!/usr/bin/env node
// The recorder beside Claude Code: a small service on this computer that
// holds the stub writer open on one book, under the slip the person signed
// last, and answers the hook (hook.mjs) that Claude Code runs before and
// after each tool call. Before a call, the check before acting says whether
// the call is within the slip; after it, a stub is written. Whoever runs it
// seals the book when they choose, and takes a new slip into the book when
// the one before ends.
//
//   provared-claude-code init          make the keys if they are missing, write the hooks into this
//                                      project's .claude/settings.local.json, and print a link that
//                                      opens the signing page with a starting permission filled in
//   provared-claude-code use <file>    put a signed slip in place and start the service in the
//                                      background; where a book exists already, renew
//   provared-claude-code renew <file>  take a new signed slip into the book, the running service included
//   provared-claude-code start         run the service (needs slip.json in the folder)
//   provared-claude-code ensure        start the service in the background if it is not running
//   provared-claude-code status        what the service holds
//   provared-claude-code seal          seal the book now, with the recorder's three keys
//   provared-claude-code check         the checker's answer for the book
//   provared-claude-code stop          stop the service
//   provared-claude-code keys          make the keys, and print the agent's public keys
//
// From a copy of the repository the same commands run as
// "node recorder.mjs <command>".
//
// The folder (PROVARED_CLAUDE_CODE_DIR, or ~/.provared/claude-code) holds:
//   agent-keys.jwk           the agent's two private keys (never share)
//   recorder-keys.jwk        the recorder's three private keys, for seals (never share)
//   slip.json                the signed slip the service acts under, from the signing page
//   slip-<fingerprint>.json  each slip that stood in its place before, kept by its fingerprint
//   trusted-passkeys.json    the thumbprints of the passkeys whose slips the recorder takes:
//                            written at the first "use", changed only by "renew --new-passkey"
//   book.jsonl               the book: the slips, a stub for each tool call, and seals
//
// It listens on 127.0.0.1 only. Any program on this computer could ask it
// to write a stub, or to take a new slip, and could change the files in its
// folder: the record is of what this computer's agent did, as its own
// software says, and the evidence that holds is a checker naming the
// person's own passkey. Nothing here reaches the network.

import { spawn, spawnSync } from 'node:child_process';
import nodeCrypto from 'node:crypto';
import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, readSync, realpathSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { homedir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkBook, checkSlip, entryLine, fingerprint, fromBase64url, keySetFingerprint, openRecorder, thumbprint, toBase64url, utf8, writeSeal } from 'provared';

const subtle = globalThis.crypto.subtle;
const SLH = 'SLH-DSA-SHA2-256s';
const MAX_BODY = 1024 * 1024;

export const DEFAULT_FOLDER = process.env.PROVARED_CLAUDE_CODE_DIR || join(homedir(), '.provared', 'claude-code');
export const DEFAULT_PORT = Number(process.env.PROVARED_CLAUDE_CODE_PORT || 8794);
export const SIGNING_PAGE = 'https://prova.red/sign/';

// This file and the hook beside it, where they really are (an npm "bin"
// may reach this file through a link).
const SELF = realpathSync(fileURLToPath(import.meta.url));
const HOOK = join(dirname(SELF), 'hook.mjs');
// How the person runs this program: by its name where it was installed
// from npm, and by its path from a copy of the repository.
const RUN = SELF.split(sep).includes('node_modules') ? 'provared-claude-code' : `node ${SELF.includes(' ') ? `"${SELF}"` : SELF}`;

const files = (folder) => ({
  agentKeys: join(folder, 'agent-keys.jwk'),
  recorderKeys: join(folder, 'recorder-keys.jwk'),
  slip: join(folder, 'slip.json'),
  trusted: join(folder, 'trusted-passkeys.json'),
  book: join(folder, 'book.jsonl'),
});
const keptSlip = (folder, slipFingerprint) => join(folder, `slip-${slipFingerprint}.json`);
const THUMBPRINT = /^[A-Za-z0-9_-]{43}$/;

// --- keys kept between runs, as JSON Web Keys in a file the person keeps ---

async function newWebKey(alg) {
  const pair = await subtle.generateKey({ name: alg }, true, ['sign', 'verify']);
  return subtle.exportKey('jwk', pair.privateKey);
}

function publicOf(privateJwk) {
  if (privateJwk.kty === 'OKP') return { alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: privateJwk.x };
  if (privateJwk.kty === 'AKP' && privateJwk.alg === 'ML-DSA-87') return { alg: 'ML-DSA-87', kty: 'AKP', pub: privateJwk.pub };
  if (privateJwk.kty === 'AKP' && privateJwk.alg === SLH) return { alg: SLH, kty: 'AKP', pub: privateJwk.pub };
  throw new Error('a key in the file is of a kind this recorder does not keep.');
}

async function importWebKey(privateJwk) {
  const name = privateJwk.kty === 'OKP' ? 'Ed25519' : 'ML-DSA-87';
  return subtle.importKey('jwk', privateJwk, { name }, false, ['sign']);
}

/** Make the agent's keys, if the file does not exist, and give back the public key set. */
export async function makeAgentKeys(folder) {
  const path = files(folder).agentKeys;
  if (!existsSync(path)) {
    mkdirSync(folder, { recursive: true });
    const jwks = [await newWebKey('Ed25519'), await newWebKey('ML-DSA-87')];
    writeFileSync(path, JSON.stringify({ about: 'The private keys of the agent recorded by Provared. Never share this file.', keys: jwks }), { mode: 0o600 });
  }
  return loadAgentKeys(folder);
}

export async function loadAgentKeys(folder) {
  const path = files(folder).agentKeys;
  if (!existsSync(path)) throw new Error(`There are no agent keys at ${path}. Make them first: ${RUN} init`);
  const { keys } = JSON.parse(readFileSync(path, 'utf8'));
  return { keys: keys.map(publicOf), privateKeys: await Promise.all(keys.map(importWebKey)) };
}

/** Make the recorder's three keys, if the file does not exist, and give back the key set. */
export async function makeRecorderKeys(folder) {
  const path = files(folder).recorderKeys;
  if (!existsSync(path)) {
    mkdirSync(folder, { recursive: true });
    const slh = nodeCrypto.generateKeyPairSync('slh-dsa-sha2-256s');
    const jwks = [await newWebKey('Ed25519'), await newWebKey('ML-DSA-87'), { ...slh.privateKey.export({ format: 'jwk' }), alg: SLH }];
    writeFileSync(path, JSON.stringify({ about: 'The private keys of the recorder that seals the book. Never share this file.', keys: jwks }), { mode: 0o600 });
  }
  return loadRecorderKeys(folder);
}

export async function loadRecorderKeys(folder) {
  const { keys } = JSON.parse(readFileSync(files(folder).recorderKeys, 'utf8'));
  const privateKeys = [await importWebKey(keys[0]), await importWebKey(keys[1]), nodeCrypto.createPrivateKey({ key: keys[2], format: 'jwk' })];
  return { keys: keys.map(publicOf), privateKeys };
}

// --- files on disk ---

// A file is replaced through a temporary file. On Windows the writing and the
// replacement are both refused while anyone holds a file open (a virus
// scanner reads each new file as it is closed), so each is tried again for
// up to ten seconds.
const BUSY = ['EPERM', 'EBUSY', 'EACCES'];
function untilFree(step) {
  const pause = new Int32Array(new SharedArrayBuffer(4));
  const deadline = Date.now() + 10000;
  for (let wait = 10; ; wait = Math.min(wait * 2, 200)) {
    try { return step(); } catch (e) {
      if (!BUSY.includes(e.code) || Date.now() >= deadline) throw e;
      Atomics.wait(pause, 0, 0, wait);
    }
  }
}
// A temporary file left by a write or a replacement that failed for the last
// time (perhaps after part of it was written) is removed. The two ways of
// writing can be handed in, for the tests.
export function replaceFile(path, text, { write = writeFileSync, rename = renameSync } = {}) {
  try {
    untilFree(() => write(`${path}.tmp`, text));
    untilFree(() => rename(`${path}.tmp`, path));
  } catch (e) {
    try { unlinkSync(`${path}.tmp`); } catch { /* nothing to remove */ }
    throw e;
  }
}

// A book only grows, so the new lines are appended to the file: that
// works while another program (an uploader, a virus scanner) is reading
// it. Where the file does not match the book's start (it was edited by
// hand), the whole file is replaced.
export function saveBook(folder, text) {
  const path = files(folder).book;
  let existing = '';
  try { existing = readFileSync(path, 'utf8'); } catch { /* no book yet */ }
  if (existing.length > 0 && text.startsWith(existing)) {
    if (text.length > existing.length) appendFileSync(path, text.slice(existing.length));
    return;
  }
  replaceFile(path, text);
}

/**
 * A way to save one stub writer's book after each entry at a cost that
 * does not grow with the book. The writer's book only grows, so where the
 * file is as this saver last left it (the same size, ending in the same
 * bytes) and the new text goes on from what it last saved (it holds the
 * same last characters at the same place), the new text is appended.
 * Otherwise, the first time, or where someone else changed the file, or
 * the book is not the one last saved (a renewal that failed), it is
 * compared whole, as saveBook does.
 * @returns {(text: string) => void}
 */
export function bookSaver(folder) {
  const path = files(folder).book;
  /** @type {{chars: number, bytes: number, tail: Buffer, tailText: string}|null} */
  let left = null;
  const TAIL = 4096;
  const remember = (text, bytes) => {
    // Not cut in the middle of a character written as two halves.
    let tail = text.slice(-TAIL);
    if (/^[\udc00-\udfff]/.test(tail)) tail = tail.slice(1);
    left = { chars: text.length, bytes, tail: Buffer.from(tail), tailText: tail };
  };
  const asLeft = () => {
    try {
      if (statSync(path).size !== left.bytes) return false;
      const end = Buffer.alloc(Math.min(left.tail.length, left.bytes));
      const fd = openSync(path, 'r');
      try {
        readSync(fd, end, 0, end.length, left.bytes - end.length);
      } finally {
        closeSync(fd);
      }
      return end.equals(left.tail.subarray(left.tail.length - end.length));
    } catch {
      return false;
    }
  };
  return (text) => {
    if (left && text.length >= left.chars && text.startsWith(left.tailText, left.chars - left.tailText.length) && asLeft()) {
      const more = text.slice(left.chars);
      if (more) appendFileSync(path, more);
      remember(text, left.bytes + Buffer.byteLength(more));
      return;
    }
    saveBook(folder, text);
    remember(text, Buffer.byteLength(text));
  };
}

// --- slips ---

/**
 * A slip as it is kept in a file: the record the signing page saves, or a
 * line of a book that holds one.
 * @param {string} text
 * @param {string} where the file's name, for the message
 */
export function slipFrom(text, where) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`${where} is not JSON. It should be the file the signing page saves (slip.json).`);
  }
  if (value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 1 && Object.hasOwn(value, 'slip')) value = value.slip;
  if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.payload !== 'string') {
    throw new Error(`${where} does not hold a signed permission (a slip). It should be the file the signing page saves (slip.json).`);
  }
  return value;
}

/** A slip's fingerprint, the thumbprint of the passkey that signed it, and its content, read from the slip itself. */
async function aboutSlip(slip) {
  const payload = fromBase64url(slip.payload);
  const content = JSON.parse(new TextDecoder().decode(payload));
  return { slip, fingerprint: await fingerprint(payload), issuerKey: await thumbprint(content.issuer.key), content };
}

/** The slip the service acts under (slip.json), its fingerprint, and the thumbprint of the passkey that signed it. */
export async function loadSlip(folder) {
  const path = files(folder).slip;
  return aboutSlip(slipFrom(readFileSync(path, 'utf8'), path));
}

// --- the passkeys the recorder trusts ---
//
// A list of thumbprints in its own file (trusted-passkeys.json), written at
// the first "use" and changed only by "renew --new-passkey". The recorder
// takes a slip only from a passkey on the list, and does not start if the
// book or slip.json holds a slip from any other. This raises the bar for a
// program that edits the folder: it does not close it, because any program
// on this computer, the agent included, can change this file too. The
// evidence that holds is a checker naming the person's own passkey.

/** The list, or null where the folder has none. */
export function readTrusted(folder) {
  const path = files(folder).trusted;
  if (!existsSync(path)) return null;
  let list;
  try {
    list = JSON.parse(readFileSync(path, 'utf8').replace(/^﻿/, '')).passkeys;
  } catch {
    list = undefined;
  }
  if (!Array.isArray(list) || list.length === 0 || !list.every((k) => typeof k === 'string' && THUMBPRINT.test(k))) {
    throw new Error(`${path} does not hold a list of passkey thumbprints as {"passkeys": ["…"]}, so the recorder trusts no passkey and does not start.`);
  }
  return [...new Set(list)];
}

function writeTrusted(folder, list) {
  mkdirSync(folder, { recursive: true });
  replaceFile(files(folder).trusted, JSON.stringify({ about: 'The thumbprints of the passkeys whose permissions this recorder takes. Written by "use", changed only by "renew --new-passkey".', passkeys: list }, null, 2) + '\n');
}

/**
 * The passkeys the recorder trusts, for a book and the slip in place.
 * Where the folder has no list: a new book trusts the passkey of its first
 * slip, and the list is written; a book kept by an earlier version of the
 * recorder, which kept no list, is taken as it is only where every slip in
 * it, and slip.json, is from one passkey, and the list is written for it.
 * Then every slip in the book, and slip.json, must be from a passkey on
 * the list, or the recorder does not start.
 * @param {string} folder
 * @param {string} text the book
 * @param {{issuerKey: string, fingerprint: string}|null} placed slip.json
 * @returns {Promise<string[]>}
 */
export async function trustFor(folder, text, placed) {
  let list = readTrusted(folder);
  const inBook = await passkeysIn(text);
  if (list === null) {
    const all = [...new Set([...inBook, ...(placed ? [placed.issuerKey] : [])])];
    if (all.length > 1) {
      throw new Error(`The book and slip.json hold permissions signed by ${all.length} passkeys (${all.join(', ')}), and the folder has no list of the passkeys this recorder trusts (${files(folder).trusted}): an earlier version kept none. If each of them is yours, write their thumbprints into that file as {"passkeys": ["…", "…"]} and start again.`);
    }
    if (all.length === 0) return [];
    list = all;
    writeTrusted(folder, list);
  }
  const foreign = inBook.filter((k) => !list.includes(k));
  if (foreign.length > 0) {
    throw new Error(`The book holds a permission signed by a passkey that is not on the list of passkeys this recorder trusts (${foreign.join(', ')}): it was not taken by "use" or "renew --new-passkey", so the recorder does not start. Check the book with the checker, naming your own passkey (--issuer), before you go on.`);
  }
  if (placed && !list.includes(placed.issuerKey)) {
    throw new Error(`The permission in place (slip.json) is signed by a passkey (${placed.issuerKey}) that signed none of the permissions this recorder trusts (${list.join(', ')}), so the recorder does not start. If you made a new passkey yourself, take the permission with "renew <file> --new-passkey".`);
  }
  return list;
}

/**
 * Check a slip before it is taken into the book: its passkey signature,
 * with the library's own checker; that it names this folder's agent keys;
 * and that it has not ended; and that its passkey is one the recorder
 * trusts already, unless "newPasskey" says the person made a new one.
 * Gives back what the recorder needs, with plain warnings: a slip not yet
 * in force, and a new passkey taken at the person's word.
 * @param {object} slip
 * @param {{agentKeys: object[], previous?: {issuerKey: string}|null, trusted?: string[], newPasskey?: boolean, now?: number, withoutMethods?: string[]}} o
 *   trusted: the thumbprints of the passkeys already trusted; by default the one that signed "previous".
 *   withoutMethods: signing methods to take as not built in, as the checker takes them (for tests)
 */
export async function checkNewSlip(slip, { agentKeys, previous = null, trusted = previous ? [previous.issuerKey] : [], newPasskey = false, now = Date.now(), withoutMethods = [] }) {
  const check = await checkSlip(slip, { withoutMethods });
  if (check.problems.length > 0) {
    throw new Error(`The permission does not pass its check, so it is not used: ${check.problems.map((p) => `[${p.code}] ${p.message}`).join(' ')}`);
  }
  if (check.signature.state !== 'valid') throw new Error(`This device could not check the passkey's signature on the permission (${check.signature.method}), so it is not used.`);
  const { content } = check;
  if (JSON.stringify(content.agent.keys) !== JSON.stringify(agentKeys)) {
    throw new Error(`The permission names other keys than the agent's keys in this folder, so it is not used. Sign one with the keys that "${RUN} keys" prints.`);
  }
  if (Date.parse(content.validUntil) <= now) throw new Error(`The permission ended at ${content.validUntil}, so it is not used. Sign a new one.`);
  const warnings = [];
  if (Date.parse(content.validFrom) > now) warnings.push(`The permission is in force only from ${content.validFrom}: until then every tool call is refused.`);
  // A passkey that signed no permission before is refused, so that no
  // program on this computer, the agent included, can bring in a permission
  // of its own making. The person's own new passkey is taken at their word.
  if (trusted.length > 0 && !trusted.includes(check.issuerKey)) {
    if (!newPasskey) {
      throw new Error(`This permission is signed by a passkey (${check.issuerKey}) that signed none of the permissions before it (${trusted.join(', ')}), so it is not used. If you made a new passkey yourself, run the command again with --new-passkey.`);
    }
    warnings.push(`This permission is signed by a new passkey (${check.issuerKey}), taken because --new-passkey was given. Whoever checks the book must now name both passkeys (--issuer, once for each).`);
  }
  return { slip, fingerprint: check.fingerprint, issuerKey: check.issuerKey, content, warnings };
}

/**
 * Put a checked slip in place as slip.json, keeping the one that stood
 * there before beside it, named by its fingerprint. The book is not
 * touched: the service takes the slip into the book when it next opens it.
 */
async function placeSlip(folder, next) {
  mkdirSync(folder, { recursive: true });
  const path = files(folder).slip;
  let before = null;
  let beforeFingerprint = null;
  try {
    before = slipFrom(readFileSync(path, 'utf8'), path);
    // Kept by the fingerprint of its content, as every receipt under it names it.
    beforeFingerprint = await fingerprint(fromBase64url(before.payload));
  } catch {
    // No slip.json yet, or one that cannot be read: it names no slip, and nothing is kept.
  }
  if (beforeFingerprint && beforeFingerprint !== next.fingerprint && !existsSync(keptSlip(folder, beforeFingerprint))) {
    writeFileSync(keptSlip(folder, beforeFingerprint), JSON.stringify(before));
  }
  replaceFile(path, JSON.stringify(next.slip));
}

// The fingerprints of the slips a book holds, read from its lines. A line
// that holds only a slip starts with {"slip": in the one canonical form.
// The passkeys that signed the slips a book holds. Each was taken into the
// book after its checks, so these are the passkeys the recorder trusts.
async function passkeysIn(text) {
  const found = [];
  for (const line of text.split('\n')) {
    if (!line.startsWith('{"slip":')) continue;
    try {
      const { issuerKey } = await aboutSlip(JSON.parse(line).slip);
      if (!found.includes(issuerKey)) found.push(issuerKey);
    } catch {
      // Not a slip that can be read: the checker reports it.
    }
  }
  return found;
}

async function slipsIn(text) {
  const found = new Set();
  for (const line of text.split('\n')) {
    if (!line.startsWith('{"slip":')) continue;
    try {
      found.add(await fingerprint(fromBase64url(JSON.parse(line).slip.payload)));
    } catch {
      // Not a slip that can be read: the checker reports it.
    }
  }
  return found;
}

// --- the service ---

/**
 * Open the stub writer on the folder's book and serve it on 127.0.0.1.
 *
 * The writer acts under slip.json. Where the book does not hold that slip
 * yet (a slip put in place while the service was not running), it is
 * checked and taken into the book first.
 * @param {{folder?: string, port?: number, name?: string}} o port 0 takes any free port
 * @returns {Promise<{port: number, close: () => Promise<void>, recorder: object, seal: () => Promise<object>, renew: (slip: object, o?: {newPasskey?: boolean}) => Promise<object>}>}
 */
export async function startService({ folder = DEFAULT_FOLDER, port = DEFAULT_PORT, name = 'The recorder beside the coding agent' } = {}) {
  const f = files(folder);
  if (!existsSync(f.slip)) throw new Error(`There is no signed slip at ${f.slip}. Sign one on the signing page and put it in place: ${RUN} use <the saved file>`);
  const placed = await loadSlip(folder);
  const agent = await loadAgentKeys(folder);
  const sealer = await makeRecorderKeys(folder);
  if (JSON.stringify(placed.content.agent.keys) !== JSON.stringify(agent.keys)) {
    throw new Error('The slip names other keys than the agent\'s keys in this folder. Sign a slip with the keys that "keys" prints.');
  }
  const sealKeys = [await keySetFingerprint(sealer.keys)];
  const options = { sealKeys };
  // Each writer opened reads the whole book once; "readings" counts them.
  let readings = 0;
  const open = (book, slipFingerprint, issuerKeys) => {
    readings++;
    return openRecorder({ book, slip: slipFingerprint, privateKeys: agent.privateKeys, issuerKeys, options });
  };
  const save = bookSaver(folder);

  let text = existsSync(f.book) ? readFileSync(f.book, 'utf8') : '';
  if (text !== '' && !text.endsWith('\n')) text += '\n';
  // The passkeys trusted: the folder's list (trusted-passkeys.json). The
  // recorder does not start if the book or slip.json holds a slip from a
  // passkey not on it.
  let trusted = await trustFor(folder, text, placed);
  const taken = text === '' || !(await slipsIn(text)).has(placed.fingerprint);
  if (taken) {
    // A new book, or a slip put in place while the service was not running:
    // taken in after the same checks as a renewal.
    await checkNewSlip(placed.slip, { agentKeys: agent.keys, trusted });
    text += entryLine({ slip: placed.slip }) + '\n';
  }
  /** What the service acts under: the writer, and the slip it was opened under. */
  let current = { writer: await open(text, placed.fingerprint, trusted), ...placed };
  save(current.writer.book());
  const started = new Date().toISOString();
  let count = 0;

  // One request at a time, so that a renewal never falls between a call
  // and its stub, and the writer is switched between two requests.
  let turn = Promise.resolve();
  const inTurn = (work) => {
    const run = turn.then(work);
    turn = run.catch(() => {});
    return run;
  };
  const entries = () => current.writer.book().split('\n').filter(Boolean).length;

  // The slip each call was allowed under, by Claude Code's identifier of
  // the call (tool_use_id, which the hook hands over before and after the
  // call). A call allowed under one slip and taken while a renewal
  // switched to the next is recorded under the slip it was allowed under.
  // The last 1,000 are kept: a call refused after it was allowed (at the
  // person's prompt) never comes back for its stub.
  const allowedUnder = new Map();
  const KEPT_CALLS = 1000;
  const callId = (given) => (typeof given.toolUseId === 'string' && given.toolUseId.length > 0 && given.toolUseId.length <= 200 ? given.toolUseId : null);

  // The writer of each slip before the one in force, kept at the switch
  // while a call allowed under that slip may still come back for its stub.
  const writersBefore = new Map();
  // Bring a writer up to a book that holds its own book and more lines after
  // it: each line is taken with "add", at the cost of one line's check, not
  // a reading of the whole book.
  async function catchUp(writer, book) {
    const have = writer.book();
    if (!book.startsWith(have)) throw new Error('The two books differ.');
    for (const line of book.slice(have.length).split('\n').filter(Boolean)) await writer.add(JSON.parse(line));
    if (writer.book() !== book) throw new Error('The two books differ.');
  }

  async function record(given) {
    const id = callId(given);
    const under = id ? allowedUnder.get(id) : undefined;
    if (id) allowedUnder.delete(id);
    const more = given.when ? { when: given.when } : {};
    if (under === undefined || under === current.fingerprint) return current.writer.record(requestFrom(given), more);
    // Under the slip before: the writer kept for it at the switch, brought
    // up to the book as it stands, writes the stub, and the writer for the
    // slip in force takes that one line. Where no such writer is kept (it
    // could not be brought up to date), one is opened: one reading of the
    // book.
    const book = current.writer.book();
    let before = writersBefore.get(under);
    if (before) {
      try {
        await catchUp(before, book);
      } catch {
        before = undefined;
      }
    }
    if (!before) {
      if (!(await slipsIn(book)).has(under)) return current.writer.record(requestFrom(given), more);
      before = await open(book, under, trusted);
      writersBefore.set(under, before);
    }
    const stub = await before.record(requestFrom(given), more);
    try {
      await catchUp(current.writer, before.book());
    } catch {
      current = { ...current, writer: await open(before.book(), current.fingerprint, trusted) };
    }
    if (![...allowedUnder.values()].includes(under)) writersBefore.delete(under);
    return stub;
  }

  async function seal() {
    const book = current.writer.book();
    // The seal before, from the writer's own answer for its book: nothing is read again.
    const result = await current.writer.check();
    const seals = result.entries.filter((e) => e.kind === 'seal' && e.problems.length === 0);
    const previous = seals.length ? seals[seals.length - 1].fingerprint : undefined;
    const sealed = await writeSeal(book, { by: { keys: sealer.keys, name }, previous, when: Date.now() }, sealer.privateKeys);
    // No outside time-stamp is put beside the seal here (a seal without one has no "stamps" member).
    await current.writer.add({ seal: sealed.record });
    save(current.writer.book());
    return { fingerprint: sealed.fingerprint, entries: entries() };
  }

  // Take a new slip: check it, open a second writer on the book with the
  // slip added and acting under it, and only once that writer is open,
  // write the files and switch to it. The service goes on listening
  // throughout: a call that arrives meanwhile waits its turn, and is
  // answered by the writer after the switch, so the hook never finds the
  // service gone. If anything fails before the switch, the writer before
  // goes on, and no passkey is added to the list. A slip from a passkey not on the list is
  // taken only with "newPasskey", which adds it to the list.
  async function renew(given, newPasskey = false) {
    const next = await checkNewSlip(given, { agentKeys: agent.keys, previous: current, trusted, newPasskey });
    const before = current.fingerprint;
    if (next.fingerprint === before) return { slip: before, previous: before, issuer: current.issuerKey, entries: entries(), unchanged: true, warnings: [] };
    const book = current.writer.book();
    const inBook = (await slipsIn(book)).has(next.fingerprint);
    const issuerKeys = trusted.includes(next.issuerKey) ? trusted : [...trusted, next.issuerKey];
    const writer = await open(inBook ? book : book + entryLine({ slip: next.slip }) + '\n', next.fingerprint, issuerKeys);
    if (!existsSync(keptSlip(folder, before))) writeFileSync(keptSlip(folder, before), JSON.stringify(current.slip));
    // slip.json and the book first, the list of passkeys last, so that a
    // renewal that fails on the way never leaves a new passkey trusted;
    // slip.json is put back where a later step fails. Whatever is left, the
    // start-up checks refuse a slip from a passkey not on the list.
    replaceFile(f.slip, JSON.stringify(next.slip));
    try {
      save(writer.book());
      if (issuerKeys !== trusted) writeTrusted(folder, issuerKeys);
    } catch (e) {
      try { replaceFile(f.slip, JSON.stringify(current.slip)); } catch { /* left to the start-up checks */ }
      // The book file too, which may already hold the new permission's line.
      try { saveBook(folder, current.writer.book()); } catch { /* the saver puts the file right with the next entry */ }
      throw e;
    }
    trusted = issuerKeys;
    // The writer before is kept while a call allowed under its slip may still come back for its stub.
    if ([...allowedUnder.values()].includes(before)) writersBefore.set(before, current.writer);
    current = { writer, slip: next.slip, fingerprint: next.fingerprint, issuerKey: next.issuerKey, content: next.content };
    return { slip: next.fingerprint, previous: before, issuer: next.issuerKey, entries: entries(), validUntil: next.content.validUntil, warnings: next.warnings };
  }

  // A caller that has gone (it gave up waiting) is not answered. Its
  // question before a call, a seal or a renewal it asked for, still waiting
  // its turn, is not done. The stub of a call that was taken is always
  // written, whether or not the hook still waits for it: the hook has said
  // that it was not confirmed, not that it was not written.
  class Gone extends Error {}
  const server = createServer(async (req, res) => {
    let gone = false;
    res.on('close', () => {
      if (!res.writableFinished) gone = true;
    });
    const unlessGone = (work) => inTurn(() => {
      if (gone) throw new Gone();
      return work();
    });
    const send = (code, body) => {
      if (gone) return;
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    try {
      if (req.method === 'GET' && req.url === '/status') {
        return send(200, {
          slip: current.fingerprint,
          issuer: current.issuerKey,
          sealer: sealKeys[0],
          agent: current.content.agent.name,
          validFrom: current.content.validFrom,
          validUntil: current.content.validUntil,
          trusted,
          entries: entries(),
          recordedSinceStart: count,
          started,
          folder,
        });
      }
      if (req.method !== 'POST') return send(404, { error: 'not found' });
      let body = '';
      for await (const chunk of req) {
        body += chunk;
        if (body.length > MAX_BODY) return send(413, { error: 'too large' });
      }
      const given = body ? JSON.parse(body) : {};
      if (req.url === '/before') {
        const answer = await unlessGone(async () => {
          const said = await current.writer.before(requestFrom(given));
          const id = callId(given);
          if (said.allowed && id) {
            allowedUnder.set(id, current.fingerprint);
            if (allowedUnder.size > KEPT_CALLS) allowedUnder.delete(allowedUnder.keys().next().value);
          }
          return said;
        });
        return send(200, answer);
      }
      if (req.url === '/record') {
        try {
          // The answer is sent only once the stub is written and saved.
          const written = await inTurn(async () => {
            const stub = await record(given);
            count++;
            save(current.writer.book());
            return stub;
          });
          return send(200, { seq: written.seq, fingerprint: written.fingerprint });
        } catch (e) {
          if (e instanceof Gone) return undefined;
          return send(409, { error: e.message, code: e.code });
        }
      }
      if (req.url === '/seal') return send(200, await unlessGone(seal));
      if (req.url === '/renew') {
        try {
          return send(200, await unlessGone(() => renew(given.slip, given.newPasskey === true)));
        } catch (e) {
          if (e instanceof Gone) return undefined;
          return send(409, { error: e.message, code: e.code });
        }
      }
      if (req.url === '/stop') {
        send(200, { stopped: true });
        setTimeout(() => server.close(), 50);
        return undefined;
      }
      return send(404, { error: 'not found' });
    } catch (e) {
      if (e instanceof Gone) return undefined;
      return send(500, { error: e.message });
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  return {
    port: server.address().port,
    get recorder() { return current.writer; },
    get readings() { return readings; },
    seal: () => inTurn(seal),
    renew: (slip, { newPasskey = false } = {}) => inTurn(() => renew(slip, newPasskey)),
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

function requestFrom(given) {
  const request = { action: String(given.action ?? '') };
  if (Array.isArray(given.details)) request.details = given.details;
  if (given.amount) request.amount = given.amount;
  if (given.with) request.with = given.with;
  return request;
}

// --- setting up: the hooks, and the starting permission ---

const slashes = (path) => path.split(sep).join('/');

/**
 * The hooks that make Claude Code ask the recorder: the service is started
 * with each session, and every tool call is asked about before it is
 * taken, and recorded after it, whether it succeeded or failed (the hook
 * itself leaves out the few tools that only talk to the person or the
 * model: actions.mjs). The paths are absolute, to this copy of the
 * recorder.
 *
 * "onFailure": "block" makes Claude Code refuse a call when the hook
 * cannot start, ends in a way it did not choose, or takes too long: by
 * default Claude Code lets the call go ahead. Claude Code reads it from
 * version 2.1.295; an older version sets it aside.
 */
export function hookSettings({ hook = HOOK, recorder = SELF } = {}) {
  const run = (script, ...args) => ({ type: 'command', command: 'node', args: ['--disable-warning=ExperimentalWarning', slashes(script), ...args], timeout: 30 });
  const ask = { ...run(hook), onFailure: 'block' };
  return {
    SessionStart: [{ hooks: [run(recorder, 'ensure')] }],
    PreToolUse: [{ matcher: '*', hooks: [ask] }],
    PostToolUse: [{ matcher: '*', hooks: [ask] }],
    PostToolUseFailure: [{ matcher: '*', hooks: [ask] }],
  };
}

// One of this package's own hooks: its whole command is exactly the one
// this package writes, "node" with the warning switch, the script's path
// and, for the start of a session, "ensure"; written with "args" or as one
// command line, with or without the warning switch, the path with either
// slash (and in any letter case on Windows). Anything more or less in the
// command (another script, a second command, a redirection, a file whose
// name only begins with ours) makes it a hook of the person's own, and it
// stays as it is.
const WARNING_SWITCH = '--disable-warning=ExperimentalWarning';
const samePath = (a, b) => {
  const plain = (p) => p.split('\\').join('/');
  return process.platform === 'win32' ? plain(a).toLowerCase() === plain(b).toLowerCase() : plain(a) === plain(b);
};
// The words of one command line: a word in double quotation marks is one word.
const lineWords = (line) => [...line.matchAll(/"([^"]*)"|(\S+)/g)].map((m) => m[1] ?? m[2]);
function sameRun(a, b) {
  if (a === null || typeof a !== 'object' || a.type !== b.type) return false;
  let words = null;
  if (a.args !== undefined) words = a.command === 'node' && Array.isArray(a.args) ? a.args : null;
  else if (typeof a.command === 'string') {
    const all = lineWords(a.command.trim());
    words = all[0] === 'node' ? all.slice(1) : null;
  }
  if (!words || !words.every((w) => typeof w === 'string')) return false;
  if (words[0] === WARNING_SWITCH) words = words.slice(1);
  const [, script, ...rest] = b.args;
  return words.length === 1 + rest.length && samePath(words[0], script) && rest.every((w, i) => words[i + 1] === w);
}
// An entry that does what ours does: the same, except a longer time-out the person set (or none, which Claude Code reads as 600 seconds).
const exceptTimeout = ({ timeout, ...rest }) => JSON.stringify(rest);
const covers = (h, mine) => h !== null && typeof h === 'object' && exceptTimeout(h) === exceptTimeout(mine) && (h.timeout === undefined || (typeof h.timeout === 'number' && h.timeout >= mine.timeout));

/**
 * Write the hooks into a project's .claude/settings.local.json, keeping
 * everything else that is there: other settings and other hooks are never
 * taken out, and a hook that is there already is not added twice. An
 * earlier entry of this same hook (the same script, with another matcher,
 * in an earlier shape, or written as one command line) is replaced by the
 * current one, keeping a longer time-out the person set; anything else in
 * its group stays as it was. Another hook that names Provared is reported,
 * not changed. The file is written only if something changed, with a
 * byte-order mark if it had one.
 *
 * The file is read and written as JSON, so where something changed, a
 * whole number too large for JavaScript to hold exactly, or a member given
 * twice, is not kept exactly as it was written.
 * @param {string} project the project's folder
 * @returns {{path: string, added: number, replaced: number, present: number, others: string[], switchedOff: boolean}}
 */
export function writeHooks(project, ours = hookSettings()) {
  const path = join(project, '.claude', 'settings.local.json');
  let settings = {};
  const existed = existsSync(path);
  let mark = '';
  if (existed) {
    const text = readFileSync(path, 'utf8');
    if (text.startsWith('\uFEFF')) mark = '\uFEFF';
    try {
      settings = JSON.parse(text.slice(mark.length));
    } catch {
      throw new Error(`${path} is not JSON, so it was left as it is. Mend it, or move it aside, and run init again.`);
    }
  }
  if (!settings || typeof settings !== 'object' || Array.isArray(settings)) throw new Error(`${path} does not hold one JSON object, so it was left as it is.`);
  if (settings.hooks === undefined) settings.hooks = {};
  const hooks = settings.hooks;
  if (!hooks || typeof hooks !== 'object' || Array.isArray(hooks)) throw new Error(`"hooks" in ${path} is not an object, so the file was left as it is.`);
  for (const event of Object.keys(ours)) {
    if (hooks[event] !== undefined && !Array.isArray(hooks[event])) throw new Error(`"hooks.${event}" in ${path} is not a list, so the file was left as it is.`);
  }
  const mine = Object.values(ours).flatMap((groups) => groups.flatMap((g) => g.hooks));
  const others = [];
  let added = 0;
  let replaced = 0;
  let present = 0;
  for (const [event, groups] of Object.entries(ours)) {
    if (hooks[event] === undefined) hooks[event] = [];
    const list = hooks[event];
    for (const group of groups) {
      const wanted = group.hooks[0];
      // There already: an entry that does what ours does, under the same matcher, whatever else shares its group.
      if (list.some((g) => g && Array.isArray(g.hooks) && g.matcher === group.matcher && g.hooks.some((h) => covers(h, wanted)))) {
        present++;
        continue;
      }
      let longest = wanted.timeout;
      let found = false;
      for (let i = list.length - 1; i >= 0; i--) {
        const g = list[i];
        if (!g || !Array.isArray(g.hooks)) continue;
        const kept = g.hooks.filter((h) => {
          if (!sameRun(h, wanted)) return true;
          if (typeof h.timeout === 'number' && h.timeout > longest) longest = h.timeout;
          return false;
        });
        if (kept.length === g.hooks.length) continue;
        found = true;
        if (kept.length === 0) list.splice(i, 1);
        else g.hooks = kept;
      }
      list.push(longest === wanted.timeout ? group : { ...group, hooks: [{ ...wanted, timeout: longest }] });
      if (found) replaced++;
      else added++;
    }
    for (const g of list) {
      for (const h of g && Array.isArray(g.hooks) ? g.hooks : []) {
        const said = JSON.stringify([h?.command, h?.args]);
        if (/provared/i.test(said) && !mine.some((m) => sameRun(h, m)) && !others.includes(said)) others.push(said);
      }
    }
  }
  if (!existed || added + replaced > 0) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, mark + JSON.stringify(settings, null, 2) + '\n');
  }
  return { path, added, replaced, present, others, switchedOff: switchedOff(project) };
}

// Whether a settings file of the project switches every hook off ("disableAllHooks": true).
function switchedOff(project) {
  return ['settings.local.json', 'settings.json'].some((name) => {
    try {
      return JSON.parse(readFileSync(join(project, '.claude', name), 'utf8').replace(/^\uFEFF/, '')).disableAllHooks === true;
    } catch {
      return false;
    }
  });
}

/**
 * A starting permission for a coding agent, for the signing page: the same
 * as the page's own starting point, with this agent's public keys and name.
 * Its times are left to the page, which sets them when it is opened.
 */
export function startingPermission(agentKeys) {
  return {
    agent: { name: 'Claude Code', keys: agentKeys },
    actions: ['provared.code.read', 'provared.code.change', 'provared.code.run', 'provared.web.read', 'provared.agent.instruct'],
    limits: [
      { action: 'provared.code.run', count: 500, per: 3600 },
      { action: 'provared.code.change', count: 500, per: 3600 },
    ],
    requires: [],
    never: ['destroys', 'conceal', 'deceive', 'bypass', 'escalate', 'continue-after-stop'],
    with: [],
    purpose: 'Coding work with Claude Code on this computer.',
  };
}

/** The signing page's address, with a starting permission in its fragment (the part after "#", which a browser never sends). */
export function signingLink(permission, page = SIGNING_PAGE) {
  return `${page}#permission=${toBase64url(utf8(JSON.stringify(permission)))}`;
}

// --- the commands ---

async function ask(port, path, method = 'GET', body) {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(60000) });
  return response.json();
}

async function running(port) {
  try {
    return await ask(port, '/status');
  } catch {
    return null;
  }
}

async function ensure(folder, port) {
  if (await running(port)) return 0;
  if (!existsSync(files(folder).slip)) {
    console.error(`The recorder has no signed permission yet (${files(folder).slip}), so it was not started. Sign one and put it in place: ${RUN} use <the saved file>`);
    return 1;
  }
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', SELF, 'start'], { detached: true, stdio: 'ignore', env: process.env });
  child.unref();
  for (let i = 0; i < 80; i++) {
    await new Promise((r) => setTimeout(r, 250));
    if (await running(port)) return 0;
  }
  console.error(`The recorder did not start. Run "${RUN} start" to see why.`);
  return 1;
}

function sayRenewed(answer) {
  for (const w of answer.warnings ?? []) console.log(`Warning: ${w}`);
  if (answer.unchanged) {
    console.log(`The recorder already acts under this permission (${answer.slip}). Nothing was changed.`);
    return;
  }
  console.log(`The new permission ${answer.slip} is in the book, and the recorder acts under it${answer.validUntil ? ` until ${answer.validUntil}` : ''}.`);
  console.log(`  The one before (${answer.previous}) is kept beside it as slip-${answer.previous}.json. The book holds ${answer.entries} entries.`);
}

// Take a slip into the book: through the running service, or, where it is
// not running, by putting the slip in place and opening the book here.
async function renewFrom(file, folder, port, newPasskey = false) {
  const slip = slipFrom(readFileSync(file, 'utf8'), file);
  if (await running(port)) {
    const answer = await ask(port, '/renew', 'POST', { slip, newPasskey });
    if (answer.error === 'not found') {
      throw new Error(`The recorder that is running is an earlier version, which cannot take a new permission while it runs. Restart it once, with both commands on one line so that no tool call falls between them, then run renew again: ${RUN} stop; ${RUN} ensure`);
    }
    if (answer.error) throw new Error(answer.error);
    sayRenewed(answer);
    return;
  }
  const agent = await loadAgentKeys(folder);
  let previous = null;
  try {
    previous = existsSync(files(folder).slip) ? await loadSlip(folder) : null;
  } catch {
    // A slip.json that cannot be read is replaced.
  }
  const bookText = existsSync(files(folder).book) ? readFileSync(files(folder).book, 'utf8') : '';
  // The folder's list, as the recorder reads it; slip.json is about to be replaced, so it is not held to it.
  const trusted = await trustFor(folder, bookText, null);
  const next = await checkNewSlip(slip, { agentKeys: agent.keys, previous, trusted, newPasskey });
  if (previous && previous.fingerprint === next.fingerprint && bookText !== '' && (await slipsIn(bookText)).has(next.fingerprint)) {
    sayRenewed({ unchanged: true, slip: next.fingerprint, warnings: [] });
    return;
  }
  // A new passkey, taken at the person's word, goes on the list; the
  // recorder, opened here, then takes the slip into the book.
  if (!trusted.includes(next.issuerKey)) writeTrusted(folder, [...trusted, next.issuerKey]);
  await placeSlip(folder, next);
  const service = await startService({ folder, port: 0 });
  try {
    sayRenewed({ slip: next.fingerprint, previous: previous ? previous.fingerprint : '(none)', entries: service.recorder.book().split('\n').filter(Boolean).length, validUntil: next.content.validUntil, warnings: next.warnings });
  } finally {
    await service.close();
  }
}

/** The slips a book holds, read from its lines: what "check" shows where the person names no passkey. */
async function slipsListed(text) {
  const out = [];
  for (const line of text.split('\n')) {
    if (!line.startsWith('{"slip":')) continue;
    try {
      const about = await aboutSlip(JSON.parse(line).slip);
      out.push({ fingerprint: about.fingerprint, issuerKey: about.issuerKey, name: String(about.content.issuer?.name ?? ''), from: about.content.validFrom, until: about.content.validUntil });
    } catch {
      // Not a slip that can be read: the checker reports it.
    }
  }
  return out;
}

const USAGE = `Usage: ${RUN} <command>

  init          make the keys if they are missing, write the hooks into this project's
                .claude/settings.local.json, and print a link to sign the permission
  use <file>    put a signed permission (slip.json from the signing page) in place, and start
  renew <file>  take a new signed permission into the book, while the recorder runs or not;
                add --new-passkey if you signed it with a passkey that signed no permission before
  start         run the recorder in this terminal
  ensure        start the recorder in the background, if it is not running
  status        what the recorder holds
  seal          seal the book now, with the recorder's three keys
  check         the checker's answer for the book; name your own passkey with
                --issuer <its thumbprint> (once for each), or see the passkeys the book names
  stop          stop the recorder
  keys          make the keys, and print the agent's public keys`;

async function main(argv) {
  const [command, ...rest] = argv;
  const folder = DEFAULT_FOLDER;
  const port = DEFAULT_PORT;
  const f = files(folder);
  if (command === 'keys') {
    const agent = await makeAgentKeys(folder);
    await makeRecorderKeys(folder);
    console.log(`The agent's keys are in ${f.agentKeys}, and the recorder's in ${f.recorderKeys}. Never share either file.`);
    console.log('\nThe agent\'s two public keys, to paste into the signing page as "agent.keys":\n');
    console.log(JSON.stringify(agent.keys));
    console.log(`\nThe fingerprint of the agent's key set: ${await keySetFingerprint(agent.keys)}`);
    console.log('The signing page shows the same fingerprint before you sign: compare the two.');
    return 0;
  }
  if (command === 'init') {
    const agent = await makeAgentKeys(folder);
    await makeRecorderKeys(folder);
    const written = writeHooks(process.cwd());
    console.log(`The agent's keys and the recorder's are in ${folder}. Never share the files there that end in .jwk.`);
    console.log(`The record (the book, the permissions and the keys) is kept in that folder too. Anything that deletes the folder, such as an agent that deletes your home folder, deletes the record with it. To keep it on another disk, set PROVARED_CLAUDE_CODE_DIR to a folder there before you run init, and keep copies of the book elsewhere (see the README).`);
    console.log(written.added + written.replaced > 0
      ? `The hooks are in ${written.path}${written.replaced > 0 ? ` (${written.replaced} earlier entries of them brought up to date)` : ''}: Claude Code, started in this folder, asks the recorder before and after each tool call.`
      : `The hooks were in ${written.path} already. Nothing was changed.`);
    for (const other of written.others) console.log(`Warning: another hook there names Provared: ${other}. If it is an older copy of this recorder, take it out by hand, or each tool call is asked about and recorded twice.`);
    if (written.switchedOff) console.log(`Warning: a settings file of this project says "disableAllHooks": true, so Claude Code runs no hook, these included, and nothing is checked or recorded. Take that setting out to record.`);
    if (SELF.split(sep).includes('_npx')) console.log(`Warning: the hooks point into npm's temporary folder (${dirname(SELF)}), which npm may clear. Install the package (npm install -g provared-claude-code) and run init again.`);
    console.log('\nNext, sign the permission with your passkey. Open this link in a browser: the page is filled in with a');
    console.log('starting permission for this agent, which you can change before you sign. The part after "#" stays in');
    console.log('your browser: it is never sent to any server.\n');
    console.log(signingLink(startingPermission(agent.keys)));
    console.log(`\nThe fingerprint of the agent's key set: ${await keySetFingerprint(agent.keys)}`);
    console.log('The signing page shows the same fingerprint before you sign: compare the two. If they differ, the page holds other keys than this agent\'s: do not sign.');
    console.log(`\nSave the signed file the page gives you, then put it in place:\n\n  ${RUN} use <the saved file>`);
    return 0;
  }
  if (command === 'use' || command === 'renew') {
    const newPasskey = rest.includes('--new-passkey');
    const named = rest.filter((a) => a !== '--new-passkey');
    if (!named[0]) {
      console.log(USAGE);
      return 2;
    }
    const file = resolve(named[0]);
    if (command === 'renew' || existsSync(f.book)) {
      await renewFrom(file, folder, port, newPasskey);
    } else {
      // The first slip: put in place, and the book begins with it when the service starts.
      const slip = slipFrom(readFileSync(file, 'utf8'), file);
      const agent = await loadAgentKeys(folder);
      const previous = existsSync(f.slip) ? await loadSlip(folder) : null;
      // The list of trusted passkeys begins here, with this slip's; one there already takes a new passkey only with --new-passkey.
      const trusted = readTrusted(folder) ?? [];
      const next = await checkNewSlip(slip, { agentKeys: agent.keys, previous, trusted, newPasskey });
      for (const w of next.warnings) console.log(`Warning: ${w}`);
      if (!trusted.includes(next.issuerKey)) writeTrusted(folder, [...trusted, next.issuerKey]);
      await placeSlip(folder, next);
      console.log(`The permission ${next.fingerprint}, signed by the passkey ${next.issuerKey}, is in place until ${next.content.validUntil}.`);
    }
    if (command === 'renew') return 0;
    const code = await ensure(folder, port);
    if (code === 0) console.log(`The recorder is running. Start Claude Code in a project where "${RUN} init" was run, and each tool call is checked and recorded.`);
    return code;
  }
  if (command === 'start') {
    const service = await startService({ folder, port });
    const status = await ask(service.port, '/status');
    console.log(`The Provared recorder beside Claude Code is running on http://127.0.0.1:${service.port}`);
    console.log(`  Slip ${status.slip}, signed by the passkey ${status.issuer}, until ${status.validUntil}; the book holds ${status.entries} entries.`);
    console.log('  Press Ctrl and C to stop. Each tool call Claude Code makes is checked against the slip and recorded.');
    return null;
  }
  if (command === 'ensure') return ensure(folder, port);
  if (command === 'check') {
    if (!existsSync(f.book)) {
      console.error(`There is no book yet at ${f.book}.`);
      return 2;
    }
    // The command-line checker of the library this recorder runs on, so that
    // its answer and its exit code are the checker's own: 0 only where the
    // person named the passkey they trust. Their options go to it as they
    // are; "check" names no passkey for them.
    const checker = fileURLToPath(new URL('../bin/provared-check.mjs', import.meta.resolve('provared')));
    const extra = [];
    if (!rest.includes('--sealer')) {
      const sealer = await keySetFingerprint((await loadRecorderKeys(folder)).keys);
      extra.push('--sealer', sealer);
      console.error(`The recorder you expect to have sealed the book (--sealer) is named from the recorder's own folder: ${sealer}. To name it yourself, give --sealer.`);
    }
    if (!rest.includes('--issuer')) {
      console.error('You named no passkey (--issuer), so the checker does not take any as one you trust. The book holds permissions signed by these passkeys, read from the book itself, not named by you:');
      for (const s of await slipsListed(readFileSync(f.book, 'utf8'))) {
        console.error(`  passkey ${s.issuerKey}: the permission ${s.fingerprint}, from ${s.from} until ${s.until}, signed as "${s.name.toWellFormed().replace(/[\u0000-\u001f\u007f-\u009f]/g, '�')}" (a label)`);
      }
      console.error(`Compare each with your own passkey's thumbprint, which the signing page shows when you sign, and run again with --issuer <thumbprint> for each that is yours: ${RUN} check --issuer <thumbprint>\n`);
    }
    const ran = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', checker, f.book, ...rest, ...extra], { stdio: 'inherit' });
    return ran.status ?? 2;
  }
  const status = await running(port);
  if (command === 'status') {
    if (!status) {
      console.log(`The recorder is not running (nothing answers on 127.0.0.1:${port}).`);
      return 1;
    }
    console.log(JSON.stringify(status, null, 2));
    return 0;
  }
  if (command === 'seal') {
    if (status) {
      const sealed = await ask(port, '/seal', 'POST', {});
      if (sealed.error || typeof sealed.fingerprint !== 'string') {
        console.error(`The book was not sealed: ${sealed.error ?? 'the recorder gave no seal.'}`);
        return 1;
      }
      console.log(`Sealed: entry ${sealed.entries} is the seal ${sealed.fingerprint}.`);
      return 0;
    }
    const service = await startService({ folder, port: 0 });
    const sealed = await service.seal();
    await service.close();
    console.log(`Sealed (the service was not running, so the book was opened here): entry ${sealed.entries} is the seal ${sealed.fingerprint}.`);
    return 0;
  }
  if (command === 'stop') {
    if (!status) return 0;
    await ask(port, '/stop', 'POST', {});
    console.log('Stopped.');
    return 0;
  }
  console.log(USAGE);
  return 2;
}

// Run as a program (directly, or through the npm "bin", which may reach
// this file through a link), not when imported by the tests.
let invoked = '';
try { invoked = process.argv[1] ? realpathSync(process.argv[1]) : ''; } catch { /* not a file */ }
if (invoked === SELF) {
  process.removeAllListeners('warning');
  // The process is left to end by itself once its connections have closed:
  // ending it at once, after a request to the service, made Node.js on
  // Windows fail an internal check on the way out (seen on 10 October 2026).
  main(process.argv.slice(2)).then((code) => {
    if (code !== null) process.exitCode = code;
  }, (e) => {
    console.error(e.message);
    process.exitCode = 1;
  });
}
