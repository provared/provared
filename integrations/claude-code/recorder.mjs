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
//   provared-claude-code new-book      seal the book, keep it, and start a new one that begins with the
//                                      permission in force (done by itself at 90,000 entries or 100 MB)
//   provared-claude-code check [file]  the checker's answer for the book, or for a book kept before it
//   provared-claude-code add-witness <address> <fingerprint> <token file>
//                                      ask a witness (provared-witness) to sign for every seal from now on
//   provared-claude-code remove-witness <fingerprint>
//                                      ask that witness no more
//   provared-claude-code stop          stop the service
//   provared-claude-code keys          make the keys, and print the agent's public keys
//   provared-claude-code remove-hooks  take the hooks "init" wrote out of this project's
//                                      .claude/settings.local.json (for the Claude Code plugin)
//   provared-claude-code session-start what the plugin's hooks run when a session starts: "ensure",
//                                      and what the person must do, told to them and to Claude
//
// From a copy of the repository the same commands run as
// "node recorder.mjs <command>". The Claude Code plugin
// (.claude-plugin/plugin.json and hooks/hooks.json in this folder) runs this
// same folder from Claude Code's plugin cache, where "init" writes no hooks,
// since the plugin brings its own.
//
// The folder (PROVARED_CLAUDE_CODE_DIR, or ~/.provared/claude-code) holds:
//   agent-keys.jwk           the agent's two private keys (never share)
//   recorder-keys.jwk        the recorder's three private keys, for seals (never share)
//   slip.json                the signed slip the service acts under, from the signing page
//   slip-<fingerprint>.json  each slip that stood in its place before, kept by its fingerprint
//   trusted-passkeys.json    the thumbprints of the passkeys this recorder trusts ("passkeys": written at the
//                            first "use", added to only by "renew --new-passkey" and "admit-passkey"), and among
//                            them those that may sign no new slip ("retired": written by "retire-passkey" and
//                            "admit-passkey")
//   book.jsonl               the book: the slips, a stub for each tool call, and seals
//   book-<n>.jsonl           each book kept before it, sealed, numbered from 1 in the order kept
//   feed-token               the token a reader gives to read the books through the feed (feed.mjs):
//                            written at the first start (never share)
//   witnesses.json           the witnesses it asks to sign for its seals, each with its address, the
//                            fingerprint of its key set and its token: written by "add-witness" (never share)
//   witnessed/               the statements that witnesses handed back after the seal's line was written, one
//                            file for each seal, in the form a checker takes beside the book (--seal)
//   pending-seal.json        a seal whose line is not yet written while "seal" waits for the witnesses; written
//                            at its place at the next start if a stop came first
//   held-cancellations.json  the person's cancellations handed over and held beside the book until this
//                            computer's clock reaches their dates; given to the writer at each start
//   waiting-permissions.json permissions handed over and refused because a passkey this computer does not
//                            trust signed them, each waiting for "admit-passkey" (nothing in it is trusted;
//                            at most 8, one for each passkey, the one that starts latest)
//
// Seals are numbered by book (format description, section 21.6): a new
// book's first seal gives the book's number and names the last seal of the
// book before it from the same passkey and agent, so that a witness
// (witness.mjs, witnessed.mjs) can follow every book of one person and agent.
//
// The feed (GET /books and /lines, feed.mjs) gives the books' lines to a
// reader on this computer that holds the token, such as the application's
// uploader, so that no other program need open a book file. The same reader
// may hand over a record the person signed elsewhere (POST /hand-over): a
// renewal, taken as "renew" takes one but never from a passkey this
// computer does not already trust, and never one that starts before a
// cancellation the recorder holds; or a cancellation of the permission in
// force, which stops every call under it and which the agent's side
// acknowledges in the book. Each must have been signed at the signing page
// (SIGNING_ORIGIN, or the setting PROVARED_CLAUDE_CODE_SIGNING_ORIGIN). The
// recorder checks each record itself.
//
// It listens on 127.0.0.1 only. Any program on this computer could ask it
// to write a stub, or to take a new slip, and could change the files in its
// folder: the record is of what this computer's agent did, as its own
// software says, and the evidence that holds is a checker naming the
// person's own passkey. Nothing here reaches the network.

import { spawn, spawnSync } from 'node:child_process';
import nodeCrypto from 'node:crypto';
import { appendFileSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, realpathSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { homedir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { checkBook, checkSlip, entryLine, fingerprint, fromBase64url, inclusionPath, keySetFingerprint, openRecorder, thumbprint, toBase64url, utf8, verifyInclusion, writeSeal } from 'provared';
import { createFeed, feedToken, isRandom } from './feed.mjs';
import { claudeFolder, doubledWords, filesOf, recorderHooksInSettings, removeInitHooks, within } from './settings-hooks.mjs';
import { firstLineOfFile, replaceDurably, witnessClient } from './witness.mjs';
import { MAX_RECORDER_WITNESSES, WITNESS_RETRY_MS, WITNESS_WAIT_MS, createWitnessing, heldSealFiles, keepStatement, readWitnessSettings, validAddress, writeWitnessSettings } from './witnessed.mjs';

const subtle = globalThis.crypto.subtle;
const SLH = 'SLH-DSA-SHA2-256s';
const MAX_BODY = 1024 * 1024;

export const DEFAULT_FOLDER = process.env.PROVARED_CLAUDE_CODE_DIR || join(homedir(), '.provared', 'claude-code');
export const DEFAULT_PORT = Number(process.env.PROVARED_CLAUDE_CODE_PORT || 8794);
export const SIGNING_PAGE = 'https://sign.prova.red/';

// This file and the hook beside it, where they really are (an npm "bin"
// may reach this file through a link).
const SELF = realpathSync(fileURLToPath(import.meta.url));
const HOOK = join(dirname(SELF), 'hook.mjs');
// How the person runs this program: by its name where it was installed
// from npm, and by its path from a copy of the repository.
// Run through the Claude Code plugin's entry (plugin.mjs), that entry names it.
const RUN = process.env.PROVARED_CLAUDE_CODE_RUN || (SELF.split(sep).includes('node_modules') ? 'provared-claude-code' : `node ${SELF.includes(' ') ? `"${SELF}"` : SELF}`);
// Claude Code's plugins folder, and whether this copy is the plugin's, in Claude Code's plugin cache.
const PLUGINS = process.env.CLAUDE_CODE_PLUGIN_CACHE_DIR || join(claudeFolder(), 'plugins');
// Run through the plugin's entry, or from a copy in Claude Code's plugin cache.
const FROM_PLUGIN = process.env.PROVARED_CLAUDE_CODE_PLUGIN === '1' || within(SELF, join(PLUGINS, 'cache'));
// The plugin's name in its marketplace, as Claude Code records an install of it.
const PLUGIN_ID = 'provared-recorder@';
function pluginInstalled() {
  try {
    return readFileSync(join(PLUGINS, 'installed_plugins.json'), 'utf8').includes(`"${PLUGIN_ID}`);
  } catch {
    return false;
  }
}

const files = (folder) => ({
  agentKeys: join(folder, 'agent-keys.jwk'),
  recorderKeys: join(folder, 'recorder-keys.jwk'),
  slip: join(folder, 'slip.json'),
  trusted: join(folder, 'trusted-passkeys.json'),
  book: join(folder, 'book.jsonl'),
  held: join(folder, 'held-cancellations.json'),
  waiting: join(folder, 'waiting-permissions.json'),
});
const keptSlip = (folder, slipFingerprint) => join(folder, `slip-${slipFingerprint}.json`);
const THUMBPRINT = /^[A-Za-z0-9_-]{43}$/;

// --- records handed over from the application ---
//
// The address a record handed over must have been signed at (the
// application's signing page), unless the setting names another:
// PROVARED_CLAUDE_CODE_SIGNING_ORIGIN, or "signingOrigins" for tests. An
// https:// address of any website may be named; http:// only for
// localhost, which only a test has a reason to name.
export const SIGNING_ORIGIN = 'https://sign.prova.red';
/** A cancellation handed over may be dated at most this far ahead of this computer's clock. */
export const CANCELLATION_AHEAD_MS = 24 * 60 * 60 * 1000;
/** At most this many permissions from passkeys this computer does not trust wait for "admit-passkey", one for each passkey. */
export const MAX_WAITING_PERMISSIONS = 8;
/**
 * The allowance between clocks, as the format uses it elsewhere: 300
 * seconds. A permission handed over may start at most this far ahead of
 * this computer's clock (else "starts-later"), and must start at least this
 * long after every cancellation the recorder holds (else
 * "before-cancellation"). A permission does not say when it was signed; with
 * the two rules together, one signed before a cancellation, with a start
 * the application allows (no more than 300 seconds after the person pressed
 * Sign), starts before the cancellation's date and 300 seconds, so it is
 * refused, while one signed after it can start at that point.
 */
export const HAND_OVER_ALLOWANCE_MS = 300 * 1000;
/** An origin written as a browser writes it: https:// any website, or http://localhost, with nothing after the name and port. */
function originForm(o) {
  let u;
  try {
    u = new URL(o);
  } catch {
    return false;
  }
  if (u.origin !== o) return false;
  return u.protocol === 'https:' || (u.protocol === 'http:' && u.hostname === 'localhost');
}

/**
 * The signing addresses a record handed over is taken from: the setting, or
 * https://sign.prova.red. Several may be named, with commas between them.
 * @param {string|string[]|undefined} setting
 * @returns {string[]}
 */
export function signingOriginsFrom(setting) {
  if (setting === undefined || setting === null || setting === '') return [SIGNING_ORIGIN];
  const list = (Array.isArray(setting) ? setting : String(setting).split(',')).map((s) => String(s).trim()).filter(Boolean);
  if (list.length === 0) return [SIGNING_ORIGIN];
  for (const o of list) {
    if (!originForm(o)) throw new Error(`The signing address ${JSON.stringify(o)} (PROVARED_CLAUDE_CODE_SIGNING_ORIGIN) is not an address such as ${SIGNING_ORIGIN}: an https:// address with nothing after the name and port, or http://localhost for a test.`);
  }
  return [...new Set(list)];
}

/** What a cancellation says (its slip and date), read from its content; null where it cannot be read. */
function cancellationSays(record) {
  try {
    const c = JSON.parse(new TextDecoder().decode(fromBase64url(record.payload)));
    const when = Date.parse(c.when);
    return typeof c.slip === 'string' && Number.isFinite(when) ? { slip: c.slip, when } : null;
  } catch {
    return null;
  }
}

/** The latest date of a cancellation line in a book's text (-Infinity where it holds none). */
function latestCancellationIn(text) {
  let latest = -Infinity;
  const mark = '\n{"cancellation":';
  for (let at = text.indexOf(mark); at >= 0; at = text.indexOf(mark, at + 1)) {
    const end = text.indexOf('\n', at + 1);
    try {
      const says = cancellationSays(JSON.parse(text.slice(at + 1, end < 0 ? undefined : end)).cancellation);
      if (says && says.when > latest) latest = says.when;
    } catch {
      // Not a line that can be read: the checker reports it.
    }
  }
  return latest;
}

/**
 * The cancellations the recorder holds beside its book, which the book does
 * not hold yet (dated ahead of this computer's clock), as held-cancellations.json
 * keeps them, so that a restart does not lose them: each in the form a
 * checker takes ({cancellation, stamps?, acknowledgements?}). Empty where
 * there is no file. A file that cannot be read stops the recorder: a
 * cancellation lost would let the agent act again.
 */
export function readHeldCancellations(folder) {
  const path = files(folder).held;
  if (!existsSync(path)) return [];
  let held;
  try {
    held = JSON.parse(readFileSync(path, 'utf8').replace(/^﻿/, ''));
  } catch {
    held = undefined;
  }
  const list = held?.cancellations;
  if (!Array.isArray(list) || list.length > 16 || !list.every((c) => c && typeof c === 'object' && c.cancellation && typeof c.cancellation.payload === 'string')) {
    throw new Error(`${path} does not hold a list of cancellations as {"cancellations": [{"cancellation": …}]}, so the recorder does not start: a cancellation it held would be lost, and the agent would act again. Look at the file; move it out of the folder only if you know it holds no cancellation of yours.`);
  }
  return list;
}

function writeHeldCancellations(folder, list) {
  const path = files(folder).held;
  if (list.length === 0) {
    try {
      unlinkSync(path);
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
    return;
  }
  const about = 'The person\'s cancellations that this recorder holds beside its book, because each is dated ahead of this computer\'s clock: each is written into the book, with the agent\'s acknowledgement, once the clock reaches its date. Kept here so that a restart does not lose them. Do not edit.';
  replaceFile(path, JSON.stringify({ about, cancellations: list }, null, 2) + '\n', { temporary: `${path}.${process.pid}.tmp` });
}

/** The permissions handed over from a passkey this computer does not trust, newest first, for "admit-passkey". */
export function readWaitingPermissions(folder) {
  const path = files(folder).waiting;
  if (!existsSync(path)) return [];
  try {
    const held = JSON.parse(readFileSync(path, 'utf8').replace(/^﻿/, ''));
    return Array.isArray(held?.permissions) ? held.permissions.filter((p) => p && typeof p === 'object' && p.slip && typeof p.slip.payload === 'string').slice(0, MAX_WAITING_PERMISSIONS) : [];
  } catch {
    return [];
  }
}

function writeWaitingPermissions(folder, list) {
  const path = files(folder).waiting;
  if (list.length === 0) {
    try {
      unlinkSync(path);
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
    return;
  }
  const about = 'Permissions handed over from the application and refused, because a passkey this computer does not trust signed them. Each waits for "admit-passkey <thumbprint>", which shows it and takes it, with its passkey, only once the person confirms on this computer. Nothing here is trusted.';
  replaceFile(path, JSON.stringify({ about, permissions: list.slice(0, MAX_WAITING_PERMISSIONS) }, null, 2) + '\n', { temporary: `${path}.${process.pid}.tmp` });
}

/** The start a permission states, read from its content (not checked here), in milliseconds; NaN where it cannot be read. */
export function startOf(slip) {
  try {
    return Date.parse(JSON.parse(new TextDecoder().decode(fromBase64url(slip.payload))).validFrom);
  } catch {
    return NaN;
  }
}

/**
 * Keep a refused permission for "admit-passkey": at most one for each
 * passkey, the one that starts latest (so that whoever hands records over
 * cannot choose an older one of the person's to be shown), newest handed
 * over first, at most MAX_WAITING_PERMISSIONS. Gives back whether it is kept.
 */
function addWaitingPermission(folder, slip, fingerprintOf, thumbprintOf) {
  const list = readWaitingPermissions(folder).filter((p) => p.fingerprint !== fingerprintOf);
  const same = list.filter((p) => p.thumbprint === thumbprintOf);
  if (same.some((p) => startOf(p.slip) >= startOf(slip))) return false;
  writeWaitingPermissions(folder, [{ fingerprint: fingerprintOf, thumbprint: thumbprintOf, slip }, ...list.filter((p) => p.thumbprint !== thumbprintOf)]);
  return true;
}

// --- new books ---
//
// The format allows at most 100,000 entries in a book, and the check
// before acting refuses every call once a book is full. So at 90,000
// entries the recorder seals the book, keeps it as book-<n>.jsonl, and
// starts a new book.jsonl that begins with the permission in force. A
// book of 90,000 receipts (about 7 KB each, for the quantum-safe
// signature) would be longer than Node.js can hold as one text (about
// 537 million characters), so a new book is started at 100 MB of text
// (100,000,000 bytes) too, whichever comes first: under the 100 MB that
// GitHub takes as one file, and a fifth of what Node.js can hold.
//
// Every limit of a permission is enforced across the books: the recorder
// keeps, for each permission, the time and amount of every receipt in its
// kept books (the figures only, not their text), and the check before
// acting counts them with the book in force and the calls not yet
// recorded. A checker given one book still counts within that book only.
export const NEW_BOOK_ENTRIES = 90000;
export const NEW_BOOK_BYTES = 100000000;
// A call allowed and not yet recorded counts against the permission's
// limits on how many of its action may be taken, for 15 minutes at most:
// a call refused at the person's prompt after it was allowed never comes
// back for its stub, and must not hold the count for ever.
export const IN_FLIGHT_MS = 15 * 60 * 1000;
// A kept book is book-<n>.jsonl, <n> a whole number from 1 to 999,999,999 written with no leading
// zero. The record page (tools/make-record-page.mjs) reads kept books by the same rule, and the
// recorder keeps no book under a name this rule would not read: where the next number would pass
// the highest, it starts no new book and says why.
export const KEPT_BOOK = /^book-([1-9][0-9]{0,8})\.jsonl$/;
export const KEPT_BOOK_HIGHEST = 999999999;

const STUB_AT = '{"stub":{"payload":"';
/**
 * Read the whole lines of a book's text from "at" on: count them, and their
 * bytes, into "counts", and put the time and amount of each stub into
 * "times", by its slip and action. Gives back where it stopped.
 */
function readFigures(text, at, times, counts) {
  for (let end = text.indexOf('\n', at); end >= 0; end = text.indexOf('\n', at)) {
    counts.entries++;
    counts.bytes += Buffer.byteLength(text.slice(at, end + 1));
    // A stub of this recorder: its line starts with the stub, whose payload comes first.
    if (text.startsWith(STUB_AT, at)) {
      const from = at + STUB_AT.length;
      const to = text.indexOf('"', from);
      try {
        const c = JSON.parse(new TextDecoder().decode(fromBase64url(text.slice(from, to))));
        const when = Date.parse(c.when);
        if (typeof c.slip === 'string' && typeof c.action === 'string' && Number.isFinite(when)) {
          const key = `${c.slip}\n${c.action}`;
          if (!times.has(key)) times.set(key, []);
          times.get(key).push({ when, unit: c.amount?.unit, value: c.amount?.value });
        }
      } catch {
        // Not a stub that can be read: the checker reports it.
      }
    }
    at = end + 1;
  }
  return at;
}

/** The books kept in the folder, oldest first: {number, file, path}. */
export function keptBooks(folder) {
  let names = [];
  try { names = readdirSync(folder); } catch { /* no folder yet */ }
  return names.flatMap((file) => {
    const m = KEPT_BOOK.exec(file);
    return m ? [{ number: Number(m[1]), file, path: join(folder, file) }] : [];
  }).sort((a, b) => a.number - b.number);
}

/**
 * Which version of a kept book's file is on the disk: its size, its
 * modification and change times and its identity. What is worked out from
 * the file (its seals, its tree of line fingerprints) is kept only while
 * this stays the same. The change time is set by the file system at each
 * change and no program can set it back, as one can the modification time,
 * so a file changed in its middle, kept to the same size and given its old
 * modification time again, still reads as another version. One limit: on
 * this computer's file system (NTFS) the change time was seen not to move
 * for a second change made within a moment of the one before, so a change
 * made at once after the file was last written may not be seen; a kept
 * book is not written again once kept. What is at stake is only that wrong
 * proofs are sent: a witness checks every proof, and refuses a wrong one.
 * "gone" where the file cannot be read.
 */
export function fileVersion(path) {
  try {
    const st = statSync(path, { bigint: true });
    return `${st.size}:${st.mtimeNs}:${st.ctimeNs}:${st.dev}:${st.ino}`;
  } catch {
    return 'gone';
  }
}

// --- a seal's book number, the seal it names, and the disk ---

const SEAL_LINE = '\n{"seal":';
/** A book's first line, without its line break. */
const firstLineOf = (text) => {
  const end = text.indexOf('\n');
  return (end < 0 ? text : text.slice(0, end)).replace(/\r$/, '');
};

/**
 * The last seal on a line of a book's text that can be read: its
 * fingerprint, the number of the book it gives (1 where it gives none), and
 * the fingerprint of the key set that signed it. null where there is none.
 */
export async function lastSealOf(text) {
  let at = text.lastIndexOf(SEAL_LINE, Math.max(0, text.length - 2));
  while (at >= 0) {
    const end = text.indexOf('\n', at + 1);
    try {
      const record = JSON.parse(text.slice(at + 1, end < 0 ? undefined : end)).seal;
      const content = JSON.parse(new TextDecoder().decode(fromBase64url(record.payload)));
      if (content.type === 'provared.seal.v0') {
        return { fingerprint: await fingerprint(fromBase64url(record.payload)), number: Number.isInteger(content.book) ? content.book : 1, sealer: await keySetFingerprint(content.by.keys) };
      }
    } catch {
      // Not a seal that can be read: the one before it is looked at.
    }
    if (at === 0) break;
    at = text.lastIndexOf(SEAL_LINE, at - 1);
  }
  return null;
}

/**
 * Whom the permission on a book's first line names, as a witness knows a
 * sequence (with the recorder's keys): the thumbprint of its passkey and the
 * fingerprint of its agent's key set, as one text; null where the line is
 * not a permission.
 */
async function whoOfLine(line) {
  try {
    const about = await aboutSlip(JSON.parse(line).slip);
    return `${about.issuerKey} ${await keySetFingerprint(about.content.agent.keys)}`;
  } catch {
    return null;
  }
}

/** The line at a place in a text (counting from 0), without its line break, found without splitting the text; null where there is none. */
function lineAt(text, place) {
  let at = 0;
  for (let i = 0; i < place; i++) {
    at = text.indexOf('\n', at) + 1;
    if (at === 0) return null;
  }
  if (at >= text.length) return null;
  const end = text.indexOf('\n', at);
  return end < 0 ? null : text.slice(at, end);
}

/** Make sure what a file holds is on the disk (fsync). */
function syncFile(path) {
  const fd = untilFree(() => openSync(path, 'r+'));
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

// A seal whose line is not yet written, kept apart from the book, on the
// disk, while "seal" waits for the witnesses (sealIn): a witness may sign
// for it before its line is written, and a witness that holds a seal that
// is in no book signs for none after it.
export const PENDING_SEAL = 'pending-seal.json';

/**
 * At the start, before anything else is added to the book in force: the
 * seal a stop left kept apart is written at its place, where the book still
 * ends just before it and the seal covers exactly the entries before it.
 * Where its line is in the book already, the file is no longer needed.
 * Where neither, it cannot be written, and the file is kept under another
 * name for the person to look at.
 * @returns {Promise<{text: string, placed: string|null, problem: string|null}>} placed: the seal's payload, where it is
 *   in the text handed back and not yet known to be on the disk
 */
async function placePending(folder, text) {
  const path = join(folder, PENDING_SEAL);
  const aside = (why) => {
    const moved = join(folder, `pending-seal-not-placed-${Date.now()}.json`);
    try { untilFree(() => renameSync(path, moved)); } catch { /* left where it is */ }
    return { text, placed: null, problem: `A seal kept apart from the book while witnesses were asked (${PENDING_SEAL}) could not be written into it: ${why} It is kept as ${moved}. A witness that signed for it may refuse every later seal of this book; "status" says so for each witness.` };
  };
  let record;
  let content;
  try {
    const p = JSON.parse(readFileSync(path, 'utf8'));
    if (p.book !== 'book.jsonl') return aside('it names another book than book.jsonl.');
    record = p.seal;
    content = JSON.parse(new TextDecoder().decode(fromBase64url(record.payload)));
  } catch {
    return aside('it cannot be read.');
  }
  const lines = text.split('\n');
  if (lines.at(-1) === '') lines.pop();
  const size = content.size;
  const itsLine = (line) => typeof line === 'string' && line.startsWith(`{"seal":{"payload":"${record.payload}"`);
  if (Number.isInteger(size) && lines.length > size && itsLine(lines[size])) {
    // Its line is in the book: it was written before the stop.
    try { unlinkSync(path); } catch { /* removed after the next seal */ }
    return { text, placed: null, problem: null };
  }
  // Its line is in a book kept since: a new book began before the file could be let go.
  if (Number.isInteger(size)) {
    for (const k of keptBooks(folder).reverse()) {
      let kept;
      try { kept = readFileSync(k.path, 'utf8'); } catch { continue; }
      if (itsLine(lineAt(kept, size))) {
        try { unlinkSync(path); } catch { /* removed after the next seal */ }
        return { text, placed: null, problem: null };
      }
    }
  }
  if (!Number.isInteger(size) || lines.length !== size || size < 1) return aside(`it covers ${size} entries, and the book holds ${lines.length}.`);
  const leaves = lines.map(utf8);
  if (!(await verifyInclusion(0, size, leaves[0], await inclusionPath(leaves, 0), fromBase64url(content.root)))) return aside('it does not cover the entries the book holds.');
  return { text: `${text}${entryLine({ seal: record })}\n`, placed: record.payload, problem: null };
}

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
// writing can be handed in, for the tests. "temporary" names the temporary
// file, beside the file, for a writer that may write at the same moment as
// another program.
export function replaceFile(path, text, { write = writeFileSync, rename = renameSync, temporary = `${path}.tmp` } = {}) {
  try {
    untilFree(() => write(temporary, text));
    untilFree(() => rename(temporary, path));
  } catch (e) {
    try { unlinkSync(temporary); } catch { /* nothing to remove */ }
    throw e;
  }
}

// A book only grows, so the new lines are appended to the file: that
// works while another program (an uploader, a virus scanner) is reading
// it. Where the file does not match the book's start (it was edited by
// hand), the whole file is replaced. "path" names a book kept before
// (book-<n>.jsonl), which a call allowed under it may still add to.
//
// The file is replaced only where it was read and does not hold the book's
// start, or does not exist: never because it could not be read. A program
// that holds the file for a few seconds (a virus scanner, a backup tool)
// makes the reading, and the appending, wait for up to ten seconds, as a
// replacement does; past that, the save fails and the file is left as it
// is, and the next save tries again. (Before 18 October 2026 a failed read
// was taken as "no book yet", and the file was replaced: the book then had
// a new identity, and the application's uploader stopped.)
// The ways of reading and of adding to the file can be handed in, for the tests.
export function saveBook(folder, text, path = files(folder).book, { read = readFileSync, append = appendFileSync } = {}) {
  let existing = '';
  try {
    existing = untilFree(() => read(path, 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
  if (existing.length > 0 && text.startsWith(existing)) {
    if (text.length > existing.length) untilFree(() => append(path, text.slice(existing.length)));
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
 * @param {string} folder
 * @param {{path?: string, saved?: string, append?: Function}} [o] path: another book file (a kept book); saved: the
 *   text known to be in the file already, so that the first save need not read it; append: the way of
 *   adding to the file (for the tests)
 * @returns {(text: string) => void}
 */
export function bookSaver(folder, { path = files(folder).book, saved, append = appendFileSync } = {}) {
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
  if (typeof saved === 'string') remember(saved, Buffer.byteLength(saved));
  return (text) => {
    if (left && text.length >= left.chars && text.startsWith(left.tailText, left.chars - left.tailText.length) && asLeft()) {
      const more = text.slice(left.chars);
      if (more) untilFree(() => append(path, more));
      remember(text, left.bytes + Buffer.byteLength(more));
      return;
    }
    saveBook(folder, text, path, { append });
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
// Two lists of thumbprints in one file (trusted-passkeys.json). "passkeys"
// holds every passkey whose slips the recorder has taken: written at the
// first "use", added to only by "renew --new-passkey", never shortened,
// because the recorder opens its books (the one in force and those kept)
// with it, and a slip in a kept book stays trusted for what is recorded
// under it. "retired", a part of that list, holds the passkeys that may sign
// no new slip: "retire-passkey" adds one, "admit-passkey" takes it out. So a
// person who has made a new passkey (say, for a signing page served at a
// name of its own) can retire the old one: the record it signed stands,
// limits are still counted across the books it signed, and a new slip
// from it is refused, with or without --new-passkey. A file written before
// "retired" existed holds "passkeys" alone, and is read as retiring none.
// The recorder takes a slip only from a passkey on the first list and not
// on the second, and does not start if the book or slip.json holds a slip
// from a passkey not on the first. This raises the bar for a program that
// edits the folder: it does not close it, because any program on this
// computer, the agent included, can change this file too. The evidence
// that holds is a checker naming the person's own passkey.

/** Both lists as the file holds them, or null where the folder has none. */
function readTrustedFile(folder) {
  const path = files(folder).trusted;
  if (!existsSync(path)) return null;
  let held;
  try {
    held = JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
  } catch {
    held = undefined;
  }
  const thumbprints = (list) => Array.isArray(list) && list.every((k) => typeof k === 'string' && THUMBPRINT.test(k));
  const list = held?.passkeys;
  if (!thumbprints(list) || list.length === 0) {
    throw new Error(`${path} does not hold a list of passkey thumbprints as {"passkeys": ["…"]}, so the recorder trusts no passkey and does not start.`);
  }
  const passkeys = [...new Set(list)];
  const retired = held.retired === undefined ? [] : held.retired;
  if (!thumbprints(retired) || !retired.every((k) => passkeys.includes(k))) {
    throw new Error(`${path} holds "retired", which must be a list of thumbprints from its "passkeys", and is not, so the recorder does not start.`);
  }
  return { passkeys, retired: [...new Set(retired)] };
}

/** The passkeys whose slips are in the record, or null where the folder has none. */
export function readTrusted(folder) {
  return readTrustedFile(folder)?.passkeys ?? null;
}

/** The passkeys that may sign no new slip; empty where the folder has no list. */
export function readRetired(folder) {
  return readTrustedFile(folder)?.retired ?? [];
}

/**
 * Write the list of passkeys. Two commands may change it at the same
 * moment (say, "retire-passkey" while the running service takes a new
 * passkey with "renew --new-passkey"), so the file is read again just
 * before it is written, and the two are merged: "passkeys" is every
 * passkey there and every one given, never fewer, and "retired" is the
 * list there with the one change asked for. The file is written to a
 * temporary file of its own in the same folder and renamed into place,
 * each step tried again while Windows holds the file busy. A narrow window
 * remains between that reading and the renaming: no lock is held.
 * @param {string} folder
 * @param {string[]} [add] passkeys to have on the list
 * @param {{retire?: string, admit?: string}|null} [change] one passkey to retire, or to admit again
 * @param {{beforeRead?: () => void}} [o] for the tests: run just before the file is read again
 * @returns {{passkeys: string[], retired: string[]}} the lists written
 */
export function writeTrusted(folder, add = [], change = null, { beforeRead } = {}) {
  mkdirSync(folder, { recursive: true });
  beforeRead?.();
  const held = readTrustedFile(folder);
  const passkeys = [...new Set([...(held?.passkeys ?? []), ...add])];
  // A list with no passkey is one the recorder refuses to start with: write nothing.
  if (passkeys.length === 0) {
    throw new Error(`The list of passkeys (${files(folder).trusted}) would hold no passkey, so it was not written: the file was missing when it was read again, and no passkey was being added. Nothing was changed.`);
  }
  let retired = held?.retired ?? [];
  if (change?.retire) retired = [...new Set([...retired, change.retire])];
  if (change?.admit) retired = retired.filter((k) => k !== change.admit);
  retired = retired.filter((k) => passkeys.includes(k));
  const about = 'The thumbprints of the passkeys this recorder trusts ("passkeys": written by "use", added to by "renew --new-passkey" and "admit-passkey"), and among them those that may sign no new permission ("retired": written by "retire-passkey" and "admit-passkey").';
  const path = files(folder).trusted;
  const temporary = `${path}.${process.pid}.${nodeCrypto.randomBytes(6).toString('hex')}.tmp`;
  replaceFile(path, JSON.stringify({ about, passkeys, retired }, null, 2) + '\n', { temporary });
  return { passkeys, retired };
}

/**
 * Retire a passkey, or admit a retired one again (the commands
 * "retire-passkey" and "admit-passkey"). A retired passkey stays trusted
 * for the slips it signed already; a new slip from it is refused. Only a
 * passkey on the list can be retired or admitted here, so that the list
 * says which passkeys are in the record and nothing else. A passkey this
 * recorder has never trusted is taken only with a permission it signed, at
 * the person's word on this computer: "renew <file> --new-passkey", or
 * "admit-passkey" for a permission handed over and refused (admitWaiting).
 * @param {string} folder
 * @param {string} thumbprint
 * @param {boolean} retire true to retire, false to admit
 * @param {{beforeRead?: () => void}} [o] for the tests (see writeTrusted)
 * @returns {{passkeys: string[], retired: string[], changed: boolean}} the lists afterwards
 */
export function retirePasskey(folder, thumbprint, retire, { beforeRead } = {}) {
  if (typeof thumbprint !== 'string' || !THUMBPRINT.test(thumbprint)) throw new Error('A passkey is named by its thumbprint: 43 letters, digits, hyphens or underscores, with no spaces.');
  const held = readTrustedFile(folder);
  if (held === null) throw new Error(`The folder has no list of passkeys yet (${files(folder).trusted}): none has signed a permission for this recorder. The first "use" writes it.`);
  if (!held.passkeys.includes(thumbprint)) {
    throw new Error(`The passkey ${thumbprint} is not on the list of passkeys this recorder trusts (${held.passkeys.join(', ')}), so there is nothing to ${retire ? 'retire' : 'admit again'}. A new passkey is taken only with a permission it signed: "renew <file> --new-passkey", or "admit-passkey" for a permission handed over from the application and waiting here.`);
  }
  const already = held.retired.includes(thumbprint);
  if (retire === already) return { ...held, changed: false };
  // Written from the file as it is just before the writing, with this one change, so that a passkey added meanwhile stays.
  const lists = writeTrusted(folder, [], retire ? { retire: thumbprint } : { admit: thumbprint }, { beforeRead });
  return { ...lists, changed: true };
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
 * @param {{agentKeys: object[], previous?: {issuerKey: string}|null, trusted?: string[], retired?: string[], newPasskey?: boolean, now?: number, withoutMethods?: string[]}} o
 *   trusted: the thumbprints of the passkeys already trusted; by default the one that signed "previous".
 *   retired: those among them that may sign no new slip ("retire-passkey"); a slip from one is refused whatever "newPasskey" says.
 *   withoutMethods: signing methods to take as not built in, as the checker takes them (for tests)
 */
export async function checkNewSlip(slip, { agentKeys, previous = null, trusted = previous ? [previous.issuerKey] : [], retired = [], newPasskey = false, now = Date.now(), withoutMethods = [] }) {
  // Each refusal carries a code, which the application turns into its own words (handOver, in startService).
  const refuse = (code, words, more = {}) => Object.assign(new Error(words), { code, ...more });
  const check = await checkSlip(slip, { withoutMethods });
  if (check.problems.length > 0) {
    throw refuse('not-sound', `The permission does not pass its check, so it is not used: ${check.problems.map((p) => `[${p.code}] ${p.message}`).join(' ')}`);
  }
  if (check.signature.state !== 'valid') throw refuse('not-checked', `This device could not check the passkey's signature on the permission (${check.signature.method}), so it is not used.`);
  const { content } = check;
  if (JSON.stringify(content.agent.keys) !== JSON.stringify(agentKeys)) {
    throw refuse('other-agent', `The permission names other keys than the agent's keys in this folder, so it is not used. Sign one with the keys that "${RUN} keys" prints.`);
  }
  if (Date.parse(content.validUntil) <= now) throw refuse('ended', `The permission ended at ${content.validUntil}, so it is not used. Sign a new one.`);
  const warnings = [];
  if (Date.parse(content.validFrom) > now) warnings.push(`The permission is in force only from ${content.validFrom}: until then every tool call is refused.`);
  // A passkey that signed no permission before is refused, so that no
  // program on this computer, the agent included, can bring in a permission
  // of its own making. The person's own new passkey is taken at their word.
  // A retired passkey signed slips that stand in the record, and may sign
  // no new one: the person said so with "retire-passkey", and only
  // "admit-passkey" takes it back. --new-passkey does not: it is for a
  // passkey the recorder has never seen.
  if (retired.includes(check.issuerKey)) {
    throw refuse('passkey-retired', `This permission is signed by a passkey (${check.issuerKey}) that was retired with "${RUN} retire-passkey", so it is not used, with or without --new-passkey. The permissions it signed before stand in the record. If the passkey is yours and you mean to sign with it again, run "${RUN} admit-passkey ${check.issuerKey}" first.`, { thumbprint: check.issuerKey });
  }
  if (trusted.length > 0 && !trusted.includes(check.issuerKey)) {
    if (!newPasskey) {
      throw refuse('passkey-not-trusted', `This permission is signed by a passkey (${check.issuerKey}) that signed none of the permissions before it (${trusted.join(', ')}) and that this recorder does not trust, so it is not used. If you made a new passkey yourself, run the command again with --new-passkey. For a permission handed over from the application, run "${RUN} admit-passkey ${check.issuerKey}" on this computer: it shows the permission and takes it, with its passkey, only once you confirm.`, { thumbprint: check.issuerKey });
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

// The fingerprint of the last permission line in a book: the permission in
// force when the book was kept (a renewal adds the new permission's line).
// Null where the book has none, or its last permission line cannot be read.
async function lastSlipIn(text) {
  const lines = text.split('\n');
  for (let i = lines.length - 1; i >= 0; i--) {
    if (!lines[i].startsWith('{"slip":')) continue;
    try {
      return await fingerprint(fromBase64url(JSON.parse(lines[i]).slip.payload));
    } catch {
      return null;
    }
  }
  return null;
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
 * checked and taken into the book first. Where the folder has no book.jsonl,
 * a new book begins with that slip: the first book, or the rest of a new
 * book that a switch had begun when the recorder stopped.
 * @param {{folder?: string, port?: number, name?: string, newBookAt?: {entries?: number, bytes?: number}, inFlightMs?: number, faults?: (step: string) => void, clock?: () => number, witnessWaitMs?: number, witnessRetryMs?: number}} o
 *   port 0 takes any free port; newBookAt and inFlightMs are for tests (90,000 entries, 100,000,000 bytes and
 *   15 minutes by default); faults is called at each step of a new book ("sealed", "kept", "written"), and of a
 *   seal kept apart while witnesses are asked ("pending", "statements"), for tests; clock gives the time the
 *   waiting calls and the retry of a new book are measured by (Date.now), for tests; witnessWaitMs is how long
 *   "seal" waits for the witnesses (5 seconds), witnessRetryMs how often a witness that is behind is asked again
 *   (a minute); signingOrigins are the addresses a record handed over may have been signed at
 *   (signingOriginsFrom: PROVARED_CLAUDE_CODE_SIGNING_ORIGIN, or https://sign.prova.red); handOverReadMs is how long
 *   the feed waits for the body of a record handed over (10 seconds), for tests
 * @returns {Promise<{port: number, close: () => Promise<void>, recorder: object, seal: () => Promise<object>, renew: (slip: object, o?: {newPasskey?: boolean}) => Promise<object>, newBook: () => Promise<object>, witnesses: () => Promise<object>}>}
 */
export async function startService({ folder = DEFAULT_FOLDER, port = DEFAULT_PORT, name = 'The recorder beside the coding agent', newBookAt = {}, inFlightMs = IN_FLIGHT_MS, faults = () => {}, clock = Date.now, witnessWaitMs = WITNESS_WAIT_MS, witnessRetryMs = WITNESS_RETRY_MS, signingOrigins = process.env.PROVARED_CLAUDE_CODE_SIGNING_ORIGIN, handOverReadMs } = {}) {
  const f = files(folder);
  const signedAt = signingOriginsFrom(signingOrigins);
  if (!existsSync(f.slip)) throw new Error(`There is no signed slip at ${f.slip}. Sign one on the signing page and put it in place: ${RUN} use <the saved file>`);
  const placed = await loadSlip(folder);
  const agent = await loadAgentKeys(folder);
  const sealer = await makeRecorderKeys(folder);
  if (JSON.stringify(placed.content.agent.keys) !== JSON.stringify(agent.keys)) {
    throw new Error('The slip names other keys than the agent\'s keys in this folder. Sign a slip with the keys that "keys" prints.');
  }
  const newAt = { entries: newBookAt.entries ?? NEW_BOOK_ENTRIES, bytes: newBookAt.bytes ?? NEW_BOOK_BYTES };
  const sealKeys = [await keySetFingerprint(sealer.keys)];
  const options = { sealKeys };
  // Each writer opened reads the whole book once; "readings" counts them.
  let readings = 0;
  // "held": the person's cancellations held beside the book (held-cancellations.json), given to the writer.
  const open = (book, slipFingerprint, issuerKeys, held = []) => {
    readings++;
    return openRecorder({ book, slip: slipFingerprint, privateKeys: agent.privateKeys, issuerKeys, options: held.length ? { ...options, cancellations: held } : options });
  };
  // The cancellations held beside the book when the recorder stopped: given to the writer of the book in force.
  const heldAtStart = readHeldCancellations(folder);

  // A book the service writes to: the one in force, at book.jsonl, and,
  // after a new book was started, the one kept before it, while a call
  // allowed under it may still come back for its stub. Each holds its
  // writer, the slip that writer acts under, the writers of the slips
  // before it that a call may still come back to ("before"), and what the
  // service has read of its lines: how many entries it holds, its size in
  // bytes, and the time and amount of each stub by its slip and action
  // ("times"). A kept book's figures go into the figures of all the kept
  // books ("keptFigures"), which every limit is counted with.
  let bookIds = 0;
  const keptFigures = new Map();
  // The feed (feed.mjs): the books' lines for a reader on this computer,
  // such as the application's uploader, so that no other program need open
  // a book file. The books it reads from memory are the one in force and
  // the kept ones a call may still come back to, each only as far as it has
  // been written to its file ("written", set by each save that succeeds), so
  // that no line whose save failed reaches a reader; every save of a book
  // answers the readers that wait.
  const feed = createFeed({
    folder,
    token: feedToken(folder),
    // A record handed over (POST /hand-over) is taken in its turn, between two calls.
    handOver: (given) => inTurn(() => handOver(given)),
    ...(handOverReadMs === undefined ? {} : { handOverReadMs }),
    memory: () => [current, ...keptOpen.values()].map((b) => ({ key: b.id, path: b.path, text: () => b.writer.book(), saved: () => b.written ?? 0, inForce: b === current })),
  });
  const watched = (b, save) => (text) => {
    try {
      save(text);
      b.written = text.length;
    } finally {
      feed.changed();
    }
  };
  // "synced": how much of the book's text (in characters) is made sure to be on the disk; a witness is asked only
  // about seals within it. "keptNumber": the number of book-<n>.jsonl, once the book is kept; null for the book in force.
  const bookAt = (path, writer, about, saved) => {
    const b = { id: ++bookIds, path, writer, written: typeof saved === 'string' ? saved.length : 0, synced: 0, keptNumber: null, slip: about.slip, fingerprint: about.fingerprint, issuerKey: about.issuerKey, content: about.content, before: new Map(), seen: 0, entries: 0, bytes: 0, times: new Map() };
    b.save = watched(b, bookSaver(folder, { path, saved }));
    follow(b);
    return b;
  };
  // Read the lines a book gained since it was last read, once each.
  function follow(b) {
    const text = b.writer.book();
    if (text.length < b.seen) Object.assign(b, { seen: 0, entries: 0, bytes: 0, times: new Map() });
    b.seen = readFigures(text, b.seen, b.times, b);
  }
  const endsWithSeal = (b) => {
    const text = b.writer.book();
    return text.startsWith('{"seal":', text.lastIndexOf('\n', text.length - 2) + 1);
  };

  let text = existsSync(f.book) ? readFileSync(f.book, 'utf8') : '';
  if (text !== '' && !text.endsWith('\n')) text += '\n';
  // A seal that a stop left kept apart from the book while witnesses were
  // asked for it: written at its place first, before anything else is added
  // to the book, so that a witness that signed for it finds it there.
  let pendingProblem = null;
  let pendingLine = null;
  // Whether the line of the seal kept apart is known to be on the disk, while the file is not yet let go.
  let pendingOnDisk = false;
  if (existsSync(join(folder, PENDING_SEAL))) {
    const done = await placePending(folder, text);
    text = done.text;
    pendingProblem = done.problem;
    if (done.placed) pendingLine = `${SEAL_LINE}{"payload":"${done.placed}"`;
  }
  // The passkeys trusted: the folder's list (trusted-passkeys.json). The
  // recorder does not start if the book or slip.json holds a slip from a
  // passkey not on it.
  let trusted = await trustFor(folder, text, placed);
  const taken = text === '' || !(await slipsIn(text)).has(placed.fingerprint);
  const kept = keptBooks(folder);
  if (!taken && (await lastSlipIn(text)) !== placed.fingerprint) {
    // A slip the book holds, but not as its last permission line: one that
    // was in force once and was replaced since (slip.json put back by hand,
    // perhaps from its kept copy slip-<fingerprint>.json). Only the last
    // permission line of the book is the one in force, and only that one is
    // taken without the checks; any other goes through the same checks as a
    // renewal, a retired passkey's among them, and no line is added.
    await checkNewSlip(placed.slip, { agentKeys: agent.keys, trusted, retired: readRetired(folder) });
  }
  if (taken) {
    // A new book, or a slip put in place while the service was not running:
    // taken in after the same checks as a renewal. Where the folder has no
    // book and this slip is the last permission in the last kept book (the
    // one in force when that book was kept), a new book that a switch had
    // begun is completed: the slip was taken in after those checks, and is
    // not checked again, so that a permission that has ended since does not
    // keep the recorder from starting (it then refuses every call, and
    // "status" and "seal" still work). Any other slip, even one that the
    // kept book holds further up, goes through the checks, a retired
    // passkey's among them.
    const completing = text === '' && kept.length > 0 && (await lastSlipIn(readFileSync(kept.at(-1).path, 'utf8'))) === placed.fingerprint;
    if (!completing) await checkNewSlip(placed.slip, { agentKeys: agent.keys, trusted, retired: readRetired(folder) });
    text += entryLine({ slip: placed.slip }) + '\n';
  }
  /** The book in force, at book.jsonl. */
  let opened;
  try {
    opened = await open(text, placed.fingerprint, trusted, heldAtStart);
  } catch (e) {
    // The book opens without the held cancellations: one of them is what stopped it.
    if (heldAtStart.length > 0 && (await open(text, placed.fingerprint, trusted).then(() => true, () => false))) {
      throw new Error(`${f.held} holds a cancellation the recorder cannot take (${e.message}), so the recorder does not start: a cancellation it held would be lost, and the agent would act again. Look at the file. If it holds only cancellations you did not sign, or ones of a permission that has ended, move it out of the folder and start the recorder again; if it also holds one you signed, take out only the others, so that yours stays held; and if you signed the one that cannot be taken, keep your own copy, which a checker is handed beside the book.`);
    }
    throw e;
  }
  let current = bookAt(f.book, opened, placed);
  // Every permission this recorder has held, in the book in force and the books kept: a renewal handed over is
  // never one of these but the permission in force (a record held back and handed over again is not taken).
  const everSlips = await slipsIn(text);
  // The latest date of a cancellation in the books kept (read below, and as each book is kept).
  let keptCancelled = -Infinity;
  // Whether held-cancellations.json may hold anything: then, after each request, it is brought up to date.
  let heldOnDisk = heldAtStart.length > 0;
  current.save(current.writer.book());
  syncBook(current);
  const started = new Date().toISOString();
  let count = 0;

  // Make sure a book's file is on the disk (fsync), as far as it was
  // written: a witness is asked only about seals within it. Once the line of
  // the seal kept apart is on the disk, that seal is no longer kept apart.
  function syncBook(b) {
    try {
      faults('sync');
      syncFile(b.path);
    } catch {
      return false;
    }
    b.synced = b.written ?? 0;
    if (pendingLine !== null && !pendingOnDisk) {
      const at = b.writer.book().indexOf(pendingLine);
      if (at >= 0 && at + pendingLine.length <= b.synced) pendingOnDisk = true;
    }
    // Once its line is on the disk (in this book, or in one kept since), the file is let go; where that fails, it
    // is tried again at the next save, whichever book that is of.
    if (pendingOnDisk) {
      try {
        unlinkSync(join(folder, PENDING_SEAL));
        pendingLine = null;
        pendingOnDisk = false;
      } catch (e) {
        if (e.code === 'ENOENT') {
          pendingLine = null;
          pendingOnDisk = false;
        }
      }
    }
    return true;
  }

  // One request at a time, so that a renewal or a new book never falls
  // between a call and its stub, and the writer is switched between two
  // requests. "queued" counts the requests waiting their turn: "seal" waits
  // for the witnesses only while none does.
  let turn = Promise.resolve();
  let queued = 0;
  const queueWatchers = new Set();
  const inTurn = (work) => {
    queued++;
    for (const wake of [...queueWatchers]) wake();
    const run = turn.then(async () => {
      queued--;
      try {
        return await work();
      } finally {
        // A cancellation held beside the book may have been written into it by this request.
        if (heldOnDisk) await settleHeld().catch(() => {});
      }
    });
    turn = run.catch(() => {});
    return run;
  };
  // Wait for "settled", for at most "ms", and no longer than until another request waits its turn.
  async function briefly(settled, ms) {
    let timer;
    let wake;
    const another = new Promise((r) => { wake = r; });
    queueWatchers.add(wake);
    if (queued > 0) wake();
    try {
      await Promise.race([settled, another, new Promise((r) => { timer = setTimeout(r, ms); })]);
    } finally {
      clearTimeout(timer);
      queueWatchers.delete(wake);
    }
  }
  const entries = () => {
    follow(current);
    return current.entries;
  };

  // The calls allowed and not yet recorded, by Claude Code's identifier of
  // the call (tool_use_id, which the hook hands over before and after the
  // call): the book and the slip each was allowed under, its action, and
  // when. A call allowed under one slip and taken while a renewal switched
  // to the next is recorded under the one it was allowed under, however
  // long it ran. A call allowed under one book and taken after a new book
  // began is recorded in that book, for 15 minutes (IN_FLIGHT_MS); after
  // that the kept book is sealed, and the stub goes into the book in force,
  // under its slip where that book holds it, or else under the slip in force.
  // These calls are held in memory only: a restart forgets them.
  // Each call counts against the permission's limits on how many of its
  // action may be taken until its stub is written, or for 15 minutes at
  // most: a call refused after it was allowed (at the person's prompt)
  // never comes back for its stub. At most 1,000 are kept, the oldest
  // giving way (as before).
  const inFlight = new Map();
  const KEPT_CALLS = 1000;
  const callId = (given) => (typeof given.toolUseId === 'string' && given.toolUseId.length > 0 && given.toolUseId.length <= 200 ? given.toolUseId : null);
  const counting = (c, now = clock()) => now - c.at < inFlightMs;
  // A call allowed under this book (and slip) that may still come back: for the writers kept for the slips before.
  const pending = (bookId, slip) => [...inFlight.values()].some((c) => c.book === bookId && (slip === undefined || c.slip === slip));
  // One that still counts: for a kept book, held open while one does.
  const holding = (bookId) => [...inFlight.values()].some((c) => c.book === bookId && counting(c));
  // The books kept at a switch while a call allowed under them may still come back.
  const keptOpen = new Map();
  let bookProblem = null;

  // The witnesses named in witnesses.json (witnessed.mjs): they are shown the
  // books, oldest first, the one in force last; a book the recorder holds is
  // read from its own copy, as far as it is on the disk, and a kept book it
  // no longer writes from its file.
  const memoryBook = (b) => ({ key: `memory:${b.id}`, kind: 'memory', text: () => b.writer.book(), firstLine: () => firstLineOf(b.writer.book()), durable: () => b.synced ?? 0, version: () => b.writer.book().length });
  const fileBook = (k) => ({
    key: `file:${k.path}`,
    kind: 'file',
    text: () => readFileSync(k.path, 'utf8'),
    firstLine: () => { try { return firstLineOfFile(k.path); } catch { return null; } },
    durable: () => Infinity,
    version: () => fileVersion(k.path),
  });
  const witnessing = createWitnessing({
    folder,
    recorder: { keys: sealer.keys, fingerprint: sealKeys[0] },
    retryMs: witnessRetryMs,
    books: () => [
      ...keptBooks(folder).map((k) => {
        const open = [...keptOpen.values()].find((o) => o.path === k.path);
        return open ? memoryBook(open) : fileBook(k);
      }),
      memoryBook(current),
    ],
  });
  // A kept book that no counting call can come back to any more is sealed,
  // if anything came after its seal.
  async function tidy() {
    for (const [id, b] of keptOpen) {
      if (holding(id)) continue;
      keptOpen.delete(id);
      try {
        if (!endsWithSeal(b)) await sealIn(b);
      } catch (e) {
        bookProblem = `The book kept as ${b.path} could not be sealed after the last call allowed under it: ${e.message}`;
      }
    }
  }

  // A call is allowed only while, for each limit of the permission on its
  // action (a total, a count, either within a period), the stubs under the
  // permission in the books kept before this one, the stubs in this book,
  // the calls of that action allowed and not yet recorded (in any book), and
  // this one fit, as the Hermes plugin does for the calls not yet recorded.
  // The check before acting of the book in force counts that book's stubs
  // alone. A limit on the largest single action needs nothing across books.
  const periodWords = (seconds) => {
    if (seconds === null) return 'in all';
    for (const [size, word] of [[86400, 'day'], [3600, 'hour'], [60, 'minute']]) {
      if (seconds % size === 0) return seconds === size ? `in any ${word}` : `in any ${seconds / size} ${word}s`;
    }
    return `in any ${seconds} seconds`;
  };
  function limitRefusal(request) {
    const { action, amount } = request;
    const now = clock();
    const key = `${current.fingerprint}\n${action}`;
    const kept = keptFigures.get(key) ?? [];
    const waiting = [...inFlight.values()].filter((c) => c.slip === current.fingerprint && c.action === action && counting(c, now));
    if (kept.length === 0 && waiting.length === 0) return null;
    follow(current);
    const here = current.times.get(key) ?? [];
    for (const limit of Array.isArray(current.content.limits) ? current.content.limits : []) {
      if (!limit || limit.action !== action) continue;
      const per = Number.isInteger(limit.per) ? limit.per : null;
      // Stubs dated later than now are counted too, as the check before acting counts them
      // (while one is, the check before acting refuses every call in any case: time-went-backwards).
      const inPeriod = (x) => per === null || x.when > now - per * 1000;
      let used;
      let total;
      let allowed;
      let unit = '';
      if (Number.isInteger(limit.count)) {
        used = [kept.filter(inPeriod).length, here.filter(inPeriod).length, waiting.length];
        total = used[0] + used[1] + used[2] + 1;
        allowed = limit.count;
      } else if (Number.isInteger(limit.max)) {
        // An action with no amount, or one in another unit, is refused by the check before acting.
        if (!amount || amount.unit !== limit.unit || !Number.isInteger(amount.value)) continue;
        const sum = (xs) => xs.reduce((s, x) => s + (x.unit === limit.unit && Number.isInteger(x.value) ? x.value : 0), 0);
        used = [sum(kept.filter(inPeriod)), sum(here.filter(inPeriod)), sum(waiting)];
        total = used[0] + used[1] + used[2] + amount.value;
        allowed = limit.max;
        unit = ` ${limit.unit}`;
      } else continue;
      if (total <= allowed) continue;
      const code = per !== null ? 'over-period-limit' : Number.isInteger(limit.count) ? 'over-count-limit' : 'over-limit';
      const running = waiting.length;
      const message = used[0] === 0
        ? `${running === 1 ? 'A call' : `${running} calls`} of this action (${action}) allowed and not yet recorded would use the rest of what the permission allows (${allowed}${unit} ${periodWords(per)}), so this one is not taken now. Make it again once ${running === 1 ? 'it has' : 'they have'} ended.`
        : `With this action (${action}), the receipts under this permission in the books kept before this one (${used[0]}${unit}), in this book (${used[1]}${unit}) and the calls allowed and not yet recorded (${used[2]}${unit}) would come to ${total}${unit}, where the permission allows ${allowed}${unit} ${periodWords(per)}, so this one is not taken. A new book starts no limit again.`;
      return { allowed: false, problems: [], breaches: [{ code, message }], needs: [] };
    }
    return null;
  }

  // Bring a writer up to a book that holds its own book and more lines after
  // it: each line is taken with "add", at the cost of one line's check, not
  // a reading of the whole book.
  async function catchUp(writer, book) {
    const have = writer.book();
    if (!book.startsWith(have)) throw new Error('The two books differ.');
    for (const line of book.slice(have.length).split('\n').filter(Boolean)) await writer.add(JSON.parse(line));
    if (writer.book() !== book) throw new Error('The two books differ.');
  }

  // Write a stub in book "b", under the slip the call was allowed under.
  async function recordUnder(b, under, request, more) {
    if (under === undefined || under === b.fingerprint) return b.writer.record(request, more);
    // Under the slip before: the writer kept for it at the switch, brought
    // up to the book as it stands, writes the stub, and the writer for the
    // slip in force takes that one line. Where no such writer is kept (it
    // could not be brought up to date), one is opened: one reading of the
    // book.
    const book = b.writer.book();
    let before = b.before.get(under);
    if (before) {
      try {
        await catchUp(before, book);
      } catch {
        before = undefined;
      }
    }
    if (!before) {
      if (!(await slipsIn(book)).has(under)) return b.writer.record(request, more);
      before = await open(book, under, trusted);
      b.before.set(under, before);
    }
    const stub = await before.record(request, more);
    try {
      await catchUp(b.writer, before.book());
    } catch {
      b.writer = await open(before.book(), b.fingerprint, trusted);
    }
    if (!pending(b.id, under)) b.before.delete(under);
    return stub;
  }

  async function record(given) {
    await tidy();
    const id = callId(given);
    const call = id ? inFlight.get(id) : undefined;
    if (id) inFlight.delete(id);
    const more = given.when ? { when: given.when } : {};
    const request = requestFrom(given);
    // Allowed under a book kept since: the stub goes into that book, and
    // the book is sealed once no call allowed under it can come back.
    const kept = call ? keptOpen.get(call.book) : undefined;
    if (kept) {
      const stub = await recordUnder(kept, call.slip, request, more);
      savedOrHeld(kept);
      follow(kept);
      await tidy();
      return stub;
    }
    const stub = await recordUnder(current, call?.slip, request, more);
    savedOrHeld(current);
    return stub;
  }
  // The stub is signed and in the recorder's own copy of the book. Where the
  // file cannot be written now (another program holds it for longer than the
  // recorder waits), the hook is told just that: the recorder writes it with
  // the next save of that book, and it is lost only if the recorder stops
  // before then. The feed gives it to no reader before it is in the file.
  function savedOrHeld(b) {
    try {
      b.save(b.writer.book());
      // A seal whose line could not be saved when it was made is on the disk once this save has written it.
      if (pendingLine !== null && b.path === f.book) syncBook(b);
    } catch (e) {
      throw Object.assign(new Error(`the stub is signed and held by the recorder, but could not be written to its book file yet (${e.message}); the recorder writes it with the next save, and it is lost if the recorder stops before then`), { code: 'held-not-saved' });
    }
  }

  // What a new book's first seal needs of each kept book (section 21.6):
  // the passkey of the permission on its first line, and its last seal. Read
  // from the file once, and again when the file has changed; read from the
  // recorder's own copy for a kept book a call may still come back to.
  const keptFacts = new Map();
  async function factsOf(k) {
    const open = [...keptOpen.values()].find((o) => o.path === k.path);
    if (open) {
      const kept = open.writer.book();
      return { who: await whoOfLine(firstLineOf(kept)), last: await lastSealOf(kept) };
    }
    let size;
    try {
      size = statSync(k.path).size;
    } catch {
      return null;
    }
    const known = keptFacts.get(k.path);
    if (known && known.size === size) return known;
    let kept;
    try {
      kept = untilFree(() => readFileSync(k.path, 'utf8'));
    } catch {
      return null;
    }
    const facts = { size, who: await whoOfLine(firstLineOf(kept)), last: await lastSealOf(kept) };
    keptFacts.set(k.path, facts);
    return facts;
  }

  // The number of the book a seal is of, and the seal it names before it
  // (format description, section 21.6). A book that holds a seal goes on as
  // its first seal says, naming its last seal. One that holds none follows
  // the latest book kept before it whose first line is a permission from the
  // same passkey for the same agent, sealed with this recorder's keys: it is
  // that book's number and one, and names that book's last seal. Where there
  // is none, it is the first book of that passkey and agent: it gives no
  // number, and names no seal. So the books of one person and agent are one
  // sequence, as a witness knows them (the recorder's keys, the passkey and
  // the agent's keys), and a book from another passkey, or for another agent,
  // begins a sequence of its own. The book a
  // recorder kept as book-<n>.jsonl keeps that name: the file's number is the
  // order kept, and the seal's number is the book's place in its sequence.
  async function linkFor(b, seals) {
    if (seals.length > 0) return { previous: seals.at(-1).fingerprint, book: Number.isInteger(seals[0].content.book) ? seals[0].content.book : undefined };
    const who = await whoOfLine(firstLineOf(b.writer.book()));
    if (who === null) return {};
    for (const k of keptBooks(folder).reverse()) {
      if (b.keptNumber !== null && b.keptNumber !== undefined && k.number >= b.keptNumber) continue;
      const facts = await factsOf(k);
      // A kept book that cannot be read (held by another program for longer than the recorder waits): the seal
      // is not made, rather than given a number that may be wrong; it is tried again at the next seal.
      if (facts === null) throw new Error(`The kept book ${k.path} could not be read, so the number of the book in force, and the seal it follows, are not known: no seal was made. Try again in a moment.`);
      if (facts.who === who && facts.last && facts.last.sealer === sealKeys[0]) return { previous: facts.last.fingerprint, book: facts.last.number + 1 };
    }
    return {};
  }

  // Seal a book. With "inTime" (the seal asked for by "seal"), and where a
  // witness is named and the book passes its check as it stands, the
  // witnesses are asked before the seal's line is written, and the
  // statements that come in time stand beside the seal on its line. The
  // seal's entry is first kept on the disk apart from the book, so that a
  // witness never signs for a seal that a stop could leave out of the book.
  // The wait is at most witnessWaitMs, and ends as soon as another request
  // waits its turn: a tool call never waits for a witness. Every seal's line
  // is made sure to be on the disk, and then each witness is asked about the
  // seals it has not signed for (in the background).
  async function sealIn(b, { inTime = false } = {}) {
    // The seal before, from the writer's own answer for its book: nothing is read again.
    const result = await b.writer.check();
    const seals = result.entries.filter((e) => e.kind === 'seal' && e.problems.length === 0);
    // Before the first seal of the book in force, every book kept before it
    // that a call allowed under it could still come back to is closed, and
    // sealed if anything came after its seal: the seal this one names is
    // then the last of its book, and no seal is added to that book after it.
    // A call that comes back for such a book later is recorded in the book in
    // force, as after 15 minutes.
    if (b === current && seals.length === 0 && keptOpen.size > 0) {
      for (const [id, k] of [...keptOpen]) {
        keptOpen.delete(id);
        if (!endsWithSeal(k)) await sealIn(k);
      }
    }
    const link = await linkFor(b, seals);
    const book = b.writer.book();
    const sealed = await writeSeal(book, { by: { keys: sealer.keys, name }, previous: link.previous, book: link.book, when: Date.now() }, sealer.privateKeys);
    // No outside time-stamp is put beside the seal here (a seal without one has no "stamps" member).
    let entry = { seal: sealed.record };
    let arrived = [];
    let asked = null;
    const sound = result.problems.length === 0 && result.entries.every((e) => e.problems.length === 0);
    try {
      if (inTime && b === current && sound && pendingLine === null && witnessing.configured()) {
        replaceDurably(join(folder, PENDING_SEAL), `${JSON.stringify({ about: 'A seal whose line was not yet written while witnesses were asked for it. The recorder writes it into book.jsonl, at its place, when it next starts.', book: 'book.jsonl', seal: sealed.record })}\n`);
        pendingLine = `${SEAL_LINE}{"payload":"${sealed.record.payload}"`;
        faults('pending');
        asked = await witnessing.inTime({ key: memoryBook(b).key, record: sealed.record, fingerprint: sealed.fingerprint, content: JSON.parse(new TextDecoder().decode(fromBase64url(sealed.record.payload))), text: book, first: firstLineOf(book) });
        await briefly(asked.settled, witnessWaitMs);
        arrived = asked.take();
        faults('statements');
        if (arrived.length > 0) entry = { seal: sealed.record, witnesses: arrived.map((a) => a.statement) };
      }
      try {
        await b.writer.add(entry);
      } catch (e) {
        if (!entry.witnesses) throw e;
        // Each statement passed the library's check for this seal, so this
        // is not expected: the seal goes in by itself, and the statements
        // are kept beside the book.
        for (const a of arrived) await keepStatement(folder, sealed.fingerprint, sealed.record, a.statement);
        arrived = [];
        entry = { seal: sealed.record };
        await b.writer.add(entry);
      }
      b.save(b.writer.book());
      syncBook(b);
    } finally {
      asked?.done();
    }
    follow(b);
    if (b !== current) keptFacts.delete(b.path);
    witnessing.trigger();
    return { fingerprint: sealed.fingerprint, entries: b.entries, ...(link.book ? { book: link.book } : {}), witnessed: arrived.map((a) => a.key) };
  }
  const seal = () => sealIn(current, { inTime: true });

  // A new book: seal the book in force (unless it ends with a seal), keep
  // it as book-<n>.jsonl, and start book.jsonl again with the permission in
  // force. The file steps, in order, each one whole: the seal is added to
  // book.jsonl; book.jsonl is renamed book-<n>.jsonl; the new book.jsonl is
  // written. A stop between the first two leaves the book as it was, with a
  // seal, and the next start makes the new book as it would have; a stop
  // between the last two leaves no book.jsonl, and the next start begins
  // one with the permission in force (slip.json), which completes the
  // switch. The service acts under the new book only once the old one is
  // kept; a call allowed under the old one is still recorded in it.
  async function newBook() {
    const old = current;
    // A new book begins with the permission in force alone: one that is
    // cancelled would act again there. No call is taken under it, so the
    // book does not grow; renewing it starts new books again.
    if (await cancelledInForce()) {
      throw Object.assign(new Error('The permission in force is cancelled, so no new book is started: the new book would begin with that permission and not its cancellation. No call is taken under it, so the book does not grow. A new permission (renew) starts new books again.'), { code: 'cancelled' });
    }
    // A cancellation held beside the book (dated ahead of the clock) goes into this book first.
    if (heldNow().length > 0) {
      throw Object.assign(new Error('A cancellation is held beside the book until this computer\'s clock reaches its date, so no new book is started yet: it goes into this book first.'), { code: 'cancellation-held' });
    }
    // Before anything is changed: a kept book must be numbered by a name the rule reads again.
    const highest = keptBooks(folder).at(-1)?.number ?? 0;
    if (highest >= KEPT_BOOK_HIGHEST) {
      throw new Error(`The folder holds book-${highest}.jsonl, the highest number a kept book may have, so no new book is started: a book kept after it could not be found again. If the recorder did not keep that file, move it out of the folder.`);
    }
    if (!endsWithSeal(old)) await sealIn(old);
    faults('sealed');
    const writer = await open(entryLine({ slip: old.slip }) + '\n', old.fingerprint, trusted);
    // The file must hold the old book exactly before it is kept, and be on
    // the disk: the new book's first seal will name its last seal.
    old.save(old.writer.book());
    if (!syncBook(old)) throw new Error(`The book ${f.book} could not be made sure to be on the disk, so it is not kept yet: the next book's first seal will name its last seal, and a witness may be asked about it.`);
    const number = (keptBooks(folder).at(-1)?.number ?? 0) + 1;
    if (number > KEPT_BOOK_HIGHEST) throw new Error(`A kept book would be numbered ${number}, past the highest a kept book may have (${KEPT_BOOK_HIGHEST}), so no new book is started.`);
    const keptPath = join(folder, `book-${number}.jsonl`);
    untilFree(() => renameSync(f.book, keptPath));
    keptCancelled = Math.max(keptCancelled, latestCancellationIn(old.writer.book()));
    faults('kept');
    follow(old);
    for (const [key, list] of old.times) {
      if (!keptFigures.has(key)) keptFigures.set(key, []);
      keptFigures.get(key).push(...list);
    }
    old.times = keptFigures;
    current = bookAt(f.book, writer, old);
    Object.assign(old, { path: keptPath, keptNumber: number, save: watched(old, bookSaver(folder, { path: keptPath, saved: old.writer.book() })) });
    keptFacts.delete(keptPath);
    if (holding(old.id)) keptOpen.set(old.id, old);
    bookProblem = null;
    try {
      current.save(current.writer.book());
    } catch (e) {
      // The switch is made: the file is written with the next entry, or at the next start.
      bookProblem = `The new book was started, and its file ${f.book} could not be written yet: ${e.message}`;
    }
    faults('written');
    return { kept: `book-${number}.jsonl`, keptEntries: old.entries, entries: entries(), ...(bookProblem ? { warning: bookProblem } : {}) };
  }
  // After each entry: a new book once the book in force is full. Where the
  // switch cannot be made (the book file held open by another program for
  // longer than the recorder waits), the book in force goes on, and the
  // switch is tried again a minute later; "status" says why.
  let retryAt = 0;
  async function whenFull() {
    if (entries() < newAt.entries && current.bytes < newAt.bytes) return;
    if (clock() < retryAt) return;
    try {
      await newBook();
    } catch (e) {
      retryAt = clock() + 60000;
      bookProblem = `A new book could not be started: ${e.message}`;
    }
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
    // The lists are read from the file each time, so that "retire-passkey" and "admit-passkey", run while the service runs, count at once.
    trusted = trustedNow();
    const next = await checkNewSlip(given, { agentKeys: agent.keys, previous: current, trusted, retired: readRetired(folder), newPasskey });
    const before = current.fingerprint;
    if (next.fingerprint === before) return { slip: before, previous: before, issuer: current.issuerKey, entries: entries(), unchanged: true, warnings: [] };
    // A cancellation of the permission in force, held beside the book until
    // the clock reaches its date: a new permission that starts before that
    // date would let the agent act in the time the person cancelled, so it is
    // refused; one that starts after it is taken, and the cancellation goes
    // on being held, by the new writer, until it is written into the book.
    const held = heldNow();
    const from = Date.parse(next.content.validFrom);
    const holding = held.map((c) => cancellationSays(c.cancellation)).filter((s) => s && s.slip === before && s.when > from);
    if (holding.length > 0) {
      const when = new Date(Math.max(...holding.map((s) => s.when))).toISOString();
      throw Object.assign(new Error(`A cancellation of the permission in force, dated ${when}, is held until this computer's clock reaches that date, and this permission starts before it (${next.content.validFrom}), so it is not taken: the agent would act in the time the person cancelled. Sign one that starts after ${when}.`), { code: 'cancellation-held' });
    }
    const book = current.writer.book();
    const inBook = (await slipsIn(book)).has(next.fingerprint);
    const issuerKeys = trusted.includes(next.issuerKey) ? trusted : [...trusted, next.issuerKey];
    const writer = await open(inBook ? book : book + entryLine({ slip: next.slip }) + '\n', next.fingerprint, issuerKeys, held);
    if (!existsSync(keptSlip(folder, before))) writeFileSync(keptSlip(folder, before), JSON.stringify(current.slip));
    // slip.json and the book first, the list of passkeys last, so that a
    // renewal that fails on the way never leaves a new passkey trusted;
    // slip.json is put back where a later step fails. Whatever is left, the
    // start-up checks refuse a slip from a passkey not on the list.
    replaceFile(f.slip, JSON.stringify(next.slip));
    try {
      current.save(writer.book());
      if (issuerKeys !== trusted) writeTrusted(folder, issuerKeys);
    } catch (e) {
      try { replaceFile(f.slip, JSON.stringify(current.slip)); } catch { /* left to the start-up checks */ }
      // The book file too, which may already hold the new permission's line.
      try {
        saveBook(folder, current.writer.book(), current.path);
        current.written = current.writer.book().length;
      } catch { /* the saver puts the file right with the next entry */ }
      feed.changed();
      throw e;
    }
    trusted = issuerKeys;
    everSlips.add(next.fingerprint);
    if (held.length > 0) heldOnDisk = true;
    // The writer before is kept while a call allowed under its slip may still come back for its stub.
    if (pending(current.id, before)) current.before.set(before, current.writer);
    Object.assign(current, { writer, slip: next.slip, fingerprint: next.fingerprint, issuerKey: next.issuerKey, content: next.content });
    return { slip: next.fingerprint, previous: before, issuer: next.issuerKey, entries: entries(), validUntil: next.content.validUntil, warnings: next.warnings };
  }

  // Each kept book is read once: the time and amount of its stubs go into
  // the kept books' figures, so that a restart after a new book restarts no
  // limit; its text is not kept. One that does not end with a seal (the
  // recorder stopped after a late stub was written into it, before it was
  // sealed again) is sealed now, under the last permission it holds. The
  // figures are read from the files as they stand: a kept book changed by
  // hand is not checked here (a checker shows it).
  for (const k of kept) {
    const keptText = readFileSync(k.path, 'utf8');
    readFigures(keptText, 0, keptFigures, { entries: 0, bytes: 0 });
    for (const held of await slipsIn(keptText)) everSlips.add(held);
    keptCancelled = Math.max(keptCancelled, latestCancellationIn(keptText));
    if (keptText.startsWith('{"seal":', keptText.lastIndexOf('\n', keptText.length - 2) + 1)) continue;
    try {
      const under = [...(await slipsIn(keptText))].at(-1);
      const b = { path: k.path, keptNumber: k.number, writer: await open(keptText, under, trusted), seen: 0, entries: 0, bytes: 0, times: new Map(), synced: 0 };
      b.save = watched(b, bookSaver(folder, { path: k.path, saved: keptText }));
      await sealIn(b);
    } catch (e) {
      bookProblem = `The book kept as ${k.path} does not end with a seal, and could not be sealed: ${e.message}`;
    }
  }
  // A book already full when the service starts is kept, and a new one begun, before any call.
  await whenFull();

  // The passkeys trusted: those in memory, and those the file lists now
  // ("admit-passkey" or "renew --new-passkey" run while the service runs).
  function trustedNow() {
    let onDisk = [];
    try {
      onDisk = readTrusted(folder) ?? [];
    } catch {
      // A list that cannot be read: the one in memory.
    }
    return [...new Set([...trusted, ...onDisk])];
  }

  // Whether the permission in force is cancelled: its cancellation is in the
  // book, or held beside it by the writer (dated ahead of the clock).
  async function cancelledInForce() {
    const answer = await current.writer.check();
    if (answer.entries.some((e) => e.kind === 'cancellation' && e.slip === current.fingerprint && e.problems.length === 0)) return true;
    return current.writer.cancellations().some((c) => slipOfCancellation(c.cancellation) === current.fingerprint);
  }

  // The cancellations the writer holds beside the book that the book does not
  // hold yet (dated ahead of the clock), whichever permission each is of.
  function heldNow() {
    const text = current.writer.book();
    return current.writer.cancellations().filter((c) => c && c.cancellation && typeof c.cancellation.payload === 'string' && !text.includes(`"payload":"${c.cancellation.payload}"`));
  }

  // held-cancellations.json brought up to date with what the writer holds,
  // after each request while it may hold anything: a cancellation written
  // into the book since is let go, and once none is held the file goes. A
  // cancellation of a permission that a later one replaced, held across that
  // renewal, goes into the book without the acknowledgement signed for it,
  // which is added after it here.
  async function settleHeld() {
    const before = readHeldCancellations(folder);
    const text = current.writer.book();
    for (const c of before) {
      if (!text.includes(`"payload":"${c.cancellation.payload}"`)) continue;
      for (const ack of Array.isArray(c.acknowledgements) ? c.acknowledgements : []) {
        if (!ack || typeof ack.payload !== 'string' || current.writer.book().includes(`"payload":"${ack.payload}"`)) continue;
        try {
          await current.writer.add({ acknowledgement: ack });
          current.save(current.writer.book());
        } catch {
          // One that does not fit the book (another agent's, say): the person's copy keeps it.
        }
      }
    }
    const now = heldNow();
    writeHeldCancellations(folder, now);
    heldOnDisk = now.length > 0;
  }

  // The latest date of a cancellation this recorder holds: in the book in
  // force, in the books kept, or held beside the book. A renewal handed over
  // must start after it.
  function latestCancellation() {
    let latest = Math.max(keptCancelled, latestCancellationIn(current.writer.book()));
    for (const c of current.writer.cancellations()) {
      const says = c && c.cancellation ? cancellationSays(c.cancellation) : null;
      if (says && says.when > latest) latest = says.when;
    }
    return latest;
  }

  // A RECORD HANDED OVER (POST /hand-over, by a reader that holds the feed's
  // token: the application's uploader). The person signed it elsewhere (on
  // the signing page, opened from the application), and the application
  // kept it sealed with the book; the uploader hands it over. Nothing about
  // it is taken on the word of whoever handed it over: the recorder checks
  // it itself. The answer says what was done, with a code a program can read
  // and words for the person:
  //   { kind, fingerprint, outcome, code?, thumbprint?, message, acknowledgement? }
  // outcome: "taken" (the book holds it now), "already" (it held it
  // before), "held" (a cancellation dated ahead of this computer's clock:
  // the writer stops, and writes it into the book once the clock reaches its
  // date) or "refused" (nothing changed; code says why).
  //
  // A RENEWAL is taken as "renew" takes one without --new-passkey: from a
  // passkey this recorder already trusts and has not retired, naming this
  // folder's agent keys, not ended. It is never a permission this recorder
  // held before (one held back and handed over again would take the agent
  // back to it), and starts no earlier than the permission in force, no
  // more than HAND_OVER_ALLOWANCE_MS ahead of this computer's clock when it
  // is handed over ("starts-later", refused for good), and at least
  // HAND_OVER_ALLOWANCE_MS after every cancellation the recorder holds. A
  // passkey this computer does not trust is refused, never added: the
  // person adds it here, with "admit-passkey", which runs these same checks
  // (POST /admit) with that one passkey admitted for that one permission.
  //
  // A CANCELLATION is taken only for the permission in force: the writer
  // stops, writes the cancellation into the book and signs the agent's
  // acknowledgement, which follows it into the book (the library's "add").
  // One handed over again gives back the same acknowledgement.
  async function handOver(given) {
    const refused = (kind, fingerprint, code, message, more = {}) => ({ kind, fingerprint, outcome: 'refused', code, message, ...more });
    if (!given || typeof given !== 'object' || Array.isArray(given)) return refused(null, null, 'not-understood', 'What was handed over is not a renewal or a cancellation.');
    const names = Object.keys(given);
    if (given.kind === 'renewal' && names.length === 2 && names.includes('slip')) return handOverRenewal(given.slip, refused);
    if (given.kind === 'cancellation' && names.length === 2 && names.includes('cancellation')) return handOverCancellation(given.cancellation, refused);
    return refused(null, null, 'not-understood', 'What was handed over is not a renewal ({kind: "renewal", slip}) or a cancellation ({kind: "cancellation", cancellation}).');
  }

  // A permission signed at another address than the signing page the recorder expects (signedAt).
  function otherAddress(kind, fp, origin, refused) {
    return refused(kind, fp, 'other-signing-address', `This permission was signed at ${typeof origin === 'string' ? origin : 'an address it does not name'}, not at ${signedAt.join(' or ')}, where the records this recorder takes from the application are signed, so it is not taken.`);
  }

  // A renewal whose start was too far ahead when it was handed over: refused
  // for good, by its fingerprint, for as long as the service runs, though
  // its start comes nearer (a restart forgets them; the uploader does not
  // hand over again a record refused with this code).
  const startsLater = new Set();
  const startsLaterWords = (from) => `This permission starts at ${from}, more than ${HAND_OVER_ALLOWANCE_MS / 60000} minutes ahead of this computer's clock when it was handed over, so it is not taken, now or later. A permission does not say when it was signed: one that starts later than that could have been signed before a cancellation and kept back until after it. Sign one that starts within ${HAND_OVER_ALLOWANCE_MS / 60000} minutes of signing; to use one that starts later, put it on this computer yourself: ${RUN} renew <file>.`;

  // admit: the thumbprint of a passkey this computer does not trust, which
  // the person admits here ("admit-passkey") for this one permission; check:
  // every check, and nothing taken (outcome "would-take").
  async function handOverRenewal(slip, refused, { admit = null, check = false } = {}) {
    const kind = 'renewal';
    let fp;
    try {
      fp = await fingerprint(fromBase64url(slip.payload));
    } catch {
      return refused(kind, null, 'not-sound', 'What was handed over is not a signed permission.');
    }
    if (fp === current.fingerprint) return { kind, fingerprint: fp, outcome: 'already', message: 'This permission is the one in force: the book holds it already.' };
    if (everSlips.has(fp)) return refused(kind, fp, 'not-again', 'This permission was in force before, and a later one replaced it: the recorder does not go back to it. Sign a new permission.');
    // Before the passkey is looked at, so that such a permission never waits for "admit-passkey".
    const stated = startOf(slip);
    if (startsLater.has(fp) || stated > clock() + HAND_OVER_ALLOWANCE_MS) {
      if (startsLater.size >= 1000) startsLater.delete(startsLater.values().next().value);
      startsLater.add(fp);
      return refused(kind, fp, 'starts-later', startsLaterWords(new Date(stated).toISOString()));
    }
    trusted = trustedNow();
    let next;
    try {
      next = await checkNewSlip(slip, { agentKeys: agent.keys, previous: current, trusted, retired: readRetired(folder), newPasskey: admit !== null });
    } catch (e) {
      if (e.code === 'passkey-not-trusted' && admit === null) {
        // Its signature checked (only the trust in its passkey failed), so what it says of its address is the passkey's.
        const origin = JSON.parse(new TextDecoder().decode(fromBase64url(slip.payload))).issuer?.origin;
        if (!signedAt.includes(origin)) return otherAddress(kind, fp, origin, refused);
        // Kept for "admit-passkey", which shows it on this computer and takes it only once the person confirms there.
        try {
          addWaitingPermission(folder, slip, fp, e.thumbprint);
        } catch {
          // Not kept: "renew <file> --new-passkey" still takes it, from the person's own file.
        }
      }
      return refused(kind, fp, e.code ?? 'not-taken', e.message, e.thumbprint ? { thumbprint: e.thumbprint } : {});
    }
    // Admitted for this one permission only: signed by the passkey the person named.
    if (admit !== null && next.issuerKey !== admit) return refused(kind, fp, 'other-passkey', `This permission is signed by the passkey ${next.issuerKey}, not by ${admit}, the passkey being admitted, so it is not taken.`);
    if (!signedAt.includes(next.content.issuer.origin)) return otherAddress(kind, fp, next.content.issuer.origin, refused);
    if (Date.parse(next.content.validFrom) < Date.parse(current.content.validFrom)) {
      return refused(kind, fp, 'older', `This permission starts at ${next.content.validFrom}, before the permission in force (from ${current.content.validFrom}), so it is not taken: a record signed earlier and handed over late would take the agent back. Sign a new permission.`);
    }
    // After a cancellation: a permission that starts before the cancellation's
    // date and the allowance may have been signed before the person cancelled
    // (held back, or handed over late), and would start the agent again
    // against the person's later word. One signed after it can start then.
    const cancelledAt = latestCancellation();
    if (Date.parse(next.content.validFrom) < cancelledAt + HAND_OVER_ALLOWANCE_MS) {
      const when = new Date(cancelledAt).toISOString();
      const from = new Date(Math.ceil((cancelledAt + HAND_OVER_ALLOWANCE_MS) / 1000) * 1000).toISOString();
      return refused(kind, fp, 'before-cancellation', `This permission starts at ${next.content.validFrom}, less than ${HAND_OVER_ALLOWANCE_MS / 60000} minutes after the person's cancellation of ${when}, so it is not taken: a permission does not say when it was signed, and one signed before a cancellation and handed over after it would start the agent again. Sign a new permission that starts at ${from} or later.`);
    }
    if (check) return { kind, fingerprint: fp, outcome: 'would-take', thumbprint: next.issuerKey, message: 'Every check passed: it would be taken.' };
    try {
      const renewed = await renew(slip, admit !== null);
      await whenFull();
      return { kind, fingerprint: fp, outcome: 'taken', entries: renewed.entries, message: `Taken: the agent acts under this permission from now on (in force from ${next.content.validFrom} until ${next.content.validUntil}).` };
    } catch (e) {
      return refused(kind, fp, e.code ?? 'failed', e.message);
    }
  }

  async function handOverCancellation(record, refused) {
    const kind = 'cancellation';
    let fp;
    let says;
    try {
      fp = await fingerprint(fromBase64url(record.payload));
      says = cancellationSays(record);
    } catch {
      return refused(kind, null, 'not-sound', 'What was handed over is not a signed cancellation.');
    }
    if (!says) return refused(kind, fp, 'not-sound', 'What was handed over is not a signed cancellation.');
    if (says.slip !== current.fingerprint) {
      return everSlips.has(says.slip)
        ? refused(kind, fp, 'not-in-force', 'This cancellation is of a permission that a later one replaced, and the agent acts under that later permission, which this cancellation does not stop. To stop the agent, cancel the permission it acts under now. The cancellation stays with the person\'s own copy.')
        : refused(kind, fp, 'unknown-permission', 'This cancellation is of a permission this recorder has never held.');
    }
    // Whatever address the permission names: a cancellation only reduces what
    // the agent may do, and it is taken only where it checks against the
    // permission's own passkey and the permission's own address (the
    // library's checker holds it to both, in "add" below).
    // Held beside the book until the clock reaches its date: no further ahead than CANCELLATION_AHEAD_MS.
    if (says.when > clock() + CANCELLATION_AHEAD_MS) {
      return refused(kind, fp, 'too-far-ahead', `This cancellation is dated ${new Date(says.when).toISOString()}, more than ${CANCELLATION_AHEAD_MS / 3600000} hours ahead of this computer's clock, so it is not taken. A cancellation signed now is dated now; look at the clock of the computer it was signed on, and of this one.`);
    }
    // The book's own line for this cancellation, found by its signed content.
    const mark = `"payload":"${record.payload}"`;
    const before = current.writer.book().includes(mark);
    let acknowledgement;
    let failure = null;
    try {
      acknowledgement = (await current.writer.add({ cancellation: record })).acknowledgement;
    } catch (e) {
      failure = e;
      acknowledgement = e.acknowledgement;
    }
    // Held beside the book: kept in held-cancellations.json at once, so that a restart does not lose it.
    if (heldNow().length > 0 || heldOnDisk) {
      try {
        await settleHeld();
      } catch (e) {
        if (acknowledgement && !current.writer.book().includes(mark)) return { kind, fingerprint: fp, outcome: 'held', acknowledgement, message: `The recorder stopped acting under the permission until it restarts, but the cancellation could not be kept in ${f.held} (${e.message}): hand it over again.` };
      }
    }
    try {
      current.save(current.writer.book());
    } catch (e) {
      if (acknowledgement) return { kind, fingerprint: fp, outcome: 'held', acknowledgement, message: `The recorder stopped acting under the permission. The cancellation could not be written to the book file yet (${e.message}): it is written with the next save.` };
      return refused(kind, fp, 'failed', e.message);
    }
    const now = current.writer.book().includes(mark);
    if (now && acknowledgement) return { kind, fingerprint: fp, outcome: before ? 'already' : 'taken', acknowledgement, message: before ? 'The book holds this cancellation already, with the agent\'s acknowledgement.' : 'Taken: the recorder stopped acting under the permission, and wrote the cancellation and the agent\'s acknowledgement into the book.' };
    if (!now && acknowledgement) return { kind, fingerprint: fp, outcome: 'held', acknowledgement, message: 'The recorder stopped acting under the permission. The cancellation is dated ahead of this computer\'s clock, so it is written into the book, with the agent\'s acknowledgement, once the clock reaches its date.' };
    return refused(kind, fp, 'not-sound', failure ? failure.message : 'The cancellation was not taken.');
  }

  // A caller that has gone (it gave up waiting) is not answered. Its
  // question before a call, a seal, a renewal or a new book it asked for,
  // still waiting its turn, is not done. The stub of a call that was taken
  // is always written, whether or not the hook still waits for it: the
  // hook has said that it was not confirmed, not that it was not written.
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
      // The feed's own requests (GET /books and /lines), with its token.
      if (await feed.handle(req, res)) return undefined;
      if (req.method === 'GET' && req.url === '/status') {
        const witnessed = await witnessing.status();
        return send(200, {
          slip: current.fingerprint,
          issuer: current.issuerKey,
          sealer: sealKeys[0],
          agent: current.content.agent.name,
          validFrom: current.content.validFrom,
          validUntil: current.content.validUntil,
          trusted,
          retired: readRetired(folder),
          entries: entries(),
          recordedSinceStart: count,
          callsNotYetRecorded: [...inFlight.values()].filter((c) => counting(c)).length,
          newBookAt: newAt,
          keptBooks: keptBooks(folder).map((k) => k.file),
          feed: feed.status(),
          ...(bookProblem ? { newBookProblem: bookProblem } : {}),
          cancelled: await cancelledInForce(),
          witnesses: witnessed.witnesses,
          ...(witnessed.problem ? { witnessesProblem: witnessed.problem } : {}),
          ...(pendingProblem ? { pendingSealProblem: pendingProblem } : {}),
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
          await tidy();
          const request = requestFrom(given);
          const refused = limitRefusal(request);
          if (refused) return refused;
          const said = await current.writer.before(request);
          const id = callId(given);
          if (said.allowed && id) {
            inFlight.delete(id);
            inFlight.set(id, { book: current.id, slip: current.fingerprint, action: request.action, at: clock(), unit: request.amount?.unit, value: request.amount?.value });
            if (inFlight.size > KEPT_CALLS) inFlight.delete(inFlight.keys().next().value);
          }
          return said;
        });
        return send(200, answer);
      }
      if (req.url === '/record') {
        try {
          // The answer is sent only once the stub is written and saved.
          const written = await inTurn(async () => {
            let stub;
            try {
              stub = await record(given);
            } catch (e) {
              // Signed and held, to be written with the next save: in the book, and counted as recorded.
              if (e.code === 'held-not-saved') count++;
              throw e;
            }
            count++;
            await whenFull();
            return stub;
          });
          return send(200, { seq: written.seq, fingerprint: written.fingerprint });
        } catch (e) {
          if (e instanceof Gone) return undefined;
          return send(409, { error: e.message, code: e.code });
        }
      }
      if (req.url === '/seal') {
        return send(200, await unlessGone(async () => {
          const sealed = await seal();
          await whenFull();
          return sealed;
        }));
      }
      // "admit-passkey" for a permission handed over and waiting: the hand-over's
      // own checks, with that one passkey admitted for that one permission;
      // "take": false checks only.
      if (req.url === '/admit') {
        return send(200, await unlessGone(async () => {
          const refused = (kind, fingerprint, code, message) => ({ kind, fingerprint, outcome: 'refused', code, message });
          if (typeof given.thumbprint !== 'string' || !THUMBPRINT.test(given.thumbprint) || !given.slip || typeof given.slip !== 'object' || typeof given.slip.payload !== 'string') {
            return refused('renewal', null, 'not-understood', 'What was asked is not a permission and the thumbprint of the passkey to admit.');
          }
          return handOverRenewal(given.slip, refused, { admit: given.thumbprint, check: given.take !== true });
        }));
      }
      if (req.url === '/renew' || req.url === '/new-book') {
        try {
          return send(200, await unlessGone(async () => {
            if (req.url === '/new-book') return newBook();
            const renewed = await renew(given.slip, given.newPasskey === true);
            await whenFull();
            return renewed;
          }));
        } catch (e) {
          if (e instanceof Gone) return undefined;
          return send(409, { error: e.message, code: e.code });
        }
      }
      if (req.url === '/stop') {
        send(200, { stopped: true });
        feed.close();
        witnessing.close();
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
  // The witnesses are asked about every seal they have not signed for, from now on.
  witnessing.start();
  return {
    port: server.address().port,
    get recorder() { return current.writer; },
    get readings() { return readings; },
    witnesses: () => witnessing.status(),
    seal: () => inTurn(async () => {
      const sealed = await seal();
      await whenFull();
      return sealed;
    }),
    renew: (slip, { newPasskey = false } = {}) => inTurn(async () => {
      const renewed = await renew(slip, newPasskey);
      await whenFull();
      return renewed;
    }),
    newBook: () => inTurn(newBook),
    close: () => {
      feed.close();
      witnessing.close();
      return new Promise((resolve) => server.close(resolve));
    },
  };
}

/** The fingerprint of the slip a cancellation names, read from its content; null where it cannot be read. */
function slipOfCancellation(record) {
  try {
    const slip = JSON.parse(new TextDecoder().decode(fromBase64url(record.payload))).slip;
    return typeof slip === 'string' ? slip : null;
  } catch {
    return null;
  }
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

/**
 * Write a settings file anew, to a new file that then takes the old one's
 * place, and only where it still holds the text read before: a change
 * made meanwhile (by Claude Code, or by the person) is never lost. A
 * change made between that last reading and the renaming is not caught.
 */
export function replaceIfUnchanged(path, text, read) {
  if (readFileSync(path, 'utf8') !== read) throw new Error(`${path} changed while it was read, so it was left as it is. Run remove-hooks again.`);
  replaceDurably(path, text, statSync(path).mode & 0o777);
}

// --- the commands ---

async function ask(port, path, method = 'GET', body, waitMs = 60000) {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(waitMs) });
  return response.json();
}

async function running(port, waitMs = 60000) {
  try {
    return await ask(port, '/status', 'GET', undefined, waitMs);
  } catch {
    return null;
  }
}

/**
 * Start the recorder in the background if it is not running, and wait for
 * it to answer: for 20 seconds, or until "until" (a time) where that comes
 * first. 0 where it answers, 1 where it does not, and "starting" where it
 * was started and the time ran out before it answered.
 */
async function ensure(folder, port, say = (words) => console.error(words), until = Infinity) {
  const left = () => Math.max(250, Math.min(60000, Math.round(until - Date.now())));
  if (await running(port, left())) return 0;
  if (!existsSync(files(folder).slip)) {
    say(`The recorder has no signed permission yet (${files(folder).slip}), so it was not started. Sign one and put it in place: ${RUN} use <the saved file>`);
    return 1;
  }
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', SELF, 'start'], { detached: true, stdio: 'ignore', env: process.env });
  child.unref();
  for (let i = 0; i < 80; i++) {
    if (Date.now() + 250 > until) return 'starting';
    await new Promise((r) => setTimeout(r, 250));
    if (await running(port, left())) return 0;
  }
  say(`The recorder did not start. Run "${RUN} start" to see why.`);
  return 1;
}

// What the person must do before anything is recorded: nothing signs for them.
const firstRunWords = () => `Provared: no permission has been signed for this agent yet, so the recorder is not running and every tool call is refused: no record, no action. To set it up, in a terminal:
  1. ${RUN} init
     (it makes the agent's keys and prints a link to https://sign.prova.red/, the signing page)
  2. Open the link, write your name, read the permission and compare the fingerprint of the agent's key set with the one init printed. Sign with your passkey, and save the file the page gives you.
  3. ${RUN} use <the saved file>
Nothing signs for you. Once "use" says the recorder is running, each tool call is checked against the permission and recorded.`;

/**
 * What the Claude Code plugin runs when a session starts: the recorder is
 * started if it is not running, as "ensure" does; and where something
 * stands in the way (no permission yet, a recorder that does not start, or
 * the recorder's hooks in force twice), it is said to the person (Claude
 * Code's "systemMessage") and to Claude ("additionalContext"), so that
 * neither takes the refusals that follow for a fault. It always ends with
 * code 0: a session starts whatever it says. Where all is well, it says
 * nothing.
 */
async function sessionStart(folder, port) {
  // The hook has 30 seconds: everything here ends 27 seconds after the program started.
  const until = performance.timeOrigin + 27000;
  const said = [];
  const project = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  const { found, problem } = recorderHooksInSettings(project);
  if (problem) said.push(`Provared: ${problem}. Before each call the plugin looks there for the recorder's hooks, which would ask about and record each call twice, so every tool call is refused until the file is smaller or the plugin is turned off.`);
  if (found.length > 0) said.push(doubledWords(found, RUN, project));
  if (!existsSync(files(folder).slip) && !(await running(port, Math.max(250, Math.min(2000, Math.round(until - Date.now())))))) said.push(firstRunWords());
  else {
    const problems = [];
    const started = await ensure(folder, port, (words) => problems.push(words), until);
    if (started === 'starting') said.push(`Provared: the recorder is still starting. Until it answers, tool calls are refused; if they still are in a minute, run "${RUN} status", or "${RUN} start" to see why.`);
    else if (started !== 0) said.push(`Provared: ${problems.join(' ')} Until it runs, every tool call is refused.`);
  }
  if (said.length > 0) {
    const words = said.join('\n\n');
    console.log(JSON.stringify({ systemMessage: words, hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: words } }));
  }
  return 0;
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
/**
 * "admit-passkey <thumbprint>" for a passkey this recorder has never
 * trusted. The server between the application and this computer could put
 * a permission signed by anyone's passkey where the uploader reads, so a
 * passkey is never admitted by itself: only with a permission it signed
 * that was handed over and refused, which waits in waiting-permissions.json.
 * Only through the running service (POST /admit), which runs every check a
 * permission handed over goes through (not held before, not older than the
 * one in force, not starting too far ahead, not starting before a
 * cancellation and the allowance, and the cancellations it holds), with
 * that one passkey admitted for that one permission. Each waiting
 * permission from the passkey is checked first; one that fails is dropped
 * from the list and said. The rest are shown in full, the one that starts
 * latest first, each with the thumbprint of the passkey worked out from the
 * permission itself, and the first is taken, with its passkey, only once
 * the person types "yes" on this computer.
 * @param {(prompt: string) => Promise<string>} answer reads what the person types
 * @returns {Promise<number>} the exit code
 */
async function admitWaiting(folder, port, thumb, answer) {
  if (!(await running(port))) {
    console.log(`The recorder is not running, so nothing is admitted: a permission waiting here is checked by the running recorder, against the cancellations it holds, before it is taken. Start it first ("${RUN} ensure"), then run this again.`);
    return 1;
  }
  // The waiting permissions this passkey signed, as each permission itself says.
  const mine = [];
  for (const p of readWaitingPermissions(folder)) {
    try {
      const check = await checkSlip(p.slip);
      if (check.problems.length === 0 && check.signature.state === 'valid' && check.issuerKey === thumb) {
        mine.push({ slip: p.slip, content: check.content, thumbprint: check.issuerKey, fingerprint: await fingerprint(fromBase64url(p.slip.payload)) });
      }
    } catch {
      // Not a permission that checks: not shown.
    }
  }
  if (mine.length === 0) {
    console.log(`No permission signed by the passkey ${thumb} is waiting here, and this recorder has never trusted that passkey, so nothing is admitted. A passkey this computer does not trust is taken only with a permission it signed: one handed over from the application and refused (it then waits here), or one you saved as a file ("${RUN} renew <file> --new-passkey").`);
    return 1;
  }
  const admit = async (p, take) => {
    const said = await ask(port, '/admit', 'POST', { slip: p.slip, thumbprint: thumb, take });
    if (said.error === 'not found') throw new Error(`The recorder that is running is an earlier version, which cannot admit a passkey while it runs. Restart it once, with both commands on one line so that no tool call falls between them, then run admit-passkey again: ${RUN} stop; ${RUN} ensure`);
    if (said.error) throw new Error(said.error);
    return said;
  };
  const drop = (fp) => writeWaitingPermissions(folder, readWaitingPermissions(folder).filter((p) => p.fingerprint !== fp));
  const left = [];
  for (const p of mine) {
    const said = await admit(p, false);
    if (said.outcome === 'would-take') left.push(p);
    else {
      drop(p.fingerprint);
      console.log(`Dropped from the list, and not taken: the permission ${p.fingerprint} (from ${p.content.validFrom}). ${said.message}`);
    }
  }
  if (left.length === 0) {
    console.log(`Nothing is left waiting from the passkey ${thumb}, so nothing is admitted.`);
    return 1;
  }
  left.sort((a, b) => Date.parse(b.content.validFrom) - Date.parse(a.content.validFrom));
  const show = (v) => (typeof v === 'string' ? v : JSON.stringify(v));
  console.log(left.length === 1
    ? 'A permission handed over from the application waits here, signed by a passkey this computer does not trust.\n'
    : `${left.length} permissions handed over from the application wait here, signed by a passkey this computer does not trust. The first, which starts latest, is the one taken.\n`);
  for (const [i, p] of left.entries()) {
    const c = p.content;
    if (left.length > 1) console.log(`  ${i + 1}.`);
    console.log(`  Passkey (thumbprint)   ${p.thumbprint}`);
    console.log(`  Signed by (a label)    ${show(c.issuer?.name)}`);
    console.log(`  Signed at              ${show(c.issuer?.origin)} (website name ${show(c.issuer?.rpId)})`);
    console.log(`  Agent                  ${show(c.agent?.name)}, key set ${await keySetFingerprint(c.agent.keys)}`);
    console.log(`  May                    ${(c.actions || []).map(show).join(', ') || 'nothing'}`);
    console.log(`  Limits                 ${(c.limits || []).length ? c.limits.map(show).join('; ') : 'none'}`);
    console.log(`  Needs                  ${(c.requires || []).length ? c.requires.map(show).join('; ') : 'nothing'}`);
    console.log(`  Never                  ${(c.never || []).length ? c.never.map(show).join(', ') : 'nothing stated'}`);
    console.log(`  With                   ${(c.with || []).length ? c.with.map((w) => show(w.id ?? w)).join(', ') : 'no service named'}`);
    console.log(`  From                   ${c.validFrom}`);
    console.log(`  Until                  ${c.validUntil}`);
    console.log(`  Purpose                ${show(c.purpose)}`);
    console.log(`  Fingerprint            ${p.fingerprint}\n`);
  }
  console.log('Take it only if you signed it yourself, with a passkey you made: compare the thumbprint above with the one your signing page or application shows for your passkey. Anyone can make a passkey and sign a permission with it, and the application\'s server could have put this one here.');
  const typed = (await answer('Type yes to take this permission and trust its passkey, or anything else to leave it: ')).trim();
  if (typed !== 'yes') {
    console.log('Nothing was changed: the passkey is not trusted, and the permission waits.');
    return 1;
  }
  const chosen = left[0];
  const said = await admit(chosen, true);
  if (said.outcome !== 'taken' && said.outcome !== 'already') {
    drop(chosen.fingerprint);
    console.log(`Not taken, and dropped from the list: ${said.message}`);
    return 1;
  }
  drop(chosen.fingerprint);
  console.log(`The passkey ${thumb} is trusted from now on, with the permission it signed (${chosen.fingerprint}). ${said.message}`);
  return 0;
}

/** The first line the person types (empty where nothing is typed before the input ends). */
function firstLineTyped(prompt) {
  process.stdout.write(prompt);
  return new Promise((done) => {
    let got = '';
    const finish = () => {
      process.stdin.off('data', more);
      process.stdin.off('end', finish);
      process.stdin.pause();
      done(got.split(/\r?\n/)[0]);
    };
    const more = (d) => {
      got += d;
      if (got.includes('\n')) finish();
    };
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', more);
    process.stdin.on('end', finish);
    process.stdin.resume();
  });
}

async function renewFrom(file, folder, port, newPasskey = false) {
  await renewWith(slipFrom(readFileSync(file, 'utf8'), file), folder, port, newPasskey);
}

async function renewWith(slip, folder, port, newPasskey = false) {
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
  const next = await checkNewSlip(slip, { agentKeys: agent.keys, previous, trusted, retired: readRetired(folder), newPasskey });
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

// What "seal" says of the witnesses.
function witnessedWords(sealed, folder) {
  const named = readWitnessSettings(folder).list.length;
  if (named === 0) return '';
  const on = Array.isArray(sealed.witnessed) ? sealed.witnessed.length : 0;
  return ` ${on} of the ${named} witnesses named signed for it in time, beside the seal on its line; ${on === named ? 'nothing is left to ask' : 'the others are asked again while the recorder runs, and what they hand back is kept beside the book ("status" says what each holds)'}.`;
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
                .claude/settings.local.json, and print a link to sign the permission; with
                --no-hooks (or as the Claude Code plugin's copy), write no hooks
  remove-hooks  take the hooks init wrote out of this project's .claude/settings.local.json,
                for a project where the Claude Code plugin brings them
  use <file>    put a signed permission (slip.json from the signing page) in place, and start
  renew <file>  take a new signed permission into the book, while the recorder runs or not;
                add --new-passkey if you signed it with a passkey that signed no permission before
  retire-passkey <thumbprint>
                take no new permission from that passkey, with or without --new-passkey; what it
                signed before stands, and limits are still counted across the books it signed
  admit-passkey <thumbprint>
                take new permissions from a retired passkey again; for a passkey this recorder has
                never trusted, show the permission it signed that was handed over from the
                application and refused, and take both only once you type "yes"
  start         run the recorder in this terminal
  ensure        start the recorder in the background, if it is not running
  status        what the recorder holds
  seal          seal the book now, with the recorder's three keys
  new-book      seal the book, keep it as book-<n>.jsonl, and start a new one that begins with
                the permission in force (the recorder does this by itself at 90,000 entries,
                or at 100 MB of text)
  check [file]  the checker's answer for the book, or for a book kept before it (book-1.jsonl);
                name your own passkey with --issuer <its thumbprint> (once for each), or see the
                passkeys the book names
  add-witness <address> <fingerprint> <token file>
                ask a witness (provared-witness, at http://127.0.0.1:<port>) to sign for each
                seal from now on: the fingerprint of its key set, and its token file
  remove-witness <fingerprint>
                ask that witness no more
  stop          stop the recorder
  keys          make the keys, and print the agent's public keys`;

export async function main(argv) {
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
    if (rest.some((a) => a !== '--no-hooks')) {
      console.log(USAGE);
      return 2;
    }
    const agent = await makeAgentKeys(folder);
    await makeRecorderKeys(folder);
    // The plugin's copy, or --no-hooks: no hooks are written, since the plugin brings its own.
    const noHooks = FROM_PLUGIN || rest.includes('--no-hooks');
    const written = noHooks ? null : writeHooks(process.cwd());
    console.log(`The agent's keys and the recorder's are in ${folder}. Never share the files there that end in .jwk.`);
    console.log(`The record (the book, the permissions and the keys) is kept in that folder too. Anything that deletes the folder, such as an agent that deletes your home folder, deletes the record with it. To keep it on another disk, set PROVARED_CLAUDE_CODE_DIR to a folder there before you run init, and keep copies of the book elsewhere (see the README).`);
    if (!written) {
      console.log(FROM_PLUGIN
        ? 'No hooks were written: this copy of the recorder is the Claude Code plugin\'s, and the plugin brings its hooks to every session in which it is turned on.'
        : 'No hooks were written (--no-hooks): the Claude Code plugin provared-recorder brings them, in every session in which it is turned on.');
    } else {
      console.log(written.added + written.replaced > 0
        ? `The hooks are in ${written.path}${written.replaced > 0 ? ` (${written.replaced} earlier entries of them brought up to date)` : ''}: Claude Code, started in this folder, asks the recorder before and after each tool call.`
        : `The hooks were in ${written.path} already. Nothing was changed.`);
      for (const other of written.others) console.log(`Warning: another hook there names Provared: ${other}. If it is an older copy of this recorder, take it out by hand, or each tool call is asked about and recorded twice.`);
      if (written.switchedOff) console.log(`Warning: a settings file of this project says "disableAllHooks": true, so Claude Code runs no hook, these included, and nothing is checked or recorded. Take that setting out to record.`);
      if (pluginInstalled()) console.log(`Warning: the Claude Code plugin provared-recorder is installed too. Where it is turned on, its hooks and these both run, and the plugin refuses every tool call in this project until one of the two is taken out: "${RUN} remove-hooks" takes these out again.`);
    }
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
      const next = await checkNewSlip(slip, { agentKeys: agent.keys, previous, trusted, retired: readRetired(folder), newPasskey });
      for (const w of next.warnings) console.log(`Warning: ${w}`);
      if (!trusted.includes(next.issuerKey)) writeTrusted(folder, [...trusted, next.issuerKey]);
      await placeSlip(folder, next);
      console.log(`The permission ${next.fingerprint}, signed by the passkey ${next.issuerKey}, is in place until ${next.content.validUntil}.`);
    }
    if (command === 'renew') return 0;
    const code = await ensure(folder, port);
    if (code === 0) console.log(FROM_PLUGIN
      ? 'The recorder is running. In each Claude Code session in which the plugin is turned on, each tool call is checked and recorded.'
      : `The recorder is running. Start Claude Code in a project where "${RUN} init" was run, or with the Claude Code plugin turned on, and each tool call is checked and recorded.`);
    return code;
  }
  if (command === 'retire-passkey' || command === 'admit-passkey') {
    if (!rest[0]) {
      console.log(USAGE);
      return 2;
    }
    const retire = command === 'retire-passkey';
    // A passkey this recorder has never trusted: only with a permission it signed that waits here, shown and confirmed.
    if (!retire && THUMBPRINT.test(rest[0]) && !(readTrusted(folder) ?? []).includes(rest[0])) {
      return admitWaiting(folder, port, rest[0], firstLineTyped);
    }
    const lists = retirePasskey(folder, rest[0], retire);
    if (!lists.changed) {
      console.log(retire ? `The passkey ${rest[0]} is retired already.` : `The passkey ${rest[0]} is not retired: new permissions from it are taken.`);
    } else if (retire) {
      console.log(`The passkey ${rest[0]} is retired: the recorder takes no new permission from it, with or without --new-passkey, until "${RUN} admit-passkey ${rest[0]}". The permissions it signed before stand in the record, and limits are still counted across the books they are in.`);
      let placed = null;
      try {
        placed = existsSync(f.slip) ? await loadSlip(folder) : null;
      } catch {
        // A slip.json that cannot be read is the start-up checks' business.
      }
      if (placed && placed.issuerKey === rest[0]) console.log(`It signed the permission in force (${placed.fingerprint}), which stays in force until it ends; the next permission must come from another passkey.`);
    } else {
      console.log(`The passkey ${rest[0]} is admitted again: the recorder takes new permissions from it.`);
    }
    console.log(`Passkeys in the record: ${lists.passkeys.join(', ')}. Retired: ${lists.retired.length ? lists.retired.join(', ') : 'none'}.`);
    return 0;
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
  if (command === 'session-start') return sessionStart(folder, port);
  if (command === 'remove-hooks') {
    // Written to a new file that then takes the old one's place, and only where nobody changed the file since it was read.
    let removed;
    try {
      removed = removeInitHooks(process.cwd(), replaceIfUnchanged);
    } catch (e) {
      console.error(e.message);
      return 1;
    }
    if (removed.problem) {
      console.error(removed.problem);
      return 1;
    }
    console.log(removed.removed > 0
      ? `Took ${removed.removed} of the recorder's hooks out of ${removed.path}; nothing else there was changed. Start Claude Code again: it reads hooks when a session starts.`
      : `${removed.path} holds none of the hooks init writes. Nothing was changed.`);
    if (removed.removed > 0) console.log('The file was written again as JSON indented by two spaces: other formatting in it is not kept.');
    const { found: left } = recorderHooksInSettings(process.cwd());
    if (left.length > 0) console.log(`Hooks that run a recorder's hook.mjs are still in ${filesOf(left).join(' and ')}. Where the Claude Code plugin is turned on, take them out by hand.`);
    return 0;
  }
  if (command === 'check') {
    // A first word that is not an option names a book: one kept in the folder by its name (book-1.jsonl), or any file.
    let bookFile = f.book;
    if (rest.length > 0 && !rest[0].startsWith('-')) {
      const named = rest.shift();
      bookFile = KEPT_BOOK.test(named) && existsSync(join(folder, named)) ? join(folder, named) : resolve(named);
    }
    if (!existsSync(bookFile)) {
      console.error(bookFile === f.book ? `There is no book yet at ${f.book}.` : `There is no book at ${bookFile}.`);
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
      for (const s of await slipsListed(readFileSync(bookFile, 'utf8'))) {
        console.error(`  passkey ${s.issuerKey}: the permission ${s.fingerprint}, from ${s.from} until ${s.until}, signed as "${s.name.toWellFormed().replace(/[\u0000-\u001f\u007f-\u009f]/g, '�')}" (a label)`);
      }
      console.error(`Compare each with your own passkey's thumbprint, which the signing page shows when you sign, and run again with --issuer <thumbprint> for each that is yours: ${RUN} check --issuer <thumbprint>\n`);
    }
    // The witnesses this recorder asks, and the statements they handed back
    // after a seal's line was written (kept beside the book, in "witnessed").
    const { list: named } = readWitnessSettings(folder);
    // What is said of the recorder's own copies of seals, handed over for their statements, before and after the checker's answer.
    let mine = null;
    if (named.length > 0 && !rest.includes('--witness')) {
      for (const w of named) extra.push('--witness', w.key);
      console.error(`The witnesses you trust (--witness) are named from this recorder's own list (${join(folder, 'witnesses.json')}): ${named.map((w) => w.key).join(', ')}. To name them yourself, give --witness.`);
    }
    if (!rest.includes('--seal')) {
      const held = heldSealFiles(folder, readFileSync(bookFile, 'utf8'));
      for (const p of held) extra.push('--seal', p);
      if (held.length > 0) {
        mine = `${held.length === 1 ? 'One seal' : `${held.length} seals`} of this book ${held.length === 1 ? 'is' : 'are'} handed over beside it (--seal) only to bring the statements that witnesses handed back after the seal's line was written: ${held.length === 1 ? 'it is a copy' : 'they are copies'} of this book's own ${held.length === 1 ? 'seal' : 'seals'}, from the recorder's own folder (${join(folder, 'witnessed')}), which the agent can write. The checker calls ${held.length === 1 ? 'it a seal' : 'them seals'} "held elsewhere": ${held.length === 1 ? 'it is' : 'they are'} not, and cannot show the book cut short; only the statements beside ${held.length === 1 ? 'it' : 'them'} count. Hand over a seal you hold yourself, apart from this computer, for that (--seal).`;
        console.error(mine);
      }
    }
    const ran = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', checker, bookFile, ...rest, ...extra], { stdio: 'inherit' });
    if (mine) console.error(`\nNote: ${mine}`);
    return ran.status ?? 2;
  }
  if (command === 'add-witness') {
    const [address, key, tokenFile] = rest;
    if (!address || !key || !tokenFile || rest.length !== 3) {
      console.log(USAGE);
      return 2;
    }
    if (!validAddress(address)) {
      console.error('The address must be http://127.0.0.1:<port>: the recorder asks a witness on this computer (one on another computer is reached through a tunnel to a port here).');
      return 2;
    }
    if (!THUMBPRINT.test(key)) {
      console.error('The second word must be the fingerprint of the witness\'s key set, as "provared-witness init" prints it: 43 letters, digits, "-" and "_".');
      return 2;
    }
    let token;
    try {
      token = readFileSync(resolve(tokenFile), 'utf8').trim();
    } catch (e) {
      console.error(`The token file ${tokenFile} could not be read (${e.code ?? e.message}).`);
      return 2;
    }
    if (!isRandom(token)) {
      console.error(`${tokenFile} does not hold a witness's token: 43 letters, digits, "-" and "_" (the file witness-token in the witness's folder).`);
      return 2;
    }
    const settings = readWitnessSettings(folder);
    if (settings.problem) {
      console.error(settings.problem);
      return 1;
    }
    const others = settings.list.filter((w) => w.key !== key);
    if (others.length >= MAX_RECORDER_WITNESSES) {
      console.error(`The recorder asks at most ${MAX_RECORDER_WITNESSES} witnesses (a seal's line holds at most four statements): remove one first.`);
      return 1;
    }
    // Who answers there: the witness must prove that it holds the token, and sign with the key set named.
    try {
      const r = await witnessClient({ address, token }).ask('GET', '/about');
      if (r.code !== 200) throw Object.assign(new Error(r.body.error ?? `the witness answered ${r.code}`), { code: 'refused' });
      if (r.body.witness?.fingerprint !== key) {
        console.error(`The witness at ${address} signs with the key set ${r.body.witness?.fingerprint}, not ${key}, so it was not added. Compare with the fingerprint "provared-witness init" printed.`);
        return 1;
      }
      console.log(`The witness "${String(r.body.witness.by?.name ?? '').replace(/[\u0000-\u001f\u007f-\u009f]/g, '�')}" at ${address} answers, proves that it holds the token, and signs with the key set ${key}.${r.body.ready ? '' : ' It does not sign yet: at every start its operator must say that its folder was not put back to an older copy (provared-witness ready).'}`);
    } catch (e) {
      if (e.code !== 'unreachable') {
        console.error(`${e.message}, so it was not added.`);
        return 1;
      }
      console.log(`Warning: nothing answers at ${address} now. The witness is added all the same, and asked after each seal; "status" says what it holds.`);
    }
    writeWitnessSettings(folder, [...others, { address, key, token }]);
    console.log(`The recorder asks it to sign for each seal from now on (a running recorder reads ${settings.path} each time). Whoever checks the book names it: --witness ${key}`);
    return 0;
  }
  if (command === 'remove-witness') {
    const [key] = rest;
    if (!key || rest.length !== 1) {
      console.log(USAGE);
      return 2;
    }
    const settings = readWitnessSettings(folder);
    if (settings.problem) {
      console.error(settings.problem);
      return 1;
    }
    if (!settings.list.some((w) => w.key === key)) {
      console.error(`The recorder does not ask a witness with the key set ${key}.`);
      return 1;
    }
    writeWitnessSettings(folder, settings.list.filter((w) => w.key !== key));
    console.log(`The recorder asks that witness no more. The statements it gave stay where they are: on the seals' lines, and in ${join(folder, 'witnessed')}.`);
    return 0;
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
      console.log(`Sealed: entry ${sealed.entries} is the seal ${sealed.fingerprint}${sealed.book ? `, of book ${sealed.book}` : ''}.${witnessedWords(sealed, folder)}`);
      return 0;
    }
    const service = await startService({ folder, port: 0 });
    const sealed = await service.seal();
    await service.close();
    console.log(`Sealed (the service was not running, so the book was opened here): entry ${sealed.entries} is the seal ${sealed.fingerprint}${sealed.book ? `, of book ${sealed.book}` : ''}.${witnessedWords(sealed, folder)}`);
    return 0;
  }
  if (command === 'new-book') {
    let made;
    if (status) {
      made = await ask(port, '/new-book', 'POST', {});
      if (made.error === 'not found') {
        console.error(`The recorder that is running is an earlier version, which cannot start a new book. Restart it once, with both commands on one line so that no tool call falls between them, then run new-book again: ${RUN} stop; ${RUN} ensure`);
        return 1;
      }
    } else {
      // Not running: the book is opened here, as "seal" opens it.
      const service = await startService({ folder, port: 0 });
      try {
        made = await service.newBook();
      } catch (e) {
        made = { error: e.message };
      } finally {
        await service.close();
      }
    }
    if (made.error || typeof made.kept !== 'string') {
      console.error(`No new book was started: ${made.error ?? 'the recorder gave no answer.'}`);
      return 1;
    }
    if (made.warning) console.log(`Warning: ${made.warning}`);
    console.log(`The book was sealed and kept as ${join(folder, made.kept)} (${made.keptEntries} entries). A new book.jsonl begins with the permission in force; each book checks on its own.`);
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
