// The executor's own copy: one line for each call it was asked for, kept
// apart from the agent's book, only ever added to, each line numbered and
// tagged with HMAC-SHA-256 (RFC 2104) under the executor's copy key. It is
// what the executor can later hold against the agent's log (compare.mjs),
// and what tells a fresh start which calls were sent and never got their
// receipt.
//
// A line is `<tag> <json>`. The JSON carries "seq", the line's number from
// 0, so that a line taken out, put twice or moved is seen (a copy cut at
// its end is not: nothing in a line says it is the last). It names the
// call by the executor's own identifier ("call"), and is one of:
//   sending: written, and made sure to be on the disk, before a call goes to the tool server
//   done:    once the call's stub is in the book ("stub"); or, where the stub could not be
//            written to the book file, with what the executor knew of the outcome
//            ("documents") and no "stub": such a call is still unfinished
//   refused: a call that was not sent, with why, and the denial's fingerprint where one was written
//   withdrawn: a call the agent cancelled before it was sent
// Nothing in a line is a credential, an argument or a result: only names,
// times, codes and fingerprints.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, writeFileSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';
import { untilFree } from './files.mjs';

/** HMAC-SHA-256 of a line, under the copy key, with the executor's name, in base64url. */
export function tagOf(key, name, text) {
  return createHmac('sha256', key).update(`${name}\n${text}`).digest('base64url');
}

/**
 * Read the copy key (32 bytes in base64url). With "create", it is made the
 * first time, for its owner alone; without, null where there is none.
 */
export function loadCopyKey(path, { create = true } = {}) {
  if (!existsSync(path)) {
    if (!create) return null;
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, randomBytes(32).toString('base64url'), { mode: 0o600, flag: 'wx' });
  }
  const key = Buffer.from(readFileSync(path, 'utf8').trim(), 'base64url');
  if (key.length !== 32) throw new Error(`The copy key ${path} is not 32 bytes in base64url.`);
  return key;
}

/**
 * Open the copy file: append lines, each numbered from "next", tagged, and
 * made sure to be on the disk before the call returns.
 */
export function openCopy(path, key, name, next = 0) {
  mkdirSync(dirname(path), { recursive: true });
  let seq = next;
  return {
    path,
    /** Append one line. Throws if the line could not be written to the disk. */
    note(entry) {
      const text = JSON.stringify({ seq, ...entry });
      if (text.includes('\n')) throw new Error('A line of the copy holds a line break.');
      const fd = untilFree(() => openSync(path, 'a'));
      try {
        writeSync(fd, `${tagOf(key, name, text)} ${text}\n`);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      seq++;
    },
  };
}

/**
 * Read the copy file: every whole line, with whether its tag checks under
 * the key, and what it says. A line whose tag does not check is never acted
 * on; it is listed so that a person sees it. Gives {lines, checked, refused,
 * cut, next, sequence}: "cut" is a last line with no line feed (a stop
 * while it was written); "next" the number the next line gets; "sequence"
 * says whether the numbers of the lines that check run 0, 1, 2 … with no
 * gap and no repeat (a gap where a line was taken out or does not check, a
 * repeat where one was put twice).
 */
export function readCopy(path, key, name) {
  let text;
  try {
    text = untilFree(() => readFileSync(path, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') return { lines: [], checked: 0, refused: 0, cut: null, next: 0, sequence: { ok: true, problem: null } };
    throw e;
  }
  const parts = text.split('\n');
  const cut = parts.at(-1) === '' ? null : parts.pop();
  if (cut === null) parts.pop();
  const lines = [];
  let checked = 0;
  let refused = 0;
  let expected = 0;
  let problem = null;
  for (const raw of parts) {
    const at = raw.indexOf(' ');
    const tag = at === -1 ? raw : raw.slice(0, at);
    const body = at === -1 ? '' : raw.slice(at + 1);
    const given = Buffer.from(tag);
    const wanted = Buffer.from(tagOf(key, name, body));
    const valid = given.length === wanted.length && timingSafeEqual(given, wanted);
    let entry = null;
    if (valid) {
      try {
        entry = JSON.parse(body);
      } catch {
        entry = null;
      }
    }
    if (valid && entry && typeof entry === 'object' && Number.isInteger(entry.seq)) {
      checked++;
      lines.push({ valid: true, entry, raw });
      if (problem === null && entry.seq !== expected) {
        problem = entry.seq < expected ? `line ${lines.length - 1} carries number ${entry.seq}, which was used already: a line was put twice, or lines were moved.` : `line ${lines.length - 1} carries number ${entry.seq} where ${expected} was expected: a line was taken out, or does not check.`;
      }
      expected = Math.max(expected, entry.seq + 1);
    } else {
      refused++;
      lines.push({ valid: false, entry: null, raw });
      if (problem === null) problem = `line ${lines.length - 1} does not check under the copy key.`;
      expected++;
    }
  }
  return { lines, checked, refused, cut, next: Math.max(expected, lines.length), sequence: { ok: problem === null, problem } };
}

/**
 * The calls of a copy that were sent and are not finished: those with a
 * "sending" line and no "done" line that names a stub. Each is given as
 * {sending, done}: "done" is the last "done" line without a stub, if any,
 * which holds what the executor knew of the outcome. Only lines whose tags
 * check count.
 */
export function unfinished(read) {
  const open = new Map();
  for (const l of read.lines) {
    if (!l.valid) continue;
    const e = l.entry;
    if (typeof e.call !== 'string') continue;
    if (e.kind === 'sending') open.set(e.call, { sending: e, done: null });
    else if (e.kind === 'done') {
      if (typeof e.stub === 'string') open.delete(e.call);
      else if (open.has(e.call)) open.get(e.call).done = e;
    }
  }
  return [...open.values()];
}
