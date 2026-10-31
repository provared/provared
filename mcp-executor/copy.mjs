// The executor's own copy: one line for each call it was asked for, kept
// apart from the agent's book, only ever added to, each line tagged with
// HMAC-SHA-256 (RFC 2104) under the executor's copy key. It is what the
// executor can later hold against the agent's log (compare.mjs), and what
// tells a fresh start which calls were sent and never got their receipt.
//
// A line is `<tag> <json>`. The JSON names the call by the executor's own
// identifier ("call"), and is one of:
//   sending: written, and made sure to be on the disk, before a call goes to the tool server
//   done:    once the call's stub is in the book (or could not be written: "stub" is then absent)
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

/** Read the copy key (32 bytes in base64url), making it the first time. The file is for its owner alone. */
export function loadCopyKey(path) {
  if (!existsSync(path)) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, randomBytes(32).toString('base64url'), { mode: 0o600, flag: 'wx' });
  }
  const key = Buffer.from(readFileSync(path, 'utf8').trim(), 'base64url');
  if (key.length !== 32) throw new Error(`The copy key ${path} is not 32 bytes in base64url.`);
  return key;
}

/**
 * Open the copy file: append lines, each tagged and made sure to be on the
 * disk before the call returns.
 */
export function openCopy(path, key, name) {
  mkdirSync(dirname(path), { recursive: true });
  return {
    path,
    /** Append one line. Throws if the line could not be written to the disk. */
    note(entry) {
      const text = JSON.stringify(entry);
      if (text.includes('\n')) throw new Error('A line of the copy holds a line break.');
      const fd = untilFree(() => openSync(path, 'a'));
      try {
        writeSync(fd, `${tagOf(key, name, text)} ${text}\n`);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
    },
  };
}

/**
 * Read the copy file: every whole line, with whether its tag checks under
 * the key, and what it says. A line whose tag does not check is never acted
 * on; it is listed so that a person sees it. Gives {lines, checked, refused,
 * cut}: "cut" is a last line with no line feed (a stop while it was written).
 */
export function readCopy(path, key, name) {
  let text;
  try {
    text = untilFree(() => readFileSync(path, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') return { lines: [], checked: 0, refused: 0, cut: null };
    throw e;
  }
  const parts = text.split('\n');
  const cut = parts.at(-1) === '' ? null : parts.pop();
  if (cut === null) parts.pop();
  const lines = [];
  let checked = 0;
  let refused = 0;
  for (const raw of parts) {
    const at = raw.indexOf(' ');
    const tag = at === -1 ? raw : raw.slice(0, at);
    const body = at === -1 ? '' : raw.slice(at + 1);
    const expected = Buffer.from(tagOf(key, name, body));
    const given = Buffer.from(tag);
    const valid = given.length === expected.length && timingSafeEqual(given, expected);
    let entry = null;
    if (valid) {
      try {
        entry = JSON.parse(body);
      } catch {
        entry = null;
      }
    }
    if (valid && entry && typeof entry === 'object') {
      checked++;
      lines.push({ valid: true, entry, raw });
    } else {
      refused++;
      lines.push({ valid: false, entry: null, raw });
    }
  }
  return { lines, checked, refused, cut };
}

/**
 * The calls of a copy that were sent and have no "done" line: each with its
 * "sending" entry. Only lines whose tags check count.
 */
export function unfinished(read) {
  const sending = new Map();
  for (const l of read.lines) {
    if (!l.valid) continue;
    const e = l.entry;
    if (typeof e.call !== 'string') continue;
    if (e.kind === 'sending') sending.set(e.call, e);
    else if (e.kind === 'done') sending.delete(e.call);
  }
  return [...sending.values()];
}
