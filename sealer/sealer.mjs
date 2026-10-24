// provared-sealer: a central sealer that runs as a program of its own.
//
// It holds a recorder's three keys (in a file only its owner may read, or
// through signer modules that reach a key service) and seals the books of
// the recorders it serves, which send it the leaf fingerprints of their
// lines and never the lines (the library's openSealer). It listens on
// 127.0.0.1 only. Each recorder proves, with every question, that it holds
// its token, which never travels: the question carries two HMAC-SHA-256
// (RFC 2104) under the token, one over the recorder's name, the path, a
// time, a number used once and the body's declared length, checked before
// the body is read, and one over the same with the SHA-256 of the body in
// place of the length; the answer carries one over the question's proof,
// the status and the body. A body waits for its turn as its bytes only,
// and is read as JSON only in its turn, so one parsed body exists at a
// time.
//
// One state holds the books of every recorder it serves. Each book, and
// every book that follows it, belongs to the recorder that started it
// (the library's forRecorder): no other recorder can send lines for it,
// seal it, bring it up to date, start a book after it, or start a book with
// its first line. Each recorder is named with the agents whose permissions
// it may start books with (an agent belongs to one recorder) and the most
// books it may hold. Every change that must last (a book started, a seal, a
// book brought up to date) is made sure to be on the disk (fsync) before
// the answer is given; a seal is never given out before the state that
// holds it is saved. The questions are answered one at a time, and once
// the state cannot be saved, every question taken up after that is
// answered "sealer-stopped" until the program is started again.
//
// What it does not do: it names no time-stamp service (a program that
// embeds it may give a "stamp" function); it asks no witness; it does not
// check that a recorder sends the fingerprints of real lines (the book's
// own check does that, when the seal is added to it).

import nodeCrypto from 'node:crypto';
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, rmSync, writeSync } from 'node:fs';
import http from 'node:http';
import { isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { fromBase64url, keySetFingerprint, openSealer, signerFromKey, toBase64url } from 'provared';

export const DEFAULT_PORT = 8797;
export const SLH = 'SLH-DSA-SHA2-256s';
export const METHODS = ['Ed25519', 'ML-DSA-87', SLH];
const LABELS = Object.freeze({
  head: 'provared sealer v1: a recorder\'s question, before its body',
  question: 'provared sealer v1: a recorder\'s question',
  answer: 'provared sealer v1: the sealer\'s answer',
});
/** A recorder's name: small letters, digits and hyphens, 1 to 63. */
export const RECORDER_NAME = /^[a-z0-9][a-z0-9-]{0,62}$/;
const RANDOM = /^[A-Za-z0-9_-]{43}$/;
/** How far a question's time may be from the sealer's clock. */
export const QUESTION_WINDOW_MS = 60 * 1000;
/** The most numbers used once the sealer keeps for one recorder. */
export const MAX_NONCES = 100000;
/** The largest body a question or an answer may have: room for a whole book's leaf fingerprints. */
export const MAX_BODY_BYTES = 8 * 1024 * 1024;
/** The most bytes of bodies still being read (the question's headers proved, its body not yet) that the sealer holds for one recorder at once. */
export const MAX_HELD_BYTES = 2 * MAX_BODY_BYTES;
/** The most questions one recorder may have waiting at once. */
export const MAX_WAITING = 16;
/** The most bytes of bodies one recorder may have waiting for their turn at once: four whole bodies. Each waits as its bytes only. */
export const MAX_WAITING_BYTES = 4 * MAX_BODY_BYTES;
/** The most books a recorder may hold, unless recorders.json says otherwise. */
export const DEFAULT_RECORDER_BOOKS = 100;
/** The most books the sealer keeps for all its recorders together (the library's limit). */
export const MAX_BOOKS = 1000;
const PATHS = ['/about', '/extend', '/seal', '/update', '/latest', '/held'];
/** The members a question's body may hold, for each path. */
const MEMBERS = Object.freeze({
  '/about': [],
  '/extend': ['book', 'at', 'leaves', 'follows', 'line'],
  '/seal': ['book', 'previous', 'when'],
  '/update': ['book', 'entry', 'leaves', 'line'],
  '/latest': ['book'],
  '/held': ['book'],
});

/**
 * Whether a value is 32 bytes written in base64url in the one way they can
 * be written (the last character carries two bits no byte uses).
 */
export function isRandom(value) {
  return typeof value === 'string' && RANDOM.test(value) && Buffer.from(value, 'base64url').toString('base64url') === value;
}

/** HMAC-SHA-256 under a key, over a label and parts, each after a line break. No part holds a line break. */
export function sealerHmac(key, label, ...parts) {
  const h = nodeCrypto.createHmac('sha256', key);
  h.update(label);
  for (const p of parts) {
    h.update('\n');
    h.update(p);
  }
  return h.digest();
}

function sameProof(given, expected) {
  if (!isRandom(given)) return false;
  const bytes = Buffer.from(given, 'base64url');
  return bytes.length === expected.length && nodeCrypto.timingSafeEqual(bytes, expected);
}

const sha256 = (bytes) => nodeCrypto.createHash('sha256').update(bytes).digest('base64url');

// On Windows, a file another program holds open (a virus scanner, a backup)
// may refuse a write for a moment, so each step is tried again for up to ten
// seconds, as the gateway does.
const BUSY = ['EPERM', 'EBUSY', 'EACCES'];
function untilFree(step, seconds = 10) {
  const pause = new Int32Array(new SharedArrayBuffer(4));
  const deadline = Date.now() + seconds * 1000;
  for (let wait = 10; ; wait = Math.min(wait * 2, 200)) {
    try {
      return step();
    } catch (e) {
      if (!BUSY.includes(e.code) || Date.now() >= deadline) throw e;
      Atomics.wait(pause, 0, 0, wait);
    }
  }
}

/** Replace a file whole: a temporary file, made sure to be on the disk, then put in its place. Only its owner may read it. */
export function writeDurably(path, text) {
  const temporary = `${path}.tmp`;
  const fd = untilFree(() => openSync(temporary, 'w', 0o600));
  try {
    writeSync(fd, text);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  untilFree(() => renameSync(temporary, path));
}

function readJson(path, what) {
  let text;
  try {
    text = untilFree(() => readFileSync(path, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw new Error(`${what} (${path}) could not be read (${e.code}).`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${what} (${path}) is not JSON.`);
  }
}

/** Where the sealer keeps each thing, in its folder. */
export function sealerFiles(folder) {
  const root = resolve(folder);
  return {
    root,
    settings: join(root, 'sealer.json'),
    keys: join(root, 'sealer-keys.jwk'),
    recorders: join(root, 'recorders.json'),
    state: join(root, 'state.json'),
    lock: join(root, 'sealer.lock'),
  };
}

// --- settings ---

/**
 * The settings, sealer.json: "name" (the recorder name the seals give, a
 * label), "port" (8797 by default), and "signers": for any of the three
 * methods, the path of a module whose default export is an async function
 * that gives a signer ({key, sign}) for that method, in place of the key
 * file's key.
 */
export function readSettings(folder) {
  const files = sealerFiles(folder);
  const s = readJson(files.settings, 'The settings');
  if (s === null) throw new Error(`There are no settings (${files.settings}): run "provared-sealer init" first.`);
  if (typeof s !== 'object' || Array.isArray(s)) throw new Error('The settings must be a JSON object.');
  for (const name of Object.keys(s)) if (!['name', 'port', 'signers'].includes(name)) throw new Error(`The settings hold "${name}", which the sealer does not know.`);
  if (typeof s.name !== 'string' || s.name.length < 1 || s.name.length > 200) throw new Error('The settings\' "name" must be text of 1 to 200 characters: the name the seals give.');
  const port = s.port ?? DEFAULT_PORT;
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('The settings\' "port" must be a port number.');
  const signers = s.signers ?? {};
  if (typeof signers !== 'object' || signers === null || Array.isArray(signers)) throw new Error('The settings\' "signers" must be an object.');
  for (const [alg, path] of Object.entries(signers)) {
    if (!METHODS.includes(alg)) throw new Error(`The settings' "signers" name "${alg}", which is not one of ${METHODS.join(', ')}.`);
    if (typeof path !== 'string' || path.length === 0) throw new Error(`The settings' "signers.${alg}" must be the path of a module.`);
  }
  return { name: s.name, port, signers };
}

// --- keys ---

function publicOf(jwk) {
  if (jwk?.kty === 'OKP' && jwk.crv === 'Ed25519') return { alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: jwk.x };
  if (jwk?.kty === 'AKP' && jwk.alg === 'ML-DSA-87') return { alg: 'ML-DSA-87', kty: 'AKP', pub: jwk.pub };
  if (jwk?.kty === 'AKP' && jwk.alg === SLH) return { alg: SLH, kty: 'AKP', pub: jwk.pub };
  throw new Error('A key in the key file is of a kind the sealer does not keep.');
}

async function newPrivateJwk(alg) {
  if (alg === SLH) return { ...nodeCrypto.generateKeyPairSync('slh-dsa-sha2-256s').privateKey.export({ format: 'jwk' }), alg: SLH };
  const pair = await globalThis.crypto.subtle.generateKey({ name: alg }, true, ['sign', 'verify']);
  return globalThis.crypto.subtle.exportKey('jwk', pair.privateKey);
}

/**
 * Make the key file, if there is none, with a key for each method that the
 * settings do not give a signer module for. Written once, for the owner
 * alone; never replaced.
 */
export async function makeKeys(folder) {
  const files = sealerFiles(folder);
  if (existsSync(files.keys)) return false;
  const settings = readSettings(folder);
  const jwks = [];
  for (const alg of METHODS) if (!Object.hasOwn(settings.signers, alg)) jwks.push(await newPrivateJwk(alg));
  const about = 'The private keys with which this central sealer signs seals. Never share this file.';
  const fd = openSync(files.keys, 'wx', 0o600);
  try {
    writeSync(fd, JSON.stringify({ about, keys: jwks }));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  return true;
}

/**
 * The sealer's three signers, in the order of the key set, and its public
 * key set: each from the signer module the settings name for its method,
 * or from the key file. A key in memory is wrapped as a signer too, so that
 * every key takes one path.
 */
export async function loadSigners(folder) {
  const files = sealerFiles(folder);
  const settings = readSettings(folder);
  const needFile = METHODS.some((alg) => !Object.hasOwn(settings.signers, alg));
  let fileKeys = [];
  if (needFile) {
    const held = readJson(files.keys, 'The key file');
    if (held === null) throw new Error(`There is no key file (${files.keys}): run "provared-sealer init" first.`);
    if (!Array.isArray(held.keys)) throw new Error('The key file must hold a list of keys.');
    fileKeys = held.keys;
  }
  const keys = [];
  const signers = [];
  for (const alg of METHODS) {
    if (Object.hasOwn(settings.signers, alg)) {
      const path = settings.signers[alg];
      const url = pathToFileURL(isAbsolute(path) ? path : join(files.root, path)).href;
      const mod = await import(url);
      if (typeof mod.default !== 'function') throw new Error(`The signer module for ${alg} (${path}) must have a default export: an async function that gives a signer.`);
      const signer = await mod.default({ alg });
      if (signer === null || typeof signer !== 'object' || typeof signer.sign !== 'function') throw new Error(`The signer module for ${alg} gave no signer: an object with "key" and "sign".`);
      keys.push(publicOf(signer.key));
      signers.push(signer);
      continue;
    }
    const jwk = fileKeys.find((k) => (alg === 'Ed25519' ? k?.crv === 'Ed25519' : k?.alg === alg));
    if (!jwk) throw new Error(`The key file holds no ${alg} key, and the settings name no signer module for it.`);
    const key = publicOf(jwk);
    const privateKey = alg === SLH ? nodeCrypto.createPrivateKey({ key: jwk, format: 'jwk' }) : await globalThis.crypto.subtle.importKey('jwk', jwk, { name: alg }, false, ['sign']);
    keys.push(key);
    signers.push(signerFromKey(alg, privateKey, key));
  }
  return { by: { keys, name: settings.name }, signers, fingerprint: await keySetFingerprint(keys) };
}

// --- recorders ---

// One recorder's entry, read strictly: its token, the agents whose permissions it may start books with (the
// fingerprints of their key sets, 1 to 64, none twice), and the most books it may hold (100 unless it says).
function readRecorder(name, entry) {
  const where = `The recorder "${name}" in the list of recorders`;
  if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) throw new Error(`${where} must be an object: "token", "agents" and, if wanted, "books".`);
  for (const member of Object.keys(entry)) if (!['token', 'agents', 'books'].includes(member)) throw new Error(`${where} holds "${member}", which the sealer does not know.`);
  if (!isRandom(entry.token)) throw new Error(`The token of the recorder "${name}" is not 32 bytes in base64url.`);
  const agents = entry.agents;
  if (!Array.isArray(agents) || agents.length < 1 || agents.length > 64 || !agents.every(isRandom) || new Set(agents).size !== agents.length) {
    throw new Error(`${where} must name in "agents" 1 to 64 fingerprints of agents' key sets (each 32 bytes in base64url, none twice): the agents whose permissions it may start books with.`);
  }
  const books = entry.books ?? DEFAULT_RECORDER_BOOKS;
  if (!Number.isSafeInteger(books) || books < 1 || books > MAX_BOOKS) throw new Error(`${where} holds "books", which must be a whole number from 1 to 1,000.`);
  return { token: entry.token, agents: [...agents], books };
}

// Every recorder's entry, and the rules they keep together: an agent belongs to one recorder, and the books they may
// hold add up to no more than the sealer keeps. Books already in the state, a removed recorder's included, count
// towards the sealer's 1,000 too, so the recorders listed can still be refused before each reaches its own number.
function checkRecorders(recorders) {
  const owner = new Map();
  let total = 0;
  for (const [name, r] of Object.entries(recorders)) {
    for (const agent of r.agents) {
      if (owner.has(agent)) throw new Error(`The agent ${agent} is named by the recorders "${owner.get(agent)}" and "${name}": an agent belongs to one recorder.`);
      owner.set(agent, name);
    }
    total += r.books;
  }
  if (total > MAX_BOOKS) throw new Error(`The recorders may hold ${total} books in all, and the sealer keeps at most 1,000: lower some recorders' "books".`);
  return recorders;
}

function readRecorders(folder) {
  const files = sealerFiles(folder);
  const held = readJson(files.recorders, 'The list of recorders');
  if (held === null) return {};
  if (typeof held.recorders !== 'object' || held.recorders === null || Array.isArray(held.recorders)) throw new Error('The list of recorders must hold "recorders": an object.');
  const out = {};
  for (const [name, entry] of Object.entries(held.recorders)) {
    if (!RECORDER_NAME.test(name)) throw new Error(`The list of recorders holds "${name}", which is not a recorder's name.`);
    out[name] = readRecorder(name, entry);
  }
  return checkRecorders(out);
}

/**
 * Add a recorder: a token of 32 random bytes, kept in recorders.json (for
 * the owner alone), with the agents whose permissions it may start books
 * with (the fingerprints of their key sets; an agent belongs to one
 * recorder) and the most books it may hold (100 by default; the books of
 * all recorders add up to at most 1,000). Where there is no state yet, and
 * no recorder, an empty state is written, so that a state that goes missing
 * later is noticed. A name that has books in the state is refused: a
 * recorder's books are never taken over by a new one of the same name.
 * Gives back the token, to hand to the recorder once.
 * @param {string} folder
 * @param {string} name
 * @param {{agents: string[], books?: number}} rules
 */
export async function addRecorder(folder, name, { agents, books } = {}) {
  if (typeof name !== 'string' || !RECORDER_NAME.test(name)) throw new Error('A recorder\'s name is 1 to 63 small letters, digits and hyphens, beginning with a letter or a digit.');
  const files = sealerFiles(folder);
  const recorders = readRecorders(folder);
  if (Object.hasOwn(recorders, name)) throw new Error(`There is a recorder named "${name}" already.`);
  const token = toBase64url(nodeCrypto.randomBytes(32));
  const all = checkRecorders({ ...recorders, [name]: readRecorder(name, { token, agents, ...(books === undefined ? {} : { books }) }) });
  const saved = readJson(files.state, 'The state');
  if (saved === null) {
    if (Object.keys(recorders).length > 0) {
      throw new Error(`The state (${files.state}) is missing, though there are recorders. Put back the latest copy of it, or start with --fresh, before a recorder is added.`);
    }
    const { by, signers } = await loadSigners(folder);
    writeDurably(files.state, JSON.stringify((await openSealer({ by, signers })).state()));
  } else if (!Array.isArray(saved?.books)) {
    throw new Error(`The state (${files.state}) holds no list of books.`);
  } else if (saved.books.some((b) => b?.recorder === name)) {
    throw new Error(`The state holds books of a recorder named "${name}"; a recorder's books are never taken over by a new one of the same name.`);
  }
  writeDurably(files.recorders, JSON.stringify({ about: 'The token of each recorder this central sealer serves, the agents whose permissions it may start books with, and the most books it may hold. Never share this file.', recorders: all }));
  return token;
}

/**
 * Release the books that hold no seal, while the sealer is stopped: nothing
 * was signed for them, so taking them off the state frees their places, in
 * the limits of books, as the next book after another, and their first
 * lines. Only one recorder's, where a name is given. Gives back the books
 * released.
 * @param {string} folder
 * @param {string} [name]
 */
export async function releaseUnsealed(folder, name) {
  if (name !== undefined && (typeof name !== 'string' || !RECORDER_NAME.test(name))) throw new Error('A recorder\'s name is 1 to 63 small letters, digits and hyphens, beginning with a letter or a digit.');
  const files = sealerFiles(folder);
  const { by, signers } = await loadSigners(folder);
  takeLock(files.lock);
  try {
    const saved = readJson(files.state, 'The state');
    if (saved === null) throw new Error(`There is no state (${files.state}): there is nothing to release.`);
    const sealer = await openSealer({ by, signers, state: saved });
    const done = await sealer.releaseUnsealed(name === undefined ? {} : { recorder: name });
    if (done.released.length > 0) writeDurably(files.state, JSON.stringify(done.state));
    return done.released;
  } finally {
    letGo(files.lock);
  }
}

// --- one at a time on a folder ---

function takeLock(path) {
  const write = () => {
    const fd = openSync(path, 'wx', 0o600);
    try {
      writeSync(fd, String(process.pid));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  };
  try {
    write();
    return;
  } catch (e) {
    if (e.code !== 'EEXIST') throw e;
  }
  const pid = Number(readFileSync(path, 'utf8'));
  let alive = false;
  try {
    process.kill(pid, 0);
    alive = Number.isInteger(pid) && pid > 0;
  } catch (e) {
    alive = e.code === 'EPERM';
  }
  if (alive) throw new Error(`Another sealer (process ${pid}) runs on this folder. If it does not, delete ${path} by hand.`);
  // A sealer that ended without its lock taken off: the lock is taken over.
  writeDurably(path, String(process.pid));
}

// The lock taken off; one left behind is taken over at the next start.
function letGo(path) {
  try {
    rmSync(path, { force: true });
  } catch {
    // A lock left behind is taken over at the next start.
  }
}

// --- the service ---

const refusal = (code, message) => ({ refused: { code, message } });

/**
 * Start the sealer: read its keys, its recorders and its state, and listen
 * on 127.0.0.1.
 * @param {object} o
 * @param {string} o.folder
 * @param {number} [o.port] in place of the settings' port; 0 for any free port
 * @param {boolean} [o.fresh] where the state is missing, begin with none (every book's seals, if any, must then be brought in with update)
 * @param {(fingerprintBytes: Uint8Array) => any} [o.stamp] asks a time-stamp service for a stamp (see the library's openSealer)
 * @param {() => number} [o.clock]
 * @param {number} [o.signWithin]
 * @param {number} [o.maxNonces] the most numbers used once kept for one recorder (100,000; smaller in tests)
 * @param {number} [o.maxWaitingBytes] the most bytes of bodies one recorder may have waiting (32 MiB; smaller in tests)
 * @returns {Promise<{address: string, port: number, fingerprint: string, by: object, close: () => Promise<void>}>}
 */
export async function startSealer({ folder, port, fresh = false, stamp, clock = Date.now, signWithin, maxNonces = MAX_NONCES, maxWaitingBytes = MAX_WAITING_BYTES } = {}) {
  if (typeof fresh !== 'boolean') throw new Error('"fresh" must be true or false.');
  if (!Number.isSafeInteger(maxNonces) || maxNonces < 1) throw new Error('"maxNonces" must be a whole number, 1 or more.');
  if (!Number.isSafeInteger(maxWaitingBytes) || maxWaitingBytes < 1) throw new Error('"maxWaitingBytes" must be a whole number, 1 or more.');
  const files = sealerFiles(folder);
  const settings = readSettings(folder);
  const { by, signers, fingerprint } = await loadSigners(folder);
  const recorders = readRecorders(folder);
  takeLock(files.lock);
  let server;
  try {
    const saved = readJson(files.state, 'The state');
    let sealer;
    if (saved === null) {
      if (Object.keys(recorders).length > 0 && !fresh) {
        throw new Error(`The state (${files.state}) is missing. Put back the latest copy of it, or start with --fresh to begin with no state: then bring each book up to date (update) before it is sealed again.`);
      }
      sealer = await openSealer({ by, signers, stamp, clock, signWithin });
      writeDurably(files.state, JSON.stringify(sealer.state()));
    } else {
      if (fresh) throw new Error(`There is a state (${files.state}): --fresh begins only a state that is missing.`);
      sealer = await openSealer({ by, signers, stamp, clock, signWithin, state: saved });
    }
    // Each recorder: its token, its calls under its rules, the questions it has waiting and the bytes of their bodies,
    // the bytes of its bodies still being read, and its own numbers used once, each kept for as long as a question with
    // it could be taken again.
    /** @type {Map<string, {token: Buffer, view: any, waiting: number, waitingBytes: number, holding: number, nonces: Map<string, number>}>} */
    const served = new Map();
    for (const [name, r] of Object.entries(recorders)) {
      served.set(name, { token: Buffer.from(r.token, 'base64url'), view: sealer.forRecorder(name, { agents: r.agents, books: r.books }), waiting: 0, waitingBytes: 0, holding: 0, nonces: new Map() });
    }
    // The latest time the clock has given: a clock that never goes back. A question dated more than the window before it
    // is refused, and numbers used once are forgotten by it, so that a clock set back never lets a question be taken twice.
    let latestSeen = -Infinity;
    const readClock = () => {
      const now = clock();
      if (Number.isFinite(now) && now > latestSeen) latestSeen = now;
      return now;
    };
    const timely = (at, now) => Math.abs(at - now) <= QUESTION_WINDOW_MS && at >= latestSeen - QUESTION_WINDOW_MS;
    const forget = (one) => {
      for (const [n, until] of one.nonces) {
        if (until > latestSeen) break;
        one.nonces.delete(n);
      }
    };
    let stopped = null;
    // One question at a time, for every recorder: one state.
    let queue = Promise.resolve();

    const save = (state) => {
      try {
        writeDurably(files.state, JSON.stringify(state));
      } catch (e) {
        stopped = `The state could not be saved (${e.code ?? e.message}). The sealer answers nothing more until it is started again.`;
        throw e;
      }
    };

    const leavesOf = (list) => {
      if (!Array.isArray(list)) return null;
      const out = [];
      for (const item of list) {
        if (!isRandom(item)) return null;
        out.push(fromBase64url(item));
      }
      return out;
    };

    // One question, for one recorder, in its turn: the library's answer, with the state saved first where a change must last.
    async function answer(name, path, body) {
      const { view } = served.get(name);
      if (body === null || typeof body !== 'object' || Array.isArray(body)) return refusal('bad-field', 'The body must be a JSON object.');
      // A member the path does not take is refused, never set aside, as the library refuses one in its options (choice K69).
      const known = MEMBERS[path];
      if (Object.keys(body).some((member) => !known.includes(member))) {
        return refusal('bad-field', `body: holds a member that a question to ${path} does not take. It takes ${known.length === 0 ? 'none' : known.join(', ')}.`);
      }
      if (path === '/about') return { name: by.name, keys: by.keys, sealer: fingerprint };
      if (path === '/latest') return { latest: view.latest(body.book) };
      if (path === '/held') return { held: view.held(body.book) };
      if (path === '/extend') {
        const leaves = leavesOf(body.leaves);
        if (leaves === null) return refusal('bad-field', 'leaves: must be a list of leaf fingerprints, each 32 bytes in base64url.');
        const more = {};
        if (body.follows !== undefined) more.follows = body.follows;
        if (body.line !== undefined) more.line = body.line;
        const got = await view.extend(body.book, body.at, leaves, more);
        if (got.refused) return got;
        // A book started binds its first line, its recorder and the book it follows.
        if (got.state) save(got.state);
        return { size: got.size };
      }
      if (path === '/update') {
        const leaves = leavesOf(body.leaves);
        if (leaves === null) return refusal('bad-field', 'leaves: must be a list of leaf fingerprints, each 32 bytes in base64url.');
        const got = await view.update(body.book, body.entry, leaves, body.line === undefined ? {} : { line: body.line });
        if (got.refused) return got;
        save(got.state);
        return { size: got.size };
      }
      // /seal: never given out before the state that holds it is saved.
      const more = { previous: body.previous };
      if (body.when !== undefined) more.when = body.when;
      const got = await view.seal(body.book, more);
      if (got.refused) return got;
      save(got.state);
      const given = { entry: got.entry, line: got.line, fingerprint: got.fingerprint };
      if (got.stampProblem) given.stampProblem = got.stampProblem;
      return given;
    }

    const reply = (res, status, body, key = null, proof = null) => {
      const bytes = Buffer.from(JSON.stringify(body));
      const headers = { 'content-type': 'application/json', 'cache-control': 'no-store' };
      if (key) headers['provared-sealer-proof'] = sealerHmac(key, LABELS.answer, proof, String(status), sha256(bytes)).toString('base64url');
      res.writeHead(status, headers);
      res.end(bytes);
    };

    const NOT_PROVED = refusal('not-proved', 'The question did not prove that it comes from a recorder this sealer serves.');

    server = http.createServer((req, res) => {
      // An answer given before the body is read: whatever more of the body arrives is let go, never held, and the
      // connection is closed after it.
      const early = (status, body) => {
        res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', connection: 'close' });
        res.end(JSON.stringify(body));
        req.resume();
      };
      if (req.method !== 'POST' || !PATHS.includes(req.url)) return early(404, refusal('not-found', 'The sealer answers POST to /about, /extend, /seal, /update, /latest and /held.'));
      // Who asks, proved without the token being sent. All that can be checked before the body is checked first, the
      // first proof included: it covers the body's declared length, so only a program that holds the token has a body
      // read under a recorder's name.
      const name = req.headers['provared-sealer-recorder'];
      const time = req.headers['provared-sealer-time'];
      const nonce = req.headers['provared-sealer-nonce'];
      const head = req.headers['provared-sealer-head'];
      const given = req.headers['provared-sealer-proof'];
      const declared = req.headers['content-length'];
      const one = typeof name === 'string' ? served.get(name) : undefined;
      const at = /^[0-9]{1,16}$/.test(time ?? '') ? Number(time) : NaN;
      // A body is sent with its length declared, never in pieces of unknown length.
      const length = req.headers['transfer-encoding'] === undefined && /^[0-9]{1,16}$/.test(declared ?? '') ? Number(declared) : NaN;
      const now = readClock();
      if (one) forget(one);
      if (!one || !isRandom(nonce) || !isRandom(given) || !Number.isSafeInteger(length) || !timely(at, now) || one.nonces.has(nonce)) return early(401, NOT_PROVED);
      if (!sameProof(head, sealerHmac(one.token, LABELS.head, name, req.url, time, nonce, declared))) return early(401, NOT_PROVED);
      if (length > MAX_BODY_BYTES) return early(413, refusal('too-large', 'The body is larger than 8 MiB.'));
      // The body, at most 8 MiB, held only while this recorder's bodies still being read add up to at most 16 MiB.
      const chunks = [];
      let size = 0;
      let over = false;
      let held = true;
      const release = () => {
        if (held) {
          held = false;
          one.holding -= size;
        }
      };
      req.on('close', release);
      req.on('data', (chunk) => {
        if (over) return;
        // "size + chunk.length > MAX_BODY_BYTES" is a second guard, which no question reaches (choice K71): the declared
        // length is checked against 8 MiB above, and Node.js reads exactly that many bytes of a body.
        if (size + chunk.length > MAX_BODY_BYTES || one.holding + chunk.length > MAX_HELD_BYTES) {
          over = true;
          const tooLarge = size + chunk.length > MAX_BODY_BYTES;
          release();
          chunks.length = 0;
          if (tooLarge) early(413, refusal('too-large', 'The body is larger than 8 MiB.'));
          else early(503, refusal('busy', 'The sealer holds as many bodies for this recorder as it takes at once. Ask again later.'));
          return;
        }
        size += chunk.length;
        one.holding += chunk.length;
        chunks.push(chunk);
      });
      req.on('end', async () => {
        if (over) return;
        const body = Buffer.concat(chunks);
        chunks.length = 0;
        release();
        const expected = sealerHmac(one.token, LABELS.question, name, req.url, time, nonce, sha256(body));
        if (!sameProof(given, expected)) return reply(res, 401, NOT_PROVED);
        if (stopped) return reply(res, 503, refusal('sealer-stopped', stopped), one.token, given);
        // Proved. Its time and its number checked again, the numbers no longer needed forgotten first, and the number kept
        // with nothing awaited between: no two questions with one number are both taken, however long a body took.
        const later = readClock();
        forget(one);
        if (!timely(at, later) || one.nonces.has(nonce)) return reply(res, 401, NOT_PROVED);
        // Turned away while it is busy before its number used once is kept, and before its body is read as JSON: a
        // question that is refused is not acted on, and every call is guarded by its place or its seal, so one taken
        // later changes nothing twice.
        if (one.waiting >= MAX_WAITING) return reply(res, 503, refusal('busy', 'This recorder has 16 questions waiting already. Ask again later.'), one.token, given);
        if (one.waitingBytes + body.length > maxWaitingBytes) return reply(res, 503, refusal('busy', 'This recorder has as many bytes of questions waiting as the sealer holds for it. Ask again later.'), one.token, given);
        if (one.nonces.size >= maxNonces) return reply(res, 503, refusal('busy', 'This recorder has asked too many questions in the last minutes. Ask again later.'), one.token, given);
        // Kept until the clock that never goes back passes the question's time and the window: no clock the sealer could
        // then read would take it.
        one.nonces.set(nonce, Math.max(at, latestSeen) + QUESTION_WINDOW_MS + 1);
        one.waiting++;
        one.waitingBytes += body.length;
        const run = queue.then(async () => {
          if (stopped) return { status: 503, body: refusal('sealer-stopped', stopped) };
          // Read as JSON only in its turn: while it waits, a body is its bytes only, so one parsed body exists at a time.
          let parsed = {};
          if (body.length > 0) {
            try {
              parsed = JSON.parse(body.toString('utf8'));
            } catch {
              return { status: 400, body: refusal('bad-field', 'The body is not JSON.') };
            }
          }
          try {
            return { status: 200, body: await answer(name, req.url, parsed) };
          } catch {
            return { status: 503, body: refusal('sealer-stopped', stopped ?? 'The sealer met something it did not expect, and gave nothing.') };
          }
        });
        queue = run.catch(() => {});
        const done = await run;
        one.waiting--;
        one.waitingBytes -= body.length;
        reply(res, done.status, done.body, one.token, given);
      });
    });
    server.requestTimeout = 60000;
    server.headersTimeout = 30000;
    const listenPort = port ?? settings.port;
    await new Promise((ok, fail) => {
      server.once('error', fail);
      server.listen(listenPort, '127.0.0.1', ok);
    });
    const actual = server.address().port;
    return {
      address: `http://127.0.0.1:${actual}`,
      port: actual,
      fingerprint,
      by,
      async close() {
        await new Promise((ok) => server.close(() => ok()));
        server.closeAllConnections?.();
        try {
          rmSync(files.lock, { force: true });
        } catch {
          // A lock left behind is taken over at the next start.
        }
      },
    };
  } catch (e) {
    server?.close();
    try {
      rmSync(files.lock, { force: true });
    } catch {
      // A lock left behind is taken over at the next start.
    }
    throw e;
  }
}

// --- a recorder's side ---

/**
 * Connect to a central sealer, as a recorder. "address" must be
 * http://127.0.0.1:<port>. Every answer must prove that it comes from a
 * sealer that holds the token, or the call throws. The methods give the
 * library's answers (openSealer), with leaf fingerprints as bytes. Their
 * "more" may hold what the program takes beside the method's own members:
 * extend "follows" and "line"; seal "previous" (required) and "when" (a
 * number of milliseconds, or a Date); update "line". Any other member, the
 * library's "id" for a seal among them, is refused (bad-field) and nothing
 * is sent.
 * @param {{address: string, recorder: string, token: string, fetchImpl?: typeof fetch, clock?: () => number}} o
 */
export function connectSealer({ address, recorder, token, fetchImpl = fetch, clock = Date.now }) {
  if (typeof address !== 'string' || !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(address)) throw new Error('The sealer\'s address must be http://127.0.0.1:<port>.');
  if (!RECORDER_NAME.test(recorder ?? '')) throw new Error('The recorder\'s name is 1 to 63 small letters, digits and hyphens.');
  if (!isRandom(token)) throw new Error('The token must be 32 bytes in base64url.');
  const key = Buffer.from(token, 'base64url');
  async function ask(path, body = {}) {
    const bytes = Buffer.from(JSON.stringify(body));
    const time = String(Math.floor(clock()));
    const nonce = toBase64url(nodeCrypto.randomBytes(32));
    const head = sealerHmac(key, LABELS.head, recorder, path, time, nonce, String(bytes.length)).toString('base64url');
    const proof = sealerHmac(key, LABELS.question, recorder, path, time, nonce, sha256(bytes)).toString('base64url');
    // The body goes as bytes, so its length is declared (Content-Length), as the first proof says.
    const r = await fetchImpl(new URL(path, address), {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'provared-sealer-recorder': recorder, 'provared-sealer-time': time, 'provared-sealer-nonce': nonce, 'provared-sealer-head': head, 'provared-sealer-proof': proof },
      body: bytes,
    });
    const answer = Buffer.from(await r.arrayBuffer());
    if (answer.length > MAX_BODY_BYTES) throw new Error('The sealer\'s answer is larger than an answer may be.');
    if (!sameProof(r.headers.get('provared-sealer-proof'), sealerHmac(key, LABELS.answer, proof, String(r.status), sha256(answer)))) {
      // A sealer that holds too many bodies at once says so before it has read the question, so with no proof. Nothing it
      // says is used either; but what to do is to ask again later, not to look for an impostor.
      if (r.status === 503) {
        throw Object.assign(new Error('The sealer answered that it is busy (status 503), before it could prove the answer. Nothing it says is used. Ask again later.'), { code: 'busy', status: 503 });
      }
      throw new Error(`The answer did not prove that it comes from the sealer that holds the token (status ${r.status}). Nothing it says is used.`);
    }
    const parsed = JSON.parse(answer.toString('utf8'));
    if (r.status !== 200) throw Object.assign(new Error(parsed?.refused?.message ?? `The sealer answered ${r.status}.`), { code: parsed?.refused?.code, status: r.status });
    return parsed;
  }
  const b64 = (leaves) => leaves.map((l) => toBase64url(l));
  // What "more" may hold, for each call: the members the program takes for that path (MEMBERS) other than the fixed ones
  // the method writes itself ("book", "at", "leaves", "entry"); "previous" must be given to seal, as the library requires.
  // Any other member is refused here, in the library's words and code, and nothing is sent: so "more" can never stand in
  // place of a fixed member, and "id", which the library's seal takes and the program does not, is refused before it
  // travels (choice K77).
  function moreOf(path, fixed, more) {
    const required = path === '/seal' ? ['previous'] : [];
    const takes = MEMBERS[path].filter((name) => !Object.hasOwn(fixed, name));
    const no = (message) => ({ refused: { code: 'bad-field', message: `more: ${message}` } });
    if (more === null || typeof more !== 'object' || Array.isArray(more)) return no('must be an object.');
    for (const name of required) if (!Object.hasOwn(more, name)) return no(`"${name}" is missing.`);
    const out = {};
    for (const name of Object.keys(more)) {
      if (!takes.includes(name)) {
        const why = name === 'id' ? ' ("id": the sealer makes the seal\'s id itself)' : '';
        return no(`holds a member that a question to ${path} does not take${why}. It takes ${takes.join(', ')}.`);
      }
      out[name] = more[name];
    }
    // A time may be given as a Date, as the library takes it; it travels as its milliseconds (choice K78).
    if (out.when instanceof Date) out.when = out.when.getTime();
    return { out };
  }
  // The fixed members are written after what "more" gave, so that not even a member let through by mistake could replace them.
  async function askWith(path, fixed, more) {
    const got = moreOf(path, fixed, more);
    if (got.refused) return got;
    return ask(path, { ...got.out, ...fixed });
  }
  return {
    about: () => ask('/about'),
    extend: async (book, at, leaves, more = {}) => askWith('/extend', { book, at, leaves: b64(leaves) }, more),
    seal: async (book, more) => askWith('/seal', { book }, more),
    update: async (book, entry, leaves, more = {}) => askWith('/update', { book, entry, leaves: b64(leaves) }, more),
    latest: async (book) => (await ask('/latest', { book })).latest,
    held: async (book) => (await ask('/held', { book })).held,
  };
}
