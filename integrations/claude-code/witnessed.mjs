// The recorder's side of witnesses (format description, section 29): after
// each seal, it asks the witnesses named in its folder's witnesses.json to
// sign for the seal, and keeps the statements they hand back.
//
// WHERE A STATEMENT GOES. A line of a book is never changed once written, so
// a statement can stand beside its seal, on the seal's own line, only where
// it comes before that line is written. The recorder asks in time only for a
// seal asked for by "seal" (the command, or POST /seal): it first keeps the
// seal's entry on the disk apart from the book (pending-seal.json), so that
// a witness never signs for a seal that a stop could leave out of the book,
// then waits up to five seconds for the witnesses, and writes the line with
// the statements that came. It waits for no longer than it takes another
// request to arrive: a tool call never waits for a witness. Every other
// statement (one that comes later, and every statement for a seal made at a
// new book, or after a late call) is kept beside the book, in the folder
// "witnessed", one file for each seal, in the form a checker takes
// ({"seal", "witnesses"}, handed over with --seal); "check" hands them over.
//
// WHAT IS SENT. Only seals whose line is on the disk (made sure with fsync),
// or the seal kept apart as above, in order: a witness that holds an earlier
// seal of the same person, agent and recorder is shown each seal after it,
// one by one, as it requires; one that holds none is shown the latest seal
// only (it signs whatever it is first shown). With each, the proof RFC 9162
// sets out, made from the book's leaf hashes kept as the book grows
// (proofs.mjs), and the book's first line. A witness is first asked what it
// holds and whether it signs now: nothing is worked out for one that does not.
//
// A statement is taken only where the library's own checker passes it, for
// that seal, as signed by the witness named (checkShow, on a Show of the
// book's first line under the seal). A witness that is down, that refuses,
// or that hands back what does not pass, never stops recording: "status"
// says what each witness holds and why it is behind, and the recorder asks
// again after its next seal, and every minute while one is behind.

import { existsSync, mkdirSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { bookIdentity, checkShow, fingerprint, fromBase64url, keySetFingerprint, toBase64url, utf8 } from 'provared';
import { bookTree } from './proofs.mjs';
import { isRandom } from './feed.mjs';
import { replaceDurably, witnessClient } from './witness.mjs';

export const WITNESSES_FILE = 'witnesses.json';
export const WITNESSED_FOLDER = 'witnessed';
/** At most this many witnesses are named: a seal's line holds at most four statements. */
export const MAX_RECORDER_WITNESSES = 4;
/** A checker takes at most this many seals handed over beside a book. */
export const MAX_HELD_SEALS = 64;
/** How long "seal" waits for the witnesses before it writes the seal's line, unless another request arrives first. */
export const WITNESS_WAIT_MS = 5000;
/** How often the recorder asks again while a witness is behind. */
export const WITNESS_RETRY_MS = 60000;

const FINGERPRINT = /^[A-Za-z0-9_-]{43}$/;
const ADDRESS = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/;
const SEAL_LINE = '\n{"seal":';

const decoded = (record) => JSON.parse(Buffer.from(record.payload, 'base64url').toString('utf8'));
/** The fingerprint of the key set that signed a record, read from the record itself. */
const signerOf = async (record) => keySetFingerprint(decoded(record).by.keys);
const firstLineOf = (text) => {
  const end = text.indexOf('\n');
  return (end < 0 ? text : text.slice(0, end)).replace(/\r$/, '');
};

/** Whether an address is one this recorder asks: http://127.0.0.1:<port>, a port from 1 to 65535. */
export function validAddress(address) {
  const m = typeof address === 'string' ? ADDRESS.exec(address) : null;
  return !!m && Number(m[1]) <= 65535;
}

/**
 * The witnesses named in the folder's witnesses.json, checked: each with its
 * address, the fingerprint of the key set it must sign with, and the token
 * it is asked with. A file that does not pass names none, and says why.
 * @returns {{path: string, list: {address: string, key: string, token: string}[], problem: string|null}}
 */
export function readWitnessSettings(folder) {
  const path = join(folder, WITNESSES_FILE);
  if (!existsSync(path)) return { path, list: [], problem: null };
  const bad = (why) => ({ path, list: [], problem: `${path} ${why}, so no witness is asked.` });
  let value;
  try {
    value = JSON.parse(readFileSync(path, 'utf8').replace(/^﻿/, ''));
  } catch {
    return bad('is not JSON');
  }
  const list = value?.witnesses;
  if (!Array.isArray(list) || list.length > MAX_RECORDER_WITNESSES) return bad(`must hold "witnesses", a list of at most ${MAX_RECORDER_WITNESSES}`);
  const seen = new Set();
  for (const w of list) {
    if (!w || typeof w !== 'object' || !validAddress(w.address)) return bad('names a witness whose address is not http://127.0.0.1:<port>');
    if (typeof w.key !== 'string' || !FINGERPRINT.test(w.key)) return bad('names a witness without the fingerprint of its key set ("key")');
    if (!isRandom(w.token)) return bad('names a witness without a token ("token", 43 letters, digits, "-" and "_")');
    if (seen.has(w.key)) return bad('names one witness twice');
    seen.add(w.key);
  }
  return { path, list: list.map(({ address, key, token }) => ({ address, key, token })), problem: null };
}

/** Write the witnesses a recorder asks, readable by its owner alone (on Windows, as the folder allows). */
export function writeWitnessSettings(folder, list) {
  mkdirSync(folder, { recursive: true });
  const about = 'The witnesses this recorder asks to sign for its seals: the address of each, the fingerprint of the key set it signs with, and the token it is asked with (never share this file). Written by add-witness.';
  replaceDurably(join(folder, WITNESSES_FILE), `${JSON.stringify({ about, witnesses: list }, null, 2)}\n`);
}

// One write at a time to each file kept beside the book: two witnesses that
// answer at the same moment each read the file and write it again, and
// without this the second would write over the first's statement.
const keeping = new Map();

/**
 * Keep a witness's statement for a seal beside the book: in the folder
 * "witnessed", as {"seal", "witnesses"}, one file for each seal, at most one
 * statement from each witness and four in all.
 * @returns {Promise<boolean>} whether it was added
 */
export function keepStatement(folder, sealFingerprint, seal, statement) {
  const path = join(folder, WITNESSED_FOLDER, `${sealFingerprint}.json`);
  const run = (keeping.get(path) ?? Promise.resolve()).then(() => keepNow(folder, path, seal, statement));
  const done = run.catch(() => {});
  keeping.set(path, done);
  done.then(() => {
    if (keeping.get(path) === done) keeping.delete(path);
  });
  return run;
}

async function keepNow(folder, path, seal, statement) {
  mkdirSync(join(folder, WITNESSED_FOLDER), { recursive: true });
  let witnesses = [];
  try {
    const v = JSON.parse(readFileSync(path, 'utf8'));
    if (v?.seal?.payload === seal.payload && Array.isArray(v.witnesses)) witnesses = v.witnesses;
  } catch {
    // None kept yet for this seal.
  }
  const key = await signerOf(statement);
  for (const s of witnesses) {
    try {
      if ((await signerOf(s)) === key) return false;
    } catch { /* not a statement that can be read */ }
  }
  if (witnesses.length >= MAX_RECORDER_WITNESSES) return false;
  replaceDurably(path, `${JSON.stringify({ seal, witnesses: [...witnesses, statement] })}\n`);
  return true;
}

/** Whether a statement of this witness for this seal is kept beside the book already. */
async function keptAlready(folder, sealFingerprint, key) {
  try {
    const v = JSON.parse(readFileSync(join(folder, WITNESSED_FOLDER, `${sealFingerprint}.json`), 'utf8'));
    for (const s of Array.isArray(v.witnesses) ? v.witnesses : []) {
      try {
        if ((await signerOf(s)) === key) return true;
      } catch { /* not a statement that can be read */ }
    }
  } catch {
    // None kept for this seal.
  }
  return false;
}

/**
 * The files of the seals of a book that are kept beside it with statements,
 * for a checker (--seal): only seals that stand on a line of this book, the
 * latest 64 of them.
 */
export function heldSealFiles(folder, bookText) {
  const dir = join(folder, WITNESSED_FOLDER);
  let names = [];
  try { names = readdirSync(dir); } catch { /* none kept */ }
  const found = [];
  for (const name of names) {
    if (!/^[A-Za-z0-9_-]{43}\.json$/.test(name)) continue;
    const path = join(dir, name);
    try {
      const v = JSON.parse(readFileSync(path, 'utf8'));
      if (typeof v?.seal?.payload !== 'string' || !Array.isArray(v.witnesses) || v.witnesses.length === 0) continue;
      if (!bookText.includes(`${SEAL_LINE}{"payload":"${v.seal.payload}"`)) continue;
      found.push({ path, size: decoded(v.seal).size });
    } catch {
      // Not a file this recorder writes.
    }
  }
  return found.sort((a, b) => a.size - b.size).slice(-MAX_HELD_SEALS).map((x) => x.path);
}

/**
 * The seals of a book's text that the recorder signed, in order: from
 * "from" on (a place in the text where a line ends), added to "into".
 */
async function sealsIn(text, recorder, from = 0, into = []) {
  for (let at = text.indexOf(SEAL_LINE, from); at >= 0; at = text.indexOf(SEAL_LINE, at + 1)) {
    const end = text.indexOf('\n', at + 1);
    if (end < 0) break;
    try {
      const value = JSON.parse(text.slice(at + 1, end));
      const content = decoded(value.seal);
      if (content.type !== 'provared.seal.v0' || (await keySetFingerprint(content.by.keys)) !== recorder) continue;
      const on = [];
      for (const s of Array.isArray(value.witnesses) ? value.witnesses : []) {
        try { on.push(await signerOf(s)); } catch { /* not a statement that can be read */ }
      }
      into.push({ record: value.seal, fingerprint: await fingerprint(fromBase64url(value.seal.payload)), content, number: Number.isInteger(content.book) ? content.book : 1, size: content.size, end, on });
    } catch {
      // Not a seal that can be read: the checker reports it.
    }
  }
  return into;
}

/**
 * Whether a statement passes the library's own checker for this seal, as
 * signed by this witness: on a Show of the book's first line under the seal.
 * @param {{record: object, fingerprint: string, content: object}} seal
 * @param {string} first the book's first line
 * @param {Uint8Array[]} path the audit path of the first line in the seal's tree
 */
export async function statementPasses(seal, first, path, statement, key) {
  const show = { type: 'provared.show.v0', size: seal.content.size, root: seal.content.root, pages: [{ index: 0, entry: first, path: path.map(toBase64url) }], seal: { seal: seal.record, witnesses: [statement] } };
  const result = await checkShow(show);
  const e = result.entries.at(-1);
  const w = e?.kind === 'seal' && e.fingerprint === seal.fingerprint && Array.isArray(e.witnesses) ? e.witnesses[0] : null;
  return !!w && w.state === 'valid' && w.witness === key;
}

/**
 * The tree of each book, kept as the book grows (proofs.mjs), so that a
 * proof never hashes a book again. A book the recorder holds ("memory") is
 * known by its key, and its tree is kept only while the recorder still
 * holds that book: once it no longer stands among the books as one the
 * recorder holds (it was kept, and nothing allowed under it can still come
 * back), its tree is let go at the next use of any tree; it is made again
 * from its file if it is needed. A kept book read from its file ("file") has
 * its tree kept while its file is the same version, two such books at most;
 * once built, its file is not read again while the version stays the same
 * (a kept book is never written again).
 * So the trees held are those of the book in force, the books held open
 * beside it, and two kept books: a few megabytes each, not one for every
 * book the recorder has held since it started.
 * @param {() => {key: string, kind: 'memory'|'file', text: () => string, version: () => string|number}[]} books
 */
export function proofTrees(books) {
  const trees = new Map();
  return {
    /** The tree of book "b", extended with its text as it now stands (or "text", where given). */
    async of(b, text) {
      let t = trees.get(b.key);
      const version = b.kind === 'file' ? b.version() : null;
      if (!t || t.version !== version) {
        t = { tree: bookTree(), version, chain: Promise.resolve() };
        trees.set(b.key, t);
        const files = [...trees.entries()].filter(([, v]) => v.version !== null);
        while (files.length > 2) trees.delete(files.shift()[0]);
      }
      // The trees of books the recorder holds no more are let go.
      const held = new Set(books().filter((x) => x.kind === 'memory').map((x) => x.key));
      for (const [key, v] of trees) if (v.version === null && key !== b.key && !held.has(key)) trees.delete(key);
      // A kept book is never written again: once its tree is built, and its file is the same version, its file is
      // not read again.
      if (t.version !== null && t.built) return t.tree;
      // One extension of a tree at a time: two at once would each add the same lines.
      const step = t.chain.then(async () => {
        if (t.version !== null && t.built) return;
        await t.tree.extend(text ?? b.text());
        t.built = true;
      });
      t.chain = step.catch(() => {});
      await step;
      return t.tree;
    },
    /** The keys of the books whose trees are held (for the tests). */
    keys: () => [...trees.keys()],
  };
}

const problemFrom = (e) =>({ code: e.code ?? 'failed', message: e.message, at: new Date().toISOString() });
const refusalOf = (answer) => Object.assign(new Error(answer.body?.refused?.message ?? answer.body?.error ?? `the witness answered ${answer.code}`), { code: answer.body?.refused?.code ?? answer.body?.code ?? String(answer.code) });

/**
 * The recorder's witnesses.
 * @param {object} o
 * @param {string} o.folder the recorder's folder
 * @param {{keys: object[], fingerprint: string}} o.recorder the recorder's key set, and its fingerprint
 * @param {() => {key: string, kind: 'memory'|'file', text: () => string, firstLine: () => string|null, durable: () => number, version: () => string|number}[]} o.books
 *   the recorder's books, oldest first, the one in force last; "durable" is how much of the text (in characters)
 *   is known to be on the disk
 * @param {number} [o.timeoutMs] the longest one question waits
 * @param {number} [o.retryMs] how often to ask again while a witness is behind
 */
export function createWitnessing({ folder, recorder, books, timeoutMs = 10000, retryMs = WITNESS_RETRY_MS }) {
  const workers = new Map();
  const abort = new AbortController();
  let settingsProblem = null;
  let started = false;
  let closed = false;
  // The seal kept apart while "seal" waits for the witnesses, if any.
  let pending = null;
  const cache = new Map();

  function workersNow() {
    const { list, problem } = readWitnessSettings(folder);
    settingsProblem = problem;
    for (const key of [...workers.keys()]) if (!list.some((w) => w.key === key)) workers.delete(key);
    for (const s of list) {
      const w = workers.get(s.key);
      if (w && w.address === s.address && w.token === s.token) continue;
      workers.set(s.key, {
        key: s.key,
        address: s.address,
        token: s.token,
        client: witnessClient({ address: s.address, token: s.token, timeoutMs, signal: abort.signal }),
        chain: Promise.resolve(),
        held: undefined, // what it holds of the sequence in force, as last seen: undefined (not known), null (nothing), or the seal
        problem: null,
        lastStatementAt: null,
        running: false,
        again: false,
      });
    }
    return [...workers.values()];
  }
  // One question at a time to each witness.
  const exclusive = (w, work) => {
    const run = w.chain.then(work);
    w.chain = run.catch(() => {});
    return run;
  };

  // The seals of a book, found once and then as the book grows.
  async function sealsOf(b) {
    const version = b.version();
    const c = cache.get(b.key);
    if (c && c.version === version) return c.seals;
    const text = b.text();
    let seals;
    if (c && b.kind === 'memory' && text.length > c.length && text.slice(c.length - 64, c.length) === c.tail) seals = await sealsIn(text, recorder.fingerprint, c.length - 1, c.seals.slice());
    else seals = await sealsIn(text, recorder.fingerprint);
    cache.set(b.key, { version, length: text.length, tail: text.slice(Math.max(0, text.length - 64)), seals });
    return seals;
  }

  // The books of the sequence of the book in force (its recorder, and the person and agent its first line names), in order.
  async function sequenceNow() {
    const all = books();
    const ids = new Map();
    const idOf = async (b) => {
      const line = b.firstLine();
      if (!line) return null;
      if (!ids.has(line)) {
        try { ids.set(line, await bookIdentity(recorder.keys, utf8(line))); } catch { ids.set(line, null); }
      }
      return ids.get(line);
    };
    const identity = await idOf(all.at(-1));
    if (!identity) return null;
    const members = [];
    for (const b of all) {
      if ((await idOf(b)) !== identity) continue;
      // Each book's text is read at most once in a round.
      let text;
      members.push({ ...b, text: () => (text ??= b.text()) });
    }
    return { identity, books: members };
  }

  /** Check a statement, and put it where it goes: in the slot of the seal waiting for its line, or beside the book. */
  async function accept(w, seal, first, path, statement, slot) {
    if (!(await statementPasses(seal, first, path, statement, w.key))) {
      throw Object.assign(new Error('The witness handed back a statement that does not pass the library\'s check for this seal, or is not signed with the key set named for it. It is not kept.'), { code: 'witness-invalid' });
    }
    w.lastStatementAt = new Date().toISOString();
    if (slot?.open) {
      slot.arrived.push({ key: w.key, statement });
      return;
    }
    if (!seal.on?.includes(w.key)) await keepStatement(folder, seal.fingerprint, seal.record, statement);
  }

  const trees = proofTrees(books);
  const treeOf = (b, text) => trees.of(b, text);
  // The proof a witness that holds "held" needs for seal "s": a consistency proof from the seal it holds, in the
  // same book; the audit path of the first line, at first contact and for the first seal of the next book.
  const proofFor = (tree, s, held) => (held && held.number === s.number ? tree.consistency(held.size, s.size) : tree.path(0, s.size));
  // What a witness holds, and whether it signs now; nothing is worked out for one that does not.
  async function holding(w, identity) {
    const r = await w.client.ask('GET', `/latest?sequence=${identity}`);
    if (r.code !== 200) throw refusalOf(r);
    if (r.body.ready !== true) throw Object.assign(new Error('The witness signs nothing until its operator says that its folder was not put back to an older copy (provared-witness ready).'), { code: 'witness-not-ready' });
    return r.body.latest ?? null;
  }

  // Bring one witness up to date with the sequence of the book in force.
  async function catchUp(w) {
    const seq = await sequenceNow();
    if (!seq) {
      w.held = undefined;
      return;
    }
    const latest = await holding(w, seq.identity);
    const heldFingerprint = latest ? await fingerprint(fromBase64url(latest.seal.payload)) : null;
    // The seal that "seal" is waiting with: its line follows, and it is shown nothing more until then.
    if (pending && pending.fingerprint === heldFingerprint) return;
    // The seals of the sequence whose lines are on the disk, in order, read
    // from the newest book back only as far as the seal the witness holds (or,
    // for a witness that holds none, the latest seal); and those not yet on
    // the disk.
    const all = [];
    const notYet = [];
    for (let i = seq.books.length - 1; i >= 0; i--) {
      const b = seq.books[i];
      const durable = b.durable();
      const seals = (await sealsOf(b)).map((s) => ({ ...s, book: b }));
      all.unshift(...seals.filter((s) => s.end < durable));
      notYet.push(...seals.filter((s) => s.end >= durable));
      if (heldFingerprint ? all.some((s) => s.fingerprint === heldFingerprint) : all.length > 0) break;
    }
    let held = null;
    let start;
    if (latest) {
      const at = all.findIndex((s) => s.fingerprint === heldFingerprint);
      if (at < 0 && notYet.some((s) => s.fingerprint === heldFingerprint)) {
        // Asked in time about a seal whose line could not yet be saved: no seal is sent until it is on the disk.
        throw Object.assign(new Error('The witness holds the latest seal, whose line is not yet on the disk (the book file was held by another program): no seal is sent to it until the line is on the disk.'), { code: 'seal-not-yet-on-the-disk' });
      }
      if (at < 0) {
        w.held = null;
        throw Object.assign(new Error(`The witness holds a seal of this recorder, person and agent (${heldFingerprint}) that is in none of the recorder's books on the disk, so it signs for none of the seals that follow it here, and no seal is sent to it; it is asked again each minute what it holds. Either a book was moved, cut short or replaced, or the witness was shown another history.`), { code: 'witness-holds-another' });
      }
      held = all[at];
      // The statement it holds for that seal, kept where none is (as after a stop that came before it was kept).
      if (!held.on.includes(w.key) && !(await keptAlready(folder, held.fingerprint, w.key))) {
        const tree = await treeOf(held.book);
        await accept(w, held, held.book.firstLine(), tree.path(0, held.size), latest.statement, null);
      }
      start = at + 1;
    } else {
      start = Math.max(0, all.length - 1);
    }
    for (let i = start; i < all.length; i++) {
      const s = all[i];
      const tree = await treeOf(s.book);
      const answer = await w.client.ask('POST', '/witness', { entry: { seal: s.record }, proof: proofFor(tree, s, held).map(toBase64url), first: s.book.firstLine() });
      if (answer.code !== 200 || !answer.body?.statement) throw refusalOf(answer);
      await accept(w, s, s.book.firstLine(), tree.path(0, s.size), answer.body.statement, null);
      held = s;
    }
    w.held = held ? { identity: seq.identity, fingerprint: held.fingerprint, number: held.number, size: held.size } : null;
    w.problem = null;
  }

  // Ask one witness for a statement for the seal that waits for its line, where it holds the seal before it (or none).
  async function inTimeOne(w, p, slot) {
    try {
      const l = await holding(w, p.identity);
      const held = l ? { identity: p.identity, fingerprint: await fingerprint(fromBase64url(l.seal.payload)), number: decoded(l.seal).book ?? 1, size: decoded(l.seal).size } : null;
      // Behind: it is brought up to date once the line is written.
      if (held && held.fingerprint !== p.content.previous) return;
      const seal = { ...p, number: p.content.book ?? 1, size: p.content.size };
      const tree = await treeOf({ key: p.key, kind: 'memory' }, p.text);
      const answer = await w.client.ask('POST', '/witness', { entry: { seal: p.record }, proof: proofFor(tree, seal, held).map(toBase64url), first: p.first });
      if (answer.code !== 200 || !answer.body?.statement) throw refusalOf(answer);
      await accept(w, p, p.first, tree.path(0, seal.size), answer.body.statement, slot);
      w.held = { identity: p.identity, fingerprint: p.fingerprint, number: seal.number, size: seal.size };
      w.problem = null;
    } catch (e) {
      w.problem = problemFrom(e);
      w.held = undefined;
    }
  }

  function trigger() {
    if (!started || closed) return;
    for (const w of workersNow()) {
      if (w.running) {
        w.again = true;
        continue;
      }
      w.running = true;
      (async () => {
        try {
          do {
            w.again = false;
            await exclusive(w, () => catchUp(w).catch((e) => {
              w.problem = problemFrom(e);
              if (w.held !== null) w.held = undefined;
            }));
          } while (w.again && !closed);
        } finally {
          w.running = false;
        }
      })();
    }
  }
  let timer = null;

  return {
    /** Whether any witness is named. */
    configured: () => readWitnessSettings(folder).list.length > 0,
    /** Begin: ask every witness now, and every minute while one is behind. */
    start() {
      started = true;
      // The tree of the book in force is made now, in the background, so that "seal" need not make it while
      // a tool call waits its turn (on a book of 93 MB, about a second, once).
      if (readWitnessSettings(folder).list.length > 0) {
        const inForce = books().at(-1);
        treeOf(inForce).catch(() => {});
      }
      trigger();
      // A witness added to the list since, or one that is behind, is asked.
      timer = setInterval(() => {
        if (workersNow().some((w) => w.problem || w.held === undefined)) trigger();
      }, retryMs);
      timer.unref();
    },
    /** Ask every witness about the seals it has not yet signed for. */
    trigger,
    /**
     * Ask every witness, now, for a statement for a seal whose line is not
     * yet written (its entry is kept on the disk apart from the book). The
     * slot gives the statements that came, checked, when it is closed
     * (take); one that comes later is kept beside the book.
     * @param {{record: object, fingerprint: string, content: object, text: string, first: string}} p
     *   text: the book before the seal; first: its first line
     */
    async inTime(p) {
      const slot = { open: true, arrived: [] };
      let identity;
      try {
        identity = await bookIdentity(recorder.keys, utf8(p.first));
      } catch {
        return { settled: Promise.resolve(), take: () => [], done() {} };
      }
      const seal = { ...p, identity };
      pending = seal;
      const settled = Promise.allSettled(workersNow().map((w) => exclusive(w, () => inTimeOne(w, seal, slot))));
      return {
        settled,
        take() {
          slot.open = false;
          return slot.arrived;
        },
        done() {
          if (pending === seal) pending = null;
        },
      };
    },
    /** What each witness holds, and why it is behind. */
    async status() {
      const list = workersNow();
      // The latest seal of the sequence on the disk: from the newest book back, to the first that holds one.
      let latest = null;
      try {
        const seq = await sequenceNow();
        for (let i = (seq?.books.length ?? 0) - 1; i >= 0 && latest === null; i--) {
          const durable = seq.books[i].durable();
          latest = (await sealsOf(seq.books[i])).filter((s) => s.end < durable).at(-1) ?? null;
        }
      } catch { /* said for each witness below */ }
      return {
        ...(settingsProblem ? { problem: settingsProblem } : {}),
        witnesses: list.map((w) => ({
          key: w.key,
          address: w.address,
          holds: w.held ? { book: w.held.number, entries: w.held.size, seal: w.held.fingerprint } : w.held === null ? null : 'not known yet',
          upToDate: !w.problem && ((w.held && latest && w.held.fingerprint === latest.fingerprint) || (w.held === null && latest === null)),
          ...(w.problem ? { problem: w.problem } : {}),
          lastStatementAt: w.lastStatementAt,
        })),
      };
    },
    close() {
      closed = true;
      if (timer) clearInterval(timer);
      abort.abort();
    },
  };
}
