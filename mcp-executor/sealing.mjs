// Sealing: the recorder's three keys, and the one object that signs a seal.
//
// A seal is the library's own (format description, section 21.1): the
// recorder signs the number of entries a book holds and their top
// fingerprint, with Ed25519, ML-DSA-87 and SLH-DSA-SHA2-256s. The executor
// writes no record of its own kind and no signature of its own making: the
// seal is made by the library's writeSeal and goes into the book through
// the stub writer's "add", which takes it only if the whole book still
// passes its check with it.
//
// Every use of the recorder's key file by the executor goes through this
// file: making it ("keys"), reading it to see that it is whole ("check"),
// and reading it to seal. The file itself is read and written by files.mjs,
// as every key file is. The executor asks a "sealer" for a seal over a book
// and is handed the record; it never holds the keys. That is the place
// where a later step can hand the signing to a central sealer (section
// 21.7), which holds the keys away from the executor: an object with the
// same "seal" takes this one's place, and a book looks the same.

import nodeCrypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { keySetFingerprint, leafFingerprint, toBase64url, writeSeal } from 'provared';
import { loadKeyFile, makeKeyFile } from './files.mjs';
import { connectSealer, isRandom } from './sealer-client.mjs';

/** Make the recorder's key file where there is none (three keys), and give its public keys. */
export function makeRecorderKeyFile(path) {
  return makeKeyFile(path, 'recorder');
}

/** Read the recorder's key file to see that it is a recorder's: its public keys. Throws where it is not. */
export async function readRecorderKeyFile(path) {
  return (await loadKeyFile(path, 'recorder')).keys;
}

/** The SLH-DSA signatures in hand, one after another: the last one asked for, which never fails. */
let signing = Promise.resolve();
/** Run "task" once the signatures asked for before it are done; its own result. */
function oneAtATime(task) {
  const run = signing.then(task);
  signing = run.catch(() => {});
  return run;
}

/**
 * The recorder as the settings name it: its key file read, with the
 * fingerprint of its key set (how a person checking says which recorder
 * they expect). The third key signs through Node.js's thread pool, not in
 * the program's own thread, where the library's signer for a key in memory
 * would hold up every agent for the second or so that an SLH-DSA signature
 * takes: the same Node.js function, in its form with a callback. One such
 * signature is made at a time, for every recorder in the program: the pool
 * has four threads unless set, and a call needs it too (its receipt is
 * signed there, and the upstream's name is looked up there), so four books
 * sealed at once would hold up every agent's call until they were done.
 * @param {{keys: string, name: string}} recorder the path of its key file, and its name (a label on each seal)
 */
export async function loadRecorder(recorder) {
  const { keys, privateKeys } = await loadKeyFile(recorder.keys, 'recorder');
  const slh = nodeCrypto.createPrivateKey({ key: JSON.parse(readFileSync(recorder.keys, 'utf8')).keys[2], format: 'jwk' });
  const third = Object.freeze({
    key: keys[2],
    sign: (data) => oneAtATime(() => new Promise((done, failed) => nodeCrypto.sign(null, data, slh, (e, signature) => (e ? failed(e) : done(new Uint8Array(signature)))))),
  });
  return { name: recorder.name, keys, privateKeys: [privateKeys[0], privateKeys[1], third], fingerprint: await keySetFingerprint(keys) };
}

// --- an outside time-stamp on each seal (format description, section 21.2) ---
//
// Where the settings give a time-stamp service ("recorder.stamp"), each
// seal signed here is sent to it as its fingerprint, and the time-stamp it
// gives goes on the seal's line, in "stamps". The request and the check of
// the answer are the library's (provared/net/timestamp, loaded only where
// the setting is given). A time-stamp that is not given never costs the
// seal: the seal goes into the book without one, and the reason is said.

/** How long the request for a time-stamp may take, unless the settings say otherwise, and the least and the most they may say: milliseconds. */
export const STAMP_TIMEOUT = 5000;
export const STAMP_TIMEOUT_MIN = 100;
export const STAMP_TIMEOUT_MAX = 20000;
/** A time limit above which "check" warns: with the signing, a seal would hold the book's files longer than a start waits for them (X355). */
export const STAMP_LONG = 8000;

/**
 * "recorder.stamp", read: {address, timeout}; null where it has a problem.
 * The address is an address on the web (http: or https:) with no user name, query,
 * password or fragment. No service is named here.
 */
export function readStampSettings(c, where, at) {
  if (c === null || typeof c !== 'object' || Array.isArray(c)) {
    at(where, 'must be an object: the address of a time-stamp service and, where wanted, a time limit.');
    return null;
  }
  let sound = true;
  const no = (what, text) => {
    sound = false;
    at(`${where}.${what}`, text);
  };
  const out = { address: c.address, timeout: c.timeout ?? STAMP_TIMEOUT };
  let url = null;
  try {
    url = typeof c.address === 'string' ? new URL(c.address) : null;
  } catch {
    url = null;
  }
  if (!url || !['http:', 'https:'].includes(url.protocol) || url.username !== '' || url.password !== '' || url.hash !== '' || /[?#]/.test(url.href)) no('address', 'must be the whole address of a time-stamp service (RFC 3161), beginning http:// or https://, with no user name, password, query or fragment.');
  if (!Number.isInteger(out.timeout) || out.timeout < STAMP_TIMEOUT_MIN || out.timeout > STAMP_TIMEOUT_MAX) no('timeout', `must be a whole number of milliseconds from ${STAMP_TIMEOUT_MIN} to ${STAMP_TIMEOUT_MAX}: how long the request for a time-stamp may take.`);
  if (c.authority !== undefined) {
    const authority = readAuthority(c.authority);
    if (authority) out.authority = authority;
    else no('authority', AUTHORITY_WORDS);
  }
  for (const k of Object.keys(c)) if (!['address', 'timeout', 'authority'].includes(k)) no(k, 'is not a setting of a time-stamp service: it takes "address", "timeout" and "authority".');
  return sound ? out : null;
}

/**
 * Text from an answer, on one line and with no character that steers a
 * terminal or cannot be seen, for the commands to print. Control and format
 * characters (those that turn text round or hide it), the characters
 * Unicode says are ignored where not understood, and every kind of blank
 * (the blank braille pattern among them) become spaces; a letter keeps one
 * accent at most; the text is cut at 600 whole characters (X356). A
 * problem's words come from the sealer, which may be another program.
 */
export const plainText = (v) => {
  const text = String(v).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\p{Zs}\u2800]/gu, ' ').replace(/(\p{M})\p{M}+/gu, '$1');
  const characters = [...text];
  return characters.length > 600 ? `${characters.slice(0, 600).join('')}...` : text;
};

/** What "recorder.stamp.authority" must be. */
export const AUTHORITY_WORDS = 'must be the fingerprint of the certificate the service signs its time-stamps with, as a checker names the service ("stampServices": the SHA-256 of the certificate in base64url, 43 characters), or a list of 1 to 16 of them.';

/** "authority", read as the library reads it (stampAuthority): a list of 1 to 16 fingerprints, or null where it is not one. */
export function readAuthority(a) {
  const list = typeof a === 'string' ? [a] : a;
  return Array.isArray(list) && list.length > 0 && list.length <= 16 && list.every((x) => typeof x === 'string' && /^[A-Za-z0-9_-]{43}$/.test(x)) ? [...list] : null;
}

/** What "check" warns of where a time-stamp service is asked over plain http: and no certificate is named. */
export const HTTP_STAMP_WARNING = 'recorder.stamp: the service is asked over plain http: and no "authority" is named, so a time-stamp signed by anyone who answers in its place is kept and reported as a time-stamp. Name the fingerprint of the service\'s certificate in "authority" (the "stampedBy" of a seal shows it).';

/**
 * The function that asks the service the settings give for a time-stamp
 * over a seal's fingerprint (the library's askForStamp): it gives the item
 * of "stamps" and the fingerprint of the certificate that signed it. Where
 * "authority" is given, a time-stamp signed by another is not kept.
 */
export async function stampHook({ address, timeout, authority }) {
  let net;
  try {
    net = await import('provared/net/timestamp');
  } catch (e) {
    throw new Error(`recorder.stamp: the library installed has no client for a time-stamp service (provared/net/timestamp), so no time-stamp can be asked for (${e.code ?? e.message}).`);
  }
  // A library from before "authority" would take a time-stamp from any signer: where one is named, it is refused.
  if (authority && typeof net.stampAuthority !== 'function') throw new Error('recorder.stamp.authority: the library installed does not hold a time-stamp to the certificate named, so no time-stamp could be trusted to be the service\'s. Install a library that does, or leave "authority" out.');
  net.stampService({ address, timeout, ...(authority ? { authority } : {}) }); // the address, the time limit and "authority", read once
  return async (fingerprintBytes, context = {}) => {
    const got = await net.askForStamp(fingerprintBytes, { address, timeout, when: context?.when, after: context?.after, ...(authority ? { authority } : {}) });
    return { stamp: got.stamp, authority: got.authority };
  };
}

/** Whether "check" is to warn that the service is asked over http: with no certificate named (HTTP_STAMP_WARNING). */
export const stampWithoutAuthority = (stamp) => Boolean(stamp && !stamp.authority && /^http:/i.test(stamp.address));

/**
 * What a time-stamp over a new seal is held against: the seal's own time as
 * a checker reads it (whole seconds), and the latest time that a sound
 * time-stamp from a service gave a seal before it in the book, or null.
 * @param {object[]} entries the entries of the book's check, as the library gives them
 * @param {number} when the new seal's time, in milliseconds
 */
export function stampContext(entries, when) {
  let after = null;
  for (const e of entries) {
    if (e.kind !== 'seal' || e.problems.length > 0) continue;
    for (const s of e.stamps ?? []) {
      if (s.kind === 'service' && (s.state === 'valid' || s.state === 'untrusted') && Number.isFinite(s.time) && (after === null || s.time > after)) after = s.time;
    }
  }
  return { when: Math.floor(when / 1000) * 1000, after };
}

/**
 * Ask for a time-stamp over a seal's fingerprint. Never throws: gives
 * {stamps: [item], stampedBy} or {stampProblem: {code, message}};
 * "stampedBy" is the fingerprint of the certificate that signed it, where
 * the hook gives it.
 */
export async function stampFor(stamp, fingerprintBytes, context = {}) {
  try {
    // "context": the seal's own time and the latest time a service's time-stamp gave a seal before it, which the
    // time-stamp is held against (the library's askForStamp).
    const got = await stamp(fingerprintBytes.slice(), context);
    if (isObject(got) && typeof got.stamp === 'string') return { stamps: [got.stamp], ...(typeof got.authority === 'string' ? { stampedBy: got.authority } : {}) };
    return { stamps: [got] };
  } catch (e) {
    const message = typeof e?.message === 'string' && e.message !== '' ? e.message : 'The time-stamp service gave no time-stamp.';
    return { stampProblem: { code: typeof e?.code === 'string' && e.code.startsWith('stamp-') ? e.code : 'stamp-not-given', message } };
  }
}

/**
 * A sealer that signs here, with the recorder's keys from its key file.
 * @param {{name: string, keys: object[], privateKeys: any[], fingerprint: string}} recorder as loadRecorder gives it
 * @param {{stamp?: ((fingerprintBytes: Uint8Array) => Promise<string>) | null}} [more] asks a time-stamp service for a time-stamp over each seal
 * @returns {{fingerprint: string, name: string, stamp: Function|null, seal: (book: string, fields: {previous?: string, when: number}) => Promise<{record: object, fingerprint: string, fingerprintBytes: Uint8Array}>}}
 */
export function localSealer(recorder, { stamp = null } = {}) {
  return {
    /** The fingerprint of the recorder's key set. */
    fingerprint: recorder.fingerprint,
    name: recorder.name,
    /** Asks for a time-stamp over a seal's fingerprint, or null where the settings give no service. */
    stamp,
    /** A seal over the book as it stands, naming the seal before it where there is one. */
    async seal(book, { previous, when }) {
      const sealed = await writeSeal(book, { by: { keys: recorder.keys, name: recorder.name }, ...(previous ? { previous } : {}), when }, recorder.privateKeys);
      return { record: sealed.record, fingerprint: sealed.fingerprint, fingerprintBytes: sealed.fingerprintBytes };
    },
  };
}

// --- a central sealer (format description, section 21.7) ---
//
// The recorder's keys are then held by another program, provared-sealer,
// and the executor holds none of them. It sends the sealer the leaf
// fingerprint of each line of a book once the line is in the book file, in
// order, each at its place, and asks for a seal only once the sealer has
// answered for every line. The questions and their proofs are the sealer's
// own (sealer-client.mjs, a copy of its client); the leaf fingerprint is
// the library's (leafFingerprint).
//
// What the executor holds itself to:
// - a line is sent only once it is in the book file, and never out of its
//   place: each question names the place of its first line, and the place
//   moves on only by the sealer's own answer;
// - no question waits without a limit ("timeout"; a seal, SEAL_WAIT_MS);
// - what the sealer says it holds is compared with the book at a start,
//   before each seal, and whenever the sealer answers that the place is not
//   the one it holds; where the two do not agree the agent is stopped;
// - a seal the sealer signed and the book does not hold yet is added
//   before any other line: a seal sits after exactly the entries it covers.

/** How long one question to the sealer may take, unless the settings say otherwise, and the least and the most they may say: milliseconds. */
export const SEALER_TIMEOUT = 5000;
export const SEALER_TIMEOUT_MIN = 100;
export const SEALER_TIMEOUT_MAX = 60000;
/** How many lines of a book may be unsent before the agent's calls are refused, unless the settings say otherwise, and the most they may say. */
export const SEALER_MAX_UNSENT = 100;
export const SEALER_MAX_UNSENT_MAX = 10000;
/** How long the question for a seal may take: the sealer's three signatures, its own check of them and its state made sure to be on the disk. */
export const SEAL_WAIT_MS = 30000;
/** How long after a question that failed the lines are sent again. */
export const SEALER_RETRY_MS = 2000;
/** The code of the refusal of a call while more lines are unsent than the settings allow. */
export const SEALER_BEHIND = 'sealer-behind';

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const FINGERPRINT = /^[A-Za-z0-9_-]{43}$/;
const lineFeeds = (text, from) => {
  let n = 0;
  for (let i = text.indexOf('\n', from); i >= 0; i = text.indexOf('\n', i + 1)) n += 1;
  return n;
};
/** Why the sealer gave a seal out without a time-stamp, from its answer ("stampProblem"), or null. */
const stampProblemOf = (answer) => (isObject(answer?.stampProblem) && typeof answer.stampProblem.message === 'string' ? { code: String(answer.stampProblem.code), message: answer.stampProblem.message } : null);
/** A question that was not taken, or an answer that cannot be used: the lines stay unsent, and are sent again later. */
const notTaken = (message) => Object.assign(new Error(message), { notTaken: true });
/** The book and what the sealer holds of it do not agree: the agent is stopped. */
const disagrees = (message) => Object.assign(new Error(message), { disagrees: true });
const within = (promise, ms) => {
  let timer;
  const late = new Promise((done) => (timer = setTimeout(done, ms)));
  return Promise.race([promise, late]).finally(() => clearTimeout(timer));
};

/** Read the recorder's token for the sealer from where the settings say: a file, or a variable of the environment. Its value is returned, never logged. */
export function readSealerToken(from, env = process.env) {
  let token;
  if (from.env !== undefined) {
    token = env[from.env];
    // eslint-disable-next-line security/detect-possible-timing-attacks -- checks only whether the variable is set; no secret is compared with another.
    if (token === undefined) throw new Error(`recorder.sealer.token: the variable ${from.env} is not set in the executor's environment.`);
  } else {
    try {
      token = readFileSync(from.file, 'utf8').replace(/\r?\n$/, '');
    } catch (e) {
      throw new Error(`recorder.sealer.token: the file ${from.file} could not be read (${e.code ?? e.message}).`);
    }
  }
  if (!isRandom(token)) throw new Error('recorder.sealer.token: is not a token of the sealer\'s (32 bytes in base64url, as "provared-sealer add-recorder" prints it).');
  return token;
}

/**
 * A central sealer, as the settings name it: its address, the name it
 * knows this recorder by, the recorder's token, and the fingerprint of the
 * key set it signs with. Gives the object the executor seals through; it
 * holds no key. "open" gives one book's link to the sealer.
 * @param {{address: string, name: string, token: {file?: string, env?: string}, keySet: string, timeout: number, maxUnsent: number}} s
 */
export function centralSealer(s) {
  const token = readSealerToken(s.token);
  // No question waits without a limit: each is given up after "limit" milliseconds, the reading of its answer included.
  let limit = s.timeout;
  const client = connectSealer({ address: s.address, recorder: s.name, token, fetchImpl: (url, init) => fetch(url, { ...init, signal: AbortSignal.timeout(limit) }) });
  // One question at a time, for every book of this executor.
  let queue = Promise.resolve();
  const ask = (work, ms = s.timeout) => {
    const mine = queue.then(() => {
      limit = ms;
      return work(client);
    });
    queue = mine.then(
      () => {},
      () => {},
    );
    return mine;
  };
  const unreached = (e) => (e.notTaken || e.disagrees ? e.message : `The central sealer at ${s.address} gave no answer that can be used (${e.cause?.code ?? (typeof e.code === 'string' ? e.code : e.name)}: ${e.message})`);
  // The sealer must sign with the key set the settings name: asked once, at its first answer.
  let keySetSeen = false;
  async function sameKeySet() {
    if (keySetSeen) return;
    const about = await ask((c) => c.about());
    if (!isObject(about) || typeof about.sealer !== 'string' || !FINGERPRINT.test(about.sealer)) throw notTaken('The sealer\'s answer about itself is not in the form its protocol gives.');
    if (about.sealer !== s.keySet) throw disagrees(`the central sealer at ${s.address} signs with the key set ${about.sealer}, and the settings name ${s.keySet} (recorder.sealer.keySet).`);
    keySetSeen = true;
  }
  const heldForm = (held) =>
    held === null ||
    (isObject(held) &&
      Number.isSafeInteger(held.size) &&
      held.size >= 1 &&
      Number.isSafeInteger(held.sealed) &&
      held.sealed >= 0 &&
      held.sealed <= held.size &&
      (held.latest === null ? held.sealed === 0 : typeof held.latest === 'string' && FINGERPRINT.test(held.latest)) &&
      typeof held.closed === 'boolean');

  /**
   * One book's link to the sealer. "first" is the book's first line, the
   * permission it starts with; "seals", the seals the book holds, in
   * order, each {index, fingerprint}; "disagree" is told where the book
   * and the sealer do not agree; "takeBack" is handed the entry of a seal
   * the sealer signed that the book does not hold yet, to be added before
   * any other line, and the fingerprint the sealer named for it.
   */
  function open({ first, seals: given = [], now = Date.now, log = () => {}, disagree = () => {}, takeBack = async () => {} }) {
    /** The book as its file holds it, and how many lines that is. */
    let text = '';
    let lines = 0;
    /** The leaf fingerprint of each line, and how far into the text they reach. */
    const leaves = [];
    let absorbed = 0;
    const seals = given.map((x) => ({ index: x.index, fingerprint: x.fingerprint }));
    let ref = null;
    /** Whether what the sealer holds has been compared with the book since the sealer last answered out of step. */
    let agreed = false;
    /** How many lines the sealer has answered for. */
    let confirmed = 0;
    /** The most lines the sealer can hold of this book: those the file held at the start, and every line sent since. */
    let offered = 0;
    /** When the oldest line not yet sent was written, why the lines are unsent, and when the sealer last answered. */
    let since = null;
    let problem = null;
    let answeredAt = null;
    let failedAt = null;
    /** Why no line may be written: a seal the sealer signed, or may have signed, is not in the book yet. */
    let doubt = null;
    /** The fingerprint the sealer named for a seal that was handed to the agent's turn and is not dealt with yet. */
    let handed = null;
    /** Why the book and the sealer do not agree. */
    let broken = null;
    let starting = false;
    let running = null;
    let retry = null;
    let ended = false;

    async function absorb() {
      while (absorbed < text.length) {
        const end = text.indexOf('\n', absorbed);
        if (end < 0) break;
        leaves.push(await leafFingerprint(text.slice(absorbed, end)));
        absorbed = end + 1;
      }
    }

    // What the sealer holds, compared with the book. Gives {takeBack} where the sealer signed a seal over the book as
    // it stands that the book does not hold; throws where the two do not agree.
    async function agree() {
      await sameKeySet();
      const held = await ask((c) => c.held(ref));
      if (!heldForm(held)) throw notTaken('The sealer\'s answer about what it holds of this book is not in the form its protocol gives.');
      const last = seals.at(-1) ?? null;
      const behind = 'its record was lost or put back to an older one. It must be brought up to date with the book\'s latest seal (the sealer\'s "update") before the executor goes on; this program does not do that.';
      if (held === null) {
        if (last) throw disagrees(`the central sealer holds nothing of this book, and the book holds a seal of it: ${behind}`);
        confirmed = 0;
      } else {
        if (held.closed) throw disagrees('the central sealer holds a later book that follows this one, so it seals no more of this book.');
        if (held.size > offered) throw disagrees(`the central sealer holds ${held.size} lines of this book, and the executor has sent it ${offered} at most: the book file was cut short or put back to an older one, or another program sent lines for this book.`);
        if (held.latest === null) {
          if (last) throw disagrees(`the central sealer holds no seal of this book, and the book holds one: ${behind}`);
        } else if (!last || last.fingerprint !== held.latest) {
          if (seals.some((x) => x.fingerprint === held.latest)) throw disagrees(`the central sealer's latest seal of this book is an earlier one than the book's: ${behind}`);
          if (lines !== held.sealed) throw disagrees(`the central sealer's latest seal covers ${held.sealed} entries and is not in the book, which holds another entry at its place: the book file was changed, or put back to an older one and written on, after that seal was made.`);
          // The sealer signed a seal over the book as it stands, and the book never took it (a stop, or an answer that did not come).
          doubt = 'the central sealer signed a seal that the book does not hold yet; it is added before any other line.';
          const latest = await ask((c) => c.latest(ref));
          if (!isObject(latest) || latest.fingerprint !== held.latest || !isObject(latest.entry)) throw notTaken('The sealer\'s answer with its latest seal is not in the form its protocol gives.');
          return { takeBack: latest.entry, named: held.latest, stampProblem: stampProblemOf(latest) };
        }
        confirmed = held.size;
      }
      doubt = null;
      agreed = true;
      answeredAt = now();
      return {};
    }

    function fail(why) {
      if (broken) return;
      broken = why;
      clearTimeout(retry);
      retry = null;
      disagree(why);
    }

    function schedule() {
      if (ended || broken || retry || running) return;
      if (lines <= confirmed && agreed && !doubt && absorbed >= text.length) return;
      retry = setTimeout(
        () => {
          retry = null;
          attempt();
        },
        problem ? SEALER_RETRY_MS : 0,
      );
      retry.unref();
    }

    /**
     * One try to bring the sealer level with the book file: compare where
     * that is due, then send every line the sealer has not answered for.
     * Never throws; gives {takeBack} to "seal" where the sealer holds a
     * seal the book lacks.
     */
    function attempt(forSeal = false) {
      if (running) return running;
      if (broken || ended) return Promise.resolve({});
      clearTimeout(retry);
      retry = null;
      running = (async () => {
        const before = problem;
        try {
          await absorb();
          for (let rounds = 0; ; ) {
            if (!agreed) {
              rounds += 1;
              if (rounds > 3) throw notTaken('The central sealer answered three times in a row that it holds another number of lines than it had just said.');
              const got = await agree();
              if (got.takeBack) {
                if (forSeal) return got;
                if (!starting) {
                  // The agent adds it in its turn; the book is compared again once the seal is in its file. One seal waits
                  // for that turn at a time: a later question that finds the same seal hands it over no second time.
                  if (handed !== got.named) {
                    const mine = got.named;
                    handed = mine;
                    Promise.resolve(takeBack(got.takeBack, mine, got.stampProblem))
                      .catch(() => {})
                      .finally(() => {
                        if (handed === mine) handed = null;
                      });
                  }
                  throw notTaken(doubt);
                }
                await takeBack(got.takeBack, got.named, got.stampProblem);
                await absorb();
                continue;
              }
            }
            await absorb();
            if (confirmed >= leaves.length) break;
            const at = confirmed;
            const chunk = leaves.slice(at);
            offered = Math.max(offered, at + chunk.length);
            const answer = await ask((c) => c.extend(ref, at, chunk, at === 0 ? { line: first } : {}));
            if (isObject(answer) && isObject(answer.refused)) {
              // The sealer holds another number of lines than the place named: it is asked what it holds, and the book is compared again.
              agreed = false;
              if (answer.refused.code === 'out-of-step') continue;
              throw notTaken(`The central sealer did not take the lines: ${answer.refused.message} (${answer.refused.code})`);
            }
            if (!isObject(answer) || answer.size !== at + chunk.length) {
              agreed = false;
              throw notTaken('The central sealer answered with another number of lines than it was sent.');
            }
            confirmed = answer.size;
            answeredAt = now();
          }
          problem = null;
          failedAt = null;
          if (lines <= confirmed) since = null;
          if (before) log({ event: 'sealer-caught-up', lines: confirmed });
        } catch (e) {
          if (e.disagrees) fail(e.message);
          else {
            problem = unreached(e);
            failedAt = Date.now();
            if (problem !== before) log({ event: 'sealer-behind', reason: problem, unsent: lines - confirmed });
          }
        }
        return {};
      })().finally(() => {
        running = null;
        schedule();
      });
      return running;
    }

    // A start that is refused sends nothing more.
    const refusedStart = (message) => {
      ended = true;
      clearTimeout(retry);
      retry = null;
      return new Error(message);
    };

    return {
      /**
       * At a start, before anything is written: the sealer must answer,
       * and what it holds must agree with the book file. Throws where it
       * does not.
       * @param {string} onDisk the book file's text
       */
      async start(onDisk) {
        text = onDisk;
        lines = lineFeeds(text, 0);
        offered = lines;
        ref = toBase64url(await leafFingerprint(first));
        starting = true;
        try {
          await attempt();
        } finally {
          starting = false;
        }
        if (broken) throw refusedStart(`The executor does not start: ${broken}`);
        if (!agreed) throw refusedStart(`The executor does not start: what the central sealer holds could not be compared with the book file, as a start needs. ${problem}`);
      },
      /** At a start, once the permission's line is in the book file: the sealer must have taken every line the file holds. Throws where it has not. */
      async level() {
        await attempt();
        if (!broken && !problem && lines > confirmed) await attempt();
        if (broken) throw refusedStart(`The executor does not start: ${broken}`);
        if (lines > confirmed) throw refusedStart(`The executor does not start: the central sealer has not taken every line of the book. ${problem ?? ''}`.trim());
      },
      /** The book file holds this text now: its new lines are sent. */
      wrote(book) {
        if (book.length <= text.length) return;
        lines += lineFeeds(book, text.length);
        text = book;
        if (since === null && lines > confirmed) since = now();
        if (!running && !retry) attempt();
      },
      /** The book took a seal at this entry. */
      sealed(index, fingerprint) {
        seals.push({ index, fingerprint });
        doubt = null;
      },
      /** Why no line may be written to the book now (a seal the sealer signed, or may have signed, comes first), or null. */
      doubt: () => doubt,
      /** The book refused a seal the sealer signed: the two do not agree. */
      fail,
      /**
       * For a call about to be sent: null where no more lines are unsent
       * than the settings allow; else one try to send them, within the
       * time a question may take (none where a try failed in the last
       * second), and {unsent, since, problem} where they still are.
       */
      async behind() {
        const over = () => lines - confirmed > s.maxUnsent;
        if (!over() || broken) return null;
        if (running || failedAt === null || Date.now() - failedAt >= 1000) await within(attempt(), s.timeout);
        return over() ? { unsent: lines - confirmed, since: since === null ? null : new Date(since).toISOString(), problem } : null;
      },
      /**
       * Ask for a seal over the book, in the agent's turn, with every
       * line in the book file. The sealer is first asked what it holds,
       * and is sent what it lacks: a seal is asked for only where it
       * answers for every line and its latest seal is the book's. Gives
       * {entry}: the new seal's entry, or {entry, named}: one the sealer
       * had signed over the book as it stands and the book had not taken,
       * with the fingerprint the sealer named for it.
       * @param {string|undefined} previous the fingerprint of the book's last seal
       * @param {number} when the seal's time
       */
      async seal(previous, when) {
        if (broken) throw new Error(`The agent is stopped: ${broken}`);
        if (running) await running;
        agreed = false;
        const got = await attempt(true);
        if (broken) throw new Error(`The agent is stopped: ${broken}`);
        if (got.takeBack) return { entry: got.takeBack, named: got.named, ...(got.stampProblem ? { stampProblem: got.stampProblem } : {}) };
        if (!agreed || confirmed !== lines) throw new Error(`No seal was asked for: the central sealer does not hold every line of the book (${lines - confirmed} not sent). ${problem ?? ''}`.trim());
        let answer;
        try {
          answer = await ask((c) => c.seal(ref, { previous: previous ?? null, when }), SEAL_WAIT_MS);
          if (!isObject(answer) || (!isObject(answer.refused) && !isObject(answer.entry))) throw notTaken('The sealer\'s answer to the question for a seal is not in the form its protocol gives.');
        } catch (e) {
          // Whether the sealer signed is not known: a seal sits after exactly the entries it covers, so no line is written until it is.
          doubt = `a seal was asked for, and whether the central sealer signed one is not known (${unreached(e)}). No line is written until the sealer has said.`;
          agreed = false;
          problem ??= doubt;
          schedule();
          throw new Error(`The book was not sealed: ${doubt}`);
        }
        if (answer.refused) {
          agreed = false;
          schedule();
          throw new Error(`The central sealer signed no seal: ${answer.refused.message} (${answer.refused.code})`);
        }
        // A time-stamp the sealer asked for and was not given: the seal is signed all the same, and the reason is handed on.
        const stampProblem = stampProblemOf(answer);
        return { entry: answer.entry, ...(stampProblem ? { stampProblem } : {}) };
      },
      /** What the status shows of the link: how many lines are unsent and since when, when the sealer last answered, and what is wrong. */
      status: () => ({ address: s.address, recorder: s.name, unsent: lines - confirmed, since: since === null ? null : new Date(since).toISOString(), answeredAt: answeredAt === null ? null : new Date(answeredAt).toISOString(), problem: broken ?? doubt ?? problem }),
      /** At the end: one last try to send what is unsent, within the time a question may take; then nothing more is sent. */
      async end() {
        clearTimeout(retry);
        retry = null;
        if (running) await within(running, s.timeout);
        if (!broken && !doubt && lines > confirmed) await within(attempt(), s.timeout);
        ended = true;
        clearTimeout(retry);
        retry = null;
      },
    };
  }

  return {
    /** The fingerprint of the key set the sealer signs with, as the settings name it. */
    fingerprint: s.keySet,
    /** The name the sealer knows this recorder by. */
    name: s.name,
    address: s.address,
    central: true,
    open,
    /**
     * For the status read from the files: what the sealer holds of a
     * book, asked once. Nothing is sent of the book but its first line's
     * leaf fingerprint, and nothing is written. Gives {reached: true,
     * holds, unsent, latestSeal} or {reached: false, problem}.
     * @param {string} onDisk the book file's text
     */
    async look(onDisk) {
      const shown = { address: s.address, recorder: s.name };
      const end = onDisk.indexOf('\n');
      if (end < 0) return { ...shown, reached: null, holds: null, unsent: 0, latestSeal: null };
      try {
        await sameKeySet();
        const ref = toBase64url(await leafFingerprint(onDisk.slice(0, end)));
        const held = await ask((c) => c.held(ref));
        if (!heldForm(held)) throw notTaken('The sealer\'s answer about what it holds of this book is not in the form its protocol gives.');
        const lines = lineFeeds(onDisk, 0);
        const holds = held === null ? 0 : held.size;
        return { ...shown, reached: true, holds, unsent: Math.max(0, lines - holds), latestSeal: held === null ? null : held.latest, ...(holds > lines ? { problem: `the central sealer holds ${holds} lines of this book, and the book file holds ${lines}.` } : {}) };
      } catch (e) {
        return { ...shown, reached: false, problem: unreached(e) };
      }
    },
  };
}
