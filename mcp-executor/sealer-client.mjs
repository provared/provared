// The recorder's side of the central sealer's protocol: a copy.
//
// Everything below the import lines is copied from sealer/sealer.mjs (the
// program provared-sealer), declaration for declaration and byte for byte,
// and a test holds it so (test/same-files.test.mjs): the labels and the
// HMAC-SHA-256 proofs (RFC 2104) of a question and of an answer, the
// members a question may hold, and connectSealer, which asks the questions
// and refuses an answer that does not prove it comes from a sealer that
// holds the token. Nothing here is the executor's own making. It is a copy,
// and not the package, so that the executor depends on the library alone
// and holds none of the sealer's own code: the part that keeps the keys and
// signs (DESIGN.md, X151).

import nodeCrypto from 'node:crypto';
import { toBase64url } from 'provared';

const LABELS = Object.freeze({
  head: 'provared sealer v1: a recorder\'s question, before its body',
  question: 'provared sealer v1: a recorder\'s question',
  answer: 'provared sealer v1: the sealer\'s answer',
});
/** A recorder's name: small letters, digits and hyphens, 1 to 63. */
export const RECORDER_NAME = /^[a-z0-9][a-z0-9-]{0,62}$/;
const RANDOM = /^[A-Za-z0-9_-]{43}$/;
/** The largest body a question or an answer may have: room for a whole book's leaf fingerprints. */
export const MAX_BODY_BYTES = 8 * 1024 * 1024;
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
    // The body goes as bytes, so its length is declared (Content-Length), as the first proof says. A redirect is not
    // followed: the question goes to the sealer's address and nowhere else, whatever listens there says.
    const r = await fetchImpl(new URL(path, address), {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'provared-sealer-recorder': recorder, 'provared-sealer-time': time, 'provared-sealer-nonce': nonce, 'provared-sealer-head': head, 'provared-sealer-proof': proof },
      body: bytes,
      redirect: 'error',
    });
    // The answer is read up to the limit and no further, since whatever listens at the address may send it: a length
    // declared over the limit is refused before any of the body is read, and the body is read piece by piece, with a
    // count that stops at the limit. The rest is not read, and the connection is given up.
    const tooLarge = () => new Error('The sealer\'s answer is larger than an answer may be.');
    if (Number(r.headers.get('content-length')) > MAX_BODY_BYTES) {
      await r.body?.cancel().catch(() => {});
      throw tooLarge();
    }
    const pieces = [];
    let size = 0;
    const reader = r.body?.getReader();
    for (let piece = await reader?.read(); piece && !piece.done; piece = await reader.read()) {
      size += piece.value.length;
      if (size > MAX_BODY_BYTES) {
        await reader.cancel().catch(() => {});
        throw tooLarge();
      }
      pieces.push(piece.value);
    }
    const answer = Buffer.concat(pieces);
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
