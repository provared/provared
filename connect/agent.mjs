// The agent's public key set, as the recorder's feed gives it (GET /agent)
// and as the uploader passes it on, in a sealed note of its own: the agent
// note. Web Crypto only, through the engine's crypto-core.
//
// The recorder works the key set out from the agent's key file and gives
// only the public members of each key; this uploader reads it only from an
// answer that carries the recorder's proof (upload.mjs, feedClient), and
// only in the form below: anything else is set aside, and a key with any
// other member, a private one (d, priv) among them, is never passed on.
// The uploader puts it with the book, sealed under the book's own key with
// the book's id bound in, where its text differs from the last one put
// (createAgentNote), for the application to fill in the keys of the agent's
// first permission. The application's server and page do not take or open
// it yet.
//
// THE NOTE OPENS WITH THE BOOK'S CURRENT KEY ONLY. Its bound context names
// no key epoch, so a note sealed under an earlier key of the book does not
// open, and is set aside.
//
// THE NOTE IS NOT PROVED TO BE THE UPLOADER'S. As the note of outcomes
// (outcomes.mjs): the book's key is also held by everyone given a read-only
// link to the book, so whoever holds such a link, working with the server,
// could seal a note the page opens, and the server can hold the note back
// or hand back an older one. What guards the agent is the recorder, which
// takes no permission for other keys than its own ("other-agent").
//
// The key set: { name, keys: [{ kty, alg, crv?, x?, pub? }, ...] }
// The note:    { version: 1, agent: <the key set> }

/** The members of a public key that are passed on: Ed25519 (kty, alg, crv, x) and ML-DSA-87 (kty, alg, pub). */
export const PUBLIC_KEY_MEMBERS = Object.freeze(['kty', 'alg', 'crv', 'x', 'pub']);
/** The most keys one key set holds. */
export const MAX_AGENT_KEYS = 8;
/** The longest agent's name passed on, in characters. */
export const MAX_AGENT_NAME = 200;
/** The longest key set passed on, as JSON text, in characters: room for the agent's two keys and more. */
export const MAX_AGENT_TEXT = 8192;

const VALUE = /^[A-Za-z0-9_-]{1,8192}$/;

/**
 * A key set made afresh from a value, in the form above, or null where the
 * value is not in that form: a name of 1 to MAX_AGENT_NAME characters; 1 to
 * MAX_AGENT_KEYS keys, each of public members only, each a value of
 * base64url letters; at most MAX_AGENT_TEXT characters in all. No member is
 * dropped: a key set with one that is not public is set aside whole.
 */
export function readKeySet(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const { name, keys } = value;
  if (typeof name !== 'string' || name.length === 0 || name.length > MAX_AGENT_NAME) return null;
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > MAX_AGENT_KEYS) return null;
  const out = [];
  for (const k of keys) {
    if (!k || typeof k !== 'object' || Array.isArray(k)) return null;
    const names = Object.keys(k);
    if (!names.includes('kty') || !names.every((n) => PUBLIC_KEY_MEMBERS.includes(n) && typeof k[n] === 'string' && VALUE.test(k[n]))) return null;
    out.push(Object.fromEntries(names.map((n) => [n, k[n]])));
  }
  const set = { name, keys: out };
  return JSON.stringify(set).length <= MAX_AGENT_TEXT ? set : null;
}

export const AGENT_PURPOSE = 'agent';

/** The note's bound context: "<namespace>/agent/v1" ‖ 0x00 ‖ object id (16 bytes), as the note of outcomes' (outcomesContext). */
export function agentContext(cc, objectId) {
  return cc.frameContext(cc.label(AGENT_PURPOSE), cc.uuidBytes(objectId));
}

/** The key set a note holds, in the form above; null where the note is not in its form. */
export function readAgent(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.version !== 1) return null;
  return readKeySet(value.agent);
}

/** The note's text for a key set; null where the key set is not in the form above. */
export function agentNoteText(agent) {
  const set = readKeySet(agent);
  return set ? JSON.stringify({ version: 1, agent: set }) : null;
}

/** Seals a key set for the server, as a note; throws where the key set is not in the form above. */
export async function sealAgent(cc, kObjectKey, objectId, agent) {
  const text = agentNoteText(agent);
  if (text === null) throw new Error('the agent\'s key set is not in the form the note holds, so it is not sealed');
  return cc.sealSymmetric(kObjectKey, new TextEncoder().encode(text), agentContext(cc, objectId));
}

/**
 * Opens a sealed note; throws where it was not sealed for this book under
 * this key (another book, an earlier key of the book, a note of another
 * kind). Gives the key set, or null where the note is not in its form.
 */
export async function openAgent(cc, kObjectKey, objectId, sealed) {
  const text = new TextDecoder().decode(await cc.openSymmetric(kObjectKey, sealed, agentContext(cc, objectId)));
  let value = null;
  try { value = JSON.parse(text); } catch { value = null; }
  return readAgent(value);
}

/** Said once where the recorder does not give its key set (an earlier version). */
export const NOT_GIVEN_WORDS = 'provared-connect: the recorder does not give the agent\'s keys (an earlier version): update the recorder to fill in the agent\'s keys by itself. Uploading goes on as before.';

/**
 * createAgentNote({ feed, putAgent, log })
 *   feed      the recorder's feed client (upload.mjs: feedClient), with agent()
 *   putAgent  (agent) => writes the agent note (handover.mjs: bookSide)
 *   round()   reads the key set from the recorder, and puts the note where its text differs from the last
 *             one put; resolves with "put", "same", "not-given" or "failed"
 * Nothing is put from an answer the feed client did not take (no proof, or not in the form above). Where the
 * recorder does not give its key set, it says so once (NOT_GIVEN_WORDS), and nothing is put. A put that fails
 * is tried again at the next round; each failure is said once until the next success.
 */
export function createAgentNote({ feed, putAgent, log = console }) {
  let noted = null;
  let said = null;
  const sayOnce = (what, words) => {
    if (said === what) return;
    said = what;
    log.error(words);
  };
  async function round() {
    let given;
    try {
      given = await feed.agent();
    } catch (e) {
      sayOnce(`read ${e.message}`, `provared-connect: the agent's keys could not be read from the recorder now: ${e.reason || e.code || 'error'}: ${e.message}`);
      return 'failed';
    }
    if (!given || given.given !== true) {
      sayOnce('not-given', NOT_GIVEN_WORDS);
      return 'not-given';
    }
    const text = agentNoteText(given.agent);
    if (text === null) {
      sayOnce('form', 'provared-connect: the recorder gave the agent\'s keys in a form this uploader does not read; they are not passed on');
      return 'failed';
    }
    if (text === noted) return 'same';
    try {
      await putAgent(JSON.parse(text).agent);
    } catch (e) {
      sayOnce(`put ${e.reason || e.code || e.message}`, e.reason === 'unknown-type'
        ? 'provared-connect: the application\'s server does not take the agent\'s keys yet (unknown-type): they are offered again at each round, and the records are handed over as before'
        : `provared-connect: the agent's keys could not be written to the server: ${e.reason || e.code || 'error'}: ${e.message}`);
      return 'failed';
    }
    noted = text;
    said = null;
    log.info(`provared-connect: the agent's keys (fingerprint ${given.fingerprint}) are with the book, sealed, for the application to fill in`);
    return 'put';
  }
  return Object.freeze({ round });
}
