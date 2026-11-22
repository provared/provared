// The agent's public key set, as the recorder's feed gives it (GET /agent)
// and as the uploader passes it on. The recorder works it out from the
// agent's key file and gives only the public members of each key; this
// uploader reads it only from an answer that carries the recorder's proof
// (upload.mjs, feedClient), and only in the form below: anything else is set
// aside, and a key with any other member, a private one (d, priv) among
// them, is never passed on.
//
// The key set: { name, keys: [{ kty, alg, crv?, x?, pub? }, ...] }

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
