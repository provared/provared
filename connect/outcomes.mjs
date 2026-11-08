// What the agent's recorder did with the records handed to it, as the
// uploader beside it reports: one sealed note a book, the same in the
// browser and in the uploader. Web Crypto only, through the engine's
// crypto-core.
//
// The person signs a renewal or a cancellation on the signing page; the
// page keeps it with the book, sealed (the application's page); the uploader beside
// the agent's recorder reads it from there and hands it to the recorder
// (handover.mjs), which checks it itself and takes it or refuses
// it. Where it takes it, the book shows it: the new permission, or the
// cancellation with the agent's acknowledgement. Where it refuses it, or
// holds it, only this note says so: the uploader writes it here, sealed
// under the book's own key with the book's id bound in, and the page reads
// it, with the book's current key only.
//
// THE NOTE IS NOT PROVED TO BE THE UPLOADER'S. The book's key is also held
// by everyone given a read-only link to the book, so whoever holds such a
// link, working with the server, could seal a note the page opens; and the
// server can hold the note back, or hand back an older one. So the page
// shows it only as an unproved hint, and only where a false one does no
// harm (the page, in its own words): never that the agent stopped acting or took
// anything, and never a command naming a passkey the person's own
// application does not trust for the book (the thumbprint here is not used
// for that). A note that a reader could tell came from the uploader would
// need a key only the uploader and the owner hold; none is built.
//
// The note: { version: 1, outcomes: [{ kind, fingerprint, outcome, code?,
// thumbprint?, at }] }
//   kind         "renewal" or "cancellation"
//   fingerprint  the record's fingerprint: the SHA-256 of its signed content
//   outcome      "taken", "already", "held" or "refused"
//   code         why, where it was refused (the recorder's code)
//   thumbprint   the passkey a refusal is about, where it is about one
//   at           when the uploader had the answer

export const OUTCOMES_PURPOSE = 'outcomes';
export const OUTCOME_KINDS = Object.freeze(['renewal', 'cancellation']);
export const OUTCOMES = Object.freeze(['taken', 'already', 'held', 'refused']);
/** The most outcomes one note holds: every renewal and cancellation a book keeps, and room to spare. */
export const MAX_OUTCOMES = 64;

const B64 = /^[A-Za-z0-9_-]{43}$/;
const CODE = /^[a-z][a-z-]{0,39}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

/** The note's bound context: "<namespace>/outcomes/v1" ‖ 0x00 ‖ object id (16 bytes). */
export function outcomesContext(cc, objectId) {
  return cc.frameContext(cc.label(OUTCOMES_PURPOSE), cc.uuidBytes(objectId));
}

/**
 * The outcomes a note holds that are in the form above; anything else is
 * set aside, never shown. At most MAX_OUTCOMES.
 */
export function readOutcomes(value) {
  const list = value && typeof value === 'object' && value.version === 1 && Array.isArray(value.outcomes) ? value.outcomes : [];
  const out = [];
  for (const o of list.slice(0, MAX_OUTCOMES)) {
    if (!o || typeof o !== 'object' || Array.isArray(o)) continue;
    if (!OUTCOME_KINDS.includes(o.kind) || typeof o.fingerprint !== 'string' || !B64.test(o.fingerprint)) continue;
    if (!OUTCOMES.includes(o.outcome) || typeof o.at !== 'string' || !TIME.test(o.at)) continue;
    if (o.code !== undefined && (typeof o.code !== 'string' || !CODE.test(o.code))) continue;
    if (o.thumbprint !== undefined && (typeof o.thumbprint !== 'string' || !B64.test(o.thumbprint))) continue;
    const item = { kind: o.kind, fingerprint: o.fingerprint, outcome: o.outcome, at: o.at };
    if (o.code !== undefined) item.code = o.code;
    if (o.thumbprint !== undefined) item.thumbprint = o.thumbprint;
    out.push(item);
  }
  return out;
}

/** Seals a list of outcomes for the server. */
export async function sealOutcomes(cc, kObjectKey, objectId, outcomes) {
  const text = JSON.stringify({ version: 1, outcomes: readOutcomes({ version: 1, outcomes }) });
  return cc.sealSymmetric(kObjectKey, new TextEncoder().encode(text), outcomesContext(cc, objectId));
}

/** Opens a sealed note; throws where it was not sealed for this book. Gives the outcomes in the form above. */
export async function openOutcomes(cc, kObjectKey, objectId, sealed) {
  const text = new TextDecoder().decode(await cc.openSymmetric(kObjectKey, sealed, outcomesContext(cc, objectId)));
  let value = null;
  try { value = JSON.parse(text); } catch { value = null; }
  return readOutcomes(value);
}
