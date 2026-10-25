// The "try it" page's own logic, kept apart from the page so that it can be
// tested in Node.js. It imports nothing: the library is handed in.
//
// Two ways to show the same thing:
//   "live"   the browser has Ed25519 and ML-DSA-87 built in, so a new record
//            is made here, signed with the library's development stand-in
//            for a passkey, and checked;
//   "sample" it has not, so the published sample record is read and
//            checked one entry at a time instead.
// SLH-DSA, the third method a seal is signed with, is in no browser, so the
// record made here has no seal.

/** The action the invented office agent takes, from the shared list. */
export const ORDER = 'provared.order.place';

/** The orders it places, in order. Together they come to 230 GBP. */
export const ORDERS = [
  { what: 'Printer paper, 10 reams', value: 45 },
  { what: 'A toner cartridge', value: 80 },
  { what: 'Envelopes, 2 boxes', value: 25 },
  { what: 'A second toner cartridge', value: 80 },
];

/** The limit the page starts with, and the range a visitor may give. */
export const DEFAULT_LIMIT = 200;
export const MIN_LIMIT = 1;
export const MAX_LIMIT = 10000;

/**
 * Which way the page shows it, and why, in words for the visitor.
 * @param {{ed25519: boolean, mldsa: boolean}} has whether the browser has each method built in
 * @returns {{path: 'live'|'sample', why: string}}
 */
export function choosePath(has) {
  if (has && has.ed25519 === true && has.mldsa === true) {
    return { path: 'live', why: 'Your browser has both signing methods that an agent\'s receipt needs built in (Ed25519, and ML-DSA-87, which is quantum-safe), so a new record is made and checked here, in this page.' };
  }
  const missing = [has && has.ed25519 === true ? null : 'Ed25519', has && has.mldsa === true ? null : 'ML-DSA-87'].filter(Boolean).join(' or ');
  return {
    path: 'sample',
    why: `Your browser has no built-in ${missing}, which an agent's receipt is signed with, so it cannot make a new record. Instead it reads the sample record that comes with the library, and checks it here one entry at a time. ${has && has.ed25519 === true ? 'It cannot check every signature, so its answer says that the check is not complete.' : "It can check only the passkey's signature on the permission, so it cannot compare the receipts with the permission, and its answer says that the check is not complete."} Edge and Brave from version 155 can make a new record here.`,
  };
}

/**
 * Read the limit a visitor typed.
 * @param {string} text
 * @returns {number|null} a whole number of GBP from MIN_LIMIT to MAX_LIMIT, or null
 */
export function readLimit(text) {
  const t = String(text).trim();
  if (!/^\d{1,6}$/.test(t)) return null;
  const n = Number(t);
  return n >= MIN_LIMIT && n <= MAX_LIMIT ? n : null;
}

/**
 * The permission the visitor's run is made under.
 * @param {number} limit the most, in GBP, the agent may order in total
 */
export function permissionFields(limit) {
  return {
    issuer: { name: 'A visitor to prova.red' },
    agent: { name: 'Office agent (invented)' },
    actions: [ORDER],
    limits: [{ action: ORDER, max: limit, unit: 'GBP' }],
    requires: [],
    never: [],
    purpose: 'Keep the office stocked with paper, envelopes and toner. Made on the "try it" page at prova.red, in the visitor\'s own browser.',
  };
}

/**
 * Make a record in one go: a permission with a limit, and a receipt for each
 * order. The agent in this story asks the check before acting each time and
 * then places the order whatever the answer, so that there is something for
 * the checker to find. A well-made agent would not place an order the check
 * refused ("act" in the library does exactly that).
 *
 * @param {{developmentRecorder: Function, checkBook: Function, sha256: Function, utf8: Function, toBase64url: Function}} lib the library
 * @param {number} limit
 * @param {(step: object) => Promise<void>|void} [onStep] told about each step as it happens
 * @returns {Promise<{book: string, issuerKeys: string[], slip: object, steps: object[], result: object}>}
 */
export async function makeRecord(lib, limit, onStep = () => {}) {
  const { recorder, issuerKeys, slip } = await lib.developmentRecorder(permissionFields(limit));
  await onStep({ kind: 'slip', slip, issuerKeys });
  const steps = [];
  let total = 0;
  for (let i = 0; i < ORDERS.length; i++) {
    const order = ORDERS[i];
    const description = `Order ${i + 1}: ${order.what}, ${order.value} GBP`;
    const request = {
      action: ORDER,
      amount: { unit: 'GBP', value: order.value },
      details: [{ name: description, sha256: lib.toBase64url(await lib.sha256(lib.utf8(description))) }],
    };
    const asked = await recorder.before(request);
    const written = await recorder.record(request);
    total += order.value;
    const step = { index: i + 1, order, description, total, allowed: asked.allowed, said: [...asked.problems, ...asked.breaches].map((b) => b.message), fingerprint: written.fingerprint, seq: written.seq };
    steps.push(step);
    await onStep({ kind: 'stub', ...step });
  }
  const book = recorder.book();
  const result = await lib.checkBook(book, { issuerKeys });
  return { book, issuerKeys, slip, steps, result };
}

/**
 * The entry of the first order that takes the total over the limit, counting
 * the permission as entry 0, as the checker does; null if none does.
 * @param {number} limit
 */
export function expectedFirstBreach(limit) {
  let total = 0;
  for (let i = 0; i < ORDERS.length; i++) {
    total += ORDERS[i].value;
    if (total > limit) return i + 1;
  }
  return null;
}
