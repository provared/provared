// The demonstration: an office agent orders supplies under a slip that sets
// limits, asks for the supplier's countersignature and, above an amount, for
// the person's own approval. The agent goes outside the slip four times, and
// the record shows exactly where.
//
// Everything here is invented: the supplier, the people and the orders. No
// real firm, money or payment is involved. Nothing is bought, sent or deleted.

import { countersign, fingerprint, toBase64url, utf8, writeRefusal, writeSeal, writeStub, writeTerms } from '../src/index.js';

const ORDER = 'provared.order.place';
const MESSAGE = 'provared.message.send';
const SUPPLIER_NAME = 'Example Stationery (invented)';

/** The slip the person signs, apart from the keys and the dates. */
export const SLIP = {
  agentName: 'Office agent',
  serviceId: 'supplier',
  serviceName: SUPPLIER_NAME,
  actions: [ORDER, MESSAGE],
  limits: [
    { action: ORDER, max: 200, unit: 'GBP' },
    { action: ORDER, each: 100, unit: 'GBP' },
    { action: MESSAGE, count: 2, per: 3600 },
  ],
  requires: [
    { action: ORDER, need: 'countersignature' },
    { above: 60, action: ORDER, need: 'approval', unit: 'GBP' },
  ],
  never: ['destroys', 'impersonate', 'bypass'],
  purpose: 'Keep the office stocked with paper, pens and toner, and tell the office what was ordered.',
};

/**
 * What happens, in order. The third step is an order above 60 GBP: the agent
 * asks the person, who approves it with the passkey. The agent here does not
 * check itself after that. That is the point of the demonstration: the record
 * shows what happened, whoever was at fault.
 */
export const STEPS = [
  { kind: 'order', what: 'Orders printer paper, 10 reams', value: 45, countersigned: true },
  { kind: 'message', what: 'Tells the office that the paper is ordered' },
  { kind: 'order', what: 'Orders a toner cartridge, after asking the person', value: 80, countersigned: true },
  { kind: 'order', what: 'Orders envelopes, 2 boxes; the supplier never confirms', value: 25, countersigned: false },
  { kind: 'order', what: 'Orders a second toner cartridge, without asking', value: 80, countersigned: true },
  { kind: 'refused', what: 'Asks for 4 office chairs; the supplier refuses', value: 500 },
  { kind: 'delete', what: 'Deletes the old order files' },
];

/** The step for which the agent asks the person's approval. */
export const APPROVAL_STEP = 2;

const iso = (ms) => new Date(ms).toISOString().slice(0, 19) + 'Z';
const MINUTE = 60 * 1000;

/**
 * The fields of the slip, ready for the person to sign.
 * @param {object} parties
 * @param {object[]} parties.agentKeys the agent's public key set
 * @param {object[]} parties.serviceKeys the supplier's public key set
 * @param {number} from when the slip starts, in milliseconds
 */
export function slipFields({ agentKeys, serviceKeys }, from) {
  return {
    agent: { name: SLIP.agentName, keys: agentKeys },
    actions: SLIP.actions,
    limits: SLIP.limits,
    requires: SLIP.requires,
    never: SLIP.never,
    with: [{ id: SLIP.serviceId, name: SLIP.serviceName, keys: serviceKeys }],
    validFrom: iso(from),
    validUntil: iso(from + 7 * 24 * 3600 * 1000),
    purpose: SLIP.purpose,
  };
}

// What a step asks for: the action, the amount, the service and the
// fingerprint of the document. The document stays with the organisation.
async function requestFor(i) {
  const step = STEPS[i];
  const document = JSON.stringify({ step: i + 1, what: step.what, value: step.value ?? null });
  const details = [{ name: `Step ${i + 1}: ${step.what}`, sha256: await fingerprint(utf8(document)) }];
  if (step.kind === 'message') return { action: MESSAGE, details };
  if (step.kind === 'delete') return { action: 'provared.data.delete', details };
  return { action: ORDER, amount: { unit: 'GBP', value: step.value }, with: SLIP.serviceId, details };
}

/**
 * Start the agent's work: the supplier's terms go into the book, then the
 * agent works until it needs the person's approval.
 *
 * @param {object} a
 * @param {string} a.slipFingerprint
 * @param {CryptoKey[]} a.agentPrivateKeys
 * @param {object[]} a.serviceKeys the supplier's public key set
 * @param {CryptoKey[]} a.servicePrivateKeys
 * @param {number} a.start the time of the first step, in milliseconds
 * @returns {Promise<{run: object, ask: object}>} "ask" is what the person is asked to approve
 */
export async function startRun(a) {
  const terms = await writeTerms(
    {
      by: { keys: a.serviceKeys, name: SUPPLIER_NAME },
      accepts: [ORDER, 'provared.order.cancel'],
      never: ['impersonate', 'bypass'],
      validFrom: iso(a.start - 30 * 24 * 3600 * 1000),
      validUntil: iso(a.start + 335 * 24 * 3600 * 1000),
    },
    a.servicePrivateKeys,
  );
  const run = { ...a, terms: terms.fingerprint, entries: [{ terms: terms.record }], after: null, next: 0 };
  while (run.next < APPROVAL_STEP) await takeStep(run);
  return { run, ask: { slip: a.slipFingerprint, ...(await requestFor(APPROVAL_STEP)), when: a.start + APPROVAL_STEP * 10 * MINUTE - MINUTE } };
}

/**
 * Finish the agent's work, once the person has approved the one step.
 * @param {object} run from startRun
 * @param {{record: object, fingerprint: string}} approval the person's signed approval
 * @returns {Promise<object[]>} the entries to add to the book after the slip
 */
export async function finishRun(run, approval) {
  await takeStep(run, approval);
  while (run.next < STEPS.length) await takeStep(run);
  return run.entries;
}

/**
 * Whoever keeps the book seals it, and a time-stamp service states when.
 * In the demonstration both are played on this computer: the time-stamp
 * service is made up, and nobody outside vouches for its time.
 *
 * @param {string} book the book so far
 * @param {object} a
 * @param {{keys: object[], privateKeys: any[]}} a.recorder
 * @param {{stamp: Function}} a.stampService
 * @param {number} a.when in milliseconds
 * @returns {Promise<object>} the entry to add to the book
 */
export async function sealBook(book, { recorder, stampService, when }) {
  const sealed = await writeSeal(book, { by: { keys: recorder.keys, name: 'Example recorder (invented)' }, when }, recorder.privateKeys);
  return { seal: sealed.record, stamps: [toBase64url(await stampService.stamp(sealed.fingerprintBytes, when + MINUTE))] };
}

async function takeStep(run, approval) {
  const i = run.next++;
  const step = STEPS[i];
  const when = run.start + i * 10 * MINUTE;
  const request = await requestFor(i);
  if (step.kind === 'refused') {
    // The supplier checked the request against the slip, refused it, and
    // says so in a record of its own.
    const refusal = await writeRefusal(
      { slip: run.slipFingerprint, by: { keys: run.serviceKeys, name: SUPPLIER_NAME }, action: request.action, amount: request.amount, reason: 'over-limit', when },
      run.servicePrivateKeys,
    );
    run.entries.push({ refusal: refusal.record });
    return;
  }
  const stub = await writeStub(
    {
      slip: run.slipFingerprint,
      after: run.after,
      ...request,
      approval: approval?.fingerprint,
      terms: request.with ? run.terms : undefined,
      when,
    },
    run.agentPrivateKeys,
  );
  const entry = { stub: stub.record };
  if (approval) entry.approval = approval.record;
  if (step.countersigned) entry.countersignature = await countersign(stub.record, run.servicePrivateKeys, when + MINUTE);
  run.entries.push(entry);
  run.after = { seq: stub.seq, fingerprint: stub.fingerprint };
}
