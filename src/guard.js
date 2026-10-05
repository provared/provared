// The check before acting: would this action be outside the slip?
//
// The software around an agent can ask this before each action, and stop the
// action when the answer is no. It uses the same comparison as the checker
// (compare.js), so nothing is allowed here that the checker would report
// afterwards. It refuses more in one case only: an action that would add to
// a period which a stub dated after it already overfills. It writes
// nothing and changes nothing.

import { MAX_ENTRIES, MAX_LINE_BYTES, checkApprovalRecord, checkBookKeepingState, fixedOptions, keysOf, passAsSlip } from './book.js';
import { compareWithSlip } from './compare.js';
import { Refusal, canonicalJson, formatTime, parseTime, problemFrom, utf8 } from './encoding.js';
import * as f from './fields.js';
import { validateRequest } from './stub.js';

const notSound = (why) => new Refusal('record-not-sound', why);

// An upper bound on the line that the record of an action will make: the
// stub with its two signatures, the approval that goes with it, and the
// other side's countersignature. A line of a book may not be longer than
// 131,072 bytes, and an action whose record would not fit is not allowed.
const STUB_BOUND = 6700 + 600;
const COUNTERSIGNATURE_BOUND = 6900;
function lineBound(c, approval) {
  let approvalBytes = 0;
  if (approval !== undefined) {
    try {
      approvalBytes = utf8(canonicalJson(approval)).length;
    } catch {
      approvalBytes = 0; // not a record at all: its own check refuses it
    }
  }
  return Math.ceil((utf8(canonicalJson(c)).length * 4) / 3) + STUB_BOUND + approvalBytes + COUNTERSIGNATURE_BOUND + 64;
}

/**
 * Ask whether an action the agent is about to take would be outside its slip.
 *
 * @param {string} book the book so far: the slip and every stub written under it
 * @param {object} proposal
 * @param {string} proposal.slip the fingerprint of the slip
 * @param {string} proposal.action
 * @param {{unit: string, value: number}} [proposal.amount]
 * @param {string} [proposal.with] the id of the service, as the slip names it
 * @param {{name: string, sha256: string}[]} [proposal.details]
 * @param {object} [proposal.approval] the person's signed approval of exactly this action, where the slip asks for one
 * @param {string} [proposal.terms] the fingerprint of the service's terms for agents, if they are in the book
 * @param {string} [proposal.pass] for a helper agent: the fingerprint of the pass it acts under
 * @param {number|Date} [proposal.when] defaults to now
 * @param {object} options the same options as checkBook
 * @param {string[]} options.issuerKeys the thumbprints of the passkeys this check trusts. It must be given:
 *   a slip signed by any other key allows nothing
 * @returns {Promise<{allowed: boolean, problems: {code: string, message: string}[], breaches: {code: string, message: string}[], needs: string[]}>}
 *   "allowed" is true only if the record so far is sound, this device
 *   checked every signature in it, and the action would be inside the slip.
 *   "needs" lists what the slip asks to go with the action. A needed
 *   approval must be handed over, or the action is not allowed. A needed
 *   countersignature cannot be known beforehand: the action is allowed, and
 *   is inside the slip only if the other side then countersigns it.
 */
export function checkBefore(book, proposal, options = {}) {
  // The options are read once, through the fixed copy a whole check reads
  // them through, for the book and for the decision alike.
  const fixed = fixedOptions(options);
  return decide(() => checkBookKeepingState(book, fixed), proposal, fixed);
}

/**
 * The same check, for a book that has already been read and is carried on
 * (recorder.js): nothing is read again. Not part of the public interface.
 * @param {() => Promise<{result: object, state: object, beside: Set<string>}>} read gives the answer for the book as it stands (answerOf in book.js)
 * @param {object} proposal as for checkBefore
 * @param {object} options as for checkBefore
 */
export function checkBeforeRead(read, proposal, options = {}) {
  return decide(read, proposal, options);
}

async function decide(read, proposal, options) {
  const answer = { allowed: false, problems: [], breaches: [], needs: [] };
  try {
    if (options === null || typeof options !== 'object') options = {};
    if (!Array.isArray(options.issuerKeys) || options.issuerKeys.length === 0) {
      throw notSound('The check before acting must be told which passkeys it trusts. A slip signed by any other key allows nothing.');
    }
    const { result, state, beside } = await read();
    if (result.summary.problemFound) throw notSound('A problem was found in the record so far. It must be looked at before the agent acts again.');
    // A record this device could only partly check is not a pass, here either.
    if (!result.summary.fullyChecked) throw notSound('This device could not check every signature in the record so far.');
    if (!result.entries.every((e) => (e.kind === 'stub' || e.kind === 'pass' ? e.compared === true : true))) {
      throw notSound('This device could not compare every stub and every pass in the record so far with its slip.');
    }
    if (result.size >= MAX_ENTRIES) throw new Refusal('too-large', 'The book is full: it holds 100,000 entries.');

    f.members(proposal, ['action', 'slip'], ['amount', 'approval', 'details', 'pass', 'terms', 'when', 'with'], 'proposal');
    const c = { action: proposal.action, when: formatTime(proposal.when ?? Date.now()) };
    for (const name of ['amount', 'details', 'with']) if (proposal[name] !== undefined) c[name] = proposal[name];
    validateRequest(c);
    const when = f.time(c.when, 'when');
    if (lineBound(c, proposal.approval) > MAX_LINE_BYTES) {
      throw new Refusal('too-large', 'The record of this action would be longer than a line of a book may be.');
    }

    const slip = state.slips.get(proposal.slip);
    if (!slip) throw new Refusal('slip-missing', 'The slip is not in the book.');
    if (!slip.verified) throw notSound('This device could not check the slip\'s signature.');
    // A helper agent acts under a pass, in a chain of its own.
    let pass = null;
    if (proposal.pass !== undefined) {
      pass = state.passes.get(proposal.pass);
      if (!pass || !pass.usable) throw new Refusal('pass-missing', 'The pass is not in the book, or did not pass its own check.');
      if (pass.content.slip !== proposal.slip) throw new Refusal('pass-mismatch', 'The pass was given under another slip.');
    }
    // The chain allows no stub dated before the one ahead of it.
    if (when < (pass ?? slip).lastWhen) throw new Refusal('time-went-backwards', 'The action is dated before the last stub in its chain.');

    const service = Object.hasOwn(c, 'with') ? slip.content.with.find((s) => s.id === c.with) : undefined;
    let terms;
    if (proposal.terms !== undefined) {
      const t = state.terms.get(proposal.terms);
      if (!t || !t.usable || !t.verified) throw new Refusal('terms-not-found', 'The terms are not in the book, or did not pass their check.');
      if (!keysOf(service) || canonicalJson(service.keys) !== canonicalJson(t.content.by.keys)) {
        throw new Refusal('terms-mismatch', 'The terms were not signed with the keys the slip gives for the service named.');
      }
      terms = t.content;
    }

    // Cancelled in the book, or by a cancellation that the person kept and handed over beside it.
    const cancelled = slip.cancelled !== null || beside.has(proposal.slip);
    const shown = compareWithSlip(slip.content, slip.tally, c, { service, terms, cancelled }, false);
    answer.needs = shown.needs;
    const breaches = [...shown.breaches];
    if (pass) {
      // The pass the helper acts under, and every pass above it, as the checker compares them.
      for (let p = pass; p; p = p.parent) {
        const under = compareWithSlip(passAsSlip(p.content), p.tally, c, { service, what: p === pass ? 'pass' : 'earlier-pass' }, false);
        for (const b of under.breaches) if (!breaches.some((x) => x.code === b.code)) breaches.push(b);
      }
      if (pass.notAllowed) breaches.push({ code: 'pass-not-allowed', message: 'The slip does not allow the pass this action would be taken under.' });
    }

    // The person's approval, checked as the checker will check it.
    if (proposal.approval !== undefined) {
      const ids = new Set(state.ids);
      ids.approvals = new Set(state.ids.approvals);
      const without = Array.isArray(options.withoutMethods) ? options.withoutMethods : [];
      const approval = await checkApprovalRecord(proposal.approval, c, proposal.slip, slip, ids, without);
      if (approval.state !== 'valid') throw notSound('This device could not check the approval\'s signature.');
      if (parseTime(approval.when) > when + 300 * 1000) {
        throw new Refusal('approval-dated-after-stub', 'The approval is dated later than the action.');
      }
    } else if (shown.needs.includes('approval')) {
      breaches.push({ code: 'approval-missing', message: 'The slip asks for the person\'s own approval of this action, and none was handed to this check.' });
    }
    // A countersignature cannot be known beforehand. But where the action
    // names no service, or one for which the slip gives no keys, none can
    // ever be given.
    if (shown.needs.includes('countersignature') && !keysOf(service)) {
      breaches.push({
        code: 'countersignature-missing',
        message: 'The slip asks for the other side to countersign this action, and the action names no service whose keys the slip gives. No countersignature could be given.',
      });
    }

    answer.breaches = breaches;
    answer.allowed = breaches.length === 0;
  } catch (e) {
    answer.problems.push(problemFrom(e));
  }
  return answer;
}
