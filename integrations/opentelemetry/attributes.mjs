// What Provared puts on a trace span, and nothing more.
//
// This file does not import OpenTelemetry. It works on any object with
// "setAttribute" (and, where asked for, "addEvent" and "setStatus"), so it
// can be used with OpenTelemetry's own span, with another tracing library,
// or in a test. index.mjs, beside it, uses it with OpenTelemetry's API.
//
// What reaches a span is what a receipt itself holds: fingerprints, names
// and codes. Never a call's arguments, never a document, never a key or a
// passkey value, never the text of a finding (which may give an amount),
// never an error's message (which may quote what the tool was given).

import { FINDING_CODES, denialCodes, fromBase64url } from 'provared';

/** The names of the attributes this bridge sets, under Provared's own namespace. */
export const ATTRIBUTES = Object.freeze({
  /** "taken" (the tool ran, and its receipt is written), "not_taken" (the check before acting said no; the tool did not run) or "error" (the call ended with an error and no receipt). */
  outcome: 'provared.outcome',
  /** The action name, as the permission (the slip) names it. */
  action: 'provared.action',
  /** Where the call was not taken: the finding codes of the check before acting, as a list of text. */
  codes: 'provared.check.codes',
  /** The receipt's fingerprint: the SHA-256, in base64url, of its content. */
  stubFingerprint: 'provared.stub.fingerprint',
  /** The receipt's place in its chain, from 0. */
  stubSeq: 'provared.stub.seq',
  /** True where the other side's countersignature was checked and kept with the receipt. */
  countersigned: 'provared.stub.countersigned',
  /** True where the receipt names this span's trace, as the document "provared.trace-id". */
  traceBound: 'provared.stub.trace_bound',
  /** The fingerprint of the permission (the slip) the receipt or the denial relies on. */
  slipFingerprint: 'provared.slip.fingerprint',
  /** Where the call was not taken and the stub writer wrote a denial: the denial's fingerprint. */
  denialFingerprint: 'provared.denial.fingerprint',
});

/** The name of the span event for a call that was not taken, where one is asked for. */
export const NOT_TAKEN_EVENT = 'provared.not_taken';

/** The three values of "provared.outcome". */
export const OUTCOMES = Object.freeze(['taken', 'not_taken', 'error']);

// A SHA-256 fingerprint in base64url: 43 characters.
const FINGERPRINT = /^[A-Za-z0-9_-]{43}$/;
// An action name is a short name the slip's issuer chose (format description, section 4.1).
const ACTION = /^[\x21-\x7e]{1,64}$/;

const fingerprintOrNull = (value) => (typeof value === 'string' && FINGERPRINT.test(value) ? value : null);
/** The value where it is an action name (1 to 64 visible ASCII characters), or null. */
export const actionOrNull = (value) => (typeof value === 'string' && ACTION.test(value) ? value : null);

// The content of a signed record, read from its payload. Nothing is checked
// here: the stub writer wrote and checked it a moment before.
function contentOf(record) {
  try {
    const content = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(fromBase64url(record.payload)));
    return content !== null && typeof content === 'object' && !Array.isArray(content) ? content : null;
  } catch {
    return null;
  }
}

/**
 * The finding codes of an answer of the check before acting, as a denial
 * would name them: only codes from the library's own list, each once. An
 * answer that gives none is "check-failed".
 * @param {{problems?: object[], breaches?: object[]}} answer
 * @returns {string[]}
 */
export function codesOf(answer) {
  const a = answer && typeof answer === 'object' ? answer : {};
  return denialCodes({ problems: Array.isArray(a.problems) ? a.problems : [], breaches: Array.isArray(a.breaches) ? a.breaches : [] }).filter((c) => FINDING_CODES.includes(c) || c === 'check-failed');
}

/**
 * The attributes for one call, from what the stub writer gave back.
 *
 * @param {object} facts
 * @param {'taken'|'not_taken'|'error'} facts.outcome
 * @param {string} [facts.action] the action name the call was asked for under
 * @param {object} [facts.stub] the written stub, as "act" or "onStub" gives it ({record, fingerprint, seq, countersignature})
 * @param {object} [facts.answer] the answer of the check before acting, for a call not taken
 * @param {object} [facts.denial] what the stub writer said of the denial it wrote, or did not write
 * @param {boolean} [facts.traceBound] whether the receipt names the span's trace
 * @returns {Record<string, string|number|boolean|string[]>}
 */
export function attributesFor(facts) {
  const out = {};
  if (!facts || !OUTCOMES.includes(facts.outcome)) return out;
  out[ATTRIBUTES.outcome] = facts.outcome;
  let action = actionOrNull(facts.action);
  if (facts.outcome === 'taken' && facts.stub && typeof facts.stub === 'object') {
    const content = facts.stub.record ? contentOf(facts.stub.record) : null;
    if (content) action = actionOrNull(content.action) ?? action;
    const stub = fingerprintOrNull(facts.stub.fingerprint);
    if (stub) out[ATTRIBUTES.stubFingerprint] = stub;
    if (Number.isSafeInteger(facts.stub.seq) && facts.stub.seq >= 0) out[ATTRIBUTES.stubSeq] = facts.stub.seq;
    const slip = content ? fingerprintOrNull(content.slip) : null;
    if (slip) out[ATTRIBUTES.slipFingerprint] = slip;
    out[ATTRIBUTES.countersigned] = facts.stub.countersignature?.accepted === true;
    out[ATTRIBUTES.traceBound] = facts.traceBound === true;
  }
  if (facts.outcome === 'not_taken') {
    out[ATTRIBUTES.codes] = codesOf(facts.answer);
    const denial = facts.denial && typeof facts.denial === 'object' && facts.denial.written === true ? facts.denial : null;
    const denialFingerprint = denial ? fingerprintOrNull(denial.fingerprint) : null;
    if (denialFingerprint) {
      out[ATTRIBUTES.denialFingerprint] = denialFingerprint;
      // The denial names the slip it relies on: read it from the line the writer wrote.
      let slip = null;
      try {
        const entry = JSON.parse(denial.line);
        const content = entry && entry.denial ? contentOf(entry.denial) : null;
        slip = content ? fingerprintOrNull(content.slip) : null;
      } catch {
        slip = null;
      }
      if (slip) out[ATTRIBUTES.slipFingerprint] = slip;
    }
  }
  if (action) out[ATTRIBUTES.action] = action;
  return out;
}

/**
 * Put the attributes for one call on a span: any object with
 * "setAttribute(name, value)". Where "event" is true and the call was not
 * taken, a span event "provared.not_taken" is added too, with the action,
 * the codes and the denial's fingerprint, through "addEvent(name,
 * attributes)" where the span has it.
 *
 * @param {{setAttribute: Function, addEvent?: Function}|null|undefined} span
 * @param {object} facts as for attributesFor
 * @param {{event?: boolean}} [options]
 * @returns {Record<string, string|number|boolean|string[]>} what was set
 */
export function annotate(span, facts, options = {}) {
  const attributes = attributesFor(facts);
  if (!span || typeof span.setAttribute !== 'function') return attributes;
  for (const [name, value] of Object.entries(attributes)) span.setAttribute(name, value);
  if (options && options.event === true && facts.outcome === 'not_taken' && typeof span.addEvent === 'function') {
    const event = {};
    for (const name of [ATTRIBUTES.action, ATTRIBUTES.codes, ATTRIBUTES.denialFingerprint]) if (name in attributes) event[name] = attributes[name];
    span.addEvent(NOT_TAKEN_EVENT, event);
  }
  return attributes;
}
