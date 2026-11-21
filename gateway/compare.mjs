// Hold the gateway's own copy of an agent's calls (copy.mjs) against the
// agent's book. It works as the MCP executor's comparison does (its
// DESIGN.md, section 7): a receipt that was never written is found only by
// comparing the records of the party that let the call through with the
// log.
//
// What it can find: a call the gateway sent whose receipt is not in the
// book ("missing"); one whose receipt the gateway itself could not write
// ("notWritten": its own stop, apart from an omission by whoever keeps the
// book); a call whose receipt in the book is not the one the gateway wrote,
// or is not the call the copy shows as sent ("differs"); a receipt that
// lacks the countersignature the copy says the gateway gave it, or carries
// another ("countersignatures"); more than one receipt for one call
// ("moreThanOne"); a receipt in the book that names the gateway, that the
// gateway's copy does not know ("notInCopy"); a denial the gateway wrote
// that the book lacks; a call the gateway sent and never gave a receipt
// ("unfinished"); a call the gateway sent that the administrator set aside,
// which has no receipt ("setAside"). It lists by name the calls the copy
// shows as withdrawn. What it cannot find: a call that never went through
// the gateway; whether an upstream did what its answer says; a copy changed
// by whoever holds the copy key; a copy cut at its end.

import { checkBook, identifierFingerprint } from 'provared';
import { countersignatureFingerprint, readCopy, stubIsSending } from './copy.mjs';
import { CALL_DOCUMENT, OUTCOME_DOCUMENTS } from './gateway.mjs';

/**
 * @param {object} o
 * @param {string} o.copyPath the agent's copy file
 * @param {Buffer} o.copyKey its key
 * @param {string} o.name the agent's name (part of each tag)
 * @param {string} o.service the gateway's id in a slip's "with"
 * @param {string} o.book the book's text
 * @param {object} [o.options] options for checkBook (issuerKeys, …)
 */
export async function compareCopyWithBook({ copyPath, copyKey, name, service, book, options = {} }) {
  const copy = readCopy(copyPath, copyKey, name);
  const checked = await checkBook(book, options);
  const bookLines = book.split('\n');
  // The book's stubs that name a gateway.call document, every one, by its fingerprint; and those naming the gateway that name none.
  const stubsByCall = new Map();
  const stubsWithoutCall = [];
  const denials = new Set();
  for (const e of checked.entries) {
    if (e.kind === 'denial' && e.fingerprint) denials.add(e.fingerprint);
    if (e.kind !== 'stub') continue;
    const doc = Array.isArray(e.content?.details) ? e.content.details.find((d) => d.name === CALL_DOCUMENT) : undefined;
    const about = { entry: e.index, stub: e.fingerprint, with: e.content?.with ?? null, countersignature: e.countersignature?.state ?? 'absent' };
    const held = { ...about, content: e.content, countersignedBy: await countersignatureFingerprint(bookLines[e.index] ?? '') };
    if (doc) stubsByCall.set(doc.sha256, [...(stubsByCall.get(doc.sha256) ?? []), held]);
    else if (about.with === service) stubsWithoutCall.push(about);
  }
  // The copy's calls, each with its last line of each kind; a "done" that names a stub is never replaced by one that does not.
  const calls = new Map();
  for (const l of copy.lines) {
    if (!l.valid || typeof l.entry.call !== 'string') continue;
    const c = calls.get(l.entry.call) ?? { call: l.entry.call };
    if (l.entry.kind === 'done' && typeof l.entry.stub !== 'string' && typeof c.done?.stub === 'string') continue;
    if (l.entry.kind === 'done' && typeof l.entry.stub === 'string' && c.done && typeof c.done.stub !== 'string') c.lateWritten = true;
    c[l.entry.kind] = l.entry;
    calls.set(l.entry.call, c);
  }
  const copyProblem = copy.refused > 0 || copy.cut !== null || !copy.sequence.ok;
  const result = {
    matched: [],
    differs: [],
    countersignatures: [],
    moreThanOne: [],
    missing: [],
    notWritten: [],
    unfinished: [],
    setAside: [],
    refused: [],
    denialsMissing: [],
    notInCopy: [],
    withdrawn: [],
    copy: { lines: copy.lines.length, checked: copy.checked, refused: copy.refused, cut: copy.cut !== null, sequence: copy.sequence, problem: copyProblem },
    // "sealersExpected": the recorders a seal in the book had to be signed by (key-set fingerprints), or null where none was named and a seal's keys were compared with nothing.
    book: { entries: checked.entries.length, problemFound: checked.summary.problemFound, fullyChecked: checked.summary.fullyChecked, withinSlips: checked.summary.withinSlips, seals: checked.entries.filter((e) => e.kind === 'seal').length, sealersExpected: Array.isArray(options.sealKeys) ? [...options.sealKeys] : null },
  };
  const shown = ({ content, countersignedBy, ...rest }) => rest;
  const seen = new Set();
  for (const c of calls.values()) {
    const about = { call: c.call, when: c.sending?.when ?? null, upstream: c.sending?.upstream ?? null, action: c.sending?.action ?? null };
    if (c.withdrawn) {
      result.withdrawn.push({ ...about, withdrawnAt: c.withdrawn.when ?? null, reason: c.withdrawn.reason ?? null });
      continue;
    }
    if (c.refused) {
      const d = c.refused.denial;
      result.refused.push({ call: c.call, when: c.refused.when, upstream: c.refused.upstream ?? null, action: c.refused.action, reason: c.refused.reason, denial: d ?? null, denialInBook: d ? denials.has(d) : null });
      if (d && !denials.has(d)) result.denialsMissing.push({ call: c.call, denial: d });
      continue;
    }
    if (!c.sending) continue;
    const key = await identifierFingerprint(c.call);
    const all = stubsByCall.get(key) ?? [];
    if (all.length) seen.add(key);
    if (all.length > 1) result.moreThanOne.push({ ...about, stubs: all.map((s) => s.stub), entries: all.map((s) => s.entry) });
    // The receipt the copy names, where the book holds it; else the first the book holds for the call.
    const inBook = all.find((s) => s.stub === c.done?.stub) ?? all[0];
    if (c['set-aside'] && typeof c.done?.stub !== 'string') {
      // Sent, and set aside by the administrator: the gateway wrote no receipt for it, and writes none.
      result.setAside.push({ ...about, setAsideAt: c['set-aside'].when, inBook: inBook ? inBook.stub : null });
      continue;
    }
    if (!c.done) {
      result.unfinished.push({ ...about, inBook: inBook ? inBook.stub : null });
      continue;
    }
    if (typeof c.done.stub !== 'string' && !inBook) {
      result.notWritten.push({ ...about, documents: c.done.documents ?? [] });
      continue;
    }
    if (!inBook) {
      result.missing.push({ ...about, stub: c.done.stub });
      continue;
    }
    // The gateway itself could not write the stub to the book file, and it is there now: written at a later start.
    const late = typeof c.done.stub !== 'string';
    if (!late && c.done.stub !== inBook.stub) {
      result.differs.push({ ...about, inCopy: c.done.stub, inBook: inBook.stub, entry: inBook.entry, why: 'another stub' });
      continue;
    }
    // The receipt's content against the copy's "sending" line, and, after it, the documents the "done" line holds.
    const after = !late && Array.isArray(c.done.documents) ? c.done.documents : undefined;
    if (!stubIsSending(inBook.content, c.sending, { after, outcomes: OUTCOME_DOCUMENTS })) {
      result.differs.push({ ...about, inCopy: late ? null : c.done.stub, inBook: inBook.stub, entry: inBook.entry, why: 'not the call sent' });
      continue;
    }
    // The countersignature the copy says the gateway gave: there, valid, and the same.
    if (!late && c.done.countersigned === true) {
      const wanted = typeof c.done.countersignature === 'string' ? c.done.countersignature : null;
      const problem = inBook.countersignature !== 'valid' ? (inBook.countersignature === 'absent' ? 'missing' : inBook.countersignature) : wanted !== null && inBook.countersignedBy !== wanted ? 'another' : null;
      if (problem) {
        result.countersignatures.push({ ...about, entry: inBook.entry, stub: inBook.stub, inCopy: wanted, inBook: inBook.countersignature === 'absent' ? null : inBook.countersignedBy, problem });
        continue;
      }
    }
    result.matched.push({ call: c.call, entry: inBook.entry, stub: inBook.stub, countersignature: inBook.countersignature, ...(late || c.lateWritten ? { note: 'written at a later start' } : {}) });
  }
  // A receipt that names the gateway, that the copy does not know: not written by this gateway.
  for (const [k, list] of stubsByCall) if (!seen.has(k)) for (const s of list) if (s.with === service) result.notInCopy.push(shown(s));
  result.notInCopy.push(...stubsWithoutCall);
  // Whether the copy and the book agree but for calls the administrator set aside.
  const restAgrees =
    result.missing.length === 0 &&
    result.differs.length === 0 &&
    result.countersignatures.length === 0 &&
    result.moreThanOne.length === 0 &&
    result.notWritten.length === 0 &&
    result.unfinished.length === 0 &&
    result.notInCopy.length === 0 &&
    result.denialsMissing.length === 0 &&
    !copyProblem &&
    !checked.summary.problemFound &&
    checked.summary.fullyChecked === true &&
    checked.summary.withinSlips === true;
  result.summary = {
    sent: result.matched.length + result.differs.length + result.countersignatures.length + result.missing.length + result.notWritten.length + result.unfinished.length + result.setAside.length,
    matched: result.matched.length,
    setAside: result.setAside.length,
    withdrawn: result.withdrawn.length,
    missingFromBook: result.missing.length,
    notWrittenByGateway: result.notWritten.length,
    differ: result.differs.length,
    countersignatureProblems: result.countersignatures.length,
    moreThanOneReceipt: result.moreThanOne.length,
    unfinished: result.unfinished.length,
    notInCopy: result.notInCopy.length,
    denialsMissingFromBook: result.denialsMissing.length,
    copyProblem,
    bookProblem: checked.summary.problemFound,
    bookFullyChecked: checked.summary.fullyChecked === true,
    bookWithinSlips: checked.summary.withinSlips === true,
    // A call set aside is a call the gateway sent that the book does not show: the two never agree while there is one.
    agree: restAgrees && result.setAside.length === 0,
    // True where the calls set aside are the only disagreement, so that this known state can be told from a new one.
    onlySetAside: restAgrees && result.setAside.length > 0,
  };
  result.notShown = [
    'A call that did not go through the gateway.',
    'A call that matches no rule, where "unlisted" is "forward": it is sent with no receipt and no line in the copy.',
    "Whether an upstream did what its answer says: the copy holds fingerprints of what was sent and what came back, not the upstream's work.",
    'A copy changed by whoever holds the copy key, or cut at its end.',
    "Receipts of this agent that do not name the gateway and name no call of the copy: the gateway does not countersign them, so anyone who holds the agent's keys could have written them.",
  ];
  return result;
}
