// Hold the executor's own copy against a book (the agent's log). The
// Internet-Draft (Section 18, "Omission, one side's word") says a receipt
// that was never written is found only by comparing the executor's own
// records with the log, and does not specify how. This is one way.
//
// What it can find: a call the executor sent whose receipt is not in the
// book ("missing"); one whose receipt the executor itself could not write
// ("notWritten": its own stop, apart from an omission by whoever keeps the
// book); a call whose receipt in the book is not the one the executor wrote,
// or is not the call the copy shows as sent ("differs"); a receipt that
// lacks the countersignature the copy says the executor gave it, or carries
// another ("countersignatures"); more than one receipt for one call
// ("moreThanOne"); a receipt in the book that names the executor but that the
// executor's copy does not know ("notInCopy"); a denial the executor wrote
// that the book lacks; a call the executor sent and never gave a receipt
// ("unfinished"); a call the executor sent that the administrator set
// aside, which has no receipt ("setAside": the copy and the book then do
// not agree, since the book does not show a call that was sent). Beside these it reports the executor's receipts and
// denials under a slip that states rules on content (an agent.software
// entry named "Content rules of ...") that name no rules file
// ("withoutRules"): records of an executor that ran without the rules the
// person approved. What it cannot find: a call that never went through the
// executor; whether a tool did what its result says; a copy changed by
// whoever holds the copy key; a copy cut at its end.

import { checkBook, identifierFingerprint } from 'provared';
import { countersignatureFingerprint, readCopy, stubIsSending } from './copy.mjs';
import { AFTER_DOCUMENTS, CALL_DOCUMENT, RULES_DOCUMENT } from './executor.mjs';
import { statesContentRules } from './rules.mjs';

/**
 * @param {object} o
 * @param {string} o.copyPath the executor's copy file
 * @param {Buffer} o.copyKey its key
 * @param {string} o.name the executor's name (part of each tag)
 * @param {string} o.service the id the slip gives the executor in "with"
 * @param {string} o.book the book's text
 * @param {object} [o.options] options for checkBook (issuerKeys, …)
 */
export async function compareCopyWithBook({ copyPath, copyKey, name, service, book, options = {} }) {
  const copy = readCopy(copyPath, copyKey, name);
  const checked = await checkBook(book, options);
  const bookLines = book.split('\n');
  // The book's stubs that name the executor, every one, by the fingerprint of their executor.call document.
  const stubsByCall = new Map();
  const stubsWithoutCall = [];
  const denials = new Set();
  // The rules on content each record names (executor.rules), and what the book's slips state of the agent's software.
  const rulesSeen = new Map();
  const stated = new Set();
  // The slips (by fingerprint) whose agent.software holds an entry named as rules on content, and the executor's records under them that name no rules file.
  const slipsStatingRules = new Set();
  const withoutRules = [];
  const noteRules = (e, kind) => {
    const doc = Array.isArray(e.content?.details) ? e.content.details.find((d) => d.name === RULES_DOCUMENT) : undefined;
    if (!doc) return;
    const r = rulesSeen.get(doc.sha256) ?? { sha256: doc.sha256, receipts: 0, denials: 0 };
    r[kind]++;
    rulesSeen.set(doc.sha256, r);
  };
  for (const e of checked.entries) {
    if (e.kind === 'slip' && Array.isArray(e.content?.agent?.software)) for (const x of e.content.agent.software) if (typeof x?.sha256 === 'string') stated.add(x.sha256);
    if (e.kind === 'slip' && e.fingerprint && statesContentRules(e.content?.agent?.software)) slipsStatingRules.add(e.fingerprint);
    if ((e.kind === 'stub' || e.kind === 'denial') && e.content?.with === service && slipsStatingRules.has(e.content.slip)) {
      const named = Array.isArray(e.content.details) && e.content.details.some((d) => d.name === RULES_DOCUMENT);
      if (!named) withoutRules.push({ kind: e.kind === 'stub' ? 'receipt' : 'denial', entry: e.index, fingerprint: e.fingerprint, slip: e.content.slip });
    }
    if (e.kind === 'denial' && e.fingerprint) denials.add(e.fingerprint);
    if (e.kind === 'denial' && e.content?.with === service) noteRules(e, 'denials');
    if (e.kind === 'stub' && e.content?.with === service) noteRules(e, 'receipts');
    if (e.kind !== 'stub' || e.content?.with !== service) continue;
    const doc = Array.isArray(e.content.details) ? e.content.details.find((d) => d.name === CALL_DOCUMENT) : undefined;
    if (!doc) stubsWithoutCall.push({ entry: e.index, stub: e.fingerprint, countersignature: e.countersignature?.state ?? 'absent' });
    else stubsByCall.set(doc.sha256, [...(stubsByCall.get(doc.sha256) ?? []), { entry: e.index, stub: e.fingerprint, countersignature: e.countersignature?.state ?? 'absent', content: e.content, countersignedBy: await countersignatureFingerprint(bookLines[e.index] ?? '') }]);
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
    withdrawn: 0,
    copy: { lines: copy.lines.length, checked: copy.checked, refused: copy.refused, cut: copy.cut !== null, sequence: copy.sequence },
    // "sealersExpected": the recorders a seal in the book had to be signed by (key-set fingerprints), or null where none was named and a seal's keys were compared with nothing.
    book: { entries: checked.entries.length, problemFound: checked.summary.problemFound, fullyChecked: checked.summary.fullyChecked, seals: checked.entries.filter((e) => e.kind === 'seal').length, sealersExpected: Array.isArray(options.sealKeys) ? [...options.sealKeys] : null },
  };
  const seen = new Set();
  for (const c of calls.values()) {
    if (c.withdrawn) {
      result.withdrawn++;
      continue;
    }
    if (c.refused) {
      const d = c.refused.denial;
      result.refused.push({ call: c.call, when: c.refused.when, tool: c.refused.tool, reason: c.refused.reason, denial: d ?? null, denialInBook: d ? denials.has(d) : null });
      if (d && !denials.has(d)) result.denialsMissing.push({ call: c.call, denial: d });
      continue;
    }
    if (!c.sending) continue;
    const key = await identifierFingerprint(c.call);
    const all = stubsByCall.get(key) ?? [];
    if (all.length) seen.add(key);
    const about = { call: c.call, when: c.sending.when, tool: c.sending.tool, action: c.sending.action };
    if (all.length > 1) result.moreThanOne.push({ ...about, stubs: all.map((s) => s.stub), entries: all.map((s) => s.entry) });
    // The receipt the copy names, where the book holds it; else the first the book holds for the call.
    const inBook = all.find((s) => s.stub === c.done?.stub) ?? all[0];
    if (c['set-aside'] && typeof c.done?.stub !== 'string') {
      // Sent, and set aside by the administrator: the executor wrote no receipt for it, and writes none.
      result.setAside.push({ ...about, setAsideAt: c['set-aside'].when, inBook: inBook ? inBook.stub : null });
      continue;
    }
    if (!c.done) {
      result.unfinished.push({ ...about, inBook: inBook ? inBook.stub : null });
      continue;
    }
    if (typeof c.done.stub !== 'string' && !inBook) {
      // The executor itself could not write the stub to the book file: its own stop, not an omission by the book's keeper.
      result.notWritten.push({ ...about, documents: c.done.documents ?? [] });
      continue;
    }
    if (!inBook) {
      result.missing.push({ ...about, stub: c.done.stub });
      continue;
    }
    // Where the copy has no "done" line naming a stub, the receipt was written at a later start.
    const late = typeof c.done.stub !== 'string';
    if (!late && c.done.stub !== inBook.stub) {
      result.differs.push({ ...about, inCopy: c.done.stub, inBook: inBook.stub, entry: inBook.entry, why: 'another stub' });
      continue;
    }
    // The receipt's content against the copy's "sending" line, and, after it, the documents the "done" line holds.
    if (!stubIsSending(inBook.content, c.sending, { after: !late && Array.isArray(c.done.documents) ? c.done.documents : undefined, outcomes: AFTER_DOCUMENTS })) {
      result.differs.push({ ...about, inCopy: late ? null : c.done.stub, inBook: inBook.stub, entry: inBook.entry, why: 'not the call sent' });
      continue;
    }
    // The countersignature the copy says the executor gave: there, valid, and, where the copy records it, the same.
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
  for (const [key, list] of stubsByCall) if (!seen.has(key)) for (const { content, countersignedBy, ...s } of list) result.notInCopy.push(s);
  // Which rules on content the executor's records name, and whether a slip in the book states them (a statement, not proof).
  result.contentRules = [...rulesSeen.values()].map((r) => ({ ...r, statedInSlip: stated.has(r.sha256) }));
  // Receipts and denials of the executor under a slip that states rules on content, which name no rules file: the executor ran without rules the person approved.
  result.withoutRules = withoutRules;
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
    copy.refused === 0 &&
    copy.cut === null &&
    copy.sequence.ok &&
    !checked.summary.problemFound;
  result.summary = {
    sent: result.matched.length + result.differs.length + result.countersignatures.length + result.missing.length + result.notWritten.length + result.unfinished.length + result.setAside.length,
    matched: result.matched.length,
    setAside: result.setAside.length,
    missingFromBook: result.missing.length,
    notWrittenByExecutor: result.notWritten.length,
    differ: result.differs.length,
    countersignatureProblems: result.countersignatures.length,
    moreThanOneReceipt: result.moreThanOne.length,
    unfinished: result.unfinished.length,
    notInCopy: result.notInCopy.length,
    denialsMissingFromBook: result.denialsMissing.length,
    withoutRules: result.withoutRules.length,
    bookProblem: checked.summary.problemFound,
    // A call set aside is a call the executor sent that the book does not show: the two never agree while there is one.
    agree: restAgrees && result.setAside.length === 0,
    // True where the calls set aside are the only disagreement, so that this known state can be told from a new one.
    onlySetAside: restAgrees && result.setAside.length > 0,
  };
  result.notShown = [
    'A call that did not go through the executor.',
    "Whether a tool did what its result says: the copy holds fingerprints of what was sent and what came back, not the tool's work.",
    'A copy changed by whoever holds the copy key, or cut at its end.',
    'Receipts of this agent that name another service, or none: the copy knows only calls through this executor.',
    "Whether the rules on content a receipt names (executor.rules) were right, or were applied: the fingerprint says which rules file the executor held; a slip's agent.software says which the person approved; neither shows what the rules did.",
  ];
  return result;
}
