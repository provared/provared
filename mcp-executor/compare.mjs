// Hold the executor's own copy against a book (the agent's log). The
// Internet-Draft (Section 18, "Omission, one side's word") says a receipt
// that was never written is found only by comparing the executor's own
// records with the log, and does not specify how. This is one way.
//
// What it can find: a call the executor sent whose receipt is not in the
// book ("missing"); one whose receipt the executor itself could not write
// ("notWritten": its own stop, apart from an omission by whoever keeps the
// book); a call whose receipt in the book is not the one the executor wrote
// ("differs"); a receipt in the book that names the executor but that the
// executor's copy does not know ("notInCopy"); a denial the executor wrote
// that the book lacks; a call the executor sent and never gave a receipt
// ("unfinished"). What it cannot find: a call that never went through the
// executor; whether a tool did what its result says; a copy changed by
// whoever holds the copy key; a copy cut at its end.

import { checkBook, identifierFingerprint } from 'provared';
import { readCopy } from './copy.mjs';
import { CALL_DOCUMENT } from './executor.mjs';

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
  // The book's stubs that name the executor, by the fingerprint of their executor.call document.
  const stubsByCall = new Map();
  const stubsWithoutCall = [];
  const denials = new Set();
  for (const e of checked.entries) {
    if (e.kind === 'denial' && e.fingerprint) denials.add(e.fingerprint);
    if (e.kind !== 'stub' || e.content?.with !== service) continue;
    const doc = Array.isArray(e.content.details) ? e.content.details.find((d) => d.name === CALL_DOCUMENT) : undefined;
    if (!doc) stubsWithoutCall.push({ entry: e.index, stub: e.fingerprint, countersignature: e.countersignature?.state ?? 'absent' });
    else stubsByCall.set(doc.sha256, { entry: e.index, stub: e.fingerprint, countersignature: e.countersignature?.state ?? 'absent' });
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
    missing: [],
    notWritten: [],
    unfinished: [],
    refused: [],
    denialsMissing: [],
    notInCopy: [],
    withdrawn: 0,
    copy: { lines: copy.lines.length, checked: copy.checked, refused: copy.refused, cut: copy.cut !== null, sequence: copy.sequence },
    book: { entries: checked.entries.length, problemFound: checked.summary.problemFound, fullyChecked: checked.summary.fullyChecked },
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
    const inBook = stubsByCall.get(key);
    if (inBook) seen.add(key);
    const about = { call: c.call, when: c.sending.when, tool: c.sending.tool, action: c.sending.action };
    if (!c.done) {
      result.unfinished.push({ ...about, inBook: inBook ? inBook.stub : null });
      continue;
    }
    if (typeof c.done.stub !== 'string') {
      // The executor itself could not write the stub to the book file: its own stop, not an omission by the book's keeper.
      if (inBook) result.matched.push({ call: c.call, entry: inBook.entry, stub: inBook.stub, countersignature: inBook.countersignature, note: 'written at a later start' });
      else result.notWritten.push({ ...about, documents: c.done.documents ?? [] });
      continue;
    }
    if (!inBook) {
      result.missing.push({ ...about, stub: c.done.stub });
      continue;
    }
    if (c.done.stub !== inBook.stub) result.differs.push({ ...about, inCopy: c.done.stub, inBook: inBook.stub, entry: inBook.entry });
    else result.matched.push({ call: c.call, entry: inBook.entry, stub: inBook.stub, countersignature: inBook.countersignature, ...(c.lateWritten ? { note: 'written at a later start' } : {}) });
  }
  for (const [key, s] of stubsByCall) if (!seen.has(key)) result.notInCopy.push(s);
  result.notInCopy.push(...stubsWithoutCall);
  result.summary = {
    sent: result.matched.length + result.differs.length + result.missing.length + result.notWritten.length + result.unfinished.length,
    matched: result.matched.length,
    missingFromBook: result.missing.length,
    notWrittenByExecutor: result.notWritten.length,
    differ: result.differs.length,
    unfinished: result.unfinished.length,
    notInCopy: result.notInCopy.length,
    denialsMissingFromBook: result.denialsMissing.length,
    bookProblem: checked.summary.problemFound,
    agree:
      result.missing.length === 0 &&
      result.differs.length === 0 &&
      result.notWritten.length === 0 &&
      result.unfinished.length === 0 &&
      result.notInCopy.length === 0 &&
      result.denialsMissing.length === 0 &&
      copy.refused === 0 &&
      copy.cut === null &&
      copy.sequence.ok &&
      !checked.summary.problemFound,
  };
  result.notShown = [
    'A call that did not go through the executor.',
    "Whether a tool did what its result says: the copy holds fingerprints of what was sent and what came back, not the tool's work.",
    'A copy changed by whoever holds the copy key, or cut at its end.',
    'Receipts of this agent that name another service, or none: the copy knows only calls through this executor.',
  ];
  return result;
}
