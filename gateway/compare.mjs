// Hold the gateway's own copy of an agent's calls (copy.mjs) against the
// agent's book. It works as the MCP executor's comparison does (its
// DESIGN.md, section 7): a receipt that was never written is found only by
// comparing the records of the party that let the call through with the
// log.
//
// What it can find: a call the gateway sent whose receipt is not in the
// book ("missing"); one whose receipt the gateway itself could not write
// ("notWritten": its own stop, apart from an omission by whoever keeps the
// book); a call whose receipt in the book is not the one the gateway wrote
// ("differs"); a receipt in the book under a service the slip gives the
// gateway's own keys for, that the gateway's copy does not know
// ("notInCopy"); a denial the gateway wrote that the book lacks; a call the
// gateway sent and never gave a receipt ("unfinished"); a call the gateway
// sent that the administrator set aside, which has no receipt ("setAside").
// What it cannot find: a call that never went through the gateway; whether
// an upstream did what its answer says; a copy changed by whoever holds the
// copy key; a copy cut at its end.

import { checkBook, identifierFingerprint } from 'provared';
import { readCopy } from './copy.mjs';
import { CALL_DOCUMENT, gatewayServices } from './gateway.mjs';

/**
 * @param {object} o
 * @param {string} o.copyPath the agent's copy file
 * @param {Buffer} o.copyKey its key
 * @param {string} o.name the agent's name (part of each tag)
 * @param {object[]} o.keys the gateway's public keys
 * @param {string} o.book the book's text
 * @param {object} [o.options] options for checkBook (issuerKeys, …)
 */
export async function compareCopyWithBook({ copyPath, copyKey, name, keys, book, options = {} }) {
  const copy = readCopy(copyPath, copyKey, name);
  const checked = await checkBook(book, options);
  // The services each slip of the book gives the gateway's keys for.
  const ownBySlip = new Map();
  for (const e of checked.entries) if (e.kind === 'slip' && e.fingerprint) ownBySlip.set(e.fingerprint, gatewayServices(e.content, keys));
  const isGateways = (e) => ownBySlip.get(e.content?.slip)?.has(e.content?.with) === true;
  // The book's stubs that name a gateway.call document, by its fingerprint; and those of the gateway's services that name none.
  const stubsByCall = new Map();
  const stubsWithoutCall = [];
  const denials = new Set();
  for (const e of checked.entries) {
    if (e.kind === 'denial' && e.fingerprint) denials.add(e.fingerprint);
    if (e.kind !== 'stub') continue;
    const doc = Array.isArray(e.content?.details) ? e.content.details.find((d) => d.name === CALL_DOCUMENT) : undefined;
    const about = { entry: e.index, stub: e.fingerprint, with: e.content?.with ?? null, countersignature: e.countersignature?.state ?? 'absent', gateways: isGateways(e) };
    if (doc) stubsByCall.set(doc.sha256, about);
    else if (about.gateways) stubsWithoutCall.push(about);
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
    setAside: [],
    refused: [],
    denialsMissing: [],
    notInCopy: [],
    withdrawn: 0,
    copy: { lines: copy.lines.length, checked: copy.checked, refused: copy.refused, cut: copy.cut !== null, sequence: copy.sequence },
    // "sealersExpected": the recorders a seal in the book had to be signed by (key-set fingerprints), or null where none was named and a seal's keys were compared with nothing.
    book: { entries: checked.entries.length, problemFound: checked.summary.problemFound, fullyChecked: checked.summary.fullyChecked, seals: checked.entries.filter((e) => e.kind === 'seal').length, sealersExpected: Array.isArray(options.sealKeys) ? [...options.sealKeys] : null },
  };
  const strip = ({ gateways, ...rest }) => rest;
  const seen = new Set();
  for (const c of calls.values()) {
    if (c.withdrawn) {
      result.withdrawn++;
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
    const inBook = stubsByCall.get(key);
    if (inBook) seen.add(key);
    const about = { call: c.call, when: c.sending.when, upstream: c.sending.upstream, action: c.sending.action };
    if (c['set-aside'] && typeof c.done?.stub !== 'string') {
      // Sent, and set aside by the administrator: the gateway wrote no receipt for it, and writes none.
      result.setAside.push({ ...about, setAsideAt: c['set-aside'].when, inBook: inBook ? inBook.stub : null });
      continue;
    }
    if (!c.done) {
      result.unfinished.push({ ...about, inBook: inBook ? inBook.stub : null });
      continue;
    }
    if (typeof c.done.stub !== 'string') {
      // The gateway itself could not write the stub to the book file: its own stop, not an omission by the book's keeper.
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
  // A receipt under a service the slip gives the gateway's keys for, that the copy does not know: not written by this gateway.
  for (const [k, s] of stubsByCall) if (!seen.has(k) && s.gateways) result.notInCopy.push(strip(s));
  result.notInCopy.push(...stubsWithoutCall.map(strip));
  // Whether the copy and the book agree but for calls the administrator set aside.
  const restAgrees =
    result.missing.length === 0 &&
    result.differs.length === 0 &&
    result.notWritten.length === 0 &&
    result.unfinished.length === 0 &&
    result.notInCopy.length === 0 &&
    result.denialsMissing.length === 0 &&
    copy.refused === 0 &&
    copy.cut === null &&
    copy.sequence.ok &&
    !checked.summary.problemFound;
  result.summary = {
    sent: result.matched.length + result.differs.length + result.missing.length + result.notWritten.length + result.unfinished.length + result.setAside.length,
    matched: result.matched.length,
    setAside: result.setAside.length,
    missingFromBook: result.missing.length,
    notWrittenByGateway: result.notWritten.length,
    differ: result.differs.length,
    unfinished: result.unfinished.length,
    notInCopy: result.notInCopy.length,
    denialsMissingFromBook: result.denialsMissing.length,
    bookProblem: checked.summary.problemFound,
    // A call set aside is a call the gateway sent that the book does not show: the two never agree while there is one.
    agree: restAgrees && result.setAside.length === 0,
    // True where the calls set aside are the only disagreement, so that this known state can be told from a new one.
    onlySetAside: restAgrees && result.setAside.length > 0,
  };
  result.notShown = [
    'A call that did not go through the gateway.',
    "Whether an upstream did what its answer says: the copy holds fingerprints of what was sent and what came back, not the upstream's work.",
    'A copy changed by whoever holds the copy key, or cut at its end.',
    "Receipts of this agent under a service the slip does not give the gateway's keys for, which name no call of the copy: the gateway does not countersign them, so anyone who holds the agent's keys could have written them.",
  ];
  return result;
}
