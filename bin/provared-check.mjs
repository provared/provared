#!/usr/bin/env node
// provared-check: check a book or a Show from the command line.
//
//   provared-check <file> [--issuer <thumbprint>]... [--sealer <fingerprint>]... [--stamp-service <fingerprint>]...
//                  [--block <fingerprint>]... [--voucher <fingerprint>]... [--disclosures <file>] [--cancellation <file>]...
//                  [--root <top fingerprint>] [--size <entries>] [--json]
//
// Exit codes:
//   0  the record is intact (no problem found, every signature checked),
//      shows nothing outside the slip, and was checked against keys you
//      named: the passkey you trust and, where the record has a seal, the
//      recorder you expect
//   1  no problem was found, but the record shows the agent outside its
//      slip, or not every signature could be checked on this device, or
//      you did not name whom you trust
//   2  a problem was found in the record, it could not be read, or what
//      you gave on the command line could not be used
//
// It reads one file and writes to the terminal. It makes no network request.

import { readFileSync } from 'node:fs';
import { MIN_BLOCKS_AFTER, REFUSAL_REASONS, blocksInChain, checkBook, checkHeaderChain, checkShow, conditionWords, limitWords, neverWords } from '../src/check.js';

// Node.js marks its ML-DSA and SLH-DSA as experimental and says so on every
// run. The checker does not repeat that warning; any other warning is shown.
process.removeAllListeners('warning');
process.on('warning', (w) => {
  if (w.name !== 'ExperimentalWarning') console.error(`${w.name}: ${w.message}`);
});

const USAGE = `Usage: provared-check <file> [--issuer <thumbprint>]... [--sealer <fingerprint>]... [--stamp-service <fingerprint>]...
                      [--block <fingerprint>]... [--voucher <fingerprint>]... [--disclosures <file>] [--cancellation <file>]...
                      [--root <top fingerprint>] [--size <entries>] [--headers <file>] [--json]

  <file>           a book (one entry to a line) or a Show (one JSON object)
  --issuer         the thumbprint of an issuer key you already trust; may be repeated
  --sealer         the fingerprint of the key set of a recorder you expect to have sealed the book; may be repeated
  --stamp-service  the fingerprint of the certificate of a time-stamp service you trust; may be repeated
  --block          the fingerprint (64 hex characters) of a block of a public blockchain that you trust to be part of the chain;
                   a block time-stamp counts only if it leads to such a block; may be repeated
  --voucher        the fingerprint of the key set of an organisation whose vouching for names you trust; may be repeated
  --disclosures    a JSON file of the disclosures you were handed for covered fields: {"<fingerprint of a slip>": ["<disclosure>", ...]}
  --cancellation   a JSON file of the person's own copy of a cancellation, as the entry it would be in a book:
                   {"cancellation": {...}, "stamps": [...]}. It counts even where the book leaves it out; may be repeated.
                   It may hold "acknowledgements": what the agent's side signed when it was handed the cancellation
  --root           the top fingerprint you already trust
  --size           the number of entries you already trust; keep it with the top fingerprint
  --headers        a file of Bitcoin block headers, as provared-headers keeps it. It is checked here, from the chain's
                   first block, and a block time-stamp counts if its block is in that chain with at least six blocks after it
  --json           print the whole result as JSON, including what failed entries say

Evidence, not a verdict.`;

// A fingerprint or a thumbprint: SHA-256 in base64url, 43 characters. A
// block's fingerprint: 64 hexadecimal characters.
const FINGERPRINT = /^[A-Za-z0-9_-]{43}$/;
const BLOCK = /^[0-9a-f]{64}$/;

// Options that may be repeated, and those that may be given once.
const LISTS = { '--issuer': 'issuerKeys', '--sealer': 'sealKeys', '--stamp-service': 'stampServices', '--block': 'blocks', '--voucher': 'vouchers', '--cancellation': 'cancellations' };
const ONCE = { '--disclosures': 'disclosures', '--root': 'expectedRoot', '--size': 'expectedSize', '--headers': 'headers' };

// The arguments, or the reason they cannot be used. A value that is not a
// fingerprint is refused, never set aside: a typing error must not quietly
// leave a time-stamp or a name uncounted.
function parseArguments(argv) {
  const out = { file: null, issuerKeys: [], sealKeys: [], stampServices: [], blocks: [], vouchers: [], cancellations: [], disclosures: undefined, expectedRoot: undefined, expectedSize: undefined, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') return { help: true };
    if (a === '--json') {
      if (out.json) return { error: '--json may be given once.' };
      out.json = true;
    } else if (Object.hasOwn(LISTS, a) || Object.hasOwn(ONCE, a)) {
      if (i + 1 >= argv.length) return { error: `${a} needs a value.` };
      const value = argv[++i];
      if (Object.hasOwn(ONCE, a) && out[ONCE[a]] !== undefined) return { error: `${a} may be given once.` };
      if (['--issuer', '--sealer', '--stamp-service', '--voucher', '--root'].includes(a) && !FINGERPRINT.test(value)) {
        return { error: `The value of ${a} is not a fingerprint. A fingerprint is 43 letters, digits, hyphens or underscores, with no spaces.` };
      }
      if (a === '--block' && !BLOCK.test(value)) return { error: 'The value of --block is not the fingerprint of a block: 64 characters, the digits 0 to 9 and the letters a to f.' };
      if (a === '--size' && !/^\d{1,6}$/.test(value)) return { error: 'The value of --size is not a number of entries.' };
      if (Object.hasOwn(LISTS, a)) out[LISTS[a]].push(value);
      else out[ONCE[a]] = a === '--size' ? Number(value) : value;
    } else if (!a.startsWith('-') && out.file === null) out.file = a;
    else return { error: `${a.startsWith('-') ? 'Unknown option' : 'More than one file'}: ${safe(a)}` };
  }
  return out.file === null ? { error: 'No file was named.' } : out;
}

// Anything from a record is untrusted text. Control characters, characters
// that cannot be seen (zero-width characters, soft hyphens, line separators,
// fillers, variation selectors, the blank Braille pattern) and characters
// that change the direction of text are shown as a visible mark, so that a
// record cannot move the cursor, hide text, reorder it, or make two
// different labels look the same. \p{DI} is every character that Unicode
// says is to be left out when text is drawn.
const UNSAFE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cs}\p{DI}\u2800]/gu;

// Marks that are drawn on top of the character before them (accents, for
// one): more than three in a row can be drawn over the lines above and
// below, so the rest of such a run is shown as one mark.
const STACKED = /(?<=\p{M}{3})\p{M}+/gu;

function safe(text) {
  // Every run of spaces becomes one space, so that a label padded with
  // spaces cannot wrap onto a line of its own and look like the checker's words.
  return String(text).replace(UNSAFE, '\ufffd').replace(STACKED, '\ufffd').replace(/\p{Zs}+/gu, ' ');
}

// In JSON the same characters are written as escapes, which keeps the JSON
// exact and the terminal safe. JSON.stringify already escapes everything
// below U+0020 inside a string; the line feeds it adds between members are
// its own. So is each mark of a run of more than three.
const UNSAFE_IN_JSON = /(?![\n])[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{DI}\u2800]|(?<=\p{M}{3})\p{M}/gu;

function escaped(character) {
  let out = '';
  for (let i = 0; i < character.length; i++) out += '\\u' + character.charCodeAt(i).toString(16).padStart(4, '0');
  return out;
}

function safeJson(value) {
  return JSON.stringify(value, null, 2).replace(UNSAFE_IN_JSON, escaped);
}

// A name or a purpose from a record is free text of up to hundreds of
// characters. It is shown inside quotation marks, and any quotation mark
// inside it is shown as an apostrophe, so that a reader can see where the
// record's words end and the checker's begin.
const QUOTES = /["\p{Pi}\p{Pf}\uff02\u2033\u2036\u02ba\u02dd\u02ee\u301d\u301e\u301f\u275d\u275e\u2e42]/gu;
const label = (text) => `"${safe(text).replace(QUOTES, "'")}"`;

const yesNo = (value) => (value ? 'yes' : 'NO');

// What an entry says is printed only if the entry passed its check and this
// device could confirm at least one of its signatures. --json gives
// everything, for whoever must find out what went wrong.
function hidden(e) {
  if (e.problems.length) return '  What this entry says is not shown, because the entry did not pass its check.';
  if (e.verified === 'none') return '  What this entry says is not shown, because this device could not check its signature.';
  return null;
}

// What stands behind a name: an organisation the reader trusts, an
// organisation the reader did not name, or nothing.
const COVERED = '(covered: not shown to you)';
// A name or a purpose is read only where the record itself holds it.
const has = (object, name) => Object.hasOwn(object, name);
const nameOf = (object, name) => (has(object, name) ? label(object[name]) : COVERED);
// Who vouches for a service: only what the checker put there for that id.
const vouchedService = (e, id) => (Object.hasOwn(e.vouched.services, id) ? e.vouched.services[id] : null);

function standing(v) {
  if (v && v.counted) return `vouched for by ${label(v.by)}, key set ${v.keys}`;
  if (v) return `a label, not checked; ${label(v.by)} vouches for it, which you did not name as trusted`;
  return 'a label, not checked';
}

function printSlip(e) {
  console.log(`\nEntry ${e.index}: SLIP ${e.fingerprint ?? ''}`);
  if (hidden(e)) console.log(hidden(e));
  else {
    const c = e.content;
    console.log(`  Issuer:                        ${nameOf(c.issuer, 'name')}${has(c.issuer, 'name') ? ` (${standing(e.vouched.issuer)})` : ''}`);
    console.log(`  Issuer's key thumbprint:       ${e.issuerKey}`);
    console.log(`  Signed on:                     ${safe(c.issuer.origin)}`);
    console.log(`  Agent:                         ${nameOf(c.agent, 'name')}${has(c.agent, 'name') ? ` (${standing(e.vouched.agent)})` : ''}`);
    for (const s of has(c.agent, 'software') ? c.agent.software : []) console.log(`  Agent's software, as stated:   ${label(s.name)} (fingerprint ${safe(s.sha256)}). A statement, not proof of what ran.`);
    console.log(`  May do:                        ${c.actions.map(safe).join(', ')}`);
    for (const l of c.limits) console.log(`  Limit:                         ${safe(limitWords(l))}`);
    for (const r of c.requires) console.log(`  Condition:                     ${safe(conditionWords(r))}`);
    for (const n of c.never) console.log(`  Stated rule:                   ${safe(neverWords(n))}`);
    if (c.with.length === 0) console.log('  With:                          nobody named');
    for (const s of c.with) console.log(`  With:                          ${nameOf(s, 'name')} [${safe(s.id)}]${has(s, 'name') ? ` (${standing(vouchedService(e, s.id))})` : ''}`);
    if (has(c, 'passes')) console.log(`  May be passed on:              ${c.passes === 1 ? 'once, to a helper agent' : `${c.passes} times in a row, to helper agents`}`);
    console.log(`  From, until:                   ${c.validFrom}, ${c.validUntil}`);
    console.log(`  Purpose:                       ${nameOf(c, 'purpose')}`);
    if (e.covered.length) console.log(`  Covered fields: ${e.covered.length}. They are part of what was signed, and are not shown to you.`);
  }
  if (e.signature) console.log(`  Signature, ${e.signature.method}: ${e.signature.state}`);
}

function printStub(e) {
  console.log(`\nEntry ${e.index}: STUB ${e.fingerprint ?? ''}`);
  if (hidden(e)) console.log(hidden(e));
  else {
    const c = e.content;
    const amount = c.amount ? `, ${c.amount.value} ${safe(c.amount.unit)}` : '';
    console.log(`  Number ${c.seq} under ${c.pass ? `pass ${c.pass}, by a helper agent, under ` : ''}slip ${c.slip}`);
    console.log(`  ${c.when}: ${safe(c.action)}${amount}${c.with ? `, with [${safe(c.with)}]` : ''}`);
    for (const d of c.details ?? []) console.log(`  Document: ${label(d.name)} (fingerprint ${d.sha256})`);
    if (c.terms) console.log(`  Relies on the service's terms for agents: ${c.terms}`);
  }
  if (e.signatures && e.signatures.length) {
    console.log(`  Agent's signatures: ${e.signatures.map((s) => `${s.method} ${s.state}`).join('; ')}`);
  }
  if (e.countersignature && !e.problems.length) {
    console.log(
      e.countersignature.state === 'absent'
        ? e.content && !e.content.with
          ? '  No other party is named. This shows what the agent\'s side said.'
          : '  ONE-SIDED: no countersignature. This shows what the agent\'s side said.'
        : `  Countersignature: ${e.countersignature.signatures.map((s) => `${s.method} ${s.state}`).join('; ')}`,
    );
  }
  if (e.approval && e.approval.state !== 'absent' && !e.problems.length) {
    console.log(`  Approved by the person, with the passkey the slip names: ${e.approval.state} (dated ${e.approval.when}, the person's device's own word)`);
  }
  if (e.running && !hidden(e)) console.log(`  Running total: ${e.running.total} of ${e.running.max} ${safe(e.running.unit)}`);
}

function printRefusal(e) {
  console.log(`\nEntry ${e.index}: REFUSAL ${e.fingerprint ?? ''}`);
  if (hidden(e)) console.log(hidden(e));
  else {
    const c = e.content;
    const amount = c.amount ? `, ${c.amount.value} ${safe(c.amount.unit)}` : '';
    const who = e.service ? `the service the slip names as [${safe(e.service)}]` : 'a party the slip does not name';
    console.log(`  Under slip ${c.slip}`);
    console.log(`  ${c.when}: refused ${safe(c.action)}${amount}`);
    console.log(`  Reason given: ${REFUSAL_REASONS[c.reason]}`);
    console.log(`  Signed by ${who}, which calls itself (a label, not checked): ${label(c.by.name)}`);
    console.log(`  Signed with the key set: ${e.signer}`);
    console.log('  This shows what the service\'s side said, not what the agent did.');
  }
  if (e.signatures && e.signatures.length) console.log(`  Service's signatures: ${e.signatures.map((s) => `${s.method} ${s.state}`).join('; ')}`);
}

// The time-stamps beside a record: from a time-stamp service, or a block
// of a public blockchain.
function printStamps(stamps) {
  for (const s of stamps) {
    if (s.kind === 'block') {
      const block = `block ${s.authority} (number ${s.height}, as the proof states)`;
      const states = `The block states the time ${s.when}; that is taken as right to within two hours.`;
      if (s.state === 'valid') console.log(`  BLOCK TIME-STAMP: in ${block}, ${whyCounted(s.authority)}. ${states}`);
      else if (s.state === 'untrusted') console.log(`  Block time-stamp, NOT COUNTED: in ${block}, which you did not name as trusted. ${states}`);
    } else if (s.state === 'valid') console.log(`  OUTSIDE TIME-STAMP: ${s.when}, from a service you named as trusted (certificate ${s.authority})`);
    else if (s.state === 'untrusted') console.log(`  Outside time-stamp, NOT COUNTED: ${s.when}, from a service you did not name as trusted (certificate ${s.authority})`);
    else if (s.state === 'unavailable') console.log('  Outside time-stamp, NOT CHECKED: this device cannot check the service\'s signing method');
  }
}

function printSeal(e) {
  console.log(`\nEntry ${e.index}: SEAL ${e.fingerprint ?? ''}`);
  if (hidden(e)) console.log(hidden(e));
  else {
    const c = e.content;
    console.log(`  Covers the first ${c.size} entries, with the top fingerprint ${c.root}`);
    console.log(`  Sealed at (the recorder's own word): ${c.when}`);
    console.log(`  Recorder:                            ${label(c.by.name)} (${standing(e.vouched)})`);
    console.log(`  Recorder's key set fingerprint:      ${e.sealer}`);
    printStamps(e.stamps);
    if (e.stamps.length === 0) console.log('  No outside time-stamp: the time is only the recorder\'s own word.');
  }
  if (e.signatures && e.signatures.length) console.log(`  Recorder's signatures: ${e.signatures.map((s) => `${s.method} ${s.state}`).join('; ')}`);
}

function printCancellation(e) {
  console.log(`\nEntry ${e.index}: CANCELLATION ${e.fingerprint ?? ''}`);
  if (hidden(e)) console.log(hidden(e));
  else {
    console.log(`  The person cancels slip ${e.content.slip}`);
    console.log(`  Dated (the person's device's own word): ${e.content.when}`);
    printStamps(e.stamps);
    if (e.stampedAt) console.log(`  Counts as cancelled at: ${e.stampedAt} (the earliest its time-stamps allow)`);
  }
  if (e.signature) console.log(`  Signature, ${e.signature.method}: ${e.signature.state}`);
}

// An acknowledgement: the agent's side says it was handed a cancellation.
function printAcknowledgement(e) {
  console.log(`\nEntry ${e.index}: ACKNOWLEDGEMENT ${e.fingerprint ?? ''}`);
  if (hidden(e)) console.log(hidden(e));
  else {
    const c = e.content;
    console.log(`  ${c.pass ? `The helper agent of pass ${c.pass}` : 'The slip\'s own agent'} states that it was handed the person's cancellation`);
    console.log(`  Of slip ${c.slip}`);
    console.log(`  The cancellation: ${c.cancellation}${e.cancellation === undefined ? '' : `, at entry ${e.cancellation}`}`);
    console.log(`  Handed over at (the agent's side's own word): ${c.when}`);
    console.log('  This shows what the agent\'s side said, not when the person cancelled.');
  }
  if (e.signatures && e.signatures.length) console.log(`  Agent's signatures: ${e.signatures.map((s) => `${s.method} ${s.state}`).join('; ')}`);
}

// A cancellation the person kept, handed over beside the book.
function printHeld(h, n) {
  console.log(`\nHanded over beside the book, ${n}: CANCELLATION ${h.fingerprint ?? ''}`);
  if (h.problems.length) {
    console.log('  It did not pass its check, so it was not used. See the problems at the top.');
    return;
  }
  // What a copy says is shown only where this device confirmed who signed it.
  if (h.signature.state !== 'valid') {
    console.log('  What this copy says is not shown, because this device could not check its signature.');
    for (const n of h.notes) console.log(`  Note: ${n}`);
    return;
  }
  console.log(`  The person cancels slip ${h.slip}`);
  console.log(`  Dated (the person's device's own word): ${h.content.when}`);
  printStamps(h.stamps);
  if (h.stampedAt) console.log(`  Counts as cancelled at: ${h.stampedAt} (the earliest its time-stamps allow)`);
  console.log(h.inBook === null ? '  In the book: NO' : `  In the book: yes, at entry ${h.inBook}`);
  for (const a of h.acknowledgements) {
    const who = a.by === 'helper' ? `the helper agent of pass ${a.pass}` : 'the slip\'s own agent';
    if (a.state === 'valid') console.log(`  Acknowledged by ${who} at: ${a.when} (the agent's side's own word)${a.inBook === null ? '' : `; the book holds the acknowledgement at entry ${a.inBook}`}`);
    else console.log(`  An acknowledgement from ${who} was handed over with it. This device could not check it: ${a.signatures.map((s) => `${s.method} ${s.state}`).join('; ')}`);
  }
  console.log(`  Signature, ${h.signature.method}: ${h.signature.state}`);
  for (const n of h.notes) console.log(`  Note: ${n}`);
}

function printPass(e) {
  console.log(`\nEntry ${e.index}: PASS ${e.fingerprint ?? ''}`);
  if (hidden(e)) console.log(hidden(e));
  else {
    const c = e.content;
    console.log(`  Under slip ${c.slip}${c.from ? `, handed on from pass ${c.from}` : ', handed on by the slip\'s own agent'}`);
    console.log(`  To the helper agent:           ${label(c.to.name)} (${standing(e.vouched)})`);
    console.log(`  May do:                        ${c.actions.map(safe).join(', ')}`);
    for (const l of c.limits) console.log(`  Limit:                         ${safe(limitWords(l))}`);
    console.log(`  From, until:                   ${c.validFrom}, ${c.validUntil}`);
  }
  if (e.signatures && e.signatures.length) console.log(`  Signatures of the agent that passes on: ${e.signatures.map((s) => `${s.method} ${s.state}`).join('; ')}`);
}

function printVouching(e) {
  console.log(`\nEntry ${e.index}: VOUCHING RECORD ${e.fingerprint ?? ''}`);
  if (hidden(e)) console.log(hidden(e));
  else {
    const c = e.content;
    console.log(`  ${label(c.by.name)} (a label; key set ${e.signer}) states:`);
    console.log(`  the ${c.for.kind} named ${label(c.for.name)} holds the key or keys given in this record`);
    console.log(`  From, until: ${c.validFrom}, ${c.validUntil}`);
    console.log(e.counted ? '  COUNTED: you named this organisation as trusted.' : '  NOT COUNTED: you did not name this organisation as trusted.');
  }
  if (e.signatures && e.signatures.length) console.log(`  Organisation's signatures: ${e.signatures.map((s) => `${s.method} ${s.state}`).join('; ')}`);
}

function printWithdrawal(e) {
  console.log(`\nEntry ${e.index}: WITHDRAWAL ${e.fingerprint ?? ''}`);
  if (hidden(e)) console.log(hidden(e));
  else {
    console.log(`  The organisation with key set ${e.signer} withdraws its vouching record ${e.content.vouching}`);
    console.log(`  Dated (its own word): ${e.content.when}. From this entry on, that record vouches for nothing.`);
  }
  if (e.signatures && e.signatures.length) console.log(`  Organisation's signatures: ${e.signatures.map((s) => `${s.method} ${s.state}`).join('; ')}`);
}

function printTerms(e) {
  console.log(`\nEntry ${e.index}: TERMS FOR AGENTS ${e.fingerprint ?? ''}`);
  if (hidden(e)) console.log(hidden(e));
  else {
    const c = e.content;
    console.log(`  From (a label, not checked):   ${label(c.by.name)}`);
    console.log(`  Signed with the key set:       ${e.signer}. These terms count for a stub only if its slip gives these keys for the service.`);
    console.log(`  Accepts from agents:           ${c.accepts.map(safe).join(', ')}`);
    for (const n of c.never) console.log(`  Asks of agents:                ${safe(neverWords(n))}`);
    console.log(`  From, until:                   ${c.validFrom}, ${c.validUntil}`);
  }
  if (e.signatures && e.signatures.length) console.log(`  Service's signatures: ${e.signatures.map((s) => `${s.method} ${s.state}`).join('; ')}`);
}

function print(result, isShow) {
  console.log(`Provared ${isShow ? 'Show' : 'book'}, draft version 0. Evidence, not a verdict.`);
  console.log(`Entries in the book: ${result.size}. Top fingerprint: ${result.root ?? 'none'}`);
  for (const p of result.problems) console.log(`\nPROBLEM [${p.code}] ${safe(p.message)}`);
  for (const e of result.entries) {
    if (e.kind === 'slip') printSlip(e);
    else if (e.kind === 'stub') printStub(e);
    else if (e.kind === 'refusal') printRefusal(e);
    else if (e.kind === 'terms') printTerms(e);
    else if (e.kind === 'seal') printSeal(e);
    else if (e.kind === 'cancellation') printCancellation(e);
    else if (e.kind === 'acknowledgement') printAcknowledgement(e);
    else if (e.kind === 'pass') printPass(e);
    else if (e.kind === 'vouching') printVouching(e);
    else if (e.kind === 'withdrawal') printWithdrawal(e);
    else console.log(`\nEntry ${e.index}: could not be read`);
    for (const p of e.problems) console.log(`  PROBLEM [${p.code}] ${safe(p.message)}`);
    for (const b of e.breaches) console.log(`  OUTSIDE THE SLIP [${b.code}] ${safe(b.message)}`);
    for (const n of e.notes ?? []) console.log(`  Note: ${n}`);
  }
  (result.held ?? []).forEach((h, i) => printHeld(h, i + 1));
  for (const n of result.notes ?? []) console.log(`\nNote: ${n}`);

  const s = result.summary;
  console.log('\nSummary');
  const intact = s.intact ? 'yes' : s.problemFound ? 'NO: a problem was found' : 'NOT CONFIRMED: no problem was found, but not every signature was checked';
  console.log(`  Is the record intact?                 ${intact}`);
  const why = s.methodsMissing.length
    ? ` (this device has no built-in ${s.methodsMissing.join(' or ')})`
    : ' (an entry that cannot be read or used cannot have its signatures checked)';
  console.log(`  Was every signature checked?          ${yesNo(s.fullyChecked)}${s.fullyChecked ? '' : why}`);
  if (!s.problemFound) {
    const outside = s.firstBreach !== null ? `first at entry ${s.firstBreach}` : null;
    const unknown = 'NOT CHECKED: an entry this device cannot confirm cannot be compared with its slip';
    if (isShow) {
      const answer = outside ? `YES: ${outside}` : s.withinSlips ? 'no (single pages cannot show whether a limit was kept)' : unknown;
      console.log(`  Do these pages show the agent outside its slip? ${answer}`);
    } else {
      const answer = outside ? `NO: ${outside}` : s.withinSlips ? 'yes, as far as this record shows' : unknown;
      console.log(`  Did the agent stay within its slip?   ${answer}`);
    }
  }
  if (!s.problemFound) {
    const stamped = s.sealed ? `yes: the first ${s.sealed.entries} entries existed by ${s.sealed.when}` : 'no';
    console.log(`  Time-stamped in a way you trust?      ${stamped}`);
    console.log(`  Checked against keys you named?       ${trustWords(s)}`);
  }
  console.log(`  Slips ${s.counts.slips}, stubs ${s.counts.stubs} (countersigned ${s.counts.countersigned}, one-sided ${s.counts.oneSided})${s.counts.seals ? `, seals ${s.counts.seals}` : ''}`);
  if (s.counts.cancellations || s.counts.acknowledgements || s.counts.vouchings || s.counts.passes) {
    console.log(`  Cancellations ${s.counts.cancellations}, acknowledgements ${s.counts.acknowledgements}, vouching records ${s.counts.vouchings}, passes ${s.counts.passes}`);
  }
  if (s.counts.approved || s.counts.refusals || s.counts.terms) {
    console.log(`  Approved by the person ${s.counts.approved}, refusals ${s.counts.refusals}, terms for agents ${s.counts.terms}`);
  }
  console.log('\nWhat this check does not show');
  for (const l of s.limits) console.log(`  - ${l}`);
}

// Whether the check rests on keys the person named: the passkey they trust
// and, where the record has a seal, the recorder they expect. Without them a
// record agrees only with the keys inside it, which anyone could have made.
function named(s) {
  return args.issuerKeys.length > 0 && (s.counts.seals === 0 || args.sealKeys.length > 0);
}

function trustWords(s) {
  if (named(s)) return s.counts.seals ? 'yes: the passkey you trust, and the recorder you expect' : 'yes: the passkey you trust';
  if (args.issuerKeys.length === 0) return 'NO: you named no passkey you trust (--issuer), so anyone could have made this record. This is not a pass.';
  return 'NO: the record has a seal, and you named no recorder you expect (--sealer), so anyone could have sealed it. This is not a pass.';
}

// Why a block counts: the person named it, or the chain of headers they
// checked holds it with enough blocks after it.
function whyCounted(block) {
  if (args.blocks.includes(block)) return 'which you named as trusted';
  const found = fromChain ? fromChain.found.find((f) => f.block === block) : null;
  return found && found.counted ? `which the chain of headers you checked holds, with ${found.after} blocks after it` : 'which is trusted';
}

// What the chain of block headers showed about the blocks the record's
// block time-stamps lead to.
function printChain(c, from) {
  console.log('\nThe chain of block headers');
  console.log(`  Checked on this device from the first block to block ${c.height} (${c.tip}), dated ${c.tipWhen}.`);
  if (from.found.length === 0) console.log('  No block time-stamp in this record leads to a block.');
  for (const f of from.found) {
    const named = args.blocks.includes(f.block) ? ' It counts all the same, because you named it with --block.' : '';
    if (f.height === null) console.log(`  Block ${f.block}: NOT in this chain.${named || ' A block time-stamp that leads to it is not counted.'}`);
    else if (!f.counted) {
      console.log(`  Block ${f.block}: number ${f.height}, with only ${f.after} blocks after it.${named || ` It counts once ${MIN_BLOCKS_AFTER} have followed: fetch the headers again later.`}`);
    } else {
      const stated = f.stated === f.height ? '' : ` The proof states the number ${f.stated}.`;
      console.log(`  Block ${f.block}: number ${f.height}, with ${f.after} blocks after it. Counted as part of the chain.${stated}`);
    }
  }
}

const args = parseArguments(process.argv.slice(2));
if (args.help) {
  console.log(USAGE);
  process.exit(0);
}
if (args.error) {
  console.error(`${args.error}\n\n${USAGE}`);
  process.exit(2);
}

let text;
try {
  text = readFileSync(args.file, 'utf8');
} catch {
  console.error(`The file could not be read: ${args.file}`);
  process.exit(2);
}

const options = {};
if (args.issuerKeys.length) options.issuerKeys = args.issuerKeys;
if (args.sealKeys.length) options.sealKeys = args.sealKeys;
if (args.stampServices.length) options.stampServices = args.stampServices;
if (args.blocks.length) options.blocks = args.blocks;
if (args.vouchers.length) options.vouchers = args.vouchers;
if (args.disclosures !== undefined) {
  try {
    options.disclosures = JSON.parse(readFileSync(args.disclosures, 'utf8'));
  } catch {
    console.error(`The file of disclosures could not be read: ${args.disclosures}`);
    process.exit(2);
  }
}
if (args.cancellations.length) {
  options.cancellations = [];
  for (const file of args.cancellations) {
    try {
      options.cancellations.push(JSON.parse(readFileSync(file, 'utf8')));
    } catch {
      console.error(`The file of a cancellation could not be read: ${file}`);
      process.exit(2);
    }
  }
}
if (args.expectedRoot !== undefined) options.expectedRoot = args.expectedRoot;
if (args.expectedSize !== undefined) options.expectedSize = args.expectedSize;

// A Show is one JSON object with a "type"; a book is entries, one to a line.
let isShow = false;
try {
  const whole = JSON.parse(text);
  isShow = whole !== null && typeof whole === 'object' && Object.hasOwn(whole, 'type');
} catch {
  isShow = false;
}

// A chain of block headers the person fetched: checked here, in full,
// before it is used. A file that is not such a chain stops the check.
let chain = null;
if (args.headers !== undefined) {
  let bytes;
  try {
    bytes = new Uint8Array(readFileSync(args.headers));
  } catch {
    console.error(`The file of block headers could not be read: ${args.headers}`);
    process.exit(2);
  }
  try {
    chain = await checkHeaderChain(bytes);
  } catch (e) {
    console.error(`The chain of block headers in ${args.headers} cannot be used: ${e.message}`);
    process.exit(2);
  }
}

// What the chain of headers showed: set once the record has been checked with it.
let fromChain = null;

let code = 2;
try {
  let result = isShow ? await checkShow(text, options) : await checkBook(text, options);
  // The blocks the record's block time-stamps lead to that the chain holds,
  // with enough blocks after them, are named as trusted, and the record is
  // checked again with them.
  if (chain) {
    fromChain = blocksInChain(result, chain);
    const added = fromChain.blocks.filter((b) => !(options.blocks ?? []).includes(b));
    if (added.length) {
      options.blocks = [...(options.blocks ?? []), ...added];
      result = isShow ? await checkShow(text, options) : await checkBook(text, options);
    }
  }
  // With --json, what the chain of headers showed is given beside the result.
  if (args.json) console.log(safeJson(chain ? { ...result, headers: { file: args.headers, height: chain.height, tip: chain.tip, tipWhen: chain.tipWhen, found: fromChain.found } } : result));
  else {
    print(result, isShow);
    if (chain) printChain(chain, fromChain);
  }
  const s = result.summary;
  code = s.problemFound ? 2 : s.intact && s.withinSlips && named(s) ? 0 : 1;
} catch {
  // The checker is written never to throw. If it ever does, that is not a pass.
  console.error('The check could not be completed. This is not a pass.');
}
process.exit(code);
