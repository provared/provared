// Shared test cases for whole books, Shows and the check before acting.
//
// Each answer is given as on a device without SLH-DSA (the seal's third
// signing method), which "withoutMethods" can show on any device: an
// implementation that lacks SLH-DSA can then be held to every answer. A
// seal's time-stamp is then never counted; a cancellation's still is.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { checkBefore, checkBook, checkShow, fingerprint, fromBase64url, generateKeySet, makeShow, toBase64url, writeBook } from '../../src/index.js';
import { thumbprint } from '../../src/keys.js';
import { keySetFingerprint } from '../../src/seal.js';
import { makeStampService } from './stamp.mjs';
import { answer, finish } from './vector-tools.mjs';
import { START, makeWorld, withContent } from './world.mjs';

const SLH = 'SLH-DSA-SHA2-256s';
const withoutSlh = (options = {}) => ({ ...options, withoutMethods: [...(Array.isArray(options.withoutMethods) ? options.withoutMethods : []), SLH] });

/** How each kind of case is answered. */
export const ANSWER = {
  checkBook: async (c) => ({ ok: await checkBook(c.text, c.options) }),
  checkShow: async (c) => ({ ok: await checkShow(c.show, c.options) }),
  makeShow: (c) => answer(() => makeShow(c.text, c.indexes, c.showOptions)),
  checkBefore: async (c) => ({ ok: await checkBefore(c.text, c.proposal, c.options) }),
};

const readFile = (...path) => readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', '..', ...path), 'utf8');
const sample = () => readFile('samples', 'office-supplies.jsonl');

async function bookCases() {
  const cases = [];
  const add = (name, text, options = {}) => cases.push({ name, text, options: withoutSlh(options) });

  // A world with every kind of limit and condition.
  const fields = {
    actions: ['supplies.order', 'provared.message.send', 'provared.data.read'],
    limits: [
      { action: 'supplies.order', max: 200, unit: 'GBP' },
      { action: 'supplies.order', each: 80, unit: 'GBP' },
      { action: 'supplies.order', count: 2, per: 7200 },
      { action: 'provared.message.send', count: 2 },
    ],
    requires: [
      { need: 'approval', action: 'supplies.order', above: 50, unit: 'GBP' },
      { need: 'countersignature', action: 'supplies.order' },
    ],
    never: ['destroys', 'deceive'],
  };
  const w = await makeWorld({ fields });
  const trusted = { issuerKeys: [await thumbprint(w.passkey.key)] };
  add('a slip alone', w.book(), trusted);
  await w.add({ value: 30 });
  await w.add({ value: 60, approve: true });
  const sound = w.book();
  add('two stubs within the slip', sound, trusted);
  add('two stubs, no passkey trusted', sound);
  add('two stubs, another passkey trusted', sound, { issuerKeys: [toBase64url(new Uint8Array(32))] });
  add('two stubs, on a device without ML-DSA-87', sound, { ...trusted, withoutMethods: ['ML-DSA-87'] });
  add('two stubs, on a device without ES256', sound, { ...trusted, withoutMethods: ['ES256'] });
  add('two stubs, on a device without Ed25519', sound, { ...trusted, withoutMethods: ['Ed25519'] });
  await w.add({ value: 20, when: START + 2 * 3600 * 1000 + 600000 });
  await w.add({ value: 90, approve: true, when: START + 2 * 3600 * 1000 + 900000 });
  await w.add({ value: 10, countersigned: false, when: START + 5 * 3600 * 1000 });
  await w.add({ action: 'provared.message.send', amount: undefined, with: undefined, countersigned: false });
  await w.add({ action: 'provared.message.send', amount: undefined, with: undefined, countersigned: false });
  await w.add({ action: 'provared.message.send', amount: undefined, with: undefined, countersigned: false });
  await w.add({ action: 'provared.data.delete', amount: undefined, with: undefined, countersigned: false });
  await w.add({ value: 5, with: 'stranger', countersigned: false });
  await w.add({ value: 5, when: Date.parse('2026-10-13T00:00:00Z') });
  await w.add({ value: 70 });
  const busy = w.book();
  add('every kind of finding', busy, trusted);
  add('every kind of finding, with the top fingerprint expected', busy, { ...trusted, expectedRoot: (await checkBook(busy)).root, expectedSize: w.entries.length });
  add('every kind of finding, another top fingerprint expected', busy, { ...trusted, expectedRoot: toBase64url(new Uint8Array(32)) });
  add('every kind of finding, another number of entries expected', busy, { ...trusted, expectedSize: 3 });
  add('every kind of finding, a number of entries given as true', busy, { ...trusted, expectedSize: true });

  // The chain and the lines.
  const lines = sound.split('\n');
  add('a stub left out', [lines[0], lines[2], ''].join('\n'), trusted);
  add('two stubs swapped', [lines[0], lines[2], lines[1], ''].join('\n'), trusted);
  add('a stub repeated', [lines[0], lines[1], lines[1], lines[2], ''].join('\n'), trusted);
  add('the slip repeated', [lines[0], lines[0], lines[1], ''].join('\n'), trusted);
  add('a stub before its slip', [lines[1], lines[0], ''].join('\n'), trusted);
  add('no line feed at the end', sound.slice(0, -1), trusted);
  add('an empty line', [lines[0], '', lines[1], ''].join('\n'), trusted);
  add('a carriage return', [lines[0] + '\r', lines[1], ''].join('\n'), trusted);
  add('a byte order mark', '﻿' + sound, trusted);
  add('a line with a space', [lines[0].replace('{', '{ '), ''].join('\n'), trusted);
  add('a line that is not JSON', 'not json\n', trusted);
  add('a line of an unknown kind', '{"note":"x"}\n', trusted);
  add('a line that is a list', '[]\n', trusted);
  add('a line too long', '"' + 'a'.repeat(131072) + '"\n', trusted);
  add('nothing at all', '', trusted);
  add('a single line feed', '\n', trusted);

  // A stub changed after it was signed.
  const stubEntry = JSON.parse(lines[1]);
  const changed = { ...stubEntry, stub: withContent(stubEntry.stub, (c) => ({ ...c, amount: { unit: 'GBP', value: 1 } })) };
  add('a stub changed after signing', [lines[0], JSON.stringify(changed), ''].join('\n'), trusted);
  const counterOnly = { ...stubEntry };
  delete counterOnly.countersignature;
  add('a stub without its countersignature', [lines[0], JSON.stringify(counterOnly), lines[2], ''].join('\n'), trusted);
  const otherCounter = { ...stubEntry, countersignature: JSON.parse(lines[2]).countersignature };
  add('the countersignature of another stub', [lines[0], JSON.stringify(otherCounter), ''].join('\n'), trusted);

  // Approvals.
  const a = await makeWorld({ fields });
  const aTrusted = { issuerKeys: [await thumbprint(a.passkey.key)] };
  const first = await a.add({ value: 60, approve: true });
  await a.add({ value: 60 });
  await a.add({ value: 60, approve: { amount: { unit: 'GBP', value: 61 } } });
  await a.add({ value: 60, approve: { when: START + 10 * 3600 * 1000 } });
  await a.add({ value: 60, approve: { assertion: { flags: 0x01 } } });
  add('approvals: missing, for something else, dated after the stub, not verified', a.book(), aTrusted);
  // The same approval again, with a later stub for exactly the same request.
  const firstApproval = first.entry.approval;
  const again = await a.add({ value: 60, approval: await fingerprint(fromBase64url(firstApproval.payload)) });
  again.entry.approval = firstApproval;
  add('an approval used twice', a.book(), aTrusted);

  // Refusals and terms.
  const t = await makeWorld({ fields: { requires: [] } });
  const tTrusted = { issuerKeys: [await thumbprint(t.passkey.key)] };
  const terms = await t.publishTerms({ accepts: ['supplies.order'] });
  await t.add({ value: 10, terms: terms.fingerprint });
  await t.refuse({ reason: 'over-limit' });
  const stranger = await generateKeySet();
  await t.refuse({ signer: stranger, reason: 'against-terms' });
  await t.add({ value: 10, terms: toBase64url(new Uint8Array(32)) });
  add('terms, a stub relying on them, and refusals', t.book(), tTrusted);
  const narrow = await t.publishTerms({ accepts: ['other.action'], validFrom: '2026-10-20T00:00:00Z' });
  await t.add({ value: 10, terms: narrow.fingerprint });
  add('a stub outside the terms it relies on', t.book(), tTrusted);

  // Passes.
  const p = await makeWorld({ fields: { passes: 2, limits: [{ action: 'supplies.order', max: 100, unit: 'GBP' }, { action: 'supplies.order', max: 40, unit: 'GBP', per: 86400 }], requires: [] } });
  const pTrusted = { issuerKeys: [await thumbprint(p.passkey.key)] };
  const helper = await p.pass({ limits: [{ action: 'supplies.order', max: 30, unit: 'GBP' }] });
  await helper.add({ value: 20 });
  await p.add({ value: 15 });
  await helper.add({ value: 20 });
  const second = await p.pass({ from: helper.fingerprint, signer: helper.helper.privateKeys, actions: ['supplies.order', 'other'] });
  await second.add({ value: 5, when: START - 3600 * 1000 });
  const third = await p.pass({ from: second.fingerprint, signer: second.helper.privateKeys });
  await third.add({ value: 5 });
  add('passes: totals, periods, wider, one too many', p.book(), pTrusted);

  // Cancellations, acknowledgements and the person's own copy.
  const k = await makeWorld({ fields: { requires: [] } });
  const kTrusted = { issuerKeys: [await thumbprint(k.passkey.key)] };
  await k.add({ value: 10 });
  const service = await makeStampService();
  k.stampService = service;
  const cancelled = await k.cancel({ stampTime: START + 3600 * 1000 + 660 * 1000 });
  await k.acknowledge(cancelled.fingerprint);
  await k.add({ value: 10 });
  const stampTrust = { stampServices: [service.fingerprint] };
  add('a cancellation, time-stamped, and stubs after it', k.book(), { ...kTrusted, ...stampTrust });
  add('a cancellation, its time-stamp service not trusted', k.book(), kTrusted);
  const kLines = k.book().split('\n');
  const withoutCancellation = kLines.filter((l) => !l.startsWith('{"cancellation"')).join('\n');
  add('the cancellation left out, the person\'s copy handed over', withoutCancellation, { ...kTrusted, ...stampTrust, cancellations: [cancelled.entry] });
  add('the person\'s copy handed over twice', withoutCancellation, { ...kTrusted, ...stampTrust, cancellations: [cancelled.entry, cancelled.entry] });
  add('copies that are not a list', withoutCancellation, { ...kTrusted, cancellations: 'x' });
  add('an empty list of copies', withoutCancellation, { ...kTrusted, cancellations: [] });

  // Vouching.
  const v = await makeWorld();
  const vouching = await v.vouch({ kind: 'person', key: v.passkey.key, name: 'Sam Example' });
  const vBook = writeBook([v.entries[1], v.entries[0]]);
  const organisation = await keySetFingerprint(v.organisation.keys);
  add('a vouching record before the slip, its organisation not named', vBook);
  add('a vouching record before the slip, its organisation named', vBook, { vouchers: [organisation] });
  add('a vouching record before the slip, another organisation named', vBook, { vouchers: [toBase64url(new Uint8Array(32))] });
  await v.withdraw(vouching.fingerprint);
  add('a vouching record, then its withdrawal', v.book());

  // Disclosures and blocks.
  add('disclosures that are a list', sound, { ...trusted, disclosures: [] });
  add('disclosures for a slip that is not here', sound, { ...trusted, disclosures: { [toBase64url(new Uint8Array(32))]: [] } });
  add('blocks that are not fingerprints', sound, { ...trusted, blocks: ['abc'] });
  add('blocks that are fingerprints', sound, { ...trusted, blocks: ['ab'.repeat(32)] });

  // The sample record.
  add('the sample record', sample());
  add('the sample record, its passkey trusted', sample(), { issuerKeys: [JSON.parse(readFile('samples', 'office-supplies.expected.json')).issuerKey] });

  // A seal signature of the wrong length is invalid on every device, even
  // where the method is not built in.
  const { sealTrusted, withSeal } = await sealedWorld();
  add('a seal whose third signature is cut short', withSeal((s) => { s.signatures[2].signature = 'AAAA'; }), sealTrusted);
  return cases;
}

async function showCases() {
  const cases = [];
  const w = await makeWorld({ fields: { requires: [] } });
  await w.add({ value: 30 });
  await w.add({ value: 300 });
  await w.add({ value: 5, with: 'stranger', countersigned: false });
  const text = w.book();
  const trusted = { issuerKeys: [await thumbprint(w.passkey.key)] };
  const show = await makeShow(text, [0, 2, 3]);
  const add = (name, s, options = {}) => cases.push({ name, show: s, options: withoutSlh(options) });
  add('three pages', show, trusted);
  add('three pages, the top fingerprint trusted', show, { ...trusted, expectedRoot: show.root, expectedSize: show.size });
  add('three pages, as text', JSON.stringify(show), trusted);
  add('a page whose proof is wrong', { ...show, pages: [show.pages[0], { ...show.pages[1], path: show.pages[2].path }] }, trusted);
  add('a page repeated', { ...show, pages: [show.pages[0], show.pages[0]] }, trusted);
  add('a stub without its slip', { ...show, pages: [show.pages[1]] }, trusted);
  add('the wrong type', { ...show, type: 'x' });
  add('no pages', { ...show, pages: [] });
  add('not JSON', 'not json');
  add('cancellations handed over', show, { ...trusted, cancellations: [{}] });
  const sealedShow = JSON.parse(readFile('samples', 'office-supplies.show.json'));
  add('the sample Show, with its seal', sealedShow);
  return cases;
}

async function makeShowCases() {
  const w = await makeWorld();
  for (let i = 0; i < 6; i++) await w.add({ value: 1 });
  const text = w.book();
  return [
    { name: 'one page', text, indexes: [0] },
    { name: 'every page', text, indexes: [0, 1, 2, 3, 4, 5, 6] },
    { name: 'pages out of order and repeated', text, indexes: [5, 1, 5, 3] },
    { name: 'no pages', text, indexes: [] },
  ];
}

async function beforeCases() {
  const cases = [];
  const w = await makeWorld({
    fields: {
      limits: [{ action: 'supplies.order', max: 100, unit: 'GBP' }, { action: 'supplies.order', count: 2, per: 3600 }],
      requires: [{ need: 'approval', action: 'supplies.order', above: 50, unit: 'GBP' }, { need: 'countersignature' }],
    },
  });
  const trusted = { issuerKeys: [await thumbprint(w.passkey.key)] };
  await w.add({ value: 30 });
  const text = w.book();
  const base = { slip: w.slipFingerprint, action: 'supplies.order', amount: { unit: 'GBP', value: 20 }, with: 'supplier', when: START + 3600 * 1000 };
  const add = (name, proposal, options = trusted, book = text) => cases.push({ name, text: book, proposal, options: withoutSlh(options) });
  add('an action within the slip', base);
  add('no passkey trusted', base, {});
  add('an action over the total', { ...base, amount: { unit: 'GBP', value: 80 } });
  const approval = (await w.approve({ ...base, amount: { unit: 'GBP', value: 60 }, when: base.when - 60000 })).record;
  add('an action that needs an approval, with it', { ...base, amount: { unit: 'GBP', value: 60 }, approval });
  add('an action that needs an approval, without it', { ...base, amount: { unit: 'GBP', value: 60 } });
  add('an approval for something else', { ...base, amount: { unit: 'GBP', value: 61 }, approval });
  add('an action dated before the last stub', { ...base, when: START - 1000 });
  add('a second action within the hour', { ...base, when: START + 60000 });
  add('an action with no amount', { ...base, amount: undefined });
  add('an action with no service', { ...base, with: undefined, when: START + 7200 * 1000 });
  // Limits on the number of actions, in all and in any hour: the words for an action that is only proposed.
  const n = await makeWorld({ fields: { limits: [{ action: 'supplies.order', count: 2 }, { action: 'supplies.order', count: 2, per: 3600 }], requires: [] } });
  await n.add({ when: START });
  await n.add({ when: START + 60000 });
  add('a third action, within the hour and in all', { ...base, slip: n.slipFingerprint, when: START + 120000 },
    { issuerKeys: [await thumbprint(n.passkey.key)] }, n.book());
  add('another slip', { ...base, slip: toBase64url(new Uint8Array(32)) });
  add('an unknown member', { ...base, colour: 'red' });
  add('an action dated by text', { ...base, when: '2026-10-05T10:00:00Z' });
  add('an action dated outside the range of times', { ...base, when: 1e20 });
  add('a book with a problem', base, trusted, text.replace('"stub"', '"stub "'));
  // A book with a seal. On this device the seal's third signature is not
  // checked, and the check goes on and says so (choice 380); any other
  // signature left unchecked, or a seal signature of the wrong length,
  // still allows nothing.
  const { sealed, sealTrusted, withSeal } = await sealedWorld();
  const sealBase = { ...base, slip: sealed.slipFingerprint, when: START + 5 * 3600 * 1000 };
  add('a book with a seal', sealBase, sealTrusted, sealed.book());
  add('a book with a seal, on a device without ML-DSA-87 either', sealBase, { ...sealTrusted, withoutMethods: ['ML-DSA-87'] }, sealed.book());
  add("a book with a seal, on a device that cannot check the person's passkey either", sealBase, { ...sealTrusted, withoutMethods: ['ES256'] }, sealed.book());
  add("a seal whose third signature is cut short", sealBase, sealTrusted, withSeal((s) => { s.signatures[2].signature = 'AAAA'; }));
  add("a seal whose third signature is changed, at its full length", sealBase, sealTrusted, withSeal((s) => { s.signatures[2].signature = flipByte(s.signatures[2].signature); }));
  add("a seal whose ML-DSA-87 signature is changed", sealBase, sealTrusted, withSeal((s) => { s.signatures[1].signature = flipByte(s.signatures[1].signature); }));
  // A permission and a seal only: the seal's Ed25519 signature is the only
  // one of its method, and a seal is excused only where its first two
  // signatures were both checked.
  const lone = await makeWorld();
  await lone.seal();
  add('a permission and a seal, on a device without Ed25519 either', { ...base, slip: lone.slipFingerprint },
    { issuerKeys: [await thumbprint(lone.passkey.key)], sealKeys: [await keySetFingerprint(lone.recorder.keys)], withoutMethods: ['Ed25519'] }, lone.book());
  add('a permission and a seal, on a device without ML-DSA-87 either', { ...base, slip: lone.slipFingerprint },
    { issuerKeys: [await thumbprint(lone.passkey.key)], sealKeys: [await keySetFingerprint(lone.recorder.keys)], withoutMethods: ['ML-DSA-87'] }, lone.book());
  return cases;
}

// A book of a slip, one stub and a seal, and a way to change its seal.
async function sealedWorld() {
  const sealed = await makeWorld();
  await sealed.add();
  await sealed.seal();
  const sealTrusted = { issuerKeys: [await thumbprint(sealed.passkey.key)], sealKeys: [await keySetFingerprint(sealed.recorder.keys)] };
  const withSeal = (change) => {
    const entries = JSON.parse(JSON.stringify(sealed.entries));
    change(entries.find((e) => e.seal).seal);
    return writeBook(entries);
  };
  return { sealed, sealTrusted, withSeal };
}

const flipByte = (b64) => {
  const bytes = fromBase64url(b64);
  bytes[10] ^= 1;
  return toBase64url(bytes);
};

// --- the denial (format description, section 28) ---

async function denialWorld() {
  const w = await makeWorld({ fields: { passes: 1, requires: [] } });
  const trusted = { issuerKeys: [await thumbprint(w.passkey.key)] };
  await w.add({ value: 30 });
  const byCheck = await w.deny({ codes: ['over-limit', 'party-not-allowed'], with: 'stranger' });
  await w.deny({ source: 'person', amount: undefined, with: undefined, action: 'provared.data.delete' });
  await w.deny({ source: 'rule', details: [{ name: 'provared.arguments', sha256: toBase64url(new Uint8Array(32).fill(7)) }] });
  const helper = await w.pass({ limits: [{ action: 'supplies.order', max: 30, unit: 'GBP' }] });
  await helper.add({ value: 20 });
  await w.deny({ pass: helper.fingerprint, signer: helper.helper.privateKeys, codes: ['over-limit'], amount: { unit: 'GBP', value: 40 } });
  await w.add({ value: 10 });
  return { w, trusted, helper, byCheck };
}

async function denialBookCases() {
  const cases = [];
  const add = (name, text, options = {}) => cases.push({ name, text, options: withoutSlh(options) });
  const { w, trusted, helper, byCheck } = await denialWorld();
  const book = w.book();
  add('denials by the check, the person and a rule, and a helper\'s, beside stubs', book, trusted);
  add('denials, no passkey trusted', book);
  add('denials, on a device without ML-DSA-87', book, { ...trusted, withoutMethods: ['ML-DSA-87'] });
  add('denials, on a device without ES256: the slip cannot be confirmed', book, { ...trusted, withoutMethods: ['ES256'] });
  const lines = book.split('\n');
  // A denial before its slip.
  add('a denial before its slip', [lines[2], lines[0], lines[1], ''].join('\n'), trusted);
  // A denial signed with keys that are not the agent's.
  const stranger = await generateKeySet();
  const wrong = await makeWorld({ fields: { requires: [] } });
  const wTrusted = { issuerKeys: [await thumbprint(wrong.passkey.key)] };
  await wrong.deny({ signer: stranger.privateKeys });
  await wrong.deny({ source: 'person', signer: [wrong.agent.privateKeys[0], stranger.privateKeys[1]] });
  add('denials signed with keys that are not the agent\'s', wrong.book(), wTrusted);
  // A helper's denial signed with the first agent's keys, and one naming a pass not in the book.
  const h = await makeWorld({ fields: { passes: 1, requires: [] } });
  const hTrusted = { issuerKeys: [await thumbprint(h.passkey.key)] };
  const hp = await h.pass({});
  await h.deny({ pass: hp.fingerprint });
  await h.deny({ pass: toBase64url(new Uint8Array(32).fill(9)), signer: hp.helper.privateKeys });
  add('a helper\'s denial signed by the first agent, and one naming a pass not in the book', h.book(), hTrusted);
  // A denial whose content was changed after it was signed, and one that repeats a unique number.
  const changed = JSON.parse(lines[2]);
  changed.denial = withContent(changed.denial, (c) => {
    const { codes: _, ...rest } = c;
    return { ...rest, source: 'rule' };
  });
  const repeated = await makeWorld({ fields: { requires: [] } });
  const rTrusted = { issuerKeys: [await thumbprint(repeated.passkey.key)] };
  const first = await repeated.add({ value: 10 });
  await repeated.deny({ id: JSON.parse(Buffer.from(first.record.payload, 'base64url').toString()).id });
  add('a denial changed after signing', [lines[0], lines[1], JSON.stringify(changed), ''].join('\n'), trusted);
  add('a denial that repeats the unique number of a stub', repeated.book(), rTrusted);
  // A denial dated outside the slip's time is compared with nothing.
  const late = await makeWorld({ fields: { requires: [] } });
  const lTrusted = { issuerKeys: [await thumbprint(late.passkey.key)] };
  await late.deny({ when: Date.parse('2026-11-01T00:00:00Z'), codes: ['outside-valid-time'] });
  add('a denial dated after the slip ended', late.book(), lTrusted);
  // A line that holds a denial and something else is not a known kind of entry.
  const both = { ...JSON.parse(lines[2]), stub: JSON.parse(lines[1]).stub };
  add('a denial and a stub on one line', [lines[0], lines[1], JSON.stringify(both), ''].join('\n'), trusted);
  // A denial record under the label of another kind of record.
  const relabelled = JSON.parse(lines[2]);
  relabelled.denial = { ...relabelled.denial, signatures: relabelled.denial.signatures.map((s, i) => ({ ...s, protected: toBase64url(Buffer.from(i === 0 ? '{"typ":"vnd.provared.refusal.v0+json","alg":"Ed25519"}' : '{"typ":"vnd.provared.refusal.v0+json","alg":"ML-DSA-87"}')) })) };
  add('a denial under the labels of a refusal', [lines[0], lines[1], JSON.stringify(relabelled), ''].join('\n'), trusted);
  void helper;
  void byCheck;
  return cases;
}

async function denialShowCases() {
  const cases = [];
  const add = (name, show, options = {}) => cases.push({ name, show, options: withoutSlh(options) });
  const { w, trusted } = await denialWorld();
  const book = w.book();
  add('a denial and its slip', await makeShow(book, [0, 2]), trusted);
  add('a denial without its slip', await makeShow(book, [2]), trusted);
  add('a helper\'s denial with its slip and pass', await makeShow(book, [0, 5, 7]), trusted);
  add('a helper\'s denial without its pass', await makeShow(book, [0, 7]), trusted);
  return cases;
}

async function denialBeforeCases() {
  const cases = [];
  const { w, trusted } = await denialWorld();
  const book = w.book();
  const add = (name, proposal, options = trusted) => cases.push({ name, text: book, proposal, options: withoutSlh(options) });
  const at = START + 6 * 3600 * 1000;
  add('an action after denials, within the slip', { slip: w.slipFingerprint, action: 'supplies.order', amount: { unit: 'GBP', value: 10 }, with: 'supplier', when: at });
  add('an action after denials, over the limit', { slip: w.slipFingerprint, action: 'supplies.order', amount: { unit: 'GBP', value: 300 }, with: 'supplier', when: at });
  add('on a device without ML-DSA-87: nothing is allowed', { slip: w.slipFingerprint, action: 'supplies.order', amount: { unit: 'GBP', value: 10 }, with: 'supplier', when: at }, { ...trusted, withoutMethods: ['ML-DSA-87'] });
  // A sealed book that holds a denial: on a device without SLH-DSA the check goes on, as for any other sealed book.
  const sealed = await makeWorld({ fields: { requires: [] } });
  await sealed.add({ value: 10 });
  await sealed.deny({ source: 'rule' });
  await sealed.seal({});
  cases.push({
    name: 'a sealed book holding a denial, on a device without SLH-DSA',
    text: sealed.book(),
    proposal: { slip: sealed.slipFingerprint, action: 'supplies.order', amount: { unit: 'GBP', value: 5 }, with: 'supplier', when: START + 2 * 3600 * 1000 },
    options: withoutSlh({ issuerKeys: [await thumbprint(sealed.passkey.key)] }),
  });
  return cases;
}

/** Each set of cases, by the name of its file. */
export const CASES = {
  'denial-books': async () => finish('Checking a whole book that holds denials (format description, section 28), on a device without SLH-DSA.', 'checkBook', await denialBookCases(), ANSWER),
  'denial-shows': async () => finish('Checking a Show whose pages hold denials (format description, sections 11 and 28), on a device without SLH-DSA.', 'checkShow', await denialShowCases(), ANSWER),
  'denial-before': async () => finish('The check before acting over a book that holds denials (format description, sections 20 and 28), on a device without SLH-DSA.', 'checkBefore', await denialBeforeCases(), ANSWER),
  books: async () => finish('Checking a whole book (format description, sections 7 to 11 and 17 to 26), on a device without SLH-DSA.', 'checkBook', await bookCases(), ANSWER),
  shows: async () => finish('Checking a Show (format description, section 11), on a device without SLH-DSA.', 'checkShow', await showCases(), ANSWER),
  'make-show': async () => finish('Making a Show: the pages, their proofs and the top fingerprint (format description, sections 10 and 11).', 'makeShow', await makeShowCases(), ANSWER),
  'check-before': async () => finish('The check before acting (format description, section 20), on a device without SLH-DSA.', 'checkBefore', await beforeCases(), ANSWER),
};
