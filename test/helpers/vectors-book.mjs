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
  add('a book with a problem', base, trusted, text.replace('"stub"', '"stub "'));
  return cases;
}

/** Each set of cases, by the name of its file. */
export const CASES = {
  books: async () => finish('Checking a whole book (format description, sections 7 to 11 and 17 to 26), on a device without SLH-DSA.', 'checkBook', await bookCases(), ANSWER),
  shows: async () => finish('Checking a Show (format description, section 11), on a device without SLH-DSA.', 'checkShow', await showCases(), ANSWER),
  'make-show': async () => finish('Making a Show: the pages, their proofs and the top fingerprint (format description, sections 10 and 11).', 'makeShow', await makeShowCases(), ANSWER),
  'check-before': async () => finish('The check before acting (format description, section 20), on a device without SLH-DSA.', 'checkBefore', await beforeCases(), ANSWER),
};
