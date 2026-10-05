// What the fourth independent review found, in cancelling, vouching,
// covered fields and passing on (3 October 2026). Each fault is fixed, and
// each is a test here.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { disclosureDigest, uncover } from '../src/cover.js';
import { canonicalJson } from '../src/encoding.js';
import {
  assembleSlip,
  checkBefore,
  checkBook,
  checkShow,
  checkSlip,
  fingerprint,
  fromBase64url,
  generateKeySet,
  keySetFingerprint,
  makeShow,
  randomId,
  sha256,
  thumbprint,
  toBase64url,
  utf8,
} from '../src/index.js';
import { protectedHeaders } from '../src/jws.js';
import { preparePasskeyRecord } from '../src/slip.js';
import { START, makeWorld } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;
const ORDER = 'supplies.order';

function codes(result) {
  const out = result.problems.map((p) => p.code);
  for (const e of result.entries) out.push(...e.problems.map((p) => p.code), ...e.breaches.map((b) => b.code));
  return out;
}
const breachesOf = (r) => r.entries.map((e) => e.breaches.map((b) => b.code).sort());
const contentOf = (w) => JSON.parse(Buffer.from(w.slip.payload, 'base64url').toString());
const trusting = async (w) => ({ issuerKeys: [await thumbprint(w.passkey.key)] });

// Replace the world's slip with one of changed content, signed with the same passkey.
async function reslip(w, change) {
  const content = contentOf(w);
  change(content);
  const prepared = await preparePasskeyRecord('slip', content);
  const slip = assembleSlip(prepared, await w.passkey.sign(prepared.challenge));
  w.slip = slip;
  w.slipFingerprint = await fingerprint(fromBase64url(slip.payload));
  w.entries[0] = { slip };
  return w.slipFingerprint;
}

// The same, from the exact text of the content: an object cannot carry a
// member named "__proto__" through the library's own writer.
async function slipFromText(w, text) {
  const payloadB64 = toBase64url(utf8(text));
  const [protectedB64] = protectedHeaders('slip');
  const challenge = await sha256(utf8(`${protectedB64}.${payloadB64}`));
  return assembleSlip({ payloadB64, protectedB64 }, await w.passkey.sign(challenge));
}
// The canonical text of an object with a member named "__proto__" put first, where it sorts.
const withProto = (object, value) => '{"__proto__":' + canonicalJson(value) + ',' + canonicalJson(object).slice(1);

// A disclosure of an item of a list: a salt and a value.
async function itemDisclosure(value) {
  const disclosure = toBase64url(utf8(canonicalJson([randomId(), value])));
  return { disclosure, digest: await disclosureDigest(disclosure) };
}

const CLI = join(fileURLToPath(new URL('..', import.meta.url)), 'bin', 'provared-check.mjs');
function cli(book, ...more) {
  const file = join(mkdtempSync(join(tmpdir(), 'provared-')), 'book.jsonl');
  writeFileSync(file, book);
  return spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', CLI, file, ...more], { encoding: 'utf8' });
}

// A stand-in for the browser's document, enough for the page to write into.
class Element {
  constructor() {
    this.children = [];
    this.textContent = '';
    this.className = '';
  }
  append(...nodes) {
    this.children.push(...nodes);
  }
  replaceChildren() {
    this.children = [];
  }
  words(out = []) {
    if (this.textContent) out.push(this.textContent);
    for (const c of this.children) c.words(out);
    return out;
  }
}
globalThis.document = { createElement: () => new Element() };
const { renderResult } = await import('../page/render.js');
function pageWords(result) {
  const target = new Element();
  renderResult(target, result);
  return target.words();
}

// --- covered fields ---

test('finding 1: an item of a list in a slip cannot be covered: not a limit, a condition, an action, a service or a key', async () => {
  // Each case covers one item of one list, and gives back its disclosure.
  const cover = async (value, put) => {
    const item = await itemDisclosure(value);
    put({ '...': item.digest });
    return item;
  };
  const cases = [
    (c) => cover({ action: ORDER, max: 200, unit: 'GBP' }, (covered) => void (c.limits = [covered])),
    (c) => cover({ need: 'approval' }, (covered) => void (c.requires = [covered])),
    (c) => cover('door.unlock', (covered) => void (c.actions = [ORDER, covered])),
    (c) => cover(c.with[0], (covered) => void (c.with = [covered])),
    (c) => cover(c.agent.keys[1], (covered) => void (c.agent.keys = [c.agent.keys[0], covered])),
  ];
  for (const [i, make] of cases.entries()) {
    const w = await makeWorld();
    const content = contentOf(w);
    const item = await make(content);
    content._sd_alg = 'sha-256';
    const fp2 = await reslip(w, (c) => void Object.assign(c, content));
    await w.add({ slip: fp2, value: 5000 });
    // With the disclosure and without it, the slip is refused: no reader is shown a different slip.
    for (const options of [{}, { disclosures: { [fp2]: [item.disclosure] } }]) {
      const r = await checkBook(w.book(), options);
      assert.ok(codes(r).includes('cover-invalid'), `case ${i}: ${codes(r)}`);
      assert.equal(r.summary.intact, false, `case ${i}`);
      assert.equal(r.summary.withinSlips, false, `case ${i}`);
    }
    const answer = await checkBefore(w.book(), { slip: fp2, action: ORDER, amount: { unit: 'GBP', value: 99999 }, with: 'supplier', when: START + 2 * HOUR }, await trusting(w));
    assert.equal(answer.allowed, false, `case ${i}`);
  }
});

test('finding 2: a member named "__proto__" is a member like any other: an unknown one is refused, and nothing is inherited from it', async () => {
  // Read by the standard's own steps, it stays a member of its own.
  const { content } = await uncover(JSON.parse('{"__proto__":{"x":1},"a":2}'));
  assert.equal(Object.getPrototypeOf(content), Object.prototype);
  assert.ok(Object.hasOwn(content, '__proto__'));
  assert.equal(content.x, undefined);

  // (a) At the top of a slip.
  const w = await makeWorld();
  const c = contentOf(w);
  const top = await checkSlip(await slipFromText(w, withProto(c, { anything: 'at all', passes: 3 })));
  assert.deepEqual(top.problems.map((p) => p.code), ['bad-field']);

  // (b) In the agent, carrying "software" that was never checked, with characters that move the cursor.
  const escape = '\u001b';
  const { agent, ...noAgent } = c;
  const software = [{ name: 'x', sha256: `${escape}[2K\rIs the record intact? yes${escape}[0m` }];
  const smuggled = canonicalJson(noAgent).replace(',"id":', () => ',"agent":' + withProto(agent, { software }) + ',"id":');
  w.entries[0] = { slip: await slipFromText(w, smuggled) };
  const r = await checkBook(w.book());
  assert.ok(codes(r).includes('bad-field'));
  const out = cli(w.book());
  assert.equal(out.status, 2);
  assert.ok(!out.stdout.includes(escape));
  // The page does not stop on it either.
  assert.ok(pageWords(r).some((line) => /NOT intact/.test(line)));

  // (c) In a service, carrying keys that were never checked.
  const w2 = await makeWorld();
  const c2 = contentOf(w2);
  const { with: services, ...noServices } = c2;
  const { keys, ...service } = services[0];
  const text = canonicalJson(noServices).replace(/}$/, () => ',"with":[' + withProto(service, { keys }) + ']}');
  assert.deepEqual((await checkSlip(await slipFromText(w2, text))).problems.map((p) => p.code), ['bad-field']);

  // (d) Beside a covered name: no stand-in name is shown in its place.
  const w3 = await makeWorld({ cover: ['issuer.name'] });
  const c3 = contentOf(w3);
  const { issuer, ...noIssuer } = c3;
  const standIn = canonicalJson(noIssuer).replace(',"limits":', () => ',"issuer":' + withProto(issuer, { name: 'Somebody Else Entirely' }) + ',"limits":');
  assert.deepEqual((await checkSlip(await slipFromText(w3, standIn))).problems.map((p) => p.code), ['bad-field']);
});

test('finding 13: a name is shown as covered only where its fingerprint stands in its place', async () => {
  const digest = 'A'.repeat(43);
  const changes = [
    // An empty list: nothing is covered, and nothing could ever be revealed.
    (c) => void (delete c.issuer.name, (c.issuer._sd = []), (c._sd_alg = 'sha-256')),
    (c) => void (delete c.purpose, (c._sd = [])),
    // A fingerprint, with the fingerprint method not named.
    (c) => void (delete c.issuer.name, (c.issuer._sd = [digest])),
    // The method named, with nothing covered.
    (c) => void (c._sd_alg = 'sha-256'),
    // Two fingerprints where one field may be covered.
    (c) => void (delete c.issuer.name, (c.issuer._sd = [digest, 'B'.repeat(42) + 'A']), (c._sd_alg = 'sha-256')),
    // The name there, and a fingerprint as well.
    (c) => void ((c.issuer._sd = [digest]), (c._sd_alg = 'sha-256')),
  ];
  for (const [i, change] of changes.entries()) {
    const w = await makeWorld();
    await reslip(w, change);
    const r = await checkBook(w.book());
    assert.ok(codes(r).includes('bad-field'), `case ${i}: ${codes(r)}`);
  }
  // As it should be written, it checks.
  const w = await makeWorld();
  await reslip(w, (c) => void (delete c.issuer.name, (c.issuer._sd = [digest]), (c._sd_alg = 'sha-256')));
  const r = await checkBook(w.book());
  assert.deepEqual(codes(r), []);
  assert.deepEqual(r.entries[0].covered, ['issuer.name']);
});

test('a disclosure for a slip must be written in the canonical form, so that two checkers cannot read it in two ways', async () => {
  const loose = Buffer.from('["c2FsdHNhbHRzYWx0c2FsdA", "name", "Sam Example"]').toString('base64url');
  const tight = Buffer.from('["c2FsdHNhbHRzYWx0c2FsdA","name","Sam Example"]').toString('base64url');
  for (const [disclosure, expected] of [
    [loose, ['cover-invalid']],
    [tight, []],
  ]) {
    const w = await makeWorld();
    const digest = await disclosureDigest(disclosure);
    const fp = await reslip(w, (c) => void (delete c.issuer.name, (c.issuer._sd = [digest]), (c._sd_alg = 'sha-256')));
    assert.deepEqual(codes(await checkBook(w.book())), []);
    assert.deepEqual(codes(await checkBook(w.book(), { disclosures: { [fp]: [disclosure] } })), expected);
  }
});

test('finding 14: disclosures handed over with a page that is not a slip are refused, and ones for a slip that is not there are pointed out', async () => {
  const w = await makeWorld({ cover: ['purpose'] });
  await w.add();
  const show = await makeShow(w.book(), [0, 1], { disclosures: { 1: ['bm90IGEgZGlzY2xvc3VyZQ'] } });
  const r = await checkShow(show);
  assert.deepEqual(r.entries[1].problems.map((p) => p.code), ['cover-invalid']);
  assert.equal(r.summary.intact, false);
  const stray = await checkBook(w.book(), { disclosures: { ['A'.repeat(43)]: w.prepared.disclosures } });
  assert.ok(stray.notes.some((n) => /for a slip that is not here/.test(n)));
  assert.deepEqual((await checkBook(w.book(), { disclosures: { [w.slipFingerprint]: w.prepared.disclosures } })).notes, []);
});

// --- limits within a period, with more than one chain ---

test('finding 3: a limit within a period counts by the times the stubs state, in whichever chain and at whichever place in the book', async () => {
  const limit = { action: ORDER, max: 100, unit: 'GBP', per: 86400 };
  // Two orders of 90 GBP an hour apart, with a helper's stub between them in the book that is dated two days later.
  const w = await makeWorld({ fields: { passes: 1, limits: [limit] } });
  await w.add({ value: 90, when: START });
  const pass = await w.pass({ helper: w.agent });
  await pass.add({ value: 0, when: START + 2 * DAY });
  await w.add({ value: 90, when: START + HOUR });
  const r = await checkBook(w.book());
  assert.deepEqual(breachesOf(r), [[], [], [], [], ['over-period-limit']]);
  assert.equal(r.summary.withinSlips, false);
  assert.match(r.entries[4].breaches[0].message, /the total in any 24 hours is 180 GBP/);
  const third = await checkBefore(w.book(), { slip: w.slipFingerprint, action: ORDER, amount: { unit: 'GBP', value: 5 }, with: 'supplier', when: START + 2 * HOUR }, await trusting(w));
  assert.deepEqual(third.breaches.map((b) => b.code), ['over-period-limit']);

  // A number of actions within a period, the same way.
  const counted = await makeWorld({ fields: { passes: 1, limits: [{ action: ORDER, count: 2, per: 86400 }] } });
  const helper = await counted.pass({ helper: counted.agent });
  await counted.add({ value: 1, when: START });
  await helper.add({ value: 0, when: START + 2 * DAY });
  await counted.add({ value: 1, when: START + HOUR });
  await helper.add({ value: 0, when: START + 4 * DAY });
  await counted.add({ value: 1, when: START + 2 * HOUR });
  assert.deepEqual(breachesOf(await checkBook(counted.book())), [[], [], [], [], [], [], ['over-period-limit']]);
});

test('finding 3: an action dated before a later stub of another chain is counted in that stub\'s period too', async () => {
  const limit = { action: ORDER, max: 100, unit: 'GBP', per: 86400 };
  const w = await makeWorld({ fields: { passes: 1, limits: [limit] } });
  await w.add({ value: 60, when: START });
  const pass = await w.pass();
  await pass.add({ value: 30, when: START + 3 * HOUR });
  const ask = async (value) =>
    checkBefore(w.book(), { slip: w.slipFingerprint, action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier', when: START + HOUR }, await trusting(w));
  assert.equal((await ask(10)).allowed, true);
  assert.deepEqual((await ask(20)).breaches.map((b) => b.code), ['over-period-limit']);
  // Written all the same, it is the later-dated stub whose 24 hours hold too much.
  await w.add({ value: 20, when: START + HOUR });
  assert.deepEqual(breachesOf(await checkBook(w.book())), [[], [], [], ['over-period-limit'], []]);
});

// --- cancelling ---

test('finding 4: where the person cancelled twice, the order of the two in the book changes nothing', async () => {
  for (const order of ['time-stamped one first', 'time-stamped one second']) {
    const w = await makeWorld();
    await w.add({ when: START });
    await w.seal({ when: START + 10 * 60 * 1000 });
    // Written after the cancellation in truth, and dated before it.
    await w.add({ when: START + 30 * 60 * 1000 });
    const stamped = await w.cancel({ when: START + HOUR, stampTime: START + HOUR + 1000 });
    const plain = await w.cancel({ when: START + 6 * HOUR });
    w.entries.splice(-2, 2, ...(order === 'time-stamped one first' ? [stamped.entry, plain.entry] : [plain.entry, stamped.entry]));
    const r = await checkBook(w.book(), { stampServices: [w.stampService.fingerprint] });
    assert.deepEqual(breachesOf(r), [[], [], [], ['after-cancellation'], [], []], order);
    assert.equal(r.summary.withinSlips, false, order);
  }
});

test('finding 5: a time-stamp dated well after the cancellation\'s own date is pointed out: a later one could have been put in its place', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  const cancel = await w.cancel({ when: START + HOUR, stampTime: START + HOUR + 1000 });
  const trust = { stampServices: [w.stampService.fingerprint] };
  const honest = await checkBook(w.book(), trust);
  assert.deepEqual(breachesOf(honest), [[], ['after-cancellation'], []]);
  assert.ok(!honest.entries[2].notes.some((n) => /later time-stamp/.test(n)));
  // Whoever keeps the book seals the stub, and swaps the time-stamp for one made three hours later.
  w.entries.pop();
  await w.seal({ when: START + 3 * HOUR });
  const later = toBase64url(await w.stampService.stamp(fromBase64url(cancel.fingerprint), START + 4 * HOUR));
  w.entries.push({ cancellation: cancel.record, stamps: [later] });
  const swapped = await checkBook(w.book(), trust);
  assert.ok(swapped.entries[3].notes.some((n) => /could have put a later time-stamp in the place of an earlier one/.test(n)));
});

test('finding 7: single pages use only the place of a cancellation, as the whole book would clear the stub', async () => {
  const w = await makeWorld();
  await w.add({ when: START });
  await w.seal({ when: START + 10 * 60 * 1000 });
  await w.cancel({ when: START + HOUR, stampTime: START + HOUR + 1000 });
  const trust = { stampServices: [w.stampService.fingerprint] };
  assert.deepEqual(codes(await checkBook(w.book(), trust)), []);
  const pages = await checkShow(await makeShow(w.book(), [0, 1, 2, 3]), trust);
  assert.deepEqual(breachesOf(pages), [[], [], [], []]);
  assert.ok(pages.entries[3].notes.some((n) => /Single pages cannot show which stubs existed before that time/.test(n)));
});

test('finding 8: every Show says that a cancellation or a withdrawal may be on a page that is not shown', async () => {
  const w = await makeWorld();
  await w.add();
  await w.cancel();
  await w.add();
  const r = await checkShow(await makeShow(w.book(), [0, 3]));
  assert.deepEqual(codes(r), []);
  assert.ok(r.notes.some((n) => /was not cancelled/.test(n) && /was not withdrawn/.test(n) && /a page that is not shown/.test(n)));
});

// --- vouching ---

test('finding 9: a vouching record stands behind a slip only if it is in force for the whole of the slip\'s time', async () => {
  const build = async (window) => {
    const w = await makeWorld({ fields: { validFrom: '2025-12-31T23:59:59Z', validUntil: '2026-12-31T00:00:00Z' } });
    const slip = w.entries.pop();
    await w.vouch({ kind: 'person', key: w.passkey.key, name: 'Sam Example' }, { ...window, when: Date.parse('2025-01-01T00:00:00Z') });
    w.entries.push(slip);
    await w.add({ when: START });
    const r = await checkBook(w.book(), { vouchers: [await keySetFingerprint(w.organisation.keys)] });
    assert.deepEqual(codes(r), []);
    return r.entries[1].vouched.issuer;
  };
  // In force for 2025 only: it had run out nine months before the action.
  assert.equal(await build({ validFrom: '2025-01-01T00:00:00Z', validUntil: '2026-01-01T00:00:00Z' }), null);
  // In force for the whole of the slip's time, to the second.
  assert.equal((await build({ validFrom: '2025-12-31T23:59:59Z', validUntil: '2026-12-31T00:00:00Z' })).counted, true);
});

test('finding 11: many vouching records from organisations the checker did not name do not crowd out the one it trusts', async () => {
  const w = await makeWorld();
  const slip = w.entries.pop();
  const who = { kind: 'person', key: w.passkey.key, name: 'Sam Example' };
  const stranger = await generateKeySet();
  const first = await w.vouch(who, { signer: stranger, by: 'A stranger (invented)' });
  for (let i = 0; i < 11; i++) await w.vouch(who, { signer: stranger, by: 'A stranger (invented)' });
  await w.vouch(who);
  w.entries.push(slip);
  const trust = { vouchers: [await keySetFingerprint(w.organisation.keys)] };
  const r = await checkBook(w.book(), trust);
  assert.deepEqual(codes(r), []);
  assert.deepEqual(r.entries.at(-1).vouched.issuer, { counted: true, by: 'Example Organisation (invented)', keys: trust.vouchers[0] });
  // Without the trusted one named, a stranger's record is shown, and not counted.
  const untrusting = await checkBook(w.book());
  assert.equal(untrusting.entries.at(-1).vouched.issuer.counted, false);
  assert.equal(first.fingerprint.length, 43);
});

test('finding 12: a service whose id is a word such as "constructor" is not shown as vouched for', async () => {
  // "constructor" is the one such word that the form of a service's id allows.
  const w = await makeWorld({ fields: { with: [{ id: 'constructor', name: 'Example Builders (invented)' }] } });
  const r = await checkBook(w.book());
  assert.deepEqual(codes(r), []);
  const { services } = r.entries[0].vouched;
  assert.ok(Object.hasOwn(services, 'constructor'));
  assert.equal(services.constructor, null);
  const lines = cli(w.book()).stdout.split('\n').filter((line) => line.includes('With:'));
  assert.equal(lines.length, 1);
  assert.match(lines[0], /\(a label, not checked\)/);
  assert.doesNotMatch(lines[0], /vouches|undefined/);
  const words = pageWords(r).filter((line) => /\[constructor\]/.test(line));
  assert.equal(words.length, 1);
  assert.match(words[0], /\(a label; it is not checked\)$/);
});

// --- passing on ---

test('finding 6: a helper that passes on does not escape the limits, the actions or the times of its own pass', async () => {
  // A pass limited to 30 GBP, passed on with no limit.
  const w = await makeWorld({ fields: { passes: 2 } });
  const first = await w.pass({ limits: [{ action: ORDER, max: 30, unit: 'GBP' }] });
  const second = await w.pass({ from: first.fingerprint, signer: first.helper.privateKeys, helper: first.helper, limits: [] });
  await second.add({ value: 150, when: START + HOUR });
  const r = await checkBook(w.book());
  assert.deepEqual(breachesOf(r), [[], [], [], ['over-limit']]);
  assert.match(r.entries[3].breaches[0].message, /The earlier pass's limit is 30 GBP/);
  const more = await checkBefore(
    w.book(),
    { slip: w.slipFingerprint, pass: second.fingerprint, action: ORDER, amount: { unit: 'GBP', value: 40 }, with: 'supplier', when: START + 2 * HOUR },
    await trusting(w),
  );
  assert.equal(more.allowed, false);
  assert.deepEqual(more.breaches.map((b) => b.code), ['over-limit']);

  // A helper that holds one action until 6 October passes on another action, until 12 October.
  const v = await makeWorld({ fields: { passes: 2, actions: [ORDER, 'door.unlock'] } });
  const narrow = await v.pass({ actions: [ORDER], validUntil: '2026-10-06T08:00:00Z' });
  const wide = await v.pass({ from: narrow.fingerprint, signer: narrow.helper.privateKeys, actions: [ORDER, 'door.unlock'] });
  await wide.add({ action: 'door.unlock', amount: undefined, with: undefined, countersigned: false, when: Date.parse('2026-10-09T09:00:00Z') });
  assert.deepEqual(breachesOf(await checkBook(v.book())), [[], [], ['pass-wider'], ['action-not-allowed', 'outside-valid-time']]);
  const unlock = await checkBefore(v.book(), { slip: v.slipFingerprint, pass: wide.fingerprint, action: 'door.unlock', when: Date.parse('2026-10-09T10:00:00Z') }, await trusting(v));
  assert.equal(unlock.allowed, false);
});

test('finding 10: a pass this device cannot check is never "within its slip"', async () => {
  const w = await makeWorld();
  await w.pass();
  const full = await checkBook(w.book());
  assert.deepEqual(breachesOf(full), [[], ['pass-not-allowed']]);
  assert.equal(full.entries[1].compared, true);
  const partial = await checkBook(w.book(), { withoutMethods: ['Ed25519', 'ML-DSA-87'] });
  assert.equal(partial.entries[1].compared, false);
  assert.equal(partial.summary.withinSlips, false);
  assert.equal(partial.summary.intact, false);
});

// --- what is shown ---

test('finding 15: the command-line checker and the page show how often a slip may be passed on', async () => {
  for (const [passes, words] of [
    [1, /May be passed on:?\s+once, to a helper agent/],
    [3, /May be passed on:?\s+3 times in a row, to helper agents/],
  ]) {
    const w = await makeWorld({ fields: { passes } });
    assert.match(cli(w.book()).stdout, words);
    assert.match(pageWords(await checkBook(w.book())).join(' '), words);
  }
  const without = await makeWorld();
  assert.doesNotMatch(cli(without.book()).stdout, /passed on/);
});

test('finding 16: a covered name is absent from what the checker hands back, and a helper\'s stub names its pass', async () => {
  const w = await makeWorld({ cover: ['issuer.name', 'agent.name', 'purpose', 'with.name'], fields: { passes: 1 } });
  const slip = await checkSlip(w.slip);
  assert.deepEqual(slip.problems, []);
  for (const object of [slip.content.issuer, slip.content.agent, slip.content.with[0]]) assert.ok(!Object.hasOwn(object, 'name'));
  assert.ok(!Object.hasOwn(slip.content, 'purpose'));
  const pass = await w.pass();
  await pass.add();
  const r = await checkBook(w.book());
  assert.equal(r.entries[2].pass, pass.fingerprint);
});
