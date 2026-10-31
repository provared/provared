// The address a permission must have been signed at, named by the reader
// (the option issuerOrigins; format description, section 4.4): a slip signed
// at any other address is refused with a code of its own; the addresses
// named must be in the one form the format allows, or the whole check is a
// problem; and a whole book, a Show, a checker that is carried on and the
// check before acting all read the option alike. The shared test files
// slips.json, issuer-origins.json and issuer-origin-shows.json hold the
// answers both languages give, words included.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBefore, checkBook, checkShow, checkSlip, isPageAddress, makeShow, openChecker, thumbprint } from '../src/index.js';
import { START, makeWorld } from './helpers/world.mjs';

const codes = (list) => list.map((p) => p.code);
// Where the test world's passkey signs (helpers/passkey.mjs), and another address.
const HERE = 'http://localhost:8787';
const ELSEWHERE = 'https://sign.example.org';
const NOTE = `This slip was signed at ${HERE}, an address you named.`;

async function three() {
  const w = await makeWorld();
  await w.add();
  await w.add();
  await w.add();
  return w;
}

test('isPageAddress: the one form the format allows for a page address, and nothing else', () => {
  for (const ok of ['https://sign.example.org', 'https://example.org', 'https://sign.example.org:8443', 'http://localhost', 'http://localhost:8787', 'https://xn--bcher-kva.example']) {
    assert.equal(isPageAddress(ok), true, ok);
  }
  const bad = [
    'https://Sign.example.org', 'https://sign.example.org/', 'https://sign.example.org:443', 'http://sign.example.org', 'http://app.localhost',
    'https://sign.example.org?a', 'sign.example.org', 'https://1.2.3.4', 'https://sign.example.org:0', '', 'HTTPS://sign.example.org',
    'https://u@sign.example.org', 'https://sign.example.org:65536', 'https://-a.example.org', 'https://a..example.org', ' https://sign.example.org',
    42, null, undefined, ['https://sign.example.org'], { toString: () => 'https://sign.example.org' },
  ];
  for (const value of bad) assert.equal(isPageAddress(value), false, String(value));
});

test('a slip signed at an address the reader named passes, with a note that says so; one signed elsewhere is refused with its own code', async () => {
  const w = await makeWorld();
  const named = await checkSlip(w.slip, { issuerOrigins: [HERE] });
  assert.deepEqual(named.problems, []);
  assert.ok(named.notes.includes(NOTE), JSON.stringify(named.notes));
  const other = await checkSlip(w.slip, { issuerOrigins: [ELSEWHERE] });
  assert.deepEqual(codes(other.problems), ['issuer-origin-not-expected']);
  assert.equal(other.problems[0].message, 'The slip was signed at a page address other than the ones expected.');
  assert.equal(other.signature.state, 'valid', 'the signature was checked first; the address is a matter of trust');
  // Several may be named; the slip's address must be one of them, exactly.
  assert.deepEqual((await checkSlip(w.slip, { issuerOrigins: [ELSEWHERE, HERE] })).problems, []);
  assert.deepEqual(codes((await checkSlip(w.slip, { issuerOrigins: ['http://localhost'] })).problems), ['issuer-origin-not-expected']);
  // An empty list names no address, so no slip was signed at one of them.
  assert.deepEqual(codes((await checkSlip(w.slip, { issuerOrigins: [] })).problems), ['issuer-origin-not-expected']);
  // Where none is named, nothing is compared, and nothing is said about it.
  const silent = await checkSlip(w.slip);
  assert.deepEqual(silent.problems, []);
  assert.ok(!silent.notes.some((n) => n.includes('address')), JSON.stringify(silent.notes));
});

test('the passkey is compared before the address: a slip from another passkey is refused as such, whatever its address', async () => {
  const w = await makeWorld();
  const r = await checkSlip(w.slip, { issuerKeys: ['A'.repeat(43)], issuerOrigins: [ELSEWHERE] });
  assert.deepEqual(codes(r.problems), ['issuer-not-expected']);
  const both = await checkSlip(w.slip, { issuerKeys: [await thumbprint(w.passkey.key)], issuerOrigins: [HERE] });
  assert.deepEqual(both.problems, []);
  assert.deepEqual(both.notes, [NOTE]);
});

test('the addresses named must be a list of at most 64, each in its plain form; anything else is a problem with the whole check, never set aside', async () => {
  const w = await three();
  for (const value of ['HTTPS://sign.example.org', `${HERE}/`, 'sign.example.org', 42, null, undefined]) {
    const r = await checkBook(w.book(), { issuerOrigins: [HERE, value] });
    assert.deepEqual(codes(r.problems), ['bad-field'], String(value));
    assert.match(r.problems[0].message, /^issuerOrigins: must be a list of at most 64 page addresses/);
    assert.equal(r.summary.problemFound, true);
    assert.deepEqual(r.entries, [], 'no line is read');
  }
  for (const value of [HERE, 'not a list', null, { 0: HERE, length: 1 }, new Set([HERE])]) {
    assert.deepEqual(codes((await checkBook(w.book(), { issuerOrigins: value })).problems), ['bad-field'], String(value));
  }
  // A gap in the list is a place that holds no address.
  const gap = [HERE];
  gap[2] = HERE;
  assert.deepEqual(codes((await checkBook(w.book(), { issuerOrigins: gap })).problems), ['bad-field']);
  assert.deepEqual(codes((await checkBook(w.book(), { issuerOrigins: new Array(65).fill(HERE) })).problems), ['bad-field']);
  assert.deepEqual((await checkBook(w.book(), { issuerOrigins: new Array(64).fill(HERE) })).problems, []);
  // Not given at all is not the same as given empty.
  assert.deepEqual((await checkBook(w.book(), { issuerOrigins: undefined })).problems, []);
  // checkSlip alone reports the same fault on the slip, having nowhere else to report it.
  assert.deepEqual(codes((await checkSlip(w.slip, { issuerOrigins: 'x' })).problems), ['bad-field']);
});

test('in a book, a slip signed elsewhere fails, and the stubs under it are not compared; a Show and a carried checker answer alike', async () => {
  const w = await three();
  const trusted = { issuerKeys: [await thumbprint(w.passkey.key)] };
  const good = await checkBook(w.book(), { ...trusted, issuerOrigins: [HERE] });
  assert.equal(good.summary.intact, true);
  assert.equal(good.summary.withinSlips, true);
  assert.deepEqual(good.entries[0].notes, [NOTE]);
  const bad = await checkBook(w.book(), { ...trusted, issuerOrigins: [ELSEWHERE] });
  assert.equal(bad.summary.problemFound, true);
  assert.equal(bad.summary.intact, false);
  assert.deepEqual(codes(bad.entries[0].problems), ['issuer-origin-not-expected']);
  for (const e of bad.entries.slice(1)) assert.deepEqual(codes(e.problems), ['slip-unusable']);
  assert.equal(bad.summary.withinSlips, false);
  // The checker that is carried on gives the answer a whole check gives.
  const carried = await openChecker('', { ...trusted, issuerOrigins: [ELSEWHERE] });
  await carried.add(w.book());
  assert.deepEqual(await carried.result(), bad);
  // A Show of the slip and one stub.
  const show = await makeShow(w.book(), [0, 1]);
  const shown = await checkShow(show, { ...trusted, issuerOrigins: [ELSEWHERE] });
  assert.deepEqual(codes(shown.entries[0].problems), ['issuer-origin-not-expected']);
  assert.equal(shown.summary.problemFound, true);
  const fine = await checkShow(show, { ...trusted, issuerOrigins: [HERE] });
  assert.deepEqual(fine.problems, []);
  assert.deepEqual(fine.entries[0].notes, [NOTE]);
  assert.deepEqual(codes((await checkShow(show, { ...trusted, issuerOrigins: ['x'] })).problems), ['bad-field']);
});

test('the check before acting allows nothing under a slip signed at an address the reader did not name', async () => {
  const w = await three();
  const trusted = { issuerKeys: [await thumbprint(w.passkey.key)] };
  const proposal = { slip: w.slipFingerprint, action: 'supplies.order', amount: { unit: 'GBP', value: 10 }, with: 'supplier', when: START + 10 * 3600 * 1000 };
  const allowed = await checkBefore(w.book(), proposal, { ...trusted, issuerOrigins: [HERE] });
  assert.equal(allowed.allowed, true, JSON.stringify(allowed));
  const refused = await checkBefore(w.book(), proposal, { ...trusted, issuerOrigins: [ELSEWHERE] });
  assert.equal(refused.allowed, false);
  assert.deepEqual(codes(refused.problems), ['record-not-sound']);
  const malformed = await checkBefore(w.book(), proposal, { ...trusted, issuerOrigins: [`${HERE}/`] });
  assert.equal(malformed.allowed, false);
  assert.deepEqual(codes(malformed.problems), ['record-not-sound']);
});
