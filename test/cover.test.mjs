// Covered fields, by the standard "Selective Disclosure for JSON Web
// Tokens" (RFC 9901): the standard's own worked example, what the standard
// says must be refused, and covered names in a slip.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { coverMembers, disclosureDigest, makeDisclosure, uncover } from '../src/cover.js';
import { checkBook, checkShow, checkSlip, makeShow, prepareSlip } from '../src/index.js';
import { makeWorld, withContent } from './helpers/world.mjs';

const example = JSON.parse(readFileSync(new URL('./fixtures/rfc9901-example.json', import.meta.url), 'utf8'));
const all = example.disclosures.map((d) => d.disclosure);
const b64 = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
const invalid = (e) => e.code === 'cover-invalid';

function codes(result) {
  const out = result.problems.map((p) => p.code);
  for (const e of result.entries) out.push(...e.problems.map((p) => p.code), ...e.breaches.map((b) => b.code));
  return out;
}

// --- the standard's own example ---

test('RFC 9901, section 4.2.3: the fingerprint of a disclosure is taken over its base64url text', async () => {
  const disclosure = 'WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0';
  assert.equal(await disclosureDigest(disclosure), 'X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0');
  // Section 4.2.2: a list item.
  assert.equal(await disclosureDigest('WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0'), 'w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs');
  for (const d of example.disclosures) assert.equal(await disclosureDigest(d.disclosure), d.hash);
});

test('RFC 9901, section 5.1: with every disclosure, the content is the claims the issuer began with', async () => {
  const { content } = await uncover(example.payload, all);
  const { iss, iat, exp, cnf, ...claims } = content;
  assert.deepEqual(claims, example.claims);
  assert.equal(iss, 'https://issuer.example.com');
  assert.ok(iat && exp && cnf);
  assert.ok(!('_sd' in content) && !('_sd_alg' in content));
});

test('RFC 9901, section 7.1: with no disclosure, only what was never covered is left', async () => {
  const { content, places } = await uncover(example.payload, []);
  assert.deepEqual(Object.keys(content).sort(), ['cnf', 'exp', 'iat', 'iss', 'nationalities', 'sub']);
  // Covered list items with no disclosure are left out.
  assert.deepEqual(content.nationalities, []);
  assert.deepEqual(places.get(''), { covered: 8, revealed: [] });
});

test('RFC 9901: some disclosures reveal exactly their own fields', async () => {
  const pick = (name) => example.disclosures.find((d) => d.contents[1] === name).disclosure;
  const german = example.disclosures.find((d) => d.contents.length === 2 && d.contents[1] === 'DE').disclosure;
  const { content, places } = await uncover(example.payload, [pick('given_name'), pick('address'), german]);
  assert.equal(content.given_name, 'John');
  assert.deepEqual(content.address, example.claims.address);
  assert.deepEqual(content.nationalities, ['DE']);
  assert.equal(content.family_name, undefined);
  assert.equal(places.get('').covered, 6);
  assert.deepEqual([...places.get('').revealed].sort(), ['address', 'given_name']);
});

test('RFC 9901, section 7.1: what the standard says must be rejected is rejected', async () => {
  const given = example.disclosures.find((d) => d.contents[1] === 'given_name');
  const cases = [
    // Step 5: a disclosure that belongs to nothing in the content.
    [example.payload, [b64(['salt', 'given_name', 'Mallory'])]],
    // A disclosure handed over twice.
    [example.payload, [given.disclosure, given.disclosure]],
    // Step 4: the same fingerprint twice in the content.
    [{ ...example.payload, _sd: [...example.payload._sd, given.hash] }, []],
    [{ ...example.payload, nationalities: [{ '...': given.hash }] }, []],
    // Step 3.c.ii.3: the name is already there.
    [{ ...example.payload, given_name: 'Mallory' }, [given.disclosure]],
    // Not a list of the right length, or with no salt.
    [example.payload, [b64(['only one'])]],
    [example.payload, [b64(['a', 'b', 'c', 'd'])]],
    [example.payload, [b64([1, 'name', 'value'])]],
    [example.payload, [b64({ salt: 'x' })]],
    [example.payload, ['not base64url!']],
    [example.payload, [b64('not json')]],
    [example.payload, [42]],
    [example.payload, 'disclosures'],
    // "_sd" that is not a list of text; "_sd_alg" elsewhere or of another method.
    [{ _sd: 'x' }, []],
    [{ _sd: [1] }, []],
    [{ ...example.payload, _sd_alg: 'sha-512' }, []],
    [{ inner: { _sd_alg: 'sha-256' } }, []],
  ];
  for (const [i, [payload, disclosures]] of cases.entries()) {
    await assert.rejects(uncover(payload, disclosures), invalid, `case ${i}`);
  }
});

test('RFC 9901, step 3.c: a disclosure of the wrong shape for its place, or with a forbidden name, is rejected', async () => {
  const forName = async (parts) => {
    const disclosure = b64(parts);
    return [{ _sd: [await disclosureDigest(disclosure)] }, [disclosure]];
  };
  for (const parts of [['s', '_sd', 1], ['s', '...', 1], ['s', '_sd_alg', 'sha-256'], ['s', 'value-with-no-name'], ['s', 5, 'x']]) {
    const [payload, disclosures] = await forName(parts);
    await assert.rejects(uncover(payload, disclosures), invalid, JSON.stringify(parts));
  }
  const item = b64(['s', 'name', 'value']);
  await assert.rejects(uncover({ list: [{ '...': await disclosureDigest(item) }] }, [item]), invalid);
  // A name that would reach into the object's own machinery is only a name.
  const proto = b64(['s', '__proto__', { admin: 1 }]);
  const { content } = await uncover({ _sd: [await disclosureDigest(proto)] }, [proto]);
  assert.equal(Object.getPrototypeOf(content), Object.prototype);
  assert.equal(content.admin, undefined);
  assert.ok(Object.hasOwn(content, '__proto__'));
});

test('a revealed field may itself hold covered fields, to any depth the standard allows, and no deeper than is safe', async () => {
  const inner = await makeDisclosure('street', 'Main St');
  const outer = await makeDisclosure('address', { _sd: [inner.digest], town: 'Anytown' });
  const payload = { _sd: [outer.digest] };
  assert.deepEqual((await uncover(payload, [outer.disclosure, inner.disclosure])).content, { address: { street: 'Main St', town: 'Anytown' } });
  assert.deepEqual((await uncover(payload, [outer.disclosure])).content, { address: { town: 'Anytown' } });
  // The inner one alone belongs to nothing that is visible.
  await assert.rejects(uncover(payload, [inner.disclosure]), invalid);
  let deep = 'x';
  for (let i = 0; i < 40; i++) deep = [deep];
  await assert.rejects(uncover({ deep }, []), invalid);
});

test('covering members of an object gives back the object when every disclosure is handed over', async () => {
  const original = { id: 'supplier', name: 'Example Stationery', keys: ['k'] };
  const { object, disclosures } = await coverMembers(original, ['name', 'absent']);
  assert.deepEqual(Object.keys(object).sort(), ['_sd', 'id', 'keys']);
  assert.equal(disclosures.length, 1);
  assert.deepEqual((await uncover(object, disclosures)).content, original);
  // Two disclosures of the same value differ: the salt is new each time.
  assert.notEqual((await makeDisclosure('a', 1)).digest, (await makeDisclosure('a', 1)).digest);
});

// --- covered names in a slip ---

const EVERY = ['issuer.name', 'agent.name', 'purpose', 'with.name'];

test('a slip with its names and purpose covered checks, and shows them only to whoever is handed the disclosures', async () => {
  const w = await makeWorld({ cover: EVERY });
  await w.add();
  const disclosures = w.prepared.disclosures;
  assert.equal(disclosures.length, 4);

  const hidden = await checkBook(w.book());
  assert.deepEqual(codes(hidden), []);
  assert.equal(hidden.summary.intact, true);
  assert.equal(hidden.summary.withinSlips, true);
  const slip = hidden.entries[0];
  assert.deepEqual(slip.covered.sort(), ['agent.name', 'issuer.name', 'purpose', 'with[0].name']);
  assert.equal(slip.content.issuer.name, undefined);
  assert.equal(slip.content.purpose, undefined);
  // The signed content holds no name anywhere.
  assert.ok(!Buffer.from(w.slip.payload, 'base64url').toString().includes('Sam Example'));

  const revealed = await checkBook(w.book(), { disclosures: { [w.slipFingerprint]: disclosures } });
  assert.deepEqual(codes(revealed), []);
  assert.deepEqual(revealed.entries[0].covered, []);
  assert.equal(revealed.entries[0].content.issuer.name, 'Sam Example');
  assert.equal(revealed.entries[0].content.purpose, 'Keep the office stocked with paper, pens and toner.');

  // Covering changes neither the fingerprint of the slip nor the top fingerprint of the book.
  assert.equal(revealed.root, hidden.root);
  assert.equal(revealed.entries[0].fingerprint, hidden.entries[0].fingerprint);
});

test('one disclosure reveals one field, and no more', async () => {
  const w = await makeWorld({ cover: EVERY });
  for (const d of w.prepared.disclosures) {
    const r = await checkSlip(w.slip, { disclosures: { [w.slipFingerprint]: [d] } });
    assert.deepEqual(r.problems, []);
    assert.equal(r.covered.length, 3);
  }
});

test('a disclosure that was changed, or belongs to another slip, is refused', async () => {
  const w = await makeWorld({ cover: ['issuer.name'] });
  const other = await makeWorld({ cover: ['issuer.name'] });
  const forged = b64(['salt', 'name', 'Mallory']);
  for (const disclosures of [[forged], other.prepared.disclosures, [w.prepared.disclosures[0], forged], 'everything', [null]]) {
    const r = await checkSlip(w.slip, {}, disclosures);
    // The disclosures are refused, all of them, and the slip is checked with its name covered.
    assert.deepEqual(r.disclosureProblems.map((p) => p.code), ['cover-invalid']);
    assert.deepEqual(r.problems, []);
    assert.deepEqual(r.covered, ['issuer.name']);
    assert.ok(!Object.hasOwn(r.content.issuer, 'name'));
    // In a book, that is a problem with what was handed over, and the check is not a pass.
    w.entries[0] = { slip: w.slip };
    const book = await checkBook(w.book(), { disclosures: { [w.slipFingerprint]: disclosures } });
    assert.deepEqual(book.problems.map((p) => p.code), ['cover-invalid']);
    assert.deepEqual(book.entries[0].problems, []);
    assert.equal(book.summary.intact, false);
  }
});

test('only a name or the purpose of a slip may be covered', async () => {
  const w = await makeWorld();
  await assert.rejects(prepareSlip(w.fields, { cover: ['limits'] }), (e) => e.code === 'bad-field');
  // A slip signed with something else covered: the limits, the actions, the agent's keys.
  const hide = async (change) => {
    const forged = withContent(w.slip, change);
    w.entries[0] = { slip: forged };
    return codes(await checkBook(w.book()));
  };
  const digest = 'A'.repeat(43);
  assert.ok((await hide((c) => void (delete c.limits, (c._sd = [digest])))).includes('bad-field'));
  assert.ok((await hide((c) => void (delete c.agent.keys, (c.agent._sd = [digest])))).includes('bad-field'));
  assert.ok((await hide((c) => void (c.limits[0]._sd = [digest]))).includes('bad-field'));
  // An item of a list may not be covered at all in a slip, though the standard allows it.
  assert.ok((await hide((c) => void (c.actions = [{ '...': digest }]))).includes('cover-invalid'));
});

test('a revealed field must be the one that may be covered there', async () => {
  // A slip whose issuer holds a covered field named "key": revealed, it would replace nothing, and it is refused.
  const w = await makeWorld();
  const extra = await makeDisclosure('extra', 'x');
  w.entries[0] = { slip: withContent(w.slip, (c) => void (c.issuer._sd = [extra.digest])) };
  const fingerprintOf = (await checkBook(w.book())).entries[0].fingerprint;
  const r = await checkBook(w.book(), { disclosures: { [fingerprintOf]: [extra.disclosure] } });
  assert.ok(codes(r).includes('bad-field'));
});

test('a covered name cannot be vouched for, and other records may not hold covered fields', async () => {
  const w = await makeWorld({ cover: ['agent.name'] });
  const stub = await w.add();
  assert.equal((await checkBook(w.book())).entries[0].vouched.agent, null);
  stub.entry.stub = withContent(stub.entry.stub, (c) => void (c._sd = ['A'.repeat(43)]));
  assert.ok(codes(await checkBook(w.book())).includes('bad-field'));
});

test('a Show can hand over the disclosures for a page, and the reader sees those fields only', async () => {
  const w = await makeWorld({ cover: EVERY });
  await w.add();
  const purposeOnly = [];
  for (const d of w.prepared.disclosures) if (Buffer.from(d, 'base64url').toString().includes('"purpose"')) purposeOnly.push(d);
  const show = await makeShow(w.book(), [0, 1], { disclosures: { 0: purposeOnly } });
  const r = await checkShow(show);
  assert.deepEqual(codes(r), []);
  assert.equal(r.entries[0].content.purpose, 'Keep the office stocked with paper, pens and toner.');
  assert.equal(r.entries[0].content.issuer.name, undefined);
  assert.equal(r.entries[0].covered.length, 3);
  // Disclosures on a page that are not a list are refused.
  assert.ok(codes(await checkShow({ ...show, pages: [{ ...show.pages[0], disclosures: 'all' }, show.pages[1]] })).includes('bad-field'));
});
