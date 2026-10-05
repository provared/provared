// Cancelling a slip, vouching for a name, withdrawing a vouching record,
// and the fingerprints of the agent's software.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkBefore, checkBook, checkShow, generateKeySet, keySetFingerprint, makeShow, prepareSlip, thumbprint } from '../src/index.js';
import { START, makeWorld, withContent } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const ORDER = 'supplies.order';

function codes(result) {
  const out = result.problems.map((p) => p.code);
  for (const e of result.entries) out.push(...e.problems.map((p) => p.code), ...e.breaches.map((b) => b.code));
  return out;
}
const breachesOf = (r) => r.entries.map((e) => e.breaches.map((b) => b.code));

// --- cancelling a slip ---

test('after the person cancels a slip, every later stub is outside it', async () => {
  const w = await makeWorld();
  await w.add();
  await w.cancel();
  await w.add();
  await w.add();
  const r = await checkBook(w.book());
  assert.equal(r.summary.intact, true);
  assert.deepEqual(breachesOf(r), [[], [], [], ['after-cancellation'], ['after-cancellation']]);
  assert.equal(r.entries[2].kind, 'cancellation');
  assert.equal(r.entries[2].signature.state, 'valid');
  assert.equal(r.summary.counts.cancellations, 1);
  // With no time-stamp, only its place in the book says when it took effect.
  assert.ok(r.entries[2].notes.some((n) => /Only its place in the book/.test(n)));
});

test('only the passkey that signed the slip can cancel it', async () => {
  const w = await makeWorld();
  await w.add();
  const other = await makeWorld();
  await w.cancel({ passkey: other.passkey });
  await w.add();
  const r = await checkBook(w.book());
  assert.ok(codes(r).includes('cancellation-invalid'));
  // The slip was not cancelled: the stub after it is compared as before.
  assert.deepEqual(r.entries[3].breaches, []);

  // A cancellation whose passkey did not confirm the person is refused too.
  const w2 = await makeWorld();
  await w2.cancel({ assertion: { flags: 0x01 } });
  assert.ok(codes(await checkBook(w2.book())).includes('cancellation-invalid'));
});

test('a cancellation names one slip: it does not cancel another, and it needs its slip in the book', async () => {
  const w = await makeWorld();
  const other = await makeWorld();
  await w.cancel({ slip: other.slipFingerprint });
  assert.ok(codes(await checkBook(w.book())).includes('slip-missing'));

  // Moved to another slip's book, with that slip's fingerprint written in, the signature no longer fits.
  const mine = await makeWorld();
  const c = await mine.cancel();
  other.entries.push({ cancellation: withContent(c.record, (content) => void (content.slip = other.slipFingerprint)) });
  assert.ok(codes(await checkBook(other.book())).includes('cancellation-invalid'));
});

test('with a time-stamped cancellation, a stub counts as earlier only if a time-stamp shows it', async () => {
  // Stub A is sealed and time-stamped before the cancellation. Stub B is
  // written into the book before the cancellation, dated before it, but
  // nothing outside shows that it existed then.
  const w = await makeWorld();
  await w.add({ when: START });
  await w.seal({ when: START + 10 * 60 * 1000 });
  await w.add({ when: START + 20 * 60 * 1000 });
  await w.cancel({ when: START + HOUR, stampTime: START + HOUR + 1000 });
  const r = await checkBook(w.book(), { stampServices: [w.stampService.fingerprint] });
  assert.deepEqual(codes(r), ['after-cancellation']);
  assert.deepEqual(breachesOf(r), [[], [], [], ['after-cancellation'], []]);
  assert.match(r.entries[3].breaches[0].message, /not shown to have existed before/);
  assert.equal(r.entries[4].stampedAt, '2026-10-05T10:00:01Z');

  // Without trusting the time-stamp service, only the place in the book counts.
  const untrusting = await checkBook(w.book());
  assert.deepEqual(codes(untrusting), []);
});

test('a time-stamp on a cancellation is for that cancellation only', async () => {
  const w = await makeWorld();
  const first = await w.cancel({ stampTime: START + HOUR });
  const other = await makeWorld();
  const second = await other.cancel();
  second.entry.stamps = first.entry.stamps;
  assert.ok(codes(await checkBook(other.book())).includes('stamp-wrong-data'));
});

test('the check before acting allows nothing under a cancelled slip', async () => {
  const w = await makeWorld();
  await w.add();
  await w.cancel();
  const answer = await checkBefore(
    w.book(),
    { slip: w.slipFingerprint, action: ORDER, amount: { unit: 'GBP', value: 1 }, with: 'supplier', when: START + 2 * HOUR },
    { issuerKeys: [await thumbprint(w.passkey.key)] },
  );
  assert.equal(answer.allowed, false);
  assert.deepEqual(answer.breaches.map((b) => b.code), ['after-cancellation']);
});

test('a Show of a cancellation and a later stub shows the stub outside the slip', async () => {
  const w = await makeWorld();
  await w.add();
  await w.cancel();
  await w.add();
  const r = await checkShow(await makeShow(w.book(), [0, 2, 3]));
  assert.deepEqual(r.entries[2].breaches.map((b) => b.code), ['after-cancellation']);
  // A stub from before the cancellation is not marked.
  const earlier = await checkShow(await makeShow(w.book(), [0, 1, 2]));
  assert.deepEqual(earlier.entries[1].breaches, []);
});

// --- vouching for a name ---

async function vouchedWorld() {
  const w = await makeWorld();
  const slip = w.entries.pop();
  const person = await w.vouch({ kind: 'person', key: w.passkey.key, name: 'Sam Example' });
  const agent = await w.vouch({ kind: 'agent', keys: w.agent.keys, name: 'Office supplies agent' });
  const service = await w.vouch({ kind: 'service', keys: w.service.keys, name: 'Example Stationery (invented)' });
  w.entries.push(slip);
  return { w, person, agent, service, trust: { vouchers: [await keySetFingerprint(w.organisation.keys)] } };
}

test('a name that an organisation the checker trusts vouched for is shown as vouched for', async () => {
  const { w, trust } = await vouchedWorld();
  await w.add();
  const r = await checkBook(w.book(), trust);
  assert.deepEqual(codes(r), []);
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.counts.vouchings, 3);
  const by = { counted: true, by: 'Example Organisation (invented)', keys: trust.vouchers[0] };
  assert.deepEqual(r.entries[3].vouched, { issuer: by, agent: by, services: { supplier: by } });
  // The person's name is vouched for, so the note about an unknown key is gone.
  assert.deepEqual(r.entries[3].notes, []);
  assert.deepEqual(r.entries[0].notes, []);
});

test('a vouching record from an organisation the checker did not name is shown and not counted', async () => {
  const { w } = await vouchedWorld();
  const r = await checkBook(w.book());
  assert.deepEqual(codes(r), []);
  assert.equal(r.entries[3].vouched.issuer.counted, false);
  assert.ok(r.entries[3].notes.some((n) => /was not compared with a key you already trust/.test(n)));
  assert.ok(r.entries[0].notes.some((n) => /did not name as trusted/.test(n)));
});

test('a vouching record vouches for exactly one key and one name, while it is in force', async () => {
  const w = await makeWorld();
  const slip = w.entries.pop();
  const stranger = await generateKeySet();
  await w.vouch({ kind: 'person', key: w.passkey.key, name: 'Somebody Else' }); // another name
  await w.vouch({ kind: 'agent', keys: stranger.keys, name: 'Office supplies agent' }); // other keys
  await w.vouch({ kind: 'agent', keys: w.service.keys, name: 'Example Stationery (invented)' }); // the wrong kind
  await w.vouch({ kind: 'service', keys: w.service.keys, name: 'Example Stationery (invented)' }, { validFrom: '2025-01-01T00:00:00Z', validUntil: '2026-01-01T00:00:00Z' }); // run out
  w.entries.push(slip);
  const r = await checkBook(w.book(), { vouchers: [await keySetFingerprint(w.organisation.keys)] });
  assert.deepEqual(codes(r), []);
  assert.deepEqual(r.entries[4].vouched, { issuer: null, agent: null, services: { supplier: null } });
});

test('a vouching record that is not signed by the keys it gives vouches for nothing', async () => {
  const w = await makeWorld();
  const slip = w.entries.pop();
  const forger = await generateKeySet();
  w.organisation = await generateKeySet();
  await w.vouch({ kind: 'person', key: w.passkey.key, name: 'Sam Example' }, { privateKeys: forger.privateKeys });
  w.entries.push(slip);
  const r = await checkBook(w.book(), { vouchers: [await keySetFingerprint(w.organisation.keys)] });
  assert.ok(codes(r).includes('signature-invalid'));
  assert.equal(r.entries[1].vouched.issuer, null);
});

test('after a withdrawal, the vouching record vouches for nothing; only the organisation that vouched can withdraw', async () => {
  const w = await makeWorld();
  const slip = w.entries.pop();
  const person = await w.vouch({ kind: 'person', key: w.passkey.key, name: 'Sam Example' });
  const trust = { vouchers: [await keySetFingerprint(w.organisation.keys)] };

  // A stranger's withdrawal changes nothing.
  const stranger = await generateKeySet();
  await w.withdraw(person.fingerprint, { privateKeys: stranger.privateKeys });
  w.entries.push(slip);
  const refused = await checkBook(w.book(), trust);
  assert.ok(codes(refused).includes('signature-invalid'));
  assert.equal(refused.entries[2].vouched.issuer.counted, true);

  // The organisation's own withdrawal ends it, from that place in the book on.
  w.entries.splice(1, 2);
  await w.withdraw(person.fingerprint);
  w.entries.push(slip);
  const r = await checkBook(w.book(), trust);
  assert.deepEqual(codes(r), []);
  assert.equal(r.entries[1].kind, 'withdrawal');
  assert.equal(r.entries[2].vouched.issuer, null);
});

test('a recorder that a trusted organisation vouched for is shown so on its seal', async () => {
  const w = await makeWorld();
  await w.add();
  // A first seal makes the recorder's keys; it is set aside, and the book
  // is sealed again once the vouching record is in it.
  await w.seal();
  w.entries.pop();
  w.lastSeal = undefined;
  await w.vouch({ kind: 'recorder', keys: w.recorder.keys, name: 'Example recorder (invented)' });
  await w.seal();
  const r = await checkBook(w.book(), { vouchers: [await keySetFingerprint(w.organisation.keys)], stampServices: [w.stampService.fingerprint] });
  assert.deepEqual(codes(r), []);
  assert.equal(r.entries[3].vouched.counted, true);
  assert.deepEqual(r.entries[3].notes, []);
});

test('records about standing that are not as the format says are refused, not crashed on', async () => {
  const w = await makeWorld();
  const v = await w.vouch({ kind: 'agent', keys: w.agent.keys, name: 'Office supplies agent' });
  const bad = [
    (c) => void (c.for.kind = 'everyone'),
    (c) => void (c.for.kind = 'toString'),
    (c) => void (c.for = 'nobody'),
    (c) => void (c.for.key = c.for.keys[0]),
    (c) => void (c.for.keys = c.for.keys.slice(0, 1)),
    (c) => void (c.for.kind = 'recorder'),
    (c) => void (c.for.kind = 'person'),
    (c) => void (c.validUntil = c.validFrom),
    (c) => void (c.extra = 1),
    (c) => void delete c.by,
  ];
  for (const [i, change] of bad.entries()) {
    w.entries[1] = { vouching: withContent(v.record, change) };
    const r = await checkBook(w.book());
    assert.equal(r.summary.problemFound, true, `case ${i}`);
    assert.ok(codes(r).some((c) => c === 'bad-field' || c === 'bad-key'), `case ${i}: ${codes(r)}`);
  }
});

// --- the agent's software ---

test('a slip may state the fingerprints of the agent\'s software; it is a statement, and is checked only for its form', async () => {
  const software = [
    { name: 'The agent program, version 3', sha256: 'A'.repeat(43) },
    { name: 'Its settings', sha256: 'B'.repeat(42) + 'A' },
  ];
  const base = await makeWorld();
  const withSoftware = await makeWorld({ fields: { agent: { ...base.fields.agent, software } } });
  // The agent's keys in this world are not the ones in the slip, so only the slip is checked here.
  const r = await checkBook(withSoftware.book());
  assert.deepEqual(codes(r), []);
  assert.deepEqual(r.entries[0].content.agent.software, software);
  for (const wrong of [[], 'program', [{ name: 'x' }], [{ name: 'x', sha256: 'short' }], [{ name: 'x', sha256: 'A'.repeat(43), extra: 1 }], Array(17).fill(software[0])]) {
    await assert.rejects(prepareSlip({ ...base.fields, agent: { ...base.fields.agent, software: wrong } }), (e) => e.code === 'bad-field');
  }
});
