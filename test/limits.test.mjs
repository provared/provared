// The framework of limits: amounts, boundaries, approvals, stated
// prohibitions, the other side's records, and the check before acting.
// Every case goes through the public interface.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  ACTION_KINDS,
  CONDUCT_RULES,
  SHARED_ACTIONS,
  actionKind,
  checkBefore,
  checkBook,
  checkShow,
  generateKeySet,
  keySetFingerprint,
  limitWords,
  makeShow,
  prepareSlip,
  thumbprint,
} from '../src/index.js';
import { START, makeWorld, withContent } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const ORDER = 'supplies.order';

function codes(result) {
  const out = result.problems.map((p) => p.code);
  for (const e of result.entries) out.push(...e.problems.map((p) => p.code), ...e.breaches.map((b) => b.code));
  return out;
}

/** A world whose slip has these limits, conditions and prohibitions. */
const worldWith = (fields) => makeWorld({ fields });

// --- the slip: what may be written ---

test('a slip may carry every kind of limit, condition and prohibition together', async () => {
  const w = await worldWith({
    actions: [ORDER, 'provared.message.send'],
    limits: [
      { action: ORDER, max: 200, unit: 'GBP' },
      { action: ORDER, each: 100, unit: 'GBP' },
      { action: ORDER, max: 150, per: 86400, unit: 'GBP' },
      { action: ORDER, count: 10 },
      { action: ORDER, count: 3, per: 3600 },
      { action: 'provared.message.send', count: 5 },
    ],
    requires: [{ need: 'countersignature' }, { above: 80, action: ORDER, need: 'approval', unit: 'GBP' }],
    never: ['destroys', 'grants', 'impersonate', 'bypass'],
  });
  await w.add({ value: 40 });
  const r = await checkBook(w.book());
  assert.deepEqual(codes(r), []);
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.withinSlips, true);
});

test('a limit, a condition or a prohibition that is not exactly as the format says is refused', async () => {
  const w = await makeWorld();
  const bad = [
    { limits: [{ action: ORDER }] }, // no kind
    { limits: [{ action: ORDER, each: 5, max: 10, unit: 'GBP' }] }, // two kinds
    { limits: [{ action: ORDER, max: 10 }] }, // no unit
    { limits: [{ action: ORDER, count: 2, unit: 'GBP' }] }, // a count has no unit
    { limits: [{ action: ORDER, count: 0 }] },
    { limits: [{ action: ORDER, each: 5, per: 60, unit: 'GBP' }] }, // each has no period
    { limits: [{ action: ORDER, max: 5, per: 0, unit: 'GBP' }] },
    { limits: [{ action: ORDER, max: 5, per: 366 * 86400 + 1, unit: 'GBP' }] },
    { limits: [{ action: ORDER, max: 5, unit: 'GBP' }, { action: ORDER, max: 6, unit: 'GBP' }] }, // the same kind twice
    { limits: [{ action: ORDER, max: 5, unit: 'GBP' }, { action: ORDER, each: 6, unit: 'items' }] }, // two units
    { limits: [{ action: 'other.action', count: 1 }] }, // not one of the slip's actions
    { limits: [{ action: ORDER, max: 5, unit: 'GBP', extra: 1 }] },
    { limits: [{ action: ORDER, max: 1.5, unit: 'GBP' }] },
    { requires: [{ need: 'luck' }] },
    { requires: [{ action: 'other.action', need: 'approval' }] },
    { requires: [{ above: 5, action: ORDER, need: 'approval' }] }, // above without unit
    { requires: [{ above: 5, need: 'approval', unit: 'GBP' }] }, // above without action
    { requires: [{ above: 5, action: ORDER, need: 'approval', unit: 'items' }] }, // not the limit's unit
    { requires: [{ need: 'approval' }, { need: 'approval' }] },
    { requires: 'approval' },
    { never: ['everything'] },
    { never: ['toString'] },
    { never: ['bypass', 'bypass'] },
    { never: [42] },
    { never: 'bypass' },
    { actions: [ORDER, 'provared.not.on-the-list'] }, // a reserved name that is not listed
    { actions: [ORDER, 'provared.data.delete'], never: ['destroys'] }, // allows what it forbids
  ];
  for (const change of bad) {
    await assert.rejects(prepareSlip({ ...w.fields, ...change }), (e) => e.code === 'bad-field', JSON.stringify(change));
  }
});

test('a slip written before the new members were added, without "requires" and "never", is refused by the checker', async () => {
  const w = await makeWorld();
  await w.add();
  const old = withContent(w.slip, (c) => {
    delete c.requires;
    delete c.never;
  });
  w.entries[0] = { slip: old };
  assert.ok(codes(await checkBook(w.book())).includes('bad-field'));
});

// --- layer 1: amounts ---

test('a limit on each action is passed only by an action above it', async () => {
  const w = await worldWith({ limits: [{ action: ORDER, each: 50, unit: 'GBP' }] });
  await w.add({ value: 50 });
  await w.add({ value: 50 });
  await w.add({ value: 50 });
  assert.equal((await checkBook(w.book())).summary.withinSlips, true);
});

test('a period slides: what is older than the period no longer counts', async () => {
  // No more than 100 in any two hours.
  const w = await worldWith({ limits: [{ action: ORDER, max: 100, per: 7200, unit: 'GBP' }] });
  await w.add({ value: 60, when: START });
  // Exactly two hours later the first is outside the period.
  await w.add({ value: 60, when: START + 2 * HOUR });
  // One second before that, it would still have counted.
  await w.add({ value: 41, when: START + 4 * HOUR - 1000 });
  const r = await checkBook(w.book());
  assert.deepEqual(r.entries.map((e) => e.breaches.map((b) => b.code)), [[], [], [], ['over-period-limit']]);
  assert.match(r.entries[3].breaches[0].message, /the total in any 2 hours is 101 GBP/);
});

test('a count in a period counts actions, whatever their amounts', async () => {
  const w = await worldWith({ limits: [{ action: ORDER, count: 2, per: 3600 }] });
  await w.add({ when: START, amount: undefined });
  await w.add({ when: START + 1000, amount: undefined });
  await w.add({ when: START + 2000, amount: undefined });
  await w.add({ when: START + HOUR + 1000, amount: undefined });
  const r = await checkBook(w.book());
  assert.deepEqual(r.entries.map((e) => e.breaches.map((b) => b.code)), [[], [], [], ['over-period-limit'], []]);
});

test('several limits on one action are each reported', async () => {
  const w = await worldWith({
    limits: [
      { action: ORDER, max: 100, unit: 'GBP' },
      { action: ORDER, each: 80, unit: 'GBP' },
      { action: ORDER, count: 1 },
    ],
  });
  await w.add({ value: 30 });
  await w.add({ value: 90 });
  const r = await checkBook(w.book());
  assert.deepEqual(r.entries[2].breaches.map((b) => b.code).sort(), ['over-count-limit', 'over-each-limit', 'over-limit']);
  assert.deepEqual(r.entries[2].running, { action: ORDER, unit: 'GBP', total: '120', max: 100 });
});

test('a stub with no amount, where a limit needs one, is reported once', async () => {
  const w = await worldWith({
    limits: [
      { action: ORDER, max: 100, unit: 'GBP' },
      { action: ORDER, each: 80, unit: 'GBP' },
    ],
    requires: [{ above: 50, action: ORDER, need: 'approval', unit: 'GBP' }],
  });
  await w.add({ amount: undefined });
  assert.deepEqual(codes(await checkBook(w.book())), ['amount-missing']);
});

test('limits are described in words', () => {
  assert.equal(limitWords({ action: 'a', max: 5, unit: 'GBP' }), 'a: no more than 5 GBP in total');
  assert.equal(limitWords({ action: 'a', each: 5, unit: 'GBP' }), 'a: no single action above 5 GBP');
  assert.equal(limitWords({ action: 'a', max: 5, per: 86400, unit: 'GBP' }), 'a: no more than 5 GBP in any 24 hours');
  assert.equal(limitWords({ action: 'a', count: 1, per: 3600 }), 'a: no more than 1 action in any hour');
  assert.equal(limitWords({ action: 'a', count: 3, per: 604800 }), 'a: no more than 3 actions in any 7 days');
  assert.equal(limitWords({ action: 'a', count: 3, per: 90 }), 'a: no more than 3 actions in any 90 seconds');
});

// --- layer 2: boundaries ---

test('where the slip asks for a countersignature, a countersigned stub is within it', async () => {
  const w = await worldWith({ requires: [{ action: ORDER, need: 'countersignature' }] });
  await w.add();
  const r = await checkBook(w.book());
  assert.equal(r.summary.withinSlips, true);
  assert.deepEqual(r.entries[1].needs, ['countersignature']);
});

test('a condition above an amount applies only above it', async () => {
  const w = await worldWith({ requires: [{ above: 50, action: ORDER, need: 'countersignature', unit: 'GBP' }] });
  await w.add({ value: 50, countersigned: false });
  await w.add({ value: 51, countersigned: false });
  const r = await checkBook(w.book());
  assert.deepEqual(r.entries.map((e) => e.breaches.map((b) => b.code)), [[], [], ['countersignature-missing']]);
});

// --- layer 3: approvals ---

test('an action the person approved with the passkey is within a slip that asks for approval', async () => {
  const w = await worldWith({ requires: [{ above: 50, action: ORDER, need: 'approval', unit: 'GBP' }] });
  await w.add({ value: 60, approve: true, details: [{ name: 'Order 1', sha256: 'A'.repeat(43) }] });
  const r = await checkBook(w.book());
  assert.deepEqual(codes(r), []);
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.withinSlips, true);
  assert.equal(r.entries[1].approval.state, 'valid');
  assert.equal(r.summary.counts.approved, 1);
});

test('an approval is for exactly one action: any difference is refused', async () => {
  for (const difference of [
    { amount: { unit: 'GBP', value: 61 } },
    { amount: undefined },
    { with: undefined },
    { action: 'supplies.return' },
    { details: [{ name: 'Another order', sha256: 'A'.repeat(43) }] },
  ]) {
    const w = await makeWorld();
    await w.add({ value: 60, approve: difference });
    assert.ok(codes(await checkBook(w.book())).includes('approval-mismatch'), JSON.stringify(difference));
  }
});

test('an approval given under another slip does not count', async () => {
  const w = await makeWorld();
  const other = await makeWorld();
  await w.add({ approve: { slip: other.slipFingerprint } });
  assert.ok(codes(await checkBook(w.book())).includes('approval-mismatch'));
});

test('an approval signed by another passkey, or changed after signing, is refused', async () => {
  const w = await makeWorld();
  const other = await makeWorld();
  const request = { slip: w.slipFingerprint, action: ORDER, amount: { unit: 'GBP', value: 10 }, with: 'supplier' };
  const forged = await other.approve(request);
  const stub = await w.add({ approval: forged.fingerprint });
  stub.entry.approval = forged.record;
  assert.ok(codes(await checkBook(w.book())).includes('approval-invalid'));

  const w2 = await makeWorld();
  await w2.add({
    approve: {
      assertion: {
        signature: (s) => {
          const changed = s.slice();
          changed[changed.length - 1] ^= 1;
          return changed;
        },
      },
    },
  });
  assert.ok(codes(await checkBook(w2.book())).includes('approval-invalid'));
});

test('an approval with a stub that does not name it is refused', async () => {
  const w = await makeWorld();
  const stub = await w.add();
  const a = await w.approve({ slip: w.slipFingerprint, action: ORDER, amount: { unit: 'GBP', value: 10 }, with: 'supplier' });
  stub.entry.approval = a.record;
  assert.ok(codes(await checkBook(w.book())).includes('approval-mismatch'));
});

test('a slip cannot stand in for an approval, nor an approval for a slip', async () => {
  const w = await makeWorld();
  const stub = await w.add({ approval: w.slipFingerprint });
  stub.entry.approval = w.slip;
  assert.ok(codes(await checkBook(w.book())).includes('payload-type-mismatch'));

  const w2 = await makeWorld();
  const a = await w2.approve({ slip: w2.slipFingerprint, action: ORDER });
  w2.entries[0] = { slip: a.record };
  assert.ok(codes(await checkBook(w2.book())).includes('payload-type-mismatch'));
});

test('where this device lacks the passkey method, an approval is not confirmed and nothing passes', async () => {
  const w = await worldWith({ requires: [{ need: 'approval' }] });
  await w.add({ approve: true });
  const r = await checkBook(w.book(), { withoutMethods: ['ES256'] });
  assert.equal(r.summary.intact, false);
  assert.equal(r.summary.withinSlips, false);
  assert.deepEqual(r.summary.methodsMissing, ['ES256']);
});

// --- layer 4: stated prohibitions, and the shared list ---

test('every shared action has a listed kind, and every name on the lists has the right form', () => {
  for (const [name, [kind, meaning]] of Object.entries(SHARED_ACTIONS)) {
    assert.match(name, /^provared\.[a-z]+\.[a-z-]+$/);
    assert.ok(Object.hasOwn(ACTION_KINDS, kind), name);
    assert.ok(meaning.length > 5);
    assert.equal(actionKind(name), kind);
  }
  assert.equal(actionKind('supplies.order'), null);
  assert.equal(actionKind('toString'), null);
  for (const name of Object.keys(CONDUCT_RULES)) assert.ok(!Object.hasOwn(ACTION_KINDS, name));
  // A "never" list is at most 16 names: every kind and every rule.
  assert.equal(Object.keys(ACTION_KINDS).length + Object.keys(CONDUCT_RULES).length, 16);
});

test('a stub cannot use a reserved name that is not on the shared list', async () => {
  const w = await makeWorld();
  await assert.rejects(w.add({ action: 'provared.not.on-the-list' }), (e) => e.code === 'bad-field');
});

test('a shared action that the slip allows is within it', async () => {
  const w = await worldWith({ actions: ['provared.message.send'], limits: [], never: ['destroys', 'deceive'] });
  await w.add({ action: 'provared.message.send', amount: undefined });
  assert.equal((await checkBook(w.book())).summary.withinSlips, true);
});

// --- layer 5: the other side's records ---

test('a refusal from a service the slip names is shown as that service\'s statement', async () => {
  const w = await makeWorld();
  await w.add();
  await w.refuse({ amount: { unit: 'GBP', value: 500 } });
  const r = await checkBook(w.book());
  assert.deepEqual(codes(r), []);
  assert.equal(r.summary.intact, true);
  // A refusal is what the service's side said. It is not a finding about the agent.
  assert.equal(r.summary.withinSlips, true);
  assert.equal(r.summary.counts.refusals, 1);
  assert.equal(r.entries[2].kind, 'refusal');
  assert.equal(r.entries[2].service, 'supplier');
  assert.equal(r.entries[2].content.reason, 'over-limit');
});

test('a refusal from someone the slip does not name says so', async () => {
  const w = await makeWorld();
  await w.refuse({ signer: await generateKeySet(), reason: 'not-in-slip', action: 'provared.account.sign-in' });
  const r = await checkBook(w.book());
  assert.deepEqual(codes(r), []);
  assert.equal(r.entries[1].service, null);
});

test('a refusal that is not signed with the keys it gives, or names no slip in the book, is refused', async () => {
  const w = await makeWorld();
  const other = await generateKeySet();
  await w.refuse({ privateKeys: other.privateKeys });
  assert.ok(codes(await checkBook(w.book())).includes('signature-invalid'));

  const w2 = await makeWorld();
  await w2.refuse({ slip: 'A'.repeat(43) });
  assert.ok(codes(await checkBook(w2.book())).includes('slip-missing'));

  const w3 = await makeWorld();
  const refusal = await w3.refuse();
  w3.entries[1] = { refusal: withContent(refusal.record, (c) => void (c.reason = 'because')) };
  assert.ok(codes(await checkBook(w3.book())).includes('bad-field'));
});

test('a stub within the service\'s terms for agents is within its slip', async () => {
  const w = await makeWorld();
  const terms = await w.publishTerms({ never: ['impersonate'] });
  await w.add({ terms: terms.fingerprint });
  const r = await checkBook(w.book());
  assert.deepEqual(codes(r), []);
  assert.equal(r.summary.withinSlips, true);
  assert.equal(r.summary.counts.terms, 1);
  assert.equal(r.entries[1].kind, 'terms');
});

test('an action dated outside the time the terms were in force is reported', async () => {
  const w = await makeWorld();
  const terms = await w.publishTerms({ validFrom: '2026-01-01T00:00:00Z', validUntil: '2026-10-05T09:00:00Z' });
  await w.add({ terms: terms.fingerprint, when: START });
  assert.deepEqual(codes(await checkBook(w.book())), ['outside-terms']);
});

test('one line may hold a stub with its approval and its countersignature', async () => {
  const w = await worldWith({ requires: [{ need: 'approval' }, { need: 'countersignature' }] });
  const stub = await w.add({ approve: true });
  assert.deepEqual(Object.keys(stub.entry).sort(), ['approval', 'countersignature', 'stub']);
  const r = await checkBook(w.book());
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.withinSlips, true);
  assert.deepEqual(r.entries[1].needs, ['approval', 'countersignature']);
});

// --- a Show ---

test('a Show can show an action above the limit for one action, and a missing approval', async () => {
  const w = await worldWith({
    limits: [
      { action: ORDER, each: 50, unit: 'GBP' },
      { action: ORDER, count: 1 },
    ],
    requires: [{ need: 'approval' }],
  });
  await w.add({ value: 10, approve: true });
  await w.add({ value: 60 });
  const r = await checkShow(await makeShow(w.book(), [0, 2]));
  // One page cannot show a count: that needs every stub under the slip.
  assert.deepEqual(r.entries[1].breaches.map((b) => b.code).sort(), ['approval-missing', 'over-each-limit']);
});

// --- the check before acting ---

/** What the check before acting must be told: whose passkey it trusts. */
const trusting = async (w) => ({ issuerKeys: [await thumbprint(w.passkey.key)] });

test('the check before acting allows what is inside the slip', async () => {
  const w = await makeWorld();
  await w.add({ value: 100 });
  const trust = await trusting(w);
  const ask = (value) => checkBefore(w.book(), { slip: w.slipFingerprint, action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier', when: START + HOUR }, trust);
  assert.deepEqual(await ask(100), { allowed: true, problems: [], breaches: [], needs: [] });
  const over = await ask(101);
  assert.equal(over.allowed, false);
  assert.deepEqual(over.breaches.map((b) => b.code), ['over-limit']);
});

test('where the slip asks for approval, the check allows the action only with a signed approval of exactly that action', async () => {
  const w = await worldWith({ requires: [{ above: 50, action: ORDER, need: 'approval', unit: 'GBP' }, { need: 'countersignature' }] });
  await w.add({ value: 10 });
  const trust = await trusting(w);
  const request = { slip: w.slipFingerprint, action: ORDER, amount: { unit: 'GBP', value: 60 }, with: 'supplier', when: START + HOUR };

  const without = await checkBefore(w.book(), request, trust);
  assert.equal(without.allowed, false);
  assert.deepEqual(without.breaches.map((b) => b.code), ['approval-missing']);
  assert.deepEqual(without.needs, ['approval', 'countersignature']);

  const approval = await w.approve({ ...request, when: START + HOUR - 60000 });
  const withIt = await checkBefore(w.book(), { ...request, approval: approval.record }, trust);
  // A countersignature cannot be known beforehand: the answer says it is needed.
  assert.deepEqual(withIt, { allowed: true, problems: [], breaches: [], needs: ['approval', 'countersignature'] });

  // An approval of another amount, from another passkey, or dated after the action, allows nothing.
  const other = await w.approve({ ...request, amount: { unit: 'GBP', value: 61 } });
  assert.deepEqual((await checkBefore(w.book(), { ...request, approval: other.record }, trust)).problems.map((p) => p.code), ['approval-mismatch']);
  const stranger = await (await makeWorld()).approve(request);
  assert.deepEqual((await checkBefore(w.book(), { ...request, approval: stranger.record }, trust)).problems.map((p) => p.code), ['approval-invalid']);
  const late = await w.approve({ ...request, when: START + 2 * HOUR });
  assert.deepEqual((await checkBefore(w.book(), { ...request, approval: late.record }, trust)).problems.map((p) => p.code), ['approval-dated-after-stub']);

  // An approval that the book has already used allows nothing.
  await w.add({ value: 60, approve: true, when: START + HOUR });
  const used = w.entries.at(-1).approval;
  const again = await checkBefore(w.book(), { ...request, when: START + 2 * HOUR, approval: used }, trust);
  assert.equal(again.allowed, false);
  assert.deepEqual(again.problems.map((p) => p.code), ['approval-reused']);
});

test('the check before acting changes nothing, and refuses exactly what the checker would report', async () => {
  const w = await worldWith({
    limits: [
      { action: ORDER, max: 100, unit: 'GBP' },
      { action: ORDER, count: 2, per: 7200 },
    ],
  });
  await w.add({ value: 60 });
  const trust = await trusting(w);
  const proposals = [
    { value: 41, with: 'supplier', action: ORDER },
    { value: 10, with: 'someone-else', action: ORDER },
    { value: 10, with: 'supplier', action: 'supplies.sell' },
    { value: 10, with: 'supplier', action: ORDER, when: Date.parse('2027-01-01T00:00:00Z') },
  ];
  for (const p of proposals) {
    const when = p.when ?? START + HOUR;
    const proposal = { slip: w.slipFingerprint, action: p.action, amount: { unit: 'GBP', value: p.value }, with: p.with, when };
    const before = await checkBefore(w.book(), proposal, trust);
    const again = await checkBefore(w.book(), proposal, trust);
    assert.deepEqual(before, again);
    assert.equal(before.allowed, false);
    // Now the agent acts anyway, and the checker reports.
    const entries = [...w.entries];
    await w.add({ action: p.action, value: p.value, with: p.with, when, countersigned: p.with === 'supplier' });
    const after = await checkBook(w.book());
    assert.deepEqual(
      after.entries.at(-1).breaches.map((b) => b.code),
      before.breaches.map((b) => b.code),
      JSON.stringify(p),
    );
    // Put the world back as it was, for the next proposal.
    w.entries = entries;
    w.after = { seq: 0, fingerprint: after.entries[1].fingerprint };
    w.count = 1;
  }
});

test('the check before acting refuses an action dated before the last stub, as the checker would', async () => {
  // Found by the second independent review: the check allowed it, and the
  // stub then broke the book for every later check.
  const w = await makeWorld();
  await w.add({ when: START + HOUR });
  const trust = await trusting(w);
  const proposal = { slip: w.slipFingerprint, action: ORDER, amount: { unit: 'GBP', value: 1 }, with: 'supplier', when: START };
  const before = await checkBefore(w.book(), proposal, trust);
  assert.equal(before.allowed, false);
  assert.deepEqual(before.problems.map((p) => p.code), ['time-went-backwards']);
  await w.add({ value: 1, when: START });
  assert.ok(codes(await checkBook(w.book())).includes('time-went-backwards'));
});

test('the check before acting allows nothing when the record so far is not sound, or was only partly checked', async () => {
  const w = await makeWorld();
  await w.add();
  const trust = await trusting(w);
  const proposal = { slip: w.slipFingerprint, action: ORDER, amount: { unit: 'GBP', value: 1 }, with: 'supplier', when: START + HOUR };
  const damaged = w.book().replace(/\n$/, '') + 'x\n';
  for (const [book, options] of [
    [damaged, trust],
    [w.book(), { ...trust, withoutMethods: ['Ed25519', 'ML-DSA-87'] }],
    // Found by the second review: with one method of two missing, the check allowed the action.
    [w.book(), { ...trust, withoutMethods: ['ML-DSA-87'] }],
    [w.book(), { ...trust, withoutMethods: ['Ed25519'] }],
    [w.book(), { ...trust, withoutMethods: ['ES256'] }],
    ['', trust],
  ]) {
    const answer = await checkBefore(book, proposal, options);
    assert.equal(answer.allowed, false);
    assert.deepEqual(answer.problems.map((p) => p.code), ['record-not-sound']);
  }
  assert.deepEqual((await checkBefore(w.book(), { ...proposal, slip: 'A'.repeat(43) }, trust)).problems.map((p) => p.code), ['slip-missing']);
  for (const hostile of [null, 42, { slip: w.slipFingerprint }, { ...proposal, extra: 1 }, { ...proposal, action: { toString: 0 } }, { ...proposal, when: 'yesterday' }, { ...proposal, approval: 'yes' }]) {
    const answer = await checkBefore(w.book(), hostile, trust);
    assert.equal(answer.allowed, false);
    assert.equal(answer.problems.length, 1);
  }
});

test('the check before acting must be told whose passkey it trusts: a slip from any other key allows nothing', async () => {
  // Found by the second review: a slip made with any key and added to the
  // book was enough for "allowed".
  const w = await makeWorld();
  const intruder = await makeWorld({ fields: { actions: ['provared.data.delete'], limits: [] } });
  const book = w.book() + intruder.book();
  const proposal = { slip: intruder.slipFingerprint, action: 'provared.data.delete', when: START };
  for (const options of [undefined, {}, { issuerKeys: [] }, { issuerKeys: 'any' }, null]) {
    const answer = await checkBefore(book, proposal, options);
    assert.equal(answer.allowed, false);
    assert.deepEqual(answer.problems.map((p) => p.code), ['record-not-sound']);
  }
  const answer = await checkBefore(book, proposal, await trusting(w));
  assert.equal(answer.allowed, false);
  assert.deepEqual(answer.problems.map((p) => p.code), ['record-not-sound']);
});

test('the check before acting takes the service\'s terms into account', async () => {
  const w = await makeWorld();
  const terms = await w.publishTerms({ accepts: ['supplies.return'] });
  const trust = await trusting(w);
  const answer = await checkBefore(w.book(), { slip: w.slipFingerprint, action: ORDER, amount: { unit: 'GBP', value: 1 }, with: 'supplier', terms: terms.fingerprint, when: START }, trust);
  assert.deepEqual(answer.breaches.map((b) => b.code), ['outside-terms']);
  const unknown = await checkBefore(w.book(), { slip: w.slipFingerprint, action: ORDER, with: 'supplier', terms: 'A'.repeat(43), when: START }, trust);
  assert.deepEqual(unknown.problems.map((p) => p.code), ['terms-not-found']);
});

// --- what the second independent review found (3 October 2026) ---

test('a Show cannot show that an approval was used twice, and says so', async () => {
  const w = await makeWorld();
  const first = await w.add({ approve: true });
  const name = JSON.parse(Buffer.from(first.entry.stub.payload, 'base64url').toString()).approval;
  const second = await w.add({ approval: name });
  second.entry.approval = first.entry.approval;
  assert.ok(codes(await checkBook(w.book())).includes('approval-reused'));
  const r = await checkShow(await makeShow(w.book(), [0, 2]));
  assert.ok(r.notes.some((n) => /whether an approval was used only once/.test(n)));
});

test('an approval whose number is the number of another record is a repeated number, not a reused approval', async () => {
  const w = await makeWorld();
  const id = 'AAAAAAAAAAAAAAAAAAAAAA';
  await w.add({ id, approve: { id } });
  assert.deepEqual(codes(await checkBook(w.book())), ['duplicate-id']);
});

test('an approval dated later than the stub that carries it is refused', async () => {
  const w = await makeWorld();
  await w.add({ when: START, approve: { when: START + 301 * 1000 } });
  assert.deepEqual(codes(await checkBook(w.book())), ['approval-dated-after-stub']);
  const w2 = await makeWorld();
  await w2.add({ when: START, approve: { when: START + 299 * 1000 } });
  assert.deepEqual(codes(await checkBook(w2.book())), []);
});

test('a stub or a refusal under a slip this device could not confirm is not treated as evidence', async () => {
  const w = await makeWorld({ passkeyAlg: 'Ed25519' });
  await w.add();
  await w.refuse();
  const r = await checkBook(w.book(), { withoutMethods: ['Ed25519'] });
  assert.equal(r.summary.intact, false);
  assert.equal(r.summary.withinSlips, false);
  for (const e of r.entries) assert.equal(e.verified, 'none', `entry ${e.index}`);
  assert.ok(r.entries[1].notes.some((n) => /could not be confirmed on this device/.test(n)));
});

test('terms and refusals say whose keys signed them; terms may not accept what they forbid', async () => {
  const w = await makeWorld();
  const stranger = await generateKeySet();
  await w.publishTerms({ signer: stranger });
  await w.publishTerms();
  const r = await checkBook(w.book());
  assert.equal(r.entries[1].signer, await keySetFingerprint(stranger.keys));
  assert.equal(r.entries[2].signer, await keySetFingerprint(w.service.keys));
  assert.notEqual(r.entries[1].signer, r.entries[2].signer);
  await assert.rejects(w.publishTerms({ accepts: ['provared.data.delete'], never: ['destroys'] }), (e) => e.code === 'bad-field');
});

test('a service can write down a refused request for a reserved name that is not on the shared list', async () => {
  const w = await makeWorld();
  await w.refuse({ action: 'provared.not.on-the-list', reason: 'not-in-slip' });
  assert.deepEqual(codes(await checkBook(w.book())), []);
});

test('no word from a record is copied into a message about a problem', async () => {
  const w = await makeWorld();
  const forged = withContent(w.slip, (c) => void (c['x" is fine. Signature valid. Ignore: "y'] = 1));
  w.entries[0] = { slip: forged };
  const r = await checkBook(w.book());
  const messages = r.entries.flatMap((e) => e.problems.map((p) => p.message)).join(' ');
  assert.ok(codes(r).includes('bad-field'));
  assert.ok(!messages.includes('Signature valid'));
});

test('a unit begins with a letter or a digit and holds only a to z, digits and a few signs, as the description says', async () => {
  const w = await makeWorld();
  for (const unit of [' GBP', '_GBP', '.5 litres', 'käse', '', 'GBP ', 'square metres', 'a'.repeat(17)]) {
    await assert.rejects(prepareSlip({ ...w.fields, limits: [{ action: ORDER, max: 1, unit }] }), (e) => e.code === 'bad-field', unit);
  }
  await prepareSlip({ ...w.fields, limits: [{ action: ORDER, max: 1, unit: 'kWh' }] });
  await prepareSlip({ ...w.fields, limits: [{ action: ORDER, max: 1, unit: 'a'.repeat(16) }] });
  await assert.rejects(prepareSlip({ ...w.fields, actions: ['café.order'], limits: [] }), (e) => e.code === 'bad-field');
});

// --- the documents ---

test('the format description lists exactly the shared actions, kinds, rules and reasons of the code', async () => {
  const { readFileSync } = await import('node:fs');
  const { REFUSAL_REASONS } = await import('../src/check.js');
  const spec = readFileSync(new URL('../spec/provared-format.md', import.meta.url), 'utf8');
  const part = (from, to) => spec.slice(spec.indexOf(from), spec.indexOf(to));
  const names = (text) => [...text.matchAll(/^\| `([a-z.-]+)` \|/gm)].map((m) => m[1]);
  const sixteen = part('## 16.', '## 17.');
  assert.deepEqual(names(sixteen), [...Object.keys(ACTION_KINDS), ...Object.keys(SHARED_ACTIONS), ...Object.keys(CONDUCT_RULES)]);
  for (const [name, [kind, meaning]] of Object.entries(SHARED_ACTIONS)) {
    assert.ok(sixteen.includes(`| \`${name}\` | \`${kind}\` | ${meaning} |`), name);
  }
  assert.deepEqual(names(part('| Reason | Meaning |', '## 19.')), Object.keys(REFUSAL_REASONS));
});
