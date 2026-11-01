// The judgement of AMW receipts against a Provared slip: records of this
// reader's own, in AMW's shape (amw-world.mjs), and the published vectors.

import './local-library.mjs';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const { argumentsFingerprint, checkBook } = await import('provared');
const { developmentRecorder, developmentSlip } = await import('provared/dev');
const { CANNOT_SHOW, DOCUMENT_NAME, judgeReceipts, parseAmwTime, readCredits, receiptDocument } = await import('../judge.mjs');
const { makeGateway, permit, receipt } = await import('./amw-world.mjs');

const read = (name) => JSON.parse(readFileSync(new URL(`vectors/${name}`, import.meta.url), 'utf8'));
const CREDITS = { unit: 'credits', decimals: 2 };
const SERVICE = { id: 'amw', name: 'The AMW gateway' };
const DAY = { validFrom: '2026-09-14T00:00:00Z', validUntil: '2026-09-15T00:00:00Z' };

async function slipWith(fields) {
  return developmentSlip({ actions: ['echo'], with: [SERVICE], ...DAY, ...fields });
}

async function judge(made, gateway, receipts, more = {}) {
  return judgeReceipts({ slip: made.slip, issuerKeys: made.issuerKeys, keys: gateway.keys, receipts, service: 'amw', credits: CREDITS, ...more });
}

const codes = (item) => item.findings.map((f) => f.code);
const at = (time) => `2026-09-14T${time}+00:00`;

test('receipts within the slip: judged, compared, within it, with what cannot be shown stated', async () => {
  const gw = makeGateway();
  const made = await slipWith({ limits: [{ action: 'echo', max: 1000, unit: 'credits' }] });
  const r = await judge(made, gw, [receipt(gw), receipt(gw, { created_at: at('17:05:00') }), receipt(gw, { created_at: at('17:10:00') })]);
  assert.deepEqual(r.problems, []);
  assert.equal(r.judged, true);
  assert.equal(r.service, 'amw');
  assert.equal(r.slip.fingerprint, made.slipFingerprint);
  assert.deepEqual(r.summary, { handed: 3, byStatus: { verified: 3 }, compared: 3, denied: 0, duplicates: 0, notCompared: 0, notJudged: 0, withinSlip: true, withinPermits: null, trusted: true });
  for (const item of r.receipts) {
    assert.equal(item.status, 'verified');
    assert.equal(item.compared, true);
    assert.equal(item.kind, 'action');
    assert.equal(item.action, 'echo');
    assert.deepEqual(item.amount, { unit: 'credits', value: '250' });
    assert.deepEqual(item.findings, []);
    assert.deepEqual(item.permitFindings, []);
    assert.equal(item.permit, 'pmt_test_0001');
  }
  assert.equal(r.receipts[1].when, '2026-09-14T17:05:00.000Z');
  assert.deepEqual(r.notJudged, []);
  assert.deepEqual(r.cannotShow, [...CANNOT_SHOW]);
  assert.equal(CANNOT_SHOW.length, 10);
  assert.ok(Object.isFrozen(CANNOT_SHOW));
  assert.ok(CANNOT_SHOW.some((s) => /No chain/.test(s)) && CANNOT_SHOW.some((s) => /No countersignature/.test(s)));
  assert.ok(CANNOT_SHOW.some((s) => /No signature of the person/.test(s)) && CANNOT_SHOW.some((s) => /Approvals by identifier/.test(s)));
});

test('over-limit falls on the receipt that passes the total, in order of time, however the receipts are handed over', async () => {
  const gw = makeGateway();
  const made = await slipWith({ limits: [{ action: 'echo', max: 600, unit: 'credits' }] });
  const r = await judge(made, gw, [receipt(gw, { created_at: at('17:00:00') }), receipt(gw, { created_at: at('17:10:00') }), receipt(gw, { created_at: at('16:50:00') })]);
  assert.equal(r.summary.withinSlip, false);
  assert.deepEqual(codes(r.receipts[0]), []);
  assert.deepEqual(codes(r.receipts[2]), []);
  assert.deepEqual(r.receipts[1].findings, [{ code: 'over-limit', message: 'With this AMW receipt the total is 750 credits. The slip\'s limit is 600 credits: over by 150.' }]);
});

test('over-each-limit, over-count-limit and the limits within a period', async () => {
  const gw = makeGateway();
  const made = await slipWith({
    limits: [
      { action: 'echo', each: 200, unit: 'credits' },
      { action: 'echo', count: 2 },
      { action: 'echo', count: 2, per: 3600 },
      { action: 'echo', max: 600, per: 1800, unit: 'credits' },
    ],
  });
  const receipts = [
    receipt(gw, { created_at: at('17:00:00'), credits_charged: '1' }),
    receipt(gw, { created_at: at('17:20:00'), credits_charged: '2.5' }),
    receipt(gw, { created_at: at('17:40:00'), credits_charged: '1' }),
    receipt(gw, { created_at: at('19:00:00'), credits_charged: '1' }),
  ];
  const r = await judge(made, gw, receipts);
  assert.deepEqual(codes(r.receipts[0]), []);
  assert.deepEqual(codes(r.receipts[1]), ['over-each-limit']);
  assert.deepEqual(codes(r.receipts[2]), ['over-count-limit', 'over-period-limit']);
  assert.deepEqual(codes(r.receipts[3]), ['over-count-limit']);
  assert.equal(r.receipts[1].findings[0].message, 'This AMW receipt is 250 credits. The slip allows no single action above 200 credits.');
  assert.equal(r.receipts[2].findings[0].message, 'This is action number 3 of this kind among the AMW receipts. The slip allows 2.');
  assert.equal(r.receipts[2].findings[1].message, 'With this AMW receipt there are 3 such actions in any hour. The slip allows 2.');
  // The total within 30 minutes: 17:00 (100) and 17:20 (250) are 350; 17:20 and 17:40 are 350; none over 600.
  const r2 = await judge(made, gw, [receipt(gw, { created_at: at('17:00:00'), credits_charged: '4' }), receipt(gw, { created_at: at('17:20:00'), credits_charged: '4' })]);
  assert.deepEqual(codes(r2.receipts[1]), ['over-each-limit', 'over-period-limit']);
  assert.equal(r2.receipts[1].findings[1].message, 'With this AMW receipt the total in any 30 minutes is 800 credits. The slip\'s limit is 600 credits.'.replace('any 30 minutes', 'any 1800 seconds'));
});

test('receipts with the same time keep the order in which they were handed over', async () => {
  const gw = makeGateway();
  const made = await slipWith({ limits: [{ action: 'echo', count: 1 }] });
  const r = await judge(made, gw, [receipt(gw, { receipt_id: 'rcpt_first' }), receipt(gw, { receipt_id: 'rcpt_second' })]);
  assert.deepEqual(codes(r.receipts[0]), []);
  assert.deepEqual(codes(r.receipts[1]), ['over-count-limit']);
});

test('action-not-allowed, prohibited and outside-valid-time, with the tool map', async () => {
  const gw = makeGateway();
  // A slip may not allow a shared action of a kind its "never" forbids, so a
  // prohibited action is also one the slip does not allow.
  const made = await slipWith({ never: ['destroys'] });
  const r = await judge(made, gw, [
    receipt(gw, { tool: 'other-tool' }),
    receipt(gw, { tool: 'wipe' }),
    receipt(gw, { created_at: '2026-09-16T17:00:00+00:00' }),
    receipt(gw, { tool: 'Echo Tool!' }),
  ], { tools: { wipe: 'provared.data.delete' } });
  assert.deepEqual(r.receipts[0].findings, [{ code: 'action-not-allowed', message: 'The slip does not allow the action "other-tool".' }]);
  assert.deepEqual(codes(r.receipts[1]), ['action-not-allowed', 'prohibited']);
  assert.equal(r.receipts[1].action, 'provared.data.delete');
  assert.match(r.receipts[1].findings[1].message, /kind "destroys"/);
  assert.deepEqual(r.receipts[2].findings, [{ code: 'outside-valid-time', message: 'The AMW receipt is dated outside the time the slip allows.' }]);
  assert.equal(r.receipts[3].action, null);
  assert.deepEqual(codes(r.receipts[3]), ['action-not-allowed']);
  assert.match(r.receipts[3].findings[0].message, /not in the form of an action name/);
  assert.doesNotMatch(r.receipts[3].findings[0].message, /Echo Tool/);
  assert.equal(r.summary.withinSlip, false);
});

test('the time of a receipt is read with its offset, and a time that cannot be read is not compared', async () => {
  const gw = makeGateway();
  const made = await slipWith({});
  const r = await judge(made, gw, [
    receipt(gw, { created_at: '2026-09-15T01:00:00+02:00' }),
    receipt(gw, { created_at: '2026-09-14T23:30:00-01:00' }),
    receipt(gw, { created_at: '2026-09-14T17:00:00' }),
  ]);
  assert.deepEqual(codes(r.receipts[0]), []);
  assert.equal(r.receipts[0].when, '2026-09-14T23:00:00.000Z');
  assert.deepEqual(codes(r.receipts[1]), ['outside-valid-time']);
  assert.equal(r.receipts[2].compared, false);
  assert.match(r.receipts[2].notes[0], /time cannot be read/);
  assert.equal(r.summary.notCompared, 1);
});

test('parseAmwTime reads RFC 3339 with an offset, and nothing else', () => {
  assert.equal(parseAmwTime('2026-09-14T17:00:00+00:00'), Date.UTC(2026, 8, 14, 17));
  assert.equal(parseAmwTime('2026-09-14T17:00:00Z'), Date.UTC(2026, 8, 14, 17));
  assert.equal(parseAmwTime('2026-09-14T17:00:00.5+00:00'), Date.UTC(2026, 8, 14, 17) + 500);
  assert.equal(parseAmwTime('2026-09-14T17:00:00.123456789Z'), Date.UTC(2026, 8, 14, 17) + 123);
  assert.equal(parseAmwTime('2026-09-14T18:30:00+01:30'), Date.UTC(2026, 8, 14, 17));
  assert.equal(parseAmwTime('2026-09-14T11:30:00-05:30'), Date.UTC(2026, 8, 14, 17));
  for (const bad of ['2026-02-30T00:00:00Z', '2026-09-14T24:00:00Z', '2026-09-14T17:00:00', '2026-09-14 17:00:00Z', '2026-09-14T17:00:00+24:00', '2026-09-14T17:00:00+00:60', 17, null]) {
    assert.ok(Number.isNaN(parseAmwTime(bad)), String(bad));
  }
});

test('readCredits scales a decimal text to a whole number, and rounds nothing', () => {
  assert.equal(readCredits('2.5', 2), 250n);
  assert.equal(readCredits('2.50', 1), 25n);
  assert.equal(readCredits('2.5', 0), null);
  assert.equal(readCredits('2.55', 1), null);
  assert.equal(readCredits('0', 2), 0n);
  assert.equal(readCredits('50', 0), 50n);
  assert.equal(readCredits('9007199254740991', 0), 9007199254740991n);
  assert.equal(readCredits('9007199254740992', 0), null);
  for (const bad of ['007', '-1', '1.', '.5', '1e3', ' 1', '', 2.5, null]) assert.equal(readCredits(bad, 2), null, String(bad));
});

test('credits that cannot be read give amount-missing where the slip needs an amount, and a note otherwise', async () => {
  const gw = makeGateway();
  const withLimit = await slipWith({ limits: [{ action: 'echo', max: 1000, unit: 'credits' }] });
  const r = await judge(withLimit, gw, [receipt(gw, { credits_charged: '2.555' })]);
  assert.equal(r.receipts[0].amount, null);
  assert.deepEqual(codes(r.receipts[0]), ['amount-missing']);
  assert.match(r.receipts[0].findings[0].message, /give no amount in that unit/);
  // The slip's unit is not the one the credits are read in.
  const r2 = await judge(withLimit, gw, [receipt(gw)], { credits: { unit: 'tokens', decimals: 2 } });
  assert.deepEqual(codes(r2.receipts[0]), ['amount-missing']);
  assert.deepEqual(r2.receipts[0].amount, { unit: 'tokens', value: '250' });
  // No amount limit: a note, no finding.
  const noLimit = await slipWith({});
  const r3 = await judge(noLimit, gw, [receipt(gw, { credits_charged: '2.555' })]);
  assert.deepEqual(codes(r3.receipts[0]), []);
  assert.match(r3.receipts[0].notes[0], /cannot be read as a whole number of credits with 2 decimal places/);
  assert.equal(r3.summary.withinSlip, true);
});

test('where the slip sets an amount limit, how credits are read must be stated; otherwise it need not be', async () => {
  const gw = makeGateway();
  const withLimit = await slipWith({ limits: [{ action: 'echo', max: 1000, unit: 'credits' }] });
  const r = await judge(withLimit, gw, [receipt(gw)], { credits: undefined });
  assert.equal(r.judged, false);
  assert.deepEqual(r.problems.map((p) => p.code), ['amw-credits-not-stated']);
  assert.deepEqual(r.receipts, []);
  const withAbove = await slipWith({ requires: [{ need: 'approval', action: 'echo', above: 100, unit: 'credits' }] });
  const r2 = await judge(withAbove, gw, [receipt(gw)], { credits: undefined });
  assert.deepEqual(r2.problems.map((p) => p.code), ['amw-credits-not-stated']);
  const noLimit = await slipWith({});
  const r3 = await judge(noLimit, gw, [receipt(gw)], { credits: undefined });
  assert.equal(r3.judged, true);
  assert.equal(r3.receipts[0].amount, null);
  assert.equal(r3.summary.withinSlip, true);
});

test('the slip\'s conditions: approval by identifier only, countersignature not judged', async () => {
  const gw = makeGateway();
  const made = await slipWith({
    actions: ['echo', 'pay'],
    requires: [{ need: 'approval', action: 'echo' }, { need: 'countersignature', action: 'pay' }, { need: 'approval', action: 'pay', above: 300, unit: 'credits' }],
  });
  const r = await judge(made, gw, [
    receipt(gw),
    receipt(gw, { approval_id: 'apr_test_0001' }),
    receipt(gw, { tool: 'pay', credits_charged: '2' }),
    receipt(gw, { tool: 'pay', credits_charged: '4' }),
    receipt(gw, { approval_id: '' }),
  ]);
  assert.deepEqual(r.notJudged, ['countersignature', 'approval']);
  assert.deepEqual(r.receipts[0].findings, [{ code: 'approval-missing', message: 'The slip asks for the person\'s approval of this action, and the AMW receipt names none.' }]);
  assert.equal(r.receipts[0].approval, false);
  assert.deepEqual(codes(r.receipts[1]), []);
  assert.equal(r.receipts[1].approval, true);
  assert.match(r.receipts[1].notes[0], /by identifier only/);
  assert.deepEqual(codes(r.receipts[2]), []);
  assert.match(r.receipts[2].notes[0], /countersignature/);
  assert.deepEqual(codes(r.receipts[3]), ['approval-missing']);
  assert.deepEqual(codes(r.receipts[4]), ['approval-missing']);
  assert.equal(r.summary.withinSlip, false);
});

test('a denied receipt, an unknown outcome and a receipt that did not verify are not compared, and a failed receipt is not shown', async () => {
  const gw = makeGateway();
  const other = makeGateway('sk_test_0001');
  const made = await slipWith({});
  const denied = receipt(gw, { outcome: 'denied', credits_charged: '0', reason_code: 'permit_budget_exceeded', ledger_entry_id: null, response_hash: null, constraints_evaluated: { allowed_tools: ['echo'], max_credits: '2.5' } });
  const forged = receipt(other, { tool: 'SECRET-TOOL', permit_id: 'pmt_SECRET' });
  const unknownKey = receipt(makeGateway('sk_test_0009'));
  const r = await judge(made, gw, [receipt(gw), denied, receipt(gw, { outcome: 'pending' }), forged, unknownKey]);
  assert.equal(r.judged, true);
  assert.deepEqual(r.summary, { handed: 5, byStatus: { verified: 3, invalid: 1, unknown_key: 1 }, compared: 1, denied: 1, duplicates: 0, notCompared: 4, notJudged: 0, withinSlip: true, withinPermits: null, trusted: true });
  assert.equal(r.receipts[1].kind, 'denied');
  assert.equal(r.receipts[1].compared, false);
  assert.equal(r.receipts[1].tool, 'echo');
  assert.match(r.receipts[1].notes[0], /refused this call/);
  assert.equal(r.receipts[2].kind, 'other');
  assert.equal(r.receipts[3].status, 'invalid');
  assert.equal(r.receipts[3].kind, null);
  assert.equal(r.receipts[3].tool, null);
  assert.equal(r.receipts[3].permit, null);
  assert.equal(r.receipts[3].when, null);
  assert.doesNotMatch(JSON.stringify(r), /SECRET/);
  assert.equal(r.receipts[4].status, 'unknown_key');
});

test('nothing is compared when the slip is not sound, not from a trusted passkey, or does not name the gateway', async () => {
  const gw = makeGateway();
  const made = await slipWith({});
  const otherPerson = await slipWith({});
  const r = await judge(made, gw, [receipt(gw)], { issuerKeys: otherPerson.issuerKeys });
  assert.equal(r.judged, false);
  assert.deepEqual(r.problems.map((p) => p.code), ['slip-unusable']);
  assert.deepEqual(r.slip.problems.map((p) => p.code), ['issuer-not-expected']);
  assert.equal(r.slip.content, null);
  const altered = { ...made.slip, payload: made.slip.payload.slice(0, -2) + (made.slip.payload.endsWith('A') ? 'B' : 'A') + made.slip.payload.slice(-1) };
  const r2 = await judge({ ...made, slip: altered }, gw, [receipt(gw)]);
  assert.equal(r2.judged, false);
  assert.deepEqual(r2.problems.map((p) => p.code), ['slip-unusable']);
  const noGateway = await developmentSlip({ actions: ['echo'], with: [{ id: 'shop', name: 'A shop' }], ...DAY });
  const r3 = await judge(noGateway, gw, [receipt(gw)]);
  assert.equal(r3.judged, false);
  assert.deepEqual(r3.problems.map((p) => p.code), ['amw-service-not-in-slip']);
  assert.ok(r3.slip.content, 'the slip itself is sound and is shown');
});

test('without a passkey the reader trusts, the judgement is made but rests on no key the reader named', async () => {
  const gw = makeGateway();
  const made = await slipWith({});
  const r = await judge(made, gw, [receipt(gw)], { issuerKeys: undefined });
  assert.equal(r.judged, true);
  assert.equal(r.summary.trusted, false);
  assert.ok(r.slip.notes.some((n) => /not compared with a key you already trust/.test(n)));
  const r2 = await judge(made, gw, [receipt(gw)], { issuerOrigins: ['https://sign.example.org'] });
  assert.equal(r2.judged, false);
  assert.deepEqual(r2.slip.problems.map((p) => p.code), ['issuer-origin-not-expected']);
});

test('the slip may be handed over as JSON text', async () => {
  const gw = makeGateway();
  const made = await slipWith({});
  const r = await judge({ ...made, slip: JSON.stringify(made.slip) }, gw, [receipt(gw)]);
  assert.equal(r.judged, true);
  const r2 = await judge({ ...made, slip: '{not json' }, gw, [receipt(gw)]);
  assert.deepEqual(r2.problems.map((p) => p.code), ['not-json']);
});

test('options that are not what they must be are refused in plain words, and nothing unexpected gives a pass', async () => {
  const gw = makeGateway();
  const made = await slipWith({});
  const problem = async (more) => (await judge(made, gw, [receipt(gw)], more)).problems;
  assert.deepEqual((await judgeReceipts(null)).problems.map((p) => p.code), ['bad-field']);
  assert.deepEqual((await judgeReceipts({})).problems.map((p) => p.code), ['bad-field']);
  assert.match((await problem({ receipts: 'x' }))[0].message, /receipts: must be a list/);
  assert.match((await problem({ keys: 7 }))[0].message, /^keys: /);
  assert.match((await problem({ service: 'Not A Name' }))[0].message, /^service: /);
  assert.match((await problem({ tools: { echo: 'Bad Name' } }))[0].message, /^tools: /);
  assert.match((await problem({ tools: [] }))[0].message, /^tools: /);
  assert.match((await problem({ credits: { unit: 'credits' } }))[0].message, /^credits: /);
  assert.match((await problem({ credits: { unit: 'credits', decimals: 19 } }))[0].message, /^credits: /);
  assert.match((await problem({ credits: { unit: 'two words', decimals: 2 } }))[0].message, /^credits: /);
  assert.match((await problem({ permits: {} }))[0].message, /^permits: /);
  // A receipt whose members cannot even be read: the reader says so and gives no pass.
  const trap = new Proxy({}, { get() { throw new Error('no'); } });
  const r = await judge(made, gw, [trap]);
  assert.equal(r.judged, false);
  assert.deepEqual(r.problems.map((p) => p.code), ['check-failed']);
  assert.equal(r.summary, null);
});

test('AMW permits, where handed over, are compared as the gateway\'s own statement', async () => {
  const gw = makeGateway();
  const made = await slipWith({ actions: ['echo', 'other'] });
  const permits = [
    permit(gw),
    permit(gw, { permit_id: 'pmt_test_0002', status: 'revoked' }),
    permit(gw, { permit_id: 'pmt_test_0003', issued_at: 'not a time' }),
    { ...permit(gw, { permit_id: 'pmt_test_0004' }), signature: 'A'.repeat(86) + '==' },
  ];
  const r = await judge(made, gw, [
    receipt(gw),
    receipt(gw, { tool: 'other' }),
    receipt(gw, { created_at: '2026-09-14T11:00:00+00:00' }),
    receipt(gw, { wallet_id: 'agt-someone-else' }),
    receipt(gw, { permit_id: 'pmt_test_0009' }),
    receipt(gw, { permit_id: 'pmt_test_0002' }),
    receipt(gw, { permit_id: 'pmt_test_0003' }),
    receipt(gw, { permit_id: 'pmt_test_0004' }),
  ], { permits });
  assert.equal(r.permits.length, 4);
  assert.deepEqual(r.permits.map((p) => p.status), ['verified', 'verified', 'verified', 'invalid']);
  assert.deepEqual(r.permits[0], { place: 0, id: 'pmt_test_0001', status: 'verified', reason: r.permits[0].reason, key: { kid: 'sk_test_0001', alg: 'Ed25519', status: 'active' }, active: true, allowedTools: ['echo'], from: Date.UTC(2026, 8, 14, 12), until: Date.UTC(2026, 8, 15, 12), subject: 'agt-test-subject' });
  assert.equal(r.permits[1].active, false);
  assert.ok(Number.isNaN(r.permits[2].from));
  const pf = (i) => r.receipts[i].permitFindings.map((f) => f.code);
  assert.deepEqual(pf(0), []);
  assert.deepEqual(pf(1), ['amw-permit-tool-not-allowed']);
  assert.deepEqual(pf(2), ['amw-permit-not-in-force']);
  assert.deepEqual(pf(3), ['amw-permit-subject-differs']);
  assert.deepEqual(pf(4), ['amw-permit-not-handed-over']);
  assert.deepEqual(pf(5), ['amw-permit-not-active']);
  assert.deepEqual(pf(6), ['amw-permit-not-in-force']);
  assert.deepEqual(pf(7), ['amw-permit-not-handed-over']);
  assert.equal(r.summary.withinSlip, true, 'the AMW permit changes nothing about the slip');
  assert.equal(r.summary.withinPermits, false);
  // Two verified permits with one identifier: the first handed over counts.
  const r2 = await judge(made, gw, [receipt(gw, { tool: 'other' })], { permits: [permit(gw), permit(gw, { allowed_tools: ['echo', 'other'] })] });
  assert.deepEqual(r2.receipts[0].permitFindings.map((f) => f.code), ['amw-permit-tool-not-allowed']);
  assert.match(r2.permits[1].notes[0], /same identifier/);
  // Permits not handed over: nothing is said about them.
  const r3 = await judge(made, gw, [receipt(gw, { permit_id: 'pmt_test_0009' })]);
  assert.deepEqual(r3.receipts[0].permitFindings, []);
  assert.equal(r3.summary.withinPermits, null);
  assert.deepEqual(r3.permits, []);
});

test('the published AMW vectors, judged against a slip that names the gateway', async () => {
  const keys = read('keys.json');
  const receipts = read('receipts.json').cases.filter((c) => c.name.endsWith('.valid') && !c.name.startsWith('p256')).map((c) => c.bundle);
  const permits = read('permits.json').cases.filter((c) => c.name.endsWith('.valid')).map((c) => c.bundle);
  assert.equal(receipts.length, 8);
  assert.equal(permits.length, 5);
  const made = await slipWith({ actions: ['golden-path-echo'], limits: [{ action: 'golden-path-echo', max: 2000, unit: 'credits' }] });
  const r = await judgeReceipts({ slip: made.slip, issuerKeys: made.issuerKeys, keys, receipts, permits, service: 'amw', credits: CREDITS });
  assert.deepEqual(r.problems, []);
  assert.equal(r.summary.handed, 8);
  assert.equal(r.summary.denied, 1);
  // Three of them are forms of one receipt, rcpt_golden_0001: it is counted once.
  assert.equal(r.summary.compared, 5);
  assert.equal(r.summary.duplicates, 2);
  assert.ok(r.receipts.filter((i) => i.kind === 'duplicate').every((i) => /same identifier as number/.test(i.notes[0])));
  assert.equal(r.summary.withinSlip, true);
  assert.deepEqual(r.permits.map((p) => p.id), ['pmt_golden_0002', 'pmt_golden_0001', 'pmt_golden_0004', 'pmt_golden_0003', 'pmt_golden_0005']);
  // The receipts are dated 14 September, before the permits' hour on 16 September, and name another wallet than the permits' subject.
  for (const item of r.receipts.filter((i) => i.compared)) {
    assert.deepEqual(item.amount, { unit: 'credits', value: '250' });
    assert.deepEqual(item.permitFindings.map((f) => f.code), ['amw-permit-not-in-force', 'amw-permit-subject-differs']);
  }
  assert.equal(r.summary.withinPermits, false);
  // Under a slip of the same hour as the permits, every receipt is outside the slip's time.
  const sameHour = await slipWith({ actions: ['golden-path-echo'], validFrom: '2026-09-16T12:00:00Z', validUntil: '2026-09-16T13:00:00Z' });
  const r2 = await judgeReceipts({ slip: sameHour.slip, issuerKeys: sameHour.issuerKeys, keys, receipts, service: 'amw' });
  assert.ok(r2.receipts.filter((i) => i.compared).every((i) => codes(i).includes('outside-valid-time')));
  assert.equal(r2.summary.withinSlip, false);
});

test('receiptDocument carries an AMW receipt by its fingerprint inside a Provared receipt', async () => {
  const gw = makeGateway();
  const bundle = receipt(gw);
  const doc = await receiptDocument(bundle);
  assert.equal(doc.name, DOCUMENT_NAME);
  assert.equal(DOCUMENT_NAME, 'agent-middleware.receipt');
  assert.equal(doc.sha256, await argumentsFingerprint(bundle));
  assert.notEqual(doc.sha256, (await receiptDocument({ ...bundle, signature: bundle.signature.slice(1) + 'A' })).sha256);
  await assert.rejects(receiptDocument('text'), /as an object/);
  const { recorder, issuerKeys } = await developmentRecorder({ actions: ['echo'], with: [SERVICE] });
  await recorder.act({ action: 'echo', with: 'amw', details: [doc] }, async () => 'done');
  const checked = await checkBook(recorder.book(), { issuerKeys });
  assert.equal(checked.summary.intact, true);
  assert.equal(checked.summary.withinSlips, true);
  assert.deepEqual(checked.entries[1].content.details, [doc]);
});

test('a slip whose passkey signature this device cannot check is not judged against', async () => {
  const gw = makeGateway();
  const made = await slipWith({});
  const r = await judge(made, gw, [receipt(gw)], { withoutMethods: ['ES256', 'RS256', 'Ed25519'] });
  assert.equal(r.judged, false);
  assert.equal(r.slip.signature.state, 'unavailable');
  assert.deepEqual(r.slip.problems, []);
  assert.deepEqual(r.problems.map((p) => p.code), ['slip-unusable']);
  assert.match(r.problems[0].message, /could not be checked on this device/);
});
