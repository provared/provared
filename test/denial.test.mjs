// The denial: the agent's own side states that it did not take an action
// that was asked for, and why. Format description, section 28.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { tempFolder } from './helpers/temp.mjs';
import { FINDING_CODES, NotTaken, argumentsFingerprint, checkBook, checkShow, denialCodes, makeShow, openChecker, recordTools, signerFromKey, thumbprint, writeBook, writeDenial } from '../src/index.js';
import { START, makeWorld, openWriter } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const ORDER = 'supplies.order';
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });
const contentOf = (line) => JSON.parse(Buffer.from(JSON.parse(line).denial.payload, 'base64url').toString());
const codesOf = (r) => [...r.problems.map((p) => p.code), ...r.entries.flatMap((e) => [...e.problems, ...e.breaches].map((p) => p.code))];

async function writer(more = {}, fields = { requires: [] }) {
  const w = await makeWorld({ fields });
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const recorder = await openWriter({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, ...more });
  return { w, issuerKeys, recorder };
}

// --- in a book ---

test('a denial in a book is the agent\'s side\'s statement: shown, counted, and never counted against the agent', async () => {
  const w = await makeWorld({ fields: { requires: [] } });
  await w.add({ value: 150 });
  // The denial names an amount far over the limit, and a service the slip does not name.
  await w.deny({ amount: { unit: 'GBP', value: 9000 }, with: 'stranger', codes: ['over-limit', 'party-not-allowed'] });
  await w.add({ value: 20 });
  const r = await checkBook(w.book(), { issuerKeys: [await thumbprint(w.passkey.key)] });
  assert.deepEqual(codesOf(r), []);
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.withinSlips, true);
  assert.equal(r.summary.firstBreach, null);
  assert.equal(r.summary.counts.denials, 1);
  const e = r.entries[2];
  assert.equal(e.kind, 'denial');
  assert.equal(e.verified, 'all');
  assert.equal(e.slip, w.slipFingerprint);
  assert.deepEqual(e.breaches, []);
  assert.match(e.notes.join(' '), /its own word: it is not counted against the agent/);
  // The denial is in no chain: the stub after it goes on from the stub before it.
  assert.equal(r.entries[3].content.seq, 1);
  // The running total takes in the stubs only.
  assert.equal(r.entries[3].running.total, '170');
});

test('a denial must come after its slip, and be signed by the agent the slip, or its pass, names', async () => {
  const w = await makeWorld({ fields: { passes: 1, requires: [] } });
  const trusted = { issuerKeys: [await thumbprint(w.passkey.key)] };
  const helper = await w.pass({});
  await w.deny({ pass: helper.fingerprint, signer: helper.helper.privateKeys }); // 2: sound
  await w.deny({ pass: helper.fingerprint }); // 3: signed by the first agent, not the helper
  await w.deny({ signer: helper.helper.privateKeys }); // 4: the helper's keys, with no pass
  const r = await checkBook(w.book(), trusted);
  assert.deepEqual(r.entries.slice(2).map((e) => e.problems.map((p) => p.code)), [[], ['signature-invalid'], ['signature-invalid']]);
  assert.equal(r.entries[2].pass, helper.fingerprint);
  const before = writeBook([w.entries[2], w.entries[0], w.entries[1]]);
  const b = await checkBook(before, trusted);
  assert.deepEqual(b.entries[0].problems.map((p) => p.code), ['slip-missing']);
});

test('a carried checker reads a denial as a whole check does, and a Show checks one with its slip', async () => {
  const w = await makeWorld({ fields: { requires: [] } });
  await w.add({ value: 10 });
  const lines = w.book();
  await w.deny({ source: 'person' });
  const whole = await checkBook(w.book());
  const carried = await openChecker(lines);
  await carried.add(w.book().slice(lines.length));
  assert.deepEqual(await carried.result(), whole);
  const show = await checkShow(await makeShow(w.book(), [0, 2]));
  assert.equal(show.summary.intact, true);
  assert.equal(show.entries[1].kind, 'denial');
});

test('every finding code the checker can give is on the format\'s own list, and the list is the table of the list of threats', () => {
  const table = readFileSync(new URL('../docs/threat-model.md', import.meta.url), 'utf8').split('## 8.')[1].split('## 9.')[0];
  const listed = [...table.matchAll(/^\| `([a-z0-9-]+)` \|/gm)].map((m) => m[1]);
  assert.deepEqual([...listed].sort(), [...FINDING_CODES].sort());
  // Every code given in the library's own source is on the list, apart from the answers of the stub writer.
  const sources = ['book', 'guard', 'recorder', 'slip', 'compare', 'stub', 'standing', 'service', 'seal', 'timestamp', 'blockstamp', 'der', 'cover', 'jws', 'encoding', 'fields', 'keys', 'webauthn', 'signatures', 'tree', 'headers', 'documents', 'pass', 'approval', 'denial', 'tools', 'witness', 'witnessing']
    .map((n) => readFileSync(new URL(`../src/${n}.js`, import.meta.url), 'utf8'))
    .join('\n');
  const given = new Set([...sources.matchAll(/(?:Refusal\(|code: )'([a-z0-9-]+)'/g)].map((m) => m[1]));
  const answersOnly = ['details-not-added', 'denials-over-limit'];
  for (const code of given) if (!answersOnly.includes(code)) assert.ok(FINDING_CODES.includes(code), code);
});

test('denialCodes: problems first, each once, from the list, at most 16', () => {
  const p = (code) => ({ code, message: '' });
  assert.deepEqual(denialCodes({ problems: [p('record-not-sound')], breaches: [p('over-limit'), p('record-not-sound')] }), ['record-not-sound', 'over-limit']);
  assert.deepEqual(denialCodes({ problems: [p('details-not-added')], breaches: [] }), ['check-failed']);
  assert.equal(denialCodes({ problems: [], breaches: FINDING_CODES.map(p) }).length, 16);
});

test('a denial through signers is the same record as with keys', async () => {
  const w = await makeWorld();
  const fields = { slip: w.slipFingerprint, action: ORDER, source: 'rule', id: 'AgICAgICAgICAgICAgICAg', when: START };
  const signers = [signerFromKey('Ed25519', w.agent.privateKeys[0], w.agent.keys[0]), signerFromKey('ML-DSA-87', w.agent.privateKeys[1], w.agent.keys[1])];
  const a = await writeDenial(fields, w.agent.privateKeys);
  const b = await writeDenial(fields, signers);
  assert.equal(a.fingerprint, b.fingerprint);
  assert.equal(a.record.signatures[0].signature, b.record.signatures[0].signature);
});

test('the command-line checker shows a denial as the agent\'s side\'s word, and counts it', async () => {
  const w = await makeWorld({ fields: { requires: [] } });
  await w.deny({ codes: ['over-limit'] });
  await w.deny({ source: 'person', details: [{ name: 'provared.arguments', sha256: 'A'.repeat(43) }] });
  const file = join(tempFolder(), 'book.jsonl');
  writeFileSync(file, w.book());
  const r = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', fileURLToPath(new URL('../bin/provared-check.mjs', import.meta.url)), file], { encoding: 'utf8' });
  assert.match(r.stdout, /Entry 1: DENIAL /);
  assert.match(r.stdout, /The slip's own agent states that it did not take an action/);
  assert.match(r.stdout, /Who said no: The check before acting \(section 20\) did not allow the action\./);
  assert.match(r.stdout, /Reasons given: over-limit/);
  assert.match(r.stdout, /Documents named: 1, by their fingerprints only/);
  assert.match(r.stdout, /Who said no: The person refused, or gave no approval when asked\./);
  assert.match(r.stdout, /Denials \(the agent's side's own word, not counted against it\) 2/);
  assert.match(r.stdout, /Did the agent stay within its slip\?\s+yes/);
});

// --- the stub writer ---

test('the stub writer writes a denial whenever "act" refuses, only when opened with denials, and never with a stub', async () => {
  const { recorder, issuerKeys } = await writer({ denials: true });
  assert.equal(recorder.denials, true);
  const refused = await recorder.act(order(250), async () => assert.fail('not taken'));
  assert.equal(refused.done, false);
  assert.equal(refused.denial.written, true);
  assert.deepEqual(contentOf(refused.denial.line).codes, ['over-limit']);
  assert.equal(contentOf(refused.denial.line).source, 'check');
  const taken = await recorder.act(order(10), async () => 'ok');
  assert.equal(taken.done, true);
  assert.equal(Object.hasOwn(taken, 'denial'), false);
  const quiet = await recorder.act(order(300), async () => 'x', { denial: false });
  assert.equal(Object.hasOwn(quiet, 'denial'), false);
  const r = await checkBook(recorder.book(), { issuerKeys });
  assert.deepEqual(r.entries.map((e) => e.kind), ['slip', 'denial', 'stub']);
  assert.equal(r.summary.intact, true);

  const off = await writer();
  assert.equal(off.recorder.denials, false);
  const none = await off.recorder.act(order(250), async () => 'x');
  assert.equal(Object.hasOwn(none, 'denial'), false);
  assert.equal((await off.recorder.deny(order(1), { source: 'person' })).written, false);
  assert.equal(off.recorder.book(), off.w.book());
});

test('the hourly limit stops denials, never a stub, and the answers count what was not written', async () => {
  const { recorder } = await writer({ denials: true, denialsPerHour: 2 });
  for (let i = 0; i < 2; i++) assert.equal((await recorder.act({ action: 'provared.data.delete' }, async () => null)).denial.written, true);
  const over = await recorder.act({ action: 'provared.data.delete' }, async () => null);
  assert.deepEqual([over.denial.written, over.denial.problem.code, over.denial.notWritten], [false, 'denials-over-limit', 1]);
  const person = await recorder.deny(order(1), { source: 'person' });
  assert.deepEqual([person.written, person.notWritten], [false, 2]);
  // A stub is still written.
  assert.equal((await recorder.act(order(5), async () => 'ok')).done, true);
  // An hour on, denials are written again; the count stays.
  const later = await recorder.act({ action: 'provared.data.delete' }, async () => null, { when: START + HOUR + 1000 });
  assert.deepEqual([later.denial.written, later.denial.notWritten], [true, 2]);
});

test('the hourly limit counts each denial at the writer\'s clock, whatever date it states', async () => {
  let clock = START + HOUR;
  const { recorder } = await writer({ denials: true, denialsPerHour: 10, now: () => clock });
  const back = () => recorder.deny(order(1), { source: 'rule', when: clock - 299000 });
  let written = 0;
  for (let i = 0; i < 10; i++) if ((await back()).written) written++;
  clock += 3302000;
  for (let i = 0; i < 10; i++) if ((await back()).written) written++;
  // Ten in the first hour of the clock; 3,302 seconds on, that hour is not over, so none more.
  assert.equal(written, 10);
  clock += 299000;
  assert.equal((await back()).written, true);
});

test('an own denial handed in through "add" counts at the writer\'s clock, however far back it is dated', async () => {
  let clock = START + 3 * HOUR;
  const { recorder, w } = await writer({ denials: true, denialsPerHour: 2, now: () => clock });
  const old = await writeDenial({ slip: w.slipFingerprint, action: ORDER, source: 'rule', when: clock - 2 * HOUR }, w.agent.privateKeys);
  await recorder.add({ denial: old.record });
  assert.equal((await recorder.deny(order(1), { source: 'rule' })).written, true);
  const over = await recorder.deny(order(1), { source: 'rule' });
  assert.deepEqual([over.written, over.problem.code], [false, 'denials-over-limit']);
});

test('"deny" is refused from inside an action, as every call from there is', async () => {
  const { recorder } = await writer({ denials: true });
  let inside;
  await recorder.act(order(1), async () => {
    inside = await recorder.deny(order(2), { source: 'rule' }).then(
      () => 'written',
      (e) => e.message,
    );
  });
  assert.match(inside, /from inside an action it is taking/);
});

test('recorded tools: the arguments are never written in clear, and one call leaves a stub or a denial, never both', async () => {
  const { recorder, issuerKeys, w } = await writer({ denials: true }, { requires: [{ need: 'approval', action: ORDER, above: 50, unit: 'GBP' }] });
  const args = { item: 'a secret item name', total: 70 };
  const request = { action: ORDER, with: 'supplier', amount: { unit: 'GBP', value: 70 }, details: [{ name: 'provared.arguments', sha256: await argumentsFingerprint(args) }] };
  const approval = await w.approve({ slip: w.slipFingerprint, ...request, when: START });
  let answer = null;
  const tools = recordTools(recorder, {
    buy: { action: ORDER, with: 'supplier', amount: (a) => ({ unit: 'GBP', value: a.total }), run: async (a) => `bought ${a.item}`, approve: async () => answer },
  });
  await assert.rejects(tools.buy(args), (e) => e instanceof NotTaken && e.denial.written === true && contentOf(e.denial.line).source === 'person');
  answer = approval;
  assert.equal(await tools.buy(args), 'bought a secret item name');
  const text = recorder.book();
  assert.equal(text.includes('secret'), false);
  for (const line of text.trim().split('\n').slice(1)) assert.equal(Buffer.from(JSON.parse(line)[Object.keys(JSON.parse(line)).find((k) => k !== 'approval')].payload, 'base64url').toString().includes('secret'), false);
  const r = await checkBook(text, { issuerKeys });
  // The first call: one denial, by the person. The second: one stub, with the approval, and no denial.
  assert.deepEqual(r.entries.map((e) => e.kind), ['slip', 'denial', 'stub']);
  assert.equal(r.summary.intact, true);
});
