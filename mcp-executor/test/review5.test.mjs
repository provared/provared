// After the review of the gateway's countersignature (review 3.4), which
// found the same gaps in the executor: a receipt found in the book at a
// start settles a call only where it is the call the copy shows, with the
// executor's countersignature; and "compare" holds each receipt's content
// and countersignature against the copy, and reports more than one receipt
// for one call.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { appendFileSync, mkdirSync, readFileSync, renameSync, rmdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { argumentsFingerprint, checkBook, countersign, entryLine, identifierFingerprint, keySetFingerprint, writeStub } = await import('provared');
const { world, openWorld, pause, signSlip } = await import('./world.mjs');
const { CALL_DOCUMENT, TOOL_DOCUMENT, openExecutor } = await import('../executor.mjs');
const { readCopy, loadCopyKey, openCopy } = await import('../copy.mjs');
const { compareCopyWithBook } = await import('../compare.mjs');
const { loadKeyFile, makeKeyFile } = await import('../files.mjs');

const RECORDER = { keys: 'keys/recorder.jwk', name: 'The test recorder' };

/** A world that made one call and stopped, with a recorder. */
async function afterOneCall() {
  const w = await world({ open: false, config: { recorder: RECORDER } });
  w.recorderKeys = await makeKeyFile(join(w.folder, 'keys', 'recorder.jwk'), 'recorder');
  w.sealKeys = [await keySetFingerprint(w.recorderKeys)];
  await openWorld(w);
  await w.client.call('echo', {});
  w.slipFingerprint = w.executor.slip.fingerprint;
  await w.close();
  return w;
}
const bookPath = (w) => join(w.folder, 'book.jsonl');
const options = (w) => ({ issuerKeys: w.settings.agent.issuerKeys, sealKeys: w.sealKeys });
const copyKeyOf = (w) => loadCopyKey(join(w.folder, 'copy.jsonl.key'));
const copyLines = (w) => readCopy(join(w.folder, 'copy.jsonl'), copyKeyOf(w), w.settings.name).lines.map((l) => l.entry);
const compareOf = (w, book) => compareCopyWithBook({ copyPath: join(w.folder, 'copy.jsonl'), copyKey: copyKeyOf(w), name: w.settings.name, service: 'executor', book: book ?? readFileSync(bookPath(w), 'utf8'), options: options(w) });
const offline = (w) => openExecutor(w.settings, { root: w.folder, log: (e) => w.logs.push(e), offline: true });

/** A "sending" line in the copy for a call under the permission in force, as a stop with the call in flight leaves it. */
async function leaveCall(w, call) {
  const read = readCopy(join(w.folder, 'copy.jsonl'), copyKeyOf(w), w.settings.name);
  const details = [{ name: 'provared.arguments', sha256: await argumentsFingerprint({}) }, { name: TOOL_DOCUMENT, sha256: await identifierFingerprint('slow') }, { name: CALL_DOCUMENT, sha256: await identifierFingerprint(call) }];
  const sending = { kind: 'sending', call, when: new Date().toISOString(), slip: w.slipFingerprint, tool: 'slow', action: 'slow.work', with: 'executor', details };
  openCopy(join(w.folder, 'copy.jsonl'), copyKeyOf(w), w.settings.name, read.next).note(sending);
  await pause(5);
  return sending;
}

/** A receipt signed with the agent's keys, put at the end of the book. */
async function forge(w, fields) {
  const checked = await checkBook(readFileSync(bookPath(w), 'utf8'), options(w));
  const last = checked.entries.filter((e) => e.kind === 'stub' && e.content.slip === fields.slip).at(-1);
  const { privateKeys } = await loadKeyFile(join(w.folder, 'keys', 'agent.jwk'), 'agent');
  const made = await writeStub({ ...fields, after: last ? { seq: last.content.seq, fingerprint: last.fingerprint } : null }, privateKeys);
  appendFileSync(bookPath(w), `${entryLine({ stub: made.record })}\n`);
  return made;
}

test('M1: a receipt found in the book at a start that is not the call the copy shows, is one-sided, or is one of two, stops the start and waits to be set aside; it is not written into the copy as the executor\'s', async () => {
  for (const how of ['other arguments', 'one-sided', 'two receipts']) {
    const w = await afterOneCall();
    const call = `crashed-${how.replace(' ', '-')}`;
    const s = await leaveCall(w, call);
    const same = { slip: s.slip, action: s.action, with: 'executor', when: Date.parse(s.when), details: [...s.details, { name: 'provared.error', sha256: await identifierFingerprint('made up') }] };
    const made = how === 'other arguments' ? await forge(w, { ...same, details: [{ name: 'provared.arguments', sha256: await argumentsFingerprint({ x: 1 }) }, ...s.details.slice(1)] }) : await forge(w, same);
    if (how === 'two receipts') await forge(w, same);
    await assert.rejects(openExecutor(w.settings, { root: w.folder, log: () => {} }), /does not settle it/, how);
    const ex = await offline(w);
    try {
      assert.ok(w.logs.some((e) => e.event === 'receipt-not-matching' && e.call === call), how);
      const waiting = (await ex.report()).agent.receiptsMissing.find((p) => p.call === call);
      assert.equal(waiting.usable, false);
      assert.match(waiting.problem, { 'other arguments': /not the call the executor's copy shows as sent/, 'one-sided': /without a valid countersignature of the executor/, 'two receipts': /holds 2 receipts for this call/ }[how]);
      assert.ok(!copyLines(w).some((l) => l.outcome === 'found-in-book'));
      await assert.rejects(ex.acknowledge(), /No call waiting can have a receipt written/);
      const done = await ex.acknowledge({ setAside: [call] });
      assert.equal(done.written.length, 0);
    } finally {
      await ex.close();
    }
    const result = await compareOf(w);
    assert.equal(result.summary.agree, false);
    assert.deepEqual(result.setAside.map((x) => [x.call, x.inBook]), [[call, made.fingerprint]]);
  }
});

test('a receipt found in the book at a start that is the call the copy shows, countersigned, is noted "found-in-book" with its countersignature, and compare agrees', async () => {
  const w = await afterOneCall();
  const text = readFileSync(join(w.folder, 'copy.jsonl'), 'utf8').split('\n');
  const { writeFileSync } = await import('node:fs');
  writeFileSync(join(w.folder, 'copy.jsonl'), `${text.slice(0, -2).join('\n')}\n`);
  const ex = await offline(w);
  await ex.close();
  const last = copyLines(w).at(-1);
  assert.equal(last.outcome, 'found-in-book');
  assert.equal(last.countersigned, true);
  assert.equal(typeof last.countersignature, 'string');
  const result = await compareOf(w);
  assert.equal(result.summary.agree, true, JSON.stringify(result.summary));
});

test('M2: compare reports a receipt whose countersignature is taken off, or is another than the one the copy records', async () => {
  const w = await afterOneCall();
  const lines = readFileSync(bookPath(w), 'utf8').trim().split('\n');
  const at = lines.findIndex((l) => l.startsWith('{"stub"') || l.includes('"countersignature"'));
  const { countersignature, ...bare } = JSON.parse(lines[at]);
  assert.ok(countersignature);
  const put = (v) => `${[...lines.slice(0, at), entryLine(v), ...lines.slice(at + 1)].join('\n')}\n`;
  const stripped = await compareOf(w, put(bare));
  assert.equal(stripped.summary.agree, false);
  assert.deepEqual(stripped.countersignatures.map((c) => c.problem), ['missing']);
  const other = await compareOf(w, put({ ...bare, countersignature: await countersign(bare.stub, await w.executorPrivateKeys(), Date.now() + 5000) }));
  assert.equal(other.summary.agree, false);
  assert.deepEqual(other.countersignatures.map((c) => c.problem), ['another']);
  assert.equal((await compareOf(w)).summary.agree, true);
});

test('M2 and L7: compare reports a receipt the copy names that is not the call sent, and more than one receipt for one call', async () => {
  const w = await afterOneCall();
  const call = 'crashed-content';
  const s = await leaveCall(w, call);
  const made = await forge(w, { slip: s.slip, action: s.action, with: 'executor', details: [{ name: 'provared.arguments', sha256: await argumentsFingerprint({ y: 2 }) }, ...s.details.slice(1)] });
  // A copy that took the receipt at a start, as the release before this change did.
  openCopy(join(w.folder, 'copy.jsonl'), copyKeyOf(w), w.settings.name, readCopy(join(w.folder, 'copy.jsonl'), copyKeyOf(w), w.settings.name).next).note({ kind: 'done', call, when: new Date().toISOString(), outcome: 'found-in-book', stub: made.fingerprint });
  const result = await compareOf(w);
  assert.equal(result.summary.agree, false);
  assert.deepEqual(result.differs.map((d) => [d.call, d.why]), [[call, 'not the call sent']]);
  // A second receipt for the first call.
  const [first] = copyLines(w);
  await forge(w, { slip: first.slip, action: first.action, with: 'executor', details: [...first.details, { name: 'provared.error', sha256: await identifierFingerprint('again') }] });
  const twice = await compareOf(w);
  assert.equal(twice.summary.moreThanOneReceipt, 1);
  assert.equal(twice.moreThanOne[0].call, first.call);
  assert.equal(twice.summary.agree, false);
});

/**
 * A world that made one call, stopped with another in flight, and was then
 * given a new permission: the call waits for the administrator. The
 * executor is opened offline, with the clock given.
 */
async function waitingUnderOldSlip(now) {
  const w = await afterOneCall();
  const s = await leaveCall(w, 'late-call');
  const signed = await signSlip({ passkey: w.passkey, agentKeys: w.agentKeys, executorKeys: w.executorKeys, until: Date.now() + 7200000 });
  writeFileSync(join(w.folder, 'slip.json'), JSON.stringify(signed));
  const ex = await openExecutor(w.settings, { root: w.folder, log: (e) => w.logs.push(e), offline: true, now });
  return { w, s, ex };
}

/** The first "acknowledge" writes the receipt into the book, and the copy cannot say so: the call still waits, its receipt in the book. */
async function receiptInBookCallWaiting(w, ex) {
  const at = join(w.folder, 'copy.jsonl');
  renameSync(at, `${at}.away`);
  mkdirSync(at);
  const first = await ex.acknowledge();
  rmdirSync(at);
  renameSync(`${at}.away`, at);
  assert.deepEqual(first.written, []);
  assert.deepEqual(first.failed.map((f) => f.call), ['late-call']);
  const call = await identifierFingerprint('late-call');
  const inBook = (await checkBook(readFileSync(bookPath(w), 'utf8'), options(w))).entries.filter((e) => e.kind === 'stub' && e.content.details.some((d) => d.name === CALL_DOCUMENT && d.sha256 === call));
  assert.equal(inBook.length, 1, 'the receipt is in the book');
  return inBook[0];
}

test('acknowledge: a receipt that reached the book after the start, and is the call sent, countersigned, settles the call and is noted "found-in-book" with its countersignature', async () => {
  const { w, ex } = await waitingUnderOldSlip(Date.now);
  try {
    const receipt = await receiptInBookCallWaiting(w, ex);
    assert.equal(receipt.countersignature?.state, 'valid');
    const again = await ex.acknowledge();
    assert.deepEqual(again.written.map((x) => [x.call, x.found ?? false, x.stub]), [['late-call', true, receipt.fingerprint]]);
    assert.deepEqual(again.failed, []);
    assert.equal((await ex.report()).agent.receiptsMissing.length, 0);
  } finally {
    await ex.close();
  }
  const last = copyLines(w).at(-1);
  assert.deepEqual([last.call, last.outcome, last.countersigned, typeof last.countersignature], ['late-call', 'found-in-book', true, 'string']);
  const result = await compareOf(w);
  assert.equal(result.summary.agree, true, JSON.stringify(result.summary));
});

test('acknowledge: a receipt that reached the book after the start without the countersignature the permission names does not settle the call; it waits to be set aside', async () => {
  // A clock an hour ahead while the countersignature is dated, and right
  // again when the library checks it: the countersignature is refused, and
  // the receipt goes into the book one-sided. (The arrow the executor hands
  // the library is named "countersign" in a stack trace.)
  let skewed = true;
  const now = () => (skewed && /\bcountersign \(/.test(new Error().stack) ? Date.now() + 3600000 : Date.now());
  const { w, ex } = await waitingUnderOldSlip(now);
  try {
    const receipt = await receiptInBookCallWaiting(w, ex);
    assert.notEqual(receipt.countersignature?.state, 'valid', 'the receipt is one-sided');
    skewed = false;
    const again = await ex.acknowledge();
    assert.deepEqual(again.written, []);
    assert.deepEqual(again.failed.map((f) => f.call), ['late-call']);
    assert.match(again.failed[0].problem, /without a valid countersignature of the executor/);
    assert.ok(w.logs.some((e) => e.event === 'receipt-not-matching' && e.call === 'late-call'));
    const waiting = (await ex.report()).agent.receiptsMissing.find((p) => p.call === 'late-call');
    assert.equal(waiting.usable, false);
    assert.deepEqual(waiting.inBook, [receipt.fingerprint]);
    assert.ok(!copyLines(w).some((l) => l.outcome === 'found-in-book'));
    await assert.rejects(ex.acknowledge(), /No call waiting can have a receipt written/);
    const aside = await ex.acknowledge({ setAside: ['late-call'] });
    assert.deepEqual(aside.setAside.map((x) => x.call), ['late-call']);
    assert.equal(aside.written.length, 0);
  } finally {
    await ex.close();
  }
  assert.equal((await compareOf(w)).summary.agree, false);
});

test('L7: two receipts for one call are no agreement, even where the copy matches one of them', async () => {
  const w = await afterOneCall();
  const [first] = copyLines(w);
  await forge(w, { slip: first.slip, action: first.action, with: 'executor', details: [...first.details, { name: 'provared.error', sha256: await identifierFingerprint('again') }] });
  const result = await compareOf(w);
  assert.equal(result.summary.matched, 1);
  assert.equal(result.summary.moreThanOneReceipt, 1);
  assert.equal(result.summary.agree, false);
});

test('M2 (re-check F3): compare checks the countersignature of a receipt written at a later start, where the copy\'s "done" line says it was countersigned', async () => {
  for (const countersigned of [false, true]) {
    const w = await afterOneCall();
    const call = `late-call-${countersigned}`;
    const s = await leaveCall(w, call);
    // The executor could not write the book file: the copy's "done" line names no stub, and says the receipt was countersigned.
    openCopy(join(w.folder, 'copy.jsonl'), copyKeyOf(w), w.settings.name, readCopy(join(w.folder, 'copy.jsonl'), copyKeyOf(w), w.settings.name).next).note({ kind: 'done', call, when: new Date().toISOString(), outcome: 'error', countersigned: true, countersignature: 'B'.repeat(43), documents: [{ name: 'provared.error', sha256: await identifierFingerprint('what the executor saw') }] });
    const made = await forge(w, { slip: s.slip, action: s.action, with: 'executor', when: Date.parse(s.when), details: [...s.details, { name: 'provared.error', sha256: await identifierFingerprint('the outcome is not known') }] });
    let book = readFileSync(bookPath(w), 'utf8');
    if (countersigned) {
      const lines = book.trim().split('\n');
      book = `${[...lines.slice(0, -1), entryLine({ stub: made.record, countersignature: await countersign(made.record, await w.executorPrivateKeys()) })].join('\n')}\n`;
    }
    const result = await compareOf(w, book);
    if (countersigned) {
      assert.deepEqual(result.matched.filter((m) => m.call === call).map((m) => [m.countersignature, m.note]), [['valid', 'written at a later start']]);
      assert.equal(result.summary.agree, true, JSON.stringify(result.summary));
    } else {
      assert.deepEqual(result.countersignatures.map((c) => [c.call, c.problem]), [[call, 'missing']]);
      assert.equal(result.matched.filter((m) => m.call === call).length, 0);
      assert.equal(result.summary.agree, false);
    }
  }
});

test('X433: a book outside its slips does not agree, even where every call of the copy matches', async () => {
  const w = await afterOneCall();
  assert.equal((await compareOf(w)).summary.agree, true);
  // A receipt of the agent under another service, which the slip does not name: not the executor's, and outside the slip.
  const [first] = copyLines(w);
  await forge(w, { slip: first.slip, action: first.action, with: 'elsewhere', details: [{ name: 'provared.arguments', sha256: await argumentsFingerprint({}) }] });
  const result = await compareOf(w);
  assert.deepEqual([result.summary.matched, result.summary.notInCopy, result.summary.bookProblem, result.summary.bookFullyChecked], [1, 0, false, true], JSON.stringify(result.summary));
  assert.equal(result.summary.bookWithinSlips, false);
  assert.equal(result.book.withinSlips, false);
  assert.equal(result.summary.agree, false);
  assert.equal(result.summary.onlySetAside, false);
});

test('X433: a book with a problem, or one this computer could not fully check, does not agree', async () => {
  const w = await afterOneCall();
  const book = readFileSync(bookPath(w), 'utf8');
  const spoilt = await compareOf(w, `${book}{"not":"a line"}\n`);
  assert.equal(spoilt.summary.matched, 1);
  assert.equal(spoilt.summary.bookProblem, true);
  assert.equal(spoilt.summary.agree, false);
  assert.equal(spoilt.summary.onlySetAside, false);
  // A computer without one of the signature methods the keys use, and a book that holds only a denial: no receipt,
  // so no countersignature this computer cannot check (that would itself be a disagreement). No problem is found,
  // the book is within its slip, and it is not fully checked.
  const v = await world({ slip: { limits: [{ action: 'supplies.order', max: 100, unit: 'GBP' }] } });
  await v.client.call('order', { total: 200 });
  await v.close();
  const sees = (withoutMethods) => compareCopyWithBook({ copyPath: join(v.folder, 'copy.jsonl'), copyKey: copyKeyOf(v), name: v.settings.name, service: 'executor', book: readFileSync(bookPath(v), 'utf8'), options: { issuerKeys: v.settings.agent.issuerKeys, withoutMethods } });
  const seen = await sees([]);
  assert.deepEqual([seen.summary.sent, seen.refused.length, seen.refused[0].denialInBook, seen.summary.agree], [0, 1, true, true], JSON.stringify(seen.summary));
  const blind = await sees(['ML-DSA-87']);
  assert.equal(blind.refused[0].denialInBook, true, JSON.stringify(blind.summary));
  assert.deepEqual([blind.summary.bookProblem, blind.summary.bookWithinSlips, blind.summary.bookFullyChecked], [false, true, false], JSON.stringify(blind.summary));
  assert.equal(blind.summary.agree, false);
  assert.equal(blind.summary.onlySetAside, false);
});
