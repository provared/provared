// After the review of the gateway's countersignature (review 3.4), which
// found the same gaps in the executor: a receipt found in the book at a
// start settles a call only where it is the call the copy shows, with the
// executor's countersignature; and "compare" holds each receipt's content
// and countersignature against the copy, and reports more than one receipt
// for one call.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { appendFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { argumentsFingerprint, checkBook, countersign, entryLine, identifierFingerprint, keySetFingerprint, writeStub } = await import('provared');
const { world, openWorld, pause } = await import('./world.mjs');
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

test('L7: two receipts for one call are no agreement, even where the copy matches one of them', async () => {
  const w = await afterOneCall();
  const [first] = copyLines(w);
  await forge(w, { slip: first.slip, action: first.action, with: 'executor', details: [...first.details, { name: 'provared.error', sha256: await identifierFingerprint('again') }] });
  const result = await compareOf(w);
  assert.equal(result.summary.matched, 1);
  assert.equal(result.summary.moreThanOneReceipt, 1);
  assert.equal(result.summary.agree, false);
});
