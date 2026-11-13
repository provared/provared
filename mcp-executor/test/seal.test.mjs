// Sealing a book, acknowledging a call sent under a permission no longer in
// force, and what the executor says about itself: over stdio, where the
// commands work on the files of an executor that is not running.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, rmdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook, identifierFingerprint, argumentsFingerprint, keySetFingerprint } = await import('provared');
const { world, openWorld, signSlip, until, pause } = await import('./world.mjs');
const { CALL_DOCUMENT, TOOL_DOCUMENT, RESULT_DOCUMENT, WRITTEN_LATE_DOCUMENT, WRITTEN_LATE, OUTCOME_UNKNOWN, ACKNOWLEDGED_DOCUMENT, ACKNOWLEDGED, WRITTEN_LATER, NO_RECORD_OF_OUTCOME, checkConfig, openExecutor, readSettings, statusFromFiles } = await import('../executor.mjs');

// The fixed texts a receipt names, with their fingerprints written out: a
// receipt already in a book names the fingerprint, so a change of one
// letter would make it unrecognisable.
const ACKNOWLEDGED_FINGERPRINT = 'poJcnPoQB6EyH2Pvp2ZPgD6_2XrDua1XAOpPHBaUezI';
const WRITTEN_LATER_FINGERPRINT = 'L_sk-qfojehaePxOm8pV-04nhqDY78T5E040ZwBKtho';
const NO_RECORD_OF_OUTCOME_FINGERPRINT = 'pOqSHPh3dRwENnfo2e8cGdYHpsYRvvGW2CUyBeGaGiU';
const { readCopy, loadCopyKey, openCopy } = await import('../copy.mjs');
const { compareCopyWithBook } = await import('../compare.mjs');
const { makeKeyFile } = await import('../files.mjs');

const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));
const RECORDER = { keys: 'keys/recorder.jwk', name: 'The test recorder' };

/** Run the command, and give its exit code and what it wrote. */
function run(args, { env = {} } = {}) {
  return new Promise((done) => {
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', BIN, ...args], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, env: { ...process.env, ...env } });
    child.stdin.end();
    const out = [];
    const err = [];
    child.stdout.on('data', (c) => out.push(c));
    child.stderr.on('data', (c) => err.push(c));
    const timer = setTimeout(() => child.kill(), 50000);
    child.on('exit', (code) => {
      clearTimeout(timer);
      done({ code, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') });
    });
  });
}

/** A world whose settings name a recorder, with the recorder's key file made; "sealKeys" is what a reader names. */
async function sealedWorld(o = {}) {
  const w = await world({ ...o, open: false, config: { recorder: RECORDER, ...(o.config ?? {}) } });
  w.recorderKeys = await makeKeyFile(join(w.folder, 'keys', 'recorder.jwk'), 'recorder');
  w.sealKeys = [await keySetFingerprint(w.recorderKeys)];
  if (o.open !== false) await openWorld(w, o.more ?? {});
  return w;
}
const bookText = (w) => readFileSync(join(w.folder, 'book.jsonl'), 'utf8');
const checked = (w, more = {}) => checkBook(bookText(w), { issuerKeys: w.settings.agent.issuerKeys, sealKeys: w.sealKeys, ...more });
const sealsOf = (c) => c.entries.filter((e) => e.kind === 'seal');
const stubsOf = (c) => c.entries.filter((e) => e.kind === 'stub');
const docs = (stub) => Object.fromEntries(stub.content.details.map((d) => [d.name, d.sha256]));
const offline = (w, more = {}) => openExecutor(w.settings, { root: w.folder, log: (e) => w.logs.push(e), offline: true, ...more });
const copyKeyOf = (w) => loadCopyKey(join(w.folder, 'copy.jsonl.key'));
const copyOf = (w) => readCopy(join(w.folder, 'copy.jsonl'), copyKeyOf(w), w.settings.name);
/** Add a "sending" line to the copy, as an executor that stopped with the call in flight leaves it. */
async function leaveCall(w, call, slip, change = (line) => line) {
  const key = copyKeyOf(w);
  const copy = openCopy(join(w.folder, 'copy.jsonl'), key, w.settings.name, copyOf(w).next);
  const details = [{ name: 'provared.arguments', sha256: await argumentsFingerprint({}) }, { name: TOOL_DOCUMENT, sha256: await identifierFingerprint('slow') }, { name: CALL_DOCUMENT, sha256: await identifierFingerprint(call) }];
  copy.note(change({ kind: 'sending', call, when: new Date().toISOString(), slip, tool: 'slow', action: 'slow.work', with: 'executor', details }));
  // The executor that finds the line starts after the call was sent.
  await pause(5);
  return copy;
}
/** Put a new permission in place, for the same keys. */
async function renewSlip(w) {
  const signed = await signSlip({ passkey: w.passkey, agentKeys: w.agentKeys, executorKeys: w.executorKeys, until: Date.now() + 7200000 });
  writeFileSync(join(w.folder, 'slip.json'), JSON.stringify(signed));
}
/** A world that ran one call under its first permission, stopped with another in flight, and was then given a new permission. Gives the first permission's fingerprint. */
async function worldWithCallUnderOldSlip(o = {}, change) {
  const w = await sealedWorld(o);
  await w.client.call('echo', {});
  const first = w.executor.slip.fingerprint;
  await w.close();
  await leaveCall(w, 'lost-call', first, change);
  await renewSlip(w);
  return { w, first };
}

test('seal: the book is sealed with the recorder\'s three keys, the seal is the library\'s and chains to the one before, and a reader who names another recorder is told', async () => {
  const w = await sealedWorld();
  await w.client.call('echo', {});
  await w.close();
  const ex = await offline(w);
  const first = await ex.seal();
  assert.equal(first.entry, 2, 'the slip, the stub, then the seal');
  let c = await checked(w);
  assert.equal(c.summary.problemFound, false);
  assert.equal(c.entries[2].kind, 'seal');
  assert.equal(c.entries[2].fingerprint, first.fingerprint);
  assert.deepEqual(c.entries[2].signatures.map((s) => s.method), ['Ed25519', 'ML-DSA-87', 'SLH-DSA-SHA2-256s']);
  assert.ok(c.entries[2].signatures.every((s) => s.state === 'valid'));
  assert.equal(c.entries[2].content.by.name, 'The test recorder');
  assert.equal(c.entries[2].content.size, 2);
  assert.equal(c.entries[2].content.previous, undefined);
  assert.equal(c.entries[2].stamps.length, 0, 'no outside time-stamp is written');
  const second = await ex.seal();
  assert.equal(second.entry, 3);
  c = await checked(w);
  assert.equal(c.summary.problemFound, false);
  assert.equal(c.entries[3].content.previous, first.fingerprint);
  const report = await ex.report();
  assert.deepEqual(report.agent.lastSeal, { entry: 3, fingerprint: second.fingerprint, when: c.entries[3].content.when });
  assert.equal(report.agent.sound, true);
  assert.equal(report.recorder.fingerprint, w.sealKeys[0]);
  assert.ok(w.logs.some((e) => e.event === 'sealed' && e.seal === second.fingerprint));
  // A reader who expects another recorder finds the seals signed with keys they did not expect.
  const other = await checked(w, { sealKeys: ['A'.repeat(43)] });
  assert.ok(sealsOf(other).every((s) => s.problems.some((p) => p.code === 'sealer-not-expected')));
  // The copy agrees with a sealed book.
  const compared = await compareCopyWithBook({ copyPath: join(w.folder, 'copy.jsonl'), copyKey: copyKeyOf(w), name: w.settings.name, service: 'executor', book: bookText(w), options: { issuerKeys: w.settings.agent.issuerKeys, sealKeys: w.sealKeys } });
  assert.equal(compared.summary.agree, true);
  assert.deepEqual([compared.book.seals, compared.book.sealersExpected], [2, w.sealKeys]);
  // The executor starts on a sealed book, and writes on after the seal.
  await ex.close();
  await openWorld(w);
  try {
    const r = await w.client.call('echo', {});
    assert.ok(r.result);
    assert.equal(stubsOf(await checked(w)).length, 2);
    assert.equal((await checked(w)).summary.problemFound, false);
  } finally {
    await w.close();
  }
});

test('seal: without a recorder in the settings nothing is sealed; a settings file with a bad recorder is refused', async () => {
  const w = await world({ open: false });
  const ex = await offline(w);
  await assert.rejects(async () => ex.seal(), /name no recorder/);
  assert.equal(ex.recorder, null);
  assert.ok(!bookText(w).includes('"seal"'));
  const report = await checkConfig(w.settings, w.folder);
  assert.deepEqual(report.problems, []);
  assert.equal(report.recorder, null);
  assert.ok(report.warnings.some((x) => /^recorder: none is named, so the executor cannot seal/.test(x)));
  for (const [recorder, words] of [
    [{}, /recorder\.keys/],
    [{ keys: 'r.jwk', sealEvery: 999 }, /recorder\.sealEvery/],
    [{ keys: 'r.jwk', sealEvery: 604800001 }, /recorder\.sealEvery/],
    [{ keys: 'r.jwk', sealEvery: '60000' }, /recorder\.sealEvery/],
    [{ keys: 'r.jwk', name: '' }, /recorder\.name/],
    ['r.jwk', /recorder: must be an object/],
  ]) {
    const { problems } = readSettings({ ...w.settings, recorder }, w.folder);
    assert.ok(problems.some((p) => words.test(p)), `${JSON.stringify(recorder)}: ${problems.join(' | ')}`);
  }
  const fine = readSettings({ ...w.settings, recorder: { keys: 'r.jwk' } }, w.folder);
  assert.deepEqual(fine.problems, []);
  assert.equal(fine.settings.recorder.name, w.settings.name, 'the recorder is named as the executor unless the settings say otherwise');
  assert.equal(fine.settings.recorder.sealEvery, null, 'no timer unless set');
  assert.ok(!fine.warnings.some((x) => /sealEvery/.test(x)));
  // A timer of less than a minute is allowed, and warned about.
  assert.ok(readSettings({ ...w.settings, recorder: { keys: 'r.jwk', sealEvery: 59999 } }, w.folder).warnings.some((x) => /^recorder\.sealEvery: 59999 ms is less than a minute/.test(x)));
  assert.ok(!readSettings({ ...w.settings, recorder: { keys: 'r.jwk', sealEvery: 60000 } }, w.folder).warnings.some((x) => /sealEvery/.test(x)));
});

test('seal: a book sealed with other keys than the settings\' recorder does not pass its check, and the executor does not open on it', async () => {
  const w = await sealedWorld({ open: false });
  const ex = await offline(w);
  await ex.seal();
  await ex.close();
  // Another recorder's keys are put in place of the ones the book was sealed with.
  rmSync(join(w.folder, 'keys', 'recorder.jwk'));
  await makeKeyFile(join(w.folder, 'keys', 'recorder.jwk'), 'recorder');
  await assert.rejects(offline(w), /does not pass its check/);
  await assert.rejects(openExecutor(w.settings, { root: w.folder, log: () => {} }), /does not pass its check/);
  const status = await statusFromFiles(w.settings, w.folder);
  assert.equal(status.agent.sound, false);
  assert.match(status.agent.problem, /does not pass its check/);
});

test('seal: a book file that something else changed is not sealed, and the agent stops', async () => {
  const w = await sealedWorld({ open: false });
  const ex = await offline(w);
  await ex.seal();
  const before = bookText(w);
  appendFileSync(join(w.folder, 'book.jsonl'), '{"not":"a line of the executor\'s"}\n');
  await assert.rejects(ex.seal(), /not as the executor left it/);
  assert.equal(bookText(w), `${before}{"not":"a line of the executor's"}\n`, 'nothing was written after the change');
  assert.match(ex.stopped(), /not as the executor left it/);
  await assert.rejects(ex.seal(), /The agent is stopped/);
});

test('seal on a timer: off unless set; at a start a book with entries after its last seal is sealed where that seal is old enough or there is none; an idle executor writes no seal over a seal', async () => {
  // Off unless set: an executor with a recorder and no timer writes no seal of its own accord.
  const quiet = await sealedWorld();
  try {
    await quiet.client.call('echo', {});
    await pause(1500);
    assert.equal(sealsOf(await checked(quiet)).length, 0);
  } finally {
    await quiet.close();
  }
  // Every second.
  const w = await sealedWorld({ config: { recorder: { ...RECORDER, sealEvery: 1000 } } });
  try {
    // At the start: there is no seal yet, so the book (the slip) is sealed.
    await until(async () => sealsOf(await checked(w)).length === 1, { timeout: 15000 });
    await w.client.call('echo', {});
    // The next round seals the stub.
    await until(async () => sealsOf(await checked(w)).length === 2, { timeout: 15000 });
    const c = await checked(w);
    assert.equal(c.summary.problemFound, false);
    assert.deepEqual(c.entries.map((e) => e.kind), ['slip', 'seal', 'stub', 'seal']);
    assert.equal(c.entries[3].content.previous, c.entries[1].fingerprint);
    // Idle: more rounds pass, with time enough to sign a seal, and no seal is written over a seal.
    await pause(8000);
    assert.equal(sealsOf(await checked(w)).length, 2);
    assert.equal(w.logs.filter((e) => e.event === 'sealed').length, 2);
    assert.equal(w.logs.filter((e) => e.event === 'not-sealed').length, 0);
  } finally {
    await w.close();
  }
});

test('seal on a timer: once the executor has ended, its timer seals nothing more, though the book holds something new', async () => {
  const w = await sealedWorld({ config: { recorder: { ...RECORDER, sealEvery: 4000 } } });
  try {
    // The round at the start has ended; the next is four seconds away.
    await until(() => w.logs.some((e) => e.event === 'sealed'), { timeout: 20000 });
    await w.client.call('echo', {});
  } finally {
    await w.close();
  }
  const size = statSync(join(w.folder, 'book.jsonl')).size;
  assert.deepEqual((await checked(w)).entries.map((e) => e.kind), ['slip', 'seal', 'stub']);
  // Time enough for the next round, and for a seal to be signed.
  await pause(10000);
  assert.equal(statSync(join(w.folder, 'book.jsonl')).size, size);
});

test('seal on a timer: a start does not seal a book whose last seal is younger than sealEvery, and does once it is older', async () => {
  const w = await sealedWorld({ config: { recorder: { ...RECORDER, sealEvery: 600000 } } });
  try {
    await until(async () => sealsOf(await checked(w)).length === 1, { timeout: 15000 });
    await w.client.call('echo', {});
  } finally {
    await w.close();
  }
  // A second start, at once: the stub is after the seal, and the seal is not ten minutes old.
  await openWorld(w);
  try {
    await w.client.call('echo', {});
    await pause(300);
    assert.equal(sealsOf(await checked(w)).length, 1);
  } finally {
    await w.close();
  }
  // A third start, eleven minutes on by the executor's clock.
  await openWorld(w, { now: () => Date.now() + 660000 });
  try {
    await until(async () => sealsOf(await checked(w)).length === 2, { timeout: 15000 });
    assert.equal((await checked(w)).summary.problemFound, false);
  } finally {
    await w.close();
  }
});

test('acknowledge: a call sent under a permission no longer in force stops the start over stdio; acknowledged offline, its receipt is written under the permission it was sent under', async () => {
  const { w, first } = await worldWithCallUnderOldSlip();
  // The executor does not start, and says what to do.
  await assert.rejects(openExecutor(w.settings, { root: w.folder, log: () => {} }), /not the one in force.*acknowledge --config <settings> --offline/s);
  const status = await statusFromFiles(w.settings, w.folder);
  assert.equal(status.agent.receiptsMissing.length, 1);
  assert.equal(status.agent.receiptsMissing[0].call, 'lost-call');
  assert.equal(status.agent.receiptsMissing[0].usable, true);
  const ex = await offline(w);
  assert.match(ex.stopped(), /1 call\(s\) sent before the executor last stopped/);
  assert.ok(w.logs.some((e) => e.event === 'receipt-missing' && e.calls[0].call === 'lost-call'));
  // Nothing is sealed while a call waits.
  await assert.rejects(ex.seal(), /The agent is stopped/);
  const report = await ex.report();
  assert.deepEqual(report.agent.receiptsMissing.map((p) => [p.call, p.usable, p.problem, p.slip, p.tool, p.outcomeKnown]), [['lost-call', true, null, first, 'slow', false]]);
  const sentAt = report.agent.receiptsMissing[0].when;
  // More than a second on, so that the receipt's date tells the time of the call from the time of the acknowledgement.
  await pause(1100);
  const done = await ex.acknowledge();
  assert.equal(done.written.length, 1);
  assert.deepEqual(done.remaining, []);
  assert.equal(ex.stopped(), null);
  const c = await checked(w);
  assert.equal(c.summary.problemFound, false);
  const stubs = stubsOf(c);
  assert.equal(stubs.length, 2);
  const stub = stubs[1];
  assert.equal(stub.fingerprint, done.written[0].stub);
  assert.equal(stub.content.slip, first, 'under the permission the call was sent under, not the one in force');
  assert.notEqual(ex.slip.fingerprint, first);
  assert.equal(stub.content.when, `${sentAt.slice(0, 19)}Z`, 'dated with the time the copy gives for the call, to the second');
  const line = JSON.parse(bookText(w).split('\n')[stub.index]);
  const countersignedAt = JSON.parse(Buffer.from(line.countersignature.payload, 'base64url').toString('utf8')).when;
  assert.ok(Date.parse(countersignedAt) >= Date.parse(stub.content.when), 'countersigned at the acknowledgement, not before the call was sent');
  assert.equal(stub.content.with, 'executor');
  const d = docs(stub);
  // The three fixed texts of an acknowledged receipt, by their fingerprints written out.
  assert.equal(d['provared.error'], NO_RECORD_OF_OUTCOME_FINGERPRINT);
  assert.equal(d[WRITTEN_LATE_DOCUMENT], WRITTEN_LATER_FINGERPRINT);
  assert.equal(d[ACKNOWLEDGED_DOCUMENT], ACKNOWLEDGED_FINGERPRINT);
  assert.equal(ACKNOWLEDGED_DOCUMENT, 'executor.acknowledged');
  assert.deepEqual(done.failed, []);
  assert.equal(d[CALL_DOCUMENT], await identifierFingerprint('lost-call'));
  assert.equal(stub.countersignature.state, 'valid', 'countersigned by the executor');
  const last = copyOf(w).lines.at(-1).entry;
  assert.deepEqual([last.kind, last.call, last.outcome, last.stub], ['done', 'lost-call', 'acknowledged-outcome-unknown', stub.fingerprint]);
  // Nothing is left to acknowledge, and the book can be sealed again.
  await assert.rejects(ex.acknowledge(), /no call without a receipt/);
  await ex.seal();
  await ex.close();
  // The executor starts, and takes calls under the permission in force.
  await openWorld(w);
  try {
    const r = await w.client.call('echo', {});
    assert.ok(r.result);
    const after = await checked(w);
    assert.equal(after.summary.problemFound, false);
    assert.equal(stubsOf(after).at(-1).content.slip, w.executor.slip.fingerprint);
  } finally {
    await w.close();
  }
  const compared = await compareCopyWithBook({ copyPath: join(w.folder, 'copy.jsonl'), copyKey: copyKeyOf(w), name: w.settings.name, service: 'executor', book: bookText(w), options: { issuerKeys: w.settings.agent.issuerKeys, sealKeys: w.sealKeys } });
  assert.equal(compared.summary.agree, true);
  assert.equal(compared.summary.matched, 3);
});

test('acknowledge: where the copy holds the outcome, the receipt names it', async () => {
  const w = await sealedWorld();
  await w.client.call('echo', {});
  const first = w.executor.slip.fingerprint;
  await w.close();
  const copy = await leaveCall(w, 'known-call', first);
  const result = await argumentsFingerprint({ content: [] });
  copy.note({ kind: 'done', call: 'known-call', when: new Date().toISOString(), outcome: 'answer', countersigned: true, documents: [{ name: RESULT_DOCUMENT, sha256: result }] });
  await renewSlip(w);
  const ex = await offline(w);
  assert.equal((await ex.report()).agent.receiptsMissing[0].outcomeKnown, true);
  await ex.acknowledge();
  const d = docs(stubsOf(await checked(w)).at(-1));
  assert.equal(d[RESULT_DOCUMENT], result);
  assert.equal(d['provared.error'], undefined);
  assert.equal(d[WRITTEN_LATE_DOCUMENT], WRITTEN_LATER_FINGERPRINT);
  assert.equal(d[ACKNOWLEDGED_DOCUMENT], ACKNOWLEDGED_FINGERPRINT);
  assert.equal(copyOf(w).lines.at(-1).entry.outcome, 'acknowledged');
});

test('acknowledge: never two receipts for one call, also where the copy could not be written after the receipt was', async () => {
  const { w, first: old } = await worldWithCallUnderOldSlip();
  // A second call waits behind the first.
  await leaveCall(w, 'second-call', old);
  const ex = await offline(w);
  // The copy cannot be written: the receipt goes into the book, and the line saying so does not go into the copy.
  const at = join(w.folder, 'copy.jsonl');
  renameSync(at, `${at}.away`);
  mkdirSync(at);
  const first = await ex.acknowledge();
  assert.deepEqual(first.written, []);
  assert.deepEqual(first.failed.map((f) => f.call), ['lost-call'], 'once the copy cannot be written, the next call is not tried');
  assert.match(first.failed[0].problem, /copy .* is not as the executor left it/);
  assert.equal(first.remaining.length, 2);
  rmdirSync(at);
  renameSync(`${at}.away`, at);
  const call = await identifierFingerprint('lost-call');
  const second = await identifierFingerprint('second-call');
  const named = async (which = call) => stubsOf(await checked(w)).filter((s) => docs(s)[CALL_DOCUMENT] === which);
  assert.equal((await named()).length, 1, 'the receipt is in the book');
  assert.equal((await named(second)).length, 0, 'no receipt was written that the copy could not have been told of');
  assert.equal((await ex.report()).agent.receiptsMissing.length, 2, 'and the calls still wait');
  // Trying again finds the first receipt in the book, and writes no second one; the other call gets its receipt.
  const again = await ex.acknowledge();
  assert.deepEqual(again.written.map((x) => [x.call, x.found ?? false]), [['lost-call', true], ['second-call', false]]);
  assert.equal((await named()).length, 1);
  assert.equal((await named(second)).length, 1);
  assert.equal(again.written[0].stub, (await named())[0].fingerprint);
  assert.deepEqual(copyOf(w).lines.slice(-2).map((l) => l.entry.outcome), ['found-in-book', 'acknowledged-outcome-unknown']);
  // And so does a new start: the call is finished.
  await ex.close();
  const next = await offline(w);
  assert.equal((await next.report()).agent.receiptsMissing.length, 0);
  assert.equal((await named()).length, 1);
});

test('acknowledge: a line from which no receipt can be written gets none, and can only be set aside', async () => {
  const B = 'B'.repeat(43);
  const order = await identifierFingerprint('order');
  const asOrder = (l) => ({ ...l, tool: 'order', action: 'supplies.order', details: l.details.map((d) => (d.name === TOOL_DOCUMENT ? { ...d, sha256: order } : d)) });
  const cases = [
    ['a member the executor does not write', (l) => ({ ...l, extra: 1 }), /a member the executor does not write/],
    ['a call identifier of another form', (l) => ({ ...l, call: 'not an identifier!' }), /call identifier is not one the executor makes/],
    ['no permission named', (l) => ({ ...l, slip: 'short' }), /does not say which permission/],
    ['a time of another form', (l) => ({ ...l, when: 'yesterday' }), /not a time written as the executor writes it/],
    ['a time after this start', (l) => ({ ...l, when: new Date(Date.now() + 3600000).toISOString() }), /after this start/],
    ['an action that is not an action name', (l) => ({ ...l, action: 'Not An Action' }), /not an action name/],
    ['another service id', (l) => ({ ...l, with: 'someone-else' }), /another service id/],
    ['a tool name that is not one', (l) => ({ ...l, tool: 'not a tool' }), /not a tool name/],
    ['an amount where its rule gives none', (l) => ({ ...l, amount: { value: 5, unit: 'GBP' } }), /not in the unit its rule gives/],
    ['no amount where its rule gives one', asOrder, /rule gives an amount, and the line has none/],
    ['an amount below 0', (l) => ({ ...asOrder(l), amount: { value: -1, unit: 'GBP' } }), /not a unit and a whole number from 0 up/],
    ['an amount that is not whole, under a rule that has changed', (l) => ({ ...l, action: 'other.work', amount: { value: 1.5, unit: 'GBP' } }), /not a unit and a whole number from 0 up/],
    ['a document the executor does not name', (l) => ({ ...l, details: [...l.details, { name: 'provared.tool-result', sha256: B }] }), /documents are not the ones/],
    ['one document twice', (l) => ({ ...l, details: [...l.details, { name: 'provared.trace-id', sha256: B }, { name: 'provared.trace-id', sha256: B }] }), /names one document twice/],
    ['no arguments', (l) => ({ ...l, details: l.details.map((d) => (d.name === 'provared.arguments' ? { name: 'provared.trace-id', sha256: B } : d)) }), /names no arguments/],
    ['a tool document that does not match the tool', (l) => ({ ...l, tool: 'crash' }), /tool document does not match/],
    ['a call document that does not match the call', (l) => ({ ...l, details: l.details.map((d) => (d.name === CALL_DOCUMENT ? { ...d, sha256: B } : d)) }), /call document does not match/],
    ['a request identifier that does not match the call', (l) => ({ ...l, details: [...l.details, { name: 'provared.request-id', sha256: B }] }), /request identifier does not match/],
  ];
  for (const [what, change, words] of cases) {
    const { w } = await worldWithCallUnderOldSlip({}, change);
    const ex = await offline(w);
    const waiting = (await ex.report()).agent.receiptsMissing;
    assert.equal(waiting.length, 1, what);
    assert.equal(waiting[0].usable, false, what);
    assert.match(waiting[0].problem, words, what);
    const before = bookText(w);
    await assert.rejects(ex.acknowledge(), /No call waiting can have a receipt written/, what);
    assert.equal(bookText(w), before, `${what}: nothing was written`);
    assert.match(ex.stopped(), /have no receipt/, what);
  }
});

test('acknowledge: a call sent under a permission the book does not hold, or one that names other keys, cannot be acknowledged; set aside, it has no receipt, and compare says so', async () => {
  const w = await sealedWorld();
  await w.client.call('echo', {});
  await w.close();
  // The book never held this permission.
  await leaveCall(w, 'stray-call', 'A'.repeat(43));
  const ex = await offline(w);
  let waiting = (await ex.report()).agent.receiptsMissing;
  assert.match(waiting[0].problem, /The book does not hold the permission/);
  await assert.rejects(ex.acknowledge(), /No call waiting can have a receipt written/);
  await assert.rejects(ex.acknowledge({ setAside: ['no-such-call'] }), /No call "no-such-call" is waiting/);
  await assert.rejects(async () => ex.acknowledge({ setAside: 'stray-call' }), /must be a list/);
  const before = bookText(w);
  const done = await ex.acknowledge({ setAside: ['stray-call', 'stray-call'] });
  assert.deepEqual(done.setAside.map((p) => p.call), ['stray-call']);
  assert.deepEqual(done.written, []);
  assert.deepEqual(done.remaining, []);
  assert.equal(bookText(w), before, 'a call set aside gets no receipt');
  assert.equal(ex.stopped(), null);
  assert.equal(copyOf(w).lines.at(-1).entry.kind, 'set-aside');
  assert.ok(w.logs.some((e) => e.event === 'call-set-aside' && e.call.call === 'stray-call'));
  // It stays set aside at the next start, which takes calls: also where a line for the same call is added to the copy afterwards.
  await ex.close();
  await leaveCall(w, 'stray-call', 'A'.repeat(43));
  await openWorld(w);
  try {
    assert.equal(w.executor.stopped(), null);
    assert.ok((await w.client.call('echo', {})).result);
  } finally {
    await w.close();
  }
  // The copy shows a call that was sent and has no receipt: it does not agree with the book.
  const compared = await compareCopyWithBook({ copyPath: join(w.folder, 'copy.jsonl'), copyKey: copyKeyOf(w), name: w.settings.name, service: 'executor', book: bookText(w), options: { issuerKeys: w.settings.agent.issuerKeys, sealKeys: w.sealKeys } });
  assert.deepEqual(compared.setAside.map((x) => x.call), ['stray-call']);
  assert.equal(compared.summary.setAside, 1);
  assert.equal(compared.summary.unfinished, 0);
  assert.equal(compared.summary.agree, false);
  assert.equal(compared.summary.onlySetAside, true, 'the calls set aside are the only disagreement, and the answer says so');

  // A permission the book holds, which names other keys for the executor than it now holds.
  const v = await sealedWorld();
  await v.client.call('echo', {});
  const first = v.executor.slip.fingerprint;
  await v.close();
  await leaveCall(v, 'old-keys-call', first);
  rmSync(join(v.folder, 'keys', 'executor.jwk'));
  v.executorKeys = await makeKeyFile(join(v.folder, 'keys', 'executor.jwk'), 'agent');
  await renewSlip(v);
  const vx = await offline(v);
  waiting = (await vx.report()).agent.receiptsMissing;
  assert.match(waiting[0].problem, /does not name the executor in "with" as "executor" with the keys the executor now holds/);
  await assert.rejects(vx.acknowledge(), /No call waiting can have a receipt written/);

  // A permission the book holds, which names other keys for the agent than the executor now holds.
  const u = await sealedWorld();
  await u.client.call('echo', {});
  const earlier = u.executor.slip.fingerprint;
  await u.close();
  await leaveCall(u, 'old-agent-keys-call', earlier);
  rmSync(join(u.folder, 'keys', 'agent.jwk'));
  u.agentKeys = await makeKeyFile(join(u.folder, 'keys', 'agent.jwk'), 'agent');
  await renewSlip(u);
  const ux = await offline(u);
  waiting = (await ux.report()).agent.receiptsMissing;
  assert.match(waiting[0].problem, /names other agent keys than the executor now holds/);
  const held = bookText(u);
  await assert.rejects(ux.acknowledge(), /No call waiting can have a receipt written/);
  assert.equal(bookText(u), held);
});

test('acknowledge: a rule taken out since the call was sent is a warning, not a refusal; what the copy holds of the outcome must be of the executor\'s form', async () => {
  const { w } = await worldWithCallUnderOldSlip();
  const { slow, ...others } = w.settings.tools;
  assert.ok(slow);
  w.settings.tools = others;
  const ex = await offline(w);
  const waiting = (await ex.report()).agent.receiptsMissing;
  assert.equal(waiting[0].usable, true);
  assert.match(waiting[0].warning, /No rule names this tool with this action now/);
  const done = await ex.acknowledge();
  assert.equal(done.written.length, 1);
  assert.equal((await checked(w)).summary.problemFound, false);

  const v = await sealedWorld();
  await v.client.call('echo', {});
  const first = v.executor.slip.fingerprint;
  await v.close();
  const copy = await leaveCall(v, 'odd-outcome', first);
  copy.note({ kind: 'done', call: 'odd-outcome', when: new Date().toISOString(), outcome: 'answer', documents: [{ name: RESULT_DOCUMENT, sha256: 'B'.repeat(43) }, { name: 'provared.error', sha256: 'B'.repeat(43) }] });
  await renewSlip(v);
  const vx = await offline(v);
  const odd = (await vx.report()).agent.receiptsMissing;
  assert.equal(odd[0].usable, false);
  assert.match(odd[0].problem, /holds of its outcome is not of the form/);
});

test('acknowledge: nothing is written where something else changed the book file, or where the library refuses the receipt; the call stays waiting', async () => {
  const { w } = await worldWithCallUnderOldSlip();
  const ex = await offline(w);
  assert.throws(() => ex.attach(), /starts no server/);
  appendFileSync(join(w.folder, 'book.jsonl'), '{"not":"a line of the executor\'s"}\n');
  const changed = bookText(w);
  await assert.rejects(ex.acknowledge(), /not as the executor left it/);
  await assert.rejects(ex.acknowledge(), /The agent is stopped/);
  assert.equal(bookText(w), changed);
  assert.equal((await ex.report()).agent.receiptsMissing.length, 1);

  // A receipt dated before the receipt ahead of it: the library does not write it.
  const v = await sealedWorld();
  await v.client.call('echo', {});
  const first = v.executor.slip.fingerprint;
  await v.close();
  await leaveCall(v, 'early-call', first, (l) => ({ ...l, when: new Date(Date.now() - 30000).toISOString() }));
  await renewSlip(v);
  const vx = await offline(v);
  assert.equal((await vx.report()).agent.receiptsMissing[0].usable, true);
  const before = bookText(v);
  const refused = await vx.acknowledge();
  assert.deepEqual([refused.written, refused.setAside], [[], []]);
  assert.deepEqual(refused.failed.map((f) => f.call), ['early-call']);
  assert.match(refused.failed[0].problem, /would not pass its check/);
  assert.ok(v.logs.some((e) => e.event === 'not-acknowledged' && e.call === 'early-call'));
  assert.equal(bookText(v), before, 'nothing was written');
  assert.equal(copyOf(v).lines.at(-1).entry.kind, 'sending');
  assert.equal((await vx.report()).agent.receiptsMissing.length, 1);
  // It can be set aside.
  const aside = await vx.acknowledge({ setAside: ['early-call'] });
  assert.deepEqual(aside.remaining, []);
  assert.equal(bookText(v), before);
});

test('status from the files writes nothing, and shows the last seal, whether the book passes its check, and the calls waiting', async () => {
  const w = await sealedWorld({ open: false });
  const fresh = await statusFromFiles(w.settings, w.folder);
  assert.deepEqual([fresh.from, fresh.agent.entries, fresh.agent.sound, fresh.agent.slipInBook, fresh.agent.lastSeal], ['files', 0, null, false, null]);
  assert.equal(fresh.recorder.fingerprint, w.sealKeys[0]);
  assert.ok(!existsSync(join(w.folder, 'book.jsonl')), 'no book file was made');
  assert.ok(!existsSync(join(w.folder, 'copy.jsonl.key')), 'no copy key was made');
  const ex = await offline(w);
  const sealed = await ex.seal();
  const size = statSync(join(w.folder, 'book.jsonl')).size;
  const status = await statusFromFiles(w.settings, w.folder);
  assert.deepEqual([status.agent.entries, status.agent.sound, status.agent.slipInBook, status.agent.bytes], [2, true, true, size]);
  assert.equal(status.agent.lastSeal.fingerprint, sealed.fingerprint);
  assert.deepEqual(status.agent.receiptsMissing, []);
  assert.equal(status.agent.receiptsAtNextStart, 0);
  assert.equal(statSync(join(w.folder, 'book.jsonl')).size, size);
  // A call sent under the permission in force, with no receipt: the next start writes it, and the status says so.
  await leaveCall(w, 'late-call', ex.slip.fingerprint);
  assert.equal((await statusFromFiles(w.settings, w.folder)).agent.receiptsAtNextStart, 1);
  await ex.close();
  // A command at work on the files is not a start: it writes no late receipt, and does not seal while one is due.
  w.logs = [];
  const off = await offline(w);
  const before = bookText(w);
  assert.ok(!w.logs.some((e) => e.event === 'receipt-written-late'));
  assert.equal((await off.report()).agent.receiptsAtNextStart, 1);
  await assert.rejects(off.seal(), /1 call\(s\) with no receipt in the book, which the executor's next start will give one/);
  assert.equal(bookText(w), before, 'nothing was written');
  assert.equal(copyOf(w).lines.at(-1).entry.kind, 'sending');
  await off.close();
  // The start writes it.
  await openWorld(w);
  try {
    assert.ok(w.logs.some((e) => e.event === 'receipt-written-late' && e.call === 'late-call'));
    assert.equal(stubsOf(await checked(w)).length, 1);
  } finally {
    await w.close();
  }
});

test('the copy is written by one program at a time: a line added by another stops the writing', async () => {
  const w = await world();
  try {
    await w.client.call('echo', {});
    // Another program adds a line, as a command run with --offline beside a running executor would.
    const other = openCopy(join(w.folder, 'copy.jsonl'), copyKeyOf(w), w.settings.name, copyOf(w).next);
    other.note({ kind: 'withdrawn', call: 'from-elsewhere', when: new Date().toISOString(), tool: 'echo', action: 'provared.data.read' });
    const lines = copyOf(w).lines.length;
    const r = await w.client.call('echo', {});
    assert.equal(r.error.code, 1001);
    assert.match(r.error.message, /not as the executor left it/);
    assert.equal(copyOf(w).lines.length, lines, 'no line with a number already used was written');
    assert.equal(copyOf(w).sequence.ok, true);
    assert.ok(w.executor.stopped());
  } finally {
    await w.close();
  }
});

test('the command over stdio: keys makes the recorder\'s key file; seal and acknowledge take --offline only; status reads the files', async () => {
  const w = await world({ open: false, config: { recorder: RECORDER } });
  const config = ['--config', w.configPath];
  const keys = await run(['keys', ...config]);
  assert.equal(keys.code, 0, keys.stderr);
  assert.ok(existsSync(join(w.folder, 'keys', 'recorder.jwk')));
  const held = JSON.parse(readFileSync(join(w.folder, 'keys', 'recorder.jwk'), 'utf8')).keys;
  assert.deepEqual(held.map((k) => k.alg), ['Ed25519', 'ML-DSA-87', 'SLH-DSA-SHA2-256s']);
  const print = /fingerprint of its key set is ([A-Za-z0-9_-]{43})/.exec(keys.stderr);
  assert.ok(print, keys.stderr);
  assert.equal(print[1], (await statusFromFiles(w.settings, w.folder)).recorder.fingerprint);
  assert.equal(JSON.parse(keys.stdout).recorder, undefined, 'what goes into the permission is unchanged');
  assert.ok(!keys.stdout.includes('"d"'), 'no private key is printed');
  // A second run makes no new keys.
  const again = await run(['keys', ...config]);
  assert.equal(/fingerprint of its key set is ([A-Za-z0-9_-]{43})/.exec(again.stderr)[1], print[1]);
  const check = await run(['check', ...config]);
  assert.equal(JSON.parse(check.stdout).recorder.fingerprint, print[1]);
  // seal: only with --offline over stdio.
  const refused = await run(['seal', ...config]);
  assert.equal(refused.code, 2);
  assert.match(refused.stderr, /Over stdio there is no running executor to ask/);
  assert.ok(!existsSync(join(w.folder, 'book.jsonl')) || !bookText(w).includes('"seal"'));
  const named = await run(['seal', ...config, '--offline', '--agent', 'alpha']);
  assert.equal(named.code, 2);
  assert.match(named.stderr, /--agent is not taken/);
  const sealed = await run(['seal', ...config, '--offline']);
  assert.equal(sealed.code, 0, sealed.stderr);
  assert.match(sealed.stdout, /^Sealed: entry 1 of the book is the seal [A-Za-z0-9_-]{43}\.\n$/);
  assert.match(sealed.stderr, /it is refused if an executor is running on them/);
  const c = await checkBook(bookText(w), { issuerKeys: w.settings.agent.issuerKeys, sealKeys: [print[1]] });
  assert.equal(c.summary.problemFound, false);
  assert.equal(c.entries[1].kind, 'seal');
  // status: from the files.
  const status = await run(['status', ...config]);
  assert.equal(status.code, 0, status.stderr);
  const shown = JSON.parse(status.stdout);
  assert.equal(shown.from, 'files');
  assert.equal(shown.agent.lastSeal.fingerprint, c.entries[1].fingerprint);
  assert.equal(shown.agent.sound, true);
  // acknowledge: nothing waits.
  const nothing = await run(['acknowledge', ...config, '--offline']);
  assert.equal(nothing.code, 2);
  assert.match(nothing.stderr, /no call without a receipt to acknowledge/);
  const asked = await run(['acknowledge', ...config]);
  assert.equal(asked.code, 2);
  assert.match(asked.stderr, /Run the command with --offline/);
  // compare holds the seal against the recorder of the settings.
  const compared = await run(['compare', ...config]);
  assert.equal(compared.code, 0, compared.stdout + compared.stderr);
});

test('the command over stdio: a call that waits is acknowledged, or set aside, with --offline', async () => {
  const { w } = await worldWithCallUnderOldSlip();
  writeFileSync(w.configPath, JSON.stringify(w.settings));
  const config = ['--config', w.configPath];
  const stopped = await run(['stdio', ...config]);
  assert.equal(stopped.code, 2);
  assert.match(stopped.stderr, /not the one in force/);
  const asked = await run(['status', ...config]);
  assert.equal(asked.code, 1, 'a call that waits is told by the exit code too');
  const status = JSON.parse(asked.stdout);
  assert.equal(status.agent.receiptsMissing[0].call, 'lost-call');
  const done = await run(['acknowledge', ...config, '--offline']);
  assert.equal(done.code, 0, done.stderr);
  assert.match(done.stdout, /its receipt, written under the permission it was sent under, is [A-Za-z0-9_-]{43}\.\nThe executor takes calls again, once it is started\.\n$/);
  assert.equal(stubsOf(await checked(w)).length, 2);
  assert.equal((await checked(w)).summary.problemFound, false);
  // Set aside.
  await leaveCall(w, 'stray-call', 'A'.repeat(43));
  const waiting = await run(['acknowledge', ...config, '--offline']);
  assert.equal(waiting.code, 2);
  assert.match(waiting.stderr, /No call waiting can have a receipt written/);
  const aside = await run(['acknowledge', ...config, '--offline', '--set-aside', 'stray-call']);
  assert.equal(aside.code, 0, aside.stderr);
  assert.match(aside.stdout, /^Set aside, with no receipt: stray-call \(The book does not hold the permission/);
  assert.equal(stubsOf(await checked(w)).length, 2);
});

// --- after the review of 0.5.0 ---

test('the fixed texts a receipt names are these, letter for letter, with these fingerprints', async () => {
  const texts = [
    [ACKNOWLEDGED, 'The administrator acknowledged this call. The permission it was made under was not the one in force when this receipt was written.', ACKNOWLEDGED_FINGERPRINT],
    [WRITTEN_LATER, "This receipt was written later than its call, from the executor's own copy. Its date is the time the copy gives for the call.", WRITTEN_LATER_FINGERPRINT],
    [NO_RECORD_OF_OUTCOME, 'The executor recorded that it was sending this call, and has no record of its outcome.', NO_RECORD_OF_OUTCOME_FINGERPRINT],
    // The two a receipt written at a restart names, as published in 0.4.1.
    [WRITTEN_LATE, 'This receipt was written when the executor next started, from its own copy of what it had sent: the executor stopped before the receipt could be written. Its date is the time the call was sent; the countersignature is dated at the restart.', 'DIPtu-Cf-GQqigMV51m5ehHX2zdFIQJyKn2gRgsOFVU'],
    [OUTCOME_UNKNOWN, 'The executor stopped while this call was with the tool server, so its outcome is not known. The receipt was written when the executor next started, from its own copy of what it had sent.', 'eDbMc7F1z_1IkhM1smIPpHFEiknFYo3G8Shp3ErLzd8'],
  ];
  for (const [constant, text, print] of texts) {
    assert.equal(constant, text);
    assert.equal(await identifierFingerprint(text), print, text);
  }
});

test('one program at a time: a command with --offline beside a running executor is refused before it reads or writes, and the call in flight gets its true receipt', async () => {
  const w = await sealedWorld({ config: { timeout: 20000 } });
  let answer;
  try {
    await w.client.call('echo', {});
    // A call that takes three seconds and then answers.
    const inFlight = w.client.call('slow', { ms: 3000, tag: 'REAL-ANSWER' }, { timeout: 30000 });
    await until(() => copyOf(w).lines.at(-1).entry.kind === 'sending');
    const book = bookText(w);
    const copy = readFileSync(join(w.folder, 'copy.jsonl'), 'utf8');
    // Beside it, on the same files: the files opened as "seal --offline" opens them, and the command itself.
    const logs = [];
    await assert.rejects(openExecutor(w.settings, { root: w.folder, log: (e) => logs.push(e), offline: true }), (e) => e.code === 'LOCKED' && /An executor is running on the book/.test(e.message));
    assert.deepEqual(logs.filter((e) => e.event !== 'warning'), [], 'it wrote no receipt and no seal');
    const sealed = await run(['seal', '--config', w.configPath, '--offline']);
    assert.equal(sealed.code, 2);
    assert.match(sealed.stderr, /An executor is running on the book .* Nothing was read or written\./);
    const acknowledged = await run(['acknowledge', '--config', w.configPath, '--offline']);
    assert.equal(acknowledged.code, 2);
    assert.match(acknowledged.stderr, /An executor is running on the book/);
    // A second executor on the same files is refused in the same way.
    await assert.rejects(openExecutor(w.settings, { root: w.folder, log: () => {} }), (e) => e.code === 'LOCKED');
    assert.equal(bookText(w), book, 'the book is as it was');
    assert.equal(readFileSync(join(w.folder, 'copy.jsonl'), 'utf8'), copy, 'and so is the copy');
    // Reading is not writing: the status may be asked at any time.
    assert.equal((await statusFromFiles(w.settings, w.folder)).agent.receiptsAtNextStart, 1);
    answer = await inFlight;
    assert.equal(w.executor.stopped(), null, 'the running executor goes on');
    assert.ok((await w.client.call('echo', {})).result);
  } finally {
    await w.close();
  }
  assert.match(JSON.stringify(answer.result), /Done, slowly\. REAL-ANSWER/);
  const c = await checked(w);
  assert.equal(c.summary.problemFound, false);
  assert.deepEqual(c.entries.map((e) => e.kind), ['slip', 'stub', 'stub', 'stub']);
  const d = docs(c.entries[2]);
  assert.equal(d[RESULT_DOCUMENT], await argumentsFingerprint(answer.result), 'the receipt names what came back');
  assert.equal(d['provared.error'], undefined);
  assert.equal(d[WRITTEN_LATE_DOCUMENT], undefined);
  assert.deepEqual(copyOf(w).lines.map((l) => [l.entry.kind, l.entry.outcome ?? null]), [['sending', null], ['done', 'answer'], ['sending', null], ['done', 'answer'], ['sending', null], ['done', 'answer']]);
  assert.ok(!w.logs.some((e) => ['book-not-written', 'copy-not-written', 'book-changed'].includes(e.event)));
  // Once the executor has ended, its lock is gone: the command works.
  const after = await run(['seal', '--config', w.configPath, '--offline']);
  assert.equal(after.code, 0, after.stderr);
  // And an executor opened and not yet closed holds it; closed, it gives it up.
  const first = await offline(w);
  await assert.rejects(offline(w), (e) => e.code === 'LOCKED');
  await first.close();
  const second = await offline(w);
  await second.close();
  // An opening that fails gives the lock up too.
  rmSync(join(w.folder, 'slip.json'));
  await assert.rejects(offline(w), /slip .* is missing/);
  await assert.rejects(offline(w), /slip .* is missing/, 'not: locked');
});

test('acknowledge says what it did where it could not do all of it, and goes on to the calls it can', async () => {
  const w = await sealedWorld();
  await w.client.call('echo', {});
  const first = w.executor.slip.fingerprint;
  await w.close();
  // Three calls wait: one the library will refuse (dated before the receipt ahead of it), one that can have its receipt, one to set aside.
  await leaveCall(w, 'early-call', first, (l) => ({ ...l, when: new Date(Date.now() - 30000).toISOString() }));
  await leaveCall(w, 'lost-call', first);
  await leaveCall(w, 'aside-call', 'A'.repeat(43));
  await renewSlip(w);
  const done = await run(['acknowledge', '--config', w.configPath, '--offline', '--set-aside', 'aside-call']);
  assert.equal(done.code, 1, done.stderr);
  assert.match(done.stdout, /^Set aside, with no receipt: aside-call /m);
  assert.match(done.stdout, /^Sent at \S+ \(slow\): its receipt, written under the permission it was sent under, is [A-Za-z0-9_-]{43}\.$/m, 'the call after the one that failed got its receipt');
  assert.match(done.stdout, /^Not done: early-call \(sent at \S+, slow\): The stub was not written: with it, the book would not pass its check\.$/m);
  assert.match(done.stdout, /^Still waiting: early-call: can be acknowledged$/m);
  assert.doesNotMatch(done.stdout + done.stderr, /nothing was acknowledged/);
  const call = await identifierFingerprint('lost-call');
  assert.equal(stubsOf(await checked(w)).filter((s) => docs(s)[CALL_DOCUMENT] === call).length, 1);
  assert.deepEqual(copyOf(w).lines.slice(-2).map((l) => [l.entry.kind, l.entry.call]), [['set-aside', 'aside-call'], ['done', 'lost-call']]);
  // In a program, the same: what was done, what was not and why, and what still waits.
  const ex = await offline(w);
  const again = await ex.acknowledge();
  assert.deepEqual([again.written, again.setAside], [[], []]);
  assert.deepEqual(again.failed.map((f) => [f.call, f.tool]), [['early-call', 'slow']]);
  assert.deepEqual(again.remaining.map((p) => p.call), ['early-call']);
  await ex.close();
});

test('seal, acknowledge, status and compare refuse an option they do not know, and then do nothing', async () => {
  const { w } = await worldWithCallUnderOldSlip();
  const config = ['--config', w.configPath];
  const book = existsSync(join(w.folder, 'book.jsonl')) ? bookText(w) : '';
  const copy = readFileSync(join(w.folder, 'copy.jsonl'), 'utf8');
  // The option to set a call aside, mistyped: the call must not be given a receipt instead.
  for (const args of [
    ['acknowledge', ...config, '--offline', '--setaside', 'lost-call'],
    ['acknowledge', ...config, '--ofline'],
    ['seal', ...config, '--offline', '--now'],
    ['status', ...config, '--offlin'],
    ['compare', ...config, '--sealers', 'x'],
  ]) {
    const r = await run(args);
    assert.equal(r.code, 2, args.join(' '));
    assert.match(r.stderr, new RegExp(`${args[0]} takes no "--[a-z]+"; only .*Nothing was done\\.`), args.join(' '));
    assert.equal(r.stdout, '');
  }
  assert.equal(bookText(w), book);
  assert.equal(readFileSync(join(w.folder, 'copy.jsonl'), 'utf8'), copy);
});

test('a key file the executor held before countersigns the receipt of a call made under a permission that names it; without it the call can only be set aside', async () => {
  const w = await sealedWorld();
  await w.client.call('echo', {});
  const first = w.executor.slip.fingerprint;
  await w.close();
  await leaveCall(w, 'old-keys-call', first);
  // The executor's keys are changed; the key file it held is kept under another name.
  renameSync(join(w.folder, 'keys', 'executor.jwk'), join(w.folder, 'keys', 'executor-before.jwk'));
  w.executorKeys = await makeKeyFile(join(w.folder, 'keys', 'executor.jwk'), 'agent');
  await renewSlip(w);
  // Not named in the settings: no receipt.
  const without = await offline(w);
  assert.match((await without.report()).agent.receiptsMissing[0].problem, /name that file in "executor\.formerKeys"/);
  await without.close();
  // Named.
  w.settings.executor = { ...w.settings.executor, formerKeys: ['keys/executor-before.jwk'] };
  const ex = await offline(w);
  const waiting = (await ex.report()).agent.receiptsMissing;
  assert.deepEqual([waiting[0].usable, waiting[0].problem, waiting[0].formerKeys], [true, null, true]);
  const done = await ex.acknowledge();
  assert.deepEqual([done.written.length, done.written[0].formerKeys, done.failed.length, done.remaining.length], [1, true, 0, 0]);
  const c = await checked(w);
  assert.equal(c.summary.problemFound, false);
  const stub = stubsOf(c).at(-1);
  assert.equal(stub.content.slip, first);
  assert.equal(stub.countersignature.state, 'valid', 'countersigned with the keys that permission names for the executor');
  assert.equal(docs(stub)[ACKNOWLEDGED_DOCUMENT], ACKNOWLEDGED_FINGERPRINT);
  assert.equal(copyOf(w).lines.at(-1).entry.formerKeys, true);
  await ex.close();
  // The executor's present keys countersign everything else.
  await openWorld(w);
  try {
    assert.ok((await w.client.call('echo', {})).result);
    const after = await checked(w);
    assert.equal(after.summary.problemFound, false);
    assert.equal(stubsOf(after).at(-1).countersignature.state, 'valid');
  } finally {
    await w.close();
  }
  // The settings: a list of paths, each a key file that is there.
  assert.ok(readSettings({ ...w.settings, executor: { ...w.settings.executor, formerKeys: 'keys/executor-before.jwk' } }, w.folder).problems.some((p) => /^executor\.formerKeys: must be a list/.test(p)));
  const missing = await checkConfig({ ...w.settings, executor: { ...w.settings.executor, formerKeys: ['keys/none.jwk'] } }, w.folder);
  assert.ok(missing.problems.some((p) => /^executor\.formerKeys\[0\]: the key file .* does not exist/.test(p)), missing.problems.join(' | '));
});

test('compare: calls set aside alone end with code 3, anything else with 1; and it says which recorder it expected a seal to be signed by', async () => {
  const w = await sealedWorld();
  await w.client.call('echo', {});
  await w.close();
  const config = ['--config', w.configPath];
  const ex = await offline(w);
  await ex.seal();
  await ex.close();
  const agreed = await run(['compare', ...config]);
  assert.equal(agreed.code, 0, agreed.stdout + agreed.stderr);
  assert.deepEqual(JSON.parse(agreed.stdout).book.sealersExpected, w.sealKeys);
  // The recorder may be named by the fingerprint of its key set, as for the checker, where the key file is not to hand.
  renameSync(join(w.folder, 'keys', 'recorder.jwk'), join(w.folder, 'keys', 'recorder-away.jwk'));
  const unnamed = await run(['compare', ...config]);
  assert.equal(unnamed.code, 0);
  assert.equal(JSON.parse(unnamed.stdout).book.sealersExpected, null, 'the answer says that the seal\'s keys were compared with nothing');
  const named = await run(['compare', ...config, '--sealer', w.sealKeys[0]]);
  assert.equal(named.code, 0);
  assert.deepEqual(JSON.parse(named.stdout).book.sealersExpected, w.sealKeys);
  const other = await run(['compare', ...config, '--sealer', 'A'.repeat(43)]);
  assert.equal(other.code, 1, 'a seal signed by another recorder than the one named');
  assert.equal(JSON.parse(other.stdout).summary.bookProblem, true);
  assert.equal((await run(['compare', ...config, '--sealer', 'short'])).code, 2);
  // Another recorder's key file in the settings' place: the seal in the book is not that recorder's.
  await makeKeyFile(join(w.folder, 'keys', 'recorder.jwk'), 'recorder');
  const replaced = await run(['compare', ...config]);
  assert.equal(replaced.code, 1);
  assert.equal(JSON.parse(replaced.stdout).summary.bookProblem, true);
  assert.notDeepEqual(JSON.parse(replaced.stdout).book.sealersExpected, w.sealKeys);
  rmSync(join(w.folder, 'keys', 'recorder.jwk'));
  renameSync(join(w.folder, 'keys', 'recorder-away.jwk'), join(w.folder, 'keys', 'recorder.jwk'));
  // A call set aside: code 3, and the answer says that it is the only disagreement.
  await leaveCall(w, 'stray-call', 'A'.repeat(43));
  assert.equal((await run(['acknowledge', ...config, '--offline', '--set-aside', 'stray-call'])).code, 0);
  const aside = await run(['compare', ...config]);
  assert.equal(aside.code, 3);
  assert.deepEqual([JSON.parse(aside.stdout).summary.agree, JSON.parse(aside.stdout).summary.onlySetAside], [false, true]);
  // A new disagreement beside it: code 1.
  const book = bookText(w).split('\n');
  writeFileSync(join(w.folder, 'short.jsonl'), `${book[0]}\n`);
  const more = await run(['compare', ...config, '--book', join(w.folder, 'short.jsonl')]);
  assert.equal(more.code, 1);
  assert.deepEqual([JSON.parse(more.stdout).summary.agree, JSON.parse(more.stdout).summary.onlySetAside, JSON.parse(more.stdout).summary.missingFromBook], [false, false, 1]);
});

test('seal on a timer: a stop that comes while a seal waits its turn leaves no timer behind', async () => {
  const w = await sealedWorld({ config: { recorder: { ...RECORDER, sealEvery: 1000 }, timeout: 20000 } });
  const old = w.logs;
  try {
    await until(() => old.some((e) => e.event === 'sealed'), { timeout: 20000 });
    // A call holds the agent's turn; the timer's next seal waits behind it.
    w.client.call('slow', { ms: 15000 }, { timeout: 30000 }).catch(() => {});
    await until(() => existsSync(join(w.folder, 'copy.jsonl')) && copyOf(w).lines.at(-1)?.entry.kind === 'sending');
    await pause(1500);
  } finally {
    // The stop comes now, while that seal waits.
    await w.close();
  }
  const sealsThen = old.filter((e) => e.event === 'sealed').length;
  // The call's receipt was written at the stop, and the seal that was waiting its turn behind it after that.
  assert.deepEqual((await checked(w)).entries.map((e) => e.kind), ['slip', 'seal', 'stub', 'seal']);
  // Another executor takes the files and writes on. A timer left behind by the first would trip over what it wrote.
  await openWorld(w);
  try {
    await w.client.call('echo', {});
    await pause(4000);
    assert.ok((await w.client.call('echo', {})).result);
  } finally {
    await w.close();
  }
  assert.equal(old.filter((e) => e.event === 'sealed').length, sealsThen);
  // The first executor's log goes where the second's does: neither asked for a seal it could not have.
  assert.deepEqual([...old, ...w.logs].filter((e) => ['not-sealed', 'book-changed', 'book-not-written'].includes(e.event)), [], 'the executor that ended asked for no further seal');
  assert.equal((await checked(w)).summary.problemFound, false);
});

test('a seal does not hold up the rest of the program while it is signed', async () => {
  const w = await sealedWorld({ open: false });
  const ex = await offline(w);
  let ticks = 0;
  const timer = setInterval(() => (ticks += 1), 10);
  const started = Date.now();
  await ex.seal();
  const took = Date.now() - started;
  clearInterval(timer);
  await ex.close();
  // A timer of 10 ms goes on firing while the seal is signed: at least a quarter of the times it could.
  assert.ok(ticks >= took / 40, `${ticks} ticks in ${took} ms`);
});
