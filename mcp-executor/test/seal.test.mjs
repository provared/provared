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
const { CALL_DOCUMENT, TOOL_DOCUMENT, RESULT_DOCUMENT, WRITTEN_LATE_DOCUMENT, OUTCOME_UNKNOWN_ACKNOWLEDGED, WRITTEN_ON_ACKNOWLEDGEMENT, openExecutor, readSettings, statusFromFiles } = await import('../executor.mjs');
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
  // The executor starts on a sealed book, and writes on after the seal.
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
});

test('seal: a book sealed with other keys than the settings\' recorder does not pass its check, and the executor does not open on it', async () => {
  const w = await sealedWorld({ open: false });
  const ex = await offline(w);
  await ex.seal();
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
    // Idle: two more rounds pass, and no seal is written over a seal.
    await pause(2500);
    assert.equal(sealsOf(await checked(w)).length, 2);
  } finally {
    await w.close();
  }
  // After the executor has ended, its timer writes nothing more.
  const size = statSync(join(w.folder, 'book.jsonl')).size;
  await pause(1500);
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
  assert.ok(Math.abs(Date.parse(stub.content.when) - Date.parse(sentAt)) < 1000, 'dated when the call was sent');
  const line = JSON.parse(bookText(w).split('\n')[stub.index]);
  const countersignedAt = JSON.parse(Buffer.from(line.countersignature.payload, 'base64url').toString('utf8')).when;
  assert.ok(Date.parse(countersignedAt) >= Date.parse(stub.content.when), 'countersigned at the acknowledgement, not before the call was sent');
  assert.equal(stub.content.with, 'executor');
  const d = docs(stub);
  assert.equal(d['provared.error'], await identifierFingerprint(OUTCOME_UNKNOWN_ACKNOWLEDGED));
  assert.equal(d[WRITTEN_LATE_DOCUMENT], await identifierFingerprint(WRITTEN_ON_ACKNOWLEDGEMENT));
  assert.equal(d[CALL_DOCUMENT], await identifierFingerprint('lost-call'));
  assert.equal(stub.countersignature.state, 'valid', 'countersigned by the executor');
  const last = copyOf(w).lines.at(-1).entry;
  assert.deepEqual([last.kind, last.call, last.outcome, last.stub], ['done', 'lost-call', 'acknowledged-outcome-unknown', stub.fingerprint]);
  // Nothing is left to acknowledge, and the book can be sealed again.
  await assert.rejects(ex.acknowledge(), /no call without a receipt/);
  await ex.seal();
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
  assert.equal(copyOf(w).lines.at(-1).entry.outcome, 'acknowledged');
});

test('acknowledge: never two receipts for one call, also where the copy could not be written after the receipt was', async () => {
  const { w } = await worldWithCallUnderOldSlip();
  const ex = await offline(w);
  // The copy cannot be written: the receipt goes into the book, and the line saying so does not go into the copy.
  const at = join(w.folder, 'copy.jsonl');
  renameSync(at, `${at}.away`);
  mkdirSync(at);
  await assert.rejects(ex.acknowledge(), /copy .* is not as the executor left it/);
  rmdirSync(at);
  renameSync(`${at}.away`, at);
  const call = await identifierFingerprint('lost-call');
  const named = async () => stubsOf(await checked(w)).filter((s) => docs(s)[CALL_DOCUMENT] === call);
  assert.equal((await named()).length, 1, 'the receipt is in the book');
  assert.equal((await ex.report()).agent.receiptsMissing.length, 1, 'and the call still waits');
  // Trying again finds the receipt in the book, and writes no second one.
  const again = await ex.acknowledge();
  assert.deepEqual(again.written.map((x) => [x.call, x.found]), [['lost-call', true]]);
  assert.equal((await named()).length, 1);
  assert.equal(again.written[0].stub, (await named())[0].fingerprint);
  assert.equal(copyOf(w).lines.at(-1).entry.outcome, 'found-in-book');
  // And so does a new start: the call is finished.
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
  await assert.rejects(vx.acknowledge(), /would not pass its check/);
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
  assert.match(sealed.stderr, /no executor may be running on them/);
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
  const status = JSON.parse((await run(['status', ...config])).stdout);
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
