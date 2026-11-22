// After the narrow re-check of step 3.4 (findings F1 to F5): with a copy,
// only the copy's own "set-aside" line sets a call aside; a journal line from
// before the copy whose call the book holds the stub for is passed over, as
// before the gateway had keys; "compare" checks the countersignature of a
// stub written at a later start; a found stub needs the gateway's
// countersignature wherever its slip names the gateway's id with keys; and
// "acknowledge" looks at the book again before each stub.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { appendFileSync, mkdirSync, readFileSync, renameSync, rmdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { checkBook, countersign, entryLine, generateKeySet, identifierFingerprint, signerFromKey, writeStub } = await import('provared');
const { world, call, signSlip, SECRET } = await import('./world.mjs');
const { CALL_DOCUMENT } = await import('../gateway.mjs');
const { openGateway } = await import('./limits.mjs');
const { compareCopyWithBook } = await import('../compare.mjs');
const { loadCopyKey, readCopy, openCopy } = await import('../copy.mjs');

async function gatewayKeys() {
  const set = await generateKeySet();
  return { keys: set.keys, privateKeys: [signerFromKey('Ed25519', set.privateKeys[0], set.keys[0]), signerFromKey('ML-DSA-87', set.privateKeys[1], set.keys[1])] };
}

const SERVICES = (keys) => [{ id: 'gateway', name: 'The test gateway', keys }, { id: 'tickets', name: 'The ticket system' }, { id: 'patch', name: 'The patch service' }];

/** A world whose gateway has its own keys, and whose slip names the gateway in "with". */
async function cw(o = {}) {
  const own = o.own ?? (await gatewayKeys());
  const w = await world({
    ...o,
    slip: { with: SERVICES(own.keys), requires: o.requires ?? [{ need: 'countersignature', action: 'provared.data.read' }] },
    config: { gateway: { name: 'The test gateway', keySet: own.keys, privateKeys: own.privateKeys } },
  });
  return { ...w, own, opts: w.gateway.checkOptions('patching'), at: w.gateway.copyOf('patching') };
}

/** A world with the given calls through the gateway, closed: its files are as a stop leaves them. */
async function afterCalls(w, paths = ['/tickets/api/now/table/a']) {
  try {
    for (const p of paths) assert.equal((await w.call('GET', p)).status, 200);
  } finally {
    await w.close();
  }
  return w.at ? { ...w, key: loadCopyKey(w.at.copyKey, { create: false }) } : w;
}

const journalOf = (w) => `${w.bookPath}.journal`;
function tagged(w, value) {
  const key = Buffer.from(readFileSync(`${w.bookPath}.journal-key`, 'utf8').trim(), 'base64url');
  const text = JSON.stringify(value);
  return `${createHmac('sha256', key).update(`patching\n${text}`).digest('base64url')} ${text}`;
}

/** A "sending" line in the copy, with no receipt, and its journal line where "journal" is "valid". */
async function stoppedMidCall(w, id, { journal = 'valid' } = {}) {
  const read = readCopy(w.at.copy, w.key, 'patching');
  const slip = read.lines[0].entry.slip;
  const when = new Date().toISOString();
  const details = [
    { name: 'provared.http-request', sha256: await identifierFingerprint(`request ${id}`) },
    { name: CALL_DOCUMENT, sha256: await identifierFingerprint(id) },
  ];
  openCopy(w.at.copy, w.key, 'patching', read.next).note({ kind: 'sending', call: id, when, slip, upstream: 'tickets', action: 'provared.data.delete', with: 'gateway', details });
  const line = { sending: id, when, slip, action: 'provared.data.delete', with: 'gateway', details };
  if (journal === 'valid') appendFileSync(journalOf(w), `${tagged(w, line)}\n`);
  return { slip, details, when, line };
}

/** A journal line, under the journal key, for a call with no receipt, made from the first line the journal holds (a gateway without a copy). */
async function journalOnlyCall(w, id) {
  const first = JSON.parse(readFileSync(journalOf(w), 'utf8').split('\n')[0].slice(44));
  const line = { sending: id, when: new Date().toISOString(), slip: first.slip, action: first.action, ...(first.with !== undefined ? { with: first.with } : {}), details: [{ name: 'provared.http-request', sha256: await identifierFingerprint(`request ${id}`) }, { name: CALL_DOCUMENT, sha256: await identifierFingerprint(id) }] };
  appendFileSync(journalOf(w), `${tagged(w, line)}\n`);
  return line;
}

/** The gateway started again on the world's files (or other settings), listening. */
async function again(w, config = w.config) {
  const logs = [];
  const g = await openGateway(config, { root: w.folder, log: (e) => logs.push(e) });
  const at = await g.listen({ host: '127.0.0.1', port: 0 });
  return { g, logs, call: (method, path, more = {}) => call(at.port, method, path, { secret: SECRET, ...more }) };
}

/** A stub signed with the agent's keys, put at the end of the book, countersigned with "countersignWith" where given. */
async function forge(w, fields, countersignWith) {
  const checked = await checkBook(readFileSync(w.bookPath, 'utf8'), w.opts);
  const last = checked.entries.filter((e) => e.kind === 'stub' && e.content.slip === fields.slip).at(-1);
  const made = await writeStub({ ...fields, after: last ? { seq: last.content.seq, fingerprint: last.fingerprint } : null }, w.config.agents.patching.privateKeys);
  appendFileSync(w.bookPath, `${entryLine({ stub: made.record, ...(countersignWith ? { countersignature: await countersign(made.record, countersignWith) } : {}) })}\n`);
  return made;
}

/** The fields of a stub for a call the copy shows as sent: the call itself, then an error. */
async function sameCall(slip, details, when) {
  return { slip, action: 'provared.data.delete', with: 'gateway', when: Date.parse(when), details: [...details, { name: 'provared.error', sha256: await identifierFingerprint('the outcome is not known') }] };
}

const compareOf = (w) => compareCopyWithBook({ copyPath: w.at.copy, copyKey: w.key, name: 'patching', service: w.at.service, book: readFileSync(w.bookPath, 'utf8'), options: w.opts });
const copyEntries = (w) => readCopy(w.at.copy, w.key, 'patching').lines.map((l) => l.entry);
const stubsIn = async (w, opts = w.opts) => (await checkBook(readFileSync(w.bookPath, 'utf8'), opts)).entries.filter((e) => e.kind === 'stub');
const stubsFor = async (w, id) => {
  const fp = await identifierFingerprint(id);
  return (await stubsIn(w)).filter((e) => e.content.details.some((d) => d.name === CALL_DOCUMENT && d.sha256 === fp));
};

/** The settings with the gateway's keys replaced by "own", and a new slip naming them. */
async function rotated(w, own, requires) {
  const slip = await signSlip({ passkey: w.passkey, agentKeys: w.agentSet.keys, with: SERVICES(own.keys), requires });
  const slipPath = join(w.folder, 'slip-after-the-change.json');
  writeFileSync(slipPath, JSON.stringify(slip));
  return { ...w.config, gateway: { name: 'The test gateway', keySet: own.keys, privateKeys: own.privateKeys }, agents: { patching: { ...w.config.agents.patching, slip: slipPath } } };
}

test('F1: with a copy, a call on the set-aside list beside the journal that the copy shows open is not set aside: the agent is stopped, the call listed, the reason logged, nothing written to the copy', async () => {
  for (const journal of ['none', 'valid']) {
    const w = await afterCalls(await cw({ requires: [{ need: 'countersignature' }] }));
    const id = `held-call-listed-aside-${journal}`;
    await stoppedMidCall(w, id, { journal });
    // A line in the list beside the journal, under the journal key: what whoever holds that key could add.
    appendFileSync(`${w.bookPath}.journal-set-aside`, `${tagged(w, { setAside: id })}\n`);
    const copyBefore = copyEntries(w).length;
    const r = await again(w);
    try {
      const status = (await r.g.status()).agents.patching;
      assert.notEqual(status.stopped, null, `${journal}: the agent is stopped`);
      const waiting = status.receiptsMissing.find((l) => l.call === id);
      assert.ok(waiting, `${journal}: the call is listed for the administrator`);
      assert.equal(waiting.usable, true);
      const event = r.logs.find((e) => e.event === 'set-aside-not-in-copy' && e.call === id);
      assert.ok(event, `${journal}: the log names the reason`);
      assert.match(event.reason, /does not show it set aside/);
      assert.equal(copyEntries(w).length, copyBefore, 'nothing is written to the copy on the journal\'s word');
      assert.equal((await r.call('GET', '/tickets/api/now/table/b')).status, 503);
      const result = await compareOf(w);
      assert.deepEqual(result.unfinished.map((u) => u.call), [id]);
      assert.equal(result.summary.setAside, 0);
      // The administrator sets it aside: now the copy says so, and the next start takes it as set aside.
      await r.g.acknowledge('patching', { setAside: [id] });
      assert.deepEqual([copyEntries(w).at(-1).kind, copyEntries(w).at(-1).call], ['set-aside', id]);
    } finally {
      await r.g.close();
    }
    const s = await again(w);
    try {
      assert.equal((await s.g.status()).agents.patching.stopped, null, `${journal}: set aside by the copy's own line`);
      assert.ok(!s.logs.some((e) => e.event === 'set-aside-not-in-copy'));
    } finally {
      await s.g.close();
    }
  }
});

test('F1: without a copy, the set-aside list beside the journal still sets a call aside, as before (X423)', async () => {
  const w = await afterCalls(await world({}));
  const line = await journalOnlyCall(w, 'journal-only-call-aside');
  const first = await again(w);
  try {
    assert.notEqual((await first.g.status()).agents.patching.stopped, null, 'a journal line with no stub stops the agent');
  } finally {
    await first.g.close();
  }
  appendFileSync(`${w.bookPath}.journal-set-aside`, `${tagged(w, { setAside: line.sending })}\n`);
  const r = await again(w);
  try {
    assert.equal((await r.g.status()).agents.patching.stopped, null);
  } finally {
    await r.g.close();
  }
});

test('F2: a gateway first given keys after calls were made passes over the journal lines whose stubs the book holds, with a new slip naming it or not; nothing is written or countersigned for them', async () => {
  for (const named of [false, true]) {
    const w = await afterCalls(await world({}), ['/tickets/api/now/table/a', '/tickets/api/now/table/b']);
    const opts = w.gateway.checkOptions('patching');
    const stubsBefore = await stubsIn(w, opts);
    assert.equal(stubsBefore.length, 2);
    const journalLines = readFileSync(journalOf(w), 'utf8').trim().split('\n').length;
    assert.ok(journalLines >= 2, 'the journal holds the last run\'s calls');
    const own = await gatewayKeys();
    const config = named ? await rotated(w, own, [{ need: 'countersignature' }]) : { ...w.config, gateway: { name: 'The test gateway', keySet: own.keys, privateKeys: own.privateKeys } };
    const r = await again(w, config);
    try {
      const status = (await r.g.status()).agents.patching;
      assert.equal(status.stopped, null, `named ${named}: not stopped`);
      assert.deepEqual(status.receiptsMissing, []);
      assert.equal(r.logs.filter((e) => e.event === 'receipt-found' && e.inCopy === false).length, 2);
      assert.ok(!r.logs.some((e) => e.event === 'journal-line-not-in-copy'));
      const at = r.g.copyOf('patching');
      const entries = readCopy(at.copy, loadCopyKey(at.copyKey, { create: false }), 'patching').lines;
      assert.equal(entries.length, 0, 'nothing is written to the copy for them');
      const after = await stubsIn(w, opts);
      assert.deepEqual(after.map((e) => e.fingerprint), stubsBefore.map((e) => e.fingerprint), 'no stub written');
      assert.ok(after.every((e) => e.countersignature?.state !== 'valid'), 'nothing countersigned');
      assert.equal(readFileSync(journalOf(w), 'utf8'), '', 'a clean start empties the journal');
    } finally {
      await r.g.close();
    }
  }
});

test('F2: where the copy is lost, the journal lines whose countersigned stubs the book holds are passed over; one whose stub is one-sided under a slip naming the gateway can still only be set aside', async () => {
  const w = await afterCalls(await cw({ requires: [{ need: 'countersignature' }] }), ['/tickets/api/now/table/a', '/tickets/api/now/table/b']);
  const { slip, details, when, line } = await stoppedMidCall(w, 'one-sided-before-the-loss');
  await forge(w, await sameCall(slip, details, when));
  // The copy is taken away (its key stays).
  renameSync(w.at.copy, `${w.at.copy}.lost`);
  const r = await again(w);
  try {
    const status = (await r.g.status()).agents.patching;
    assert.equal(r.logs.filter((e) => e.event === 'receipt-found' && e.inCopy === false).length, 2, 'the two calls sent are passed over');
    assert.deepEqual(status.receiptsMissing.map((l) => [l.call, l.usable]), [[line.sending, false]], 'the one-sided stub does not pass');
    assert.ok(r.logs.some((e) => e.event === 'journal-line-not-in-copy' && e.call === line.sending));
    assert.ok(r.logs.some((e) => e.event === 'warning' && /does not know/.test(e.message)), 'the start still warns of receipts the copy does not know');
    assert.equal(copyEntries(w).length, 0, 'nothing is written to the copy');
  } finally {
    await r.g.close();
  }
});

test('F1: with a copy, a line the copy shows set aside stays set aside where the list beside the journal is gone', async () => {
  const w = await afterCalls(await cw());
  const slip = readCopy(w.at.copy, w.key, 'patching').lines[0].entry.slip;
  // A journal line for a call nobody sent: listed, and set aside by the administrator.
  const forged = { sending: 'never-sent-by-anyone', when: new Date().toISOString(), slip, action: 'provared.data.delete', with: 'gateway', details: [{ name: 'provared.http-request', sha256: await identifierFingerprint('x') }, { name: CALL_DOCUMENT, sha256: await identifierFingerprint('never-sent-by-anyone') }] };
  appendFileSync(journalOf(w), `${tagged(w, forged)}\n`);
  const journalBefore = readFileSync(journalOf(w), 'utf8');
  const r = await again(w);
  try {
    assert.notEqual((await r.g.status()).agents.patching.stopped, null);
    await r.g.acknowledge('patching', { setAside: ['never-sent-by-anyone'] });
  } finally {
    await r.g.close();
  }
  // The journal put back as it was before (no line in it says the call was set aside), and the list beside it gone.
  writeFileSync(journalOf(w), journalBefore);
  renameSync(`${w.bookPath}.journal-set-aside`, `${w.bookPath}.journal-set-aside.gone`);
  const s = await again(w);
  try {
    assert.equal((await s.g.status()).agents.patching.stopped, null, 'the copy\'s own "set-aside" line decides');
    assert.ok(!s.logs.some((e) => e.event === 'journal-line-not-in-copy'));
  } finally {
    await s.g.close();
  }
});

test('F2: where the lost copy leaves only calls whose countersigned stubs the book holds, the gateway starts with the agent not stopped', async () => {
  const w = await afterCalls(await cw({ requires: [{ need: 'countersignature' }] }), ['/tickets/api/now/table/a', '/tickets/api/now/table/b']);
  const stubs = (await stubsIn(w)).length;
  renameSync(w.at.copy, `${w.at.copy}.lost`);
  const r = await again(w);
  try {
    assert.equal((await r.g.status()).agents.patching.stopped, null);
    assert.equal(r.logs.filter((e) => e.event === 'receipt-found' && e.inCopy === false).length, 2);
    assert.equal((await stubsIn(w)).length, stubs);
  } finally {
    await r.g.close();
  }
});

test('F3: compare checks the countersignature of a stub written at a later start, where the copy\'s "done" line says it was countersigned', async () => {
  for (const countersigned of [false, true]) {
    const w = await afterCalls(await cw({ requires: [{ need: 'countersignature', action: 'provared.data.read' }] }));
    const id = `late-call-${countersigned}`;
    const { slip, details, when } = await stoppedMidCall(w, id);
    // The book file could not be written: the copy's "done" line names no stub, and says the call was countersigned.
    const outcome = [{ name: 'provared.http-response', sha256: await identifierFingerprint('what came back') }];
    openCopy(w.at.copy, w.key, 'patching', readCopy(w.at.copy, w.key, 'patching').next).note({ kind: 'done', call: id, when: new Date().toISOString(), outcome: 'answer', countersigned: true, countersignature: 'B'.repeat(43), documents: outcome });
    await forge(w, await sameCall(slip, details, when), countersigned ? w.own.privateKeys : undefined);
    const result = await compareOf(w);
    if (countersigned) {
      assert.deepEqual(result.matched.filter((m) => m.call === id).map((m) => [m.countersignature, m.note]), [['valid', 'written at a later start']]);
      assert.equal(result.summary.agree, true, JSON.stringify(result.summary));
    } else {
      assert.deepEqual(result.countersignatures.map((c) => [c.call, c.problem]), [[id, 'missing']]);
      assert.equal(result.matched.filter((m) => m.call === id).length, 0);
      assert.equal(result.summary.bookWithinSlips, true, 'the slip asks for no countersignature for this action: only the copy shows it');
      assert.equal(result.summary.agree, false);
    }
  }
});

test('F4: after the gateway\'s keys are changed, a one-sided stub found for a call sent under the earlier slip does not settle it; one countersigned with the earlier keys does', async () => {
  for (const how of ['one-sided', 'countersigned']) {
    const w = await afterCalls(await cw({ requires: [{ need: 'countersignature', action: 'provared.data.read' }] }));
    const id = `held-before-the-change-${how}`;
    const { slip, details, when } = await stoppedMidCall(w, id);
    await forge(w, await sameCall(slip, details, when), how === 'countersigned' ? w.own.privateKeys : undefined);
    const r = await again(w, await rotated(w, await gatewayKeys(), [{ need: 'countersignature', action: 'provared.data.read' }]));
    try {
      const status = (await r.g.status()).agents.patching;
      if (how === 'one-sided') {
        assert.ok(r.logs.some((e) => e.event === 'receipt-not-matching' && e.call === id));
        assert.ok(!r.logs.some((e) => e.event === 'receipt-found' && e.call === id));
        assert.notEqual(status.stopped, null);
        assert.deepEqual(status.receiptsMissing.map((l) => [l.call, l.usable]), [[id, false]]);
        assert.match(status.receiptsMissing[0].problem, /without a valid countersignature/);
      } else {
        assert.ok(r.logs.some((e) => e.event === 'receipt-found' && e.call === id));
        assert.equal(status.stopped, null);
        assert.equal(copyEntries(w).at(-1).countersigned, true);
      }
    } finally {
      await r.g.close();
    }
  }
});

test('F4: an honest acknowledgement after the gateway\'s keys are changed writes a one-sided stub for a call sent under the earlier slip', async () => {
  const w = await afterCalls(await cw({ requires: [{ need: 'countersignature' }] }));
  const id = 'held-honest-before-the-change';
  await stoppedMidCall(w, id);
  const r = await again(w, await rotated(w, await gatewayKeys(), [{ need: 'countersignature' }]));
  try {
    const ack = await r.g.acknowledge('patching');
    assert.deepEqual(ack.written.map((x) => x.countersigned), [false]);
    const [stub] = await stubsFor(w, id);
    assert.equal(stub.countersignature?.state ?? 'absent', 'absent');
    assert.equal((await checkBook(readFileSync(w.bookPath, 'utf8'), w.opts)).summary.withinSlips, false, 'the earlier slip requires the countersignature');
    assert.equal((await r.g.status()).agents.patching.stopped, null);
  } finally {
    await r.g.close();
  }
});

test('F5: an acknowledgement tried again after the journal could not be written writes no second stub; once the journal can be written, the stub in the book settles the call', async () => {
  const w = await afterCalls(await cw({ requires: [{ need: 'countersignature' }] }));
  const id = 'held-call-acknowledged-twice';
  await stoppedMidCall(w, id);
  const r = await again(w);
  try {
    // The journal is made something that cannot be written: a folder in its place.
    renameSync(journalOf(w), `${journalOf(w)}.moved`);
    mkdirSync(journalOf(w));
    for (let i = 0; i < 2; i++) await assert.rejects(r.g.acknowledge('patching'));
    assert.equal((await stubsFor(w, id)).length, 1, 'one stub for the call');
    assert.deepEqual((await r.g.status()).agents.patching.receiptsMissing.map((l) => l.call), [id], 'the call still waits');
    rmdirSync(journalOf(w));
    renameSync(`${journalOf(w)}.moved`, journalOf(w));
    const ack = await r.g.acknowledge('patching');
    assert.deepEqual(ack.written.map((x) => [x.found, x.countersigned]), [[true, true]]);
    const stubs = await stubsFor(w, id);
    assert.equal(stubs.length, 1);
    const last = copyEntries(w).at(-1);
    assert.deepEqual([last.kind, last.outcome, last.stub, last.countersigned], ['done', 'found-in-book', stubs[0].fingerprint, true]);
    assert.ok(r.logs.some((e) => e.event === 'receipt-found' && e.call === id));
    assert.equal((await r.g.status()).agents.patching.stopped, null);
    const result = await compareOf(w);
    assert.equal(result.summary.moreThanOneReceipt, 0);
    assert.equal(result.summary.agree, true, JSON.stringify(result.summary));
  } finally {
    await r.g.close();
  }
});

test('F4 and F5: after a change of keys, a one-sided stub the acknowledgement wrote, which the journal could not record, does not settle the call when tried again; the call can only be set aside', async () => {
  const w = await afterCalls(await cw({ requires: [{ need: 'countersignature' }] }));
  const id = 'held-one-sided-after-the-change';
  await stoppedMidCall(w, id);
  const r = await again(w, await rotated(w, await gatewayKeys(), [{ need: 'countersignature' }]));
  try {
    renameSync(journalOf(w), `${journalOf(w)}.moved`);
    mkdirSync(journalOf(w));
    await assert.rejects(r.g.acknowledge('patching'));
    rmdirSync(journalOf(w));
    renameSync(`${journalOf(w)}.moved`, journalOf(w));
    await assert.rejects(r.g.acknowledge('patching'), /does not settle it/);
    assert.ok(r.logs.some((e) => e.event === 'receipt-not-matching' && e.call === id));
    const waiting = (await r.g.status()).agents.patching.receiptsMissing;
    assert.deepEqual(waiting.map((l) => [l.call, l.usable]), [[id, false]]);
    assert.ok(!copyEntries(w).some((e) => e.kind === 'done' && e.call === id), 'not noted as the gateway\'s');
    const ack = await r.g.acknowledge('patching', { setAside: [id] });
    assert.equal(ack.written.length, 0);
    assert.equal((await stubsFor(w, id)).length, 1, 'no second stub');
  } finally {
    await r.g.close();
  }
});

test('F5: without a copy, an acknowledgement tried again after the journal could not be written writes no second stub either', async () => {
  const w = await afterCalls(await world({}));
  const line = await journalOnlyCall(w, 'journal-only-acknowledged-twice');
  const r = await again(w);
  try {
    renameSync(journalOf(w), `${journalOf(w)}.moved`);
    mkdirSync(journalOf(w));
    for (let i = 0; i < 2; i++) await assert.rejects(r.g.acknowledge('patching'));
    const opts = w.gateway.checkOptions('patching');
    const fp = await identifierFingerprint(line.sending);
    const forCall = async () => (await stubsIn(w, opts)).filter((e) => e.content.details.some((d) => d.name === CALL_DOCUMENT && d.sha256 === fp));
    assert.equal((await forCall()).length, 1);
    rmdirSync(journalOf(w));
    renameSync(`${journalOf(w)}.moved`, journalOf(w));
    const ack = await r.g.acknowledge('patching');
    assert.deepEqual(ack.written.map((x) => x.found), [true]);
    assert.equal((await forCall()).length, 1);
    assert.equal((await r.g.status()).agents.patching.stopped, null);
  } finally {
    await r.g.close();
  }
});
