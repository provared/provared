// After the review of the gateway's countersignature (review 3.4): the
// gateway's own copy, not the journal, decides what happened to a call; a
// stub found in the book at a start settles a call only where it is the call
// the copy shows; "compare" holds each receipt's content and its
// countersignature against the copy; the gateway has a "with" entry of its
// own; and each rule the review found that no test caught now has one.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { appendFileSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook, countersign, entryLine, generateKeySet, identifierFingerprint, signerFromKey, thumbprint, writeStub } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { world, json, call, upstream, tempFolder, signSlip, SECRET, ADMIN_SECRET } = await import('./world.mjs');
const { openGateway, checkConfig, secretHash, CALL_DOCUMENT } = await import('../gateway.mjs');
const { compareCopyWithBook } = await import('../compare.mjs');
const { loadCopyKey, readCopy, openCopy, tagOf } = await import('../copy.mjs');
const { makeKeyFile } = await import('../files.mjs');

const JSONTYPE = { 'content-type': 'application/json' };
const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));

async function gatewayKeys() {
  const set = await generateKeySet();
  return { keys: set.keys, privateKeys: [signerFromKey('Ed25519', set.privateKeys[0], set.keys[0]), signerFromKey('ML-DSA-87', set.privateKeys[1], set.keys[1])] };
}

/** A world whose gateway has its own keys, and whose slip names the gateway in "with" (or what "services" gives). */
async function cw(o = {}) {
  const own = o.own ?? (await gatewayKeys());
  const services = o.services ?? [{ id: 'gateway', name: 'The test gateway', keys: own.keys }, { id: 'tickets', name: 'The ticket system' }, { id: 'patch', name: 'The patch service' }];
  const w = await world({
    ...o,
    slip: { with: typeof services === 'function' ? services(own) : services, requires: o.requires ?? [{ need: 'countersignature', action: 'provared.data.read' }], ...(o.slip ?? {}) },
    config: { gateway: { name: 'The test gateway', keySet: o.keySet ?? own.keys, privateKeys: own.privateKeys, ...(o.gateway ?? {}) }, ...(o.config ?? {}) },
  });
  return { ...w, own, opts: w.gateway.checkOptions('patching'), at: w.gateway.copyOf('patching') };
}

/** A world with one call through the gateway, closed: its files are as a stop leaves them. */
async function afterOneCall(o = {}, path = '/tickets/api/now/table/a') {
  const w = await cw(o);
  try {
    assert.equal((await w.call('GET', path)).status, 200);
  } finally {
    await w.close();
  }
  return { ...w, key: loadCopyKey(w.at.copyKey, { create: false }) };
}

const journalOf = (w) => `${w.bookPath}.journal`;
function tagged(w, value) {
  const key = Buffer.from(readFileSync(`${w.bookPath}.journal-key`, 'utf8').trim(), 'base64url');
  const text = JSON.stringify(value);
  return `${createHmac('sha256', key).update(`patching\n${text}`).digest('base64url')} ${text}`;
}

/**
 * The files a stop leaves where the gateway had written a call's line in its copy and was about to send it, or had sent
 * it: a "sending" line in the copy, and a line in the journal that is whole ("valid"), spoiled ("spoiled") or not there
 * ("none": never written, or the journal emptied since).
 */
async function stoppedMidCall(w, id, { journal = 'valid', action = 'provared.data.delete' } = {}) {
  const read = readCopy(w.at.copy, w.key, 'patching');
  const slip = read.lines[0].entry.slip;
  const when = new Date().toISOString();
  const details = [
    { name: 'provared.http-request', sha256: await identifierFingerprint(`request ${id}`) },
    { name: CALL_DOCUMENT, sha256: await identifierFingerprint(id) },
  ];
  openCopy(w.at.copy, w.key, 'patching', read.next).note({ kind: 'sending', call: id, when, slip, upstream: 'tickets', action, with: 'gateway', details });
  const line = { sending: id, when, slip, action, with: 'gateway', details };
  if (journal === 'valid') appendFileSync(journalOf(w), `${tagged(w, line)}\n`);
  if (journal === 'spoiled') appendFileSync(journalOf(w), `${'A'.repeat(43)} ${JSON.stringify(line)}\n`);
  return { slip, details, when, line };
}

/** The gateway started again on the world's files, listening. */
async function again(w) {
  const logs = [];
  const g = await openGateway(w.config, { root: w.folder, log: (e) => logs.push(e) });
  const at = await g.listen({ host: '127.0.0.1', port: 0 });
  return { g, logs, call: (method, path, more = {}) => call(at.port, method, path, { secret: SECRET, ...more }) };
}

/** A stub signed with the agent's keys, put at the end of the book: what whoever holds those keys and the book could write. */
async function forge(w, fields) {
  const checked = await checkBook(readFileSync(w.bookPath, 'utf8'), w.opts);
  const last = checked.entries.filter((e) => e.kind === 'stub' && e.content.slip === fields.slip).at(-1);
  const made = await writeStub({ ...fields, after: last ? { seq: last.content.seq, fingerprint: last.fingerprint } : null }, w.config.agents.patching.privateKeys);
  appendFileSync(w.bookPath, `${entryLine({ stub: made.record })}\n`);
  return made;
}

const compareOf = (w, { book, copyPath } = {}) => compareCopyWithBook({ copyPath: copyPath ?? w.at.copy, copyKey: w.key, name: 'patching', service: w.at.service, book: book ?? readFileSync(w.bookPath, 'utf8'), options: w.opts });
const copyEntries = (w) => readCopy(w.at.copy, w.key, 'patching').lines.map((l) => l.entry);
const stubsIn = async (w) => (await checkBook(readFileSync(w.bookPath, 'utf8'), w.opts)).entries.filter((e) => e.kind === 'stub');
const elsewhere = (name, text) => {
  const p = join(tempFolder(), name);
  writeFileSync(p, text);
  return p;
};

test('H1: a call the copy shows as sent, with no receipt, stops the agent and waits for the administrator, whether its journal line is there, spoiled or gone; its stub is written from the copy', async () => {
  for (const journal of ['none', 'spoiled']) {
    const w = await afterOneCall();
    const id = `held-call-${journal}`;
    const { details } = await stoppedMidCall(w, id, { journal });
    const r = await again(w);
    try {
      const status = (await r.g.status()).agents.patching;
      assert.notEqual(status.stopped, null, `${journal}: the agent is stopped`);
      const waiting = status.receiptsMissing.find((l) => l.call === id);
      assert.ok(waiting, `${journal}: the call is listed for the administrator`);
      assert.equal(waiting.usable, true);
      assert.ok(r.logs.some((e) => e.event === 'journal-line-missing' && e.call === id));
      assert.ok(!copyEntries(w).some((e) => e.kind === 'withdrawn'), 'nothing is noted "never sent" from the journal\'s silence');
      // The agent's next call is not taken.
      const next = await r.call('GET', '/tickets/api/now/table/b');
      assert.equal(next.status, 503, next.text);
      const before = await compareOf(w);
      assert.equal(before.summary.agree, false);
      assert.deepEqual(before.unfinished.map((u) => u.call), [id], 'compare lists the unfinished call by name');
      // The administrator acknowledges it (setting aside the spoiled journal line, which no stub is written from).
      const aside = status.receiptsMissing.filter((l) => !l.usable).map((l) => l.call);
      assert.equal(aside.length, journal === 'spoiled' ? 1 : 0);
      const ack = await r.g.acknowledge('patching', { setAside: aside });
      assert.equal(ack.written.length, 1);
      assert.equal(ack.written[0].countersigned, true);
      const stub = (await stubsIn(w)).at(-1);
      assert.equal(stub.content.with, 'gateway');
      assert.equal(stub.content.action, 'provared.data.delete');
      assert.deepEqual(stub.content.details.slice(0, 2), details, 'written from the copy\'s own line');
      assert.equal(stub.countersignature.state, 'valid');
      assert.equal(copyEntries(w).at(-1).outcome, 'acknowledged-outcome-unknown');
      const after = await compareOf(w);
      assert.equal(after.summary.agree, true, JSON.stringify(after.summary));
      assert.equal(after.summary.matched, 2);
      assert.equal((await r.g.status()).agents.patching.stopped, null);
    } finally {
      await r.g.close();
    }
  }
});

test('H1: a call the administrator sets aside is noted so in the copy, and compare says the set-aside calls are the only disagreement', async () => {
  const w = await afterOneCall();
  await stoppedMidCall(w, 'held-call-aside', { journal: 'none' });
  const r = await again(w);
  try {
    const ack = await r.g.acknowledge('patching', { setAside: ['held-call-aside'] });
    assert.equal(ack.setAside.length, 1);
    assert.equal(ack.written.length, 0);
    const last = copyEntries(w).at(-1);
    assert.equal(last.kind, 'set-aside');
    assert.equal(last.call, 'held-call-aside');
    const result = await compareOf(w);
    assert.equal(result.summary.setAside, 1);
    assert.equal(result.summary.agree, false);
    assert.equal(result.summary.onlySetAside, true);
  } finally {
    await r.g.close();
  }
});

test('H3: a journal line for a call the copy does not hold is never given a stub, nor countersigned; one that differs from the copy\'s line is not acted on', async () => {
  const w = await afterOneCall();
  const slip = readCopy(w.at.copy, w.key, 'patching').lines[0].entry.slip;
  // A line put into the journal, under the journal key, for a call nobody sent.
  const forged = { sending: 'never-sent-by-anyone', when: new Date().toISOString(), slip, action: 'provared.data.delete', with: 'gateway', details: [{ name: 'provared.http-request', sha256: await identifierFingerprint('x') }, { name: CALL_DOCUMENT, sha256: await identifierFingerprint('never-sent-by-anyone') }] };
  appendFileSync(journalOf(w), `${tagged(w, forged)}\n`);
  // And a call the copy holds, whose journal line names another action: the copy's line is the one acted on.
  await stoppedMidCall(w, 'held-call-differs', { journal: 'none' });
  const differs = { ...forged, sending: 'held-call-differs', action: 'ticket.update', details: [forged.details[0], { name: CALL_DOCUMENT, sha256: await identifierFingerprint('held-call-differs') }] };
  appendFileSync(journalOf(w), `${tagged(w, differs)}\n`);
  const stubsBefore = (await stubsIn(w)).length;
  const r = await again(w);
  try {
    const waiting = (await r.g.status()).agents.patching.receiptsMissing;
    const never = waiting.find((l) => l.call === 'never-sent-by-anyone');
    assert.ok(never);
    assert.equal(never.usable, false);
    assert.match(never.problem, /holds no "sending" line for this call/);
    assert.ok(r.logs.some((e) => e.event === 'journal-line-not-in-copy' && e.call === 'never-sent-by-anyone'));
    assert.ok(r.logs.some((e) => e.event === 'journal-line-differs' && e.call === 'held-call-differs'));
    assert.deepEqual(waiting.filter((l) => l.call === 'held-call-differs').map((l) => [l.action, l.usable]), [['provared.data.delete', true]]);
    const ack = await r.g.acknowledge('patching', { setAside: ['never-sent-by-anyone'] });
    assert.equal(ack.written.length, 1, 'only the call the copy holds gets a stub');
    const stubs = await stubsIn(w);
    assert.equal(stubs.length, stubsBefore + 1);
    assert.equal(stubs.at(-1).content.action, 'provared.data.delete', 'written from the copy, not the journal');
    for (const s of stubs) assert.notEqual(s.content.details.find((d) => d.name === CALL_DOCUMENT).sha256, await identifierFingerprint('never-sent-by-anyone'));
  } finally {
    await r.g.close();
  }
});

test('M1: a stub found in the book at a start that is not the call the copy shows, or lacks the gateway\'s countersignature, stops the agent and is reported; it is not written into the copy as the gateway\'s', async () => {
  for (const how of ['another action', 'one-sided', 'two stubs']) {
    const w = await afterOneCall();
    const id = `crashed-call-${how.replace(' ', '-')}`;
    const { slip, details, when } = await stoppedMidCall(w, id);
    const same = { slip, action: 'provared.data.delete', with: 'gateway', when: Date.parse(when), details: [...details, { name: 'provared.error', sha256: await identifierFingerprint('made up') }] };
    const made =
      how === 'another action'
        ? await forge(w, { slip, action: 'ticket.update', with: 'gateway', details: [{ name: 'provared.http-request', sha256: await identifierFingerprint('something harmless') }, details[1]] })
        : await forge(w, same);
    if (how === 'two stubs') await forge(w, same);
    const r = await again(w);
    try {
      assert.ok(r.logs.some((e) => e.event === 'receipt-not-matching' && e.call === id), how);
      assert.ok(!r.logs.some((e) => e.event === 'receipt-found' && e.call === id));
      const status = (await r.g.status()).agents.patching;
      assert.notEqual(status.stopped, null);
      const waiting = status.receiptsMissing.find((l) => l.call === id);
      assert.equal(waiting.usable, false);
      assert.match(waiting.problem, { 'one-sided': /without a valid countersignature of the gateway/, 'another action': /not the call the gateway's copy shows as sent/, 'two stubs': /holds 2 stubs for this call/ }[how]);
      assert.ok(!copyEntries(w).some((e) => e.outcome === 'found-in-book'), 'the copy does not take the stub as the gateway\'s');
      await assert.rejects(r.g.acknowledge('patching'), /No call waiting can have a stub written/);
      await r.g.acknowledge('patching', { setAside: [id] });
      const result = await compareOf(w);
      assert.equal(result.summary.agree, false);
      assert.deepEqual(result.setAside.map((s) => [s.call, s.inBook]), [[id, made.fingerprint]]);
    } finally {
      await r.g.close();
    }
  }
});

test('a stub found in the book at a start that is the call the copy shows, countersigned, is noted "found-in-book" with its countersignature, and compare agrees', async () => {
  const w = await afterOneCall();
  // The copy's last line (its "done") was not written: a stop just after the book took the stub.
  const text = readFileSync(w.at.copy, 'utf8').split('\n');
  writeFileSync(w.at.copy, `${text.slice(0, -2).join('\n')}\n`);
  const r = await again(w);
  try {
    assert.equal((await r.g.status()).agents.patching.stopped, null);
    const [stub] = await stubsIn(w);
    const last = copyEntries(w).at(-1);
    assert.equal(last.outcome, 'found-in-book');
    assert.equal(last.stub, stub.fingerprint);
    assert.equal(last.countersigned, true);
    assert.equal(typeof last.countersignature, 'string');
    const result = await compareOf(w);
    assert.equal(result.summary.agree, true, JSON.stringify(result.summary));
  } finally {
    await r.g.close();
  }
});

test('M2: compare reports a receipt whose countersignature is taken off, or is another than the one the copy records', async () => {
  const w = await afterOneCall({ requires: [] });
  const lines = readFileSync(w.bookPath, 'utf8').trim().split('\n');
  const last = JSON.parse(lines.at(-1));
  const { countersignature, ...bare } = last;
  assert.ok(countersignature);
  const stripped = await compareOf(w, { book: `${[...lines.slice(0, -1), entryLine(bare)].join('\n')}\n` });
  assert.equal(stripped.summary.agree, false, 'a receipt the gateway countersigned, without its countersignature');
  assert.deepEqual(stripped.countersignatures.map((c) => c.problem), ['missing']);
  assert.equal(stripped.matched.length, 0);
  // Another countersignature by the same keys, at another time: it checks, and is not the one the gateway gave.
  const other = { ...bare, countersignature: await countersign(bare.stub, w.own.privateKeys, Date.now() + 5000) };
  const book = `${[...lines.slice(0, -1), entryLine(other)].join('\n')}\n`;
  assert.equal((await checkBook(book, w.opts)).entries.at(-1).countersignature.state, 'valid');
  const swapped = await compareOf(w, { book });
  assert.equal(swapped.summary.agree, false);
  assert.deepEqual(swapped.countersignatures.map((c) => c.problem), ['another']);
  assert.equal((await compareOf(w)).summary.agree, true);
});

test('M2: compare reports a receipt the copy names that is not the call its "sending" line shows', async () => {
  const w = await afterOneCall({ requires: [] });
  const id = 'crashed-call-0009';
  const { slip, details } = await stoppedMidCall(w, id);
  const made = await forge(w, { slip, action: 'ticket.update', with: 'gateway', details: [{ name: 'provared.http-request', sha256: await identifierFingerprint('harmless') }, details[1]] });
  // A copy that took the stub at a start, as the build before this one did.
  openCopy(w.at.copy, w.key, 'patching', readCopy(w.at.copy, w.key, 'patching').next).note({ kind: 'done', call: id, when: new Date().toISOString(), outcome: 'found-in-book', stub: made.fingerprint });
  const result = await compareOf(w);
  assert.equal(result.summary.agree, false);
  assert.deepEqual(result.differs.map((d) => [d.call, d.why]), [[id, 'not the call sent']]);
});

test('compare reports a receipt in the book that is not the one the copy names (differs)', async () => {
  const w = await afterOneCall();
  const [sending] = copyEntries(w);
  const { seq, ...rest } = sending;
  const path = join(tempFolder(), 'other.jsonl');
  const c = openCopy(path, w.key, 'patching', 0);
  c.note(rest);
  c.note({ kind: 'done', call: sending.call, when: new Date().toISOString(), stub: 'A'.repeat(43), countersigned: false, documents: [] });
  const result = await compareOf(w, { copyPath: path });
  assert.deepEqual(result.differs.map((d) => d.why), ['another stub']);
  assert.equal(result.summary.agree, false);
});

test('compare lists by name a call a copy shows as withdrawn', async () => {
  const w = await afterOneCall();
  const read = readCopy(w.at.copy, w.key, 'patching');
  const c = openCopy(w.at.copy, w.key, 'patching', read.next);
  c.note({ kind: 'sending', call: 'withdrawn-call-1', when: new Date().toISOString(), slip: read.lines[0].entry.slip, upstream: 'tickets', action: 'provared.data.read', with: 'gateway', details: [] });
  c.note({ kind: 'withdrawn', call: 'withdrawn-call-1', when: new Date().toISOString(), reason: 'not-sent' });
  const result = await compareOf(w);
  assert.deepEqual(result.withdrawn.map((x) => [x.call, x.upstream, x.action, x.reason]), [['withdrawn-call-1', 'tickets', 'provared.data.read', 'not-sent']]);
  assert.equal(result.summary.withdrawn, 1);
});

test('L7: compare reports more than one receipt for one call', async () => {
  const w = await afterOneCall({ requires: [] });
  const [sending] = copyEntries(w);
  await forge(w, { slip: sending.slip, action: sending.action, with: 'gateway', details: [...sending.details, { name: 'provared.error', sha256: await identifierFingerprint('again') }] });
  const result = await compareOf(w);
  assert.equal(result.summary.moreThanOneReceipt, 1);
  assert.equal(result.moreThanOne[0].stubs.length, 2);
  assert.equal(result.summary.agree, false);
});

test('compare does not agree where a line of the copy does not check, a line is put twice or taken out, or the copy is cut; the gateway does not start on a line put twice', async () => {
  const w = await afterOneCall();
  assert.equal((await compareOf(w)).summary.agree, true);
  const text = readFileSync(w.at.copy, 'utf8');
  const [first, second] = text.trim().split('\n');
  const cases = {
    'does not check': `${text}abc {"seq":2}\n`,
    'put twice': `${first}\n${second}\n${second}\n`,
    'taken out': `${second}\n`,
    cut: `${text}abc`,
  };
  for (const [what, body] of Object.entries(cases)) {
    const result = await compareOf(w, { copyPath: elsewhere(`${what}.jsonl`, body) });
    assert.equal(result.summary.agree, false, what);
    assert.equal(result.summary.copyProblem, true, what);
    if (what === 'put twice' || what === 'taken out') assert.equal(result.copy.sequence.ok, false, what);
  }
  writeFileSync(w.at.copy, cases['put twice']);
  await assert.rejects(openGateway(w.config, { root: w.folder, log: () => {} }), /its copy .* is not whole: line 2 carries number 1, which was used already/);
});

test("L4: the copy's tag is HMAC-SHA-256 under the copy key of the agent's name in UTF-8, one line feed, then the line's JSON text, in base64url without padding", () => {
  const text = '{"seq":0,"kind":"sending","call":"abc"}';
  assert.equal(tagOf(Buffer.alloc(32, 1), 'patching', text), 'V1N4ViB9pIn6xrWQQUCo6gGAglG6NFUFvTKuKy-ZSBE');
  // The agent's name is part of the tag: a copy read under another agent's name has no line that checks.
  const path = elsewhere('named.jsonl', `${tagOf(Buffer.alloc(32, 1), 'patching', text)} ${text}\n`);
  assert.equal(readCopy(path, Buffer.alloc(32, 1), 'patching').checked, 1);
  assert.equal(readCopy(path, Buffer.alloc(32, 1), 'another').checked, 0);
});

test('compare reports a denial the gateway wrote that the book lacks, and does not agree where the book has a problem or is not within its slips', async () => {
  const w = await cw();
  try {
    assert.equal((await w.call('GET', '/tickets/api/now/table/a')).status, 200);
    const refused = await w.call('GET', '/tickets/nothing/here');
    assert.equal(refused.status, 403);
  } finally {
    await w.close();
  }
  w.key = loadCopyKey(w.at.copyKey, { create: false });
  const lines = readFileSync(w.bookPath, 'utf8').trim().split('\n');
  assert.equal((await compareOf(w)).summary.agree, true);
  const noDenial = await compareOf(w, { book: `${lines.slice(0, -1).join('\n')}\n` });
  assert.equal(noDenial.summary.denialsMissingFromBook, 1);
  assert.equal(noDenial.summary.agree, false);
  const spoilt = await compareOf(w, { book: `${lines.join('\n')}\nnot a line of a book\n` });
  assert.equal(spoilt.summary.bookProblem, true);
  assert.equal(spoilt.summary.agree, false);
  // A one-sided receipt of a read, which the slip requires to be countersigned, that names no call of the copy and not the gateway.
  const [sending] = copyEntries(w);
  await forge(w, { slip: sending.slip, action: 'provared.data.read', with: 'tickets', details: [{ name: 'provared.http-request', sha256: await identifierFingerprint('y') }] });
  const outside = await compareOf(w);
  assert.equal(outside.summary.notInCopy, 0);
  assert.equal(outside.summary.bookWithinSlips, false);
  assert.equal(outside.summary.agree, false);
});

test('H2: the gateway countersigns only under its own entry; where the slip does not name it, an upstream that says it can countersigns, under its own entry', async () => {
  const service = await generateKeySet();
  const w = await cw({
    services: [{ id: 'tickets', name: 'The ticket system' }, { id: 'patch', name: 'The patch service', keys: service.keys }],
    requires: [],
    patch: { countersign: '/countersign' },
    patchAnswer: async (c, res) => {
      if (c.url === '/countersign') return json(res, 200, await countersign(JSON.parse(c.body.toString()), service.privateKeys));
      return json(res, 200, { ok: true });
    },
  });
  try {
    assert.equal((await w.call('POST', '/patch/v1/hosts/h1/reboot', { headers: JSONTYPE, body: {} })).status, 200);
    const [stub] = await stubsIn(w);
    assert.equal(stub.content.with, 'patch');
    assert.equal(stub.countersignature.state, 'valid', "the upstream's own countersignature, under its own keys");
    assert.ok(w.patch.calls.some((c) => c.url === '/countersign'));
    assert.equal((await w.gateway.status()).agents.patching.countersigns, false);
    assert.ok(w.logs.some((e) => e.event === 'warning' && /does not name the gateway in "with"/.test(e.message)));
  } finally {
    await w.close();
  }
});

test("H2: a slip that gives the gateway's keys under an upstream's service is not countersigned there, and is warned of; the gateway's id is set in the settings, and is no upstream's service", async () => {
  const w = await cw({ services: (own) => [{ id: 'tickets', name: 'The ticket system', keys: own.keys }, { id: 'patch', name: 'The patch service' }], requires: [] });
  try {
    assert.equal((await w.call('GET', '/tickets/api/now/table/a')).status, 200);
    const [stub] = await stubsIn(w);
    assert.equal(stub.content.with, 'tickets');
    assert.equal(stub.countersignature.state, 'absent', "the gateway's countersignature would read as the upstream's");
    assert.ok(w.logs.some((e) => e.event === 'warning' && /gives the gateway's own keys under "tickets", not under the gateway's id "gateway"/.test(e.message)));
  } finally {
    await w.close();
  }
  const v = await cw({ gateway: { id: 'front-door' }, services: (own) => [{ id: 'front-door', name: 'The front door', keys: own.keys }, { id: 'tickets', name: 'The ticket system' }] });
  try {
    assert.equal((await v.call('GET', '/tickets/api/now/table/a')).status, 200);
    const [stub] = await stubsIn(v);
    assert.equal(stub.content.with, 'front-door');
    assert.equal(stub.countersignature.state, 'valid');
    await assert.rejects(openGateway({ ...v.config, gateway: { ...v.config.gateway, id: 'tickets' } }, { root: v.folder, log: () => {} }), /its id "tickets" is also the service of upstream "tickets"/);
  } finally {
    await v.close();
  }
});

test('L5: a setting the gateway does not know, or a copy that is not a path, stops the start and is a problem for check; key sets with their members in another order are the same keys', async () => {
  const own = await gatewayKeys();
  const w = await cw({ own, keySet: own.keys.map((k) => Object.fromEntries(Object.entries(k).reverse())) });
  try {
    assert.equal((await w.call('GET', '/tickets/api/now/table/a')).status, 200);
    assert.equal((await stubsIn(w))[0].countersignature.state, 'valid');
    assert.equal((await w.gateway.status()).agents.patching.countersigns, true);
  } finally {
    await w.close();
  }
  const { gateway, ...rest } = w.config;
  const misspelt = { ...rest, gatway: gateway };
  await assert.rejects(openGateway(misspelt, { root: w.folder, log: () => {} }), /"gatway" is not a setting the gateway knows/);
  assert.ok((await checkConfig(misspelt, { root: w.folder })).problems.some((p) => /"gatway" is not a setting/.test(p)));
  for (const [extra, wanted] of [[{ copykey: 'x' }, /"copykey" is not a setting/], [{ copy: 5 }, /"copy" must be the path of a file/], [{ copyKey: true }, /"copyKey" must be the path of a file/]]) {
    const config = { ...w.config, agents: { patching: { ...w.config.agents.patching, ...extra } } };
    await assert.rejects(openGateway(config, { root: w.folder, log: () => {} }), wanted);
    assert.ok((await checkConfig(config, { root: w.folder })).problems.some((p) => wanted.test(p)));
  }
});

test("L3: an agent's copy may not be its own book or journal, nor its copy key its journal key", async () => {
  const w = await cw();
  await w.close();
  const a = w.config.agents.patching;
  for (const [extra, wanted] of [
    [{ copy: a.book }, /its copy is also its book file/],
    [{ copy: `${a.book}.journal` }, /its copy is also its journal/],
    [{ copyKey: `${a.book}.journal-key` }, /its copy key is also its journal key/],
  ]) {
    const config = { ...w.config, agents: { patching: { ...a, ...extra } } };
    assert.ok((await checkConfig(config, { root: w.folder })).problems.some((p) => wanted.test(p)), String(wanted));
    await assert.rejects(openGateway(config, { root: w.folder, log: () => {} }), wanted);
  }
});

test('L2: a copy taken away whole, its key left, is said at the next start: the book holds receipts naming the gateway that the copy does not know', async () => {
  const w = await afterOneCall();
  writeFileSync(w.at.copy, '');
  const r = await again(w);
  try {
    assert.ok(r.logs.some((e) => e.event === 'warning' && /its book holds 1 receipt\(s\) naming the gateway \("gateway"\) that its copy .* does not know/.test(e.message)));
  } finally {
    await r.g.close();
  }
});

test('L1: "unlisted": "forward" with the gateway\'s own keys is warned of at start and by check, and compare says what it cannot see', async () => {
  const w = await cw({ unlisted: 'forward' });
  try {
    assert.equal((await w.call('GET', '/tickets/not/a/rule')).status, 200);
    assert.ok(w.logs.some((e) => e.event === 'warning' && /"unlisted" is "forward" and the gateway has its own keys/.test(e.message)));
    assert.ok((await checkConfig(w.config, { root: w.folder })).warnings.some((x) => /"unlisted" is "forward" and the gateway has its own keys/.test(x)));
    w.key = loadCopyKey(w.at.copyKey, { create: false });
    assert.ok((await compareOf(w)).notShown.some((s) => /"unlisted" is "forward"/.test(s)));
  } finally {
    await w.close();
  }
});

function run(args) {
  return new Promise((done) => {
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', BIN, ...args], { env: process.env });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('close', (code) => done({ code, out, err }));
  });
}

test('L6 and the key file: "keys --gateway" refuses an agent\'s key file; "compare" reads no key file of the gateway, and refuses an option it does not know', { timeout: 120000 }, async () => {
  const folder = tempFolder();
  const passkey = await developmentPasskey();
  const agentKeys = await makeKeyFile(join(folder, 'agent.jwk'), 'agent');
  const up = await upstream();
  const config = {
    admin: { secretHash: await secretHash(ADMIN_SECRET) },
    gateway: { name: 'The test gateway', keys: 'agent.jwk' },
    upstreams: { tickets: { base: up.base, service: 'tickets' } },
    rules: [{ upstream: 'tickets', method: 'GET', path: '/x/:id', action: 'provared.data.read' }],
    agents: { patching: { secretHash: await secretHash(SECRET), slip: 'slip.json', book: 'book.jsonl', keys: 'agent.jwk', issuerKeys: [await thumbprint(passkey.key)] } },
  };
  const configPath = join(folder, 'gateway.json');
  writeFileSync(configPath, JSON.stringify(config));
  const agentFile = readFileSync(join(folder, 'agent.jwk'), 'utf8');
  const refused = await run(['keys', '--config', configPath, '--gateway']);
  assert.notEqual(refused.code, 0);
  assert.match(refused.err, /Nothing was written: gateway\.keys .* is also the key file of the recorder or of an agent/);
  assert.equal(readFileSync(join(folder, 'agent.jwk'), 'utf8'), agentFile);
  config.gateway.keys = 'gateway.jwk';
  writeFileSync(configPath, JSON.stringify(config));
  const keys = await run(['keys', '--config', configPath, '--gateway']);
  assert.equal(keys.code, 0, keys.err);
  const printed = JSON.parse(keys.out.slice(keys.out.indexOf('{')));
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(await signSlip({ passkey, agentKeys, with: [...printed.with, { id: 'tickets', name: 'The ticket system' }], requires: printed.requires })));
  const g = await openGateway(config, { root: folder, log: () => {} });
  const at = await g.listen({ host: '127.0.0.1', port: 0 });
  assert.equal((await call(at.port, 'GET', '/tickets/x/1', { secret: SECRET })).status, 200);
  await g.close();
  await up.close();
  // The gateway's key file moved away: compare needs only the gateway's id.
  renameSync(join(folder, 'gateway.jwk'), join(folder, 'gateway.jwk.moved'));
  const compared = await run(['compare', '--config', configPath, '--agent', 'patching']);
  assert.equal(compared.code, 0, compared.out + compared.err);
  assert.equal(JSON.parse(compared.out).summary.matched, 1);
  const mistyped = await run(['compare', '--config', configPath, '--agent', 'patching', '--bok', 'other.jsonl']);
  assert.notEqual(mistyped.code, 0);
  assert.match(mistyped.err, /"--bok" is not one of them/);
});
