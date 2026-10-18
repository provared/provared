// The faults the second independent review of the gateway found, each as a
// test that fails on the code it reviewed: one call with two receipts, a
// journal taken as it stands, names that only some readers fold together,
// encoded characters that fold into others, a book cut part-way through a
// line, and two agents that share a file.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook, fingerprint, fromBase64url, identifierFingerprint } = await import('provared');
const { world, call, SECRET, OTHER_SECRET, ADMIN_SECRET } = await import('./world.mjs');
const { openGateway, checkConfig, secretHash, CALL_DOCUMENT, OUTCOME_UNKNOWN } = await import('../gateway.mjs');

const JSONTYPE = { 'content-type': 'application/json' };
const docs = (entry) => Object.fromEntries((entry.content.details ?? []).map((d) => [d.name, d.sha256]));
const stubsIn = async (w, opts) => (await checkBook(readFileSync(w.bookPath, 'utf8'), opts)).entries.filter((e) => e.kind === 'stub');
const silent = () => {};

/** A journal line as the gateway writes it: its tag (HMAC-SHA-256 under the journal key, over the agent's name and the text), a space, the text. */
function tagged(w, value, agent = 'patching') {
  const key = Buffer.from(readFileSync(`${w.bookPath}.journal-key`, 'utf8').trim(), 'base64url');
  const text = JSON.stringify(value);
  return `${createHmac('sha256', key).update(`${agent}\n${text}`).digest('base64url')} ${text}`;
}

/** A line the gateway could have written for a read of the ticket system. */
async function readLine(w, id, when) {
  return {
    sending: id,
    when: new Date(when).toISOString(),
    slip: await fingerprint(fromBase64url(w.slip.payload)),
    action: 'provared.data.read',
    with: 'tickets',
    details: [
      { name: 'provared.http-request', sha256: await identifierFingerprint(`request ${id}`) },
      { name: CALL_DOCUMENT, sha256: await identifierFingerprint(id) },
    ],
  };
}

test('R2-M1 (a): a stop after the stub is in the book and before the "done" line leaves no call to acknowledge, and no second receipt', async () => {
  const w = await world();
  const opts = w.gateway.checkOptions('patching');
  assert.equal((await w.call('GET', '/tickets/api/now/table/incident')).status, 200);
  await w.gateway.close();
  const jpath = `${w.bookPath}.journal`;
  const lines = readFileSync(jpath, 'utf8').split('\n').filter(Boolean);
  const sending = JSON.parse(lines[0].slice(lines[0].indexOf(' ') + 1));
  const [stub] = await stubsIn(w, opts);
  assert.equal(docs(stub)[CALL_DOCUMENT], await identifierFingerprint(sending.sending), 'the stub names its call');
  writeFileSync(jpath, `${lines.filter((l) => !l.includes(' {"done"')).join('\n')}\n`);
  const logs = [];
  const g = await openGateway(w.config, { root: w.folder, log: (e) => logs.push(e) });
  try {
    const st = await g.status();
    assert.equal(st.agents.patching.stopped, null);
    assert.deepEqual(st.agents.patching.receiptsMissing, []);
    assert.ok(logs.some((e) => e.event === 'receipt-found'));
    await assert.rejects(g.acknowledge('patching'), /no call without a receipt/);
  } finally {
    await g.close();
  }
  assert.equal((await stubsIn(w, opts)).length, 1);
  assert.equal(w.tickets.calls.length, 1);
  await w.tickets.close();
  await w.patch.close();
});

test('R2-M1 (b): an acknowledgement that fails part of the way, tried again, writes no call\'s stub twice', async () => {
  const w = await world();
  const opts = w.gateway.checkOptions('patching');
  await w.gateway.close();
  const t0 = Date.now();
  writeFileSync(`${w.bookPath}.journal`, `${tagged(w, await readLine(w, 'call-early', t0 - 900e3))}\n${tagged(w, await readLine(w, 'call-late', t0 - 1000))}\n`);
  let clock = t0;
  const g = await openGateway(w.config, { root: w.folder, log: silent, now: () => clock });
  try {
    assert.equal((await g.status()).agents.patching.receiptsMissing.filter((p) => p.usable).length, 2);
    clock = t0 - 600e3; // the second call is now ahead of the clock, and its stub cannot be written
    await assert.rejects(g.acknowledge('patching'), /ahead of the clock|record-not-sound|not written/i);
    const left = (await g.status()).agents.patching.receiptsMissing;
    assert.deepEqual(left.map((p) => p.call), ['call-late'], 'the call acknowledged is off the list at once');
    clock = t0;
    const again = await g.acknowledge('patching');
    assert.equal(again.written.length, 1);
    assert.equal((await g.status()).agents.patching.stopped, null);
  } finally {
    await g.close();
  }
  const stubs = await stubsIn(w, opts);
  assert.equal(stubs.length, 2);
  assert.deepEqual(new Set(stubs.map((s) => docs(s)[CALL_DOCUMENT])), new Set([await identifierFingerprint('call-early'), await identifierFingerprint('call-late')]));
  for (const s of stubs) assert.equal(docs(s)['provared.error'], await identifierFingerprint(OUTCOME_UNKNOWN));
  await w.tickets.close();
  await w.patch.close();
});

test('R2-M2: a journal line whose tag does not check is never acted on; it is shown whole, and the administrator sets it aside', async () => {
  const w = await world({ slip: { limits: [{ action: 'host.reboot', count: 1 }] } });
  const opts = w.gateway.checkOptions('patching');
  await w.gateway.close();
  const forged = { sending: 'forged-1', when: new Date(Date.now() - 3 * 3600e3).toISOString(), action: 'host.reboot', amount: { unit: 'hosts', value: 1 }, with: 'patch', details: [{ name: 'provared.http-request', sha256: 'A'.repeat(43) }] };
  const changed = tagged(w, await readLine(w, 'call-1', Date.now() - 5000)).replace('provared.data.read', 'host.reboot');
  const otherKey = `${createHmac('sha256', Buffer.alloc(32, 7)).update(`patching\n${JSON.stringify(forged)}`).digest('base64url')} ${JSON.stringify(forged)}`;
  // One line that checks (a call done long ago), so that the journal is this key's and the gateway starts.
  writeFileSync(`${w.bookPath}.journal`, `${tagged(w, { done: 'earlier-call' })}\n${JSON.stringify(forged)}\n${changed}\n${otherKey}\n`);
  const logs = [];
  const g = await openGateway(w.config, { root: w.folder, log: (e) => logs.push(e) });
  const at = await g.listen({ host: '127.0.0.1', port: 0 });
  try {
    const st = (await call(at.port, 'GET', '/provared/status', { secret: ADMIN_SECRET })).json.agents.patching;
    assert.equal(st.receiptsMissing.length, 3);
    for (const p of st.receiptsMissing) {
      assert.equal(p.tag, 'invalid');
      assert.equal(p.usable, false);
    }
    assert.match(st.receiptsMissing[0].call, /^line-[A-Za-z0-9_-]{16}$/);
    assert.deepEqual(st.receiptsMissing[0], { call: st.receiptsMissing[0].call, tag: 'invalid', usable: false, problem: 'Its tag does not check: the gateway did not write this line, or it was changed.', warning: null, when: forged.when, action: 'host.reboot', amount: { unit: 'hosts', value: 1 }, with: 'patch', details: forged.details });
    assert.equal(logs.filter((e) => e.event === 'journal-line-refused').length, 3);
    const refused = await call(at.port, 'POST', '/provared/acknowledge', { secret: ADMIN_SECRET, headers: JSONTYPE, body: { agent: 'patching' } });
    assert.equal(refused.status, 409);
    const aside = await call(at.port, 'POST', '/provared/acknowledge', { secret: ADMIN_SECRET, headers: JSONTYPE, body: { agent: 'patching', setAside: st.receiptsMissing.map((p) => p.call) } });
    assert.equal(aside.status, 200, aside.text);
    assert.equal(aside.json.written.length, 0);
    assert.equal(aside.json.setAside.length, 3);
    assert.equal(logs.filter((e) => e.event === 'journal-line-set-aside').length, 3);
    const r = await call(at.port, 'POST', '/patch/v1/hosts/a/reboot', { secret: SECRET, headers: JSONTYPE, body: {} });
    assert.equal(r.status, 200, 'the forged lines used up nothing');
  } finally {
    await g.close();
  }
  const stubs = await stubsIn(w, opts);
  assert.equal(stubs.length, 1);
  // Set aside for good: a start does not ask again.
  const again = await openGateway(w.config, { root: w.folder, log: silent });
  assert.equal((await again.status()).agents.patching.stopped, null);
  await again.close();
  await w.tickets.close();
  await w.patch.close();
});

test('R2-M2: a tagged line that cannot have a stub written from it is shown with why, and can only be set aside', async () => {
  const w = await world();
  await w.gateway.close();
  const now = Date.now();
  const base = await readLine(w, 'good-1', now - 1000);
  const cases = [
    [{ ...base, sending: 'bad-1', action: 'Not An Action' }, /not an action name/],
    [{ ...base, sending: 'bad-2', when: 'yesterday' }, /not a time/],
    [{ ...base, sending: 'bad-3', when: new Date(now + 3600e3).toISOString() }, /after this start/],
    [{ ...base, sending: 'bad-4', details: [...base.details, { name: 'provared.nonsense', sha256: 'A'.repeat(43) }] }, /documents are not the ones/],
    [{ ...base, sending: 'bad-6', amount: { unit: 'hosts', value: 1 } }, /rule gives an amount|not in the unit/],
    [{ ...base, sending: 'bad-7' }, /call document does not match/],
    [{ ...base, sending: 'bad-8', extra: 1 }, /member the gateway does not write/],
    [{ ...base, sending: 'bad-9', when: base.when.replace('Z', '+00:00') }, /not a time written as the gateway writes it/],
  ];
  writeFileSync(`${w.bookPath}.journal`, `${cases.map(([l]) => tagged(w, l)).join('\n')}\n`);
  const g = await openGateway(w.config, { root: w.folder, log: silent });
  try {
    const shown = (await g.status()).agents.patching.receiptsMissing;
    assert.equal(shown.length, cases.length);
    cases.forEach(([, words], i) => {
      assert.equal(shown[i].tag, 'valid');
      assert.equal(shown[i].usable, false);
      assert.match(shown[i].problem, words, shown[i].call);
    });
    await assert.rejects(g.acknowledge('patching'), /No call waiting can have a stub/);
    await assert.rejects(g.acknowledge('patching', { setAside: ['nothing-like-it'] }), /No call "nothing-like-it"/);
    const done = await g.acknowledge('patching', { setAside: shown.map((p) => p.call) });
    assert.equal(done.written.length, 0);
    assert.equal((await g.status()).agents.patching.stopped, null);
  } finally {
    await g.close();
  }
  assert.equal((await stubsIn(w, w.gateway.checkOptions('patching'))).length, 0);
  await w.tickets.close();
  await w.patch.close();
});

test('R2-L3: a book cut part-way through a line: "repair" shows the cut bytes, takes them off on request, and the call is then acknowledged', async () => {
  const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));
  const w = await world();
  const opts = w.gateway.checkOptions('patching');
  assert.equal((await w.call('GET', '/tickets/api/now/table/a')).status, 200);
  await w.gateway.close();
  const whole = readFileSync(w.bookPath, 'utf8');
  writeFileSync(w.bookPath, whole.slice(0, whole.length - 40));
  await assert.rejects(openGateway(w.config, { root: w.folder, log: silent }), /does not end with a whole line/);
  const settings = join(w.folder, 'repair.json');
  writeFileSync(settings, JSON.stringify({ agents: { patching: { book: w.bookPath } } }));
  const run = (...args) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', BIN, ...args], { encoding: 'utf8', env: process.env });
  const shown = run('repair', '--config', settings, '--agent', 'patching');
  assert.equal(shown.status, 1, shown.stderr);
  const partial = whole.slice(whole.lastIndexOf('\n', whole.length - 2) + 1, whole.length - 40);
  assert.match(shown.stdout, new RegExp(`ends with ${Buffer.byteLength(partial)} bytes`));
  assert.equal(readFileSync(w.bookPath, 'utf8'), whole.slice(0, whole.length - 40), 'nothing is taken off without --cut');
  assert.equal(run('repair', '--config', settings, '--agent', 'patching', '--cut', '3').status, 2, 'only the bytes shown');
  const cut = run('repair', '--config', settings, '--agent', 'patching', '--cut', String(Buffer.byteLength(partial)));
  assert.equal(cut.status, 0, cut.stderr);
  assert.ok(readFileSync(w.bookPath, 'utf8').endsWith('\n'));
  const kept = /kept in (.+)\.$/m.exec(cut.stdout)[1];
  assert.equal(readFileSync(kept, 'utf8'), partial);
  const g = await openGateway(w.config, { root: w.folder, log: silent });
  try {
    const st = (await g.status()).agents.patching;
    assert.equal(st.receiptsMissing.length, 1, 'the call whose stub was cut off has no receipt');
    assert.equal(st.receiptsMissing[0].usable, true);
    assert.equal((await g.acknowledge('patching')).written.length, 1);
  } finally {
    await g.close();
  }
  assert.equal((await stubsIn(w, opts)).length, 1);
  await w.tickets.close();
  await w.patch.close();
});

test('R2-L5: two agents may not share a file, by any path that names it: a book, a journal, a journal key', async () => {
  const w = await world();
  await w.close();
  const second = (more) => ({ ...w.config, agents: { ...w.config.agents, other: { ...w.config.agents.patching, secretHash: undefined, ...more } } });
  const hash = await secretHash(OTHER_SECRET);
  const cases = [
    { secretHash: hash, book: `${w.bookPath}.journal` },
    { secretHash: hash, book: join(w.folder, 'other.jsonl'), journalKey: w.bookPath },
    { secretHash: hash, book: join(w.folder, 'books', '..', 'books', 'patching.jsonl') },
  ];
  if (process.platform === 'win32') cases.push({ secretHash: hash, book: w.bookPath.toUpperCase() });
  // The same folder reached through a link (a junction, which needs no special rights on Windows).
  mkdirSync(join(w.folder, 'links'));
  symlinkSync(join(w.folder, 'books'), join(w.folder, 'links', 'books'), 'junction');
  cases.push({ secretHash: hash, book: join(w.folder, 'links', 'books', 'patching.jsonl') });
  for (const more of cases) {
    const config = second(more);
    await assert.rejects(openGateway(config, { root: w.folder, log: silent }), /share a file/, JSON.stringify(more));
    const checked = await checkConfig(config, { root: w.folder });
    assert.ok(checked.problems.some((p) => /share a file/.test(p)), JSON.stringify(checked.problems));
  }
});

test('R2-L1, through the gateway: names that only some readers fold together give no amount', async () => {
  const w = await world();
  try {
    for (const body of ['{"hosts":[1],"m":{"σ":1,"ς":2}}', '{"hosts":[1],"m":{"ıd":1,"id":2}}', '{"hosts":[1],"m":{"ID":1,"id":2}}']) {
      const r = await w.call('POST', '/patch/v1/waves', { headers: JSONTYPE, body });
      assert.equal(r.status, 403, body);
      assert.equal(r.json.code, 'amount-not-found');
    }
    assert.equal(w.patch.calls.length, 0);
  } finally {
    await w.close();
  }
});
