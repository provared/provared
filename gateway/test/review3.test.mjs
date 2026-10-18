// The faults the third independent review of the gateway found, each as a
// test that fails on the code it reviewed: a stub written on acknowledgement
// under the wrong slip, files shared through hard links, honest calls that
// could lose their receipt, a set-aside line that comes back, a fingerprint
// the library refuses, and the dotted capital I.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { linkSync, readFileSync, renameSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { checkBook, fingerprint, fromBase64url, identifierFingerprint } = await import('provared');
const { world, signSlip, OTHER_SECRET, RULES } = await import('./world.mjs');
const { openGateway, checkConfig, secretHash, CALL_DOCUMENT } = await import('../gateway.mjs');

const silent = () => {};
const docs = (entry) => Object.fromEntries((entry.content.details ?? []).map((d) => [d.name, d.sha256]));
const slipOf = (slip) => fingerprint(fromBase64url(slip.payload));

function tagged(w, value, agent = 'patching') {
  const key = Buffer.from(readFileSync(`${w.bookPath}.journal-key`, 'utf8').trim(), 'base64url');
  const text = JSON.stringify(value);
  return `${createHmac('sha256', key).update(`${agent}\n${text}`).digest('base64url')} ${text}`;
}

async function readLine(w, id, when, more = {}) {
  return {
    sending: id,
    when: new Date(when).toISOString(),
    slip: await slipOf(w.slip),
    action: 'provared.data.read',
    with: 'tickets',
    details: [
      { name: 'provared.http-request', sha256: await identifierFingerprint(`request ${id}`) },
      { name: CALL_DOCUMENT, sha256: await identifierFingerprint(id) },
    ],
    ...more,
  };
}

test('R3-M1: each "sending" line names the slip its call is sent under', async () => {
  const v = await world();
  try {
    assert.equal((await v.call('GET', '/tickets/api/now/table/a')).status, 200);
    const first = readFileSync(`${v.bookPath}.journal`, 'utf8').split('\n')[0];
    assert.equal(JSON.parse(first.slice(first.indexOf(' ') + 1)).slip, await slipOf(v.slip));
  } finally {
    await v.close();
  }
});

test('R3-M1: a call sent under an earlier slip is acknowledged under that slip, not the one in force at the start', async () => {
  const w = await world({ slip: { limits: [{ action: 'provared.data.read', count: 1 }] } });
  await w.gateway.close();
  // A call with no receipt, sent under the first slip; then a renewed slip is put in place before the start.
  writeFileSync(`${w.bookPath}.journal`, `${tagged(w, await readLine(w, 'under-first', Date.now() - 30000))}\n`);
  const slip2 = await signSlip({ passkey: w.passkey, agentKeys: w.agentSet.keys, from: Date.now() - 10000, limits: [{ action: 'provared.data.read', count: 1 }] });
  writeFileSync(join(w.folder, 'slip.json'), JSON.stringify(slip2));
  const g = await openGateway(w.config, { root: w.folder, log: silent });
  try {
    const [p] = (await g.status()).agents.patching.receiptsMissing;
    assert.equal(p.usable, true, p.problem);
    assert.equal(p.slip, await slipOf(w.slip));
    const ack = await g.acknowledge('patching');
    assert.equal(ack.written[0].slip, await slipOf(w.slip));
    const book = await checkBook(readFileSync(w.bookPath, 'utf8'), g.checkOptions('patching'));
    const stub = book.entries.filter((e) => e.kind === 'stub').at(-1);
    assert.equal(stub.content.slip, await slipOf(w.slip), 'under the slip the call was sent under');
    assert.deepEqual([...stub.problems, ...stub.breaches].map((f) => f.code), [], 'within the first slip, dated inside it');
    assert.equal(book.summary.problemFound, false);
    assert.equal(book.summary.withinSlips, true);
    // The renewed slip's own limit is untouched.
    const at = await g.listen({ host: '127.0.0.1', port: 0 });
    const { call } = await import('./world.mjs');
    assert.equal((await call(at.port, 'GET', '/tickets/api/now/table/b', { secret: 'agent-secret-for-the-tests-0123456789abcdef' })).status, 200);
  } finally {
    await g.close();
  }
  await w.tickets.close();
  await w.patch.close();
});

test('R3-M1: a call sent under a slip the book does not hold cannot be acknowledged, and can be set aside', async () => {
  const w = await world();
  await w.gateway.close();
  writeFileSync(`${w.bookPath}.journal`, `${tagged(w, await readLine(w, 'under-unknown', Date.now() - 5000, { slip: 'B'.repeat(43) }))}\n`);
  const g = await openGateway(w.config, { root: w.folder, log: silent });
  try {
    const [p] = (await g.status()).agents.patching.receiptsMissing;
    assert.equal(p.usable, false);
    assert.match(p.problem, /does not hold the slip its call was sent under/);
    await assert.rejects(g.acknowledge('patching'), /No call waiting can have a stub/);
    assert.equal((await g.acknowledge('patching', { setAside: [p.call] })).setAside.length, 1);
  } finally {
    await g.close();
  }
  await w.tickets.close();
  await w.patch.close();
});

test('R3-L1: a hard link, or a link to the file, is the same file to the shared-file check', async () => {
  const w = await world();
  await w.close();
  const hash = await secretHash(OTHER_SECRET);
  const linked = join(w.folder, 'hard-link.jsonl');
  linkSync(w.bookPath, linked);
  const books = [linked];
  try {
    symlinkSync(w.bookPath, join(w.folder, 'soft-link.jsonl'), 'file');
    books.push(join(w.folder, 'soft-link.jsonl'));
  } catch (e) {
    // A link to a file needs rights on Windows that the test may not have: the hard link is still tested.
    if (e.code !== 'EPERM') throw e;
  }
  for (const book of books) {
    const config = { ...w.config, agents: { ...w.config.agents, other: { ...w.config.agents.patching, secretHash: hash, book } } };
    await assert.rejects(openGateway(config, { root: w.folder, log: silent }), /share a file/, book);
    assert.ok((await checkConfig(config, { root: w.folder })).problems.some((p) => /share a file/.test(p)));
  }
});

test('R3-L1: the list of calls set aside is among the files two agents may not share', async () => {
  const w = await world();
  await w.close();
  const config = { ...w.config, agents: { ...w.config.agents, other: { ...w.config.agents.patching, secretHash: await secretHash(OTHER_SECRET), book: `${w.bookPath}.journal-set-aside` } } };
  await assert.rejects(openGateway(config, { root: w.folder, log: silent }), /share a file: the list of calls set aside of one is the book file of the other/);
});

test('R4-L1: a journal none of whose lines checks under the key stops the start; one where some check starts, showing the others', async () => {
  const w = await world();
  await w.gateway.close();
  const honest = tagged(w, await readLine(w, 'honest-1', Date.now() - 5000));
  writeFileSync(`${w.bookPath}.journal-key`, `${Buffer.alloc(32, 9).toString('base64url')}\n`);
  writeFileSync(`${w.bookPath}.journal`, `${honest}\n`);
  await assert.rejects(openGateway(w.config, { root: w.folder, log: silent }), /no line of its journal .* checks under its journal key .* leaves the calls they stand for with no receipt/);
  // A line that checks under the key in place, beside the other: the gateway starts, and shows the one that does not.
  writeFileSync(`${w.bookPath}.journal`, `${honest}\n${tagged(w, { done: 'other' })}\n`);
  const g = await openGateway(w.config, { root: w.folder, log: silent });
  try {
    const [p] = (await g.status()).agents.patching.receiptsMissing;
    assert.equal(p.tag, 'invalid');
  } finally {
    await g.close();
  }
  // Only a cut last line: nothing was sent, and the gateway starts.
  writeFileSync(`${w.bookPath}.journal`, honest.slice(0, 30));
  const h = await openGateway(w.config, { root: w.folder, log: silent });
  assert.deepEqual((await h.status()).agents.patching.receiptsMissing, []);
  await h.close();
  await w.tickets.close();
  await w.patch.close();
});

test('R3-L2: a journal that holds lines and has lost its key stops the start, with a sentence; a new key is made only for an empty journal', async () => {
  const w = await world();
  await w.gateway.close();
  writeFileSync(`${w.bookPath}.journal`, `${tagged(w, await readLine(w, 'a', Date.now() - 5000))}\n`);
  renameSync(`${w.bookPath}.journal-key`, `${w.bookPath}.journal-key.moved`);
  await assert.rejects(openGateway(w.config, { root: w.folder, log: silent }), /holds lines, and its journal key .* is missing/);
  writeFileSync(`${w.bookPath}.journal`, '');
  const g = await openGateway(w.config, { root: w.folder, log: silent });
  await g.close();
  assert.equal(readFileSync(`${w.bookPath}.journal-key`, 'utf8').trim().length, 43);
  await w.tickets.close();
  await w.patch.close();
});

test('R3-L2: a line whose rule has since been taken out can be acknowledged, with a warning; a clock behind is said plainly', async () => {
  const w = await world();
  await w.gateway.close();
  const del = { action: 'provared.data.delete', with: 'tickets' };
  writeFileSync(`${w.bookPath}.journal`, `${tagged(w, await readLine(w, 'rule-gone', Date.now() - 5000, del))}\n`);
  const without = { ...w.config, rules: RULES().filter((r) => r.action !== 'provared.data.delete') };
  const g = await openGateway(without, { root: w.folder, log: silent });
  try {
    const [p] = (await g.status()).agents.patching.receiptsMissing;
    assert.equal(p.usable, true, p.problem);
    assert.match(p.warning, /No rule names this action for this service now/);
    assert.equal((await g.acknowledge('patching')).written.length, 1);
  } finally {
    await g.close();
  }
  writeFileSync(`${w.bookPath}.journal`, `${tagged(w, await readLine(w, 'clock', Date.now() - 1000))}\n`);
  const behind = await openGateway(w.config, { root: w.folder, log: silent, now: () => Date.now() - 60000 });
  try {
    const [p] = (await behind.status()).agents.patching.receiptsMissing;
    assert.equal(p.usable, false);
    assert.match(p.problem, /clock is behind .* Put the clock right/);
  } finally {
    await behind.close();
  }
  await w.tickets.close();
  await w.patch.close();
});

test('R3-L3: a line set aside stays set aside, copied back after its set-aside line or into a journal a clean start emptied', async () => {
  const w = await world();
  await w.gateway.close();
  const genuine = tagged(w, await readLine(w, 'aside-1', Date.now() - 5000));
  const forged = 'x {"sending":"f1","action":"host.reboot"}';
  writeFileSync(`${w.bookPath}.journal`, `${genuine}\n${forged}\n`);
  let g = await openGateway(w.config, { root: w.folder, log: silent });
  const calls = (await g.status()).agents.patching.receiptsMissing.map((p) => p.call);
  assert.equal(calls.length, 2);
  await g.acknowledge('patching', { setAside: calls });
  await g.close();
  // Copied back after the set-aside lines.
  writeFileSync(`${w.bookPath}.journal`, `${readFileSync(`${w.bookPath}.journal`, 'utf8')}${genuine}\n${forged}\n`);
  g = await openGateway(w.config, { root: w.folder, log: silent });
  assert.deepEqual((await g.status()).agents.patching.receiptsMissing, []);
  await g.close();
  // A clean start emptied the journal; the lines are put back alone.
  assert.equal(readFileSync(`${w.bookPath}.journal`, 'utf8'), '');
  writeFileSync(`${w.bookPath}.journal`, `${genuine}\n${forged}\n`);
  g = await openGateway(w.config, { root: w.folder, log: silent });
  assert.deepEqual((await g.status()).agents.patching.receiptsMissing, []);
  await g.close();
  assert.match(readFileSync(`${w.bookPath}.journal-set-aside`, 'utf8'), /"setAside":"aside-1"/);
  await w.tickets.close();
  await w.patch.close();
});

test('R3-L4: a fingerprint the library refuses (a stray last character) makes the line unusable, rather than failing the acknowledgement', async () => {
  const w = await world();
  await w.gateway.close();
  const line = await readLine(w, 'stray', Date.now() - 5000);
  line.details[0].sha256 = `${'A'.repeat(42)}B`;
  writeFileSync(`${w.bookPath}.journal`, `${tagged(w, line)}\n`);
  const g = await openGateway(w.config, { root: w.folder, log: silent });
  try {
    const [p] = (await g.status()).agents.patching.receiptsMissing;
    assert.equal(p.usable, false);
    assert.match(p.problem, /The library refuses it: details\[0\]\.sha256/);
    await assert.rejects(g.acknowledge('patching'), /No call waiting can have a stub/);
  } finally {
    await g.close();
  }
  await w.tickets.close();
  await w.patch.close();
});

test('R3-L6, through the gateway: the dotted capital I is "i"', async () => {
  const w = await world();
  try {
    const r = await w.call('POST', '/patch/v1/waves', { headers: { 'content-type': 'application/json' }, body: '{"hosts":[1],"m":{"İTEMS":1,"items":2}}' });
    assert.equal(r.status, 403);
    assert.equal(r.json.code, 'amount-not-found');
    assert.ok(docs !== null);
  } finally {
    await w.close();
  }
});

test('R3 (probe 13): repair takes --cut only as the digits shown, and puts back a lost line ending where the last bytes are a whole entry', async () => {
  const { spawnSync } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));
  const w = await world();
  assert.equal((await w.call('GET', '/tickets/api/now/table/a')).status, 200);
  await w.gateway.close();
  const whole = readFileSync(w.bookPath, 'utf8');
  writeFileSync(w.bookPath, whole.slice(0, -1));
  const settings = join(w.folder, 'repair.json');
  writeFileSync(settings, JSON.stringify({ agents: { patching: { book: w.bookPath } } }));
  const run = (...args) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', BIN, 'repair', '--config', settings, '--agent', 'patching', ...args], { encoding: 'utf8', env: process.env });
  const lastLine = whole.slice(whole.lastIndexOf('\n', whole.length - 2) + 1, -1);
  const n = Buffer.byteLength(lastLine);
  const shown = run();
  assert.match(shown.stdout, /a whole entry, without its line ending/);
  assert.equal(run('--cut', `0x${n.toString(16)}`).status, 2, 'not in another form of number');
  assert.equal(run('--cut', ` ${n}`).status, 2);
  assert.equal(readFileSync(w.bookPath, 'utf8'), whole.slice(0, -1), 'nothing taken off');
  assert.equal(run('--end-line').status, 0);
  assert.equal(readFileSync(w.bookPath, 'utf8'), whole);
  const g = await openGateway(w.config, { root: w.folder, log: silent });
  assert.equal((await g.status()).agents.patching.stopped, null);
  await g.close();
  // A part-written line is not a whole entry: --end-line refuses it.
  writeFileSync(w.bookPath, whole.slice(0, -40));
  assert.equal(run('--end-line').status, 2);
  await w.tickets.close();
  await w.patch.close();
});
