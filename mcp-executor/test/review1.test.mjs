// What the first independent review found, each now a test: a receipt lost
// where the book could not be written after a call (S1); a late answer
// taken for a later call's (M1); a tools/call sent as a notification (M2);
// too many calls or lists waiting (M4); a bare program name (M5); a result
// that cannot be fingerprinted (M6); a copy with a line taken out or put
// twice (L1); the comparison's "differs" and the book's own problems (L2);
// whole numbers beyond what every reader holds (L3); "check" writes
// nothing (L4); and the smaller cases of L9.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { checkBook, identifierFingerprint, argumentsFingerprint } = await import('provared');
const { world, openWorld, until, pause } = await import('./world.mjs');
const { RESULT_DOCUMENT, RESULT_NOT_FINGERPRINTED, OUTCOME_UNKNOWN, openExecutor, checkConfig, resolveCommand } = await import('../executor.mjs');
const { readCopy, loadCopyKey, unfinished } = await import('../copy.mjs');
const { compareCopyWithBook } = await import('../compare.mjs');

async function bookOf(w) {
  return checkBook(w.executor.writer.book(), { issuerKeys: w.settings.agent.issuerKeys });
}
const stubsOf = (checked) => checked.entries.filter((e) => e.kind === 'stub');
const docs = (stub) => Object.fromEntries(stub.content.details.map((d) => [d.name, d.sha256]));
const copyOf = (w) => readCopy(join(w.folder, 'copy.jsonl'), loadCopyKey(join(w.folder, 'copy.jsonl.key')), w.settings.name);
const compareOf = (w, book) =>
  compareCopyWithBook({ copyPath: join(w.folder, 'copy.jsonl'), copyKey: loadCopyKey(join(w.folder, 'copy.jsonl.key')), name: w.settings.name, service: 'executor', book: book ?? readFileSync(join(w.folder, 'book.jsonl'), 'utf8'), options: { issuerKeys: w.settings.agent.issuerKeys } });

test('S1: the book cannot be written after a call was answered: the copy keeps the outcome, the call stays unfinished, and the next start writes the receipt with the result the executor knew', async () => {
  const w = await world();
  const bookPath = join(w.folder, 'book.jsonl');
  let kept;
  try {
    await w.client.call('echo', { first: true });
    kept = readFileSync(bookPath, 'utf8');
    const slow = w.client.call('slow', { ms: 600, tag: 'kept' });
    await until(() => w.fakeSeen().some((s) => s.seen?.method === 'tools/call' && s.seen.params.name === 'slow'));
    // While the call is with the server, the book file becomes unwritable (a folder in its place).
    rmSync(bookPath);
    mkdirSync(bookPath);
    const r = await slow;
    assert.match(r.result.content[0].text, /Done, slowly/, 'the call happened, so the client gets its answer');
    assert.match(w.executor.stopped(), /book could not be written/);
    const copy = copyOf(w);
    const last = copy.lines.at(-1).entry;
    assert.equal(last.kind, 'done');
    assert.equal(last.stub, undefined, 'no stub is named: it is not on the disk');
    assert.equal(last.documents[0].name, RESULT_DOCUMENT);
    assert.equal(last.documents[0].sha256, await argumentsFingerprint(r.result));
    assert.equal(unfinished(copy).length, 1, 'the call is still unfinished');
    const next = await w.client.call('echo', { later: true });
    assert.equal(next.error.code, 1001, 'no more calls are taken');
  } finally {
    await w.close();
  }
  // The book file is put back as it was before the lost receipt; the next start writes it from the copy.
  rmSync(bookPath, { recursive: true });
  writeFileSync(bookPath, kept);
  await openWorld(w);
  try {
    assert.ok(w.logs.some((e) => e.event === 'receipt-written-late' && e.outcome === 'as the copy knew it'));
    const checked = await bookOf(w);
    assert.equal(checked.summary.problemFound, false);
    const stubs = stubsOf(checked);
    assert.equal(stubs.length, 2);
    const d = docs(stubs[1]);
    assert.equal(d[RESULT_DOCUMENT], copyOf(w).lines.find((l) => l.entry.kind === 'done' && !l.entry.stub).entry.documents[0].sha256, 'the result the executor knew, not "outcome unknown"');
    assert.equal(d['provared.error'], undefined);
    assert.equal(stubs[1].countersignature.state, 'valid');
    assert.equal(copyOf(w).lines.at(-1).entry.outcome, 'written-late');
    assert.equal(unfinished(copyOf(w)).length, 0);
    const c = await compareOf(w);
    assert.equal(c.summary.agree, true, JSON.stringify(c.summary));
    assert.equal(c.matched.filter((m) => m.note === 'written at a later start').length, 1);
  } finally {
    await w.close();
  }
});

test('S1, compare: a receipt the executor itself could not write is reported apart from one the book\'s keeper left out', async () => {
  const w = await world();
  const bookPath = join(w.folder, 'book.jsonl');
  try {
    await w.client.call('echo', { a: 1 });
    const kept = readFileSync(bookPath, 'utf8');
    const slow = w.client.call('slow', { ms: 500 });
    await until(() => w.fakeSeen().some((s) => s.seen?.method === 'tools/call' && s.seen.params.name === 'slow'));
    rmSync(bookPath);
    mkdirSync(bookPath);
    await slow;
    await w.close();
    rmSync(bookPath, { recursive: true });
    writeFileSync(bookPath, kept);
    const c = await compareOf(w, kept);
    assert.equal(c.summary.notWrittenByExecutor, 1);
    assert.equal(c.summary.missingFromBook, 0);
    assert.equal(c.summary.agree, false);
    assert.equal(c.notWritten[0].tool, 'slow');
  } finally {
    await w.close();
  }
});

test('M1: a server that ignores cancellation answers late; the late answer is dropped, and a later call under the same client id gets its own answer and its own receipt', async () => {
  const w = await world({ config: { timeout: 1000 }, env: { FAKE_IGNORE_CANCEL: { value: '1' } } });
  try {
    const first = await w.client.call('slow', { ms: 1800, tag: 'late' }, { id: 'reused' });
    assert.equal(first.error.code, 1002, 'the time ran out');
    const second = await w.client.call('echo', { fresh: true }, { id: 'reused' });
    assert.equal(second.result.structuredContent.args.fresh, true, 'the second call gets its own answer, not the late one');
    await until(() => w.logs.some((e) => e.event === 'late-answer-dropped'));
    assert.equal(w.client.others.filter((m) => m.id === 'reused').length, 0, 'the late answer never reached the client');
    const stubs = stubsOf(await bookOf(w));
    assert.equal(stubs.length, 2);
    assert.ok(docs(stubs[0])['provared.error'], 'the first receipt names the error');
    assert.equal(docs(stubs[1])[RESULT_DOCUMENT], await argumentsFingerprint(second.result), 'the second names its own result');
    const seen = w.fakeSeen().filter((s) => s.seen?.method === 'tools/call').map((s) => s.seen.id);
    assert.deepEqual(seen, ['provared-1', 'provared-2'], 'each call went to the server under an id of the executor\'s own');
  } finally {
    await w.close();
  }
});

test('M2: a tools/call sent as a notification, or any notification outside the protocol\'s own, is dropped and logged', async () => {
  const w = await world();
  try {
    w.client.notify('tools/call', { name: 'echo', arguments: { sneaky: true } });
    w.client.notify('resources/read', { uri: 'x' });
    w.client.notify('notifications/initialized');
    const ping = await w.client.request('ping');
    assert.deepEqual(ping.result, {});
    const seen = w.fakeSeen().filter((s) => s.seen).map((s) => s.seen.method);
    assert.deepEqual(seen, ['notifications/initialized', 'ping']);
    assert.equal(w.logs.filter((e) => e.event === 'notification-dropped').length, 2);
  } finally {
    await w.close();
  }
});

test('M4: calls past maxWaiting are refused with 1001 and nothing written; too many tools/list requests waiting are refused', async () => {
  const w = await world({ config: { maxWaiting: 2 } });
  try {
    const a = w.client.call('slow', { ms: 500 }, { id: 'a' });
    const b = w.client.call('slow', { ms: 100 }, { id: 'b' });
    await pause(50);
    const c = await w.client.call('echo', {}, { id: 'c' });
    assert.equal(c.error.code, 1001);
    assert.match(c.error.message, /maxWaiting/);
    await a;
    await b;
    const d = await w.client.call('echo', {}, { id: 'd' });
    assert.equal(d.result.resultType, 'complete', 'room again once one has ended');
    const checked = await bookOf(w);
    assert.equal(stubsOf(checked).length, 3);
    assert.equal(checked.entries.filter((e) => e.kind === 'denial').length, 0, 'a refusal for want of room is no denial');
    assert.ok(!copyOf(w).lines.some((l) => l.entry.call === undefined && l.entry.kind === 'refused'));
  } finally {
    await w.close();
  }
  const v = await world();
  try {
    // 256 tools/list requests may wait; the 257th is refused. The server answers each, so send them before it can.
    for (let i = 0; i < 256; i++) v.client.send({ jsonrpc: '2.0', id: `l${i}`, method: 'tools/list' });
    v.client.send({ jsonrpc: '2.0', id: 'l256', method: 'tools/list' });
    const refused = await until(() => v.client.others.find((m) => m.id === 'l256' && m.error));
    assert.equal(refused.error.code, 1001);
    await until(() => v.client.others.filter((m) => m.result?.tools).length === 256, { timeout: 15000 });
  } finally {
    await v.close();
  }
});

test('M5: a program named by a bare name is found through the folders given, or warned about when found through the environment; one not found stops the start', async () => {
  const w = await world({ open: false });
  const bare = { ...w.settings, server: { ...w.settings.server, command: 'definitely-not-a-program-of-this-computer' } };
  await assert.rejects(openExecutor(bare, { root: w.folder, log: () => {} }), /no program named/);
  const report = await checkConfig(bare, w.folder);
  assert.match(report.problems[0], /no program named/);
  // process.execPath is absolute, so the world's own settings give no warning.
  const plain = await checkConfig(w.settings, w.folder);
  assert.ok(!plain.warnings.some((m) => m.includes('bare name')));
  assert.equal(plain.program, process.execPath);
  // Resolved through the executor's own PATH: a warning. Through server.path: none.
  const dir = join(w.folder, 'bin');
  mkdirSync(dir);
  writeFileSync(join(dir, process.platform === 'win32' ? 'made-up-server.exe' : 'made-up-server'), '');
  const viaEnv = resolveCommand('made-up-server', { root: w.folder, path: null, env: { PATH: dir } });
  assert.equal(viaEnv.path, join(dir, process.platform === 'win32' ? 'made-up-server.exe' : 'made-up-server'));
  assert.match(viaEnv.warning, /bare name/);
  const viaPath = resolveCommand('made-up-server', { root: w.folder, path: [dir], env: { PATH: '' } });
  assert.equal(viaPath.warning, null);
  assert.throws(() => resolveCommand('made-up-server', { root: w.folder, path: ['/nowhere'], env: { PATH: dir } }), /no program named/);
  // On Windows a .cmd shim is not found: a program started without a shell cannot run it.
  writeFileSync(join(dir, 'shim.cmd'), '');
  assert.throws(() => resolveCommand('shim', { root: w.folder, path: [dir], env: {}, platform: 'win32' }), /no program named/);
});

test('M6: a result that cannot be written in the one form gets provared.error with a fixed text, and the executor says so', async () => {
  const w = await world({ config: { tools: { weird: { action: 'tool.run' } } } });
  try {
    const r = await w.client.call('weird', {});
    assert.equal(r.result.resultType, 'complete', 'the server\'s answer still reaches the client as it is');
    const [stub] = stubsOf(await bookOf(w));
    const d = docs(stub);
    assert.equal(d[RESULT_DOCUMENT], undefined);
    assert.equal(d['provared.error'], await identifierFingerprint(RESULT_NOT_FINGERPRINTED));
    assert.equal(stub.countersignature.state, 'valid');
    assert.ok(w.logs.some((e) => e.event === 'result-not-fingerprinted'));
    assert.equal(copyOf(w).lines.at(-1).entry.documents[0].name, 'provared.error');
  } finally {
    await w.close();
  }
});

test('L1: a line of the copy taken out, put twice or moved stops the start; a line whose tag fails is not acted on', async () => {
  const w = await world();
  await w.client.call('echo', {});
  await w.client.call('echo', {});
  await w.close();
  const copyPath = join(w.folder, 'copy.jsonl');
  const whole = readFileSync(copyPath, 'utf8');
  const lines = whole.split('\n').filter(Boolean);
  assert.equal(lines.length, 4);
  const start = () => openExecutor(w.settings, { root: w.folder, log: () => {} });
  writeFileSync(copyPath, `${[lines[0], lines[2], lines[3]].join('\n')}\n`);
  await assert.rejects(start(), /taken out, or does not check/);
  writeFileSync(copyPath, `${[...lines, lines[1]].join('\n')}\n`);
  await assert.rejects(start(), /put twice/);
  writeFileSync(copyPath, `${[lines[1], lines[0], lines[2], lines[3]].join('\n')}\n`);
  await assert.rejects(start(), /not whole/);
  // A line that does not check: it is refused, and unfinished() does not see the "sending" it holds.
  const key = loadCopyKey(join(w.folder, 'copy.jsonl.key'));
  const forged = `${lines[0].slice(0, 43)} ${JSON.stringify({ seq: 4, kind: 'sending', call: 'forged', when: new Date().toISOString(), slip: 'x', tool: 'echo', action: 'provared.data.read', with: 'executor', details: [] })}`;
  writeFileSync(copyPath, `${[...lines, forged].join('\n')}\n`);
  const read = readCopy(copyPath, key, w.settings.name);
  assert.equal(read.refused, 1);
  assert.equal(unfinished(read).length, 0);
  assert.equal(read.sequence.ok, false);
  await assert.rejects(start(), /does not check/);
  writeFileSync(copyPath, whole);
  await openWorld(w);
  await w.close();
});

test('L2: compare reports "differs" where the book holds another receipt for the call, and does not agree where the book has a problem', async () => {
  const w = await world();
  await w.client.call('echo', { x: 1 });
  await w.close();
  const book = readFileSync(join(w.folder, 'book.jsonl'), 'utf8');
  const lines = book.split('\n').filter(Boolean);
  // The stub's line changed in a way that keeps it a stub for the same call: the copy's stub fingerprint no longer matches the book's entry.
  const entry = JSON.parse(lines[1]);
  const other = { ...entry, stub: { ...entry.stub, signatures: [] } };
  let c = await compareOf(w, `${lines[0]}\n${JSON.stringify(other)}\n`);
  assert.equal(c.summary.agree, false);
  assert.ok(c.book.problemFound, 'a stub with its signatures taken off has a problem');
  c = await compareOf(w, `${book}{"not":"a line"}\n`);
  assert.equal(c.summary.matched, 1);
  assert.equal(c.summary.agree, false, 'the book has a problem, so nothing agrees');
  assert.equal(c.summary.bookProblem, true);
  // "differs": a stub that reads as the same call but is not the one the copy names. Made by changing the copy's record of the stub.
  const copyPath = join(w.folder, 'copy.jsonl');
  const key = loadCopyKey(join(w.folder, 'copy.jsonl.key'));
  const read = readCopy(copyPath, key, w.settings.name);
  const done = read.lines.find((l) => l.entry.kind === 'done').entry;
  const { openCopy } = await import('../copy.mjs');
  writeFileSync(copyPath, `${read.lines[0].raw}\n`);
  openCopy(copyPath, key, w.settings.name, 1).note({ ...done, stub: 'A'.repeat(43) });
  delete done.seq;
  c = await compareOf(w, book);
  assert.equal(c.summary.differ, 1);
  assert.equal(c.differs[0].inBook, stubsOf(await checkBook(book, { issuerKeys: w.settings.agent.issuerKeys }))[0].fingerprint);
});

test('L3: a line holding a whole number beyond 2^53 - 1 is refused, in an id or anywhere else', async () => {
  const w = await world();
  try {
    w.client.raw('{"jsonrpc":"2.0","id":9007199254740993,"method":"ping"}\n');
    let m = await w.client.nextOther();
    assert.equal(m.error.code, -32600);
    w.client.raw('{"jsonrpc":"2.0","id":"big","method":"tools/call","params":{"name":"order","arguments":{"total":18446744073709551616}}}\n');
    m = await w.client.nextOther();
    assert.equal(m.error.code, -32600);
    w.client.raw('{"jsonrpc":"2.0","id":"neg","method":"ping","params":{"n":-9007199254740992}}\n');
    m = await w.client.nextOther();
    assert.equal(m.error.code, -32600);
    assert.equal(w.fakeSeen().filter((s) => s.seen).length, 0);
    w.client.raw('{"jsonrpc":"2.0","id":9007199254740991,"method":"ping","params":{"s":"9007199254740993","f":1e300}}\n');
    m = await w.client.nextOther();
    assert.deepEqual(m.result, {}, 'the largest safe number, a number in text, and a float pass');
  } finally {
    await w.close();
  }
});

test('L4: check writes nothing: no book line, no copy key, no copy', async () => {
  const w = await world({ open: false });
  const before = ['book.jsonl', 'copy.jsonl.key', 'copy.jsonl'].map((f) => existsSync(join(w.folder, f)));
  assert.deepEqual(before, [false, false, false]);
  const r = await checkConfig(w.settings, w.folder);
  assert.deepEqual(r.problems, []);
  assert.equal(r.unfinished, 0);
  const after = ['book.jsonl', 'copy.jsonl.key', 'copy.jsonl'].map((f) => existsSync(join(w.folder, f)));
  assert.deepEqual(after, [false, false, false]);
  // A copy that exists without its key: check says so.
  writeFileSync(join(w.folder, 'copy.jsonl'), 'x y\n');
  const r2 = await checkConfig(w.settings, w.folder);
  assert.match(r2.problems[0], /key .* is missing/);
});

test('L6: a permission that names other services beside the executor gets a warning', async () => {
  const w = await world({ open: false, slip: { with: undefined } });
  const v = await world({ open: false });
  const { signSlip } = await import('./world.mjs');
  const slip = await signSlip({ passkey: v.passkey, agentKeys: v.agentKeys, executorKeys: v.executorKeys, with: [{ id: 'executor', name: 'The executor', keys: v.executorKeys }, { id: 'elsewhere', name: 'Another service' }] });
  writeFileSync(join(v.folder, 'slip.json'), JSON.stringify(slip));
  const r = await checkConfig(v.settings, v.folder);
  assert.deepEqual(r.problems, []);
  assert.ok(r.warnings.some((m) => m.includes('other services beside the executor') && m.includes('elsewhere')));
  assert.ok(w.folder);
});

test('L9: a call still waiting its turn when the executor stops is not sent; a cancellation that lands while the stub is being made withdraws the call', async () => {
  const w = await world();
  try {
    const a = w.client.call('slow', { ms: 600 }, { id: 'a' });
    await until(() => w.fakeSeen().some((s) => s.seen?.method === 'tools/call'));
    const b = w.client.call('echo', { queued: true }, { id: 'b' });
    // The book file changes while "a" is with the server: the executor stops when "b" comes to its turn.
    writeFileSync(join(w.folder, 'book.jsonl'), `${readFileSync(join(w.folder, 'book.jsonl'), 'utf8')}{"not":"a line"}\n`);
    await a;
    const rb = await b;
    assert.equal(rb.error.code, 1001);
    assert.equal(w.fakeSeen().filter((s) => s.seen?.method === 'tools/call').length, 1, 'the queued call was never sent');
  } finally {
    await w.close();
  }
  const v = await world();
  try {
    // Many calls at once: a cancellation for one still waiting lands while an earlier one holds the turn.
    const first = v.client.call('slow', { ms: 300 }, { id: 'f' });
    await until(() => v.fakeSeen().some((s) => s.seen?.method === 'tools/call'));
    const second = v.client.call('echo', {}, { id: 's', timeout: 1500 });
    second.catch(() => {});
    v.client.notify('notifications/cancelled', { requestId: 's' });
    await first;
    await pause(400);
    assert.equal(v.fakeSeen().filter((s) => s.seen?.method === 'tools/call').length, 1);
    assert.deepEqual(copyOf(v).lines.map((l) => l.entry.kind), ['sending', 'done', 'withdrawn']);
  } finally {
    await v.close();
  }
});
