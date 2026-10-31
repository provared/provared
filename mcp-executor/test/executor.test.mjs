// The executor on the made-up server: what passes through, what is checked,
// what is written, and what happens when the server or the agent misbehaves.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { checkBook, identifierFingerprint, argumentsFingerprint } = await import('provared');
const { world, openWorld, until, pause } = await import('./world.mjs');
const { CALL_DOCUMENT, TOOL_DOCUMENT, RESULT_DOCUMENT, CALL_META, UNLISTED_ACTION, OUTCOME_UNKNOWN, openExecutor } = await import('../executor.mjs');
const { readCopy, loadCopyKey, openCopy } = await import('../copy.mjs');
const { compareCopyWithBook } = await import('../compare.mjs');

const META = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} };

async function bookOf(w) {
  return checkBook(w.executor.writer.book(), { issuerKeys: w.settings.agent.issuerKeys });
}
function stubsOf(checked) {
  return checked.entries.filter((e) => e.kind === 'stub');
}
function docs(stub) {
  return Object.fromEntries(stub.content.details.map((d) => [d.name, d.sha256]));
}
function copyOf(w) {
  return readCopy(join(w.folder, 'copy.jsonl'), loadCopyKey(join(w.folder, 'copy.jsonl.key')), w.settings.name);
}

test('messages of both eras pass through unchanged; the server\'s answers come back; tools/list hides tools without a rule', async () => {
  const w = await world();
  try {
    const discover = await w.client.request('server/discover', { _meta: META });
    assert.deepEqual(discover.result.supportedVersions, ['2026-07-28']);
    const init = await w.client.request('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '1' } });
    assert.equal(init.result.serverInfo.name, 'fake-server');
    w.client.notify('notifications/initialized');
    const ping = await w.client.request('ping');
    assert.deepEqual(ping.result, {});
    const unknown = await w.client.request('resources/list');
    assert.equal(unknown.error.code, -32601, 'the server\'s own error comes back as it is');
    const page1 = await w.client.request('tools/list', { _meta: META });
    assert.deepEqual(page1.result.tools.map((t) => t.name), ['echo', 'order', 'slow', 'crash', 'fail']);
    assert.equal(page1.result.nextCursor, 'page2', 'the rest of the answer is kept');
    const page2 = await w.client.request('tools/list', { cursor: 'page2', _meta: META });
    assert.deepEqual(page2.result.tools.map((t) => t.name), ['error', 'ask', 'big'], '"hidden" has no rule and is not shown');
    assert.ok(w.logs.some((e) => e.event === 'tools-hidden' && e.hidden === 1));
    const seen = w.fakeSeen().filter((s) => s.seen).map((s) => s.seen.method);
    assert.deepEqual(seen, ['server/discover', 'initialize', 'notifications/initialized', 'ping', 'resources/list', 'tools/list', 'tools/list']);
  } finally {
    await w.close();
  }
  const shown = await world({ config: { hideUnlisted: false } });
  try {
    const page2 = await shown.client.request('tools/list', { cursor: 'page2', _meta: META });
    assert.deepEqual(page2.result.tools.map((t) => t.name), ['error', 'hidden', 'ask', 'big']);
  } finally {
    await shown.close();
  }
});

test('a call the permission allows is sent with the server\'s credential and without the agent\'s environment, answered as the server answered, and given a countersigned receipt', async () => {
  process.env.AGENT_SECRET = 'the-agent-holds-this';
  const w = await world();
  try {
    const r = await w.client.call('echo', { b: 2, a: 'one' }, { meta: { traceparent: '00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01' } });
    assert.equal(r.result.resultType, 'complete');
    const seen = r.result.structuredContent;
    assert.equal(seen.token, 'made-up-token-for-the-tests', 'the credential reached the server from the executor\'s file');
    assert.equal(seen.agentSecret, null, 'the executor\'s own environment is not passed on');
    assert.equal(typeof seen.meta[CALL_META], 'string', 'the executor\'s identifier for the call went to the server');
    assert.equal(seen.meta.traceparent, '00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01', 'the client\'s _meta is kept');
    const checked = await bookOf(w);
    assert.equal(checked.summary.problemFound, false);
    assert.equal(checked.summary.fullyChecked, true);
    assert.equal(checked.summary.withinSlips, true);
    const [stub] = stubsOf(checked);
    assert.equal(stub.content.with, 'executor');
    assert.equal(stub.content.action, 'provared.data.read');
    assert.equal(stub.countersignature.state, 'valid', 'countersigned with the executor\'s keys');
    const d = docs(stub);
    assert.equal(d['provared.arguments'], await argumentsFingerprint({ b: 2, a: 'one' }));
    assert.equal(d[TOOL_DOCUMENT], await identifierFingerprint('echo'));
    assert.equal(d[CALL_DOCUMENT], await identifierFingerprint(seen.meta[CALL_META]));
    assert.equal(d['provared.request-id'], d[CALL_DOCUMENT]);
    assert.equal(d['provared.trace-id'], await identifierFingerprint('0af7651916cd43dd8448eb211c80319c'));
    assert.equal(d[RESULT_DOCUMENT], await argumentsFingerprint(r.result), 'the result as the server gave it, in the one form');
    assert.equal(d['provared.error'], undefined);
    // The copy: a line before the call was sent, and one after.
    const copy = copyOf(w);
    assert.equal(copy.refused, 0);
    const kinds = copy.lines.map((l) => l.entry.kind);
    assert.deepEqual(kinds, ['sending', 'done']);
    assert.equal(copy.lines[0].entry.call, seen.meta[CALL_META]);
    assert.equal(copy.lines[1].entry.stub, stub.fingerprint);
    assert.equal(copy.lines[1].entry.countersigned, true);
    assert.equal(copy.lines[1].entry.outcome, 'answer');
    assert.ok(!JSON.stringify(copy.lines).includes('made-up-token'), 'no credential in the copy');
    assert.ok(!JSON.stringify(w.logs).includes('made-up-token'), 'no credential in the log');
    // The book file holds the same book.
    assert.equal(readFileSync(join(w.folder, 'book.jsonl'), 'utf8'), w.executor.writer.book());
  } finally {
    delete process.env.AGENT_SECRET;
    await w.close();
  }
});

test('a call outside the permission is not sent: the model is told, and a denial is written', async () => {
  const w = await world({ slip: { limits: [{ action: 'supplies.order', max: 100, unit: 'GBP' }] } });
  try {
    const ok = await w.client.call('order', { total: 60 });
    assert.equal(ok.result.content[0].text, 'Ordered for 60.');
    const over = await w.client.call('order', { total: 50 });
    assert.equal(over.result.isError, true);
    assert.equal(over.result._meta['red.prova/refused'], 'not-allowed');
    assert.deepEqual(over.result._meta['red.prova/codes'], ['over-limit']);
    assert.match(over.result.content[0].text, /^Not taken by the Provared executor/);
    const calls = w.fakeSeen().filter((s) => s.seen?.method === 'tools/call');
    assert.equal(calls.length, 1, 'the second call never reached the server');
    const checked = await bookOf(w);
    const denial = checked.entries.find((e) => e.kind === 'denial');
    assert.ok(denial);
    assert.equal(denial.content.source, 'check');
    assert.deepEqual(denial.content.codes, ['over-limit']);
    assert.deepEqual(denial.content.amount, { unit: 'GBP', value: 50 });
    assert.equal(over.result._meta['red.prova/denial'], denial.fingerprint);
    assert.equal(checked.summary.withinSlips, true, 'nothing outside the permission was taken');
    const copy = copyOf(w);
    const refused = copy.lines.find((l) => l.entry.kind === 'refused');
    assert.equal(refused.entry.reason, 'not-allowed');
    assert.equal(refused.entry.denial, denial.fingerprint);
    assert.ok(!denial.content.details.some((d) => d.name === CALL_DOCUMENT || d.name === 'provared.request-id'), 'a denial names no identifier that was never sent');
  } finally {
    await w.close();
  }
});

test('a tool with no rule is refused and written as a denial; an amount that cannot be read is refused', async () => {
  const w = await world();
  try {
    const r = await w.client.call('hidden', {});
    assert.equal(r.result.isError, true);
    assert.equal(r.result._meta['red.prova/refused'], 'unlisted');
    const none = await w.client.call('order', { amount: 5 });
    assert.equal(none.result._meta['red.prova/refused'], 'amount-not-found');
    const folded = await w.client.raw(`${JSON.stringify({ jsonrpc: '2.0', id: 'f1', method: 'tools/call', params: { name: 'order', arguments: { total: 5, TOTAL: 7 } } })}\n`);
    assert.ok(folded);
    const answer = await until(() => w.client.others.find((m) => m.id === 'f1'));
    assert.equal(answer.result._meta['red.prova/refused'], 'amount-not-found', 'two names that differ only in capitals');
    assert.equal(w.fakeSeen().filter((s) => s.seen?.method === 'tools/call').length, 0);
    const checked = await bookOf(w);
    const denials = checked.entries.filter((e) => e.kind === 'denial');
    assert.equal(denials.length, 3);
    assert.equal(denials[0].content.action, UNLISTED_ACTION);
    assert.equal(denials[0].content.source, 'rule');
    assert.equal(denials[1].content.action, 'supplies.order');
  } finally {
    await w.close();
  }
  const forward = await world({ config: { unlisted: 'forward' } });
  try {
    const r = await forward.client.call('hidden', {});
    assert.equal(r.error.code, -32602, 'the server\'s own answer: it knows no tool "hidden" either');
    assert.ok(forward.logs.some((e) => e.event === 'forwarded-unlisted'));
    assert.equal(stubsOf(await bookOf(forward)).length, 0, 'no receipt');
  } finally {
    await forward.close();
  }
});

test('a tool execution error and a protocol error from the server come back as they are, each with a receipt', async () => {
  const w = await world();
  try {
    const failed = await w.client.call('fail', {});
    assert.equal(failed.result.isError, true);
    assert.equal(failed.result.content[0].text, 'It did not work.');
    const error = await w.client.call('error', {});
    assert.deepEqual(error.error, { code: -32602, message: 'Bad arguments.' });
    const stubs = stubsOf(await bookOf(w));
    assert.equal(stubs.length, 2);
    assert.ok(docs(stubs[0])[RESULT_DOCUMENT], 'an isError result is still a result');
    assert.equal(docs(stubs[1])['provared.error'], await identifierFingerprint('The tool server answered with an error: {"code":-32602,"message":"Bad arguments."}'));
    assert.equal(stubs[1].countersignature.state, 'valid');
  } finally {
    await w.close();
  }
});

test('the server ends while a call is with it: the call gets its receipt with an error, the client an error, and the executor ends with the server\'s code', async () => {
  const w = await world();
  try {
    const r = await w.client.call('crash', {});
    assert.equal(r.error.code, 1002);
    assert.match(r.error.message, /ended before it answered/);
    const ended = await w.ended;
    assert.equal(ended.code, 3);
    const [stub] = stubsOf(await bookOf(w));
    assert.equal(docs(stub)['provared.error'], await identifierFingerprint('The tool server ended before it answered this call, so its outcome is not known.'));
    assert.equal(stub.countersignature.state, 'valid');
    assert.equal(copyOf(w).lines.at(-1).entry.outcome, 'error');
  } finally {
    w.client.end();
  }
});

test('no answer within the time allowed: the executor cancels the call, writes the receipt with an error, and tells the client', async () => {
  const w = await world({ config: { timeout: 1000 } });
  try {
    const r = await w.client.call('slow', { never: true });
    assert.equal(r.error.code, 1002);
    assert.match(r.error.message, /no answer within 1000 ms/);
    assert.ok(w.fakeSeen().some((s) => s.seen?.method === 'notifications/cancelled'));
    const [stub] = stubsOf(await bookOf(w));
    assert.ok(docs(stub)['provared.error']);
    const next = await w.client.call('echo', {});
    assert.equal(next.result.resultType, 'complete', 'the executor goes on');
  } finally {
    await w.close();
  }
});

test('the agent cancels a call: while it is with the server the receipt says so; while it still waits its turn nothing is sent and nothing is written', async () => {
  const w = await world();
  try {
    const first = w.client.call('slow', { ms: 1500 }, { id: 'c1' });
    await until(() => w.fakeSeen().some((s) => s.seen?.method === 'tools/call'));
    const second = w.client.call('echo', { q: 1 }, { id: 'c2', timeout: 1500 });
    second.catch(() => {});
    await pause(50);
    w.client.notify('notifications/cancelled', { requestId: 'c2', reason: 'changed my mind' });
    w.client.notify('notifications/cancelled', { requestId: 'c1', reason: 'too slow' });
    const r1 = await first;
    assert.equal(r1.error.code, 1002);
    assert.match(r1.error.message, /cancelled this call while it was with the tool server/);
    // The server knows the call by the executor's own id, and the cancellation names that id.
    const sentCall = w.fakeSeen().find((s) => s.seen?.method === 'tools/call');
    assert.match(sentCall.seen.id, /^provared-[0-9]+-/);
    assert.ok(w.fakeSeen().some((s) => s.seen?.method === 'notifications/cancelled' && s.seen.params.requestId === sentCall.seen.id));
    let answered = false;
    second.then(
      () => {
        answered = true;
      },
      () => {},
    );
    await pause(300);
    assert.equal(answered, false, 'a withdrawn call gets no answer');
    assert.equal(w.fakeSeen().filter((s) => s.seen?.method === 'tools/call').length, 1, 'the withdrawn call never reached the server');
    const checked = await bookOf(w);
    assert.equal(stubsOf(checked).length, 1);
    assert.equal(checked.entries.filter((e) => e.kind === 'denial').length, 0);
    assert.deepEqual(
      copyOf(w).lines.map((l) => l.entry.kind),
      ['sending', 'done', 'withdrawn'],
    );
    const late = await until(() => w.fakeSeen().find((s) => s.notAnswered !== undefined));
    assert.ok(late, 'the server did not answer the cancelled call');
  } finally {
    await w.close();
  }
});

test('a server of the earlier revision that asks the client something mid-call: both directions pass through', async () => {
  const w = await world();
  try {
    const asked = w.client.call('ask', {}, { id: 'a1' });
    const question = await w.client.nextOther();
    assert.equal(question.method, 'sampling/createMessage');
    w.client.send({ jsonrpc: '2.0', id: question.id, result: { role: 'assistant', content: { type: 'text', text: 'yes' } } });
    const r = await asked;
    assert.match(r.result.content[0].text, /The client said/);
    assert.equal(stubsOf(await bookOf(w)).length, 1);
  } finally {
    await w.close();
  }
});

test('lines the executor cannot read strictly are refused, not passed on', async () => {
  const w = await world();
  try {
    w.client.raw('not json\n');
    let m = await w.client.nextOther();
    assert.equal(m.error.code, -32700);
    w.client.raw(`${JSON.stringify([{ jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'hidden' } }])}\n`);
    m = await w.client.nextOther();
    assert.equal(m.error.code, -32600, 'a batch');
    w.client.raw('{"jsonrpc":"2.0","id":"d1","method":"ping","method":"tools/call","params":{"name":"hidden"}}\n');
    m = await w.client.nextOther();
    assert.equal(m.error.code, -32600, 'a member name given twice');
    assert.equal(m.id, null);
    w.client.raw('{"jsonrpc":"2.0","id":"d2","method":"tools/call","params":{"name":"echo","arguments":{"a":1,"a":2}}}\n');
    m = await w.client.nextOther();
    assert.equal(m.error.code, -32600, 'a member name given twice, deep in the arguments');
    w.client.raw('{"jsonrpc":"2.0","id":1.5,"method":"ping"}\n');
    m = await w.client.nextOther();
    assert.equal(m.error.code, -32600, 'an id that is not a whole number');
    w.client.raw('{"jsonrpc":"2.0","id":"d3","method":"tools/call","params":{"name":"../echo"}}\n');
    m = await w.client.nextOther();
    assert.equal(m.error.code, -32602, 'a tool name outside the form');
    w.client.raw('{"jsonrpc":"2.0","id":"d4","method":"tools/call","params":{"name":"echo","arguments":[1]}}\n');
    m = await w.client.nextOther();
    assert.equal(m.error.code, -32602, 'arguments that are not an object');
    w.client.raw(`{"jsonrpc":"2.0","id":"long","method":"ping","pad":"${'x'.repeat(17 * 1024 * 1024)}"}\n`);
    m = await w.client.nextOther(20000);
    assert.equal(m.error.code, -32600, 'a line too long');
    assert.equal(w.fakeSeen().filter((s) => s.seen).length, 0, 'none of it reached the server');
    const fine = await w.client.request('ping');
    assert.deepEqual(fine.result, {}, 'the executor goes on');
  } finally {
    await w.close();
  }
});

test('two calls with one id: the second is refused while the first is in progress', async () => {
  const w = await world();
  try {
    w.client.raw(`${JSON.stringify({ jsonrpc: '2.0', id: 'same', method: 'tools/call', params: { name: 'slow', arguments: { ms: 400 } } })}\n`);
    await until(() => w.fakeSeen().some((s) => s.seen?.method === 'tools/call'));
    w.client.raw(`${JSON.stringify({ jsonrpc: '2.0', id: 'same', method: 'tools/call', params: { name: 'echo' } })}\n`);
    const m = await w.client.nextOther();
    assert.equal(m.error.code, -32600);
    const r = await w.client.nextOther();
    assert.equal(r.result.content[0].text, 'Done, slowly.');
  } finally {
    await w.close();
  }
});

test('the executor refuses calls it cannot record: the book file changed by someone else, or its own copy unwritable', async () => {
  const w = await world();
  try {
    await w.client.call('echo', {});
    writeFileSync(join(w.folder, 'book.jsonl'), `${readFileSync(join(w.folder, 'book.jsonl'), 'utf8')}{"not":"a line of the book"}\n`);
    const r = await w.client.call('echo', {});
    assert.equal(r.error.code, 1001);
    assert.match(r.error.message, /not as the executor left it/);
    assert.equal(w.fakeSeen().filter((s) => s.seen?.method === 'tools/call').length, 1);
    assert.ok(w.executor.stopped());
  } finally {
    await w.close();
  }
  const v = await world();
  try {
    await v.client.call('echo', {});
    rmSync(join(v.folder, 'copy.jsonl'));
    mkdirSync(join(v.folder, 'copy.jsonl'));
    const r = await v.client.call('echo', {});
    assert.equal(r.error.code, 1001);
    assert.match(r.error.message, /could not write its own copy/);
    assert.equal(v.fakeSeen().filter((s) => s.seen?.method === 'tools/call').length, 1, 'nothing more was sent');
    assert.equal(stubsOf(await bookOf(v)).length, 1);
    assert.ok(v.executor.stopped());
  } finally {
    await v.close();
  }
});

test('a call sent and never given its receipt (the executor stopped) is given one at the next start, from the copy', async () => {
  const w = await world();
  await w.client.call('echo', {});
  await w.close();
  const key = loadCopyKey(join(w.folder, 'copy.jsonl.key'));
  const copy = openCopy(join(w.folder, 'copy.jsonl'), key, w.settings.name, readCopy(join(w.folder, 'copy.jsonl'), key, w.settings.name).next);
  const details = [{ name: 'provared.arguments', sha256: await argumentsFingerprint({}) }, { name: TOOL_DOCUMENT, sha256: await identifierFingerprint('slow') }, { name: CALL_DOCUMENT, sha256: await identifierFingerprint('lost-call') }];
  copy.note({ kind: 'sending', call: 'lost-call', when: new Date().toISOString(), slip: w.executor.slip.fingerprint, tool: 'slow', action: 'slow.work', with: 'executor', details });
  await openWorld(w);
  try {
    assert.ok(w.logs.some((e) => e.event === 'receipt-written-late' && e.call === 'lost-call'));
    const checked = await bookOf(w);
    assert.equal(checked.summary.problemFound, false);
    const stubs = stubsOf(checked);
    assert.equal(stubs.length, 2);
    const d = docs(stubs[1]);
    assert.equal(d['provared.error'], await identifierFingerprint(OUTCOME_UNKNOWN));
    assert.equal(d[CALL_DOCUMENT], await identifierFingerprint('lost-call'));
    assert.equal(stubs[1].countersignature.state, 'valid');
    const last = copyOf(w).lines.at(-1).entry;
    assert.equal(last.kind, 'done');
    assert.equal(last.outcome, 'outcome-unknown');
    assert.equal(last.stub, stubs[1].fingerprint);
  } finally {
    await w.close();
  }
  // A second start writes nothing more.
  await openWorld(w);
  try {
    assert.ok(!w.logs.some((e) => e.event === 'receipt-written-late'));
    assert.equal(stubsOf(await bookOf(w)).length, 2);
  } finally {
    await w.close();
  }
  // Under another permission: the executor does not open.
  const again = openCopy(join(w.folder, 'copy.jsonl'), key, w.settings.name, readCopy(join(w.folder, 'copy.jsonl'), key, w.settings.name).next);
  again.note({ kind: 'sending', call: 'other-slip-call', when: new Date().toISOString(), slip: 'A'.repeat(43), tool: 'slow', action: 'slow.work', with: 'executor', details });
  await assert.rejects(openExecutor(w.settings, { root: w.folder, log: () => {} }), /not the one in force/);
});

test('the copy held against the book: they agree; a receipt taken out of the book is found missing; a copy line that does not check is reported', async () => {
  const w = await world({ slip: { limits: [{ action: 'supplies.order', max: 100, unit: 'GBP' }] } });
  await w.client.call('echo', {});
  await w.client.call('order', { total: 30 });
  await w.client.call('order', { total: 90 });
  await w.close();
  const options = { copyPath: join(w.folder, 'copy.jsonl'), copyKey: loadCopyKey(join(w.folder, 'copy.jsonl.key')), name: w.settings.name, service: 'executor', options: { issuerKeys: w.settings.agent.issuerKeys } };
  const book = readFileSync(join(w.folder, 'book.jsonl'), 'utf8');
  let c = await compareCopyWithBook({ ...options, book });
  assert.equal(c.summary.agree, true, JSON.stringify(c.summary));
  assert.equal(c.summary.sent, 2);
  assert.equal(c.summary.matched, 2);
  assert.equal(c.refused.length, 1);
  assert.equal(c.refused[0].denialInBook, true);
  // The last receipt and the denial taken out of the book.
  const lines = book.split('\n').filter(Boolean);
  const cut = `${lines.slice(0, 2).join('\n')}\n`;
  c = await compareCopyWithBook({ ...options, book: cut });
  assert.equal(c.summary.agree, false);
  assert.equal(c.summary.missingFromBook, 1);
  assert.equal(c.missing[0].tool, 'order');
  assert.equal(c.summary.denialsMissingFromBook, 1);
  // A line of the copy changed.
  const copyPath = join(w.folder, 'copy.jsonl');
  writeFileSync(copyPath, readFileSync(copyPath, 'utf8').replace('"tool":"echo"', '"tool":"ECHO"'));
  c = await compareCopyWithBook({ ...options, book });
  assert.equal(c.copy.refused, 1);
  assert.equal(c.summary.agree, false);
});

test('the keys and the slip must match: other agent keys, the executor missing from "with", other executor keys, or a passkey not trusted stop the start', async () => {
  const w = await world({ open: false });
  const other = await world({ open: false });
  const start = (settings, root) => openExecutor(settings, { root, log: () => {} });
  await assert.rejects(start({ ...w.settings, agent: { ...w.settings.agent, slip: join(other.folder, 'slip.json') } }, w.folder), /other agent keys/);
  const noWith = await world({ open: false, slip: { with: [{ id: 'elsewhere', name: 'Another service' }] } });
  await assert.rejects(start(noWith.settings, noWith.folder), /does not name the executor in "with"/);
  const wrongKeys = await world({ open: false });
  const swapped = await world({ open: false, slip: { executorKeys: wrongKeys.executorKeys } });
  await assert.rejects(start(swapped.settings, swapped.folder), /other keys than/);
  await assert.rejects(start({ ...w.settings, agent: { ...w.settings.agent, issuerKeys: ['B'.repeat(43)] } }, w.folder), /does not list/);
});
