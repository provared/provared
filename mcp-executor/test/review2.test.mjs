// The second review's findings, each a test: a server answer holding a
// whole number beyond 2^53 - 1 reaches the client exactly and gets a
// truthful receipt (R1); every request goes to the server under an id of
// the executor's own, so nothing the client sends can collide with a call
// in flight (R2); requests the server never answers are forgotten past a
// cap (R3); an answer the executor cannot read still reaches the client
// under the client's id; and a receipt written at a restart says so in
// the book (X37).

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { checkBook, identifierFingerprint } = await import('provared');
const { world, openWorld, until } = await import('./world.mjs');
const { RESULT_DOCUMENT, RESULT_NOT_FINGERPRINTED, UNREADABLE_ANSWER, WRITTEN_LATE, WRITTEN_LATE_DOCUMENT, OUTCOME_UNKNOWN, MAX_MAPPED } = await import('../executor.mjs');
const { spliceId, topLevelId } = await import('../jsonrpc.mjs');
const { readCopy, loadCopyKey, openCopy } = await import('../copy.mjs');

async function bookOf(w) {
  return checkBook(w.executor.writer.book(), { issuerKeys: w.settings.agent.issuerKeys });
}
const stubsOf = (checked) => checked.entries.filter((e) => e.kind === 'stub');
const docs = (stub) => Object.fromEntries(stub.content.details.map((d) => [d.name, d.sha256]));

/** The raw lines the client got, as text. */
function rawLines(w) {
  return w.client.rawText.split('\n').filter(Boolean);
}

test('R1: a tool result holding a whole number beyond 2^53 - 1 reaches the client with its digits exact, at once, and the receipt says the result could not be fingerprinted', async () => {
  const w = await world({ config: { tools: { bigint: { action: 'tool.run' }, echo: { action: 'provared.data.read' } } } });
  try {
    const started = Date.now();
    const r = await w.client.call('bigint', {}, { id: 'b1' });
    assert.ok(Date.now() - started < 2000, 'answered at once, not by the timeout');
    assert.equal(r.result.content[0].text, 'ok');
    const raw = rawLines(w).find((l) => l.includes('"snowflake"'));
    assert.ok(raw.includes('"snowflake":1234567890123456789'), 'the digits are exactly as the server wrote them');
    assert.ok(raw.includes('"ratio":1.50'), 'the spelling of a number is as the server wrote it');
    assert.ok(raw.startsWith('{"jsonrpc":"2.0","id":"b1",'), "under the client's id, in the server's own bytes");
    const [stub] = stubsOf(await bookOf(w));
    const d = docs(stub);
    assert.equal(d[RESULT_DOCUMENT], undefined);
    assert.equal(d['provared.error'], await identifierFingerprint(RESULT_NOT_FINGERPRINTED));
    assert.equal(stub.countersignature.state, 'valid');
    assert.ok(w.logs.some((e) => e.event === 'result-not-fingerprinted'));
    assert.ok(!w.logs.some((e) => e.event === 'late-answer-dropped'));
  } finally {
    await w.close();
  }
});

test('R1: a tools/list answer holding such a number is filtered with every number kept as the server wrote it', async () => {
  const w = await world({ env: { FAKE_BIG_LIST: { value: '1' } } });
  try {
    const page = await w.client.request('tools/list', { cursor: 'page2' }, { id: 'p2' });
    assert.deepEqual(page.result.tools.map((t) => t.name), ['error', 'big']);
    const raw = rawLines(w).find((l) => l.includes('"id":"p2"'));
    assert.ok(raw.includes('"ordinal":1234567890123456789'), 'the number survives the filtering');
    assert.equal((raw.match(/1234567890123456789/g) ?? []).length, 1, 'the hidden tool, with its number, is gone');
  } finally {
    await w.close();
  }
});

test('R1: an answer the executor cannot read as a message, whose id it can still find, reaches the client under the client\'s id, and the receipt says the answer could not be read', async () => {
  const w = await world({ config: { tools: { garbage: { action: 'tool.run' } } } });
  try {
    const m = await w.client.request('tools/call', { name: 'garbage' }, { id: 'g1' });
    assert.equal(m.id, 'g1');
    const raw = rawLines(w).find((l) => l.includes('"id":"g1"'));
    assert.ok(raw.includes('"a":1,"a":2'), 'the bytes are as the server wrote them');
    const [stub] = stubsOf(await bookOf(w));
    assert.equal(docs(stub)['provared.error'], await identifierFingerprint(UNREADABLE_ANSWER));
    assert.ok(w.logs.some((e) => e.event === 'server-line-not-read' && e.matched === 'call'));
  } finally {
    await w.close();
  }
});

test('R2: every request goes to the server under an id of the executor\'s own with a random part; a ping under the id of a call in flight neither settles the call nor takes its answer', async () => {
  const w = await world();
  try {
    const slow = w.client.call('slow', { ms: 700, tag: 'mine' }, { id: 7 });
    await until(() => w.fakeSeen().some((s) => s.seen?.method === 'tools/call'));
    const inFlight = w.fakeSeen().find((s) => s.seen?.method === 'tools/call').seen.id;
    assert.match(inFlight, /^provared-\d+-[A-Za-z0-9_-]{16,}$/);
    // The client guesses that id for a ping.
    const ping = await w.client.request('ping', undefined, { id: inFlight });
    assert.deepEqual(ping.result, {}, 'the ping gets its own answer');
    const pingSeen = w.fakeSeen().find((s) => s.seen?.method === 'ping').seen.id;
    assert.notEqual(pingSeen, inFlight, 'the ping went to the server under another id');
    assert.match(pingSeen, /^provared-/);
    const r = await slow;
    assert.match(r.result.content[0].text, /Done, slowly. mine/, 'the call gets its own answer');
    const [stub] = stubsOf(await bookOf(w));
    const { argumentsFingerprint } = await import('provared');
    assert.equal(docs(stub)[RESULT_DOCUMENT], await argumentsFingerprint(r.result), 'the receipt names the real result, not the ping\'s');
    // A cancellation for a request that is not a tool call is renamed too.
    const never = w.client.request('never', undefined, { id: 'n1', timeout: 1500 });
    never.catch(() => {});
    await until(() => w.fakeSeen().some((s) => s.seen?.method === 'never'));
    w.client.notify('notifications/cancelled', { requestId: 'n1' });
    await until(() => w.fakeSeen().some((s) => s.seen?.method === 'notifications/cancelled'));
    const cancel = w.fakeSeen().find((s) => s.seen?.method === 'notifications/cancelled').seen.params.requestId;
    assert.equal(cancel, w.fakeSeen().find((s) => s.seen?.method === 'never').seen.id);
  } finally {
    await w.close();
  }
});

test('R3: requests the server never answers are forgotten past the cap, the oldest first; tool calls are not', async () => {
  const w = await world();
  try {
    for (let i = 0; i < MAX_MAPPED + 5; i++) w.client.send({ jsonrpc: '2.0', id: `nv${i}`, method: 'never' });
    await until(() => w.fakeSeen().filter((s) => s.seen?.method === 'never').length === MAX_MAPPED + 5, { timeout: 20000 });
    assert.equal(w.executor.status().requests, MAX_MAPPED, 'the oldest five are forgotten');
    const ping = await w.client.request('ping');
    assert.deepEqual(ping.result, {}, 'the executor goes on');
    assert.equal(w.executor.status().requests, MAX_MAPPED - 1, 'the ping pushed out one more, and was then answered and forgotten');
    // The server now answers the first "never" late: its id is forgotten, so the line is handed on as it is (the client ignores an unknown id).
    const first = w.fakeSeen().find((s) => s.seen?.method === 'never').seen.id;
    const last = w.fakeSeen().filter((s) => s.seen?.method === 'never').at(-1).seen.id;
    assert.match(first, /^provared-1-/);
    assert.match(last, /^provared-/);
  } finally {
    await w.close();
  }
});

test('X37: a receipt written at a restart names executor.written-late, keeps the sending time, and is countersigned at the restart', async () => {
  const w = await world();
  await w.client.call('echo', {});
  await w.close();
  const key = loadCopyKey(join(w.folder, 'copy.jsonl.key'));
  const copyPath = join(w.folder, 'copy.jsonl');
  const copy = openCopy(copyPath, key, w.settings.name, readCopy(copyPath, key, w.settings.name).next);
  const sentAt = new Date().toISOString();
  const { argumentsFingerprint } = await import('provared');
  copy.note({ kind: 'sending', call: 'lost', when: sentAt, slip: w.executor.slip.fingerprint, tool: 'slow', action: 'slow.work', with: 'executor', details: [{ name: 'provared.arguments', sha256: await argumentsFingerprint({}) }, { name: 'executor.call', sha256: await identifierFingerprint('lost') }] });
  await new Promise((d) => setTimeout(d, 1100));
  await openWorld(w);
  try {
    const checked = await bookOf(w);
    const late = stubsOf(checked)[1];
    const d = docs(late);
    assert.equal(d[WRITTEN_LATE_DOCUMENT], await identifierFingerprint(WRITTEN_LATE));
    assert.equal(d['provared.error'], await identifierFingerprint(OUTCOME_UNKNOWN));
    assert.equal(late.content.when, sentAt.replace(/\.\d{3}Z$/, 'Z'), 'dated when the call was sent');
    const line = JSON.parse(readFileSync(join(w.folder, 'book.jsonl'), 'utf8').split('\n').filter(Boolean).at(-1));
    const csWhen = JSON.parse(Buffer.from(line.countersignature.payload, 'base64url').toString('utf8')).when;
    assert.ok(csWhen > late.content.when, 'the countersignature is dated at the restart');
    assert.equal(late.countersignature.state, 'valid');
  } finally {
    await w.close();
  }
});

test('F1: a server line with "id" twice at the top level matches no call: it is handed on as it is, and the call ends by the timeout with a "no answer" receipt', async () => {
  const w = await world({ config: { timeout: 1000, tools: { twoids: { action: 'tool.run' } } } });
  try {
    const r = await w.client.request('tools/call', { name: 'twoids' }, { id: 't1' });
    assert.equal(r.error.code, 1002, 'the call ended by the timeout');
    const raw = rawLines(w).find((l) => l.includes('"id":"provared-'));
    assert.ok(raw, 'the line was handed on unmatched, under the executor\'s id');
    assert.ok(!rawLines(w).some((l) => l.includes('"id":"t1","id"')), 'nothing was spliced into it');
    const [stub] = stubsOf(await bookOf(w));
    assert.match(Buffer.from(JSON.stringify(docs(stub))).toString(), /provared\.error/);
    assert.equal(docs(stub)['provared.error'], await identifierFingerprint(`The tool server gave no answer within 1000 ms, so the executor cancelled the call (call ${w.logs.find((e) => e.event === 'taken').call}). Its outcome is not known.`));
    assert.ok(w.logs.some((e) => e.event === 'server-line-not-read' && e.matched === undefined));
  } finally {
    await w.close();
  }
});

test('F2: a batch (a line that is not one object) from the server is not a message: handed on unmatched, and the call ends by the timeout with a "no answer" receipt', async () => {
  const w = await world({ config: { timeout: 1000, tools: { batch: { action: 'tool.run' } } } });
  try {
    const r = await w.client.request('tools/call', { name: 'batch' }, { id: 'b1' });
    assert.equal(r.error.code, 1002);
    assert.ok(rawLines(w).some((l) => l.startsWith('[')), 'the batch was handed on as it was');
    const [stub] = stubsOf(await bookOf(w));
    assert.ok(docs(stub)['provared.error']);
    assert.equal(docs(stub)[RESULT_DOCUMENT], undefined);
  } finally {
    await w.close();
  }
});

test('spliceId and topLevelId: the id and nothing else', () => {
  assert.equal(topLevelId('{"id":1,"result":{},"id":2}'), null, '"id" twice at the top level matches nothing');
  assert.equal(spliceId('{"id":1,"id":1}', 'c'), null);
  assert.deepEqual(topLevelId('{"id":1,"result":{"id":2}}').value, 1, 'a nested "id" does not count as a second');
  assert.equal(spliceId('{"jsonrpc":"2.0","id":"provared-1-x","result":{"id":5,"n":1.50}}', 'c'), '{"jsonrpc":"2.0","id":"c","result":{"id":5,"n":1.50}}');
  assert.equal(spliceId('{ "id" : 12345678901234567890 , "a":"\\"id\\":7"}', 1), '{ "id" : 1 , "a":"\\"id\\":7"}');
  assert.equal(spliceId('{"result":{"id":1}}', 'c'), null, 'a nested id is not the top-level one');
  assert.equal(spliceId('[1,2]', 'c'), null);
  assert.deepEqual(topLevelId('{"a":[1,{"id":2}],"id":"z"}'), { start: 23, end: 26, value: 'z' });
  assert.equal(topLevelId('{"a":1,"a":2,"id":3}').value, 3, 'found although JSON.parse would take the last of two names elsewhere');
});
