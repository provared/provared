// What one agent's messages may hold of the executor's memory (F1 of the
// check against the MCP SDK's advisories of October 2026): the bytes its
// requests in flight hold together (waitingBytes), the number of elements
// in one message, and the size of one body by default. Each limit refuses
// past its value and takes a message at it; another agent is answered while
// one agent is at its budget.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import http from 'node:http';
import { test } from 'node:test';
import { setFlagsFromString } from 'node:v8';
import { runInNewContext } from 'node:vm';

const { checkBook } = await import('provared');
const { httpWorld, post, rawRequest, auth, call, request } = await import('./http-world.mjs');
const { BODY_LIMIT, WAITING_BYTES, readHttpSettings } = await import('../http.mjs');
const { MAX_ELEMENTS, CODES, readMessage } = await import('../jsonrpc.mjs');
const { until } = await import('./world.mjs');

/**
 * A POST whose body is "declared" bytes long, of which "first" is sent now:
 * the rest waits for finish(). Gives {answer: Promise<{status, json}>,
 * finish(rest), cut()}.
 */
function openBody(w, agent, declared, first) {
  const u = new URL(w.url);
  const req = http.request({ host: u.hostname, port: u.port, path: u.pathname, method: 'POST', agent: false });
  req.setHeader('connection', 'close');
  req.setHeader('content-type', 'application/json');
  req.setHeader('authorization', auth(w, agent).authorization);
  req.setHeader('content-length', declared);
  const answer = new Promise((done, failed) => {
    req.on('error', failed);
    req.on('response', (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        let json;
        try {
          json = JSON.parse(body);
        } catch {
          json = undefined;
        }
        done({ status: res.statusCode, json });
      });
    });
  });
  answer.catch(() => {});
  req.write(first);
  req.flushHeaders();
  return { answer, finish: (rest) => req.end(rest), cut: () => req.destroy() };
}

/** A ping whose text is exactly "size" bytes, made up with spaces. */
function pingOf(size, id) {
  const text = JSON.stringify({ jsonrpc: '2.0', id, method: 'ping' });
  assert.ok(size >= text.length);
  return `${text.slice(0, -1)}${' '.repeat(size - text.length)}}`;
}

test('limits: the defaults are a body of 4 MiB, the SDK\'s, and 32 MiB held for each agent, the gateway\'s; waitingBytes is read and checked', () => {
  assert.equal(BODY_LIMIT, 4 * 1024 * 1024);
  assert.equal(WAITING_BYTES, 32 * 1024 * 1024);
  const base = { listen: { port: 0 }, upstream: { url: 'http://127.0.0.1:1/mcp' }, agents: { a: { secretHash: 'A'.repeat(43), slip: 's', book: 'b', keys: 'k', issuerKeys: ['x'] } }, executor: { keys: 'e' }, tools: {} };
  const read = (more) => readHttpSettings({ ...base, ...more }, '.');
  assert.equal(read({}).partial.bodyLimit, BODY_LIMIT);
  assert.equal(read({}).partial.waitingBytes, WAITING_BYTES);
  assert.equal(read({ waitingBytes: 65536 }).partial.waitingBytes, 65536);
  assert.ok(read({ waitingBytes: -1 }).problems.some((p) => p.startsWith('waitingBytes')));
  assert.ok(read({ waitingBytes: 1.5 }).problems.some((p) => p.startsWith('waitingBytes')));
  assert.ok(!read({ waitingBytes: 65536, bodyLimit: 4096 }).warnings.some((w) => w.startsWith('waitingBytes')), 'a setting, not set aside');
  assert.ok(read({ waitingBytes: 2048, bodyLimit: 4096 }).warnings.some((w) => w.startsWith('waitingBytes')), 'a budget below one body is said');
});

test('limits: the bytes one agent\'s requests hold together are bounded (waitingBytes); past it, 503; at it, taken; another agent is answered meanwhile', async () => {
  const w = await httpWorld({ config: { bodyLimit: 16384, waitingBytes: 32768, timeout: 5000 } });
  const open = [];
  try {
    // Two bodies being read, declared at 16 KiB each: alpha's budget, exactly. Both are taken.
    const a1 = openBody(w, 'alpha', 16384, '{"jsonrpc":"2.0",');
    const a2 = openBody(w, 'alpha', 16384, '{"jsonrpc":"2.0",');
    open.push(a1, a2);
    await until(() => w.executor.agent('alpha').open() === 2, { timeout: 5000 });
    // One more byte would be past it: refused at once, with 503, and nothing reaches the upstream.
    const seen = w.upstream.seen.length;
    const third = await post(w, 'alpha', { jsonrpc: '2.0', id: 3, method: 'ping' });
    assert.equal(third.status, 503);
    assert.equal(third.json.error.code, CODES.notRecorded);
    assert.match(third.json.error.message, /32768 bytes/);
    assert.equal(w.upstream.seen.length, seen);
    assert.ok(w.logs.some((e) => e.event === 'refused' && e.code === 'too-much-held'));
    // Another agent is answered while alpha is at its budget.
    const beta = await post(w, 'beta', { jsonrpc: '2.0', id: 4, method: 'ping' });
    assert.equal(beta.status, 200);
    assert.deepEqual(beta.json.result, {});
    // The two bodies end as pings of exactly 16 KiB: each is answered.
    const head = '{"jsonrpc":"2.0",';
    a1.finish(pingOf(16384, 1).slice(head.length));
    a2.finish(pingOf(16384, 2).slice(head.length));
    assert.equal((await a1.answer).status, 200);
    assert.equal((await a2.answer).status, 200);
    // Their bytes are given back once they have been answered.
    await until(() => w.executor.agent('alpha').open() === 0, { timeout: 5000 });
    assert.equal((await post(w, 'alpha', { jsonrpc: '2.0', id: 5, method: 'ping' })).status, 200);
  } finally {
    for (const o of open) o.cut();
    await w.close();
  }
});

test('limits: a body sent without a length counts as it arrives, and a request held at the upstream holds its body until it is answered', async () => {
  const w = await httpWorld({ config: { bodyLimit: 16384, waitingBytes: 20000, timeout: 1500 } });
  try {
    // A request the upstream never answers holds its 16 KiB until the executor's timeout.
    const hang = `${JSON.stringify({ jsonrpc: '2.0', id: 'h', method: 'hang' }).slice(0, -1)}${' '.repeat(16000)}}`;
    const held = post(w, 'alpha', null, { raw: hang });
    await until(() => w.upstream.seen.some((s) => s.body?.method === 'hang'), { timeout: 5000 });
    // A second body without a length, of 8 KiB: past the budget as it arrives.
    const chunked = await rawRequest(w, { headers: { 'content-type': 'application/json', ...auth(w, 'alpha'), 'transfer-encoding': 'chunked' }, body: pingOf(8000, 'c') });
    assert.equal(chunked.status, 503);
    assert.equal((await post(w, 'beta', { jsonrpc: '2.0', id: 'b', method: 'ping' })).status, 200);
    assert.equal((await held).status, 504);
    // Once the held request has its answer, the budget is free again.
    assert.equal((await rawRequest(w, { headers: { 'content-type': 'application/json', ...auth(w, 'alpha'), 'transfer-encoding': 'chunked' }, body: pingOf(8000, 'd') })).status, 200);
  } finally {
    await w.close();
  }
});

test('limits: a message of more than MAX_ELEMENTS elements (list items and member names) is refused before it is built; one of exactly that many is read', async () => {
  // The message's own four names, the name "x", and the items of its list.
  const text = (items) => `{"jsonrpc":"2.0","id":7,"method":"ping","params":{"x":[${new Array(items).fill('0').join(',')}]}}`;
  const at = readMessage(Buffer.from(text(MAX_ELEMENTS - 5)));
  assert.equal(at.refused, undefined);
  const past = readMessage(Buffer.from(text(MAX_ELEMENTS - 4)));
  assert.equal(past.refused.code, CODES.invalidRequest);
  assert.match(past.refused.message, /more than 100,000 elements/);
  assert.equal(past.id, 7, 'answered under its id');
  // Nested lists and objects count each of their items and names.
  assert.equal(readMessage(Buffer.from(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":[${new Array(MAX_ELEMENTS / 2).fill('[0]').join(',')}]}}`)).refused.code, CODES.invalidRequest);
  assert.equal(readMessage(Buffer.from(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{${Array.from({ length: MAX_ELEMENTS }, (_, i) => `"n${i}":0`).join(',')}}}`)).refused.code, CODES.invalidRequest);
  // Empty lists and objects, and text that holds commas and brackets, count as they are.
  assert.equal(readMessage(Buffer.from(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":[${new Array(MAX_ELEMENTS - 5).fill('[]').join(',')}],"t":"${',['.repeat(1000)}"}}`)).refused.code, CODES.invalidRequest, 'one name more than the limit');
  assert.equal(readMessage(Buffer.from(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":[${new Array(MAX_ELEMENTS - 6).fill('{}').join(',')}],"t":"${',['.repeat(1000)}"}}`)).refused, undefined, 'at the limit');
  // A server's answer is not held to it: an upstream's list may be long.
  assert.equal(readMessage(Buffer.from(`{"jsonrpc":"2.0","id":1,"result":{"x":[${new Array(MAX_ELEMENTS).fill('0').join(',')}]}}`), { strictNumbers: false }).refused, undefined);

  const w = await httpWorld();
  try {
    const seen = w.upstream.seen.length;
    const refused = await post(w, 'alpha', null, { raw: text(MAX_ELEMENTS - 4) });
    assert.equal(refused.status, 400);
    assert.equal(refused.json.id, 7);
    assert.equal(w.upstream.seen.length, seen, 'nothing reached the upstream');
    const taken = await post(w, 'alpha', null, { raw: text(MAX_ELEMENTS - 5) });
    assert.equal(taken.status, 200);
    assert.deepEqual(taken.json.result, {});
  } finally {
    await w.close();
  }
});

test('limits: a request that only passes through lets go of its message, as read, while the upstream answers: it holds about its text, not many times it', async () => {
  // Garbage is collected on demand here, so that what is held is what is measured.
  setFlagsFromString('--expose-gc');
  const gc = runInNewContext('gc');
  const heap = () => {
    gc();
    gc();
    return process.memoryUsage().heapUsed;
  };
  const w = await httpWorld({ config: { timeout: 30000 } });
  const n = 16;
  // 49,000 small objects (98,005 elements): about 380 KiB of text, and some 3 MiB once read.
  const text = (i) => `{"jsonrpc":"2.0","id":${i},"method":"hang","params":{"x":[${new Array(49000).fill('{"a":0}').join(',')}]}}`;
  const pending = [];
  try {
    const before = heap();
    for (let i = 0; i < n; i++) pending.push(post(w, 'alpha', null, { raw: text(i) }).catch(() => {}));
    await until(() => w.upstream.seen.filter((s) => s.body?.method === 'hang').length === n, { timeout: 20000 });
    // What the made-up upstream keeps of each message is let go, so that only the executor's part is measured.
    for (const s of w.upstream.seen) delete s.body;
    const each = (heap() - before) / n;
    assert.ok(each < 4 * text(0).length, `each request held ${Math.round(each / 1024)} KiB for ${Math.round(text(0).length / 1024)} KiB of text`);
  } finally {
    await w.close();
    await Promise.all(pending);
  }
});

test('limits: what the executor holds of the upstream\'s answers for an agent counts in waitingBytes too: past it a JSON answer is refused (503) and a stream is closed; the executor goes on, and another agent is answered', async () => {
  const w = await httpWorld({ config: { bodyLimit: 16384, waitingBytes: 65536, timeout: 5000 } });
  try {
    // An answer within the budget is handed on.
    const small = await request(w, 'alpha', 'big', { size: 30000 }, { id: 'small' });
    assert.equal(small.status, 200);
    assert.equal(small.json.result.text.length, 30000);
    // A JSON answer that would take alpha past it: refused under the request's id, and the rest not read.
    const big = await request(w, 'alpha', 'big', { size: 200000 }, { id: 'big' });
    assert.equal(big.status, 503);
    assert.equal(big.json.id, 'big');
    assert.equal(big.json.error.code, CODES.noAnswer);
    assert.match(big.json.error.message, /waitingBytes/);
    assert.ok(w.logs.some((e) => e.event === 'refused' && e.code === 'answer-too-much-held'));
    // The same as one event of a stream: the stream is closed before the event has come whole.
    let streamed = null;
    try {
      streamed = await request(w, 'alpha', 'big', { size: 200000, sse: true }, { id: 'streamed' });
    } catch {
      streamed = null;
    }
    assert.ok(streamed === null || streamed.json?.result === undefined, 'no result reached the agent');
    // A call whose answer is past it: its outcome is not known, and its receipt says so.
    const c = await call(w, 'alpha', 'odd', { how: 'big-json', size: 200000 }, { id: 'c' });
    assert.equal(c.json.error.code, CODES.noAnswer);
    const stubs = (await checkBook(w.executor.agent('alpha').writer.book(), { issuerKeys: w.settings.agents.alpha.issuerKeys })).entries.filter((e) => e.kind === 'stub');
    assert.ok(stubs.at(-1).content.details.some((d) => d.name === 'provared.error'));
    // The executor goes on: another agent is answered, and so is alpha once its answers are given back.
    assert.equal((await post(w, 'beta', { jsonrpc: '2.0', id: 'b', method: 'ping' })).status, 200);
    await until(() => w.executor.agent('alpha').open() === 0, { timeout: 5000 });
    assert.equal((await request(w, 'alpha', 'big', { size: 30000 }, { id: 'again' })).status, 200);
    // Everything held is given back once the answers have gone.
    await until(() => { const h = w.executor.agent('alpha').held(); return h.bodies === 0 && h.answers === 0; }, { timeout: 5000 });
  } finally {
    await w.close();
  }
});

test('limits: a body of exactly bodyLimit is taken by default; one byte more is refused with 413', async () => {
  const w = await httpWorld();
  try {
    assert.equal((await post(w, 'alpha', null, { raw: pingOf(BODY_LIMIT, 'at') })).status, 200);
    assert.equal((await post(w, 'alpha', null, { raw: pingOf(BODY_LIMIT + 1, 'past') })).status, 413);
  } finally {
    await w.close();
  }
});

test('limits: one agent\'s messages, costly to read, do not stall another agent: its ping waits for a few of them at most, not for all those in flight', async (t) => {
  const w = await httpWorld({ config: { timeout: 30000 } });
  const IN_FLIGHT = 30;
  // A message of about 1 MiB with 95,000 member names, each costly to read, refused once read (tasks are not allowed), so the upstream, in this process too, does nothing with it.
  const bodyOf = (id) => {
    const names = [];
    for (let i = 0; i < 95000; i++) names.push(`"k${i}":0`);
    return Buffer.from(`{"jsonrpc":"2.0","id":"${id}","method":"tasks/get","params":{${names.join(',')}}}`);
  };
  const bodies = Array.from({ length: IN_FLIGHT }, (_, i) => bodyOf(`a${i}`));
  // What reading one of them costs here: the measure of the limit, so that a slower computer has a longer one.
  const costs = [];
  for (let i = 0; i < 3; i++) {
    const t = performance.now();
    readMessage(bodies[0]);
    costs.push(performance.now() - t);
  }
  const oneRead = costs.sort((a, b) => a - b)[1];
  let going = true;
  let answered = 0;
  const loops = bodies.map(async (body) => {
    while (going) {
      const r = await rawRequest(w, { headers: { 'content-type': 'application/json', ...auth(w, 'alpha') }, body }).catch(() => null);
      if (r && r.status !== 200) throw new Error(`alpha was answered ${r.status}`);
      if (r) answered += 1;
    }
  });
  try {
    await new Promise((d) => setTimeout(d, 1500));
    const before = answered;
    // Before the fix, beta waited for every message alpha had in flight to be read: here 9 to 11 seconds, about 60 reads. Now it waits for about one of alpha's reads for each turn of the event loop its own exchange takes (to the executor, to the upstream and back): about 5 reads here. The limit is twice that and a second more, for a busy computer.
    const limit = 10 * oneRead + 1000;
    const waits = [];
    for (let i = 0; i < 8 && !(waits.at(-1) >= limit); i++) {
      const t = performance.now();
      const r = await post(w, 'beta', { jsonrpc: '2.0', id: `b${i}`, method: 'ping' });
      waits.push(performance.now() - t);
      assert.equal(r.status, 200);
      await new Promise((d) => setTimeout(d, 50));
    }
    // alpha was served meanwhile, as many messages as it keeps in flight at least.
    assert.ok(answered - before >= IN_FLIGHT, `alpha was answered ${answered - before} times while beta pinged`);
    const worst = Math.max(...waits);
    t.diagnostic(`beta's pings: ${waits.map(Math.round).join(', ')} ms; one read ${Math.round(oneRead)} ms; limit ${Math.round(limit)} ms; alpha answered ${answered - before} times`);
    assert.ok(worst < limit, `beta's ping took up to ${Math.round(worst)} ms (${waits.map(Math.round).join(', ')}); one of alpha's messages takes ${Math.round(oneRead)} ms to read, and the limit is ${Math.round(limit)} ms`);
  } finally {
    going = false;
    await Promise.allSettled(loops);
    await w.close();
  }
});
