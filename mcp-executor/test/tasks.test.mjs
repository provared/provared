// Tasks in front of an upstream HTTP server (F2 of the check against the
// MCP SDK's advisories of October 2026). Every agent reaches the upstream
// with the executor's one credential, so an upstream that keeps its tasks
// for whoever presents that credential cannot tell one agent's from
// another's. The made-up upstream here does just that (fake-http-server.mjs).
// By default the executor refuses tasks; with "allowTasks" it keeps each
// task to the agent whose call made it. And Last-Event-ID, which asks the
// upstream to replay a stream, goes on only for an event the executor gave
// that agent.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { test } from 'node:test';

const { checkBook } = await import('provared');
const { httpWorld, call, request, rawRequest, auth, META, TOKEN } = await import('./http-world.mjs');
const { CODES } = await import('../jsonrpc.mjs');
const { readHttpSettings } = await import('../http.mjs');
const { until } = await import('./world.mjs');

const SLIPS = { beta: { actions: ['provared.data.read'] } };
/** A tools/call that asks for a task (params.task), as an agent. */
const taskCall = (w, agent, id) => rawRequest(w, { headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...auth(w, agent) }, body: JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'order', arguments: { total: 5, item: 'payroll run' }, task: { ttl: 60000 }, _meta: META } }) }).then((r) => ({ ...r, json: JSON.parse(r.body) }));
const methodsSeen = (w) => w.upstream.seen.filter((s) => s.method === 'POST').map((s) => s.body.method);
const stubs = async (w, name) => (await checkBook(w.executor.agent(name).writer.book(), { issuerKeys: w.settings.agents[name].issuerKeys })).entries.filter((e) => e.kind === 'stub');

/** A task made at the upstream by another caller with the same credential, past the executor. */
async function taskElsewhere(w) {
  const r = await fetch(w.upstream.url, { method: 'POST', headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'order', arguments: { total: 9 }, task: {} } }) });
  return (await r.json()).result.task.taskId;
}

test('tasks: by default every tasks/ request, and a tools/call that asks for a task, is refused with a JSON-RPC error and reaches no upstream', async () => {
  const w = await httpWorld({ slips: SLIPS });
  try {
    // 1. beta's own call to "order" is refused by its permission, as before.
    const own = await call(w, 'beta', 'order', { total: 5, item: 'payroll run' }, { id: 1 });
    assert.equal(own.json.result.isError, true);
    // 2. alpha's call to "order" as a task: refused, and not sent.
    const made = await taskCall(w, 'alpha', 1);
    assert.equal(made.status, 200, 'answered as the executor\'s other refusals of a request it has read (X112)');
    assert.equal(made.json.id, 1);
    assert.equal(made.json.error.code, CODES.invalidParams);
    assert.match(made.json.error.message, /task/);
    assert.equal((await stubs(w, 'alpha')).length, 0, 'nothing written for a call not taken');
    // 3 to 5. tasks/list, tasks/result and tasks/cancel, here for a task another caller made at the upstream.
    const taskId = await taskElsewhere(w);
    for (const [method, params] of [['tasks/list', undefined], ['tasks/result', { taskId }], ['tasks/cancel', { taskId }], ['tasks/get', { taskId }]]) {
      const r = await request(w, 'beta', method, params, { id: method });
      assert.equal(r.status, 200, method);
      assert.equal(r.json.id, method);
      assert.equal(r.json.error.code, CODES.methodNotFound, method);
    }
    assert.deepEqual(methodsSeen(w).filter((m) => m.startsWith('tasks/') || m === 'tools/call'), ['tools/call'], 'none of them reached the upstream: the one call there is the one made past the executor');
    assert.equal(w.upstream.tasks.get(taskId).status, 'completed', 'the task was not cancelled');
    assert.ok(w.logs.some((e) => e.event === 'refused' && e.code === 'tasks-refused'));
  } finally {
    await w.close();
  }
});

test('tasks: with allowTasks, each task is kept to the agent whose call made it; the five steps of the check are refused or kept to beta; alpha still gets its own result', async () => {
  const w = await httpWorld({ slips: SLIPS, config: { allowTasks: true } });
  try {
    // 1. beta's own call to "order": refused by its permission.
    assert.equal((await call(w, 'beta', 'order', { total: 5, item: 'payroll run' }, { id: 1 })).json.result.isError, true);
    // 2. alpha's call to "order" as a task: checked and receipted as any call; its result is the task's handle.
    const made = await taskCall(w, 'alpha', 1);
    assert.equal(made.status, 200);
    const taskId = made.json.result.task.taskId;
    assert.equal(typeof taskId, 'string');
    assert.equal((await stubs(w, 'alpha')).length, 1, 'a receipt for the call');
    const other = await taskElsewhere(w);
    // 3. beta's tasks/list: alpha's task, and the one made past the executor, are not in it.
    const listed = await request(w, 'beta', 'tasks/list', undefined, { id: 2 });
    assert.equal(listed.status, 200);
    assert.equal(listed.json.id, 2);
    assert.deepEqual(listed.json.result.tasks, []);
    // 4. beta's tasks/result for alpha's task: refused, and not sent.
    const before = methodsSeen(w).length;
    const got = await request(w, 'beta', 'tasks/result', { taskId }, { id: 3 });
    assert.equal(got.status, 200);
    assert.equal(got.json.error.code, CODES.invalidParams);
    assert.doesNotMatch(got.body, /Ordered/);
    // 5. beta's tasks/cancel and tasks/get for alpha's task: refused, and not sent; the task runs on.
    assert.equal((await request(w, 'beta', 'tasks/cancel', { taskId }, { id: 4 })).json.error.code, CODES.invalidParams);
    assert.equal((await request(w, 'beta', 'tasks/get', { taskId }, { id: 5 })).json.error.code, CODES.invalidParams);
    assert.equal((await request(w, 'beta', 'tasks/get', { taskId: other }, { id: 6 })).json.error.code, CODES.invalidParams, 'nor a task the executor did not make');
    assert.equal(methodsSeen(w).length, before, 'none of them reached the upstream');
    assert.equal(w.upstream.tasks.get(taskId).status, 'completed');
    // alpha: its own task is listed, and it gets its status and its own result.
    const own = await request(w, 'alpha', 'tasks/list', undefined, { id: 7 });
    assert.deepEqual(own.json.result.tasks.map((t) => t.taskId), [taskId]);
    assert.equal((await request(w, 'alpha', 'tasks/get', { taskId }, { id: 8 })).json.result.status, 'completed');
    const result = await request(w, 'alpha', 'tasks/result', { taskId }, { id: 9 });
    assert.equal(result.status, 200);
    assert.equal(result.json.id, 9);
    assert.equal(result.json.result.content[0].text, 'Ordered for 5.');
    // A method of tasks the executor does not know is refused even so.
    assert.equal((await request(w, 'alpha', 'tasks/other', { taskId }, { id: 10 })).json.error.code, CODES.methodNotFound);
    // On a stream, the status of alpha's task reaches alpha alone.
    const stream = async (agent) => {
      const s = await rawRequest(w, { method: 'GET', headers: { accept: 'text/event-stream', ...auth(w, agent) }, stream: true });
      let text = '';
      s.res.on('data', (c) => {
        text += c;
      });
      await until(() => text.includes('hello'), { timeout: 5000 });
      // The made-up upstream writes every event at once; a little more time lets any later one come.
      await new Promise((d) => setTimeout(d, 100));
      s.res.destroy();
      return text;
    };
    assert.match(await stream('alpha'), new RegExp(taskId));
    const betaStream = await stream('beta');
    assert.doesNotMatch(betaStream, new RegExp(taskId));
    assert.match(betaStream, new RegExp(other), 'a task the executor did not make is not the executor\'s to hold back');
  } finally {
    await w.close();
  }
});

test('tasks: allowTasks is a setting in front of an upstream, true or false; in front of a local program it is set aside', () => {
  const base = { listen: { port: 0 }, agents: { a: { secretHash: 'A'.repeat(43), slip: 's', book: 'b', keys: 'k', issuerKeys: ['x'] } }, executor: { keys: 'e' }, tools: {} };
  const up = (more) => readHttpSettings({ ...base, upstream: { url: 'http://127.0.0.1:1/mcp' }, ...more }, '.');
  assert.equal(up({}).partial.allowTasks, false);
  assert.equal(up({ allowTasks: true }).partial.allowTasks, true);
  assert.ok(up({ allowTasks: 'yes' }).problems.some((p) => p.startsWith('allowTasks')));
  assert.ok(!up({ allowTasks: true }).warnings.some((x) => x.startsWith('allowTasks')));
  const local = readHttpSettings({ ...base, server: { command: 'node' }, allowTasks: true }, '.');
  assert.ok(local.warnings.some((x) => x.startsWith('allowTasks')));
});

test('Last-Event-ID goes on to the upstream only for an event the executor gave that agent: another agent cannot have a stream replayed', async () => {
  const w = await httpWorld();
  try {
    const lastIds = () => w.upstream.seen.filter((s) => s.method === 'GET').map((s) => s.headers['last-event-id'] ?? null);
    const open = async (agent, headers = {}) => {
      const s = await rawRequest(w, { method: 'GET', headers: { accept: 'text/event-stream', ...auth(w, agent), ...headers }, stream: true });
      let text = '';
      s.res.on('data', (c) => {
        text += c;
      });
      await until(() => text.includes('hello'), { timeout: 5000 });
      s.res.destroy();
      return text;
    };
    // alpha is given the event "ev-1".
    assert.match(await open('alpha'), /id: ev-1/);
    // beta names it: the header does not go on.
    await open('beta', { 'last-event-id': 'ev-1' });
    // alpha names it: it goes on.
    await open('alpha', { 'last-event-id': 'ev-1' });
    // An id no one was given does not go on either.
    await open('alpha', { 'last-event-id': 'ev-99' });
    assert.deepEqual(lastIds(), [null, null, 'ev-1', null]);
    assert.ok(w.logs.some((e) => e.event === 'headers-dropped' && e.headers.includes('last-event-id')));
  } finally {
    await w.close();
  }
});
