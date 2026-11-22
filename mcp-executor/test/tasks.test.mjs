// Tasks in front of an upstream HTTP server (F2 of the check against the
// MCP SDK's advisories of October 2026). Every agent reaches the upstream
// with the executor's one credential, so an upstream that keeps its tasks
// for whoever presents that credential cannot tell one agent's from
// another's. The made-up upstream here does just that (fake-http-server.mjs).
// By default the executor refuses tasks; "allowTasks" is taken only where
// the settings name one agent, and then a task the executor did not see
// made for that agent is refused. And Last-Event-ID, which asks the
// upstream to replay a stream, goes on only for an event the executor gave
// that agent.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { test } from 'node:test';

const { checkBook } = await import('provared');
const { httpWorld, openHttpWorld, call, request, post, rawRequest, auth, beginSession, META, TOKEN } = await import('./http-world.mjs');
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
    // In other capitals too, as an upstream that reads without regard to capitals would take them: a method of tasks, and the member that asks for a task.
    const seenBefore = w.upstream.seen.length;
    assert.equal((await request(w, 'beta', 'Tasks/List', undefined, { id: 'folded' })).json.error.code, CODES.methodNotFound);
    const folded = await post(w, 'alpha', { jsonrpc: '2.0', id: 'T', method: 'tools/call', params: { name: 'order', arguments: { total: 5, item: 'payroll run' }, Task: { ttl: 60000 }, _meta: META } });
    assert.equal(folded.json.error.code, CODES.invalidParams);
    assert.equal(w.upstream.seen.length, seenBefore, 'neither reached the upstream');
    assert.deepEqual(methodsSeen(w).filter((m) => m.startsWith('tasks/') || m === 'tools/call'), ['tools/call'], 'none of them reached the upstream: the one call there is the one made past the executor');
    assert.equal(w.upstream.tasks.get(taskId).status, 'completed', 'the task was not cancelled');
    assert.ok(w.logs.some((e) => e.event === 'refused' && e.code === 'tasks-refused'));
  } finally {
    await w.close();
  }
});

test('tasks: allowTasks is a settings error unless the settings name exactly one agent, since several agents share one caller at the tool server; two agents with it are refused at start, one starts', async () => {
  const two = await httpWorld({ config: { allowTasks: true }, open: false });
  try {
    await assert.rejects(openHttpWorld(two), /allowTasks: .*exactly one agent.*another's task/);
  } finally {
    await two.close();
  }
  const one = await httpWorld({ agents: ['alpha'], config: { allowTasks: true } });
  await one.close();
  const base = { listen: { port: 0 }, upstream: { url: 'http://127.0.0.1:1/mcp' }, executor: { keys: 'e' }, tools: {} };
  const agent = (n) => ({ secretHash: n.repeat(43), slip: `s${n}`, book: `b${n}`, keys: `k${n}`, issuerKeys: ['x'] });
  assert.ok(readHttpSettings({ ...base, agents: { a: agent('A'), b: agent('B') }, allowTasks: true }, '.').problems.some((p) => p.startsWith('allowTasks')));
  assert.ok(!readHttpSettings({ ...base, agents: { a: agent('A'), b: agent('B') } }, '.').problems.some((p) => p.startsWith('allowTasks')), 'without allowTasks, several agents start, and tasks are refused');
});

test('tasks: with allowTasks and one agent, its own task is served; a task the executor did not see made is refused and not sent, and is left out of tasks/list; the agent gets its own result', async () => {
  const w = await httpWorld({ agents: ['alpha'], config: { allowTasks: true } });
  try {
    // The call to "order" as a task: checked and receipted as any call; its result is the task's handle.
    const made = await taskCall(w, 'alpha', 1);
    assert.equal(made.status, 200);
    const taskId = made.json.result.task.taskId;
    assert.equal(typeof taskId, 'string');
    assert.equal((await stubs(w, 'alpha')).length, 1, 'a receipt for the call');
    // A task made past the executor, by another caller with the same credential: refused by every method that names it, and not sent; it runs on.
    const other = await taskElsewhere(w);
    const before = methodsSeen(w).length;
    for (const [i, method] of ['tasks/result', 'tasks/cancel', 'tasks/get', 'tasks/update'].entries()) {
      const r = await request(w, 'alpha', method, { taskId: other }, { id: 20 + i });
      assert.equal(r.status, 200, method);
      assert.equal(r.json.error.code, CODES.invalidParams, method);
      assert.doesNotMatch(r.body, /Ordered/);
    }
    assert.equal(methodsSeen(w).length, before, 'none of them reached the upstream');
    assert.equal(w.upstream.tasks.get(other).status, 'completed');
    // Its own task is listed (and the other not), and it gets its status and its own result.
    const own = await request(w, 'alpha', 'tasks/list', undefined, { id: 7 });
    assert.deepEqual(own.json.result.tasks.map((t) => t.taskId), [taskId]);
    assert.equal((await request(w, 'alpha', 'tasks/get', { taskId }, { id: 8 })).json.result.status, 'completed');
    const result = await request(w, 'alpha', 'tasks/result', { taskId }, { id: 9 });
    assert.equal(result.status, 200);
    assert.equal(result.json.id, 9);
    assert.equal(result.json.result.content[0].text, 'Ordered for 5.');
    // A method of tasks the executor does not know is refused even so.
    assert.equal((await request(w, 'alpha', 'tasks/other', { taskId }, { id: 10 })).json.error.code, CODES.methodNotFound);
    // On a stream, the status of its own task reaches it, and so does that of the task made past the executor: not the executor's to hold back.
    const s = await rawRequest(w, { method: 'GET', headers: { accept: 'text/event-stream', ...auth(w, 'alpha'), 'mcp-session-id': await beginSession(w, 'alpha') }, stream: true });
    let text = '';
    s.res.on('data', (c) => {
      text += c;
    });
    await until(() => text.includes('hello'), { timeout: 5000 });
    // The made-up upstream writes every event at once; a little more time lets any later one come.
    await new Promise((d) => setTimeout(d, 100));
    s.res.destroy();
    assert.match(text, new RegExp(taskId));
    assert.match(text, new RegExp(other));
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
    // Each agent's streams under a session of its own: with two agents, a GET without one is not opened.
    const sessions = { alpha: await beginSession(w, 'alpha'), beta: await beginSession(w, 'beta') };
    const open = async (agent, headers = {}) => {
      const s = await rawRequest(w, { method: 'GET', headers: { accept: 'text/event-stream', ...auth(w, agent), 'mcp-session-id': sessions[agent], ...headers }, stream: true });
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

test('tasks: without allowTasks, the upstream\'s offer of tasks does not reach the agent (capabilities.tasks, a tool\'s execution.taskSupport), so a client is not asked to use what is refused; with it, the offer passes', async () => {
  const offered = async (w) => {
    const init = await request(w, 'alpha', 'initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '0' } }, { id: 'i' });
    const discover = await request(w, 'alpha', 'server/discover', {}, { id: 'd' });
    const lists = [await request(w, 'alpha', 'tools/list', {}, { id: 'l' }), await request(w, 'alpha', 'tools/list', { sse: true }, { id: 'ls' })];
    const order = lists.map((l) => l.json.result.tools.find((t) => t.name === 'order'));
    return { init: init.json.result.capabilities, discover: discover.json.result.capabilities, order };
  };
  for (const hideUnlisted of [true, false]) {
    const w = await httpWorld({ config: { hideUnlisted } });
    try {
      w.upstream.offerTasks();
      const o = await offered(w);
      assert.deepEqual(o.init, { tools: {} }, `initialize, hideUnlisted ${hideUnlisted}`);
      assert.deepEqual(o.discover, { tools: {} }, 'server/discover');
      for (const order of o.order) assert.equal(order.execution?.taskSupport, undefined, 'tools/list');
    } finally {
      await w.close();
    }
  }
  const w = await httpWorld({ agents: ['alpha'], config: { allowTasks: true } });
  try {
    w.upstream.offerTasks();
    const o = await offered(w);
    assert.ok(o.init.tasks && o.discover.tasks);
    for (const order of o.order) assert.equal(order.execution.taskSupport, 'optional');
  } finally {
    await w.close();
  }
});

// Tasks of the 2026-07-28 revision, as the review of 0.5.2 describes them: an extension (io.modelcontextprotocol/tasks) a client declares in its _meta's client capabilities; the server decides whether a call becomes a task, answered with a flat handle ({resultType: "task", taskId}); tasks/get, tasks/update and tasks/cancel name it by params.taskId; notifications/tasks come through subscriptions/listen, which names tasks in params.notifications.taskIds.
const TASKS_EXTENSION = 'io.modelcontextprotocol/tasks';
const OTHER_EXTENSION = 'example.org/other';
const META_TASKS = { ...META, 'io.modelcontextprotocol/clientCapabilities': { extensions: { [TASKS_EXTENSION]: {}, [OTHER_EXTENSION]: {} } } };
const ask = (w, agent, method, params, id) => request(w, agent, method, { ...params, _meta: META_TASKS }, { id });
const lastSent = (w, method) => w.upstream.seen.filter((s) => s.method === 'POST' && s.body?.method === method).at(-1)?.body;

test('tasks of 2026-07-28, by default: the extension is taken out of what an agent declares, so a call is answered at once with its result; tasks/update and a subscription to tasks are refused and not sent; a call answered with a task anyway has its outcome not known', async () => {
  const w = await httpWorld({ slips: SLIPS });
  try {
    const made = await call(w, 'alpha', 'order', { total: 5, item: 'payroll run' }, { id: 'o', meta: META_TASKS });
    assert.equal(made.status, 200);
    assert.notEqual(made.json.result.resultType, 'task', 'not a task');
    assert.match(made.json.result.content[0].text, /Ordered for 5/);
    const sent = lastSent(w, 'tools/call').params._meta['io.modelcontextprotocol/clientCapabilities'].extensions;
    assert.equal(Object.hasOwn(sent, TASKS_EXTENSION), false, 'the extension was not sent on');
    assert.equal(Object.hasOwn(sent, OTHER_EXTENSION), true, 'another extension was');
    assert.equal((await stubs(w, 'alpha')).length, 1);
    // tasks/update, and a subscription that names tasks: refused, and not sent.
    const before = methodsSeen(w).length;
    const update = await ask(w, 'alpha', 'tasks/update', { taskId: 'task-1', inputResponses: {} }, 'u');
    assert.equal(update.json.error.code, CODES.methodNotFound);
    const listen = await ask(w, 'beta', 'subscriptions/listen', { notifications: { taskIds: ['task-1'] } }, 'l');
    assert.equal(listen.status, 200);
    assert.equal(listen.json.error.code, CODES.invalidParams);
    assert.equal(methodsSeen(w).length, before, 'neither reached the upstream');
    // An upstream that makes a task all the same: the call's outcome is not known, and its receipt says so.
    const anyway = await call(w, 'alpha', 'odd', { how: 'task-anyway' }, { id: 'a' });
    assert.equal(anyway.json.error.code, CODES.noAnswer);
    assert.match(anyway.json.error.message, /task/);
    assert.ok((await stubs(w, 'alpha')).at(-1).content.details.some((d) => d.name === 'provared.error'));
  } finally {
    await w.close();
  }
});

test('tasks of 2026-07-28, with allowTasks and one agent: the task a call is answered with is the agent\'s, which may get, update and subscribe to it; a task the executor did not see made may not be got, updated, cancelled or subscribed to', async () => {
  const w = await httpWorld({ agents: ['alpha'], config: { allowTasks: true } });
  try {
    const made = await call(w, 'alpha', 'order', { total: 5, item: 'payroll run' }, { id: 'o', meta: META_TASKS });
    assert.equal(made.json.result.resultType, 'task');
    const { taskId } = made.json.result;
    assert.equal(typeof taskId, 'string');
    assert.equal(Object.hasOwn(lastSent(w, 'tools/call').params._meta['io.modelcontextprotocol/clientCapabilities'].extensions, TASKS_EXTENSION), true, 'the extension goes on');
    // Its own.
    assert.equal((await ask(w, 'alpha', 'tasks/get', { taskId }, 'g')).json.result.taskId, taskId);
    assert.deepEqual((await ask(w, 'alpha', 'tasks/update', { taskId, inputResponses: {} }, 'u')).json.result, { resultType: 'complete' });
    // A task it was not answered with, by every route: refused, and not sent.
    const before = methodsSeen(w).length;
    for (const method of ['tasks/get', 'tasks/update', 'tasks/cancel']) {
      const r = await ask(w, 'alpha', method, { taskId: 'task-unknown', inputResponses: {} }, method);
      assert.equal(r.json.error.code, CODES.invalidParams, method);
    }
    assert.equal((await ask(w, 'alpha', 'subscriptions/listen', { notifications: { taskIds: [taskId, 'task-unknown'] } }, 'l')).json.error.code, CODES.invalidParams);
    assert.equal((await ask(w, 'alpha', 'subscriptions/listen', { notifications: { TaskIds: [taskId] } }, 'l2')).json.error.code, CODES.invalidParams, 'in other capitals too');
    assert.equal(methodsSeen(w).length, before, 'none of them reached the upstream');
    // Its subscription to its own task: its notification comes.
    const alphas = await ask(w, 'alpha', 'subscriptions/listen', { notifications: { taskIds: [taskId] } }, 'l4');
    assert.ok(alphas.events.some((e) => e.method === 'notifications/tasks' && e.params.taskId === taskId));
  } finally {
    await w.close();
  }
});
