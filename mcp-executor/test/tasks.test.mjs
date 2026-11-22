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
const { httpWorld, call, request, rawRequest, auth, beginSession, META, TOKEN } = await import('./http-world.mjs');
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
    // On a stream (each under the agent's own session: with two agents, a GET without one is not opened), the status of alpha's task reaches alpha alone.
    const stream = async (agent) => {
      const s = await rawRequest(w, { method: 'GET', headers: { accept: 'text/event-stream', ...auth(w, agent), 'mcp-session-id': await beginSession(w, agent) }, stream: true });
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
  const w = await httpWorld({ config: { allowTasks: true } });
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

test('tasks of 2026-07-28, with allowTasks: the task a call is answered with is its agent\'s, who may get and update it; another agent may not get, update, cancel or subscribe to it, and is not given its notifications', async () => {
  const w = await httpWorld({ slips: SLIPS, config: { allowTasks: true } });
  try {
    const made = await call(w, 'alpha', 'order', { total: 5, item: 'payroll run' }, { id: 'o', meta: META_TASKS });
    assert.equal(made.json.result.resultType, 'task');
    const { taskId } = made.json.result;
    assert.equal(typeof taskId, 'string');
    assert.equal(Object.hasOwn(lastSent(w, 'tools/call').params._meta['io.modelcontextprotocol/clientCapabilities'].extensions, TASKS_EXTENSION), true, 'the extension goes on');
    // alpha's own.
    assert.equal((await ask(w, 'alpha', 'tasks/get', { taskId }, 'g')).json.result.taskId, taskId);
    assert.deepEqual((await ask(w, 'alpha', 'tasks/update', { taskId, inputResponses: {} }, 'u')).json.result, { resultType: 'complete' });
    // beta, by every route: refused, and not sent.
    const before = methodsSeen(w).length;
    for (const method of ['tasks/get', 'tasks/update', 'tasks/cancel']) {
      const r = await ask(w, 'beta', method, { taskId, inputResponses: {} }, method);
      assert.equal(r.json.error.code, CODES.invalidParams, method);
    }
    assert.equal((await ask(w, 'beta', 'subscriptions/listen', { notifications: { taskIds: [taskId] } }, 'l')).json.error.code, CODES.invalidParams);
    assert.equal((await ask(w, 'beta', 'subscriptions/listen', { notifications: { TaskIds: [taskId] } }, 'l2')).json.error.code, CODES.invalidParams, 'in other capitals too');
    assert.equal(methodsSeen(w).length, before, 'none of them reached the upstream');
    // A subscription of beta's that names no task: alpha's task's notification is not given to beta.
    const betas = await ask(w, 'beta', 'subscriptions/listen', { notifications: {} }, 'l3');
    assert.equal(betas.status, 200);
    assert.doesNotMatch(betas.body, new RegExp(taskId));
    assert.doesNotMatch(betas.body, /4471/);
    // alpha's subscription to its own task: its notification comes.
    const alphas = await ask(w, 'alpha', 'subscriptions/listen', { notifications: { taskIds: [taskId] } }, 'l4');
    assert.ok(alphas.events.some((e) => e.method === 'notifications/tasks' && e.params.taskId === taskId));
  } finally {
    await w.close();
  }
});

test('tasks of 2026-07-28, with allowTasks: a task named in answers to two agents is neither\'s, so an agent that has an id named to it first does not get the other\'s task', async () => {
  const w = await httpWorld({ slips: SLIPS, config: { allowTasks: true } });
  try {
    // beta has the id "task-shared" named to it, in the answer to a request of its own.
    assert.equal((await ask(w, 'beta', 'claim', { taskId: 'task-shared' }, 'c')).json.result.taskId, 'task-shared');
    // The upstream then makes that task for alpha's call.
    const made = await call(w, 'alpha', 'odd', { how: 'task-anyway', taskId: 'task-shared' }, { id: 'o', meta: META_TASKS });
    assert.equal(made.json.result.taskId, 'task-shared');
    // Neither may reach it now: not beta, who would have alpha's task, and not alpha, since the executor cannot tell which agent's it is.
    const before = methodsSeen(w).length;
    for (const agent of ['beta', 'alpha']) assert.equal((await ask(w, agent, 'tasks/get', { taskId: 'task-shared' }, `g-${agent}`)).json.error.code, CODES.invalidParams, agent);
    assert.equal(methodsSeen(w).length, before);
    assert.ok(w.logs.some((e) => e.event === 'task-disputed'));
  } finally {
    await w.close();
  }
});
