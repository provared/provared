// A made-up MCP tool server for the tests, over the Streamable HTTP
// transport, in this process on the local address. It answers both eras
// (server/discover, and the initialize handshake with a session id), and
// has tools that behave in the ways the tests need: answers as JSON or as a
// stream of events, answers under another id, twice, never, or with a
// stream cut midway; a redirection; an answer that echoes every header it
// was given, so that a test can see what reached it; a refusal with a
// non-2xx status and a JSON-RPC body; a stream as fast as the client
// takes it; a request it never answers. Nothing here leaves this computer.

import http from 'node:http';

const TOOLS = [
  // "echo" annotates two arguments with x-mcp-header, one of them nested: the tests of Mcp-Param-* headers use them.
  { name: 'echo', description: 'Gives back its arguments, and what the server sees.', inputSchema: { type: 'object', properties: { region: { type: 'string', 'x-mcp-header': 'region' }, tenant: { type: 'object', properties: { id: { type: 'string', 'x-mcp-header': 'Tenant-Id' } } }, count: { type: 'integer', 'x-mcp-header': 'count' } } } },
  { name: 'order', description: 'Places an order.', inputSchema: { type: 'object', properties: { total: { type: 'integer' } } } },
  { name: 'slow', description: 'Answers after a while, or never.', inputSchema: { type: 'object' } },
  { name: 'stream', description: 'Answers as a stream of events.', inputSchema: { type: 'object' } },
  { name: 'fail', description: 'A tool execution error.', inputSchema: { type: 'object' } },
  { name: 'error', description: 'A protocol error.', inputSchema: { type: 'object' } },
  { name: 'hidden', description: 'A tool the executor has no rule for.', inputSchema: { type: 'object' } },
  { name: 'odd', description: 'Misbehaves as its arguments say.', inputSchema: { type: 'object' } },
];

/**
 * Start the server. "token": the bearer token it expects (a call without it
 * is answered 401, with the header it got echoed in the body). Gives
 * {url, port, seen, elsewhere, aborted, sessions, close}: "seen" every
 * message with the headers it came with; "elsewhere" how many times the
 * redirection's target was asked for; "aborted" how many requests the
 * client closed before the answer.
 */
export function startFakeUpstream({ token = null, path = '/mcp' } = {}) {
  const seen = [];
  const sessions = new Set();
  const tasks = new Map();
  /** The server's own requests waiting for a client's answer, by id: whoever answers under the id settles it, as a server without sessions does. */
  const asks = new Map();
  let nextAsk = 1;
  const state = { elsewhere: 0, aborted: 0, fold: false, ran: [], deepList: 0 };
  /** The text of a value nested "depth" lists deep. */
  const deep = (depth) => `${'['.repeat(depth)}1${']'.repeat(depth)}`;
  // With "fold" set, the server reads member names without regard to capitals, the last one winning, as some JSON readers do for the fields they know.
  const fold = (o) => (o && typeof o === 'object' && !Array.isArray(o) ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k.toLowerCase().toUpperCase().toLowerCase(), v])) : o);
  let nextSession = 1;

  const json = (res, status, value, headers = {}) => {
    const body = Buffer.from(JSON.stringify(value));
    res.writeHead(status, { 'content-type': 'application/json', 'content-length': body.length, ...headers });
    res.end(body);
  };
  const result = (res, id, r, headers) => json(res, 200, { jsonrpc: '2.0', id, result: r }, headers);
  const failure = (res, id, code, message) => json(res, 200, { jsonrpc: '2.0', id, error: { code, message } });
  const sse = (res, headers = {}) => {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', ...headers });
    res.flushHeaders();
    return (m, extra = '') => res.write(`${extra}data: ${typeof m === 'string' ? m : JSON.stringify(m)}\n\n`);
  };

  const server = http.createServer((req, res) => {
    const url = req.url ?? '';
    if (url === '/elsewhere') {
      state.elsewhere += 1;
      return json(res, 200, { jsonrpc: '2.0', id: 'x', result: { content: [] } });
    }
    if (url.split('?')[0] !== path) return json(res, 404, { error: 'not here' });
    if (token !== null && req.headers.authorization !== `Bearer ${token}`) {
      return json(res, 401, { error: `bad token: ${req.headers.authorization ?? 'none'}` }, { 'www-authenticate': `Bearer realm="fake", error="invalid_token", expected="${token}"` });
    }
    let aborted = false;
    req.on('aborted', () => {
      aborted = true;
      state.aborted += 1;
    });
    res.on('close', () => {
      if (!res.writableFinished && !aborted) state.aborted += 1;
    });
    if (req.method === 'GET') {
      // The stream of server messages (legacy): one notification, then open until the client closes.
      seen.push({ method: 'GET', headers: req.headers });
      if (req.headers['last-event-id'] === 'fast' || req.headers['mcp-session-id'] === 'fast') {
        // A stream as fast as the client takes it: 64 KiB events for as long as the connection lasts (the review's case of an agent that reads nothing).
        const big = 'y'.repeat(65536);
        state.fastBytes = 0;
        state.fastClosed = false;
        res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store' });
        res.on('close', () => {
          state.fastClosed = true;
        });
        const pump = () => {
          for (;;) {
            if (res.destroyed) return;
            const ok = res.write(`data: ${big}\n\n`);
            state.fastBytes += big.length + 8;
            if (!ok) return res.once('drain', pump);
          }
        };
        pump();
        return;
      }
      const send = sse(res);
      send({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: `hello ${req.headers['mcp-session-id'] ?? 'no-session'}` } }, 'id: ev-1\n');
      // With "askOnStream" set, a request of the server's own on the stream too (roots/list), whose answer, from whichever client, is kept in "state.answers".
      if (state.askOnStream) {
        const askId = `up-${nextAsk++}`;
        asks.set(askId, (answer) => (state.answers ??= []).push(answer));
        send({ jsonrpc: '2.0', id: askId, method: 'roots/list' });
      }
      // The status of every task it holds, for whoever opens a stream: it keeps one store of tasks for every caller with its token.
      for (const t of tasks.values()) send({ jsonrpc: '2.0', method: 'notifications/tasks/status', params: { taskId: t.taskId, status: t.status } }, `id: task-${t.taskId}\n`);
      return;
    }
    if (req.method === 'DELETE') {
      seen.push({ method: 'DELETE', headers: req.headers });
      const id = req.headers['mcp-session-id'];
      if (!sessions.has(id)) return json(res, 404, { error: 'no such session' });
      sessions.delete(id);
      res.writeHead(200);
      return res.end();
    }
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let m;
      try {
        m = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch {
        return json(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      }
      seen.push({ method: 'POST', headers: req.headers, body: m });
      if (state.fold && !Array.isArray(m)) {
        m = fold(m);
        if (m.params) m.params = { ...fold(m.params), arguments: fold(fold(m.params).arguments) };
      }
      if (Array.isArray(m)) return json(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'No batches' } });
      if (Object.hasOwn(m, 'result') || Object.hasOwn(m, 'error') || m.id === undefined) {
        // A client's answer to a request of the server's own ("ask", below): it settles the call that asked.
        const asked = asks.get(m.id);
        if (asked) {
          asks.delete(m.id);
          asked(m);
        }
        res.writeHead(202);
        return res.end();
      }
      const { id, method, params = {} } = m;
      // With "offerTasks", the server says it takes tasks (2025-11-25: capabilities.tasks; 2026-07-28: the tasks extension in capabilities.extensions of server/discover, beside another extension).
      const capabilities = { tools: {}, ...(state.offerTasks ? { tasks: { list: {}, cancel: {}, requests: { tools: { call: {} } } } } : {}) };
      if (method === 'server/discover') return result(res, id, { resultType: 'complete', supportedVersions: ['2026-07-28'], capabilities: { ...capabilities, ...(state.offerTasks ? { extensions: { 'io.modelcontextprotocol/tasks': {}, 'example.org/other': {} } } : {}) } });
      if (method === 'initialize') {
        const session = `sess-${nextSession++}`;
        sessions.add(session);
        return result(res, id, { protocolVersion: params.protocolVersion ?? '2025-11-25', capabilities, serverInfo: { name: 'fake-http-server', version: '0.0.1' } }, { 'mcp-session-id': session });
      }
      if (method === 'ping') return result(res, id, {});
      // An answer of "count" one-item lists, as a JSON body, or (params.sse) as one event.
      if (method === 'dense') {
        const r = `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"rows":[${new Array(params.count ?? 10).fill('[0]').join(',')}]}}`;
        if (params.sse) {
          sse(res)(r);
          return res.end();
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end(r);
      }
      // An answer of "size" bytes of text, as a JSON body, or (params.sse) as one event.
      if (method === 'big') {
        const r = { text: 'x'.repeat(params.size ?? 100) };
        if (params.sse) {
          sse(res)({ jsonrpc: '2.0', id, result: r });
          return res.end();
        }
        return result(res, id, r);
      }
      // Tasks (2025-11-25), in one store for whoever presents its token, with no sessions: a tools/call that asks for a task is answered with its handle, and tasks/list, tasks/get, tasks/result and tasks/cancel serve any task to any caller.
      // Tasks of the 2026-07-28 revision (the extension io.modelcontextprotocol/tasks), as the review of 0.5.2 describes them: a client that declares the extension in its _meta's client capabilities asks for nothing, and the server decides; here, a call to "order" is made a task, answered with the flat handle {resultType: "task", taskId}. tasks/get and tasks/update name it by params.taskId; subscriptions/listen gives notifications/tasks for the tasks in params.notifications.taskIds, or for every task it holds where none are named (one store for its one caller).
      const extensions = params._meta?.['io.modelcontextprotocol/clientCapabilities']?.extensions;
      const declares = extensions !== null && typeof extensions === 'object' && Object.hasOwn(params._meta['io.modelcontextprotocol/clientCapabilities'].extensions, 'io.modelcontextprotocol/tasks');
      if (method === 'tools/call' && declares && params.name === 'order') {
        const taskId = `task-${tasks.size + 1}-${Math.random().toString(36).slice(2, 10)}`;
        tasks.set(taskId, { taskId, status: 'completed', result: { resultType: 'complete', content: [{ type: 'text', text: `Ordered for ${params.arguments?.total}. Delivery code 4471.` }] } });
        return result(res, id, { resultType: 'task', taskId, status: 'working', ttlMs: 60000 });
      }
      // An answer that gives back, as a task's flat handle, the id the client named: a server whose answer an agent can shape.
      if (method === 'claim') return result(res, id, { resultType: 'task', taskId: params.taskId });
      if (method === 'tasks/update') {
        if (!tasks.has(params.taskId)) return failure(res, id, -32602, 'No such task.');
        return result(res, id, { resultType: 'complete' });
      }
      if (method === 'subscriptions/listen') {
        const named = params.notifications?.taskIds;
        const send = sse(res);
        for (const t of Array.isArray(named) ? named.filter((x) => tasks.has(x)) : [...tasks.keys()]) send({ jsonrpc: '2.0', method: 'notifications/tasks', params: { ...tasks.get(t) } });
        send({ jsonrpc: '2.0', id, result: { resultType: 'complete' } });
        return res.end();
      }
      if (method === 'tools/call' && params.task) {
        const taskId = `task-${tasks.size + 1}-${Math.random().toString(36).slice(2, 10)}`;
        tasks.set(taskId, { taskId, status: 'completed', result: { content: [{ type: 'text', text: `Ordered for ${params.arguments?.total}.` }] } });
        return result(res, id, { task: { taskId, status: 'working', createdAt: new Date().toISOString(), ttl: 60000 } });
      }
      if (method === 'tasks/list') return result(res, id, { tasks: [...tasks.values()].map((t) => ({ taskId: t.taskId, status: t.status })) });
      if (['tasks/get', 'tasks/result', 'tasks/cancel'].includes(method)) {
        const task = tasks.get(params.taskId);
        if (!task) return failure(res, id, -32602, 'No such task.');
        if (method === 'tasks/result') return result(res, id, task.result);
        if (method === 'tasks/cancel') task.status = 'cancelled';
        return result(res, id, { taskId: task.taskId, status: task.status });
      }
      if (method === 'hang') return; // never answers
      // Opens a session of the client's naming, with the status it asks for (a session id on a non-2xx answer is the review's case).
      if (method === 'with-session') return json(res, params.status ?? 200, { jsonrpc: '2.0', id, result: {} }, { 'mcp-session-id': params.session });
      if (method === 'tools/list' && state.rawList) {
        // An answer to tools/list exactly as the test gives it: the status, the headers and the body (text or bytes, or a function of the request's id that gives one).
        res.writeHead(state.rawList.status, state.rawList.headers);
        return res.end(typeof state.rawList.body === 'function' ? state.rawList.body(id) : state.rawList.body);
      }
      if (method === 'tools/list' && state.oddList === 'error') return failure(res, id, -32601, 'This server lists no tools.');
      if (method === 'tools/list' && (state.deepList || state.oddList)) {
        // A list the executor cannot read, as a JSON body or as an event: its first tool's schema nested very deeply; or ("twice") a member named twice beside it; or a result with no "tools", and the tools under "Tools"; or ("other-id") a list under another id.
        const result = state.deepList ? `{"tools":[{"name":"echo","inputSchema":{"type":"object","x":${deep(state.deepList)}}},{"name":"hidden","inputSchema":{"type":"object"}}]}`
          : state.oddList === 'twice' ? '{"tools":[{"name":"echo"},{"name":"hidden"}],"a":1,"a":2}'
            : state.oddList === 'other-id' ? '{"tools":[{"name":"echo"},{"name":"hidden"}]}' : '{"Tools":[{"name":"echo"},{"name":"hidden"}]}';
        const text = `{"jsonrpc":"2.0","id":${JSON.stringify(state.oddList === 'other-id' ? 'someone-else' : id)},"result":${result}}`;
        if (params.sse) {
          sse(res)(text);
          return res.end();
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end(text);
      }
      if (method === 'tools/list') {
        // With "offerTasks", "order" says it may be called as a task (2025-11-25).
        const page = (params.cursor === 'page2' ? TOOLS.slice(4) : TOOLS.slice(0, 4)).map((t) => (state.offerTasks && t.name === 'order' ? { ...t, execution: { taskSupport: 'optional' } } : t));
        if (params.sse) {
          const send = sse(res);
          send({ jsonrpc: '2.0', id, result: { resultType: 'complete', tools: page } });
          return res.end();
        }
        return result(res, id, { resultType: 'complete', tools: page, ...(params.cursor === 'page2' ? {} : { nextCursor: 'page2' }) });
      }
      if (method !== 'tools/call') return failure(res, id, -32601, `Method not found: ${method}`);
      const name = params.name;
      const args = params.arguments ?? {};
      state.ran.push({ name, args });
      const text = (t) => result(res, id, { resultType: 'complete', content: [{ type: 'text', text: t }] });
      if (name === 'hang') return; // a call never answered
      if (name === 'echo') return result(res, id, { resultType: 'complete', content: [{ type: 'text', text: JSON.stringify(args) }], structuredContent: { args, meta: params._meta ?? null, headers: req.headers } });
      if (name === 'order') return text(`Ordered for ${args.total}.`);
      if (name === 'fail') return result(res, id, { resultType: 'complete', content: [{ type: 'text', text: 'It did not work.' }], isError: true });
      if (name === 'error') return failure(res, id, -32602, 'Bad arguments.');
      if (name === 'slow') {
        if (args.never) return; // open until the client closes
        const t = setTimeout(() => text(`Done, slowly.${args.tag ? ` ${args.tag}` : ''}`), args.ms ?? 200);
        res.on('close', () => clearTimeout(t));
        return;
      }
      if (name === 'stream') {
        const send = sse(res);
        send({ jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: params._meta?.progressToken ?? 'p', progress: 1, total: 2 } }, 'id: ev-1\n');
        send({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: `working with ${req.headers.authorization}` } }, ': a comment\nid: ev-2\n');
        setTimeout(() => {
          send({ jsonrpc: '2.0', id, result: { resultType: 'complete', content: [{ type: 'text', text: `Streamed. ${req.headers.authorization}` }] } }, 'id: ev-3\n');
          res.end();
        }, 50);
        return;
      }
      if (name === 'odd') {
        const how = args.how;
        if (how === 'other-id') return result(res, 'someone-else', { resultType: 'complete', content: [{ type: 'text', text: 'not yours' }] });
        if (how === 'other-id-sse') {
          const send = sse(res);
          send({ jsonrpc: '2.0', id: 'someone-else', result: { resultType: 'complete', content: [{ type: 'text', text: 'not yours' }] } });
          return res.end();
        }
        if (how === 'twice') {
          const send = sse(res);
          // Both in one write, so that they arrive in one chunk.
          send(`${JSON.stringify({ jsonrpc: '2.0', id, result: { resultType: 'complete', content: [{ type: 'text', text: 'first' }] } })}\n\nid: ev-2\ndata: ${JSON.stringify({ jsonrpc: '2.0', id, result: { resultType: 'complete', content: [{ type: 'text', text: 'second' }] } })}`, 'id: ev-1\n');
          return res.end();
        }
        // A task's flat handle (2026-07-28) whether or not the client declared the extension: a server that does not keep to it.
        if (how === 'task-anyway') {
          const taskId = args.taskId ?? `task-${tasks.size + 1}-${Math.random().toString(36).slice(2, 10)}`;
          tasks.set(taskId, { taskId, status: 'completed', result: { resultType: 'complete', content: [{ type: 'text', text: 'made anyway' }] } });
          return result(res, id, { resultType: 'task', taskId, status: 'working', ttlMs: 60000 });
        }
        if (how === 'ask') {
          // A request of the server's own on the call's stream (elicitation), under an id it numbers itself; the call is answered with whatever answer comes under that id, from whichever client.
          const send = sse(res);
          const askId = `up-${nextAsk++}`;
          asks.set(askId, (answer) => {
            send({ jsonrpc: '2.0', id, result: { resultType: 'complete', content: [{ type: 'text', text: `answered: ${JSON.stringify(answer.result ?? answer.error)}` }] } });
            res.end();
          });
          res.on('close', () => asks.delete(askId));
          return send({ jsonrpc: '2.0', id: askId, method: 'elicitation/create', params: { message: 'Which account?', requestedSchema: { type: 'object', properties: {} } } });
        }
        if (how === 'drop') {
          const send = sse(res);
          send({ jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: 'p', progress: 1 } });
          return setTimeout(() => res.destroy(), 20);
        }
        if (how === 'endless') {
          const send = sse(res);
          const t = setInterval(() => send({ jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: 'p', progress: 1 } }), 10);
          res.on('close', () => clearInterval(t));
          return;
        }
        if (how === 'big-event') {
          const send = sse(res);
          send({ jsonrpc: '2.0', id, result: { resultType: 'complete', content: [{ type: 'text', text: 'x'.repeat(args.size ?? 100) }] } });
          return res.end();
        }
        if (how === 'big-json') return text('x'.repeat(args.size ?? 100));
        // A result of "count" one-item lists, which costs many times its bytes once read; as one event with "sse".
        if (how === 'dense') {
          const r = `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"resultType":"complete","content":[{"type":"text","text":"dense"}],"structuredContent":{"rows":[${new Array(args.count ?? 10).fill('[0]').join(',')}]}}}`;
          if (args.sse) {
            sse(res)(r);
            return res.end();
          }
          res.writeHead(200, { 'content-type': 'application/json' });
          return res.end(r);
        }
        if (how === 'redirect') {
          res.writeHead(302, { location: `http://127.0.0.1:${server.address().port}/elsewhere` });
          return res.end();
        }
        if (how === 'status') {
          res.writeHead(args.status ?? 500, { 'content-type': 'text/plain' });
          return res.end(`broken ${req.headers.authorization}`);
        }
        // A refusal the specification makes normal: a non-2xx status with a JSON-RPC error under the call's id.
        if (how === 'status-json') return json(res, args.status ?? 400, { jsonrpc: '2.0', id: args.otherId ? 'someone-else' : id, ...(args.result ? { result: { content: [] } } : { error: { code: args.code ?? -32022, message: `Refused by the server ${req.headers.authorization}`, data: { supported: ['2025-11-25'] } } }) });
        if (how === 'after') {
          // The response and a notification after it, in one write: nothing after the response should reach the agent.
          const send = sse(res);
          send(`${JSON.stringify({ jsonrpc: '2.0', id, result: { resultType: 'complete', content: [{ type: 'text', text: 'done' }] } })}\n\ndata: ${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'after the answer' } })}`, 'id: ev-1\n');
          return res.end();
        }
        if (how === 'answer-then-endless') {
          const send = sse(res);
          send({ jsonrpc: '2.0', id, result: { resultType: 'complete', content: [{ type: 'text', text: 'done' }] } });
          const t = setInterval(() => send({ jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: 'p', progress: 1 } }), 10);
          res.on('close', () => clearInterval(t));
          return;
        }
        if (how === 'short') {
          // Declares more than it sends, then drops the connection.
          res.writeHead(200, { 'content-type': 'application/json', 'content-length': 100 });
          res.write('{"jsonrpc":');
          return setTimeout(() => res.destroy(), 20);
        }
        if (how === 'not-json') {
          res.writeHead(200, { 'content-type': 'application/json' });
          return res.end('{"jsonrpc":"2.0","id":' + JSON.stringify(id) + ',"result":{"a":1,"a":2}}');
        }
        // A second result, or a second id, under a name in other capitals: a client that ignores capitals would read the second.
        if (how === 'capital-result' || how === 'capital-id') {
          res.writeHead(200, { 'content-type': 'application/json' });
          const second = how === 'capital-id' ? '"ID":"someone-else"' : '"Result":{"content":[{"type":"text","text":"the other result"}]}';
          return res.end('{"jsonrpc":"2.0","id":' + JSON.stringify(id) + ',"result":{"content":[{"type":"text","text":"the result"}]},' + second + '}');
        }
        // Answers nested "depth" levels deep, written as text: a result or an error, as a JSON body or as an event.
        if (how === 'deep-result' || how === 'deep-error' || how === 'deep-result-sse') {
          const text = how === 'deep-error'
            ? `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"error":{"code":-32000,"message":"deep","data":${deep(args.depth)}}}`
            : `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"content":[{"type":"text","text":"deep"}],"structuredContent":{"a":${deep(args.depth)}}}}`;
          if (how === 'deep-result-sse') {
            sse(res)(text);
            return res.end();
          }
          res.writeHead(200, { 'content-type': 'application/json' });
          return res.end(text);
        }
        if (how === 'bigint') {
          res.writeHead(200, { 'content-type': 'application/json' });
          return res.end(`{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"resultType":"complete","content":[{"type":"text","text":"ok"}],"structuredContent":{"snowflake":1234567890123456789}}}`);
        }
        return text('nothing odd');
      }
      return failure(res, id, -32602, `Unknown tool: ${name}`);
    });
  });
  return new Promise((done) => {
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      done({
        url: `http://127.0.0.1:${port}${path}`,
        port,
        seen,
        sessions,
        /** The tasks it holds, by id: {taskId, status, result}. */
        tasks,
        /** Every tools/call the server ran: {name, args}, as it read them. */
        ran: state.ran,
        /** Read member names without regard to capitals from now on. */
        foldNames: () => {
          state.fold = true;
        },
        /** Answer tools/list, from now on, with a list nested this deeply. */
        deepList: (depth) => {
          state.deepList = depth;
        },
        /** Answer tools/list, from now on, with a list the executor cannot read in the way named, or ("error") with an error; null: as usual. */
        oddList: (kind) => {
          state.oddList = kind;
        },
        /** Answer tools/list, from now on, with exactly this: {status, headers, body (text or bytes, or a function of the request's id)}; null: as usual. */
        rawList: (answer) => {
          state.rawList = answer;
        },
        /** Offer tasks, from now on: capabilities.tasks, and "order" as a tool that may be called as a task. */
        offerTasks: () => {
          state.offerTasks = true;
        },
        /** Send, from now on, a request of its own (roots/list) on every GET stream too. */
        askOnStream: () => {
          state.askOnStream = true;
        },
        /** The answers that came to the requests it sent on GET streams. */
        get answers() {
          return state.answers ?? [];
        },
        get elsewhere() {
          return state.elsewhere;
        },
        get aborted() {
          return state.aborted;
        },
        /** Bytes written to the "fast" GET stream, and whether its connection has closed. */
        get fastBytes() {
          return state.fastBytes ?? 0;
        },
        get fastClosed() {
          return state.fastClosed ?? false;
        },
        close: () =>
          new Promise((closed) => {
            server.closeAllConnections();
            server.close(() => closed());
          }),
      });
    });
  });
}
