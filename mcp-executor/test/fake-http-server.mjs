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
  const state = { elsewhere: 0, aborted: 0 };
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
      if (req.headers['last-event-id'] === 'fast') {
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
      if (Array.isArray(m)) return json(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'No batches' } });
      if (Object.hasOwn(m, 'result') || Object.hasOwn(m, 'error') || m.id === undefined) {
        res.writeHead(202);
        return res.end();
      }
      const { id, method, params = {} } = m;
      if (method === 'server/discover') return result(res, id, { resultType: 'complete', supportedVersions: ['2026-07-28'], capabilities: { tools: {} } });
      if (method === 'initialize') {
        const session = `sess-${nextSession++}`;
        sessions.add(session);
        return result(res, id, { protocolVersion: params.protocolVersion ?? '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'fake-http-server', version: '0.0.1' } }, { 'mcp-session-id': session });
      }
      if (method === 'ping') return result(res, id, {});
      if (method === 'hang') return; // never answers
      // Opens a session of the client's naming, with the status it asks for (a session id on a non-2xx answer is the review's case).
      if (method === 'with-session') return json(res, params.status ?? 200, { jsonrpc: '2.0', id, result: {} }, { 'mcp-session-id': params.session });
      if (method === 'tools/list') {
        const page = params.cursor === 'page2' ? TOOLS.slice(4) : TOOLS.slice(0, 4);
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
      const text = (t) => result(res, id, { resultType: 'complete', content: [{ type: 'text', text: t }] });
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
          send({ jsonrpc: '2.0', id, result: { resultType: 'complete', content: [{ type: 'text', text: 'first' }] } });
          send({ jsonrpc: '2.0', id, result: { resultType: 'complete', content: [{ type: 'text', text: 'second' }] } });
          return res.end();
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
        if (how === 'redirect') {
          res.writeHead(302, { location: `http://127.0.0.1:${server.address().port}/elsewhere` });
          return res.end();
        }
        if (how === 'status') {
          res.writeHead(args.status ?? 500, { 'content-type': 'text/plain' });
          return res.end(`broken ${req.headers.authorization}`);
        }
        // A refusal the specification makes normal: a non-2xx status with a JSON-RPC error under the call's id.
        if (how === 'status-json') return json(res, args.status ?? 400, { jsonrpc: '2.0', id, error: { code: args.code ?? -32022, message: `Refused by the server ${req.headers.authorization}`, data: { supported: ['2025-11-25'] } } });
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
