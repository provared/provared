// A made-up MCP tool server for the tests, over stdio. It answers the
// messages of both eras of the specification (server/discover of
// 2026-07-28, and the initialize handshake of 2025-11-25 and earlier), and
// has tools that behave in the ways the tests need. Nothing here reaches
// the network. It writes what it saw to a file named by FAKE_LOG, one JSON
// object to a line, so that a test can see what reached it.

import { appendFileSync } from 'node:fs';

const log = (entry) => {
  if (process.env.FAKE_LOG) appendFileSync(process.env.FAKE_LOG, `${JSON.stringify(entry)}\n`);
};

process.stderr.write('fake-server: started\n');

const TOOLS = [
  { name: 'echo', description: 'Gives back its arguments, and what the server sees.', inputSchema: { type: 'object' } },
  { name: 'order', description: 'Places an order.', inputSchema: { type: 'object', properties: { total: { type: 'integer' } } } },
  { name: 'slow', description: 'Answers after a while, or never.', inputSchema: { type: 'object' } },
  { name: 'crash', description: 'Ends the server.', inputSchema: { type: 'object' } },
  { name: 'fail', description: 'A tool execution error.', inputSchema: { type: 'object' } },
  { name: 'error', description: 'A protocol error.', inputSchema: { type: 'object' } },
  { name: 'hidden', description: 'A tool the executor has no rule for.', inputSchema: { type: 'object' } },
  { name: 'ask', description: 'Asks the client something first (legacy sampling).', inputSchema: { type: 'object' } },
  { name: 'big', description: 'A large answer.', inputSchema: { type: 'object' } },
];

const cancelled = new Set();
const pendingAsks = new Map();
let serverRequestId = 1000;
let buffer = '';

const send = (m) => process.stdout.write(`${JSON.stringify(m)}\n`);
const result = (id, r) => send({ jsonrpc: '2.0', id, result: r });
const failure = (id, code, message) => send({ jsonrpc: '2.0', id, error: { code, message } });

function onMessage(m) {
  log({ seen: m });
  if (Object.hasOwn(m, 'result') || Object.hasOwn(m, 'error')) {
    // A client's answer to a request of this server (legacy era).
    const waiting = pendingAsks.get(m.id);
    if (waiting) {
      pendingAsks.delete(m.id);
      waiting(m);
    }
    return;
  }
  const { id, method, params = {} } = m;
  if (method === 'notifications/cancelled') {
    cancelled.add(String(params.requestId));
    return;
  }
  if (id === undefined) return; // other notifications
  if (method === 'server/discover') return result(id, { resultType: 'complete', supportedVersions: ['2026-07-28'], capabilities: { tools: {} }, _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'fake-server', version: '0.0.1' } } });
  if (method === 'initialize') return result(id, { protocolVersion: params.protocolVersion ?? '2025-11-25', capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'fake-server', version: '0.0.1' } });
  if (method === 'ping') return result(id, {});
  if (method === 'tools/list') {
    const page = params.cursor === 'page2' ? TOOLS.slice(5) : TOOLS.slice(0, 5);
    return result(id, { resultType: 'complete', tools: page, ...(params.cursor === 'page2' ? {} : { nextCursor: 'page2' }) });
  }
  if (method === 'tools/call') {
    const name = params.name;
    const args = params.arguments ?? {};
    const text = (t) => result(id, { resultType: 'complete', content: [{ type: 'text', text: t }] });
    if (name === 'echo') return result(id, { resultType: 'complete', content: [{ type: 'text', text: JSON.stringify(args) }], structuredContent: { args, meta: params._meta ?? null, token: process.env.FAKE_TOKEN ?? null, agentSecret: process.env.AGENT_SECRET ?? null, passed: process.env.PASSED_THROUGH ?? null } });
    if (name === 'order') return text(`Ordered for ${args.total}.`);
    if (name === 'fail') return result(id, { resultType: 'complete', content: [{ type: 'text', text: 'It did not work.' }], isError: true });
    if (name === 'error') return failure(id, -32602, 'Bad arguments.');
    if (name === 'crash') {
      process.stdout.write('', () => process.exit(3));
      return;
    }
    if (name === 'big') return text('x'.repeat(args.size ?? 100000));
    if (name === 'slow') {
      if (args.never) return;
      setTimeout(() => {
        // With FAKE_IGNORE_CANCEL the server answers all the same, as a server that does not honour cancellation would.
        if (!cancelled.has(String(id)) || process.env.FAKE_IGNORE_CANCEL) text(`Done, slowly.${args.tag ? ` ${args.tag}` : ''}`);
        else log({ notAnswered: id });
      }, args.ms ?? 200);
      return;
    }
    if (name === 'weird') return send({ jsonrpc: '2.0', id, result: { resultType: 'complete', content: [{ type: 'text', text: 'a lone surrogate follows: \ud800' }] } });
    if (name === 'ask') {
      const askId = serverRequestId++;
      pendingAsks.set(askId, (answer) => text(`The client said: ${JSON.stringify(answer.result ?? answer.error)}`));
      send({ jsonrpc: '2.0', id: askId, method: 'sampling/createMessage', params: { messages: [] } });
      return;
    }
    return failure(id, -32602, `Unknown tool: ${name}`);
  }
  return failure(id, -32601, `Method not found: ${method}`);
}

process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  for (;;) {
    const at = buffer.indexOf('\n');
    if (at === -1) break;
    const line = buffer.slice(0, at).replace(/\r$/, '');
    buffer = buffer.slice(at + 1);
    if (line === '') continue;
    let m;
    try {
      m = JSON.parse(line);
    } catch {
      failure(null, -32700, 'Parse error');
      continue;
    }
    onMessage(m);
  }
});
process.stdin.on('end', () => {
  log({ stdinEnded: true });
  if (process.env.FAKE_LINGER) setTimeout(() => process.exit(0), Number(process.env.FAKE_LINGER));
  else process.exit(0);
});
