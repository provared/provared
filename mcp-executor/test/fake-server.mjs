// A made-up MCP tool server for the tests, over stdio. It answers the
// messages of both eras of the specification (server/discover of
// 2026-07-28, and the initialize handshake of 2025-11-25 and earlier), and
// has tools that behave in the ways the tests need. Nothing here reaches
// the network. It writes what it saw to a file named by FAKE_LOG, one JSON
// object to a line, so that a test can see what reached it.

import { appendFileSync } from 'node:fs';
import { createInterface } from 'node:readline';

const log = (entry) => {
  if (!process.env.FAKE_LOG) return;
  let line;
  try {
    line = JSON.stringify(entry);
  } catch {
    // Nested too deeply to be written out: the log says only what kind of message it was.
    line = JSON.stringify({ seen: { method: entry.seen?.method ?? null, id: entry.seen?.id ?? null, tooDeepToLog: true } });
  }
  appendFileSync(process.env.FAKE_LOG, `${line}\n`);
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

// With FAKE_FOLD the server reads member names without regard to capitals, the last one winning, as some JSON readers do for the fields they know.
const fold = (o) => (o && typeof o === 'object' && !Array.isArray(o) ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k.toLowerCase().toUpperCase().toLowerCase(), v])) : o);

function onMessage(given) {
  let m = given;
  log({ seen: m });
  if (process.env.FAKE_FOLD) {
    m = fold(m);
    if (m.params) m.params = { ...fold(m.params), arguments: fold(fold(m.params).arguments) };
  }
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
  if (method === 'never') return; // a request that is never answered
  if (method === 'tools/list' && params.cursor === 'page2' && process.env.FAKE_BIG_LIST) {
    // The answer written as raw text, so that the number is exact: a whole number beyond 2^53 - 1 in a tool's definition.
    return process.stdout.write(`{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"resultType":"complete","tools":[{"name":"error","description":"A protocol error.","inputSchema":{"type":"object"}},{"name":"hidden","description":"No rule.","inputSchema":{"type":"object"},"ordinal":1234567890123456789},{"name":"big","description":"A large answer.","inputSchema":{"type":"object"},"ordinal":1234567890123456789}]}}\n`);
  }
  if (method === 'tools/list' && process.env.FAKE_CAPITAL_LIST) {
    // A list with names in other capitals: a tool the executor shows under one name and a client that ignores capitals reads under another, and a second list.
    return process.stdout.write(`{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"tools":[{"name":"echo","inputSchema":{"type":"object"}},{"name":"order","Name":"hidden","inputSchema":{"type":"object"}},{"name":"slow","NAME":"hidden","inputSchema":{"type":"object"}}],"Tools":[{"name":"hidden","inputSchema":{"type":"object"}}],"TOOLS":[]}}\n`);
  }
  if (method === 'tools/list') {
    const page = params.cursor === 'page2' ? TOOLS.slice(5) : TOOLS.slice(0, 5);
    return result(id, { resultType: 'complete', tools: page, ...(params.cursor === 'page2' ? {} : { nextCursor: 'page2' }) });
  }
  if (method === 'tools/call') {
    const name = params.name;
    const args = params.arguments ?? {};
    if (process.env.FAKE_FOLD) log({ ran: name, args });
    const text = (t) => result(id, { resultType: 'complete', content: [{ type: 'text', text: t }] });
    if (name === 'echo') return result(id, { resultType: 'complete', content: [{ type: 'text', text: JSON.stringify(args) }], structuredContent: { args, meta: params._meta ?? null, token: process.env.FAKE_TOKEN ?? null, agentSecret: process.env.AGENT_SECRET ?? null, passed: process.env.PASSED_THROUGH ?? null } });
    if (name === 'order') return text(`Ordered for ${args.total}.`);
    if (name === 'write_file') return text('Written.');
    if (name === 'edit_file') return text('Edited.');
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
    if (name === 'bigint') return process.stdout.write(`{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"resultType":"complete","content":[{"type":"text","text":"ok"}],"structuredContent":{"snowflake":1234567890123456789,"ratio":1.50}}}\n`);
    // A second result, or a second id, under a name in other capitals: a client that ignores capitals would read the second.
    if (name === 'capresult') return process.stdout.write(`{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"content":[{"type":"text","text":"the result"}]},"Result":{"content":[{"type":"text","text":"the other result"}]}}\n`);
    if (name === 'capid') return process.stdout.write(`{"jsonrpc":"2.0","id":${JSON.stringify(id)},"ID":"someone-else","result":{"content":[{"type":"text","text":"the result"}]}}\n`);
    if (name === 'twoids') return process.stdout.write(`{"jsonrpc":"2.0","id":${JSON.stringify(id)},"id":${JSON.stringify(id)},"result":{"resultType":"complete","content":[]}}\n`);
    if (name === 'batch') return process.stdout.write(`[{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"resultType":"complete","content":[]}}]\n`);
    if (name === 'garbage') return process.stdout.write(`{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"resultType":"complete","a":1,"a":2}}\n`);
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

function onLine(line) {
  if (line === '') return;
  let m;
  try {
    m = JSON.parse(line);
  } catch {
    log({ notJson: line.slice(0, 120) });
    failure(null, -32700, 'Parse error');
    return;
  }
  onMessage(m);
}

// FAKE_LINE_ENDS: how the server ends a line. Not set: at a line feed alone.
// "readline": as node:readline does, at a bare carriage return, U+2028 and
// U+2029 too. "universal": at a line feed, a carriage return, or the two
// together, as a text reader with universal newlines does, which Python's
// io.TextIOWrapper gives unless told otherwise, as the official Python
// SDK's stdio server uses, and how Python opens its standard input on
// Windows.
const lineEnd = process.env.FAKE_LINE_ENDS === 'universal' ? /\r\n|\r(?!$)|\n/ : /\n/;
process.stdin.setEncoding('utf8');
if (process.env.FAKE_LINE_ENDS === 'readline') createInterface({ input: process.stdin }).on('line', onLine);
else {
  process.stdin.on('data', (chunk) => {
    buffer += chunk;
    for (;;) {
      const found = lineEnd.exec(buffer);
      if (!found) break;
      const line = buffer.slice(0, found.index).replace(/\r$/, '');
      buffer = buffer.slice(found.index + found[0].length);
      onLine(line);
    }
  });
}
process.stdin.on('end', () => {
  log({ stdinEnded: true });
  if (process.env.FAKE_LINGER) setTimeout(() => process.exit(0), Number(process.env.FAKE_LINGER));
  else process.exit(0);
});
