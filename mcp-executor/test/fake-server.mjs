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

// With FAKE_IGNORE_TERM the server takes no notice of SIGTERM and does not end when its input closes: only a signal it cannot ignore ends it.
if (process.env.FAKE_IGNORE_TERM) {
  process.on('SIGTERM', () => log({ sigterm: true }));
  setInterval(() => {}, 1000);
}

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

/** The text of a value nested "depth" lists deep. */
const deep = (depth) => `${'['.repeat(depth)}1${']'.repeat(depth)}`;
/** With FAKE_ODD_LIST one of these names: the line that answers tools/list, from the request's id as JSON and the result's text. */
const UNMATCHED_LIST = {
  'id-twice': (id, r) => `{"jsonrpc":"2.0","id":${id},"id":${id},"result":${r}}`,
  'no-id': (id, r) => `{"jsonrpc":"2.0","result":${r}}`,
  'null-id': (id, r) => `{"jsonrpc":"2.0","id":null,"result":${r}}`,
  batch: (id, r) => `[{"jsonrpc":"2.0","id":${id},"result":${r}}]`,
  bom: (id, r) => `﻿{"jsonrpc":"2.0","id":${id},"result":${r}}`,
};

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
  // FAKE_INIT: "error" answers initialize with an error, "never" does not answer it, "deaf" answers it and reads nothing after.
  if (method === 'initialize' && process.env.FAKE_INIT === 'error') return failure(id, -32602, 'Unsupported protocol version');
  if (method === 'initialize' && process.env.FAKE_INIT === 'never') return;
  if (method === 'initialize' && process.env.FAKE_INIT === 'deaf') {
    setImmediate(() => process.stdin.pause());
    setInterval(() => {}, 1000);
  }
  if (method === 'initialize') return result(id, { protocolVersion: params.protocolVersion ?? '2025-11-25', capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'fake-server', version: '0.0.1' } });
  if (method === 'ping') return result(id, {});
  if (method === 'never') return; // a request that is never answered
  if (method === 'tools/list' && params.cursor === 'page2' && process.env.FAKE_BIG_LIST) {
    // The answer written as raw text, so that the number is exact: a whole number beyond 2^53 - 1 in a tool's definition.
    return process.stdout.write(`{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"resultType":"complete","tools":[{"name":"error","description":"A protocol error.","inputSchema":{"type":"object"}},{"name":"hidden","description":"No rule.","inputSchema":{"type":"object"},"ordinal":1234567890123456789},{"name":"big","description":"A large answer.","inputSchema":{"type":"object"},"ordinal":1234567890123456789}]}}\n`);
  }
  if (method === 'tools/list' && process.env.FAKE_ODD_LIST === 'error') return failure(id, -32601, 'This server lists no tools.');
  if (method === 'tools/list' && Object.hasOwn(UNMATCHED_LIST, process.env.FAKE_ODD_LIST ?? '')) {
    // A list on a line that no reader can match to the request.
    return process.stdout.write(`${UNMATCHED_LIST[process.env.FAKE_ODD_LIST](JSON.stringify(id), '{"tools":[{"name":"echo"},{"name":"hidden"}]}')}\n`);
  }
  if (method === 'tools/list' && process.env.FAKE_ODD_LIST) {
    // A list the executor cannot read: "twice", a member named twice beside it; anything else, a result with no "tools", and the tools under "Tools".
    const odd = process.env.FAKE_ODD_LIST === 'twice' ? '{"tools":[{"name":"echo"},{"name":"hidden"}],"a":1,"a":2}' : '{"Tools":[{"name":"echo"},{"name":"hidden"}]}';
    return process.stdout.write(`{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":${odd}}\n`);
  }
  if (method === 'tools/list' && process.env.FAKE_DEEP_LIST) {
    // A list whose first tool has a schema nested very deeply.
    return process.stdout.write(`{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"tools":[{"name":"echo","inputSchema":{"type":"object","x":${deep(Number(process.env.FAKE_DEEP_LIST))}}},{"name":"hidden","inputSchema":{"type":"object"}}]}}\n`);
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
    if (name === 'flood') {
      // Notifications without pause, until the server is ended; or "count" of them, and then the answer.
      const line = `${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'x'.repeat(80) } })}\n`;
      let left = args.count ?? Infinity;
      const more = () => {
        const now = Math.min(left, 500);
        left -= now;
        process.stdout.write(line.repeat(now), () => (left > 0 ? setImmediate(more) : text('Flooded.')));
      };
      return more();
    }
    // "count" notifications, then the answer, and the server ends as soon as the answer is written: an exit close behind much output.
    if (name === 'chatty') {
      let notes = '';
      for (let i = 0; i < (args.count ?? 1500); i++) notes += `${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: `n${i}` } })}\n`;
      if (notes) process.stdout.write(notes);
      return process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: 'Chatty.' }] } })}\n`, () => process.exit(0));
    }
    // A line of 100 KiB on its standard error, then a short one.
    if (name === 'longerr') return process.stderr.write(`${'L'.repeat(100 * 1024)}\nafter the long line\n`, () => text('Long.'));
    // An answer to nothing the executor asked, then a notification, then the answer.
    if (name === 'stray') {
      send({ jsonrpc: '2.0', id: 'nobody', result: { content: [{ type: 'text', text: 'an answer to nothing' }] } });
      send({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'after the stray answer' } });
      return text('Strayed.');
    }
    // Much on its standard error, and the answer only once all of it is written.
    if (name === 'loud') return process.stderr.write(`${'e'.repeat(1023)}\n`.repeat(args.kib ?? 1024), () => text('Loud.'));
    // Half a line on its standard error, with no line feed.
    if (name === 'mutter') return process.stderr.write('half a line', () => text('Muttered.'));
    // Answers nested "depth" levels deep, written as text: a result, an error, and a notification before a plain result.
    if (name === 'deep') return process.stdout.write(`{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"content":[{"type":"text","text":"deep"}],"structuredContent":{"a":${deep(args.depth)}}}}\n`);
    if (name === 'deeperror') return process.stdout.write(`{"jsonrpc":"2.0","id":${JSON.stringify(id)},"error":{"code":-32000,"message":"deep","data":${deep(args.depth)}}}\n`);
    if (name === 'deepnote') {
      process.stdout.write(`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":${deep(args.depth)}}}\n`);
      return text('After a deep notification.');
    }
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

// FAKE_LINE_ENDS=universal: the server ends a line at a line feed, a carriage
// return, or the two together, as a text reader with universal newlines
// does, which Python's io.TextIOWrapper gives unless told otherwise, as the
// official Python SDK's stdio server uses, and how Python opens its standard
// input on Windows. Not set: at a line feed alone. (FAKE_READLINE, below, is
// node:readline itself.)
const lineEnd = process.env.FAKE_LINE_ENDS === 'universal' ? /\r\n|\r(?!$)|\n/ : /\n/;
process.stdin.setEncoding('utf8');
const onData = (chunk) => {
  buffer += chunk;
  for (;;) {
    const found = lineEnd.exec(buffer);
    if (!found) break;
    const line = buffer.slice(0, found.index).replace(/\r$/, '');
    buffer = buffer.slice(found.index + found[0].length);
    if (line === '') continue;
    let m;
    try {
      m = JSON.parse(line);
    } catch {
      log({ notJson: line.slice(0, 120) });
      failure(null, -32700, 'Parse error');
      continue;
    }
    onMessage(m);
  }
};
// With FAKE_READLINE the server reads its lines as node:readline does, which ends a line at a bare carriage return, U+2028 and U+2029 as well as at a line feed.
if (process.env.FAKE_READLINE) {
  createInterface({ input: process.stdin }).on('line', (line) => {
    if (line === '') return;
    let m;
    try {
      m = JSON.parse(line);
    } catch {
      log({ notJson: line.slice(0, 120) });
      return failure(null, -32700, 'Parse error');
    }
    onMessage(m);
  });
} else process.stdin.on('data', onData);
process.stdin.on('end', () => {
  log({ stdinEnded: true });
  if (process.env.FAKE_IGNORE_TERM) return;
  if (process.env.FAKE_LINGER) setTimeout(() => process.exit(0), Number(process.env.FAKE_LINGER));
  else process.exit(0);
});
