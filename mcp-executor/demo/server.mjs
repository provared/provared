// A made-up MCP tool server, for the demonstration only. It speaks the
// Model Context Protocol over the stdio transport (one JSON-RPC message to
// a line), uses nothing but Node.js itself, reaches no network and touches
// no file. It has two harmless tools: "echo" hands back the text it is
// given, and "add" adds two whole numbers.
//
// It will not start without DEMO_TOKEN in its environment: a made-up
// credential that only the executor holds (start.mjs writes it into the
// demonstration's folder, and the executor's settings name that file). So
// the agent's client cannot reach this server except through the executor.

import { createInterface } from 'node:readline';

if (!process.env.DEMO_TOKEN) {
  process.stderr.write('demo server: DEMO_TOKEN is not set. Start the executor, which holds it, not this server.\n');
  process.exit(1);
}

const TOOLS = [
  {
    name: 'echo',
    description: 'Hands back the text it is given. A made-up tool, for the demonstration.',
    inputSchema: { type: 'object', properties: { text: { type: 'string', description: 'The text to hand back.' } }, required: ['text'], additionalProperties: false },
  },
  {
    name: 'add',
    description: 'Adds two whole numbers. A made-up tool, for the demonstration.',
    inputSchema: { type: 'object', properties: { a: { type: 'integer' }, b: { type: 'integer' } }, required: ['a', 'b'], additionalProperties: false },
  },
];

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function text(value, isError = false) {
  return { content: [{ type: 'text', text: value }], ...(isError ? { isError: true } : {}) };
}

function call(name, args) {
  if (name === 'echo') {
    if (typeof args?.text !== 'string') return text('echo needs "text", a text.', true);
    return text(args.text);
  }
  if (name === 'add') {
    if (!Number.isSafeInteger(args?.a) || !Number.isSafeInteger(args?.b)) return text('add needs "a" and "b", whole numbers.', true);
    return text(String(args.a + args.b));
  }
  return null;
}

createInterface({ input: process.stdin }).on('line', (line) => {
  let m;
  try {
    m = JSON.parse(line);
  } catch {
    send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (!m || typeof m !== 'object' || typeof m.method !== 'string' || !Object.hasOwn(m, 'id')) return; // a notification, or a response: nothing to answer
  const { id, method, params } = m;
  if (method === 'initialize') {
    const version = typeof params?.protocolVersion === 'string' ? params.protocolVersion : '2025-06-18';
    send({ jsonrpc: '2.0', id, result: { protocolVersion: version, capabilities: { tools: {} }, serverInfo: { name: 'provared-demo-server', version: '0.2.0' } } });
  } else if (method === 'ping') {
    send({ jsonrpc: '2.0', id, result: {} });
  } else if (method === 'tools/list') {
    send({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
  } else if (method === 'tools/call') {
    const result = call(params?.name, params?.arguments);
    if (result) send({ jsonrpc: '2.0', id, result });
    else send({ jsonrpc: '2.0', id, error: { code: -32602, message: `Unknown tool: ${String(params?.name)}` } });
  } else {
    send({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
  }
});
