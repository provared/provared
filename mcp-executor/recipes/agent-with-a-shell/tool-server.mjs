// tool-server.mjs: a STAND-IN tool server (not a real one) for the example. Runs in provared-example-tools-server. SDK tool server over HTTP requiring a bearer token (read from /secret/token). Logs one line per request to stdout.
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
const TOKEN = readFileSync('/secret/token', 'utf8').trim();
const sessions = new Map();
const make = () => {
  const mcp = new McpServer({ name: 'tools-server', version: '1.0.0' });
  mcp.registerTool('allowed_tool', { description: 'Returns some text' }, async () => { console.log('TOOL-RAN allowed_tool'); return { content: [{ type: 'text', text: 'hello from allowed_tool' }] }; });
  mcp.registerTool('other_tool', { description: 'Another tool' }, async () => { console.log('TOOL-RAN other_tool'); return { content: [{ type: 'text', text: 'hello from other_tool' }] }; });
  return mcp;
};
http.createServer(async (req, res) => {
  let raw = '';
  for await (const c of req) raw += c;
  let body; try { body = raw ? JSON.parse(raw) : undefined; } catch { body = undefined; }
  const digest = (v) => createHash('sha256').update(String(v ?? '')).digest();
  const granted = timingSafeEqual(digest(req.headers.authorization), digest(`Bearer ${TOKEN}`));
  console.log(`REQ ${req.method} ${req.url} rpc=${body?.method ?? '-'} tool=${body?.params?.name ?? '-'} auth=${granted ? 'token-ok' : 'token-BAD'} host=${req.headers.host}`);
  if (!granted) { res.writeHead(401).end('{}'); return; }
  const sid = req.headers['mcp-session-id'];
  let transport;
  if (sid && sessions.has(sid)) transport = sessions.get(sid);
  else if (!sid && req.method === 'POST' && isInitializeRequest(body)) {
    transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID(), onsessioninitialized: (id) => sessions.set(id, transport) });
    await make().connect(transport);
  } else { res.writeHead(400).end('{}'); return; }
  await transport.handleRequest(req, res, body);
}).listen(9000, '0.0.0.0', () => console.log('tools-server listening 9000'));
