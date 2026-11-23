// tool-server.mjs: a STAND-IN tool server (not a real one) for the example. Runs in provared-example-tools-server. SDK tool server over HTTP requiring a bearer token (read from /secret/token). Logs one line per request to stdout.
// TOKEN_FILE, HOST and PORT, for the recipe's own test only, name another token file and address; the example sets none of them.
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
const TOKEN = readFileSync(process.env.TOKEN_FILE ?? '/secret/token', 'utf8').trim();
const sessions = new Map();
const make = () => {
  const mcp = new McpServer({ name: 'tools-server', version: '1.0.0' });
  mcp.registerTool('allowed_tool', { description: 'Returns some text' }, async () => { console.log('TOOL-RAN allowed_tool'); return { content: [{ type: 'text', text: 'hello from allowed_tool' }] }; });
  mcp.registerTool('other_tool', { description: 'Another tool' }, async () => { console.log('TOOL-RAN other_tool'); return { content: [{ type: 'text', text: 'hello from other_tool' }] }; });
  return mcp;
};
// The most a body may be: 4 MiB, the SDK's own limit. The token is checked first, so that nobody without it has a body read at all.
const LIMIT = 4 * 1024 * 1024;
const readBody = (req) => new Promise((done) => {
  const chunks = [];
  let size = 0;
  req.on('data', (c) => {
    size += c.length;
    if (size > LIMIT) { req.removeAllListeners('data'); req.resume(); done(null); return; }
    chunks.push(c);
  });
  req.on('end', () => done(Buffer.concat(chunks).toString('utf8')));
  req.on('error', () => done(undefined));
});
const server = http.createServer(async (req, res) => {
  const digest = (v) => createHash('sha256').update(String(v ?? '')).digest();
  const granted = timingSafeEqual(digest(req.headers.authorization), digest(`Bearer ${TOKEN}`));
  if (!granted) { console.log(`REQ ${req.method} ${req.url} rpc=- tool=- auth=token-BAD host=${req.headers.host}`); res.writeHead(401, { connection: 'close' }).end('{}'); return; }
  if (Number(req.headers['content-length']) > LIMIT) { console.log(`REQ ${req.method} ${req.url} rpc=- tool=- auth=token-ok host=${req.headers.host} too-large`); res.writeHead(413, { connection: 'close' }).end('{}'); return; }
  const raw = await readBody(req);
  if (raw === undefined) return; // the connection failed: no one to answer
  if (raw === null) { console.log(`REQ ${req.method} ${req.url} rpc=- tool=- auth=token-ok host=${req.headers.host} too-large`); res.writeHead(413, { connection: 'close' }).end('{}'); return; }
  let body; try { body = raw ? JSON.parse(raw) : undefined; } catch { body = undefined; }
  console.log(`REQ ${req.method} ${req.url} rpc=${body?.method ?? '-'} tool=${body?.params?.name ?? '-'} auth=token-ok host=${req.headers.host}`);
  const sid = req.headers['mcp-session-id'];
  let transport;
  if (sid && sessions.has(sid)) transport = sessions.get(sid);
  else if (!sid && req.method === 'POST' && isInitializeRequest(body)) {
    transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID(), onsessioninitialized: (id) => sessions.set(id, transport) });
    await make().connect(transport);
  } else { res.writeHead(400).end('{}'); return; }
  await transport.handleRequest(req, res, body);
});
server.listen(Number(process.env.PORT ?? 9000), process.env.HOST ?? '0.0.0.0', () => console.log(`tools-server listening ${server.address().port}`));
