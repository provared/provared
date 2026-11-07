// agent-client.mjs: runs in the agent container. SDK client; secret from env AGENT_SECRET. Reports the TLS version, lists and calls the two tools, and saves what it received to /tmp/received.txt
import tls from 'node:tls';
import { writeFileSync } from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
const URL_ = process.argv[2] ?? 'https://pv3-guard:8443/mcp';
const received = [];
const show = (l, v) => { const s = JSON.stringify(v); received.push(s); console.log(`[${l}]`, s); };
// check 1: report the negotiated TLS version with a separate handshake
await new Promise((done) => {
  const u = new globalThis.URL(URL_);
  const s = tls.connect({ host: u.hostname, port: Number(u.port), servername: u.hostname }, () => { console.log('[tls]', 'protocol=' + s.getProtocol(), 'cipher=' + s.getCipher().name, 'authorized=' + s.authorized); s.end(); done(); });
  s.on('error', (e) => { console.log('[tls] error', e.code || e.message); done(); });
});
const transport = new StreamableHTTPClientTransport(new globalThis.URL(URL_), { requestInit: { headers: { authorization: `Bearer ${process.env.AGENT_SECRET}` } } });
const client = new Client({ name: 'agent-client', version: '1.0.0' });
try {
  await client.connect(transport);
  show('connect', { negotiatedMcpProtocolVersion: transport.protocolVersion, server: client.getServerVersion() });
  show('tools/list', (await client.listTools()).tools.map((t) => t.name));
  for (const n of ['allowed_tool', 'other_tool']) {
    try { show('call ' + n, await client.callTool({ name: n, arguments: {} })); }
    catch (e) { show('call ' + n + ' FAIL', { message: String(e?.message ?? e), code: e?.code, data: e?.data }); }
  }
  try { await transport.terminateSession(); } catch {}
  await client.close();
} catch (e) {
  show('CONNECT-FAIL', { message: String(e?.message ?? e), cause: String(e?.cause?.code ?? e?.cause?.message ?? '') });
}
writeFileSync('/tmp/received.txt', received.join('\n'));
process.exit(0);
