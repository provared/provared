// The recipe agent-with-a-shell (F5 of the check against the MCP SDK's
// advisories of October 2026): its stand-in tool server checks the token
// before it reads a body, and reads no more than a limit. The server is run
// here as it is, on the local address, with a stand-in of the few pieces of
// the MCP SDK it uses (the recipe's own container installs the SDK itself),
// so nothing is downloaded. And the guard it installs is the current one,
// from a lockfile, with npm ci.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { tempFolder } from './world.mjs';

const RECIPE = join(dirname(fileURLToPath(import.meta.url)), '..', 'recipes', 'agent-with-a-shell');
const TOKEN = 'made-up-token-for-the-recipe-test';
const LIMIT = 4 * 1024 * 1024;

/** The few pieces of the SDK the stand-in server uses, made up: a transport that answers every request with its method. */
const STUB = {
  'package.json': JSON.stringify({ name: '@modelcontextprotocol/sdk', type: 'module', exports: { './server/mcp.js': './server/mcp.js', './server/streamableHttp.js': './server/streamableHttp.js', './types.js': './types.js' } }),
  'server/mcp.js': 'export class McpServer { registerTool() {} async connect(t) { this.t = t; } }\n',
  'server/streamableHttp.js': "export class StreamableHTTPServerTransport { constructor(o) { this.o = o; } async handleRequest(req, res, body) { this.o.onsessioninitialized?.('stub-session'); res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: body?.id ?? null, result: { method: body?.method ?? null } })); } }\n",
  'types.js': "export const isInitializeRequest = (b) => b?.method === 'initialize';\n",
};

/** The stand-in tool server, started from a copy of the recipe's file: {port, log(), stop()}. */
async function startToolServer() {
  const dir = tempFolder();
  const sdk = join(dir, 'node_modules', '@modelcontextprotocol', 'sdk');
  for (const [name, text] of Object.entries(STUB)) {
    mkdirSync(dirname(join(sdk, name)), { recursive: true });
    writeFileSync(join(sdk, name), text);
  }
  copyFileSync(join(RECIPE, 'tool-server.mjs'), join(dir, 'tool-server.mjs'));
  writeFileSync(join(dir, 'token'), `${TOKEN}\n`);
  const child = spawn(process.execPath, [join(dir, 'tool-server.mjs')], { cwd: dir, env: { ...process.env, TOKEN_FILE: join(dir, 'token'), HOST: '127.0.0.1', PORT: '0' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  child.stdout.on('data', (c) => {
    out += c;
  });
  child.stderr.on('data', (c) => {
    out += c;
  });
  const port = await new Promise((done, failed) => {
    const timer = setTimeout(() => failed(new Error(`the tool server did not start within 10 s: ${out}`)), 10000);
    const look = () => {
      const m = /tools-server listening (\d+)/.exec(out);
      if (m) {
        clearTimeout(timer);
        done(Number(m[1]));
      }
    };
    child.stdout.on('data', look);
    child.on('exit', () => failed(new Error(`the tool server ended: ${out}`)));
  });
  return { port, log: () => out, stop: () => child.kill() };
}

/** One request; "send" writes what it likes of the body. Gives {status} or fails after "within" ms (setTimeout keeps the monotonic clock). */
function ask(port, { headers, send, within = 3000 }) {
  return new Promise((done, failed) => {
    const req = http.request({ host: '127.0.0.1', port, path: '/mcp', method: 'POST', headers: { 'content-type': 'application/json', ...headers }, agent: false });
    const timer = setTimeout(() => {
      req.destroy();
      failed(new Error(`no answer within ${within} ms`));
    }, within);
    req.on('response', (res) => {
      res.resume();
      res.on('end', () => {
        clearTimeout(timer);
        done({ status: res.statusCode });
      });
    });
    req.on('error', (e) => {
      clearTimeout(timer);
      failed(e);
    });
    send(req);
  });
}

test('recipe agent-with-a-shell: the stand-in tool server checks the token before it reads a body, and reads no more than 4 MiB', async (t) => {
  const s = await startToolServer();
  t.after(() => s.stop());
  // No token, and a body declared at 8 MiB of which 1 KiB is sent: refused at once, the body unread.
  assert.equal((await ask(s.port, { headers: { 'content-length': 8 * 1024 * 1024 }, send: (req) => req.write('x'.repeat(1024)) })).status, 401);
  // The token, and a body declared past the limit: refused at once.
  assert.equal((await ask(s.port, { headers: { authorization: `Bearer ${TOKEN}`, 'content-length': LIMIT + 1 }, send: (req) => req.write('{') })).status, 413);
  // The token, and a body sent without a length that goes past the limit: refused once it does.
  assert.equal((await ask(s.port, { headers: { authorization: `Bearer ${TOKEN}`, 'transfer-encoding': 'chunked' }, send: (req) => req.end(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"x":"${'y'.repeat(LIMIT)}"}}`), within: 10000 })).status, 413);
  // The token, and a body at the limit or under it: served.
  const init = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  assert.equal((await ask(s.port, { headers: { authorization: `Bearer ${TOKEN}` }, send: (req) => req.end(init) })).status, 200);
  assert.match(s.log(), /^REQ POST \/mcp rpc=- tool=- auth=token-BAD/m, 'the refusal is logged, as before');
  assert.match(s.log(), /^REQ POST \/mcp rpc=initialize tool=- auth=token-ok/m);
});

test('recipe agent-with-a-shell: the guard is the one the claude.ai recipe builds, installed from a lockfile with npm ci; the SDK is pinned', () => {
  const read = (...p) => JSON.parse(readFileSync(join(...p), 'utf8'));
  // The claude.ai recipe's guard is kept to the published one by the release (tools/release/check-recipe-lock.mjs): this recipe follows it.
  const current = read(RECIPE, '..', 'claude-ai', 'compose', 'package-lock.json').packages;
  const guard = read(RECIPE, 'guard', 'package.json');
  const lock = read(RECIPE, 'guard', 'package-lock.json').packages;
  for (const name of ['provared-mcp-executor', 'provared']) {
    assert.equal(guard.dependencies[name], current[`node_modules/${name}`].version, name);
    assert.equal(lock[`node_modules/${name}`].version, current[`node_modules/${name}`].version, name);
    assert.equal(lock[`node_modules/${name}`].integrity, current[`node_modules/${name}`].integrity, `${name}: npm's hash`);
  }
  assert.equal(lock[''].dependencies['provared-mcp-executor'], guard.dependencies['provared-mcp-executor']);
  const version = guard.dependencies['provared-mcp-executor'];
  const run = readFileSync(join(RECIPE, 'run.sh'), 'utf8');
  assert.match(run, /npm ci --ignore-scripts/);
  assert.doesNotMatch(run, /npm install --ignore-scripts provared-mcp-executor@/, 'no longer installed by name and version, unchecked');
  assert.ok(run.includes(`provared-mcp-executor ${version}`), 'the step names the version');
  assert.ok(readFileSync(join(RECIPE, 'README.md'), 'utf8').includes(`\`provared-mcp-executor\` ${version}`), 'the README names it');
  assert.match(read(RECIPE, 'package.json').dependencies['@modelcontextprotocol/sdk'], /^\d+\.\d+\.\d+$/, 'one version of the SDK, exactly');
});
