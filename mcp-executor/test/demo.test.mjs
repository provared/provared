// The demonstration (demo/): started as a real process, as a directory of
// MCP servers would start it, it sets itself up, answers initialize and
// tools/list, takes a call with a countersigned receipt, refuses one by its
// content rule with a denial, and on a second start uses what it made.

import './local-library.mjs'; // first: "provared" is this repository's own library
import './local-executor.mjs'; // and "provared-mcp-executor" is this folder
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook } = await import('provared');
const { tempFolder } = await import('./world.mjs');

const START = fileURLToPath(new URL('../demo/start.mjs', import.meta.url));

/** Start the demonstration in a folder; ask() sends a request and awaits its answer; end() closes its input and awaits its exit. */
function demo(folder) {
  const child = spawn(process.execPath, [START], { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, PROVARED_DEMO_DIR: folder }, windowsHide: true });
  let said = '';
  child.stderr.setEncoding('utf8').on('data', (d) => {
    said += d;
  });
  const waiting = new Map();
  createInterface({ input: child.stdout }).on('line', (line) => {
    const m = JSON.parse(line);
    waiting.get(m.id)?.(m);
    waiting.delete(m.id);
  });
  const exited = new Promise((done) => child.on('exit', done));
  const killer = setTimeout(() => child.kill(), 50000);
  let next = 0;
  return {
    said: () => said,
    ask(method, params = {}) {
      const id = ++next;
      return new Promise((done, fail) => {
        waiting.set(id, done);
        exited.then(() => fail(new Error(`The demonstration ended before answering ${method}:\n${said}`)));
        child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
      });
    },
    async end() {
      child.stdin.end();
      const code = await exited;
      clearTimeout(killer);
      return code;
    },
  };
}

test('the demonstration sets itself up, answers introspection, takes a call with a receipt and refuses one by its content rule', async () => {
  const folder = tempFolder();
  const d = demo(folder);
  const init = await d.ask('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
  assert.equal(init.result.serverInfo.name, 'provared-demo-server');
  const list = await d.ask('tools/list');
  assert.deepEqual(list.result.tools.map((t) => t.name), ['echo', 'add']);
  const echo = await d.ask('tools/call', { name: 'echo', arguments: { text: 'hello' } });
  assert.equal(echo.result.content[0].text, 'hello');
  const add = await d.ask('tools/call', { name: 'add', arguments: { a: 2, b: 3 } });
  assert.equal(add.result.content[0].text, '5');
  const refused = await d.ask('tools/call', { name: 'echo', arguments: { text: 'the password is here' } });
  assert.equal(refused.result.isError, true);
  assert.equal(refused.result._meta['red.prova/refused'], 'content-rule');
  assert.equal(await d.end(), 0);
  assert.match(d.said(), /set up in .*signed by a development stand-in for a passkey/);

  const settings = JSON.parse(readFileSync(`${folder}/executor.json`, 'utf8'));
  const result = await checkBook(readFileSync(`${folder}/book.jsonl`, 'utf8'), { issuerKeys: settings.agent.issuerKeys });
  assert.equal(result.summary.intact, true);
  assert.equal(result.summary.fullyChecked, true);
  assert.equal(result.summary.withinSlips, true);
  assert.deepEqual(result.entries.map((e) => e.kind), ['slip', 'stub', 'stub', 'denial']);
  assert.ok(result.entries.filter((e) => e.kind === 'stub').every((e) => e.countersignature.state === 'valid'), 'both receipts are countersigned');
  const slip = JSON.parse(readFileSync(`${folder}/slip.json`, 'utf8'));
  assert.match(JSON.parse(Buffer.from(slip.payload, 'base64url').toString('utf8')).issuer.name, /\(development\)$/);

  // A second start uses the same folder, keys and permission.
  const again = demo(folder);
  const call = await again.ask('tools/call', { name: 'add', arguments: { a: 1, b: 1 } });
  assert.equal(call.result.content[0].text, '2');
  assert.equal(await again.end(), 0);
  assert.match(again.said(), /using the demonstration set up in/);
  assert.equal(readFileSync(`${folder}/book.jsonl`, 'utf8').trim().split('\n').length, 5);
});
