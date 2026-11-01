// The demonstration (demo/): started as a real process, as a directory of
// MCP servers would start it, it sets itself up, answers initialize and
// tools/list, takes a call with a countersigned receipt, refuses one by its
// content rule with a denial, and on a second start uses what it made. It
// refuses a folder it did not make, starts again after its paths change,
// makes a new set-up beside one it cannot use, and two starts at once on an
// empty folder each get a set-up of their own.

import './local-library.mjs'; // first: "provared" is this repository's own library
import './local-executor.mjs'; // and "provared-mcp-executor" is this folder
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook } = await import('provared');
const { tempFolder } = await import('./world.mjs');

const START = fileURLToPath(new URL('../demo/start.mjs', import.meta.url));
const SERVER = fileURLToPath(new URL('../demo/server.mjs', import.meta.url));

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
    exited: exited.then((code) => {
      clearTimeout(killer);
      return code;
    }),
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

const mark = (folder) => JSON.parse(readFileSync(join(folder, 'provared-demo.json'), 'utf8'));
const setUps = (folder) => readdirSync(folder).filter((n) => n.startsWith('set-up-')).sort();

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

  const setUp = join(folder, mark(folder).current);
  assert.deepEqual(setUps(folder), [mark(folder).current]);
  const settings = JSON.parse(readFileSync(join(setUp, 'executor.json'), 'utf8'));
  const result = await checkBook(readFileSync(join(setUp, 'book.jsonl'), 'utf8'), { issuerKeys: settings.agent.issuerKeys });
  assert.equal(result.summary.intact, true);
  assert.equal(result.summary.fullyChecked, true);
  assert.equal(result.summary.withinSlips, true);
  assert.deepEqual(result.entries.map((e) => e.kind), ['slip', 'stub', 'stub', 'denial']);
  assert.ok(result.entries.filter((e) => e.kind === 'stub').every((e) => e.countersignature.state === 'valid'), 'both receipts are countersigned');
  const slip = JSON.parse(readFileSync(join(setUp, 'slip.json'), 'utf8'));
  assert.match(JSON.parse(Buffer.from(slip.payload, 'base64url').toString('utf8')).issuer.name, /\(development\)$/);

  // The paths in the settings are out of date, as after a move or a new
  // Node.js: the next start writes them afresh and uses the same set-up.
  writeFileSync(join(setUp, 'executor.json'), JSON.stringify({ ...settings, server: { ...settings.server, command: join(folder, 'old-node'), args: [join(folder, 'old', 'server.mjs')] }, contentRules: join(folder, 'old', 'content-rules.json') }));
  const again = demo(folder);
  const call = await again.ask('tools/call', { name: 'add', arguments: { a: 1, b: 1 } });
  assert.equal(call.result.content[0].text, '2');
  assert.equal(await again.end(), 0);
  assert.match(again.said(), /using the demonstration set up in/);
  assert.deepEqual(setUps(folder), [mark(folder).current], 'no new set-up');
  assert.equal(readFileSync(join(setUp, 'book.jsonl'), 'utf8').trim().split('\n').length, 5);

  // A permission that cannot be read: the set-up is left where it is, and a new one is made beside it.
  writeFileSync(join(setUp, 'slip.json'), 'not a permission');
  const third = demo(folder);
  assert.equal((await third.ask('tools/call', { name: 'add', arguments: { a: 2, b: 2 } })).result.content[0].text, '4');
  assert.equal(await third.end(), 0);
  assert.match(third.said(), /left where it is and not used: its permission cannot be read/);
  assert.equal(setUps(folder).length, 2);
  assert.ok(existsSync(join(setUp, 'book.jsonl')), 'the old set-up is kept');
  assert.notEqual(join(folder, mark(folder).current), setUp);
});

test('a folder the demonstration did not make is refused, and nothing in it is touched', async () => {
  const folder = tempFolder();
  writeFileSync(join(folder, 'notes.txt'), 'mine');
  const d = demo(folder);
  assert.equal(await d.exited, 2);
  assert.match(d.said(), /not empty and was not made by this demonstration/);
  assert.deepEqual(readdirSync(folder), ['notes.txt']);
});

test('an empty mark alone in the folder, left by a start stopped after making it, is written again and used', async () => {
  const folder = tempFolder();
  writeFileSync(join(folder, 'provared-demo.json'), '');
  const d = demo(folder);
  assert.equal((await d.ask('tools/call', { name: 'add', arguments: { a: 5, b: 6 } })).result.content[0].text, '11');
  assert.equal(await d.end(), 0);
  assert.deepEqual(setUps(folder), [mark(folder).current]);
});

test('a name that is a file, not a folder, is refused with words that say so', async () => {
  const file = join(tempFolder(), 'a-file');
  writeFileSync(file, 'mine');
  const d = demo(file);
  assert.equal(await d.exited, 2);
  assert.match(d.said(), /is a file, not a folder/);
  assert.equal(readFileSync(file, 'utf8'), 'mine');
});

test('two starts at once on an empty folder each make a set-up of their own and both answer', async () => {
  const folder = tempFolder();
  const a = demo(folder);
  const b = demo(folder);
  const [ra, rb] = await Promise.all([a.ask('tools/call', { name: 'add', arguments: { a: 1, b: 2 } }), b.ask('tools/call', { name: 'add', arguments: { a: 3, b: 4 } })]);
  assert.equal(ra.result.content[0].text, '3');
  assert.equal(rb.result.content[0].text, '7');
  assert.deepEqual(await Promise.all([a.end(), b.end()]), [0, 0]);
  assert.equal(setUps(folder).length, 2);
  assert.ok(setUps(folder).includes(mark(folder).current));
});

test('the made-up server will not start with a credential other than the one in its folder', () => {
  const folder = tempFolder();
  writeFileSync(join(folder, 'demo-token'), 'the-right-one\n');
  const wrong = spawnSync(process.execPath, [SERVER], { cwd: folder, input: '', env: { ...process.env, DEMO_TOKEN: 'another-one-!' }, encoding: 'utf8' });
  assert.equal(wrong.status, 1);
  assert.match(wrong.stderr, /not the credential in this folder/);
  const right = spawnSync(process.execPath, [SERVER], { cwd: folder, input: '{"jsonrpc":"2.0","id":1,"method":"ping"}\n', env: { ...process.env, DEMO_TOKEN: 'the-right-one' }, encoding: 'utf8' });
  assert.equal(right.status, 0);
  assert.equal(JSON.parse(right.stdout).id, 1);
});
