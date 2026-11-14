// One message, one line (DESIGN.md, X248). A message the executor writes
// to a program's standard input is one line under every way of ending a
// line, and the demonstration's made-up server ends a line at a line feed
// alone. A tool server that reads with node:readline ends a line at a bare
// carriage return, U+2028 and U+2029 too, and an agent's HTTP body may hold
// line feeds between its values: without this, one message of the agent's
// reached such a program as several, and a piece of it was read as a
// message of its own. Nothing leaves this computer.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook } = await import('provared');
const { RESULT_DOCUMENT } = await import('../executor.mjs');
const { oneLine } = await import('../jsonrpc.mjs');
const { httpWorld, openHttpWorld, post } = await import('./http-world.mjs');
const { FAKE_SERVER, tempFolder, until, world } = await import('./world.mjs');

const DEMO_SERVER = fileURLToPath(new URL('../demo/server.mjs', import.meta.url));
const stubsOf = (checked) => checked.entries.filter((e) => e.kind === 'stub');
const docs = (stub) => Object.fromEntries(stub.content.details.map((d) => [d.name, d.sha256]));
const ODD = 'a\u2028b\u2029c\u0085d';
const HIDDEN = { jsonrpc: '2.0', id: 'hidden', method: 'tools/call', params: { name: 'order', arguments: { total: 999999 } } };
/** A ping that holds a whole tools/call between two line ends, where JSON allows them: between the values of a list. */
const carrier = (lineEnd) => `{"jsonrpc":"2.0","id":"outer","method":"ping","params":{"a":[${lineEnd}${JSON.stringify(HIDDEN)}${lineEnd}]}}`;

test('oneLine: the same JSON, with no line end of any kind in it', () => {
  for (const text of [carrier('\n'), carrier('\r'), carrier('\r\n'), JSON.stringify({ a: ODD, [ODD]: [ODD] }), '{"a":\t1 }', '{"a":"\\n\\r\\u2028"}']) {
    const line = oneLine(text);
    assert.ok(!/[\n\r\u0085\u2028\u2029]/.test(line), JSON.stringify(text));
    assert.deepEqual(JSON.parse(line), JSON.parse(text));
  }
  assert.equal(oneLine('{"a":"\u2028"}'), '{"a":"\\u2028"}');
  assert.equal(oneLine('{"a":1}'), '{"a":1}');
});

test('stdio, in front of a server that reads with node:readline: a text with U+2028, U+2029 or U+0085 is answered, and a call hidden between carriage returns is not run', async () => {
  const w = await world({ env: { FAKE_READLINE: { value: '1' } } });
  try {
    // The text reaches the tool whole, and comes back as it was sent.
    w.client.raw(`${JSON.stringify({ jsonrpc: '2.0', id: 'odd', method: 'tools/call', params: { name: 'echo', arguments: { text: ODD } } })}\n`);
    const echoed = await until(() => w.client.others.find((m) => m.id === 'odd'));
    assert.equal(echoed.result?.structuredContent.args.text, ODD, JSON.stringify(echoed));
    const [stub] = stubsOf(await checkBook(w.executor.writer.book(), { issuerKeys: w.settings.agent.issuerKeys }));
    assert.ok(docs(stub)[RESULT_DOCUMENT], 'the receipt names the result, not an outcome that is not known');
    // One ping to the executor; to a reader that ends a line at a carriage return, three lines, the second a call of "order".
    w.client.raw(`${carrier('\r')}\n`);
    const outer = await until(() => w.client.others.find((m) => m.id === 'outer'));
    assert.deepEqual(outer.result, {}, 'the ping is answered');
    const seen = w.fakeSeen();
    assert.deepEqual(seen.filter((e) => e.seen).map((e) => e.seen.method), ['tools/call', 'ping'], 'the server read one call and one ping');
    assert.equal(seen.filter((e) => e.notJson).length, 0, 'and no piece of a message');
    assert.equal(stubsOf(await checkBook(w.executor.writer.book(), { issuerKeys: w.settings.agent.issuerKeys })).length, 1);
  } finally {
    await w.close();
  }
});

for (const [reader, env] of [['at a line feed alone', {}], ['as node:readline does', { FAKE_READLINE: { value: '1' } }]]) test(`HTTP, in front of a local program that ends a line ${reader}: whatever white space the agent's body holds, each message reaches the program as one line, and a call hidden between line ends is not run`, async () => {
  const w = await httpWorld({ open: false });
  delete w.settings.upstream;
  w.fakeLog = join(w.folder, 'fake.log');
  w.settings.server = { command: process.execPath, args: [FAKE_SERVER], env: { FAKE_LOG: { value: w.fakeLog }, ...env } };
  w.settings.tools = { echo: { action: 'provared.data.read' } };
  await openHttpWorld(w, { serverStderr: null });
  const seen = () => (existsSync(w.fakeLog) ? readFileSync(w.fakeLog, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
  try {
    const begun = await post(w, 'alpha', { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } } });
    const headers = { 'mcp-session-id': begun.headers.get('mcp-session-id'), 'mcp-protocol-version': '2025-11-25' };
    // One ping to the executor; to any program that reads lines, three lines, the second a call of "order", which no rule names.
    const lineEnds = ['\n', '\r\n', '\r', '\n\n', ' \r \t \n '];
    for (const lineEnd of lineEnds) {
      const outer = await post(w, 'alpha', null, { headers, raw: `${lineEnd}${carrier(lineEnd)}${lineEnd}` });
      assert.equal(outer.status, 200, `${JSON.stringify(lineEnd)}: ${outer.body}`);
      assert.deepEqual(outer.json.result, {});
    }
    // A body set out over many lines, as a person or a tool may write it, with the three odd line ends in a text.
    for (const indent of [2, '\t', '\r']) {
      const call = await post(w, 'alpha', null, { headers, raw: JSON.stringify({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'echo', arguments: { text: ODD } } }, null, 2).replaceAll('\n  ', typeof indent === 'number' ? '\n  ' : `\r${indent}`) });
      assert.equal(call.status, 200, call.body);
      assert.equal(call.json.result?.structuredContent.args.text, ODD, 'the text reaches the tool whole');
    }
    assert.deepEqual(seen().filter((e) => e.seen).map((e) => e.seen.method), ['initialize', ...lineEnds.map(() => 'ping'), 'tools/call', 'tools/call', 'tools/call'], 'the program read each message once');
    assert.equal(seen().filter((e) => e.notJson).length, 0, 'and no piece of a message');
    assert.equal(stubsOf(await checkBook(w.executor.agent('alpha').writer.book(), { issuerKeys: w.settings.agents.alpha.issuerKeys })).length, 3);
  } finally {
    await w.close();
  }
});

test('the demonstration\'s made-up server ends a line at a line feed alone', async () => {
  const folder = tempFolder();
  writeFileSync(join(folder, 'demo-token'), 'made-up\n');
  const child = spawn(process.execPath, [DEMO_SERVER], { cwd: folder, env: { ...process.env, DEMO_TOKEN: 'made-up' }, stdio: ['pipe', 'pipe', 'inherit'], windowsHide: true });
  let out = '';
  child.stdout.setEncoding('utf8').on('data', (d) => {
    out += d;
  });
  const ended = new Promise((done) => child.on('exit', done));
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: { text: 'a\u2028b\u2029c' } } })}\n`);
  child.stdin.write(`${carrier('\r')}\r\n`);
  // The last line has no line feed.
  child.stdin.end(JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'ping' }));
  await ended;
  const answers = out.split('\n').filter(Boolean).map((l) => JSON.parse(l));
  assert.deepEqual(answers.map((a) => a.id), [1, 'outer', 3], 'three messages, three answers: no piece of a message was read as one');
  assert.equal(answers[0].result.content[0].text, 'a\u2028b\u2029c');
  assert.deepEqual(answers[1].result, {}, 'the ping, with a call inside its params, is a ping');
});
