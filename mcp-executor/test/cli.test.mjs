// The command: keys, check, compare, and stdio as a real process that an MCP
// client starts, speaking to it over its standard streams.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook } = await import('provared');
const { world, until } = await import('./world.mjs');

const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));

// Every process a test starts is ended when the test is over, whatever
// happened in it: a child left alive would keep this process alive too.
const children = new Set();
function start(args, cwd) {
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', BIN, ...args], { cwd, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  children.add(child);
  child.on('exit', () => children.delete(child));
  return child;
}
/** End a child: close its input, give it a moment to exit on its own, then end it. */
function end(child, wait = 3000) {
  return new Promise((done) => {
    if (child.exitCode !== null || child.signalCode !== null) return done(child.exitCode);
    const t = setTimeout(() => child.kill(), wait);
    child.on('exit', (code) => {
      clearTimeout(t);
      done(code);
    });
    try {
      child.stdin.end();
    } catch {
      child.kill();
    }
  });
}
process.on('exit', () => {
  for (const c of children) {
    try {
      c.kill();
    } catch {
      // Already gone.
    }
  }
});

function run(args, { input, cwd } = {}) {
  return new Promise((done) => {
    const child = start(args, cwd);
    const out = [];
    const err = [];
    child.stdout.on('data', (c) => out.push(c));
    child.stderr.on('data', (c) => err.push(c));
    child.on('exit', (code) => done({ code, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }));
    if (input !== undefined) child.stdin.end(input);
    else child.stdin.end();
  });
}

test('keys makes the key files once and prints what goes into the permission; check reports the slip, the rules and what is wrong', async () => {
  const w = await world({ open: false });
  // keys: the files exist already (the world made them), so they are kept and printed.
  const keys = await run(['keys', '--config', w.configPath]);
  assert.equal(keys.code, 0, keys.stderr);
  const printed = JSON.parse(keys.stdout);
  assert.deepEqual(printed.agent.keys, w.agentKeys);
  assert.deepEqual(printed.with.keys, w.executorKeys);
  assert.equal(printed.with.id, 'executor');
  assert.deepEqual(printed.requires, [{ need: 'countersignature' }]);
  const again = await run(['keys', '--config', w.configPath]);
  assert.deepEqual(JSON.parse(again.stdout), printed, 'a second run makes no new keys');
  // check
  const check = await run(['check', '--config', w.configPath]);
  assert.equal(check.code, 0, check.stderr);
  const report = JSON.parse(check.stdout);
  assert.deepEqual(report.problems, []);
  assert.match(report.slip.fingerprint, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(report.unfinished, 0);
  assert.equal(report.tools.find((t) => t.tool === 'order').amount.pointer, '/total');
  assert.deepEqual(report.credentials, ['FAKE_TOKEN', 'FAKE_LOG']);
  assert.ok(report.warnings.some((m) => m.startsWith('server.env.FAKE_LOG')), 'a value written in the settings is warned about');
  assert.ok(!check.stdout.includes('made-up-token'), 'no credential is printed');
  // check with problems
  writeFileSync(join(w.folder, 'bad.json'), JSON.stringify({ ...w.settings, tools: { 'bad name': { action: 'x' } }, timeout: 5 }));
  const bad = await run(['check', '--config', join(w.folder, 'bad.json')]);
  assert.equal(bad.code, 1);
  const badReport = JSON.parse(bad.stdout);
  assert.ok(badReport.problems.some((p) => p.startsWith('tools.bad name')));
  assert.ok(badReport.problems.some((p) => p.startsWith('timeout')));
  // a slip that does not require a countersignature: a warning
  const loose = await world({ open: false, slip: { requires: [] } });
  const looseCheck = JSON.parse((await run(['check', '--config', loose.configPath])).stdout);
  assert.ok(looseCheck.warnings.some((m) => m.includes('does not require a countersignature')));
  // no settings file
  const none = await run(['check']);
  assert.equal(none.code, 2);
  assert.match(none.stderr, /--config/);
  const help = await run([]);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /provared-mcp-executor stdio/);
});

test('stdio: started as the tool server, the executor speaks MCP on its own streams, writes nothing else to standard output, and ends when its input ends', async () => {
  const w = await world({ open: false });
  const child = start(['stdio', '--config', w.configPath]);
  const out = [];
  const err = [];
  child.stdout.on('data', (c) => out.push(c));
  child.stderr.on('data', (c) => err.push(c));
  const lines = () => Buffer.concat(out).toString('utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  let code;
  try {
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'server/discover', params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} } } })}\n`);
    await until(() => lines().some((m) => m.id === 1));
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { hello: 'world' } } })}\n`);
    await until(() => lines().some((m) => m.id === 2));
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'hidden' } })}\n`);
    await until(() => lines().some((m) => m.id === 3));
    const got = lines();
    assert.equal(got[0].result.supportedVersions[0], '2026-07-28');
    assert.equal(got[1].result.structuredContent?.token, 'made-up-token-for-the-tests');
    assert.equal(got[2].result.isError, true);
  } finally {
    code = await end(child);
  }
  assert.equal(code, 0, 'the server ended on its own when its input ended, and so did the executor');
  const stderr = Buffer.concat(err).toString('utf8');
  assert.match(stderr, /fake-server: started/, 'the server\'s standard error passes through');
  assert.match(stderr, /"event":"taken"/);
  assert.ok(!stderr.includes('made-up-token'));
  const checked = await checkBook(readFileSync(join(w.folder, 'book.jsonl'), 'utf8'), { issuerKeys: w.settings.agent.issuerKeys });
  assert.equal(checked.summary.intact, true);
  assert.equal(checked.summary.counts.stubs, 1);
  assert.equal(checked.summary.counts.denials, 1);
  assert.equal(checked.summary.counts.countersigned, 1);
  assert.ok(existsSync(join(w.folder, 'copy.jsonl')));
  // compare
  const compare = await run(['compare', '--config', w.configPath]);
  assert.equal(compare.code, 0, compare.stdout);
  const c = JSON.parse(compare.stdout);
  assert.equal(c.summary.agree, true);
  assert.equal(c.summary.matched, 1);
  assert.equal(c.refused.length, 1);
});
