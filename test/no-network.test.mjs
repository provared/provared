// The watch on the network while the library's tests run
// (helpers/no-network.mjs): it is loaded in every test file and in the
// programs the tests start, it stops a connection that library code (src/
// and bin/) opens, and it lets through what net/ and the tests' own helpers
// do. Nothing here reaches beyond this computer.

import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import dns from 'node:dns';
import http from 'node:http';
import net from 'node:net';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { libraryFileOf } from './helpers/no-network.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const watch = globalThis[Symbol.for('provared.test.no-network')];
const at = (...parts) => `    at f (${join(root, ...parts)}:1:2)`;

// Runs code as if it were written in a file of the repository, so that its
// frames name that file, without changing the file.
function runAs(file, code) {
  return vm.runInThisContext(code, { filename: join(root, file) });
}

// Runs a call that the watch must stop, then clears what it set, so that
// the stopped call does not fail this file.
async function stopped(call) {
  const before = watch.found.length;
  let error;
  watch.quiet = true;
  try {
    await call();
  } catch (caught) {
    error = caught;
  } finally {
    watch.quiet = false;
  }
  const found = watch.found.splice(before);
  if (process.exitCode === 1 && watch.found.length === 0) process.exitCode = undefined;
  assert.equal(error?.code, 'PROVARED_TEST_NETWORK', `not stopped: ${error?.message ?? 'no error'}`);
  assert.equal(found.length, 1);
  return found[0];
}

test('the watch is loaded in this test file, and in the programs the tests start', () => {
  assert.ok(watch, 'helpers/no-network.mjs is not loaded: "npm test" and the test workflow load it with --import');
  assert.deepEqual(watch.library, ['src/', 'bin/']);
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', 'console.log(typeof globalThis[Symbol.for("provared.test.no-network")])'], { encoding: 'utf8', timeout: 30_000 });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout.trim(), 'object');
});

test('a call is judged by the innermost frame in the repository', () => {
  const stack = (...lines) => ['Error', ...lines].join('\n');
  assert.equal(libraryFileOf(stack(at('src', 'check.js'))), join(root, 'src', 'check.js'));
  assert.equal(libraryFileOf(stack(at('bin', 'provared-check.mjs'))), join(root, 'bin', 'provared-check.mjs'));
  assert.equal(libraryFileOf(stack('    at connect (node:net:1:2)', at('src', 'check.js'))), join(root, 'src', 'check.js'));
  assert.equal(libraryFileOf(stack(at('net', 'timestamp.js'), at('src', 'sealer.js'))), null, 'net/ is left out by design');
  assert.equal(libraryFileOf(stack(at('test', 'helpers', 'tsa.mjs'), at('src', 'sealer.js'))), null, 'a test\'s own hook');
  assert.equal(libraryFileOf(stack(at('page', 'check-page.js'))), null, 'the pages load their own files');
  assert.equal(libraryFileOf(stack('    at connect (node:net:1:2)')), null);
  assert.equal(libraryFileOf(stack(`    at f (file://${root.startsWith('/') ? '' : '/'}${join(root, 'src', 'a.js').replace(/\\/g, '/')}:3:4)`)), join(root, 'src', 'a.js'));
});

test('a connection that library code opens is stopped, whatever it goes through', async () => {
  const server = net.createServer((socket) => socket.destroy());
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  globalThis.__noNetworkProbe = { net, http, dgram, dns, port };
  try {
    const calls = {
      'a socket\'s connect': 'p.net.connect(p.port, "127.0.0.1").on("error", () => {})',
      'http.request': 'p.http.request({ host: "127.0.0.1", port: p.port }).on("error", () => {}).end()',
      'http.get': 'p.http.get({ host: "127.0.0.1", port: p.port }).on("error", () => {})',
      'a UDP socket\'s send': '(() => { const s = p.dgram.createSocket("udp4"); try { s.send("x", p.port, "127.0.0.1"); } finally { s.close(); } })()',
      'dns.lookup': 'p.dns.lookup("localhost", () => {})',
      'dns/promises.lookup': 'p.dns.promises.lookup("localhost")',
      fetch: 'fetch(`http://127.0.0.1:${p.port}/`)',
    };
    for (const [what, code] of Object.entries(calls)) {
      const found = await stopped(() => runAs(join('src', 'probe-for-a-test.js'), `(() => { const p = globalThis.__noNetworkProbe; return ${code}; })()`));
      assert.deepEqual(found, { what, where: 'src/probe-for-a-test.js' });
    }
    if (typeof globalThis.WebSocket === 'function') {
      const found = await stopped(() => runAs(join('bin', 'probe-for-a-test.mjs'), `new WebSocket("ws://127.0.0.1:${port}/")`));
      assert.deepEqual(found, { what: 'WebSocket', where: 'bin/probe-for-a-test.mjs' });
    }
  } finally {
    delete globalThis.__noNetworkProbe;
    await new Promise((resolve) => server.close(resolve));
  }
});

test('a library error that is caught still fails the test file, through the exit code', async () => {
  const before = watch.found.length;
  globalThis.__noNetworkProbe = { net };
  watch.quiet = true;
  try {
    runAs(join('src', 'probe-for-a-test.js'), 'try { globalThis.__noNetworkProbe.net.connect(9, "127.0.0.1"); } catch {}');
    assert.equal(process.exitCode, 1);
    assert.equal(watch.found.length, before + 1);
  } finally {
    watch.quiet = false;
    delete globalThis.__noNetworkProbe;
    watch.found.splice(before);
    if (watch.found.length === 0) process.exitCode = undefined;
  }
});

test('the tests\' own helpers, and net/, still reach servers on this computer', async () => {
  const server = http.createServer((request, response) => response.end('ok'));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const { port } = server.address();
    const before = watch.found.length;
    const answer = await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(await answer.text(), 'ok');
    globalThis.__noNetworkProbe = { port };
    try {
      const fromNet = await runAs(join('net', 'probe-for-a-test.js'), 'fetch(`http://127.0.0.1:${globalThis.__noNetworkProbe.port}/`).then((r) => r.text())');
      assert.equal(fromNet, 'ok');
    } finally {
      delete globalThis.__noNetworkProbe;
    }
    assert.equal(watch.found.length, before);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
