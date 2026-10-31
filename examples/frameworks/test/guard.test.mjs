// Checks the guard of _offline.mjs itself: each way past it that an
// independent check of the examples found is refused, nothing reaches a
// listener on this computer, and the guard lets go when offline() returns,
// unless holdOffline() has been called. Every attempt is aimed at this
// computer, so nothing would leave it even if the guard failed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as dns from 'node:dns';
import * as net from 'node:net';
import * as http from 'node:http';
import * as http2 from 'node:http2';
import * as dgram from 'node:dgram';
import { ChildProcess, spawn } from 'node:child_process';
import { Worker } from 'node:worker_threads';
import { holdOffline, isOffline, offline, refused } from '../_offline.mjs';

const REFUSED = /sends nothing to the network/;

let hits = 0;
const server = net.createServer((socket) => { hits++; socket.destroy(); });
await new Promise((done) => server.listen(0, '127.0.0.1', done));
const { port } = server.address();
const at = `127.0.0.1:${port}`;

test('each way past the guard is refused, and nothing reaches the listener', async () => {
  refused.length = 0;
  await offline(async () => {
    await assert.rejects(() => fetch(`http://${at}/`), REFUSED);
    assert.throws(() => net.connect(port, '127.0.0.1'), REFUSED);
    assert.throws(() => new net.Socket().connect(port, '127.0.0.1'), REFUSED);
    assert.throws(() => http.get(`http://${at}/`), REFUSED);
    assert.throws(() => http2.connect(`http://${at}`), REFUSED);
    assert.throws(() => new WebSocket(`ws://${at}/`), REFUSED);
    assert.throws(() => dgram.createSocket('udp4').send('x', port, '127.0.0.1'), REFUSED);
    assert.throws(() => dns.lookup('localhost', () => {}), REFUSED);
    assert.throws(() => dns.lookupService('127.0.0.1', 22, () => {}), REFUSED);
    assert.throws(() => dns.resolveTxt('localhost', () => {}), REFUSED);
    assert.throws(() => dns.resolve4('localhost', () => {}), REFUSED);
    assert.throws(() => dns.reverse('127.0.0.1', () => {}), REFUSED);
    await assert.rejects(() => dns.promises.lookup('localhost'), REFUSED);
    await assert.rejects(() => dns.promises.resolveTxt('localhost'), REFUSED);
    assert.throws(() => new dns.Resolver().resolve4('localhost', () => {}), REFUSED);
    await assert.rejects(() => new dns.promises.Resolver().resolve4('localhost'), REFUSED);
    assert.throws(() => spawn(process.execPath, ['--version']), REFUSED);
    assert.throws(() => new ChildProcess().spawn({ file: process.execPath, args: [process.execPath, '--version'], stdio: 'ignore' }), REFUSED);
    if (typeof process.execve === 'function') assert.throws(() => process.execve(process.execPath, [process.execPath, '--version']), REFUSED);
    assert.throws(() => new Worker(`fetch('http://${at}/')`, { eval: true }), REFUSED);
    assert.throws(() => process.binding('tcp_wrap'), REFUSED);
  });
  await new Promise((done) => setTimeout(done, 300));
  assert.equal(hits, 0);
  assert.equal(refused.length, typeof process.execve === 'function' ? 21 : 20);
});

test('the guard lets go when offline() returns', () => {
  assert.equal(isOffline(), false);
  assert.notEqual(net.connect.name, 'refusing');
  assert.notEqual(globalThis.fetch.name, 'refusing');
});

test('held open, it refuses work scheduled during the run and carried out after it', async () => {
  refused.length = 0;
  let late;
  await offline(async () => {
    holdOffline();
    late = new Promise((done) => setTimeout(() => fetch(`http://${at}/late`).then(() => done('sent'), (e) => done(e.message)), 100));
  });
  assert.equal(isOffline(), true);
  assert.match(await late, REFUSED);
  assert.equal(hits, 0);
  assert.equal(refused.length, 1);
  server.close();
});
