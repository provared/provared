// Two fixes before the first publication: each case of a replaced
// connection gets its own true sentence (a line for another book where
// nothing was sent; a line for the same book at another address; a new
// key), naming no value from the line; and the stop signal goes only to a
// process that is this package's uploader, a stale pid file whose number
// another program now holds being removed instead.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createCryptoCore } from '@microtoll/crypto-core';
import { commandLineOf, connect, connectionFile, encodeLine, isUploaderCommandLine, readSaved, saveConnection, stopUploader } from 'provared-connect';
import { NAMESPACE } from '../entry.mjs';

const cc = createCryptoCore({ namespace: NAMESPACE });
const fresh = (more = {}) => ({
  server: 'ws://127.0.0.1:1/ws', origin: 'http://127.0.0.1:1', namespace: NAMESPACE, objectId: crypto.randomUUID(),
  kObject: cc.toBase64Url(cc.generateSymmetricKey()), appendCapabilitySecret: cc.toBase64Url(cc.randomBytes(32)), ...more,
});
const valuesOf = (c) => [c.kObject, c.appendCapabilitySecret, c.objectId, c.server, c.origin];
const namesNoValue = (text, ...cs) => cs.every((c) => valuesOf(c).every((v) => !text.includes(v)));

function recorderFolder() {
  const folder = mkdtempSync(join(tmpdir(), 'provared-connect-pub-'));
  const feedToken = join(folder, 'feed-token');
  writeFileSync(feedToken, `${'C'.repeat(43)}\n`);
  const base = join(folder, 'book.jsonl');
  return { folder, feedToken, base, file: connectionFile(folder), pidFile: `${base}.uploader.pid` };
}
function keep() {
  const out = [];
  return { out, log: (t) => out.push(t), error: (t) => out.push(t), text: () => out.join('\n') };
}
function standIns() {
  const s = { started: 0, stopped: 0 };
  s.start = async (said, pidFile) => { s.started++; writeFileSync(pidFile, String(process.pid)); return 0; };
  s.stop = async (pidFile) => { s.stopped++; const { unlinkSync } = await import('node:fs'); unlinkSync(pidFile); return true; };
  return s;
}
const feedArgs = (r) => ['--feed', 'http://127.0.0.1:1', '--feed-token', r.feedToken];

test('a line for another book, where nothing was sent: its own sentence, not "the book\'s new key"', async () => {
  const r = recorderFolder();
  const s = standIns();
  const c = fresh();
  saveConnection(r.file, c);
  const other = fresh();
  const k = keep();
  assert.equal(await connect([encodeLine(other), ...feedArgs(r)], { log: k, start: s.start, stop: s.stop }), 0);
  assert.equal(k.out.length, 1);
  assert.match(k.out[0], /^provared-connect: connected to another book of the application, in place of the one before \(nothing had been sent to that one from this recorder\): the connection is kept in .*, and the uploader is running in the background\.$/);
  assert.ok(!k.out[0].includes('new key'));
  assert.ok(namesNoValue(k.text(), c, other));
  assert.equal(readSaved(r.file).objectId, other.objectId);
  assert.equal(s.started, 1);
  // With an uploader running: "was restarted".
  const k2 = keep();
  const third = fresh();
  assert.equal(await connect([encodeLine(third), ...feedArgs(r)], { log: k2, start: s.start, stop: s.stop }), 0);
  assert.match(k2.out[0], /connected to another book .*and the uploader was restarted\.$/);
  assert.equal(s.stopped, 1);
});

test('a line for the same book at another address: its own sentence; a new key keeps its sentence', async () => {
  const r = recorderFolder();
  const s = standIns();
  const c = fresh();
  saveConnection(r.file, c);
  const moved = { ...c, server: 'wss://elsewhere.example/ws', origin: 'https://elsewhere.example' };
  const k = keep();
  assert.equal(await connect([encodeLine(moved), ...feedArgs(r)], { log: k, start: s.start, stop: s.stop }), 0);
  assert.equal(k.out.length, 1);
  assert.match(k.out[0], /^provared-connect: connected again, to the same book at another address: the connection is kept in .*, and the uploader is running in the background\.$/);
  assert.ok(!k.out[0].includes('new key'));
  assert.ok(namesNoValue(k.text(), c, moved) && !k.text().includes('elsewhere'));
  assert.equal(readSaved(r.file).server, moved.server);
  // The new key, with the uploader running from the step before.
  const rekeyed = { ...moved, kObject: cc.toBase64Url(cc.generateSymmetricKey()) };
  const k2 = keep();
  assert.equal(await connect([encodeLine(rekeyed), ...feedArgs(r)], { log: k2, start: s.start, stop: s.stop }), 0);
  assert.match(k2.out[0], /^provared-connect: connected again with the book's new key: the connection is kept in .*, and the uploader was restarted\.$/);
  assert.ok(namesNoValue(k2.text(), rekeyed));
  assert.equal(s.stopped, 1);
  assert.equal(s.started, 2);
});

test('the stop signal goes only to this package\'s uploader; a stale pid file is removed and said so; a process that cannot be looked at is left alone', async () => {
  // What counts as the uploader's command line, as Linux and Windows show it.
  assert.ok(isUploaderCommandLine('/usr/local/bin/node --disable-warning=ExperimentalWarning /work/app/node_modules/provared-connect/bin.mjs --connection /root/.provared/claude-code/provared-app-connection.json --feed http://127.0.0.1:8794 --feed-token /root/.provared/claude-code/feed-token'));
  assert.ok(isUploaderCommandLine('"C:\\Program Files\\nodejs\\node.exe" --disable-warning=ExperimentalWarning D:\\Users\\me\\connect\\bin.mjs --connection "C:\\Users\\me\\.provared\\claude-code\\provared-app-connection.json" --feed http://127.0.0.1:8794 --feed-token C:\\Users\\me\\.provared\\claude-code\\feed-token'));
  assert.ok(!isUploaderCommandLine('/usr/local/bin/node --test test/connect.test.mjs'));
  assert.ok(!isUploaderCommandLine('/usr/bin/python3 bin.mjs --connection x'));
  assert.ok(!isUploaderCommandLine('node /work/bin.mjs --help'));
  assert.ok(!isUploaderCommandLine('node /work/bin.mjs provared-connect:1:abc'));
  assert.ok(!isUploaderCommandLine(null));
  // This process is a node process, but not the uploader: the system's own reading says so.
  const mine = commandLineOf(process.pid);
  assert.ok(mine && /node/i.test(mine), mine);
  assert.ok(!isUploaderCommandLine(mine));
  assert.equal(commandLineOf(2 ** 22 + 7), null, 'a process that is not there');

  // A stale pid file: the number is this test process's (alive, another program). Nothing is signalled; the file goes.
  const r = recorderFolder();
  writeFileSync(r.pidFile, String(process.pid));
  const signalled = [];
  const kill = (pid, signal) => { signalled.push([pid, signal]); };
  const k = keep();
  assert.equal(await stopUploader(r.pidFile, { kill, log: k }), 'stale');
  assert.deepEqual(signalled, []);
  assert.ok(!existsSync(r.pidFile), 'the stale file is removed');
  assert.equal(k.out.length, 1);
  assert.match(k.out[0], new RegExp(`names process ${process.pid}, which is not this package's uploader .*the stale file is removed, and nothing was signalled\\.$`));
  // The uploader itself (its command line says so): signalled, and gone within the wait.
  writeFileSync(r.pidFile, String(process.pid));
  const uploaderLine = () => '/usr/local/bin/node /x/node_modules/provared-connect/bin.mjs --connection /x/provared-app-connection.json --feed http://127.0.0.1:8794 --feed-token /x/feed-token';
  const k2 = keep();
  const killAndGo = async (pid, signal) => { signalled.push([pid, signal]); const { unlinkSync } = await import('node:fs'); unlinkSync(r.pidFile); };
  assert.equal(await stopUploader(r.pidFile, { kill: (pid, signal) => { killAndGo(pid, signal); }, commandLine: uploaderLine, log: k2 }), true);
  assert.deepEqual(signalled, [[process.pid, 'SIGTERM']]);
  assert.deepEqual(k2.out, []);
  // A process that cannot be looked at: nothing signalled, the file kept, false.
  writeFileSync(r.pidFile, String(process.pid));
  const k3 = keep();
  assert.equal(await stopUploader(r.pidFile, { kill, commandLine: () => null, log: k3 }), false);
  assert.equal(signalled.length, 1);
  assert.ok(existsSync(r.pidFile));
  assert.match(k3.out[0], /could not be looked at, so it was not stopped/);
  // Through the flow: a new connection with a stale pid file connects, and says the file was stale.
  writeFileSync(r.pidFile, String(process.pid));
  const s = standIns();
  const k4 = keep();
  assert.equal(await connect([encodeLine(fresh()), ...feedArgs(r)], { log: k4, start: s.start }), 0);
  assert.equal(k4.out.length, 2);
  assert.match(k4.out[0], /stale file is removed/);
  assert.match(k4.out[1], /connected: .*and the uploader is running in the background\./, 'no uploader ran, so none was restarted');
  assert.ok(!k4.out[1].includes('restarted') && !k4.out[1].includes('stopped'));
  assert.equal(s.started, 1);
});
