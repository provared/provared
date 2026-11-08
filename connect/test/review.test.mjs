// What the first review of the package found, each with a test that failed
// before the fix: a connection file that is there but cannot be read is
// never taken for none (probe 4), and a running uploader is stopped
// whenever the connection on disk changes or was not there (probe 5); a
// refusal echoes no field name and no version from the line, whatever they
// hold; on Windows the file is restricted while still empty; --feed without
// --feed-token is refused; bin.mjs and connect.mjs read the bare words of a
// command line with one function; the uploader's own reader of the file
// agrees with the command's.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createCryptoCore } from '@microtoll/crypto-core';
import { FIELDS, bareWords, checkConnection, connect, connectionFile, decodeLine, encodeLine, readConnectArguments, readConnection, readSaved, saveConnection } from 'provared-connect';
import { NAMESPACE } from '../entry.mjs';

const cc = createCryptoCore({ namespace: NAMESPACE });
const fresh = (more = {}) => ({
  server: 'ws://127.0.0.1:1/ws', origin: 'http://127.0.0.1:1', namespace: NAMESPACE, objectId: crypto.randomUUID(),
  kObject: cc.toBase64Url(cc.generateSymmetricKey()), appendCapabilitySecret: cc.toBase64Url(cc.randomBytes(32)), ...more,
});
const withBody = (o) => `provared-connect:1:${Buffer.from(JSON.stringify({ version: 1, ...o })).toString('base64url')}`;

function recorderFolder() {
  const folder = mkdtempSync(join(tmpdir(), 'provared-connect-review-'));
  const feedToken = join(folder, 'feed-token');
  writeFileSync(feedToken, `${'C'.repeat(43)}\n`);
  const base = join(folder, 'book.jsonl');
  return { folder, feedToken, base, file: connectionFile(folder), pidFile: `${base}.uploader.pid`, stateFile: `${base}.uploaded.json` };
}
function keep() {
  const out = [];
  return { out, log: (t) => out.push(t), error: (t) => out.push(t), text: () => out.join('\n') };
}
/** Stand-ins: starting writes a pid file naming this process (so it "runs"); stopping notes the call and removes it. */
function standIns() {
  const s = { started: [], stopped: [] };
  s.start = async (said, pidFile) => { s.started.push(said); writeFileSync(pidFile, String(process.pid)); return 0; };
  s.stop = async (pidFile) => { s.stopped.push(pidFile); const { unlinkSync } = await import('node:fs'); unlinkSync(pidFile); return true; };
  return s;
}
const feedArgs = (r) => ['--feed', 'http://127.0.0.1:1', '--feed-token', r.feedToken];

test('probe 4: a connection file that is there but is not one this version reads is never taken for none: refused where the state is beside the book, replaced where it is not', async () => {
  const r = recorderFolder();
  const s = standIns();
  const c = fresh();
  // A file the old, looser reader would take (an extra field), the state of a book, and a live uploader.
  writeFileSync(r.file, JSON.stringify({ ...c, extra: 'kept by another version' }));
  writeFileSync(r.stateFile, '{"parts":[]}');
  writeFileSync(r.pidFile, String(process.pid));
  const before = readFileSync(r.file, 'utf8');
  const other = fresh();
  const k = keep();
  assert.equal(await connect([encodeLine(other), ...feedArgs(r)], { log: k, start: s.start, stop: s.stop }), 1);
  assert.equal(k.out.length, 1);
  assert.match(k.out[0], /is not one this version reads, and this recorder has sent its book to a book of the application already; to connect it to this one instead, stop the uploader and move .* away first/);
  assert.equal(readFileSync(r.file, 'utf8'), before, 'the file is untouched');
  assert.deepEqual(s.started, []);
  assert.deepEqual(s.stopped, []);
  assert.ok(existsSync(r.stateFile));
  // The same file where nothing was sent yet: replaced, and the live uploader stopped first.
  const r2 = recorderFolder();
  writeFileSync(r2.file, '{"not":"a connection"}');
  writeFileSync(r2.pidFile, String(process.pid));
  const k2 = keep();
  assert.equal(await connect([encodeLine(other), ...feedArgs(r2)], { log: k2, start: s.start, stop: s.stop }), 0);
  assert.match(k2.out[0], /connected: .*in place of a file that was not one this version reads, and the uploader was restarted\./);
  assert.deepEqual(s.stopped, [r2.pidFile]);
  assert.equal(s.started.length, 1);
  assert.equal(readSaved(r2.file).objectId, other.objectId);
});

test('probe 5: no connection file, but a live uploader and the state: the uploader is stopped and started again with the saved connection', async () => {
  const r = recorderFolder();
  const s = standIns();
  writeFileSync(r.stateFile, '{"parts":[]}');
  writeFileSync(r.pidFile, String(process.pid));
  const c = fresh();
  const k = keep();
  assert.equal(await connect([encodeLine(c), ...feedArgs(r)], { log: k, start: s.start, stop: s.stop }), 0);
  assert.match(k.out[0], /connected: .*the uploader that ran before was stopped and started again with it\./);
  assert.deepEqual(s.stopped, [r.pidFile]);
  assert.equal(s.started.length, 1);
  assert.equal(readSaved(r.file).objectId, c.objectId);
  // The uploader that does not stop: said, and nothing started.
  const r3 = recorderFolder();
  writeFileSync(r3.pidFile, String(process.pid));
  const k3 = keep();
  assert.equal(await connect([encodeLine(c), ...feedArgs(r3)], { log: k3, start: s.start, stop: async () => false }), 1);
  assert.match(k3.out[0], /the uploader that ran before did not stop \(process \d+\); stop it, then run this command again\./);
  assert.equal(s.started.length, 1);
});

test('the uploader reads the connection file as the command does: the same checks, so the two agree on what a connection is', () => {
  const r = recorderFolder();
  const c = fresh();
  saveConnection(r.file, c);
  assert.deepEqual(readConnection(r.file), readSaved(r.file));
  writeFileSync(r.file, JSON.stringify({ ...c, extra: 1 }));
  assert.throws(() => readConnection(r.file), /is not a connection: The connection has a field this version does not know\./);
  assert.throws(() => readSaved(r.file), { code: 'bad-connection' });
  writeFileSync(r.file, 'not json');
  assert.throws(() => readConnection(r.file), /could not be read/);
});

test('a refusal echoes no field name and no version from the line, whatever they hold: one line', () => {
  const c = fresh();
  const hostile = 'INJECTED\u001b[31mNAME\nSECOND LINE\r\u0007';
  const lines = [
    withBody({ ...c, [hostile]: 'x' }),
    `provared-connect:9999999999999999999999:${encodeLine(c).slice(19)}`,
    `provared-connect:2:${encodeLine(c).slice(19)}`,
  ];
  for (const text of lines) {
    let e = null;
    try { decodeLine(text); } catch (x) { e = x; }
    assert.ok(e);
    assert.equal(e.message.split('\n').length, 1, e.message);
    assert.ok(!/[\u0000-\u001f\u007f]/.test(e.message), 'no control character');
    assert.ok(!e.message.includes('INJECTED') && !e.message.includes('NAME') && !e.message.includes('SECOND'));
    assert.ok(!/\d{2,}/.test(e.message.replace(/provared-connect@latest|8794/g, '')), `no number from the line: ${e.message}`);
    assert.match(e.message, /^[A-Z][^\n]*\.$/);
  }
  // The same through checkConnection, as a file is read.
  assert.throws(() => checkConnection({ ...c, [hostile]: 'x' }), (e) => !e.message.includes('INJECTED') && e.message.split('\n').length === 1);
});

test('the checks: a version other than 1 in a file is refused; a server with a user name or a password is refused', () => {
  const c = fresh();
  assert.deepEqual(Object.keys(checkConnection({ version: 1, ...c })), ['about', 'version', ...FIELDS]);
  assert.throws(() => checkConnection({ version: 'zzz', ...c }), { code: 'bad-connection', message: /version this package does not know/ });
  assert.throws(() => checkConnection({ version: 2, ...c }), { code: 'bad-connection' });
  assert.throws(() => checkConnection({ ...c, server: 'wss://user:pw@app.example/ws' }), { code: 'bad-connection', message: /user name or a password/ });
  assert.throws(() => checkConnection({ ...c, server: 'wss://user@app.example/ws' }), { code: 'bad-connection', message: /user name or a password/ });
  let e = null;
  try { decodeLine(withBody({ ...c, server: 'wss://user:pw@app.example/ws' })); } catch (x) { e = x; }
  assert.ok(e && !e.message.includes('user:pw') && !e.message.includes('app.example'), e && e.message);
});

test('--feed without --feed-token is refused by the command, as the uploader refuses it; the bare words are read by one function', async () => {
  const r = recorderFolder();
  const c = fresh();
  assert.match(readConnectArguments([encodeLine(c), '--feed', 'http://127.0.0.1:9000']).error, /both --feed <address> and --feed-token <file>/);
  assert.match(readConnectArguments([encodeLine(c), '--feed-token', r.feedToken]).error, /both --feed/);
  assert.match(readConnectArguments([encodeLine(c), '--feed']).error, /both --feed/);
  const s = standIns();
  const k = keep();
  assert.equal(await connect([encodeLine(c), '--feed', 'http://127.0.0.1:9000'], { log: k, start: s.start, stop: s.stop }), 2);
  assert.match(k.out[0], /give both --feed/);
  assert.ok(!existsSync(r.file));
  assert.deepEqual(s.started, []);
  // bareWords: an option's value is not a word, nor is a value that starts with "--" (which is no value at all).
  assert.deepEqual(bareWords(['x', '--feed', 'http://f', '--feed-token', 't', '--once']), ['x']);
  assert.deepEqual(bareWords(['--connection', 'c.json', '--book', 'b']), []);
  assert.deepEqual(bareWords(['--feed', '--feed-token', 't', 'x']), ['x']);
  assert.deepEqual(bareWords(['a', 'b']), ['a', 'b']);
  // bin.mjs takes the bare words from the same function: the text says so.
  const bin = readFileSync(new URL('../bin.mjs', import.meta.url), 'utf8');
  assert.match(bin, /import \{ bareWords, connect \} from '\.\/connect\.mjs'/);
  assert.match(bin, /const bare = bareWords\(argv\);/);
  assert.ok(!bin.includes('argv.filter('));
});

test('on Windows (or as if there) the file is restricted while still empty, and written only then', () => {
  const r = recorderFolder();
  const c = fresh();
  const seen = [];
  const saved = saveConnection(r.file, c, { platform: 'win32', restrict: (file) => { seen.push({ file, size: statSync(file).size }); return true; } });
  assert.equal(saved.restricted, true);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].size, 0, 'nothing is in the file when its access list is set');
  assert.notEqual(seen[0].file, r.file);
  assert.equal(readSaved(r.file).objectId, c.objectId);
  assert.ok(readFileSync(r.file, 'utf8').endsWith('}\n'));
});
