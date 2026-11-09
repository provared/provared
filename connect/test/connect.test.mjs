// The connection by one line (connect.mjs, store.mjs, bin.mjs): the line is
// checked, the connection saved where only its owner can read it, beside the
// recorder, and the uploader started in the background with the file's
// name, never the secret. The same line again changes nothing; a line from
// a new key of the same book replaces the connection and restarts the
// uploader; a line for another book, where lines of a book were sent, is
// refused with what to do. Through the package's interface, and through
// the command as a program.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCryptoCore } from '@microtoll/crypto-core';
import { CONNECTION_FILE, connectionFile, decodeLine, encodeLine, readSaved, saveConnection } from 'provared-connect';
import { connect, readConnectArguments, stopUploader } from 'provared-connect';
import { NAMESPACE } from '../entry.mjs';

const cc = createCryptoCore({ namespace: NAMESPACE });
const bin = fileURLToPath(new URL('../bin.mjs', import.meta.url));
const fresh = (more = {}) => ({
  server: 'ws://127.0.0.1:1/ws', origin: 'http://127.0.0.1:1', namespace: NAMESPACE, objectId: crypto.randomUUID(),
  kObject: cc.toBase64Url(cc.generateSymmetricKey()), appendCapabilitySecret: cc.toBase64Url(cc.randomBytes(32)), ...more,
});
const secretsOf = (c) => [c.kObject, c.appendCapabilitySecret];
const holdsNoSecret = (text, c) => secretsOf(c).every((s) => !text.includes(s));

/** A recorder's folder, with its token. */
function recorderFolder() {
  const folder = mkdtempSync(join(tmpdir(), 'provared-connect-'));
  const feedToken = join(folder, 'feed-token');
  writeFileSync(feedToken, `${'C'.repeat(43)}\n`);
  return { folder, feedToken, base: join(folder, 'book.jsonl'), file: connectionFile(folder) };
}

/** A log that keeps what was said. */
function keep() {
  const out = [];
  return { out, log: (t) => out.push(t), error: (t) => out.push(t), text: () => out.join('\n') };
}

/** A stand-in for starting the uploader: notes what it is asked, and pretends a process number. */
function starter(r) {
  const s = { calls: [], code: 0 };
  s.start = async (said, pidFile) => {
    s.calls.push({ said, pidFile });
    if (s.code === 0) writeFileSync(pidFile, String(process.pid));
    return s.code;
  };
  s.running = () => existsSync(`${r.base}.uploader.pid`);
  return s;
}

test('the arguments: a line, and the recorder beside Claude Code unless another is named', () => {
  const a = readConnectArguments(['provared-connect:1:abc']);
  assert.equal(a.line, 'provared-connect:1:abc');
  assert.equal(a.feedAddress, 'http://127.0.0.1:8794');
  assert.match(a.feedToken, /feed-token$/);
  assert.equal(a.base, join(a.folder, 'book.jsonl'));
  const b = readConnectArguments(['--feed', 'http://127.0.0.1:9000', 'provared-connect:1:abc', '--feed-token', '/r/feed-token']);
  assert.equal(b.line, 'provared-connect:1:abc');
  assert.equal(b.feedAddress, 'http://127.0.0.1:9000');
  assert.equal(b.folder, '/r');
  const c = readConnectArguments(['provared-connect:1:abc', '--book', '/r/book.jsonl']);
  assert.equal(c.book, '/r/book.jsonl');
  assert.equal(c.folder, '/r');
  assert.equal(c.feedToken, undefined);
  assert.match(readConnectArguments(['x', '--book', 'b', '--feed', 'f']).error, /not both/);
  assert.match(readConnectArguments(['provared-connect:1:ab', 'c']).error, /one line only/);
});

test('a bad line: one sentence, no value from the line, nothing saved, nothing started', async () => {
  const r = recorderFolder();
  const s = starter(r);
  const c = fresh();
  for (const bad of ['hello', encodeLine(c).slice(0, -3), `provared-connect:2:${encodeLine(c).slice(19)}`]) {
    const k = keep();
    assert.equal(await connect([bad, '--feed', 'http://127.0.0.1:1', '--feed-token', r.feedToken], { log: k, start: s.start }), 1);
    assert.equal(k.out.length, 1);
    assert.match(k.out[0], /^provared-connect: [A-Z].*\.$/);
    assert.ok(holdsNoSecret(k.text(), c) && !k.text().includes(encodeLine(c).slice(19, 40)));
  }
  assert.ok(!existsSync(r.file));
  assert.equal(s.calls.length, 0);
});

test('no token where the recorder should be: one sentence saying to start the recorder or name the token', async () => {
  const r = recorderFolder();
  const s = starter(r);
  const k = keep();
  assert.equal(await connect([encodeLine(fresh()), '--feed', 'http://127.0.0.1:1', '--feed-token', join(r.folder, 'elsewhere', 'feed-token')], { log: k, start: s.start }), 1);
  assert.equal(k.out.length, 1);
  assert.match(k.out[0], /no recorder's feed token at .*start the recorder once.*--feed-token/);
  assert.ok(!existsSync(join(r.folder, 'elsewhere', CONNECTION_FILE)));
  assert.equal(s.calls.length, 0);
  // --book names a file that is not there.
  const k2 = keep();
  assert.equal(await connect([encodeLine(fresh()), '--book', join(r.folder, 'none.jsonl')], { log: k2, start: s.start }), 1);
  assert.match(k2.out[0], /no book file at/);
});

test('a good line: the connection is saved beside the token, the uploader started with the file\'s name, and the same line again changes nothing', async () => {
  const r = recorderFolder();
  const s = starter(r);
  const c = fresh();
  const line = encodeLine(c);
  const k = keep();
  assert.equal(await connect([line, '--feed', 'http://127.0.0.1:1', '--feed-token', r.feedToken], { log: k, start: s.start }), 0);
  assert.equal(k.out.length, 1);
  assert.match(k.out[0], /^provared-connect: connected: the connection is kept in .*uploader is running in the background\.$/);
  assert.ok(holdsNoSecret(k.text(), c));
  // Saved as the connection file the uploader has always read, with "about".
  const saved = JSON.parse(readFileSync(r.file, 'utf8'));
  assert.equal(saved.version, 1);
  assert.match(saved.about, /never share it/);
  for (const key of ['server', 'origin', 'namespace', 'objectId', 'kObject', 'appendCapabilitySecret']) assert.equal(saved[key], c[key]);
  assert.deepEqual(readSaved(r.file), decodeLine(line));
  if (process.platform !== 'win32') assert.equal(statSync(r.file).mode & 0o777, 0o600);
  // Started with the file's name and the feed, never the line or its values.
  assert.equal(s.calls.length, 1);
  const { said, pidFile } = s.calls[0];
  assert.equal(said.connection, r.file);
  assert.equal(said.feedAddress, 'http://127.0.0.1:1');
  assert.equal(said.feedToken, r.feedToken);
  assert.equal(said.base, r.base);
  assert.equal(pidFile, `${r.base}.uploader.pid`);
  assert.ok(holdsNoSecret(JSON.stringify(said), c));
  // The same line again, with the uploader running: nothing changed, nothing started.
  const before = readFileSync(r.file, 'utf8');
  const k2 = keep();
  assert.equal(await connect([line, '--feed', 'http://127.0.0.1:1', '--feed-token', r.feedToken], { log: k2, start: s.start }), 0);
  assert.match(k2.out[0], /already connected: the uploader is running \(process \d+\); nothing changed\./);
  assert.equal(readFileSync(r.file, 'utf8'), before);
  assert.equal(s.calls.length, 1);
  // The same line, with the uploader not running: it is started, the file untouched.
  unlinkSync(`${r.base}.uploader.pid`);
  const k3 = keep();
  assert.equal(await connect([line, '--feed', 'http://127.0.0.1:1', '--feed-token', r.feedToken], { log: k3, start: s.start }), 0);
  assert.match(k3.out[0], /already connected; the uploader was not running, and is started now/);
  assert.equal(readFileSync(r.file, 'utf8'), before);
  assert.equal(s.calls.length, 2);
});

test('a line from a new key of the same book replaces the connection and restarts the uploader; a line for another book is refused once lines were sent', async () => {
  const r = recorderFolder();
  const s = starter(r);
  const c = fresh();
  assert.equal(await connect([encodeLine(c), '--feed', 'http://127.0.0.1:1', '--feed-token', r.feedToken], { log: keep(), start: s.start }), 0);
  writeFileSync(`${r.base}.uploaded.json`, '{"parts":[]}');
  // The uploader "runs" (the pid file names this process); the stand-in for stopping it notes the call and removes the pid file.
  const stopped = [];
  const stop = async (pidFile) => { stopped.push(pidFile); unlinkSync(pidFile); return true; };
  const rekeyed = { ...c, kObject: cc.toBase64Url(cc.generateSymmetricKey()) };
  const k = keep();
  assert.equal(await connect([encodeLine(rekeyed), '--feed', 'http://127.0.0.1:1', '--feed-token', r.feedToken], { log: k, start: s.start, stop }), 0);
  assert.match(k.out[0], /connected again with the book's new key: .*the uploader was restarted\./);
  assert.ok(holdsNoSecret(k.text(), rekeyed));
  assert.deepEqual(stopped, [`${r.base}.uploader.pid`]);
  assert.equal(s.calls.length, 2);
  assert.equal(readSaved(r.file).kObject, rekeyed.kObject);
  assert.ok(existsSync(`${r.base}.uploaded.json`), 'the uploader\'s state stays: it goes on from where it was');
  // The uploader that does not stop: said, and the new connection stays saved.
  const another = { ...c, kObject: cc.toBase64Url(cc.generateSymmetricKey()) };
  const k2 = keep();
  assert.equal(await connect([encodeLine(another), '--feed', 'http://127.0.0.1:1', '--feed-token', r.feedToken], { log: k2, start: s.start, stop: async () => false }), 1);
  assert.match(k2.out[0], /did not stop \(process \d+\); stop it, then run this command again\./);
  assert.equal(readSaved(r.file).kObject, another.kObject);
  assert.equal(s.calls.length, 2);
  // Another book, where this recorder has sent lines (the state is beside the book): refused, with what to do.
  const other = fresh();
  const k3 = keep();
  assert.equal(await connect([encodeLine(other), '--feed', 'http://127.0.0.1:1', '--feed-token', r.feedToken], { log: k3, start: s.start, stop }), 1);
  assert.match(k3.out[0], new RegExp(`another book of the application \\(${c.objectId}\\); to connect it to this one instead, stop the uploader and move .* away first`));
  assert.ok(holdsNoSecret(k3.text(), other));
  assert.equal(readSaved(r.file).objectId, c.objectId);
  assert.equal(s.calls.length, 2);
  // Another book, where nothing was sent yet: replaced.
  const r2 = recorderFolder();
  const s2 = starter(r2);
  assert.equal(await connect([encodeLine(c), '--feed', 'http://127.0.0.1:1', '--feed-token', r2.feedToken], { log: keep(), start: s2.start }), 0);
  const k4 = keep();
  assert.equal(await connect([encodeLine(other), '--feed', 'http://127.0.0.1:1', '--feed-token', r2.feedToken], { log: k4, start: s2.start, stop }), 0);
  assert.match(k4.out[0], /connected to another book of the application, in place of the one before/);
  assert.equal(readSaved(r2.file).objectId, other.objectId);
  // The uploader that does not start: the file is saved, and the log named.
  const r3 = recorderFolder();
  const s3 = starter(r3);
  s3.code = 1;
  const k5 = keep();
  assert.equal(await connect([encodeLine(c), '--feed', 'http://127.0.0.1:1', '--feed-token', r3.feedToken], { log: k5, start: s3.start }), 1);
  assert.match(k5.out[0], /saved in .*, but the uploader did not start; see .*uploader\.log\./);
  assert.ok(existsSync(r3.file));
});

test('--book: the connection is kept beside the book file, for a recorder with no feed', async () => {
  const r = recorderFolder();
  writeFileSync(r.base, '{"a":0}\n');
  const s = starter(r);
  const c = fresh();
  const k = keep();
  assert.equal(await connect([encodeLine(c), '--book', r.base], { log: k, start: s.start }), 0);
  assert.equal(s.calls[0].said.book, r.base);
  assert.equal(s.calls[0].said.feedAddress, undefined);
  assert.equal(s.calls[0].said.connection, r.file);
  assert.equal(readSaved(r.file).objectId, c.objectId);
});

test('saving: whole or not at all, for its owner only; on Windows the access list is set with icacls, and a failure of that is said', () => {
  const r = recorderFolder();
  const c = fresh();
  // On Windows (or as if on Windows): icacls is asked to replace the access list with the person alone.
  const asked = [];
  const run = (program, args) => { asked.push([program, ...args]); };
  const saved = saveConnection(r.file, c, { platform: 'win32', restrict: (file) => { run('icacls', [file, '/inheritance:r', '/grant:r', 'me:F']); return true; } });
  assert.equal(saved.restricted, true);
  assert.equal(asked.length, 1);
  assert.equal(asked[0][0], 'icacls');
  assert.deepEqual(asked[0].slice(2), ['/inheritance:r', '/grant:r', 'me:F']);
  assert.ok(asked[0][1].startsWith(r.file), 'the file written beside its final name is restricted before it is put in place');
  assert.notEqual(asked[0][1], r.file);
  assert.equal(readSaved(r.file).objectId, c.objectId);
  // Where icacls cannot run, the file is still saved, and the reason given back.
  const saved2 = saveConnection(r.file, c, { platform: 'win32', restrict: () => 'the file\'s access list could not be set with icacls (ENOENT); the file is as readable as its folder' });
  assert.match(saved2.restricted, /could not be set with icacls/);
  // The real restriction on Windows, through the system's own tool.
  if (process.platform === 'win32') {
    const real = saveConnection(r.file, c);
    assert.equal(real.restricted, true, String(real.restricted));
    const acl = execFileSync('icacls', [r.file], { encoding: 'utf8' });
    const names = acl.split('\n').filter((l) => l.includes(':(')).map((l) => l.trim());
    assert.equal(names.length, 1, acl);
    assert.match(names[0], /:\(F\)$/);
  } else {
    const real = saveConnection(r.file, c);
    assert.equal(real.restricted, true);
    assert.equal(statSync(r.file).mode & 0o777, 0o600);
  }
  // Nothing half-written is left beside it.
  assert.deepEqual(readdirSync(r.folder).filter((n) => n.startsWith(CONNECTION_FILE)), [CONNECTION_FILE]);
  // A connection that is not one is not saved.
  assert.throws(() => saveConnection(r.file, { ...c, objectId: 'x' }), { code: 'bad-connection' });
});

test('the command as a program: --help, a bad line (one sentence, no value from it), and a line that starts the uploader with the file\'s name only', async (t) => {
  const run = (args, env = {}) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', bin, ...args], { encoding: 'utf8', env: { ...process.env, ...env }, timeout: 30000 });
  const help = run(['--help']);
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /usage: npx provared-connect <line>/);
  assert.match(run([]).stdout, /usage:/);
  assert.equal(run([]).status, 2);
  const r = recorderFolder();
  const c = fresh();
  const line = encodeLine(c);
  const bad = run([line.slice(0, -2), '--feed', 'http://127.0.0.1:1', '--feed-token', r.feedToken]);
  assert.equal(bad.status, 1);
  assert.equal(bad.stdout, '');
  assert.equal(bad.stderr.trim().split('\n').length, 1);
  assert.match(bad.stderr, /copy the whole line/);
  assert.ok(holdsNoSecret(bad.stderr, c) && !bad.stderr.includes(line.slice(19, 40)));
  assert.ok(!existsSync(r.file));
  // A real connection: the uploader is started in the background, with the file's name; the server is not there, so it waits to try again.
  const good = run([line, '--feed', 'http://127.0.0.1:1', '--feed-token', r.feedToken]);
  const pidFile = `${r.base}.uploader.pid`;
  let pid = null;
  t.after(() => { if (pid) { try { process.kill(pid); } catch { /* gone */ } } });
  assert.equal(good.status, 0, good.stderr);
  assert.match(good.stdout, /connected: the connection is kept in .*uploader is running in the background/);
  assert.ok(holdsNoSecret(good.stdout + good.stderr, c));
  assert.ok(existsSync(pidFile), 'the uploader runs');
  pid = Number(readFileSync(pidFile, 'utf8').trim());
  assert.ok(pid > 0 && pid !== process.pid);
  // The long-running program's command line names the file, not the secret.
  const commandLine = process.platform === 'win32'
    ? execFileSync('powershell', ['-NoProfile', '-Command', `(Get-CimInstance Win32_Process -Filter "ProcessId=${pid}").CommandLine`], { encoding: 'utf8' })
    : readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').join(' ');
  assert.match(commandLine, /--connection/, commandLine);
  assert.ok(commandLine.includes(CONNECTION_FILE));
  assert.ok(holdsNoSecret(commandLine, c) && !commandLine.includes('provared-connect:1:'), commandLine);
  // Nor the log.
  const logFile = `${r.base}.uploader.log`;
  for (let i = 0; i < 40 && !existsSync(logFile); i++) await new Promise((ok) => setTimeout(ok, 250));
  assert.ok(holdsNoSecret(readFileSync(logFile, 'utf8'), c));
  // The same line again: nothing changed, the same process.
  const again = run([line, '--feed', 'http://127.0.0.1:1', '--feed-token', r.feedToken]);
  assert.equal(again.status, 0, again.stderr);
  assert.match(again.stdout, new RegExp(`already connected: the uploader is running \\(process ${pid}\\); nothing changed`));
  // A new key: the connection replaced, the uploader restarted as another process.
  const rekeyed = { ...c, kObject: cc.toBase64Url(cc.generateSymmetricKey()) };
  const renewed = run([encodeLine(rekeyed), '--feed', 'http://127.0.0.1:1', '--feed-token', r.feedToken]);
  assert.equal(renewed.status, 0, renewed.stderr);
  assert.match(renewed.stdout, /connected again with the book's new key/);
  const pid2 = Number(readFileSync(pidFile, 'utf8').trim());
  assert.notEqual(pid2, pid);
  pid = pid2;
  assert.equal(readSaved(r.file).kObject, rekeyed.kObject);
  // Stopped: gone within the wait.
  assert.equal(await stopUploader(pidFile), true);
  pid = null;
  assert.ok(!existsSync(pidFile) || (() => { try { process.kill(Number(readFileSync(pidFile, 'utf8')), 0); return false; } catch { return true; } })());
});
