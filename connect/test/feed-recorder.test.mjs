// The uploader through the feed of the real recorder beside Claude Code,
// run as a program on a temporary folder and a port of the test's own
// (never the recorder's own folder or port 8794), with a stand-in for the
// application's server. The recorder is found in the public repository
// beside this one (../provared/integrations/claude-code/recorder.mjs), or
// where PROVARED_RECORDER names it; without it these tests are skipped
// with one line, and with PROVARED_EXPECT_STACK=1 they fail.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { createCryptoCore } from '@microtoll/crypto-core';
import { assembleSlip, checkBook, formatTime, prepareSlip, thumbprint } from 'provared';
import { developmentPasskey } from 'provared/dev';
import { createUploader, feedClient, identityOf } from '../upload.mjs';
import { NAMESPACE, openEntry } from '../entry.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const recorderFile = resolve(process.env.PROVARED_RECORDER || join(here, '..', '..', 'integrations', 'claude-code', 'recorder.mjs'));
const found = existsSync(recorderFile);
const expected = process.env.PROVARED_EXPECT_STACK === '1';
if (!found) console.log(`# The recorder beside Claude Code is not at ${recorderFile}: the tests through its feed are ${expected ? 'failed' : 'skipped'}. Name it in PROVARED_RECORDER.`);
const skip = !found && !expected ? 'no recorder to run' : false;

const cc = createCryptoCore({ namespace: NAMESPACE });
const quiet = { info() {}, error() {} };
const sha = (text) => createHash('sha256').update(text).digest('base64url');
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const LIVE_PORT = 8794;

function freePort() {
  return new Promise((ok, no) => {
    const s = createServer();
    s.once('error', no);
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => ok(port)); });
  });
}

/** As in upload.test.mjs: the server's append, with its rules. */
function standIn() {
  const parts = [];
  const server = { parts, sent: 0 };
  const fail = (reason, extra) => Object.assign(new Error(reason), { reason, serverMessage: { type: 'provared-append-failed', reason, ...extra } });
  server.append = async (msg) => {
    const part = msg.part === undefined ? 0 : msg.part;
    if (part > parts.length) throw fail('part-gap', { parts: parts.length });
    const list = parts[part] || [];
    if (msg.seq !== list.length) throw fail(msg.seq < list.length ? 'conflict' : 'gap', { part, next: list.length });
    list.push(msg.sealed);
    parts[part] = list;
    server.sent++;
    return { type: 'provared-append-ok', part, seq: msg.seq };
  };
  return server;
}

/**
 * The recorder, run as a program on a folder of its own: the agent's keys
 * made by it, a permission signed with the development stand-in for a
 * passkey, and the service started on a free port.
 */
async function recorder() {
  assert.ok(found, `the recorder beside Claude Code is not at ${recorderFile}; name it in PROVARED_RECORDER`);
  const folder = mkdtempSync(join(tmpdir(), 'provared-app-recorder-'));
  const port = await freePort();
  assert.notEqual(port, LIVE_PORT);
  const env = { ...process.env, PROVARED_CLAUDE_CODE_DIR: folder, PROVARED_CLAUDE_CODE_PORT: String(port) };
  const keys = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', recorderFile, 'keys'], { env, encoding: 'utf8' });
  assert.equal(keys.status, 0, keys.stderr);
  const agentKeys = JSON.parse(keys.stdout.split('\n').find((l) => l.startsWith('[')));
  const passkey = await developmentPasskey();
  const now = Date.now();
  const prepared = await prepareSlip({
    issuer: { name: 'Sam (development)', key: passkey.key, rpId: passkey.rpId, origin: passkey.origin },
    agent: { name: 'A coding agent', keys: agentKeys },
    actions: ['provared.code.read', 'provared.code.run'],
    limits: [], requires: [], never: [], with: [],
    validFrom: formatTime(now - 60000), validUntil: formatTime(now + 3600000),
    purpose: 'Test the uploader through the recorder\'s feed.',
  });
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(assembleSlip(prepared, await passkey.sign(prepared.challenge))));
  const start = () => {
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', recorderFile, 'start'], { env, stdio: 'ignore' });
    return child;
  };
  const base = `http://127.0.0.1:${port}`;
  const up = async () => {
    for (let i = 0; i < 120; i++) {
      try { if ((await fetch(`${base}/status`)).ok) return; } catch { /* not yet */ }
      await pause(250);
    }
    throw new Error('the recorder did not start');
  };
  let child = start();
  await up();
  let calls = 0;
  const post = async (path, body = {}) => (await fetch(`${base}${path}`, { method: 'POST', body: JSON.stringify(body) })).json();
  const r = {
    folder, port, base, issuerKey: await thumbprint(passkey.key),
    token: () => readFileSync(join(folder, 'feed-token'), 'utf8').trim(),
    feed: (token = r.token()) => feedClient({ address: base, token }),
    /** A receipt for a call, as the hook asks for it after the call. */
    record: (more = {}) => post('/record', { action: 'provared.code.run', details: [{ name: 'Bash', sha256: sha(String(++calls)) }], ...more }),
    before: (toolUseId) => post('/before', { action: 'provared.code.run', toolUseId }),
    newBook: () => post('/new-book'),
    seal: () => post('/seal'),
    file: (name) => join(folder, name),
    read: (name) => readFileSync(join(folder, name), 'utf8'),
    async stop() {
      try { await post('/stop'); } catch { /* stopped */ }
      await new Promise((ok) => { if (child.exitCode !== null) ok(); else child.once('exit', ok); });
    },
    async restart() {
      await r.stop();
      child = start();
      await up();
    },
  };
  return r;
}

async function upload(r, server, more = {}) {
  const kObject = cc.generateSymmetricKey();
  const connection = { server: 'ws://nowhere', origin: 'http://nowhere', namespace: NAMESPACE, objectId: crypto.randomUUID(), kObject: cc.toBase64Url(kObject), appendCapabilitySecret: cc.toBase64Url(cc.randomBytes(32)) };
  const key = await cc.importSymmetricKey(kObject);
  const make = (o = {}) => createUploader({ connection, book: r.file('book.jsonl'), log: quiet, append: server.append, feed: r.feed(), ...more, ...o });
  const opened = async () => {
    const out = [];
    for (let p = 0; p < server.parts.length; p++) out.push(await Promise.all(server.parts[p].map((s, seq) => openEntry(cc, key, connection.objectId, seq, cc.fromBase64Url(s), p))));
    return out;
  };
  return { make, opened, connection };
}

const lines = (text) => text.split('\n').filter(Boolean);

test('through the feed of a recorder writing quickly: exactly the lines of the book, in order, and the server\'s copy checks as the file does', { skip }, async () => {
  const r = await recorder();
  try {
    const server = standIn();
    const t = await upload(r, server);
    const u = t.make();
    // Receipts written as fast as the recorder takes them, while the uploader follows, waiting at the recorder.
    const writing = (async () => { for (let i = 0; i < 40; i++) await r.record(); })();
    let done = false;
    writing.then(() => { done = true; });
    while (!done) await u.sync({ wait: 2 });
    await u.sync();
    const file = r.read('book.jsonl');
    assert.deepEqual(await t.opened(), [lines(file)]);
    const asFile = await checkBook(file, { issuerKeys: [r.issuerKey] });
    const asServer = await checkBook((await t.opened())[0].map((l) => `${l}\n`).join(''), { issuerKeys: [r.issuerKey] });
    assert.deepEqual(asServer.summary, asFile.summary);
    assert.equal(asFile.entries.length, 41);
  } finally {
    await r.stop();
  }
});

test('a line written while the uploader waits at the recorder goes out at once', { skip }, async () => {
  const r = await recorder();
  try {
    const server = standIn();
    const u = (await upload(r, server)).make();
    await u.sync();
    const started = Date.now();
    const waiting = u.sync({ wait: 20 });
    await pause(500);
    await r.record();
    assert.equal(await waiting, 2);
    assert.ok(Date.now() - started < 10000, 'not when the wait ended');
  } finally {
    await r.stop();
  }
});

test('a new book while the uploader runs, with a late receipt into the kept book and its seal again', { skip }, async () => {
  const r = await recorder();
  try {
    const server = standIn();
    const t = await upload(r, server);
    const u = t.make();
    await r.record();
    await u.sync();
    // A call allowed under the first book, and recorded after the switch.
    assert.equal((await r.before('late')).allowed, true);
    const made = await r.newBook();
    assert.equal(made.kept, 'book-1.jsonl');
    await r.record();
    await u.sync();
    await r.record({ toolUseId: 'late' });
    await u.sync();
    await u.sync();
    const opened = await t.opened();
    assert.deepEqual(opened, [lines(r.read('book-1.jsonl')), lines(r.read('book.jsonl'))]);
    assert.deepEqual(opened[0].slice(-2).map((l) => Object.keys(JSON.parse(l))[0]), ['stub', 'seal'], 'the late receipt, and the seal again after it');
    assert.deepEqual(u.parts().map((p) => p.file), ['book-1.jsonl', 'book.jsonl']);
  } finally {
    await r.stop();
  }
});

test('a new book, and a second one, while the uploader is stopped; and the recorder restarted in between', { skip }, async () => {
  const r = await recorder();
  try {
    const server = standIn();
    const t = await upload(r, server);
    await r.record();
    await t.make().sync();
    await r.newBook();
    await r.record();
    await r.restart();
    await r.newBook();
    await r.record();
    await t.make({ feed: r.feed() }).sync();
    assert.deepEqual(await t.opened(), [lines(r.read('book-1.jsonl')), lines(r.read('book-2.jsonl')), lines(r.read('book.jsonl'))]);
  } finally {
    await r.stop();
  }
});

test('a part sent from the book file (--book) goes on through the feed without a gap or a repeat: the recorder names the file as the uploader did', { skip }, async () => {
  const r = await recorder();
  try {
    const server = standIn();
    const t = await upload(r, server);
    for (let i = 0; i < 3; i++) await r.record();
    // The old way first: the uploader reads the file.
    await t.make({ feed: null }).sync();
    const before = JSON.parse(readFileSync(`${r.file('book.jsonl')}.uploaded.json`, 'utf8')).parts[0];
    assert.equal(before.id, identityOf(statSync(r.file('book.jsonl'), { bigint: true })));
    assert.equal((await r.feed().books()).books.at(-1).id, before.id, 'the same identity, through the feed');
    for (let i = 0; i < 2; i++) await r.record();
    await t.make().sync();
    const opened = await t.opened();
    assert.deepEqual(opened, [lines(r.read('book.jsonl'))]);
    const after = JSON.parse(readFileSync(`${r.file('book.jsonl')}.uploaded.json`, 'utf8')).parts[0];
    assert.equal(after.count, 6);
    assert.equal(after.sha, sha(readFileSync(r.file('book.jsonl'))), 'the fingerprint of every byte sent went on');
  } finally {
    await r.stop();
  }
});

test('no token, or a wrong one: refused, and nothing is sent', { skip }, async () => {
  const r = await recorder();
  try {
    const server = standIn();
    await r.record();
    const t = await upload(r, server);
    const wrong = `${r.token().slice(0, -1)}${r.token().endsWith('A') ? 'B' : 'A'}`;
    await assert.rejects(() => t.make({ feed: r.feed(wrong) }).sync(), (e) => e.reason === 'feed-refused');
    const none = await fetch(`${r.base}/lines?from=0&wait=0`);
    assert.equal(none.status, 401);
    assert.equal(server.sent, 0);
  } finally {
    await r.stop();
  }
});

test('on Windows, with book.jsonl held open by another program with no sharing, the uploader goes on through the feed; the file way cannot', { skip: skip || (process.platform !== 'win32' && 'needs Windows') }, async () => {
  const r = await recorder();
  const book = r.file('book.jsonl');
  let holder;
  try {
    for (let i = 0; i < 3; i++) await r.record();
    const server = standIn();
    const t = await upload(r, server);
    holder = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `$f = [System.IO.File]::Open('${book.replace(/'/g, "''")}', 'Open', 'ReadWrite', 'None'); [Console]::Out.WriteLine('held'); [Console]::In.ReadLine() | Out-Null; $f.Close()`], { stdio: ['pipe', 'pipe', 'inherit'] });
    await new Promise((ok, no) => {
      holder.stdout.on('data', (d) => { if (String(d).includes('held')) ok(); });
      holder.once('exit', () => no(new Error('PowerShell did not hold the file')));
    });
    assert.throws(() => readFileSync(book), /EBUSY|EPERM|EACCES/, 'held: no other program can open it');
    assert.equal(await t.make().sync(), 4, 'every line, through the feed');
    // The file way, meanwhile, sends nothing: it cannot open the file.
    const fileServer = standIn();
    const other = await upload(r, fileServer);
    await other.make({ feed: null, stateFile: r.file('other.uploaded.json') }).sync().catch(() => {});
    assert.equal(fileServer.sent, 0);
  } finally {
    if (holder) {
      holder.stdin.end('\n');
      await new Promise((ok) => (holder.exitCode !== null ? ok() : holder.once('exit', ok)));
    }
    await r.stop();
  }
});
