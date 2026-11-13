// The lock that keeps a second program off an agent's book and copy
// (lock.mjs): short names on Windows, a start that asks again while the
// program before it ends, and the socket file of other systems.

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

const { lockAt, lockFiles, lockName } = await import('../lock.mjs');

const pause = (ms) => new Promise((done) => setTimeout(done, ms));
const folder = () => mkdtempSync(join(tmpdir(), 'provared-lock-'));

/** The short name Windows gives a path, or null where the file system gives none. */
function shortName(path) {
  const r = spawnSync('cmd.exe', ['/d', '/s', '/c', `for %I in ("${path}") do @echo %~sI`], { encoding: 'utf8', windowsVerbatimArguments: true, windowsHide: true });
  const short = r.stdout.trim();
  return r.status === 0 && short && short.toLowerCase() !== path.toLowerCase() ? short : null;
}

test('on Windows, a short name for the book\'s folder is the same lock as its full name', { skip: process.platform !== 'win32' && 'Windows only' }, async (t) => {
  const dir = folder();
  try {
    const long = join(dir, 'a folder with a long name');
    mkdirSync(long);
    const short = shortName(long);
    if (!short) return t.skip('this file system makes no short names');
    assert.notEqual(short, long);
    assert.equal(lockName(join(short, 'alpha.book.jsonl')), lockName(join(long, 'alpha.book.jsonl')));
    const held = await lockFiles(join(long, 'alpha.book.jsonl'));
    try {
      await assert.rejects(lockFiles(join(short, 'alpha.book.jsonl')), (e) => e.code === 'LOCKED');
    } finally {
      await held.release();
    }
    const again = await lockFiles(join(short, 'alpha.book.jsonl'));
    await again.release();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a start asks again for a lock that is held, and has it once the program before has let it go; a command asks once', async () => {
  const dir = folder();
  try {
    const book = join(dir, 'alpha.book.jsonl');
    const first = await lockFiles(book);
    // Asked once: refused at once.
    const began = Date.now();
    await assert.rejects(lockFiles(book), (e) => e.code === 'LOCKED' && /Nothing was read or written\./.test(e.message));
    assert.ok(Date.now() - began < 1000);
    // Asked for 5 seconds, while the first lets go after one.
    const second = lockFiles(book, { wait: 5000 });
    await pause(1000);
    await first.release();
    const had = await second;
    // Asked for a short time, while it stays held: refused once that time is up.
    const waited = Date.now();
    await assert.rejects(lockFiles(book, { wait: 1200 }), (e) => e.code === 'LOCKED');
    assert.ok(Date.now() - waited >= 1100, `${Date.now() - waited} ms`);
    await had.release();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The socket file of systems other than Windows and Linux. On Linux a
// socket file works the same way, so the branch runs there; Windows has
// no socket files for Node.js to listen on.
const socketFiles = process.platform === 'win32' && 'needs socket files, which Node.js does not listen on in Windows';

/** A socket file left behind: a program listens on it and is killed, so that it does not take it away. */
async function leftBehind(path) {
  const child = spawn(process.execPath, ['-e', `require('node:net').createServer().listen(${JSON.stringify(path)}, () => process.kill(process.pid, 'SIGKILL'))`], { stdio: 'ignore' });
  await new Promise((done) => child.on('exit', done));
  assert.ok(existsSync(path), 'the socket file is left behind');
}

test('a socket file left behind: two programs that ask at the same moment do not both get the lock', { skip: socketFiles }, async () => {
  const dir = folder();
  try {
    for (let round = 0; round < 5; round += 1) {
      const path = join(dir, `lock-${round}.sock`);
      await leftBehind(path);
      const tries = await Promise.allSettled([lockAt(path, { file: true }), lockAt(path, { file: true }), lockAt(path, { file: true })]);
      const had = tries.filter((r) => r.status === 'fulfilled');
      assert.equal(had.length, 1, `round ${round}: ${tries.map((r) => r.status).join(', ')}`);
      for (const r of tries.filter((x) => x.status === 'rejected')) assert.equal(r.reason.code, 'LOCKED');
      assert.ok(!existsSync(`${path}.clearing`), 'the folder is taken away');
      // The one that has it holds it: asked again, it is refused.
      await assert.rejects(lockAt(path, { file: true }), (e) => e.code === 'LOCKED');
      await new Promise((done) => had[0].value.close(done));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a socket file left behind is cleared away, a live one is not, and a folder left by a program stopped while clearing refuses the lock', { skip: socketFiles }, async () => {
  const dir = folder();
  try {
    const path = join(dir, 'lock.sock');
    await leftBehind(path);
    const server = await lockAt(path, { file: true });
    await assert.rejects(lockAt(path, { file: true }), (e) => e.code === 'LOCKED');
    await new Promise((done) => server.close(done));
    await leftBehind(path);
    mkdirSync(`${path}.clearing`);
    await assert.rejects(lockAt(path, { file: true }), (e) => e.code === 'LOCKED' && e.clearing === `${path}.clearing`);
    assert.ok(existsSync(path), 'the socket file is not cleared while the folder is there');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
