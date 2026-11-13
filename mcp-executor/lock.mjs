// One program at a time writes an agent's book and copy. Before a program
// opens them to write (stdio, http, or a command run with --offline), it
// takes a lock named after the book file, and keeps it until it has closed
// the files or has ended. A second program that asks for the same lock is
// refused at once, before it has read or written anything.
//
// The lock is a listener that the operating system takes away when the
// program ends, however it ends, so that no lock is left behind by a
// program that was stopped:
//   Windows  a named pipe, \\.\pipe\provared-mcp-executor-<name>
//   Linux    a socket in the abstract namespace, with no file
//   others   a socket file in /tmp; one left behind by a program that has
//            ended is told from a live one by trying to connect to it
//            (no answer within 2 seconds counts as live). Only one program
//            at a time may clear such a file away and listen in its place:
//            it first makes a folder beside it, <socket file>.clearing,
//            which a second program cannot make too, and takes it away
//            once it listens. A program stopped in that moment leaves the
//            folder, and the lock is then refused until it is taken away.
// <name> is the SHA-256, in hexadecimal, of the book file's path as the
// file system resolves it. Nothing is ever sent over the listener: a
// connection to it is closed at once.
//
// A start (stdio, http) asks again for a few seconds before it gives up,
// so that a client that starts the executor again while the one before is
// still ending is not refused; a command asks once.
//
// What it does not do. It names the path, not the file: two paths that
// reach one file through a link the file system does not resolve, or
// through two computers' views of a shared folder, are two locks. The
// folder is written out in full, short names on Windows included; the
// book file's own name is taken as written. On Linux
// the abstract namespace belongs to a network namespace, so two containers
// that share a folder and not a network do not see each other's lock. A
// program that takes the lock's name first keeps the executor from
// starting on those files, and gains nothing else.

import { createHash } from 'node:crypto';
import { mkdirSync, realpathSync, rmdirSync, unlinkSync } from 'node:fs';
import net from 'node:net';
import { basename, dirname, resolve } from 'node:path';

/** The lock's name for a book file: the SHA-256 of its resolved path (lower case on Windows, where case does not tell paths apart). */
export function lockName(bookPath) {
  const full = resolve(bookPath);
  let folder = dirname(full);
  try {
    folder = realpathNative(folder);
  } catch {
    // The folder is not there yet: its path as written.
  }
  const path = resolve(folder, basename(full));
  return createHash('sha256').update(process.platform === 'win32' ? path.toLowerCase() : path, 'utf8').digest('hex');
}

/** A path as the file system resolves it: the form that writes a short name on Windows out in full, or the other where that fails. */
function realpathNative(path) {
  try {
    return realpathSync.native(path);
  } catch {
    return realpathSync(path);
  }
}

/** How long a start asks again for a lock held by another program (milliseconds), at least. */
export const LOCK_WAIT_MS = 10000;
/** How long a socket file is given to answer before it is taken to be live (milliseconds). */
const ALIVE_WAIT_MS = 2000;

/** Where the lock's listener is, on this kind of computer. */
function lockAddress(name) {
  if (process.platform === 'win32') return `\\\\.\\pipe\\provared-mcp-executor-${name}`;
  if (process.platform === 'linux') return `\0provared-mcp-executor-${name}`;
  return `/tmp/provared-mcp-executor-${name}.sock`;
}

function listen(address) {
  return new Promise((done, failed) => {
    const server = net.createServer((socket) => socket.destroy());
    server.once('error', failed);
    server.listen(address, () => {
      server.removeListener('error', failed);
      server.on('error', () => {});
      // The lock does not keep the program running.
      server.unref();
      done(server);
    });
  });
}

/** Whether a program is listening at a socket file: false where the file was left behind by one that has ended. No answer in time counts as live. */
function alive(address, wait = ALIVE_WAIT_MS) {
  return new Promise((done) => {
    const socket = net.connect(address);
    const timer = setTimeout(() => {
      socket.destroy();
      done(true);
    }, wait);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.destroy();
      done(true);
    });
    socket.once('error', (e) => {
      clearTimeout(timer);
      done(e.code !== 'ECONNREFUSED' && e.code !== 'ENOENT');
    });
  });
}

const LOCKED = 'LOCKED';
const locked = () => Object.assign(new Error('The lock is held.'), { code: LOCKED });

/**
 * Listen at a lock's address: the listener, or an error with code LOCKED
 * where another program holds it (and code CANNOT where it cannot be
 * asked for). "file": the address is a socket file, which a program that
 * has ended leaves behind.
 * @param {string} address
 * @param {{file?: boolean}} [o]
 */
export async function lockAt(address, { file = process.platform !== 'win32' && process.platform !== 'linux' } = {}) {
  try {
    return await listen(address);
  } catch (e) {
    if (e.code !== 'EADDRINUSE' && e.code !== 'EACCES') throw Object.assign(new Error(e.code ?? e.message), { code: 'CANNOT' });
    // A socket file is left behind by a program that has ended; a named pipe and an abstract socket are not.
    if (!file || e.code === 'EACCES') throw locked();
  }
  // One program at a time looks, clears the file away and listens: the one that makes the folder.
  const clearing = `${address}.clearing`;
  try {
    mkdirSync(clearing);
  } catch (e) {
    if (e.code === 'EEXIST') throw Object.assign(locked(), { clearing });
    throw Object.assign(new Error(e.code ?? e.message), { code: 'CANNOT' });
  }
  try {
    if (await alive(address)) throw locked();
    try {
      unlinkSync(address);
    } catch (e) {
      if (e.code !== 'ENOENT') throw locked();
    }
    try {
      return await listen(address);
    } catch {
      throw locked();
    }
  } finally {
    try {
      rmdirSync(clearing);
    } catch {
      // Taken away already.
    }
  }
}

/**
 * Take the lock for a book file. Gives {release}, to be called once the
 * files are closed; the operating system releases the lock when the
 * program ends. Throws, with code LOCKED, where another program (or this
 * one) holds it. "wait": how long to ask again while it is held
 * (milliseconds), or 0 to ask once.
 * @param {string} bookPath
 * @param {{wait?: number}} [o]
 */
export async function lockFiles(bookPath, { wait = 0 } = {}) {
  const address = lockAddress(lockName(bookPath));
  const end = Date.now() + wait;
  let server;
  for (;;) {
    try {
      server = await lockAt(address);
      break;
    } catch (e) {
      if (e.code === 'CANNOT') throw new Error(`The lock for the book ${bookPath} could not be taken (${e.message}), so the executor does not open it.`);
      if (e.code !== LOCKED) throw e;
      if (Date.now() >= end) {
        const left = e.clearing ? ` Or a program was stopped as it took the lock, and left the folder ${e.clearing}: where no executor and no command is at work on these files, take that folder away.` : '';
        throw Object.assign(new Error(`An executor is running on the book ${bookPath} and its copy, or a command is at work on them. One program writes them at a time: stop the executor first, or wait for the command to end.${left} Nothing was read or written.`), { code: LOCKED });
      }
      await new Promise((done) => setTimeout(done, Math.min(250, end - Date.now())));
    }
  }
  let released = false;
  return {
    release() {
      if (released) return Promise.resolve();
      released = true;
      return new Promise((done) => server.close(() => done()));
    },
  };
}
