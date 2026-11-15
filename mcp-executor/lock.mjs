// One program at a time writes an agent's book and copy. Before a program
// opens them to write (stdio, http, or a command run with --offline), it
// takes a lock named after the book file, and keeps it until it has closed
// the files or has ended. A second program that asks for the same lock is
// refused at once, before it has read or written anything. The front door's
// state file (oauth.state) is locked in the same way, for the HTTP executor
// that opens it and for the command "owner" (lockState, X285).
//
// The lock is a listener that the operating system takes away when the
// program ends, however it ends, so that no lock is left behind by a
// program that was stopped:
//   Windows  a named pipe, \\.\pipe\provared-mcp-executor-<name>
//   Linux    a socket in the abstract namespace, with no file
//   others   a socket file in /tmp; one left behind by a program that has
//            ended is told from a live one by trying to connect to it
// <name> is the SHA-256, in hexadecimal, of the book file's path as the
// file system resolves it. Nothing is ever sent over the listener: a
// connection to it is closed at once.
//
// What it does not do. It names the path, not the file: two paths that
// reach one file through a link the file system does not resolve, or
// through two computers' views of a shared folder, are two locks. On Linux
// the abstract namespace belongs to a network namespace, so two containers
// that share a folder and not a network do not see each other's lock. A
// program that takes the lock's name first keeps the executor from
// starting on those files, and gains nothing else.

import { createHash } from 'node:crypto';
import { realpathSync, unlinkSync } from 'node:fs';
import net from 'node:net';
import { basename, dirname, resolve } from 'node:path';

/** The lock's name for a book file: the SHA-256 of its resolved path (lower case on Windows, where case does not tell paths apart). */
export function lockName(bookPath) {
  const full = resolve(bookPath);
  let folder = dirname(full);
  try {
    folder = realpathSync(folder);
  } catch {
    // The folder is not there yet: its path as written.
  }
  const path = resolve(folder, basename(full));
  return createHash('sha256').update(process.platform === 'win32' ? path.toLowerCase() : path, 'utf8').digest('hex');
}

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

/** Whether a program is listening at a socket file: false where the file was left behind by one that has ended. */
function alive(address) {
  return new Promise((done) => {
    const socket = net.connect(address);
    socket.once('connect', () => {
      socket.destroy();
      done(true);
    });
    socket.once('error', (e) => done(e.code !== 'ECONNREFUSED' && e.code !== 'ENOENT'));
  });
}

/**
 * Take the lock for a book file. Gives {release}, to be called once the
 * files are closed; the operating system releases the lock when the
 * program ends. Throws, with code LOCKED, where another program (or this
 * one) holds it.
 * @param {string} bookPath
 */
export function lockFiles(bookPath) {
  return lock(bookPath, {
    held: `An executor is running on the book ${bookPath} and its copy, or a command is at work on them. One program writes them at a time: stop the executor first, or wait for the command to end. Nothing was read or written.`,
    failed: (why) => `The lock for the book ${bookPath} could not be taken (${why}), so the executor does not open it.`,
  });
}

/**
 * Take the lock for the front door's state file (oauth.state), in the same
 * way and under the same kind of name: the SHA-256 of the file's resolved
 * path. An HTTP executor whose settings name "oauth" takes it before it
 * reads anything, and holds it until it has closed; the command "owner"
 * holds it while it works. So two executors whose settings name the same
 * state file, with whatever agents, do not both run: each would keep the
 * owner and the connections in its own memory and write the whole of it
 * over the file (X285). Gives {release}; throws, with code LOCKED, where
 * another program (or this one) holds it.
 * @param {string} statePath
 */
export function lockState(statePath) {
  return lock(statePath, {
    held: `An executor is running on the state file ${statePath} (oauth.state), or the command "owner" is at work on it. One program holds a state file at a time: stop the other first, or wait for the command to end. Two executors need a state file each: name another in this one's settings ("oauth", "state"). Neither the state file nor any agent's files were read or written.`,
    failed: (why) => `The lock for the state file ${statePath} (oauth.state) could not be taken (${why}), so the executor does not open it.`,
  });
}

/** Take the lock named after a path: "held" is what is said where another program holds it, "failed" where it could not be taken for another reason. */
async function lock(path, words) {
  const address = lockAddress(lockName(path));
  const held = () => Object.assign(new Error(words.held), { code: 'LOCKED' });
  let server;
  try {
    server = await listen(address);
  } catch (e) {
    if (e.code !== 'EADDRINUSE' && e.code !== 'EACCES') throw new Error(words.failed(e.code ?? e.message));
    // A socket file is left behind by a program that has ended; a named pipe and an abstract socket are not.
    const file = process.platform !== 'win32' && process.platform !== 'linux';
    if (!file || e.code === 'EACCES' || (await alive(address))) throw held();
    try {
      unlinkSync(address);
      server = await listen(address);
    } catch {
      throw held();
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
