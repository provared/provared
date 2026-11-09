// Where the connection is kept on the agent's computer, and how: a file
// that only its owner can read, beside the recorder's own files (the
// folder that holds the recorder's feed token, or the book file the
// uploader reads). The long-running uploader is given the file's name,
// never what it holds, so the secret is in no command line and no log.
//
// ONLY ITS OWNER CAN READ IT means:
//   - on Linux and macOS, the file is made with mode 0600 (read and write
//     for its owner, nothing for anyone else), as a key file is;
//   - on Windows, a file's mode means little: who may read it is decided by
//     its access list, which a new file inherits from its folder. So the
//     file is written and then its access list is replaced with the
//     system's own tool (icacls): inheritance off, and the person who runs
//     the command the only name on it, with full control. Where that tool
//     cannot be run, the file is as readable as its folder, and the caller
//     is told so; a folder under the person's own profile (C:\Users\<name>)
//     is readable by that person, administrators and the system only.
// The file is written whole beside its final name and then renamed over
// it, so a reader never sees half of it.

import { chmodSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { userInfo } from 'node:os';
import { join } from 'node:path';
import { checkConnection } from './line.mjs';

/** The connection file's name beside the recorder: the name the uploader has always read by default. */
export const CONNECTION_FILE = 'provared-app-connection.json';

export function connectionFile(folder) {
  return join(folder, CONNECTION_FILE);
}

/** The connection kept in a file, checked; null where there is no file. Throws where the file holds something else. */
export function readSaved(file) {
  if (!existsSync(file)) return null;
  return checkConnection(JSON.parse(readFileSync(file, 'utf8')));
}

/**
 * Restricts a file to the person running this, on Windows (see the top).
 * Gives back true where done, or the reason it was not.
 */
export function restrictOnWindows(file, { run = execFileSync, user = userInfo().username } = {}) {
  try {
    run('icacls', [file, '/inheritance:r', '/grant:r', `${user}:F`], { stdio: 'pipe', timeout: 15000, windowsHide: true });
    return true;
  } catch (e) {
    return `the file's access list could not be set with icacls (${e.code || (e.stderr && String(e.stderr).trim()) || e.message}); the file is as readable as its folder`;
  }
}

/**
 * Saves a connection where only its owner can read it. Gives back
 * { file, restricted: true | <reason it is not> }. On Windows the access
 * list is set as described at the top; elsewhere the mode 0600 is.
 */
export function saveConnection(file, connection, { platform = process.platform, restrict = restrictOnWindows } = {}) {
  const c = checkConnection(connection);
  const text = `${JSON.stringify(c, null, 2)}\n`;
  const folder = join(file, '..');
  mkdirSync(folder, { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.new`;
  // Made empty first, restricted, and only then written: on Windows the
  // mode at creation means nothing, so the secret is never on disk under
  // the folder's inherited access list.
  closeSync(openSync(temporary, 'wx', 0o600));
  let restricted = true;
  if (platform === 'win32') restricted = restrict(temporary);
  else chmodSync(temporary, 0o600);
  const fd = openSync(temporary, 'r+');
  try {
    writeSync(fd, text);
    fsyncSync(fd);
  } catch (e) {
    closeSync(fd);
    try { unlinkSync(temporary); } catch { /* gone */ }
    throw e;
  }
  closeSync(fd);
  try {
    renameSync(temporary, file);
  } catch (e) {
    try { unlinkSync(temporary); } catch { /* gone */ }
    throw e;
  }
  return { file, restricted };
}
