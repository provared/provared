// The connection by one line: npx provared-connect <line>.
//
// The person copies one line from the book's page on the application and
// runs it on the agent's computer. This checks the line (its prefix, its
// version and every field), saves the connection where only its owner can
// read it (store.mjs), beside the recorder, and starts the uploader in the
// background, as --ensure does. The uploader is started with the file's
// name, never with the line: the secret is in no command line of a
// long-running program, and in no log this package writes; nothing here
// prints it. (npm itself writes a debug log of each npx run, with its
// arguments, unless told not to: the page offers the command with
// --logs-max=0 for that; see the README.)
//
//   - Run again with the same line, it changes nothing: where the uploader
//     runs, it says so; where it does not, it starts it.
//   - Run with a line from a new key of the same book, it replaces the
//     connection and restarts the uploader, which goes on from where it was.
//   - Run with a line for another book, where this recorder has sent lines
//     of a book already (the uploader's state is beside the book), it
//     refuses and says what to do: the state is of the other book, and
//     would be ahead of the new one. A connection file that is there but
//     cannot be read as a connection is treated the same way, never as if
//     there were none.
//   - Whenever the connection on disk changes, or there was none, an
//     uploader that runs is stopped before the new one is started, so the
//     one that runs is always the one with the connection saved.
//
// The recorder is the one beside Claude Code unless another is named: its
// feed at http://127.0.0.1:8794 and its token in ~/.provared/claude-code
// (upload.mjs: DEFAULT_FEED, DEFAULT_FEED_TOKEN); --feed and --feed-token
// name another, both together; --book <file> names a book file for a
// recorder that offers no feed, and the connection is then kept beside
// that file.

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { decodeLine, sameConnection } from './line.mjs';
import { connectionFile, readSaved, saveConnection } from './store.mjs';
import { DEFAULT_FEED, DEFAULT_FEED_TOKEN, USAGE, ensure, uploaderRunning } from './upload.mjs';

export { decodeLine, encodeLine, checkConnection, sameConnection, LINE_PREFIX, LINE_VERSION, FIELDS } from './line.mjs';
export { connectionFile, readSaved, saveConnection, CONNECTION_FILE } from './store.mjs';
export { DEFAULT_FEED, DEFAULT_FEED_TOKEN, DEFAULT_FOLDER, USAGE, createUploader, feedClient, readConnection, readCommandLine, ensure, main as uploaderMain } from './upload.mjs';

const pause = (ms) => new Promise((r) => setTimeout(r, ms));

/** The options that take a value. */
const VALUED = Object.freeze(['--feed', '--feed-token', '--book', '--connection']);

/** The value given after an option, or null where there is none (a word that starts with "--" is not a value). */
export function optionValue(argv, name) {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : null;
}

/** The words of a command line that are neither options nor an option's value: a line, or something taken for one. */
export function bareWords(argv) {
  const values = new Set(VALUED.map((name) => optionValue(argv, name)).filter(Boolean));
  return argv.filter((a) => !a.startsWith('--') && !values.has(a));
}

/** The arguments of "npx provared-connect <line> ...": the line, and the recorder named. */
export function readConnectArguments(argv) {
  const bare = bareWords(argv);
  const line = bare[0] ?? null;
  const book = optionValue(argv, '--book');
  const feedAddress = optionValue(argv, '--feed');
  const feedToken = optionValue(argv, '--feed-token');
  const feedNamed = feedAddress || feedToken || argv.includes('--feed') || argv.includes('--feed-token');
  if (book && feedNamed) return { error: 'give --feed or --book, not both: through the feed, the uploader opens no book file' };
  if (feedNamed && !(feedAddress && feedToken)) return { error: 'give both --feed <address> and --feed-token <file>' };
  if (bare.length > 1) return { error: 'one line only, and nothing after it but options: a line copied with a break in it is two words here' };
  if (book) return { line, book, base: book, folder: dirname(book) };
  const token = feedToken ?? DEFAULT_FEED_TOKEN;
  return { line, feedAddress: feedAddress ?? DEFAULT_FEED, feedToken: token, base: join(dirname(token), 'book.jsonl'), folder: dirname(token) };
}

/**
 * Stops the uploader whose process number the file holds, and waits up to
 * ten seconds for it to be gone. true once gone.
 */
export async function stopUploader(pidFile, { kill = process.kill } = {}) {
  if (!uploaderRunning(pidFile)) return true;
  const pid = Number(readFileSync(pidFile, 'utf8').trim());
  try { kill(pid, 'SIGTERM'); } catch { /* gone meanwhile */ }
  for (let i = 0; i < 40; i++) {
    if (!uploaderRunning(pidFile)) return true;
    await pause(250);
  }
  return false;
}

/**
 * Connects the recorder with a line. Prints one sentence of what it did (or
 * what to do) to log, and gives back the exit code: 0 connected (or already
 * so), 1 refused or failed, 2 the command line is wrong. Prints no value
 * from the line.
 */
export async function connect(argv, { log = console, start = ensure, stop = stopUploader } = {}) {
  const said = readConnectArguments(argv);
  if (said.error) { log.error(`provared-connect: ${said.error}\n${USAGE}`); return 2; }
  let connection;
  try { connection = decodeLine(said.line); } catch (e) { log.error(`provared-connect: ${e.message}`); return 1; }
  if (said.feedToken && !existsSync(said.feedToken)) {
    log.error(`provared-connect: no recorder's feed token at ${said.feedToken}: start the recorder once (it writes the token into its folder at its first start), or name the token file with --feed-token and the feed with --feed.`);
    return 1;
  }
  if (said.book && !existsSync(said.book)) {
    log.error(`provared-connect: there is no book file at ${said.book}: name the recorder's book.jsonl with --book, or leave --book out for a recorder that offers a feed.`);
    return 1;
  }
  const file = connectionFile(said.folder);
  const pidFile = `${said.base}.uploader.pid`;
  const stateFile = `${said.base}.uploaded.json`;
  // The connection on disk: one, none, or a file that is there but is not a
  // connection to this package (never taken for none).
  let existing = null;
  let unreadable = false;
  if (existsSync(file)) {
    try { existing = readSaved(file); } catch { unreadable = true; }
  }
  const forUploader = { connection: file, base: said.base, book: said.book, feedAddress: said.feedAddress, feedToken: said.feedToken };
  const pid = () => { try { return readFileSync(pidFile, 'utf8').trim(); } catch { return '?'; } };
  const started = async (words) => {
    const code = await start(forUploader, pidFile);
    if (code !== 0) { log.error(`provared-connect: the connection is saved in ${file}, but the uploader did not start; see ${said.base}.uploader.log.`); return 1; }
    log.log(`provared-connect: ${words}`);
    return 0;
  };
  if (existing && sameConnection(existing, connection)) {
    if (uploaderRunning(pidFile)) { log.log(`provared-connect: already connected: the uploader is running (process ${pid()}); nothing changed.`); return 0; }
    return started(`already connected; the uploader was not running, and is started now (its connection is in ${file}).`);
  }
  if (existsSync(stateFile) && (unreadable || (existing && existing.objectId !== connection.objectId))) {
    const whose = unreadable ? `the connection file beside the recorder (${file}) is not one this version reads, and this recorder has sent its book to a book of the application already` : `this recorder has sent its book to another book of the application (${existing.objectId})`;
    log.error(`provared-connect: ${whose}; to connect it to this one instead, stop the uploader and move ${file} and ${stateFile} away first, then run this command again.`);
    return 1;
  }
  let saved;
  try { saved = saveConnection(file, connection); } catch (e) { log.error(`provared-connect: the connection could not be saved in ${file}: ${e.message}`); return 1; }
  const where = saved.restricted === true ? `kept in ${file}, readable by you only` : `kept in ${file} (${saved.restricted})`;
  // The connection on disk has changed (or there was none): an uploader that
  // runs holds something else, and is stopped before the new one starts.
  const wasRunning = uploaderRunning(pidFile);
  if (wasRunning && !(await stop(pidFile))) { log.error(`provared-connect: the new connection is ${where}, but the uploader that ran before did not stop (process ${pid()}); stop it, then run this command again.`); return 1; }
  if (existing) return started(`connected again with the book's new key: the connection is ${where}, and the uploader was restarted.`);
  if (unreadable) return started(`connected: the connection is ${where}, in place of a file that was not one this version reads, and the uploader ${wasRunning ? 'was restarted' : 'is running in the background'}.`);
  return started(`connected: the connection is ${where}, and the uploader ${wasRunning ? 'that ran before was stopped and started again with it' : 'is running in the background'}.`);
}
