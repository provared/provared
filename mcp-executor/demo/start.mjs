// The demonstration's start: set up when needed, then run the executor in
// front of the made-up tool server (server.mjs), over the stdio transport.
//
// DEMONSTRATION ONLY. The permission is signed by the library's development
// stand-in for a passkey (provared/dev), not by a person: its issuer's name
// ends with "(development)", and its records prove nothing about anyone.
//
// Everything is kept in the folder PROVARED_DEMO_DIR (by default
// ".provared-mcp-demo" in the home folder). The start uses that folder only
// if it is empty or holds the demonstration's own mark,
// "provared-demo.json"; any other folder is refused, and nothing in it is
// touched. Each set-up is a folder of its own inside it ("set-up-…"), and
// the mark names the one in use. A set-up:
//   1. makes a development stand-in for a passkey, used for this set-up
//      only and then forgotten;
//   2. writes the executor's settings, naming that stand-in's thumbprint as
//      the passkey it trusts, and a made-up credential for the server;
//   3. makes the agent's and the executor's keys with the executor's own
//      "keys" command, which prints what goes into the permission;
//   4. signs a permission for the two tools, valid for 30 days, with the
//      stand-in;
//   5. checks the settings with the executor's own "check" command.
// On every start, the paths to Node.js, to server.mjs and to the rules
// file are written into the settings afresh (none of them is signed, and
// the rules file's fingerprint does not depend on its path), and the
// settings are checked again. A set-up whose permission has ended, ends
// within the hour, cannot be read, or whose settings no longer pass the
// check is not used: it is left where it is (with at most its paths
// written afresh), and a new set-up is made beside it.
//
// Then it starts "provared-mcp-executor stdio" with this process's own
// input and output. Everything this file says goes to its standard error:
// standard output carries MCP messages and nothing else.

import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assembleSlip, formatTime, prepareSlip, thumbprint } from 'provared';
import { developmentPasskey } from 'provared/dev';

const HERE = dirname(fileURLToPath(import.meta.url));
// The executor's command, run by its path in the installed package: bin.mjs
// is the file npm's "bin" names, though the package does not export it.
const BIN = join(dirname(fileURLToPath(import.meta.resolve('provared-mcp-executor/package.json'))), 'bin.mjs');
const STATE = resolve(process.env.PROVARED_DEMO_DIR || join(homedir(), '.provared-mcp-demo'));
const MARK_NAME = 'provared-demo.json';
const MARK = join(STATE, MARK_NAME);
const MARK_TEXT = 'provared-mcp-executor demonstration';
const EMPTY_MARK = `${JSON.stringify({ demonstration: MARK_TEXT, current: null })}\n`;
const DAYS = 30;
const NODE_FLAGS = ['--disable-warning=ExperimentalWarning'];

const say = (text) => process.stderr.write(`provared demo: ${text}\n`);

function executor(args) {
  const run = spawnSync(process.execPath, [...NODE_FLAGS, BIN, ...args], { encoding: 'utf8' });
  if (run.error) throw run.error;
  return run;
}

function parse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function readJson(path) {
  try {
    return parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

/** Write a file in one step: a temporary file beside it, then renamed over it. */
function writeWhole(path, text) {
  const temporary = `${path}.${randomBytes(6).toString('hex')}.tmp`;
  writeFileSync(temporary, text);
  for (let tries = 0; ; tries++) {
    try {
      renameSync(temporary, path);
      return;
    } catch (e) {
      // Windows refuses for a moment while another program has the file open.
      if (tries >= 40 || !['EPERM', 'EBUSY', 'EACCES'].includes(e.code)) throw e;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
    }
  }
}

/** Why the demonstration's folder cannot be used: it is a file, or it cannot be made or written. */
function folderProblem(e) {
  let file = false;
  try {
    file = !statSync(STATE).isDirectory();
  } catch {
    // Missing, or not to be looked at: the second message covers both.
  }
  if (file) return new Error(`${STATE} is a file, not a folder. Name a folder with PROVARED_DEMO_DIR.`);
  return new Error(`The demonstration's folder ${STATE} cannot be made or written (the system reported ${e.code ?? e.message}). It needs a folder it can write: name one with PROVARED_DEMO_DIR or, in a container started read-only, give it a writable volume or a tmpfs at that path.`);
}

/** Whether a file error is about a path inside the demonstration's folder. */
function inFolder(e) {
  if (typeof e?.path !== 'string') return false;
  const r = relative(STATE, resolve(e.path));
  return r === '' || (!r.startsWith('..') && !isAbsolute(r));
}

/** The folder holds only an empty mark (and at most a mark being written): a start began the mark and did not finish it. */
function markUnfinished() {
  try {
    return statSync(MARK).size === 0 && readdirSync(STATE).every((n) => n === MARK_NAME || /^provared-demo\.json\.[0-9a-f]{12}\.tmp$/.test(n));
  } catch {
    return false;
  }
}

/** The demonstration's folder: made if missing; refused unless empty or marked as the demonstration's. */
function openFolder() {
  let mark;
  try {
    mkdirSync(STATE, { recursive: true });
    if (!readdirSync(STATE).length) {
      try {
        // Exclusive: of two starts on an empty folder, one writes the mark and both use it.
        writeFileSync(MARK, EMPTY_MARK, { flag: 'wx' });
      } catch (e) {
        if (e.code !== 'EEXIST') throw e;
      }
    }
    mark = readJson(MARK);
    // The mark is made, then written: a start that was stopped in between,
    // or another start at this moment, leaves it empty. Alone in the
    // folder, it is the demonstration's own, and is written again, whole.
    if (mark === null && markUnfinished()) {
      writeWhole(MARK, EMPTY_MARK);
      mark = readJson(MARK);
    }
  } catch (e) {
    throw folderProblem(e);
  }
  if (mark?.demonstration !== MARK_TEXT) {
    throw new Error(`The folder ${STATE} is not empty and was not made by this demonstration (it holds no provared-demo.json that says so). Nothing in it was touched. Name another folder with PROVARED_DEMO_DIR.`);
  }
  return mark;
}

/** The settings, with the paths of this copy of the demonstration and of this Node.js written in. */
function settingsFor(passkeyThumbprint) {
  return {
    name: 'Provared MCP executor, demonstration',
    service: 'executor',
    server: {
      command: process.execPath,
      args: [join(HERE, 'server.mjs')],
      env: { DEMO_TOKEN: { file: 'demo-token' } },
    },
    agent: { slip: 'slip.json', book: 'book.jsonl', keys: 'keys/agent.jwk', issuerKeys: [passkeyThumbprint] },
    executor: { keys: 'keys/executor.jwk', copy: 'copy.jsonl' },
    tools: {
      echo: { action: 'demo.echo' },
      add: { action: 'demo.add' },
    },
    contentRules: join(HERE, 'content-rules.json'),
    unlisted: 'refuse',
  };
}

/** Why a set-up cannot be used, or null where it can; its paths are written in afresh first. */
function whyNot(folder) {
  const settingsPath = join(folder, 'executor.json');
  const trusted = readJson(settingsPath)?.agent?.issuerKeys?.[0];
  if (typeof trusted !== 'string') return 'its settings cannot be read';
  const slip = readJson(join(folder, 'slip.json'));
  let ends = NaN;
  if (typeof slip?.payload === 'string') ends = Date.parse(parse(Buffer.from(slip.payload, 'base64url').toString('utf8'))?.validUntil);
  if (!Number.isFinite(ends)) return 'its permission cannot be read';
  if (ends <= Date.now()) return 'its permission has ended';
  if (ends < Date.now() + 3600 * 1000) return 'its permission ends within the hour';
  writeWhole(settingsPath, `${JSON.stringify(settingsFor(trusted), null, 2)}\n`);
  const check = executor(['check', '--config', settingsPath]);
  if (check.status !== 0) {
    const problems = parse(check.stdout)?.problems;
    return `its settings no longer pass the executor's check (${Array.isArray(problems) && problems.length ? problems.join('; ') : check.stderr.trim() || `exit ${check.status}`})`;
  }
  return null;
}

/** A new set-up, in a folder of its own inside the demonstration's folder. */
async function setUp() {
  const name = `set-up-${new Date().toISOString().replace(/[:.]/g, '-')}-${randomBytes(3).toString('hex')}`;
  const folder = join(STATE, name);
  mkdirSync(join(folder, 'keys'), { recursive: true });
  const passkey = await developmentPasskey();
  writeFileSync(join(folder, 'demo-token'), `${randomBytes(16).toString('hex')}\n`, { mode: 0o600 });
  const settingsPath = join(folder, 'executor.json');
  writeFileSync(settingsPath, `${JSON.stringify(settingsFor(await thumbprint(passkey.key)), null, 2)}\n`);

  const keys = executor(['keys', '--config', settingsPath]);
  if (keys.status !== 0) throw new Error(`"keys" failed: ${keys.stderr.trim()}`);
  const entries = JSON.parse(keys.stdout);

  const now = Date.now();
  const prepared = await prepareSlip({
    issuer: { name: 'Provared demonstration (development)', key: passkey.key, rpId: passkey.rpId, origin: passkey.origin },
    agent: { ...entries.agent, name: 'Any agent, through the demonstration executor' },
    actions: ['demo.echo', 'demo.add'],
    limits: [{ action: 'demo.add', count: 1000, per: 86400 }],
    requires: entries.requires,
    never: [],
    with: [entries.with],
    validFrom: formatTime(now - 60 * 1000),
    validUntil: formatTime(now + DAYS * 24 * 3600 * 1000),
    purpose: 'A demonstration of the Provared MCP executor in front of a made-up tool server. Signed by a development stand-in for a passkey, which no person signed: it proves nothing about anyone.',
  });
  const slip = assembleSlip(prepared, await passkey.sign(prepared.challenge));
  writeFileSync(join(folder, 'slip.json'), `${JSON.stringify(slip)}\n`);

  const check = executor(['check', '--config', settingsPath]);
  if (check.status !== 0) throw new Error(`"check" found problems: ${check.stdout.trim()} ${check.stderr.trim()}`);
  writeWhole(MARK, `${JSON.stringify({ demonstration: MARK_TEXT, current: name })}\n`);
  say(`set up in ${folder}: a permission for "echo" and "add", signed by a development stand-in for a passkey, valid for ${DAYS} days.`);
  return folder;
}

async function main() {
  const mark = openFolder();
  const current = typeof mark.current === 'string' && /^set-up-[0-9A-Za-z-]+$/.test(mark.current) ? join(STATE, mark.current) : null;
  let folder = null;
  if (current && existsSync(current)) {
    const reason = whyNot(current);
    if (reason) say(`the set-up ${current} is left where it is and not used: ${reason}. A new one is made.`);
    else {
      folder = current;
      say(`using the demonstration set up in ${folder}.`);
    }
  }
  if (!folder) folder = await setUp();

  const child = spawn(process.execPath, [...NODE_FLAGS, BIN, 'stdio', '--config', join(folder, 'executor.json')], { stdio: 'inherit' });
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
  child.on('exit', (code, signal) => {
    process.exitCode = typeof code === 'number' ? code : signal ? 1 : 0;
  });
}

main().catch((e) => {
  // A file error inside the folder (a set-up's folder mounted read-only, a
  // full disk) gets the same words as a folder that cannot be written.
  say(inFolder(e) ? folderProblem(e).message : e.message);
  process.exitCode = 2;
});
