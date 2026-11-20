#!/usr/bin/env node
// The first-start program of the guard's container, in the Docker Compose
// recipe for claude.ai (README.md, one folder up). It runs the guard's own
// commands (provared-mcp-executor), in the data folder, and nothing else:
// it makes no request to anyone, and it never fills in what a person must
// give (the permission, and the thumbprint of the passkey that signed it).
//
//   node start.mjs                   set up what is missing, wait for the
//                                    permission, check, write the owner's
//                                    link, then run the guard over HTTP
//   node start.mjs folders <folder>=<uid>:<gid> …
//                                    (the "folders" service, as root) give
//                                    each folder to its user, mode 700
//   node start.mjs owner [--reset]   the guard's "owner", with the link
//                                    written to owner-link.txt, not shown
//   node start.mjs <command> …       any other command of the guard, with
//                                    --config executor-http.json
//
// The guard's "owner" changes the state file that a running guard holds a
// lock on. So the start writes the link before the guard runs, and the
// commands are run with the guard stopped (docker compose run). While the
// guard runs, the start listens on guard-running.sock in the data folder,
// and a command that writes (owner, http, stdio, anything with --offline)
// is refused where something answers there, whichever network the guard
// is in; the guard's own lock refuses it too where both share a network.

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, chownSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

/** The settings file in the data folder, as "init --http --demo" names it. */
export const SETTINGS = 'executor-http.json';
/** What the permission must hold, as "keys --out" writes it. */
export const ENTRIES = 'permission-entries.json';
/** The owner's link, readable by the guard's user alone. */
export const LINK = 'owner-link.txt';
/** claude.ai's client metadata document. */
export const CLIENT = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
/** The data folder as the compose file names it on the server, beside compose.yaml. */
export const HOST_FOLDER = 'guard-data';
/** The guard's user, as the compose file sets it. */
export const GUARD_USER = '10001';
/** How often the start looks again for the permission, in ms. */
const WAIT = Number(process.env.PROVARED_WAIT_MS ?? 10_000);
/** A link with less than this left is not kept at a start, in ms. */
const LINK_MARGIN = 120_000;
/** The socket file the start listens on while the guard runs, in the data folder: what a command that writes looks for (X350). */
export const RUNNING = 'guard-running.sock';

const data = () => resolve(process.env.PROVARED_DATA ?? '/data');
const bin = () => process.env.PROVARED_BIN ?? join(HERE, 'node_modules', 'provared-mcp-executor', 'bin.mjs');
const say = (line) => process.stdout.write(`provared-guard: ${line}\n`);

/** A value still written <like this>. */
const unset = (v) => typeof v !== 'string' || v.startsWith('<');

/**
 * The domain the business gave, as Caddy and the issuer use it: a DNS name
 * of two labels or more, lower case, with no scheme, port, path or final
 * dot. An IP address is refused, since a browser makes no passkey for one.
 */
export function checkDomain(text) {
  const d = String(text ?? '').trim().toLowerCase();
  if (d === '') throw new Error('PROVARED_DOMAIN is not set. Put the domain in the file .env beside compose.yaml (PROVARED_DOMAIN=guard.example.com).');
  const labels = d.split('.');
  const ok =
    d.length <= 253 &&
    labels.length >= 2 &&
    // eslint-disable-next-line security/detect-unsafe-regex -- one optional part holding one bounded run, on a label with no full stop: no text can match two ways, so matching takes time in proportion to the input.
    labels.every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l)) &&
    !/^[0-9]+$/.test(labels[labels.length - 1]);
  if (!ok) throw new Error(`PROVARED_DOMAIN is "${text}", which is not a domain name such as guard.example.com: no "https://", no port, no path, and not an IP address (a browser makes no passkey for an IP address).`);
  return d;
}

/**
 * The settings with the issuer and claude.ai's document filled in where they
 * are still written <like this>. Gives {settings, changed, problem}; a
 * problem where the settings name another issuer than the domain.
 */
export function fillSettings(settings, domain) {
  const issuer = `https://${domain}`;
  const s = structuredClone(settings);
  let changed = false;
  if (typeof s.oauth !== 'object' || s.oauth === null) return { settings: s, changed, problem: `${SETTINGS} names no "oauth": the recipe is for a connection through OAuth. Start from executor-oauth.example.json.` };
  if (unset(s.oauth.issuer)) {
    s.oauth.issuer = issuer;
    changed = true;
  } else if (s.oauth.issuer !== issuer) {
    return {
      settings: s,
      changed,
      problem: `${SETTINGS} names ${s.oauth.issuer} as "oauth.issuer", and .env names the domain ${domain}. The owner's passkey belongs to the address it was made at. To move the guard: set "oauth.issuer" to ${issuer} in ${HOST_FOLDER}/${SETTINGS}; then, with the guard stopped, run "docker compose run --rm guard owner --reset" (every connection ends) and start the guard.`,
    };
  }
  if (!Array.isArray(s.oauth.clients) || s.oauth.clients.length === 0 || s.oauth.clients.every(unset)) {
    s.oauth.clients = [CLIENT];
    changed = true;
  }
  return { settings: s, changed, problem: null };
}

/** The agents kept for a connection through OAuth, each with what it still lacks: the permission's file, the passkey's thumbprint. */
export function waiting(settings, folder) {
  const out = [];
  for (const [name, agent] of Object.entries(settings.agents ?? {})) {
    if (agent?.oauth !== true) continue;
    const slip = typeof agent.slip === 'string' ? agent.slip : `slips/${name}.json`;
    const lacks = [];
    if (!existsSync(resolve(folder, slip))) lacks.push('slip');
    if (!Array.isArray(agent.issuerKeys) || agent.issuerKeys.length === 0 || agent.issuerKeys.some(unset)) lacks.push('thumbprint');
    if (lacks.length) out.push({ name, slip, lacks });
  }
  return out;
}

/**
 * The agents that wait for their permission and that the file of entries
 * does not name, or whose key file is not there: an agent added to the
 * settings after the first start (X351). Their entries are made again.
 */
export function unlisted(settings, folder, agents) {
  let listed = {};
  try {
    listed = JSON.parse(readFileSync(join(folder, ENTRIES), 'utf8'));
  } catch {
    listed = {};
  }
  return agents.filter((a) => a.lacks.includes('slip')).map((a) => a.name).filter((name) => {
    const keys = settings.agents?.[name]?.keys;
    return !Object.hasOwn(listed ?? {}, name) || (typeof keys === 'string' && !existsSync(resolve(folder, keys)));
  });
}

/** What the business does next, for the agents that wait. */
export function nextSteps(settings, agents) {
  const actions = [...new Set(Object.values(settings.tools ?? {}).map((t) => t?.action).filter((a) => typeof a === 'string'))];
  const lines = [`The guard is set up for ${settings.oauth.issuer}, and waits for the permission. On the server, in the folder of compose.yaml:`];
  lines.push(`  1. Read what the permission must hold: sudo cat ${HOST_FOLDER}/${ENTRIES}`);
  for (const a of agents) {
    lines.push(`  For the agent "${a.name}":`);
    if (a.lacks.includes('slip')) {
      lines.push(`  2. The person who answers for the guard signs a permission with their passkey, at https://sign.prova.red, for the agent "${a.name}" and the actions ${actions.join(' and ') || '(those of "tools")'}, holding the entries of "${a.name}" in that file: its "agent" as the agent, the "with" entry in "with", and "requires" as it is.`);
      lines.push(`  3. Put the signed permission on the server, owned by the guard's user: sudo install -o ${GUARD_USER} -g ${GUARD_USER} -m 600 ${a.name}.json ${HOST_FOLDER}/${a.slip}`);
    }
    if (a.lacks.includes('thumbprint')) lines.push(`  4. In ${HOST_FOLDER}/${SETTINGS}, under agents."${a.name}".issuerKeys, put the thumbprint of the passkey that signed it in place of the value written <like this> (sudo nano ${HOST_FOLDER}/${SETTINGS}).`);
  }
  lines.push(`The guard looks again every ${Math.round(WAIT / 1000)} seconds, and goes on by itself.`);
  return lines.join('\n');
}

/** "folders": each "<folder>=<uid>:<gid>" made the user's, mode 700. Only the folder itself; what is in it is left as it is. */
export function giveFolders(specs) {
  if (specs.length === 0) throw new Error('folders takes one or more <folder>=<uid>:<gid>.');
  for (const spec of specs) {
    const m = /^(\/[^=]+)=(\d+):(\d+)$/.exec(spec);
    if (!m) throw new Error(`folders: "${spec}" is not <folder>=<uid>:<gid>.`);
    const [, path, uid, gid] = m;
    const st = lstatSync(path);
    if (!st.isDirectory()) throw new Error(`folders: ${path} is not a folder.`);
    const changes = [];
    if (st.uid !== Number(uid) || st.gid !== Number(gid)) {
      chownSync(path, Number(uid), Number(gid));
      changes.push(`owner ${uid}:${gid}`);
    }
    if ((st.mode & 0o777) !== 0o700) {
      chmodSync(path, 0o700);
      changes.push('mode 700');
    }
    say(`${path}: ${changes.length ? changes.join(', ') : 'as it was'}.`);
  }
}

/** Whether the state file holds an owner, and the setup link's end. */
export function ownerState(path) {
  if (!existsSync(path)) return { owner: false, setupEnds: null };
  const state = JSON.parse(readFileSync(path, 'utf8'));
  return { owner: state.owner !== null && state.owner !== undefined, setupEnds: typeof state.setup?.expires === 'number' ? state.setup.expires : null };
}

function guard(args, { show = false } = {}) {
  return spawnSync(process.execPath, [bin(), ...args], { cwd: data(), encoding: 'utf8', stdio: ['ignore', show ? 'inherit' : 'pipe', show ? 'inherit' : 'pipe'] });
}

/** The settings, read from the data folder. */
function readSettings() {
  return JSON.parse(readFileSync(join(data(), SETTINGS), 'utf8'));
}

/** A file written whole, readable by its owner alone. */
function writePrivate(path, text) {
  writeFileSync(`${path}.new`, text, { mode: 0o600 });
  renameSync(`${path}.new`, path);
}

/** "owner" (or "owner --reset"): the link goes to owner-link.txt, mode 600; what is printed names the file, not the link. */
export function ownerLink(extra = []) {
  const r = guard(['owner', '--config', SETTINGS, ...extra]);
  if (r.stderr) process.stderr.write(r.stderr);
  if (r.status !== 0) return r.status ?? 1;
  const found = /\bhttps?:\/\/\S+\/oauth\/owner#\S+/.exec(r.stdout);
  if (!found) {
    process.stderr.write('provared-guard: the owner command printed no link, so none was written.\n');
    return 1;
  }
  writePrivate(join(data(), LINK), `${found[0]}\n`);
  process.stdout.write(r.stdout.replace(found[0], `[the link is in ${HOST_FOLDER}/${LINK}]`));
  say(`The owner's link is in ${HOST_FOLDER}/${LINK}, readable by the guard's user alone. Read it on the server with: sudo cat ${HOST_FOLDER}/${LINK}. Keep it private: whoever opens it first becomes the guard's owner. It is not written to this log.`);
  return 0;
}

const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

/** The modification times of the settings and the permissions, to see when the person has changed them. */
function marks(settings) {
  const paths = [SETTINGS, ...Object.values(settings.agents ?? {}).map((a) => a?.slip).filter((p) => typeof p === 'string')];
  return paths.map((p) => (existsSync(join(data(), p)) ? statSync(join(data(), p)).mtimeMs : 0)).join(',');
}

async function start() {
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => process.exit(0));
  const domain = checkDomain(process.env.PROVARED_DOMAIN);
  const folder = data();
  // From here until the start ends, it listens on a socket file in the data folder, which a command that writes looks
  // for before it begins: the guard's own lock belongs to the network the guard is in, and a command started while the
  // guard is still in Caddy's old network would not see it (X350). It is made before anything is written, so that a
  // command is refused while a start that Docker has just begun again is still at its first steps, too (X364).
  await markRunning();
  if (!existsSync(join(folder, SETTINGS))) {
    say(`First start: writing the settings for the demonstration's tools ("init --http --demo") in ${HOST_FOLDER}/.`);
    const r = guard(['init', '--http', '--demo']);
    if (r.status !== 0) throw new Error(`"init --http --demo" failed: ${r.stderr.trim()}`);
    // The rules are copied with the package's mode; every file here is the guard's user's alone.
    for (const f of [SETTINGS, 'content-rules.json', 'demo-token']) if (existsSync(join(folder, f))) chmodSync(join(folder, f), 0o600);
  }
  const filled = fillSettings(readSettings(), domain);
  if (filled.problem) throw new Error(filled.problem);
  if (filled.changed) {
    writePrivate(join(folder, SETTINGS), `${JSON.stringify(filled.settings, null, 2)}\n`);
    say(`Set "oauth.issuer" to https://${domain} and "oauth.clients" to claude.ai's document, in ${HOST_FOLDER}/${SETTINGS}.`);
  }
  if (!existsSync(join(folder, ENTRIES))) {
    const r = guard(['keys', '--config', SETTINGS, '--out', ENTRIES]);
    if (r.status !== 0) throw new Error(`"keys" failed: ${r.stderr.trim()}`);
    say(`Made the guard's keys and each agent's, in ${HOST_FOLDER}/keys/. What the permission must hold is in ${HOST_FOLDER}/${ENTRIES} (public keys only).`);
  } else {
    // An agent added after the first start: its key file and its entries are made, the file before kept beside (X351).
    const missing = unlisted(readSettings(), folder, waiting(readSettings(), folder));
    if (missing.length) {
      const kept = ENTRIES.replace(/\.json$/, `.before-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
      renameSync(join(folder, ENTRIES), join(folder, kept));
      const r = guard(['keys', '--config', SETTINGS, '--out', ENTRIES]);
      if (r.status !== 0) {
        renameSync(join(folder, kept), join(folder, ENTRIES));
        throw new Error(`"keys" failed: ${r.stderr.trim()}`);
      }
      say(`The agent${missing.length > 1 ? 's' : ''} ${missing.map((n) => `"${n}"`).join(', ')} had no entry in ${HOST_FOLDER}/${ENTRIES}: made the missing keys, in ${HOST_FOLDER}/keys/, and wrote the file again for every agent; the one before is ${HOST_FOLDER}/${kept}. The keys already there were kept.`);
    }
  }
  mkdirSync(join(folder, 'slips'), { recursive: true, mode: 0o700 });

  // Wait for the person's part, then for a check with no problem.
  let shown = null;
  for (;;) {
    const settings = readSettings();
    const agents = waiting(settings, folder);
    const mark = marks(settings);
    if (agents.length) {
      if (shown !== mark) say(nextSteps(settings, agents));
      shown = mark;
      await sleep(WAIT);
      continue;
    }
    // "check" again at every look, whichever file was mended (it reads local files only); its problems said once (X358).
    const r = guard(['check', '--config', SETTINGS]);
    if (r.status === 0) {
      say('"check": no problem in the settings, the keys, the permission and the credentials.');
      break;
    }
    let problems;
    try {
      problems = JSON.parse(r.stdout).problems;
    } catch {
      problems = [r.stderr.trim() || r.stdout.trim()];
    }
    const listed = problems.join('\n- ');
    if (shown !== `checked ${listed}`) say(`"check" found problems, so the guard does not start yet. Mend what is listed, in ${HOST_FOLDER}/: the guard runs "check" again every ${Math.round(WAIT / 1000)} seconds and starts once it finds none (docker compose restart guard runs it at once):\n- ${listed}`);
    shown = `checked ${listed}`;
    await sleep(WAIT);
  }

  // The owner's link, made while the guard is not running (it holds the state file).
  const statePath = resolve(folder, readSettings().oauth.state ?? 'oauth-state.json');
  const state = ownerState(statePath);
  const linkPath = join(folder, LINK);
  if (state.owner) {
    if (existsSync(linkPath)) {
      rmSync(linkPath);
      say(`The guard has an owner, so ${HOST_FOLDER}/${LINK}, of no more use, was taken away.`);
    }
  } else if (existsSync(linkPath) && state.setupEnds !== null && state.setupEnds - Date.now() > LINK_MARGIN) {
    say(`The guard has no owner yet. The owner's link in ${HOST_FOLDER}/${LINK} still works, until ${new Date(state.setupEnds).toISOString()}: read it with sudo cat ${HOST_FOLDER}/${LINK}. Once that time has passed, "docker compose restart guard" writes a new one.`);
  } else {
    const code = ownerLink();
    if (code !== 0) throw new Error('The owner\'s link could not be made.');
    say('Once the link\'s time has passed, "docker compose restart guard" writes a new one.');
  }

  // The guard itself, until it is stopped.
  say(`Starting the guard. claude.ai's custom connector is to be added with the address https://${domain}${readSettings().path ?? '/mcp'}.`);
  const child = spawn(process.execPath, [bin(), 'http', '--config', SETTINGS], { cwd: folder, stdio: 'inherit' });
  let lost = false;
  for (const signal of ['SIGTERM', 'SIGINT']) {
    process.removeAllListeners(signal);
    process.on(signal, () => child.kill(signal));
  }
  child.on('exit', (code, signal) => process.exit(lost ? 1 : (code ?? (signal ? 1 : 0))));
  watchPeer(() => {
    lost = true;
    child.kill('SIGTERM');
  });
}

/**
 * Listen on the socket file RUNNING in the data folder, for as long as this
 * program runs. A file left by a guard that ended is replaced: nothing
 * answers at it. The operating system closes the listener however the
 * program ends.
 */
export async function markRunning() {
  const path = runningPath();
  if (process.platform !== 'win32') rmSync(path, { force: true });
  const server = net.createServer((socket) => socket.destroy());
  await new Promise((done, fail) => {
    server.once('error', fail);
    server.listen(path, done);
  });
  if (process.platform !== 'win32') chmodSync(path, 0o600);
  server.unref();
  return server;
}

/** Where the mark is: the socket file in the data folder; on Windows, where the recipe's tests run, a named pipe named after it. */
function runningPath() {
  const path = join(data(), RUNNING);
  return process.platform === 'win32' ? `\\\\.\\pipe\\provared-guard-${createHash('sha256').update(path.toLowerCase()).digest('hex')}` : path;
}

/**
 * Whether a guard is running on this data folder, by the socket file
 * RUNNING, whichever network it is in: true where something answers there,
 * or does not say within 2 seconds that nothing does; false where there is
 * no such file, or nothing listens at it.
 */
export function guardRunning() {
  const path = runningPath();
  if (process.platform !== 'win32' && !existsSync(path)) return Promise.resolve(false);
  return new Promise((done) => {
    const socket = net.connect(path);
    const end = (running) => {
      socket.destroy();
      done(running);
    };
    socket.setTimeout(2000, () => end(true));
    socket.once('connect', () => end(true));
    socket.once('error', (e) => end(!['ENOENT', 'ECONNREFUSED'].includes(e.code)));
  });
}

/** Whether a command opens the books or the state file to write them, which only one program may do at a time. */
export const writes = (command, rest) => ['owner', 'http', 'stdio'].includes(command) || rest.includes('--offline');

/** What a command that writes is told where the guard is running. */
export const RUNNING_WORDS = `The guard is running on these files (its start answers at ${HOST_FOLDER}/${RUNNING}), and this command writes them, which only one program may do at a time. Stop the guard first (docker compose stop guard), run the command, then start it again (docker compose start guard).`;

/**
 * The guard shares Caddy's network. Where Caddy's container is restarted on
 * its own, Caddy has a new network and the guard is left in the old one,
 * where nothing reaches it. So the start looks for Caddy's port in the
 * network it has (PROVARED_PEER, 127.0.0.1:443; empty, not at all), and
 * where it has not answered PEER_TRIES times in a row, stops the guard (each
 * call in flight settled and receipted, as at any stop) and ends with code
 * 1: Docker then starts the guard again, in Caddy's network as it now is.
 */
export function watchPeer(onLost, { peer = process.env.PROVARED_PEER ?? '127.0.0.1:443', every = Number(process.env.PROVARED_PEER_EVERY_MS ?? 5_000), tries = 3 } = {}) {
  if (!peer) return null;
  const at = peer.lastIndexOf(':');
  const host = peer.slice(0, at);
  const port = Number(peer.slice(at + 1));
  let missed = 0;
  const timer = setInterval(() => {
    const socket = net.connect({ host, port });
    const done = (answered) => {
      socket.destroy();
      missed = answered ? 0 : missed + 1;
      if (missed === tries) {
        clearInterval(timer);
        say(`Caddy's port (${peer}) has not answered in this network ${tries} times in a row: Caddy's container was started again on its own, in a network of its own. The guard stops, so that Docker starts it again in Caddy's network.`);
        onLost();
      }
    };
    socket.setTimeout(3000, () => done(false));
    socket.once('connect', () => done(true));
    socket.once('error', () => done(false));
  }, every);
  timer.unref();
  return timer;
}

async function main(args) {
  // Every file the start or a command writes is the writer's alone, as the start's own always were.
  process.umask(0o077);
  const [command, ...rest] = args;
  if (command === undefined) return start();
  if (command === 'folders') return giveFolders(rest);
  // A command that writes is refused while the guard runs, in whichever network it is (X350).
  if (writes(command, rest) && (await guardRunning())) {
    process.stderr.write(`provared-guard: ${RUNNING_WORDS}\n`);
    process.exitCode = 2;
    return;
  }
  if (command === 'owner') {
    const extra = rest.filter((a) => a === '--reset');
    if (extra.length !== rest.length) throw new Error('owner takes only --reset here: the settings are always executor-http.json.');
    process.exitCode = ownerLink(extra);
    return;
  }
  // "secret", "--help" and "--version" read no settings.
  const bare = command === 'secret' || command.startsWith('-') || rest.includes('--config');
  const r = guard([command, ...(bare ? [] : ['--config', SETTINGS]), ...rest], { show: true });
  process.exitCode = r.status ?? 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((e) => {
    process.stderr.write(`provared-guard: ${e.message}\n`);
    process.exitCode = 1;
  });
}
