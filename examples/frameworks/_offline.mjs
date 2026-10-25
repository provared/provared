// Nothing leaves this computer while the example runs.
//
// While the guard is open, it replaces these functions of Node.js by ones
// that refuse:
//
// - connections: net.Socket.prototype.connect (which every TCP connection
//   made through Node.js's own modules goes through, among them http,
//   https, http2 and fetch), net.connect, net.createConnection and
//   tls.connect;
// - messages sent without a connection: dgram.Socket.prototype.send and
//   dgram.Socket.prototype.connect;
// - look-ups of a name: every dns and dns.promises function whose name
//   begins "lookup", "resolve" or "reverse", and every such method of
//   dns.Resolver and dns.promises.Resolver;
// - starting a program: spawn, spawnSync, exec, execSync, execFile,
//   execFileSync and fork of child_process, and
//   child_process.ChildProcess.prototype.spawn;
// - a new thread: worker_threads.Worker (a thread has its own copies of
//   all of the above, which this guard does not reach);
// - globalThis.fetch and globalThis.WebSocket;
// - process.binding, for the bindings beneath Node.js's network, name
//   look-up and program modules (tcp_wrap, udp_wrap, pipe_wrap, tls_wrap,
//   cares_wrap, stream_wrap, process_wrap, spawn_sync).
//
// What it refused is kept in `refused`, so that a refusal which a framework
// caught and set aside still shows: the tests check that it stays empty.
//
// For the command-line run, holdOffline() opens the guard and never closes
// it, so that work the example schedules and carries out later is refused
// too. `npm start` loads _offline-whole-run.mjs with --import, which opens
// it before any other module is loaded.
//
// It guards a demonstration. It is not a sandbox for code you do not trust:
// code can still reach the network in ways it does not replace, such as a
// native add-on, or a function it kept from before the guard was opened.

import { createRequire, syncBuiltinESMExports } from 'node:module';

const require = createRequire(import.meta.url);
const net = require('node:net');
const tls = require('node:tls');
const dns = require('node:dns');
const dgram = require('node:dgram');
const childProcess = require('node:child_process');
const workerThreads = require('node:worker_threads');

/** What the guard refused while it was open. */
export const refused = [];

function refusal(what) {
  refused.push(what);
  const error = new Error(`This example sends nothing to the network: ${what} was refused.`);
  error.code = 'ECONNREFUSED';
  return error;
}

function describe(args) {
  const [first, second] = args;
  if (first !== null && typeof first === 'object') {
    if (Array.isArray(first)) return describe(first);
    return `${first.host ?? first.path ?? '?'}:${first.port ?? ''}`;
  }
  return second === undefined ? String(first) : `${second}:${first}`;
}

const connection = (a) => `a connection to ${describe(a)}`;
const lookUp = (a) => `a look-up of ${String(a[0])}`;
const DNS_NAMES = /^(lookup|resolve|reverse)/;
const names = (object) => Object.getOwnPropertyNames(object).filter((n) => DNS_NAMES.test(n) && typeof object[n] === 'function');
const LOW_BINDINGS = new Set(['tcp_wrap', 'udp_wrap', 'pipe_wrap', 'tls_wrap', 'cares_wrap', 'stream_wrap', 'process_wrap', 'spawn_sync']);

// Each entry: the object, the name of the function on it, what to call it in
// a refusal, and how it refuses: by throwing ('throw'), through a promise
// ('promise', as the real one would fail), or as a class that cannot be made
// ('class').
const replaced = [
  [net.Socket.prototype, 'connect', connection, 'throw'],
  [net, 'connect', connection, 'throw'],
  [net, 'createConnection', connection, 'throw'],
  [tls, 'connect', (a) => `a secure connection to ${describe(a)}`, 'throw'],
  [dgram.Socket.prototype, 'send', () => 'a message sent without a connection', 'throw'],
  [dgram.Socket.prototype, 'connect', () => 'a message socket connected', 'throw'],
  ...names(dns).map((n) => [dns, n, lookUp, 'throw']),
  ...names(dns.promises).map((n) => [dns.promises, n, lookUp, 'promise']),
  ...names(dns.Resolver.prototype).map((n) => [dns.Resolver.prototype, n, lookUp, 'throw']),
  ...names(dns.promises.Resolver.prototype).map((n) => [dns.promises.Resolver.prototype, n, lookUp, 'promise']),
  ...['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']
    .map((n) => [childProcess, n, () => `starting a program (child_process.${n})`, 'throw']),
  [childProcess.ChildProcess.prototype, 'spawn', () => 'starting a program (ChildProcess.prototype.spawn)', 'throw'],
  // Node.js 24 can replace the running process with another program; on Windows it is unavailable.
  ...(typeof process.execve === 'function' ? [[process, 'execve', () => 'starting a program in place of this one (process.execve)', 'throw']] : []),
  [workerThreads, 'Worker', () => 'a new thread (worker_threads.Worker)', 'class'],
  [globalThis, 'fetch', (a) => `a request to ${String(a[0]?.url ?? a[0])}`, 'promise'],
  [globalThis, 'WebSocket', (a) => `a WebSocket to ${String(a[0])}`, 'class'],
];

function refusing(words, how) {
  if (how === 'promise') return async function refusing(...args) { throw refusal(words(args)); };
  if (how === 'class') return class Refusing { constructor(...args) { throw refusal(words(args)); } };
  return function refusing(...args) { throw refusal(words(args)); };
}

let open = 0;
let held = false;
let originals = null;

function openGuard() {
  if (open++ > 0) return;
  originals = replaced.map(([object, name]) => [object, name, object[name]]);
  for (const [object, name, words, how] of replaced) object[name] = refusing(words, how);
  const binding = process.binding;
  originals.push([process, 'binding', binding]);
  process.binding = function refusingBinding(name) {
    if (LOW_BINDINGS.has(name)) throw refusal(`process.binding('${name}')`);
    return binding.call(this, name);
  };
  // So that modules that imported these functions by name get the refusing ones too.
  syncBuiltinESMExports();
}

function closeGuard() {
  if (--open > 0) return;
  for (const [object, name, original] of originals) object[name] = original;
  originals = null;
  syncBuiltinESMExports();
}

/**
 * Runs fn with the guard open, and gives what fn gives. Calls may be
 * nested; the guard closes with the outermost, unless holdOffline() has
 * been called, which keeps it open until the process ends.
 */
export async function offline(fn) {
  openGuard();
  try {
    return await fn();
  } finally {
    closeGuard();
  }
}

/** Opens the guard and keeps it open until the process ends. */
export function holdOffline() {
  if (held) return;
  held = true;
  openGuard();
}

/** Whether the guard is open. */
export function isOffline() {
  return open > 0;
}
