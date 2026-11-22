// For tests: makes a test fail when library code opens a network
// connection or looks up a name. Loaded before every test file, with
// --import, by "npm test" and by the test and publish workflows; no test
// file imports it. test/no-network.test.mjs fails where it was not loaded
// that way, and where a test file imports it.
//
// Library code here is src/ and bin/. Left out by design: net/, the
// package's network code, kept apart so that src/ makes no request; page/,
// the browser pages, which load their own files; and test/, whose helpers
// start servers on this computer and talk to them. A call is judged by the
// innermost frame on its stack that is a file of this repository (this
// file aside): in src/ or bin/, it is the library's. So a hook that a test
// hands the library, or net/ code that it is handed, is judged by its own
// frame, not by the library code that called it.
//
// Watched, with Node.js's own modules only: a socket's connect (which
// net, tls, http, https and http2 all go through), http and https request
// and get, http2 connect, a UDP socket's send and connect, every name
// lookup of dns and dns/promises and of their Resolver, and the global
// fetch, WebSocket and EventSource. Also watched, from library code: one
// of those, or net.connect, net.createConnection or tls.connect, handed to
// setTimeout, setInterval, setImmediate, queueMicrotask, process.nextTick
// or a promise's then or catch (it would run later, with no library code
// on its stack); a worker started from code in a string (eval, or a data:
// URL); and process.binding of tcp_wrap, udp_wrap, tls_wrap or cares_wrap.
//
// On such a call from library code the call throws without connecting,
// the reason goes to the standard error, and the exit code is set to 1. A
// listener on the process's exit sets it to 1 again as the process ends,
// after anything the program asked for: process.exit(2) in the checker
// still ends with 1. So node:test marks the test file as failed even where
// the library catches the error. The same --import is added to
// NODE_OPTIONS, so that a program a test starts with Node.js (the checker,
// for one) is watched too, and a worker is watched as well. Each such
// program and worker also writes what it found to a file named in
// PROVARED_TEST_NO_NETWORK_INBOX by the process that started it, which
// reads the file as it ends and then ends with 1 itself: a test that
// expects the checker to end with 1 still fails.
//
// Not watched, as stated limits: a child Node.js run with code in a string
// (node -e), or with an environment that leaves out NODE_OPTIONS; a
// network function bound, wrapped or handed to any other scheduler (an
// event listener, for one) before it runs; any other built-in binding; a
// program that is not Node.js; and a program or worker stopped by force
// before it ends, whose findings are lost (its exit code is not 0).

import { randomUUID } from 'node:crypto';
import dgram from 'node:dgram';
import dns from 'node:dns';
import { appendFileSync, readFileSync, rmSync } from 'node:fs';
import http from 'node:http';
import http2 from 'node:http2';
import https from 'node:https';
import { syncBuiltinESMExports } from 'node:module';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import timers from 'node:timers';
import tls from 'node:tls';
import { fileURLToPath, pathToFileURL } from 'node:url';
import workerThreads from 'node:worker_threads';

const MARK = Symbol.for('provared.test.no-network');
const here = fileURLToPath(import.meta.url);
const root = path.resolve(path.dirname(here), '..', '..');
const LIBRARY = ['src', 'bin'];
const same = (name) => (process.platform === 'win32' ? name.toLowerCase() : name);
const rootKey = same(root + path.sep);
const hereKey = same(here);

// The file a line of a stack names, or null: "at f (file:///…/a.js:1:2)",
// "at file:///…/a.js:1:2", "at f (D:\…\a.js:1:2)" or "at f (/…/a.js:1:2)".
function fileOfLine(line) {
  const found = /^\s*at (?:.*?\()?((?:file:\/\/\/|[A-Za-z]:\\|\/)[^()]*?):\d+:\d+\)?\s*$/.exec(line);
  if (!found) return null;
  try {
    return found[1].startsWith('file:') ? fileURLToPath(found[1]) : path.resolve(found[1]);
  } catch {
    return null;
  }
}

// The library file that made the call a stack shows, or null where the
// innermost file of this repository on it is outside src/ and bin/, or
// where there is none.
export function libraryFileOf(stack) {
  for (const line of String(stack).split('\n').slice(1)) {
    const file = fileOfLine(line);
    if (file === null) continue;
    const key = same(file);
    if (key === hereKey || !key.startsWith(rootKey)) continue;
    const top = path.relative(root, file).split(path.sep)[0];
    return LIBRARY.includes(top) ? file : null;
  }
  return null;
}

// Whether this file was named by --import on the command line or in
// NODE_OPTIONS as the process started, so loaded before any test file.
function preloaded() {
  const words = [...process.execArgv, ...(process.env.NODE_OPTIONS ?? '').split(/\s+/)];
  for (let i = 0; i < words.length; i++) {
    let value = null;
    if (words[i] === '--import') value = words[i + 1];
    else if (words[i]?.startsWith('--import=')) value = words[i].slice('--import='.length);
    if (!value) continue;
    value = value.replace(/^["']|["']$/g, '');
    try {
      if (same(value.startsWith('file:') ? fileURLToPath(value) : path.resolve(value)) === hereKey) return true;
    } catch {
      // not a file this could be
    }
  }
  return false;
}

const INBOX = 'PROVARED_TEST_NO_NETWORK_INBOX';

function install() {
  const found = [];
  const loadedFirst = preloaded();
  // The file that the process which started this one reads as it ends, and
  // this process's own (none in a worker, which writes to its process's).
  const upstream = process.env[INBOX] || null;
  const inbox = workerThreads.isMainThread ? path.join(os.tmpdir(), `provared-no-network-${process.pid}-${randomUUID()}.txt`) : null;
  if (inbox !== null) process.env[INBOX] = inbox;
  // quiet is set only by test/no-network.test.mjs, around the calls it
  // makes on purpose.
  const state = { found, root, library: LIBRARY.map((name) => `${name}/`), quiet: false, preloaded: loadedFirst, inbox, libraryFileOf };

  function tell(lines) {
    if (upstream === null || lines.length === 0) return;
    try {
      appendFileSync(upstream, lines.map((line) => `${line}\n`).join(''));
    } catch {
      // the process that started this one has ended; the exit code still tells
    }
  }

  function check(what) {
    const holder = {};
    const limit = Error.stackTraceLimit;
    Error.stackTraceLimit = Infinity;
    Error.captureStackTrace(holder, check);
    Error.stackTraceLimit = limit;
    const file = libraryFileOf(holder.stack);
    if (file === null) return;
    const where = path.relative(root, file).split(path.sep).join('/');
    const message = `Library code opened the network (${what}, from ${where}). The library makes no network request; only net/ may.`;
    found.push({ what, where });
    process.exitCode = 1;
    if (!state.quiet) {
      process.stderr.write(`${message}\n`);
      tell([message]);
    }
    throw Object.assign(new Error(message), { code: 'PROVARED_TEST_NETWORK' });
  }

  // The functions that open the network, by what they are called here.
  const network = new WeakMap();

  // Wraps a function so that each call or new first asks judge, with the
  // call's arguments, what it is (null where it is nothing to watch).
  function watchCall(owner, name, judge) {
    const original = owner?.[name];
    if (typeof original !== 'function') return null;
    // A proxy, so that a class such as WebSocket can still be called with new.
    const wrapper = new Proxy(original, {
      construct(target, args, newTarget) {
        const what = judge(args);
        if (what !== null) check(what);
        return Reflect.construct(target, args, newTarget);
      },
      apply(target, self, args) {
        const what = judge(args);
        if (what !== null) check(what);
        return Reflect.apply(target, self, args);
      },
    });
    Object.defineProperty(owner, name, { value: wrapper, writable: true, configurable: true, enumerable: Object.getOwnPropertyDescriptor(owner, name)?.enumerable ?? false });
    return { original, wrapper };
  }

  function watchFunction(owner, name, what) {
    const made = watchCall(owner, name, () => what);
    if (made === null) return;
    network.set(made.original, what);
    network.set(made.wrapper, what);
  }

  // A scheduler that is handed a network function, at the given places
  // among its arguments, to call later.
  function watchHandOver(owner, name, label, places) {
    watchCall(owner, name, (args) => {
      for (const place of places) {
        const what = network.get(args[place]);
        if (what !== undefined) return `${what}, handed to ${label}`;
      }
      return null;
    });
  }

  const LOOKUPS = /^(lookup|lookupService|resolve|resolve[A-Z0-9][A-Za-z0-9]*|reverse)$/;
  function watchLookups(owner, what) {
    if (!owner) return;
    for (const name of Object.getOwnPropertyNames(owner)) {
      if (LOOKUPS.test(name)) watchFunction(owner, name, `${what}.${name}`);
    }
  }

  watchFunction(net.Socket.prototype, 'connect', 'a socket\'s connect');
  for (const [module, label] of [[http, 'http'], [https, 'https']]) {
    watchFunction(module, 'request', `${label}.request`);
    watchFunction(module, 'get', `${label}.get`);
  }
  watchFunction(http2, 'connect', 'http2.connect');
  watchFunction(dgram.Socket.prototype, 'send', 'a UDP socket\'s send');
  watchFunction(dgram.Socket.prototype, 'connect', 'a UDP socket\'s connect');
  watchLookups(dns, 'dns');
  watchLookups(dns.promises, 'dns/promises');
  watchLookups(dns.Resolver?.prototype, 'dns.Resolver');
  watchLookups(dns.promises.Resolver?.prototype, 'dns/promises Resolver');
  for (const name of ['fetch', 'WebSocket', 'EventSource']) watchFunction(globalThis, name, name);
  for (const [owner, name, what] of [[net, 'connect', 'net.connect'], [net, 'createConnection', 'net.createConnection'], [tls, 'connect', 'tls.connect']]) {
    // net.createConnection is net.connect; it keeps the first name.
    if (typeof owner[name] === 'function' && !network.has(owner[name])) network.set(owner[name], what);
  }

  for (const name of ['setTimeout', 'setInterval', 'setImmediate']) {
    watchHandOver(globalThis, name, name, [0]);
    watchHandOver(timers, name, name, [0]);
  }
  watchHandOver(globalThis, 'queueMicrotask', 'queueMicrotask', [0]);
  watchHandOver(process, 'nextTick', 'process.nextTick', [0]);
  // A promise's catch calls its then.
  watchHandOver(Promise.prototype, 'then', 'a promise\'s then', [0, 1]);

  const fromString = (args) => {
    const [where, options] = args;
    if (options?.eval === true) return 'a worker run from a string';
    if (String(where?.href ?? where).startsWith('data:')) return 'a worker run from a data: URL';
    return null;
  };
  watchCall(workerThreads, 'Worker', fromString);
  const BINDINGS = new Set(['tcp_wrap', 'udp_wrap', 'tls_wrap', 'cares_wrap']);
  watchCall(process, 'binding', ([name]) => (BINDINGS.has(name) ? `process.binding("${name}")` : null));
  syncBuiltinESMExports();

  const flag = `--import=${pathToFileURL(here).href}`;
  const options = process.env.NODE_OPTIONS ?? '';
  if (!options.split(/\s+/).includes(flag)) process.env.NODE_OPTIONS = options ? `${options} ${flag}` : flag;

  // As the process ends: what the programs and workers it started found
  // is passed on, and anything found, here or there, makes it end with 1,
  // whatever code it asked for (process.exitCode is read again after this
  // listener, even after process.exit(code)).
  if (inbox !== null) {
    process.on('exit', () => {
      let lines = [];
      try {
        lines = readFileSync(inbox, 'utf8').split('\n').filter(Boolean);
        rmSync(inbox, { force: true });
      } catch {
        // nothing was written there
      }
      if (lines.length > 0) {
        process.stderr.write(lines.map((line) => `Found in a program or worker that this process started: ${line}\n`).join(''));
        tell(lines);
      }
      if (found.length > 0 || lines.length > 0) process.exitCode = 1;
    });
  }

  return state;
}

globalThis[MARK] ??= install();
