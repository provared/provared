// For tests: makes a test fail when library code opens a network
// connection or looks up a name. Loaded before every test file, with
// --import, by "npm test" and by the test workflow; test/no-network.test.mjs
// fails where it is not loaded.
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
// fetch, WebSocket and EventSource. On such a call from library code the
// call throws without connecting, the reason goes to the standard error,
// and the process's exit code is set to 1, so that node:test marks the
// test file as failed even where the library catches the error. The same
// --import is added to NODE_OPTIONS, so that a program a test starts with
// Node.js (the checker, for one) is watched too.

import dgram from 'node:dgram';
import dns from 'node:dns';
import http from 'node:http';
import http2 from 'node:http2';
import https from 'node:https';
import { syncBuiltinESMExports } from 'node:module';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

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

function install() {
  const found = [];
  // Set only by test/no-network.test.mjs, around the calls it makes on purpose.
  const state = { found, root, library: LIBRARY.map((name) => `${name}/`), quiet: false };

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
    if (!state.quiet) process.stderr.write(`${message}\n`);
    throw Object.assign(new Error(message), { code: 'PROVARED_TEST_NETWORK' });
  }

  function watchFunction(owner, name, what) {
    const original = owner?.[name];
    if (typeof original !== 'function') return;
    // A proxy, so that a class such as WebSocket can still be called with new.
    const wrapper = new Proxy(original, {
      construct(target, args, newTarget) {
        check(what);
        return Reflect.construct(target, args, newTarget);
      },
      apply(target, self, args) {
        check(what);
        return Reflect.apply(target, self, args);
      },
    });
    Object.defineProperty(owner, name, { value: wrapper, writable: true, configurable: true, enumerable: Object.getOwnPropertyDescriptor(owner, name)?.enumerable ?? false });
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
  syncBuiltinESMExports();

  const flag = `--import=${pathToFileURL(here).href}`;
  const options = process.env.NODE_OPTIONS ?? '';
  if (!options.split(/\s+/).includes(flag)) process.env.NODE_OPTIONS = options ? `${options} ${flag}` : flag;

  return state;
}

globalThis[MARK] ??= install();
