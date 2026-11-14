// What the tests share: provared-shopify started as a program of its own,
// as the guard starts it, with the made-up Shopify of fake-shopify.mjs in
// place of the real one, and a small MCP client over its standard input
// and output. Everything the program writes, on either output, is kept, so
// that a test can look through all of it.

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CLIENT_ID, CLIENT_SECRET } from './fake-shopify.mjs';

export const SERVER = join(dirname(fileURLToPath(import.meta.url)), '..', 'server.mjs');

/** The variables of this computer a program needs to run at all; nothing of the tests' own. */
function plainEnv() {
  const out = {};
  for (const name of ['PATH', 'Path', 'SYSTEMROOT', 'SystemRoot', 'TEMP', 'TMP', 'HOME', 'USERPROFILE']) {
    if (process.env[name] !== undefined) out[name] = process.env[name];
  }
  return out;
}

/** Run the program to its end with these arguments and this environment: {code, stdout, stderr}. */
export function runToEnd(args, env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [SERVER, ...args], { env: { ...plainEnv(), ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => {
      stdout += c;
    });
    child.stderr.on('data', (c) => {
      stderr += c;
    });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
    child.stdin.end();
  });
}

/**
 * Start the server against a made-up Shopify. By default the client ID and
 * the client secret are in files named in its environment; `env` adds to
 * or replaces what it is given (undefined takes a variable out).
 */
export function startServer(fake, { env = {} } = {}) {
  const folder = mkdtempSync(join(tmpdir(), 'provared-shopify-'));
  writeFileSync(join(folder, 'client-id'), `${CLIENT_ID}\n`);
  writeFileSync(join(folder, 'client-secret'), `${CLIENT_SECRET}\n`);
  const given = {
    ...plainEnv(),
    SHOPIFY_SHOP: 'made-up-store',
    SHOPIFY_TEST_ORIGIN: fake.origin,
    SHOPIFY_CLIENT_ID_FILE: join(folder, 'client-id'),
    SHOPIFY_CLIENT_SECRET_FILE: join(folder, 'client-secret'),
    ...env,
  };
  for (const name of Object.keys(given)) if (given[name] === undefined) delete given[name];
  const child = spawn(process.execPath, [SERVER], { env: given, stdio: ['pipe', 'pipe', 'pipe'] });

  let stdout = '';
  let stderr = '';
  let rest = '';
  let nextId = 1;
  const waiting = new Map();
  const unasked = []; // lines that answer no request of ours
  child.stderr.on('data', (c) => {
    stderr += c;
  });
  child.stdout.on('data', (c) => {
    stdout += c;
    rest += c;
    for (;;) {
      const at = rest.indexOf('\n');
      if (at === -1) break;
      const line = rest.slice(0, at);
      rest = rest.slice(at + 1);
      const m = JSON.parse(line);
      const resolve = waiting.get(m.id);
      if (resolve) {
        waiting.delete(m.id);
        resolve(m);
      } else unasked.push(m);
    }
  });
  const ended = new Promise((resolve) => {
    child.on('close', (code) => {
      for (const resolve of waiting.values()) resolve({ ended: true });
      rmSync(folder, { recursive: true, force: true });
      resolve(code);
    });
  });

  /** The answer that has this id. One that has not come in 20 seconds is given as {timedOut: true}, so that a test fails where it would have waited for ever. */
  function answerTo(id) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        waiting.delete(id);
        resolve({ timedOut: true });
      }, 20000);
      waiting.set(id, (m) => {
        clearTimeout(timer);
        resolve(m);
      });
    });
  }

  /** Send one request and wait for its answer. */
  function request(method, params) {
    const id = nextId++;
    const answer = answerTo(id);
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) })}\n`);
    return answer;
  }

  /** Call a tool: {text, isError, data (the text read as JSON, where it is), answer}. */
  async function call(name, args) {
    const answer = await request('tools/call', { name, arguments: args });
    const text = answer.result?.content?.[0]?.text;
    let data = null;
    try {
      data = JSON.parse(text);
    } catch {
      // A sentence, not JSON.
    }
    return { text, isError: answer.result?.isError === true, data, answer };
  }

  const server = {
    request,
    call,
    /** Write a line as it is. */
    write: (line) => child.stdin.write(`${line}\n`),
    /** Write text as it is, with no line feed added, and wait for the answer that has this id. */
    raw(id, text) {
      const answer = answerTo(id);
      child.stdin.write(text);
      return answer;
    },
    unasked,
    /** Everything the program has written so far, on both outputs. */
    output: () => stdout + stderr,
    stderr: () => stderr,
    ended,
    /** Close the program's input, as the guard does, and wait for it to end: its exit code. One that has not ended ten seconds later is ended by force. */
    async close() {
      running.delete(server);
      child.stdin.end();
      const timer = setTimeout(() => child.kill(), 10000);
      try {
        return await ended;
      } finally {
        clearTimeout(timer);
      }
    },
  };
  running.add(server);
  return server;
}

// Every server started and not yet closed, so that a test that fails
// half-way leaves none running (each test file closes them after each test).
const running = new Set();

/** Close every server still running. */
export async function closeServers() {
  for (const server of [...running]) await server.close();
}
