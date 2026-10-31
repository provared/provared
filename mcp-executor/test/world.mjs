// What the tests share: a temporary folder with key files, a slip signed
// with the library's development stand-in for a passkey that names the
// executor in "with", settings that start the made-up server
// (fake-server.mjs), the executor opened in this process on a pair of
// streams, and a small MCP client. Nothing leaves this computer.
//
// Imported with import(), after local-library.mjs.

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { assembleSlip, formatTime, prepareSlip, thumbprint } from 'provared';
import { developmentPasskey } from 'provared/dev';
import { openExecutor } from '../executor.mjs';
import { loadKeyFile, makeKeyFile } from '../files.mjs';

export const FAKE_SERVER = fileURLToPath(new URL('./fake-server.mjs', import.meta.url));

const made = [];
process.on('exit', () => {
  for (const dir of made) {
    try {
      rmSync(dir, { recursive: true, force: true, maxRetries: 3 });
    } catch {
      // Still in use: left for the computer's own clearing of its temporary folder.
    }
  }
});
export function tempFolder() {
  const dir = mkdtempSync(join(tmpdir(), 'provared-mcp-'));
  made.push(dir);
  return dir;
}

export const ACTIONS = ['provared.data.read', 'supplies.order', 'slow.work', 'tool.run'];

/** A slip for the agent's keys that names the executor in "with" with its keys, signed with the development stand-in for a passkey. */
export async function signSlip({ passkey, agentKeys, executorKeys, service = 'executor', actions = ACTIONS, limits = [], never = [], requires = [{ need: 'countersignature' }], with: services, from = Date.now() - 60000, until = Date.now() + 3600000 }) {
  const prepared = await prepareSlip({
    issuer: { name: 'Sam (development)', key: passkey.key, rpId: passkey.rpId, origin: passkey.origin },
    agent: { name: 'An agent, through the MCP executor', keys: agentKeys },
    actions,
    limits,
    requires,
    never,
    with: services ?? [{ id: service, name: 'The Provared MCP executor', keys: executorKeys }],
    validFrom: formatTime(from),
    validUntil: formatTime(until),
    purpose: 'Test the executor.',
  });
  return assembleSlip(prepared, await passkey.sign(prepared.challenge));
}

export const TOOLS = {
  echo: { action: 'provared.data.read' },
  order: { action: 'supplies.order', amount: { unit: 'GBP', pointer: '/total' } },
  slow: { action: 'slow.work' },
  crash: { action: 'tool.run' },
  fail: { action: 'tool.run' },
  error: { action: 'tool.run' },
  ask: { action: 'tool.run' },
  big: { action: 'provared.data.read' },
};

/**
 * A world: folder, keys, slip, settings. "open" opens the executor in this
 * process and attaches it to a client. Settings and the slip can be changed
 * through the options.
 */
export async function world({ slip = {}, config = {}, env = {}, open = true, more = {} } = {}) {
  const folder = tempFolder();
  mkdirSync(join(folder, 'keys'));
  const agentKeys = await makeKeyFile(join(folder, 'keys', 'agent.jwk'), 'agent');
  const executorKeys = await makeKeyFile(join(folder, 'keys', 'executor.jwk'), 'agent');
  const passkey = await developmentPasskey();
  const signed = await signSlip({ passkey, agentKeys, executorKeys, ...slip });
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(signed));
  writeFileSync(join(folder, 'token'), 'made-up-token-for-the-tests\n');
  const fakeLog = join(folder, 'fake.log');
  const settings = {
    name: 'The test executor',
    service: 'executor',
    server: { command: process.execPath, args: [FAKE_SERVER], env: { FAKE_TOKEN: { file: 'token' }, FAKE_LOG: { value: fakeLog }, ...env } },
    agent: { slip: 'slip.json', book: 'book.jsonl', keys: 'keys/agent.jwk', issuerKeys: [await thumbprint(passkey.key)] },
    executor: { keys: 'keys/executor.jwk', copy: 'copy.jsonl' },
    tools: TOOLS,
    timeout: 3000,
    shutdownWait: 1000,
    ...config,
  };
  writeFileSync(join(folder, 'executor.json'), JSON.stringify(settings));
  const w = { folder, passkey, agentKeys, executorKeys, signed, settings, fakeLog, logs: [], configPath: join(folder, 'executor.json') };
  w.fakeSeen = () => {
    let text;
    try {
      text = readFileSync(fakeLog, 'utf8');
    } catch {
      return [];
    }
    return text.split('\n').filter(Boolean).map((l) => JSON.parse(l));
  };
  w.executorPrivateKeys = async () => (await loadKeyFile(join(folder, 'keys', 'executor.jwk'), 'agent')).privateKeys;
  if (open) await openWorld(w, more);
  return w;
}

/** Open the executor on a world's settings and attach a client to it. */
export async function openWorld(w, more = {}) {
  w.logs = [];
  w.executor = await openExecutor(w.settings, { root: w.folder, log: (e) => w.logs.push(e), serverStderr: null, ...more });
  w.client = client();
  w.ended = w.executor.attach(w.client.toExecutor, w.client.fromExecutor);
  w.close = async () => {
    w.client.end();
    return w.ended;
  };
  return w;
}

/** A small MCP client on two streams: send a request and await its response by id; keep every other message. */
export function client() {
  const toExecutor = new PassThrough();
  const fromExecutor = new PassThrough();
  const waiting = new Map();
  const others = [];
  const listeners = [];
  let consumed = 0;
  let next = 1;
  let buffer = '';
  fromExecutor.setEncoding('utf8');
  fromExecutor.on('data', (chunk) => {
    buffer += chunk;
    for (;;) {
      const at = buffer.indexOf('\n');
      if (at === -1) break;
      const line = buffer.slice(0, at);
      buffer = buffer.slice(at + 1);
      let m;
      try {
        m = JSON.parse(line);
      } catch {
        m = { unreadable: line };
      }
      const key = m && (Object.hasOwn(m, 'result') || Object.hasOwn(m, 'error')) && !Object.hasOwn(m, 'method') ? `${typeof m.id}:${m.id}` : null;
      if (key && waiting.has(key)) {
        waiting.get(key)(m);
        waiting.delete(key);
      } else {
        others.push(m);
        for (const l of listeners.splice(0)) l(m);
      }
    }
  });
  return {
    toExecutor,
    fromExecutor,
    others,
    raw: (text) => toExecutor.write(text),
    send: (m) => toExecutor.write(`${JSON.stringify(m)}\n`),
    notify(method, params) {
      toExecutor.write(`${JSON.stringify({ jsonrpc: '2.0', method, ...(params ? { params } : {}) })}\n`);
    },
    /** Send a request and await its response. "id" may be given; otherwise the next number. */
    request(method, params, { id, timeout = 10000 } = {}) {
      const useId = id ?? next++;
      return new Promise((done, failed) => {
        const t = setTimeout(() => {
          waiting.delete(`${typeof useId}:${useId}`);
          failed(new Error(`No response to ${method} (id ${useId}) within ${timeout} ms.`));
        }, timeout);
        t.unref();
        waiting.set(`${typeof useId}:${useId}`, (m) => {
          clearTimeout(t);
          done(m);
        });
        toExecutor.write(`${JSON.stringify({ jsonrpc: '2.0', id: useId, method, ...(params ? { params } : {}) })}\n`);
      });
    },
    /** The next message that is not a response to a request made here. */
    nextOther(timeout = 5000) {
      if (consumed < others.length) return Promise.resolve(others[consumed++]);
      return new Promise((done, failed) => {
        const t = setTimeout(() => failed(new Error('No other message arrived.')), timeout);
        listeners.push((m) => {
          clearTimeout(t);
          consumed = others.length;
          done(m);
        });
      });
    },
    /** A tools/call with the usual _meta of the 2026-07-28 revision. */
    call(name, args, more = {}) {
      return this.request('tools/call', { name, ...(args === undefined ? {} : { arguments: args }), _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {}, ...(more.meta ?? {}) } }, more);
    },
    end: () => toExecutor.end(),
  };
}

export async function pause(ms) {
  await new Promise((d) => setTimeout(d, ms));
}

/** Wait until a condition holds, polling. */
export async function until(check, { timeout = 5000, every = 20 } = {}) {
  const deadline = Date.now() + timeout;
  for (;;) {
    const v = await check();
    if (v) return v;
    if (Date.now() > deadline) throw new Error('The condition did not come true in time.');
    await pause(every);
  }
}
