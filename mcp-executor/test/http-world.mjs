// What the HTTP tests share: a temporary folder with the executor's keys and,
// for each agent, its keys, its slip, its secret and its own paths; a
// made-up upstream (fake-http-server.mjs) in this process; the HTTP
// executor listening on the local address at a free port; and a small
// client that posts one message and reads the answer, as JSON or as a
// stream of events. Nothing leaves this computer.
//
// Imported with import(), after local-library.mjs.

import { mkdirSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { join } from 'node:path';
import { thumbprint } from 'provared';
import { developmentPasskey } from 'provared/dev';
import { makeKeyFile } from '../files.mjs';
import { newSecret, openHttpExecutor, secretHash } from '../http.mjs';
import { startFakeUpstream } from './fake-http-server.mjs';
import { ACTIONS, signSlip, tempFolder } from './world.mjs';

export const TOKEN = 'made-up-upstream-token-for-the-tests-0123456789';

export const HTTP_TOOLS = {
  echo: { action: 'provared.data.read' },
  order: { action: 'supplies.order', amount: { unit: 'GBP', pointer: '/total' } },
  slow: { action: 'slow.work' },
  stream: { action: 'tool.run' },
  fail: { action: 'tool.run' },
  error: { action: 'tool.run' },
  odd: { action: 'tool.run' },
};

export const META = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} };

/**
 * A world with the agents named (each with its own slip, keys, book, copy
 * and secret), the fake upstream and the executor. "config" overrides the
 * settings; "slips" gives per-agent slip options; "open" false leaves the
 * executor for the caller to open (openHttpWorld).
 */
export async function httpWorld({ agents = ['alpha', 'beta'], config = {}, slips = {}, open = true, token = TOKEN, fileToken = token, more = {} } = {}) {
  const folder = tempFolder();
  for (const d of ['keys', 'slips', 'books', 'copies', 'secrets']) mkdirSync(join(folder, d));
  const executorKeys = await makeKeyFile(join(folder, 'keys', 'executor.jwk'), 'agent');
  const passkey = await developmentPasskey();
  const issuer = await thumbprint(passkey.key);
  // The upstream expects "token"; the executor's file holds "fileToken" (the same, unless a test wants the upstream to refuse it).
  const upstream = await startFakeUpstream({ token });
  writeFileSync(join(folder, 'secrets', 'upstream'), `${fileToken}\n`);
  const w = { folder, passkey, executorKeys, upstream, agents: {}, logs: [] };
  const settingsAgents = {};
  for (const name of agents) {
    const agentKeys = await makeKeyFile(join(folder, 'keys', `${name}.jwk`), 'agent');
    const signed = await signSlip({ passkey, agentKeys, executorKeys, actions: ACTIONS, ...(slips[name] ?? {}) });
    writeFileSync(join(folder, 'slips', `${name}.json`), JSON.stringify(signed));
    const secret = newSecret();
    settingsAgents[name] = { secretHash: secretHash(secret), slip: `slips/${name}.json`, book: `books/${name}.jsonl`, keys: `keys/${name}.jwk`, issuerKeys: [issuer] };
    w.agents[name] = { name, secret, agentKeys, signed, book: join(folder, 'books', `${name}.jsonl`), copy: join(folder, 'copies', `${name}.jsonl`), copyKey: join(folder, 'copies', `${name}.jsonl.key`) };
  }
  w.settings = {
    name: 'The test HTTP executor',
    service: 'executor',
    listen: { host: '127.0.0.1', port: 0 },
    upstream: { url: token === null ? upstream.url : upstream.url, ...(token === null ? {} : { credential: { file: 'secrets/upstream' } }) },
    agents: settingsAgents,
    executor: { keys: 'keys/executor.jwk' },
    tools: HTTP_TOOLS,
    timeout: 3000,
    ...config,
  };
  w.configPath = join(folder, 'executor-http.json');
  writeFileSync(w.configPath, JSON.stringify(w.settings));
  if (open) await openHttpWorld(w, more);
  return w;
}

/** Open the executor on a world's settings and listen on a free local port. */
export async function openHttpWorld(w, more = {}) {
  w.logs = [];
  w.executor = await openHttpExecutor(w.settings, { root: w.folder, log: (e) => w.logs.push(e), ...more });
  const at = await w.executor.listen({ port: 0 });
  w.url = `http://${at.address}:${at.port}${w.settings.path ?? '/mcp'}`;
  w.address = at;
  w.close = async () => {
    await w.executor.close();
    await w.upstream.close();
  };
  w.closeExecutor = () => w.executor.close();
  return w;
}

/** The Authorization header for an agent (its name), or as given. */
export function auth(w, agent) {
  if (agent === null) return {};
  if (typeof agent === 'string' && w.agents[agent]) return { authorization: `Bearer ${w.agents[agent].secret}` };
  return { authorization: agent };
}

/**
 * One HTTP request to the executor, on a connection of its own (no
 * keep-alive, so that nothing outlives a test). "headers" is an object; a
 * value that is a list sends the header that many times. "signal" (an
 * AbortSignal) closes the connection, and the promise fails with an error
 * named AbortError. With "stream", it gives {status, headers, res} as soon
 * as the headers come, the body still to be read from "res".
 */
export function rawRequest(w, { method = 'POST', headers = {}, body, signal, stream = false } = {}) {
  return new Promise((done, failed) => {
    const u = new URL(w.url);
    const req = http.request({ host: u.hostname, port: u.port, path: u.pathname, method, agent: false });
    req.setHeader('connection', 'close');
    for (const [name, value] of Object.entries(headers)) req.setHeader(name, value);
    if (body !== undefined && !req.hasHeader('transfer-encoding')) req.setHeader('content-length', Buffer.byteLength(body));
    const aborted = Object.assign(new Error('aborted'), { name: 'AbortError' });
    signal?.addEventListener('abort', () => req.destroy(aborted));
    req.on('error', (e) => failed(e === aborted ? aborted : e));
    req.on('response', (res) => {
      const got = { status: res.statusCode, headers: new Headers(Object.entries(res.headers).filter(([, v]) => typeof v === 'string')), res };
      if (stream) return done(got);
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('error', (e) => failed(signal?.aborted ? aborted : e));
      res.on('aborted', () => failed(signal?.aborted ? aborted : new Error('the answer was cut')));
      res.on('end', () => done({ ...got, body: Buffer.concat(chunks).toString('utf8') }));
    });
    if (body !== undefined) req.end(body);
    else req.end();
  });
}

/**
 * Post one message as an agent. Gives {status, headers, body (text), json
 * (the one message, where the answer is JSON), events (where it is a
 * stream: each event's data as parsed JSON, or the text)}.
 */
export async function post(w, agent, message, { headers = {}, signal, raw } = {}) {
  const res = await rawRequest(w, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...auth(w, agent), ...headers }, body: raw ?? JSON.stringify(message), signal });
  return readAnswer(res);
}

export function readAnswer(res) {
  const type = res.headers.get('content-type') ?? '';
  const body = res.body;
  const out = { status: res.status, headers: res.headers, body, type };
  if (type.startsWith('application/json') && body.trim()) {
    try {
      out.json = JSON.parse(body);
    } catch {
      out.json = undefined;
    }
  }
  if (type.startsWith('text/event-stream')) {
    out.events = [];
    out.rawEvents = body.split(/\r?\n\r?\n/).filter((b) => b.trim() !== '');
    for (const block of out.rawEvents) {
      const data = block
        .split(/\r?\n/)
        .filter((l) => l.startsWith('data:'))
        .map((l) => l.replace(/^data: ?/, ''))
        .join('\n');
      if (data === '') continue;
      try {
        out.events.push(JSON.parse(data));
      } catch {
        out.events.push({ unreadable: data });
      }
    }
    // The response to the request, if any: the last event with a result or an error.
    out.json = out.events.findLast((e) => e && typeof e === 'object' && (Object.hasOwn(e, 'result') || Object.hasOwn(e, 'error')) && !Object.hasOwn(e, 'method'));
  }
  return out;
}

let nextId = 1;
/** A tools/call with the usual _meta of the 2026-07-28 revision, as an agent. */
export function call(w, agent, name, args, { id, meta, headers, signal } = {}) {
  const useId = id ?? nextId++;
  return post(w, agent, { jsonrpc: '2.0', id: useId, method: 'tools/call', params: { name, ...(args === undefined ? {} : { arguments: args }), _meta: { ...META, ...(meta ?? {}) } } }, { headers, signal });
}

/** A request other than a call, as an agent. */
export function request(w, agent, method, params, { id, headers } = {}) {
  const useId = id ?? nextId++;
  return post(w, agent, { jsonrpc: '2.0', id: useId, method, ...(params ? { params } : {}) }, { headers });
}

export { thumbprint };
