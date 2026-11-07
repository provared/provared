// What the HTTP tests share: a temporary folder with the executor's keys and,
// for each agent, its keys, its slip, its secret and its own paths; a
// made-up upstream (fake-http-server.mjs) in this process; the HTTP
// executor listening on the local address at a free port; and a small
// client that posts one message and reads the answer, as JSON or as a
// stream of events. Nothing leaves this computer.
//
// Imported with import(), after local-library.mjs.

import { mkdirSync, writeFileSync } from 'node:fs';
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
export async function httpWorld({ agents = ['alpha', 'beta'], config = {}, slips = {}, open = true, token = TOKEN, more = {} } = {}) {
  const folder = tempFolder();
  for (const d of ['keys', 'slips', 'books', 'copies', 'secrets']) mkdirSync(join(folder, d));
  const executorKeys = await makeKeyFile(join(folder, 'keys', 'executor.jwk'), 'agent');
  const passkey = await developmentPasskey();
  const issuer = await thumbprint(passkey.key);
  const upstream = await startFakeUpstream({ token });
  writeFileSync(join(folder, 'secrets', 'upstream'), `${token}\n`);
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
function auth(w, agent) {
  if (agent === null) return {};
  if (typeof agent === 'string' && w.agents[agent]) return { authorization: `Bearer ${w.agents[agent].secret}` };
  return { authorization: agent };
}

/**
 * Post one message as an agent. Gives {status, headers, body (text), json
 * (the one message, where the answer is JSON), events (where it is a
 * stream: each event's data as parsed JSON, or the text)}.
 */
export async function post(w, agent, message, { headers = {}, signal, raw } = {}) {
  const res = await fetch(w.url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...auth(w, agent), ...headers }, body: raw ?? JSON.stringify(message), signal });
  return readAnswer(res);
}

export async function readAnswer(res) {
  const type = res.headers.get('content-type') ?? '';
  const body = await res.text();
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
