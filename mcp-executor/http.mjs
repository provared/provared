// provared-mcp-executor over HTTP: the executor as a Streamable HTTP MCP
// server (specification 2026-07-28: "each message is an HTTP POST to a
// single MCP endpoint; replies arrive as a JSON object or a request-scoped
// SSE stream") in front of one upstream HTTP MCP server, for several
// agents at once.
//
// Each agent signs in with a secret of its own (Authorization: Bearer
// <secret>, as the gateway's agents do) and has its own slip, keys, book
// and copy. The executor accepts only those secrets, removes the agent's
// Authorization header, and sends the upstream its own credential, a bearer
// token read from a file. Nothing the upstream answers reaches an agent
// with that credential in it: every byte to the client is checked for it.
//
// The rules, the check before acting, the documents, the countersignature
// and the copy are the same code as on stdio (executor.mjs, callCore): this
// file only carries messages. A tools/call is checked before anything goes
// to the upstream; every other message passes through, the answer to a
// tools/list filtered as on stdio.

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import { readFileSync } from 'node:fs';
import { unfinished } from './copy.mjs';
import { SHARED_KEYS, SHORT_NAME, UNLISTED_FORWARD_WARNING, callCore, describeContentRules, describeSlip, describeTools, filteredList, isObject, openAgent, pathFrom, prepareAgent, prepareShared, readAgentPaths, readCredentialFile, readIdentity, readKnobs, readToolRules, serverIds } from './executor.mjs';
import { CODES, MAX_LINE_BYTES, idKey, isId, readMessage, responseText, spliceId, topLevelId, unsafeInteger } from './jsonrpc.mjs';

/** The most a POST body may be, unless the settings say otherwise: 10 MiB, as the gateway takes. */
export const BODY_LIMIT = 10 * 1024 * 1024;
/** The most one answer of the upstream may be (a JSON body, or one event of a stream): 16 MiB, as one line of a stdio server. */
export const ANSWER_LIMIT = MAX_LINE_BYTES;
/** The most sessions the executor remembers; past it the oldest is forgotten, and its agent begins a new one. */
export const MAX_SESSIONS = 10000;
/** The most requests of one agent in flight at once, of every kind; tool calls are also bounded by maxWaiting. */
export const MAX_OPEN = 256;
/** The hash of a secret, as the settings hold it: SHA-256 in base64url. */
export const SECRET_HASH = /^[A-Za-z0-9_-]{43}$/;
/** What stands in place of the upstream's credential wherever it would have reached an agent. */
export const CREDENTIAL_REMOVED = '[a credential was removed by the Provared executor]';

/** The agent's headers that go on to the upstream. Every other is dropped: a header is a way to carry a token, and the upstream must get none but the executor's. */
const FORWARDED_HEADERS = ['accept', 'accept-language', 'content-type', 'mcp-session-id', 'last-event-id'];
/** The upstream's headers that come back to the agent. */
const RETURNED_HEADERS = ['content-type', 'mcp-session-id', 'mcp-protocol-version', 'cache-control'];
/** Dropped headers that are not worth a log line. */
const QUIET_HEADERS = ['host', 'connection', 'content-length', 'accept-encoding', 'user-agent', 'authorization', 'transfer-encoding', 'keep-alive', 'origin', 'mcp-protocol-version'];
const SESSION_ID = /^[\x21-\x7e]{1,512}$/;
const PROTOCOL_VERSION_META = 'io.modelcontextprotocol/protocolVersion';

/** SHA-256 of a secret, in base64url: the form the settings hold (the same as the gateway's). */
export function secretHash(secret) {
  return createHash('sha256').update(secret, 'utf8').digest('base64url');
}

/** A new secret for an agent: 32 random bytes in base64url. */
export function newSecret() {
  return randomBytes(32).toString('base64url');
}

// --- the settings ---

/**
 * Read the settings of the HTTP executor and say what is wrong with them,
 * without opening any key, slip or credential. Gives
 * {settings, problems, warnings}; "settings" is complete only where there
 * are no problems.
 */
export function readHttpSettings(config, root) {
  const problems = [];
  const warnings = [];
  const s = {};
  const at = (what, text) => problems.push(`${what}: ${text}`);
  if (!isObject(config)) return { settings: null, problems: ['The settings must be a JSON object.'], warnings };
  readIdentity(config, s, at);

  const listen = config.listen ?? {};
  if (!isObject(listen)) at('listen', 'must be an object: host, port.');
  else {
    s.listen = { host: listen.host ?? '127.0.0.1', port: listen.port ?? 8796 };
    if (typeof s.listen.host !== 'string' || s.listen.host === '') at('listen.host', 'must be the address to listen on; 127.0.0.1 unless the settings say otherwise.');
    else if (!['127.0.0.1', 'localhost', '::1'].includes(s.listen.host)) warnings.push(`listen.host: ${s.listen.host} is not the local address. Every agent that can reach that address can try secrets against the executor; keep it behind an encrypted connection.`);
    if (!Number.isInteger(s.listen.port) || s.listen.port < 0 || s.listen.port > 65535) at('listen.port', 'must be a whole number from 0 to 65535.');
  }
  s.path = config.path ?? '/mcp';
  if (typeof s.path !== 'string' || !/^\/[A-Za-z0-9._~\-/]*$/.test(s.path) || s.path.includes('//')) at('path', 'must be the path of the MCP endpoint, beginning with "/", such as "/mcp".');

  const up = config.upstream;
  if (!isObject(up)) at('upstream', 'must be an object: url, credential.');
  else {
    s.upstream = {};
    let url = null;
    try {
      url = new URL(up.url);
    } catch {
      url = null;
    }
    if (!url || !['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) at('upstream.url', 'must be the address of the upstream MCP endpoint (http or https, with no user, password or fragment).');
    else {
      s.upstream.url = url.href;
      if (url.protocol === 'http:' && !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) warnings.push(`upstream.url: ${url.href} is not encrypted and not on this computer, so the credential travels in the clear.`);
    }
    if (up.credential === undefined) {
      s.upstream.credential = null;
      warnings.push('upstream.credential: none is named, so the upstream is called with no credential of the executor\'s. The agents\' own are still removed.');
    } else if (!isObject(up.credential) || typeof up.credential.file !== 'string' || up.credential.file === '' || Object.keys(up.credential).some((k) => k !== 'file')) at('upstream.credential', 'must be {"file": <path>}: the file that holds the upstream\'s bearer token, readable by the executor alone.');
    else s.upstream.credential = { file: pathFrom(root, up.credential.file) };
    for (const k of Object.keys(up)) if (!['url', 'credential'].includes(k)) warnings.push(`upstream.${k}: not a setting; set aside.`);
  }

  s.agents = new Map();
  if (!isObject(config.agents) || Object.keys(config.agents).length === 0) at('agents', 'must be an object with one member for each agent: its secretHash, slip, book, keys, issuerKeys and, where wanted, copy and copyKey.');
  else {
    const seen = new Map();
    for (const [name, a] of Object.entries(config.agents)) {
      const prefix = `agents.${name}`;
      if (!SHORT_NAME.test(name)) {
        at(prefix, 'is not an agent name (1 to 64 lower-case letters, digits, full stops, hyphens or underscores).');
        continue;
      }
      if (!isObject(a)) {
        at(prefix, 'must be an object: secretHash, slip, book, keys, issuerKeys.');
        continue;
      }
      const paths = readAgentPaths(a, root, at, prefix);
      paths.name = name;
      if (typeof a.secretHash !== 'string' || !SECRET_HASH.test(a.secretHash)) at(`${prefix}.secretHash`, 'must be the hash of the agent\'s secret (provared-mcp-executor secret makes one).');
      else paths.secretHash = a.secretHash;
      const copy = a.copy ?? `copies/${name}.jsonl`;
      if (typeof copy !== 'string' || copy === '') at(`${prefix}.copy`, 'must be a path.');
      else paths.copy = pathFrom(root, copy);
      const copyKey = a.copyKey ?? `${copy}.key`;
      if (typeof copyKey !== 'string' || copyKey === '') at(`${prefix}.copyKey`, 'must be a path.');
      else paths.copyKey = pathFrom(root, copyKey);
      // Nothing of one agent may be another's: a shared book, copy or key would let one agent's record stand for another's.
      for (const k of ['secretHash', 'slip', 'book', 'keys', 'copy', 'copyKey']) {
        if (paths[k] === undefined) continue;
        const key = `${k}\n${paths[k]}`;
        if (seen.has(key)) at(`${prefix}.${k}`, `is also agents.${seen.get(key)}.${k}: each agent has its own.`);
        else seen.set(key, name);
      }
      for (const k of Object.keys(a)) if (!['secretHash', 'slip', 'book', 'keys', 'issuerKeys', 'copy', 'copyKey'].includes(k)) warnings.push(`${prefix}.${k}: not a setting; set aside.`);
      s.agents.set(name, paths);
    }
  }

  const ex = config.executor;
  if (!isObject(ex)) at('executor', 'must be an object: keys.');
  else {
    s.executor = {};
    if (typeof ex.keys !== 'string' || ex.keys === '') at('executor.keys', 'must be a path.');
    else s.executor.keys = pathFrom(root, ex.keys);
    for (const k of Object.keys(ex)) if (k !== 'keys') warnings.push(`executor.${k}: not a setting here (each agent has its own copy and copyKey); set aside.`);
  }

  readToolRules(config, s, at);
  readKnobs(config, s, at, root);
  s.bodyLimit = config.bodyLimit ?? BODY_LIMIT;
  if (!Number.isInteger(s.bodyLimit) || s.bodyLimit < 1024 || s.bodyLimit > 1024 * 1024 * 1024) at('bodyLimit', 'must be a whole number of bytes from 1,024 to 1,073,741,824.');
  s.allowedOrigins = config.allowedOrigins ?? [];
  if (!Array.isArray(s.allowedOrigins) || !s.allowedOrigins.every((o) => typeof o === 'string' && /^https?:\/\/[^/\s]+$/.test(o))) at('allowedOrigins', 'must be a list of origins (scheme, host and port, such as "http://localhost:3000") whose pages may call the executor; with none, a call that names an Origin is refused.');
  for (const k of Object.keys(config)) {
    if (![...SHARED_KEYS, 'listen', 'path', 'upstream', 'agents', 'executor', 'bodyLimit', 'allowedOrigins'].includes(k)) warnings.push(`${k}: not a setting; set aside.`);
  }
  if (s.unlisted === 'forward') warnings.push(UNLISTED_FORWARD_WARNING);
  return { settings: problems.length ? null : s, problems, warnings };
}

/** The upstream's credential, read once at start and held in memory. Never logged. */
function readUpstreamCredential(settings) {
  if (!settings.upstream.credential) return null;
  const token = readCredentialFile(settings.upstream.credential.file, 'upstream.credential');
  if (token === '' || /[^\x21-\x7e]/.test(token)) throw new Error('upstream.credential: the file holds no token, or one with a space, a line break or a character that cannot be sent in a header.');
  return { token, header: `Bearer ${token}` };
}

/**
 * Check the settings, the keys, each agent's slip and the credential, as a
 * start would, without listening and without writing anything.
 */
export async function checkHttpConfig(config, root) {
  const { settings, problems, warnings } = readHttpSettings(config, root);
  const tools = settings ? describeTools(settings) : [];
  if (problems.length) return { problems, warnings, tools };
  try {
    const shared = await prepareShared(settings);
    warnings.push(...shared.warnings);
    readUpstreamCredential(settings);
    const agents = {};
    for (const [name, paths] of settings.agents) {
      const p = await prepareAgent(paths, settings, shared, { readOnly: true });
      warnings.push(...p.warnings.map((w) => `agents.${name}: ${w}`));
      agents[name] = { slip: describeSlip(p.about), contentRules: describeContentRules(settings, shared.content, p.about), unfinished: unfinished(p.read).length };
    }
    return { problems: [], warnings, tools, upstream: settings.upstream.url, credential: settings.upstream.credential !== null, listen: settings.listen, path: settings.path, agents };
  } catch (e) {
    return { problems: [e.message], warnings, tools };
  }
}

// --- server-sent events ---

/**
 * A reader of a stream of server-sent events: "feed" it the text as it
 * arrives, and each whole event is handed to "onEvent" as {raw, data,
 * others}: "raw" the event's lines as they came, with their line endings
 * and the blank line that ended it; "data" the joined data lines, or null
 * where there were none; "others" the lines that are not data (event, id,
 * retry, comments). An event over "limit" characters is not read: "onTooLong"
 * is called once and the stream should be closed.
 */
export function sseReader({ onEvent, onTooLong, limit = ANSWER_LIMIT }) {
  let buffer = '';
  let lines = [];
  let raw = '';
  let over = false;
  let first = true;
  return {
    feed(text) {
      if (over) return;
      buffer += text;
      if (first) {
        first = false;
        if (buffer.startsWith('﻿')) buffer = buffer.slice(1);
      }
      for (;;) {
        const m = /\r\n|\r|\n/.exec(buffer);
        if (!m) break;
        // A lone CR at the very end may be the first half of CRLF: wait for more.
        if (m[0] === '\r' && m.index === buffer.length - 1) break;
        const line = buffer.slice(0, m.index);
        buffer = buffer.slice(m.index + m[0].length);
        if (line === '') {
          if (lines.length) {
            const data = lines.filter((l) => l.startsWith('data:') || l === 'data').map((l) => (l.startsWith('data: ') ? l.slice(6) : l.slice(5)));
            onEvent({ raw: raw + m[0], data: data.length ? data.join('\n') : null, others: lines.filter((l) => !(l.startsWith('data:') || l === 'data')) });
          }
          lines = [];
          raw = '';
          continue;
        }
        lines.push(line);
        raw += line + m[0];
      }
      if (raw.length + buffer.length > limit) {
        over = true;
        onTooLong(raw.length + buffer.length);
      }
    },
  };
}

/** One event as text: the lines that are not data as they were, then one data line, then the blank line. */
export function sseEvent(others, data) {
  return `${others.map((l) => `${l}\n`).join('')}data: ${data}\n\n`;
}

// --- the executor ---

/**
 * Open the HTTP executor on its settings: the executor's keys, each agent's
 * keys, slip, book and copy, and the upstream's credential are read now;
 * "listen" starts the server, "handle" takes one request (for tests, or a
 * server of the caller's own). Each agent's unfinished calls are given
 * their receipts now (openAgent).
 *
 * @param {object} config the settings, as in executor-http.example.json
 * @param {{root?: string, now?: () => number, log?: (event: object) => void}} [more]
 */
export async function openHttpExecutor(config, more = {}) {
  const root = more.root ?? process.cwd();
  const now = more.now ?? Date.now;
  const log = more.log ?? ((event) => process.stderr.write(`${JSON.stringify({ provared: 'mcp-executor', ...event })}\n`));
  const { settings, problems, warnings } = readHttpSettings(config, root);
  if (problems.length) throw new Error(`The settings have problems:\n- ${problems.join('\n- ')}`);
  const shared = await prepareShared(settings);
  warnings.push(...shared.warnings);
  const credential = readUpstreamCredential(settings);
  if (credential && credential.token.length < 16) warnings.push('upstream.credential: the token is shorter than 16 characters, so any text of the upstream\'s that happens to hold it is replaced on its way to an agent.');
  const agents = new Map();
  for (const [name, paths] of settings.agents) {
    const prepared = await prepareAgent(paths, settings, shared, { now });
    warnings.push(...prepared.warnings.map((w) => `agents.${name}: ${w}`));
    const agent = await openAgent(prepared, { settings, executorKeys: shared.executorKeys, now, log, name });
    agent.hash = Buffer.from(paths.secretHash);
    agent.open = 0;
    agents.set(name, agent);
  }
  for (const w of warnings) log({ event: 'warning', message: w });
  const core = callCore({ settings, content: shared.content, executorKeys: shared.executorKeys, now });
  const newServerId = serverIds();
  const upstream = new URL(settings.upstream.url);
  const lib = upstream.protocol === 'https:' ? https : http;

  /** The text with the upstream's credential taken out, wherever it stands. Everything that goes to an agent passes through here. */
  const scrub = credential ? (text) => text.split(credential.token).join(CREDENTIAL_REMOVED) : (text) => text;

  // Sessions the upstream opened (Mcp-Session-Id), each owned by the agent that opened it.
  const sessions = new Map();
  const ownSession = (id, agent) => {
    if (sessions.has(id)) return;
    sessions.set(id, agent.name);
    if (sessions.size > MAX_SESSIONS) sessions.delete(sessions.keys().next().value);
  };

  const signedIn = (header) => {
    const given = Buffer.from(secretHash(header));
    for (const agent of agents.values()) if (given.length === agent.hash.length && timingSafeEqual(given, agent.hash)) return agent;
    return null;
  };
  /** The bearer secret of a request: exactly one Authorization header, "Bearer <secret>". */
  const bearer = (req) => {
    const all = req.headersDistinct.authorization ?? [];
    if (all.length !== 1) return null;
    const m = /^Bearer ([\x21-\x7e]{1,512})$/i.exec(all[0]);
    return m ? m[1] : null;
  };

  // --- answering the agent ---

  const JSON_TYPE = 'application/json; charset=utf-8';
  const json = (res, status, text, extra = {}) => {
    if (res.headersSent || res.writableEnded) return;
    const body = Buffer.from(`${text}\n`);
    res.writeHead(status, { 'content-type': JSON_TYPE, 'content-length': body.length, 'cache-control': 'no-store', ...extra });
    res.end(body);
  };
  /** An error of the executor's own, as a JSON-RPC error under the request's id (null where none was read), with the HTTP status given. */
  const refuse = (res, status, id, code, message, extra = {}) => json(res, status, responseText(id, { error: { code, message } }), extra);

  /** The agreed headers for the upstream: the agent's few that pass, the body's protocol version, and the Mcp-Param headers that agree with the body. */
  function headersFor(req, message, body) {
    const dropped = [];
    const headers = {};
    for (const [name, values] of Object.entries(req.headersDistinct)) {
      if (FORWARDED_HEADERS.includes(name)) headers[name] = values.length === 1 ? values[0] : values;
      else if (name === 'mcp-protocol-version' || name.startsWith('mcp-param-')) continue;
      else if (!QUIET_HEADERS.includes(name) && !name.startsWith('sec-')) dropped.push(name);
    }
    const meta = isObject(message?.params) && isObject(message.params._meta) ? message.params._meta : null;
    const versions = req.headersDistinct['mcp-protocol-version'] ?? [];
    if (versions.length > 1) return { problem: 'The MCP-Protocol-Version header is given twice.' };
    const bodyVersion = meta?.[PROTOCOL_VERSION_META];
    if (bodyVersion !== undefined && typeof bodyVersion !== 'string') return { problem: `The body's _meta.${PROTOCOL_VERSION_META} must be text.` };
    if (versions.length === 1 && bodyVersion !== undefined && versions[0] !== bodyVersion) return { problem: `The MCP-Protocol-Version header (${versions[0]}) does not agree with the body's _meta.${PROTOCOL_VERSION_META} (${bodyVersion}).` };
    if (bodyVersion !== undefined) headers['mcp-protocol-version'] = bodyVersion;
    else if (versions.length === 1) headers['mcp-protocol-version'] = versions[0];
    // Mcp-Param-<name> mirrors a _meta member: it goes on only where the body holds that member with the same value.
    for (const [name, values] of Object.entries(req.headersDistinct)) {
      if (!name.startsWith('mcp-param-')) continue;
      if (!message) return { problem: `The header ${name} mirrors a member of a message's _meta, and this request carries no message.` };
      const param = name.slice('mcp-param-'.length);
      if (values.length !== 1) return { problem: `The header ${name} is given twice.` };
      const found = meta ? Object.entries(meta).find(([k, v]) => (k.toLowerCase() === param || k.slice(k.lastIndexOf('/') + 1).toLowerCase() === param) && ['string', 'number', 'boolean'].includes(typeof v) && String(v) === values[0]) : undefined;
      if (!found) return { problem: `The header ${name} does not agree with the body: no member of the message's _meta is named so with that value.` };
      headers[name] = values[0];
    }
    if (body !== undefined) {
      headers['content-type'] = 'application/json';
      headers.accept ??= 'application/json, text/event-stream';
    }
    if (credential) headers.authorization = credential.header;
    return { headers, dropped };
  }

  /**
   * One exchange with the upstream, streamed to the agent. "kind" says what
   * the agent's message was: "call" (a tools/call: the response under
   * "serverId" is the outcome, handed to "onOutcome" and not written; every
   * HTTP failure is an outcome too), "request" (any other request: the
   * response under "serverId" goes to the agent under "clientId", filtered
   * where it answers a tools/list), or "other" (a notification or a
   * response: whatever comes back is relayed). Gives {end: Promise, cancel}.
   */
  function exchange(ctx, { method, headers, body, kind, clientId, serverId, list, onOutcome }) {
    const { res, agent } = ctx;
    let finished = false;
    let settledOutcome = false;
    let timer = null;
    let req = null;
    let streaming = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      if (timer) clearTimeout(timer);
      ctx.upstream = null;
    };
    /** The outcome of a call, once. */
    const outcome = (o) => {
      if (kind !== 'call' || settledOutcome) return;
      settledOutcome = true;
      onOutcome(o);
    };
    /** End the agent's side with an error of the executor's own: a JSON-RPC error for a request; for a call the outcome speaks. */
    const fail = (status, text) => {
      finish();
      if (kind === 'call') return outcome({ kind: 'error', text, code: CODES.noAnswer });
      if (streaming) return res.end();
      refuse(res, status, kind === 'request' ? clientId : null, CODES.noAnswer, text);
    };
    const end = new Promise((done) => {
      const finishAnd = (f) => (...a) => {
        f(...a);
        done();
      };
      const fail_ = finishAnd(fail);
      try {
        // The length is of the body as sent (the executor's id spliced in), never of the agent's text.
        req = lib.request(upstream, { method, headers: body === undefined ? headers : { ...headers, 'content-length': Buffer.byteLength(body) }, agent: false });
      } catch (e) {
        fail_(502, `The executor could not send the message to the upstream (${e.code ?? 'error'}).`);
        return;
      }
      ctx.upstream = req;
      if (kind !== 'stream') {
        timer = setTimeout(() => {
          fail_(504, `The upstream gave no whole answer within ${settings.timeout} ms.`);
          req.destroy();
        }, settings.timeout);
        timer.unref();
      }
      req.on('error', (e) => {
        if (finished) return done();
        fail_(502, `The message to the upstream failed before a whole answer came (${e.code ?? 'error'}).`);
      });
      req.on('response', (up) => {
        const status = up.statusCode ?? 0;
        const type = String(up.headers['content-type'] ?? '').toLowerCase();
        const returned = {};
        for (const name of RETURNED_HEADERS) if (up.headers[name] !== undefined && typeof up.headers[name] === 'string') returned[name] = up.headers[name];
        const sessionId = up.headers['mcp-session-id'];
        if (typeof sessionId === 'string' && SESSION_ID.test(sessionId) && status < 300) ownSession(sessionId, agent);
        // Never followed: a redirection would carry the credential elsewhere. And the upstream's refusal of the executor's credential is the executor's problem, not the agent's: nothing of it is relayed.
        if (status >= 300 && status < 400) {
          req.destroy();
          agent.log({ event: 'upstream-redirect', status });
          return fail_(502, `The upstream answered with a redirection (HTTP ${status}), which the executor does not follow.`);
        }
        if (status === 401 || status === 403) {
          req.destroy();
          agent.log({ event: 'upstream-refused-credential', status });
          return fail_(502, `The upstream refused the executor's credential (HTTP ${status}).`);
        }
        if (kind === 'call' && (status < 200 || status >= 300)) {
          req.destroy();
          return fail_(502, `The upstream answered HTTP ${status} to this call, so its outcome is not known.`);
        }
        if (type.startsWith('text/event-stream')) {
          // Each event goes on as it arrives; the one that answers under the executor's id is taken.
          streaming = true;
          ctx.streaming = true;
          if (!res.headersSent) res.writeHead(status, { ...returned, 'content-type': 'text/event-stream', 'cache-control': 'no-store' });
          res.flushHeaders?.();
          const decoder = new TextDecoder('utf-8');
          const reader = sseReader({
            limit: ANSWER_LIMIT,
            onTooLong: (length) => {
              agent.log({ event: 'upstream-event-dropped', code: 'too-long', length });
              req.destroy();
              fail_(502, `The upstream sent an event longer than ${ANSWER_LIMIT} bytes, which the executor does not read.`);
            },
            onEvent: (event) => {
              if (finished) return;
              if (event.data === null) return void res.write(scrub(event.raw));
              const read = readMessage(Buffer.from(event.data), { strictNumbers: false });
              const m = read.refused ? null : read.message;
              const foundId = read.refused ? topLevelId(event.data)?.value : m?.id;
              if (serverId !== undefined && (read.kind === 'response' || (read.refused && foundId !== undefined))) {
                if (foundId === serverId) {
                  if (kind === 'call') {
                    finish();
                    req.destroy();
                    ctx.finalEvent = event.others;
                    if (read.refused) outcome({ kind: 'unreadable', text: event.data, errorText: null });
                    else if (Object.hasOwn(m, 'result')) outcome({ kind: 'answer', text: read.text, result: m.result, unsafe: unsafeInteger(read.text) !== null });
                    else outcome({ kind: 'server-error', text: read.text, errorText: `The tool server answered with an error: ${JSON.stringify(m.error)}` });
                    return done();
                  }
                  const filtered = list && m ? filteredList(read.text, m, clientId, settings) : null;
                  if (filtered?.hidden) agent.log({ event: 'tools-hidden', hidden: filtered.hidden });
                  return void res.write(scrub(sseEvent(event.others, filtered ? filtered.text : (spliceId(event.data, clientId) ?? event.data))));
                }
                if (kind === 'call') agent.log({ event: 'upstream-other-id', id: typeof foundId === 'string' ? foundId.slice(0, 80) : foundId });
              }
              res.write(scrub(event.raw));
            },
          });
          up.on('data', (chunk) => reader.feed(decoder.decode(chunk, { stream: true })));
          up.on('error', () => fail_(502, 'The upstream closed the stream before it was complete.'));
          up.on('aborted', () => fail_(502, 'The upstream closed the stream before its answer came.'));
          up.on('end', () => {
            if (finished) return done();
            finish();
            if (kind === 'call') return done(outcome({ kind: 'error', text: 'The upstream ended the stream before it answered this call, so its outcome is not known.', code: CODES.noAnswer }));
            res.end();
            done();
          });
          return;
        }
        // One JSON body, or none (202 to a notification): read whole, up to the limit.
        const chunks = [];
        let size = 0;
        up.on('data', (chunk) => {
          size += chunk.length;
          if (size > ANSWER_LIMIT) {
            req.destroy();
            return fail_(502, `The upstream's answer was larger than ${ANSWER_LIMIT} bytes, the most the executor takes.`);
          }
          chunks.push(chunk);
        });
        up.on('error', () => fail_(502, 'The upstream closed the connection before its answer was complete.'));
        up.on('aborted', () => fail_(502, 'The upstream closed the connection before its answer was complete.'));
        up.on('end', () => {
          if (finished) return done();
          if (!up.complete) return fail_(502, 'The upstream closed the connection before its answer was complete.');
          finish();
          const bytes = Buffer.concat(chunks);
          if (kind === 'other') {
            if (bytes.length === 0) {
              res.writeHead(status, returned);
              return done(res.end());
            }
            const body_ = Buffer.from(scrub(bytes.toString('utf8')));
            res.writeHead(status, { ...returned, 'content-length': body_.length });
            return done(res.end(body_));
          }
          if (bytes.length === 0) {
            if (kind === 'call') return done(outcome({ kind: 'error', text: `The upstream answered HTTP ${status} with no message to this call, so its outcome is not known.`, code: CODES.noAnswer }));
            res.writeHead(status, returned);
            return done(res.end());
          }
          const read = readMessage(bytes, { strictNumbers: false });
          let text = null;
          try {
            text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
          } catch {
            text = null;
          }
          const m = read.refused ? null : read.message;
          const foundId = read.refused ? (text === null ? undefined : topLevelId(text)?.value) : m?.id;
          if (kind === 'call') {
            if (foundId !== serverId) {
              agent.log({ event: 'upstream-other-id', id: typeof foundId === 'string' ? foundId.slice(0, 80) : (foundId ?? null) });
              return done(outcome({ kind: 'error', text: 'The upstream answered this call with a message that is not its response (another id, or no message), so its outcome is not known.', code: CODES.noAnswer }));
            }
            if (read.refused) return done(outcome({ kind: 'unreadable', text, errorText: null }));
            if (read.kind !== 'response') return done(outcome({ kind: 'error', text: 'The upstream answered this call with a message that is not a response, so its outcome is not known.', code: CODES.noAnswer }));
            if (Object.hasOwn(m, 'result')) return done(outcome({ kind: 'answer', text: read.text, result: m.result, unsafe: unsafeInteger(read.text) !== null }));
            return done(outcome({ kind: 'server-error', text: read.text, errorText: `The tool server answered with an error: ${JSON.stringify(m.error)}` }));
          }
          // A request's answer: under the client's id, filtered where it lists tools.
          let out = text ?? bytes.toString('utf8');
          if (serverId !== undefined && foundId === serverId) {
            const filtered = list && m && read.kind === 'response' ? filteredList(read.text, m, clientId, settings) : null;
            if (filtered?.hidden) agent.log({ event: 'tools-hidden', hidden: filtered.hidden });
            out = filtered ? filtered.text : (spliceId(out, clientId) ?? out);
          }
          const body_ = Buffer.from(scrub(out));
          res.writeHead(status, { ...returned, 'content-type': type || JSON_TYPE, 'content-length': body_.length });
          done(res.end(body_));
        });
      });
      if (body !== undefined) req.end(body);
      else req.end();
    });
    return {
      end,
      /** Close the stream to the upstream: the transport's cancellation. */
      cancel() {
        if (finished) return;
        finish();
        req?.destroy();
      },
    };
  }

  // --- one request ---

  /** Read the request's body, up to the limit: the bytes, or null where it is too large. */
  function readBody(req) {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > settings.bodyLimit) return Promise.resolve(null);
    return new Promise((done, failed) => {
      const chunks = [];
      let size = 0;
      let over = false;
      req.on('data', (chunk) => {
        if (over) return;
        size += chunk.length;
        if (size > settings.bodyLimit) {
          over = true;
          chunks.length = 0;
          return done(null);
        }
        chunks.push(chunk);
      });
      req.on('end', () => done(over ? null : Buffer.concat(chunks)));
      req.on('error', failed);
    });
  }

  /**
   * Handle one request, for Node.js's own server: (request, response).
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   */
  async function handle(req, res) {
    try {
      await take(req, res);
    } catch (e) {
      log({ event: 'executor-error', error: e.message });
      if (!res.headersSent) refuse(res, 500, null, CODES.notRecorded, 'The executor met something it did not expect. The message did not reach the upstream.');
      else res.destroy();
    }
  }

  async function take(req, res) {
    const path = (req.url ?? '').split('?')[0];
    if (path !== settings.path) return refuse(res, 404, null, CODES.invalidRequest, `The MCP endpoint is ${settings.path}.`);
    // A browser page's request names its Origin; none may call unless the settings name it (the transport's rule against DNS rebinding).
    const origin = req.headers.origin;
    if (origin !== undefined && !settings.allowedOrigins.includes(origin)) {
      log({ event: 'refused', code: 'origin-refused' });
      return refuse(res, 403, null, CODES.invalidRequest, 'The executor takes no request from a web page (an Origin it does not allow).', { connection: 'close' });
    }
    // Who is calling: the agent's own secret, in the one Authorization header. The secret itself is never logged.
    const secret = bearer(req);
    const agent = secret ? signedIn(secret) : null;
    if (!agent) {
      log({ event: 'not-signed-in' });
      return refuse(res, 401, null, CODES.invalidRequest, 'Sign in to the executor with your own secret, in one header: Authorization: Bearer <secret>.', { 'www-authenticate': 'Bearer' });
    }
    if (req.headers.upgrade !== undefined || req.method === 'CONNECT') return refuse(res, 400, null, CODES.invalidRequest, 'The executor takes no upgrade and no tunnel.');
    if (!['POST', 'GET', 'DELETE'].includes(req.method)) return refuse(res, 405, null, CODES.invalidRequest, 'The MCP endpoint takes POST (a message), GET (the stream of server messages) and DELETE (the end of a session).', { allow: 'POST, GET, DELETE' });
    // A session belongs to the agent that opened it.
    const sessionIds = req.headersDistinct['mcp-session-id'] ?? [];
    if (sessionIds.length > 1 || (sessionIds.length === 1 && !SESSION_ID.test(sessionIds[0]))) return refuse(res, 400, null, CODES.invalidRequest, 'The Mcp-Session-Id header must be given once, as 1 to 512 visible ASCII characters.');
    if (sessionIds.length === 1 && sessions.get(sessionIds[0]) !== agent.name) {
      agent.log({ event: 'refused', code: 'session-not-found' });
      return refuse(res, 404, null, CODES.invalidRequest, 'The session is not known to the executor, or is not this agent\'s. Begin a new one.');
    }
    if (agent.open >= MAX_OPEN) {
      agent.log({ event: 'refused', code: 'too-many-open', open: agent.open });
      return refuse(res, 503, null, CODES.notRecorded, `This agent already has ${MAX_OPEN} requests in flight, the most it may have. Try again when one has ended.`, { connection: 'close' });
    }
    agent.open += 1;
    const ctx = { req, res, agent, upstream: null, streaming: false, finalEvent: null };
    try {
      await one(ctx, sessionIds[0]);
    } finally {
      agent.open -= 1;
    }
  }

  async function one(ctx, sessionId) {
    const { req, res, agent } = ctx;
    if (req.method !== 'POST') {
      // The GET stream of server messages, or the DELETE that ends a session: no message, so no mirrored metadata to check; the same few headers go on.
      const h = headersFor(req, null, undefined);
      if (h.problem) return refuse(res, 400, null, CODES.invalidRequest, h.problem);
      if (h.dropped.length) agent.log({ event: 'headers-dropped', headers: h.dropped });
      const ex = exchange(ctx, { method: req.method, headers: h.headers, kind: req.method === 'GET' ? 'stream' : 'other' });
      res.on('close', () => ex.cancel());
      await ex.end;
      if (req.method === 'DELETE' && sessionId && res.statusCode < 300) sessions.delete(sessionId);
      return;
    }
    const type = String(req.headers['content-type'] ?? '').toLowerCase();
    if (!/^application\/json\s*(;|$)/.test(type)) return refuse(res, 415, null, CODES.invalidRequest, 'A message is sent as application/json.');
    let body;
    try {
      body = await readBody(req);
    } catch {
      return refuse(res, 400, null, CODES.invalidRequest, 'The body could not be read.');
    }
    if (body === null) {
      agent.log({ event: 'refused', code: 'body-too-large' });
      return refuse(res, 413, null, CODES.invalidRequest, `The body is larger than ${settings.bodyLimit} bytes, the most the executor takes.`, { connection: 'close' });
    }
    // One message, read strictly: a batch, a repeated name or a shape that is not a message goes no further.
    const read = readMessage(body);
    if (read.refused) {
      agent.log({ event: 'client-message-refused', code: read.refused.code });
      return refuse(res, 400, read.id, read.refused.code, read.refused.message);
    }
    const m = read.message;
    const h = headersFor(req, m, read.text);
    if (h.problem) {
      agent.log({ event: 'refused', code: 'header-mismatch' });
      return refuse(res, 400, read.kind === 'request' ? m.id : null, CODES.invalidRequest, h.problem);
    }
    if (h.dropped.length) agent.log({ event: 'headers-dropped', headers: h.dropped });

    if (read.kind === 'request') {
      if (m.method === 'tools/call') {
        const link = {
          newServerId,
          answer: (text) => {
            if (ctx.streaming) {
              if (!res.writableEnded) res.end(scrub(sseEvent(ctx.finalEvent ?? [], text)));
              return;
            }
            json(res, 200, scrub(text));
          },
          unavailable: () => null,
          send: (call, forwarded) => {
            const ex = exchange(ctx, { method: 'POST', headers: h.headers, body: JSON.stringify(forwarded), kind: 'call', serverId: call.serverId, onOutcome: (o) => call.settle?.(o) });
            ctx.exchange = ex;
            // Closing the stream to the upstream is the transport's cancellation: on the executor's timeout, the agent's closing of its stream, or its notification.
            call.cancelUpstream = ex.cancel;
            return true;
          },
          cancel: (call) => call.cancelUpstream?.(),
          forward: (id, serverId, text) => {
            const ex = exchange(ctx, { method: 'POST', headers: h.headers, body: spliceId(text, serverId) ?? text, kind: 'request', clientId: id, serverId });
            ctx.exchange = ex;
            ctx.forwarded = ex.end;
          },
          track: () => {},
          untrack: () => {},
        };
        // The call this request began, once handleCall has begun it (it does so before its first await); not one already in progress under the same id, which handleCall refuses.
        const key = idKey(m.id);
        const before = agent.calls.get(key);
        const handled = core.handleCall(agent, link, m.id, m, read.text);
        const begun = agent.calls.get(key);
        const call = begun && begun !== before ? begun : null;
        // The agent closing the response stream is its cancellation: the stream to the upstream is closed, and the outcome is not known, as on stdio.
        res.on('close', () => {
          if (res.writableFinished || !call || call.cancelled) return;
          call.cancelled = true;
          if (call.state === 'sent' && call.settle) {
            call.cancelUpstream?.();
            call.settle({ kind: 'error', text: 'The agent closed the connection while this call was with the tool server, so its outcome is not known.', code: CODES.noAnswer });
          }
        });
        await handled;
        if (ctx.forwarded) await ctx.forwarded;
        // Withdrawn before it was sent: nothing to answer but that the connection ends.
        if (!res.writableEnded && !res.headersSent && !ctx.exchange) res.end();
        return;
      }
      // Every other request goes under an id of the executor's own, and its answer comes back under the agent's.
      const serverId = newServerId();
      const ex = exchange(ctx, { method: 'POST', headers: h.headers, body: spliceId(read.text, serverId) ?? JSON.stringify({ ...m, id: serverId }), kind: 'request', clientId: m.id, serverId, list: m.method === 'tools/list' && settings.hideUnlisted });
      res.on('close', () => ex.cancel());
      await ex.end;
      return;
    }
    if (read.kind === 'notification') {
      // A request's method sent without an id would reach the upstream unchecked; only the protocol's own notifications pass.
      if (!m.method.startsWith('notifications/')) {
        agent.log({ event: 'notification-dropped', method: m.method });
        res.writeHead(202);
        return res.end();
      }
      let text = read.text;
      if (m.method === 'notifications/cancelled' && isId(m.params?.requestId)) {
        const call = agent.calls.get(idKey(m.params.requestId));
        if (call && !call.cancelled) {
          call.cancelled = true;
          if (call.state === 'sent' && call.settle) {
            call.cancelUpstream?.();
            call.settle({ kind: 'error', text: 'The agent cancelled this call while it was with the tool server, so its outcome is not known.', code: CODES.noAnswer });
          }
          // The upstream knows the call by the executor's id; its stream was closed, which is the cancellation, so nothing more goes to it.
          res.writeHead(202);
          return res.end();
        }
      }
      const ex = exchange(ctx, { method: 'POST', headers: h.headers, body: text, kind: 'other' });
      res.on('close', () => ex.cancel());
      await ex.end;
      return;
    }
    // The agent's response to a request of the upstream (a legacy session): relayed as it is.
    const ex = exchange(ctx, { method: 'POST', headers: h.headers, body: read.text, kind: 'other' });
    res.on('close', () => ex.cancel());
    await ex.end;
  }

  let server = null;
  return {
    settings,
    /** The names of the agents. */
    agents: [...agents.keys()],
    /** One agent's stub writer and copy, for tests and tools: {writer, stopped, calls}. */
    agent: (name) => {
      const a = agents.get(name);
      return a ? { writer: a.writer, stopped: a.stopped, slip: { fingerprint: a.about.fingerprint }, calls: () => a.calls.size, open: () => a.open } : null;
    },
    executorKeys: shared.executorKeys.keys,
    handle,
    /** Start listening as the settings say (or on "port", for tests). Gives {address, port}. */
    listen({ port = settings.listen.port, host = settings.listen.host } = {}) {
      if (server) throw new Error('The executor is already listening.');
      server = http.createServer({ requestTimeout: 0, headersTimeout: 60000 }, handle);
      server.on('clientError', (e, socket) => {
        if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nconnection: close\r\n\r\n');
      });
      return new Promise((done, failed) => {
        server.once('error', failed);
        server.listen(port, host, () => {
          const at = server.address();
          log({ event: 'listening', address: at.address, port: at.port, path: settings.path, upstream: settings.upstream.url, credential: credential !== null, agents: [...agents.keys()] });
          done({ address: at.address, port: at.port });
        });
      });
    },
    /** Stop listening, and let every agent's writer finish what it has. */
    async close() {
      if (server) {
        const s = server;
        server = null;
        await new Promise((done) => {
          s.close(() => done());
          s.closeAllConnections?.();
        });
      }
      for (const a of agents.values()) await a.inTurn(() => {});
    },
  };
}
