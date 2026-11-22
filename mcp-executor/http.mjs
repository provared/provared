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
//
// In place of an upstream HTTP MCP server the settings may name a local
// program ("server", as the stdio executor's): the executor then starts one
// for each MCP session an agent begins and speaks to it over its standard
// input and output (local.mjs; DESIGN.md, section 10.1). The check, the
// documents, the countersignature and the copy are the same.
//
// Beside the MCP endpoint the executor has three addresses of its own, as
// the gateway has, for the administrator alone, who signs in with a secret
// no agent holds: GET /provared/status, POST /provared/seal and POST
// /provared/acknowledge. Nothing sent to them reaches the upstream.

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import { unfinished } from './copy.mjs';
import { EXECUTOR_STOPPED, LIST_NOT_READ, NOT_FOR_KEYS, NO_RECORDER_WARNING, SHARED_KEYS, SHORT_NAME, UNLISTED_FORWARD_WARNING, callCore, describeContentRules, describeRecorder, describeSlip, describeTools, filteredList, isObject, isPlaceholder, missingFiles, openAgent, pathFrom, placeholderProblems, prepareAgent, prepareShared, programProblems, readAgentPaths, readCredentialFile, readIdentity, readFormerKeys, readKnobs, readProgramEnvironment, readRecorderSettings, readServerSettings, readShutdownWait, readToolRules, reportFromFiles, resolveProgram, sealTimer, serverIds } from './executor.mjs';
import { CHALLENGE, identify, plainAddress } from './identity.mjs';
import { CODES, MAX_LINE_BYTES, errorAnswer, foldName, idKey, isId, misspelt, readMessage, responseText, spliceId, topLevelId, unsafeInteger } from './jsonrpc.mjs';
import { openLocalSessions, readSessionSettings } from './local.mjs';
import { LOCK_WAIT_MS, lockState } from './lock.mjs';
import { CLIENT_LIMIT, OAUTH_PATH, OAUTH_TIMEOUT, WELL_KNOWN, openFrontDoor, readOAuthSettings } from './oauth.mjs';

/** The most a POST body may be, unless the settings say otherwise: 4 MiB, the MCP TypeScript SDK's own limit. */
export const BODY_LIMIT = 4 * 1024 * 1024;
/**
 * The most bytes of bodies one agent's requests may hold at once, unless the
 * settings say otherwise (waitingBytes): 32 MiB, as the gateway's. A body is
 * counted from its first byte (or its declared length) until its request has
 * been answered, so that one agent cannot hold the executor's memory, and
 * with it every other agent's service, with requests each inside bodyLimit.
 */
export const WAITING_BYTES = 32 * 1024 * 1024;
/** The most one answer of the upstream may be (a JSON body, or one event of a stream): 16 MiB, as one line of a stdio server. */
export const ANSWER_LIMIT = MAX_LINE_BYTES;
/** The most the executor holds for an agent that is not reading its stream (res.writableLength): one answer's worth. Past it the exchange is cut. The upstream is paused as soon as the agent's connection takes no more, so this is reached only where one event nearly fills it and more follow in the same read of the upstream (X113). */
export const BACKLOG_LIMIT = ANSWER_LIMIT;
/** The most sessions the executor remembers for one agent; past it that agent's oldest is forgotten, and the agent begins a new one. The total is bounded by this times the number of agents, which the settings fix. */
export const MAX_SESSIONS = 1000;
/** The most requests of one agent in flight at once, of every kind; tool calls are also bounded by maxWaiting. */
export const MAX_OPEN = 256;
/** How long a stop waits for the calls in flight to be receipted and answered before it closes the connections. */
export const STOP_WAIT = 5000;
/** The hash of a secret, as the settings hold it: SHA-256 in base64url. */
export const SECRET_HASH = /^[A-Za-z0-9_-]{43}$/;
/** The JSON-RPC error code of the specification's HeaderMismatch: the executor's own refusal of a header that does not agree with the body, so that a client reading the body does not take the executor for a legacy server. */
export const HEADER_MISMATCH = -32020;
/** The most tools whose x-mcp-header annotations are remembered from the upstream's tools/list; past it the oldest learnt is forgotten. */
export const MAX_ANNOTATED_TOOLS = 1000;
/** What stands in place of the upstream's credential wherever it would have reached an agent. */
export const CREDENTIAL_REMOVED = '[a credential was removed by the Provared executor]';
/** The executor's own addresses, for the administrator, are this path and those under it: GET /provared/status, POST /provared/seal and POST /provared/acknowledge (the gateway's). */
export const ADMIN_PATH = '/provared';
/** The most a body sent to one of the executor's own addresses may be: 64 KiB. */
export const ADMIN_BODY_LIMIT = 64 * 1024;
/**
 * POST /provared/hello needs no secret, so anyone may ask: the most its
 * body may be (bytes), how long the body may take (milliseconds), how many
 * such questions are signed for at once, and how many of those for callers
 * at one address. A question takes a place only once its body has arrived
 * whole, so a caller who never ends a body holds none (X168).
 */
export const HELLO_BODY_LIMIT = 256;
export const HELLO_WAIT_MS = 1000;
export const HELLO_AT_ONCE = 8;
export const HELLO_PER_CALLER = 4;

/**
 * The methods of tasks (MCP 2025-11-25) the executor serves in front of an
 * upstream, where the settings allow tasks (allowTasks): each names one
 * task by params.taskId, but tasks/list, whose answer is filtered.
 */
const TASK_METHODS = ['tasks/get', 'tasks/result', 'tasks/cancel', 'tasks/list'];
/** The _meta member that ties a message to a task (MCP 2025-11-25). */
const RELATED_TASK = 'io.modelcontextprotocol/related-task';
/** The answer, under the agent's id, where the upstream's list of tasks could not be read. */
export const TASKS_NOT_READ = 'The tool server\'s list of tasks could not be read by the executor, which is to leave out of it the tasks that are not this agent\'s. So the list was not handed on.';
/** The most tasks the executor remembers for one agent; past it that agent's oldest is forgotten, and asking for it is refused. */
export const MAX_TASKS = 1000;
/** The most ids of events (of the upstream's streams) the executor remembers giving one agent, so that a Last-Event-ID it names goes on; past it the oldest is forgotten. */
export const MAX_EVENT_IDS = 1000;
/** The most requests of the upstream's own the executor remembers handing on to one agent, unanswered; past it the oldest is forgotten, and an answer to it is refused. */
export const MAX_ASKS = 1000;

/** What readBody gives where a body would take its agent past waitingBytes. */
const TOO_MUCH_HELD = Symbol('too much held');

/** The agent's headers that go on to the upstream. Every other is dropped: a header is a way to carry a token, and the upstream must get none but the executor's. */
const FORWARDED_HEADERS = ['accept', 'accept-language', 'content-type', 'mcp-session-id', 'last-event-id'];
/** The upstream's headers that come back to the agent. */
const RETURNED_HEADERS = ['content-type', 'mcp-session-id', 'mcp-protocol-version', 'cache-control'];
/** Dropped headers that are not worth a log line. */
const QUIET_HEADERS = ['host', 'connection', 'content-length', 'accept-encoding', 'user-agent', 'authorization', 'transfer-encoding', 'keep-alive', 'origin', 'mcp-protocol-version'];
const SESSION_ID = /^[\x21-\x7e]{1,512}$/;
const PROTOCOL_VERSION_META = 'io.modelcontextprotocol/protocolVersion';
/** The revisions of the specification the executor serves in front of a local program: those with Streamable HTTP and sessions. A request whose MCP-Protocol-Version names another is refused with 400, unless it is the version the session's program answered "initialize" with (X247). */
export const LOCAL_VERSIONS = Object.freeze(['2025-11-25', '2025-06-18', '2025-03-26']);
/** How a revision of the specification is written: a date. Only a header value of this form is named in the log (X287). */
const REVISION = /^\d{4}-\d{2}-\d{2}$/;
/** The member of params that Mcp-Name mirrors, for each method that has one, as the 2026-07-28 revision's table of standard request headers says (X110). */
const MIRRORED_NAME = new Map([['tools/call', 'name'], ['prompts/get', 'name'], ['resources/read', 'uri']]);
/** A number as JSON writes one (RFC 8259): no hexadecimal, no space, no "Infinity", none of what Number() would take besides. */
// eslint-disable-next-line security/detect-unsafe-regex -- no repetition inside repetition can match the same text two ways (runs of digits kept apart by a full stop and an "e" the digits cannot match), so matching takes time in step with the text.
const JSON_NUMBER = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/;

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
 * {settings, problems, warnings, partial}; "settings" is complete only
 * where there are no problems, and "partial" is what could be read. With
 * "keysOnly", the passkeys' thumbprints and the agents' secret hashes are
 * not needed (readSettings).
 */
export function readHttpSettings(config, root, { keysOnly = false } = {}) {
  const problems = [];
  const warnings = [];
  const s = {};
  const at = (what, text) => {
    if (!(keysOnly && NOT_FOR_KEYS.test(what))) problems.push(`${what}: ${text}`);
  };
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
  else if (s.path === ADMIN_PATH || s.path.startsWith(`${ADMIN_PATH}/`)) at('path', `must not be ${ADMIN_PATH} or under it: those are the executor's own addresses, for the administrator.`);
  // Signing in through OAuth (oauth.mjs): the public address, the clients' list and the state file.
  readOAuthSettings(config, root, s, at, warnings, pathFrom);
  if (s.oauth && typeof s.path === 'string' && [OAUTH_PATH, WELL_KNOWN].some((p) => s.path === p || s.path.startsWith(`${p}/`))) at('path', `must not be ${OAUTH_PATH} or ${WELL_KNOWN}, or under them: with "oauth", those are the executor's own addresses.`);

  // The administrator's secret, kept as its hash: without one, the executor's own addresses (status, seal, acknowledge) answer nothing.
  s.admin = null;
  if (config.admin !== undefined) {
    if (!isObject(config.admin) || typeof config.admin.secretHash !== 'string' || !SECRET_HASH.test(config.admin.secretHash)) at('admin.secretHash', 'must be the hash of the administrator\'s secret (provared-mcp-executor secret makes one).');
    else s.admin = { secretHash: config.admin.secretHash };
    if (isObject(config.admin)) for (const k of Object.keys(config.admin)) if (k !== 'secretHash') warnings.push(`admin.${k}: not a setting; set aside.`);
  }

  // What the executor stands in front of: an upstream HTTP MCP server ("upstream"), or a local program it starts ("server", as the stdio executor's, read by the same code), never both (X231).
  const up = config.upstream;
  const local = config.server !== undefined;
  if (local && up !== undefined) at('upstream', 'is given beside "server": the executor stands in front of one tool server, an HTTP MCP server ("upstream") or a local program it starts ("server"), never both.');
  else if (local) {
    readServerSettings(config, s, at, warnings, root, 'http');
    readShutdownWait(config, s, at);
    readSessionSettings(config, s, at, warnings);
  } else if (!isObject(up)) at('upstream', 'must be an object: url, credential. Or, for a local program the executor starts, give "server" in its place.');
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
    // Tasks: every agent reaches the upstream as one caller, so they are refused unless the settings allow them, and then each is kept to the agent whose call made it.
    s.allowTasks = config.allowTasks ?? false;
    if (typeof s.allowTasks !== 'boolean') at('allowTasks', 'must be true or false: whether agents may use tasks of the upstream (a call that asks for a task; tasks/get, tasks/result, tasks/cancel and tasks/list), each task kept to the agent whose call made it. Default false: refused.');
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
      // An agent signs in with its secret, or is a connection made through OAuth ("oauth": true), never both.
      if (a.oauth !== undefined) {
        if (a.oauth !== true) at(`${prefix}.oauth`, 'must be true: the agent is a connection made through OAuth, approved by the owner.');
        else if (a.secretHash !== undefined) at(prefix, 'has both "secretHash" and "oauth": an agent signs in one way.');
        else if (!s.oauth) at(`${prefix}.oauth`, 'needs the "oauth" settings: issuer and clients.');
        else paths.oauth = true;
      } else if (typeof a.secretHash !== 'string' || !SECRET_HASH.test(a.secretHash)) at(`${prefix}.secretHash`, 'must be the hash of the agent\'s secret (provared-mcp-executor secret makes one), or the agent "oauth": true.');
      else if (s.admin && a.secretHash === s.admin.secretHash) at(`${prefix}.secretHash`, 'is also admin.secretHash: an agent must not hold the administrator\'s secret.');
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
      for (const k of Object.keys(a)) if (!['secretHash', 'oauth', 'slip', 'book', 'keys', 'issuerKeys', 'copy', 'copyKey'].includes(k)) warnings.push(`${prefix}.${k}: not a setting; set aside.`);
      s.agents.set(name, paths);
    }
  }

  const ex = config.executor;
  if (!isObject(ex)) at('executor', 'must be an object: keys.');
  else {
    s.executor = {};
    if (typeof ex.keys !== 'string' || ex.keys === '') at('executor.keys', 'must be a path.');
    else s.executor.keys = pathFrom(root, ex.keys);
    readFormerKeys(ex, s, at, root);
    for (const k of Object.keys(ex)) if (k !== 'keys' && k !== 'formerKeys') warnings.push(`executor.${k}: not a setting here (each agent has its own copy and copyKey); set aside.`);
  }

  readToolRules(config, s, at);
  readKnobs(config, s, at, root);
  if (s.oauth) {
    // A client gives a tool call up to CLIENT_LIMIT: the executor answers first, by default (X213).
    if (config.timeout === undefined) s.timeout = OAUTH_TIMEOUT;
    else if (Number.isInteger(s.timeout) && s.timeout > CLIENT_LIMIT) warnings.push(`timeout: ${s.timeout} ms is longer than the ${CLIENT_LIMIT} ms a client gives a tool call, so a slow call may be given up by the client before the executor answers it. Its receipt is still written.`);
  }
  readRecorderSettings(config, s, at, root, warnings);
  s.bodyLimit = config.bodyLimit ?? BODY_LIMIT;
  if (!Number.isInteger(s.bodyLimit) || s.bodyLimit < 1024 || s.bodyLimit > 1024 * 1024 * 1024) at('bodyLimit', 'must be a whole number of bytes from 1,024 to 1,073,741,824.');
  s.waitingBytes = config.waitingBytes ?? WAITING_BYTES;
  if (!Number.isInteger(s.waitingBytes) || s.waitingBytes < 0 || s.waitingBytes > 1024 * 1024 * 1024) at('waitingBytes', 'must be a whole number of bytes from 0 to 1,073,741,824: the most the bodies of one agent\'s requests in flight may hold together.');
  else if (Number.isInteger(s.bodyLimit) && s.waitingBytes < s.bodyLimit) warnings.push('waitingBytes: is less than bodyLimit, so a body of the largest size the executor takes can never be held.');
  s.allowedOrigins = config.allowedOrigins ?? [];
  if (!Array.isArray(s.allowedOrigins) || !s.allowedOrigins.every((o) => typeof o === 'string' && /^https?:\/\/[^/\s]+$/.test(o))) at('allowedOrigins', 'must be a list of origins (scheme, host and port, such as "http://localhost:3000") whose pages may call the executor; with none, a call that names an Origin is refused.');
  for (const k of Object.keys(config)) {
    if (![...SHARED_KEYS, 'listen', 'path', 'upstream', 'agents', 'executor', 'bodyLimit', 'waitingBytes', 'allowedOrigins', 'admin', 'oauth', ...(local ? ['server', 'shutdownWait', 'sessions'] : ['allowTasks'])].includes(k)) warnings.push(`${k}: not a setting${['shutdownWait', 'sessions'].includes(k) ? ' without "server", a local program' : (k === 'allowTasks' ? ' in front of a local program, where each session has a program of its own and so tasks of its own' : '')}; set aside.`);
  }
  if (s.unlisted === 'forward') warnings.push(UNLISTED_FORWARD_WARNING);
  return { settings: problems.length ? null : s, problems, warnings, partial: s };
}

/** The upstream's credential, read once at start and held in memory. Never logged. */
function readUpstreamCredential(settings) {
  if (!settings.upstream?.credential) return null;
  const token = readCredentialFile(settings.upstream.credential.file, 'upstream.credential');
  if (token === '' || /[^\x21-\x7e]/.test(token)) throw new Error('upstream.credential: the file holds no token, or one with a space, a line break or a character that cannot be sent in a header.');
  return { token, header: `Bearer ${token}` };
}

/**
 * Check the settings, the keys, each agent's slip and the credential, as a
 * start would, without listening and without writing anything. As with
 * checkConfig, every problem that can be found on its own is listed in one
 * run; the slips are held against the keys and the rules only where none is.
 */
export async function checkHttpConfig(config, root) {
  const { settings, problems: found, warnings, partial } = readHttpSettings(config, root);
  const tools = settings ? describeTools(settings) : [];
  const problems = placeholderProblems(config, found);
  if (partial) {
    if (partial.upstream?.credential && !isPlaceholder(config.upstream?.credential?.file)) {
      try {
        readUpstreamCredential(partial);
      } catch (e) {
        problems.push(e.message);
      }
    }
    // A local program: its program, its folder and its credentials, as the stdio executor's "check" looks at them.
    if (partial.server) problems.push(...programProblems(config, partial, root));
    problems.push(...(await missingFiles(partial, [...(partial.agents ?? new Map())].map(([name, paths]) => [`agents.${name}`, paths]))));
  }
  if (problems.length) return { problems, warnings, tools };
  try {
    let program = null;
    if (settings.server) {
      resolveProgram(settings, root, warnings, 'http');
      program = { program: settings.server.resolved, credentials: readProgramEnvironment(settings).credentialNames, sessions: settings.sessions };
    }
    const shared = await prepareShared(settings);
    warnings.push(...shared.warnings);
    readUpstreamCredential(settings);
    const agents = {};
    for (const [name, paths] of settings.agents) {
      const p = await prepareAgent(paths, settings, shared, { readOnly: true });
      warnings.push(...p.warnings.map((w) => `agents.${name}: ${w}`));
      agents[name] = { slip: describeSlip(p.about), contentRules: describeContentRules(settings, shared.content, p.about), unfinished: unfinished(p.read).length };
    }
    if (!shared.sealer) warnings.push(NO_RECORDER_WARNING);
    if (!settings.admin) warnings.push('admin: no administrator\'s secret is named, so GET /provared/status, POST /provared/seal and POST /provared/acknowledge answer nothing; "seal", "acknowledge" and "status" then work only with --offline, on a stopped executor.');
    return { problems: [], warnings, tools, ...(program ?? { upstream: settings.upstream.url, credential: settings.upstream.credential !== null }), listen: settings.listen, path: settings.path, agents, recorder: describeRecorder(settings, shared.sealer), admin: settings.admin !== null };
  } catch (e) {
    return { problems: [e.message], warnings, tools };
  }
}

/** The "status" of an HTTP executor from its files, where it is not running to be asked (reportFromFiles): {executor, from: 'files', recorder, agents}. Nothing is written. */
export async function httpStatusFromFiles(config, root, { now = Date.now } = {}) {
  const { settings, problems } = readHttpSettings(config, root);
  if (problems.length) throw new Error(`The settings have problems:\n- ${problems.join('\n- ')}`);
  const shared = await prepareShared(settings);
  const agents = {};
  for (const [name, paths] of settings.agents) agents[name] = await reportFromFiles(paths, settings, shared, { now });
  return { executor: 'provared-mcp-executor', from: 'files', recorder: describeRecorder(settings, shared.sealer), agents };
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
    /** How many characters are held of the event not yet whole. */
    pending: () => raw.length + buffer.length,
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
 * @param {{root?: string, now?: () => number, log?: (event: object) => void, serverStderr?: NodeJS.WritableStream|null, offline?: boolean, lockWait?: number, identify?: typeof identify}} [more] "serverStderr": where the standard error of a local program goes (by default, the executor's own; null, nowhere); "lockWait": how long a start asks again for a book's lock, or the state file's, that is held, in place of LOCK_WAIT_MS (for tests); "identify": what signs a challenge sent to POST /provared/hello, in place of identity.mjs's (for tests, which make it slow)
 */
export async function openHttpExecutor(config, more = {}) {
  const root = more.root ?? process.cwd();
  const now = more.now ?? Date.now;
  const log = more.log ?? ((event) => process.stderr.write(`${JSON.stringify({ provared: 'mcp-executor', ...event })}\n`));
  const { settings, problems, warnings } = readHttpSettings(config, root);
  if (problems.length) throw new Error(`The settings have problems:\n- ${problems.join('\n- ')}`);
  const shared = await prepareShared(settings);
  warnings.push(...shared.warnings);
  // Opened to work on the files of an executor that is not running ("seal", "acknowledge" with --offline): the upstream's credential is not read, and it does not listen.
  const offline = more.offline === true;
  const credential = offline ? null : readUpstreamCredential(settings);
  // A local program ("server"): found now, and its credentials read now, as a stdio executor's start does, so that a missing one stops the start (X238).
  if (settings.server && !offline) resolveProgram(settings, root, warnings, 'http');
  const program = settings.server && !offline ? readProgramEnvironment(settings) : { env: {}, credentialNames: [] };
  if (credential && credential.token.length < 16) warnings.push('upstream.credential: the token is shorter than 16 characters, so any text of the upstream\'s that happens to hold it is replaced on its way to an agent.');
  const admin = settings.admin ? Buffer.from(settings.admin.secretHash) : null;
  // The OAuth front door (oauth.mjs), where the settings name "oauth": opened below, once every agent's lock is held.
  let door = null;
  const agents = new Map();
  /** Give up every lock taken so far: at close, and where the opening fails part-way. */
  const releases = [];
  const releaseAll = async () => {
    for (const release of releases.splice(0)) await release();
  };
  try {
    // The front door's state file is locked for this program first, before anything is read: a second executor whose settings name the same state file, with whatever agents, does not start (lock.mjs, X285). A command at work on the agents' files (offline) does not open the state file, and takes no lock for it; the command "owner", which writes it, takes the lock itself.
    // A start asks again for it as for a book's lock, for 10 seconds, while the executor before it may still be ending (X289).
    if (settings.oauth && !offline) releases.push((await lockState(settings.oauth.state, { wait: more.lockWait ?? LOCK_WAIT_MS })).release);
    for (const [name, paths] of settings.agents) {
      // Each agent's book and copy are locked for this program before anything of theirs is read (lock.mjs).
      // A start asks again for the lock for 10 seconds, while the executor before it may still be ending; a command asks once.
      const prepared = await prepareAgent(paths, settings, shared, { now, lockWait: offline ? 0 : (more.lockWait ?? LOCK_WAIT_MS) });
      releases.push(prepared.release);
      warnings.push(...prepared.warnings.map((w) => `agents.${name}: ${w}`));
      // A command at work on the files (offline) is not a start: it writes no late receipt by itself.
      const agent = await openAgent(prepared, { settings, executorKeys: shared.executorKeys, now, log, name, sealer: shared.sealer, late: !offline, formerKeys: shared.formerKeys });
      // From here the agent's own release is used: with a central sealer it first sends what the sealer lacks.
      releases[releases.length - 1] = agent.release;
      agent.hash = paths.secretHash ? Buffer.from(paths.secretHash) : null;
      agent.open = 0;
      /** The bytes of bodies this agent's requests in flight hold, being read or waiting for their answers: at most waitingBytes. */
      agent.held = 0;
      /** The bytes of the upstream's answers to this agent the executor holds, read and not yet handed on, or waiting for the agent's connection: at most waitingBytes, counted apart from the bodies. */
      agent.answers = 0;
      /** The sessions this agent opened, oldest first. */
      agent.sessions = new Set();
      /** In front of an upstream: the tasks this agent's calls made (allowTasks), and the ids of the events it was given, oldest first. */
      agent.tasks = new Set();
      agent.eventIds = new Set();
      /** In front of an upstream: the requests of the upstream's own handed on to this agent and not yet answered, by session and id, oldest first. */
      agent.asks = new Set();
      agents.set(name, agent);
    }
    // The front door's state file is read only now, with the locks held, its own among them: the command "owner" works on it under the same locks, so what it wrote is what is read, and nothing it writes later is undone. "ownerCheck" is the owner's check at its page: left out (as the command "http" leaves it), the one by the owner's passkey (owner.mjs); null, none.
    if (settings.oauth && !offline) door = openFrontDoor({ settings, now, log, ownerCheck: more.ownerCheck });
  } catch (e) {
    await releaseAll();
    throw e;
  }
  for (const w of warnings) log({ event: 'warning', message: w });
  const core = callCore({ settings, content: shared.content, executorKeys: shared.executorKeys, now });
  const newServerId = serverIds();
  const upstream = settings.upstream ? new URL(settings.upstream.url) : null;
  const lib = upstream?.protocol === 'https:' ? https : http;
  // The sessions of a local program, each with a program of its own, where the settings name "server" in place of "upstream" (local.mjs; DESIGN.md, section 10.1).
  const local = settings.server ? openLocalSessions({ settings, env: program.env, credentialNames: program.credentialNames, log, backlog: BACKLOG_LIMIT, ...(more.serverStderr === undefined ? {} : { serverStderr: more.serverStderr }) }) : null;

  /** The text with the upstream's credential taken out, wherever it stands. Everything that goes to an agent passes through here. */
  const scrub = credential ? (text) => text.split(credential.token).join(CREDENTIAL_REMOVED) : (text) => text;

  /** Set by close(): no new request is taken, no waiting call is sent, and a call with the upstream is settled as the executor's stop. */
  let stopping = false;

  // What the upstream's tools/list said of each tool's arguments: for each tool, the Mcp-Param-<name> (lower case) each x-mcp-header annotation names, and the path of the annotated property in the call's arguments. Learnt from every tools/list answer that passes, before any filtering.
  const annotations = new Map();
  const walkSchema = (schema, path, found, depth) => {
    if (!isObject(schema) || depth > 8 || found.size >= 64) return;
    if (path.length && typeof schema['x-mcp-header'] === 'string' && /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$/.test(schema['x-mcp-header'])) found.set(schema['x-mcp-header'].toLowerCase(), path);
    if (isObject(schema.properties)) for (const [key, sub] of Object.entries(schema.properties)) walkSchema(sub, [...path, key], found, depth + 1);
  };
  /** The answer, under the agent's id, where the upstream's list of tools is to be filtered and could not be read. */
  const listNotRead = (clientId) => responseText(clientId, { error: { code: CODES.internal, message: LIST_NOT_READ } });
  const learnAnnotations = (m) => {
    const tools = m?.result?.tools;
    if (!Array.isArray(tools)) return;
    for (const tool of tools) {
      if (!isObject(tool) || typeof tool.name !== 'string') continue;
      const found = new Map();
      walkSchema(tool.inputSchema, [], found, 0);
      annotations.delete(tool.name);
      annotations.set(tool.name, found);
      if (annotations.size > MAX_ANNOTATED_TOOLS) annotations.delete(annotations.keys().next().value);
    }
  };
  /** The value of a mirrored header as the body holds it: the Base64 form (=?base64?...?=) decoded, as the specification says a server must before comparing; null where it cannot be. */
  const decodeMirrored = (value) => {
    const m = /^=\?base64\?([A-Za-z0-9+/]*={0,2})\?=$/.exec(value);
    if (!m) return value;
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(m[1], 'base64'));
    } catch {
      return null;
    }
  };
  /**
   * A number's exact value as text, one text however it is written (42, 42.0
   * and 4.2e1 alike), or null where the text is not a number in JSON's form.
   * Exact, where Number() would round: a header that differs from the body
   * only past what a double holds must not pass as equal to it (X110).
   */
  const exactNumber = (text) => {
    const m = JSON_NUMBER.exec(text);
    if (!m) return null;
    const [, sign, whole, fraction = '', exponent = '0'] = m;
    const digits = (whole + fraction).replace(/^0+/, '');
    let end = digits.length;
    while (end > 0 && digits[end - 1] === '0') end -= 1;
    if (end === 0) return '0';
    return `${sign}${digits.slice(0, end)}e${Number(exponent) - fraction.length + digits.length - end}`;
  };
  /** The instance value at the exact property path in the call's arguments, or undefined. */
  const argumentAt = (args, path) => {
    let at = args;
    for (const key of path) {
      if (!isObject(at) || !Object.hasOwn(at, key)) return undefined;
      at = at[key];
    }
    return at;
  };

  // Sessions the upstream opened (Mcp-Session-Id), each owned by the agent that opened it and held to the connection made through OAuth it was begun under (null for an agent's own secret), as a local program's session is (X234). An agent past its cap loses its own oldest, never another's.
  const sessions = new Map();
  const ownSession = (id, agent, connection) => {
    if (sessions.has(id)) return;
    sessions.set(id, { agent: agent.name, connection });
    agent.sessions.add(id);
    if (agent.sessions.size > MAX_SESSIONS) {
      const oldest = agent.sessions.values().next().value;
      agent.sessions.delete(oldest);
      sessions.delete(oldest);
    }
  };
  const forgetSession = (id, agent) => {
    sessions.delete(id);
    agent.sessions.delete(id);
  };
  /** Whether the upstream's session under this id is this agent's, begun under this connection. One used under another connection than its own is forgotten: no connection of the agent's may use it after. */
  const upstreamSession = (id, agent, connection) => {
    const s = sessions.get(id);
    if (!s || s.agent !== agent.name) return false;
    if (s.connection === connection) return true;
    agent.log({ event: 'session-ended', why: 'another-connection' });
    forgetSession(id, agent);
    return false;
  };
  /**
   * Count for the request's agent what the executor holds of the upstream's
   * answer to it: "buffered", what has been read and not yet handed on, and
   * what waits for the agent's connection to take it (res.writableLength).
   * The count is in agent.answers until the response has gone: apart from
   * the bodies (agent.held), so that bodies at their budget leave room for
   * their answers, and against the same limit, waitingBytes. Gives whether
   * the agent is still within it.
   */
  const holdAnswer = (ctx, buffered = ctx.buffered ?? 0) => {
    const { res, agent } = ctx;
    ctx.buffered = buffered;
    const now = buffered + (res.destroyed || res.writableFinished ? 0 : res.writableLength);
    agent.answers += now - (ctx.answerHeld ?? 0);
    ctx.answerHeld = now;
    return agent.answers <= settings.waitingBytes;
  };
  /** The key a call in flight is held by, in front of an upstream: its session and its id where a session id is given, since an id is unique only within its session (as in front of a local program, X236); its id alone where none is. */
  const callKey = (sessionId, id) => (sessionId === undefined ? idKey(id) : `session\n${sessionId}\n${idKey(id)}`);

  // Tasks the upstream made for an agent's call (allowTasks), each held to that agent: to the upstream every agent is one caller, so nothing there keeps one agent's tasks from another. An agent past its cap loses its own oldest, never another's.
  const taskOwners = new Map();
  const ownTask = (taskId, agent) => {
    if (typeof taskId !== 'string' || taskId === '' || taskId.length > 512 || taskOwners.has(taskId)) return;
    taskOwners.set(taskId, agent.name);
    agent.tasks.add(taskId);
    if (agent.tasks.size > MAX_TASKS) {
      const oldest = agent.tasks.values().next().value;
      agent.tasks.delete(oldest);
      taskOwners.delete(oldest);
    }
  };
  /** A result that is a task's handle (CreateTaskResult: {task: {taskId, ...}}): the task is the agent's. */
  const learnTask = (result, agent) => {
    if (isObject(result) && isObject(result.task)) ownTask(result.task.taskId, agent);
  };
  /** The task a message of the upstream's names: the taskId of notifications/tasks/status, or of its _meta's related task; undefined where none. */
  const taskNamed = (m) => {
    if (!isObject(m)) return undefined;
    if (m.method === 'notifications/tasks/status' && isObject(m.params)) return m.params.taskId;
    const meta = isObject(m.params?._meta) ? m.params._meta : (isObject(m.result?._meta) ? m.result._meta : null);
    return isObject(meta?.[RELATED_TASK]) ? meta[RELATED_TASK].taskId : undefined;
  };
  /** Whether a message names a task the executor holds for another agent. */
  const othersTask = (m, agent) => {
    const owner = taskOwners.get(taskNamed(m));
    return owner !== undefined && owner !== agent.name;
  };
  /**
   * Why an agent's request about tasks is not sent on, or null where it may
   * be: without allowTasks, every method of tasks and every request that
   * asks for a task (params.task); with it, a method of tasks the executor
   * does not know, and one that names a task not this agent's. A method or
   * name in other capitals counts as itself: an upstream that reads without
   * regard to capitals would take it so.
   */
  const taskRefusal = (m, agent) => {
    const params = isObject(m.params) ? m.params : {};
    const tasksMethod = foldName(m.method).startsWith('tasks/');
    const asks = Object.keys(params).some((k) => foldName(k) === 'task');
    if (!settings.allowTasks) {
      const why = 'In front of an upstream every agent reaches it with the executor\'s one credential, as one caller, so one agent\'s task could be read or cancelled by another; the settings do not allow tasks (allowTasks).';
      if (tasksMethod) return { rpc: CODES.methodNotFound, message: `The executor does not send ${m.method.slice(0, 80)} on. ${why}` };
      if (asks) return { rpc: CODES.invalidParams, message: `This request asks for a task (params.task), which the executor does not send on. ${why}` };
      return null;
    }
    if (tasksMethod && !TASK_METHODS.includes(m.method)) return { rpc: CODES.methodNotFound, message: `${m.method.slice(0, 80)} is not a method of tasks the executor knows (${TASK_METHODS.join(', ')}), so it cannot keep it to this agent's tasks, and does not send it on.` };
    if (misspelt(params, ['task']) !== null) return { rpc: CODES.invalidParams, message: 'The params name "task" in other capitals, which two readers may read differently.' };
    if (tasksMethod && m.method !== 'tasks/list') {
      if (misspelt(params, ['taskId']) !== null) return { rpc: CODES.invalidParams, message: 'The params name "taskId" in other capitals, which two readers may read differently.' };
      if (taskOwners.get(params.taskId) !== agent.name) return { rpc: CODES.invalidParams, message: 'The task is not known to the executor, or is not this agent\'s.' };
    }
    if (othersTask(m, agent)) return { rpc: CODES.invalidParams, message: 'The message names a task that is not this agent\'s.' };
    return null;
  };
  /** A tasks/list answer with only this agent's tasks in it, under the agent's id; null where it cannot be read. */
  const filteredTasks = (text, m, clientId, agent) => {
    if (!Object.hasOwn(m, 'result') || !isObject(m.result) || !Array.isArray(m.result.tasks) || misspelt(m.result, ['tasks']) !== null) return null;
    // Read again with every number kept as the server wrote it, so that filtering changes nothing else (as filteredList does).
    let exact;
    try {
      exact = JSON.parse(text, (k, v, context) => (typeof v === 'number' ? JSON.rawJSON(context.source) : v));
    } catch {
      exact = m;
    }
    const tasks = exact.result.tasks.filter((t) => isObject(t) && typeof t.taskId === 'string' && taskOwners.get(t.taskId) === agent.name && misspelt(t, ['taskId']) === null);
    return { text: JSON.stringify({ ...exact, id: clientId, result: { ...exact.result, tasks } }), hidden: exact.result.tasks.length - tasks.length };
  };

  /** The id an event gives (its last "id:" line), or undefined. */
  const eventIdOf = (others) => {
    let id;
    for (const line of others) if (line.startsWith('id:')) id = line.slice(line.startsWith('id: ') ? 4 : 3);
    return id;
  };
  /** An event's id given to this agent: a Last-Event-ID that names it may go on. */
  const gaveEvent = (agent, id) => {
    if (id === undefined || id === '' || id.length > 512) return;
    agent.eventIds.delete(id);
    agent.eventIds.add(id);
    if (agent.eventIds.size > MAX_EVENT_IDS) agent.eventIds.delete(agent.eventIds.values().next().value);
  };
  /** A request of the upstream's own handed on to this agent, on a stream of a request of its, or of its session: its answer may come from this agent alone, under the same session, once. */
  const askedOf = (ctx, m) => {
    if (!isId(m.id)) return;
    const key = callKey(ctx.sessionId, m.id);
    ctx.agent.asks.delete(key);
    ctx.agent.asks.add(key);
    if (ctx.agent.asks.size > MAX_ASKS) ctx.agent.asks.delete(ctx.agent.asks.values().next().value);
  };

  /** Who a bearer secret signs in: {agent, token}, where "token" is null for an agent's own secret and {connection, expires} for an access token; or null. */
  const signedIn = (header) => {
    const given = Buffer.from(secretHash(header));
    for (const agent of agents.values()) if (agent.hash && given.length === agent.hash.length && timingSafeEqual(given, agent.hash)) return { agent, token: null };
    // Else an access token the front door issued, for one agent marked "oauth".
    const token = door?.agentFor(header) ?? null;
    const agent = token ? agents.get(token.agent) : null;
    return agent ? { agent, token } : null;
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
    if (res.headersSent || res.writableEnded || res.destroyed) return;
    const body = Buffer.from(`${text}\n`);
    res.writeHead(status, { 'content-type': JSON_TYPE, 'content-length': body.length, 'cache-control': 'no-store', ...extra });
    res.end(body);
  };
  /** An error of the executor's own, as a JSON-RPC error under the request's id (null where none was read), with the HTTP status given. */
  const refuse = (res, status, id, code, message, extra = {}) => json(res, status, responseText(id, { error: { code, message } }), extra);

  /**
   * The agreed headers for the upstream: the agent's few that pass, the
   * body's protocol version, and the mirrored headers of the 2026-07-28
   * revision (Mcp-Method, Mcp-Name, Mcp-Param-*) where each agrees with the
   * body (X110). A header that does not, or that cannot be checked, is a
   * problem, and nothing goes to the upstream.
   */
  function headersFor(req, message, body, agent) {
    const dropped = [];
    const headers = {};
    for (const [name, values] of Object.entries(req.headersDistinct)) {
      // Last-Event-ID asks the upstream to replay a stream after that event. To the upstream every agent is one caller, so it goes on only where it names an event the executor gave this agent, once.
      if (name === 'last-event-id' && upstream && !(values.length === 1 && agent?.eventIds.has(values[0]))) dropped.push(name);
      else if (FORWARDED_HEADERS.includes(name)) headers[name] = values.length === 1 ? values[0] : values;
      else if (name === 'mcp-protocol-version' || name === 'mcp-method' || name === 'mcp-name' || name.startsWith('mcp-param-')) continue;
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
    // The mirrored headers of the 2026-07-28 revision go on only where each agrees with the body; a mismatch, or a header the executor cannot check, stops the request (X110).
    const mirrored = Object.entries(req.headersDistinct).filter(([name]) => name === 'mcp-method' || name === 'mcp-name' || name.startsWith('mcp-param-'));
    for (const [name, values] of mirrored) {
      if (!message) return { problem: `The header ${name} mirrors a member of a message, and this request carries no message.` };
      if (values.length !== 1) return { problem: `The header ${name} is given twice.` };
      const given = decodeMirrored(values[0]);
      if (given === null) return { problem: `The header ${name} is in the Base64 form (=?base64?...?=) and cannot be decoded.` };
      if (name === 'mcp-method') {
        if (typeof message.method !== 'string') return { problem: `The header ${name} mirrors a request's method, and this message is a response.` };
        if (given !== message.method) return { problem: `The header ${name} (${given}) does not agree with the body's method (${message.method}).` };
      } else if (name === 'mcp-name') {
        const member = MIRRORED_NAME.get(message.method);
        if (!member) return { problem: `The header ${name} mirrors a member of a tools/call, resources/read or prompts/get, and this message is none of them.` };
        const bodyName = message.params?.[member];
        if (typeof bodyName !== 'string') return { problem: `The header ${name} mirrors the body's params.${member}, which this message does not have as text.` };
        if (given !== bodyName) return { problem: `The header ${name} does not agree with the body's params.${member}.` };
      } else {
        // Mcp-Param-<name> mirrors the call's argument whose inputSchema property the upstream annotated with x-mcp-header: <name>, as its tools/list said.
        const param = name.slice('mcp-param-'.length);
        if (message.method !== 'tools/call' || typeof message.params?.name !== 'string') return { problem: `The header ${name} mirrors an argument of a tools/call, and this message is not one.` };
        const path = annotations.get(message.params.name)?.get(param);
        if (!path) return { problem: `The header ${name} names no argument of the tool "${message.params.name}" that the upstream's tools/list annotates with x-mcp-header, so the executor cannot check it against the body.` };
        const value = argumentAt(message.params.arguments, path);
        const number = typeof value === 'number' ? exactNumber(String(value)) : null;
        const agrees = typeof value === 'string' ? value === given : (typeof value === 'boolean' ? String(value) === given : number !== null && number === exactNumber(given));
        if (!agrees) return { problem: `The header ${name} does not agree with the body's arguments at ${path.join('.')}.` };
      }
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
  function exchange(ctx, { method, headers, body, kind, clientId, serverId, list: listKind = null, learn, task = false, onOutcome }) {
    const { res, agent } = ctx;
    // The answer to a list that is to be filtered: a tools/list ("tools": the tools with no rule left out) or a tasks/list ("tasks": other agents' tasks left out). One that cannot be read is not handed on.
    const list = listKind === 'tasks'
      ? { filter: (text, m) => filteredTasks(text, m, clientId, agent), notRead: 'tasks-list-not-read', hidden: 'tasks-hidden', answer: () => responseText(clientId, { error: { code: CODES.internal, message: TASKS_NOT_READ } }) }
      : (listKind ? { filter: (text, m) => filteredList(text, m, clientId, settings), notRead: 'tools-list-not-read', hidden: 'tools-hidden', answer: () => listNotRead(clientId) } : null);
    /** What the response under the executor's id teaches: the upstream's annotations, from a tools/list; the task it made for this agent, from a request that asked for one. */
    const learnFrom = (m) => {
      if (learn) learnAnnotations(m);
      if (task && Object.hasOwn(m, 'result')) learnTask(m.result, agent);
    };
    let finished = false;
    let settledOutcome = false;
    let timer = null;
    let req = null;
    let streaming = false;
    /** The upstream's response, once it has come: paused while the agent is not reading. */
    let up_ = null;
    let stallTimer = null;
    let done;
    const end = new Promise((d) => {
      // At the end of the exchange, what was read of the answer is held no longer; what waits for the agent's connection still counts (waitingBytes).
      done = (v) => {
        holdAnswer(ctx, 0);
        d(v);
      };
    });
    const finishAnd = (f) => (...a) => {
      f(...a);
      done();
    };
    /** The agent's connection is not taking what the executor has waiting: the exchange is cut, since it would otherwise hold memory and a slot for ever. */
    const stalled = (why) => {
      agent.log({ event: 'agent-not-reading', kind, held: res.writableLength, reason: why });
      req?.destroy();
      fail_(502, `The agent's connection did not take what the executor had waiting (${why}), so the exchange with the upstream was cut.`);
      res.destroy();
    };
    /** Write to the agent, unless it has gone. Where the agent's connection takes no more, the upstream is paused until it drains; an agent whose connection does not fully drain within the timeout, even one reading slowly, or for which more than the limit is waiting, is cut off (X113). */
    /** What the executor holds of the upstream's answer would take this agent past waitingBytes: the exchange is cut (a JSON answer is refused, a stream closed). */
    const tooMuchHeld = () => {
      agent.log({ event: 'refused', code: 'answer-too-much-held', kind, held: agent.answers });
      req?.destroy();
      fail_(503, `The upstream's answer would take what the executor holds of answers for this agent past ${settings.waitingBytes} bytes (waitingBytes), so the exchange with the upstream was cut.`);
    };
    const toAgent = (text) => {
      if (res.destroyed || res.writableEnded || finished) return;
      if (res.writableLength > BACKLOG_LIMIT) return stalled(`more than ${BACKLOG_LIMIT} bytes waiting`);
      const taken = res.write(text);
      if (!holdAnswer(ctx)) return tooMuchHeld();
      if (taken || !up_ || stallTimer) return;
      up_.pause();
      stallTimer = setTimeout(() => stalled(`not all taken within ${settings.timeout} ms`), settings.timeout);
      stallTimer.unref();
      res.once('drain', () => {
        clearTimeout(stallTimer);
        stallTimer = null;
        if (!finished) up_.resume();
      });
    };
    const endAgent = () => {
      if (!res.destroyed && !res.writableEnded) res.end();
    };
    const finish = () => {
      if (finished) return;
      finished = true;
      if (timer) clearTimeout(timer);
      if (stallTimer) clearTimeout(stallTimer);
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
      if (streaming) return endAgent();
      refuse(res, status, kind === 'request' ? clientId : null, CODES.noAnswer, text);
    };
    const fail_ = finishAnd(fail);
    (() => {
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
        up_ = up;
        const status = up.statusCode ?? 0;
        const type = String(up.headers['content-type'] ?? '').toLowerCase();
        const returned = {};
        // The few headers that come back are scrubbed as a body is: a header is a way to carry a token too.
        for (const name of RETURNED_HEADERS) if (up.headers[name] !== undefined && typeof up.headers[name] === 'string') returned[name] = scrub(up.headers[name]);
        const sessionId = up.headers['mcp-session-id'];
        if (typeof sessionId === 'string' && SESSION_ID.test(sessionId) && status < 300) ownSession(sessionId, agent, ctx.token?.connection ?? null);
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
        // A call's answer on a non-2xx status is read whole: the specification refuses with a 4xx and a JSON-RPC error under the id (X116).
        if (type.startsWith('text/event-stream') && (kind !== 'call' || (status >= 200 && status < 300))) {
          // Each event goes on as it arrives; the one that answers under the executor's id is taken.
          streaming = true;
          ctx.streaming = true;
          if (!res.headersSent && !res.destroyed) res.writeHead(status, { ...returned, 'content-type': 'text/event-stream', 'cache-control': 'no-store' });
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
              if (event.data === null) {
                gaveEvent(agent, eventIdOf(event.others));
                return toAgent(scrub(event.raw));
              }
              const read = readMessage(Buffer.from(event.data), { strictNumbers: false });
              const m = read.refused ? null : read.message;
              // A message that names a task the executor holds for another agent (its status, or a message tied to it) is not this agent's to see: to the upstream every agent is one caller, so it may send it on any of their streams.
              if (m && othersTask(m, agent)) {
                agent.log({ event: 'event-dropped', code: 'another-agents-task' });
                return;
              }
              gaveEvent(agent, eventIdOf(event.others));
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
                  if (m && read.kind === 'response') learnFrom(m);
                  const filtered = list && m ? list.filter(read.text, m) : null;
                  if (filtered?.hidden) agent.log({ event: list.hidden, hidden: filtered.hidden });
                  // A list that is to be filtered and cannot be read is not handed on: the agent is answered with an error under its id (X250). The upstream's own error goes on as it is.
                  if (list && !filtered && !(m && Object.hasOwn(m, 'error'))) {
                    agent.log({ event: list.notRead });
                    return toAgent(sseEvent(event.others, list.answer()));
                  }
                  return toAgent(scrub(sseEvent(event.others, filtered ? filtered.text : (spliceId(event.data, clientId) ?? event.data))));
                }
                if (kind === 'call') agent.log({ event: 'upstream-other-id', id: typeof foundId === 'string' ? foundId.slice(0, 80) : foundId });
              }
              if (m && read.kind === 'request') askedOf(ctx, m);
              toAgent(scrub(event.raw));
            },
          });
          up.on('data', (chunk) => {
            if (finished) return;
            reader.feed(decoder.decode(chunk, { stream: true }));
            // The part of an event not yet whole counts for the agent, as what waits for its connection does.
            if (!finished && !holdAnswer(ctx, reader.pending())) tooMuchHeld();
          });
          up.on('error', () => fail_(502, 'The upstream closed the stream before it was complete.'));
          up.on('aborted', () => fail_(502, 'The upstream closed the stream before its answer came.'));
          up.on('end', () => {
            if (finished) return done();
            finish();
            if (kind === 'call') return done(outcome({ kind: 'error', text: 'The upstream ended the stream before it answered this call, so its outcome is not known.', code: CODES.noAnswer }));
            endAgent();
            done();
          });
          return;
        }
        // One JSON body, or none (202 to a notification): read whole, up to the limit.
        const chunks = [];
        let size = 0;
        up.on('data', (chunk) => {
          if (finished) return;
          size += chunk.length;
          if (size > ANSWER_LIMIT) {
            req.destroy();
            return fail_(502, `The upstream's answer was larger than ${ANSWER_LIMIT} bytes, the most the executor takes.`);
          }
          // What is read of the answer counts for the agent until it has been handed on (waitingBytes).
          if (!holdAnswer(ctx, size)) return tooMuchHeld();
          chunks.push(chunk);
        });
        up.on('error', () => fail_(502, 'The upstream closed the connection before its answer was complete.'));
        up.on('aborted', () => fail_(502, 'The upstream closed the connection before its answer was complete.'));
        up.on('end', () => {
          if (finished) return done();
          finish();
          // A call's outcome is recorded whether or not the agent is still there to hear it.
          if (res.destroyed && kind !== 'call') return done();
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
            const ok = status >= 200 && status < 300;
            if (foundId !== serverId) {
              agent.log({ event: 'upstream-other-id', id: typeof foundId === 'string' ? foundId.slice(0, 80) : (foundId ?? null) });
              return done(outcome({ kind: 'error', text: ok ? 'The upstream answered this call with a message that is not its response (another id, or no message), so its outcome is not known.' : `The upstream answered HTTP ${status} to this call with no response under its id, so its outcome is not known.`, code: CODES.noAnswer }));
            }
            if (!ok) {
              // The specification's way of refusing: a 4xx with a JSON-RPC error under the call's id. That error is the outcome, relayed with its status; anything else on a non-2xx is no outcome.
              if (read.refused || read.kind !== 'response' || !Object.hasOwn(m, 'error')) return done(outcome({ kind: 'error', text: `The upstream answered HTTP ${status} to this call without a JSON-RPC error under its id, so its outcome is not known.`, code: CODES.noAnswer }));
              agent.log({ event: 'upstream-refused-call', status, code: typeof m.error.code === 'number' ? m.error.code : null });
              ctx.answerStatus = status;
              return done(outcome({ kind: 'server-error', text: read.text, errorText: `The tool server answered with an error: ${JSON.stringify(m.error)}` }));
            }
            if (read.refused) return done(outcome({ kind: 'unreadable', text, errorText: null }));
            if (read.kind !== 'response') return done(outcome({ kind: 'error', text: 'The upstream answered this call with a message that is not a response, so its outcome is not known.', code: CODES.noAnswer }));
            if (Object.hasOwn(m, 'result')) return done(outcome({ kind: 'answer', text: read.text, result: m.result, unsafe: unsafeInteger(read.text) !== null }));
            return done(outcome({ kind: 'server-error', text: read.text, errorText: `The tool server answered with an error: ${JSON.stringify(m.error)}` }));
          }
          // A request's answer: under the client's id, filtered where it lists tools.
          let out = text ?? bytes.toString('utf8');
          let filtered = null;
          if (serverId !== undefined && foundId === serverId) {
            if (m && read.kind === 'response') learnFrom(m);
            filtered = list && m && read.kind === 'response' ? list.filter(read.text, m) : null;
            if (filtered?.hidden) agent.log({ event: list.hidden, hidden: filtered.hidden });
            out = filtered ? filtered.text : (spliceId(out, clientId) ?? out);
          }
          // A list that is to be filtered and cannot be read (or is under another id, or is no message) is not handed on: the agent is answered with an error under its id (X250). The upstream's own error goes on as it is, with its status: under the request's id; or, under any id or a null one, where it is an error answer and nothing more, which holds no result for any reader and so no list (X260).
          let own = false;
          if (list && !filtered && !(m && read.kind === 'response' && foundId === serverId && Object.hasOwn(m, 'error')) && !errorAnswer(text)) {
            agent.log({ event: list.notRead });
            out = list.answer();
            own = true;
          }
          if (!own && m && read.kind === 'request') askedOf(ctx, m);
          const body_ = Buffer.from(scrub(out));
          // The executor's own error is JSON whatever the upstream sent, and is not to be stored: the upstream's content type and its word on caching were about the body that is not handed on (X260).
          res.writeHead(status, own ? { ...returned, 'content-type': JSON_TYPE, 'cache-control': 'no-store', 'content-length': body_.length } : { ...returned, 'content-type': type || JSON_TYPE, 'content-length': body_.length });
          done(res.end(body_));
        });
      });
      if (body !== undefined) req.end(body);
      else req.end();
    })();
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

  /**
   * Read the request's body, up to the limit: the bytes, or null where it is
   * too large. A body that does not arrive whole within the timeout fails
   * with code BODY_TIMEOUT: the server's own request timeout is off, since a
   * GET stream or a long answer must not be cut, so the body's reading has
   * a limit of its own (X119).
   *
   * With "held" ({agent, bytes}), the body's bytes are counted for the agent
   * (agent.held) as they arrive, its declared length at once, and kept until
   * the caller gives them back; a body that would take the agent past
   * waitingBytes gives TOO_MUCH_HELD, and is read no further.
   */
  function readBody(req, limit = settings.bodyLimit, wait = settings.timeout, held = null) {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > limit) return Promise.resolve(null);
    const share = (more) => {
      if (!held) return true;
      if (held.agent.held + more > settings.waitingBytes) return false;
      held.agent.held += more;
      held.bytes += more;
      return true;
    };
    const reserved = Number.isFinite(declared) && declared > 0 ? declared : 0;
    if (!share(reserved)) return Promise.resolve(TOO_MUCH_HELD);
    return new Promise((done, failed) => {
      const chunks = [];
      let size = 0;
      let over = false;
      const timer = setTimeout(() => failed(Object.assign(new Error('The body did not arrive whole in time.'), { code: 'BODY_TIMEOUT' })), wait);
      timer.unref();
      const settle = (f) => (v) => {
        clearTimeout(timer);
        f(v);
      };
      req.on('data', (chunk) => {
        if (over) return;
        size += chunk.length;
        if (size > reserved && !share(Math.min(chunk.length, size - reserved))) {
          over = true;
          chunks.length = 0;
          return settle(done)(TOO_MUCH_HELD);
        }
        if (size > limit) {
          over = true;
          chunks.length = 0;
          return settle(done)(null);
        }
        chunks.push(chunk);
      });
      req.on('end', settle(() => done(over ? null : Buffer.concat(chunks))));
      req.on('error', settle(failed));
      req.on('close', settle(() => failed(Object.assign(new Error('The connection closed before the body was whole.'), { code: 'BODY_CLOSED' }))));
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

  // --- the executor's own addresses, for the administrator ---

  /** How many POST /provared/hello are being signed for, in all and for the callers at each address. */
  let hellos = 0;
  const hellosBy = new Map();
  /** What signs a challenge: identity.mjs's, or a test's in its place. */
  const signHello = more.identify ?? identify;
  const isAdmin = (secret) => {
    const given = Buffer.from(secretHash(secret));
    return admin !== null && given.length === admin.length && timingSafeEqual(given, admin);
  };
  /** An answer of one of the executor's own addresses: JSON, in the gateway's form. Nothing of the upstream's is in it; it passes through the scrub all the same. */
  const adminJson = (res, status, value, extra = {}) => json(res, status, scrub(JSON.stringify(value)), extra);
  const adminRefuse = (res, status, code, message, extra = {}) => adminJson(res, status, { taken: false, code, message }, extra);

  /**
   * GET /provared/status, POST /provared/seal and POST /provared/acknowledge,
   * as the gateway's: for the administrator alone, by a secret of the
   * administrator's own, which no agent holds. Without an administrator's
   * secret in the settings they answer nothing. A request that names an
   * Origin (a web page's) is refused whatever "allowedOrigins" says.
   */
  async function adminAddress(req, res, path) {
    if (req.headers.origin !== undefined) {
      log({ event: 'refused', code: 'origin-refused', address: path });
      return adminRefuse(res, 403, 'origin-refused', 'The executor\'s own addresses take no request from a web page (a request that names an Origin).', { connection: 'close' });
    }
    if (admin === null) return adminRefuse(res, 404, 'not-found', 'This executor has no administrator\'s secret ("admin"), so its own addresses answer nothing.');
    // Before a command sends the secret it asks the executor to show that it is the executor (identity.mjs). No secret is needed, and none should be sent.
    if (req.method === 'POST' && path === `${ADMIN_PATH}/hello`) {
      // Anyone may ask, so little is read, for a short time: a challenge is some 60 bytes of JSON.
      let asked;
      try {
        asked = JSON.parse((await readBody(req, HELLO_BODY_LIMIT, HELLO_WAIT_MS))?.toString('utf8') ?? '');
      } catch {
        asked = null;
      }
      if (!isObject(asked) || typeof asked.challenge !== 'string' || !CHALLENGE.test(asked.challenge)) return adminRefuse(res, 400, 'bad-request', 'Send a challenge of 32 random bytes in base64url: {"challenge": "<43 characters>"}.', { connection: 'close' });
      // Only a question that has arrived whole takes a place, and keeps it for the two signatures alone: the places bound
      // the signing, and a caller who sends a body slowly, or never ends it, holds none. Callers at one address share part of them.
      const caller = plainAddress(req.socket.remoteAddress);
      const theirs = hellosBy.get(caller) ?? 0;
      if (hellos >= HELLO_AT_ONCE || theirs >= HELLO_PER_CALLER) return adminRefuse(res, 503, 'busy', `The executor is answering ${hellos >= HELLO_AT_ONCE ? `${HELLO_AT_ONCE} such questions, the most it takes at once` : `${HELLO_PER_CALLER} such questions from this address, the most it takes from one address at once`}. Ask again.`, { connection: 'close' });
      hellos += 1;
      hellosBy.set(caller, theirs + 1);
      try {
        const address = plainAddress(req.socket.localAddress);
        const port = req.socket.localPort;
        return adminJson(res, 200, { executor: 'provared-mcp-executor', address, port, signatures: await signHello(shared.executorKeys.privateKeys, asked.challenge, address, port) });
      } finally {
        hellos -= 1;
        const left = hellosBy.get(caller) - 1;
        if (left > 0) hellosBy.set(caller, left);
        else hellosBy.delete(caller);
      }
    }
    const secret = bearer(req);
    if (!secret || !isAdmin(secret)) {
      log({ event: 'not-signed-in', address: path });
      return adminRefuse(res, 401, 'not-signed-in', 'The executor\'s own addresses need the administrator\'s secret, in one header: Authorization: Bearer <secret>.', { 'www-authenticate': 'Bearer' });
    }
    if (stopping) return adminRefuse(res, 503, 'stopping', 'The executor is stopping and takes no request.', { connection: 'close' });
    if (req.method === 'GET' && path === `${ADMIN_PATH}/status`) return adminJson(res, 200, await report());
    const posted = req.method === 'POST' && [`${ADMIN_PATH}/seal`, `${ADMIN_PATH}/acknowledge`].includes(path);
    if (!posted) return adminRefuse(res, 404, 'not-found', 'The executor\'s own addresses are GET /provared/status, POST /provared/seal, POST /provared/acknowledge and POST /provared/hello.');
    let body;
    try {
      // Read up to the limit of these addresses and no further.
      body = await readBody(req, ADMIN_BODY_LIMIT);
    } catch (e) {
      return adminRefuse(res, e.code === 'BODY_TIMEOUT' ? 408 : 400, 'bad-request', 'The body did not arrive whole.', { connection: 'close' });
    }
    if (body === null) return adminRefuse(res, 413, 'too-large', `A body sent to the executor's own addresses may be ${ADMIN_BODY_LIMIT} bytes at most.`, { connection: 'close' });
    let asked;
    try {
      asked = JSON.parse(body.toString('utf8'));
    } catch {
      asked = null;
    }
    const name = isObject(asked) ? asked.agent : undefined;
    if (path === `${ADMIN_PATH}/seal`) {
      if (typeof name !== 'string' || !agents.has(name)) return adminRefuse(res, 400, 'bad-request', 'Name the agent whose book to seal: {"agent": "<name>"}.');
      try {
        return adminJson(res, 200, await seal(name));
      } catch (e) {
        return adminRefuse(res, 409, 'not-sealed', e.message);
      }
    }
    if (typeof name !== 'string' || !agents.has(name)) return adminRefuse(res, 400, 'bad-request', 'Name the agent whose calls to acknowledge: {"agent": "<name>"}.');
    try {
      return adminJson(res, 200, await acknowledge(name, { setAside: asked.setAside }));
    } catch (e) {
      return adminRefuse(res, 409, 'not-acknowledged', e.message);
    }
  }

  /** Seal an agent's book now, with the recorder's keys: {agent, entry, fingerprint}, with "stamped" or "stampProblem" where a time-stamp was asked for. */
  async function seal(name) {
    const agent = agents.get(name);
    if (!agent) throw new Error(`The executor has no agent named "${name}".`);
    const { entry, fingerprint, stamped, stampedBy, stampProblem } = await agent.seal();
    return { agent: name, entry, fingerprint, ...(stamped !== undefined ? { stamped } : {}), ...(stampedBy ? { stampedBy } : {}), ...(stampProblem ? { stampProblem } : {}) };
  }

  /** The administrator acknowledges an agent's calls sent under a permission no longer in force, and may set some aside (openAgent's "acknowledge"): {agent, written, setAside, remaining}. */
  async function acknowledge(name, o = {}) {
    const agent = agents.get(name);
    if (!agent) throw new Error(`The executor has no agent named "${name}".`);
    return { agent: name, ...(await agent.acknowledge(o)) };
  }

  /** What the executor says about itself: the recorder, and for each agent its book, its last seal, whether the book passes its check and the calls waiting to be acknowledged. */
  async function report() {
    const out = {};
    for (const [name, agent] of agents) out[name] = await agent.report();
    return { executor: 'provared-mcp-executor', from: 'running', recorder: describeRecorder(settings, shared.sealer), agents: out };
  }

  const timer = settings.recorder?.sealEvery ? sealTimer([...agents.values()], settings.recorder.sealEvery) : null;

  async function take(req, res) {
    const path = (req.url ?? '').split('?')[0];
    if (path === ADMIN_PATH || path.startsWith(`${ADMIN_PATH}/`)) return adminAddress(req, res, path);
    if (door?.owns(path)) {
      if (stopping) return refuse(res, 503, null, CODES.notRecorded, 'The executor is stopping and takes no request.', { connection: 'close' });
      return door.take(req, res, path);
    }
    if (path !== settings.path) return refuse(res, 404, null, CODES.invalidRequest, `The MCP endpoint is ${settings.path}.`);
    // A browser page's request names its Origin; none may call unless the settings name it (the transport's rule against DNS rebinding).
    const origin = req.headers.origin;
    if (origin !== undefined && !settings.allowedOrigins.includes(origin)) {
      log({ event: 'refused', code: 'origin-refused' });
      return refuse(res, 403, null, CODES.invalidRequest, 'The executor takes no request from a web page (an Origin it does not allow).', { connection: 'close' });
    }
    // Who is calling: the agent's own secret, in the one Authorization header. The secret itself is never logged.
    const secret = bearer(req);
    const who = secret ? signedIn(secret) : null;
    const agent = who?.agent ?? null;
    if (!agent) {
      log({ event: 'not-signed-in' });
      // With OAuth, the challenge names the resource's metadata, where a client learns how to sign in (RFC 9728).
      if (door) return refuse(res, 401, null, CODES.invalidRequest, `Sign in to the executor: with your own secret, or through OAuth (the resource's metadata is at ${door.resourceMetadataUrl}). One header: Authorization: Bearer <secret or token>.`, { 'www-authenticate': door.challenge(secret !== null) });
      return refuse(res, 401, null, CODES.invalidRequest, 'Sign in to the executor with your own secret, in one header: Authorization: Bearer <secret>.', { 'www-authenticate': 'Bearer' });
    }
    if (stopping) return refuse(res, 503, null, CODES.notRecorded, 'The executor is stopping and takes no request.', { connection: 'close' });
    if (req.headers.upgrade !== undefined || req.method === 'CONNECT') return refuse(res, 400, null, CODES.invalidRequest, 'The executor takes no upgrade and no tunnel.');
    if (!['POST', 'GET', 'DELETE'].includes(req.method)) return refuse(res, 405, null, CODES.invalidRequest, 'The MCP endpoint takes POST (a message), GET (the stream of server messages) and DELETE (the end of a session).', { allow: 'POST, GET, DELETE' });
    // A session belongs to the agent that opened it.
    const sessionIds = req.headersDistinct['mcp-session-id'] ?? [];
    if (sessionIds.length > 1 || (sessionIds.length === 1 && !SESSION_ID.test(sessionIds[0]))) return refuse(res, 400, null, CODES.invalidRequest, 'The Mcp-Session-Id header must be given once, as 1 to 512 visible ASCII characters.');
    // A local program's session is also held to the connection made through OAuth it was begun under (X234).
    const session = local && sessionIds.length === 1 ? local.owned(sessionIds[0], agent.name, who.token?.connection ?? null) : null;
    if (sessionIds.length === 1 && (local ? !session : !upstreamSession(sessionIds[0], agent, who.token?.connection ?? null))) {
      agent.log({ event: 'refused', code: 'session-not-found' });
      return refuse(res, 404, null, CODES.invalidRequest, 'The session is not known to the executor, or is not this agent\'s. Begin a new one.');
    }
    if (agent.open >= MAX_OPEN) {
      agent.log({ event: 'refused', code: 'too-many-open', open: agent.open });
      return refuse(res, 503, null, CODES.notRecorded, `This agent already has ${MAX_OPEN} requests in flight, the most it may have. Try again when one has ended.`, { connection: 'close' });
    }
    agent.open += 1;
    // The bytes of this request's body, counted for the agent until the request has been answered (waitingBytes).
    const held = { agent, bytes: 0 };
    const ctx = { req, res, agent, token: who.token, upstream: null, streaming: false, finalEvent: null, session, entered: null, held };
    // What waits for the agent's connection counts in its budget until the connection has taken it, or has gone.
    res.on('drain', () => holdAnswer(ctx));
    res.once('finish', () => holdAnswer(ctx));
    res.once('close', () => holdAnswer(ctx, 0));
    // A message in hand keeps its session from being taken for idle; an open stream of the program's own messages does not (X235).
    if (session && req.method !== 'GET') enter(ctx, session);
    try {
      await one(ctx, sessionIds[0]);
    } finally {
      agent.open -= 1;
      agent.held -= held.bytes;
      // The answer as written, where the agent has not yet taken it all.
      holdAnswer(ctx);
      if (ctx.entered) local.leave(ctx.entered);
    }
  }

  // --- a local program: one for each session (local.mjs; DESIGN.md, section 10.1) ---

  /** The request in hand is this session's, until it has been answered. */
  const enter = (ctx, session) => {
    ctx.session = session;
    ctx.entered = session;
    local.enter(session);
  };

  /** The answer to a request other than a tool call, from a session's program ("got" is what local.ask gave), under the agent's id; the answer to a tools/list filtered as on stdio. */
  function answerLocal(ctx, clientId, got, { list = false, extra = {} } = {}) {
    const { res, agent } = ctx;
    if (got.failed === 'gone') return;
    if (got.failed === 'not-reading') return refuse(res, 503, clientId, CODES.noAnswer, 'The tool server is not reading what it is sent, so this request was not sent and the session was ended. Begin a new one.');
    if (got.failed) return refuse(res, got.failed === 'timeout' ? 504 : 502, clientId, CODES.noAnswer, got.failed === 'timeout' ? `The tool server gave no answer within ${settings.timeout} ms.` : 'The tool server ended before it answered.');
    if (list && got.message) learnAnnotations(got.message);
    const filtered = list && settings.hideUnlisted && got.message ? filteredList(got.text, got.message, clientId, settings) : null;
    if (filtered?.hidden) agent.log({ event: 'tools-hidden', hidden: filtered.hidden });
    // A list of tools that is to be filtered and cannot be read is not handed on: the agent is answered with an error under its id (X250). The program's own error goes on as it is.
    if (list && settings.hideUnlisted && !filtered && !(got.message && Object.hasOwn(got.message, 'error'))) {
      agent.log({ event: 'tools-list-not-read' });
      return json(res, 200, listNotRead(clientId), extra);
    }
    json(res, 200, scrub(filtered ? filtered.text : (spliceId(got.text, clientId) ?? got.text)), extra);
  }

  /** The link the shared call handling uses for a session's program: one line each way, as on stdio. */
  const localLink = (ctx, session) => ({
    newServerId,
    key: (id) => local.key(session, id),
    answer: (text) => json(ctx.res, 200, scrub(text)),
    unavailable: () => (stopping ? 'The executor is stopping, so this call was not sent.' : session.gone || session.ended ? 'The tool server has ended.' : null),
    send: (call, forwarded) => {
      ctx.exchange = true;
      return local.write(session, JSON.stringify(forwarded));
    },
    // On the executor's timeout the program is told, as on stdio; an answer that comes later names nothing in flight, and is dropped.
    cancel: (call, reason) => local.write(session, JSON.stringify({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: call.serverId, reason } })),
    forward: (id, serverId, text) => {
      ctx.exchange = true;
      ctx.forwarded = local.ask(session, spliceId(text, serverId) ?? text, serverId, id).then((got) => answerLocal(ctx, id, got));
    },
    track: (call) => local.track(session, call),
    untrack: (call) => local.untrack(session, call),
  });

  /** The stream of a session's program's own messages (its requests and notifications), for a GET: {end, cancel}, as "exchange" gives. One stream for a session: a later one takes the place of the earlier (X233). */
  function localStream(ctx, session) {
    const { res, agent } = ctx;
    let done;
    const end = new Promise((d) => {
      done = d;
    });
    session.closeStream?.();
    const write = (text) => {
      if (res.destroyed || res.writableEnded) return false;
      if (res.writableLength > BACKLOG_LIMIT) {
        agent.log({ event: 'agent-not-reading', kind: 'stream', held: res.writableLength });
        res.destroy();
        return false;
      }
      res.write(scrub(sseEvent([], text)));
      return true;
    };
    const close = () => {
      if (session.toStream === write) {
        session.toStream = null;
        session.closeStream = null;
      }
      if (!res.writableEnded && !res.destroyed) res.end();
      done();
    };
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store' });
    res.flushHeaders?.();
    session.toStream = write;
    session.closeStream = close;
    res.on('close', close);
    return { end, cancel: close };
  }

  /**
   * One message for a local program, other than a tool call under a session
   * (which "one" handles with the session's link). An "initialize" without
   * a session begins one, and starts its program; every other message needs
   * its session. A request is answered with one JSON body; a notification
   * or a response with 202 (X232, X233).
   */
  async function localPost(ctx, read) {
    const { res, agent } = ctx;
    const m = read.message;
    const clientId = read.kind === 'request' ? m.id : null;
    if (read.kind === 'request' && m.method === 'initialize') {
      if (ctx.session) return refuse(res, 400, clientId, CODES.invalidRequest, 'A session is begun by an "initialize" sent without an Mcp-Session-Id; this one names a session.');
      // Where the agent has its most programs, this waits for room (X243).
      const begun = await local.begin(agent.name, ctx.token?.connection ?? null);
      // The stop began while this request's body was read, or while it waited for room: no program is started after it (X246).
      if (begun.refused === 'stopping') return refuse(res, 503, clientId, CODES.notRecorded, 'The executor is stopping and takes no request.', { connection: 'close' });
      if (begun.refused === 'too-many') {
        agent.log({ event: 'refused', code: 'too-many-sessions', sessions: settings.sessions.max });
        return refuse(res, 503, clientId, CODES.notRecorded, `This agent already has ${settings.sessions.max} programs running, the most it may have at once (sessions.max), and room could not be made: each of its sessions has a request in flight, or a program that was ended has not gone yet. Try again when one has ended.`, { connection: 'close' });
      }
      if (begun.refused) return refuse(res, 502, clientId, CODES.noAnswer, 'The tool server could not be started, so no session was begun.');
      const session = begun.session;
      enter(ctx, session);
      // The agent went away while room was made: there is no one to give the session to.
      if (res.destroyed) return local.end(session, 'not-begun');
      // A session begun under a connection made through OAuth ends with that connection.
      if (ctx.token) session.release = door.watch(ctx.token.connection, () => local.end(session, 'connection-ended'));
      const serverId = newServerId();
      // "initialize" is never cancelled; where it is not answered in time the program is ended.
      const asked = local.ask(session, spliceId(read.text, serverId) ?? JSON.stringify({ ...m, id: serverId }), serverId, clientId, { cancel: false });
      res.on('close', () => {
        if (!res.writableFinished) local.forget(session, serverId);
      });
      const got = await asked;
      // No session without the program's own result to "initialize": the program is ended, and the agent is told why.
      const begunWell = !got.failed && got.message !== null && Object.hasOwn(got.message, 'result');
      if (!begunWell) local.end(session, 'not-begun');
      // The version the program answered with is one the session's later requests may name in MCP-Protocol-Version (X247).
      else if (isObject(got.message.result) && typeof got.message.result.protocolVersion === 'string') session.version = got.message.result.protocolVersion;
      if (got.failed === 'timeout') return refuse(res, 504, clientId, CODES.noAnswer, `The tool server gave no answer to "initialize" within ${settings.timeout} ms, so no session was begun.`);
      if (got.failed === 'ended') return refuse(res, 502, clientId, CODES.noAnswer, 'The tool server ended before it answered "initialize", so no session was begun.');
      return answerLocal(ctx, clientId, got, { extra: begunWell ? { 'mcp-session-id': session.id } : {} });
    }
    const session = ctx.session;
    if (!session) {
      agent.log({ event: 'refused', code: 'no-session' });
      return refuse(res, 400, clientId, CODES.invalidRequest, 'In front of a local program the executor serves sessions: begin one with "initialize", and send the Mcp-Session-Id it answers with on every message after.');
    }
    const accepted = () => {
      res.writeHead(202);
      res.end();
    };
    if (read.kind === 'request') {
      const serverId = newServerId();
      const asked = local.ask(session, spliceId(read.text, serverId) ?? JSON.stringify({ ...m, id: serverId }), serverId, clientId);
      res.on('close', () => {
        if (!res.writableFinished) local.forget(session, serverId);
      });
      return answerLocal(ctx, clientId, await asked, { list: m.method === 'tools/list' });
    }
    // A message that could not be given to the program is not answered 202: "If the server cannot accept the input, it MUST return an HTTP error status code" (X247).
    const notWritten = () => (session.ended === 'not-reading'
      ? refuse(res, 503, null, CODES.noAnswer, 'The tool server is not reading what it is sent, so this message was not sent and the session was ended. Begin a new one.')
      : refuse(res, 502, null, CODES.noAnswer, 'The tool server has ended, so this message was not sent.'));
    if (read.kind === 'notification') {
      // A request's method sent without an id would reach the program unchecked; only the protocol's own notifications pass.
      if (!m.method.startsWith('notifications/')) return notANotification(ctx, m);
      if (m.method === 'notifications/cancelled' && isId(m.params?.requestId)) {
        // The program knows a request by the executor's id for it, as on stdio.
        const call = agent.calls.get(local.key(session, m.params.requestId));
        if (call && !call.cancelled) {
          call.cancelled = true;
          if (call.state === 'sent' && call.settle) {
            local.write(session, JSON.stringify({ ...m, params: { ...m.params, requestId: call.serverId } }));
            call.settle({ kind: 'error', text: 'The agent cancelled this call while it was with the tool server, so its outcome is not known.', code: CODES.noAnswer });
          }
          return accepted();
        }
        const other = local.serverIdOf(session, m.params.requestId);
        if (other !== undefined) return local.write(session, JSON.stringify({ ...m, params: { ...m.params, requestId: other } })) ? accepted() : notWritten();
      }
    }
    // A notification, or the agent's response to a request of the program's own: as it is.
    return local.write(session, read.text) ? accepted() : notWritten();
  }

  /** A request's method sent without an id: it is not sent on, since it would reach the tool server unchecked, and it is refused with 400, since it was not accepted (X247). */
  function notANotification(ctx, m) {
    ctx.agent.log({ event: 'notification-dropped', method: m.method.slice(0, 80) });
    return refuse(ctx.res, 400, null, CODES.invalidRequest, 'A message with no id is a notification, and only the protocol\'s own notifications (notifications/...) are sent on. This one names a request\'s method, so it was not sent: give it an id.');
  }

  async function one(ctx, sessionId) {
    const { req, res, agent } = ctx;
    ctx.sessionId = sessionId;
    // In front of a local program no one else reads the header, so the executor answers for it: "If the server receives a request with an invalid or unsupported MCP-Protocol-Version, it MUST respond with 400 Bad Request." A request that names no version is taken, as the specification allows (X247).
    const versions = local ? req.headersDistinct['mcp-protocol-version'] ?? [] : [];
    const otherVersion = versions.length === 1 && !LOCAL_VERSIONS.includes(versions[0]) && versions[0] !== ctx.session?.version;
    const refuseVersion = () => {
      // The log names the version only where it is written as a revision is, and says whether a session id came with the request; nothing else of the request (X287).
      agent.log({ event: 'refused', code: 'protocol-version', version: REVISION.test(versions[0]) ? versions[0] : 'other', session: sessionId !== undefined });
      return refuse(res, 400, null, CODES.invalidRequest, `The MCP-Protocol-Version header names a version the executor does not serve in front of a local program. It serves ${LOCAL_VERSIONS.join(', ')}, and the version a session's program answered "initialize" with. An "initialize" sent without an Mcp-Session-Id is taken under any version: the program's answer settles it.`);
    };
    // A POST with no session id may be the "initialize" that begins a session, which is not held to this header: so for such a POST the check waits until its message has been read (below). Every other request is checked here, as before (X287).
    const versionWaits = otherVersion && req.method === 'POST' && sessionId === undefined;
    if (otherVersion && !versionWaits) return refuseVersion();
    if (req.method !== 'POST') {
      // The GET stream of server messages, or the DELETE that ends a session: no message, so no mirrored metadata to check; the same few headers go on.
      const h = headersFor(req, null, undefined, agent);
      if (h.problem) return refuse(res, 400, null, HEADER_MISMATCH, h.problem);
      // In front of an upstream, with more than one agent: a stream of the upstream's messages tied to no session is tied to no agent either, since to the upstream every agent is one caller. What comes on it (its own requests, list changes) could be another agent's, so it is not opened; 405 is the specification's way of saying that no stream is offered (X450).
      if (!local && req.method === 'GET' && sessionId === undefined && agents.size > 1) {
        agent.log({ event: 'refused', code: 'stream-not-tied' });
        return refuse(res, 405, null, CODES.invalidRequest, 'In front of this upstream, with more than one agent, a stream of the server\'s messages is opened only under a session (Mcp-Session-Id): without one, what comes on it is no one agent\'s.', { allow: 'POST, DELETE' });
      }
      if (h.dropped.length) agent.log({ event: 'headers-dropped', headers: h.dropped });
      if (local) {
        // A local program: the stream is of its session's own messages, and a DELETE ends the session and, with it, its program (X233, X234).
        if (!ctx.session) return refuse(res, 400, null, CODES.invalidRequest, 'Name the session: the Mcp-Session-Id that the answer to "initialize" gave.');
        if (req.method === 'DELETE') {
          local.end(ctx.session, 'ended-by-agent');
          res.writeHead(204);
          return res.end();
        }
      }
      const ex = local ? localStream(ctx, ctx.session) : exchange(ctx, { method: req.method, headers: h.headers, kind: req.method === 'GET' ? 'stream' : 'other' });
      res.on('close', () => ex.cancel());
      // A token is checked when its request arrives, and a stream has no end of its own. So a stream opened with an access token is ended when that token stops standing, for whatever reason: it expires, its connection ends, or later tokens push it out; it then no longer holds one of the agent's places (X229). A call already taken is not cut: it ends within the timeout, with its receipt.
      let release = null;
      let expiry = null;
      if (req.method === 'GET' && ctx.token) {
        const endStream = (why) => {
          agent.log({ event: 'stream-ended', why });
          ex.cancel();
          if (!res.headersSent) refuse(res, 401, null, CODES.invalidRequest, 'The access token this stream was opened with has ended. Sign in again.', { 'www-authenticate': door.challenge(true) });
          else if (!res.writableEnded && !res.destroyed) res.end();
        };
        release = door.hold(ctx.token, endStream);
        expiry = setTimeout(() => endStream('token-expired'), Math.max(0, ctx.token.expires - now()));
        expiry.unref();
      }
      try {
        await ex.end;
      } finally {
        release?.();
        if (expiry) clearTimeout(expiry);
      }
      if (req.method === 'DELETE' && sessionId && res.statusCode < 300) forgetSession(sessionId, agent);
      return;
    }
    const type = String(req.headers['content-type'] ?? '').toLowerCase();
    if (!/^application\/json\s*(;|$)/.test(type)) return refuse(res, 415, null, CODES.invalidRequest, 'A message is sent as application/json.');
    let body;
    try {
      body = await readBody(req, settings.bodyLimit, settings.timeout, ctx.held);
    } catch (e) {
      if (e.code === 'BODY_TIMEOUT') {
        agent.log({ event: 'refused', code: 'body-timeout' });
        refuse(res, 408, null, CODES.invalidRequest, `The body did not arrive whole within ${settings.timeout} ms.`, { connection: 'close' });
        return req.destroy();
      }
      if (e.code === 'BODY_CLOSED') return;
      return refuse(res, 400, null, CODES.invalidRequest, 'The body could not be read.');
    }
    if (body === TOO_MUCH_HELD) {
      agent.log({ event: 'refused', code: 'too-much-held', held: agent.held });
      return refuse(res, 503, null, CODES.notRecorded, `This agent's requests in flight already hold ${settings.waitingBytes} bytes of bodies, or would with this one, the most they may (waitingBytes). Try again when one has been answered.`, { connection: 'close' });
    }
    if (body === null) {
      agent.log({ event: 'refused', code: 'body-too-large' });
      return refuse(res, 413, null, CODES.invalidRequest, `The body is larger than ${settings.bodyLimit} bytes, the most the executor takes.`, { connection: 'close' });
    }
    // One message, read strictly: a batch, a repeated name or a shape that is not a message goes no further.
    // "let": a request that only passes through lets go of its message, read and as bytes, once it has been sent on (below).
    let read = readMessage(body);
    if (read.refused) {
      agent.log({ event: 'client-message-refused', code: read.refused.code });
      return refuse(res, 400, read.id, read.refused.code, read.refused.message);
    }
    let m = read.message;
    // The check of MCP-Protocol-Version that waited for the message: an "initialize" with no session id is taken whatever version the header names, since the version is agreed inside "initialize" and the program's answer becomes the session's; any other message is refused as it would have been above (X287).
    if (versionWaits && !(read.kind === 'request' && m.method === 'initialize')) return refuseVersion();
    const h = headersFor(req, m, read.text, agent);
    if (h.problem) {
      agent.log({ event: 'refused', code: 'header-mismatch' });
      return refuse(res, 400, read.kind === 'request' ? m.id : null, HEADER_MISMATCH, h.problem);
    }
    if (h.dropped.length) agent.log({ event: 'headers-dropped', headers: h.dropped });
    // A legacy session (2025-11-25: a session id, or a protocol version before 2026-07-28) cancels by notification, not by closing the stream (X111).
    const version = h.headers['mcp-protocol-version'];
    const legacy = sessionId !== undefined || (typeof version === 'string' && version < '2026-07-28');
    // A local program: every message but a session's tool call is carried by localPost; the call goes on below, through the same check, with the session's link.
    if (local && !(ctx.session && read.kind === 'request' && m.method === 'tools/call')) return localPost(ctx, read);

    // In front of an upstream: tasks are refused unless the settings allow them, and then kept to the agent whose call made each.
    if (!local) {
      const refusal = read.kind === 'request' ? taskRefusal(m, agent) : (othersTask(m, agent) ? { rpc: CODES.invalidParams, message: 'The message names a task that is not this agent\'s.' } : null);
      if (refusal) {
        agent.log({ event: 'refused', code: settings.allowTasks ? 'task-not-this-agents' : 'tasks-refused', method: typeof m.method === 'string' ? m.method.slice(0, 80) : null });
        // A request is answered 200, as the executor's other refusals of a message it has read, so that the agent's MCP library reads the error as the response (X112); a notification or a response, which has no response, 400.
        return refuse(res, read.kind === 'request' ? 200 : 400, read.kind === 'request' ? m.id : null, refusal.rpc, refusal.message);
      }
    }
    // A request that asks for a task (allowTasks): the task its answer names is this agent's.
    const asksTask = !local && read.kind === 'request' && isObject(m.params) && Object.hasOwn(m.params, 'task');

    if (read.kind === 'request') {
      if (m.method === 'tools/call') {
        const link = ctx.session ? localLink(ctx, ctx.session) : {
          newServerId,
          key: (id) => callKey(sessionId, id),
          answer: (text) => {
            if (ctx.streaming) {
              if (!res.writableEnded && !res.destroyed) res.end(scrub(sseEvent(ctx.finalEvent ?? [], text)));
              return;
            }
            json(res, ctx.answerStatus ?? 200, scrub(text));
          },
          unavailable: () => (stopping ? 'The executor is stopping, so this call was not sent.' : null),
          send: (call, forwarded) => {
            const ex = exchange(ctx, { method: 'POST', headers: h.headers, body: JSON.stringify(forwarded), kind: 'call', serverId: call.serverId, onOutcome: (o) => {
              if (asksTask && o.kind === 'answer') learnTask(o.result, agent);
              call.settle?.(o);
            } });
            ctx.exchange = ex;
            // Closing the stream to the upstream is the transport's cancellation: on the executor's timeout, the agent's closing of its stream, or its notification.
            call.cancelUpstream = ex.cancel;
            return true;
          },
          cancel: (call) => call.cancelUpstream?.(),
          forward: (id, serverId, text) => {
            const ex = exchange(ctx, { method: 'POST', headers: h.headers, body: spliceId(text, serverId) ?? text, kind: 'request', clientId: id, serverId, task: asksTask });
            ctx.exchange = ex;
            ctx.forwarded = ex.end;
          },
          track: () => {},
          untrack: () => {},
        };
        // The call this request began, once handleCall has begun it (it does so before its first await); not one already in progress under the same id, which handleCall refuses.
        const key = link.key ? link.key(m.id) : idKey(m.id);
        const before = agent.calls.get(key);
        const handled = core.handleCall(agent, link, m.id, m, read.text);
        const begun = agent.calls.get(key);
        const call = begun && begun !== before ? begun : null;
        // The agent closing the response stream is its cancellation (2026-07-28): the stream to the upstream is closed, and the outcome is not known, as on stdio. On a legacy session it is not ("Disconnection SHOULD NOT be interpreted as the client cancelling its request"): a call that was sent runs on, bounded by the timeout, and its outcome is recorded; the agent is not there for the answer.
        res.on('close', () => {
          if (res.writableFinished || !call || call.cancelled) return;
          if (legacy && !stopping && call.state === 'sent') return agent.log({ event: 'agent-gone', legacy: true });
          call.cancelled = true;
          if (call.state === 'sent' && call.settle) {
            call.cancelUpstream?.();
            call.settle({ kind: 'error', text: stopping ? EXECUTOR_STOPPED : 'The agent closed the connection while this call was with the tool server, so its outcome is not known.', code: CODES.noAnswer });
          }
        });
        await handled;
        if (ctx.forwarded) await ctx.forwarded;
        // Withdrawn before it was sent: nothing to answer but that the connection ends.
        if (!res.writableEnded && !res.headersSent && !res.destroyed && !ctx.exchange) res.end();
        return;
      }
      // Every other request goes under an id of the executor's own, and its answer comes back under the agent's.
      const serverId = newServerId();
      const ex = exchange(ctx, { method: 'POST', headers: h.headers, body: spliceId(read.text, serverId) ?? JSON.stringify({ ...m, id: serverId }), kind: 'request', clientId: m.id, serverId, list: m.method === 'tools/list' && settings.hideUnlisted ? 'tools' : (m.method === 'tasks/list' ? 'tasks' : null), learn: m.method === 'tools/list', task: asksTask });
      // Its text, as sent, is all the exchange needs: the message as read, which may cost many times its bytes, is let go while the upstream answers.
      read = null;
      m = null;
      body = null;
      res.on('close', () => ex.cancel());
      await ex.end;
      return;
    }
    if (read.kind === 'notification') {
      // A request's method sent without an id would reach the upstream unchecked; only the protocol's own notifications pass.
      if (!m.method.startsWith('notifications/')) return notANotification(ctx, m);
      let text = read.text;
      if (m.method === 'notifications/cancelled' && isId(m.params?.requestId)) {
        // The call of this session under that id: a cancellation under another session, or none, names another call.
        const call = agent.calls.get(callKey(sessionId, m.params.requestId));
        if (call && !call.cancelled) {
          call.cancelled = true;
          const cancelled = () => {
            if (call.state !== 'sent' || !call.settle) return;
            call.cancelUpstream?.();
            call.settle({ kind: 'error', text: 'The agent cancelled this call while it was with the tool server, so its outcome is not known.', code: CODES.noAnswer });
          };
          if (legacy && call.state === 'sent') {
            // 2025-11-25: "To cancel, the client SHOULD explicitly send an MCP CancelledNotification." It goes on under the upstream's id for the call, with the upstream's answer (202) as the agent's; then the stream is closed.
            const ex = exchange(ctx, { method: 'POST', headers: h.headers, body: JSON.stringify({ ...m, params: { ...m.params, requestId: call.serverId } }), kind: 'other' });
            res.on('close', () => ex.cancel());
            await ex.end;
            cancelled();
            return;
          }
          // 2026-07-28: "closing the SSE response stream is itself the cancellation signal and no notifications/cancelled message is expected." The upstream knows the call by the executor's id; its stream is closed, and nothing more goes to it.
          cancelled();
          res.writeHead(202);
          return res.end();
        }
      }
      const ex = exchange(ctx, { method: 'POST', headers: h.headers, body: text, kind: 'other' });
      read = null;
      m = null;
      body = null;
      res.on('close', () => ex.cancel());
      await ex.end;
      return;
    }
    // The agent's response to a request of the upstream: relayed as it is, where it answers a request the executor handed on to this agent under this session, once; anything else could answer another agent's, to an upstream that tells no caller from another, and is not sent on (X451).
    const asked = callKey(sessionId, m.id);
    if (!agent.asks.has(asked)) {
      agent.log({ event: 'refused', code: 'response-not-asked' });
      return refuse(res, 400, null, CODES.invalidRequest, 'The message answers no request the upstream sent to this agent, or one already answered, so it was not sent on.');
    }
    agent.asks.delete(asked);
    const ex = exchange(ctx, { method: 'POST', headers: h.headers, body: read.text, kind: 'other' });
    read = null;
    m = null;
    body = null;
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
      return a ? { writer: a.writer, stopped: a.stopped, slip: { fingerprint: a.about.fingerprint }, calls: () => a.calls.size, open: () => a.open, held: () => ({ bodies: a.held, answers: a.answers }), sessions: () => (local ? local.count(name) : a.sessions.size) } : null;
    },
    /** In front of a local program: how many of its programs are running now, those of sessions just ended among them; null in front of an upstream HTTP server. */
    programs: () => (local ? local.programs() : null),
    executorKeys: shared.executorKeys.keys,
    /** The recorder that seals: its name, the fingerprint of its key set and the timer; null where the settings name none. */
    recorder: describeRecorder(settings, shared.sealer),
    handle,
    seal,
    acknowledge,
    report,
    /** Start listening as the settings say (or on "port", for tests). Gives {address, port}. The books are sealed on a timer from now, where the settings say so. */
    listen({ port = settings.listen.port, host = settings.listen.host } = {}) {
      if (server) throw new Error('The executor is already listening.');
      if (offline) throw new Error('The executor was opened to work on its files (offline), and does not listen.');
      // No request timeout of the server's own, which would cut a long GET stream; the headers have a minute, and the body's reading its own limit (readBody).
      server = http.createServer({ requestTimeout: 0, headersTimeout: 60000 }, handle);
      server.on('clientError', (e, socket) => {
        if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nconnection: close\r\n\r\n');
      });
      return new Promise((done, failed) => {
        server.once('error', failed);
        server.listen(port, host, () => {
          const at = server.address();
          log({ event: 'listening', address: at.address, port: at.port, path: settings.path, ...(local ? { server: settings.server.resolved, credentials: program.credentialNames } : { upstream: settings.upstream.url, credential: credential !== null }), agents: [...agents.keys()] });
          // The timer starts only once the executor is listening: a start that cannot listen seals nothing.
          timer?.start();
          done({ address: at.address, port: at.port });
        });
      });
    },
    /**
     * Stop: no new request is taken; every call that is with the upstream is
     * settled as the executor's stop (EXECUTOR_STOPPED), its receipt written
     * and the agent answered; a call waiting its turn is not sent and is
     * answered so; then the connections are closed and every agent's writer
     * finishes what it has. The answers are waited for up to STOP_WAIT ms.
     *
     * Gives {endsNotWritten}: the connections made through OAuth that were
     * ended while the executor ran and whose end could not be written to
     * the state file, even now ({agent, client, why} each; none in the usual
     * case). The file still holds them, so a start from it would bring them
     * back: whoever stops the executor must be told (the command "http" says
     * so and ends with code 1; DESIGN.md, X210).
     */
    async close() {
      stopping = true;
      // No program is started from here on: an "initialize" already in hand, whose body arrives later, begins no session (X246).
      local?.noMore();
      timer?.stop();
      const s = server;
      server = null;
      for (const a of agents.values()) {
        for (const call of a.calls.values()) {
          if (call.state === 'sent' && call.settle) {
            call.cancelUpstream?.();
            call.settle({ kind: 'error', text: EXECUTOR_STOPPED, code: CODES.noAnswer });
          }
        }
      }
      const deadline = Date.now() + STOP_WAIT;
      while ([...agents.values()].some((a) => a.calls.size > 0) && Date.now() < deadline) await new Promise((d) => setTimeout(d, 20));
      // Every session of a local program ends with the executor, and no program is started after this: each program's input is closed, and one that has not ended within "shutdownWait" is ended by force (SIGTERM, then SIGKILL). This always finishes (X242).
      if (local) await local.close();
      if (s) {
        await new Promise((done) => {
          s.close(() => done());
          s.closeAllConnections?.();
        });
      }
      for (const a of agents.values()) await a.inTurn(() => {});
      // The front door's last write, while the locks are still held: the end of a connection that the state file does not hold yet.
      const endsNotWritten = door ? door.close() : [];
      // Nothing more is written: another program may now open the files.
      await releaseAll();
      return { endsNotWritten };
    },
  };
}
