// The executor as an OAuth-protected connector (DESIGN.md, section 14,
// choices X201 onward).
//
// Over HTTP, an agent may sign in with a secret of its own (http.mjs) or,
// where the settings name "oauth", through OAuth: the MCP authorization
// specification (2025-11-25), OAuth 2.1, protected resource metadata (RFC
// 9728), authorisation server metadata (RFC 8414), PKCE (RFC 7636),
// resource indicators (RFC 8707) and clients known by a Client ID Metadata
// Document. The executor is its own authorisation server, for itself alone.
//
// What it serves, under the public address the settings name (the issuer):
//
//   GET  /.well-known/oauth-protected-resource<path>  the resource's metadata
//   GET  /.well-known/oauth-authorization-server      the server's metadata
//   GET  /oauth/authorize                             the owner's page
//   POST /oauth/authorize                             the owner's answer
//   POST /oauth/token                                 codes and refresh tokens
//
// A client is only one on the settings' list, known by the URL of its
// metadata document, which the executor fetches itself. An approved
// connection is one agent under "agents", marked "oauth": true, with its own
// slip, keys and book. The owner's check at the page is behind one
// interface (ownerCheck, X212). The one built in is by the owner's passkey
// (owner.mjs, section 14.1), with its own addresses under /oauth/owner.
//
// No cryptography is new: tokens are random bytes from Node.js, kept only
// as their SHA-256, as the agents' secrets are; PKCE's S256 is SHA-256.

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { untilFree } from './files.mjs';
import { OWNER_PATH, SETUP_LIFE, openPasskeyCheck, readOwner } from './owner.mjs';

/** Where the executor's own OAuth addresses are. */
export const OAUTH_PATH = '/oauth';
export const WELL_KNOWN = '/.well-known';
/** How long each thing lasts, in milliseconds (X207, X208, X209). */
export const REQUEST_LIFE = 10 * 60 * 1000;
export const CODE_LIFE = 60 * 1000;
export const ACCESS_LIFE = 60 * 60 * 1000;
export const REFRESH_LIFE = 30 * 24 * 60 * 60 * 1000;
/** A client's metadata document: at most this many bytes, fetched within this many milliseconds (X204). */
export const DOCUMENT_LIMIT = 5 * 1024;
export const DOCUMENT_TIME = 5000;
/** How long a document is kept before it is fetched again: its Cache-Control max-age, within these bounds (X205). */
export const DOCUMENT_KEPT = { least: 5 * 60 * 1000, usual: 60 * 60 * 1000, most: 24 * 60 * 60 * 1000 };
/** Failed attempts, counted for the whole executor (X211). */
export const OWNER_FAILURES = { most: 5, window: 15 * 60 * 1000 };
export const TOKEN_FAILURES = { most: 20, window: 60 * 1000 };
/** The executor's timeout, with OAuth, unless the settings say otherwise; a client gives a tool call up to CLIENT_LIMIT (X213). */
export const OAUTH_TIMEOUT = 230 * 1000;
export const CLIENT_LIMIT = 240 * 1000;
/** The most of each kept at once. */
export const MAX_REQUESTS = 1000;
export const MAX_ACCESS = 16;
export const MAX_SPENT = 1000;
const FORM_LIMIT = 16 * 1024;
const FORM_TIME = 10 * 1000;
const STATE_VERSION = 1;

const HASH = /^[A-Za-z0-9_-]{43}$/;
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
const PRINTABLE = /^[\x20-\x7e]*$/;

const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const hashOf = (text) => createHash('sha256').update(text, 'utf8').digest('base64url');
const newToken = () => randomBytes(32).toString('base64url');
const sameText = (a, b) => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

/** The issuer as the settings give it, or null: an https origin, or http://127.0.0.1 with a port for tests (X202). */
export function readIssuer(text) {
  if (typeof text !== 'string') return null;
  let u;
  try {
    u = new URL(text);
  } catch {
    return null;
  }
  if (u.username || u.password || u.search || u.hash || u.pathname !== '/') return null;
  if (text !== u.origin && text !== `${u.origin}/`) return null;
  if (u.protocol === 'https:') return u.origin;
  if (u.protocol === 'http:' && u.hostname === '127.0.0.1' && u.port !== '') return u.origin;
  return null;
}

/** Whether a client's id is a URL the executor may fetch: https with a path, or http://127.0.0.1 where the issuer is too (X203). */
function clientIdProblem(id, issuer) {
  if (typeof id !== 'string' || id.length > 2048) return 'is not a URL';
  let u;
  try {
    u = new URL(id);
  } catch {
    return 'is not a URL';
  }
  if (u.href !== id) return 'is not written as the URL it is (use its exact form)';
  if (u.username || u.password || u.hash) return 'has a user, a password or a fragment';
  if (u.pathname === '/' || u.pathname === '') return 'has no path';
  if (u.protocol === 'https:') return null;
  if (u.protocol === 'http:' && u.hostname === '127.0.0.1' && issuer?.startsWith('http://127.0.0.1:')) return null;
  return 'is not https';
}

/**
 * The "oauth" member of the settings, into s.oauth (null where there is
 * none). "at" records a problem, "warnings" a warning; paths are read from
 * "root" by "pathFrom".
 */
export function readOAuthSettings(config, root, s, at, warnings, pathFrom) {
  s.oauth = null;
  if (config.oauth === undefined) return;
  const o = config.oauth;
  if (!isObject(o)) {
    at('oauth', 'must be an object: issuer, clients and, where wanted, state.');
    return;
  }
  const out = { issuer: readIssuer(o.issuer), clients: [], state: null };
  if (!out.issuer) at('oauth.issuer', 'must be the executor\'s public address, as clients reach it: an https origin with no path, such as "https://guard.example.com" (the executor itself speaks plain HTTP behind a reverse proxy), or http://127.0.0.1 with a port, for tests.');
  const clients = o.clients ?? [];
  if (!Array.isArray(clients)) at('oauth.clients', 'must be a list of the URLs of the clients\' metadata documents; with none, no client can connect.');
  else {
    for (const [i, id] of clients.entries()) {
      const problem = clientIdProblem(id, out.issuer);
      if (problem) at(`oauth.clients[${i}]`, `${problem}: a client is named by the https URL of its metadata document.`);
      else if (!out.clients.includes(id)) out.clients.push(id);
    }
    if (out.clients.length === 0) warnings.push('oauth.clients: the list is empty, so no client can connect through OAuth.');
  }
  const state = o.state ?? 'oauth-state.json';
  if (typeof state !== 'string' || state === '') at('oauth.state', 'must be the path of the file that holds the connections\' state.');
  else out.state = pathFrom(root, state);
  for (const k of Object.keys(o)) if (!['issuer', 'clients', 'state'].includes(k)) warnings.push(`oauth.${k}: not a setting; set aside.`);
  s.oauth = out;
}

// --- the state file: the connections, and the copies of the client documents ---

/** Write the file whole, through a new temporary file only its owner may read, then put it in place (X210). */
function writeState(path, text) {
  const temporary = `${path}.tmp`;
  untilFree(() => rmSync(temporary, { force: true }));
  untilFree(() => writeFileSync(temporary, text, { mode: 0o600, flag: 'wx' }));
  untilFree(() => renameSync(temporary, path));
}

function readState(path) {
  let text;
  try {
    text = untilFree(() => readFileSync(path, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') return { version: STATE_VERSION, grants: [], documents: {}, owner: null, setup: null };
    throw new Error(`oauth.state: the file could not be read (${e.code ?? e.message}).`);
  }
  let state;
  try {
    state = JSON.parse(text);
  } catch {
    throw new Error('oauth.state: the file is not JSON. It is the executor\'s own; it is not read past this.');
  }
  const grantOk = (g) => isObject(g) && typeof g.id === 'string' && typeof g.agent === 'string' && typeof g.client === 'string' && typeof g.resource === 'string' && (g.scope === null || typeof g.scope === 'string') && (g.refresh === null || HASH.test(g.refresh)) && Number.isInteger(g.refreshExpires) && Array.isArray(g.spent) && g.spent.every((h) => HASH.test(h)) && Array.isArray(g.access) && g.access.every((a) => isObject(a) && HASH.test(a.hash) && Number.isInteger(a.expires));
  // The owner and a setup waiting for its link (X226): absent in a file written before them, which is read as having neither.
  const ownerOk = (v) => v === undefined || v === null || (isObject(v) && Number.isInteger(v.created) && !readOwner({ routingPublicKey: v.routingPublicKey, passkey: v.passkey, recovery: v.recovery }).problem && Object.keys(v).length === 4);
  const setupOk = (v) => v === undefined || v === null || (isObject(v) && typeof v.hash === 'string' && HASH.test(v.hash) && Number.isInteger(v.expires));
  if (!isObject(state) || state.version !== STATE_VERSION || !Array.isArray(state.grants) || !state.grants.every(grantOk) || !isObject(state.documents) || !ownerOk(state.owner) || !setupOk(state.setup)) {
    throw new Error('oauth.state: the file is not in the form the executor writes.');
  }
  state.owner ??= null;
  state.setup ??= null;
  return state;
}

/**
 * Make a one-time setup link for the owner, on the files of an executor
 * that is not running (the command "owner"). Refused where an owner exists,
 * unless "reset": then the owner is removed and every connection ends, with
 * its tokens. Gives {link, expires, revoked} (X218, X223).
 */
export function makeOwnerSetup(settings, { reset = false, now = Date.now } = {}) {
  const o = settings.oauth;
  const state = readState(o.state);
  if (state.owner && !reset) throw new Error('An owner is already set up on this executor, so a second setup is refused. To replace the owner, run the command again with --reset: every connection then ends, with its tokens.');
  const revoked = reset ? state.grants.length : 0;
  if (reset) {
    state.grants = [];
    state.owner = null;
  }
  const code = newToken();
  state.setup = { hash: hashOf(code), expires: now() + SETUP_LIFE };
  writeState(o.state, JSON.stringify(state));
  return { link: `${o.issuer}${OWNER_PATH}#${code}`, expires: state.setup.expires, revoked };
}

// --- a client's metadata document ---

/**
 * Fetch the document at "url": no redirection followed, at most
 * DOCUMENT_LIMIT bytes, within DOCUMENT_TIME ms. Gives {document, kept}
 * (how long it may be kept, from Cache-Control) or throws.
 */
export function fetchDocument(url, { limit = DOCUMENT_LIMIT, time = DOCUMENT_TIME } = {}) {
  return new Promise((done, failed) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    let finished = false;
    const fail = (why) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      req.destroy();
      failed(new Error(why));
    };
    const req = lib.get(u, { agent: false, headers: { accept: 'application/json' } });
    const timer = setTimeout(() => fail(`no whole answer within ${time} ms`), time);
    req.on('error', (e) => fail(e.code ?? e.message));
    req.on('response', (res) => {
      if (res.statusCode !== 200) return fail(`the answer was ${res.statusCode}, not 200`);
      if (Number(res.headers['content-length'] ?? 0) > limit) return fail(`the document is longer than ${limit} bytes`);
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > limit) return fail(`the document is longer than ${limit} bytes`);
        chunks.push(c);
      });
      res.on('error', (e) => fail(e.code ?? e.message));
      res.on('end', () => {
        if (finished) return;
        let document;
        try {
          document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
        } catch {
          return fail('the document is not JSON');
        }
        finished = true;
        clearTimeout(timer);
        const age = /(?:^|,)\s*max-age=(\d{1,10})\s*(?:,|$)/i.exec(String(res.headers['cache-control'] ?? ''));
        const kept = age ? Math.min(Math.max(Number(age[1]) * 1000, DOCUMENT_KEPT.least), DOCUMENT_KEPT.most) : DOCUMENT_KEPT.usual;
        done({ document, kept });
      });
    });
  });
}

/** What the executor reads of a client's document, or {problem} (X203). */
export function readDocument(document, url) {
  if (!isObject(document)) return { problem: 'the document is not a JSON object' };
  if (document.client_id !== url) return { problem: 'the document\'s client_id is not the URL it was fetched from' };
  const uris = document.redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0 || uris.length > 20 || !uris.every((r) => typeof r === 'string' && r.length <= 2048)) return { problem: 'the document names no redirect_uris' };
  if (document.token_endpoint_auth_method !== 'none') return { problem: 'the document\'s token_endpoint_auth_method is not "none" (the executor knows only public clients)' };
  if (document.grant_types !== undefined && !(Array.isArray(document.grant_types) && document.grant_types.includes('authorization_code'))) return { problem: 'the document\'s grant_types do not include authorization_code' };
  if (document.response_types !== undefined && !(Array.isArray(document.response_types) && document.response_types.includes('code'))) return { problem: 'the document\'s response_types do not include code' };
  const name = typeof document.client_name === 'string' && document.client_name.length <= 200 ? document.client_name : null;
  return { client: { id: url, redirectUris: [...uris], name } };
}

/**
 * Whether the redirect URI asked for is one the document names: the same
 * text, except that for a loopback address written as an IP address
 * (http://127.0.0.1 or http://[::1]) the port may differ, as OAuth 2.1
 * says for programs on the person's own computer (X206).
 */
export function redirectMatches(registered, asked) {
  if (typeof asked !== 'string') return false;
  if (registered.includes(asked)) return true;
  let a;
  try {
    a = new URL(asked);
  } catch {
    return false;
  }
  if (a.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(a.hostname)) return false;
  return registered.some((r) => {
    try {
      const u = new URL(r);
      if (u.protocol !== 'http:' || u.hostname !== a.hostname) return false;
      u.port = a.port;
      return u.href === a.href && asked === a.href;
    } catch {
      return false;
    }
  });
}

// --- the page ---

const escape = (text) => String(text).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function page(title, body) {
  return `<!doctype html>\n<html lang="en-GB">\n<head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escape(title)}</title></head>\n<body>\n<h1>${escape(title)}</h1>\n${body}\n</body>\n</html>\n`;
}

function sendPage(res, status, title, body, { formTo = [], scripts = false } = {}) {
  if (res.headersSent) return;
  const text = Buffer.from(page(title, body));
  // Nothing on the page loads or frames, and nothing runs but a script from the executor's own address where the owner's check has one, which fetches from there only (X224); the form goes to the executor, which then sends the browser to the client (X212).
  const csp = `default-src 'none';${scripts ? " script-src 'self'; connect-src 'self';" : ''} form-action 'self'${formTo.map((o) => ` ${o}`).join('')}; frame-ancestors 'none'; base-uri 'none'`;
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'content-length': text.length,
    'cache-control': 'no-store',
    'content-security-policy': csp,
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
  });
  res.end(text);
}

function sendJson(res, status, value, extra = {}) {
  if (res.headersSent) return;
  const text = Buffer.from(`${JSON.stringify(value)}\n`);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': text.length, 'cache-control': 'no-store', pragma: 'no-cache', ...extra });
  res.end(text);
}

function redirect(res, to) {
  if (res.headersSent) return;
  res.writeHead(303, { location: to, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'content-length': 0 });
  res.end();
}

/** A form body, read to FORM_LIMIT bytes within FORM_TIME ms: URLSearchParams, or null. */
function readForm(req) {
  return new Promise((done) => {
    const type = String(req.headers['content-type'] ?? '').toLowerCase();
    if (!/^application\/x-www-form-urlencoded\s*(;|$)/.test(type)) {
      req.resume();
      return done(null);
    }
    const chunks = [];
    let size = 0;
    let over = false;
    const timer = setTimeout(() => {
      over = true;
      req.destroy();
      done(null);
    }, FORM_TIME);
    req.on('data', (c) => {
      size += c.length;
      if (size > FORM_LIMIT && !over) {
        over = true;
        clearTimeout(timer);
        done(null);
      }
      if (!over) chunks.push(c);
    });
    req.on('error', () => {
      clearTimeout(timer);
      if (!over) done(null);
    });
    req.on('end', () => {
      clearTimeout(timer);
      if (over) return;
      try {
        done(new URLSearchParams(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))));
      } catch {
        done(null);
      }
    });
  });
}

/** A named parameter given more than once, or null. */
const repeated = (params) => [...new Set(params.keys())].find((k) => params.getAll(k).length > 1) ?? null;

/** A count of failures over a window; past "most", everything is refused until the window has passed since the first (X211). */
function failureCount({ most, window }, now) {
  let first = 0;
  let count = 0;
  return {
    locked() {
      if (now() - first >= window) count = 0;
      return count >= most;
    },
    failed() {
      if (now() - first >= window) {
        first = now();
        count = 0;
      }
      count += 1;
    },
    retryAfter: () => Math.max(1, Math.ceil((first + window - now()) / 1000)),
  };
}

/**
 * The front door: the OAuth addresses and the check of an access token.
 *
 * settings  the executor's settings (settings.oauth, settings.path, settings.name, settings.agents)
 * ownerCheck  the owner's check at the page: {form() -> HTML of its fields, check(fields, {request, origin}) -> Promise<boolean>},
 *           with, where it has them, "scripts" (the page runs a script of the executor's own) and its own addresses
 *           (owns(path), take(req, res, path)); null for none; left out, the check by the owner's passkey (owner.mjs)
 * fetch     fetchDocument, or a stand-in
 */
export function openFrontDoor({ settings, now = Date.now, log = () => {}, ownerCheck: given = undefined, fetch = fetchDocument }) {
  const o = settings.oauth;
  const issuer = o.issuer;
  const resource = `${issuer}${settings.path}`;
  const resourceMetadataPath = `${WELL_KNOWN}/oauth-protected-resource${settings.path === '/' ? '' : settings.path}`;
  const resourceMetadataUrl = `${issuer}${resourceMetadataPath}`;
  const serverMetadataPath = `${WELL_KNOWN}/oauth-authorization-server`;
  const oauthAgents = [...settings.agents].filter(([, p]) => p.oauth === true).map(([name]) => name);

  const state = readState(o.state);
  // Each access token, refresh token and spent refresh token, by its hash, to the grant it belongs to.
  const byAccess = new Map();
  const byRefresh = new Map();
  const bySpent = new Map();
  const index = () => {
    byAccess.clear();
    byRefresh.clear();
    bySpent.clear();
    for (const g of state.grants) {
      for (const a of g.access) byAccess.set(a.hash, { grant: g, expires: a.expires });
      if (g.refresh) byRefresh.set(g.refresh, g);
      for (const h of g.spent) bySpent.set(h, g);
    }
  };
  const save = () => {
    const t = now();
    for (const g of state.grants) g.access = g.access.filter((a) => a.expires > t);
    state.grants = state.grants.filter((g) => g.refreshExpires > t || g.access.length > 0);
    for (const k of Object.keys(state.documents)) if (!o.clients.includes(k)) delete state.documents[k];
    index();
    writeState(o.state, JSON.stringify(state));
  };
  index();
  const revoke = (grant, why) => {
    state.grants = state.grants.filter((g) => g !== grant);
    save();
    log({ event: 'oauth-revoked', agent: grant.agent, client: grant.client, why });
  };

  // In memory only: the owner's pages waiting for an answer, and the codes (X207).
  const requests = new Map();
  const codes = new Map();
  const tidy = () => {
    const t = now();
    for (const [k, r] of requests) if (r.expires <= t) requests.delete(k);
    for (const [k, c] of codes) if (c.expires + REQUEST_LIFE <= t) codes.delete(k);
  };
  const ownerFailures = failureCount(OWNER_FAILURES, now);
  const tokenFailures = failureCount(TOKEN_FAILURES, now);

  // The owner's check: the one given, or by the owner's passkey (owner.mjs), which keeps the owner in the state file.
  const ownerCheck = given !== undefined ? given : openPasskeyCheck({
    issuer,
    now,
    log,
    store: {
      owner: () => state.owner,
      setup: () => state.setup,
      setOwner: (owner) => {
        state.owner = owner;
        state.setup = null;
        save();
      },
    },
    failures: ownerFailures,
    isRequest: (id) => {
      const r = requests.get(id);
      return r !== undefined && r.expires > now();
    },
    page: (res, status, title, body) => sendPage(res, status, title, body, { scripts: true }),
    json: sendJson,
    hashOf,
  });
  const checkOwns = (path) => typeof ownerCheck?.owns === 'function' && ownerCheck.owns(path);

  /** The client's document: the copy while it is fresh, else fetched again; where the fetch fails, the copy kept, however old (X205). */
  async function clientFor(id) {
    const kept = state.documents[id];
    if (kept && kept.until > now()) return readDocument(kept.document, id);
    try {
      const got = await fetch(id);
      const read = readDocument(got.document, id);
      if (read.problem) {
        log({ event: 'oauth-document-refused', client: id, problem: read.problem });
        return read;
      }
      state.documents[id] = { document: got.document, fetched: now(), until: now() + got.kept };
      save();
      return read;
    } catch (e) {
      if (kept) {
        log({ event: 'oauth-document-copy', client: id, problem: e.message });
        return readDocument(kept.document, id);
      }
      log({ event: 'oauth-document-unreachable', client: id, problem: e.message });
      return { problem: `the client's document could not be fetched (${e.message})` };
    }
  }

  const resourceMetadata = () => ({ resource, authorization_servers: [issuer], bearer_methods_supported: ['header'], resource_name: settings.name });
  const serverMetadata = () => ({
    issuer,
    authorization_endpoint: `${issuer}${OAUTH_PATH}/authorize`,
    token_endpoint: `${issuer}${OAUTH_PATH}/token`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
  });

  const back = (res, to, params) => {
    const u = new URL(to);
    for (const [k, v] of Object.entries(params)) if (v !== null && v !== undefined) u.searchParams.append(k, v);
    u.searchParams.append('iss', issuer);
    redirect(res, u.href);
  };
  const problemPage = (res, status, text) => sendPage(res, status, 'The connection cannot be made', `<p>${escape(text)}</p>`);

  /** GET /oauth/authorize: the request is checked, then the owner is shown the page (X203, X206, X207). */
  async function askOwner(req, res, query) {
    const twice = repeated(query);
    if (twice) return problemPage(res, 400, `The request names ${twice} more than once.`);
    const clientId = query.get('client_id');
    if (!clientId || !o.clients.includes(clientId)) {
      log({ event: 'oauth-refused', code: 'client-not-listed' });
      return problemPage(res, 400, 'This client is not one the executor\'s settings name, so it cannot connect.');
    }
    const { client, problem } = await clientFor(clientId);
    if (problem) return problemPage(res, 502, `The client's metadata document is not usable: ${problem}.`);
    const to = query.get('redirect_uri');
    if (!redirectMatches(client.redirectUris, to)) {
      log({ event: 'oauth-refused', code: 'redirect-not-registered', client: clientId });
      return problemPage(res, 400, 'The redirect address is not one the client\'s metadata document names.');
    }
    const st = query.get('state');
    const fail = (error, description) => {
      log({ event: 'oauth-refused', code: error, client: clientId });
      back(res, to, { error, error_description: description, state: st });
    };
    if (st !== null && (st.length > 2048 || !PRINTABLE.test(st))) return fail('invalid_request', 'state is longer than 2048 characters or not printable');
    if (query.get('response_type') !== 'code') return fail('unsupported_response_type', 'only response_type=code is supported');
    const challenge = query.get('code_challenge');
    if (challenge === null) return fail('invalid_request', 'PKCE is required: send code_challenge and code_challenge_method=S256');
    if (query.get('code_challenge_method') !== 'S256') return fail('invalid_request', 'only code_challenge_method=S256 is supported');
    if (!CHALLENGE.test(challenge)) return fail('invalid_request', 'code_challenge is not an S256 challenge (43 characters of base64url)');
    if (query.get('resource') !== resource) return fail('invalid_target', `resource must be ${resource}`);
    const scope = query.get('scope');
    if (scope !== null && (scope.length > 1024 || !PRINTABLE.test(scope))) return fail('invalid_scope', 'scope is longer than 1024 characters or not printable');
    if (oauthAgents.length === 0) return fail('access_denied', 'the executor has no agent for connections');
    tidy();
    if (requests.size >= MAX_REQUESTS) requests.delete(requests.keys().next().value);
    const id = newToken();
    requests.set(id, { client, redirectUri: to, state: st, challenge, scope, expires: now() + REQUEST_LIFE });
    const where = new URL(to);
    const options = oauthAgents.map((n) => `<option value="${escape(n)}">${escape(n)}</option>`).join('');
    const check = ownerCheck ? ownerCheck.form() : '<p>No owner\'s check is set up on this executor, so no connection can be approved here.</p>';
    const body = [
      `<p><strong>${escape(client.name ?? new URL(client.id).host)}</strong> (client ${escape(client.id)}) asks to connect to ${escape(settings.name ?? 'this executor')} at ${escape(resource)}.</p>`,
      `<p>Once approved, it is one agent: it may call the tools that agent's permission allows, and each call gets a receipt in that agent's book. The answer goes to ${escape(where.origin)}.</p>`,
      `<form method="post" action="${OAUTH_PATH}/authorize">`,
      `<input type="hidden" name="request" value="${id}">`,
      `<p><label>The agent it becomes <select name="agent">${options}</select></label></p>`,
      check,
      '<p><button type="submit" name="decision" value="approve">Approve</button> <button type="submit" name="decision" value="refuse">Refuse</button></p>',
      '</form>',
    ].join('\n');
    sendPage(res, 200, 'Approve a connection', body, { formTo: [where.origin], scripts: ownerCheck?.scripts === true });
  }

  /** POST /oauth/authorize: the owner's answer (X212). */
  async function ownerAnswers(req, res) {
    if (req.headers.origin !== issuer) {
      req.resume();
      log({ event: 'oauth-refused', code: 'origin-refused' });
      return problemPage(res, 403, 'The answer must come from the executor\'s own page.');
    }
    const form = await readForm(req);
    if (!form || repeated(form)) return problemPage(res, 400, 'The answer is not a form the page sends.');
    tidy();
    const id = form.get('request') ?? '';
    const r = requests.get(id);
    if (!r) return problemPage(res, 400, 'This request has ended or is not known. Begin again from the client.');
    if (form.get('decision') === 'refuse') {
      requests.delete(id);
      log({ event: 'oauth-refused', code: 'access-denied', client: r.client.id });
      return back(res, r.redirectUri, { error: 'access_denied', error_description: 'the owner refused', state: r.state });
    }
    if (form.get('decision') !== 'approve') return problemPage(res, 400, 'The answer is neither approve nor refuse.');
    if (ownerFailures.locked()) {
      log({ event: 'oauth-refused', code: 'too-many-attempts' });
      res.setHeader('retry-after', String(ownerFailures.retryAfter()));
      return problemPage(res, 429, 'Too many failed attempts. Wait, then begin again.');
    }
    if (!ownerCheck) return problemPage(res, 503, 'No owner\'s check is set up on this executor, so no connection can be approved.');
    const agent = form.get('agent');
    if (!oauthAgents.includes(agent)) return problemPage(res, 400, 'That is not an agent for connections.');
    let proved = false;
    try {
      proved = (await ownerCheck.check(form, { request: id, origin: issuer })) === true;
    } catch {
      proved = false;
    }
    if (!proved) {
      ownerFailures.failed();
      log({ event: 'oauth-refused', code: 'owner-not-proved' });
      return problemPage(res, 403, 'The owner\'s check did not pass. Go back and try again.');
    }
    requests.delete(id);
    const code = newToken();
    codes.set(hashOf(code), { client: r.client.id, redirectUri: r.redirectUri, challenge: r.challenge, scope: r.scope, agent, expires: now() + CODE_LIFE, used: false, grant: null });
    log({ event: 'oauth-approved', agent, client: r.client.id });
    back(res, r.redirectUri, { code, state: r.state });
  }

  const tokenError = (res, status, error, description) => {
    tokenFailures.failed();
    log({ event: 'oauth-refused', code: error, description });
    sendJson(res, status, { error, error_description: description });
  };

  /** A new access token and refresh token for a grant; the refresh token it replaces, if any, becomes spent (X208, X209). */
  const issue = (res, grant) => {
    const access = newToken();
    const refresh = newToken();
    if (grant.refresh) {
      grant.spent.push(grant.refresh);
      if (grant.spent.length > MAX_SPENT) grant.spent.splice(0, grant.spent.length - MAX_SPENT);
    }
    grant.refresh = hashOf(refresh);
    grant.refreshExpires = now() + REFRESH_LIFE;
    grant.access.push({ hash: hashOf(access), expires: now() + ACCESS_LIFE });
    if (grant.access.length > MAX_ACCESS) grant.access.splice(0, grant.access.length - MAX_ACCESS);
    save();
    const out = { access_token: access, token_type: 'Bearer', expires_in: ACCESS_LIFE / 1000, refresh_token: refresh };
    if (grant.scope !== null) out.scope = grant.scope;
    sendJson(res, 200, out);
  };

  /** POST /oauth/token (X207, X208, X209). */
  async function token(req, res) {
    if (tokenFailures.locked()) {
      req.resume();
      log({ event: 'oauth-refused', code: 'too-many-attempts' });
      return sendJson(res, 429, { error: 'temporarily_unavailable', error_description: 'too many failed attempts; try again later' }, { 'retry-after': String(tokenFailures.retryAfter()) });
    }
    const form = await readForm(req);
    if (!form) return tokenError(res, 400, 'invalid_request', 'the body must be application/x-www-form-urlencoded, at most 16 KiB');
    const twice = repeated(form);
    if (twice) return tokenError(res, 400, 'invalid_request', `${twice} is given more than once`);
    const clientId = form.get('client_id');
    if (!clientId || !o.clients.includes(clientId)) return tokenError(res, 401, 'invalid_client', 'the client is not one the executor\'s settings name');
    const asked = form.get('resource');
    if (asked !== null && asked !== resource) return tokenError(res, 400, 'invalid_target', `resource must be ${resource}`);
    const grantType = form.get('grant_type');
    if (grantType === 'authorization_code') {
      const code = form.get('code') ?? '';
      const key = hashOf(code);
      const c = codes.get(key);
      if (!c) return tokenError(res, 400, 'invalid_grant', 'the code is not known');
      if (c.used) {
        // A code used twice: refused, and whatever was issued for it is revoked (OAuth 2.1).
        codes.delete(key);
        const g = state.grants.find((x) => x.id === c.grant);
        if (g) revoke(g, 'code-used-twice');
        return tokenError(res, 400, 'invalid_grant', 'the code has already been used');
      }
      if (c.expires <= now()) return tokenError(res, 400, 'invalid_grant', 'the code has expired');
      if (c.client !== clientId) return tokenError(res, 400, 'invalid_grant', 'the code was issued to another client');
      if (form.get('redirect_uri') !== c.redirectUri) return tokenError(res, 400, 'invalid_grant', 'redirect_uri is not the one the code was issued for');
      const verifier = form.get('code_verifier');
      if (verifier === null || !VERIFIER.test(verifier) || !sameText(hashOf(verifier), c.challenge)) return tokenError(res, 400, 'invalid_grant', 'code_verifier does not match the code_challenge');
      c.used = true;
      // One connection for each agent: approving a new one ends the one before (X201).
      for (const old of state.grants.filter((g) => g.agent === c.agent)) revoke(old, 'replaced');
      const grant = { id: newToken(), agent: c.agent, client: c.client, resource, scope: c.scope, created: now(), refresh: null, refreshExpires: 0, spent: [], access: [] };
      c.grant = grant.id;
      state.grants.push(grant);
      log({ event: 'oauth-connected', agent: grant.agent, client: grant.client });
      return issue(res, grant);
    }
    if (grantType === 'refresh_token') {
      const key = hashOf(form.get('refresh_token') ?? '');
      const spent = bySpent.get(key);
      if (spent) {
        // A refresh token used twice: the whole family is revoked (X209).
        revoke(spent, 'refresh-token-used-twice');
        return tokenError(res, 400, 'invalid_grant', 'the refresh token has already been used; the connection is ended');
      }
      const grant = byRefresh.get(key);
      if (!grant || grant.refreshExpires <= now()) return tokenError(res, 400, 'invalid_grant', 'the refresh token is not known or has expired');
      if (grant.client !== clientId) return tokenError(res, 400, 'invalid_grant', 'the refresh token was issued to another client');
      if (grant.resource !== resource) return tokenError(res, 400, 'invalid_grant', 'the refresh token was issued for another resource');
      if (form.get('scope') !== null && form.get('scope') !== grant.scope) return tokenError(res, 400, 'invalid_scope', 'a refresh keeps the scope of the approval');
      return issue(res, grant);
    }
    return tokenError(res, 400, 'unsupported_grant_type', 'grant_type must be authorization_code or refresh_token');
  }

  return {
    resource,
    resourceMetadataUrl,
    /** Whether a path is one of the front door's. */
    owns: (path) => path === resourceMetadataPath || path === serverMetadataPath || path === `${OAUTH_PATH}/authorize` || path === `${OAUTH_PATH}/token` || checkOwns(path),
    /** Answer a request to one of the front door's paths. */
    async take(req, res, path) {
      if (checkOwns(path)) return ownerCheck.take(req, res, path);
      if (path === resourceMetadataPath || path === serverMetadataPath) {
        req.resume();
        if (req.method !== 'GET' && req.method !== 'HEAD') return sendJson(res, 405, { error: 'invalid_request', error_description: 'GET only' }, { allow: 'GET, HEAD' });
        return sendJson(res, 200, path === serverMetadataPath ? serverMetadata() : resourceMetadata(), { 'cache-control': 'max-age=300' });
      }
      if (path === `${OAUTH_PATH}/authorize`) {
        if (req.method === 'GET') {
          req.resume();
          return askOwner(req, res, new URL(req.url, issuer).searchParams);
        }
        if (req.method === 'POST') return ownerAnswers(req, res);
        req.resume();
        return problemPage(res, 405, 'The page takes GET and POST.');
      }
      if (req.method !== 'POST') {
        req.resume();
        return sendJson(res, 405, { error: 'invalid_request', error_description: 'POST only' }, { allow: 'POST' });
      }
      return token(req, res);
    },
    /**
     * The agent an access token stands for, or null: a token the executor
     * issued, not expired, for this resource, to a client still on the list,
     * for an agent still marked for connections (X208).
     */
    agentFor(text) {
      const found = byAccess.get(hashOf(text));
      if (!found || found.expires <= now()) return null;
      const g = found.grant;
      if (g.resource !== resource || !o.clients.includes(g.client) || !oauthAgents.includes(g.agent)) return null;
      return g.agent;
    },
    /** The WWW-Authenticate header of a 401 at the MCP endpoint (RFC 9728, section 5.1; RFC 6750). */
    challenge: (tokenGiven) => `Bearer resource_metadata="${resourceMetadataUrl}"${tokenGiven ? ', error="invalid_token"' : ''}`,
  };
}
