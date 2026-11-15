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
// as their SHA-256, as the agents' secrets are; PKCE's S256 is SHA-256; a
// request waiting at the page is kept in its form under Node.js's
// HMAC-SHA-256, as a JWS with HS256 (X228).

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { closeSync, fsyncSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { untilFree } from './files.mjs';
import { OWNER_PATH, SETUP_LIFE, isOldOwner, openPasskeyCheck, readOwner } from './owner.mjs';

/** Where the executor's own OAuth addresses are. */
export const OAUTH_PATH = '/oauth';
export const WELL_KNOWN = '/.well-known';
/** The names an owner's check may give for the proof that passed (X274). They approve, as true does; no other value does (X282). */
export const PROOFS = Object.freeze(['passkey', 'recovery', 'setup']);
/** How long each thing lasts, in milliseconds (X207, X208, X209). */
export const REQUEST_LIFE = 10 * 60 * 1000;
export const CODE_LIFE = 60 * 1000;
export const ACCESS_LIFE = 60 * 60 * 1000;
export const REFRESH_LIFE = 30 * 24 * 60 * 60 * 1000;
/** A client's metadata document: at most this many bytes, fetched within this many milliseconds (X204). */
export const DOCUMENT_LIMIT = 5 * 1024;
export const DOCUMENT_TIME = 5000;
/** How long a document is kept before it is fetched again: its Cache-Control max-age, within these bounds; "longest" is how old a copy may be and still stand in for a fetch that got no answer (X205). */
export const DOCUMENT_KEPT = { least: 5 * 60 * 1000, usual: 60 * 60 * 1000, most: 24 * 60 * 60 * 1000, longest: 7 * 24 * 60 * 60 * 1000 };
/** After a fetch of a document has failed, no new one is made for this long (X205). */
export const DOCUMENT_RETRY = 60 * 1000;
/** The executor's timeout, with OAuth, unless the settings say otherwise; a client gives a tool call up to CLIENT_LIMIT (X213). */
export const OAUTH_TIMEOUT = 230 * 1000;
export const CLIENT_LIMIT = 240 * 1000;
/** The most of each kept at once. */
export const MAX_ACCESS = 16;
export const MAX_SPENT = 1000;
const FORM_LIMIT = 16 * 1024;
const FORM_TIME = 10 * 1000;
const STATE_VERSION = 1;
/** How long each step of a write of the state file is tried again while another program holds the file, in seconds (X210). */
const STATE_WAIT = 1;
/** How often a write of the state file that failed where a connection was ended is tried again, in milliseconds (X210). */
export const STATE_RETRY = 1000;

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

/** A local address, for tests: 127.0.0.1, or the name "localhost", which a browser takes for this computer and at which, unlike an IP address, it lets a passkey be made (X277). */
const LOCAL_HOSTS = ['127.0.0.1', 'localhost'];

/** The issuer as the settings give it, or null: an https origin, or http://127.0.0.1 or http://localhost with a port for tests (X202, X277). */
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
  if (u.protocol === 'http:' && LOCAL_HOSTS.includes(u.hostname) && u.port !== '') return u.origin;
  return null;
}

/** Whether a client's id is a URL the executor may fetch: https with a path, or http://127.0.0.1 where the issuer is a local address too (X203, X277). */
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
  if (u.protocol === 'http:' && u.hostname === '127.0.0.1' && LOCAL_HOSTS.some((h) => issuer?.startsWith(`http://${h}:`))) return null;
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
  if (!out.issuer) at('oauth.issuer', 'must be the executor\'s public address, as clients reach it: an https origin with no path, such as "https://guard.example.com" (the executor itself speaks plain HTTP behind a reverse proxy), or http://127.0.0.1 or http://localhost with a port, for tests.');
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

/** Write the file whole, through a new temporary file only its owner may read, made sure to be on the disk and then put in place (X210). Each step is tried again for "wait" seconds while another program holds the file. */
function writeState(path, text, wait = STATE_WAIT) {
  const temporary = `${path}.tmp`;
  untilFree(() => rmSync(temporary, { force: true }), wait);
  const fd = untilFree(() => openSync(temporary, 'wx', 0o600), wait);
  try {
    writeFileSync(fd, text);
    // On the disk before it takes the old file's place: a power cut then leaves the old file or the new, never an empty one.
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  untilFree(() => renameSync(temporary, path), wait);
}

/**
 * The seal of a request waiting at the page, which is kept in the page's
 * form and not in memory (X228): its fields under HMAC-SHA-256 (RFC 2104),
 * written as a JWS in compact form with HS256 (RFC 7515; RFC 7518, section
 * 3.2). The key is 32 random bytes made now, held in memory and never
 * written, so a start ends every waiting request.
 */
const SEAL_HEADER = Buffer.from('{"alg":"HS256"}').toString('base64url');
function newSeal() {
  const key = randomBytes(32);
  const mac = (text) => createHmac('sha256', key).update(text, 'utf8').digest('base64url');
  return {
    seal(value) {
      const body = `${SEAL_HEADER}.${Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')}`;
      return `${body}.${mac(body)}`;
    },
    /** The value sealed, or null where the text is not one this executor sealed since its start. The MAC is over the header and the fields as they were sent, so a text with another header, or with one character changed, does not pass. */
    open(text) {
      if (typeof text !== 'string' || text.length > FORM_LIMIT) return null;
      const parts = text.split('.');
      if (parts.length !== 3 || !sameText(parts[2], mac(`${parts[0]}.${parts[1]}`))) return null;
      try {
        return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      } catch {
        return null;
      }
    },
  };
}

/** What a start says of a state file whose owner is in the form of the builds before the plain passkey, which were never released (X278). */
const OLD_OWNER = 'oauth.state: the file holds an owner in an earlier form (a key kept in the browser, which this version does not use), so it cannot be read. Run "provared-mcp-executor owner --config <settings> --reset": it removes that owner, ends every connection, and prints a new setup link.';

/** The state file, read whole. "forReset": an owner in the earlier form is let through as it is, since the caller is about to remove it. */
function readState(path, { forReset = false } = {}) {
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
  if (isObject(state) && isOldOwner(state.owner)) {
    if (!forReset) throw new Error(OLD_OWNER);
    // Only that it is there matters to a reset, which removes it.
    state.owner = { earlier: true };
  }
  // "recoverySpent" is there, and true, only once the recovery code has been used (X282): an owner whose code still works has the four members it always had.
  const ownerOk = (v) => v === undefined || v === null || (forReset && v.earlier === true) || (isObject(v) && Number.isInteger(v.created) && !readOwner({ credentialId: v.credentialId, key: v.key, recoveryHash: v.recoveryHash }).problem && Object.keys(v).length === (Object.hasOwn(v, 'recoverySpent') ? 5 : 4) && (!Object.hasOwn(v, 'recoverySpent') || v.recoverySpent === true));
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
  const state = readState(o.state, { forReset: reset });
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
    // "passing": there was no answer, or the client's server said the fault was its own (5xx), so a copy kept may stand in (X205).
    const fail = (why, passing = false) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      req.destroy();
      failed(Object.assign(new Error(why), { passing }));
    };
    const req = lib.get(u, { agent: false, headers: { accept: 'application/json' } });
    const timer = setTimeout(() => fail(`no whole answer within ${time} ms`, true), time);
    req.on('error', (e) => fail(e.code ?? e.message, true));
    req.on('response', (res) => {
      if (res.statusCode !== 200) return fail(`the answer was ${res.statusCode}, not 200`, res.statusCode >= 500);
      if (Number(res.headers['content-length'] ?? 0) > limit) return fail(`the document is longer than ${limit} bytes`);
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > limit) return fail(`the document is longer than ${limit} bytes`);
        chunks.push(c);
      });
      res.on('error', (e) => fail(e.code ?? e.message, true));
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
        const cache = String(res.headers['cache-control'] ?? '');
        const age = /(?:^|,)\s*max-age=(\d{1,10})\s*(?:,|$)/i.exec(cache);
        // A document that asks not to be kept (no-store, no-cache) is kept for the least time, as one with max-age=0 is.
        const never = /(?:^|,)\s*no-(?:store|cache)\s*(?:,|$)/i.test(cache);
        const kept = never ? DOCUMENT_KEPT.least : age ? Math.min(Math.max(Number(age[1]) * 1000, DOCUMENT_KEPT.least), DOCUMENT_KEPT.most) : DOCUMENT_KEPT.usual;
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
    // Not no-referrer: under that policy a browser sends the page's own form with "Origin: null", and the owner's answer is refused. With same-origin the form carries the executor's origin, and still no referrer goes to another site (X212).
    'referrer-policy': 'same-origin',
  });
  res.end(text);
}

function sendJson(res, status, value, extra = {}) {
  if (res.headersSent) return;
  const text = Buffer.from(`${JSON.stringify(value)}\n`);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': text.length, 'cache-control': 'no-store', pragma: 'no-cache', 'x-content-type-options': 'nosniff', ...extra });
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

/**
 * The front door: the OAuth addresses and the check of an access token.
 * Opened once the agents' files are locked for this program (http.mjs), since
 * it reads the state file and may write it at once.
 *
 * settings  the executor's settings (settings.oauth, settings.path, settings.name, settings.agents)
 * ownerCheck  the owner's check at the page: {form() -> HTML of its fields, check(fields, {request, origin, note}) -> Promise<boolean>},
 *           where true approves, as does the name of the proof that passed, one of PROOFS, and nothing else does (X282),
 *           with, where it has them, "scripts" (the page runs a script of the executor's own) and its own addresses
 *           (owns(path), take(req, res, path)); null for none; left out, the check by the owner's passkey (owner.mjs).
 *           The executor counts no failed attempts (X211), so what a check asks for must not be guessable.
 * fetch     fetchDocument, or a stand-in
 */
export function openFrontDoor({ settings, now = Date.now, log = () => {}, ownerCheck: given = undefined, fetch = fetchDocument }) {
  const o = settings.oauth;
  const issuer = o.issuer;
  const resource = `${issuer}${settings.path}`;
  /** Whether a resource a client names is the executor's: the same text, but that the scheme and the host may be in capitals, as the MCP specification asks a server to take them (X207). The path is compared as it is. */
  const isResource = (asked) => typeof asked === 'string' && asked.slice(0, issuer.length).toLowerCase() === issuer && asked.slice(issuer.length) === settings.path;
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
  // The connections ended in memory whose end the file does not hold yet, since it could not be written: {agent, client, why} each. While there are any, the write is tried again on a timer, and once more at close (X210).
  let unwritten = [];
  let retry = null;
  const save = (wait = STATE_WAIT) => {
    const t = now();
    for (const g of state.grants) g.access = g.access.filter((a) => a.expires > t);
    state.grants = state.grants.filter((g) => g.refreshExpires > t || g.access.length > 0);
    for (const k of Object.keys(state.documents)) if (!o.clients.includes(k)) delete state.documents[k];
    index();
    writeState(o.state, JSON.stringify(state), wait);
    // The file now holds all of memory, so every end with it.
    if (unwritten.length > 0) log({ event: 'oauth-state-written', ends: unwritten.length });
    unwritten = [];
    if (retry) clearInterval(retry);
    retry = null;
  };
  index();

  /** What the access token with this hash stands for, or null: a token the executor issued, not pushed out, not expired, of a connection that stands, for this resource, to a client still on the list, for an agent still marked for connections (X208). */
  const standsFor = (hash) => {
    const found = byAccess.get(hash);
    if (!found || found.expires <= now()) return null;
    const g = found.grant;
    if (g.resource !== resource || !o.clients.includes(g.client) || !oauthAgents.includes(g.agent)) return null;
    return { agent: g.agent, connection: g.id, expires: found.expires, hash };
  };
  // The requests held open, each under the access token it came with: {hash, connection, end}, where "end" ends the request (X229).
  const held = new Set();
  // What is kept under a connection, whatever token it came with (a session of a local program): {connection, end}, where "end" is called when the connection ends (X234).
  const watched = new Set();
  /** End every request held open whose token no longer stands, for whatever reason: its connection has ended, or later tokens have pushed it out; and everything kept under a connection that has ended. Called once memory has changed for good. */
  const endHeld = () => {
    for (const w of [...watched]) {
      if (state.grants.some((g) => g.id === w.connection)) continue;
      watched.delete(w);
      w.end();
    }
    for (const h of [...held]) {
      if (standsFor(h.hash)) continue;
      held.delete(h);
      h.end(state.grants.some((g) => g.id === h.connection) ? 'token-dropped' : 'connection-ended');
    }
  };
  /**
   * Change the state and write it. The new state is in memory only once it
   * is on the disk: where the write fails, memory is put back as it was and
   * the failure is thrown, so that memory never runs ahead of the file (X210).
   */
  const change = (mutate) => {
    const before = JSON.stringify(state);
    try {
      mutate();
      save();
    } catch (e) {
      for (const k of Object.keys(state)) delete state[k];
      Object.assign(state, JSON.parse(before));
      index();
      throw e;
    }
    endHeld();
  };
  const notWritten = (e) => log({ event: 'oauth-state-not-written', problem: e.code ?? e.message });

  /**
   * End a connection, and with it the streams open under it. It is ended in
   * memory at once, whether or not the file can be written: an ended
   * connection is never used again while the executor runs. Where the file
   * could not be written, it is behind, and a start from it would bring the
   * connection back: so the write is tried again every STATE_RETRY ms, with
   * no waiting inside a try, until it is made, and once more at close (X210).
   */
  const revoke = (grant, why) => {
    state.grants = state.grants.filter((g) => g.id !== grant.id);
    index();
    try {
      save();
    } catch (e) {
      notWritten(e);
      unwritten.push({ agent: grant.agent, client: grant.client, why });
      if (!retry) {
        retry = setInterval(() => {
          try {
            save(0);
          } catch {
            // Still not written: said once, when it failed first; tried again at the next turn.
          }
        }, STATE_RETRY);
        // The timer alone does not keep the program running.
        retry.unref();
      }
    }
    log({ event: 'oauth-revoked', agent: grant.agent, client: grant.client, why });
    endHeld();
  };
  // At a start, the connections of clients no longer on the list, and of agents no longer marked for connections, are ended, so that putting one back does not bring them back (X215).
  for (const g of [...state.grants]) {
    if (!o.clients.includes(g.client)) revoke(g, 'client-not-listed');
    else if (!oauthAgents.includes(g.agent)) revoke(g, 'agent-not-for-connections');
  }

  // A request waiting at the page is kept in the page's form, under the executor's seal, not in memory: so nothing anyone sends can push the owner's page out (X228). In memory only: the requests the owner approved, until they would have ended, and the codes (X207). Both are made only by an answer that passed the owner's check.
  const seals = newSeal();
  const answered = new Map();
  const codes = new Map();
  const tidy = () => {
    const t = now();
    for (const [k, expires] of answered) if (expires <= t) answered.delete(k);
    for (const [k, c] of codes) if (c.expires + REQUEST_LIFE <= t) codes.delete(k);
  };
  /** The waiting request a form's text stands for, or null: sealed by this executor since its start, not ended, not yet approved. */
  const waiting = (text) => {
    const r = seals.open(text);
    if (!isObject(r) || typeof r.id !== 'string' || !(r.expires > now()) || answered.has(r.id)) return null;
    return r;
  };

  // The owner's check: the one given, or by the owner's passkey (owner.mjs), which keeps the owner in the state file.
  const ownerCheck = given !== undefined ? given : openPasskeyCheck({
    issuer,
    resource,
    clients: o.clients,
    now,
    log,
    store: {
      owner: () => state.owner,
      setup: () => state.setup,
      setOwner: (owner) => change(() => {
        state.owner = owner;
        state.setup = null;
      }),
      /**
       * The recovery code is spent (X282): true where this call spent it,
       * false where it was spent before. The look and the write are one
       * step, with nothing waited for between them, so of any number of
       * calls one is told true. Its hash stays, so that the code typed
       * again can be told it was used. Where the state cannot be written
       * it throws, and the code is not spent.
       */
      spendRecovery: () => {
        if (!state.owner || state.owner.recoverySpent === true) return false;
        change(() => {
          state.owner = { ...state.owner, recoverySpent: true };
        });
        return true;
      },
    },
    /** The same waiting request with a note of the check's own sealed into it, as the text for the form; null where the text is not a waiting request. */
    withNote: (text, note) => {
      const r = waiting(text);
      return r ? seals.seal({ ...r, note }) : null;
    },
    clientOf: (text) => waiting(text)?.client ?? null,
    page: (res, status, title, body) => sendPage(res, status, title, body, { scripts: true }),
    json: sendJson,
    hashOf,
  });
  const checkOwns = (path) => typeof ownerCheck?.owns === 'function' && ownerCheck.owns(path);

  // One fetch at a time for each client, and none for DOCUMENT_RETRY after one that failed (X205). Only a client on the list is ever fetched, so both are as small as the list.
  const fetching = new Map();
  const lastFailed = new Map();
  const fetchAgain = (id) => {
    const going = fetching.get(id);
    if (going) return going;
    const p = (async () => {
      try {
        const got = await fetch(id);
        const read = readDocument(got.document, id);
        if (read.problem) throw Object.assign(new Error(read.problem), { refused: true });
        try {
          change(() => {
            state.documents[id] = { document: got.document, fetched: now(), until: now() + got.kept };
          });
        } catch (e) {
          notWritten(e);
        }
        lastFailed.delete(id);
        return { read };
      } catch (e) {
        const failure = { at: now(), passing: e.passing === true, refused: e.refused === true, problem: e.message };
        lastFailed.set(id, failure);
        return failure;
      } finally {
        fetching.delete(id);
      }
    })();
    fetching.set(id, p);
    return p;
  };

  /**
   * The client's document: the copy while it is fresh, else fetched again.
   * Where that fetch gets no answer, or a 5xx, the copy kept is used while
   * it is no older than DOCUMENT_KEPT.longest. Any other failure (a 404, a
   * redirection, a document too large, not JSON or not the client's own)
   * refuses the request, copy or no copy (X205).
   */
  async function clientFor(id) {
    const kept = state.documents[id];
    if (kept && kept.until > now()) return readDocument(kept.document, id);
    const last = lastFailed.get(id);
    const got = last && now() - last.at < DOCUMENT_RETRY ? last : await fetchAgain(id);
    if (got.read) return got.read;
    const copy = state.documents[id];
    if (got.passing && copy && now() - copy.fetched < DOCUMENT_KEPT.longest) {
      log({ event: 'oauth-document-copy', client: id, problem: got.problem });
      return readDocument(copy.document, id);
    }
    log({ event: got.refused ? 'oauth-document-refused' : 'oauth-document-unreachable', client: id, problem: got.problem });
    return { problem: got.refused ? got.problem : `the client's document could not be fetched (${got.problem})` };
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
    if (!isResource(query.get('resource'))) return fail('invalid_target', `resource must be ${resource}`);
    // An empty scope is no scope: RFC 6749's grammar has no empty one (X214).
    const scope = query.get('scope') || null;
    if (scope !== null && (scope.length > 1024 || !PRINTABLE.test(scope))) return fail('invalid_scope', 'scope is longer than 1024 characters or not printable');
    if (oauthAgents.length === 0) return fail('access_denied', 'the executor has no agent for connections');
    // The request waits in the page's form, under the executor's seal (X228): nothing of it is kept here.
    showRequest(res, seals.seal({ id: newToken(), client: client.id, redirectUri: to, state: st, challenge, scope, expires: now() + REQUEST_LIFE }), client.id, to);
  }

  /** The page for a request that waits, as its form holds it: who asks, named by the host of its document's address and not by the name the document gives (X279), the warning, the agent, the owner's check and the two answers (X212). */
  function showRequest(res, sealed, clientId, to) {
    const where = new URL(to);
    const host = new URL(clientId).host;
    const options = oauthAgents.map((n) => `<option value="${escape(n)}">${escape(n)}</option>`).join('');
    const check = ownerCheck ? ownerCheck.form() : '<p>No owner\'s check is set up on this executor, so no connection can be approved here.</p>';
    const body = [
      `<p><strong>${escape(host)}</strong> (client ${escape(clientId)}) asks to connect to ${escape(settings.name ?? 'this executor')} at ${escape(resource)}.</p>`,
      `<p>Once approved, it is one agent: it may call the tools that agent's permission allows, and each call gets a receipt in that agent's book. The answer goes to ${escape(where.origin)}.</p>`,
      // The page cannot tell whose request this is: any user of the client can begin one and send its link to the owner.
      '<p><strong>Approve only a connection you began yourself, just now.</strong> If this page came to you as a link from someone else, refuse.</p>',
      `<form method="post" action="${OAUTH_PATH}/authorize">`,
      `<input type="hidden" name="request" value="${escape(sealed)}">`,
      `<p><label>The agent it becomes <select name="agent">${options}</select></label></p>`,
      check,
      '<p><button type="submit" name="decision" value="approve">Approve</button> <button type="submit" name="decision" value="refuse">Refuse</button></p>',
      '</form>',
    ].join('\n');
    sendPage(res, 200, `Approve ${host} connecting to your guard`, body, { formTo: [where.origin], scripts: ownerCheck?.scripts === true });
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
    const r = waiting(form.get('request'));
    if (!r) return problemPage(res, 400, 'This request has ended or is not known. Begin again from the client.');
    if (form.get('decision') === 'refuse') {
      // Nothing is kept of a refusal: it needs no proof, so it must cost the executor no memory.
      log({ event: 'oauth-refused', code: 'access-denied', client: r.client });
      return back(res, r.redirectUri, { error: 'access_denied', error_description: 'the owner refused', state: r.state });
    }
    // The setup page sends the request of a page that waited where no owner existed, to have it shown again (X272). It is the same request, with the same end: nothing is approved by showing it.
    if (form.get('decision') === 'show') return showRequest(res, form.get('request'), r.client, r.redirectUri);
    if (form.get('decision') !== 'approve') return problemPage(res, 400, 'The answer is neither approve nor refuse.');
    if (!ownerCheck) return problemPage(res, 503, 'No owner\'s check is set up on this executor, so no connection can be approved.');
    const agent = form.get('agent');
    if (!oauthAgents.includes(agent)) return problemPage(res, 400, 'That is not an agent for connections.');
    // What the check says (X212): true, or the name of the proof that passed, one of PROOFS; a page to show before the approval, whose Continue sends the request again; a problem of the executor's own; a refusal with its own words. Anything else is a refusal too: no other value approves, whatever it is (X282).
    let proved = false;
    try {
      proved = await ownerCheck.check(form, { request: r.id, origin: issuer, note: r.note ?? null });
    } catch {
      proved = false;
    }
    if (isObject(proved) && typeof proved.problem === 'string') {
      log({ event: 'oauth-refused', code: 'not-written' });
      return problemPage(res, 500, proved.problem);
    }
    if (isObject(proved) && isObject(proved.pause) && typeof proved.pause.request === 'string') {
      // Nothing is approved yet, and nothing kept: the page's form holds the request, as the first page's did.
      const { title, body, request } = proved.pause;
      return sendPage(res, 200, title, [
        body,
        `<form method="post" action="${OAUTH_PATH}/authorize">`,
        `<input type="hidden" name="request" value="${escape(request)}">`,
        `<input type="hidden" name="agent" value="${escape(agent)}">`,
        '<p><button type="submit" name="decision" value="approve">Continue</button></p>',
        '</form>',
      ].join('\n'), { formTo: [new URL(r.redirectUri).origin], scripts: ownerCheck.scripts === true });
    }
    if (proved !== true && !PROOFS.includes(proved)) {
      log({ event: 'oauth-refused', code: 'owner-not-proved' });
      // The check's own words, where it gives them: a recovery code that was already used (X282).
      return problemPage(res, 403, isObject(proved) && typeof proved.refusal === 'string' && proved.refusal !== '' ? proved.refusal : 'The owner\'s check did not pass. Go back and try again.');
    }
    // An approved request is answered once: the same form sent again gets no second code.
    if (answered.has(r.id)) return problemPage(res, 400, 'This request has ended or is not known. Begin again from the client.');
    answered.set(r.id, r.expires);
    const code = newToken();
    codes.set(hashOf(code), { client: r.client, redirectUri: r.redirectUri, challenge: r.challenge, scope: r.scope, agent, expires: now() + CODE_LIFE, used: false, grant: null });
    // With which proof it was approved, where the check names it: the passkey, the recovery code, or the setup that made the owner (X274).
    log({ event: 'oauth-approved', agent, client: r.client, ...(proved === true ? {} : { by: proved }) });
    back(res, r.redirectUri, { code, state: r.state });
  }

  const tokenError = (res, status, error, description) => {
    log({ event: 'oauth-refused', code: error, description });
    sendJson(res, status, { error, error_description: description });
  };

  /** A new access token and refresh token for a grant, set in it; the refresh token it replaces, if any, becomes spent (X208, X209). Called inside change(). */
  const newTokens = (grant) => {
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
    const out = { access_token: access, token_type: 'Bearer', expires_in: ACCESS_LIFE / 1000, refresh_token: refresh };
    if (grant.scope !== null) out.scope = grant.scope;
    return out;
  };
  /** The state could not be written, so nothing was changed: the client keeps what it had, and may try again (X210). */
  const tokenNotWritten = (res, e) => {
    notWritten(e);
    sendJson(res, 500, { error: 'server_error', error_description: 'the executor could not write its state, so nothing was changed; try again' });
  };

  /** POST /oauth/token (X207, X208, X209). */
  async function token(req, res) {
    const form = await readForm(req);
    if (!form) return tokenError(res, 400, 'invalid_request', 'the body must be application/x-www-form-urlencoded, at most 16 KiB');
    const twice = repeated(form);
    if (twice) return tokenError(res, 400, 'invalid_request', `${twice} is given more than once`);
    const clientId = form.get('client_id');
    if (!clientId || !o.clients.includes(clientId)) return tokenError(res, 401, 'invalid_client', 'the client is not one the executor\'s settings name');
    const asked = form.get('resource');
    if (asked !== null && !isResource(asked)) return tokenError(res, 400, 'invalid_target', `resource must be ${resource}`);
    tidy();
    const grantType = form.get('grant_type');
    if (grantType === 'authorization_code') {
      const code = form.get('code') ?? '';
      const key = hashOf(code);
      const c = codes.get(key);
      if (!c) return tokenError(res, 400, 'invalid_grant', 'the code is not known');
      if (c.client !== clientId) return tokenError(res, 400, 'invalid_grant', 'the code was issued to another client');
      // OAuth 2.1 takes redirect_uri out of this request, since PKCE ties the code to the client that asked; where a client still sends it, it must be the same.
      const sent = form.get('redirect_uri');
      if (sent !== null && sent !== c.redirectUri) return tokenError(res, 400, 'invalid_grant', 'redirect_uri is not the one the code was issued for');
      const verifier = form.get('code_verifier');
      if (verifier === null || !VERIFIER.test(verifier) || !sameText(hashOf(verifier), c.challenge)) return tokenError(res, 400, 'invalid_grant', 'code_verifier does not match the code_challenge');
      if (c.used) {
        // A code used twice, in a request that is otherwise right: refused, and whatever was issued for it is revoked (OAuth 2.1). A used code shown by someone without its verifier proves nothing, and ends nothing.
        codes.delete(key);
        const g = state.grants.find((x) => x.id === c.grant);
        if (g) revoke(g, 'code-used-twice');
        return tokenError(res, 400, 'invalid_grant', 'the code has already been used');
      }
      if (c.expires <= now()) return tokenError(res, 400, 'invalid_grant', 'the code has expired');
      // One connection for each agent: approving a new one ends the one before (X201). All of it is one change: where it cannot be written, the code is still unused and the connection before still stands.
      let grant;
      let ended;
      let out;
      try {
        change(() => {
          ended = state.grants.filter((g) => g.agent === c.agent);
          state.grants = state.grants.filter((g) => g.agent !== c.agent);
          grant = { id: newToken(), agent: c.agent, client: c.client, resource, scope: c.scope, created: now(), refresh: null, refreshExpires: 0, spent: [], access: [] };
          state.grants.push(grant);
          out = newTokens(grant);
        });
      } catch (e) {
        return tokenNotWritten(res, e);
      }
      c.used = true;
      c.grant = grant.id;
      // The streams open under the connection before were ended by the change itself.
      for (const old of ended) log({ event: 'oauth-revoked', agent: old.agent, client: old.client, why: 'replaced' });
      log({ event: 'oauth-connected', agent: grant.agent, client: grant.client });
      return sendJson(res, 200, out);
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
      // An empty scope is no scope (X214).
      const scope = form.get('scope') || null;
      if (scope !== null && scope !== grant.scope) return tokenError(res, 400, 'invalid_scope', 'a refresh keeps the scope of the approval');
      let out;
      try {
        change(() => {
          out = newTokens(grant);
        });
      } catch (e) {
        return tokenNotWritten(res, e);
      }
      return sendJson(res, 200, out);
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
     * What an access token stands for, or null: a token the executor
     * issued, not expired, for this resource, to a client still on the list,
     * for an agent still marked for connections (X208). Gives {agent,
     * connection, expires, hash}: the agent's name, the connection's id,
     * when the token ends, and the token's hash (for "hold").
     */
    agentFor: (text) => standsFor(hashOf(text)),
    /**
     * Keep a request open under the access token it came with ("token" is
     * what agentFor gave for it): "end" is called, once, with the reason,
     * when that token stops standing before its time: "connection-ended" (a
     * refresh token used twice, a code used twice, a new approval of its
     * agent) or "token-dropped" (later tokens of its connection pushed it
     * out). The token's own expiry is the caller's to time. Gives the
     * function that lets the request go (X229).
     */
    hold(token, end) {
      const h = { hash: token.hash, connection: token.connection, end };
      held.add(h);
      return () => held.delete(h);
    },
    /**
     * Keep something under a connection ("connection" is the id agentFor
     * gave), whatever token each of its requests comes with: "end" is
     * called, once, when the connection ends (a refresh token used twice, a
     * code used twice, a new approval of its agent). Gives the function
     * that lets it go (X234).
     */
    watch(connection, end) {
      const w = { connection, end };
      watched.add(w);
      return () => watched.delete(w);
    },
    /**
     * At the executor's close, with the agents' locks still held: where the
     * end of a connection is still not in the file, the write is tried once
     * more. Gives the connections whose end is still unwritten ({agent,
     * client, why} each; none where the file holds all): a start from this
     * file would bring them back (X210).
     */
    close() {
      if (retry) clearInterval(retry);
      retry = null;
      if (unwritten.length === 0) return [];
      try {
        save();
      } catch (e) {
        log({ event: 'oauth-ends-not-written', problem: e.code ?? e.message, connections: unwritten });
      }
      return [...unwritten];
    },
    /** The WWW-Authenticate header of a 401 at the MCP endpoint (RFC 9728, section 5.1; RFC 6750). */
    challenge: (tokenGiven) => `Bearer resource_metadata="${resourceMetadataUrl}"${tokenGiven ? ', error="invalid_token"' : ''}`,
  };
}
