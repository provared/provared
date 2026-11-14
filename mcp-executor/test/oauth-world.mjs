// The world of the OAuth tests (oauth.test.mjs, owner.test.mjs): an
// executor with an agent for connections, a small server of client metadata
// documents on the local address, and a client that follows the MCP
// authorization specification in plain HTTP requests. Nothing leaves this
// computer.
//
// Imported with import(), after local-library.mjs.

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import { join } from 'node:path';
import { httpWorld, post } from './http-world.mjs';
import { openHttpExecutor } from '../http.mjs';
import { DOCUMENT_LIMIT } from '../oauth.mjs';

export const DAY = 24 * 60 * 60 * 1000;
export const OWNER_WORD = 'it-is-the-owner';
/** The test owner's check: the page asks for a word, and the check is that it is the right one. */
export const TEST_OWNER = {
  form: () => '<p><label>The owner\'s word <input type="password" name="owner"></label></p>',
  check: async (fields) => fields.get('owner') === OWNER_WORD,
};
export const CALLBACK = 'https://client.example/callback';

export function freePort() {
  return new Promise((done, failed) => {
    const s = net.createServer();
    s.once('error', failed);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => done(port));
    });
  });
}

/** A server of client metadata documents: GET /client is the document; "mode" makes it fail in one way. */
export async function startDocuments() {
  const d = { mode: 'ok', hits: 0, extra: {}, cache: null };
  const server = http.createServer((req, res) => {
    d.hits += 1;
    const id = `${d.base}${req.url}`;
    if (d.mode === 'down') return res.destroy();
    if (d.mode === 'redirect') {
      res.writeHead(302, { location: `${d.base}/elsewhere` });
      return res.end();
    }
    const doc = { client_id: id, client_name: 'The test client', redirect_uris: [CALLBACK, 'http://127.0.0.1/cb'], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none', ...d.extra };
    if (d.mode === 'big') doc.padding = 'x'.repeat(DOCUMENT_LIMIT);
    const body = JSON.stringify(doc);
    res.writeHead(200, { 'content-type': 'application/json', ...(d.cache ? { 'cache-control': d.cache } : {}) });
    res.end(body);
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  d.base = `http://127.0.0.1:${server.address().port}`;
  d.client = `${d.base}/client`;
  d.close = () => new Promise((done) => {
    server.close(() => done());
    server.closeAllConnections();
  });
  return d;
}

/**
 * A world with two agents: "alpha", which signs in with its secret, and
 * "conn", an agent for a connection made through OAuth. The issuer is the
 * local address and the port the executor listens on. "ownerCheck" left as
 * undefined gives the executor's own check, by the owner's passkey.
 */
export async function oauthWorld({ clients, config = {}, ownerCheck = TEST_OWNER, open = true } = {}) {
  const docs = await startDocuments();
  const port = await freePort();
  const issuer = `http://127.0.0.1:${port}`;
  const w = await httpWorld({ agents: ['alpha', 'conn'], open: false, slips: { conn: { until: Date.now() + 90 * DAY } } });
  const conn = w.settings.agents.conn;
  delete conn.secretHash;
  conn.oauth = true;
  w.settings.oauth = { issuer, clients: clients ?? [docs.client], state: 'oauth-state.json' };
  Object.assign(w.settings, config);
  w.docs = docs;
  w.issuer = issuer;
  w.port = port;
  w.clock = { offset: 0 };
  w.more = { now: () => Date.now() + w.clock.offset, ownerCheck };
  w.statePath = join(w.folder, 'oauth-state.json');
  w.close = async () => {
    await w.executor?.close();
    await w.upstream.close();
    await docs.close();
  };
  if (open) await reopen(w);
  return w;
}

/** Open (or open again) the executor on the world's settings, at its port. */
export async function reopen(w) {
  if (w.executor) await w.executor.close();
  w.executor = null;
  w.logs = [];
  w.executor = await openHttpExecutor(w.settings, { root: w.folder, log: (e) => w.logs.push(e), ...w.more });
  await w.executor.listen({ port: w.port });
  w.url = `${w.issuer}${w.settings.path ?? '/mcp'}`;
}

/** One HTTP request, on a connection of its own: {status, headers, body}. */
export function send(method, url, { headers = {}, body } = {}) {
  return new Promise((done, failed) => {
    const u = new URL(url);
    const req = http.request({ host: u.hostname, port: u.port, path: `${u.pathname}${u.search}`, method, agent: false, headers: { connection: 'close', ...headers } });
    req.on('error', failed);
    req.on('response', (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => done({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.end(body);
  });
}
export const form = (fields) => ({ headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields).toString() });
export const json = (r) => JSON.parse(r.body);

export const pkce = () => {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
};

/** The authorisation request a client makes, with any parameter changed (undefined leaves it out). */
export function authorizeUrl(w, discovered, over = {}) {
  const params = { response_type: 'code', client_id: w.docs.client, redirect_uri: CALLBACK, code_challenge: over.pkce?.challenge, code_challenge_method: 'S256', state: 'st-1', resource: discovered.resource, ...over };
  delete params.pkce;
  const u = new URL(discovered.server.authorization_endpoint);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) u.searchParams.set(k, v);
  return u.href;
}

/** Discovery, as the specification has a client make it: the 401, the resource's metadata, the server's metadata. */
export async function discover(w) {
  const first = await post(w, null, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '1' } } });
  assert.equal(first.status, 401);
  const m = /resource_metadata="([^"]+)"/.exec(first.headers.get('www-authenticate'));
  assert.ok(m, 'the 401 names the resource\'s metadata');
  const prm = json(await send('GET', m[1]));
  const asUrl = new URL('/.well-known/oauth-authorization-server', prm.authorization_servers[0]);
  const server = json(await send('GET', asUrl.href));
  return { resource: prm.resource, prm, server, challenge: first.headers.get('www-authenticate') };
}

/** The owner's page for a request: {status, request (its id), page}. */
export async function ask(w, url) {
  const r = await send('GET', url);
  const m = /name="request" value="([^"]+)"/.exec(r.body);
  return { ...r, request: m?.[1] };
}

/** The owner's answer on the page: the 303, and the parameters it sends the browser back with. "fields" are the owner's check's. */
export async function answer(w, id, { owner = OWNER_WORD, agent = 'conn', decision = 'approve', origin = w.issuer, fields = { owner } } = {}) {
  const r = await send('POST', `${w.issuer}/oauth/authorize`, { headers: { 'content-type': 'application/x-www-form-urlencoded', ...(origin ? { origin } : {}) }, body: new URLSearchParams({ request: id, agent, decision, ...fields }).toString() });
  const back = r.headers.location ? new URL(r.headers.location) : null;
  return { ...r, back, params: back ? Object.fromEntries(back.searchParams) : null };
}

export const token = (w, fields) => send('POST', `${w.issuer}/oauth/token`, form(fields));

/** The whole flow to tokens: {access, refresh, discovered}. "prove" gives the owner's check's fields for a request id. */
export async function connect(w, { prove } = {}) {
  const discovered = await discover(w);
  const p = pkce();
  const page = await ask(w, authorizeUrl(w, discovered, { pkce: p }));
  assert.equal(page.status, 200, page.body);
  const a = await answer(w, page.request, prove ? { fields: await prove(page.request) } : {});
  assert.equal(a.status, 303, a.body);
  const t = await token(w, { grant_type: 'authorization_code', code: a.params.code, redirect_uri: CALLBACK, client_id: w.docs.client, code_verifier: p.verifier, resource: discovered.resource });
  assert.equal(t.status, 200, t.body);
  const got = json(t);
  return { access: got.access_token, refresh: got.refresh_token, discovered, got };
}

export const bearer = (t) => `Bearer ${t}`;
