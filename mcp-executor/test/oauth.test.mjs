// The executor as an OAuth-protected connector (DESIGN.md, section 14):
// the whole flow, as a client that follows the MCP authorization
// specification (2025-11-25) makes it, in plain HTTP requests (the package's
// tests install nothing, so no client library is used), and each refusal.
//
// The client's metadata document is served by a small server in this
// process, on the local address; the owner's check is a test one (a word
// typed on the page). Nothing leaves this computer.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { join } from 'node:path';
import { test } from 'node:test';

const { checkBook } = await import('provared');
const { httpWorld, call, request, post } = await import('./http-world.mjs');
const { openHttpExecutor, readHttpSettings } = await import('../http.mjs');
const { ACCESS_LIFE, CODE_LIFE, DOCUMENT_KEPT, DOCUMENT_LIMIT, OWNER_FAILURES, TOKEN_FAILURES, OAUTH_TIMEOUT } = await import('../oauth.mjs');

const DAY = 24 * 60 * 60 * 1000;
const OWNER_WORD = 'it-is-the-owner';
/** The test owner's check: the page asks for a word, and the check is that it is the right one. */
const TEST_OWNER = {
  form: () => '<p><label>The owner\'s word <input type="password" name="owner"></label></p>',
  check: async (fields) => fields.get('owner') === OWNER_WORD,
};
const CALLBACK = 'https://client.example/callback';

function freePort() {
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
async function startDocuments() {
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
 * local address and the port the executor listens on.
 */
async function oauthWorld({ clients, config = {}, ownerCheck = TEST_OWNER, open = true } = {}) {
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
async function reopen(w) {
  if (w.executor) await w.executor.close();
  w.logs = [];
  w.executor = await openHttpExecutor(w.settings, { root: w.folder, log: (e) => w.logs.push(e), ...w.more });
  await w.executor.listen({ port: w.port });
  w.url = `${w.issuer}${w.settings.path ?? '/mcp'}`;
}

/** One HTTP request, on a connection of its own: {status, headers, body}. */
function send(method, url, { headers = {}, body } = {}) {
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
const form = (fields) => ({ headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields).toString() });
const json = (r) => JSON.parse(r.body);

const pkce = () => {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
};

/** The authorisation request a client makes, with any parameter changed (undefined leaves it out). */
function authorizeUrl(w, discovered, over = {}) {
  const params = { response_type: 'code', client_id: w.docs.client, redirect_uri: CALLBACK, code_challenge: over.pkce?.challenge, code_challenge_method: 'S256', state: 'st-1', resource: discovered.resource, ...over };
  delete params.pkce;
  const u = new URL(discovered.server.authorization_endpoint);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) u.searchParams.set(k, v);
  return u.href;
}

/** Discovery, as the specification has a client make it: the 401, the resource's metadata, the server's metadata. */
async function discover(w) {
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
async function ask(w, url) {
  const r = await send('GET', url);
  const m = /name="request" value="([^"]+)"/.exec(r.body);
  return { ...r, request: m?.[1] };
}

/** The owner's answer on the page: the 303, and the parameters it sends the browser back with. */
async function answer(w, id, { owner = OWNER_WORD, agent = 'conn', decision = 'approve', origin = w.issuer } = {}) {
  const r = await send('POST', `${w.issuer}/oauth/authorize`, { headers: { 'content-type': 'application/x-www-form-urlencoded', ...(origin ? { origin } : {}) }, body: new URLSearchParams({ request: id, agent, decision, owner }).toString() });
  const back = r.headers.location ? new URL(r.headers.location) : null;
  return { ...r, back, params: back ? Object.fromEntries(back.searchParams) : null };
}

const token = (w, fields) => send('POST', `${w.issuer}/oauth/token`, form(fields));

/** The whole flow to tokens: {access, refresh, discovered}. */
async function connect(w) {
  const discovered = await discover(w);
  const p = pkce();
  const page = await ask(w, authorizeUrl(w, discovered, { pkce: p }));
  assert.equal(page.status, 200, page.body);
  const a = await answer(w, page.request);
  assert.equal(a.status, 303);
  const t = await token(w, { grant_type: 'authorization_code', code: a.params.code, redirect_uri: CALLBACK, client_id: w.docs.client, code_verifier: p.verifier, resource: discovered.resource });
  assert.equal(t.status, 200, t.body);
  const got = json(t);
  return { access: got.access_token, refresh: got.refresh_token, discovered, got };
}

const bearer = (t) => `Bearer ${t}`;

test('the whole flow: discovery, the owner\'s page, the code, the tokens, a tool call receipted in the connection\'s own book, a refresh; an agent with a secret works as before', async () => {
  const w = await oauthWorld();
  try {
    const d = await discover(w);
    assert.equal(d.challenge, `Bearer resource_metadata="${w.issuer}/.well-known/oauth-protected-resource/mcp"`);
    assert.deepEqual(d.prm, { resource: `${w.issuer}/mcp`, authorization_servers: [w.issuer], bearer_methods_supported: ['header'], resource_name: w.settings.name });
    assert.equal(d.server.issuer, w.issuer);
    assert.deepEqual(d.server.code_challenge_methods_supported, ['S256']);
    assert.deepEqual(d.server.token_endpoint_auth_methods_supported, ['none']);
    assert.equal(d.server.client_id_metadata_document_supported, true);
    assert.equal(d.server.registration_endpoint, undefined, 'no dynamic client registration');

    const p = pkce();
    const page = await ask(w, authorizeUrl(w, d, { pkce: p, scope: 'tools' }));
    assert.equal(page.status, 200);
    assert.match(page.body, /The test client/);
    assert.match(page.headers['content-security-policy'], /default-src 'none'.*form-action 'self' https:\/\/client\.example.*frame-ancestors 'none'/);
    assert.equal(page.headers['x-frame-options'], 'DENY');
    assert.doesNotMatch(page.body, /<script/i, 'nothing on the page runs');
    const a = await answer(w, page.request);
    assert.equal(a.status, 303);
    assert.equal(`${a.back.origin}${a.back.pathname}`, CALLBACK);
    assert.equal(a.params.state, 'st-1');
    assert.equal(a.params.iss, w.issuer);

    const t = await token(w, { grant_type: 'authorization_code', code: a.params.code, redirect_uri: CALLBACK, client_id: w.docs.client, code_verifier: p.verifier, resource: d.resource });
    assert.equal(t.status, 200);
    assert.equal(t.headers['cache-control'], 'no-store');
    const got = json(t);
    assert.equal(got.token_type, 'Bearer');
    assert.equal(got.expires_in, ACCESS_LIFE / 1000);
    assert.equal(got.scope, 'tools', 'the scope asked for is given back as it was');

    const echo = await call(w, bearer(got.access_token), 'echo', { a: 1 });
    assert.equal(echo.status, 200, echo.body);
    assert.equal(w.upstream.seen.at(-1).headers.authorization, 'Bearer made-up-upstream-token-for-the-tests-0123456789', 'the upstream gets the executor\'s credential, not the access token');
    const book = await checkBook(w.executor.agent('conn').writer.book(), { issuerKeys: w.settings.agents.conn.issuerKeys });
    assert.equal(book.entries.filter((e) => e.kind === 'stub').length, 1, 'the call is receipted in the connection\'s own book');
    const alphaBook = await checkBook(w.executor.agent('alpha').writer.book(), { issuerKeys: w.settings.agents.alpha.issuerKeys });
    assert.equal(alphaBook.entries.filter((e) => e.kind === 'stub').length, 0);

    const alpha = await call(w, 'alpha', 'echo', {});
    assert.equal(alpha.status, 200, 'an agent with a secret works unchanged');

    const r = await token(w, { grant_type: 'refresh_token', refresh_token: got.refresh_token, client_id: w.docs.client, resource: d.resource });
    assert.equal(r.status, 200, r.body);
    const again = json(r);
    assert.notEqual(again.refresh_token, got.refresh_token, 'the refresh token is rotated');
    assert.equal((await call(w, bearer(again.access_token), 'echo', {})).status, 200);

    // The state file holds hashes only, and only the executor may read it; a start again keeps the connection.
    const stateText = readFileSync(w.statePath, 'utf8');
    for (const secret of [got.access_token, got.refresh_token, again.access_token, again.refresh_token]) assert.ok(!stateText.includes(secret), 'no token is written');
    if (process.platform !== 'win32') assert.equal(statSync(w.statePath).mode & 0o777, 0o600);
    await reopen(w);
    assert.equal((await call(w, bearer(again.access_token), 'echo', {})).status, 200, 'the connection outlives a start');
    for (const e of w.logs) assert.ok(!JSON.stringify(e).includes(again.access_token), 'no token is logged');
  } finally {
    await w.close();
  }
});

test('refused at the page: a client not on the list, a redirect the document does not name (neither sent back), no PKCE, the plain method, the wrong resource (sent back as errors)', async () => {
  const w = await oauthWorld();
  try {
    const d = await discover(w);
    const p = pkce();
    const notListed = await ask(w, authorizeUrl(w, d, { pkce: p, client_id: `${w.docs.base}/other` }));
    assert.equal(notListed.status, 400);
    assert.equal(notListed.headers.location, undefined);
    assert.equal(w.docs.hits, 0, 'a client not on the list is not fetched');
    const wrongRedirect = await ask(w, authorizeUrl(w, d, { pkce: p, redirect_uri: 'https://client.example/callback/other' }));
    assert.equal(wrongRedirect.status, 400);
    assert.equal(wrongRedirect.headers.location, undefined, 'never sent to an address the document does not name');
    assert.equal((await ask(w, authorizeUrl(w, d, { pkce: p, redirect_uri: 'https://client.example/Callback' }))).status, 400, 'matched exactly');

    const errorOf = (r) => Object.fromEntries(new URL(r.headers.location).searchParams);
    const noPkce = await ask(w, authorizeUrl(w, d, { code_challenge_method: undefined }));
    assert.equal(noPkce.status, 303);
    assert.equal(errorOf(noPkce).error, 'invalid_request');
    assert.equal(errorOf(noPkce).state, 'st-1');
    const plain = await ask(w, authorizeUrl(w, d, { code_challenge: p.verifier, code_challenge_method: 'plain' }));
    assert.equal(errorOf(plain).error, 'invalid_request');
    const noMethod = await ask(w, authorizeUrl(w, d, { pkce: p, code_challenge_method: undefined }));
    assert.equal(errorOf(noMethod).error, 'invalid_request', 'with no method named, plain is not assumed');
    const wrongResource = await ask(w, authorizeUrl(w, d, { pkce: p, resource: `${w.issuer}/other` }));
    assert.equal(errorOf(wrongResource).error, 'invalid_target');
    const twice = await send('GET', `${authorizeUrl(w, d, { pkce: p })}&state=again`);
    assert.equal(twice.status, 400, 'a parameter given twice');

    // The loopback exception of OAuth 2.1: http://127.0.0.1 with another port matches; another path does not.
    assert.equal((await ask(w, authorizeUrl(w, d, { pkce: p, redirect_uri: 'http://127.0.0.1:49152/cb' }))).status, 200);
    assert.equal((await ask(w, authorizeUrl(w, d, { pkce: p, redirect_uri: 'http://127.0.0.1:49152/cb2' }))).status, 400);

    // The owner refuses: the client is told access_denied.
    const page = await ask(w, authorizeUrl(w, d, { pkce: p }));
    const refused = await answer(w, page.request, { decision: 'refuse' });
    assert.equal(refused.params.error, 'access_denied');
    // An answer from another page (Origin), or none, is refused.
    const page2 = await ask(w, authorizeUrl(w, d, { pkce: p }));
    assert.equal((await answer(w, page2.request, { origin: 'https://attacker.example' })).status, 403);
    assert.equal((await answer(w, page2.request, { origin: null })).status, 403);
    // An agent with a secret cannot be chosen.
    assert.equal((await answer(w, page2.request, { agent: 'alpha' })).status, 400);
  } finally {
    await w.close();
  }
});

test('a code is used once, by the client it was issued to, with its verifier, within its life; used twice, what it gave is revoked', async () => {
  const w = await oauthWorld();
  try {
    const d = await discover(w);
    const codeFor = async (p) => (await answer(w, (await ask(w, authorizeUrl(w, d, { pkce: p }))).request)).params.code;
    const p = pkce();
    const code = await codeFor(p);
    const base = { grant_type: 'authorization_code', code, redirect_uri: CALLBACK, client_id: w.docs.client, code_verifier: p.verifier };
    assert.equal(json(await token(w, { ...base, code_verifier: pkce().verifier })).error, 'invalid_grant', 'another verifier');
    assert.equal(json(await token(w, { ...base, redirect_uri: 'http://127.0.0.1/cb' })).error, 'invalid_grant', 'another redirect');
    assert.equal(json(await token(w, { ...base, resource: `${w.issuer}/other` })).error, 'invalid_target');
    const first = await token(w, base);
    assert.equal(first.status, 200);
    const { access_token: access } = json(first);
    assert.equal((await call(w, bearer(access), 'echo', {})).status, 200);
    const second = await token(w, base);
    assert.equal(second.status, 400);
    assert.equal(json(second).error, 'invalid_grant');
    assert.equal((await call(w, bearer(access), 'echo', {})).status, 401, 'the tokens the code gave are revoked');

    const p2 = pkce();
    const late = await codeFor(p2);
    w.clock.offset += CODE_LIFE + 1;
    assert.equal(json(await token(w, { ...base, code: late, code_verifier: p2.verifier })).error, 'invalid_grant', 'an expired code');
  } finally {
    await w.close();
  }
});

test('a refresh token is used once: used again, the whole family is revoked', async () => {
  const w = await oauthWorld();
  try {
    const c = await connect(w);
    const r1 = json(await token(w, { grant_type: 'refresh_token', refresh_token: c.refresh, client_id: w.docs.client }));
    assert.ok(r1.access_token);
    const reused = await token(w, { grant_type: 'refresh_token', refresh_token: c.refresh, client_id: w.docs.client });
    assert.equal(reused.status, 400);
    assert.equal(json(reused).error, 'invalid_grant');
    assert.equal((await call(w, bearer(r1.access_token), 'echo', {})).status, 401, 'the newest access token is revoked too');
    assert.equal((await call(w, bearer(c.access), 'echo', {})).status, 401);
    assert.equal(json(await token(w, { grant_type: 'refresh_token', refresh_token: r1.refresh_token, client_id: w.docs.client })).error, 'invalid_grant', 'and the newest refresh token');
    assert.ok(w.logs.some((e) => e.event === 'oauth-revoked' && e.why === 'refresh-token-used-twice'));
  } finally {
    await w.close();
  }
});

test('an access token serves only its own resource, client and agent, and only while it lasts; a new approval of the agent ends the one before', async () => {
  const w = await oauthWorld();
  try {
    const c = await connect(w);
    assert.equal((await call(w, bearer(c.access), 'echo', {})).status, 200);
    // Expired: refused with invalid_token; the refresh token still works.
    w.clock.offset += ACCESS_LIFE + 1;
    const expired = await call(w, bearer(c.access), 'echo', {});
    assert.equal(expired.status, 401);
    assert.match(expired.headers.get('www-authenticate'), /error="invalid_token"/);
    const r = json(await token(w, { grant_type: 'refresh_token', refresh_token: c.refresh, client_id: w.docs.client }));
    assert.equal((await call(w, bearer(r.access_token), 'echo', {})).status, 200);
    assert.equal(json(await token(w, { grant_type: 'refresh_token', refresh_token: r.refresh_token, client_id: `${w.docs.base}/other` })).error, 'invalid_client');

    // The wrong audience: the same state, but the executor's resource is now another address.
    const before = w.settings.path;
    w.settings.path = '/mcp2';
    await reopen(w);
    assert.equal((await call(w, bearer(r.access_token), 'echo', {})).status, 401, 'a token for /mcp is not taken at /mcp2');
    assert.equal(json(await token(w, { grant_type: 'refresh_token', refresh_token: r.refresh_token, client_id: w.docs.client })).error, 'invalid_grant');
    w.settings.path = before;
    await reopen(w);
    assert.equal((await call(w, bearer(r.access_token), 'echo', {})).status, 200);

    // A client taken off the list: its connection ends.
    w.settings.oauth.clients = [];
    await reopen(w);
    assert.equal((await call(w, bearer(r.access_token), 'echo', {})).status, 401);
    w.settings.oauth.clients = [w.docs.client];
    await reopen(w);

    // Approved again for the same agent: the earlier connection ends.
    const c2 = await connect(w);
    assert.equal((await call(w, bearer(r.access_token), 'echo', {})).status, 401);
    assert.equal((await call(w, bearer(c2.access), 'echo', {})).status, 200);
  } finally {
    await w.close();
  }
});

test('too many failed attempts: the owner\'s check, then the token endpoint, refuse even a right answer for a while', async () => {
  const w = await oauthWorld();
  try {
    const d = await discover(w);
    const page = await ask(w, authorizeUrl(w, d, { pkce: pkce() }));
    for (let i = 0; i < OWNER_FAILURES.most; i += 1) assert.equal((await answer(w, page.request, { owner: 'wrong' })).status, 403);
    const locked = await answer(w, page.request);
    assert.equal(locked.status, 429, 'even the right word, while locked');
    assert.ok(Number(locked.headers['retry-after']) > 0);
    w.clock.offset += OWNER_FAILURES.window;
    const later = await ask(w, authorizeUrl(w, d, { pkce: pkce() }));
    assert.equal((await answer(w, later.request)).status, 303, 'after the window, the right word passes');

    for (let i = 0; i < TOKEN_FAILURES.most; i += 1) assert.equal((await token(w, { grant_type: 'refresh_token', refresh_token: 'guess', client_id: w.docs.client })).status, 400);
    const t = await token(w, { grant_type: 'refresh_token', refresh_token: 'guess', client_id: w.docs.client });
    assert.equal(t.status, 429);
    assert.equal(json(t).error, 'temporarily_unavailable');
  } finally {
    await w.close();
  }
});

test('the client\'s document: fetched once and kept; refetched after it expires; where the fetch then fails, the copy is used; none, too large, redirected or not its own is refused', async () => {
  const w = await oauthWorld();
  try {
    const d = await discover(w);
    const p = pkce();
    assert.equal((await ask(w, authorizeUrl(w, d, { pkce: p }))).status, 200);
    assert.equal((await ask(w, authorizeUrl(w, d, { pkce: p }))).status, 200);
    assert.equal(w.docs.hits, 1, 'kept while fresh');
    w.clock.offset += DOCUMENT_KEPT.usual + 1;
    w.docs.mode = 'down';
    await reopen(w);
    assert.equal((await ask(w, authorizeUrl(w, d, { pkce: p }))).status, 200, 'a failed fetch does not stop a known client');
    assert.equal(w.docs.hits, 2);
    assert.ok(w.logs.some((e) => e.event === 'oauth-document-copy'));
    w.docs.mode = 'ok';
    w.docs.extra = { redirect_uris: ['https://client.example/new'] };
    assert.equal((await ask(w, authorizeUrl(w, d, { pkce: p }))).status, 400, 'a document fetched again is the one used');
    assert.equal((await ask(w, authorizeUrl(w, d, { pkce: p, redirect_uri: 'https://client.example/new' }))).status, 200);
  } finally {
    await w.close();
  }

  for (const [mode, extra, why] of [['down', {}, 'unreachable, with no copy'], ['big', {}, 'too large'], ['redirect', {}, 'a redirection is not followed'], ['ok', { client_id: 'https://someone.example/else' }, 'not its own'], ['ok', { token_endpoint_auth_method: 'client_secret_basic' }, 'a client with a secret']]) {
    const v = await oauthWorld();
    try {
      v.docs.mode = mode;
      v.docs.extra = extra;
      const d = await discover(v);
      const r = await ask(v, authorizeUrl(v, d, { pkce: pkce() }));
      assert.equal(r.status, 502, why);
      assert.equal(r.headers.location, undefined, why);
    } finally {
      await v.close();
    }
  }
});

test('without an owner\'s check, the page approves nothing', async () => {
  const w = await oauthWorld({ ownerCheck: null });
  try {
    const d = await discover(w);
    const page = await ask(w, authorizeUrl(w, d, { pkce: pkce() }));
    assert.equal(page.status, 200);
    assert.match(page.body, /No owner's check is set up/);
    assert.equal((await answer(w, page.request)).status, 503);
  } finally {
    await w.close();
  }
});

test('the settings: the issuer is https, or http://127.0.0.1 for tests; clients are https URLs; an agent signs in one way; with OAuth the timeout is under the client\'s 240 seconds', async () => {
  const base = { listen: {}, upstream: { url: 'http://127.0.0.1:1/mcp' }, executor: { keys: 'k' }, tools: {}, agents: { a: { oauth: true, slip: 's', book: 'b', keys: 'k2', issuerKeys: ['B'.repeat(43)] } } };
  const read = (oauth, more = {}) => readHttpSettings({ ...base, oauth, ...more }, process.cwd());
  const problems = (oauth, more) => read(oauth, more).problems.join('\n');
  assert.equal(problems({ issuer: 'https://guard.example.com', clients: ['https://client.example/doc'] }), '');
  assert.match(problems({ issuer: 'http://guard.example.com', clients: [] }), /oauth\.issuer/);
  assert.match(problems({ issuer: 'http://127.0.0.1', clients: [] }), /oauth\.issuer/, 'a port is needed');
  assert.match(problems({ issuer: 'https://guard.example.com/sub', clients: [] }), /oauth\.issuer/);
  assert.match(problems({ issuer: 'https://guard.example.com', clients: ['http://client.example/doc'] }), /oauth\.clients\[0\]/);
  assert.match(problems({ issuer: 'https://guard.example.com', clients: ['http://127.0.0.1:9/doc'] }), /oauth\.clients\[0\]/, 'a loopback client only with a loopback issuer');
  assert.match(problems({ issuer: 'https://guard.example.com', clients: ['https://client.example/'] }), /no path/);
  assert.match(problems(undefined), /agents\.a\.oauth: needs the "oauth" settings/);
  assert.match(problems({ issuer: 'https://guard.example.com', clients: [] }, { agents: { a: { ...base.agents.a, secretHash: 'A'.repeat(43) } } }), /signs in one way/);
  assert.match(problems({ issuer: 'https://guard.example.com', clients: [] }, { path: '/oauth/mcp' }), /path/);
  const empty = read({ issuer: 'https://guard.example.com', clients: [] });
  assert.ok(empty.warnings.some((x) => /no client can connect/.test(x)));
  assert.equal(read({ issuer: 'https://guard.example.com', clients: [] }).partial.timeout, OAUTH_TIMEOUT);
  assert.equal(OAUTH_TIMEOUT < 240000, true);
  assert.ok(read({ issuer: 'https://guard.example.com', clients: [] }, { timeout: 300000 }).warnings.some((x) => /240000 ms/.test(x)));
  // Without "oauth", nothing changes: the timeout's default stays.
  const plain = readHttpSettings({ ...base, agents: { a: { ...base.agents.a, oauth: undefined, secretHash: 'A'.repeat(43) } } }, process.cwd());
  assert.equal(plain.partial.timeout, 300000);
  assert.equal(plain.partial.oauth, null);
});

test('the recipe\'s example settings, with their placeholders filled in, have no problem', () => {
  const text = readFileSync(new URL('../recipes/claude-ai/executor-oauth.example.json', import.meta.url), 'utf8')
    .replace('<address of the upstream MCP endpoint>', 'https://upstream.example/mcp')
    .replace('<file that holds the upstream\'s bearer token>', 'secrets/upstream')
    .replace('<public https address of the reverse proxy, such as https://guard.example.com>', 'https://guard.example.com')
    .replace('<thumbprint of the person\'s passkey>', 'B'.repeat(43));
  const read = readHttpSettings(JSON.parse(text), process.cwd());
  assert.deepEqual(read.problems, []);
  assert.deepEqual(read.settings.oauth.clients, ['https://claude.ai/oauth/mcp-oauth-client-metadata']);
  assert.equal(read.settings.timeout, 230000);
});

test('without "oauth" in the settings there is no front door: its paths are not found, and a 401 names no metadata', async () => {
  const w = await httpWorld();
  try {
    const r = await request(w, null, 'ping');
    assert.equal(r.status, 401);
    assert.equal(r.headers.get('www-authenticate'), 'Bearer');
    const u = new URL(w.url);
    assert.equal((await send('GET', `${u.origin}/.well-known/oauth-authorization-server`)).status, 404);
  } finally {
    await w.close();
  }
});
