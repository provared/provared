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
import { readFileSync, statSync } from 'node:fs';
import { test } from 'node:test';

const { checkBook } = await import('provared');
const { httpWorld, call, request } = await import('./http-world.mjs');
const { readHttpSettings } = await import('../http.mjs');
const { ACCESS_LIFE, CODE_LIFE, DOCUMENT_KEPT, DOCUMENT_RETRY, OAUTH_TIMEOUT, PROOFS } = await import('../oauth.mjs');
const { CALLBACK, oauthWorld, reopen, send, json, pkce, authorizeUrl, discover, ask, answer, token, connect, bearer } = await import('./oauth-world.mjs');

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
    // The client is named by the host of its document's address, which the settings list, and not by the name the document gives itself.
    assert.ok(page.body.includes(`<h1>Approve ${new URL(w.docs.client).host} connecting to your guard</h1>`), page.body);
    assert.doesNotMatch(page.body, /The test client/);
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
    const c3 = await connect(w);
    assert.equal((await call(w, bearer(c2.access), 'echo', {})).status, 401);
    assert.equal((await call(w, bearer(c3.access), 'echo', {})).status, 200);
    assert.ok(w.logs.some((e) => e.event === 'oauth-revoked' && e.why === 'replaced'));
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
    // No new fetch for a minute after one that failed (test/review3.test.mjs); then the document is fetched again.
    w.clock.offset += DOCUMENT_RETRY;
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

test('an owner\'s check approves by saying true, or the name of the proof that passed, and by nothing else: an empty text, another word, a number, an object or a check that throws refuses', async () => {
  // A check that answers whatever the test names: the value at the place the form's field gives.
  const says = [];
  const check = {
    form: () => '<p>A check for the test.</p>',
    check: async (fields) => {
      const v = says[Number(fields.get('says'))];
      if (v instanceof Error) throw v;
      return v;
    },
  };
  const w = await oauthWorld({ ownerCheck: check });
  try {
    const d = await discover(w);
    const answerOf = async (value) => {
      says.push(value);
      w.logs.length = 0;
      return answer(w, (await ask(w, authorizeUrl(w, d, { pkce: pkce() }))).request, { fields: { says: String(says.length - 1) } });
    };
    // What approves, and what the log then says of the proof.
    assert.deepEqual(PROOFS, ['passkey', 'recovery', 'setup']);
    for (const [value, by] of [[true, undefined], ['passkey', 'passkey'], ['recovery', 'recovery'], ['setup', 'setup']]) {
      const a = await answerOf(value);
      assert.equal(a.status, 303, String(value));
      assert.ok(a.params.code);
      const line = w.logs.find((e) => e.event === 'oauth-approved');
      assert.equal(line.by, by);
      assert.equal(Object.hasOwn(line, 'by'), by !== undefined);
    }
    // What does not: every other value, among them the ones that are true to an "if".
    const not = ['', ' ', 'no', 'yes', 'true', 'ok', 'Passkey', 'passkey ', 'refused', 1, -1, 0, Number.NaN, 1n, null, undefined, {}, [], ['passkey'], [true], { ok: true }, { by: 'passkey' }, { pause: true }, { pause: {} }, { problem: 1 }, () => true, Symbol('passkey'), new String('passkey'), new Boolean(true), new Error('the check failed')];
    for (const [i, value] of not.entries()) {
      const a = await answerOf(value);
      const said = `value ${i} of the list (${typeof value})`;
      assert.equal(a.status, 403, said);
      assert.equal(a.headers.location, undefined, said);
      assert.ok(a.body.includes('The owner&#39;s check did not pass. Go back and try again.'), said);
      assert.equal(w.logs.some((e) => e.event === 'oauth-approved'), false, said);
      assert.deepEqual(w.logs.filter((e) => e.event === 'oauth-refused').map((e) => e.code), ['owner-not-proved'], said);
    }
    // A refusal in the check's own words is a refusal, and the page shows the words as text.
    const worded = await answerOf({ refusal: 'Not <this> time.' });
    assert.equal(worded.status, 403);
    assert.ok(worded.body.includes('<p>Not &#60;this&#62; time.</p>'), worded.body);
    assert.equal(w.logs.some((e) => e.event === 'oauth-approved'), false);
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
