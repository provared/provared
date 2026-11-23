// The findings of the third review, of the OAuth sign-in and the owner's
// check (DESIGN.md, section 14): each fault as a test that fails without
// its fix. Through the executor's public interface, as the other tests of
// OAuth are. The page's script (owner-page.mjs) is run as the executor
// serves it in owner.test.mjs, since the owner's check became a plain
// passkey. Nothing leaves this computer.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import fs, { readFileSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { test } from 'node:test';

const { call, rawRequest, beginSession } = await import('./http-world.mjs');
const { openHttpExecutor, secretHash } = await import('../http.mjs');
const { ACCESS_LIFE, DOCUMENT_KEPT, DOCUMENT_RETRY, REQUEST_LIFE } = await import('../oauth.mjs');
const { openPasskeyCheck } = await import('../owner.mjs');
const { FIELD_CHALLENGE, FIELD_AUTHENTICATOR_DATA, FIELD_CLIENT_DATA, FIELD_SIGNATURE, FIELD_RECOVERY, CHALLENGE_PATH, LINK_PATH } = await import('../owner-steps.mjs');
const { CALLBACK, oauthWorld, reopen, send, json, pkce, authorizeUrl, discover, ask, answer, token, connect, bearer } = await import('./oauth-world.mjs');
const { ownerWorld, setUpOwner, prove, sender, refusal, waiting } = await import('./owner-world.mjs');
const { fromBase64url, sha256, toBase64url } = await import('provared');
const { makePasskey } = await import('../../test/helpers/passkey.mjs');

const state = (w) => JSON.parse(readFileSync(w.statePath, 'utf8'));
const pause = (ms) => new Promise((done) => setTimeout(done, ms));
/** Whether a promise settles within so many milliseconds. */
const within = (p, ms) => Promise.race([p.then(() => true), pause(ms).then(() => false)]);
/** Many requests, a hundred at a time. */
async function many(count, one) {
  for (let done = 0; done < count; done += 100) await Promise.all(Array.from({ length: Math.min(100, count - done) }, () => one()));
}

// --- finding 1: the page's own form must carry the executor's Origin ---

test('finding 1: the pages are sent with Referrer-Policy same-origin, under which a browser gives the form the page\'s own Origin; the 303 keeps no-referrer; "Origin: null" is never taken', async () => {
  const w = await ownerWorld();
  try {
    const d = await discover(w);
    // Under no-referrer a browser sends the page's form with "Origin: null" (the Fetch standard), and the owner's answer was refused. A browser is not run here: the header is what decides it.
    const page = await ask(w, authorizeUrl(w, d, { pkce: pkce() }));
    assert.equal(page.headers['referrer-policy'], 'same-origin', 'the authorisation page');
    assert.equal((await send('GET', `${w.issuer}/oauth/owner`)).headers['referrer-policy'], 'same-origin', 'the setup page');
    const problem = await ask(w, authorizeUrl(w, d, { pkce: pkce(), client_id: `${w.docs.base}/other` }));
    assert.equal(problem.status, 400);
    assert.equal(problem.headers['referrer-policy'], 'same-origin', 'a page that says what is wrong');
    // The browser goes to the client with no referrer.
    const refused = await answer(w, page.request, { decision: 'refuse' });
    assert.equal(refused.status, 303);
    assert.equal(refused.headers['referrer-policy'], 'no-referrer');
    // "null" is what a page of unknown origin sends: never the executor's own page.
    const fromNowhere = await answer(w, (await waiting(w)), { decision: 'refuse', origin: 'null' });
    assert.equal(fromNowhere.status, 403);
    assert.equal(fromNowhere.headers.location, undefined);
    assert.deepEqual(await refusal(sender(w, 'null')(LINK_PATH, { code: w.code })), { status: 403, code: 'origin-refused' });
  } finally {
    await w.close();
  }
});

// --- finding 2: no one can hold the setup, the approval or the token endpoint shut ---

test('finding 2: failed attempts shut nothing: after many wrong answers and bad token requests, the right ones pass at once', async () => {
  const w = await oauthWorld();
  try {
    const c = await connect(w);
    const request = await waiting(w);
    for (let i = 0; i < 12; i += 1) assert.equal((await answer(w, request, { owner: 'wrong' })).status, 403);
    const right = await answer(w, request);
    assert.equal(right.status, 303, 'the right answer, straight after twelve wrong ones');
    assert.ok(right.params.code);
    // The same form again: an approved request is answered once.
    const again = await answer(w, request);
    assert.equal(again.status, 400);
    assert.equal(again.headers.location, undefined);
    for (let i = 0; i < 40; i += 1) assert.equal((await token(w, { grant_type: 'refresh_token', refresh_token: 'guess', client_id: w.docs.client })).status, 400);
    const refreshed = await token(w, { grant_type: 'refresh_token', refresh_token: c.refresh, client_id: w.docs.client });
    assert.equal(refreshed.status, 200, 'a rightful refresh, straight after forty bad requests');
    assert.equal(w.logs.some((e) => e.code === 'too-many-attempts'), false);
  } finally {
    await w.close();
  }
});

test('finding 2: wrong setup codes and wrong recovery codes shut nothing: the link and the passkey work straight after', async () => {
  const w = await ownerWorld();
  try {
    for (let i = 0; i < 12; i += 1) assert.deepEqual(await refusal(sender(w)(LINK_PATH, { code: randomBytes(32).toString('base64url') })), { status: 403, code: 'setup-refused' });
    const { passkey, recoveryCode } = await setUpOwner(w);
    assert.ok(state(w).owner, 'the right code, straight after twelve wrong ones');
    const request = await waiting(w);
    for (let i = 0; i < 12; i += 1) assert.equal((await answer(w, request, { fields: { [FIELD_RECOVERY]: recoveryCode.replace(/.$/, (c) => (c === 'A' ? 'B' : 'A')) } })).status, 403);
    for (let i = 0; i < 12; i += 1) assert.equal((await answer(w, request, { fields: { [FIELD_CHALLENGE]: randomBytes(32).toString('base64url'), [FIELD_AUTHENTICATOR_DATA]: randomBytes(37).toString('base64url'), [FIELD_CLIENT_DATA]: randomBytes(64).toString('base64url'), [FIELD_SIGNATURE]: randomBytes(64).toString('base64url') } })).status, 403);
    const a = await answer(w, request, { fields: await prove(w, passkey)(request) });
    assert.equal(a.status, 303, a.body);
  } finally {
    await w.close();
  }
});

test('finding 2: nothing anyone sends pushes the owner\'s page out: after 1,200 other requests at the page and 1,200 other challenges, the owner\'s answer passes', async () => {
  const w = await ownerWorld();
  try {
    const { passkey } = await setUpOwner(w);
    const d = await discover(w);
    // The owner's page, and the owner's answer made ready: the challenge signed.
    const request = await waiting(w);
    const fields = await prove(w, passkey)(request);
    // Meanwhile anyone asks for pages, and for challenges for a page of their own.
    const url = authorizeUrl(w, d, { pkce: pkce() });
    await many(1200, async () => assert.equal((await send('GET', url)).status, 200));
    const other = await waiting(w);
    await many(1200, async () => assert.ok((await sender(w)(CHALLENGE_PATH, { request: other })).challenge));
    const a = await answer(w, request, { fields });
    assert.equal(a.status, 303, a.body);
    assert.ok(a.params.code);
  } finally {
    await w.close();
  }
});

test('finding 2: the request in the form is under the executor\'s seal: one changed, forged, ended or from before a start is not known', async () => {
  const w = await oauthWorld();
  try {
    const request = await waiting(w);
    const [header, body, mac] = request.split('.');
    assert.deepEqual(JSON.parse(Buffer.from(header, 'base64url').toString()), { alg: 'HS256' }, 'a JWS in compact form, with HS256');
    const held = JSON.parse(Buffer.from(body, 'base64url').toString());
    assert.equal(held.redirectUri, CALLBACK);
    const notKnown = async (text, what) => {
      const a = await answer(w, text);
      assert.equal(a.status, 400, what);
      assert.equal(a.headers.location, undefined, what);
    };
    // The fields changed (the code would go to another address), under the old MAC, under a MAC of another key, and with no MAC under "none".
    const forged = Buffer.from(JSON.stringify({ ...held, redirectUri: 'http://127.0.0.1/cb' })).toString('base64url');
    await notKnown(`${header}.${forged}.${mac}`, 'the fields changed under the old MAC');
    await notKnown(`${header}.${forged}.${createHmac('sha256', randomBytes(32)).update(`${header}.${forged}`).digest('base64url')}`, 'a MAC of another key');
    const none = Buffer.from('{"alg":"none"}').toString('base64url');
    await notKnown(`${none}.${forged}.`, 'no MAC');
    await notKnown(`${none}.${body}.${mac}`, 'another header');
    await notKnown(`${header}.${body}`, 'two parts');
    await notKnown('', 'nothing');
    // Ended: ten minutes later.
    w.clock.offset += REQUEST_LIFE;
    await notKnown(request, 'ended');
    w.clock.offset -= REQUEST_LIFE;
    // From before a start: the key is made at each start and never written.
    await reopen(w);
    assert.equal(readFileSync(w.statePath, 'utf8').includes(mac), false);
    await notKnown(request, 'from before a start');
    assert.equal((await answer(w, await waiting(w))).status, 303);
  } finally {
    await w.close();
  }
});

test('finding 2: a challenge passes the check once', async () => {
  const origin = 'https://guard.example.com';
  const soft = await makePasskey('ES256', { rpId: 'guard.example.com', origin });
  const owner = { credentialId: 'AAAA', key: soft.key, recoveryHash: 'x' };
  const check = openPasskeyCheck({ issuer: origin, store: { owner: () => owner, setup: () => null, setOwner() {} }, withNote: () => null, page() {}, json() {}, hashOf: (text) => text });
  const challenge = randomBytes(32).toString('base64url');
  const signed = async (change) => {
    const s = await soft.sign(await sha256(fromBase64url(challenge)), change);
    return new URLSearchParams({ [FIELD_CHALLENGE]: challenge, [FIELD_AUTHENTICATOR_DATA]: toBase64url(s.authenticatorData), [FIELD_CLIENT_DATA]: toBase64url(s.clientDataJSON), [FIELD_SIGNATURE]: toBase64url(s.signature) });
  };
  const note = { challenge, expires: Date.now() + 60000 };
  assert.equal(await check.check(await signed({ signature: (s) => s.map((b, i) => (i === s.length - 1 ? b ^ 1 : b)) }), { origin, note }), false, 'a wrong signature');
  const fields = await signed();
  assert.equal(await check.check(fields, { origin, note }), 'passkey', 'a wrong signature before it spends nothing');
  assert.equal(await check.check(fields, { origin, note }), false, 'the same challenge and signature again');
  // Two answers with one challenge, checked at the same moment: one passes. The executor's addresses cannot bring this about, since an approved request is not read again; the check holds it by itself.
  const again = randomBytes(32).toString('base64url');
  const s = await soft.sign(await sha256(fromBase64url(again)));
  const both = () => new URLSearchParams({ [FIELD_CHALLENGE]: again, [FIELD_AUTHENTICATOR_DATA]: toBase64url(s.authenticatorData), [FIELD_CLIENT_DATA]: toBase64url(s.clientDataJSON), [FIELD_SIGNATURE]: toBase64url(s.signature) });
  const at = { origin, note: { challenge: again, expires: Date.now() + 60000 } };
  assert.deepEqual((await Promise.all([check.check(both(), at), check.check(both(), at)])).sort(), ['passkey', false].sort());
});

test('a note that a setup or a recovery code approved the request passes only for the owner it names', async () => {
  const origin = 'https://guard.example.com';
  const soft = await makePasskey('ES256', { rpId: 'guard.example.com', origin });
  // A run of the executor has one owner, so its addresses cannot show a note for another: the check holds it by itself.
  let owner = { credentialId: 'AAAA', key: soft.key, recoveryHash: 'x' };
  const check = openPasskeyCheck({ issuer: origin, store: { owner: () => owner, setup: () => null, setOwner() {} }, withNote: () => null, page() {}, json() {}, hashOf: (text) => text });
  const none = new URLSearchParams();
  assert.equal(await check.check(none, { origin, note: { setup: 'AAAA' } }), 'setup');
  assert.equal(await check.check(none, { origin, note: { recovery: 'AAAA' } }), 'recovery');
  assert.equal(await check.check(none, { origin, note: { setup: 'BBBB' } }), false, 'a setup\'s note for another owner');
  assert.equal(await check.check(none, { origin, note: { recovery: 'BBBB' } }), false, 'a recovery code\'s note for another owner');
  assert.equal(await check.check(none, { origin, note: { setup: true } }), false);
  owner = null;
  assert.equal(await check.check(none, { origin, note: { setup: 'AAAA' } }), false, 'no owner, no approval');
});

// --- finding 3: a stream does not outlive its token or its connection ---

/** The GET stream of server messages, opened as an agent: {res, closed (a promise)}. */
async function openStream(w, authorization) {
  // Under a session begun with the same authorization: with more than one agent, a GET without one is not opened.
  const session = await beginSession(w, authorization);
  const s = await rawRequest(w, { method: 'GET', headers: { accept: 'text/event-stream', authorization, 'mcp-session-id': session }, stream: true });
  assert.equal(s.status, 200);
  s.closed = new Promise((done) => s.res.on('close', done));
  s.res.resume();
  return s;
}
/** Wait until the agent has no request open. */
async function noneOpen(w, name) {
  for (let i = 0; i < 100 && w.executor.agent(name).open() > 0; i += 1) await pause(20);
  return w.executor.agent(name).open();
}

test('finding 3: a stream opened with a token is ended when its connection ends (a refresh token used twice, a new approval) and when the token expires; an agent with a secret keeps its stream', async () => {
  const w = await oauthWorld();
  try {
    // The connection ends: a refresh token used twice.
    const c = await connect(w);
    const s = await openStream(w, bearer(c.access));
    assert.equal(w.executor.agent('conn').open(), 1);
    assert.equal(await within(s.closed, 400), false, 'open while the connection stands');
    assert.equal((await token(w, { grant_type: 'refresh_token', refresh_token: c.refresh, client_id: w.docs.client })).status, 200);
    assert.equal((await token(w, { grant_type: 'refresh_token', refresh_token: c.refresh, client_id: w.docs.client })).status, 400);
    assert.equal(await within(s.closed, 3000), true, 'the stream is ended with the connection');
    assert.equal(await noneOpen(w, 'conn'), 0, 'and no longer holds one of the agent\'s places');
    assert.ok(w.logs.some((e) => e.event === 'stream-ended' && e.why === 'connection-ended'));

    // A new approval of the agent ends the connection before, and its stream.
    const c2 = await connect(w);
    const s2 = await openStream(w, bearer(c2.access));
    // The executor's clock before the next connection's token is made, and after: the token ends ACCESS_LIFE after a moment between the two.
    const before = w.more.now();
    const c3 = await connect(w);
    const made = w.more.now();
    assert.equal(await within(s2.closed, 3000), true, 'ended by the new approval');

    // The token expires: the clock is put LEFT before the soonest moment it can end, so it has LEFT or a little more when the stream is opened, however long the lines above took. (The clock was once moved on by a fixed ACCESS_LIFE less half a second: the real time that had passed since the token was made came out of that half second, and on a busy computer the token had ended before the stream was opened, which was then refused with 401.)
    const LEFT = 2000;
    w.clock.offset += before + ACCESS_LIFE - LEFT - w.more.now();
    const s3 = await openStream(w, bearer(c3.access));
    // It ends LEFT from now at the soonest, and later by no more than the making of the connection took.
    assert.equal(await within(s3.closed, LEFT + (made - before) + 3000), true, 'ended when the token expires');
    assert.ok(w.logs.some((e) => e.event === 'stream-ended' && e.why === 'token-expired'));
    assert.equal(await noneOpen(w, 'conn'), 0);

    // An agent with a secret has no token to expire.
    const a = await openStream(w, `Bearer ${w.agents.alpha.secret}`);
    assert.equal(await within(a.closed, 700), false);
    a.res.destroy();
  } finally {
    await w.close();
  }
});

// --- finding 4: the page says what it cannot check ---

test('finding 4: the page tells the owner to approve only a connection they began themselves', async () => {
  const w = await oauthWorld();
  try {
    const page = await ask(w, authorizeUrl(w, await discover(w), { pkce: pkce() }));
    assert.match(page.body, /Approve only a connection you began yourself, just now\./);
  } finally {
    await w.close();
  }
});

// --- findings 5 and 14: the page's script, run as the executor serves it ---
//
// These were of a passkey that had to give PRF: where the device's own gave
// none, a second button asked for one on a phone or a security key, and the
// passkey's transports were kept. The owner's check is now a plain passkey
// (DESIGN.md, X270 and X275): one call, the library's own, with no
// attachment named, so the browser itself offers this device, a phone or a
// security key. The page's script is run as served in owner.test.mjs.

// --- finding 6: memory never runs ahead of the state file ---

/** Put stand-ins in place of functions of node:fs, for the modules that imported them by name too. Gives the function that puts the real ones back. */
function withFs(standIns) {
  const real = Object.fromEntries(Object.keys(standIns).map((k) => [k, fs[k]]));
  Object.assign(fs, Object.fromEntries(Object.entries(standIns).map(([k, make]) => [k, make(real[k])])));
  syncBuiltinESMExports();
  return () => {
    Object.assign(fs, real);
    syncBuiltinESMExports();
  };
}

test('finding 6: where the state cannot be written, nothing is changed: the refresh token and the code still work once it can; the write gives up within seconds', async () => {
  const w = await oauthWorld();
  let restore = () => {};
  try {
    const c = await connect(w);
    const d = c.discovered;
    const p = pkce();
    const code = (await answer(w, (await ask(w, authorizeUrl(w, d, { pkce: p }))).request)).params.code;
    // The file is held by another program: putting the new file in place fails, as Windows reports it.
    const held = () => withFs({ renameSync: (real) => (from, to) => {
      if (String(to) === w.statePath) throw Object.assign(new Error('the file is held'), { code: 'EBUSY' });
      return real(from, to);
    } });
    restore = held();
    const began = Date.now();
    const failed = await token(w, { grant_type: 'refresh_token', refresh_token: c.refresh, client_id: w.docs.client });
    assert.equal(failed.status, 500);
    assert.equal(json(failed).error, 'server_error');
    assert.ok(Date.now() - began < 5000, `the write gives up well inside a client's 10 seconds (${Date.now() - began} ms)`);
    const failedCode = await token(w, { grant_type: 'authorization_code', code, client_id: w.docs.client, code_verifier: p.verifier });
    assert.equal(failedCode.status, 500);
    restore();
    restore = () => {};
    assert.ok(w.logs.some((e) => e.event === 'oauth-state-not-written'));
    assert.equal((await call(w, bearer(c.access), 'echo', {})).status, 200, 'the connection stands');
    // The client tries again with what it had: not taken for a token used twice.
    const again = await token(w, { grant_type: 'refresh_token', refresh_token: c.refresh, client_id: w.docs.client });
    assert.equal(again.status, 200, again.body);
    assert.equal(w.logs.some((e) => e.event === 'oauth-revoked'), false, 'nothing was revoked');
    assert.equal((await call(w, bearer(json(again).access_token), 'echo', {})).status, 200);
    // The code was not spent, and the connection before it was not ended.
    const exchanged = await token(w, { grant_type: 'authorization_code', code, client_id: w.docs.client, code_verifier: p.verifier });
    assert.equal(exchanged.status, 200, exchanged.body);
    assert.equal((await call(w, bearer(json(exchanged).access_token), 'echo', {})).status, 200);
  } finally {
    restore();
    await w.close();
  }
});

test('finding 6: the new state file is made sure to be on the disk before it takes the old one\'s place', async () => {
  const w = await oauthWorld();
  let restore = () => {};
  try {
    const c = await connect(w);
    const steps = [];
    let temporary = null;
    restore = withFs({
      openSync: (real) => (path, ...rest) => {
        const fd = real(path, ...rest);
        if (String(path) === `${w.statePath}.tmp`) temporary = fd;
        return fd;
      },
      fsyncSync: (real) => (fd) => {
        if (fd === temporary) steps.push('synced');
        return real(fd);
      },
      renameSync: (real) => (from, to) => {
        if (String(to) === w.statePath) steps.push('put in place');
        return real(from, to);
      },
    });
    assert.equal((await token(w, { grant_type: 'refresh_token', refresh_token: c.refresh, client_id: w.docs.client })).status, 200);
    restore();
    restore = () => {};
    assert.deepEqual(steps, ['synced', 'put in place']);
  } finally {
    restore();
    await w.close();
  }
});

// --- finding 7: a used code shown without its verifier ends nothing ---

test('finding 7: a used code shown again ends the connection only where the request is otherwise right', async () => {
  const w = await oauthWorld();
  try {
    const d = await discover(w);
    const p = pkce();
    const code = (await answer(w, (await ask(w, authorizeUrl(w, d, { pkce: p }))).request)).params.code;
    const base = { grant_type: 'authorization_code', code, client_id: w.docs.client };
    const first = await token(w, { ...base, code_verifier: p.verifier });
    assert.equal(first.status, 200);
    const access = json(first).access_token;
    // Someone who saw the code in the callback's address, but has no verifier.
    for (const more of [{}, { code_verifier: pkce().verifier }, { code_verifier: p.verifier, redirect_uri: 'http://127.0.0.1/cb' }]) {
      const shown = await token(w, { ...base, ...more });
      assert.equal(shown.status, 400);
      assert.equal(json(shown).error, 'invalid_grant');
    }
    assert.equal((await call(w, bearer(access), 'echo', {})).status, 200, 'the connection stands');
    assert.equal(w.logs.some((e) => e.event === 'oauth-revoked'), false);
    // The client itself, with the verifier: a code used twice.
    assert.equal((await token(w, { ...base, code_verifier: p.verifier })).status, 400);
    assert.equal((await call(w, bearer(access), 'echo', {})).status, 401);
    assert.ok(w.logs.some((e) => e.event === 'oauth-revoked' && e.why === 'code-used-twice'));
  } finally {
    await w.close();
  }
});

// --- finding 8: a client put back on the list does not get its old connections back ---

test('finding 8: at a start, the connections of a client no longer on the list, and of an agent no longer marked for connections, are ended for good', async () => {
  const w = await oauthWorld();
  try {
    const c = await connect(w);
    w.settings.oauth.clients = [];
    await reopen(w);
    assert.equal((await call(w, bearer(c.access), 'echo', {})).status, 401);
    assert.deepEqual(state(w).grants, [], 'the connection is out of the file');
    assert.ok(w.logs.some((e) => e.event === 'oauth-revoked' && e.why === 'client-not-listed'));
    w.settings.oauth.clients = [w.docs.client];
    await reopen(w);
    assert.equal((await call(w, bearer(c.access), 'echo', {})).status, 401, 'back on the list, the old access token is still refused');
    assert.equal(json(await token(w, { grant_type: 'refresh_token', refresh_token: c.refresh, client_id: w.docs.client })).error, 'invalid_grant', 'and the old refresh token');

    // The agent given a secret in place of "oauth", then marked again.
    const c2 = await connect(w);
    const conn = w.settings.agents.conn;
    delete conn.oauth;
    conn.secretHash = secretHash('a-secret-for-the-agent-that-was-a-connection');
    await reopen(w);
    assert.deepEqual(state(w).grants, []);
    assert.ok(w.logs.some((e) => e.event === 'oauth-revoked' && e.why === 'agent-not-for-connections'));
    delete conn.secretHash;
    conn.oauth = true;
    await reopen(w);
    assert.equal((await call(w, bearer(c2.access), 'echo', {})).status, 401);
  } finally {
    await w.close();
  }
});

// --- finding 9: the state is read once the locks are held ---

test('finding 9: the state file is read only once the agents\' locks are held: while an executor runs, a second start stops at the lock and does not reach the file', async () => {
  const w = await oauthWorld();
  try {
    await connect(w);
    const good = readFileSync(w.statePath, 'utf8');
    // A file the front door would refuse: were it read before the locks, that would be the error.
    writeFileSync(w.statePath, '{not json');
    await assert.rejects(openHttpExecutor(w.settings, { root: w.folder, log: () => {}, ...w.more }), (e) => {
      assert.equal(e.code, 'LOCKED', e.message);
      return true;
    });
    // With the locks free, the file is read, and refused.
    await w.executor.close();
    w.executor = null;
    await assert.rejects(reopen(w), /oauth\.state: the file is not JSON/);
    // And the locks taken for that start were given up: the next start works.
    writeFileSync(w.statePath, good);
    await reopen(w);
  } finally {
    await w.close();
  }
});

// --- finding 10: the client's document ---

test('finding 10: one fetch at a time for each client, and none for a minute after one that failed', async () => {
  const w = await oauthWorld();
  try {
    const d = await discover(w);
    const url = authorizeUrl(w, d, { pkce: pkce() });
    w.docs.delay = 150;
    const together = await Promise.all(Array.from({ length: 50 }, () => send('GET', url)));
    assert.ok(together.every((r) => r.status === 200));
    assert.equal(w.docs.hits, 1, '50 requests with no copy make one fetch');
    // The copy has expired and the client's server gives no answer.
    w.clock.offset += DOCUMENT_KEPT.usual + 1;
    w.docs.mode = 'down';
    const failing = await Promise.all(Array.from({ length: 20 }, () => send('GET', url)));
    assert.ok(failing.every((r) => r.status === 200), 'the copy stands in');
    assert.equal((await send('GET', url)).status, 200);
    assert.equal(w.docs.hits, 2, '21 requests make one fetch that fails, and no other within the minute');
    w.clock.offset += DOCUMENT_RETRY;
    assert.equal((await send('GET', url)).status, 200);
    assert.equal(w.docs.hits, 3, 'a minute later it is tried again');
  } finally {
    await w.close();
  }
});

test('finding 10: the copy stands in only for no answer or a 5xx, and for a week; a document withdrawn (404) refuses the client; no-store is kept five minutes, not an hour', async () => {
  const w = await oauthWorld();
  try {
    const d = await discover(w);
    const url = authorizeUrl(w, d, { pkce: pkce() });
    const next = async (mode) => {
      w.clock.offset += Math.max(DOCUMENT_KEPT.usual + 1, DOCUMENT_RETRY);
      w.docs.mode = mode;
      return (await send('GET', url)).status;
    };
    assert.equal((await send('GET', url)).status, 200);
    assert.equal(await next('fault'), 200, 'a 503: the copy stands in');
    assert.equal(await next('gone'), 502, 'a 404: the client has withdrawn its document, copy or no copy');
    assert.ok(w.logs.some((e) => e.event === 'oauth-document-unreachable'));
    assert.equal(await next('redirect'), 502, 'a redirection is not a passing failure');
    assert.equal(await next('big'), 502, 'nor a document too large');
    assert.equal(await next('ok'), 200);
    // The copy just fetched, a week on, with no answer from the client's server.
    w.clock.offset += DOCUMENT_KEPT.longest - DOCUMENT_KEPT.usual - 1;
    assert.equal(await next('down'), 502, 'a copy a week old no longer stands in');

    // no-store, and no-cache: kept for the least time, five minutes.
    w.clock.offset += DOCUMENT_RETRY;
    w.docs.mode = 'ok';
    w.docs.cache = 'no-store';
    assert.equal((await send('GET', url)).status, 200);
    const hits = w.docs.hits;
    w.clock.offset += DOCUMENT_KEPT.least - 1000;
    assert.equal((await send('GET', url)).status, 200);
    assert.equal(w.docs.hits, hits, 'kept for five minutes');
    w.clock.offset += 2000;
    assert.equal((await send('GET', url)).status, 200);
    assert.equal(w.docs.hits, hits + 1, 'and fetched again after them');
  } finally {
    await w.close();
  }
});

// --- finding 13: no stricter than the standards ---

test('finding 13: the token request needs no redirect_uri; the resource\'s scheme and host may be in capitals; an empty scope is no scope', async () => {
  const w = await oauthWorld();
  try {
    const d = await discover(w);
    const capitals = `HTTP://127.0.0.1:${w.port}/mcp`;
    const p = pkce();
    // The page: the resource in capitals, and an empty scope.
    const page = await ask(w, authorizeUrl(w, d, { pkce: p, resource: capitals, scope: '' }));
    assert.equal(page.status, 200, page.body);
    const errorOf = (r) => Object.fromEntries(new URL(r.headers.location).searchParams).error;
    assert.equal(errorOf(await ask(w, authorizeUrl(w, d, { pkce: p, resource: `${d.resource}/` }))), 'invalid_target', 'another path is another resource');
    assert.equal(errorOf(await ask(w, authorizeUrl(w, d, { pkce: p, resource: `http://127.0.0.1:${w.port}/MCP` }))), 'invalid_target', 'the path is compared as it is');
    assert.equal(errorOf(await ask(w, authorizeUrl(w, d, { pkce: p, resource: undefined }))), 'invalid_target');
    const code = (await answer(w, page.request)).params.code;
    // The token request as OAuth 2.1 has it: no redirect_uri.
    const t = await token(w, { grant_type: 'authorization_code', code, client_id: w.docs.client, code_verifier: p.verifier, resource: capitals });
    assert.equal(t.status, 200, t.body);
    const got = json(t);
    assert.equal(Object.hasOwn(got, 'scope'), false, 'no scope is given back for an empty one');
    assert.equal(state(w).grants[0].scope, null);
    // A refresh that sends an empty scope where none was approved.
    const r = await token(w, { grant_type: 'refresh_token', refresh_token: got.refresh_token, client_id: w.docs.client, scope: '' });
    assert.equal(r.status, 200, r.body);
    assert.equal(json(await token(w, { grant_type: 'refresh_token', refresh_token: json(r).refresh_token, client_id: w.docs.client, scope: 'tools' })).error, 'invalid_scope');
  } finally {
    await w.close();
  }
});
