// The findings of the re-check of the third review, of the OAuth sign-in
// and the owner's check (DESIGN.md, section 14): each fault as a test that
// fails without its fix, and the two tests the re-check found missing.
// Through the executor's public interface and its command. Nothing leaves
// this computer.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs, { mkdirSync, readFileSync, rmdirSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createCryptoCore } from '@microtoll/crypto-core';
import * as id from '@microtoll/identity';

const { call, rawRequest } = await import('./http-world.mjs');
const { until } = await import('./world.mjs');
const { readHttpSettings } = await import('../http.mjs');
const { MAX_ACCESS, REQUEST_LIFE, STATE_RETRY, makeOwnerSetup } = await import('../oauth.mjs');
const { NAMESPACE, CHALLENGE_PATH, LINK_PATH, SETUP_PATH, setUp, signIn } = await import('../owner-steps.mjs');
const { oauthWorld, reopen, send, json, pkce, authorizeUrl, discover, ask, answer, token, connect, bearer } = await import('./oauth-world.mjs');

const WRAPPER = fileURLToPath(new URL('./signal-wrapper.mjs', import.meta.url));
const cc = createCryptoCore({ namespace: NAMESPACE });
const state = (w) => JSON.parse(readFileSync(w.statePath, 'utf8'));
const pause = (ms) => new Promise((done) => setTimeout(done, ms));
/** Whether a promise settles within so many milliseconds. */
const within = (p, ms) => Promise.race([p.then(() => true), pause(ms).then(() => false)]);
const refresh = (w, text) => token(w, { grant_type: 'refresh_token', refresh_token: text, client_id: w.docs.client });

/** The re-check's forced failure: a folder stands where the state's temporary file goes, so no write of the state can be made. Gives the function that takes the folder away. */
function blockState(w) {
  const at = `${w.statePath}.tmp`;
  mkdirSync(at);
  let there = true;
  return () => {
    if (there) rmdirSync(at);
    there = false;
  };
}

/** A connection whose refresh token has been used once: {old (the spent refresh token), access, refresh (the newest two)}. */
async function refreshedOnce(w) {
  const c = await connect(w);
  const r = await refresh(w, c.refresh);
  assert.equal(r.status, 200, r.body);
  return { old: c.refresh, access: json(r).access_token, refresh: json(r).refresh_token };
}
/** The connection is ended for a client: its access token and its refresh token are refused. */
async function refused(w, c, what) {
  assert.equal((await call(w, bearer(c.access), 'echo', {})).status, 401, `${what}: the access token`);
  assert.equal((await refresh(w, c.refresh)).status, 400, `${what}: the refresh token`);
}

// --- N1: a connection that has been ended does not come back ---

test('N1: a connection\'s end that could not be written holds in memory, is written by the timer once the file can be written, and a start then does not bring the connection back', async () => {
  const w = await oauthWorld();
  let unblock = () => {};
  try {
    const c = await refreshedOnce(w);
    unblock = blockState(w);
    // The spent refresh token again: the sign that one was stolen. The state cannot be written at that moment.
    assert.equal((await refresh(w, c.old)).status, 400);
    assert.ok(w.logs.some((e) => e.event === 'oauth-revoked' && e.why === 'refresh-token-used-twice'));
    assert.ok(w.logs.some((e) => e.event === 'oauth-state-not-written'));
    assert.equal((await call(w, bearer(c.access), 'echo', {})).status, 401, 'ended in memory at once');
    assert.equal(state(w).grants.length, 1, 'the file is behind: it still holds the connection');
    // The timer goes on trying while the file cannot be written, and says so once only.
    await pause(STATE_RETRY * 2 + 300);
    assert.equal(state(w).grants.length, 1);
    assert.equal(w.logs.filter((e) => e.event === 'oauth-state-not-written').length, 1);
    unblock();
    await until(() => state(w).grants.length === 0, { timeout: STATE_RETRY * 4 + 2000 });
    assert.ok(w.logs.some((e) => e.event === 'oauth-state-written'), 'the log says the file has caught up');
    const closed = await w.executor.close();
    w.executor = null;
    assert.deepEqual(closed, { endsNotWritten: [] });
    await reopen(w);
    await refused(w, c, 'after a start');
  } finally {
    unblock();
    await w.close();
  }
});

test('N1: an end still unwritten when the executor closes is written then; where it cannot be, close() names the connection', async () => {
  // Written at the close.
  const w = await oauthWorld();
  let unblock = () => {};
  try {
    const c = await refreshedOnce(w);
    unblock = blockState(w);
    assert.equal((await refresh(w, c.old)).status, 400);
    assert.equal(state(w).grants.length, 1);
    unblock();
    const closed = await w.executor.close();
    w.executor = null;
    assert.deepEqual(closed, { endsNotWritten: [] });
    assert.equal(state(w).grants.length, 0, 'the close wrote the end');
    await reopen(w);
    await refused(w, c, 'after a start');
  } finally {
    unblock();
    await w.close();
  }

  // Not written, even at the close.
  const v = await oauthWorld();
  unblock = () => {};
  try {
    const c = await refreshedOnce(v);
    unblock = blockState(v);
    // A code used twice ends the connection as a refresh token used twice does; here the refresh token.
    assert.equal((await refresh(v, c.old)).status, 400);
    const logs = v.logs;
    const closed = await v.executor.close();
    v.executor = null;
    assert.deepEqual(closed, { endsNotWritten: [{ agent: 'conn', client: v.docs.client, why: 'refresh-token-used-twice' }] });
    assert.ok(logs.some((e) => e.event === 'oauth-ends-not-written' && e.connections.length === 1));
    assert.equal(state(v).grants.length, 1, 'the file still holds the connection');
  } finally {
    unblock();
    await v.close();
  }
});

test('N1: the command "http", stopped while a connection\'s end is unwritten, says so on its error output and ends with code 1; with the end written, with code 0', async () => {
  const w = await oauthWorld({ open: false });
  w.settings.listen = { host: '127.0.0.1', port: w.port };
  writeFileSync(w.configPath, JSON.stringify(w.settings));
  // A connection of a client that is no longer on the list: a start ends it (X215).
  const hash = () => randomBytes(32).toString('base64url');
  const grant = { id: hash(), agent: 'conn', client: 'https://gone.example/client', resource: `${w.issuer}/mcp`, scope: null, created: Date.now(), refresh: hash(), refreshExpires: Date.now() + 24 * 60 * 60 * 1000, spent: [], access: [{ hash: hash(), expires: Date.now() + 60 * 60 * 1000 }] };
  writeFileSync(w.statePath, JSON.stringify({ version: 1, grants: [grant], documents: {}, owner: null, setup: null }));
  /** Start the command, wait until it listens, stop it by SIGINT: {code, stderr}. */
  const startAndStop = async () => {
    // Through the wrapper, with an IPC channel: Windows delivers no signal to a child (http-cli.test.mjs).
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', WRAPPER, 'http', '--config', w.configPath], { cwd: w.folder, stdio: ['pipe', 'pipe', 'pipe', 'ipc'], windowsHide: true });
    child.stdin.end();
    const err = [];
    child.stderr.on('data', (c) => err.push(c));
    const stderr = () => Buffer.concat(err).toString('utf8');
    const exited = new Promise((done) => child.on('exit', (code) => done(code)));
    try {
      await until(() => stderr().includes('"event":"listening"') || child.exitCode !== null, { timeout: 20000, every: 50 });
      assert.equal(child.exitCode, null, stderr());
      if (process.platform === 'win32') child.send('SIGINT');
      else child.kill('SIGINT');
      return { code: await exited, stderr: stderr() };
    } finally {
      if (child.exitCode === null) child.kill('SIGKILL');
    }
  };
  let unblock = blockState(w);
  try {
    const behind = await startAndStop();
    assert.match(behind.stderr, /"event":"oauth-revoked"[^\n]*"why":"client-not-listed"/);
    assert.equal(behind.code, 1, behind.stderr);
    assert.match(behind.stderr, /\nprovared-mcp-executor: 1 connection was ended, and its end could not be written/);
    assert.match(behind.stderr, /agent "conn", client "https:\/\/gone\.example\/client"/);
    assert.equal(state(w).grants.length, 1);
    unblock();
    const written = await startAndStop();
    assert.equal(written.code, 0, written.stderr);
    assert.doesNotMatch(written.stderr, /could not be written/);
    assert.equal(state(w).grants.length, 0);
  } finally {
    unblock();
    await w.close();
  }
});

// --- N2: a stream ends when its token stops being valid, for any reason ---

/** The GET stream of server messages, opened as an agent: {res, closed (a promise)}. */
async function openStream(w, authorization) {
  const s = await rawRequest(w, { method: 'GET', headers: { accept: 'text/event-stream', authorization }, stream: true });
  assert.equal(s.status, 200);
  s.closed = new Promise((done) => s.res.on('close', done));
  s.res.resume();
  return s;
}

test('N2: a stream is ended when later refreshes push its access token out; a stream opened with a token that still stands stays open', async () => {
  const w = await oauthWorld();
  try {
    const c = await connect(w);
    const first = await openStream(w, bearer(c.access));
    let newest = { access_token: c.access, refresh_token: c.refresh };
    // One refresh short of pushing the first token out: it still stands, and so does its stream.
    for (let i = 0; i < MAX_ACCESS - 1; i += 1) newest = json(await refresh(w, newest.refresh_token));
    assert.equal((await call(w, bearer(c.access), 'echo', {})).status, 200);
    assert.equal(await within(first.closed, 300), false, 'open while its token stands');
    const later = await openStream(w, bearer(newest.access_token));
    newest = json(await refresh(w, newest.refresh_token));
    assert.equal((await call(w, bearer(c.access), 'echo', {})).status, 401, 'the first token is pushed out');
    assert.equal(await within(first.closed, 3000), true, 'and its stream is ended with it');
    assert.ok(w.logs.some((e) => e.event === 'stream-ended' && e.why === 'token-dropped'));
    assert.equal(await within(later.closed, 500), false, 'a stream whose token stands is not touched');
    assert.equal(w.executor.agent('conn').open(), 1, 'the ended stream no longer holds one of the agent\'s places');
    later.res.destroy();
  } finally {
    await w.close();
  }
});

// --- N3, and the two tests the re-check found missing (N4) ---

/** The way the page reaches the executor: POST JSON, with the page's Origin. Throws {status, code} where the answer is not 200. */
const sender = (w) => async (path, value) => {
  const r = await send('POST', `${w.issuer}${path}`, { headers: { 'content-type': 'application/json', origin: w.issuer }, body: JSON.stringify(value) });
  const v = json(r);
  if (r.status !== 200) throw Object.assign(new Error(v.message), { status: r.status, code: v.error });
  return v;
};
const refusal = async (p) => {
  try {
    await p;
  } catch (e) {
    return { status: e.status, code: e.code };
  }
  assert.fail('it was not refused');
};
/** A stand-in for the owner's passkey, which reports the transports given; "asked" holds the transports each unlock was told. */
function fakePasskey(transports) {
  const credentialId = new Uint8Array(randomBytes(16));
  const prfOutput32 = new Uint8Array(randomBytes(32));
  const p = {
    asked: [],
    create: async () => ({ credentialId, prfSalt: new Uint8Array(randomBytes(32)), prfOutput32, transports }),
    evaluate: async (cid, salt, told) => {
      p.asked.push(told);
      return { prfOutput32 };
    },
  };
  return p;
}
/** A world whose executor has the check by passkey, and a setup link made before the start. */
async function ownerWorld() {
  const w = await oauthWorld({ open: false });
  delete w.more.ownerCheck;
  w.parsed = readHttpSettings(w.settings, w.folder).settings;
  w.code = new URL(makeOwnerSetup(w.parsed, { now: w.more.now }).link).hash.slice(1);
  await reopen(w);
  return w;
}
/** A page waiting for the owner's answer: the form's request field. */
async function waiting(w) {
  const page = await ask(w, authorizeUrl(w, await discover(w), { pkce: pkce() }));
  assert.equal(page.status, 200, page.body);
  return page.request;
}
/** What the page sends at the setup, for a new identity, with these transports. */
async function ownerToSend(w, transports) {
  const identity = await id.createIdentity(cc);
  const byPasskey = await id.wrapRootKeyWithPrf(cc, identity.rootKey, new Uint8Array(randomBytes(32)), new Uint8Array(randomBytes(16)), new Uint8Array(randomBytes(32)));
  const { method: byCode } = await id.wrapRootKeyWithNewRecoveryCode(cc, identity.rootKey);
  const b = cc.toBase64Url;
  return {
    code: w.code,
    routingPublicKey: b(identity.routing.publicKeyRaw),
    passkey: { credentialId: b(byPasskey.credentialId), prfSalt: b(byPasskey.prfSalt), wrappedRootKey: b(byPasskey.wrappedRootKey), ...(transports === undefined ? {} : { transports }) },
    recovery: { salt: b(byCode.salt), lookupHash: byCode.lookupHash, wrappedRootKey: b(byCode.wrappedRootKey) },
  };
}

test('N3: a transport name that is not in the executor\'s form is left out, and the owner is set up: [\'Internal\'] through the page\'s own steps, then a sign-in', async () => {
  const w = await ownerWorld();
  try {
    const passkey = fakePasskey(['Internal']);
    const { recoveryCode } = await setUp({ cc, id, passkey, code: w.code, send: sender(w) });
    assert.equal(typeof recoveryCode, 'string');
    assert.deepEqual(state(w).owner.passkey.transports, [], 'the name is dropped, the owner kept');
    const c = await connect(w, { prove: (request) => signIn({ cc, id, passkey, request, origin: w.issuer, send: sender(w) }) });
    assert.deepEqual(passkey.asked, [[]], 'the unlock is told no transport');
    assert.equal((await call(w, bearer(c.access), 'echo', {})).status, 200);
  } finally {
    await w.close();
  }
});

test('N3: of a passkey\'s transports, the names in the form are kept, in their order, eight at most; a list that is no list is still refused', async () => {
  const w = await ownerWorld();
  try {
    assert.deepEqual(await refusal(sender(w)(SETUP_PATH, await ownerToSend(w, 'usb'))), { status: 400, code: 'bad-request' });
    assert.equal(state(w).owner, null);
    const sent = ['Internal', 'usb', 'USB key', 7, 'nfc', '', 'ble', 'hybrid', 'internal', 'smart-card', 'x'.repeat(33), 'a', 'b', 'c', 'd'];
    assert.deepEqual(await sender(w)(SETUP_PATH, await ownerToSend(w, sent)), { owner: 'set' });
    assert.deepEqual(state(w).owner.passkey.transports, ['usb', 'nfc', 'ble', 'hybrid', 'internal', 'smart-card', 'a', 'b']);
    // What was kept is in the form a start reads.
    await reopen(w);
    assert.deepEqual((await sender(w)('/oauth/owner/passkey', {})).transports, ['usb', 'nfc', 'ble', 'hybrid', 'internal', 'smart-card', 'a', 'b']);
  } finally {
    await w.close();
  }
});

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

test('N4: where the state cannot be written at the owner\'s setup, the answer is "not-written", there is no owner, and the link still works', async () => {
  const w = await ownerWorld();
  let restore = () => {};
  try {
    const owner = await ownerToSend(w, ['internal']);
    // The file is held by another program: putting the new file in place fails, as Windows reports it.
    restore = withFs({ renameSync: (real) => (from, to) => {
      if (String(to) === w.statePath) throw Object.assign(new Error('the file is held'), { code: 'EBUSY' });
      return real(from, to);
    } });
    assert.deepEqual(await refusal(sender(w)(SETUP_PATH, owner)), { status: 500, code: 'not-written' });
    restore();
    restore = () => {};
    assert.equal(w.logs.some((e) => e.event === 'owner-set'), false);
    assert.equal(state(w).owner, null, 'no owner in the file');
    assert.deepEqual(await refusal(sender(w)('/oauth/owner/passkey', {})), { status: 409, code: 'no-owner' }, 'and none in memory');
    assert.deepEqual(await sender(w)(LINK_PATH, { code: w.code }), { link: 'open' }, 'the link still works');
    assert.deepEqual(await sender(w)(SETUP_PATH, owner), { owner: 'set' });
    assert.equal(state(w).owner.routingPublicKey, owner.routingPublicKey);
  } finally {
    restore();
    await w.close();
  }
});

test('N4: a challenge is given only for a request that waits: not for one that has ended, nor for one already approved', async () => {
  const w = await ownerWorld();
  try {
    const passkey = fakePasskey(['internal']);
    await setUp({ cc, id, passkey, code: w.code, send: sender(w) });
    const challenge = (request) => sender(w)(CHALLENGE_PATH, { request });
    // Ended: ten minutes after the page was made.
    const ended = await waiting(w);
    assert.equal(typeof (await challenge(ended)).challenge, 'string', 'given while the request waits');
    w.clock.offset += REQUEST_LIFE;
    assert.deepEqual(await refusal(challenge(ended)), { status: 400, code: 'bad-request' }, 'ended');
    // Approved: the request as the page had it, and as it was approved, with its challenge sealed in.
    const first = await waiting(w);
    const fields = await signIn({ cc, id, passkey, request: first, origin: w.issuer, send: sender(w) });
    assert.equal((await answer(w, fields.request, { fields })).status, 303);
    assert.deepEqual(await refusal(challenge(first)), { status: 400, code: 'bad-request' }, 'approved, as the page had it');
    assert.deepEqual(await refusal(challenge(fields.request)), { status: 400, code: 'bad-request' }, 'approved, as it was sent');
    assert.deepEqual(await refusal(challenge('not a request')), { status: 400, code: 'bad-request' });
  } finally {
    await w.close();
  }
});
