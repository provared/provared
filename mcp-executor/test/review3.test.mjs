// The findings of the third review, of the OAuth sign-in and the owner's
// check (DESIGN.md, section 14): each fault as a test that fails without
// its fix. Through the executor's public interface, as the other tests of
// OAuth are; the page's script (owner-page.mjs) is run here as the executor
// serves it, with a stand-in for the page and for navigator.credentials.
// Nothing leaves this computer.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import fs, { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';
import { createCryptoCore } from '@microtoll/crypto-core';
import * as id from '@microtoll/identity';

const { call, rawRequest } = await import('./http-world.mjs');
const { openHttpExecutor, readHttpSettings, secretHash } = await import('../http.mjs');
const { ACCESS_LIFE, DOCUMENT_KEPT, DOCUMENT_RETRY, REQUEST_LIFE, makeOwnerSetup } = await import('../oauth.mjs');
const { openPasskeyCheck } = await import('../owner.mjs');
const { NAMESPACE, FIELD_CHALLENGE, FIELD_SIGNATURE, CHALLENGE_PATH, LINK_PATH, RECOVERY_PATH, ELSEWHERE_AFTER, setUp, signIn } = await import('../owner-steps.mjs');
const { CALLBACK, oauthWorld, reopen, send, json, pkce, authorizeUrl, discover, ask, answer, token, connect, bearer } = await import('./oauth-world.mjs');

const cc = createCryptoCore({ namespace: NAMESPACE });
const state = (w) => JSON.parse(readFileSync(w.statePath, 'utf8'));
const pause = (ms) => new Promise((done) => setTimeout(done, ms));
/** Whether a promise settles within so many milliseconds. */
const within = (p, ms) => Promise.race([p.then(() => true), pause(ms).then(() => false)]);
/** Many requests, a hundred at a time. */
async function many(count, one) {
  for (let done = 0; done < count; done += 100) await Promise.all(Array.from({ length: Math.min(100, count - done) }, () => one()));
}

/** A stand-in for the owner's passkey, as in owner.test.mjs. */
function fakePasskey() {
  const credentialId = new Uint8Array(randomBytes(16));
  const prfOutput32 = new Uint8Array(randomBytes(32));
  return { create: async () => ({ credentialId, prfSalt: new Uint8Array(randomBytes(32)), prfOutput32, transports: ['internal'] }), evaluate: async () => ({ prfOutput32 }) };
}
/** The way the page reaches the executor: POST JSON, with the page's Origin. Throws {status, code} where the answer is not 200. */
const sender = (w, origin = w.issuer) => async (path, value) => {
  const r = await send('POST', `${w.issuer}${path}`, { headers: { 'content-type': 'application/json', ...(origin ? { origin } : {}) }, body: JSON.stringify(value) });
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
    const passkey = fakePasskey();
    await setUp({ cc, id, passkey, code: w.code, send: sender(w) });
    assert.ok(state(w).owner, 'the right code, straight after twelve wrong ones');
    for (let i = 0; i < 12; i += 1) assert.deepEqual(await refusal(sender(w)(RECOVERY_PATH, { lookupHash: randomBytes(32).toString('hex') })), { status: 404, code: 'not-found' });
    const request = await waiting(w);
    for (let i = 0; i < 12; i += 1) assert.equal((await answer(w, request, { fields: { [FIELD_CHALLENGE]: randomBytes(32).toString('base64url'), [FIELD_SIGNATURE]: randomBytes(64).toString('base64url') } })).status, 403);
    const a = await answer(w, request, { fields: await signIn({ cc, id, passkey, request, origin: w.issuer, send: sender(w) }) });
    assert.equal(a.status, 303, a.body);
  } finally {
    await w.close();
  }
});

test('finding 2: nothing anyone sends pushes the owner\'s page out: after 1,200 other requests at the page and 1,200 other challenges, the owner\'s answer passes', async () => {
  const w = await ownerWorld();
  try {
    const passkey = fakePasskey();
    await setUp({ cc, id, passkey, code: w.code, send: sender(w) });
    const d = await discover(w);
    // The owner's page, and the owner's answer made ready: the root key open, the challenge signed.
    const request = await waiting(w);
    const fields = await signIn({ cc, id, passkey, request, origin: w.issuer, send: sender(w) });
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
  const identity = await id.createIdentity(cc);
  const origin = 'https://guard.example.com';
  const owner = { routingPublicKey: cc.toBase64Url(identity.routing.publicKeyRaw) };
  const check = openPasskeyCheck({ issuer: origin, store: { owner: () => owner, setup: () => null, setOwner() {} }, withNote: () => null, page() {}, json() {}, hashOf: (text) => text });
  const nonce = new Uint8Array(randomBytes(32));
  const challenge = cc.toBase64Url(nonce);
  const signature = cc.toBase64Url(await cc.signBytes(identity.routing.privateKey, await id.authMessage(cc, origin, nonce)));
  const fields = new URLSearchParams({ [FIELD_CHALLENGE]: challenge, [FIELD_SIGNATURE]: signature });
  const note = { challenge, expires: Date.now() + 60000 };
  assert.equal(await check.check(new URLSearchParams({ [FIELD_CHALLENGE]: challenge, [FIELD_SIGNATURE]: cc.toBase64Url(new Uint8Array(64)) }), { origin, note }), false, 'a wrong signature');
  assert.equal(await check.check(fields, { origin, note }), true, 'a wrong signature before it spends nothing');
  assert.equal(await check.check(fields, { origin, note }), false, 'the same challenge and signature again');
});

// --- finding 3: a stream does not outlive its token or its connection ---

/** The GET stream of server messages, opened as an agent: {res, closed (a promise)}. */
async function openStream(w, authorization) {
  const s = await rawRequest(w, { method: 'GET', headers: { accept: 'text/event-stream', authorization }, stream: true });
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
    const c3 = await connect(w);
    assert.equal(await within(s2.closed, 3000), true, 'ended by the new approval');

    // The token expires: here it has half a second left when the stream is opened.
    w.clock.offset += ACCESS_LIFE - 500;
    const s3 = await openStream(w, bearer(c3.access));
    assert.equal(await within(s3.closed, 3000), true, 'ended when the token expires');
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

/** The files the page loads, fetched from the executor as a browser would and written to a folder of the same shape: the address of page.js there. */
async function pageScript(w) {
  const root = mkdtempSync(join(tmpdir(), 'provared-page-'));
  writeFileSync(join(root, 'package.json'), '{"type":"module"}');
  const seen = new Set();
  const fetchFile = async (path) => {
    if (seen.has(path)) return;
    seen.add(path);
    const r = await send('GET', `${w.issuer}${path}`);
    assert.equal(r.status, 200, path);
    const file = join(root, path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, r.body);
    // Every file it imports by a relative address, as a browser would ask for them.
    for (const m of r.body.matchAll(/\bfrom\s+['"](\.{1,2}\/[^'"]+)['"]|\bimport\s*\(?\s*['"](\.{1,2}\/[^'"]+)['"]/g)) await fetchFile(new URL(m[1] ?? m[2], `http://x${path}`).pathname);
  };
  await fetchFile('/oauth/owner/page.js');
  assert.ok(seen.size > 4, 'the page\'s script, its steps and the two packages\' files');
  return pathToFileURL(join(root, 'oauth', 'owner', 'page.js')).href;
}

/** A stand-in for an element of the page: what the script reads and sets, and its listeners. */
function element(more = {}) {
  const listeners = {};
  return { textContent: '', hidden: false, disabled: false, value: '', ...more, addEventListener: (type, f) => (listeners[type] = f), fire: (type, event) => listeners[type](event) };
}

/**
 * A stand-in for navigator.credentials, for the package's own WebAuthn
 * functions. "onDevice" is what the device's own authenticator does: 'no-prf'
 * (it makes a passkey that gives no PRF), 'refused' (its prompt is closed),
 * 'unavailable', or 'ok'. A phone or a security key always works here.
 */
function fakeCredentials(onDevice) {
  const secret = randomBytes(32);
  const prf = (salt) => new Uint8Array(createHash('sha256').update(secret).update(Buffer.from(salt)).digest());
  const c = {
    /** The attachment of each passkey asked for, and the transports and hints of each unlock. */
    made: [],
    asked: [],
    async create({ publicKey: k }) {
      const attachment = k.authenticatorSelection.authenticatorAttachment;
      c.made.push(attachment);
      assert.equal(k.authenticatorSelection.userVerification, 'required');
      if (attachment === 'platform' && onDevice === 'refused') throw Object.assign(new Error('closed'), { name: 'NotAllowedError' });
      if (attachment === 'platform' && onDevice === 'unavailable') throw Object.assign(new Error('not here'), { name: 'SecurityError' });
      const noPrf = attachment === 'platform' && onDevice === 'no-prf';
      const transports = attachment === 'platform' ? ['internal'] : ['hybrid', 'usb'];
      return {
        rawId: new Uint8Array(randomBytes(16)),
        response: { getTransports: () => transports, getAuthenticatorData: () => new Uint8Array(37) },
        getClientExtensionResults: () => ({ prf: noPrf ? { enabled: false } : { enabled: true, results: { first: prf(k.extensions.prf.eval.first) } } }),
      };
    },
    async get({ publicKey: k }) {
      c.asked.push({ transports: k.allowCredentials[0].transports, hints: k.hints });
      return { rawId: k.allowCredentials[0].id, response: {}, getClientExtensionResults: () => ({ prf: { results: { first: prf(k.extensions.prf.eval.first) } } }) };
    },
  };
  return c;
}

/**
 * Run the page's script on a stand-in page made from the HTML the executor
 * sent: every element with an id, and the form with its named fields.
 * Gives {el (the elements by id), form, replaced (what history.replaceState
 * was given)}. The globals a page has are set for the run, and put back by
 * "after".
 */
let runs = 0;
async function runPage(w, script, { html, hash = '', path, credentials, after }) {
  const el = {};
  for (const m of html.matchAll(/<(\w+)[^>]*\sid="([^"]+)"([^>]*)>/g)) el[m[2]] = element({ hidden: /\shidden(\s|$)/.test(` ${m[3]}`) });
  let form = null;
  if (/<form method="post" action="\/oauth\/authorize">/.test(html)) {
    form = element({ elements: {}, submitted: null, requestSubmit: (submitter) => (form.submitted = submitter) });
    for (const m of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) form.elements[m[1]] = { value: m[2] };
  }
  const page = { el, form, replaced: null };
  const globals = {
    document: { getElementById: (name) => el[name] ?? null, querySelector: (q) => (q === 'form[action="/oauth/authorize"]' ? form : null) },
    location: { hash, host: new URL(w.issuer).host, origin: w.issuer, pathname: path },
    history: { replaceState: (...a) => (page.replaced = a) },
    navigator: { credentials },
    // The page's fetch: to the executor's own address, with the Origin a browser gives a page's own request.
    fetch: async (to, o) => {
      const r = await send(o.method, `${w.issuer}${to}`, { headers: { ...o.headers, origin: w.issuer }, body: o.body });
      return { ok: r.status >= 200 && r.status < 300, status: r.status, json: async () => JSON.parse(r.body) };
    },
  };
  const before = Object.fromEntries(Object.keys(globals).map((k) => [k, Object.getOwnPropertyDescriptor(globalThis, k)]));
  for (const [k, value] of Object.entries(globals)) Object.defineProperty(globalThis, k, { value, configurable: true, writable: true });
  after(() => {
    for (const [k, d] of Object.entries(before)) {
      if (d) Object.defineProperty(globalThis, k, d);
      else delete globalThis[k];
    }
  });
  runs += 1;
  await import(`${script}?run=${runs}`);
  return page;
}

test('findings 5 and 14: the page\'s script, as served: where the device\'s passkey gives no PRF, a passkey on a phone or a security key is offered and sets up the owner; its transports are kept and given back at the unlock', async (t) => {
  const w = await ownerWorld();
  const undo = [];
  t.after(async () => {
    for (const f of undo.reverse()) f();
    await w.close();
  });
  const after = (f) => undo.push(f);
  const script = await pageScript(w);
  const credentials = fakeCredentials('no-prf');
  const setupHtml = (await send('GET', `${w.issuer}/oauth/owner`)).body;
  const setup = await runPage(w, script, { html: setupHtml, hash: `#${w.code}`, path: '/oauth/owner', credentials, after });
  assert.deepEqual(setup.replaced?.[2], '/oauth/owner', 'the link\'s code is taken out of the address');
  assert.equal(setup.el['owner-setup-elsewhere'].hidden, true, 'the second way is not offered before the first has failed');
  // The passkey on the device: made, but with no PRF. Nothing is set up, and the second way is offered.
  await setup.el['owner-setup'].fire('click');
  assert.deepEqual(credentials.made, ['platform']);
  assert.equal(state(w).owner, null);
  assert.equal(setup.el['owner-setup-elsewhere'].hidden, false, 'a phone or a security key is offered');
  assert.equal(setup.el['owner-setup'].disabled, false);
  assert.match(setup.el['owner-status'].textContent, /^Not done: .*phone or a security key/);
  assert.equal(setup.el['owner-recovery'].hidden, true);
  // On a phone or a security key: the package's own "cross-platform".
  await setup.el['owner-setup-elsewhere'].fire('click');
  assert.deepEqual(credentials.made, ['platform', 'cross-platform']);
  assert.match(setup.el['owner-status'].textContent, /^The owner is set up\./);
  assert.equal(setup.el['owner-recovery'].hidden, false);
  assert.match(setup.el['owner-recovery'].textContent, /\S/, 'the recovery code is shown');
  assert.deepEqual(state(w).owner.passkey.transports, ['hybrid', 'usb'], 'the executor keeps where the passkey is');
  assert.equal(readFileSync(w.statePath, 'utf8').includes(setup.el['owner-recovery'].textContent), false);

  // The authorisation page: Approve asks the passkey where it is kept, then sends the form with the request and the check's two fields.
  const d = await discover(w);
  const p = pkce();
  const html = (await ask(w, authorizeUrl(w, d, { pkce: p }))).body;
  const page = await runPage(w, script, { html, path: '/oauth/authorize', credentials, after });
  const submitter = { value: 'approve' };
  let prevented = false;
  await page.form.fire('submit', { submitter, preventDefault: () => (prevented = true) });
  assert.equal(prevented, true, 'the form waits for the owner\'s proof');
  assert.deepEqual(credentials.asked, [{ transports: ['hybrid', 'usb'], hints: ['hybrid', 'security-key'] }], 'the browser is told where the passkey is kept');
  assert.equal(page.form.submitted, submitter, `the form is sent (${page.el['owner-status'].textContent})`);
  const a = await answer(w, page.form.elements.request.value, { fields: { [FIELD_CHALLENGE]: page.form.elements[FIELD_CHALLENGE].value, [FIELD_SIGNATURE]: page.form.elements[FIELD_SIGNATURE].value } });
  assert.equal(a.status, 303, a.body);
  const got = await token(w, { grant_type: 'authorization_code', code: a.params.code, client_id: w.docs.client, code_verifier: p.verifier });
  assert.equal(got.status, 200, got.body);
  assert.equal((await call(w, bearer(json(got).access_token), 'echo', {})).status, 200);
  // Refuse is sent as it is, with no proof asked for.
  const refuse = await runPage(w, script, { html: (await ask(w, authorizeUrl(w, d, { pkce: pkce() }))).body, path: '/oauth/authorize', credentials, after });
  let stopped = false;
  await refuse.form.fire('submit', { submitter: { value: 'refuse' }, preventDefault: () => (stopped = true) });
  assert.equal(stopped, false);
  assert.equal(credentials.asked.length, 1);
});

test('finding 5: the second way is offered after the device\'s prompt is closed or refused too, and after no other failure', async (t) => {
  assert.deepEqual(ELSEWHERE_AFTER, ['prf-unsupported', 'not-allowed']);
  const w = await ownerWorld();
  const undo = [];
  t.after(async () => {
    for (const f of undo.reverse()) f();
    await w.close();
  });
  const after = (f) => undo.push(f);
  const script = await pageScript(w);
  const html = (await send('GET', `${w.issuer}/oauth/owner`)).body;
  const refused = await runPage(w, script, { html, hash: `#${w.code}`, path: '/oauth/owner', credentials: fakeCredentials('refused'), after });
  await refused.el['owner-setup'].fire('click');
  assert.equal(refused.el['owner-setup-elsewhere'].hidden, false, 'after "not-allowed"');
  const unavailable = await runPage(w, script, { html, hash: `#${w.code}`, path: '/oauth/owner', credentials: fakeCredentials('unavailable'), after });
  await unavailable.el['owner-setup'].fire('click');
  assert.match(unavailable.el['owner-status'].textContent, /^Not done: /);
  assert.equal(unavailable.el['owner-setup-elsewhere'].hidden, true, 'not after "webauthn-unavailable"');
  assert.equal(state(w).owner, null);
  // Where the device's own passkey works, it is the owner's, and its transports are kept.
  const works = fakeCredentials('ok');
  const ok = await runPage(w, script, { html, hash: `#${w.code}`, path: '/oauth/owner', credentials: works, after });
  await ok.el['owner-setup'].fire('click');
  assert.deepEqual(works.made, ['platform']);
  assert.deepEqual(state(w).owner.passkey.transports, ['internal']);
});

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
