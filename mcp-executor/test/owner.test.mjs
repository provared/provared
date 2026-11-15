// The owner's check by the owner's passkey (DESIGN.md, section 14.1,
// X270 onward), through the executor's public interface: its addresses, the
// command "owner", and openHttpExecutor with no check given, as the command
// "http" opens it.
//
// The browser's half runs here too: the steps the page runs
// (owner-steps.mjs) and, as the executor serves it, the page's script
// itself (owner-page.mjs), with the library's own browser functions, on a
// stand-in page. Only the passkey is made up: a software passkey that
// builds what a real one returns (owner-world.mjs). Nothing leaves this
// computer.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { copyFileSync, cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { call } = await import('./http-world.mjs');
const { REQUEST_LIFE, makeOwnerSetup, readIssuer } = await import('../oauth.mjs');
const { CHALLENGE_LIFE, CONTINUE_LIFE, LIBRARY_PROBLEM, RECOVERY_BYTES, RECOVERY_USED, RESET_COMMAND, SETUP_LIFE, base32, passkeyChecks } = await import('../owner.mjs');
const { FIELD_CHALLENGE, FIELD_AUTHENTICATOR_DATA, FIELD_CLIENT_DATA, FIELD_SIGNATURE, FIELD_RECOVERY, SETUP_PATH, CHALLENGE_PATH, LINK_PATH, STORE_CODE, STORE_WAITING, setUp } = await import('../owner-steps.mjs');
const { oauthWorld, reopen, send, pkce, authorizeUrl, discover, ask, answer, connect, token, json, bearer, CALLBACK } = await import('./oauth-world.mjs');
const { openHttpExecutor } = await import('../http.mjs');
const { ownerWorld, softPasskey, setUpOwner, prove, sender, refusal, waiting, state, pageScript, runPage, softCredentials, softStorage } = await import('./owner-world.mjs');

const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));
/** A recovery code as it is shown: 32 characters of base32, in eight groups of four. */
const RECOVERY_SHOWN = /^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$/;
const FOUR = [FIELD_CHALLENGE, FIELD_AUTHENTICATOR_DATA, FIELD_CLIENT_DATA, FIELD_SIGNATURE];
/** The check's four fields of an answer, without the request that came with them. */
const fourOf = (fields) => Object.fromEntries(FOUR.map((name) => [name, fields[name]]));
/** The fields a page's form would send: its hidden fields as the script left them. */
const formFields = (page) => Object.fromEntries(Object.entries(page.form.elements).filter(([name]) => name !== 'request').map(([name, e]) => [name, e.value]));
/** From an approval's 303 to a tool call: the code is traded for a token, and the token calls a tool. */
async function callsATool(w, a, p) {
  assert.equal(a.status, 303, a.body);
  assert.ok(a.params.code, 'the browser goes back to the client with a code');
  const got = await token(w, { grant_type: 'authorization_code', code: a.params.code, client_id: w.docs.client, code_verifier: p.verifier });
  assert.equal(got.status, 200, got.body);
  assert.equal((await call(w, bearer(json(got).access_token), 'echo', {})).status, 200);
}
/** A test's page runs: the globals a page has are put back, and the world closed, when the test ends. */
function pages(t, w) {
  const undo = [];
  t.after(async () => {
    for (const f of undo.reverse()) f();
    await w.close();
  });
  return (f) => undo.push(f);
}

test('setup, then an approval with the passkey: the pages run only the executor\'s own scripts; the executor keeps the public key and a hash; the connection calls a tool', async () => {
  const w = await ownerWorld();
  try {
    assert.match(w.made.link, new RegExp(`^${w.issuer}/oauth/owner#[A-Za-z0-9_-]{43}$`));
    const left = w.made.expires - w.more.now();
    assert.ok(left <= SETUP_LIFE && left > SETUP_LIFE - 60000, 'the link lasts 15 minutes');
    // The setup page and its files: from the executor itself, no inline script.
    const setupPage = await send('GET', `${w.issuer}/oauth/owner`);
    assert.equal(setupPage.status, 200);
    assert.equal(setupPage.headers['content-security-policy'], "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    assert.match(setupPage.body, /<script type="module" src="\/oauth\/owner\/page\.js"><\/script>/);
    assert.doesNotMatch(setupPage.body, /<script(?![^>]*\ssrc=)/, 'no inline script');
    for (const path of ['page.js', 'steps.js', 'lib/provared/passkey-browser.js', 'lib/provared/encoding.js']) {
      const f = await send('GET', `${w.issuer}/oauth/owner/${path}`);
      assert.equal(f.status, 200, path);
      assert.equal(f.headers['content-type'], 'text/javascript; charset=utf-8');
    }
    // The page's passkey functions are the library's own file, byte for byte.
    assert.equal((await send('GET', `${w.issuer}/oauth/owner/lib/provared/passkey-browser.js`)).body, readFileSync(new URL('../../src/passkey-browser.js', import.meta.url), 'utf8'));
    for (const path of ['lib/provared/..%2Fpackage.json', 'lib/provared/../../package.json', 'lib/provared/index.d.ts', 'lib/identity/index.js', 'lib/crypto-core/index.js']) assert.equal((await send('GET', `${w.issuer}/oauth/owner/${path}`)).status, 404, path);

    const { passkey, recoveryCode } = await setUpOwner(w);
    assert.match(recoveryCode, RECOVERY_SHOWN);
    assert.equal(RECOVERY_BYTES * 8 >= 128, true, 'at least 128 random bits');
    assert.equal(passkey.made, 1);
    const kept = state(w);
    assert.equal(kept.setup, null, 'the link is spent');
    assert.deepEqual(Object.keys(kept.owner).sort(), ['created', 'credentialId', 'key', 'recoveryHash']);
    assert.deepEqual(kept.owner.key, passkey.key, 'the passkey\'s public key, as a JWK');
    assert.equal(kept.owner.credentialId, passkey.credentialId);
    const text = readFileSync(w.statePath, 'utf8');
    assert.equal(text.includes(recoveryCode) || text.includes(recoveryCode.replaceAll('-', '')), false, 'no recovery code in the file');

    // The authorisation page: who asks, by its host; the warning; the check's fields and its script, under the policy.
    const d = await discover(w);
    const page = await ask(w, authorizeUrl(w, d, { pkce: pkce() }));
    assert.match(page.headers['content-security-policy'], /^default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self' https:\/\/client\.example; frame-ancestors 'none'; base-uri 'none'$/);
    const host = new URL(w.docs.client).host;
    assert.ok(page.body.includes(`<h1>Approve ${host} connecting to your guard</h1>`), 'the client is named by its host');
    assert.match(page.body, /Approve only a connection you began yourself, just now\./);
    assert.match(page.body, new RegExp(`name="${FIELD_CHALLENGE}"`));
    assert.doesNotMatch(page.body, /id="owner-first"/);
    assert.doesNotMatch(page.body, /<script(?![^>]*\ssrc=)/, 'no inline script');

    const { access } = await connect(w, { prove: prove(w, passkey) });
    assert.equal((await call(w, bearer(access), 'echo', { a: 1 })).status, 200);
    assert.equal(passkey.signed, 1, 'one prompt for the approval');
    assert.ok(w.logs.some((e) => e.event === 'owner-set' && e.approves === false));
    assert.ok(w.logs.some((e) => e.event === 'oauth-approved' && e.agent === 'conn' && e.by === 'passkey'), 'the log says which proof approved');
    // The JSON answers are not to be read as anything else.
    assert.equal((await send('POST', `${w.issuer}/oauth/owner/link`, { headers: { 'content-type': 'application/json', origin: w.issuer }, body: '{}' })).headers['x-content-type-options'], 'nosniff');
    assert.equal((await send('GET', `${w.issuer}/.well-known/oauth-authorization-server`)).headers['x-content-type-options'], 'nosniff');
  } finally {
    await w.close();
  }
});

for (const alg of ['RS256', 'Ed25519']) {
  test(`a passkey that signs with ${alg} is the owner's as one with ES256 is, and another key of its kind is refused`, async () => {
    const w = await ownerWorld();
    try {
      const { passkey } = await setUpOwner(w, alg);
      assert.equal(state(w).owner.key.alg, alg);
      const stranger = await softPasskey(w, alg);
      stranger.credentialId = passkey.credentialId;
      const request = await waiting(w);
      assert.equal((await answer(w, request, { fields: await prove(w, stranger)(request) })).status, 403);
      const { access } = await connect(w, { prove: prove(w, passkey) });
      assert.equal((await call(w, bearer(access), 'echo', {})).status, 200);
    } finally {
      await w.close();
    }
  });
}

test('one prompt the first time, the setup link first: the setup message that makes the owner approves the one request sent with it, once, and only while that request waits', async () => {
  const w = await ownerWorld();
  try {
    const d = await discover(w);
    const p = pkce();
    const page = await ask(w, authorizeUrl(w, d, { pkce: p }));
    // With no owner the page says so, shows the approval and its warning all the same, and has no box for a recovery code.
    assert.match(page.body, /<p id="owner-first">This executor has no owner yet/);
    assert.match(page.body, /Approve only a connection you began yourself, just now\./);
    assert.doesNotMatch(page.body, /owner-recovery-code/);
    // Nothing is approved for the asking: no owner, no code.
    assert.equal((await answer(w, page.request, { fields: {} })).status, 403);
    assert.deepEqual(await refusal(sender(w)(SETUP_PATH, { code: randomBytes(32).toString('base64url'), credentialId: 'AAAA', key: (await softPasskey(w)).key, request: page.request })), { status: 403, code: 'setup-refused' });
    assert.equal(state(w).owner, null);

    const passkey = await softPasskey(w);
    const done = await setUp({ passkey, code: w.code, request: page.request, send: sender(w) });
    assert.equal(done.owner, 'set');
    assert.match(done.recoveryCode, RECOVERY_SHOWN);
    assert.equal(typeof done.request, 'string');
    assert.equal(state(w).setup, null, 'the code is spent');
    assert.ok(w.logs.some((e) => e.event === 'owner-set' && e.approves === true));
    // The request the page had is not approved: only the one the setup gave back, under the executor's seal.
    assert.equal((await answer(w, page.request, { fields: {} })).status, 403);
    // The approval is the owner's to send, or not: nothing has gone to the client yet.
    assert.equal(w.logs.some((e) => e.event === 'oauth-approved'), false);
    await callsATool(w, await answer(w, done.request, { fields: {} }), p);
    assert.ok(w.logs.some((e) => e.event === 'oauth-approved' && e.by === 'setup'), 'the log says which proof approved');
    assert.deepEqual([passkey.made, passkey.signed], [1, 0], 'one prompt: the passkey was made, and never asked to sign');
    // Approved once: the same form again gets no second code.
    const again = await answer(w, done.request, { fields: {} });
    assert.equal(again.status, 400, again.body);
    assert.equal(again.headers.location, undefined);
    // The code is spent: it sets up no second owner, and approves no second request.
    const other = await softPasskey(w);
    assert.deepEqual(await refusal(setUp({ passkey: other, code: w.code, request: await waiting(w), send: sender(w) })), { status: 409, code: 'owner-exists' });
    assert.equal(other.made, 0);
    // Every later approval asks the passkey.
    await connect(w, { prove: prove(w, passkey) });
    assert.equal(passkey.signed, 1);
  } finally {
    await w.close();
  }
  // A request that has ended (10 minutes; the link lasts 15) is not approved; the owner is set up all the same, since by then the passkey has been made.
  const late = await ownerWorld();
  try {
    const request = await waiting(late);
    late.clock.offset += REQUEST_LIFE;
    const done = await setUp({ passkey: await softPasskey(late), code: late.code, request, send: sender(late) });
    assert.equal(done.request, null);
    assert.ok(state(late).owner);
    assert.ok(late.logs.some((e) => e.event === 'owner-set' && e.approves === false));
    assert.equal((await answer(late, request, { fields: {} })).status, 400, 'the request has ended');
  } finally {
    await late.close();
  }
});

test('one prompt the first time, by the page\'s script as served, the setup link opened first: Approve makes the passkey, shows the recovery code, and the form goes only when the owner continues', async (t) => {
  const w = await ownerWorld();
  const after = pages(t, w);
  const script = await pageScript(w);
  const credentials = softCredentials(w);
  const storage = softStorage();
  const host = new URL(w.issuer).host;
  // The setup link, opened and left: its code is kept for the authorisation page, and no passkey is made.
  const setupHtml = (await send('GET', `${w.issuer}/oauth/owner`)).body;
  const setup = await runPage(w, script, { html: setupHtml, hash: `#${w.code}`, path: '/oauth/owner', credentials, storage, after });
  assert.deepEqual(setup.replaced?.[2], '/oauth/owner', 'the link\'s code is taken out of the address');
  assert.equal(storage.getItem(STORE_CODE), w.code);
  assert.equal(setup.el['owner-review'].hidden, true, 'no request waits');
  assert.equal(setup.el['owner-setup'].disabled, false);
  assert.equal(credentials.made.length, 0);

  const d = await discover(w);
  const p = pkce();
  const html = (await ask(w, authorizeUrl(w, d, { pkce: p }))).body;
  const page = await runPage(w, script, { html, path: '/oauth/authorize', credentials, storage, after });
  assert.match(page.el['owner-first'].textContent, /Approve makes the owner's passkey for .* and approves this connection, in one prompt/);
  assert.equal(storage.getItem(STORE_WAITING), null);
  assert.equal(page.el['owner-keep'].hidden, true, 'nothing to keep: the setup link is already here');
  // Refuse is sent as it is: no passkey is made for it.
  let stopped = false;
  await page.form.fire('submit', { submitter: { value: 'refuse' }, preventDefault: () => (stopped = true) });
  assert.equal(stopped, false);
  assert.equal(credentials.made.length, 0);
  // Approve: one prompt, which makes the passkey.
  const submitter = { value: 'approve', textContent: 'Approve' };
  let prevented = false;
  await page.form.fire('submit', { submitter, preventDefault: () => (prevented = true) });
  assert.equal(prevented, true);
  assert.deepEqual(credentials.made, [{ rp: new URL(w.issuer).hostname, user: `Owner of ${host}`, userVerification: 'required', attachment: undefined, methods: [-7, -8, -257] }], 'the library\'s own call: this address, the user verified, ES256, Ed25519 or RS256, on whatever the browser offers');
  assert.equal(state(w).owner.credentialId, Buffer.from(credentials.rawId).toString('base64url'));
  assert.equal(page.el['owner-recovery'].hidden, false);
  assert.match(page.el['owner-recovery'].textContent, RECOVERY_SHOWN, 'the recovery code is shown');
  assert.match(page.el['owner-status'].textContent, /^The owner is set up, and this connection is approved once you continue\./);
  assert.equal(page.form.submitted, null, 'the form is not sent for the owner: the code is to be written down first');
  assert.equal(submitter.textContent, 'Continue');
  assert.equal(storage.getItem(STORE_CODE), null, 'the spent code is not kept');
  // Continue: the form goes as it is, with no second prompt.
  prevented = false;
  await page.form.fire('submit', { submitter, preventDefault: () => (prevented = true) });
  assert.equal(prevented, false);
  await callsATool(w, await answer(w, page.form.elements.request.value, { fields: formFields(page) }), p);
  assert.deepEqual([credentials.made.length, credentials.asked.length], [1, 0], 'one prompt in all');
});

test('one prompt the first time, by the page\'s script as served, the authorisation page opened first: the setup link shows that request again while it waits, and approves nothing by itself', async (t) => {
  const w = await ownerWorld();
  const after = pages(t, w);
  const script = await pageScript(w);
  const credentials = softCredentials(w);
  const storage = softStorage();
  const d = await discover(w);
  const p = pkce();
  const first = await ask(w, authorizeUrl(w, d, { pkce: p }));
  // The authorisation page, with no owner and no setup link in this browser: Approve does nothing, and the page keeps nothing by opening.
  const early = await runPage(w, script, { html: first.body, path: '/oauth/authorize', credentials, storage, after });
  assert.match(first.body, /<p id="owner-first">This executor has no owner yet, so nothing can be approved here\./);
  assert.equal(early.el['owner-first'].textContent, '', 'the script leaves the executor\'s own words as they are');
  assert.equal(storage.kept.size, 0, 'a page that opens keeps nothing in the browser\'s storage');
  assert.equal(early.el['owner-keep'].hidden, false, 'the owner is offered to keep the request');
  let prevented = false;
  await early.form.fire('submit', { submitter: { value: 'approve' }, preventDefault: () => (prevented = true) });
  assert.equal(prevented, true);
  assert.match(early.el['owner-status'].textContent, /^Not done: this executor has no owner yet/);
  assert.equal(credentials.made.length, 0);
  assert.equal(state(w).owner, null);
  assert.equal(storage.kept.size, 0);
  // The owner presses "Keep this connection for the setup link": only then is the request left for the setup page.
  await early.el['owner-keep'].fire('click');
  assert.equal(storage.getItem(STORE_WAITING), first.request);
  assert.match(early.el['owner-status'].textContent, /^Kept in this browser\./);

  // The setup link, opened second: it offers the waiting request for review, named by its client's host.
  const setupHtml = (await send('GET', `${w.issuer}/oauth/owner`)).body;
  const setup = await runPage(w, script, { html: setupHtml, hash: `#${w.code}`, path: '/oauth/owner', credentials, storage, after });
  assert.equal(setup.el['owner-review'].hidden, false);
  assert.equal(setup.el['owner-review-request'].value, first.request);
  assert.ok(setup.el['owner-status'].textContent.startsWith(`${new URL(w.docs.client).host} is waiting to connect to this executor.`), setup.el['owner-status'].textContent);
  assert.equal(state(w).owner, null, 'opening the link sets nothing up');
  // Its form asks the executor for that request's page again: the same request, with the warning; nothing approved by it. Only from the executor's own page.
  assert.equal((await answer(w, first.request, { decision: 'show', origin: 'null', fields: {} })).status, 403);
  const shown = await answer(w, first.request, { decision: 'show', fields: {} });
  assert.equal(shown.status, 200, shown.body);
  assert.equal(/name="request" value="([^"]+)"/.exec(shown.body)?.[1], first.request, 'the same request, with the same end');
  assert.match(shown.body, /Approve only a connection you began yourself, just now\./);
  assert.match(shown.headers['content-security-policy'], /form-action 'self' https:\/\/client\.example;/);
  assert.equal(w.logs.some((e) => e.event === 'oauth-approved'), false);

  const page = await runPage(w, script, { html: shown.body, path: '/oauth/authorize', credentials, storage, after });
  assert.match(page.el['owner-first'].textContent, /in one prompt/);
  const submitter = { value: 'approve', textContent: 'Approve' };
  await page.form.fire('submit', { submitter, preventDefault: () => {} });
  assert.equal(credentials.made.length, 1);
  assert.match(page.el['owner-recovery'].textContent, RECOVERY_SHOWN);
  assert.equal(storage.getItem(STORE_WAITING), null);
  prevented = false;
  await page.form.fire('submit', { submitter, preventDefault: () => (prevented = true) });
  assert.equal(prevented, false);
  await callsATool(w, await answer(w, page.form.elements.request.value, { fields: formFields(page) }), p);
  assert.deepEqual([credentials.made.length, credentials.asked.length], [1, 0], 'one prompt in all');
});

test('no other page can put its request in the place of the one the owner kept: a page that merely opens keeps nothing, and the setup link shows the owner\'s own', async (t) => {
  const w = await ownerWorld();
  const after = pages(t, w);
  const script = await pageScript(w);
  const credentials = softCredentials(w);
  const storage = softStorage();
  const d = await discover(w);
  const mine = pkce();
  const theirs = pkce();
  // Someone else's request, opened in this browser before the owner's own (a link, a redirect, a pop-up): nothing pressed, nothing kept.
  const before = await ask(w, authorizeUrl(w, d, { pkce: theirs, state: 'someone-elses-first' }));
  await runPage(w, script, { html: before.body, path: '/oauth/authorize', credentials, storage, after });
  assert.equal(storage.kept.size, 0);
  // The owner's own page, and the owner's press.
  const own = await ask(w, authorizeUrl(w, d, { pkce: mine, state: 'the-owners-own' }));
  const ownPage = await runPage(w, script, { html: own.body, path: '/oauth/authorize', credentials, storage, after });
  await ownPage.el['owner-keep'].fire('click');
  assert.equal(storage.getItem(STORE_WAITING), own.request);
  // Someone else's request again, opened after it: the owner's own stays.
  const planted = await ask(w, authorizeUrl(w, d, { pkce: theirs, state: 'someone-elses' }));
  await runPage(w, script, { html: planted.body, path: '/oauth/authorize', credentials, storage, after });
  assert.equal(storage.getItem(STORE_WAITING), own.request, 'the request the owner kept is still the one kept');
  const setupHtml = (await send('GET', `${w.issuer}/oauth/owner`)).body;
  const setup = await runPage(w, script, { html: setupHtml, hash: `#${w.code}`, path: '/oauth/owner', credentials, storage, after });
  assert.equal(setup.el['owner-review-request'].value, own.request, 'the setup page offers the owner\'s own request');
  const shown = await answer(w, own.request, { decision: 'show', fields: {} });
  const page = await runPage(w, script, { html: shown.body, path: '/oauth/authorize', credentials, storage, after });
  const submitter = { value: 'approve', textContent: 'Approve' };
  await page.form.fire('submit', { submitter, preventDefault: () => {} });
  await page.form.fire('submit', { submitter, preventDefault: () => {} });
  const a = await answer(w, page.form.elements.request.value, { fields: formFields(page) });
  assert.equal(a.params.state, 'the-owners-own');
  await callsATool(w, a, mine);
  assert.equal((await token(w, { grant_type: 'authorization_code', code: a.params.code, client_id: w.docs.client, code_verifier: theirs.verifier })).status, 400, 'the other party gets nothing');
});

test('"Make the passkey" on the setup page, pressed while a request waits, makes the owner and approves nothing', async (t) => {
  const w = await ownerWorld();
  const after = pages(t, w);
  const script = await pageScript(w);
  const credentials = softCredentials(w);
  const storage = softStorage();
  const d = await discover(w);
  const first = await ask(w, authorizeUrl(w, d, { pkce: pkce() }));
  const early = await runPage(w, script, { html: first.body, path: '/oauth/authorize', credentials, storage, after });
  await early.el['owner-keep'].fire('click');
  const setupHtml = (await send('GET', `${w.issuer}/oauth/owner`)).body;
  const setup = await runPage(w, script, { html: setupHtml, hash: `#${w.code}`, path: '/oauth/owner', credentials, storage, after });
  assert.equal(setup.el['owner-review'].hidden, false, 'the waiting request is offered');
  await setup.el['owner-setup'].fire('click');
  assert.match(setup.el['owner-status'].textContent, /^The owner is set up\./);
  assert.ok(w.logs.some((e) => e.event === 'owner-set' && e.approves === false), 'the setup was sent with no request');
  assert.equal(w.logs.some((e) => e.event === 'owner-set' && e.approves === true), false);
  assert.equal(setup.el['owner-review'].hidden, true);
  assert.equal(storage.kept.size, 0, 'neither the spent code nor the request is kept');
  // The request that waited is as it was: not approved, and still the owner's to approve with the passkey.
  assert.equal((await answer(w, first.request, { fields: {} })).status, 403);
  assert.equal(w.logs.some((e) => e.event === 'oauth-approved'), false);
});

test('a setup whose answer is lost: the page says the setup may have finished, the next press says it did and how to get a recovery code, and the passkey just made approves', async (t) => {
  const w = await ownerWorld();
  const after = pages(t, w);
  const script = await pageScript(w);
  const credentials = softCredentials(w);
  const storage = softStorage();
  const setupHtml = (await send('GET', `${w.issuer}/oauth/owner`)).body;
  await runPage(w, script, { html: setupHtml, hash: `#${w.code}`, path: '/oauth/owner', credentials, storage, after });
  const d = await discover(w);
  const p = pkce();
  const html = (await ask(w, authorizeUrl(w, d, { pkce: p }))).body;
  let lost = true;
  const page = await runPage(w, script, { html, path: '/oauth/authorize', credentials, storage, after, lose: (to) => lost && to === SETUP_PATH });
  const submitter = { value: 'approve', textContent: 'Approve' };
  // The executor makes the owner; its answer, with the recovery code, never arrives.
  await page.form.fire('submit', { submitter, preventDefault: () => {} });
  assert.ok(state(w).owner, 'the owner was set up');
  assert.match(page.el['owner-status'].textContent, /^Not known: the executor's answer did not arrive \(Failed to fetch\)\. A passkey was made here, so the setup may have finished\. Press again to find out\.$/);
  assert.equal(page.el['owner-recovery'].hidden, true, 'no recovery code was seen');
  lost = false;
  // Pressed again: an owner exists. The words are of a setup that finished, not of someone else's.
  await page.form.fire('submit', { submitter, preventDefault: () => {} });
  const said = page.el['owner-status'].textContent;
  assert.match(said, /^An owner is already set up on this executor, so this setup link is of no more use\. If you made the passkey here a moment ago and saw no recovery code, the setup finished but its answer did not arrive: your passkey is the owner's and approves connections\. To get a recovery code, run "provared-mcp-executor owner --reset" on the server and set up again\./);
  assert.doesNotMatch(said, /^Not done/);
  assert.equal(credentials.made.length, 1, 'no second passkey was made');
  assert.equal(storage.getItem(STORE_CODE), null);
  // Pressed once more: the passkey just made is the owner's, and approves this connection as at any later approval.
  let prevented = false;
  await page.form.fire('submit', { submitter, preventDefault: () => (prevented = true) });
  assert.equal(prevented, true);
  assert.equal(credentials.asked.length, 1);
  assert.equal(page.form.submitted, submitter, page.el['owner-status'].textContent);
  await callsATool(w, await answer(w, page.form.elements.request.value, { fields: formFields(page) }), p);
  assert.ok(w.logs.some((e) => e.event === 'oauth-approved' && e.by === 'passkey'));
  // The same on the setup page, where the passkey is made alone: the executor's own words for a link that finds an owner.
  assert.deepEqual(await refusal(sender(w)(LINK_PATH, { code: w.code })), { status: 409, code: 'owner-exists' });
});

test('the setup link takes only a request that still waits: one that has ended is not offered, and is not shown again', async (t) => {
  const w = await ownerWorld();
  const after = pages(t, w);
  const script = await pageScript(w);
  const credentials = softCredentials(w);
  const storage = softStorage();
  const request = await waiting(w);
  storage.setItem(STORE_WAITING, request);
  assert.deepEqual(await sender(w)(LINK_PATH, { code: w.code, request }), { link: 'open', waiting: new URL(w.docs.client).host });
  // Ten minutes on (the link lasts fifteen): the request has ended.
  w.clock.offset += REQUEST_LIFE;
  assert.deepEqual(await sender(w)(LINK_PATH, { code: w.code, request }), { link: 'open' });
  assert.equal((await answer(w, request, { decision: 'show', fields: {} })).status, 400);
  const setupHtml = (await send('GET', `${w.issuer}/oauth/owner`)).body;
  const setup = await runPage(w, script, { html: setupHtml, hash: `#${w.code}`, path: '/oauth/owner', credentials, storage, after });
  assert.equal(setup.el['owner-review'].hidden, true);
  assert.equal(storage.getItem(STORE_WAITING), null, 'the ended request is not kept');
  // The link alone still makes the passkey, and says what to do next.
  assert.match(setupHtml, new RegExp(`<p id="owner-next" hidden>Next: add ${w.url} in ${new URL(w.docs.client).host}, and approve that connection with this passkey\\.</p>`));
  await setup.el['owner-setup'].fire('click');
  assert.equal(credentials.made.length, 1);
  assert.match(setup.el['owner-status'].textContent, /^The owner is set up\./);
  assert.match(setup.el['owner-recovery'].textContent, RECOVERY_SHOWN);
  assert.equal(setup.el['owner-next'].hidden, false);
  assert.equal(storage.getItem(STORE_CODE), null);
  assert.equal(w.logs.some((e) => e.event === 'oauth-approved'), false);
});

test('a later approval by the page\'s script as served: one prompt, which asks the owner\'s passkey with the user verified; a prompt that is closed sends nothing', async (t) => {
  const w = await ownerWorld();
  const after = pages(t, w);
  const script = await pageScript(w);
  const credentials = softCredentials(w);
  const storage = softStorage();
  const setupHtml = (await send('GET', `${w.issuer}/oauth/owner`)).body;
  const setup = await runPage(w, script, { html: setupHtml, hash: `#${w.code}`, path: '/oauth/owner', credentials, storage, after });
  // A prompt the person closes sets nothing up, and the link still works.
  credentials.refuse = true;
  await setup.el['owner-setup'].fire('click');
  assert.match(setup.el['owner-status'].textContent, /^Not done: /);
  assert.equal(state(w).owner, null);
  assert.equal(setup.el['owner-setup'].disabled, false);
  credentials.refuse = false;
  await setup.el['owner-setup'].fire('click');
  assert.ok(state(w).owner);

  const d = await discover(w);
  const p = pkce();
  const page = await runPage(w, script, { html: (await ask(w, authorizeUrl(w, d, { pkce: p }))).body, path: '/oauth/authorize', credentials, storage, after });
  assert.equal(page.el['owner-first'], undefined);
  const submitter = { value: 'approve' };
  credentials.refuse = true;
  await page.form.fire('submit', { submitter, preventDefault: () => {} });
  assert.match(page.el['owner-status'].textContent, /^Not done: /);
  assert.equal(page.form.submitted, null);
  credentials.refuse = false;
  let prevented = false;
  await page.form.fire('submit', { submitter, preventDefault: () => (prevented = true) });
  assert.equal(prevented, true, 'the form waits for the owner\'s proof');
  assert.deepEqual(credentials.asked.at(-1), { rpId: new URL(w.issuer).hostname, userVerification: 'required', credential: state(w).owner.credentialId });
  assert.equal(page.form.submitted, submitter, `the form is sent (${page.el['owner-status'].textContent})`);
  await callsATool(w, await answer(w, page.form.elements.request.value, { fields: formFields(page) }), p);
  // With a recovery code typed, the form goes as it is, and the passkey is not asked.
  const typed = await runPage(w, script, { html: (await ask(w, authorizeUrl(w, d, { pkce: pkce() }))).body, path: '/oauth/authorize', credentials, storage, after });
  typed.el['owner-recovery-code'].value = 'abcd';
  const asked = credentials.asked.length;
  let stopped = false;
  await typed.form.fire('submit', { submitter: { value: 'approve' }, preventDefault: () => (stopped = true) });
  assert.equal(stopped, false);
  assert.equal(credentials.asked.length, asked);
});

test('by the page\'s script as served, an approval is sent once: with a recovery code typed, Approve sends the form and is then disabled, and a second press sends nothing; the same for Continue on the page that follows, and for Approve after the passkey; once an approval is sent, Refuse sends nothing either', async (t) => {
  const w = await ownerWorld();
  const after = pages(t, w);
  const script = await pageScript(w);
  const credentials = softCredentials(w);
  const storage = softStorage();
  const setup = await runPage(w, script, { html: (await send('GET', `${w.issuer}/oauth/owner`)).body, hash: `#${w.code}`, path: '/oauth/owner', credentials, storage, after });
  await setup.el['owner-setup'].fire('click');
  const recoveryCode = setup.el['owner-recovery'].textContent;
  assert.match(recoveryCode, RECOVERY_SHOWN);
  const d = await discover(w);
  /** A press of a button of the page's form: whether the form went to the executor. */
  const press = async (page, submitter) => {
    let stopped = false;
    await page.form.fire('submit', { submitter, preventDefault: () => (stopped = true) });
    return !stopped;
  };
  const moment = () => new Promise((done) => setTimeout(done, 20));

  // Where no approval was sent, Refuse is a button like any other: it goes, and is not held to one press by itself.
  const other = await runPage(w, script, { html: (await ask(w, authorizeUrl(w, d, { pkce: pkce() }))).body, path: '/oauth/authorize', credentials, storage, after });
  assert.equal(await press(other, other.form.buttons.refuse), true, 'Refuse goes where nothing was sent');
  assert.equal(await press(other, other.form.buttons.refuse), true);

  // The recovery code typed: the form goes as it is, once.
  const p = pkce();
  const typed = await runPage(w, script, { html: (await ask(w, authorizeUrl(w, d, { pkce: p }))).body, path: '/oauth/authorize', credentials, storage, after });
  typed.el['owner-recovery-code'].value = recoveryCode;
  const { approve, refuse } = typed.form.buttons;
  assert.equal(await press(typed, approve), true, 'the first press sends the form');
  assert.equal(approve.disabled, false, 'not disabled yet: the browser has still to read the button\'s "decision" for the form');
  assert.equal(refuse.disabled, false);
  // Refuse pressed in that moment, before the buttons are disabled: nothing goes (X284).
  assert.equal(await press(typed, refuse), false, 'Refuse behind an approval sends nothing');
  await moment();
  assert.equal(approve.disabled, true, 'disabled after the first press');
  assert.equal(refuse.disabled, true, 'and Refuse with it: every submit button of the form');
  assert.equal(await press(typed, approve), false, 'a second press sends nothing');
  assert.equal(await press(typed, approve), false, 'nor a third');
  assert.equal(await press(typed, refuse), false, 'nor Refuse');
  assert.equal(credentials.asked.length, 0, 'the passkey was not asked');
  // What the one form sent: the executor spends the code and answers with the page that says so.
  const paused = await answer(w, typed.form.elements.request.value, { fields: { ...formFields(typed), [FIELD_RECOVERY]: recoveryCode } });
  assert.equal(paused.status, 200, paused.body);
  // That page's Continue: once, too.
  const spent = await runPage(w, script, { html: paused.body, path: '/oauth/authorize', credentials, storage, after });
  const go = spent.form.buttons.approve;
  assert.deepEqual(Object.keys(spent.form.buttons), ['approve'], 'one button, Continue');
  assert.equal(await press(spent, go), true);
  await moment();
  assert.equal(go.disabled, true);
  assert.equal(await press(spent, go), false, 'a second press of Continue sends nothing');
  // A page the browser shows again as it was left takes one more press; one it merely shows does not.
  spent.window.pageshow({ persisted: false });
  assert.equal(await press(spent, go), false);
  spent.window.pageshow({ persisted: true });
  assert.equal(go.disabled, false);
  assert.equal(await press(spent, go), true);
  await callsATool(w, await answer(w, spent.form.elements.request.value, { agent: spent.form.elements.agent.value, fields: {} }), p);

  // After the passkey: the script sends the form itself, which the browser tells the page of as it does a press; a press after that sends nothing.
  const p2 = pkce();
  const page = await runPage(w, script, { html: (await ask(w, authorizeUrl(w, d, { pkce: p2 }))).body, path: '/oauth/authorize', credentials, storage, after });
  assert.equal(page.el['owner-recovery-code'], undefined, 'no box for a code that is spent');
  const again = page.form.buttons.approve;
  assert.equal(await press(page, again), false, 'the form waits for the passkey');
  assert.equal(page.form.submitted, again, 'and is then sent by the script');
  assert.equal(await press(page, again), true, 'the sending itself');
  // Refuse behind an approval the passkey signed sends nothing either, in the moment before it is disabled and after (X284).
  assert.equal(await press(page, page.form.buttons.refuse), false);
  await moment();
  assert.equal(again.disabled, true);
  assert.equal(page.form.buttons.refuse.disabled, true);
  assert.equal(await press(page, again), false, 'a press after it sends nothing');
  assert.equal(await press(page, page.form.buttons.refuse), false);
  // A page the browser shows again as it was left takes a press of either button again.
  page.window.pageshow({ persisted: true });
  assert.equal(page.form.buttons.refuse.disabled, false);
  assert.equal(again.disabled, false);
  assert.equal(await press(page, page.form.buttons.refuse), true);
  await callsATool(w, await answer(w, page.form.elements.request.value, { fields: formFields(page) }), p2);
});

test('"Keep this connection" says so where it takes the place of a connection kept before', async (t) => {
  const w = await ownerWorld();
  const after = pages(t, w);
  const script = await pageScript(w);
  const credentials = softCredentials(w);
  const storage = softStorage();
  const d = await discover(w);
  const open = async () => {
    const asked = await ask(w, authorizeUrl(w, d, { pkce: pkce() }));
    return { request: asked.request, page: await runPage(w, script, { html: asked.body, path: '/oauth/authorize', credentials, storage, after }) };
  };
  const then = ' Now open the setup link here, within 10 minutes of this page opening: it shows this connection again.';
  // The first that is kept, and the same one kept again: nothing was replaced.
  const one = await open();
  await one.page.el['owner-keep'].fire('click');
  assert.equal(one.page.el['owner-status'].textContent, `Kept in this browser.${then}`);
  await one.page.el['owner-keep'].fire('click');
  assert.equal(one.page.el['owner-status'].textContent, `Kept in this browser.${then}`);
  // Another, kept after it: it takes the first one's place, and its page says so.
  const two = await open();
  assert.equal(storage.getItem(STORE_WAITING), one.request, 'opening a page keeps nothing');
  await two.page.el['owner-keep'].fire('click');
  assert.equal(two.page.el['owner-status'].textContent, `Kept in this browser, in place of another connection that was kept here before: only one is kept, and the setup link will show this one, not that one.${then}`);
  assert.equal(storage.getItem(STORE_WAITING), two.request);
});

test('refused at the authorisation page: a passkey used at another origin, for another relying party, without the user verified, to make and not to sign, by another key, or with a challenge used twice, expired, for another request or never given', async () => {
  const w = await ownerWorld();
  try {
    const { passkey } = await setUpOwner(w);
    const refused = async (request, fields, what) => {
      const a = await answer(w, request, { fields });
      assert.equal(a.status, 403, `${what}: ${a.body}`);
      assert.match(a.body, /did not pass/);
    };
    // What the passkey signs, changed in one part each time.
    const changes = {
      'another origin: the page was not the executor\'s': { origin: 'https://elsewhere.example' },
      'the page was inside another site\'s': { crossOrigin: true },
      'another relying party': { rpId: 'elsewhere.example' },
      'the user not verified': { flags: 0x01 },
      'no person present': { flags: 0x04 },
      'an answer to "make a passkey"': { type: 'webauthn.create' },
      'bytes after the authenticator data': { extra: new Uint8Array(4) },
      'a broken signature': { signature: (s) => s.map((b, i) => (i === s.length - 1 ? b ^ 1 : b)) },
    };
    for (const [what, change] of Object.entries(changes)) {
      const request = await waiting(w);
      passkey.change = change;
      await refused(request, await prove(w, passkey)(request), what);
    }
    passkey.change = {};
    // By another key: a passkey that is not the owner's, under the owner's identifier.
    let request = await waiting(w);
    const stranger = await softPasskey(w);
    stranger.credentialId = passkey.credentialId;
    await refused(request, await prove(w, stranger)(request), 'another key');
    // Expired: two minutes later.
    request = await waiting(w);
    const late = await prove(w, passkey)(request);
    w.clock.offset += CHALLENGE_LIFE;
    await refused(request, late, 'expired');
    // For another request: the first request's challenge and signature, sent with the second request.
    const first = await waiting(w);
    const second = await waiting(w);
    const forFirst = await prove(w, passkey)(first);
    await refused(second, fourOf(forFirst), 'another request\'s challenge');
    // And with the second request once it has a challenge of its own.
    const forSecond = await sender(w)(CHALLENGE_PATH, { request: second });
    await refused(second, { request: forSecond.request, ...fourOf(forFirst) }, 'another request\'s challenge, beside its own');
    // Never given: a challenge the executor did not make, and none at all.
    request = await waiting(w);
    const made = await prove(w, passkey)(request);
    await refused(request, { ...made, [FIELD_CHALLENGE]: randomBytes(32).toString('base64url') }, 'a challenge never given');
    request = await waiting(w);
    await refused(request, {}, 'nothing');
    // The request's seal: a request changed by one character, or one this executor never sealed, is not known, and gets no challenge.
    const changed = `${made.request.slice(0, -1)}${made.request.endsWith('A') ? 'B' : 'A'}`;
    assert.equal((await answer(w, changed, { fields: fourOf(made) })).status, 400);
    assert.deepEqual(await refusal(sender(w)(CHALLENGE_PATH, { request: changed })), { status: 400, code: 'bad-request' });
    assert.deepEqual(await refusal(sender(w)(CHALLENGE_PATH, { request: 'A'.repeat(43) })), { status: 400, code: 'bad-request' });

    // After all that, with no wait, the right answer passes: failed attempts are not counted (X211).
    request = await waiting(w);
    const right = await prove(w, passkey)(request);
    const a = await answer(w, request, { fields: right });
    assert.equal(a.status, 303);
    assert.ok(a.params.code);
    // A challenge passes once, and an approved request is answered once: the same form again gets no second code.
    const again = await answer(w, request, { fields: right });
    assert.equal(again.status, 400, again.body);
    assert.equal(again.headers.location, undefined);
  } finally {
    await w.close();
  }
});

test('a passkey\'s challenge gives its request no time of its own: asked with a minute left, its form sent just after the request\'s 10 minutes is refused, and nothing is approved (X283)', async () => {
  const w = await ownerWorld();
  try {
    const { passkey } = await setUpOwner(w);
    const request = await waiting(w);
    w.clock.offset += REQUEST_LIFE - 60 * 1000;
    const signed = await prove(w, passkey)(request);
    // The challenge has two minutes; the request, one minute and a second fewer.
    w.clock.offset += 61 * 1000;
    const approved = count(w, 'oauth-approved');
    const a = await answer(w, request, { fields: signed });
    assert.equal(a.status, 400, a.body);
    assert.equal(a.headers.location, undefined);
    assert.equal(count(w, 'oauth-approved'), approved);
  } finally {
    await w.close();
  }
});

/** What a page's form would send: the value of one of its hidden fields. */
const hidden = (body, name) => new RegExp(`<input type="hidden" name="${name}" value="([^"]+)">`).exec(body)?.[1];
/** The owner's answer by a recovery code: the page that says the code is spent, with what its Continue would send. {paused (the answer), request, agent, p (the client's PKCE), first (the request as the first page had it)}. */
async function typeRecovery(w, typed) {
  const p = pkce();
  const page = await ask(w, authorizeUrl(w, await discover(w), { pkce: p }));
  const paused = await answer(w, page.request, { fields: { [FIELD_RECOVERY]: typed } });
  return { paused, request: hidden(paused.body, 'request'), agent: hidden(paused.body, 'agent'), p, first: page.request };
}
/** Text as a page shows it: the executor writes these five characters as numbers. */
const shown = (text) => text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
/** Anything written as a recovery code is: eight groups of four, or 32 characters in a row. */
const ANY_CODE = /\b([A-Z2-7]{4}-){7}[A-Z2-7]{4}\b|\b[A-Z2-7]{32}\b/;
/** How many of the log's lines are of one event. */
const count = (w, event) => w.logs.filter((e) => e.event === event).length;

test('the recovery code approves one connection in the passkey\'s place and is then spent: no new code is made or shown; the page says it is spent and how a new one is to be had; another code is refused; it sets up no new passkey', async () => {
  const w = await ownerWorld();
  try {
    const { passkey, recoveryCode } = await setUpOwner(w);
    const before = state(w).owner;
    assert.equal(Object.hasOwn(before, 'recoverySpent'), false);
    // Another code, of the same form and of none; and a wrong code is not made right by the passkey's fields beside it. None of them spends anything, and none is told more than that the check did not pass.
    const other = recoveryCode.replace(/.$/, (c) => (c === 'A' ? 'B' : 'A'));
    for (const wrong of [other, other.replaceAll('-', ''), 'AAAA', '0', recoveryCode.slice(0, -1), `${recoveryCode}A`, before.recoveryHash]) {
      const request = await waiting(w);
      const refused = await answer(w, request, { fields: { [FIELD_RECOVERY]: wrong } });
      assert.equal(refused.status, 403, wrong);
      assert.ok(refused.body.includes('<p>The owner&#39;s check did not pass. Go back and try again.</p>'), wrong);
      assert.equal((await answer(w, request, { fields: { ...(await prove(w, passkey)(request)), [FIELD_RECOVERY]: wrong } })).status, 403, wrong);
    }
    assert.deepEqual(state(w).owner, before);
    assert.equal(count(w, 'owner-recovery-spent') + count(w, 'owner-recovery-refused'), 0);
    const asked = passkey.signed;
    // Wrong codes shut nothing (X211): the right one passes straight after, as a person types it, in small letters with spaces for the hyphens. Nothing is approved yet: the code is spent, and a page says so, with Continue.
    const one = await typeRecovery(w, ` ${recoveryCode.toLowerCase().replaceAll('-', ' ')} `);
    assert.equal(one.paused.status, 200, one.paused.body);
    assert.equal(one.agent, 'conn');
    assert.equal(count(w, 'oauth-approved'), 0, 'not approved until the owner continues');
    assert.equal(count(w, 'owner-recovery-spent'), 1);
    // The page's text after the use: the code is spent, none takes its place, and the command that makes a new owner, as the command's own help writes it.
    assert.ok(one.paused.body.includes('<h1>The recovery code is spent</h1>'));
    assert.ok(one.paused.body.includes('<p id="owner-spent">The recovery code you typed is spent. It is good for this one connection, which Continue approves, and for nothing after it. No new code takes its place.</p>'));
    assert.ok(one.paused.body.includes('<p>To have a recovery code again, stop the executor and run this on the server:</p>\n<pre id="owner-reset">provared-mcp-executor owner --config &#60;settings&#62; --reset</pre>'));
    assert.ok(one.paused.body.includes('It removes the owner and ends every connection, and prints a setup link.'));
    assert.ok(one.paused.body.includes(`<p id="owner-continue">You have 5 minutes to press Continue, once: the connection is approved when you do, and the browser goes back to ${new URL(w.docs.client).host}. If the time runs out first, nothing is approved, and the code is spent all the same.</p>`), one.paused.body);
    assert.match(one.paused.body, /<button type="submit" name="decision" value="approve">Continue<\/button>/);
    const help = spawnSync(process.execPath, [BIN, '--help'], { encoding: 'utf8' }).stdout;
    assert.ok(help.split('\n').some((line) => line.trim().replace(/\s+/g, ' ').replace('[--reset]', '--reset') === RESET_COMMAND), 'the command is the one the help gives');
    // No new code: none on the page, none in the file, and the hash on file is the one it was.
    assert.doesNotMatch(one.paused.body, ANY_CODE);
    assert.equal(one.paused.body.includes('id="owner-recovery"'), false);
    assert.deepEqual(state(w).owner, { ...before, recoverySpent: true }, 'the owner is as it was, with the code marked as spent');
    assert.doesNotMatch(readFileSync(w.statePath, 'utf8'), ANY_CODE);
    // The page runs the executor's own script and no other, so that Continue is pressed once; it holds no secret.
    assert.match(one.paused.headers['content-security-policy'], /^default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self' https:\/\/client\.example; frame-ancestors 'none'; base-uri 'none'$/);
    assert.deepEqual([...one.paused.body.matchAll(/<script[^>]*>/g)].map((m) => m[0]), ['<script type="module" src="/oauth/owner/page.js">']);
    // The request as the first page had it is not approved by this: only the one on the page that says the code is spent.
    assert.equal((await answer(w, one.first, { fields: {} })).status, 403);
    // Continue: the connection is made, and the log says by which proof.
    await callsATool(w, await answer(w, one.request, { agent: one.agent, fields: {} }), one.p);
    assert.ok(w.logs.some((e) => e.event === 'oauth-approved' && e.by === 'recovery'));
    assert.equal((await answer(w, one.request, { agent: one.agent, fields: {} })).status, 400, 'approved once');
    assert.equal(passkey.signed, asked, 'the passkey was not asked');
    // It approves; it does not set up: the owner's passkey stays as it was.
    assert.deepEqual(await refusal(sender(w)(SETUP_PATH, { code: recoveryCode, credentialId: 'AAAA', key: (await softPasskey(w)).key })), { status: 409, code: 'owner-exists' });
    assert.equal(state(w).owner.credentialId, before.credentialId);
    assert.deepEqual(state(w).owner.key, before.key);
  } finally {
    await w.close();
  }
});

test('a recovery code that was used approves nothing more: typed again it is told that it was already used, by whoever types it, in any request and after a restart; the page then has no box for it; the passkey still approves', async () => {
  const w = await ownerWorld();
  try {
    const { passkey, recoveryCode } = await setUpOwner(w);
    const one = await typeRecovery(w, recoveryCode);
    await callsATool(w, await answer(w, one.request, { agent: one.agent, fields: {} }), one.p);
    const spent = state(w).owner;
    // The second use, in a new request: refused, in words that say why and what to do.
    const used = (r) => {
      assert.equal(r.status, 403, r.body);
      assert.ok(r.body.includes('<h1>The connection cannot be made</h1>'));
      assert.ok(r.body.includes(`<p>${shown(RECOVERY_USED)}</p>`), r.body);
      assert.equal(r.headers.location, undefined);
      assert.doesNotMatch(r.body, ANY_CODE);
    };
    assert.match(RECOVERY_USED, /^This recovery code was already used, and is spent: a code approves one connection\. Nothing was approved by this\./);
    assert.ok(RECOVERY_USED.includes(`running "${RESET_COMMAND}" on the server, which removes the owner and ends every connection.`));
    const two = await typeRecovery(w, recoveryCode);
    used(two.paused);
    assert.equal(two.request, undefined, 'no page with a Continue');
    // The same in the form a person types, and beside a passkey's fields that would pass by themselves: a spent code typed is refused, not passed over.
    used((await typeRecovery(w, recoveryCode.toLowerCase().replaceAll('-', ' '))).paused);
    const request = await waiting(w);
    used(await answer(w, request, { fields: { ...(await prove(w, passkey)(request)), [FIELD_RECOVERY]: recoveryCode } }));
    assert.equal(count(w, 'owner-recovery-spent'), 1, 'spent once');
    assert.equal(count(w, 'owner-recovery-refused'), 3, 'and each later use is in the log');
    assert.ok(w.logs.some((e) => e.event === 'owner-recovery-refused' && e.code === 'spent'));
    assert.equal(count(w, 'oauth-approved'), 1, 'one approval from the code, and no more');
    assert.deepEqual(state(w).owner, spent, 'a later use changes nothing');
    // A wrong code is still told only that the check did not pass.
    assert.ok((await typeRecovery(w, 'AAAA')).paused.body.includes('The owner&#39;s check did not pass.'));
    // After a restart the code is still spent: the file says so.
    await reopen(w);
    used((await typeRecovery(w, recoveryCode)).paused);
    assert.equal(count(w, 'oauth-approved'), 0);
    // Every authorisation page now says that the code is spent, with the same command, and has no box for one.
    const page = await ask(w, authorizeUrl(w, await discover(w), { pkce: pkce() }));
    assert.ok(page.body.includes(`<p id="owner-recovery-spent">Approve asks for the owner's passkey. This executor's recovery code has been used and is spent, so there is none to type. If you did not use it, someone else did: reset the owner. A new code comes from stopping the executor and running "${shown(RESET_COMMAND)}" on the server, which removes the owner and ends every connection.</p>`), page.body);
    assert.equal(page.body.includes(`name="${FIELD_RECOVERY}"`), false);
    // The passkey approves as before.
    const { access } = await connect(w, { prove: prove(w, passkey) });
    assert.equal((await call(w, bearer(access), 'echo', {})).status, 200);
    assert.ok(w.logs.some((e) => e.event === 'oauth-approved' && e.by === 'passkey'));
  } finally {
    await w.close();
  }
});

test('the same recovery code in several answers at once approves one connection at most: one answer spends it, and each of the others is told it was already used', async () => {
  const w = await ownerWorld();
  try {
    const { recoveryCode } = await setUpOwner(w);
    const d = await discover(w);
    // Two presses on one page, and two more pages open beside it: four answers with the one code, sent together.
    const open = [];
    for (let i = 0; i < 3; i += 1) open.push({ p: pkce() });
    for (const page of open) page.request = (await ask(w, authorizeUrl(w, d, { pkce: page.p }))).request;
    const sent = [open[0], open[0], open[1], open[2]];
    const answers = await Promise.all(sent.map((page) => answer(w, page.request, { fields: { [FIELD_RECOVERY]: recoveryCode } })));
    assert.deepEqual(answers.map((r) => r.status).sort(), [200, 403, 403, 403]);
    for (const r of answers.filter((a) => a.status === 403)) assert.ok(r.body.includes(`<p>${shown(RECOVERY_USED)}</p>`), r.body);
    assert.equal(count(w, 'owner-recovery-spent'), 1);
    assert.equal(count(w, 'owner-recovery-refused'), 3);
    assert.equal(count(w, 'oauth-approved'), 0);
    // The one page with a Continue approves its own connection, once; none of the requests as the first pages had them is approved.
    const i = answers.findIndex((r) => r.status === 200);
    const body = answers[i].body;
    for (const page of open) assert.equal((await answer(w, page.request, { fields: {} })).status, 403);
    const both = await Promise.all([1, 2].map(() => answer(w, hidden(body, 'request'), { agent: hidden(body, 'agent'), fields: {} })));
    assert.deepEqual(both.map((r) => r.status).sort(), [303, 400], 'Continue sent twice at once approves once');
    await callsATool(w, both.find((r) => r.status === 303), sent[i].p);
    assert.equal(count(w, 'oauth-approved'), 1, 'one connection, from four answers');
    assert.equal(state(w).grants.length, 1);
  } finally {
    await w.close();
  }
});

test('a recovery code whose request has ended is not spent; a page whose Continue is not pressed in time approves nothing, and the code is spent all the same; a reset of the owner gives a new code', async () => {
  const w = await ownerWorld();
  try {
    const { recoveryCode } = await setUpOwner(w);
    const before = state(w).owner;
    // The request ended before the code was sent: the front door answers, the check is not asked, nothing is spent.
    const late = await waiting(w);
    w.clock.offset += REQUEST_LIFE;
    assert.equal((await answer(w, late, { fields: { [FIELD_RECOVERY]: recoveryCode } })).status, 400);
    // Refuse, show, an agent that is not for connections and another origin spend nothing either.
    const request = await waiting(w);
    assert.equal((await answer(w, request, { decision: 'refuse', fields: { [FIELD_RECOVERY]: recoveryCode } })).status, 303);
    assert.equal((await answer(w, request, { decision: 'show', fields: { [FIELD_RECOVERY]: recoveryCode } })).status, 200);
    assert.equal((await answer(w, request, { agent: 'alpha', fields: { [FIELD_RECOVERY]: recoveryCode } })).status, 400);
    assert.equal((await answer(w, request, { origin: 'https://other.example', fields: { [FIELD_RECOVERY]: recoveryCode } })).status, 403);
    assert.deepEqual(state(w).owner, before);
    assert.equal(count(w, 'owner-recovery-spent'), 0);
    // Spent, and Continue not pressed within the request's 10 minutes: nothing is approved.
    const last = await typeRecovery(w, recoveryCode);
    assert.equal(last.paused.status, 200);
    w.clock.offset += REQUEST_LIFE;
    assert.equal((await answer(w, last.request, { agent: last.agent, fields: {} })).status, 400);
    assert.equal(count(w, 'oauth-approved'), 0);
    assert.equal(state(w).owner.recoverySpent, true);
    await w.executor.close();
    w.executor = null;
    // The state file says that a code is spent by "recoverySpent": true, and in no other way: a file that says anything else there is not read.
    const text = readFileSync(w.statePath, 'utf8');
    for (const other of [false, 1, 'true', null]) {
      writeFileSync(w.statePath, JSON.stringify({ ...JSON.parse(text), owner: { ...JSON.parse(text).owner, recoverySpent: other } }));
      await assert.rejects(reopen(w), /oauth\.state: the file is not in the form the executor writes\./, String(other));
    }
    writeFileSync(w.statePath, text);
    // "owner --reset", as the command works, on the files of a stopped executor: a new owner, with a new code that works once.
    const reset = makeOwnerSetup(w.parsed, { reset: true, now: w.more.now });
    assert.equal(state(w).owner, null);
    await reopen(w);
    w.code = new URL(reset.link).hash.slice(1);
    const again = await setUpOwner(w);
    assert.match(again.recoveryCode, RECOVERY_SHOWN);
    assert.notEqual(again.recoveryCode, recoveryCode);
    assert.equal(Object.hasOwn(state(w).owner, 'recoverySpent'), false);
    assert.equal((await typeRecovery(w, recoveryCode)).paused.status, 403, 'the old code is nothing to the new owner');
    const fresh = await typeRecovery(w, again.recoveryCode);
    assert.equal(fresh.paused.status, 200, fresh.paused.body);
    await callsATool(w, await answer(w, fresh.request, { agent: fresh.agent, fields: {} }), fresh.p);
  } finally {
    await w.close();
  }
});

test('a recovery code typed late on its page is not spent for nothing: the page that says it is spent has five minutes of its own for Continue, and says so; a code typed early keeps the time its page had; the request is still answered once', async () => {
  assert.equal(CONTINUE_LIFE, 5 * 60 * 1000);
  // Typed one second before the first page's 10 minutes end, and Continue pressed after them: approved.
  {
    const w = await ownerWorld();
    try {
      const { recoveryCode } = await setUpOwner(w);
      const p = pkce();
      const page = await ask(w, authorizeUrl(w, await discover(w), { pkce: p }));
      w.clock.offset += REQUEST_LIFE - 1000;
      const paused = await answer(w, page.request, { fields: { [FIELD_RECOVERY]: recoveryCode } });
      assert.equal(paused.status, 200, paused.body);
      assert.ok(paused.body.includes('<p id="owner-continue">You have 5 minutes to press Continue, once:'), paused.body);
      w.clock.offset += 2000;
      assert.equal((await answer(w, page.request, { fields: {} })).status, 400, 'the first page has ended');
      await callsATool(w, await answer(w, hidden(paused.body, 'request'), { agent: hidden(paused.body, 'agent'), fields: {} }), p);
      assert.equal(count(w, 'oauth-approved'), 1);
    } finally {
      await w.close();
    }
  }
  // The five minutes end: Continue pressed after them approves nothing, and the code is spent.
  {
    const w = await ownerWorld();
    try {
      const { recoveryCode } = await setUpOwner(w);
      const page = await ask(w, authorizeUrl(w, await discover(w), { pkce: pkce() }));
      w.clock.offset += REQUEST_LIFE - 1000;
      const paused = await answer(w, page.request, { fields: { [FIELD_RECOVERY]: recoveryCode } });
      assert.equal(paused.status, 200, paused.body);
      w.clock.offset += CONTINUE_LIFE;
      assert.equal((await answer(w, hidden(paused.body, 'request'), { agent: hidden(paused.body, 'agent'), fields: {} })).status, 400);
      assert.equal(count(w, 'oauth-approved'), 0);
      assert.equal(state(w).owner.recoverySpent, true);
    } finally {
      await w.close();
    }
  }
  // Typed at once, on a page with more than five minutes left: the page keeps the time it had, and is not cut to five minutes.
  {
    const w = await ownerWorld();
    try {
      const { recoveryCode } = await setUpOwner(w);
      const one = await typeRecovery(w, recoveryCode);
      w.clock.offset += REQUEST_LIFE - 1000;
      await callsATool(w, await answer(w, one.request, { agent: one.agent, fields: {} }), one.p);
    } finally {
      await w.close();
    }
  }
  // One request, one answer: a request the passkey approved is not approved again by the Continue of a page that outlives the first page's 10 minutes.
  {
    const w = await ownerWorld();
    try {
      const { passkey, recoveryCode } = await setUpOwner(w);
      const p = pkce();
      const page = await ask(w, authorizeUrl(w, await discover(w), { pkce: p }));
      w.clock.offset += REQUEST_LIFE - 60 * 1000;
      const paused = await answer(w, page.request, { fields: { [FIELD_RECOVERY]: recoveryCode } });
      assert.equal(paused.status, 200, paused.body);
      // In another tab, the same request is approved by the passkey.
      await callsATool(w, await answer(w, page.request, { fields: await prove(w, passkey)(page.request) }), p);
      // The first page's 10 minutes are over; the page with Continue has three minutes left.
      w.clock.offset += 2 * 60 * 1000;
      assert.equal((await answer(w, hidden(paused.body, 'request'), { agent: hidden(paused.body, 'agent'), fields: {} })).status, 400, 'answered once');
      assert.equal(count(w, 'oauth-approved'), 1);
      assert.equal(state(w).grants.length, 1);
    } finally {
      await w.close();
    }
  }
});

test('a log that throws at the line that says the code is spent does not turn the spent code into a plain refusal: the page with Continue follows, and Continue approves', async () => {
  const w = await ownerWorld();
  try {
    const { recoveryCode } = await setUpOwner(w);
    // A program that opens the executor as a library gives it a log of its own; this one fails at that one line.
    let thrown = 0;
    w.more.log = (e) => {
      if (e.event === 'owner-recovery-spent') {
        thrown += 1;
        throw new Error('the log could not be written');
      }
      w.logs.push(e);
    };
    await reopen(w);
    const one = await typeRecovery(w, recoveryCode);
    assert.equal(thrown, 1, 'the log was asked, and threw');
    assert.equal(state(w).owner.recoverySpent, true);
    assert.equal(one.paused.status, 200, one.paused.body);
    assert.ok(one.paused.body.includes('<h1>The recovery code is spent</h1>'));
    assert.match(one.paused.body, /<button type="submit" name="decision" value="approve">Continue<\/button>/);
    await callsATool(w, await answer(w, one.request, { agent: one.agent, fields: {} }), one.p);
    assert.ok(w.logs.some((e) => e.event === 'oauth-approved' && e.by === 'recovery'));
  } finally {
    await w.close();
  }
});

test('a log that throws at the line of the approval does not leave the code spent and nothing approved: Continue sends the browser back with its code, and the connection calls a tool', async () => {
  const w = await ownerWorld();
  try {
    const { recoveryCode } = await setUpOwner(w);
    let thrown = 0;
    w.more.log = (e) => {
      if (e.event === 'oauth-approved') {
        thrown += 1;
        throw new Error('the log could not be written');
      }
      w.logs.push(e);
    };
    await reopen(w);
    const one = await typeRecovery(w, recoveryCode);
    assert.equal(state(w).owner.recoverySpent, true);
    assert.equal(one.paused.status, 200, one.paused.body);
    await callsATool(w, await answer(w, one.request, { agent: one.agent, fields: {} }), one.p);
    assert.equal(thrown, 1, 'the log was asked, and threw');
  } finally {
    await w.close();
  }
});

test('a recovery code is 20 random bytes in base32, as RFC 4648 writes it: the standard\'s own examples, and two codes are never the same', async () => {
  // RFC 4648, section 10, without the padding.
  for (const [text, written] of [['', ''], ['f', 'MY'], ['fo', 'MZXQ'], ['foo', 'MZXW6'], ['foob', 'MZXW6YQ'], ['fooba', 'MZXW6YTB'], ['foobar', 'MZXW6YTBOI']]) assert.equal(base32(Buffer.from(text)), written);
  assert.equal(base32(new Uint8Array(RECOVERY_BYTES).fill(255)), '7'.repeat(32));
  assert.equal(RECOVERY_BYTES, 20);
  const codes = new Set();
  for (let i = 0; i < 3; i += 1) {
    const w = await ownerWorld();
    try {
      codes.add((await setUpOwner(w)).recoveryCode);
    } finally {
      await w.close();
    }
  }
  assert.equal(codes.size, 3);
});

test('the library\'s passkey checks are found where the executor looks for them, and a library without them stops the start with its reason', async () => {
  const real = fileURLToPath(new URL('../../src/', import.meta.url));
  const found = await passkeyChecks(real);
  assert.equal(typeof found.checkAssertion, 'function');
  assert.equal(typeof found.checkKey, 'function');
  assert.deepEqual(found.PASSKEY_METHODS, ['ES256', 'RS256', 'Ed25519']);
  // A library whose files are not there, and one whose files no longer hold the names.
  const reason = /the "provared" library at .* does not have the passkey checks this version was built with \(checkAssertion in webauthn\.js; checkKey and PASSKEY_METHODS in keys\.js\)\. Install the version of "provared" that this package's package\.json names\. Nothing was started\./;
  const empty = mkdtempSync(join(tmpdir(), 'provared-no-library-'));
  await assert.rejects(passkeyChecks(empty), reason);
  const other = mkdtempSync(join(tmpdir(), 'provared-other-library-'));
  writeFileSync(join(other, 'package.json'), '{"type":"module"}');
  writeFileSync(join(other, 'webauthn.js'), 'export const checkPasskey = () => "valid";\n');
  writeFileSync(join(other, 'keys.js'), 'export const PASSKEY_METHODS = ["ES256"];\nexport function checkKey() {}\n');
  await assert.rejects(passkeyChecks(other), reason);
  // The error is marked, so that the command knows it from any other and prints its message alone.
  await assert.rejects(passkeyChecks(other), { code: LIBRARY_PROBLEM });
  assert.equal(LIBRARY_PROBLEM, 'ERR_PROVARED_LIBRARY');
  // The package names one exact version of the library: the one these checks were read in.
  const named = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).dependencies;
  assert.deepEqual(named, { provared: '0.7.0' });
  const locked = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8')).packages;
  assert.equal(locked[''].dependencies.provared, '0.7.0');
  assert.equal(locked['node_modules/provared'].version, '0.7.0');
});

test('installed beside a library without the passkey checks, every command prints the executor\'s own message, and nothing round it, and ends with 1', () => {
  const here = fileURLToPath(new URL('../', import.meta.url));
  const manifest = JSON.parse(readFileSync(join(here, 'package.json'), 'utf8'));
  // The package as npm lays it out: its own files, and the library in its node_modules. The library is this repository's.
  const root = mkdtempSync(join(tmpdir(), 'provared-installed-'));
  const executor = join(root, 'provared-mcp-executor');
  for (const f of ['package.json', ...manifest.files.filter((x) => x.endsWith('.mjs') || x.endsWith('.json'))]) {
    mkdirSync(dirname(join(executor, f)), { recursive: true });
    copyFileSync(join(here, f), join(executor, f));
  }
  const library = join(executor, 'node_modules', 'provared');
  mkdirSync(library, { recursive: true });
  copyFileSync(join(here, '..', 'package.json'), join(library, 'package.json'));
  cpSync(join(here, '..', 'src'), join(library, 'src'), { recursive: true });
  // The command finds the library as Node.js finds it, not by the tests' own way to it (local-library.mjs).
  const run = (...args) => spawnSync(process.execPath, [join(executor, 'bin.mjs'), ...args], { encoding: 'utf8', cwd: root, env: { ...process.env, NODE_OPTIONS: '' } });
  // With the library whole, the command runs.
  const whole = run('--version');
  assert.equal(whole.status, 0, whole.stderr);
  assert.equal(whole.stdout, `provared-mcp-executor ${manifest.version}\n`);
  // The check of a passkey's signature under another name, throughout the library: it loads, and has no checkAssertion.
  for (const f of readdirSync(join(library, 'src')).filter((x) => x.endsWith('.js'))) {
    const text = readFileSync(join(library, 'src', f), 'utf8');
    if (text.includes('checkAssertion')) writeFileSync(join(library, 'src', f), text.replaceAll('checkAssertion', 'checkSignedByPasskey'));
  }
  const message = /^provared-mcp-executor: the "provared" library at [^\n]+ does not have the passkey checks this version was built with \(checkAssertion in webauthn\.js; checkKey and PASSKEY_METHODS in keys\.js\)\. Install the version of "provared" that this package's package\.json names\. Nothing was started\.\n$/;
  for (const args of [['--version'], ['--help'], [], ['secret'], ['stdio', '--config', 'none.json'], ['http', '--config', 'none.json'], ['owner', '--config', 'none.json']]) {
    const r = run(...args);
    const said = `"${args.join(' ')}": ${r.stderr}`;
    assert.equal(r.status, 1, said);
    assert.equal(r.stdout, '', said);
    // One line: no stack, no source line, no "Node.js v…" under it.
    assert.match(r.stderr, message, said);
  }
});

test('the setup link: used twice, expired, the wrong code, or not from the executor\'s page, it is refused', async () => {
  const w = await ownerWorld();
  try {
    // Not from the executor's own page: no Origin, or another.
    assert.deepEqual(await refusal(setUp({ passkey: await softPasskey(w), code: w.code, send: sender(w, null) })), { status: 403, code: 'origin-refused' });
    assert.deepEqual(await refusal(setUp({ passkey: await softPasskey(w), code: w.code, send: sender(w, 'https://elsewhere.example') })), { status: 403, code: 'origin-refused' });
    // The wrong code: at the page's first question, and at the message itself.
    const wrong = randomBytes(32).toString('base64url');
    const unmade = await softPasskey(w);
    assert.deepEqual(await refusal(setUp({ passkey: unmade, code: wrong, send: sender(w) })), { status: 403, code: 'setup-refused' });
    assert.equal(unmade.made, 0, 'no passkey was made');
    assert.deepEqual(await refusal(sender(w)(SETUP_PATH, { code: wrong, credentialId: unmade.credentialId, key: unmade.key })), { status: 403, code: 'setup-refused' });
    assert.equal(state(w).owner, null);
    // Used twice: the second is refused before a passkey is made, and the owner is the first.
    await setUpOwner(w);
    const owner = state(w).owner;
    const second = await softPasskey(w);
    assert.deepEqual(await refusal(setUp({ passkey: second, code: w.code, send: sender(w) })), { status: 409, code: 'owner-exists' });
    assert.equal(second.made, 0, 'no passkey was made');
    assert.deepEqual(await refusal(sender(w)(SETUP_PATH, { code: w.code, credentialId: second.credentialId, key: second.key })), { status: 409, code: 'owner-exists' });
    assert.deepEqual(state(w).owner, owner);
  } finally {
    await w.close();
  }
  // Expired: 15 minutes after the command.
  const late = await ownerWorld();
  try {
    late.clock.offset += SETUP_LIFE;
    const passkey = await softPasskey(late);
    assert.deepEqual(await refusal(setUp({ passkey, code: late.code, send: sender(late) })), { status: 403, code: 'setup-ended' });
    assert.equal(passkey.made, 0, 'no passkey was made');
    // The message itself is refused too, without the page's first question.
    assert.deepEqual(await refusal(sender(late)(SETUP_PATH, { code: late.code, credentialId: passkey.credentialId, key: passkey.key })), { status: 403, code: 'setup-ended' });
    assert.equal(state(late).owner, null);
  } finally {
    await late.close();
  }
});

test('a second setup while an owner exists is refused, unless the owner is reset, which ends every connection with its tokens', async () => {
  const w = await ownerWorld();
  try {
    const { passkey } = await setUpOwner(w);
    const { access } = await connect(w, { prove: prove(w, passkey) });
    assert.equal((await call(w, bearer(access), 'echo', {})).status, 200);
    // As the command works: on the files of a stopped executor.
    await w.executor.close();
    w.executor = null;
    const before = readFileSync(w.statePath, 'utf8');
    assert.throws(() => makeOwnerSetup(w.parsed, { now: w.more.now }), /already set up/);
    assert.equal(readFileSync(w.statePath, 'utf8'), before, 'nothing changed');
    const reset = makeOwnerSetup(w.parsed, { reset: true, now: w.more.now });
    assert.equal(reset.revoked, 1);
    assert.equal(state(w).owner, null);
    assert.deepEqual(state(w).grants, []);
    await reopen(w);
    assert.equal((await call(w, bearer(access), 'echo', {})).status, 401, 'the token was revoked');
    // The old passkey is no longer the owner's; a new setup, with the new link, is.
    const request = await waiting(w);
    assert.deepEqual(await refusal(sender(w)(CHALLENGE_PATH, { request })), { status: 409, code: 'no-owner' });
    w.code = new URL(reset.link).hash.slice(1);
    const again = await setUpOwner(w);
    const { access: fresh } = await connect(w, { prove: prove(w, again.passkey) });
    assert.equal((await call(w, bearer(fresh), 'echo', {})).status, 200);
  } finally {
    await w.close();
  }
});

test('a setup whose passkey is missing or malformed is refused, and the link still works after', async () => {
  const w = await ownerWorld();
  try {
    const passkey = await softPasskey(w);
    const rsa = await softPasskey(w, 'RS256');
    const right = () => ({ code: w.code, credentialId: passkey.credentialId, key: { ...passkey.key } });
    const wrong = {
      'no public key': (v) => delete v.key,
      'no identifier': (v) => delete v.credentialId,
      'an empty identifier': (v) => (v.credentialId = ''),
      'an identifier of 1,024 bytes': (v) => (v.credentialId = randomBytes(1024).toString('base64url')),
      'base64 with padding': (v) => (v.credentialId += '='),
      'a key as text': (v) => (v.key = JSON.stringify(v.key)),
      'a key with a private part': (v) => (v.key.d = v.key.x),
      'a key with no method': (v) => delete v.key.alg,
      'a method a passkey does not sign with': (v) => (v.key = { alg: 'ML-DSA-87', kty: 'AKP', pub: randomBytes(2592).toString('base64url') }),
      'a point that is not on the curve': (v) => (v.key.y = v.key.x),
      'an RSA key of 1,024 bits': (v) => (v.key = { ...rsa.key, n: randomBytes(128).toString('base64url') }),
      'a member the page does not send': (v) => (v.transports = ['internal']),
      'a request that is not text': (v) => (v.request = 1),
    };
    for (const [what, change] of Object.entries(wrong)) {
      const v = right();
      change(v);
      assert.deepEqual(await refusal(sender(w)(SETUP_PATH, v)), { status: 400, code: 'bad-request' }, what);
    }
    assert.deepEqual(await refusal(sender(w)(SETUP_PATH, '{not json')), { status: 400, code: 'bad-request' });
    assert.deepEqual(await refusal(sender(w)(LINK_PATH, { code: w.code, request: 1 })), { status: 400, code: 'bad-request' });
    assert.equal(state(w).owner, null);
    const done = await sender(w)(SETUP_PATH, right());
    assert.deepEqual(Object.keys(done).sort(), ['owner', 'recoveryCode']);
    assert.deepEqual(state(w).owner.key, passkey.key);
    // A state file whose owner is not in the executor's form stops the start.
    await w.executor.close();
    w.executor = null;
    const s = state(w);
    s.owner.key.x = 'x';
    writeFileSync(w.statePath, JSON.stringify(s));
    await assert.rejects(reopen(w), /not in the form the executor writes/);
  } finally {
    await w.close();
  }
});

test('a state file whose owner is in the form of the builds before the plain passkey stops the start, and says to reset the owner; the reset then works', async () => {
  const w = await ownerWorld();
  try {
    const { passkey } = await setUpOwner(w);
    await connect(w, { prove: prove(w, passkey) });
    await w.executor.close();
    w.executor = null;
    // The earlier form: a public key for signatures made in the browser, and two locked copies of the key behind it.
    const b = (n) => randomBytes(n).toString('base64url');
    const s = state(w);
    s.owner = { routingPublicKey: b(32), passkey: { credentialId: b(16), prfSalt: b(32), wrappedRootKey: b(60), transports: ['internal'] }, recovery: { salt: b(16), lookupHash: randomBytes(32).toString('hex'), wrappedRootKey: b(60) }, created: 1 };
    writeFileSync(w.statePath, JSON.stringify(s));
    await assert.rejects(reopen(w), /holds an owner in an earlier form.*owner --config <settings> --reset/);
    assert.throws(() => makeOwnerSetup(w.parsed, { now: w.more.now }), /holds an owner in an earlier form.*--reset/);
    assert.deepEqual(state(w), s, 'nothing changed');
    const reset = makeOwnerSetup(w.parsed, { reset: true, now: w.more.now });
    assert.equal(reset.revoked, 1);
    assert.equal(state(w).owner, null);
    await reopen(w);
    w.code = new URL(reset.link).hash.slice(1);
    await connect(w, { prove: prove(w, (await setUpOwner(w)).passkey) });
  } finally {
    await w.close();
  }
});

test('the command "owner": a link on a stopped executor; refused while it runs; refused where an owner exists, unless --reset', async () => {
  const w = await ownerWorld();
  try {
    const settingsFile = join(w.folder, 'executor-http.json');
    writeFileSync(settingsFile, JSON.stringify(w.settings));
    const owner = (...more) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', BIN, 'owner', '--config', settingsFile, ...more], { encoding: 'utf8', windowsHide: true, timeout: 60000 });
    // While the executor runs, its files are its own.
    const running = owner();
    assert.equal(running.status, 2, running.stderr);
    assert.doesNotMatch(running.stdout, /oauth\/owner#/);
    await w.executor.close();
    w.executor = null;
    const made = owner();
    assert.equal(made.status, 0, made.stderr);
    const link = /(http:\/\/127\.0\.0\.1:\d+\/oauth\/owner#[A-Za-z0-9_-]{43})/.exec(made.stdout)?.[1];
    assert.ok(link, made.stdout);
    await reopen(w);
    w.code = new URL(link).hash.slice(1);
    await setUpOwner(w);
    await w.executor.close();
    w.executor = null;
    const second = owner();
    assert.equal(second.status, 2);
    assert.match(second.stderr, /already set up/);
    assert.match(owner('--reset').stdout, /The owner was removed/);
    assert.equal(state(w).owner, null);
    assert.equal(owner('--again').status, 2, 'an unknown option does nothing');
  } finally {
    await w.close();
  }
});

test('one program holds a state file: a second executor whose settings name the same state file, with agents and books of its own, does not start, and is told why; nor does the command "owner" work on it; a command on the second one\'s own books is not stopped; once the first has closed, the second starts', async () => {
  const a = await ownerWorld();
  // The second executor: its own folder, agents, books and port; the first one's issuer, client list and state file.
  const b = await oauthWorld({ open: false });
  let second = null;
  try {
    await setUpOwner(a);
    b.settings.oauth = { issuer: a.issuer, clients: [a.docs.client], state: a.statePath };
    const open = (more = {}) => openHttpExecutor(b.settings, { root: b.folder, log: () => {}, now: a.more.now, ...more });
    /** What the second one's folder holds: each name, with a file's size. */
    const files = () => readdirSync(b.folder, { recursive: true }).map(String).sort().map((name) => {
      const s = statSync(join(b.folder, name));
      return [name, s.isDirectory() ? 'folder' : s.size];
    });
    const before = { state: readFileSync(a.statePath, 'utf8'), files: files() };
    await assert.rejects(open(), (e) => {
      assert.equal(e.code, 'LOCKED', e.message);
      assert.equal(e.message, `An executor is running on the state file ${a.statePath} (oauth.state), or the command "owner" is at work on it. One program holds a state file at a time: stop the other first, or wait for the command to end. Two executors need a state file each: name another in this one's settings ("oauth", "state"). Neither the state file nor any agent's files were read or written.`);
      return true;
    });
    // The command "owner" on the second one's settings: refused in the same words, and nothing written.
    const settingsFile = join(b.folder, 'second.json');
    writeFileSync(settingsFile, JSON.stringify(b.settings));
    const owner = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', BIN, 'owner', '--config', settingsFile, '--reset'], { encoding: 'utf8', windowsHide: true, timeout: 60000 });
    assert.equal(owner.status, 2, owner.stderr);
    assert.match(owner.stderr, /An executor is running on the state file .* \(oauth\.state\)/);
    assert.doesNotMatch(owner.stdout, /oauth\/owner#/);
    assert.equal(readFileSync(a.statePath, 'utf8'), before.state);
    assert.notEqual(state(a).owner, null, 'the owner is still there');
    assert.deepEqual(files().filter(([name]) => name !== 'second.json'), before.files, 'nothing of the second one\'s was made or changed');
    // The lock is the state file's alone: a command at work on the second one's own books (offline) opens them, and the first one runs on.
    await (await open({ offline: true })).close();
    assert.equal((await ask(a, authorizeUrl(a, await discover(a), { pkce: pkce() }))).status, 200);
    // Once the first has closed, the second starts on the file, and reads the owner the first one kept.
    await a.executor.close();
    a.executor = null;
    second = await open();
    await second.close();
    second = null;
    // And gave the lock up at its close: the first starts again.
    await reopen(a);
    assert.notEqual(state(a).owner, null);
  } finally {
    await second?.close();
    await a.close();
    await b.close();
  }
});

test('the form the page sends: the request, the check\'s four fields and, once there is an owner, the recovery code\'s box', async () => {
  const w = await ownerWorld();
  try {
    const d = await discover(w);
    const names = (body) => [...body.matchAll(/<input [^>]*name="([^"]+)"/g)].map((m) => m[1]);
    const before = await ask(w, authorizeUrl(w, d, { pkce: pkce(), redirect_uri: CALLBACK }));
    assert.deepEqual(names(before.body), ['request', ...FOUR]);
    await setUpOwner(w);
    const page = await ask(w, authorizeUrl(w, d, { pkce: pkce(), redirect_uri: CALLBACK }));
    assert.deepEqual(names(page.body), ['request', ...FOUR, FIELD_RECOVERY]);
    // The box does not show what is typed, and the browser is asked not to keep it.
    assert.ok(page.body.includes(`<input type="password" name="${FIELD_RECOVERY}" id="owner-recovery-code" autocomplete="off" spellcheck="false">`));
  } finally {
    await w.close();
  }
});

test('the issuer may be http://localhost with a port, for tests: a browser makes no passkey at an IP address', () => {
  assert.equal(readIssuer('http://localhost:8787'), 'http://localhost:8787');
  assert.equal(readIssuer('http://127.0.0.1:8787'), 'http://127.0.0.1:8787');
  for (const not of ['http://localhost', 'http://localhost.example:8787', 'http://guard.example:8787', 'http://[::1]:8787', 'http://localhost:8787/x']) assert.equal(readIssuer(not), null, not);
});
