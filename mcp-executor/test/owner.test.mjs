// The owner's check by the owner's passkey (DESIGN.md, section 14.1,
// X217 onward), through the executor's public interface: its addresses, the
// command "owner", and openHttpExecutor with no check given, as the command
// "http" opens it.
//
// The browser's half runs here too: the steps the page runs
// (owner-steps.mjs), with the packages' own functions. Only the passkey is
// made up: a stand-in gives a fixed PRF output, as the passkey ceremony
// itself needs a real browser and authenticator (the recipe's README says
// how to try that by hand). Nothing leaves this computer.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createCryptoCore } from '@microtoll/crypto-core';
import * as id from '@microtoll/identity';

const { call } = await import('./http-world.mjs');
const { readHttpSettings } = await import('../http.mjs');
const { makeOwnerSetup } = await import('../oauth.mjs');
const { CHALLENGE_LIFE, SETUP_LIFE, cryptoCore } = await import('../owner.mjs');
const { NAMESPACE, FIELD_CHALLENGE, FIELD_SIGNATURE, SETUP_PATH, PASSKEY_PATH, CHALLENGE_PATH, setUp, signIn } = await import('../owner-steps.mjs');
const { oauthWorld, reopen, send, json, pkce, authorizeUrl, discover, ask, answer, connect, bearer, CALLBACK } = await import('./oauth-world.mjs');

const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));
const cc = createCryptoCore({ namespace: NAMESPACE });

/** A stand-in for the owner's passkey: it makes one credential and gives the same made-up PRF output for it each time. */
function fakePasskey() {
  const credentialId = new Uint8Array(randomBytes(16));
  const prfOutput32 = new Uint8Array(randomBytes(32));
  const p = {
    prfOutput32,
    /** How many passkeys were made. */
    made: 0,
    create: async () => {
      p.made += 1;
      return { credentialId, prfSalt: new Uint8Array(randomBytes(32)), prfOutput32, transports: ['internal'] };
    },
    evaluate: async (cid, salt, transports) => {
      assert.deepEqual(cid, credentialId, 'the page asks the passkey the executor keeps');
      assert.deepEqual(transports, ['internal'], 'and tells the browser where it is kept');
      return { prfOutput32 };
    },
  };
  return p;
}
/** A device with no PRF: every use of the passkey fails. */
const noPasskey = { create: async () => { throw new Error('no PRF'); }, evaluate: async () => { throw new Error('no PRF'); } };

/** The way the page reaches the executor: POST JSON, with the page's Origin. Throws {status, code} where the answer is not 200. */
const sender = (w, origin = w.issuer) => async (path, value) => {
  const r = await send('POST', `${w.issuer}${path}`, { headers: { 'content-type': 'application/json', ...(origin ? { origin } : {}) }, body: typeof value === 'string' ? value : JSON.stringify(value) });
  const v = json(r);
  if (r.status !== 200) throw Object.assign(new Error(v.message), { status: r.status, code: v.error });
  return v;
};
/** The error a promise fails with: {status, code}. */
const refusal = async (p) => {
  try {
    await p;
  } catch (e) {
    return { status: e.status, code: e.code };
  }
  assert.fail('it was not refused');
};

/** A world whose executor has the check by passkey, as the command "http" opens it, and a setup link made by "owner" before the start. */
async function ownerWorld() {
  const w = await oauthWorld({ open: false });
  delete w.more.ownerCheck;
  w.parsed = readHttpSettings(w.settings, w.folder).settings;
  w.made = makeOwnerSetup(w.parsed, { now: w.more.now });
  w.code = new URL(w.made.link).hash.slice(1);
  await reopen(w);
  return w;
}
/** Set up the owner through the steps the page runs: {passkey, recoveryCode}. */
async function setUpOwner(w) {
  const passkey = fakePasskey();
  const { recoveryCode } = await setUp({ cc, id, passkey, code: w.code, send: sender(w) });
  return { passkey, recoveryCode };
}
/** A page waiting for the owner's answer: its request id. */
async function waiting(w) {
  const d = await discover(w);
  const page = await ask(w, authorizeUrl(w, d, { pkce: pkce() }));
  assert.equal(page.status, 200, page.body);
  return page.request;
}
const state = (w) => JSON.parse(readFileSync(w.statePath, 'utf8'));

test('the namespace is "provared-mcp-executor", in the executor and in the page, and a signature under another namespace is refused', async () => {
  assert.equal(NAMESPACE, 'provared-mcp-executor');
  assert.equal(cryptoCore().profile.namespace, 'provared-mcp-executor');
  const page = readFileSync(new URL('../owner-page.mjs', import.meta.url), 'utf8');
  assert.match(page, /createCryptoCore\(\{ namespace: NAMESPACE \}\)/);
  assert.match(page, /from '\.\/steps\.js'/);
  const identity = await id.createIdentity(cc);
  const nonce = new Uint8Array(randomBytes(32));
  const origin = 'https://guard.example.com';
  const sign = async (core) => cc.signBytes(identity.routing.privateKey, await id.authMessage(core, origin, nonce));
  assert.equal(await id.verifyAuthSignature(cryptoCore(), identity.routing.publicKeyRaw, origin, nonce, await sign(cc)), true);
  assert.equal(await id.verifyAuthSignature(cryptoCore(), identity.routing.publicKeyRaw, origin, nonce, await sign(createCryptoCore({ namespace: 'another-namespace' }))), false);
});

test('setup, then a full sign-in with the passkey: the pages run only the executor\'s own scripts; the executor keeps ciphertext only; the connection calls a tool', async () => {
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
    for (const path of ['page.js', 'steps.js', 'lib/identity/index.js', 'lib/identity/handshake.js', 'lib/crypto-core/index.js', 'lib/crypto-core/primitives.js']) {
      const f = await send('GET', `${w.issuer}/oauth/owner/${path}`);
      assert.equal(f.status, 200, path);
      assert.equal(f.headers['content-type'], 'text/javascript; charset=utf-8');
    }
    assert.equal((await send('GET', `${w.issuer}/oauth/owner/lib/identity/..%2Fpackage.json`)).status, 404);
    assert.equal((await send('GET', `${w.issuer}/oauth/owner/lib/identity/../../package.json`)).status, 404);

    const { passkey, recoveryCode } = await setUpOwner(w);
    assert.match(recoveryCode, /\S/);
    const kept = state(w);
    assert.equal(kept.setup, null, 'the link is spent');
    assert.deepEqual(Object.keys(kept.owner).sort(), ['created', 'passkey', 'recovery', 'routingPublicKey']);
    const text = readFileSync(w.statePath, 'utf8');
    assert.equal(text.includes(Buffer.from(passkey.prfOutput32).toString('base64url')), false, 'no PRF output in the file');
    assert.equal(text.includes(recoveryCode), false, 'no recovery code in the file');

    // The authorisation page: the check's fields and its script, under the policy.
    const d = await discover(w);
    const page = await ask(w, authorizeUrl(w, d, { pkce: pkce() }));
    assert.match(page.headers['content-security-policy'], /^default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self' https:\/\/client\.example; frame-ancestors 'none'; base-uri 'none'$/);
    assert.match(page.body, new RegExp(`name="${FIELD_CHALLENGE}"`));
    assert.doesNotMatch(page.body, /<script(?![^>]*\ssrc=)/, 'no inline script');

    const prove = (request) => signIn({ cc, id, passkey, request, origin: w.issuer, send: sender(w) });
    const { access } = await connect(w, { prove });
    assert.equal((await call(w, bearer(access), 'echo', { a: 1 })).status, 200);
    assert.ok(w.logs.some((e) => e.event === 'owner-set'));
    assert.ok(w.logs.some((e) => e.event === 'oauth-approved' && e.agent === 'conn'));
  } finally {
    await w.close();
  }
});

test('a sign-in with the recovery code, on a device with no PRF; another recovery code is refused', async () => {
  const w = await ownerWorld();
  try {
    const { recoveryCode } = await setUpOwner(w);
    const { access } = await connect(w, { prove: (request) => signIn({ cc, id, passkey: noPasskey, recoveryCode, request, origin: w.issuer, send: sender(w) }) });
    assert.equal((await call(w, bearer(access), 'echo', {})).status, 200);
    const other = await id.wrapRootKeyWithNewRecoveryCode(cc, (await id.createIdentity(cc)).rootKey);
    const request = await waiting(w);
    assert.deepEqual(await refusal(signIn({ cc, id, passkey: noPasskey, recoveryCode: other.displayString, request, origin: w.issuer, send: sender(w) })), { status: 404, code: 'not-found' });
  } finally {
    await w.close();
  }
});

test('refused at the authorisation page: a signature over another origin, by another key, or with a challenge used twice, expired, for another request or never given', async () => {
  const w = await ownerWorld();
  try {
    const { passkey } = await setUpOwner(w);
    const prove = (request, origin = w.issuer) => signIn({ cc, id, passkey, request, origin, send: sender(w) });
    const refused = async (request, fields) => {
      const a = await answer(w, request, { fields });
      assert.equal(a.status, 403, a.body);
      assert.match(a.body, /did not pass/);
    };

    // Over another origin: the page was not the executor's.
    let request = await waiting(w);
    await refused(request, await prove(request, 'https://elsewhere.example'));
    // By another key: an identity that is not the owner's.
    request = await waiting(w);
    const stranger = await id.createIdentity(cc);
    const given = await sender(w)(CHALLENGE_PATH, { request });
    const signature = await cc.signBytes(stranger.routing.privateKey, await id.authMessage(cc, w.issuer, cc.fromBase64Url(given.challenge)));
    await refused(request, { request: given.request, [FIELD_CHALLENGE]: given.challenge, [FIELD_SIGNATURE]: cc.toBase64Url(signature) });

    // A broken signature is refused.
    request = await waiting(w);
    const good = await prove(request);
    await refused(request, { ...good, [FIELD_SIGNATURE]: cc.toBase64Url(new Uint8Array(64)) });
    // Expired: two minutes later.
    request = await waiting(w);
    const late = await prove(request);
    w.clock.offset += CHALLENGE_LIFE;
    await refused(request, late);
    // For another request: the first request's challenge and signature, sent with the second request.
    const first = await waiting(w);
    const second = await waiting(w);
    const forFirst = await prove(first);
    await refused(second, { [FIELD_CHALLENGE]: forFirst[FIELD_CHALLENGE], [FIELD_SIGNATURE]: forFirst[FIELD_SIGNATURE] });
    // And with the second request once it has a challenge of its own.
    const forSecond = await sender(w)(CHALLENGE_PATH, { request: second });
    await refused(second, { request: forSecond.request, [FIELD_CHALLENGE]: forFirst[FIELD_CHALLENGE], [FIELD_SIGNATURE]: forFirst[FIELD_SIGNATURE] });
    // Never given: a challenge the executor did not make, and none at all.
    request = await waiting(w);
    const made = await prove(request);
    await refused(request, { ...made, [FIELD_CHALLENGE]: Buffer.from(randomBytes(32)).toString('base64url') });
    request = await waiting(w);
    await refused(request, {});
    // The request's seal: a request changed by one character, or one this executor never sealed, is not known, and gets no challenge.
    const changed = `${made.request.slice(0, -1)}${made.request.endsWith('A') ? 'B' : 'A'}`;
    assert.equal((await answer(w, changed, { fields: { [FIELD_CHALLENGE]: made[FIELD_CHALLENGE], [FIELD_SIGNATURE]: made[FIELD_SIGNATURE] } })).status, 400);
    assert.deepEqual(await refusal(sender(w)(CHALLENGE_PATH, { request: changed })), { status: 400, code: 'bad-request' });
    assert.deepEqual(await refusal(sender(w)(CHALLENGE_PATH, { request: 'A'.repeat(43) })), { status: 400, code: 'bad-request' });

    // After all that, with no wait, the right answer passes: failed attempts are not counted (X211).
    request = await waiting(w);
    const right = await prove(request);
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

test('the setup link: used twice, expired, the wrong code, or not from the executor\'s page, it is refused', async () => {
  const w = await ownerWorld();
  try {
    // Not from the executor's own page: no Origin, or another.
    assert.deepEqual(await refusal(setUp({ cc, id, passkey: fakePasskey(), code: w.code, send: sender(w, null) })), { status: 403, code: 'origin-refused' });
    assert.deepEqual(await refusal(setUp({ cc, id, passkey: fakePasskey(), code: w.code, send: sender(w, 'https://elsewhere.example') })), { status: 403, code: 'origin-refused' });
    // The wrong code.
    assert.deepEqual(await refusal(setUp({ cc, id, passkey: fakePasskey(), code: Buffer.from(randomBytes(32)).toString('base64url'), send: sender(w) })), { status: 403, code: 'setup-refused' });
    // Used twice: the second is refused before a passkey is made, and the owner is the first.
    await setUpOwner(w);
    const owner = state(w).owner;
    const second = fakePasskey();
    assert.deepEqual(await refusal(setUp({ cc, id, passkey: second, code: w.code, send: sender(w) })), { status: 409, code: 'owner-exists' });
    assert.equal(second.made, 0, 'no passkey was made');
    assert.deepEqual(await refusal(sender(w)(SETUP_PATH, { code: w.code })), { status: 409, code: 'owner-exists' });
    assert.deepEqual(state(w).owner, owner);
  } finally {
    await w.close();
  }
  // Expired: 15 minutes after the command.
  const late = await ownerWorld();
  try {
    late.clock.offset += SETUP_LIFE;
    const passkey = fakePasskey();
    assert.deepEqual(await refusal(setUp({ cc, id, passkey, code: late.code, send: sender(late) })), { status: 403, code: 'setup-ended' });
    assert.equal(passkey.made, 0, 'no passkey was made');
    // The message itself is refused too, without the page's first question.
    assert.deepEqual(await refusal(sender(late)(SETUP_PATH, { code: late.code })), { status: 403, code: 'setup-ended' });
    assert.equal(state(late).owner, null);
  } finally {
    await late.close();
  }
});

test('a second setup while an owner exists is refused, unless the owner is reset, which ends every connection with its tokens', async () => {
  const w = await ownerWorld();
  try {
    const { passkey } = await setUpOwner(w);
    const { access } = await connect(w, { prove: (request) => signIn({ cc, id, passkey, request, origin: w.issuer, send: sender(w) }) });
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
    assert.deepEqual(await refusal(sender(w)(PASSKEY_PATH, {})), { status: 409, code: 'no-owner' });
    w.code = new URL(reset.link).hash.slice(1);
    const again = await setUpOwner(w);
    const { access: fresh } = await connect(w, { prove: (request) => signIn({ cc, id, passkey: again.passkey, request, origin: w.issuer, send: sender(w) }) });
    assert.equal((await call(w, bearer(fresh), 'echo', {})).status, 200);
  } finally {
    await w.close();
  }
});

test('a setup with an unlock method missing or malformed is refused, and the link still works after', async () => {
  const w = await ownerWorld();
  try {
    const identity = await id.createIdentity(cc);
    const byPasskey = await id.wrapRootKeyWithPrf(cc, identity.rootKey, new Uint8Array(randomBytes(32)), new Uint8Array(randomBytes(16)), new Uint8Array(randomBytes(32)));
    const { method: byCode } = await id.wrapRootKeyWithNewRecoveryCode(cc, identity.rootKey);
    const b = cc.toBase64Url;
    const right = () => ({
      code: w.code,
      routingPublicKey: b(identity.routing.publicKeyRaw),
      passkey: { credentialId: b(byPasskey.credentialId), prfSalt: b(byPasskey.prfSalt), wrappedRootKey: b(byPasskey.wrappedRootKey) },
      recovery: { salt: b(byCode.salt), lookupHash: byCode.lookupHash, wrappedRootKey: b(byCode.wrappedRootKey) },
    });
    const wrong = {
      'no recovery code': (v) => delete v.recovery,
      'no passkey': (v) => delete v.passkey,
      'a passkey with no wrapped root key': (v) => delete v.passkey.wrappedRootKey,
      'a PRF salt of 31 bytes': (v) => (v.passkey.prfSalt = b(new Uint8Array(31))),
      'an empty credential id': (v) => (v.passkey.credentialId = ''),
      'a lookup hash in capitals': (v) => (v.recovery.lookupHash = v.recovery.lookupHash.toUpperCase()),
      'a recovery salt of 32 bytes': (v) => (v.recovery.salt = b(new Uint8Array(32))),
      'a routing key of 31 bytes': (v) => (v.routingPublicKey = b(new Uint8Array(31))),
      'base64 with padding': (v) => (v.passkey.wrappedRootKey += '='),
      'a member the page does not send': (v) => (v.passkey.label = 'laptop'),
      'a transport that is not a name': (v) => (v.passkey.transports = ['USB key']),
      'nine transports': (v) => (v.passkey.transports = Array(9).fill('usb')),
      'transports as a string': (v) => (v.passkey.transports = 'usb'),
      'a method as a string': (v) => (v.recovery = 'x'),
    };
    for (const [what, change] of Object.entries(wrong)) {
      const v = right();
      change(v);
      assert.deepEqual(await refusal(sender(w)(SETUP_PATH, v)), { status: 400, code: 'bad-request' }, what);
    }
    assert.deepEqual(await refusal(sender(w)(SETUP_PATH, '{not json')), { status: 400, code: 'bad-request' });
    assert.equal(state(w).owner, null);
    assert.deepEqual(await sender(w)(SETUP_PATH, right()), { owner: 'set' });
    assert.equal(state(w).owner.routingPublicKey, b(identity.routing.publicKeyRaw));
    assert.deepEqual(state(w).owner.passkey.transports, [], 'a passkey sent with no transports is kept as having none');
    // A state file whose owner is not in the executor's form stops the start.
    await w.executor.close();
    w.executor = null;
    const s = state(w);
    s.owner.passkey.prfSalt = 'x';
    writeFileSync(w.statePath, JSON.stringify(s));
    await assert.rejects(reopen(w), /not in the form the executor writes/);
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

test('the form the page sends: the owner\'s fields and nothing of the recovery code', async () => {
  const w = await ownerWorld();
  try {
    const d = await discover(w);
    const page = await ask(w, authorizeUrl(w, d, { pkce: pkce(), redirect_uri: CALLBACK }));
    // The recovery code's box has no name, so the form never sends it.
    assert.match(page.body, /<input type="text" id="owner-recovery-code" autocomplete="off" spellcheck="false">/);
    assert.equal([...page.body.matchAll(/<input [^>]*name="/g)].length, 3, 'request and the two fields of the check');
  } finally {
    await w.close();
  }
});
