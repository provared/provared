// The world of the tests of the owner's check by passkey (owner.test.mjs,
// review3.test.mjs, review4.test.mjs): an executor opened as the command
// "http" opens it, a setup link made before the start, a software passkey,
// and a stand-in for the page the executor's own script runs on. Nothing
// leaves this computer.
//
// The software passkey is the library's own (test/helpers/passkey.mjs): it
// builds the three values a real passkey returns, in the forms Web
// Authentication sets out. It is not a passkey: its private key is an
// ordinary key in this process's memory.
//
// Imported with import(), after local-library.mjs.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { fromBase64url, sha256, toBase64url, utf8 } from 'provared';
import { ecdsaRawToDer, makePasskey } from '../../test/helpers/passkey.mjs';
import { readHttpSettings } from '../http.mjs';
import { makeOwnerSetup } from '../oauth.mjs';
import { setUp, signIn } from '../owner-steps.mjs';
import { oauthWorld, reopen, send, json, pkce, authorizeUrl, discover, ask } from './oauth-world.mjs';

export const state = (w) => JSON.parse(readFileSync(w.statePath, 'utf8'));

/** The way the page reaches the executor: POST JSON, with the page's Origin. Throws {status, code} where the answer is not 200. */
export const sender = (w, origin = w.issuer) => async (path, value) => {
  const r = await send('POST', `${w.issuer}${path}`, { headers: { 'content-type': 'application/json', ...(origin ? { origin } : {}) }, body: typeof value === 'string' ? value : JSON.stringify(value) });
  const v = json(r);
  if (r.status !== 200) throw Object.assign(new Error(v.message), { status: r.status, code: v.error });
  return v;
};
/** The error a promise fails with: {status, code}. */
export const refusal = async (p) => {
  try {
    await p;
  } catch (e) {
    return { status: e.status, code: e.code };
  }
  assert.fail('it was not refused');
};

/** A world whose executor has the check by passkey, as the command "http" opens it, and a setup link made by "owner" before the start. */
export async function ownerWorld() {
  const w = await oauthWorld({ open: false });
  delete w.more.ownerCheck;
  w.parsed = readHttpSettings(w.settings, w.folder).settings;
  w.made = makeOwnerSetup(w.parsed, { now: w.more.now });
  w.code = new URL(w.made.link).hash.slice(1);
  await reopen(w);
  return w;
}

/** A page waiting for the owner's answer: the form's request field. */
export async function waiting(w) {
  const page = await ask(w, authorizeUrl(w, await discover(w), { pkce: pkce() }));
  assert.equal(page.status, 200, page.body);
  return page.request;
}

/**
 * A software passkey for the page's steps (owner-steps.mjs). "made" and
 * "signed" count its prompts. "change" overrides a part of what it signs,
 * to build the answers the executor must refuse.
 */
export async function softPasskey(w, alg = 'ES256') {
  const soft = await makePasskey(alg, { rpId: new URL(w.issuer).hostname, origin: w.issuer });
  const p = {
    key: soft.key,
    credentialId: randomBytes(16).toString('base64url'),
    made: 0,
    signed: 0,
    change: {},
    create: async () => {
      p.made += 1;
      return { credentialId: p.credentialId, key: soft.key };
    },
    sign: async (credentialId, challenge) => {
      assert.equal(credentialId, p.credentialId, 'the page asks the passkey the executor keeps');
      p.signed += 1;
      // What the page's script gives the passkey: the SHA-256 of the executor's challenge.
      return soft.sign(await sha256(fromBase64url(challenge)), p.change);
    },
  };
  return p;
}

/** Set up the owner through the steps the page runs: {passkey, recoveryCode}. */
export async function setUpOwner(w, alg = 'ES256') {
  const passkey = await softPasskey(w, alg);
  const { recoveryCode } = await setUp({ passkey, code: w.code, send: sender(w) });
  return { passkey, recoveryCode };
}

/** The fields that prove the owner for a request, by the steps the page runs. */
export const prove = (w, passkey) => (request) => signIn({ passkey, request, send: sender(w), encode: toBase64url });

// --- the page's script, run as the executor serves it ---

/** The files the page loads, fetched from the executor as a browser would and written to a folder of the same shape: the address of page.js there. */
export async function pageScript(w) {
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
  assert.ok(seen.has('/oauth/owner/lib/provared/passkey-browser.js'), 'the page\'s script, its steps and the library\'s files');
  return pathToFileURL(join(root, 'oauth', 'owner', 'page.js')).href;
}

/** A stand-in for an element of the page: what the script reads and sets, and its listeners. */
function element(more = {}) {
  const listeners = {};
  return { textContent: '', hidden: false, disabled: false, value: '', ...more, addEventListener: (type, f) => (listeners[type] = f), fire: (type, event) => listeners[type](event) };
}

/**
 * A stand-in for navigator.credentials, for the library's own browser
 * functions: one ES256 passkey, made by create() and asked by get(), with
 * the user verified. "refuse" makes the next prompt fail, as one closed by
 * the person does. "made" and "asked" record the prompts.
 */
export function softCredentials(w) {
  const subtle = globalThis.crypto.subtle;
  const { hostname } = new URL(w.issuer);
  let pair = null;
  const c = {
    made: [],
    asked: [],
    refuse: false,
    rawId: new Uint8Array(randomBytes(16)),
    async create({ publicKey: k }) {
      c.made.push({ rp: k.rp.id, user: k.user.name, userVerification: k.authenticatorSelection.userVerification, attachment: k.authenticatorSelection.authenticatorAttachment, methods: k.pubKeyCredParams.map((m) => m.alg) });
      if (c.refuse) throw Object.assign(new Error('closed'), { name: 'NotAllowedError' });
      pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      const spki = await subtle.exportKey('spki', pair.publicKey);
      return { rawId: c.rawId.buffer, response: { getPublicKey: () => spki, getPublicKeyAlgorithm: () => -7 } };
    },
    async get({ publicKey: k }) {
      c.asked.push({ rpId: k.rpId, userVerification: k.userVerification, credential: toBase64url(new Uint8Array(k.allowCredentials[0].id)) });
      if (c.refuse) throw Object.assign(new Error('closed'), { name: 'NotAllowedError' });
      assert.equal(k.rpId, hostname);
      const clientDataJSON = utf8(JSON.stringify({ type: 'webauthn.get', challenge: toBase64url(new Uint8Array(k.challenge)), origin: w.issuer, crossOrigin: false }));
      // Flags 0x05: user present and user verified.
      const authenticatorData = new Uint8Array([...(await sha256(utf8(k.rpId))), 0x05, 0, 0, 0, 1]);
      const signed = new Uint8Array([...authenticatorData, ...(await sha256(clientDataJSON))]);
      const signature = ecdsaRawToDer(new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, signed)));
      return { rawId: c.rawId.buffer, response: { authenticatorData: authenticatorData.buffer, clientDataJSON: clientDataJSON.buffer, signature: signature.buffer } };
    },
  };
  return c;
}

/** A stand-in for the browser's storage for the executor's address: one for each browser a test has. */
export function softStorage() {
  const kept = new Map();
  return { kept, getItem: (k) => (kept.has(k) ? kept.get(k) : null), setItem: (k, v) => kept.set(k, String(v)), removeItem: (k) => kept.delete(k) };
}

/**
 * Run the page's script on a stand-in page made from the HTML the executor
 * sent: every element with an id, and the authorisation form with its
 * hidden fields. Gives {el (the elements by id), form, replaced (what
 * history.replaceState was given)}. The globals a page has are set for the
 * run, and put back by "after".
 */
let runs = 0;
export async function runPage(w, script, { html, hash = '', path, credentials, storage = softStorage(), after }) {
  const el = {};
  for (const m of html.matchAll(/<(\w+)[^>]*\sid="([^"]+)"([^>]*)>/g)) el[m[2]] = element({ hidden: /\shidden(\s|$)/.test(` ${m[3]}`) });
  let form = null;
  if (/<form method="post" action="\/oauth\/authorize">/.test(html)) {
    form = element({ elements: {}, submitted: null, requestSubmit: (submitter) => (form.submitted = submitter) });
    for (const m of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) form.elements[m[1]] = { value: m[2] };
  }
  const page = { el, form, replaced: null };
  const u = new URL(w.issuer);
  const globals = {
    document: { getElementById: (name) => el[name] ?? null, querySelector: (q) => (q === 'form[action="/oauth/authorize"]' ? form : null) },
    location: { hash, host: u.host, hostname: u.hostname, origin: w.issuer, pathname: path },
    history: { replaceState: (...a) => (page.replaced = a) },
    navigator: { credentials },
    isSecureContext: true,
    PublicKeyCredential: function PublicKeyCredential() {},
    localStorage: storage,
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
