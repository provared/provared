// The owner's check by the owner's passkey (DESIGN.md, section 14.1, choices
// X217 onward), for the OAuth front door (oauth.mjs, X212).
//
// The founder's packages @microtoll/identity and @microtoll/crypto-core do
// the cryptography; this file calls their public functions only. In the
// browser, the owner's passkey (its PRF output) or recovery code opens a
// root key that never leaves the browser, and the routing key derived from
// it signs the executor's challenge with the page's origin bound in. The
// executor keeps the routing public key and the two wrapped copies of the
// root key, which are ciphertext, and checks the signature with
// verifyAuthSignature. It never sees a key, and never verifies a passkey.
//
// What it serves, beside the front door's addresses:
//
//   GET  /oauth/owner                  the setup page (the link's code is in its fragment)
//   GET  /oauth/owner/page.js          the pages' script (owner-page.mjs)
//   GET  /oauth/owner/steps.js         its steps (owner-steps.mjs)
//   GET  /oauth/owner/lib/<package>/…  the two packages' own files
//   POST /oauth/owner/setup            the new owner (X219)
//   POST /oauth/owner/passkey          the passkey's wrapped copy (X220)
//   POST /oauth/owner/recovery         the recovery code's wrapped copy, by its lookup hash (X220)
//   POST /oauth/owner/challenge        a challenge for one request at the page (X221)

import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCryptoCore } from '@microtoll/crypto-core';
import { verifyAuthSignature } from '@microtoll/identity';
import { CHALLENGE_PATH, FIELD_CHALLENGE, FIELD_SIGNATURE, NAMESPACE, OWNER_PATH, PASSKEY_PATH, RECOVERY_PATH, SETUP_PATH } from './owner-steps.mjs';

export { NAMESPACE, OWNER_PATH };

/** How long a setup link and a challenge last, in milliseconds (X218, X221). */
export const SETUP_LIFE = 15 * 60 * 1000;
export const CHALLENGE_LIFE = 2 * 60 * 1000;
/** The most challenges kept at once; past it the oldest goes. */
export const MAX_CHALLENGES = 1000;
const BODY_LIMIT = 16 * 1024;
const BODY_TIME = 10 * 1000;

const HERE = dirname(fileURLToPath(import.meta.url));
const B64URL = /^[A-Za-z0-9_-]*$/;
const LOOKUP = /^[0-9a-f]{64}$/;
const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

/** The bytes a base64url text stands for, where it is written as the executor writes it and its length is within [least, most]; else null. */
export function bytesOf(text, least, most = least) {
  if (typeof text !== 'string' || !B64URL.test(text)) return null;
  const b = Buffer.from(text, 'base64url');
  if (b.toString('base64url') !== text || b.length < least || b.length > most) return null;
  return new Uint8Array(b);
}

/** Whether an object has exactly these members. */
const only = (v, keys) => isObject(v) && Object.keys(v).length === keys.length && keys.every((k) => Object.hasOwn(v, k));

/**
 * The owner as the executor keeps it, or {problem} (X219): the routing
 * public key, and the two unlock methods as the package makes them, in
 * base64url (the lookup hash in the package's hexadecimal).
 */
export function readOwner(v) {
  if (!only(v, ['routingPublicKey', 'passkey', 'recovery'])) return { problem: 'the owner is not {routingPublicKey, passkey, recovery}' };
  if (!bytesOf(v.routingPublicKey, 32)) return { problem: 'routingPublicKey is not 32 bytes in base64url' };
  const p = v.passkey;
  if (!only(p, ['credentialId', 'prfSalt', 'wrappedRootKey'])) return { problem: 'passkey is not {credentialId, prfSalt, wrappedRootKey}' };
  if (!bytesOf(p.credentialId, 1, 1023)) return { problem: 'passkey.credentialId is not 1 to 1023 bytes in base64url' };
  if (!bytesOf(p.prfSalt, 32)) return { problem: 'passkey.prfSalt is not 32 bytes in base64url' };
  if (!bytesOf(p.wrappedRootKey, 1, 1024)) return { problem: 'passkey.wrappedRootKey is not 1 to 1024 bytes in base64url' };
  const r = v.recovery;
  if (!only(r, ['salt', 'lookupHash', 'wrappedRootKey'])) return { problem: 'recovery is not {salt, lookupHash, wrappedRootKey}' };
  if (!bytesOf(r.salt, 16)) return { problem: 'recovery.salt is not 16 bytes in base64url' };
  if (typeof r.lookupHash !== 'string' || !LOOKUP.test(r.lookupHash)) return { problem: 'recovery.lookupHash is not 64 hexadecimal digits' };
  if (!bytesOf(r.wrappedRootKey, 1, 1024)) return { problem: 'recovery.wrappedRootKey is not 1 to 1024 bytes in base64url' };
  return {
    owner: {
      routingPublicKey: v.routingPublicKey,
      passkey: { credentialId: p.credentialId, prfSalt: p.prfSalt, wrappedRootKey: p.wrappedRootKey },
      recovery: { salt: r.salt, lookupHash: r.lookupHash, wrappedRootKey: r.wrappedRootKey },
    },
  };
}

const sameText = (a, b) => {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
};

/** A JSON body, read to BODY_LIMIT bytes within BODY_TIME ms: the value, or undefined. */
function readJson(req) {
  return new Promise((done) => {
    const type = String(req.headers['content-type'] ?? '').toLowerCase();
    if (!/^application\/json\s*(;|$)/.test(type)) {
      req.resume();
      return done(undefined);
    }
    const chunks = [];
    let size = 0;
    let over = false;
    const end = (value) => {
      if (over) return;
      over = true;
      clearTimeout(timer);
      done(value);
    };
    const timer = setTimeout(() => {
      end(undefined);
      req.destroy();
    }, BODY_TIME);
    req.on('data', (c) => {
      size += c.length;
      if (size > BODY_LIMIT) end(undefined);
      else if (!over) chunks.push(c);
    });
    req.on('error', () => end(undefined));
    req.on('end', () => {
      try {
        end(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))));
      } catch {
        end(undefined);
      }
    });
  });
}

/** The files the pages load, by their address: the script, its steps, and the two packages' own files (X224). */
function pageFiles() {
  const files = new Map();
  const js = (path, file) => files.set(path, readFileSync(file));
  js(`${OWNER_PATH}/page.js`, join(HERE, 'owner-page.mjs'));
  js(`${OWNER_PATH}/steps.js`, join(HERE, 'owner-steps.mjs'));
  for (const [name, spec] of [['crypto-core', '@microtoll/crypto-core'], ['identity', '@microtoll/identity']]) {
    // The folder of the package's main file, as Node.js resolves it: its src/.
    const folder = dirname(fileURLToPath(import.meta.resolve(spec)));
    for (const f of readdirSync(folder)) if (f.endsWith('.js')) js(`${OWNER_PATH}/lib/${name}/${f}`, join(folder, f));
  }
  return files;
}

/** The namespace's one crypto core, made once: createCryptoCore with the namespace only, every other option at its default (X217). */
let core = null;
export const cryptoCore = () => (core ??= createCryptoCore({ namespace: NAMESPACE }));

/**
 * The owner's check by passkey, for openFrontDoor.
 *
 * issuer     the executor's public address: the origin bound into every signature
 * store      {owner() -> the owner or null, setup() -> {hash, expires} or null, setOwner(owner)}: the front door's state file
 * failures   the front door's count of failed attempts at the owner's check (X211)
 * isRequest  whether an id names a request waiting at the page
 * page, json the front door's ways to answer with a page and with JSON
 * hashOf     SHA-256 in base64url, as the front door keeps its hashes
 */
export function openPasskeyCheck({ issuer, now = Date.now, log = () => {}, store, failures, isRequest, page, json, hashOf }) {
  const cc = cryptoCore();
  const files = pageFiles();
  const host = new URL(issuer).host;
  /** The challenges given out, by their text: {request, expires}; each is taken out at its first use (X221). */
  const challenges = new Map();
  const tidy = () => {
    const t = now();
    for (const [k, c] of challenges) if (c.expires <= t) challenges.delete(k);
  };
  const refuse = (res, status, code, message, extra = {}) => {
    log({ event: 'oauth-refused', code });
    json(res, status, { error: code, message }, extra);
  };

  const setupPage = [
    `<p>This page makes the owner of the executor at ${host}: a key that never leaves this browser, a passkey that opens it, and a recovery code that opens it too. The executor keeps only the key's public half and the two locked copies.</p>`,
    `<p>The passkey belongs to ${host}. If the executor's public address changes, the passkey no longer opens the key, and only the recovery code does.</p>`,
    '<p><button type="button" id="owner-setup">Make the passkey</button></p>',
    '<p id="owner-status" role="status"></p>',
    '<pre id="owner-recovery" hidden></pre>',
    `<script type="module" src="${OWNER_PATH}/page.js"></script>`,
  ].join('\n');

  /** POST /oauth/owner/setup (X219): once, with the link's code, while no owner exists. */
  function setUp(res, v) {
    if (store.owner()) return refuse(res, 409, 'owner-exists', 'An owner is already set up on this executor. A second setup is refused unless the owner is reset on the server.');
    const setup = store.setup();
    if (!setup || setup.expires <= now()) return refuse(res, 403, 'setup-ended', 'This setup link has been used or has ended. Make a new one on the server.');
    if (!isObject(v) || typeof v.code !== 'string' || !sameText(hashOf(v.code), setup.hash)) {
      failures.failed();
      return refuse(res, 403, 'setup-refused', 'This is not the code of the setup link.');
    }
    const rest = { ...v };
    delete rest.code;
    const read = readOwner(rest);
    if (read.problem) return refuse(res, 400, 'bad-request', `The owner is not in the form the page sends: ${read.problem}.`);
    store.setOwner({ ...read.owner, created: now() });
    log({ event: 'owner-set' });
    json(res, 200, { owner: 'set' });
  }

  /** POST /oauth/owner/passkey, /recovery and /challenge (X220, X221). */
  function unlock(res, path, v) {
    const owner = store.owner();
    if (!owner) return refuse(res, 409, 'no-owner', 'No owner is set up on this executor yet.');
    if (path === PASSKEY_PATH) {
      if (!only(v, [])) return refuse(res, 400, 'bad-request', 'Send {}.');
      return json(res, 200, owner.passkey);
    }
    if (path === RECOVERY_PATH) {
      if (!only(v, ['lookupHash']) || typeof v.lookupHash !== 'string' || !LOOKUP.test(v.lookupHash)) return refuse(res, 400, 'bad-request', 'Send {"lookupHash": "<64 hexadecimal digits>"}.');
      if (!sameText(v.lookupHash, owner.recovery.lookupHash)) {
        failures.failed();
        return refuse(res, 404, 'not-found', 'That recovery code is not the owner\'s.');
      }
      return json(res, 200, owner.recovery);
    }
    if (!only(v, ['request']) || typeof v.request !== 'string' || !isRequest(v.request)) return refuse(res, 400, 'bad-request', 'Send {"request": "<the id of a request waiting at the page>"}.');
    tidy();
    if (challenges.size >= MAX_CHALLENGES) challenges.delete(challenges.keys().next().value);
    const challenge = randomBytes(32).toString('base64url');
    challenges.set(challenge, { request: v.request, expires: now() + CHALLENGE_LIFE });
    return json(res, 200, { challenge });
  }

  return {
    /** The authorisation page runs the script from the executor's own address, and fetches from there only (X224). */
    scripts: true,
    form: () =>
      [
        `<input type="hidden" name="${FIELD_CHALLENGE}" value="">`,
        `<input type="hidden" name="${FIELD_SIGNATURE}" value="">`,
        '<p>Approve asks for the owner\'s passkey. On a device without it, type the recovery code here first:</p>',
        '<p><label>Recovery code <input type="text" id="owner-recovery-code" autocomplete="off" spellcheck="false"></label></p>',
        '<p id="owner-status" role="status"></p>',
        `<script type="module" src="${OWNER_PATH}/page.js"></script>`,
      ].join('\n'),
    /** The signature over this executor's own challenge for this request, by the owner's routing key, with the issuer as the origin (X222). */
    async check(fields, { request, origin }) {
      const text = fields.get(FIELD_CHALLENGE) ?? '';
      const given = challenges.get(text);
      challenges.delete(text);
      if (!given || given.expires <= now() || given.request !== request) return false;
      const owner = store.owner();
      const nonce = bytesOf(text, 32);
      const signature = bytesOf(fields.get(FIELD_SIGNATURE) ?? '', 64);
      if (!owner || !nonce || !signature) return false;
      return (await verifyAuthSignature(cc, bytesOf(owner.routingPublicKey, 32), origin, nonce, signature)) === true;
    },
    owns: (path) => path === OWNER_PATH || path.startsWith(`${OWNER_PATH}/`),
    async take(req, res, path) {
      if (req.method === 'GET' || req.method === 'HEAD') {
        req.resume();
        if (path === OWNER_PATH) return page(res, 200, 'Set up the owner', setupPage);
        const file = files.get(path);
        if (!file) return json(res, 404, { error: 'not-found', message: 'Not one of the executor\'s files.' });
        res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8', 'content-length': file.length, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
        return res.end(req.method === 'HEAD' ? undefined : file);
      }
      if (req.method !== 'POST' || ![SETUP_PATH, PASSKEY_PATH, RECOVERY_PATH, CHALLENGE_PATH].includes(path)) {
        req.resume();
        return json(res, 405, { error: 'not-allowed', message: 'The owner\'s addresses take GET for the pages and their files, and POST for the four exchanges.' });
      }
      // As the owner's answer at the page (X212): only from the executor's own pages.
      if (req.headers.origin !== issuer) {
        req.resume();
        return refuse(res, 403, 'origin-refused', 'Only the executor\'s own pages may send this.');
      }
      if (failures.locked()) {
        req.resume();
        return refuse(res, 429, 'too-many-attempts', 'Too many failed attempts. Wait, then begin again.', { 'retry-after': String(failures.retryAfter()) });
      }
      const v = await readJson(req);
      if (v === undefined) return refuse(res, 400, 'bad-request', 'The body must be JSON (application/json), at most 16 KiB.');
      if (path === SETUP_PATH) return setUp(res, v);
      return unlock(res, path, v);
    },
  };
}
