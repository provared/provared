// The owner's check by the owner's passkey (DESIGN.md, section 14.1, choices
// X270 onward), for the OAuth front door (oauth.mjs, X212).
//
// A plain passkey: no extension of it is asked for, so any passkey that
// verifies its user will do. At the setup the browser makes the passkey and
// sends its identifier and its public key, with the setup link's code. At
// each approval the passkey signs the executor's challenge for that one
// request, and the executor checks the signature with the library's own
// check of a passkey's signature (checkAssertion: Web Authentication Level
// 3, section 7.2), against the public key it keeps, with its public address
// as the origin and that address's host as the relying party. A recovery
// code, made here and shown once, approves a connection in the passkey's
// place; only its SHA-256 is kept.
//
// What it serves, beside the front door's addresses:
//
//   GET  /oauth/owner                  the setup page (the link's code is in its fragment)
//   GET  /oauth/owner/page.js          the pages' script (owner-page.mjs)
//   GET  /oauth/owner/steps.js         its steps (owner-steps.mjs)
//   GET  /oauth/owner/lib/provared/…   the library's own files, for its passkey functions
//   POST /oauth/owner/link             whether the setup link still works (X271)
//   POST /oauth/owner/setup            the new owner, and with it the approval of one request that waits (X271, X272)
//   POST /oauth/owner/challenge        a challenge for one request at the page (X273)
//
// No failed attempt is counted here (X211): the setup link's code and a
// challenge are 256 random bits, the recovery code 160, and the answer is a
// signature, so none can be guessed, and a count could only shut the owner
// out.

import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { CHALLENGE_PATH, FIELD_AUTHENTICATOR_DATA, FIELD_CHALLENGE, FIELD_CLIENT_DATA, FIELD_RECOVERY, FIELD_SIGNATURE, LINK_PATH, OWNER_PATH, SETUP_PATH } from './owner-steps.mjs';

export { OWNER_PATH };

/**
 * The library's folder of files, as Node.js finds the package. The pages
 * are served its files from there (X224), and the executor takes from
 * there the two functions the library has for a passkey but does not name
 * among its exports: the check of a passkey's signature and the check of a
 * public key's form (X270).
 */
const LIBRARY = dirname(fileURLToPath(import.meta.resolve('provared')));
const { checkAssertion } = await import(pathToFileURL(join(LIBRARY, 'webauthn.js')).href);
const { PASSKEY_METHODS, checkKey } = await import(pathToFileURL(join(LIBRARY, 'keys.js')).href);

/** How long a setup link and a challenge last, in milliseconds (X218, X273). */
export const SETUP_LIFE = 15 * 60 * 1000;
export const CHALLENGE_LIFE = 2 * 60 * 1000;
/** A recovery code is this many random bytes, written in base32 (X276). */
export const RECOVERY_BYTES = 20;
const BODY_LIMIT = 16 * 1024;
const BODY_TIME = 10 * 1000;

const HERE = dirname(fileURLToPath(import.meta.url));
const B64URL = /^[A-Za-z0-9_-]*$/;
const HASH = /^[A-Za-z0-9_-]{43}$/;
const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const escape = (text) => String(text).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/** The bytes a base64url text stands for, where it is written as the executor writes it and its length is within [least, most]; else null. */
export function bytesOf(text, least, most = least) {
  if (typeof text !== 'string' || !B64URL.test(text)) return null;
  const b = Buffer.from(text, 'base64url');
  if (b.toString('base64url') !== text || b.length < least || b.length > most) return null;
  return new Uint8Array(b);
}

/** Whether an object has exactly these members. */
const only = (v, keys) => isObject(v) && Object.keys(v).length === keys.length && keys.every((k) => Object.hasOwn(v, k));

/** Bytes in base32 (RFC 4648, section 6), with no padding. */
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32(bytes) {
  let out = '';
  let held = 0;
  let bits = 0;
  for (const b of bytes) {
    held = (held << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32[(held >>> bits) & 31];
    }
    held &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32[(held << (5 - bits)) & 31];
  return out;
}
const RECOVERY_FORM = new RegExp(`^[A-Z2-7]{${(RECOVERY_BYTES * 8) / 5}}$`);

/** A recovery code as it was typed, in the form its hash was made from: its 32 characters, in capitals, with the spaces and hyphens taken out; or null where it is not one (X276). */
export function recoveryText(typed) {
  if (typeof typed !== 'string' || typed.length > 256) return null;
  const text = typed.replace(/[\s-]/g, '').toUpperCase();
  return RECOVERY_FORM.test(text) ? text : null;
}

/** What says that a state file holds an owner in the form of the builds before the plain passkey (never released). */
export const isOldOwner = (v) => isObject(v) && Object.hasOwn(v, 'routingPublicKey');

/**
 * The owner as the executor keeps it, or {problem} (X226): the passkey's
 * identifier, in base64url; its public key as a JWK, in exactly the form
 * the library takes for a passkey's key (ES256, RS256 or Ed25519; the
 * method is the key's "alg"); and the SHA-256 of the recovery code, in
 * base64url.
 */
export function readOwner(v) {
  if (!only(v, ['credentialId', 'key', 'recoveryHash'])) return { problem: 'the owner is not {credentialId, key, recoveryHash}' };
  if (!bytesOf(v.credentialId, 1, 1023)) return { problem: 'credentialId is not 1 to 1023 bytes in base64url' };
  try {
    checkKey(v.key, PASSKEY_METHODS, 'key');
  } catch (e) {
    return { problem: `key is not a passkey's public key as a JWK (${e.message})` };
  }
  if (typeof v.recoveryHash !== 'string' || !HASH.test(v.recoveryHash)) return { problem: 'recoveryHash is not a SHA-256 in base64url' };
  const key = {};
  for (const name of Object.keys(v.key).sort()) key[name] = v.key[name];
  return { owner: { credentialId: v.credentialId, key, recoveryHash: v.recoveryHash } };
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

/** The files the pages load, by their address: the script, its steps, and the library's own files (X224). */
function pageFiles() {
  const files = new Map();
  const js = (path, file) => files.set(path, readFileSync(file));
  js(`${OWNER_PATH}/page.js`, join(HERE, 'owner-page.mjs'));
  js(`${OWNER_PATH}/steps.js`, join(HERE, 'owner-steps.mjs'));
  for (const f of readdirSync(LIBRARY)) if (f.endsWith('.js')) js(`${OWNER_PATH}/lib/provared/${f}`, join(LIBRARY, f));
  return files;
}

/**
 * The owner's check by passkey, for openFrontDoor.
 *
 * issuer     the executor's public address: the origin every signature must name, and its host the relying party
 * resource   the address a client is given for the executor, and "clients" the clients the settings list: what the setup page says to do next
 * store      {owner() -> the owner or null, setup() -> {hash, expires} or null, setOwner(owner)}: the front door's state file
 * withNote   (request, note) -> the same waiting request with the note sealed into it, as the text for the page's form; null where the text is not a request waiting at the page (X228)
 * clientOf   (request) -> the client of a request waiting at the page, or null where the text is not one
 * page, json the front door's ways to answer with a page and with JSON
 * hashOf     SHA-256 in base64url, as the front door keeps its hashes
 */
export function openPasskeyCheck({ issuer, resource = `${issuer}/mcp`, clients = [], now = Date.now, log = () => {}, store, withNote, clientOf = () => null, page, json, hashOf }) {
  const files = pageFiles();
  const { host, hostname } = new URL(issuer);
  /**
   * A challenge is not kept here: it is sealed into its request, in the
   * page's form (X273). Kept here, until they end, are only the challenges
   * whose signature passed, so that none passes twice. Only the owner can
   * add to them, so they need no cap.
   */
  const used = new Map();
  const tidy = () => {
    const t = now();
    for (const [k, expires] of used) if (expires <= t) used.delete(k);
  };
  const refuse = (res, status, code, message, extra = {}) => {
    log({ event: 'oauth-refused', code });
    json(res, status, { error: code, message }, extra);
  };
  /** The host a client is known by: that of its metadata document's address. */
  const hostOf = (client) => {
    try {
      return new URL(client).host;
    } catch {
      return 'a client';
    }
  };
  const clientHosts = [...new Set(clients.map(hostOf))];

  const setupPage = [
    `<p>This page makes the owner of the executor at ${escape(host)}: a passkey, and a recovery code. The executor keeps the passkey's public key and a hash of the recovery code, and nothing that could stand in for either.</p>`,
    `<p>The passkey belongs to ${escape(host)}. If the executor's public address changes, the passkey no longer works there; the recovery code still approves a connection.</p>`,
    // Shown by the page's script where a request waits that an authorisation page left in this browser (X272): the owner is shown that page again, and approves there or not.
    '<form method="post" action="/oauth/authorize" id="owner-review" hidden>',
    '<input type="hidden" name="request" id="owner-review-request" value="">',
    '<p><button type="submit" name="decision" value="show">Review the connection that is waiting</button></p>',
    '</form>',
    '<p><button type="button" id="owner-setup">Make the passkey</button></p>',
    '<p id="owner-status" role="status"></p>',
    '<pre id="owner-recovery" hidden></pre>',
    `<p id="owner-next" hidden>Next: add ${escape(resource)} in ${escape(clientHosts.length > 0 ? clientHosts.join(' or ') : 'a client the settings list')}, and approve that connection with this passkey.</p>`,
    `<script type="module" src="${OWNER_PATH}/page.js"></script>`,
  ].join('\n');

  /** Whether a setup with this code is refused: no, while no owner exists and the link's code is given before it ends (X218, X223). Answers the refusal. */
  function linkRefused(res, v) {
    if (store.owner()) {
      refuse(res, 409, 'owner-exists', 'An owner is already set up on this executor. A second setup is refused unless the owner is reset on the server.');
      return true;
    }
    const setup = store.setup();
    if (!setup || setup.expires <= now()) {
      refuse(res, 403, 'setup-ended', 'This setup link has been used or has ended. Make a new one on the server.');
      return true;
    }
    if (!isObject(v) || typeof v.code !== 'string' || !sameText(hashOf(v.code), setup.hash)) {
      refuse(res, 403, 'setup-refused', 'This is not the code of the setup link.');
      return true;
    }
    return false;
  }

  /** POST /oauth/owner/link (X271): whether the link still works, before the page makes a passkey; and, where the page holds a request, whether it still waits, and whose it is (X272). */
  function linkOpen(res, v) {
    if (linkRefused(res, v)) return;
    const withRequest = Object.hasOwn(v, 'request');
    if (!only(v, withRequest ? ['code', 'request'] : ['code']) || (withRequest && typeof v.request !== 'string')) return refuse(res, 400, 'bad-request', 'Send {"code": "<the code after the # of the link>"} and, where the page holds one, "request".');
    const client = withRequest ? clientOf(v.request) : null;
    json(res, 200, client === null ? { link: 'open' } : { link: 'open', waiting: hostOf(client) });
  }

  /** POST /oauth/owner/setup (X271): once, with the link's code, while no owner exists. With a request that waits at the page, the same message approves it (X272). */
  function setUp(res, v) {
    if (linkRefused(res, v)) return;
    const withRequest = Object.hasOwn(v, 'request');
    if (!only(v, withRequest ? ['code', 'credentialId', 'key', 'request'] : ['code', 'credentialId', 'key']) || (withRequest && typeof v.request !== 'string')) return refuse(res, 400, 'bad-request', 'The owner is not in the form the page sends: {code, credentialId, key} and, where the page holds one, request.');
    // The code is the executor's own, from Node.js's random source; only its hash is kept (X276).
    const recovery = base32(randomBytes(RECOVERY_BYTES));
    const read = readOwner({ credentialId: v.credentialId, key: v.key, recoveryHash: hashOf(recovery) });
    if (read.problem) return refuse(res, 400, 'bad-request', `The owner is not in the form the page sends: ${read.problem}.`);
    try {
      store.setOwner({ ...read.owner, created: now() });
    } catch {
      // The state file could not be written: there is no owner, and the link still works.
      return refuse(res, 500, 'not-written', 'The executor could not write its state, so no owner was set up. The link still works: try again.');
    }
    // The request the page sent with the setup, where it still waits, is approved by this setup: the page's form then needs no passkey. The note is under the request's seal, and names the owner it was made for. A request that has ended is not approved, and the owner is set up all the same: by now the passkey has been made.
    const approved = withRequest ? withNote(v.request, { setup: read.owner.credentialId }) : null;
    log({ event: 'owner-set', approves: approved !== null });
    json(res, 200, { owner: 'set', recoveryCode: recovery.match(/.{4}/g).join('-'), ...(withRequest ? { request: approved } : {}) });
  }

  /** POST /oauth/owner/challenge (X273). */
  function challengeFor(res, v) {
    const owner = store.owner();
    if (!owner) return refuse(res, 409, 'no-owner', 'No owner is set up on this executor yet.');
    // The challenge: sealed into the request it is for, which the page puts in its form in place of the one it had. A request so has one challenge, and a new one takes the old one's place; nothing is kept here.
    const challenge = randomBytes(32).toString('base64url');
    const request = only(v, ['request']) && typeof v.request === 'string' ? withNote(v.request, { challenge, expires: now() + CHALLENGE_LIFE }) : null;
    if (request === null) return refuse(res, 400, 'bad-request', 'Send {"request": "<the request of a page waiting for the owner, as its form holds it>"}.');
    // With it, which passkey to ask: its identifier, which is no secret.
    return json(res, 200, { challenge, request, credentialId: owner.credentialId });
  }

  return {
    /** The authorisation page runs the script from the executor's own address, and fetches from there only (X224). */
    scripts: true,
    form: () =>
      [
        `<input type="hidden" name="${FIELD_CHALLENGE}" value="">`,
        `<input type="hidden" name="${FIELD_AUTHENTICATOR_DATA}" value="">`,
        `<input type="hidden" name="${FIELD_CLIENT_DATA}" value="">`,
        `<input type="hidden" name="${FIELD_SIGNATURE}" value="">`,
        ...(store.owner()
          ? [
              '<p>Approve asks for the owner\'s passkey. Without the passkey, type the recovery code here first:</p>',
              `<p><label>Recovery code <input type="text" name="${FIELD_RECOVERY}" id="owner-recovery-code" autocomplete="off" spellcheck="false"></label></p>`,
            ]
          : [
              // The page's script says more here, where this browser holds the setup link (X272).
              '<p id="owner-first">This executor has no owner yet, so nothing can be approved here. Its owner is made by the setup link, which the command "provared-mcp-executor owner" prints on the server. If you have that link, open it in this browser within 10 minutes: it shows this connection again, and one passkey prompt then makes the owner and approves it.</p>',
              '<pre id="owner-recovery" hidden></pre>',
            ]),
        '<p id="owner-status" role="status"></p>',
        `<script type="module" src="${OWNER_PATH}/page.js"></script>`,
      ].join('\n'),
    /**
     * Whether the form's fields prove the owner, for this request (X274).
     * "note" is what the request's seal holds of the check's. One of three
     * things proves the owner: the request was approved by the setup that
     * made this owner (X272); the recovery code (X276); or the passkey's
     * signature over this executor's own challenge for this request, with
     * the issuer as the origin and its host as the relying party, the user
     * verified (X273). The signature is checked before anything is kept,
     * and a challenge passes once.
     */
    async check(fields, { origin, note }) {
      tidy();
      const owner = store.owner();
      if (!owner) return false;
      if (isObject(note) && typeof note.setup === 'string') return sameText(note.setup, owner.credentialId);
      const typed = fields.get(FIELD_RECOVERY) ?? '';
      if (typed.trim() !== '') {
        const recovery = recoveryText(typed);
        return recovery !== null && sameText(hashOf(recovery), owner.recoveryHash);
      }
      const text = fields.get(FIELD_CHALLENGE) ?? '';
      if (!isObject(note) || typeof note.challenge !== 'string' || !sameText(text, note.challenge) || !(note.expires > now()) || used.has(text)) return false;
      const signedBytes = bytesOf(text, 32);
      const authenticatorData = bytesOf(fields.get(FIELD_AUTHENTICATOR_DATA) ?? '', 37, 1024);
      const clientDataJSON = bytesOf(fields.get(FIELD_CLIENT_DATA) ?? '', 1, 4096);
      const signature = bytesOf(fields.get(FIELD_SIGNATURE) ?? '', 1, 1024);
      if (!signedBytes || !authenticatorData || !clientDataJSON || !signature) return false;
      let checked;
      try {
        checked = await checkAssertion({ key: owner.key, rpId: hostname, origin, signedBytes, authenticatorData, clientDataJSON, signature });
      } catch {
        return false;
      }
      if (checked !== 'valid' || used.has(text)) return false;
      used.set(text, note.expires);
      return true;
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
      if (req.method !== 'POST' || ![LINK_PATH, SETUP_PATH, CHALLENGE_PATH].includes(path)) {
        req.resume();
        return json(res, 405, { error: 'not-allowed', message: 'The owner\'s addresses take GET for the pages and their files, and POST for the three exchanges.' });
      }
      // As the owner's answer at the page (X212): only from the executor's own pages.
      if (req.headers.origin !== issuer) {
        req.resume();
        return refuse(res, 403, 'origin-refused', 'Only the executor\'s own pages may send this.');
      }
      const v = await readJson(req);
      if (v === undefined) return refuse(res, 400, 'bad-request', 'The body must be JSON (application/json), at most 16 KiB.');
      if (path === LINK_PATH) return linkOpen(res, v);
      if (path === SETUP_PATH) return setUp(res, v);
      return challengeFor(res, v);
    },
  };
}
