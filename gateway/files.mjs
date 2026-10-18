// What the gateway keeps on disk: the agents' and the recorder's keys, the
// slips, and each agent's book, appended line by line.

import nodeCrypto from 'node:crypto';
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, readSync, renameSync, statSync, writeFileSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';
import { fingerprint, fromBase64url, signerFromKey, thumbprint } from 'provared';

const subtle = globalThis.crypto.subtle;
const SLH = 'SLH-DSA-SHA2-256s';

// On Windows, writing to a file is refused while another program (a virus
// scanner, a program reading the book) holds it open in some ways, so each
// write is tried again for up to ten seconds, as the recorder beside Claude
// Code does.
const BUSY = ['EPERM', 'EBUSY', 'EACCES'];
export function untilFree(step, seconds = 10) {
  const pause = new Int32Array(new SharedArrayBuffer(4));
  const deadline = Date.now() + seconds * 1000;
  for (let wait = 10; ; wait = Math.min(wait * 2, 200)) {
    try {
      return step();
    } catch (e) {
      if (!BUSY.includes(e.code) || Date.now() >= deadline) throw e;
      Atomics.wait(pause, 0, 0, wait);
    }
  }
}

// --- keys, as JSON Web Keys in a file only its owner may read ---

function publicOf(jwk) {
  if (jwk?.kty === 'OKP' && jwk.crv === 'Ed25519') return { alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: jwk.x };
  if (jwk?.kty === 'AKP' && jwk.alg === 'ML-DSA-87') return { alg: 'ML-DSA-87', kty: 'AKP', pub: jwk.pub };
  if (jwk?.kty === 'AKP' && jwk.alg === SLH) return { alg: SLH, kty: 'AKP', pub: jwk.pub };
  throw new Error('a key in the file is of a kind the gateway does not keep.');
}

async function newWebKey(alg) {
  const pair = await subtle.generateKey({ name: alg }, true, ['sign', 'verify']);
  return subtle.exportKey('jwk', pair.privateKey);
}

/**
 * Make a key file if there is none: two keys for an agent (Ed25519, ML-DSA-87),
 * or three for the recorder that seals (and SLH-DSA-SHA2-256s). Gives back
 * the public keys.
 */
export async function makeKeyFile(path, kind) {
  if (!existsSync(path)) {
    mkdirSync(dirname(path), { recursive: true });
    const jwks = [await newWebKey('Ed25519'), await newWebKey('ML-DSA-87')];
    if (kind === 'recorder') jwks.push({ ...nodeCrypto.generateKeyPairSync('slh-dsa-sha2-256s').privateKey.export({ format: 'jwk' }), alg: SLH });
    const about = kind === 'recorder' ? 'The private keys with which the gateway seals its books. Never share this file.' : 'The private keys of an agent, held by the gateway. Never share this file.';
    writeFileSync(path, JSON.stringify({ about, keys: jwks }), { mode: 0o600, flag: 'wx' });
  }
  return (await loadKeyFile(path, kind)).keys;
}

/**
 * Read a key file: the public keys, and each private key wrapped as a signer,
 * so that it takes the same path as a key held elsewhere.
 */
export async function loadKeyFile(path, kind) {
  let jwks;
  try {
    jwks = JSON.parse(readFileSync(path, 'utf8')).keys;
  } catch (e) {
    throw new Error(`The key file ${path} could not be read as a key file (${e.code ?? 'not JSON'}).`);
  }
  const count = kind === 'recorder' ? 3 : 2;
  if (!Array.isArray(jwks) || jwks.length !== count) throw new Error(`The key file ${path} must hold ${count} keys.`);
  const keys = jwks.map(publicOf);
  const order = ['Ed25519', 'ML-DSA-87', SLH].slice(0, count);
  if (!keys.every((k, i) => k.alg === order[i])) throw new Error(`The keys in ${path} must be ${order.join(', then ')}.`);
  const privateKeys = [];
  for (const [i, jwk] of jwks.entries()) {
    const alg = order[i];
    const key = alg === SLH ? nodeCrypto.createPrivateKey({ key: jwk, format: 'jwk' }) : await subtle.importKey('jwk', jwk, { name: alg }, false, ['sign']);
    privateKeys.push(signerFromKey(alg, key, keys[i]));
  }
  return { keys, privateKeys };
}

// --- slips ---

/** A slip as the signing page saves it, or a book's line that holds one. */
export function slipFrom(value, where) {
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch {
      throw new Error(`${where} is not JSON. It should be the file the signing page saves (slip.json).`);
    }
  }
  if (value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 1 && Object.hasOwn(value, 'slip')) value = value.slip;
  if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.payload !== 'string' || !Array.isArray(value.signatures)) {
    throw new Error(`${where} does not hold a signed permission (a slip).`);
  }
  return value;
}

/** The slip's fingerprint, its content as it states it, and the thumbprint of the passkey named in it. */
export async function aboutSlip(slip) {
  const payload = fromBase64url(slip.payload);
  const content = JSON.parse(new TextDecoder().decode(payload));
  return { slip, fingerprint: await fingerprint(payload), content, issuerKey: await thumbprint(content.issuer.key) };
}

// --- the book file ---

// The last characters of a text, as bytes, not cut in the middle of a character written as two halves.
function tailOf(text) {
  let end = text.slice(-1024);
  if (/^[\udc00-\udfff]/.test(end)) end = end.slice(1);
  return Buffer.from(end);
}

/**
 * A book file that only grows. The gateway alone writes it: each save appends
 * what the book gained since the last. Where the file is no longer as the
 * gateway left it (its size, or its last bytes, changed), nothing is written
 * and the save fails: someone else changed it.
 * @param {string} path
 * @param {string} onDisk the text the file holds now ('' where there is no file)
 */
export function bookFile(path, onDisk) {
  let chars = onDisk.length;
  let bytes = Buffer.byteLength(onDisk);
  let tail = tailOf(onDisk);
  const asLeft = () => {
    let size;
    try {
      size = statSync(path).size;
    } catch (e) {
      if (e.code === 'ENOENT') return bytes === 0;
      throw e;
    }
    if (size !== bytes) return false;
    if (bytes === 0) return true;
    const end = Buffer.alloc(Math.min(tail.length, bytes));
    const fd = untilFree(() => openSync(path, 'r'));
    try {
      readSync(fd, end, 0, end.length, bytes - end.length);
    } finally {
      closeSync(fd);
    }
    return end.equals(tail.subarray(tail.length - end.length));
  };
  return {
    path,
    /** Whether the file is still as the gateway left it. */
    intact: () => asLeft(),
    /** Whether the file holds the whole of this text. */
    holds: (text) => text.length === chars,
    save(text) {
      if (text.length === chars) return;
      if (text.length < chars) throw new Error('The book became shorter than the file, which a book never does.');
      if (!asLeft()) throw new Error(`The book file ${path} is not as the gateway left it: something else changed it. The gateway writes no more to it.`);
      const more = text.slice(chars);
      mkdirSync(dirname(path), { recursive: true });
      // Made sure to be on the disk before the call's line in the journal says it is done.
      const fd = untilFree(() => openSync(path, 'a'));
      try {
        writeSync(fd, more);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      chars = text.length;
      bytes += Buffer.byteLength(more);
      tail = tailOf(text);
    },
  };
}

/** Read a file of text, or '' where there is none. */
export function readIfThere(path) {
  try {
    return untilFree(() => readFileSync(path, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') return '';
    throw e;
  }
}

/** Replace a small file whole, through a temporary file. */
export function replaceFile(path, text) {
  untilFree(() => writeFileSync(`${path}.tmp`, text));
  untilFree(() => renameSync(`${path}.tmp`, path));
}
