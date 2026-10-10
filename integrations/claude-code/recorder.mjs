#!/usr/bin/env node
// The recorder beside Claude Code: a small service on this computer that
// holds the stub writer open on one book, under one slip the person signed,
// and answers the hook (hook.mjs) that Claude Code runs before and after
// each tool call. Before a call, the check before acting says whether the
// call is within the slip; after it, a stub is written. Whoever runs it
// seals the book when they choose.
//
//   node recorder.mjs keys     make the agent's keys and the recorder's keys, and print the agent's public keys
//   node recorder.mjs start    run the service (needs slip.json in the folder)
//   node recorder.mjs ensure   start the service in the background if it is not running
//   node recorder.mjs status   what the service holds
//   node recorder.mjs seal     seal the book now, with the recorder's three keys
//   node recorder.mjs stop     stop the service
//
// The folder (PROVARED_CLAUDE_CODE_DIR, or ~/.provared/claude-code) holds:
//   agent-keys.jwk      the agent's two private keys (never share)
//   recorder-keys.jwk   the recorder's three private keys, for seals (never share)
//   slip.json           the signed slip, from the signing page
//   book.jsonl          the book: the slip, then a stub for each tool call, and seals
//
// It listens on 127.0.0.1 only. Any program on this computer could ask it
// to write a stub: the record is of what this computer's agent did, as its
// own software says. Nothing here reaches the network.

import { spawn } from 'node:child_process';
import nodeCrypto from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkBook, fingerprint, fromBase64url, keySetFingerprint, openRecorder, thumbprint, writeBook, writeSeal } from '../../src/index.js';

const subtle = globalThis.crypto.subtle;
const SLH = 'SLH-DSA-SHA2-256s';
const MAX_BODY = 1024 * 1024;

export const DEFAULT_FOLDER = process.env.PROVARED_CLAUDE_CODE_DIR || join(homedir(), '.provared', 'claude-code');
export const DEFAULT_PORT = Number(process.env.PROVARED_CLAUDE_CODE_PORT || 8794);

const files = (folder) => ({
  agentKeys: join(folder, 'agent-keys.jwk'),
  recorderKeys: join(folder, 'recorder-keys.jwk'),
  slip: join(folder, 'slip.json'),
  book: join(folder, 'book.jsonl'),
});

// --- keys kept between runs, as JSON Web Keys in a file the person keeps ---

async function newWebKey(alg) {
  const pair = await subtle.generateKey({ name: alg }, true, ['sign', 'verify']);
  return subtle.exportKey('jwk', pair.privateKey);
}

function publicOf(privateJwk) {
  if (privateJwk.kty === 'OKP') return { alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: privateJwk.x };
  if (privateJwk.kty === 'AKP' && privateJwk.alg === 'ML-DSA-87') return { alg: 'ML-DSA-87', kty: 'AKP', pub: privateJwk.pub };
  if (privateJwk.kty === 'AKP' && privateJwk.alg === SLH) return { alg: SLH, kty: 'AKP', pub: privateJwk.pub };
  throw new Error('a key in the file is of a kind this recorder does not keep.');
}

async function importWebKey(privateJwk) {
  const name = privateJwk.kty === 'OKP' ? 'Ed25519' : 'ML-DSA-87';
  return subtle.importKey('jwk', privateJwk, { name }, false, ['sign']);
}

/** Make the agent's keys, if the file does not exist, and give back the public key set. */
export async function makeAgentKeys(folder) {
  const path = files(folder).agentKeys;
  if (!existsSync(path)) {
    mkdirSync(folder, { recursive: true });
    const jwks = [await newWebKey('Ed25519'), await newWebKey('ML-DSA-87')];
    writeFileSync(path, JSON.stringify({ about: 'The private keys of the agent recorded by Provared. Never share this file.', keys: jwks }), { mode: 0o600 });
  }
  return loadAgentKeys(folder);
}

export async function loadAgentKeys(folder) {
  const { keys } = JSON.parse(readFileSync(files(folder).agentKeys, 'utf8'));
  return { keys: keys.map(publicOf), privateKeys: await Promise.all(keys.map(importWebKey)) };
}

/** Make the recorder's three keys, if the file does not exist, and give back the key set. */
export async function makeRecorderKeys(folder) {
  const path = files(folder).recorderKeys;
  if (!existsSync(path)) {
    mkdirSync(folder, { recursive: true });
    const slh = nodeCrypto.generateKeyPairSync('slh-dsa-sha2-256s');
    const jwks = [await newWebKey('Ed25519'), await newWebKey('ML-DSA-87'), { ...slh.privateKey.export({ format: 'jwk' }), alg: SLH }];
    writeFileSync(path, JSON.stringify({ about: 'The private keys of the recorder that seals the book. Never share this file.', keys: jwks }), { mode: 0o600 });
  }
  return loadRecorderKeys(folder);
}

export async function loadRecorderKeys(folder) {
  const { keys } = JSON.parse(readFileSync(files(folder).recorderKeys, 'utf8'));
  const privateKeys = [await importWebKey(keys[0]), await importWebKey(keys[1]), nodeCrypto.createPrivateKey({ key: keys[2], format: 'jwk' })];
  return { keys: keys.map(publicOf), privateKeys };
}

// --- the book on disk ---

function saveBook(folder, text) {
  const path = files(folder).book;
  writeFileSync(`${path}.tmp`, text);
  renameSync(`${path}.tmp`, path);
}

/** The slip the person signed, its fingerprint, and the thumbprint of their passkey (read from the slip itself). */
export async function loadSlip(folder) {
  const slip = JSON.parse(readFileSync(files(folder).slip, 'utf8'));
  const content = JSON.parse(new TextDecoder().decode(fromBase64url(slip.payload)));
  return { slip, fingerprint: await fingerprint(fromBase64url(slip.payload)), issuerKey: await thumbprint(content.issuer.key), content };
}

// --- the service ---

/**
 * Open the stub writer on the folder's book and serve it on 127.0.0.1.
 * @param {{folder?: string, port?: number, name?: string}} o port 0 takes any free port
 * @returns {Promise<{port: number, close: () => Promise<void>, recorder: object}>}
 */
export async function startService({ folder = DEFAULT_FOLDER, port = DEFAULT_PORT, name = 'The recorder beside the coding agent' } = {}) {
  const f = files(folder);
  if (!existsSync(f.slip)) throw new Error(`There is no signed slip at ${f.slip}. Sign one on the signing page and save it there.`);
  const { slip, fingerprint: slipFingerprint, issuerKey, content } = await loadSlip(folder);
  const agent = await loadAgentKeys(folder);
  const sealer = await makeRecorderKeys(folder);
  if (JSON.stringify(content.agent.keys) !== JSON.stringify(agent.keys)) {
    throw new Error('The slip names other keys than the agent\'s keys in this folder. Sign a slip with the keys that "keys" prints.');
  }
  if (!existsSync(f.book)) saveBook(folder, writeBook([{ slip }]));
  const sealKeys = [await keySetFingerprint(sealer.keys)];
  const options = { sealKeys };
  const recorder = await openRecorder({ book: readFileSync(f.book, 'utf8'), slip: slipFingerprint, privateKeys: agent.privateKeys, issuerKeys: [issuerKey], options });
  const started = new Date().toISOString();
  let count = 0;

  async function seal() {
    const book = recorder.book();
    const result = await checkBook(book, { issuerKeys: [issuerKey], sealKeys });
    const seals = result.entries.filter((e) => e.kind === 'seal' && e.problems.length === 0);
    const previous = seals.length ? seals[seals.length - 1].fingerprint : undefined;
    const sealed = await writeSeal(book, { by: { keys: sealer.keys, name }, previous, when: Date.now() }, sealer.privateKeys);
    // No outside time-stamp is put beside the seal here (a seal without one has no "stamps" member).
    await recorder.add({ seal: sealed.record });
    saveBook(folder, recorder.book());
    return { fingerprint: sealed.fingerprint, entries: recorder.book().split('\n').filter(Boolean).length };
  }

  const server = createServer(async (req, res) => {
    const send = (code, body) => {
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    try {
      if (req.method === 'GET' && req.url === '/status') {
        return send(200, {
          slip: slipFingerprint,
          issuer: issuerKey,
          sealer: sealKeys[0],
          agent: content.agent.name,
          entries: recorder.book().split('\n').filter(Boolean).length,
          recordedSinceStart: count,
          started,
          folder,
        });
      }
      if (req.method !== 'POST') return send(404, { error: 'not found' });
      let body = '';
      for await (const chunk of req) {
        body += chunk;
        if (body.length > MAX_BODY) return send(413, { error: 'too large' });
      }
      const given = body ? JSON.parse(body) : {};
      if (req.url === '/before') {
        const answer = await recorder.before(requestFrom(given));
        return send(200, answer);
      }
      if (req.url === '/record') {
        try {
          const written = await recorder.record(requestFrom(given), given.when ? { when: given.when } : {});
          count++;
          saveBook(folder, recorder.book());
          return send(200, { seq: written.seq, fingerprint: written.fingerprint });
        } catch (e) {
          return send(409, { error: e.message, code: e.code });
        }
      }
      if (req.url === '/seal') return send(200, await seal());
      if (req.url === '/stop') {
        send(200, { stopped: true });
        setTimeout(() => server.close(), 50);
        return undefined;
      }
      return send(404, { error: 'not found' });
    } catch (e) {
      return send(500, { error: e.message });
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  return {
    port: server.address().port,
    recorder,
    seal,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

function requestFrom(given) {
  const request = { action: String(given.action ?? '') };
  if (Array.isArray(given.details)) request.details = given.details;
  if (given.amount) request.amount = given.amount;
  if (given.with) request.with = given.with;
  return request;
}

// --- the commands ---

async function ask(port, path, method = 'GET', body) {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(10000) });
  return response.json();
}

async function running(port) {
  try {
    return await ask(port, '/status');
  } catch {
    return null;
  }
}

async function main(argv) {
  const command = argv[0];
  const folder = DEFAULT_FOLDER;
  const port = DEFAULT_PORT;
  if (command === 'keys') {
    const agent = await makeAgentKeys(folder);
    await makeRecorderKeys(folder);
    console.log(`The agent's keys are in ${files(folder).agentKeys}, and the recorder's in ${files(folder).recorderKeys}. Never share either file.`);
    console.log('\nThe agent\'s two public keys, to paste into the signing page as "agent.keys":\n');
    console.log(JSON.stringify(agent.keys));
    return 0;
  }
  if (command === 'start') {
    const service = await startService({ folder, port });
    const status = await ask(service.port, '/status');
    console.log(`The Provared recorder beside Claude Code is running on http://127.0.0.1:${service.port}`);
    console.log(`  Slip ${status.slip}, signed by the passkey ${status.issuer}; the book holds ${status.entries} entries.`);
    console.log('  Press Ctrl and C to stop. Each tool call Claude Code makes is checked against the slip and recorded.');
    return null;
  }
  if (command === 'ensure') {
    if (await running(port)) return 0;
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', fileURLToPath(import.meta.url), 'start'], { detached: true, stdio: 'ignore', env: process.env });
    child.unref();
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 250));
      if (await running(port)) return 0;
    }
    console.error('The recorder did not start. Run "node recorder.mjs start" to see why.');
    return 1;
  }
  const status = await running(port);
  if (command === 'status') {
    if (!status) {
      console.log(`The recorder is not running (nothing answers on 127.0.0.1:${port}).`);
      return 1;
    }
    console.log(JSON.stringify(status, null, 2));
    return 0;
  }
  if (command === 'seal') {
    if (status) {
      const sealed = await ask(port, '/seal', 'POST', {});
      console.log(`Sealed: entry ${sealed.entries} is the seal ${sealed.fingerprint}.`);
      return 0;
    }
    const service = await startService({ folder, port: 0 });
    const sealed = await service.seal();
    await service.close();
    console.log(`Sealed (the service was not running, so the book was opened here): entry ${sealed.entries} is the seal ${sealed.fingerprint}.`);
    return 0;
  }
  if (command === 'stop') {
    if (!status) return 0;
    await ask(port, '/stop', 'POST', {});
    console.log('Stopped.');
    return 0;
  }
  console.log('Usage: node recorder.mjs keys | start | ensure | status | seal | stop');
  return 2;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.removeAllListeners('warning');
  main(process.argv.slice(2)).then((code) => {
    if (code !== null) process.exit(code);
  }, (e) => {
    console.error(e.message);
    process.exit(1);
  });
}
