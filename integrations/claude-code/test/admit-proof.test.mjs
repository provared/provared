// POST /admit, and POST /renew with a new passkey, carry the feed's proof
// (feed.mjs): the question and every byte of its body, proved with the
// feed's token from the recorder's folder, in a conversation the recorder
// began, each question once; the answer carries the recorder's proof. A
// program that cannot read the folder cannot have a passkey trusted. Every
// test works in a temporary folder and on a port of its own.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { thumbprint } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { FEED_LABELS, feedHmac, feedReader } = await import('../feed.mjs');
const { readTrusted, readWaitingPermissions, startService } = await import('../recorder.mjs');
const { startWaiting } = await import('../waiting.mjs');
const { freshWorld, runCommand, signSlip, status, tempFolder, world } = await import('./world.mjs');

const LOCAL = { signingOrigins: ['http://localhost'] };
const tokenOf = (folder) => readFileSync(join(folder, 'feed-token'), 'utf8').trim();

/** Every file in the folder and what it holds. */
function snapshot(folder) {
  const all = {};
  for (const name of readdirSync(folder).sort()) {
    const path = join(folder, name);
    all[name] = statSync(path).isFile() ? readFileSync(path, 'utf8') : 'a folder';
  }
  return all;
}

/** A plain POST, as any program on this computer can send it: no proof. */
const plainPost = async (port, path, body) => {
  const r = await fetch(`http://127.0.0.1:${port}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(10000) });
  return { code: r.status, body: await r.json() };
};

/** The feed's headers for one question, proved for "proveFor" (method, path and body), in a new conversation. */
async function provedHeaders(port, token, proveFor, bytes) {
  const mine = randomBytes(32).toString('base64url');
  const hello = await (await fetch(`http://127.0.0.1:${port}/hello`, { headers: { 'Provared-Feed-Hello': mine }, signal: AbortSignal.timeout(10000) })).json();
  const key = feedHmac(Buffer.from(token), FEED_LABELS.key, mine, hello.session);
  const nonce = randomBytes(32).toString('base64url');
  return { 'Content-Type': 'application/json', 'Provared-Feed-Session': hello.session, 'Provared-Feed-Hello': mine, 'Provared-Feed-Nonce': nonce, 'Provared-Feed-Proof': feedHmac(key, FEED_LABELS.questionWithBody, hello.session, nonce, proveFor, bytes).toString('base64url') };
}

const sendWith = async (port, path, headers, bytes) => {
  const r = await fetch(`http://127.0.0.1:${port}${path}`, { method: 'POST', headers, body: bytes, signal: AbortSignal.timeout(10000) });
  return { code: r.status, body: await r.json() };
};

/** A running recorder, with a stranger's permission handed over and waiting for "admit-passkey". */
async function withWaiting() {
  const w = await world([]);
  const service = await startService({ folder: w.folder, port: 0, ...LOCAL });
  const reader = feedReader({ address: `http://127.0.0.1:${service.port}`, token: tokenOf(w.folder) });
  const stranger = await developmentPasskey();
  const T = await thumbprint(stranger.key);
  const theirs = await signSlip({ agentKeys: w.agent.keys, passkey: stranger, purpose: 'A second passkey\'s permission.' });
  const handed = await reader.post('/hand-over', { kind: 'renewal', slip: theirs });
  assert.equal(handed.body.code, 'passkey-not-trusted');
  return { ...w, service, port: service.port, reader, T, theirs, fp: handed.body.fingerprint };
}

test('POST /admit, and POST /renew with a new passkey, without the feed\'s proof are refused, and nothing is written', async () => {
  const w = await withWaiting();
  try {
    const before = { files: snapshot(w.folder), slip: (await status(w.port)).slip };
    for (const [path, body] of [
      ['/admit', { slip: w.theirs, thumbprint: w.T, take: true }],
      ['/admit', { fingerprint: w.fp, thumbprint: w.T, take: true }],
      ['/renew', { slip: w.theirs, newPasskey: true }],
    ]) {
      const r = await plainPost(w.port, path, body);
      assert.equal(r.code, 401, `${path}: ${JSON.stringify(r.body)}`);
      assert.match(r.body.error, /no such conversation: begin one with GET \/hello/);
    }
    assert.equal(readTrusted(w.folder).includes(w.T), false, 'the passkey is not trusted');
    assert.equal((await status(w.port)).slip, before.slip, 'the permission in force is unchanged');
    assert.deepEqual(snapshot(w.folder), before.files, 'no file is written');
    // A renewal from a passkey already trusted needs no proof, as before.
    const next = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, purpose: 'The next permission.' });
    const renewed = await plainPost(w.port, '/renew', { slip: next });
    assert.equal(renewed.code, 200, JSON.stringify(renewed.body));
    assert.notEqual((await status(w.port)).slip, before.slip);
  } finally {
    await w.service.close();
  }
});

test('with the token\'s proof, POST /admit and POST /renew with a new passkey are answered, with the recorder\'s proof', async () => {
  const w = await withWaiting();
  try {
    const checked = await w.reader.post('/admit', { fingerprint: w.fp, thumbprint: w.T, take: false });
    assert.equal(checked.code, 200);
    assert.equal(checked.proved, true, 'the answer carries the recorder\'s proof');
    assert.equal(checked.body.kind, 'renewal');
    assert.equal(readTrusted(w.folder).includes(w.T), false, 'a check takes nothing');
    const renewed = await w.reader.post('/renew', { slip: w.theirs, newPasskey: true });
    assert.equal(renewed.code, 200, JSON.stringify(renewed.body));
    assert.equal(renewed.proved, true);
    assert.equal(renewed.body.slip, w.fp);
    assert.equal(readTrusted(w.folder).includes(w.T), true, 'the new passkey is trusted');
    assert.equal((await status(w.port)).slip, w.fp);
  } finally {
    await w.service.close();
  }
});

test('a proof made for another path or another body is refused, and a question sent twice is refused the second time', async () => {
  const w = await withWaiting();
  try {
    const token = tokenOf(w.folder);
    const before = snapshot(w.folder);
    const body = Buffer.from(JSON.stringify({ slip: w.theirs, newPasskey: true }));
    const other = Buffer.from(JSON.stringify({ slip: w.theirs, newPasskey: true, x: 1 }));
    for (const [what, path, proveFor, proved, sent] of [
      ['proved for /hand-over', '/renew', 'POST /hand-over', body, body],
      ['proved for /admit', '/renew', 'POST /admit', body, body],
      ['proved as a GET', '/renew', 'GET /renew', body, body],
      ['proved over another body', '/renew', 'POST /renew', other, body],
      ['proved for /renew, sent to /admit', '/admit', 'POST /renew', body, body],
    ]) {
      const r = await sendWith(w.port, path, await provedHeaders(w.port, token, proveFor, proved), sent);
      assert.equal(r.code, 401, `${what}: ${JSON.stringify(r.body)}`);
    }
    assert.deepEqual(snapshot(w.folder), before, 'no file is written');
    assert.equal(readTrusted(w.folder).includes(w.T), false);
    // The same question twice: answered once, refused the second time.
    const headers = await provedHeaders(w.port, token, 'POST /renew', body);
    const first = await sendWith(w.port, '/renew', headers, body);
    assert.equal(first.code, 200, JSON.stringify(first.body));
    assert.equal(first.body.slip, w.fp);
    const again = await sendWith(w.port, '/renew', headers, body);
    assert.equal(again.code, 401, JSON.stringify(again.body));
    assert.match(again.body.error, /asked before/);
  } finally {
    await w.service.close();
  }
});

test('the waiting recorder\'s POST /admit needs the feed\'s proof too', async () => {
  const w = await freshWorld();
  const waiting = await startWaiting({ folder: w.folder, port: 0, ...LOCAL });
  try {
    const before = snapshot(w.folder);
    const r = await plainPost(waiting.port, '/admit', { fingerprint: 'F'.repeat(43), thumbprint: await thumbprint(w.passkey.key), take: true });
    assert.equal(r.code, 401, JSON.stringify(r.body));
    assert.deepEqual(snapshot(w.folder), before, 'no file is written');
    const reader = feedReader({ address: `http://127.0.0.1:${waiting.port}`, token: tokenOf(w.folder) });
    const proved = await reader.post('/admit', { fingerprint: 'F'.repeat(43), thumbprint: await thumbprint(w.passkey.key), take: false });
    assert.notEqual(proved.code, 401, JSON.stringify(proved.body));
    assert.equal(proved.proved, true);
  } finally {
    await waiting.close();
  }
});

test('"renew --new-passkey", "use --new-passkey" and "admit-passkey" say so where the feed\'s token cannot be read, and take nothing', async () => {
  const w = await withWaiting();
  try {
    unlinkSync(join(w.folder, 'feed-token'));
    const file = join(tempFolder('provared-cc-proof-'), 'theirs.json');
    writeFileSync(file, JSON.stringify(w.theirs));
    for (const args of [['renew', file, '--new-passkey'], ['use', file, '--new-passkey'], ['admit-passkey', w.T]]) {
      const r = await runCommand(args, { folder: w.folder, port: w.port, input: 'yes\n' });
      assert.notEqual(r.code, 0, `${args[0]}: ${r.out} ${r.err}`);
      assert.match(`${r.out} ${r.err}`, /feed's token .*could not be read/, `${args[0]}: ${r.out} ${r.err}`);
      assert.equal(readTrusted(w.folder).includes(w.T), false, `${args[0]}: nothing is taken`);
    }
    assert.equal(readWaitingPermissions(w.folder).length, 1, 'the permission still waits');
  } finally {
    await w.service.close();
  }
});
