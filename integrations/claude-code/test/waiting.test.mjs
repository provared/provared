// The waiting recorder (waiting.mjs) and a first permission handed over
// through its feed: the checks that need no permission in force, shared with
// the full recorder; then the permission waits, in waiting-permissions.json,
// for the person's thumbprint and "yes" on this computer. Nothing is taken
// from the feed: no slip.json, no list of trusted passkeys, no book. Every
// test works in a temporary folder and on a port of its own.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { assembleCancellation, prepareCancellation, thumbprint } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { feedReader } = await import('../feed.mjs');
const { makeAgentKeys, readWaitingPermissions } = await import('../recorder.mjs');
const { startWaiting } = await import('../waiting.mjs');
const { freshWorld, runHook, signSlip, status, tempFolder } = await import('./world.mjs');

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

async function waitingWorld(more = LOCAL) {
  const w = await freshWorld();
  const waiting = await startWaiting({ folder: w.folder, port: 0, ...more });
  const reader = feedReader({ address: `http://127.0.0.1:${waiting.port}`, token: tokenOf(w.folder) });
  const hand = async (record) => {
    const r = await reader.post('/hand-over', record);
    assert.equal(r.proved, true);
    return r.body;
  };
  return { ...w, waiting, port: waiting.port, reader, hand };
}

const neverWritten = (folder) => {
  for (const name of ['slip.json', 'trusted-passkeys.json', 'book.jsonl']) assert.equal(existsSync(join(folder, name)), false, `${name} is not written`);
};

test('a sound first permission handed over to the waiting recorder waits for "yes", and slip.json, the trusted list and the book are not written', async () => {
  const w = await waitingWorld();
  try {
    const T = await thumbprint(w.passkey.key);
    const slip = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, purpose: 'The first permission.' });
    const said = await w.hand({ kind: 'renewal', slip });
    assert.equal(said.outcome, 'refused', JSON.stringify(said));
    assert.equal(said.code, 'waits-for-yes');
    assert.equal(said.thumbprint, T);
    assert.match(said.fingerprint, /^[A-Za-z0-9_-]{43}$/);
    assert.match(said.message, /admit-passkey/);
    neverWritten(w.folder);
    const waiting = readWaitingPermissions(w.folder);
    assert.equal(waiting.length, 1);
    assert.equal(waiting[0].fingerprint, said.fingerprint);
    assert.equal(waiting[0].thumbprint, T);
    assert.equal((await status(w.port)).waitingPermissions, 1);
    // Still waiting: every call is refused, and the feed lists no book.
    assert.equal((await status(w.port)).waiting, true);
    assert.equal((await runHook(w.port, 'PreToolUse', 'Read', { file_path: 'README.md' })).decision.permissionDecision, 'deny');
    assert.deepEqual((await w.reader.get('/books')).body.books, []);
    // Handed over again: it waits, once.
    assert.equal((await w.hand({ kind: 'renewal', slip })).code, 'waits-for-yes');
    assert.equal(readWaitingPermissions(w.folder).length, 1);
  } finally {
    await w.waiting.close();
  }
});

test('a permission not kept, because one from the same passkey that starts no earlier waits already, is answered "not-kept", not "waits-for-yes"', async () => {
  const w = await waitingWorld();
  try {
    const newer = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, purpose: 'The newer one.' });
    assert.equal((await w.hand({ kind: 'renewal', slip: newer })).code, 'waits-for-yes');
    const older = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, purpose: 'The older one.', from: Date.now() - 120000 });
    const said = await w.hand({ kind: 'renewal', slip: older });
    assert.equal(said.outcome, 'refused', JSON.stringify(said));
    assert.equal(said.code, 'not-kept');
    assert.equal(said.thumbprint, await thumbprint(w.passkey.key));
    assert.match(said.message, /starts no earlier/);
    assert.equal(readWaitingPermissions(w.folder).length, 1, 'only the newer one waits');
  } finally {
    await w.waiting.close();
  }
});

test('the waiting recorder refuses, and keeps nothing of, a permission for other keys, one signed at another address, one that starts too far ahead, one that has ended, and a cancellation', async () => {
  const w = await waitingWorld();
  const elsewhere = await waitingWorld({});
  try {
    const before = snapshot(w.folder);
    const otherKeys = (await makeAgentKeys(tempFolder('provared-cc-other-'))).keys;
    const cases = [
      ['other-agent', w, await signSlip({ agentKeys: otherKeys, passkey: w.passkey })],
      ['starts-later', w, await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, from: Date.now() + 600000, until: Date.now() + 7200000 })],
      ['ended', w, await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, from: Date.now() - 7200000, until: Date.now() - 3600000 })],
      ['not-sound', w, { payload: 'not a permission', signatures: [] }],
      ['other-signing-address', elsewhere, await signSlip({ agentKeys: elsewhere.agent.keys, passkey: elsewhere.passkey })],
    ];
    for (const [code, where, slip] of cases) {
      const said = await where.hand({ kind: 'renewal', slip });
      assert.equal(said.outcome, 'refused', `${code}: ${JSON.stringify(said)}`);
      assert.equal(said.code, code, `${code}: ${said.message}`);
      assert.equal(readWaitingPermissions(where.folder).length, 0, `${code}: nothing waits`);
      neverWritten(where.folder);
    }
    // A cancellation: no permission is in force, so there is nothing to cancel.
    const prepared = await prepareCancellation({ slip: 'A'.repeat(43), when: Date.now() });
    const cancellation = assembleCancellation(prepared, await w.passkey.sign(prepared.challenge));
    const said = await w.hand({ kind: 'cancellation', cancellation });
    assert.equal(said.outcome, 'refused');
    assert.equal(said.code, 'nothing-in-force');
    assert.equal((await w.hand({ kind: 'nonesuch' })).code, 'not-understood');
    assert.deepEqual(snapshot(w.folder), before, 'no file is written');
  } finally {
    await w.waiting.close();
    await elsewhere.waiting.close();
  }
});

test('the waiting recorder\'s /before, /record, /seal, /renew and /new-book refuse with no-permission-yet and write nothing, a permission waiting or not', async () => {
  const w = await waitingWorld();
  try {
    assert.equal((await w.hand({ kind: 'renewal', slip: await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey }) })).code, 'waits-for-yes');
    const before = snapshot(w.folder);
    const post = async (path, body) => {
      const r = await fetch(`http://127.0.0.1:${w.port}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(10000) });
      return { code: r.status, body: await r.json() };
    };
    const asked = await post('/before', { action: 'provared.code.read' });
    assert.equal(asked.code, 200);
    assert.equal(asked.body.allowed, false);
    assert.equal(asked.body.waiting, true);
    assert.deepEqual(asked.body.breaches, []);
    assert.equal(asked.body.problems[0].code, 'no-permission-yet');
    const slip = readWaitingPermissions(w.folder)[0].slip;
    for (const [path, body] of [['/record', { action: 'provared.code.read', details: [] }], ['/seal', {}], ['/renew', { slip }], ['/new-book', {}]]) {
      const r = await post(path, body);
      assert.equal(r.code, 409, path);
      assert.equal(r.body.code, 'no-permission-yet', path);
    }
    assert.equal((await runHook(w.port, 'PostToolUse', 'Read', { file_path: 'README.md' })).code, 2, 'the call after is reported, not recorded');
    assert.deepEqual(snapshot(w.folder), before, 'no file is written');
  } finally {
    await w.waiting.close();
  }
});
