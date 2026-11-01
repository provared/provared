// A record handed over through the feed (POST /hand-over): a renewal or a
// cancellation the person signed elsewhere, which the application kept
// sealed and its uploader hands to the recorder. The recorder checks each
// itself: a renewal only from a passkey this computer already trusts, a
// cancellation only of the permission in force, which the agent's side
// acknowledges in the book. Every test works in a temporary folder and on a
// port of its own.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { assembleCancellation, checkBook, prepareCancellation, thumbprint } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { FEED_LABELS, FEED_MAX_HAND_OVER_BYTES, feedHmac, feedReader } = await import('../feed.mjs');
const { readTrusted, retirePasskey, startService } = await import('../recorder.mjs');
const { runCommand, runHook, signSlip, status, world } = await import('./world.mjs');

const read = (folder, name) => readFileSync(join(folder, name), 'utf8');
const lines = (text) => text.split('\n').filter(Boolean);
const kinds = (folder) => lines(read(folder, 'book.jsonl')).map((l) => Object.keys(JSON.parse(l))[0]);
const tokenOf = (folder) => read(folder, 'feed-token').trim();

async function running() {
  const w = await world([]);
  const service = await startService({ folder: w.folder, port: 0 });
  const reader = feedReader({ address: `http://127.0.0.1:${service.port}`, token: tokenOf(w.folder) });
  const hand = async (record) => {
    const r = await reader.post('/hand-over', record);
    assert.equal(r.proved, true);
    return r.body;
  };
  return { ...w, service, port: service.port, hand };
}

async function cancel(passkey, slipFingerprint, when = Date.now()) {
  const prepared = await prepareCancellation({ slip: slipFingerprint, when });
  return assembleCancellation(prepared, await passkey.sign(prepared.challenge));
}

const pre = (port, id) => runHook(port, 'PreToolUse', 'Bash', { command: `npm run ${id}` }, { more: { tool_use_id: id } });

test('a renewal handed over from a passkey the recorder trusts is taken, once; the agent acts under it at once', async () => {
  const w = await running();
  try {
    const renewal = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, purpose: 'The renewed permission.' });
    const first = await w.hand({ kind: 'renewal', slip: renewal });
    assert.equal(first.outcome, 'taken', first.message);
    assert.match(first.fingerprint, /^[A-Za-z0-9_-]{43}$/);
    assert.equal((await status(w.port)).slip, first.fingerprint);
    // Handed over again: the book holds it once.
    const again = await w.hand({ kind: 'renewal', slip: renewal });
    assert.equal(again.outcome, 'already');
    assert.deepEqual(kinds(w.folder), ['slip', 'slip']);
    assert.equal((await pre(w.port, 'one')).out, '', 'a call is allowed under it');
  } finally {
    await w.service.close();
  }
});

test('a renewal from a passkey the recorder does not trust is refused and reported, and nothing is admitted; "admit-passkey" on this computer lets it through', async () => {
  const w = await running();
  try {
    const stranger = await developmentPasskey();
    const T = await thumbprint(stranger.key);
    const renewal = await signSlip({ agentKeys: w.agent.keys, passkey: stranger });
    const refused = await w.hand({ kind: 'renewal', slip: renewal });
    assert.equal(refused.outcome, 'refused');
    assert.equal(refused.code, 'passkey-not-trusted');
    assert.equal(refused.thumbprint, T);
    assert.match(refused.message, new RegExp(`admit-passkey ${T}`));
    assert.equal(readTrusted(w.folder).includes(T), false, 'nothing admitted');
    assert.equal((await status(w.port)).slip, (await status(w.port)).slip);
    assert.deepEqual(kinds(w.folder), ['slip']);
    // The person admits it on this computer; handed over again, it is taken.
    const admitted = await runCommand(['admit-passkey', T], { folder: w.folder, port: w.port });
    assert.equal(admitted.code, 0, admitted.err);
    assert.match(admitted.out, /is admitted: the recorder takes new permissions from it/);
    assert.equal((await w.hand({ kind: 'renewal', slip: renewal })).outcome, 'taken');
    assert.deepEqual(kinds(w.folder), ['slip', 'slip']);
  } finally {
    await w.service.close();
  }
});

test('a renewal from a retired passkey is refused, and names the command that admits it again', async () => {
  const w = await running();
  try {
    const A = await thumbprint(w.passkey.key);
    retirePasskey(w.folder, A, true);
    const refused = await w.hand({ kind: 'renewal', slip: await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey }) });
    assert.equal(refused.code, 'passkey-retired');
    assert.equal(refused.thumbprint, A);
    assert.deepEqual(kinds(w.folder), ['slip']);
  } finally {
    await w.service.close();
  }
});

test('a record altered on the way, or a permission replaced before and handed over again, is refused; nothing changes', async () => {
  const w = await running();
  try {
    const before = read(w.folder, 'book.jsonl');
    const renewal = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, purpose: 'Signed by the person.' });
    // The content changed after signing: the passkey's signature no longer fits.
    const content = JSON.parse(Buffer.from(renewal.payload, 'base64url').toString());
    content.purpose = 'Changed on the way.';
    const altered = { ...renewal, payload: Buffer.from(JSON.stringify(content)).toString('base64url') };
    const a = await w.hand({ kind: 'renewal', slip: altered });
    assert.equal(a.outcome, 'refused');
    assert.equal(a.code, 'not-sound');
    assert.equal(read(w.folder, 'book.jsonl'), before);
    // The first permission, replaced by a renewal, then handed over again: the agent is not taken back to it.
    assert.equal((await w.hand({ kind: 'renewal', slip: renewal })).outcome, 'taken');
    const replay = await w.hand({ kind: 'renewal', slip: w.slip });
    assert.equal(replay.code, 'not-again');
    // A renewal signed to start before the permission in force (held back, then handed over late) is refused.
    const early = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, from: Date.now() - 3600000, purpose: 'An early one.' });
    assert.equal((await w.hand({ kind: 'renewal', slip: early })).code, 'older');
    // A cancellation whose content was changed: refused.
    const c = await cancel(w.passkey, (await status(w.port)).slip);
    const cc = JSON.parse(Buffer.from(c.payload, 'base64url').toString());
    cc.when = '2026-01-01T00:00:00Z';
    const changed = await w.hand({ kind: 'cancellation', cancellation: { ...c, payload: Buffer.from(JSON.stringify(cc)).toString('base64url') } });
    assert.equal(changed.outcome, 'refused');
    assert.deepEqual(kinds(w.folder), ['slip', 'slip']);
    assert.equal((await pre(w.port, 'still')).out, '', 'the agent still acts');
    // Not a record at all.
    assert.equal((await w.hand({ kind: 'renewal', slip: 'no' })).code, 'not-sound');
    assert.equal((await w.hand({ kind: 'other' })).code, 'not-understood');
  } finally {
    await w.service.close();
  }
});

test('a cancellation of the permission in force stops the agent, and the agent\'s side acknowledges it in the book; handed over twice, it is taken once', async () => {
  const w = await running();
  try {
    assert.equal((await pre(w.port, 'before')).out, '');
    const c = await cancel(w.passkey, (await status(w.port)).slip);
    const taken = await w.hand({ kind: 'cancellation', cancellation: c });
    assert.equal(taken.outcome, 'taken', taken.message);
    assert.ok(taken.acknowledgement, 'the acknowledgement is handed back');
    assert.deepEqual(kinds(w.folder), ['slip', 'cancellation', 'acknowledgement']);
    const refusedCall = await pre(w.port, 'after');
    assert.equal(refusedCall.decision.permissionDecision, 'deny', 'no call is taken under a cancelled permission');
    const again = await w.hand({ kind: 'cancellation', cancellation: c });
    assert.equal(again.outcome, 'already');
    assert.deepEqual(again.acknowledgement, taken.acknowledgement, 'the same acknowledgement');
    assert.deepEqual(kinds(w.folder), ['slip', 'cancellation', 'acknowledgement']);
    assert.equal((await status(w.port)).cancelled, true);
    const answer = await checkBook(read(w.folder, 'book.jsonl'));
    assert.equal(answer.summary.problemFound, false);
    // No new book while the permission in force is cancelled: it would begin with that permission alone.
    const r = await fetch(`http://127.0.0.1:${w.port}/new-book`, { method: 'POST', body: '{}' });
    assert.equal(r.status, 409);
    assert.match((await r.json()).error, /cancelled, so no new book is started/);
    // A renewal after it: the agent acts again, under the new permission.
    assert.equal((await w.hand({ kind: 'renewal', slip: await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey }) })).outcome, 'taken');
    assert.equal((await pre(w.port, 'renewed')).out, '');
  } finally {
    await w.service.close();
  }
});

test('a cancellation of a permission that is not in force, or that the recorder never held, is refused and the book is not changed', async () => {
  const w = await running();
  try {
    const first = (await status(w.port)).slip;
    assert.equal((await w.hand({ kind: 'renewal', slip: await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey }) })).outcome, 'taken');
    const before = read(w.folder, 'book.jsonl');
    assert.equal((await w.hand({ kind: 'cancellation', cancellation: await cancel(w.passkey, first) })).code, 'not-in-force');
    assert.equal((await w.hand({ kind: 'cancellation', cancellation: await cancel(w.passkey, 'A'.repeat(43)) })).code, 'unknown-permission');
    // Signed by another passkey than the permission's.
    const stranger = await developmentPasskey();
    const wrong = await w.hand({ kind: 'cancellation', cancellation: await cancel(stranger, (await status(w.port)).slip) });
    assert.equal(wrong.outcome, 'refused');
    assert.equal(read(w.folder, 'book.jsonl'), before);
  } finally {
    await w.service.close();
  }
});

test('a cancellation in the book stops the permission after a restart', async () => {
  const w = await running();
  try {
    const c = await cancel(w.passkey, (await status(w.port)).slip);
    assert.equal((await w.hand({ kind: 'cancellation', cancellation: c })).outcome, 'taken');
  } finally {
    await w.service.close();
  }
  const again = await startService({ folder: w.folder, port: 0 });
  try {
    assert.equal((await pre(again.port, 'after-restart')).decision.permissionDecision, 'deny');
    assert.equal((await status(again.port)).cancelled, true);
  } finally {
    await again.close();
  }
});

test('the hand-over is proved like every question of the feed: over the body, with the token, and the answer with the recorder\'s proof', async () => {
  const w = await running();
  try {
    const renewal = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey });
    // Another token: the recorder does not prove itself, nothing is taken.
    const stranger = feedReader({ address: `http://127.0.0.1:${w.port}`, token: 'W'.repeat(43) });
    await assert.rejects(stranger.post('/hand-over', { kind: 'renewal', slip: renewal }));
    // A proof over another body than the one sent: refused.
    const token = tokenOf(w.folder);
    const mine = createHash('sha256').update('mine').digest('base64url');
    const hello = await (await fetch(`http://127.0.0.1:${w.port}/hello`, { headers: { 'Provared-Feed-Hello': mine } })).json();
    const key = feedHmac(Buffer.from(token), FEED_LABELS.key, mine, hello.session);
    const nonce = createHash('sha256').update('nonce').digest('base64url');
    const sent = Buffer.from(JSON.stringify({ kind: 'renewal', slip: renewal }));
    const other = Buffer.from(JSON.stringify({ kind: 'renewal', slip: w.slip }));
    const headers = (body) => ({ 'Provared-Feed-Session': hello.session, 'Provared-Feed-Hello': mine, 'Provared-Feed-Nonce': nonce, 'Provared-Feed-Proof': feedHmac(key, FEED_LABELS.questionWithBody, hello.session, nonce, 'POST /hand-over', body).toString('base64url') });
    const r = await fetch(`http://127.0.0.1:${w.port}/hand-over`, { method: 'POST', body: sent, headers: headers(other) });
    assert.equal(r.status, 401);
    // A proof that leaves the body out does not do.
    const noBody = { ...headers(sent), 'Provared-Feed-Proof': feedHmac(key, FEED_LABELS.questionWithBody, hello.session, nonce, 'POST /hand-over').toString('base64url') };
    assert.equal((await fetch(`http://127.0.0.1:${w.port}/hand-over`, { method: 'POST', body: sent, headers: noBody })).status, 401);
    // A GET question's proof (no body) is not one for a question with a body.
    const asGet = { ...headers(sent), 'Provared-Feed-Proof': feedHmac(key, FEED_LABELS.question, hello.session, nonce, 'POST /hand-over').toString('base64url') };
    assert.equal((await fetch(`http://127.0.0.1:${w.port}/hand-over`, { method: 'POST', body: sent, headers: asGet })).status, 401);
    assert.equal((await fetch(`http://127.0.0.1:${w.port}/hand-over`)).status, 405);
    const big = await fetch(`http://127.0.0.1:${w.port}/hand-over`, { method: 'POST', body: Buffer.alloc(FEED_MAX_HAND_OVER_BYTES + 1, 32) });
    assert.equal(big.status, 413);
    assert.deepEqual(kinds(w.folder), ['slip'], 'nothing was taken');
  } finally {
    await w.service.close();
  }
});
