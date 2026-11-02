// A record handed over through the feed (POST /hand-over): a renewal or a
// cancellation the person signed elsewhere, which the application kept
// sealed and its uploader hands to the recorder. The recorder checks each
// itself: a renewal only from a passkey this computer already trusts, a
// cancellation only of the permission in force, which the agent's side
// acknowledges in the book. Every test works in a temporary folder and on a
// port of its own.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { connect } from 'node:net';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

const { assembleCancellation, checkBook, prepareCancellation, thumbprint } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { FEED_LABELS, FEED_MAX_HANDING, FEED_MAX_HAND_OVER_BYTES, feedHmac, feedReader } = await import('../feed.mjs');
const { HAND_OVER_ALLOWANCE_MS, MAX_WAITING_PERMISSIONS, SIGNING_ORIGIN, readTrusted, readWaitingPermissions, retirePasskey, signingOriginsFrom, startService } = await import('../recorder.mjs');
const { runCommand, runHook, signSlip, status, world } = await import('./world.mjs');

const read = (folder, name) => readFileSync(join(folder, name), 'utf8');
const lines = (text) => text.split('\n').filter(Boolean);
const kinds = (folder) => lines(read(folder, 'book.jsonl')).map((l) => Object.keys(JSON.parse(l))[0]);
const tokenOf = (folder) => read(folder, 'feed-token').trim();

// The development stand-in for a passkey signs at http://localhost: the recorder is told to take records signed there.
const LOCAL = { signingOrigins: ['http://localhost'] };

async function running(more = LOCAL) {
  const w = await world([]);
  const service = await startService({ folder: w.folder, port: 0, ...more });
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
    const first = (await status(w.port)).slip;
    assert.deepEqual(kinds(w.folder), ['slip']);
    // On this computer, the command shows the permission waiting, and takes nothing unless the person types "yes".
    const declined = await runCommand(['admit-passkey', T], { folder: w.folder, port: w.port, input: 'no\n' });
    assert.equal(declined.code, 1);
    assert.match(declined.out, new RegExp(`Passkey \\(thumbprint\\)\\s+${T}`));
    assert.match(declined.out, /Signed at\s+http:\/\/localhost/);
    assert.match(declined.out, /Nothing was changed/);
    assert.equal(readTrusted(w.folder).includes(T), false);
    assert.equal((await status(w.port)).slip, first);
    // Nothing typed at all: nothing is changed either.
    assert.equal((await runCommand(['admit-passkey', T], { folder: w.folder, port: w.port })).code, 1);
    assert.equal(readTrusted(w.folder).includes(T), false);
    const admitted = await runCommand(['admit-passkey', T], { folder: w.folder, port: w.port, input: 'yes\n' });
    assert.equal(admitted.code, 0, admitted.err);
    assert.match(admitted.out, /is trusted from now on, with the permission it signed/);
    assert.equal(readTrusted(w.folder).includes(T), true);
    assert.deepEqual(kinds(w.folder), ['slip', 'slip']);
    // Handed over again: the book holds it already.
    assert.equal((await w.hand({ kind: 'renewal', slip: renewal })).outcome, 'already');
    // A passkey never trusted, with nothing waiting from it: nothing is admitted.
    const another = await thumbprint((await developmentPasskey()).key);
    const none = await runCommand(['admit-passkey', another], { folder: w.folder, port: w.port, input: 'yes\n' });
    assert.equal(none.code, 1);
    assert.match(none.out, /No permission signed by the passkey/);
    assert.equal(readTrusted(w.folder).includes(another), false);
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
    const cancelledAt = Date.now() - 10000;
    const c = await cancel(w.passkey, (await status(w.port)).slip, cancelledAt);
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
    // A renewal signed after it, starting five minutes after it: taken; the agent acts again under it from then.
    const renewal = await w.hand({ kind: 'renewal', slip: await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, from: cancelledAt + HAND_OVER_ALLOWANCE_MS }) });
    assert.equal(renewal.outcome, 'taken', renewal.message);
    assert.equal((await status(w.port)).slip, renewal.fingerprint);
    assert.equal((await status(w.port)).cancelled, false);
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
    // Headers that are not a proof's, in a conversation the recorder never began: refused before the body is read.
    assert.equal((await fetch(`http://127.0.0.1:${w.port}/hand-over`, { method: 'POST', body: '{}' })).status, 401);
    // So the answer comes at once, though the body it states never arrives.
    const early = await new Promise((done, fail) => {
      const socket = connect(w.port, '127.0.0.1');
      let got = '';
      const timer = setTimeout(() => { socket.destroy(); done('no answer'); }, 3000);
      socket.on('data', (d) => { got += d; if (got.includes('\r\n')) { clearTimeout(timer); socket.destroy(); done(got.split('\r\n')[0]); } });
      socket.on('error', fail);
      socket.write(['POST /hand-over HTTP/1.1', 'Host: 127.0.0.1', 'Content-Length: 100', 'Provared-Feed-Session: x', '', '{'].join('\r\n'));
    });
    assert.match(early, /^HTTP\/1\.1 401/);
    // A body that does not state its length (sent in pieces): refused before it is read.
    const pieces = await new Promise((done, fail) => {
      const req = request({ host: '127.0.0.1', port: w.port, method: 'POST', path: '/hand-over' }, (res) => {
        res.resume();
        done(res.statusCode);
      });
      req.on('error', fail);
      req.write('{"kind":');
      req.end('"renewal"}');
    });
    assert.equal(pieces, 411);
    assert.deepEqual(kinds(w.folder), ['slip'], 'nothing was taken');
  } finally {
    await w.service.close();
  }
});

/** A question's headers, proved over a body, in a conversation begun with the recorder's own token. */
async function provedHeaders(port, token, body) {
  const mine = randomBytes(32).toString('base64url');
  const hello = await (await fetch(`http://127.0.0.1:${port}/hello`, { headers: { 'Provared-Feed-Hello': mine } })).json();
  const key = feedHmac(Buffer.from(token), FEED_LABELS.key, mine, hello.session);
  const nonce = randomBytes(32).toString('base64url');
  return { 'Provared-Feed-Session': hello.session, 'Provared-Feed-Hello': mine, 'Provared-Feed-Nonce': nonce, 'Provared-Feed-Proof': feedHmac(key, FEED_LABELS.questionWithBody, hello.session, nonce, 'POST /hand-over', body).toString('base64url') };
}

test(`at most ${FEED_MAX_HANDING} records are taken on at once, counted before their bodies are read; one more is told to ask again`, async () => {
  const w = await running();
  const slow = [];
  try {
    // Records whose bodies do not come: each is taken on, waiting for its body, with headers in the right form.
    for (let i = 0; i < FEED_MAX_HANDING; i++) {
      const headers = await provedHeaders(w.port, tokenOf(w.folder), Buffer.from('{}'));
      const socket = connect(w.port, '127.0.0.1');
      await new Promise((done) => socket.once('connect', done));
      socket.write([`POST /hand-over HTTP/1.1`, 'Host: 127.0.0.1', 'Content-Length: 100', ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`), '', '{'].join('\r\n'));
      slow.push(socket);
    }
    await delay(300);
    const body = Buffer.from(JSON.stringify({ kind: 'renewal', slip: await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey }) }));
    const busy = await fetch(`http://127.0.0.1:${w.port}/hand-over`, { method: 'POST', body, headers: await provedHeaders(w.port, tokenOf(w.folder), body) });
    assert.equal(busy.status, 429);
    assert.deepEqual(kinds(w.folder), ['slip'], 'nothing was taken');
    // Once those are let go, a record is taken again.
    for (const s of slow) s.destroy();
    await delay(300);
    const taken = await fetch(`http://127.0.0.1:${w.port}/hand-over`, { method: 'POST', body, headers: await provedHeaders(w.port, tokenOf(w.folder), body) });
    assert.equal(taken.status, 200);
    assert.equal((await taken.json()).outcome, 'taken');
  } finally {
    for (const s of slow) s.destroy();
    await w.service.close();
  }
});

test('a renewal signed before a cancellation, and handed over after it, is refused: the agent stays stopped; one that starts five minutes or more after the cancellation is taken', async () => {
  const w = await running();
  try {
    // The person signs a renewal; it is held back (the computer asleep, or the server holding it).
    const early = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, from: Date.now() - 30000, purpose: 'Signed first, then the person cancelled.' });
    // Then the person cancels the permission in force. The uploader hands the cancellation over first, then the renewal.
    const cancelledAt = Date.now() - 10000;
    const c = await cancel(w.passkey, (await status(w.port)).slip, cancelledAt);
    assert.equal((await w.hand({ kind: 'cancellation', cancellation: c })).outcome, 'taken');
    const late = await w.hand({ kind: 'renewal', slip: early });
    assert.equal(late.outcome, 'refused');
    assert.equal(late.code, 'before-cancellation');
    assert.equal((await pre(w.port, 'after')).decision.permissionDecision, 'deny', 'the agent stays stopped');
    assert.deepEqual(kinds(w.folder), ['slip', 'cancellation', 'acknowledgement']);
    // A renewal starting the second the cancellation was dated: refused too, as one signed before it could start.
    const shown = JSON.parse(Buffer.from(c.payload, 'base64url').toString()).when;
    const atOnce = await w.hand({ kind: 'renewal', slip: await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, from: Date.parse(shown), purpose: 'Starts as the cancellation.' }) });
    assert.equal(atOnce.code, 'before-cancellation');
    assert.match(atOnce.message, /less than 5 minutes after the person's cancellation/);
    // Signed after the cancellation, starting five minutes after its date (as the application moves it): taken.
    const after = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, from: Date.parse(shown) + HAND_OVER_ALLOWANCE_MS, purpose: 'Signed after the cancellation.' });
    const taken = await w.hand({ kind: 'renewal', slip: after });
    assert.equal(taken.outcome, 'taken', taken.message);
    assert.equal((await status(w.port)).slip, taken.fingerprint);
    // It starts in under five minutes: until then the agent stays stopped.
    assert.equal((await pre(w.port, 'renewed')).decision.permissionDecision, 'deny');
    // The early one, handed over again, is still refused (now as older than the permission in force).
    assert.equal((await w.hand({ kind: 'renewal', slip: early })).outcome, 'refused');
  } finally {
    await w.service.close();
  }
});

test('a cancellation dated ahead of the clock is held, kept on the disk, and still stops the agent after a restart', async () => {
  const w = await running();
  try {
    const c = await cancel(w.passkey, (await status(w.port)).slip, Date.now() + 10 * 60000);
    const held = await w.hand({ kind: 'cancellation', cancellation: c });
    assert.equal(held.outcome, 'held', held.message);
    assert.ok(existsSync(join(w.folder, 'held-cancellations.json')));
    assert.equal((await pre(w.port, 'while-held')).decision.permissionDecision, 'deny');
  } finally {
    await w.service.close();
  }
  const again = await startService({ folder: w.folder, port: 0, ...LOCAL });
  try {
    assert.equal((await pre(again.port, 'after-restart')).decision.permissionDecision, 'deny', 'the held cancellation was not lost');
    assert.equal((await status(again.port)).cancelled, true);
    // No new book while it is held: it goes into this book first.
    const r = await fetch(`http://127.0.0.1:${again.port}/new-book`, { method: 'POST', body: '{}' });
    assert.equal(r.status, 409);
  } finally {
    await again.close();
  }
});

test('while a cancellation is held, a renewal that starts before its date is refused; one that starts after it is taken, and the cancellation stays held', async () => {
  const w = await running();
  try {
    const first = (await status(w.port)).slip;
    const date = Date.now() + 10 * 60000;
    const c = await cancel(w.passkey, first, date);
    assert.equal((await w.hand({ kind: 'cancellation', cancellation: c })).outcome, 'held');
    const early = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, from: Date.now() - 1000 });
    const before = await w.hand({ kind: 'renewal', slip: early });
    assert.equal(before.code, 'before-cancellation');
    // Renewed on this computer ("renew", not handed over): refused as well, while the cancellation is held.
    await assert.rejects(w.service.renew(early), { code: 'cancellation-held' });
    assert.deepEqual(kinds(w.folder), ['slip']);
    // One that starts after the held date is more than five minutes ahead: not taken from the
    // application, now or later. The person puts such a one in place on this computer ("renew").
    const later = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, from: date + 60000, until: date + 3600000 });
    const handed = await w.hand({ kind: 'renewal', slip: later });
    assert.equal(handed.code, 'starts-later', handed.message);
    assert.match(handed.message, /renew <file>/);
    const after = await w.service.renew(later);
    assert.equal(after.slip, (await status(w.port)).slip);
    // Still held, by the new writer, and still on the disk: it goes into the book when the clock reaches its date.
    const kept = JSON.parse(read(w.folder, 'held-cancellations.json')).cancellations;
    assert.equal(kept.length, 1);
    assert.equal(kept[0].cancellation.payload, c.payload);
    assert.ok(kept[0].acknowledgements?.length, 'with the acknowledgement signed for it');
    // No new book while it is held, though the permission in force is not the one it cancels.
    assert.equal((await status(w.port)).cancelled, false);
    const r = await fetch(`http://127.0.0.1:${w.port}/new-book`, { method: 'POST', body: '{}' });
    assert.equal(r.status, 409);
    assert.match((await r.json()).error, /held beside the book/);
  } finally {
    await w.service.close();
  }
  const again = await startService({ folder: w.folder, port: 0, ...LOCAL });
  try {
    assert.equal(JSON.parse(read(w.folder, 'held-cancellations.json')).cancellations.length, 1, 'kept across a restart');
  } finally {
    await again.close();
  }
});

test('a cancellation dated more than a day ahead is refused, and changes nothing', async () => {
  const w = await running();
  try {
    const c = await cancel(w.passkey, (await status(w.port)).slip, Date.now() + 2 * 86400000);
    const a = await w.hand({ kind: 'cancellation', cancellation: c });
    assert.equal(a.outcome, 'refused');
    assert.equal(a.code, 'too-far-ahead');
    assert.equal((await pre(w.port, 'still')).out, '', 'the agent still acts');
    assert.equal(existsSync(join(w.folder, 'held-cancellations.json')), false);
  } finally {
    await w.service.close();
  }
});

test('a record handed over must have been signed at the signing page (https://sign.prova.red unless the setting names another)', async () => {
  assert.deepEqual(signingOriginsFrom(undefined), [SIGNING_ORIGIN]);
  assert.equal(SIGNING_ORIGIN, 'https://sign.prova.red');
  assert.deepEqual(signingOriginsFrom('http://localhost:5173, https://sign.example.org'), ['http://localhost:5173', 'https://sign.example.org']);
  for (const wrong of ['http://example.org', 'https://sign.prova.red/', 'https://sign.prova.red/page', 'localhost']) assert.throws(() => signingOriginsFrom(wrong), /not an address such as/);
  // The default: a permission signed at http://localhost is refused; nothing changes.
  const w = await running({});
  try {
    const renewal = await w.hand({ kind: 'renewal', slip: await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey }) });
    assert.equal(renewal.code, 'other-signing-address');
    // From a passkey it does not trust, signed elsewhere: refused for its address, and nothing waits for "admit-passkey".
    const stranger = await w.hand({ kind: 'renewal', slip: await signSlip({ agentKeys: w.agent.keys, passkey: await developmentPasskey() }) });
    assert.equal(stranger.code, 'other-signing-address');
    assert.equal(existsSync(join(w.folder, 'waiting-permissions.json')), false);
    assert.deepEqual(kinds(w.folder), ['slip']);
    assert.equal((await pre(w.port, 'still')).out, '');
    // A cancellation of the permission in force, signed at http://localhost too, is taken all the same: it only
    // takes away, and it checks against the permission's own passkey and the permission's own address.
    const cancellation = await w.hand({ kind: 'cancellation', cancellation: await cancel(w.passkey, (await status(w.port)).slip) });
    assert.equal(cancellation.outcome, 'taken', cancellation.message);
    assert.deepEqual(kinds(w.folder), ['slip', 'cancellation', 'acknowledgement']);
    assert.equal((await pre(w.port, 'stopped')).decision.permissionDecision, 'deny');
    // One signed by another passkey is still refused, whatever the setting.
    const forged = await w.hand({ kind: 'cancellation', cancellation: await cancel(await developmentPasskey(), (await status(w.port)).slip) });
    assert.equal(forged.outcome, 'refused');
  } finally {
    await w.service.close();
  }
});

// A renewal signed before a cancellation, with any start the application allows (no more than ten minutes
// before the person pressed Sign, and no more than five minutes after), starts before the cancellation's date
// and five minutes, so it is refused; one signed after it, starting at that point as the application moves it,
// is taken. The two rules ("starts-later", "before-cancellation") together, checked here with real times.
test('the arithmetic of the two rules: signed before a cancellation, refused whatever start the application allows; signed after, as the application makes it, taken', async () => {
  const w = await running();
  try {
    const signedAt = Date.now();
    const before = [];
    for (const from of [signedAt - 600000, signedAt - 60000, signedAt, signedAt + HAND_OVER_ALLOWANCE_MS]) {
      before.push(await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, from, purpose: `Signed before, from ${from - signedAt} ms.` }));
    }
    await delay(3100);
    // The person cancels after signing them (dated two seconds ago, so that it goes into the book at once).
    const cancelledAt = Date.now() - 2000;
    assert.ok(cancelledAt > signedAt + 1000);
    assert.equal((await w.hand({ kind: 'cancellation', cancellation: await cancel(w.passkey, (await status(w.port)).slip, cancelledAt) })).outcome, 'taken');
    for (const slip of before) {
      const a = await w.hand({ kind: 'renewal', slip });
      assert.equal(a.outcome, 'refused', a.message);
      // The one that starts ten minutes back is older than the permission in force; the rest start too soon after the cancellation.
      assert.ok(['older', 'before-cancellation'].includes(a.code), a.code);
    }
    // Signed now, after the cancellation, starting at its date and five minutes, to the whole second after.
    const from = Math.ceil((cancelledAt + HAND_OVER_ALLOWANCE_MS) / 1000) * 1000;
    assert.ok(from <= Date.now() + HAND_OVER_ALLOWANCE_MS, 'within five minutes of signing');
    const taken = await w.hand({ kind: 'renewal', slip: await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, from, purpose: 'Signed after.' }) });
    assert.equal(taken.outcome, 'taken', taken.message);
  } finally {
    await w.service.close();
  }
});

test('a renewal that starts more than five minutes ahead when handed over is refused for good, before its passkey is looked at; it never waits for "admit-passkey"', async () => {
  const w = await running();
  try {
    const ahead = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, from: Date.now() + HAND_OVER_ALLOWANCE_MS + 60000 });
    const a = await w.hand({ kind: 'renewal', slip: ahead });
    assert.equal(a.code, 'starts-later', a.message);
    assert.match(a.message, /more than 5 minutes ahead/);
    // Handed over again: still refused, by its fingerprint.
    assert.equal((await w.hand({ kind: 'renewal', slip: ahead })).code, 'starts-later');
    // Five minutes ahead and no more: taken.
    const within = await w.hand({ kind: 'renewal', slip: await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, from: Date.now() + HAND_OVER_ALLOWANCE_MS - 5000 }) });
    assert.equal(within.outcome, 'taken', within.message);
    // From a passkey this computer does not trust: refused for its start, and nothing waits.
    const stranger = await w.hand({ kind: 'renewal', slip: await signSlip({ agentKeys: w.agent.keys, passkey: await developmentPasskey(), from: Date.now() + 2 * HAND_OVER_ALLOWANCE_MS }) });
    assert.equal(stranger.code, 'starts-later');
    assert.equal(existsSync(join(w.folder, 'waiting-permissions.json')), false);
  } finally {
    await w.service.close();
  }
  // Refused for good: once its start has come near (the recorder's clock moved on ten minutes), still refused.
  const shift = { ms: 0 };
  const v = await world([]);
  const service = await startService({ folder: v.folder, port: 0, ...LOCAL, clock: () => Date.now() + shift.ms });
  try {
    const reader = feedReader({ address: `http://127.0.0.1:${service.port}`, token: tokenOf(v.folder) });
    const hand = async (record) => (await reader.post('/hand-over', record)).body;
    const ahead = await signSlip({ agentKeys: v.agent.keys, passkey: v.passkey, from: Date.now() + HAND_OVER_ALLOWANCE_MS + 60000 });
    assert.equal((await hand({ kind: 'renewal', slip: ahead })).code, 'starts-later');
    shift.ms = 10 * 60000;
    const later = await hand({ kind: 'renewal', slip: ahead });
    assert.equal(later.code, 'starts-later', later.message);
    // Another, never handed over before, with the same start: taken at that clock.
    assert.equal((await hand({ kind: 'renewal', slip: await signSlip({ agentKeys: v.agent.keys, passkey: v.passkey, from: Date.parse(JSON.parse(Buffer.from(ahead.payload, 'base64url').toString()).validFrom) }) })).outcome, 'taken');
  } finally {
    await service.close();
  }
});

test('"admit-passkey" runs the hand-over\'s checks: a renewal from a new passkey that waits from before a cancellation is dropped, not taken, and the agent stays stopped', async () => {
  const w = await running();
  try {
    const mine = await developmentPasskey(); // the person's second passkey, not yet trusted here
    const T = await thumbprint(mine.key);
    const early = await signSlip({ agentKeys: w.agent.keys, passkey: mine, from: Date.now() - 30000, purpose: 'Signed before the cancellation.' });
    assert.equal((await w.hand({ kind: 'renewal', slip: early })).code, 'passkey-not-trusted');
    await delay(1100);
    assert.equal((await w.hand({ kind: 'cancellation', cancellation: await cancel(w.passkey, (await status(w.port)).slip) })).outcome, 'taken');
    // Handed over again after the cancellation: it still waits (its passkey is looked at first).
    assert.equal((await w.hand({ kind: 'renewal', slip: early })).code, 'passkey-not-trusted');
    const out = await runCommand(['admit-passkey', T], { folder: w.folder, port: w.port, input: 'yes\n' });
    assert.equal(out.code, 1, out.out);
    assert.match(out.out, /Dropped from the list, and not taken/);
    assert.match(out.out, /less than 5 minutes after the person's cancellation/);
    assert.match(out.out, /Nothing is left waiting from the passkey/);
    assert.equal(readTrusted(w.folder).includes(T), false, 'the passkey is not admitted');
    assert.equal(readWaitingPermissions(w.folder).length, 0, 'dropped from the list');
    assert.deepEqual(kinds(w.folder), ['slip', 'cancellation', 'acknowledgement']);
    assert.equal((await pre(w.port, 'after-admit')).decision.permissionDecision, 'deny', 'the agent stays stopped');
  } finally {
    await w.service.close();
  }
});

test('"admit-passkey" refuses while the recorder is stopped, and says to start it first; nothing is admitted', async () => {
  const w = await running();
  const stranger = await developmentPasskey();
  const T = await thumbprint(stranger.key);
  try {
    assert.equal((await w.hand({ kind: 'renewal', slip: await signSlip({ agentKeys: w.agent.keys, passkey: stranger }) })).code, 'passkey-not-trusted');
  } finally {
    await w.service.close();
  }
  const out = await runCommand(['admit-passkey', T], { folder: w.folder, port: w.port, input: 'yes\n' });
  assert.equal(out.code, 1);
  assert.match(out.out, /The recorder is not running, so nothing is admitted/);
  assert.match(out.out, /ensure/);
  assert.equal(readTrusted(w.folder).includes(T), false);
  assert.equal(readWaitingPermissions(w.folder).length, 1, 'it still waits');
  assert.deepEqual(kinds(w.folder), ['slip']);
});

test('"admit-passkey" shows only what that passkey signed, by the permission itself, never by the list\'s own note of the thumbprint', async () => {
  const w = await running();
  try {
    const stranger = await developmentPasskey();
    const S = await thumbprint(stranger.key);
    const T = await thumbprint((await developmentPasskey()).key);
    assert.equal((await w.hand({ kind: 'renewal', slip: await signSlip({ agentKeys: w.agent.keys, passkey: stranger, purpose: 'The stranger\'s.' }) })).code, 'passkey-not-trusted');
    // The list's own note of the thumbprint changed to T (by any program on this computer): T is still not shown it.
    const path = join(w.folder, 'waiting-permissions.json');
    const list = JSON.parse(read(w.folder, 'waiting-permissions.json'));
    list.permissions[0].thumbprint = T;
    writeFileSync(path, JSON.stringify(list));
    const out = await runCommand(['admit-passkey', T], { folder: w.folder, port: w.port, input: 'yes\n' });
    assert.equal(out.code, 1);
    assert.match(out.out, /No permission signed by the passkey/);
    assert.doesNotMatch(out.out, /The stranger's/);
    assert.equal(readWaitingPermissions(w.folder).length, 1, 'the stranger\'s still waits');
    assert.equal(readTrusted(w.folder).includes(T), false);
    assert.equal(readTrusted(w.folder).includes(S), false);
    // Asked with the stranger's own thumbprint, it is shown, by the thumbprint worked out from the permission.
    const shown = await runCommand(['admit-passkey', S], { folder: w.folder, port: w.port, input: 'no\n' });
    assert.match(shown.out, new RegExp(`Passkey \\(thumbprint\\)\\s+${S}`));
    assert.match(shown.out, /The stranger's/);
    // And the service itself takes nothing for one passkey that another signed.
    const said = await (await fetch(`http://127.0.0.1:${w.port}/admit`, { method: 'POST', body: JSON.stringify({ slip: list.permissions[0].slip, thumbprint: T, take: true }) })).json();
    assert.equal(said.code, 'other-passkey');
    assert.deepEqual(kinds(w.folder), ['slip']);
  } finally {
    await w.service.close();
  }
});

test(`the waiting list keeps one permission for each passkey, the one that starts latest, whichever is handed over last; at most ${MAX_WAITING_PERMISSIONS} in all`, async () => {
  const w = await running();
  try {
    const mine = await developmentPasskey();
    const T = await thumbprint(mine.key);
    const newer = await signSlip({ agentKeys: w.agent.keys, passkey: mine, from: Date.now() - 10000, purpose: 'NEWER' });
    const older = await signSlip({ agentKeys: w.agent.keys, passkey: mine, from: Date.now() - 50000, purpose: 'OLDER' });
    await w.hand({ kind: 'renewal', slip: newer });
    await w.hand({ kind: 'renewal', slip: older });
    let waiting = readWaitingPermissions(w.folder);
    assert.equal(waiting.length, 1);
    assert.equal(waiting[0].thumbprint, T);
    assert.equal(waiting[0].slip.payload, newer.payload, 'the one that starts latest, though handed over first');
    const shown = await runCommand(['admit-passkey', T], { folder: w.folder, port: w.port, input: 'no\n' });
    assert.match(shown.out, /Purpose\s+NEWER/);
    assert.doesNotMatch(shown.out, /OLDER/);
    // A later one replaces it.
    const latest = await signSlip({ agentKeys: w.agent.keys, passkey: mine, from: Date.now() + 2000, purpose: 'LATEST' });
    await w.hand({ kind: 'renewal', slip: latest });
    waiting = readWaitingPermissions(w.folder);
    assert.equal(waiting.length, 1);
    assert.equal(waiting[0].slip.payload, latest.payload);
    // Other passkeys: one each, newest handed over first, at most MAX_WAITING_PERMISSIONS; the first is pushed out.
    for (let i = 0; i < MAX_WAITING_PERMISSIONS; i++) {
      await w.hand({ kind: 'renewal', slip: await signSlip({ agentKeys: w.agent.keys, passkey: await developmentPasskey(), purpose: `stranger ${i}` }) });
    }
    waiting = readWaitingPermissions(w.folder);
    assert.equal(waiting.length, MAX_WAITING_PERMISSIONS);
    assert.equal(JSON.parse(read(w.folder, 'waiting-permissions.json')).permissions.length, MAX_WAITING_PERMISSIONS);
    assert.ok(!waiting.some((p) => p.thumbprint === T), 'the first one handed over is pushed out');
    assert.equal(new Set(waiting.map((p) => p.thumbprint)).size, MAX_WAITING_PERMISSIONS);
  } finally {
    await w.service.close();
  }
});

test('a body of a record handed over that does not arrive in time is let go, and its place is free again', async () => {
  const w = await world([]);
  const service = await startService({ folder: w.folder, port: 0, ...LOCAL, handOverReadMs: 300 });
  const slow = [];
  try {
    for (let i = 0; i < FEED_MAX_HANDING; i++) {
      const headers = await provedHeaders(service.port, tokenOf(w.folder), Buffer.from('{}'));
      const socket = connect(service.port, '127.0.0.1');
      socket.on('error', () => {});
      await new Promise((done) => socket.once('connect', done));
      socket.write(['POST /hand-over HTTP/1.1', 'Host: 127.0.0.1', 'Content-Length: 100', ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`), '', '{'].join('\r\n'));
      slow.push(socket);
    }
    const body = Buffer.from(JSON.stringify({ kind: 'renewal', slip: await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey }) }));
    const busy = await fetch(`http://127.0.0.1:${service.port}/hand-over`, { method: 'POST', body, headers: await provedHeaders(service.port, tokenOf(w.folder), body) });
    assert.equal(busy.status, 429);
    // The test lets none of them go: the recorder does, once the time for the body has passed.
    await delay(900);
    const taken = await fetch(`http://127.0.0.1:${service.port}/hand-over`, { method: 'POST', body, headers: await provedHeaders(service.port, tokenOf(w.folder), body) });
    assert.equal(taken.status, 200);
    assert.equal((await taken.json()).outcome, 'taken');
    assert.ok(slow.every((s) => s.destroyed || s.readableEnded), 'each slow one was let go by the recorder');
  } finally {
    for (const s of slow) s.destroy();
    await service.close();
  }
});

test('a held-cancellations.json the recorder cannot take stops the start, and names the file and what to do', async () => {
  const w = await running();
  try {
    assert.equal((await w.hand({ kind: 'cancellation', cancellation: await cancel(w.passkey, (await status(w.port)).slip, Date.now() + 600000) })).outcome, 'held');
  } finally {
    await w.service.close();
  }
  const path = join(w.folder, 'held-cancellations.json');
  const held = JSON.parse(readFileSync(path, 'utf8'));
  held.cancellations.push({ cancellation: { payload: 'e30', signatures: [] } });
  writeFileSync(path, JSON.stringify(held));
  await assert.rejects(startService({ folder: w.folder, port: 0, ...LOCAL }), (e) => {
    assert.ok(e.message.startsWith(`${path} holds a cancellation the recorder cannot take`), e.message);
    assert.match(e.message, /does not start/);
    assert.match(e.message, /move it out of the folder/);
    return true;
  });
});

test('"admit-passkey" with two waiting from one passkey (a list written by an earlier version, or by hand) shows both, the one that starts latest first, and takes that one', async () => {
  const w = await running();
  try {
    const mine = await developmentPasskey();
    const T = await thumbprint(mine.key);
    const newer = await signSlip({ agentKeys: w.agent.keys, passkey: mine, from: Date.now() - 10000, purpose: 'NEWER' });
    const older = await signSlip({ agentKeys: w.agent.keys, passkey: mine, from: Date.now() - 50000, purpose: 'OLDER' });
    await w.hand({ kind: 'renewal', slip: newer });
    const kept = readWaitingPermissions(w.folder)[0];
    // The older one written first, as the newest handed over.
    const path = join(w.folder, 'waiting-permissions.json');
    const list = JSON.parse(read(w.folder, 'waiting-permissions.json'));
    list.permissions = [{ ...kept, fingerprint: 'O'.repeat(43), slip: older }, kept];
    writeFileSync(path, JSON.stringify(list));
    const both = await runCommand(['admit-passkey', T], { folder: w.folder, port: w.port, input: 'no\n' });
    assert.match(both.out, /2 permissions handed over from the application wait here/);
    assert.ok(both.out.indexOf('NEWER') >= 0 && both.out.indexOf('NEWER') < both.out.indexOf('OLDER'), 'the one that starts latest first');
    const took = await runCommand(['admit-passkey', T], { folder: w.folder, port: w.port, input: 'yes\n' });
    assert.equal(took.code, 0, took.out);
    assert.equal((await status(w.port)).slip, kept.fingerprint, 'the one that starts latest is taken');
    assert.equal(readTrusted(w.folder).includes(T), true);
  } finally {
    await w.service.close();
  }
});
