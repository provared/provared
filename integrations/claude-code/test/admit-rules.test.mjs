// The rules of "admit-passkey" and POST /admit for a passkey this computer
// does not trust. The person names the passkey by its thumbprint, or its
// first 16 characters or more, pasted from the signing window; with no
// argument the command only lists. The recorder takes the permission from
// its own waiting list, by fingerprint, never from the request. Checking
// drops nothing. Only "yes" typed at a terminal takes; only a typed "no"
// declines, and a declined permission is refused from then on. Every test
// works in a temporary folder and on a port of its own.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

const { assembleCancellation, prepareCancellation, thumbprint } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { feedReader } = await import('../feed.mjs');
const { ADMIT_THUMBPRINT_LEAST, admitWaiting, readTrusted, readWaitingPermissions, startService } = await import('../recorder.mjs');
const { runCommand, signSlip, status, world } = await import('./world.mjs');

const LOCAL = { signingOrigins: ['http://localhost'] };
const read = (folder, name) => readFileSync(join(folder, name), 'utf8');

async function running() {
  const w = await world([]);
  const service = await startService({ folder: w.folder, port: 0, ...LOCAL });
  const reader = feedReader({ address: `http://127.0.0.1:${service.port}`, token: read(w.folder, 'feed-token').trim() });
  const hand = async (record) => (await reader.post('/hand-over', record)).body;
  return { ...w, service, port: service.port, reader, hand };
}

/** "admit-passkey" as a person runs it at a terminal, typing "typed": its exit code and every line it says. */
async function admitAt(w, given, typed, more = {}) {
  const said = [];
  const asked = [];
  const code = await admitWaiting(w.folder, w.port, given, { answer: async (prompt) => { asked.push(prompt); return typed; }, terminal: true, say: (words) => said.push(words), ...more });
  return { code, out: said.join('\n'), asked };
}

/** A second passkey's permission, handed over and waiting. */
async function waitingFrom(w, purpose = 'From my second passkey.', passkey) {
  passkey ??= await developmentPasskey();
  const T = await thumbprint(passkey.key);
  const slip = await signSlip({ agentKeys: w.agent.keys, passkey, purpose });
  const said = await w.hand({ kind: 'renewal', slip });
  assert.equal(said.code, 'passkey-not-trusted');
  return { passkey, T, slip, fp: said.fingerprint };
}

test('a kept permission swapped for one of the same wording from another passkey is not admitted with the person\'s thumbprint', async () => {
  const w = await running();
  try {
    const mine = await waitingFrom(w, 'The same wording.');
    const theirs = await signSlip({ agentKeys: w.agent.keys, passkey: await developmentPasskey(), purpose: 'The same wording.' });
    const A = await thumbprint(JSON.parse(Buffer.from(theirs.payload, 'base64url').toString()).issuer.key);
    // The server puts the stranger's permission in place of the person's, under the person's thumbprint and fingerprint.
    const list = JSON.parse(read(w.folder, 'waiting-permissions.json'));
    list.permissions[0].slip = theirs;
    writeFileSync(join(w.folder, 'waiting-permissions.json'), JSON.stringify(list));
    const r = await admitAt(w, mine.T, 'yes');
    assert.equal(r.code, 1, r.out);
    assert.match(r.out, /No permission from a passkey starting with/);
    assert.deepEqual(r.asked, [], 'nothing is asked');
    // Asked of the recorder directly, with the person's thumbprint: refused, since its own list's permission is the stranger's.
    const listed = readWaitingPermissions(w.folder)[0];
    const direct = await w.reader.post('/admit', { fingerprint: listed.fingerprint, thumbprint: mine.T, take: true });
    assert.equal(direct.body.outcome, 'refused');
    assert.notEqual(direct.body.code, undefined);
    assert.equal(readTrusted(w.folder).includes(mine.T), false);
    assert.equal(readTrusted(w.folder).includes(A), false);
    assert.equal((await status(w.port)).issuer, await thumbprint(w.passkey.key), 'the permission in force is the first one still');
  } finally {
    await w.service.close();
  }
});

test('POST /admit takes the permission from the recorder\'s own list by fingerprint: a slip sent in the request, and a fingerprint not waiting, are refused', async () => {
  const w = await running();
  try {
    const stranger = await developmentPasskey();
    const S = await thumbprint(stranger.key);
    const notWaiting = await signSlip({ agentKeys: w.agent.keys, passkey: stranger, purpose: 'Never handed over.' });
    const before = read(w.folder, 'trusted-passkeys.json');
    const sent = await w.reader.post('/admit', { slip: notWaiting, thumbprint: S, take: true });
    assert.equal(sent.body.outcome, 'refused');
    assert.equal(sent.body.code, 'not-understood');
    const { fingerprint, fromBase64url } = await import('provared');
    const fp = await fingerprint(fromBase64url(notWaiting.payload));
    const named = await w.reader.post('/admit', { fingerprint: fp, thumbprint: S, take: true });
    assert.equal(named.body.outcome, 'refused');
    assert.equal(named.body.code, 'no-such-permission');
    assert.equal(read(w.folder, 'trusted-passkeys.json'), before, 'no passkey is trusted');
    assert.equal(readTrusted(w.folder).includes(S), false);
  } finally {
    await w.service.close();
  }
});

test('"take": false, and a check that fails, drop nothing from the waiting list; the command says why and leaves it waiting', async () => {
  const w = await running();
  try {
    const mine = await waitingFrom(w);
    const checked = await w.reader.post('/admit', { fingerprint: mine.fp, thumbprint: mine.T, take: false });
    assert.equal(checked.body.outcome, 'would-take', checked.body.message);
    assert.equal(readWaitingPermissions(w.folder).length, 1, 'a check drops nothing');
    // A cancellation of the permission in force after it was signed: the check fails, and the permission is left waiting.
    await delay(1100);
    const prepared = await prepareCancellation({ slip: (await status(w.port)).slip, when: Date.now() });
    assert.equal((await w.hand({ kind: 'cancellation', cancellation: assembleCancellation(prepared, await w.passkey.sign(prepared.challenge)) })).outcome, 'taken');
    const r = await admitAt(w, mine.T, 'yes');
    assert.equal(r.code, 1, r.out);
    assert.match(r.out, /left waiting/);
    assert.match(r.out, /less than 5 minutes after the person's cancellation/);
    assert.deepEqual(r.asked, [], 'nothing is asked');
    assert.equal(readWaitingPermissions(w.folder).length, 1, 'the command drops nothing');
    assert.equal(readTrusted(w.folder).includes(mine.T), false);
  } finally {
    await w.service.close();
  }
});

test(`a thumbprint start under ${ADMIT_THUMBPRINT_LEAST} characters, in other case, or matching two passkeys, takes nothing; the first ${ADMIT_THUMBPRINT_LEAST} characters, exactly, take`, async () => {
  const w = await running();
  try {
    // Passkeys until two share a first character (they never share 16), to see what is said where a start matches two.
    const seen = new Map();
    let pair = null;
    while (!pair) {
      const p = await developmentPasskey();
      const T = await thumbprint(p.key);
      if (seen.has(T[0])) pair = [seen.get(T[0]), p];
      else seen.set(T[0], p);
    }
    const a = await waitingFrom(w, 'First of two.', pair[0]);
    const b = await waitingFrom(w, 'Second of two.', pair[1]);
    assert.equal(a.T[0], b.T[0]);
    const short = await admitAt(w, a.T.slice(0, ADMIT_THUMBPRINT_LEAST - 1), 'yes');
    assert.equal(short.code, 2, short.out);
    assert.match(short.out, new RegExp(`at least ${ADMIT_THUMBPRINT_LEAST} characters`));
    assert.match(short.out, /paste it from the signing window/);
    const both = await admitAt(w, a.T[0], 'yes', { least: 1 });
    assert.equal(both.code, 1, both.out);
    assert.match(both.out, /2 passkeys/);
    assert.match(both.out, /more characters/);
    assert.deepEqual([short.asked, both.asked], [[], []], 'nothing is asked');
    const start = a.T.slice(0, ADMIT_THUMBPRINT_LEAST);
    const swapped = start.replace(/[A-Za-z]/, (c) => (c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase()));
    if (swapped !== start) {
      const otherCase = await admitAt(w, swapped, 'yes');
      assert.equal(otherCase.code, 1, otherCase.out);
      assert.match(otherCase.out, /No permission from a passkey starting with/);
    }
    assert.equal(readTrusted(w.folder).includes(a.T), false);
    assert.equal(readTrusted(w.folder).includes(b.T), false);
    assert.equal(readWaitingPermissions(w.folder).length, 2);
    const took = await admitAt(w, start, 'yes');
    assert.equal(took.code, 0, took.out);
    assert.equal(readTrusted(w.folder).includes(a.T), true);
    assert.equal(readTrusted(w.folder).includes(b.T), false);
    assert.equal((await status(w.port)).slip, a.fp);
    assert.deepEqual(readWaitingPermissions(w.folder).map((p) => p.fingerprint), [b.fp], 'the one taken is taken out of the list by the recorder');
  } finally {
    await w.service.close();
  }
});

test('"admit-passkey" shows control and other characters that do not print as escapes, never as they are, in every field', async () => {
  const w = await running();
  try {
    const passkey = await developmentPasskey();
    const T = await thumbprint(passkey.key);
    // An escape sequence, a carriage return, a C1 control, a right-to-left override, a line break, a line separator
    // and a zero-width space (a lone surrogate cannot be signed: the library refuses it).
    const hostile = 'Read only.\u001b[2K\r\u0085‮line one\nFingerprint fake ​';
    const slip = await signSlip({ agentKeys: w.agent.keys, passkey, purpose: hostile, issuerName: `Sam${hostile}`, agentName: `Agent${hostile}` });
    assert.equal((await w.hand({ kind: 'renewal', slip })).code, 'passkey-not-trusted');
    const r = await admitAt(w, T, 'leave it');
    assert.equal(r.code, 1, r.out);
    for (const line of r.out.split('\n')) assert.doesNotMatch(line, /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/u, JSON.stringify(line));
    assert.match(r.out, /Read only\.\\u001b\[2K\\u000d\\u0085\\u202eline one\\u000aFingerprint fake\\u2028\\u200b/);
    assert.match(r.out, /Signed by \(a label\) {4}SamRead only\.\\u001b/);
    assert.match(r.out, /Agent {18}AgentRead only\.\\u001b/);
    assert.equal(readTrusted(w.folder).includes(T), false);
  } finally {
    await w.service.close();
  }
});

test('"admit-passkey" with no argument only lists what waits, and takes nothing', async () => {
  const w = await running();
  try {
    const mine = await waitingFrom(w, 'Listed only.');
    const r = await runCommand(['admit-passkey'], { folder: w.folder, port: w.port, input: 'yes\n' });
    assert.equal(r.code, 0, `${r.out} ${r.err}`);
    assert.ok(r.out.includes(mine.T), r.out);
    assert.ok(r.out.includes(mine.fp), r.out);
    assert.match(r.out, /signing window/);
    assert.doesNotMatch(r.out, /Type yes/);
    assert.equal(readTrusted(w.folder).includes(mine.T), false);
    assert.equal(readWaitingPermissions(w.folder).length, 1);
  } finally {
    await w.service.close();
  }
});

test('"yes" from a pipe takes nothing: the command says it must be typed at a terminal', async () => {
  const w = await running();
  try {
    const mine = await waitingFrom(w);
    const r = await runCommand(['admit-passkey', mine.T], { folder: w.folder, port: w.port, input: 'yes\n' });
    assert.equal(r.code, 1, r.out);
    assert.match(r.out, /Nothing was changed: the answer must be typed at a terminal/);
    assert.equal(readTrusted(w.folder).includes(mine.T), false);
    assert.equal(readWaitingPermissions(w.folder).length, 1, 'it still waits');
  } finally {
    await w.service.close();
  }
});

test('only a typed "no" declines: anything else leaves the permission waiting; a declined permission is refused from then on', async () => {
  const w = await running();
  try {
    const mine = await waitingFrom(w);
    for (const typed of ['', 'nope', 'No', ' maybe ']) {
      const r = await admitAt(w, mine.T, typed);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /the permission waits/);
      assert.equal(readWaitingPermissions(w.folder).length, 1, `"${typed}" leaves it waiting`);
    }
    const no = await admitAt(w, mine.T, 'no');
    assert.equal(no.code, 1, no.out);
    assert.match(no.out, /declined/);
    assert.equal(readWaitingPermissions(w.folder).length, 0, 'declined: it no longer waits');
    assert.deepEqual(JSON.parse(read(w.folder, 'waiting-permissions.json')).declined, [mine.fp]);
    // Handed over again: refused, and not kept.
    const again = await w.hand({ kind: 'renewal', slip: mine.slip });
    assert.equal(again.outcome, 'refused');
    assert.equal(again.code, 'declined');
    assert.equal(readWaitingPermissions(w.folder).length, 0);
    const after = await admitAt(w, mine.T, 'yes');
    assert.equal(after.code, 1);
    assert.equal(readTrusted(w.folder).includes(mine.T), false);
  } finally {
    await w.service.close();
  }
});
