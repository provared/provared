// Records handed to the agent's recorder (handover.mjs): the
// renewals and cancellations the application keeps with the book, handed
// by the uploader to the real recorder beside Claude Code, run as a program
// on a temporary folder and a port of the test's own (never the recorder's
// own folder or port 8794). What the book keeps is a stand-in here; the
// recorder, its feed and its checks are real. The recorder is found as in
// feed-recorder.test.mjs (PROVARED_RECORDER); without it these tests are
// skipped with one line, and with PROVARED_EXPECT_STACK=1 they fail.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCryptoCore } from '@microtoll/crypto-core';
import { assembleCancellation, assembleSlip, formatTime, prepareCancellation, prepareSlip, thumbprint } from 'provared';
import { developmentPasskey } from 'provared/dev';
import { feedClient } from '../upload.mjs';
import { CANCELLATION_ALLOWANCE_MS, bookSide, createHandover, recordFingerprint, recordsToHand } from '../handover.mjs';
import { NAMESPACE } from '../entry.mjs';
import { openOutcomes, sealOutcomes } from '../outcomes.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const recorderFile = resolve(process.env.PROVARED_RECORDER || join(here, '..', '..', 'integrations', 'claude-code', 'recorder.mjs'));
const found = existsSync(recorderFile) && readFileSync(recorderFile, 'utf8').includes('handOver');
const expected = process.env.PROVARED_EXPECT_STACK === '1';
if (!found) console.log(`# No recorder beside Claude Code that takes records handed over at ${recorderFile}: these tests are ${expected ? 'failed' : 'skipped'}. Name one in PROVARED_RECORDER.`);
const skip = !found && !expected ? 'no recorder that takes records handed over' : false;

const cc = createCryptoCore({ namespace: NAMESPACE });
const quiet = { info() {}, error() {} };
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const LIVE_PORT = 8794;

function freePort() {
  return new Promise((ok, no) => {
    const s = createServer();
    s.once('error', no);
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => ok(port)); });
  });
}

/** The recorder, run as a program on a folder of its own, under a permission from the person's passkey. */
async function recorder() {
  assert.ok(found, `no recorder that takes records handed over at ${recorderFile}; name one in PROVARED_RECORDER`);
  const folder = mkdtempSync(join(tmpdir(), 'provared-app-handover-'));
  const port = await freePort();
  assert.notEqual(port, LIVE_PORT);
  // The development stand-in for a passkey signs at http://localhost: the recorder is told to take records signed there.
  const env = { ...process.env, PROVARED_CLAUDE_CODE_DIR: folder, PROVARED_CLAUDE_CODE_PORT: String(port), PROVARED_CLAUDE_CODE_SIGNING_ORIGIN: 'http://localhost' };
  const command = (...args) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', recorderFile, ...args], { env, encoding: 'utf8' });
  // A command the person answers by typing (admit-passkey asks before it takes a passkey never trusted).
  const answered = (typed, ...args) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', recorderFile, ...args], { env, encoding: 'utf8', input: typed });
  const keys = command('keys');
  assert.equal(keys.status, 0, keys.stderr);
  const agentKeys = JSON.parse(keys.stdout.split('\n').find((l) => l.startsWith('[')));
  const passkey = await developmentPasskey();
  const slip = async (signer = passkey, { from = Date.now() - 60000, purpose = 'The permission.' } = {}) => {
    const prepared = await prepareSlip({
      issuer: { name: 'Sam (development)', key: signer.key, rpId: signer.rpId, origin: signer.origin },
      agent: { name: 'A coding agent', keys: agentKeys },
      actions: ['provared.code.read', 'provared.code.run'],
      limits: [], requires: [], never: [], with: [],
      validFrom: formatTime(from), validUntil: formatTime(Date.now() + 3600000),
      purpose,
    });
    return assembleSlip(prepared, await signer.sign(prepared.challenge));
  };
  const first = await slip();
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(first));
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', recorderFile, 'start'], { env, stdio: 'ignore' });
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 120; i++) {
    try { if ((await fetch(`${base}/status`)).ok) break; } catch { /* not yet */ }
    await pause(250);
  }
  const status = async () => (await fetch(`${base}/status`)).json();
  return {
    folder, port, passkey, first, slip, command, answered, status,
    feed: () => feedClient({ address: base, token: readFileSync(join(folder, 'feed-token'), 'utf8').trim() }),
    book: () => readFileSync(join(folder, 'book.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)),
    before: async (id) => (await fetch(`${base}/before`, { method: 'POST', body: JSON.stringify({ action: 'provared.code.run', toolUseId: id }) })).json(),
    async stop() {
      try { await fetch(`${base}/stop`, { method: 'POST', body: '{}' }); } catch { /* stopped */ }
      await new Promise((ok) => { if (child.exitCode !== null) ok(); else child.once('exit', ok); });
    },
  };
}

async function cancellationOf(passkey, slip) {
  const prepared = await prepareCancellation({ slip: recordFingerprint(slip) });
  return assembleCancellation(prepared, await passkey.sign(prepared.challenge));
}

/** A hand-over on the recorder's feed, with what the book keeps as given, the notes written kept, and a clock of the test's own. */
function handing(r, kept) {
  const notes = [];
  const clock = { now: Date.now() };
  const asked = [];
  const feed = r.feed();
  const counted = { ...feed, handOver: (record) => { asked.push(record); return feed.handOver(record); } };
  const h = createHandover({ feed: counted, readKept: async () => kept, putOutcomes: async (list) => { notes.push(list); }, log: quiet, now: () => clock.now });
  return { h, notes, clock, asked, last: () => notes.at(-1) ?? [] };
}

const kinds = (book) => book.map((e) => Object.keys(e)[0]);

test('a renewal and a cancellation kept with the book are handed to the recorder, which takes each once; the book shows both, with the agent\'s acknowledgement', { skip }, async (t) => {
  const r = await recorder();
  t.after(() => r.stop());
  const renewal = await r.slip(r.passkey, { purpose: 'The renewed permission.' });
  const kept = { renewals: [{ slip: renewal, fingerprint: recordFingerprint(renewal) }], cancellations: [] };
  const { h, notes, asked, clock, last } = handing(r, kept);
  const answers = await h.round();
  assert.deepEqual(answers.map((a) => [a.kind, a.outcome]), [['renewal', 'taken']]);
  assert.equal((await r.status()).slip, recordFingerprint(renewal));
  assert.deepEqual(kinds(r.book()), ['slip', 'slip']);
  assert.deepEqual(last().map((o) => [o.kind, o.fingerprint, o.outcome]), [['renewal', recordFingerprint(renewal), 'taken']]);
  // Not handed over again: the recorder said the book holds it.
  clock.now += 3600000;
  await h.round();
  assert.equal(asked.length, 1);
  assert.equal(notes.length, 1, 'the note is not written again where nothing changed');

  // The person cancels the renewed permission.
  kept.cancellations.push({ cancellation: await cancellationOf(r.passkey, renewal) });
  const cancelled = await h.round();
  assert.deepEqual(cancelled.map((a) => [a.kind, a.outcome]), [['cancellation', 'taken']]);
  assert.deepEqual(kinds(r.book()), ['slip', 'slip', 'cancellation', 'acknowledgement']);
  const ack = r.book().at(-1).acknowledgement;
  const content = JSON.parse(Buffer.from(ack.payload, 'base64url').toString());
  assert.equal(content.cancellation, recordFingerprint(kept.cancellations[0].cancellation));
  assert.equal((await r.before('after')).allowed, false, 'no call is taken under a cancelled permission');
});

test('a record handed over twice, or by an uploader started again, is taken once', { skip }, async (t) => {
  const r = await recorder();
  t.after(() => r.stop());
  const renewal = await r.slip(r.passkey, { purpose: 'Handed over twice.' });
  const kept = { renewals: [{ slip: renewal, fingerprint: recordFingerprint(renewal) }, { slip: renewal, fingerprint: recordFingerprint(renewal) }], cancellations: [] };
  const first = handing(r, kept);
  assert.deepEqual((await first.h.round()).map((a) => a.outcome), ['taken']);
  // A second uploader (started again) knows nothing of the first: the recorder answers that it holds it.
  const second = handing(r, kept);
  assert.deepEqual((await second.h.round()).map((a) => [a.kind, a.outcome]), [['renewal', 'already']]);
  // The person cancels it. The kept renewal starts before the cancellation, so it is no longer handed over.
  kept.cancellations.push({ cancellation: await cancellationOf(r.passkey, renewal) });
  const third = handing(r, kept);
  assert.deepEqual((await third.h.round()).map((a) => [a.kind, a.outcome]), [['cancellation', 'taken']]);
  const fourth = handing(r, kept);
  assert.deepEqual((await fourth.h.round()).map((a) => [a.kind, a.outcome]), [['cancellation', 'already']]);
  assert.deepEqual(kinds(r.book()), ['slip', 'slip', 'cancellation', 'acknowledgement'], 'each once in the book');
});

test('a renewal from a passkey the agent\'s computer does not trust is refused and reported, and nothing is admitted; admitted there, it is taken at the next try', { skip }, async (t) => {
  const r = await recorder();
  t.after(() => r.stop());
  const stranger = await developmentPasskey();
  const T = await thumbprint(stranger.key);
  const renewal = await r.slip(stranger, { purpose: 'From another passkey.' });
  const kept = { renewals: [{ slip: renewal, fingerprint: recordFingerprint(renewal) }], cancellations: [] };
  const { h, asked, clock, last } = handing(r, kept);
  const [a] = await h.round();
  assert.equal(a.outcome, 'refused');
  assert.equal(a.code, 'passkey-not-trusted');
  assert.deepEqual(last(), [{ kind: 'renewal', fingerprint: recordFingerprint(renewal), outcome: 'refused', code: 'passkey-not-trusted', thumbprint: T, at: last()[0].at }]);
  const trusted = JSON.parse(readFileSync(join(r.folder, 'trusted-passkeys.json'), 'utf8'));
  assert.equal(trusted.passkeys.includes(T), false, 'nothing admitted');
  assert.deepEqual(kinds(r.book()), ['slip']);
  // Not asked again within the minute.
  await h.round();
  assert.equal(asked.length, 1);
  // On the agent's computer, the command shows the permission waiting and takes nothing until the person types "yes".
  const shown = r.answered('no', 'admit-passkey', T);
  assert.equal(shown.status, 1);
  assert.ok(shown.stdout.includes(T), shown.stdout);
  assert.match(shown.stdout, /Purpose\s+From another passkey\./);
  assert.match(shown.stdout, /Nothing was changed/);
  assert.equal(JSON.parse(readFileSync(join(r.folder, 'trusted-passkeys.json'), 'utf8')).passkeys.includes(T), false);
  // The person confirms: the passkey is taken with that permission, which the book now holds.
  const admitted = r.answered('yes', 'admit-passkey', T);
  assert.equal(admitted.status, 0, admitted.stderr || admitted.stdout);
  assert.deepEqual(kinds(r.book()), ['slip', 'slip']);
  // A minute later it is handed over again: the book holds it already.
  clock.now += 61000;
  assert.deepEqual((await h.round()).map((x) => x.outcome), ['already']);
  assert.equal(last()[0].outcome, 'already');
});

test('a record altered, or a permission replaced before and handed over again, is refused by the recorder; the book does not change', { skip }, async (t) => {
  const r = await recorder();
  t.after(() => r.stop());
  const renewal = await r.slip(r.passkey, { purpose: 'Signed by the person.' });
  const content = JSON.parse(Buffer.from(renewal.payload, 'base64url').toString());
  content.purpose = 'Changed on the way.';
  const altered = { ...renewal, payload: Buffer.from(JSON.stringify(content)).toString('base64url') };
  const kept = { renewals: [{ slip: altered, fingerprint: recordFingerprint(altered) }], cancellations: [] };
  const { h, asked, clock, last } = handing(r, kept);
  const [a] = await h.round();
  assert.deepEqual([a.outcome, a.code], ['refused', 'not-sound']);
  assert.deepEqual(kinds(r.book()), ['slip']);
  clock.now += 3600000;
  await h.round();
  assert.equal(asked.length, 1, 'refused for good: not handed over again');
  // The person's renewal, then the first permission handed over again (a record held back and replayed).
  kept.renewals = [{ slip: renewal, fingerprint: recordFingerprint(renewal) }];
  assert.deepEqual((await h.round()).map((x) => x.outcome), ['taken']);
  kept.renewals = [{ slip: r.first, fingerprint: recordFingerprint(r.first) }];
  const [replay] = await h.round();
  assert.deepEqual([replay.outcome, replay.code], ['refused', 'not-again']);
  assert.equal((await r.status()).slip, recordFingerprint(renewal), 'the renewal stays in force');
  assert.deepEqual(last().map((o) => [o.outcome, o.code]), [['refused', 'not-again']], 'the note holds what the book keeps now');
  assert.deepEqual(kinds(r.book()), ['slip', 'slip']);
});

test('what the book keeps is read with the book\'s key: content the server changed does not open, and nothing is handed over', async () => {
  const objectId = crypto.randomUUID();
  const kObject = cc.generateSymmetricKey();
  const key = await cc.importSymmetricKey(kObject);
  const { sealContent } = await import('@microtoll/access');
  const sealed = await sealContent(cc, key, objectId, 1, { name: 'b', renewals: [], cancellations: [] });
  sealed[sealed.length - 1] ^= 1;
  // A connection that answers "fetch-event" with the changed content, as a server would.
  const sent = [];
  const listeners = new Set();
  const socket = {
    readyState: 1,
    send(text) {
      const msg = JSON.parse(text);
      sent.push(msg.type);
      if (msg.type === 'fetch-event') setImmediate(() => { for (const l of listeners) l({ data: JSON.stringify({ type: 'event', requestId: msg.requestId, event: { id: objectId, keyEpoch: 1, encryptedEventData: cc.toBase64Url(sealed), selector: 'ab' } }) }); });
    },
    addEventListener(type, l) { if (type === 'message') listeners.add(l); },
    removeEventListener(type, l) { listeners.delete(l); },
  };
  const side = bookSide({ cc, connection: { objectId, appendCapabilitySecret: cc.toBase64Url(cc.randomBytes(32)) }, connect: async () => socket, key: async () => key });
  await assert.rejects(side.readKept(), { reason: 'rekeyed' });
  let handed = 0;
  const h = createHandover({ feed: { handOver: async () => { handed++; return { outcome: 'taken' }; } }, readKept: side.readKept, putOutcomes: async () => {}, log: quiet });
  await assert.rejects(h.round());
  assert.equal(handed, 0);
});

test('the note of outcomes opens only for its own book, and holds only outcomes in its form', async () => {
  const objectId = crypto.randomUUID();
  const key = await cc.importSymmetricKey(cc.generateSymmetricKey());
  const fp = 'A'.repeat(43);
  const sealed = await sealOutcomes(cc, key, objectId, [
    { kind: 'renewal', fingerprint: fp, outcome: 'refused', code: 'passkey-not-trusted', thumbprint: 'B'.repeat(43), at: '2026-11-01T10:00:00.000Z' },
    { kind: 'renewal', fingerprint: 'short', outcome: 'taken', at: '2026-11-01T10:00:00.000Z' },
    { kind: 'renewal', fingerprint: fp, outcome: 'refused', code: '<b>bold</b>', at: '2026-11-01T10:00:00.000Z' },
    { kind: 'other', fingerprint: fp, outcome: 'taken', at: '2026-11-01T10:00:00.000Z' },
    // A thumbprint that is not one: the whole outcome is set aside.
    { kind: 'cancellation', fingerprint: fp, outcome: 'refused', code: 'passkey-retired', thumbprint: '<b>x</b>', at: '2026-11-01T10:00:00.000Z' },
    { kind: 'cancellation', fingerprint: fp, outcome: 'refused', code: 'passkey-retired', thumbprint: 'B'.repeat(42), at: '2026-11-01T10:00:00.000Z' },
  ]);
  assert.deepEqual(await openOutcomes(cc, key, objectId, sealed), [{ kind: 'renewal', fingerprint: fp, outcome: 'refused', code: 'passkey-not-trusted', thumbprint: 'B'.repeat(43), at: '2026-11-01T10:00:00.000Z' }]);
  await assert.rejects(openOutcomes(cc, key, crypto.randomUUID(), sealed), 'another book');
});

/** A record with the content given, as the uploader reads it (its signature is the recorder's business). */
const recordOf = (content) => ({ payload: Buffer.from(JSON.stringify(content)).toString('base64url'), signatures: [] });

test('the order a hand-over takes: cancellations first, then new permissions; a new permission that starts less than five minutes after a kept cancellation is not handed over', () => {
  assert.equal(CANCELLATION_ALLOWANCE_MS, 300 * 1000);
  const slipFp = 'S'.repeat(43);
  const c1 = recordOf({ type: 'provared.cancellation.v0', slip: slipFp, when: '2026-11-01T10:00:00Z' });
  const c2 = recordOf({ type: 'provared.cancellation.v0', slip: slipFp, when: '2026-11-01T11:00:00Z' });
  const early = recordOf({ validFrom: '2026-11-01T10:30:00Z', purpose: 'signed between the two cancellations' });
  const same = recordOf({ validFrom: '2026-11-01T11:00:00Z', purpose: 'starts the second the last cancellation is dated' });
  const soon = recordOf({ validFrom: '2026-11-01T11:04:59Z', purpose: 'starts a second short of five minutes after it' });
  const later = recordOf({ validFrom: '2026-11-01T11:05:00Z', purpose: 'starts five minutes after it, as the page makes it' });
  const order = recordsToHand({ renewals: [{ slip: early }, { slip: same }, { slip: soon }, { slip: later }], cancellations: [{ cancellation: c1 }, { cancellation: c2 }] });
  assert.deepEqual(order.map((o) => [o.kind, o.fingerprint]), [
    ['cancellation', recordFingerprint(c1)], ['cancellation', recordFingerprint(c2)], ['renewal', recordFingerprint(later)],
  ]);
  // With no cancellation kept, every readable new permission is handed over, in its order.
  assert.deepEqual(recordsToHand({ renewals: [{ slip: later }, { slip: early }], cancellations: [] }).map((o) => o.fingerprint), [recordFingerprint(later), recordFingerprint(early)]);
});

test('an earlier renewal kept beside a later cancellation is not handed over: the agent stays stopped', { skip }, async (t) => {
  const r = await recorder();
  t.after(() => r.stop());
  // The person signs a renewal, which is held back; then cancels the permission in force.
  const early = await r.slip(r.passkey, { from: Date.now() - 30000, purpose: 'Signed before the cancellation.' });
  await pause(1100);
  const kept = { renewals: [{ slip: early, fingerprint: recordFingerprint(early) }], cancellations: [{ cancellation: await cancellationOf(r.passkey, r.first) }] };
  const { h, asked } = handing(r, kept);
  assert.deepEqual((await h.round()).map((a) => [a.kind, a.outcome]), [['cancellation', 'taken']]);
  assert.deepEqual(asked.map((a) => a.kind), ['cancellation'], 'the earlier renewal is not handed over');
  assert.equal((await r.before('after')).allowed, false);
  // Handed over all the same (an uploader of an earlier version): the recorder refuses it.
  const [refused] = await createHandover({ feed: r.feed(), readKept: async () => ({ renewals: [{ slip: early }], cancellations: [] }), putOutcomes: async () => {}, log: quiet }).round();
  assert.deepEqual([refused.outcome, refused.code], ['refused', 'before-cancellation']);
  assert.equal((await r.before('still')).allowed, false, 'the agent stays stopped');
  assert.deepEqual(kinds(r.book()), ['slip', 'cancellation', 'acknowledgement']);
});
