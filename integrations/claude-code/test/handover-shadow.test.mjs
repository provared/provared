// The uploader beside this recorder (connect/handover.mjs, connect/upload.mjs)
// against the real waiting recorder, in this process, through its own feed:
// a record kept with the book that names the person's passkey and a later
// start, but is larger than the feed takes, does not keep the person's first
// permission back. The uploader answers it for good itself ("too-large") and
// hands over the passkey's next in the same round. Skipped where the
// uploader is not beside this package.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { formatTime } = await import('provared');
const { readWaitingPermissions } = await import('../recorder.mjs');
const { startWaiting } = await import('../waiting.mjs');
const { freshWorld, signSlip } = await import('./world.mjs');

const connect = new URL('../../../connect/', import.meta.url);
const skip = existsSync(new URL('handover.mjs', connect)) ? false : 'no uploader beside this package';
const quiet = { info() {}, error() {} };

test('a kept record over 256 KiB with the person\'s passkey and a later start does not keep the person\'s first permission back', { skip }, async () => {
  const { createHandover, recordFingerprint } = await import(new URL('handover.mjs', connect));
  const { feedClient } = await import(new URL('upload.mjs', connect));
  const w = await freshWorld();
  const waiting = await startWaiting({ folder: w.folder, port: 0, signingOrigins: ['http://localhost'] });
  try {
    const client = feedClient({ address: `http://127.0.0.1:${waiting.port}`, token: readFileSync(join(w.folder, 'feed-token'), 'utf8').trim() });
    const real = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, from: Date.now() - 120000, purpose: 'the person\'s real first permission' });
    const content = JSON.parse(Buffer.from(real.payload, 'base64url').toString('utf8'));
    const forged = { ...real, payload: Buffer.from(JSON.stringify({ ...content, validFrom: formatTime(Date.now() - 1000), purpose: 'x'.repeat(300000) })).toString('base64url') };
    const clock = { now: Date.now() };
    const h = createHandover({ feed: client, readKept: async () => ({ renewals: [{ slip: real }, { slip: forged }], cancellations: [] }), putOutcomes: async () => {}, log: quiet, now: () => clock.now });
    const named = (answers) => answers.map((a) => [a.fingerprint === recordFingerprint(real) ? 'real' : 'other', a.code]);
    assert.deepEqual(named(await h.round()), [['other', 'too-large'], ['real', 'waits-for-yes']]);
    assert.deepEqual(readWaitingPermissions(w.folder).map((p) => p.fingerprint), [recordFingerprint(real)], 'the person\'s permission waits on the computer');
    // A minute later, only the person's is handed over again.
    clock.now += 61000;
    assert.deepEqual(named(await h.round()), [['real', 'waits-for-yes']]);
  } finally {
    await waiting.close();
  }
});
