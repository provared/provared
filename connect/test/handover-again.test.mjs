// What the uploader hands over again, and how many (handover.mjs,
// createHandover), with a stand-in for the recorder's feed and a clock of
// the test's own: a first permission that waits for the person's "yes"
// ("waits-for-yes") and a cancellation that came while nothing was in force
// ("nothing-in-force") are handed over again; and in one round at most one
// new permission for each passkey, the one that starts latest, as the
// waiting recorder keeps one for each passkey.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AGAIN, createHandover, recordFingerprint } from '../handover.mjs';

const quiet = { info() {}, error() {} };
/** A record with the content given, as the uploader reads it (its signature is the recorder's business). */
const recordOf = (content) => ({ payload: Buffer.from(JSON.stringify(content)).toString('base64url'), signatures: [] });
const passkey = (x) => ({ kty: 'EC', crv: 'P-256', x: x.repeat(43), y: 'Y'.repeat(43) });
const renewal = (key, validFrom, purpose = 'a permission') => recordOf({ issuer: { name: 'Sam', key }, validFrom, purpose });

/** A hand-over against a feed that answers each record with answer(record), on the test's own clock. */
function handing(kept, answer, againMs = 1000) {
  const asked = [];
  const clock = { now: Date.parse('2026-11-22T10:00:00Z') };
  const feed = { handOver: async (record) => { asked.push(record); return answer(record); } };
  const h = createHandover({ feed, readKept: async () => kept, putOutcomes: async () => {}, log: quiet, now: () => clock.now, againMs });
  return { h, asked, clock };
}

const fingerprints = (records) => records.map((r) => recordFingerprint(r.slip ?? r.cancellation));

test('"waits-for-yes" and "nothing-in-force" are handed over again', async () => {
  assert.ok(AGAIN.includes('waits-for-yes'));
  assert.ok(AGAIN.includes('nothing-in-force'));
  const first = renewal(passkey('A'), '2026-11-22T09:59:00Z');
  const cancellation = recordOf({ type: 'provared.cancellation.v0', slip: 'S'.repeat(43), when: '2026-11-22T09:00:00Z' });
  const kept = { renewals: [{ slip: first }], cancellations: [{ cancellation }] };
  // While the recorder waits: the cancellation finds nothing in force, the permission waits for "yes".
  let waiting = true;
  const { h, asked, clock } = handing(kept, (record) => {
    if (record.kind === 'cancellation') return waiting ? { outcome: 'refused', code: 'nothing-in-force' } : { outcome: 'taken' };
    return waiting ? { outcome: 'refused', code: 'waits-for-yes', thumbprint: 'T'.repeat(43) } : { outcome: 'already' };
  });
  assert.deepEqual((await h.round()).map((a) => a.code), ['nothing-in-force', 'waits-for-yes']);
  // Not within the again time.
  await h.round();
  assert.equal(asked.length, 2);
  clock.now += 1001;
  assert.deepEqual((await h.round()).map((a) => a.code), ['nothing-in-force', 'waits-for-yes']);
  // The person typed "yes" on the agent's computer: both are answered for good at the next try.
  waiting = false;
  clock.now += 1001;
  assert.deepEqual((await h.round()).map((a) => a.outcome), ['taken', 'already']);
  clock.now += 3600000;
  await h.round();
  assert.equal(asked.length, 6);
});

test('at most one new permission for each passkey in a round: the one that starts latest', async () => {
  const p = passkey('P');
  const q = passkey('Q');
  const p1 = renewal(p, '2026-11-22T09:00:00Z', 'P, earlier');
  const p2 = renewal(p, '2026-11-22T09:30:00Z', 'P, latest');
  const p3 = renewal(p, '2026-11-22T09:10:00Z', 'P, between');
  const q1 = renewal(q, '2026-11-22T09:20:00Z', 'Q, the one');
  // The same passkey with its members written in another order is the same passkey.
  const p4 = renewal(Object.fromEntries(Object.entries(p).reverse()), '2026-11-22T09:05:00Z', 'P, written otherwise');
  const kept = { renewals: [{ slip: p1 }, { slip: p2 }, { slip: q1 }, { slip: p3 }, { slip: p4 }], cancellations: [] };
  const answers = new Map([[recordFingerprint(p2), { outcome: 'refused', code: 'waits-for-yes' }]]);
  const { h, asked, clock } = handing(kept, (record) => answers.get(recordFingerprint(record.slip)) ?? { outcome: 'refused', code: 'waits-for-yes' });
  await h.round();
  assert.deepEqual(fingerprints(asked), fingerprints([{ slip: p2 }, { slip: q1 }]));
  // Again after the again time: the same ones, never the earlier ones from P while P's latest waits.
  clock.now += 500;
  await h.round();
  assert.equal(asked.length, 2, 'P\'s latest is not due yet, and no other of P\'s takes its place');
  clock.now += 501;
  await h.round();
  assert.deepEqual(fingerprints(asked.slice(2)), fingerprints([{ slip: p2 }, { slip: q1 }]));
  // The recorder answers P's latest for good (it starts too far ahead, say): the next of P's, by its start, comes next.
  answers.set(recordFingerprint(p2), { outcome: 'refused', code: 'starts-later' });
  clock.now += 1001;
  await h.round();
  assert.deepEqual(fingerprints(asked.slice(4)), fingerprints([{ slip: p2 }, { slip: q1 }]));
  clock.now += 1001;
  await h.round();
  assert.deepEqual(fingerprints(asked.slice(6)), fingerprints([{ slip: q1 }, { slip: p3 }]));
});

test('two of one passkey that start alike: the first kept is handed over; one whose passkey cannot be read is its own', async () => {
  const p = passkey('P');
  const a = renewal(p, '2026-11-22T09:00:00Z', 'first kept');
  const b = renewal(p, '2026-11-22T09:00:00Z', 'second kept');
  const unread = recordOf({ validFrom: '2026-11-22T09:00:00Z', purpose: 'no passkey named' });
  const unread2 = recordOf({ validFrom: '2026-11-22T09:01:00Z', purpose: 'no passkey named either' });
  const { h, asked } = handing({ renewals: [{ slip: a }, { slip: b }, { slip: unread }, { slip: unread2 }], cancellations: [] }, () => ({ outcome: 'refused', code: 'not-sound' }));
  await h.round();
  assert.deepEqual(fingerprints(asked), fingerprints([{ slip: a }, { slip: unread }, { slip: unread2 }]));
});
