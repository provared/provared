// A book sealed by a central sealer (format description, section 21.7):
// the recorder's keys are held by the program in sealer/, the executor
// sends it the leaf fingerprint of each line as the line is written, and
// the sealer signs seals only over what it was sent.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { test } from 'node:test';

const { leafFingerprint, toBase64url } = await import('provared');
const { openWorld } = await import('./world.mjs');
const { centralWorld } = await import('./sealer-world.mjs');

test('central sealer: each line\'s leaf fingerprint is sent as the line is written, and the seal the sealer signs is added to the book', async () => {
  const w = await centralWorld();
  try {
    // At the start the sealer was sent the permission's line, the book's first.
    assert.equal((await w.held()).size, 1);
    await w.client.call('echo', {});
    await w.client.call('echo', {});
    await w.level();
    assert.equal(w.lines().length, 3);
    assert.deepEqual((await w.executor.report()).agent.sealer, { address: w.settings.recorder.sealer.address, recorder: 'guard-one', unsent: 0, since: null, answeredAt: (await w.executor.report()).agent.sealer.answeredAt, problem: null });
    const sealed = await w.executor.seal();
    assert.equal(sealed.entry, 3, 'the permission, two receipts, then the seal');
    const c = await w.checked();
    assert.equal(c.summary.problemFound, false);
    assert.equal(c.entries[3].kind, 'seal');
    assert.equal(c.entries[3].fingerprint, sealed.fingerprint);
    assert.equal(c.entries[3].content.size, 3);
    assert.deepEqual(c.entries[3].signatures.map((s) => s.state), ['valid', 'valid', 'valid']);
    // The seal's own line is a line of the book like any other: the sealer is sent it too.
    await w.level();
    const held = await w.held();
    assert.equal(held.size, 4);
    assert.equal(held.latest, sealed.fingerprint);
    // A second seal names the first.
    await w.client.call('echo', {});
    const second = await w.executor.seal();
    assert.equal(second.entry, 5);
    const again = await w.checked();
    assert.equal(again.summary.problemFound, false);
    assert.equal(again.entries[5].content.previous, sealed.fingerprint);
    assert.equal(toBase64url(await leafFingerprint(w.lines()[0])), await w.first());
  } finally {
    await w.close();
    await w.sealer.stop();
  }
});

test('central sealer: a restart of the executor goes on from the line the sealer holds, and sends no line twice', async () => {
  const w = await centralWorld();
  try {
    await w.client.call('echo', {});
    await w.close();
    assert.equal((await w.held()).size, 2, 'the last line was sent before the executor ended');
    await openWorld(w);
    await w.client.call('echo', {});
    await w.level();
    assert.equal((await w.held()).size, 3);
    await w.executor.seal();
    assert.equal((await w.checked()).summary.problemFound, false);
  } finally {
    await w.close();
    await w.sealer.stop();
  }
});
