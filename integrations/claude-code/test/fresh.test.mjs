// A fresh folder, as "init" leaves it: the recorder waits there for its
// first permission ("start", "ensure"), and only there. Each of slip.json,
// book.jsonl, a kept book, a kept slip, trusted-passkeys.json and
// held-cancellations.json stops the waiting start; waiting-permissions.json
// alone does not. "ensure" and "use" tell a waiting recorder from a running
// one; "use <file>" while the recorder waits stops it, waits until the port
// is free, and takes the file. Every test works in a temporary folder and on
// a port of its own.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { test } from 'node:test';

const { fingerprint, fromBase64url } = await import('provared');
const { freshFolder } = await import('../recorder.mjs');
const { startWaiting } = await import('../waiting.mjs');
const { freePort, freshWorld, refusedStart, runCommand, signSlip, status, stopService, tempFolder } = await import('./world.mjs');

/** Whether anything answers on the port, asked again until "ms" have passed on the monotonic clock. */
async function answersWithin(port, ms) {
  for (const until = performance.now() + ms; performance.now() < until;) {
    try {
      return await status(port);
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  return null;
}

test('each file that shows a permission was ever here stops the waiting start; waiting-permissions.json alone does not', async () => {
  const stops = ['slip.json', 'book.jsonl', 'book-1.jsonl', `slip-${'A'.repeat(43)}.json`, 'trusted-passkeys.json', 'held-cancellations.json'];
  for (const name of stops) {
    const w = await freshWorld();
    assert.equal(freshFolder(w.folder).fresh, true, 'fresh before');
    writeFileSync(join(w.folder, name), '{}');
    const said = freshFolder(w.folder);
    assert.equal(said.fresh, false, name);
    assert.deepEqual(said.found, [name]);
    // A start that is not refused is closed at once, and the test fails.
    await refusedStart(startWaiting, { folder: w.folder, port: 0 }, new RegExp(`holds ${name.replace(/[.]/g, '\\.')}, so it is not fresh`));
  }
  // A folder without the agent's keys is not fresh either.
  assert.equal(freshFolder(tempFolder('provared-cc-empty-')).fresh, false);
  // The waiting list alone: the waiting recorder writes it itself, and waits again after a restart.
  const w = await freshWorld();
  writeFileSync(join(w.folder, 'waiting-permissions.json'), JSON.stringify({ permissions: [] }));
  assert.equal(freshFolder(w.folder).fresh, true);
  const waiting = await startWaiting({ folder: w.folder, port: 0 });
  try {
    assert.equal((await status(waiting.port)).waiting, true);
  } finally {
    await waiting.close();
  }
});

test('"ensure" starts the waiting recorder in a fresh folder and says that it waits, not that it runs with a permission; in a folder that is not fresh and holds no permission it starts nothing', async () => {
  const w = await freshWorld();
  const port = await freePort();
  try {
    const r = await runCommand(['ensure'], { folder: w.folder, port });
    assert.equal(r.code, 0, `${r.out} ${r.err}`);
    assert.match(r.err, /waits for its first permission/);
    assert.match(r.err, /admit-passkey/);
    assert.equal((await status(port)).waiting, true);
    // Asked again while it waits: it is told as waiting.
    const again = await runCommand(['ensure'], { folder: w.folder, port });
    assert.equal(again.code, 0);
    assert.match(again.err, /waits for its first permission/);
  } finally {
    await stopService(port);
  }
  const used = await freshWorld();
  writeFileSync(join(used.folder, 'trusted-passkeys.json'), JSON.stringify({ passkeys: ['A'.repeat(43)] }));
  const other = await freePort();
  const r = await runCommand(['ensure'], { folder: used.folder, port: other });
  assert.equal(r.code, 1, `${r.out} ${r.err}`);
  assert.match(r.err, /no signed permission yet/);
  assert.equal(await answersWithin(other, 1000), null, 'nothing was started');
});

test('"use <file>" while the recorder waits stops it, waits until the port is free, and takes the file: the full recorder then runs under it', async () => {
  const w = await freshWorld();
  const port = await freePort();
  try {
    assert.equal((await runCommand(['ensure'], { folder: w.folder, port })).code, 0);
    assert.equal((await status(port)).waiting, true);
    const slip = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, purpose: 'Saved from the signing window.' });
    const file = join(tempFolder('provared-cc-use-'), 'slip.json');
    writeFileSync(file, JSON.stringify(slip));
    const r = await runCommand(['use', file], { folder: w.folder, port });
    assert.equal(r.code, 0, `${r.out} ${r.err}`);
    assert.match(r.out, /waited for its first permission was stopped/);
    assert.match(r.out, /The recorder is running/);
    const st = await answersWithin(port, 20000);
    assert.equal(st.waiting, undefined, 'not waiting');
    assert.equal(st.slip, await fingerprint(fromBase64url(slip.payload)));
  } finally {
    await stopService(port);
  }
});
