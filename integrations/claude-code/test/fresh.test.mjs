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
import { existsSync, writeFileSync } from 'node:fs';
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

test('"ensure" in a folder that holds a trusted list and no permission (an admit stopped between its two writes) names what stands in the way and what to do', async () => {
  const w = await freshWorld();
  writeFileSync(join(w.folder, 'trusted-passkeys.json'), JSON.stringify({ passkeys: ['A'.repeat(43)] }));
  const port = await freePort();
  const r = await runCommand(['ensure'], { folder: w.folder, port });
  assert.equal(r.code, 1, `${r.out} ${r.err}`);
  assert.match(r.err, /holds trusted-passkeys\.json/);
  assert.match(r.err, /not fresh/);
  assert.match(r.err, /use <the saved file>/);
  assert.equal(await answersWithin(port, 1000), null, 'nothing was started');
});

test('"renew <file>", with or without --new-passkey, against the waiting recorder says that it waits for its first permission, and what to do; nothing is taken', async () => {
  const w = await freshWorld();
  const waiting = await startWaiting({ folder: w.folder, port: 0, signingOrigins: ['http://localhost'] });
  try {
    const file = join(tempFolder('provared-cc-renew-'), 'slip.json');
    writeFileSync(file, JSON.stringify(await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey })));
    for (const args of [['renew', file, '--new-passkey'], ['renew', file]]) {
      const r = await runCommand(args, { folder: w.folder, port: waiting.port });
      const said = `${r.out} ${r.err}`;
      assert.notEqual(r.code, 0, said);
      assert.match(said, /waits for (its|the) first/, said);
      assert.match(said, /use <the saved file>/, said);
      assert.doesNotMatch(said, /did not prove/, said);
      assert.equal(existsSync(join(w.folder, 'slip.json')), false, `${args.join(' ')}: nothing is taken`);
    }
    assert.equal((await status(waiting.port)).waiting, true);
  } finally {
    await waiting.close();
  }
});

/**
 * A stand-in on the port for a waiting recorder: it answers /status as one
 * that waits, with the first "silent" questions left unanswered for
 * "silentMs" each; "/stop" is answered, and closes it where "stops".
 */
async function standIn(port, { silentFirst = 0, silentAfterStop = 0, silentMs = 6000, stops = true } = {}) {
  const { createServer } = await import('node:http');
  let asked = 0;
  let stopped = false;
  let afterStop = 0;
  const server = createServer((req, res) => {
    const answer = (body) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
    if (req.url === '/stop') {
      answer({ stopped: true });
      stopped = true;
      if (stops) { server.close(); server.closeAllConnections(); }
      return;
    }
    const silent = stopped ? ++afterStop <= silentAfterStop : ++asked <= silentFirst;
    if (silent) { setTimeout(() => res.destroy(), silentMs).unref(); return; }
    answer({ waiting: true, version: 'stand-in' });
  });
  await new Promise((ok) => server.listen(port, '127.0.0.1', ok));
  return { close: () => { server.close(); server.closeAllConnections(); } };
}

/**
 * A stand-in on the port for a waiting recorder that follows a plan: each
 * GET /status in turn is answered as one that waits ("waiting"), or left
 * unanswered for that many milliseconds (a number); after the plan, it
 * answers as one that waits. Every /stop is answered "stopped", and it goes
 * on. "asked" lists what it was asked, in order.
 */
async function plannedStandIn(port, plan) {
  const { createServer } = await import('node:http');
  const asked = [];
  let questions = 0;
  const server = createServer((req, res) => {
    const answer = (body) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
    if (req.url === '/stop') {
      asked.push('stop');
      answer({ stopped: true });
      return;
    }
    const step = plan[questions++] ?? 'waiting';
    asked.push(step);
    if (typeof step === 'number') { setTimeout(() => res.destroy(), step).unref(); return; }
    answer({ waiting: true, version: 'stand-in' });
  });
  await new Promise((ok) => server.listen(port, '127.0.0.1', ok));
  return { asked, close: () => { server.close(); server.closeAllConnections(); } };
}

test('"use <file>" ends with 1 and says every tool call is still refused where what answers still waits after it was stopped and the recorder started again', async () => {
  const w = await freshWorld();
  const port = await freePort();
  // It answers /stop and goes on; after each stop two questions in a row go unanswered, so the port seems free.
  const stand = await plannedStandIn(port, ['waiting', 1500, 1500, 'waiting', 'waiting', 1500, 1500, 'waiting', 'waiting']);
  try {
    const file = join(tempFolder('provared-cc-use-'), 'slip.json');
    writeFileSync(file, JSON.stringify(await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey })));
    const r = await runCommand(['use', file], { folder: w.folder, port });
    assert.equal(r.code, 1, `${r.out} ${r.err} ${stand.asked.join(' ')}`);
    assert.match(r.out, /The permission is in place, but the recorder that answers on 127\.0\.0\.1:\d+ still waits for its first permission, so every tool call is refused/);
    assert.doesNotMatch(r.out, /The recorder is running/);
  } finally {
    stand.close();
  }
});

test('"use <file>" with a file that is refused leaves the waiting recorder running, and says nothing of stopping it', async () => {
  const w = await freshWorld();
  const port = await freePort();
  try {
    assert.equal((await runCommand(['ensure'], { folder: w.folder, port })).code, 0);
    const otherKeys = (await freshWorld()).agent.keys;
    const file = join(tempFolder('provared-cc-use-'), 'slip.json');
    writeFileSync(file, JSON.stringify(await signSlip({ agentKeys: otherKeys, passkey: w.passkey })));
    const r = await runCommand(['use', file], { folder: w.folder, port });
    assert.notEqual(r.code, 0, `${r.out} ${r.err}`);
    assert.doesNotMatch(r.out, /was stopped/);
    assert.equal((await status(port)).waiting, true, 'the waiting recorder still runs');
    assert.equal(existsSync(join(w.folder, 'slip.json')), false);
  } finally {
    await stopService(port);
  }
});

test('"use <file>" does not say the recorder runs where what answers after it still waits (its first question went unanswered): it stops it, and the full recorder then runs', async () => {
  const w = await freshWorld();
  const port = await freePort();
  const stand = await standIn(port, { silentFirst: 1 });
  try {
    const slip = await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey, purpose: 'Saved from the signing window.' });
    const file = join(tempFolder('provared-cc-use-'), 'slip.json');
    writeFileSync(file, JSON.stringify(slip));
    const r = await runCommand(['use', file], { folder: w.folder, port });
    const st = await answersWithin(port, 20000);
    assert.equal(st?.waiting, undefined, `not waiting: ${r.out} ${r.err}`);
    assert.equal(st.slip, await fingerprint(fromBase64url(slip.payload)));
    assert.equal(r.code, 0, `${r.out} ${r.err}`);
    assert.match(r.out, /The recorder is running/);
    assert.doesNotMatch(r.err, /waits for its first permission: every tool call is refused/);
  } finally {
    stand.close();
    await stopService(port);
  }
});

test('"use <file>" does not take the port for free on one unanswered question: a waiting recorder that still answers after that keeps the file from being taken', async () => {
  const w = await freshWorld();
  const port = await freePort();
  // It answers /stop but does not stop; the first question after it goes unanswered for 1.5 seconds.
  const stand = await standIn(port, { silentAfterStop: 1, silentMs: 1500, stops: false });
  try {
    const file = join(tempFolder('provared-cc-use-'), 'slip.json');
    writeFileSync(file, JSON.stringify(await signSlip({ agentKeys: w.agent.keys, passkey: w.passkey })));
    const r = await runCommand(['use', file], { folder: w.folder, port });
    assert.equal(r.code, 1, `${r.out} ${r.err}`);
    assert.match(r.out, /did not let go of its port/);
    assert.equal(existsSync(join(w.folder, 'slip.json')), false, 'nothing was taken');
  } finally {
    stand.close();
  }
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
