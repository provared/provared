// Taking a new slip into a book that has one already: while the service
// runs, with no moment in which the hook finds it gone, and while it does
// not. The book then checks with both slips, and every stub after the
// renewal is under the new slip.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { checkBook, fingerprint, fromBase64url, thumbprint } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { startService } = await import('../recorder.mjs');
const { freePort, runCommand, runHook, signSlip, status, tempFolder, world } = await import('./world.mjs');

const slipFingerprint = (slip) => fingerprint(fromBase64url(slip.payload));
const read = (folder, name) => readFileSync(join(folder, name), 'utf8');

// Another program holds the file open while "act" runs, and lets it go once
// "act" has answered (not after a fixed time): { r: what act gave }.
async function holdingOpen(file, act) {
  const holder = spawn(process.execPath, ['-e', `const fs=require('fs');const fd=fs.openSync(${JSON.stringify(file)},'r');console.log('held');process.stdin.on('end',()=>fs.closeSync(fd));process.stdin.resume()`], { stdio: ['pipe', 'pipe', 'inherit'] });
  const closed = new Promise((resolve) => holder.on('close', resolve));
  await new Promise((resolve) => holder.stdout.once('data', resolve));
  try {
    return { r: await act() };
  } finally {
    holder.stdin.end();
    await closed;
  }
}

/** Check a book as a reader would, trusting the given passkeys and the recorder. */
async function checked(folder, passkeys, sealer) {
  const result = await checkBook(read(folder, 'book.jsonl'), { issuerKeys: passkeys, ...(sealer ? { sealKeys: [sealer] } : {}) });
  return result;
}

function saveSlip(slip) {
  const file = join(tempFolder('provared-slip-'), 'slip.json');
  writeFileSync(file, JSON.stringify(slip));
  return file;
}

test('a new slip is taken while the service runs: no call finds it gone, and stubs after it are under the new slip', async () => {
  const { folder, passkey, agent, slip: first } = await world([]);
  const service = await startService({ folder, port: 0 });
  const port = service.port;
  try {
    let r = await runHook(port, 'PostToolUse', 'Bash', { command: 'npm test' });
    assert.equal(r.code, 0, r.err);
    const second = await signSlip({ agentKeys: agent.keys, passkey, purpose: 'The same work, for another week.' });
    // The renewal, through the command, with calls made at the same moment:
    // hooks run as Claude Code runs them, and a loop that asks the service
    // directly, without a pause, from before the command starts until it ends.
    let renewing = true;
    const asked = [];
    const loop = (async () => {
      // eslint-disable-next-line no-unmodified-loop-condition -- set to false by the renewal command when it ends, while the loop waits.
      while (renewing) {
        const response = await fetch(`http://127.0.0.1:${port}/before`, { method: 'POST', body: JSON.stringify({ action: 'provared.code.read' }) });
        asked.push({ ok: response.ok, allowed: (await response.json()).allowed, slip: (await status(port)).slip });
      }
    })();
    const during = [
      runCommand(['renew', saveSlip(second)], { folder, port }).finally(() => { renewing = false; }),
      ...[1, 2, 3].map((i) => runHook(port, 'PreToolUse', 'Bash', { command: `npm run step${i}` })),
      ...[1, 2, 3].map((i) => runHook(port, 'PostToolUse', 'Read', { file_path: `file${i}.js` })),
    ];
    const [renewed, ...calls] = await Promise.all(during);
    await loop;
    assert.equal(renewed.code, 0, renewed.err);
    assert.match(renewed.out, /is in the book, and the recorder acts under it/);
    for (const c of calls) {
      assert.equal(c.code, 0, c.err);
      assert.ok(!c.decision || c.decision.permissionDecision !== 'deny', `a call was refused during the renewal: ${c.out}`);
    }
    // Every question was answered, and allowed, under the first slip and then under the second, with nothing between.
    assert.ok(asked.length >= 5, `the loop asked ${asked.length} times`);
    assert.ok(asked.every((a) => a.ok && a.allowed), JSON.stringify(asked.filter((a) => !a.ok || !a.allowed)));
    const switched = asked.findIndex((a) => a.slip !== asked[0].slip);
    assert.equal(asked[0].slip, await slipFingerprint(first));
    assert.ok(switched > 0, 'the loop saw the switch');
    assert.ok(asked.slice(switched).every((a) => a.slip === asked[switched].slip), 'the service switched once');
    // After the renewal: a stub, under the new slip.
    r = await runHook(port, 'PostToolUse', 'Edit', { file_path: 'a.js' });
    assert.equal(r.code, 0, r.err);
    const [fp1, fp2] = [await slipFingerprint(first), await slipFingerprint(second)];
    const s = await status(port);
    assert.equal(s.slip, fp2);
    const result = await checked(folder, [await thumbprint(passkey.key)], s.sealer);
    assert.equal(result.summary.intact, true, JSON.stringify(result.entries.flatMap((e) => e.problems)));
    assert.equal(result.summary.withinSlips, true);
    assert.equal(result.summary.counts.slips, 2);
    assert.deepEqual(result.entries.filter((e) => e.kind === 'slip').map((e) => e.fingerprint), [fp1, fp2]);
    const stubs = result.entries.filter((e) => e.kind === 'stub');
    assert.equal(stubs.length, 5);
    assert.equal(stubs[0].slip, fp1, 'the stub before the renewal is under the first slip');
    assert.equal(stubs.at(-1).slip, fp2, 'the stub after the renewal is under the new slip');
    // Each slip's chain starts at 0.
    assert.equal(stubs.find((e) => e.slip === fp2).content.seq, 0);
    // The files: the new slip in place, the one before kept by its fingerprint.
    assert.equal(read(folder, 'slip.json'), JSON.stringify(second));
    assert.equal(read(folder, `slip-${fp1}.json`), JSON.stringify(first));
    // The same slip again changes nothing.
    const again = await runCommand(['renew', saveSlip(second)], { folder, port });
    assert.equal(again.code, 0, again.err);
    assert.match(again.out, /already acts under this permission/);
    assert.equal((await status(port)).entries, s.entries);
  } finally {
    await service.close();
  }
});

test('a new slip is taken while the service is stopped, and the next start acts under it', async () => {
  const { folder, passkey, agent, slip: first } = await world([]);
  let service = await startService({ folder, port: 0 });
  await runHook(service.port, 'PostToolUse', 'Bash', { command: 'npm test' });
  await service.close();
  const second = await signSlip({ agentKeys: agent.keys, passkey });
  const renewed = await runCommand(['renew', saveSlip(second)], { folder, port: await freePort() });
  assert.equal(renewed.code, 0, renewed.err);
  assert.match(renewed.out, /is in the book/);
  const fp2 = await slipFingerprint(second);
  assert.match(read(folder, 'book.jsonl').trim().split('\n').at(-1), /^\{"slip":/, 'the new slip is the last line of the book');
  service = await startService({ folder, port: 0 });
  try {
    assert.equal((await status(service.port)).slip, fp2);
    const r = await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'b.js' });
    assert.equal(r.code, 0, r.err);
    const result = await checked(folder, [await thumbprint(passkey.key)]);
    assert.equal(result.summary.intact, true, JSON.stringify(result.entries.flatMap((e) => e.problems)));
    assert.equal(result.summary.withinSlips, true);
    const stubs = result.entries.filter((e) => e.kind === 'stub');
    assert.deepEqual(stubs.map((e) => e.slip), [await slipFingerprint(first), fp2]);
  } finally {
    await service.close();
  }
});

test('a slip put in place by hand, while the service was stopped, is taken into the book when it starts', async () => {
  const { folder, passkey, agent } = await world([]);
  let service = await startService({ folder, port: 0 });
  await service.close();
  const second = await signSlip({ agentKeys: agent.keys, passkey });
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(second));
  service = await startService({ folder, port: 0 });
  try {
    assert.equal((await status(service.port)).slip, await slipFingerprint(second));
    assert.equal((await status(service.port)).entries, 2);
  } finally {
    await service.close();
  }
});

test('a slip that names other agent keys is refused, and nothing changes', async () => {
  const { folder, passkey } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const before = { book: read(folder, 'book.jsonl'), slip: read(folder, 'slip.json'), status: await status(service.port) };
    const stranger = await world([]);
    const other = await signSlip({ agentKeys: stranger.agent.keys, passkey });
    const r = await runCommand(['renew', saveSlip(other)], { folder, port: service.port });
    assert.equal(r.code, 1);
    assert.match(r.err, /names other keys than the agent's keys in this folder/);
    assert.equal(read(folder, 'book.jsonl'), before.book);
    assert.equal(read(folder, 'slip.json'), before.slip);
    assert.equal((await status(service.port)).slip, before.status.slip);
    // Stopped, the same.
    await service.close();
    const stopped = await runCommand(['renew', saveSlip(other)], { folder, port: await freePort() });
    assert.equal(stopped.code, 1);
    assert.match(stopped.err, /other keys/);
    assert.equal(read(folder, 'book.jsonl'), before.book);
    assert.equal(read(folder, 'slip.json'), before.slip);
  } finally {
    await service.close();
  }
});

test('a slip whose passkey signature does not check is refused, and nothing changes', async () => {
  const { folder, passkey, agent } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const before = { book: read(folder, 'book.jsonl'), slip: read(folder, 'slip.json') };
    // Signed over another challenge: a well-formed signature that does not fit this slip.
    const forged = await signSlip({ agentKeys: agent.keys, passkey, sign: (challenge) => passkey.sign(challenge.map((b, i) => (i === 0 ? b ^ 1 : b))) });
    const r = await runCommand(['renew', saveSlip(forged)], { folder, port: service.port });
    assert.equal(r.code, 1);
    assert.match(r.err, /does not pass its check/);
    // In the service itself, too.
    await assert.rejects(service.renew(forged), /does not pass its check/);
    assert.equal(read(folder, 'book.jsonl'), before.book);
    assert.equal(read(folder, 'slip.json'), before.slip);
    // A file that is not a slip at all.
    const notSlip = join(tempFolder(), 'x.json');
    writeFileSync(notSlip, '{"hello":1}');
    const n = await runCommand(['renew', notSlip], { folder, port: service.port });
    assert.equal(n.code, 1);
    assert.match(n.err, /does not hold a signed permission/);
  } finally {
    await service.close();
  }
});

test('a slip that has ended is refused; one not yet in force is taken, with a warning', async () => {
  const { folder, passkey, agent } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const ended = await signSlip({ agentKeys: agent.keys, passkey, from: Date.now() - 7200000, until: Date.now() - 3600000 });
    const r = await runCommand(['renew', saveSlip(ended)], { folder, port: service.port });
    assert.equal(r.code, 1);
    assert.match(r.err, /ended at/);
    const later = await signSlip({ agentKeys: agent.keys, passkey, from: Date.now() + 3600000, until: Date.now() + 7200000 });
    const l = await runCommand(['renew', saveSlip(later)], { folder, port: service.port });
    assert.equal(l.code, 0, l.err);
    assert.match(l.out, /Warning: The permission is in force only from/);
    // Until then, a call is refused, not taken.
    const call = await runHook(service.port, 'PreToolUse', 'Bash', { command: 'npm test' });
    assert.equal(call.decision.permissionDecision, 'deny');
  } finally {
    await service.close();
  }
});

test('a slip signed by a passkey new to the book is refused, unless the person gives --new-passkey; a checker must then name both passkeys', async () => {
  const { folder, passkey, agent } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const other = await developmentPasskey();
    const second = await signSlip({ agentKeys: agent.keys, passkey: other });
    const refused = await runCommand(['renew', saveSlip(second)], { folder, port: service.port });
    assert.notEqual(refused.code, 0);
    assert.match(refused.out + refused.err, /signed none of the permissions before it/);
    assert.equal(readFileSync(join(folder, 'book.jsonl'), 'utf8').split('\n').filter((l) => l.startsWith('{"slip":')).length, 1, 'the book holds the first slip only');
    const r = await runCommand(['renew', saveSlip(second), '--new-passkey'], { folder, port: service.port });
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /Warning: This permission is signed by a new passkey/);
    assert.match(r.out, new RegExp(await thumbprint(other.key)));
    const call = await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'c.js' });
    assert.equal(call.code, 0, call.err);
    const both = await checked(folder, [await thumbprint(passkey.key), await thumbprint(other.key)]);
    assert.equal(both.summary.intact, true, JSON.stringify(both.entries.flatMap((e) => e.problems)));
    // Named alone, the first passkey does not stand behind the second slip, and the checker says so.
    const one = await checked(folder, [await thumbprint(passkey.key)]);
    assert.ok(one.entries.some((e) => e.problems.some((p) => p.code === 'issuer-not-expected')));
    // The recorder trusts both from now on: it opens the book again.
    await service.close();
    const again = await startService({ folder, port: 0 });
    await again.close();
  } finally {
    await service.close();
  }
});

test('a renewal that fails after the book file took the new permission puts the book file back, and the stubs after it are saved whole', async () => {
  const { folder, passkey, agent } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'first' });
    const second = await signSlip({ agentKeys: agent.keys, passkey: await developmentPasskey() });
    // The list of trusted passkeys is held open, so that writing it fails after slip.json and the book are written. It
    // is let go only once the renewal has answered, however long the recorder's retries take on a busy computer.
    const { r } = await holdingOpen(join(folder, 'trusted-passkeys.json'), () => fetch(`http://127.0.0.1:${service.port}/renew`, { method: 'POST', body: JSON.stringify({ slip: second, newPasskey: true }) }));
    if (process.platform !== 'win32' && r.ok) return; // elsewhere a file held open can be replaced: nothing failed
    assert.equal(r.ok, false, 'the renewal failed');
    assert.equal(read(folder, 'book.jsonl'), service.recorder.book(), 'the book file is the recorder\'s book again');
    for (const n of [1, 2]) {
      const call = await runHook(service.port, 'PostToolUse', 'Bash', { command: `npm run step${n}` });
      assert.equal(call.code, 0, call.err);
      assert.equal(read(folder, 'book.jsonl'), service.recorder.book(), `after stub ${n}`);
    }
    await service.close();
    const again = await startService({ folder, port: 0 });
    try {
      assert.deepEqual((await status(again.port)).trusted, [await thumbprint(passkey.key)]);
    } finally {
      await again.close();
    }
  } finally {
    await service.close();
  }
});

test('a renewal with --new-passkey that fails on the way leaves the new passkey untrusted, and the folder as it was', async () => {
  const { folder, passkey, agent } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const other = await developmentPasskey();
    const second = await signSlip({ agentKeys: agent.keys, passkey: other });
    const before = await status(service.port);
    const slipBefore = read(folder, 'slip.json');
    const listBefore = read(folder, 'trusted-passkeys.json');
    // Another program holds slip.json open until the renewal has answered, so
    // that on Windows it cannot be replaced, however long the recorder's two
    // seconds of retries take to run on a busy computer.
    const { r } = await holdingOpen(join(folder, 'slip.json'), () => fetch(`http://127.0.0.1:${service.port}/renew`, { method: 'POST', body: JSON.stringify({ slip: second, newPasskey: true }) }));
    if (process.platform !== 'win32' && r.ok) return; // elsewhere a file held open can be replaced: nothing failed
    assert.equal(r.ok, false, 'the renewal failed');
    const after = await status(service.port);
    assert.equal(after.slip, before.slip, 'the service acts under the slip before');
    assert.deepEqual(after.trusted, [await thumbprint(passkey.key)]);
    assert.equal(read(folder, 'trusted-passkeys.json'), listBefore, 'no passkey was added to the list');
    assert.equal(read(folder, 'slip.json'), slipBefore);
    assert.equal(existsSync(join(folder, 'slip.json.tmp')), false, 'no temporary file is left');
    await service.close();
    // Started again, it trusts the first passkey alone and acts under the slip before.
    const again = await startService({ folder, port: 0 });
    try {
      const st = await status(again.port);
      assert.deepEqual(st.trusted, [await thumbprint(passkey.key)]);
      assert.equal(st.slip, before.slip);
    } finally {
      await again.close();
    }
  } finally {
    await service.close();
  }
});

test('"use" with a book in place renews; the old slip file is kept and the service runs under the new one', async () => {
  const { folder, passkey, agent, slip: first } = await world([]);
  let service = await startService({ folder, port: 0 });
  await service.close();
  const port = await freePort();
  try {
    const second = await signSlip({ agentKeys: agent.keys, passkey });
    const r = await runCommand(['use', saveSlip(second)], { folder, port });
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /The recorder is running/);
    assert.equal((await status(port)).slip, await slipFingerprint(second));
    assert.ok(existsSync(join(folder, `slip-${await slipFingerprint(first)}.json`)));
  } finally {
    await runCommand(['stop'], { folder, port });
  }
});

test('a slip put in place by hand, signed by a passkey new to the book, stops the recorder from starting', async () => {
  const { folder, agent } = await world([]);
  const first = await startService({ folder, port: 0 });
  await first.close();
  const other = await developmentPasskey();
  const second = await signSlip({ agentKeys: agent.keys, passkey: other });
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(second));
  await assert.rejects(startService({ folder, port: 0 }), /signed none of the permissions this recorder trusts/);
  // Taken at the person's word, with the recorder stopped: then it starts.
  const r = await runCommand(['renew', saveSlip(second), '--new-passkey'], { folder, port: await freePort() });
  assert.equal(r.code, 0, r.err);
  const again = await startService({ folder, port: 0 });
  await again.close();
});
