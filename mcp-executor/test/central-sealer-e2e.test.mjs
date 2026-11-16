// A book sealed by a central sealer, end to end: the sealer's own program,
// set up by its commands and run as a process of its own on 127.0.0.1; and
// several agents' books on one HTTP executor.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook, keySetFingerprint, leafFingerprint, toBase64url } = await import('provared');
const { world, openWorld, tempFolder, until } = await import('./world.mjs');
const { httpWorld, openHttpWorld, call } = await import('./http-world.mjs');
const { RECORDER, freePort, refusal, sealerCommand, sealerFolder, sealerProcess } = await import('./sealer-world.mjs');
const { startSealer } = await import('../../sealer/sealer.mjs');
const { connectSealer } = await import('../sealer-client.mjs');

const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));

/** Run the executor's command, and give its exit code and what it wrote. */
function run(args) {
  return new Promise((done) => {
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', BIN, ...args], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    child.stdin.end();
    const out = [];
    const err = [];
    child.stdout.on('data', (c) => out.push(c));
    child.stderr.on('data', (c) => err.push(c));
    const timer = setTimeout(() => child.kill(), 50000);
    child.on('exit', (code) => {
      clearTimeout(timer);
      done({ code, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') });
    });
  });
}

test('central sealer, end to end: the sealer\'s program is set up by its own commands and runs as a process of its own; the lines go to it, the timer\'s seals come from it, and it is stopped and started again while calls go on', async () => {
  const w = await world({ open: false });
  const folder = tempFolder();
  const port = await freePort();
  const init = sealerCommand(['init', '--folder', folder, '--name', 'The end-to-end sealer (invented)']);
  assert.equal(init.code, 0, init.stderr);
  const keySet = /Key set:\s+(\S+)/.exec(init.stdout)[1];
  // The settings as they stand before the recorder is added at the sealer: they name the sealer's address, and no token yet.
  w.settings.recorder = { sealer: { address: `http://127.0.0.1:${port}` }, sealEvery: 1000 };
  writeFileSync(w.configPath, JSON.stringify(w.settings));
  // The executor's "keys" runs on them (X157), and prints the fingerprint of the agent's key set, which the sealer is told when the recorder is added.
  const keys = await run(['keys', '--config', w.configPath]);
  assert.equal(keys.code, 0, keys.stderr);
  const agent = /the fingerprint of the key set of the agent is (\S+):/.exec(keys.stderr)[1];
  assert.equal(agent, await keySetFingerprint(w.agentKeys));
  // Every other command names what the settings lack.
  const early = await run(['check', '--config', w.configPath]);
  assert.notEqual(early.code, 0);
  assert.match(early.stdout + early.stderr, /recorder\.sealer\.token/);
  const added = sealerCommand(['add-recorder', '--folder', folder, '--agent', agent, RECORDER]);
  assert.equal(added.code, 0, added.stderr);
  const token = added.stdout.trim().split('\n').at(-1).trim();
  writeFileSync(join(w.folder, 'keys', 'sealer-token'), `${token}\n`);
  w.settings.recorder = { sealer: { address: `http://127.0.0.1:${port}`, name: RECORDER, token: { file: 'keys/sealer-token' }, keySet, timeout: 1000 }, sealEvery: 1000 };
  writeFileSync(w.configPath, JSON.stringify(w.settings));

  const bookText = () => readFileSync(join(w.folder, 'book.jsonl'), 'utf8');
  const checked = () => checkBook(bookText(), { issuerKeys: w.settings.agent.issuerKeys, sealKeys: [keySet] });
  /** Wait until the book's last entry is a seal over at least so many entries. */
  const sealedOver = (entries) =>
    until(
      async () => {
        const last = (await checked()).entries.at(-1);
        return last.kind === 'seal' && last.content.size >= entries;
      },
      { timeout: 40000, every: 200 },
    );
  let sealer = await sealerProcess(folder, port);
  try {
    assert.equal(sealer.keySet, keySet);
    await openWorld(w);
    assert.equal(refusal(await w.client.call('echo', {})), null);
    assert.equal(refusal(await w.client.call('echo', {})), null);
    await sealedOver(3);

    // The sealer's process is ended, and calls go on.
    await sealer.stop();
    assert.equal(refusal(await w.client.call('echo', {})), null);
    assert.equal(refusal(await w.client.call('echo', {})), null);
    const behind = await until(async () => {
      const now = (await w.executor.report()).agent.sealer;
      return now.problem ? now : null;
    });
    assert.ok(behind.unsent >= 2);
    assert.ok(behind.since);
    const receipts = (await checked()).entries.filter((e) => e.kind === 'stub').length;
    assert.equal(receipts, 4);

    // It is started again, on its own state: the lines since its latest seal are sent again, and the timer's next seal covers them.
    sealer = await sealerProcess(folder, port);
    assert.equal(refusal(await w.client.call('echo', {})), null);
    await until(async () => {
      const c = await checked();
      const last = c.entries.at(-1);
      return last.kind === 'seal' && c.entries.filter((e) => e.kind === 'stub').length === 5;
    }, { timeout: 40000, every: 200 });
    await until(async () => (await w.executor.report()).agent.sealer.unsent === 0, { timeout: 10000 });
    await w.close();

    const c = await checked();
    assert.equal(c.summary.problemFound, false);
    const seals = c.entries.filter((e) => e.kind === 'seal');
    assert.ok(seals.length >= 2);
    for (const [i, seal] of seals.entries()) {
      assert.deepEqual(seal.signatures.map((s) => s.state), ['valid', 'valid', 'valid']);
      assert.equal(seal.content.by.name, 'The end-to-end sealer (invented)');
      assert.equal(seal.content.previous, i === 0 ? undefined : seals[i - 1].fingerprint, 'each seal names the one before');
    }
    assert.equal(seals.at(-1).content.size, c.entries.length - 1, 'the last seal covers every entry before it');

    // The status, from the command: the sealer is asked how many lines it holds.
    const status = await run(['status', '--config', w.configPath]);
    assert.equal(status.code, 0, status.stderr);
    const shown = JSON.parse(status.stdout);
    assert.equal(shown.agent.sealer.reached, true);
    assert.equal(shown.agent.sealer.holds, c.entries.length);
    assert.equal(shown.agent.sealer.unsent, 0);
    assert.equal(shown.agent.sealer.latestSeal, seals.at(-1).fingerprint);
    // Neither the settings nor what the commands wrote holds the token.
    for (const text of [readFileSync(w.configPath, 'utf8'), keys.stdout, keys.stderr, status.stdout, status.stderr]) assert.equal(text.includes(token), false);
  } finally {
    // Where the test failed before it closed the executor, it is closed here, so that the file ends.
    await w.close();
    await sealer.stop();
  }
});

test('central sealer, over HTTP: each agent\'s book is a book of its own at the sealer, sent and sealed apart, and the status shows each', async () => {
  const w = await httpWorld({ open: false });
  const s = await sealerFolder([w.agents.alpha.agentKeys, w.agents.beta.agentKeys]);
  const running = await startSealer({ folder: s.folder, port: s.port });
  try {
    writeFileSync(join(w.folder, 'secrets', 'sealer-token'), `${s.token}\n`);
    w.settings.recorder = { sealer: { address: running.address, name: RECORDER, token: { file: 'secrets/sealer-token' }, keySet: running.fingerprint, timeout: 2000 } };
    writeFileSync(w.configPath, JSON.stringify(w.settings));
    await openHttpWorld(w);
    assert.ok((await call(w, 'alpha', 'echo', {})).json.result);
    assert.ok((await call(w, 'beta', 'echo', {})).json.result);
    assert.ok((await call(w, 'beta', 'echo', {})).json.result);
    const sealer = connectSealer({ address: running.address, recorder: RECORDER, token: s.token });
    const lines = (name) => readFileSync(w.agents[name].book, 'utf8').split('\n').filter(Boolean);
    const held = async (name) => sealer.held(toBase64url(await leafFingerprint(lines(name)[0])));
    await until(async () => (await held('alpha'))?.size === 2 && (await held('beta'))?.size === 3);
    const alpha = await w.executor.seal('alpha');
    const beta = await w.executor.seal('beta');
    assert.equal(alpha.entry, 2);
    assert.equal(beta.entry, 3);
    for (const name of ['alpha', 'beta']) {
      const c = await checkBook(readFileSync(w.agents[name].book, 'utf8'), { issuerKeys: w.settings.agents[name].issuerKeys, sealKeys: [running.fingerprint] });
      assert.equal(c.summary.problemFound, false);
      assert.equal(c.entries.at(-1).kind, 'seal');
    }
    assert.equal((await held('alpha')).latest, alpha.fingerprint);
    assert.equal((await held('beta')).latest, beta.fingerprint);
    await until(async () => (await held('alpha')).size === 3 && (await held('beta')).size === 4);
    const report = await w.executor.report();
    assert.deepEqual(report.recorder, { fingerprint: running.fingerprint, sealEvery: null, sealer: { address: running.address, recorder: RECORDER, maxUnsent: 100 } });
    assert.equal(report.agents.alpha.sealer.unsent, 0);
    assert.equal(report.agents.beta.sealer.unsent, 0);
  } finally {
    await w.close?.();
    await running.close();
  }
});
