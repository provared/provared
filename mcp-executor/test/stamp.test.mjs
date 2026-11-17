// An outside time-stamp on each seal the executor signs ("recorder.stamp"),
// from a time-stamp service on this computer that the OpenSSL program answers
// for (the repository's test/helpers/tsa.mjs). No test reaches beyond this
// computer. Where there is no OpenSSL program, the tests that need it are
// skipped and say why.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook, keySetFingerprint } = await import('provared');
const { world, openWorld } = await import('./world.mjs');
const { openExecutor, readSettings } = await import('../executor.mjs');
const { makeKeyFile } = await import('../files.mjs');
const { stampContext } = await import('../sealing.mjs');
const { NO_OPENSSL, findOpenssl, startTestTsa } = await import('../../test/helpers/tsa.mjs');

const skip = findOpenssl() ? false : NO_OPENSSL;
let tsa;
before(async () => {
  if (!skip) tsa = await startTestTsa();
});
after(async () => {
  await tsa?.close();
});

/** An address on this computer that nothing listens on: a port that was free a moment ago. */
async function nobodyThere() {
  const s = http.createServer();
  await new Promise((done) => s.listen(0, '127.0.0.1', done));
  const port = s.address().port;
  await new Promise((done) => s.close(done));
  return `http://127.0.0.1:${port}/`;
}

/** A world whose recorder signs here and sends each seal to the time-stamp service at "address"; one call made, the executor ended. */
async function stampedWorld(stamp) {
  const w = await world({ open: false, config: { recorder: { keys: 'keys/recorder.jwk', name: 'The test recorder', stamp } } });
  w.recorderKeys = await makeKeyFile(join(w.folder, 'keys', 'recorder.jwk'), 'recorder');
  w.sealKeys = [await keySetFingerprint(w.recorderKeys)];
  await openWorld(w);
  await w.client.call('echo', {});
  await w.close();
  return w;
}
const bookText = (w) => readFileSync(join(w.folder, 'book.jsonl'), 'utf8');
const offline = (w) => openExecutor(w.settings, { root: w.folder, log: (e) => w.logs.push(e), offline: true });

test('recorder.stamp: each seal signed here carries the time-stamp the service gave, which counts for a reader who trusts the service', { skip }, async () => {
  tsa.mode = 'good';
  const w = await stampedWorld({ address: tsa.address });
  const ex = await offline(w);
  try {
    const sealed = await ex.seal();
    assert.equal(sealed.stamped, true);
    assert.equal(sealed.stampProblem, undefined);
    assert.deepEqual(ex.recorder.stamp, { address: tsa.address, timeout: 10000 });
    const c = await checkBook(bookText(w), { issuerKeys: w.settings.agent.issuerKeys, sealKeys: w.sealKeys, stampServices: [tsa.authority] });
    assert.equal(c.summary.problemFound, false);
    const seal = c.entries[sealed.entry];
    assert.equal(seal.kind, 'seal');
    assert.deepEqual(seal.stamps.map((s) => [s.kind, s.state]), [['service', 'valid']]);
    // A reader who names no service is shown the time-stamp as not counted, and the book still checks.
    const other = await checkBook(bookText(w), { issuerKeys: w.settings.agent.issuerKeys, sealKeys: w.sealKeys });
    assert.equal(other.summary.problemFound, false);
    assert.equal(other.entries[sealed.entry].stamps[0].state, 'untrusted');
    assert.ok(w.logs.some((e) => e.event === 'sealed' && e.stamped === true));
  } finally {
    await ex.close();
  }
});

test('recorder.stamp: a service that refuses, or that gives a time-stamp for another request, costs no seal: the seal goes in without one, and the reason is said', { skip }, async () => {
  const w = await stampedWorld({ address: tsa.address });
  const ex = await offline(w);
  try {
    for (const [mode, code] of [
      ['refuse', 'stamp-not-given'],
      ['wrong-nonce', 'stamp-wrong-data'],
      ['wrong-imprint', 'stamp-wrong-data'],
    ]) {
      tsa.mode = mode;
      const sealed = await ex.seal();
      assert.equal(sealed.stamped, undefined, mode);
      assert.equal(sealed.stampProblem.code, code, mode);
      const c = await checkBook(bookText(w), { issuerKeys: w.settings.agent.issuerKeys, sealKeys: w.sealKeys });
      assert.equal(c.summary.problemFound, false, mode);
      assert.equal(c.entries[sealed.entry].kind, 'seal', mode);
      assert.equal(c.entries[sealed.entry].stamps.length, 0, mode);
      assert.ok(w.logs.some((e) => e.event === 'stamp-not-given' && e.seal === sealed.fingerprint && e.code === code), mode);
    }
  } finally {
    await ex.close();
  }
});

test('recorder.stamp: a service that cannot be reached costs no seal, and the reason is said', async () => {
  const w = await stampedWorld({ address: await nobodyThere(), timeout: 2000 });
  const ex = await offline(w);
  try {
    const sealed = await ex.seal();
    assert.equal(sealed.stampProblem.code, 'stamp-not-given');
    assert.match(sealed.stampProblem.message, /could not be reached/);
    const c = await checkBook(bookText(w), { issuerKeys: w.settings.agent.issuerKeys, sealKeys: w.sealKeys });
    assert.equal(c.summary.problemFound, false);
    assert.equal(c.entries[sealed.entry].kind, 'seal');
    assert.ok(w.logs.some((e) => e.event === 'stamp-not-given' && /could not be reached/.test(e.reason)));
  } finally {
    await ex.close();
  }
});

test('with a central sealer, a time-stamp the sealer was not given costs no seal, and the executor logs the sealer\'s reason', async () => {
  const { centralWorld, closeAll } = await import('./sealer-world.mjs');
  try {
    const w = await centralWorld({ open: false });
    // The sealer's own settings give a time-stamp service that nothing answers for.
    await w.sealer.stop();
    const settingsPath = join(w.sealer.folder, 'sealer.json');
    writeFileSync(settingsPath, JSON.stringify({ ...JSON.parse(readFileSync(settingsPath, 'utf8')), stamp: { address: await nobodyThere(), timeout: 1000 } }));
    await w.sealer.start();
    await openWorld(w);
    await w.client.call('echo', {});
    await w.level();
    const sealed = await w.executor.seal();
    assert.equal(sealed.stampProblem.code, 'stamp-not-given');
    assert.match(sealed.stampProblem.message, /could not be reached/);
    assert.equal((await w.checked()).summary.problemFound, false);
    assert.ok(w.logs.some((e) => e.event === 'stamp-not-given' && e.seal === sealed.fingerprint && /could not be reached/.test(e.reason)));
  } finally {
    await closeAll();
  }
});

test('with a central sealer, a seal taken back after its answer was lost keeps the sealer\'s reason for having no time-stamp (X306)', async () => {
  const { centralWorld, closeAll, standIn } = await import('./sealer-world.mjs');
  let fake = null;
  try {
    const w = await centralWorld({ open: false });
    await w.sealer.stop();
    const settingsPath = join(w.sealer.folder, 'sealer.json');
    writeFileSync(settingsPath, JSON.stringify({ ...JSON.parse(readFileSync(settingsPath, 'utf8')), stamp: { address: await nobodyThere(), timeout: 1000 } }));
    await w.sealer.start();
    const real = `http://127.0.0.1:${w.sealer.port}`;
    // The sealer signs the seal, and its answer never comes back.
    fake = await standIn({ token: w.sealer.token, real, answer: async (path, body, forward) => (path === '/seal' ? (await forward(), null) : forward()) });
    w.settings.recorder.sealer.address = fake.address;
    await openWorld(w);
    await w.client.call('echo', {});
    await assert.rejects(w.executor.seal(), /whether the central sealer signed one is not known/);
    await w.close();
    // At the next start the seal is taken back from the sealer's latest, with the reason.
    w.settings.recorder.sealer.address = real;
    await openWorld(w);
    const c = await w.checked();
    assert.equal(c.summary.problemFound, false);
    const seal = c.entries.find((e) => e.kind === 'seal');
    assert.ok(seal);
    assert.ok(w.logs.some((e) => e.event === 'stamp-not-given' && e.seal === seal.fingerprint && /could not be reached/.test(e.reason)), JSON.stringify(w.logs.filter((e) => /seal|stamp/.test(e.event))));
  } finally {
    await fake?.close();
    await closeAll();
  }
});

test('recorder.stamp: left out, nothing is asked; given, it must be an address on the web and a time limit in range, and never with a central sealer', async () => {
  const w = await world({ open: false });
  const base = { keys: 'r.jwk' };
  const fine = readSettings({ ...w.settings, recorder: base }, w.folder);
  assert.deepEqual(fine.problems, []);
  assert.equal(fine.settings.recorder.stamp, null, 'no service unless one is given');
  const given = readSettings({ ...w.settings, recorder: { ...base, stamp: { address: 'https://127.0.0.1:8443/tsa', timeout: 5000 } } }, w.folder);
  assert.deepEqual(given.problems, []);
  assert.deepEqual(given.settings.recorder.stamp, { address: 'https://127.0.0.1:8443/tsa', timeout: 5000 });
  assert.equal(readSettings({ ...w.settings, recorder: { ...base, stamp: { address: 'http://127.0.0.1/' } } }, w.folder).settings.recorder.stamp.timeout, 10000);
  for (const [stamp, words] of [
    ['http://127.0.0.1/', /recorder\.stamp: must be an object/],
    [{}, /recorder\.stamp\.address/],
    [{ address: 'ftp://127.0.0.1/' }, /recorder\.stamp\.address/],
    [{ address: 'http://user:secret@127.0.0.1/' }, /recorder\.stamp\.address/],
    [{ address: 'http://127.0.0.1/#x' }, /recorder\.stamp\.address/],
    [{ address: 'http://127.0.0.1/tsa?key=secret' }, /recorder\.stamp\.address: .*query/],
    [{ address: 'http://127.0.0.1/tsa?' }, /recorder\.stamp\.address/],
    [{ address: 'http://127.0.0.1/', timeout: 99 }, /recorder\.stamp\.timeout/],
    [{ address: 'http://127.0.0.1/', timeout: 60001 }, /recorder\.stamp\.timeout/],
    [{ address: 'http://127.0.0.1/', policy: '1.2.3' }, /recorder\.stamp\.policy/],
  ]) {
    const { problems } = readSettings({ ...w.settings, recorder: { ...base, stamp } }, w.folder);
    assert.ok(problems.some((p) => words.test(p)), `${JSON.stringify(stamp)}: ${problems.join(' | ')}`);
  }
  const central = { sealer: { address: 'http://127.0.0.1:8797', name: 'r', token: { env: 'T' }, keySet: 'A'.repeat(43) }, stamp: { address: 'http://127.0.0.1/' } };
  assert.ok(readSettings({ ...w.settings, recorder: central }, w.folder).problems.some((p) => /recorder\.stamp: must not be named together with recorder\.sealer/.test(p)));
});

test('recorder.stamp: a time more than 300 seconds before the seal\'s own time costs no seal; the time-stamp is not kept (X307)', { skip }, async () => {
  tsa.mode = 'good';
  const w = await stampedWorld({ address: tsa.address });
  // The executor's clock 320 seconds ahead of the service's: the seal would be dated after its time-stamp.
  const ex = await openExecutor(w.settings, { root: w.folder, log: (e) => w.logs.push(e), offline: true, now: () => Date.now() + 320000 });
  try {
    const sealed = await ex.seal();
    assert.equal(sealed.stamped, undefined);
    assert.equal(sealed.stampProblem.code, 'stamp-not-given');
    assert.match(sealed.stampProblem.message, /before the seal's own time/);
    const c = await checkBook(bookText(w), { issuerKeys: w.settings.agent.issuerKeys, sealKeys: w.sealKeys, stampServices: [tsa.authority] });
    assert.equal(c.summary.problemFound, false);
  } finally {
    await ex.close();
  }
});

test('stampContext: the seal\'s time in whole seconds, and the latest time a sound service time-stamp gave a sound seal (X307)', () => {
  const service = (state, time) => ({ kind: 'service', state, time });
  const entries = [
    { kind: 'call', problems: [] },
    { kind: 'seal', problems: [], stamps: [service('valid', 1000), { kind: 'block', state: 'valid', time: 9000 }] },
    { kind: 'seal', problems: [], stamps: [service('untrusted', 5000), service('invalid', 8000)] },
    { kind: 'seal', problems: ['seal-bad'], stamps: [service('valid', 7000)] },
    { kind: 'seal', problems: [] },
  ];
  assert.deepEqual(stampContext(entries, 12345), { when: 12000, after: 5000 });
  assert.deepEqual(stampContext([], 999), { when: 0, after: null });
});

test('recorder.stamp.authority: a time-stamp signed by a certificate other than the one named is not kept; the one named is, and its signer is shown in the answer, the log and the status (X344)', { skip }, async () => {
  tsa.mode = 'good';
  // A stranger answering at the service's address: a key and a certificate of its own.
  const stranger = await startTestTsa();
  try {
    const w = await stampedWorld({ address: stranger.address, authority: tsa.authority });
    const ex = await offline(w);
    try {
      const refused = await ex.seal();
      assert.equal(refused.stamped, undefined);
      assert.equal(refused.stampProblem.code, 'stamp-not-given');
      assert.match(refused.stampProblem.message, new RegExp(`signed by the certificate whose fingerprint is ${stranger.authority}`));
      assert.ok(!w.logs.some((e) => e.event === 'sealed' && e.stamped === true));
    } finally {
      await ex.close();
    }
    const c = await checkBook(bookText(w), { issuerKeys: w.settings.agent.issuerKeys, sealKeys: w.sealKeys });
    assert.equal(c.summary.problemFound, false);
    assert.deepEqual(c.entries.filter((e) => e.kind === 'seal').map((e) => e.stamps.length), [0]);
    // The service named: kept, and the certificate that signed it is shown.
    w.settings.recorder.stamp = { address: tsa.address, timeout: 10000, authority: [tsa.authority] };
    const again = await offline(w);
    try {
      const sealed = await again.seal();
      assert.equal(sealed.stamped, true);
      assert.equal(sealed.stampedBy, tsa.authority);
      assert.ok(w.logs.some((e) => e.event === 'sealed' && e.stamped === true && e.stampedBy === tsa.authority));
      const report = await again.report();
      assert.equal(report.agent.lastSeal.stampedBy, tsa.authority);
      assert.deepEqual(report.recorder.stamp.authority, [tsa.authority]);
    } finally {
      await again.close();
    }
  } finally {
    await stranger.close();
  }
});

test('recorder.stamp.authority: one fingerprint or a list; "check" warns where the service is asked over http: with none named (X344)', async () => {
  const w = await world({ open: false });
  const base = { keys: 'r.jwk' };
  const read = (stamp) => readSettings({ ...w.settings, recorder: { ...base, stamp } }, w.folder);
  const fp = 'A'.repeat(43);
  assert.deepEqual(read({ address: 'http://127.0.0.1/', authority: fp }).settings.recorder.stamp, { address: 'http://127.0.0.1/', timeout: 10000, authority: [fp] });
  assert.deepEqual(read({ address: 'http://127.0.0.1/', authority: [fp, 'b'.repeat(43)] }).problems, []);
  for (const bad of ['', 'A'.repeat(42), [], [fp, 7], Array(17).fill(fp), {}, null]) {
    assert.ok(read({ address: 'http://127.0.0.1/', authority: bad }).problems.some((p) => /recorder\.stamp\.authority: must be the fingerprint/.test(p)), JSON.stringify(bad));
  }
  const warned = (stamp) => read(stamp).warnings.some((x) => /plain http: and no "authority" is named/.test(x));
  assert.equal(warned({ address: 'http://127.0.0.1/' }), true);
  assert.equal(warned({ address: 'http://127.0.0.1/', authority: fp }), false);
  assert.equal(warned({ address: 'https://127.0.0.1/' }), false);
  assert.equal(readSettings({ ...w.settings, recorder: base }, w.folder).warnings.some((x) => /authority/.test(x)), false);
});

test('with a central sealer, a seal the sealer time-stamped is said to be, with its signer; one with none is said to have none (X348)', { skip }, async () => {
  tsa.mode = 'good';
  const { centralWorld, closeAll } = await import('./sealer-world.mjs');
  try {
    const w = await centralWorld({ open: false });
    await w.sealer.stop();
    const settingsPath = join(w.sealer.folder, 'sealer.json');
    const plain = JSON.parse(readFileSync(settingsPath, 'utf8'));
    writeFileSync(settingsPath, JSON.stringify({ ...plain, stamp: { address: tsa.address, timeout: 4000 } }));
    await w.sealer.start();
    await openWorld(w);
    await w.client.call('echo', {});
    await w.level();
    const sealed = await w.executor.seal();
    assert.equal(sealed.stamped, true);
    assert.equal(sealed.stampedBy, tsa.authority);
    assert.ok(w.logs.some((e) => e.event === 'sealed' && e.seal === sealed.fingerprint && e.stamped === true && e.stampedBy === tsa.authority));
    // The sealer with no time-stamp service: the seal is said to carry none.
    await w.close();
    await w.sealer.stop();
    writeFileSync(settingsPath, JSON.stringify(plain));
    await w.sealer.start();
    await openWorld(w);
    await w.client.call('echo', {});
    await w.level();
    const bare = await w.executor.seal();
    assert.equal(bare.stamped, false);
    assert.equal(bare.stampedBy, undefined);
    assert.ok(w.logs.some((e) => e.event === 'sealed' && e.seal === bare.fingerprint && e.stamped === false));
  } finally {
    await closeAll();
  }
});

test('check: a library without the time-stamp client (provared/net/timestamp) is said plainly where recorder.stamp is given (X309)', async () => {
  const w = await stampedWorld({ address: 'http://127.0.0.1:9/tsa' });
  const bin = fileURLToPath(new URL('../bin.mjs', import.meta.url));
  const hide = new URL('../../test/helpers/no-net-timestamp.mjs', import.meta.url).href;
  const check = (more) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', bin, 'check', '--config', w.configPath], { cwd: w.folder, encoding: 'utf8', env: { ...process.env, NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} ${more}`.trim() }, windowsHide: true });
  const fine = check('');
  assert.equal(fine.status, 0, fine.stdout + fine.stderr);
  const without = check(`--import=${hide}`);
  assert.equal(without.status, 1, without.stdout + without.stderr);
  assert.ok(JSON.parse(without.stdout).problems.some((p) => /no client for a time-stamp service \(provared\/net\/timestamp\)/.test(p)), without.stdout);
});
