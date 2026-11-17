// An outside time-stamp on each seal the executor signs ("recorder.stamp"),
// from a time-stamp service on this computer that the OpenSSL program answers
// for (the repository's test/helpers/tsa.mjs). No test reaches beyond this
// computer. Where there is no OpenSSL program, the tests that need it are
// skipped and say why.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { join } from 'node:path';
import { after, before, test } from 'node:test';

const { checkBook, keySetFingerprint } = await import('provared');
const { world, openWorld } = await import('./world.mjs');
const { openExecutor, readSettings } = await import('../executor.mjs');
const { makeKeyFile } = await import('../files.mjs');
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
