// An outside time-stamp on each seal the gateway signs ("recorder.stamp"),
// from a time-stamp service on this computer that the OpenSSL program
// answers for (the repository's test/helpers/tsa.mjs). No test reaches
// beyond this computer. Where there is no OpenSSL program, the test that
// needs it is skipped and says why.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import { test } from 'node:test';

const { checkBook } = await import('provared');
const { world, call, ADMIN_SECRET } = await import('./world.mjs');
const { checkConfig, openGateway } = await import('../gateway.mjs');
const { NO_OPENSSL, findOpenssl, startTestTsa } = await import('../../test/helpers/tsa.mjs');

/** An address on this computer that nothing listens on: a port that was free a moment ago. */
async function nobodyThere() {
  const s = http.createServer();
  await new Promise((done) => s.listen(0, '127.0.0.1', done));
  const port = s.address().port;
  await new Promise((done) => s.close(done));
  return `http://127.0.0.1:${port}/`;
}

test('recorder.stamp: each seal carries the time-stamp the service gave, which counts for a reader who trusts the service; a refusal costs no seal', { skip: findOpenssl() ? false : NO_OPENSSL }, async () => {
  const tsa = await startTestTsa();
  const w = await world({ recorder: { stamp: { address: tsa.address } } });
  try {
    await w.call('GET', '/tickets/api/now/table/x');
    const sealed = await call(w.port, 'POST', '/provared/seal', { secret: ADMIN_SECRET, headers: { 'content-type': 'application/json' }, body: { agent: 'patching' } });
    assert.equal(sealed.status, 200, sealed.text);
    assert.equal(sealed.json.stamped, true);
    const options = { ...w.gateway.checkOptions('patching'), stampServices: [tsa.authority] };
    let c = await checkBook(readFileSync(w.bookPath, 'utf8'), options);
    assert.equal(c.summary.intact, true);
    assert.deepEqual(c.entries[sealed.json.entry].stamps.map((s) => [s.kind, s.state]), [['service', 'valid']]);
    // A service that refuses: the seal goes in without a time-stamp, and the reason is said.
    tsa.mode = 'refuse';
    await w.call('GET', '/tickets/api/now/table/y');
    const second = await w.gateway.seal('patching');
    assert.equal(second.stamped, undefined);
    assert.equal(second.stampProblem.code, 'stamp-not-given');
    assert.match(second.stampProblem.message, /refused \(status 2\)/);
    c = await checkBook(readFileSync(w.bookPath, 'utf8'), options);
    assert.equal(c.summary.intact, true);
    assert.equal(c.summary.counts.seals, 2);
    assert.equal(c.entries[second.entry].stamps.length, 0);
    assert.ok(w.logs.some((e) => e.event === 'stamp-not-given' && e.agent === 'patching' && e.seal === second.fingerprint));
  } finally {
    await w.close();
    await tsa.close();
  }
});

test('recorder.stamp: a service that cannot be reached costs no seal, and the answer says why', async () => {
  const w = await world({ recorder: { stamp: { address: await nobodyThere(), timeout: 2000 } } });
  try {
    const sealed = await call(w.port, 'POST', '/provared/seal', { secret: ADMIN_SECRET, headers: { 'content-type': 'application/json' }, body: { agent: 'patching' } });
    assert.equal(sealed.status, 200, sealed.text);
    assert.equal(sealed.json.stampProblem.code, 'stamp-not-given');
    assert.match(sealed.json.stampProblem.message, /could not be reached/);
    const c = await checkBook(readFileSync(w.bookPath, 'utf8'), w.gateway.checkOptions('patching'));
    assert.equal(c.summary.intact, true);
    assert.equal(c.summary.counts.seals, 1);
  } finally {
    await w.close();
  }
});

test('recorder.stamp: given, it is an address on the web and a time limit in range; "check" says what is wrong', async () => {
  const w = await world();
  try {
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
      const config = { ...w.config, recorder: { ...w.config.recorder, stamp } };
      await assert.rejects(openGateway(config, { root: w.folder }), words, JSON.stringify(stamp));
      assert.ok((await checkConfig(config, { root: w.folder })).problems.some((p) => words.test(p)), JSON.stringify(stamp));
    }
    assert.ok(!(await checkConfig({ ...w.config, recorder: { ...w.config.recorder, stamp: { address: 'https://127.0.0.1:8443/tsa' } } }, { root: w.folder })).problems.some((p) => /stamp/.test(p)));
  } finally {
    await w.close();
  }
});
