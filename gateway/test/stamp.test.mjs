// An outside time-stamp on each seal the gateway signs ("recorder.stamp"),
// from a time-stamp service on this computer that the OpenSSL program
// answers for (the repository's test/helpers/tsa.mjs). No test reaches
// beyond this computer. Where there is no OpenSSL program, the test that
// needs it is skipped and says why.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { join } from 'node:path';
import { test } from 'node:test';

const { checkBook } = await import('provared');
const { world, call, ADMIN_SECRET } = await import('./world.mjs');
const { checkConfig } = await import('../gateway.mjs');
const { RUN_LIMIT, openGateway, refusedStart } = await import('./limits.mjs');
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
      // Whatever it holds, where it is given (X308).
      [null, /recorder\.stamp: must be an object/],
      ['', /recorder\.stamp: must be an object/],
      [false, /recorder\.stamp: must be an object/],
      [0, /recorder\.stamp: must be an object/],
      [{}, /recorder\.stamp\.address/],
      [{ address: 'ftp://127.0.0.1/' }, /recorder\.stamp\.address/],
      [{ address: 'http://user:secret@127.0.0.1/' }, /recorder\.stamp\.address/],
      [{ address: 'http://127.0.0.1/#x' }, /recorder\.stamp\.address/],
      [{ address: 'http://127.0.0.1/tsa?key=secret' }, /recorder\.stamp\.address: .*query/],
      [{ address: 'http://127.0.0.1/tsa?' }, /recorder\.stamp\.address/],
      [{ address: 'http://127.0.0.1/', timeout: 99 }, /recorder\.stamp\.timeout/],
      [{ address: 'http://127.0.0.1/', timeout: 20001 }, /recorder\.stamp\.timeout: must be a whole number of milliseconds from 100 to 20000/],
      [{ address: 'http://127.0.0.1/', policy: '1.2.3' }, /recorder\.stamp\.policy/],
    ]) {
      const config = { ...w.config, recorder: { ...w.config.recorder, stamp } };
      await refusedStart(openGateway(config, { root: w.folder }), words, JSON.stringify(stamp));
      assert.ok((await checkConfig(config, { root: w.folder })).problems.some((p) => words.test(p)), JSON.stringify(stamp));
    }
    assert.ok(!(await checkConfig({ ...w.config, recorder: { ...w.config.recorder, stamp: { address: 'https://127.0.0.1:8443/tsa' } } }, { root: w.folder })).problems.some((p) => /stamp/.test(p)));
  } finally {
    await w.close();
  }
});

test('recorder.stamp: a time more than 300 seconds before the seal\'s own time costs no seal; the time-stamp is not kept (X307)', { skip: findOpenssl() ? false : NO_OPENSSL }, async () => {
  const tsa = await startTestTsa();
  // The gateway's clock 320 seconds ahead of the service's: the seal would be dated after its time-stamp.
  const w = await world({ recorder: { stamp: { address: tsa.address } }, more: { now: () => Date.now() + 320000 } });
  try {
    await w.call('GET', '/tickets/api/now/table/x');
    const sealed = await w.gateway.seal('patching');
    assert.equal(sealed.stamped, undefined);
    assert.equal(sealed.stampProblem.code, 'stamp-not-given');
    assert.match(sealed.stampProblem.message, /before the seal's own time/);
    const c = await checkBook(readFileSync(w.bookPath, 'utf8'), { ...w.gateway.checkOptions('patching'), stampServices: [tsa.authority] });
    assert.equal(c.summary.intact, true);
  } finally {
    await w.close();
    await tsa.close();
  }
});

test('recorder.stamp.authority: a time-stamp signed by another certificate is not kept; the one named is, and its signer is shown in the answer and the status (X344)', { skip: findOpenssl() ? false : NO_OPENSSL }, async () => {
  const tsa = await startTestTsa();
  const stranger = await startTestTsa();
  let w = await world({ recorder: { stamp: { address: stranger.address, authority: tsa.authority } } });
  try {
    await w.call('GET', '/tickets/api/now/table/x');
    const refused = await w.gateway.seal('patching');
    assert.equal(refused.stamped, undefined);
    assert.equal(refused.stampProblem.code, 'stamp-not-given');
    assert.match(refused.stampProblem.message, new RegExp(`signed by the certificate whose fingerprint is ${stranger.authority}`));
    await w.close();
    w = await world({ recorder: { stamp: { address: tsa.address, authority: [tsa.authority] } } });
    await w.call('GET', '/tickets/api/now/table/x');
    const sealed = await call(w.port, 'POST', '/provared/seal', { secret: ADMIN_SECRET, headers: { 'content-type': 'application/json' }, body: { agent: 'patching' } });
    assert.equal(sealed.status, 200, sealed.text);
    assert.equal(sealed.json.stamped, true);
    assert.equal(sealed.json.stampedBy, tsa.authority);
    const status = await call(w.port, 'GET', '/provared/status', { secret: ADMIN_SECRET });
    assert.equal(status.json.agents.patching.lastSeal.stampedBy, tsa.authority, status.text);
  } finally {
    await w.close();
    await tsa.close();
    await stranger.close();
  }
});

test('recorder.stamp.authority: one fingerprint or a list; "check" warns where the service is asked over http: with none named (X344)', async () => {
  const w = await world();
  try {
    const fp = 'A'.repeat(43);
    const checked = (stamp) => checkConfig({ ...w.config, recorder: { ...w.config.recorder, stamp } }, { root: w.folder });
    for (const bad of ['', 'A'.repeat(42), [], [fp, 7], Array(17).fill(fp), {}, null]) {
      assert.ok((await checked({ address: 'http://127.0.0.1/', authority: bad })).problems.some((p) => /recorder\.stamp\.authority: must be the fingerprint/.test(p)), JSON.stringify(bad));
    }
    const warned = async (stamp) => (await checked(stamp)).warnings.some((x) => /plain http: and no "authority" is named/.test(x));
    assert.equal(await warned({ address: 'http://127.0.0.1/' }), true);
    assert.equal(await warned({ address: 'http://127.0.0.1/', authority: fp }), false);
    assert.equal(await warned({ address: 'http://127.0.0.1/', authority: [fp, 'b'.repeat(43)] }), false);
    assert.equal(await warned({ address: 'https://127.0.0.1/' }), false);
    assert.equal((await checked({ address: 'http://127.0.0.1/', authority: fp })).problems.some((p) => /stamp/.test(p)), false);
  } finally {
    await w.close();
  }
});

test('plainText: what the commands print of a sealer\'s words has no hidden or padding characters, one accent at most, and is cut at whole characters (X356)', async () => {
  const { plainText } = await import('../gateway.mjs');
  assert.equal(plainText('ok\u3164\u115f\u2800\u00a0\u2003x\u0301\u0301\u0301\ufe0f\u202eend'), 'ok     x\u0301  end');
  const long = plainText('\u{1f600}'.repeat(700));
  assert.equal(long.isWellFormed(), true);
  assert.equal([...long.slice(0, -3)].length, 600);
});

test('check: a library without the time-stamp client (provared/net/timestamp) is said plainly where recorder.stamp is given (X309)', async () => {
  const w = await world();
  try {
    const hide = new URL('../../test/helpers/no-net-timestamp.mjs', import.meta.url).href;
    const gateway = new URL('../gateway.mjs', import.meta.url).href;
    // checkConfig in a program of its own, so that the library can be hidden there; the settings hold keys, so they go by a file.
    const config = { ...w.config, recorder: { ...w.config.recorder, stamp: { address: 'http://127.0.0.1:9/tsa' } } };
    const file = join(w.folder, 'check-settings.json');
    writeFileSync(file, JSON.stringify(config));
    const code = `const { checkConfig } = await import(${JSON.stringify(gateway)}); const c = JSON.parse(require('node:fs').readFileSync(process.argv[1], 'utf8')); process.stdout.write(JSON.stringify((await checkConfig(c, { root: process.argv[2] })).problems));`;
    const run = (more) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '--input-type=commonjs', '-e', `(async () => { ${code} })()`, file, w.folder], { encoding: 'utf8', env: { ...process.env, NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} ${more}`.trim() }, windowsHide: true, timeout: RUN_LIMIT });
    // (Its other problems, if any, come of the signers in the test's settings, which a file cannot hold.)
    const fine = run('');
    const found = JSON.parse(fine.stdout || 'null');
    assert.ok(Array.isArray(found) && !found.some((p) => /stamp/.test(p)), fine.stdout + fine.stderr);
    const without = run(`--import=${hide}`);
    const problems = JSON.parse(without.stdout || 'null');
    assert.ok(problems?.some((p) => /recorder\.stamp: the library installed has no client for a time-stamp service \(provared\/net\/timestamp\)/.test(p)), without.stdout + without.stderr);
  } finally {
    await w.close();
  }
});
