// Sealing, acknowledging and the status over HTTP: the executor's own
// addresses, for the administrator alone, and the commands that ask a
// running executor or work on the files of a stopped one.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook, identifierFingerprint, argumentsFingerprint, keySetFingerprint, utf8, fromBase64url } = await import('provared');
const { httpWorld, openHttpWorld, call, rawRequest } = await import('./http-world.mjs');
const { signSlip, until, pause } = await import('./world.mjs');
const { CALL_DOCUMENT, TOOL_DOCUMENT, RESULT_DOCUMENT, WRITTEN_LATE_DOCUMENT, ACKNOWLEDGED_DOCUMENT } = await import('../executor.mjs');
const { ADMIN_BODY_LIMIT, checkHttpConfig, newSecret, openHttpExecutor, readHttpSettings, secretHash, httpStatusFromFiles } = await import('../http.mjs');
const { checkIdentity } = await import('../identity.mjs');

// The fixed texts of an acknowledged receipt, by their fingerprints written out (seal.test.mjs holds the texts).
const ACKNOWLEDGED_FINGERPRINT = 'poJcnPoQB6EyH2Pvp2ZPgD6_2XrDua1XAOpPHBaUezI';
const WRITTEN_LATER_FINGERPRINT = 'L_sk-qfojehaePxOm8pV-04nhqDY78T5E040ZwBKtho';
const { readCopy, loadCopyKey, openCopy } = await import('../copy.mjs');
const { makeKeyFile } = await import('../files.mjs');

const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));
const ENV = 'PROVARED_MCP_EXECUTOR_ADMIN_SECRET';

// A second local address, beside 127.0.0.1, for the tests of the address the executor signs. Windows and Linux answer on the
// whole of 127.0.0.0/8; a Mac has 127.0.0.1 alone until another is set up. Asked here, before any test is named: the tests
// that need it are skipped, with the reason, where it is not there.
const SECOND = '127.0.0.2';
function canListenAt(host) {
  return new Promise((done) => {
    const probe = net.createServer();
    probe.once('error', () => done(false));
    probe.listen(0, host, () => probe.close(() => done(true)));
  });
}
const NO_SECOND = (await canListenAt(SECOND)) ? false : `this computer cannot listen at a second local address, ${SECOND} (a Mac has 127.0.0.1 alone until another is set up)`;

function run(args, { env = {} } = {}) {
  return new Promise((done) => {
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', BIN, ...args], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, env: { ...process.env, [ENV]: '', ...env } });
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

/** An HTTP world with an administrator's secret and a recorder (unless "recorder" is null). */
async function adminWorld({ recorder = { keys: 'keys/recorder.jwk', name: 'The test recorder' }, makeKeys = true, config = {}, open = true, ...rest } = {}) {
  const admin = newSecret();
  const w = await httpWorld({ ...rest, open: false, config: { admin: { secretHash: secretHash(admin) }, ...(recorder ? { recorder } : {}), ...config } });
  w.admin = admin;
  if (recorder && makeKeys) w.sealKeys = [await keySetFingerprint(await makeKeyFile(join(w.folder, recorder.keys), 'recorder'))];
  if (open) await openHttpWorld(w);
  return w;
}
/** One request to one of the executor's own addresses. "secret" null sends no Authorization. */
async function ask(w, method, path, { secret = w.admin, body, headers = {} } = {}) {
  const res = await rawRequest({ url: `http://${w.address.address}:${w.address.port}${path}` }, { method, headers: { ...(secret === null ? {} : { authorization: `Bearer ${secret}` }), ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...headers }, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body) });
  let json;
  try {
    json = JSON.parse(res.body);
  } catch {
    json = undefined;
  }
  return { status: res.status, json, body: res.body };
}
const bookText = (w, name) => readFileSync(w.agents[name].book, 'utf8');
const checked = (w, name) => checkBook(bookText(w, name), { issuerKeys: w.settings.agents[name].issuerKeys, ...(w.sealKeys ? { sealKeys: w.sealKeys } : {}) });
const sealsOf = (c) => c.entries.filter((e) => e.kind === 'seal');
const stubsOf = (c) => c.entries.filter((e) => e.kind === 'stub');
const docs = (stub) => Object.fromEntries(stub.content.details.map((d) => [d.name, d.sha256]));

/** Stop the executor, leave a call of "name" in flight in its copy under the permission it ran under, and put a new permission in place. */
async function leaveCallUnderOldSlip(w, name, callId = 'lost-call') {
  const first = w.executor.agent(name).slip.fingerprint;
  await w.closeExecutor();
  const a = w.agents[name];
  const key = loadCopyKey(a.copyKey);
  const copy = openCopy(a.copy, key, w.settings.name, readCopy(a.copy, key, w.settings.name).next);
  const details = [{ name: 'provared.arguments', sha256: await argumentsFingerprint({}) }, { name: TOOL_DOCUMENT, sha256: await identifierFingerprint('slow') }, { name: CALL_DOCUMENT, sha256: await identifierFingerprint(callId) }];
  copy.note({ kind: 'sending', call: callId, when: new Date().toISOString(), slip: first, tool: 'slow', action: 'slow.work', with: 'executor', details });
  await pause(5);
  const signed = await signSlip({ passkey: w.passkey, agentKeys: a.agentKeys, executorKeys: w.executorKeys, until: Date.now() + 7200000 });
  writeFileSync(join(w.folder, 'slips', `${name}.json`), JSON.stringify(signed));
  return first;
}

test('the executor\'s own addresses are for the administrator alone: no secret in the settings, no answer; an agent\'s secret, a web page, or no secret is refused', async () => {
  // Without an administrator's secret in the settings the addresses answer nothing, whatever is sent.
  const plain = await httpWorld();
  try {
    plain.admin = plain.agents.alpha.secret;
    for (const [method, path] of [['GET', '/provared/status'], ['POST', '/provared/seal'], ['POST', '/provared/acknowledge']]) {
      const r = await ask(plain, method, path, { body: method === 'POST' ? { agent: 'alpha' } : undefined });
      assert.equal(r.status, 404, path);
      assert.equal(r.json.code, 'not-found');
    }
    assert.ok(!bookText(plain, 'alpha').includes('"seal"'));
  } finally {
    await plain.close();
  }
  // "check" says that such an executor cannot seal, and that its own addresses answer nothing.
  const report = await checkHttpConfig(plain.settings, plain.folder);
  assert.deepEqual(report.problems, []);
  assert.deepEqual([report.recorder, report.admin], [null, false]);
  assert.ok(report.warnings.some((x) => /^recorder: none is named/.test(x)) && report.warnings.some((x) => /^admin: no administrator's secret is named/.test(x)), report.warnings.join(' | '));
  const w = await adminWorld({ config: { allowedOrigins: ['http://localhost:3000'] } });
  try {
    await call(w, 'alpha', 'echo', {});
    const before = bookText(w, 'alpha');
    // No secret, an agent's secret, a wrong secret, two Authorization headers.
    for (const secret of [null, w.agents.alpha.secret, w.agents.beta.secret, newSecret()]) {
      for (const [method, path] of [['GET', '/provared/status'], ['POST', '/provared/seal'], ['POST', '/provared/acknowledge']]) {
        const r = await ask(w, method, path, { secret, body: method === 'POST' ? { agent: 'alpha' } : undefined });
        assert.equal(r.status, 401, `${path} with ${secret === null ? 'no secret' : 'another secret'}`);
        assert.equal(r.json.code, 'not-signed-in');
        assert.equal(r.json.agents, undefined);
      }
    }
    const twice = await ask(w, 'GET', '/provared/status', { secret: null, headers: { authorization: [`Bearer ${w.admin}`, `Bearer ${w.admin}`] } });
    assert.equal(twice.status, 401);
    // A web page: refused, even from an origin the MCP endpoint allows.
    const page = await ask(w, 'POST', '/provared/seal', { body: { agent: 'alpha' }, headers: { origin: 'http://localhost:3000' } });
    assert.equal(page.status, 403);
    assert.equal(page.json.code, 'origin-refused');
    assert.equal(bookText(w, 'alpha'), before, 'nothing was sealed');
    // The administrator's secret is not an agent's: it opens nothing at the MCP endpoint.
    const asAgent = await call(w, `Bearer ${w.admin}`, 'echo', {});
    assert.equal(asAgent.status, 401);
    // Other addresses under /provared, and other methods.
    assert.equal((await ask(w, 'GET', '/provared/seal')).status, 404);
    assert.equal((await ask(w, 'POST', '/provared/status', { body: {} })).status, 404);
    assert.equal((await ask(w, 'GET', '/provared')).status, 404);
    // A body over the limit.
    const big = await ask(w, 'POST', '/provared/seal', { body: JSON.stringify({ agent: 'alpha', filler: 'x'.repeat(ADMIN_BODY_LIMIT) }) });
    assert.equal(big.status, 413);
    assert.equal(bookText(w, 'alpha'), before);
    // The administrator.
    const ok = await ask(w, 'GET', '/provared/status');
    assert.equal(ok.status, 200);
    assert.deepEqual(Object.keys(ok.json.agents), ['alpha', 'beta']);
  } finally {
    await w.close();
  }
  // Settings in which an agent would hold the administrator's secret, or the MCP endpoint would stand on the executor's own addresses, are refused.
  const same = readHttpSettings({ ...w.settings, admin: { secretHash: w.settings.agents.alpha.secretHash } }, w.folder);
  assert.ok(same.problems.some((p) => /agents\.alpha\.secretHash: is also admin\.secretHash/.test(p)), same.problems.join(' | '));
  await assert.rejects(openHttpExecutor({ ...w.settings, admin: { secretHash: w.settings.agents.alpha.secretHash } }, { root: w.folder, log: () => {} }), /is also admin\.secretHash/);
  for (const path of ['/provared', '/provared/status', '/provared/mcp']) {
    assert.ok(readHttpSettings({ ...w.settings, path }, w.folder).problems.some((p) => /^path: must not be \/provared/.test(p)), path);
  }
  assert.ok(readHttpSettings({ ...w.settings, admin: { secretHash: 'short' } }, w.folder).problems.some((p) => /^admin\.secretHash/.test(p)));
  // An executor that is stopping, or has stopped, takes nothing at its own addresses: the administrator is told so, and nothing is sealed.
  const sealedBefore = bookText(w, 'alpha');
  for (const [method, url] of [['POST', '/provared/seal'], ['GET', '/provared/status'], ['POST', '/provared/acknowledge']]) {
    const res = { headersSent: false, writableEnded: false, destroyed: false, writeHead(status) { this.status = status; this.headersSent = true; }, end(body) { this.body = String(body); this.writableEnded = true; } };
    await w.executor.handle({ url, method, headers: { authorization: `Bearer ${w.admin}` }, headersDistinct: { authorization: [`Bearer ${w.admin}`] }, socket: {} }, res);
    assert.equal(res.status, 503, url);
    assert.equal(JSON.parse(res.body).code, 'stopping');
  }
  assert.equal(bookText(w, 'alpha'), sealedBefore);
  // Opened to work on its files, the executor does not listen.
  const off = await openHttpExecutor(w.settings, { root: w.folder, offline: true, log: () => {} });
  assert.throws(() => off.listen(), /does not listen/);
  await off.close();
});

test('POST /provared/seal seals one agent\'s book with the recorder\'s keys; GET /provared/status shows the last seal, the check and no call waiting', async () => {
  const w = await adminWorld();
  try {
    await call(w, 'alpha', 'echo', {});
    const sealed = await ask(w, 'POST', '/provared/seal', { body: { agent: 'alpha' } });
    assert.equal(sealed.status, 200, sealed.body);
    assert.deepEqual(Object.keys(sealed.json), ['agent', 'entry', 'fingerprint']);
    assert.deepEqual([sealed.json.agent, sealed.json.entry], ['alpha', 2]);
    const c = await checked(w, 'alpha');
    assert.equal(c.summary.problemFound, false);
    assert.equal(c.entries[2].kind, 'seal');
    assert.equal(c.entries[2].fingerprint, sealed.json.fingerprint);
    assert.ok(c.entries[2].signatures.every((s) => s.state === 'valid') && c.entries[2].signatures.length === 3);
    assert.equal(sealsOf(await checked(w, 'beta')).length, 0, 'the other agent\'s book is not sealed');
    // Calls go on after the seal.
    assert.ok((await call(w, 'alpha', 'echo', {})).json.result);
    assert.equal((await checked(w, 'alpha')).summary.problemFound, false);
    // An agent the settings do not name, and a body that names none.
    for (const body of [{ agent: 'gamma' }, {}, 'not json', { agent: ['alpha'] }]) {
      const r = await ask(w, 'POST', '/provared/seal', { body });
      assert.equal(r.status, 400, JSON.stringify(body));
      assert.equal(r.json.code, 'bad-request');
    }
    const status = await ask(w, 'GET', '/provared/status');
    assert.equal(status.status, 200);
    assert.deepEqual([status.json.executor, status.json.from, status.json.recorder.fingerprint], ['provared-mcp-executor', 'running', w.sealKeys[0]]);
    const a = status.json.agents.alpha;
    assert.deepEqual([a.entries, a.sound, a.withinSlips, a.checkedNow, a.stopped, a.waiting, a.fileHoldsBook], [4, true, true, true, null, 0, true]);
    assert.equal(a.lastSeal.fingerprint, sealed.json.fingerprint);
    assert.equal(a.lastSeal.entry, 2);
    assert.deepEqual(a.receiptsMissing, []);
    assert.equal(a.slip, w.executor.agent('alpha').slip.fingerprint);
    assert.equal(status.json.agents.beta.lastSeal, null);
    assert.ok(!status.body.includes(w.agents.alpha.secret) && !status.body.includes(w.admin), 'the status holds no secret');
  } finally {
    await w.close();
  }
  // Without a recorder the address says why nothing was sealed.
  const bare = await adminWorld({ recorder: null });
  try {
    const r = await ask(bare, 'POST', '/provared/seal', { body: { agent: 'alpha' } });
    assert.equal(r.status, 409);
    assert.equal(r.json.code, 'not-sealed');
    assert.match(r.json.message, /name no recorder/);
    assert.equal((await ask(bare, 'GET', '/provared/status')).json.recorder, null);
  } finally {
    await bare.close();
  }
});

test('a call sent under a permission no longer in force holds that agent alone; the administrator acknowledges it, and the agent takes calls again', async () => {
  const w = await adminWorld();
  await call(w, 'alpha', 'echo', {});
  const first = await leaveCallUnderOldSlip(w, 'alpha');
  await openHttpWorld(w);
  try {
    // The executor started; alpha takes no call, beta does.
    assert.ok(w.logs.some((e) => e.event === 'receipt-missing' && e.agent === 'alpha'));
    const held = await call(w, 'alpha', 'echo', {});
    assert.equal(held.json.error.code, 1001);
    assert.match(held.json.error.message, /takes no call: 1 call\(s\) sent before the executor last stopped/);
    assert.equal(stubsOf(await checked(w, 'alpha')).length, 1, 'no receipt was written: the call was not taken');
    assert.ok((await call(w, 'beta', 'echo', {})).json.result);
    const status = (await ask(w, 'GET', '/provared/status')).json;
    assert.match(status.agents.alpha.stopped, /have no receipt in the book/);
    assert.deepEqual(status.agents.alpha.receiptsMissing.map((p) => [p.call, p.usable, p.slip]), [['lost-call', true, first]]);
    assert.equal(status.agents.beta.stopped, null);
    // A book with a call waiting is not sealed.
    const sealed = await ask(w, 'POST', '/provared/seal', { body: { agent: 'alpha' } });
    assert.equal(sealed.status, 409);
    assert.match(sealed.json.message, /The agent is stopped/);
    // An agent cannot acknowledge its own calls.
    assert.equal((await ask(w, 'POST', '/provared/acknowledge', { secret: w.agents.alpha.secret, body: { agent: 'alpha' } })).status, 401);
    assert.equal(stubsOf(await checked(w, 'alpha')).length, 1);
    // What is asked must be of the right form.
    assert.equal((await ask(w, 'POST', '/provared/acknowledge', { body: { agent: 'gamma' } })).status, 400);
    const bad = await ask(w, 'POST', '/provared/acknowledge', { body: { agent: 'alpha', setAside: 'lost-call' } });
    assert.equal(bad.status, 409);
    assert.match(bad.json.message, /must be a list/);
    const none = await ask(w, 'POST', '/provared/acknowledge', { body: { agent: 'beta' } });
    assert.equal(none.status, 409);
    assert.equal(none.json.code, 'not-acknowledged');
    // The administrator acknowledges.
    const done = await ask(w, 'POST', '/provared/acknowledge', { body: { agent: 'alpha' } });
    assert.equal(done.status, 200, done.body);
    assert.deepEqual([done.json.agent, done.json.written.length, done.json.setAside.length, done.json.remaining.length], ['alpha', 1, 0, 0]);
    const c = await checked(w, 'alpha');
    assert.equal(c.summary.problemFound, false);
    const stub = stubsOf(c).at(-1);
    assert.equal(stub.fingerprint, done.json.written[0].stub);
    assert.equal(stub.content.slip, first);
    assert.equal(docs(stub)[WRITTEN_LATE_DOCUMENT], WRITTEN_LATER_FINGERPRINT);
    assert.equal(docs(stub)[ACKNOWLEDGED_DOCUMENT], ACKNOWLEDGED_FINGERPRINT);
    assert.deepEqual(done.json.failed, []);
    assert.equal(stub.countersignature.state, 'valid');
    // alpha takes calls again, under the permission in force; a second acknowledgement finds nothing.
    const again = await call(w, 'alpha', 'echo', {});
    assert.ok(again.json.result);
    assert.equal(stubsOf(await checked(w, 'alpha')).at(-1).content.slip, w.executor.agent('alpha').slip.fingerprint);
    assert.equal((await ask(w, 'POST', '/provared/acknowledge', { body: { agent: 'alpha' } })).status, 409);
    assert.equal((await ask(w, 'POST', '/provared/seal', { body: { agent: 'alpha' } })).status, 200);
    assert.equal((await checked(w, 'alpha')).summary.problemFound, false);
  } finally {
    await w.close();
  }
});

test('a timer over HTTP seals each agent\'s book that has something new, and stops with the executor', async () => {
  const w = await adminWorld({ recorder: { keys: 'keys/recorder.jwk', sealEvery: 1000 } });
  try {
    // At the start each book (its slip) is sealed.
    await until(async () => sealsOf(await checked(w, 'alpha')).length === 1 && sealsOf(await checked(w, 'beta')).length === 1, { timeout: 20000 });
    await call(w, 'alpha', 'echo', {});
    await until(async () => sealsOf(await checked(w, 'alpha')).length === 2, { timeout: 20000 });
    await pause(8000);
    assert.equal(sealsOf(await checked(w, 'alpha')).length, 2, 'no seal over a seal');
    assert.equal(sealsOf(await checked(w, 'beta')).length, 1, 'nothing new in the other book');
    assert.equal((await checked(w, 'alpha')).summary.problemFound, false);
    assert.equal((await checked(w, 'alpha')).entries.at(-1).content.by.name, w.settings.name, 'named as the executor unless the settings say otherwise');
    assert.equal((await ask(w, 'GET', '/provared/status')).json.recorder.sealEvery, 1000);
  } finally {
    await w.close();
  }
});

test('a timer over HTTP: once the executor has closed, its timer seals nothing more, though a book holds something new', async () => {
  const w = await adminWorld({ agents: ['alpha'], recorder: { keys: 'keys/recorder.jwk', sealEvery: 4000 } });
  try {
    // The round at the start has ended; the next is four seconds away.
    await until(() => w.logs.some((e) => e.event === 'sealed'), { timeout: 20000 });
    await call(w, 'alpha', 'echo', {});
  } finally {
    await w.close();
  }
  const text = bookText(w, 'alpha');
  assert.deepEqual((await checked(w, 'alpha')).entries.map((e) => e.kind), ['slip', 'seal', 'stub']);
  // Time enough for the next round, and for a seal to be signed.
  await pause(10000);
  assert.equal(bookText(w, 'alpha'), text);
});

test('the command over HTTP: seal, status and acknowledge ask the running executor with the administrator\'s secret; with --offline they work on the files', async () => {
  const w = await adminWorld({ open: false, config: { listen: { host: '127.0.0.1', port: 0 } } });
  // The command reads the port from the settings: listen on a free one, and write it there.
  await openHttpWorld(w);
  w.settings.listen = { host: '127.0.0.1', port: w.address.port };
  writeFileSync(w.configPath, JSON.stringify(w.settings));
  const config = ['--config', w.configPath];
  const secret = { env: { [ENV]: w.admin } };
  try {
    await call(w, 'alpha', 'echo', {});
    // No secret in the environment, the wrong one, no agent named.
    const none = await run(['seal', ...config, '--agent', 'alpha']);
    assert.equal(none.code, 2);
    assert.match(none.stderr, new RegExp(ENV));
    const wrong = await run(['seal', ...config, '--agent', 'alpha'], { env: { [ENV]: w.agents.alpha.secret } });
    assert.equal(wrong.code, 1);
    assert.match(wrong.stderr, /was not sealed: .*administrator's secret/);
    const unnamed = await run(['seal', ...config], secret);
    assert.equal(unnamed.code, 2);
    assert.match(unnamed.stderr, /Name the agent whose book to seal: --agent <name> \(one of alpha, beta\)/);
    assert.equal((await run(['seal', ...config, '--agent', 'gamma'], secret)).code, 2);
    assert.equal(sealsOf(await checked(w, 'alpha')).length, 0);
    // The administrator.
    const sealed = await run(['seal', ...config, '--agent', 'alpha'], secret);
    assert.equal(sealed.code, 0, sealed.stderr);
    assert.match(sealed.stdout, /^Sealed: entry 2 of alpha's book is the seal [A-Za-z0-9_-]{43}\.\n$/);
    assert.equal(sealsOf(await checked(w, 'alpha')).length, 1);
    assert.ok(!sealed.stdout.includes(w.admin) && !sealed.stderr.includes(w.admin));
    const status = await run(['status', ...config], secret);
    assert.equal(status.code, 0, status.stderr);
    const shown = JSON.parse(status.stdout);
    assert.equal(shown.from, 'running');
    assert.equal(shown.agents.alpha.lastSeal.entry, 2);
    assert.equal((await run(['status', ...config])).code, 2);
    const nothing = await run(['acknowledge', ...config, '--agent', 'alpha'], secret);
    assert.equal(nothing.code, 1);
    assert.match(nothing.stderr, /nothing was acknowledged or set aside: This agent has no call without a receipt/);
  } finally {
    await w.closeExecutor();
  }
  // The executor is stopped: the command says so, and --offline works on the files.
  const stopped = await run(['seal', ...config, '--agent', 'alpha'], secret);
  assert.equal(stopped.code, 2);
  assert.match(stopped.stderr, /is not running at 127\.0\.0\.1:\d+\. To seal a book while it is stopped, add --offline/);
  const offline = await run(['seal', ...config, '--agent', 'beta', '--offline']);
  assert.equal(offline.code, 0, offline.stderr);
  assert.match(offline.stdout, /^Sealed: entry 1 of beta's book is the seal /);
  assert.equal((await checked(w, 'beta')).summary.problemFound, false);
  const files = await run(['status', ...config, '--offline']);
  assert.equal(files.code, 0, files.stderr);
  assert.equal(JSON.parse(files.stdout).from, 'files');
  assert.equal(JSON.parse(files.stdout).agents.beta.lastSeal.entry, 1);
  assert.deepEqual(await httpStatusFromFiles(w.settings, w.folder).then((s) => Object.keys(s.agents)), ['alpha', 'beta']);
  // A call that waits is acknowledged offline; then set aside.
  await openHttpWorld(w);
  await leaveCallUnderOldSlip(w, 'alpha');
  const waiting = JSON.parse((await run(['status', ...config, '--offline'])).stdout);
  assert.equal(waiting.agents.alpha.receiptsMissing[0].call, 'lost-call');
  const done = await run(['acknowledge', ...config, '--agent', 'alpha', '--offline']);
  assert.equal(done.code, 0, done.stderr);
  assert.match(done.stdout, /its receipt, written under the permission it was sent under, is [A-Za-z0-9_-]{43}\.\nalpha takes calls again, once it is started\.\n$/);
  assert.equal((await checked(w, 'alpha')).summary.problemFound, false);
  assert.equal(stubsOf(await checked(w, 'alpha')).length, 2);
  await w.upstream.close();
});

test('the command over HTTP: keys makes the recorder\'s key file beside the others, and check shows the recorder', async () => {
  const w = await adminWorld({ open: false, agents: ['alpha'], recorder: { keys: 'sealing/recorder.jwk' }, makeKeys: false });
  await w.upstream.close();
  const keys = await run(['keys', '--config', w.configPath]);
  assert.equal(keys.code, 0, keys.stderr);
  assert.ok(existsSync(join(w.folder, 'sealing', 'recorder.jwk')));
  const print = /fingerprint of its key set is ([A-Za-z0-9_-]{43})/.exec(keys.stderr);
  assert.ok(print, keys.stderr);
  assert.deepEqual(Object.keys(JSON.parse(keys.stdout)), ['alpha'], 'what goes into the permissions is unchanged');
  const check = JSON.parse((await run(['check', '--config', w.configPath])).stdout);
  assert.deepEqual(check.problems, []);
  assert.deepEqual(check.recorder, { name: w.settings.name, fingerprint: print[1], sealEvery: null });
  assert.equal(check.admin, true);
  // The recorder's key file may not be the executor's or an agent's.
  writeFileSync(w.configPath, JSON.stringify({ ...w.settings, recorder: { keys: 'keys/alpha.jwk' } }));
  const shared = await run(['keys', '--config', w.configPath]);
  assert.equal(shared.code, 2);
  assert.match(shared.stderr, /recorder\.keys .* is also the key file of the executor or of an agent/);
  // A missing recorder key file is a problem "check" names.
  writeFileSync(w.configPath, JSON.stringify({ ...w.settings, recorder: { keys: 'sealing/none.jwk' } }));
  const missing = JSON.parse((await run(['check', '--config', w.configPath])).stdout);
  assert.ok(missing.problems.some((p) => /^recorder\.keys: the key file .* does not exist yet/.test(p)), missing.problems.join(' | '));
});

// --- after the review of 0.5.0 ---

/** A settings file like the world's, with the address to ask at changed: what a command reads. */
function settingsAt(w, name, port, change = (s) => s) {
  const path = join(w.folder, name);
  writeFileSync(path, JSON.stringify(change({ ...w.settings, listen: { host: '127.0.0.1', port } })));
  return path;
}
function listenOn(server) {
  return new Promise((done) => server.listen(0, '127.0.0.1', () => done(server.address().port)));
}

test('POST /provared/hello: the executor signs a fresh challenge and the address it was asked at, and nothing that could be a record', async () => {
  const w = await adminWorld({ agents: ['alpha'] });
  try {
    const challenge = randomBytes(32).toString('base64url');
    // No secret is needed, and none is sent.
    const r = await ask(w, 'POST', '/provared/hello', { secret: null, body: { challenge } });
    assert.equal(r.status, 200, r.body);
    assert.deepEqual(Object.keys(r.json), ['executor', 'address', 'port', 'signatures']);
    assert.deepEqual([r.json.executor, r.json.address, r.json.port, r.json.signatures.length], ['provared-mcp-executor', '127.0.0.1', w.address.port, 2]);
    const port = w.address.port;
    assert.equal(await checkIdentity(w.executorKeys, challenge, '127.0.0.1', port, r.json.signatures), true);
    assert.equal(await checkIdentity(w.executorKeys, challenge, '::ffff:127.0.0.1', port, r.json.signatures), true, 'the same address, as IPv6 writes it');
    // What is signed is this text and no other, by the executor's Ed25519 key (and by its ML-DSA-87 key).
    const text = utf8(`provared-mcp-executor hello v1\n${challenge}\n127.0.0.1\n${port}\n`);
    const ed = await globalThis.crypto.subtle.importKey('jwk', w.executorKeys[0], { name: 'Ed25519' }, false, ['verify']);
    assert.equal(await globalThis.crypto.subtle.verify({ name: 'Ed25519' }, ed, fromBase64url(r.json.signatures[0]), text), true);
    // Anything else does not check: another challenge, another port, another address, one signature alone, another executor's keys.
    assert.equal(await checkIdentity(w.executorKeys, randomBytes(32).toString('base64url'), '127.0.0.1', port, r.json.signatures), false);
    assert.equal(await checkIdentity(w.executorKeys, challenge, '127.0.0.1', port + 1, r.json.signatures), false);
    assert.equal(await checkIdentity(w.executorKeys, challenge, '127.0.0.2', port, r.json.signatures), false);
    assert.equal(await checkIdentity(w.executorKeys, challenge, '127.0.0.1', port, [r.json.signatures[0]]), false);
    assert.equal(await checkIdentity(w.executorKeys, challenge, '127.0.0.1', port, [r.json.signatures[0], r.json.signatures[0]]), false);
    assert.equal(await checkIdentity(w.executorKeys, challenge, '127.0.0.1', port, [r.json.signatures[1], r.json.signatures[0]]), false);
    assert.equal(await checkIdentity(w.executorKeys, challenge, '127.0.0.1', port, undefined), false);
    assert.equal(await checkIdentity(w.agents.alpha.agentKeys, challenge, '127.0.0.1', port, r.json.signatures), false);
    // A challenge is 43 characters of base64url. What a record is signed over (two runs of base64url and a full stop) is not one.
    for (const body of [{}, { challenge: 'short' }, { challenge: 'x'.repeat(44) }, { challenge: `${'a'.repeat(21)}.${'b'.repeat(21)}` }, { challenge: ['x'.repeat(43)] }, 'not json']) {
      const bad = await ask(w, 'POST', '/provared/hello', { secret: null, body });
      assert.equal(bad.status, 400, JSON.stringify(body));
      assert.equal(bad.json.signatures, undefined);
    }
    // A web page is refused here as at the other addresses.
    assert.equal((await ask(w, 'POST', '/provared/hello', { secret: null, body: { challenge }, headers: { origin: 'http://localhost:3000' } })).status, 403);
    assert.equal((await ask(w, 'GET', '/provared/hello', { secret: null })).status, 401);
  } finally {
    await w.close();
  }
  // Without an administrator's secret in the settings this address answers nothing either.
  const plain = await httpWorld({ agents: ['alpha'] });
  try {
    plain.admin = 'x';
    const r = await ask(plain, 'POST', '/provared/hello', { secret: null, body: { challenge: randomBytes(32).toString('base64url') } });
    assert.equal(r.status, 404);
    assert.equal(r.json.signatures, undefined);
  } finally {
    await plain.close();
  }
});

test('POST /provared/hello, which anyone may ask: a body of 256 bytes at most, 5 seconds at most for it to arrive, and 8 such questions in hand at once', async () => {
  // A long timeout for the agents' calls, so that a wait cut short is the hello's own.
  const w = await adminWorld({ agents: ['alpha'], config: { timeout: 120000 } });
  const open = [];
  /** A hello whose body is begun and not ended: the answer's status, once it comes. */
  const unfinished = () => {
    const req = http.request({ host: '127.0.0.1', port: w.address.port, path: '/provared/hello', method: 'POST', agent: false, headers: { 'content-type': 'application/json', 'content-length': '60' } });
    open.push(req);
    const answered = new Promise((done) => {
      req.on('response', (res) => {
        res.resume();
        done(res.statusCode);
      });
      req.on('error', () => done('the connection failed'));
    });
    req.write('{"challenge":"');
    return answered;
  };
  try {
    const challenge = randomBytes(32).toString('base64url');
    // More than 256 bytes is refused, and nothing is signed, even where the challenge in it is sound.
    const long = await ask(w, 'POST', '/provared/hello', { secret: null, body: JSON.stringify({ challenge, filler: 'x'.repeat(200) }) });
    assert.equal(long.status, 400);
    assert.equal(long.json.signatures, undefined);
    assert.equal((await ask(w, 'POST', '/provared/hello', { secret: null, body: JSON.stringify({ challenge, filler: 'x'.repeat(150) }) })).status, 200, 'under 256 bytes is taken');
    // A body that never ends is given up on after 5 seconds, not after the agents' timeout.
    const began = Date.now();
    const slow = await Promise.race([unfinished(), pause(15000).then(() => 'no answer')]);
    const took = Date.now() - began;
    assert.equal(slow, 400);
    assert.ok(took >= 4500 && took < 12000, `${took} ms`);
    // Eight in hand at once: the ninth is turned away at once, and nothing is signed for it.
    const eight = Array.from({ length: 8 }, unfinished);
    await pause(500);
    const ninth = await ask(w, 'POST', '/provared/hello', { secret: null, body: { challenge } });
    assert.equal(ninth.status, 503);
    assert.equal(ninth.json.code, 'busy');
    assert.equal(ninth.json.signatures, undefined);
    // Once those are given up on, the executor answers again.
    assert.deepEqual(await Promise.all(eight), Array(8).fill(400));
    const after = await ask(w, 'POST', '/provared/hello', { secret: null, body: { challenge } });
    assert.equal(after.status, 200, after.body);
    // An agent's call was not held up by them.
    assert.ok((await call(w, 'alpha', 'echo', {})).json.result);
  } finally {
    for (const req of open) req.destroy();
    await w.close();
  }
});

test('the commands send the administrator\'s secret to the executor of their settings alone: not to another listener at that address, and not through one that passes the challenge on', async () => {
  const w = await adminWorld({ agents: ['alpha'] });
  const secret = { env: { [ENV]: w.admin } };
  const seen = [];
  const body = (req) => new Promise((done) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => done(Buffer.concat(chunks).toString('utf8')));
  });
  // A listener that is not the executor, and answers as if it were.
  const pretender = http.createServer(async (req, res) => {
    seen.push({ to: 'pretender', url: req.url, authorization: req.headers.authorization ?? null, body: await body(req) });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ executor: 'provared-mcp-executor', from: 'running', recorder: null, agents: {}, address: '127.0.0.1', port: 1, signatures: ['AAAA', 'BBBB'], entry: 1, fingerprint: 'x', written: [], setAside: [], remaining: [] }));
  });
  // A listener in the middle: it passes the challenge on to the executor and hands back the executor's own answer.
  const middle = http.createServer(async (req, res) => {
    const sent = await body(req);
    seen.push({ to: 'middle', url: req.url, authorization: req.headers.authorization ?? null, body: sent });
    if (req.url !== '/provared/hello') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end('{}');
    }
    const answer = await fetch(`http://127.0.0.1:${w.address.port}/provared/hello`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: sent });
    res.writeHead(answer.status, { 'content-type': 'application/json' });
    res.end(await answer.text());
  });
  try {
    const atPretender = settingsAt(w, 'at-pretender.json', await listenOn(pretender));
    for (const args of [['status'], ['seal', '--agent', 'alpha'], ['acknowledge', '--agent', 'alpha']]) {
      const r = await run([...args, '--config', atPretender], secret);
      assert.equal(r.code, 2, args.join(' '));
      assert.match(r.stderr, /did not show that it is the executor of these settings: its signatures do not check .* The administrator's secret was not sent\./, args.join(' '));
      assert.equal(r.stdout, '', 'what the listener made up is not printed');
    }
    const atMiddle = settingsAt(w, 'at-middle.json', await listenOn(middle));
    const through = await run(['status', '--config', atMiddle], secret);
    assert.equal(through.code, 2);
    assert.match(through.stderr, /its signatures do not check .* The administrator's secret was not sent\./);
    assert.equal(seen.filter((s) => s.to === 'middle').length, 1, 'the executor did sign for the listener in the middle');
    // Neither listener was sent the secret, in a header or anywhere else; each was sent a challenge and no more.
    assert.equal(seen.length, 4);
    for (const s of seen) {
      assert.equal(s.url, '/provared/hello');
      assert.equal(s.authorization, null);
      assert.ok(!s.body.includes(w.admin));
      assert.deepEqual(Object.keys(JSON.parse(s.body)), ['challenge']);
    }
    assert.equal(new Set(seen.map((s) => JSON.parse(s.body).challenge)).size, 4, 'a fresh challenge each time');
    // The executor itself: the command works.
    const direct = settingsAt(w, 'direct.json', w.address.port);
    const ok = await run(['status', '--config', direct], secret);
    assert.equal(ok.code, 0, ok.stderr);
    assert.deepEqual(Object.keys(JSON.parse(ok.stdout).agents), ['alpha']);
    // The command checks against the executor's key file: another key file, and it does not trust the executor it reaches; none, and it sends nothing.
    await makeKeyFile(join(w.folder, 'keys', 'other.jwk'), 'agent');
    const otherKeys = settingsAt(w, 'other-keys.json', w.address.port, (s) => ({ ...s, executor: { keys: 'keys/other.jwk' } }));
    const distrusted = await run(['status', '--config', otherKeys], secret);
    assert.equal(distrusted.code, 2);
    assert.match(distrusted.stderr, /its signatures do not check/);
    const noKeys = settingsAt(w, 'no-keys.json', w.address.port, (s) => ({ ...s, executor: { keys: 'keys/none.jwk' } }));
    const unread = await run(['status', '--config', noKeys], secret);
    assert.equal(unread.code, 2);
    assert.match(unread.stderr, /key file .*none\.jwk could not be read/);
  } finally {
    pretender.close();
    middle.close();
    pretender.closeAllConnections();
    middle.closeAllConnections();
    await w.close();
  }
});

test('an executor that listens on every address signs the address it was reached at: 127.0.0.2 where it is asked there, 127.0.0.1 where it is asked there', { skip: NO_SECOND }, async () => {
  const w = await adminWorld({ agents: ['alpha'], config: { listen: { host: '0.0.0.0', port: 0 } } });
  try {
    const port = w.address.port;
    const ed = await globalThis.crypto.subtle.importKey('jwk', w.executorKeys[0], { name: 'Ed25519' }, false, ['verify']);
    for (const [at, other] of [[SECOND, '127.0.0.1'], ['127.0.0.1', SECOND]]) {
      const challenge = randomBytes(32).toString('base64url');
      const res = await rawRequest({ url: `http://${at}:${port}/provared/hello` }, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ challenge }) });
      assert.equal(res.status, 200, res.body);
      const answer = JSON.parse(res.body);
      assert.deepEqual([answer.address, answer.port], [at, port], `asked at ${at}`);
      assert.equal(await checkIdentity(w.executorKeys, challenge, at, port, answer.signatures), true, `asked at ${at}, it signs ${at}`);
      assert.equal(await checkIdentity(w.executorKeys, challenge, other, port, answer.signatures), false, `asked at ${at}, it does not sign ${other}`);
      // The text signed names the address the request came to, and no other.
      const text = utf8(`provared-mcp-executor hello v1\n${challenge}\n${at}\n${port}\n`);
      assert.equal(await globalThis.crypto.subtle.verify({ name: 'Ed25519' }, ed, fromBase64url(answer.signatures[0]), text), true);
    }
  } finally {
    await w.close();
  }
});

test('a relay at one local address that passes the challenge on to the executor at another, on the same port, is sent no secret: the executor signs the address it was reached at, not the one the command connected to', { skip: NO_SECOND }, async () => {
  const w = await adminWorld({ agents: ['alpha'], open: false, config: { listen: { host: SECOND, port: 0 } } });
  const secret = { env: { [ENV]: w.admin } };
  const seen = [];
  const passedOn = [];
  // The relay: whatever it is sent it notes; a challenge it passes on to the executor, at the executor's own address, and hands back the answer.
  const newRelay = () => http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const sent = Buffer.concat(chunks).toString('utf8');
      seen.push({ url: req.url, authorization: req.headers.authorization ?? null, body: sent });
      if (req.url !== '/provared/hello') {
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end('{"agents":{}}');
      }
      const answer = await fetch(`http://${SECOND}:${w.address.port}/provared/hello`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: sent });
      const text = await answer.text();
      passedOn.push({ status: answer.status, text });
      res.writeHead(answer.status, { 'content-type': 'application/json' });
      res.end(text);
    });
  });
  let relay = null;
  try {
    // The executor at 127.0.0.2 and the relay at 127.0.0.1, on one port: the port the executor is given, where it is free at 127.0.0.1 too (another program may hold it there).
    for (let tries = 0; relay === null && tries < 5; tries++) {
      await openHttpWorld(w);
      const server = newRelay();
      relay = await new Promise((done) => {
        server.once('error', () => done(null));
        server.listen(w.address.port, '127.0.0.1', () => done(server));
      });
      if (relay === null) await w.closeExecutor();
    }
    assert.ok(relay, 'no port was free at both addresses in five tries');
    const port = w.address.port;
    assert.equal(w.address.address, SECOND);
    // The command asks at 127.0.0.1, where the relay is.
    const through = await run(['status', '--config', settingsAt(w, 'at-relay.json', port)], secret);
    assert.equal(through.code, 2, through.stdout + through.stderr);
    assert.match(through.stderr, /its signatures do not check .* over this command's challenge and the address it connected to\. The administrator's secret was not sent\./);
    assert.equal(through.stdout, '');
    // The relay was sent a challenge and no more: no secret, in a header or anywhere else.
    assert.equal(seen.length, 1);
    assert.deepEqual([seen[0].url, seen[0].authorization], ['/provared/hello', null]);
    assert.ok(!seen[0].body.includes(w.admin));
    // The executor did sign for the relay: the address it was reached at, 127.0.0.2, with the port both listen on. That address alone kept the secret back.
    assert.equal(passedOn.length, 1);
    const challenge = JSON.parse(seen[0].body).challenge;
    const signed = JSON.parse(passedOn[0].text);
    assert.deepEqual([passedOn[0].status, signed.address, signed.port], [200, SECOND, port]);
    assert.equal(await checkIdentity(w.executorKeys, challenge, SECOND, port, signed.signatures), true);
    assert.equal(await checkIdentity(w.executorKeys, challenge, '127.0.0.1', port, signed.signatures), false, 'it did not sign the address the command connected to');
    // Asked at the address it listens on, with no relay between: the command works.
    const direct = await run(['status', '--config', settingsAt(w, 'direct.json', port, (s) => ({ ...s, listen: { host: SECOND, port } }))], secret);
    assert.equal(direct.code, 0, direct.stderr);
    assert.deepEqual(Object.keys(JSON.parse(direct.stdout).agents), ['alpha']);
    assert.equal(seen.length, 1, 'and the relay saw nothing of it');
  } finally {
    relay?.close();
    relay?.closeAllConnections();
    // w.close is there once the executor has been opened; before that, only the upstream is.
    await (w.close ? w.close() : w.upstream.close());
  }
});

test('the commands check a running executor with its public keys alone: the file "keys --public-keys" writes, named by --public-keys or as "executor.keys"; a file with no usable keys is said in plain words and nothing is sent', async () => {
  const w = await adminWorld({ agents: ['alpha'] });
  const secret = { env: { [ENV]: w.admin } };
  // A listener that notes what it is sent: a command that has no keys to check with sends it nothing, not even a challenge.
  const seen = [];
  const listener = http.createServer((req, res) => {
    seen.push(req.url);
    res.writeHead(404);
    res.end();
  });
  try {
    const keyFile = readFileSync(join(w.folder, 'keys', 'executor.jwk'), 'utf8');
    // "keys --public-keys" writes the executor's two public keys to a new file, in a folder it makes, and nothing private.
    const publicAt = join(w.folder, 'for-the-administrator', 'executor-public.json');
    const made = await run(['keys', '--config', w.configPath, '--public-keys', publicAt]);
    assert.equal(made.code, 0, made.stderr);
    assert.match(made.stderr, /wrote the executor's two public keys to .*executor-public\.json\. It holds no private key and is no secret\./);
    const written = JSON.parse(readFileSync(publicAt, 'utf8'));
    assert.deepEqual(Object.keys(written), ['about', 'keys']);
    assert.deepEqual(written.keys, w.executorKeys);
    assert.deepEqual(written.keys.map((k) => Object.keys(k).sort()), [['alg', 'crv', 'kty', 'x'], ['alg', 'kty', 'pub']], 'no private part: no "d", no "priv"');
    // It overwrites nothing, and does not write over a key file of the settings.
    const twice = await run(['keys', '--config', w.configPath, '--public-keys', publicAt]);
    assert.equal(twice.code, 2);
    assert.match(twice.stderr, /Nothing was written: .*executor-public\.json \(--public-keys\) already exists/);
    const onKeyFile = await run(['keys', '--config', w.configPath, '--public-keys', join(w.folder, 'keys', 'executor.jwk')]);
    assert.equal(onKeyFile.code, 2);
    assert.match(onKeyFile.stderr, /Nothing was written: .* is a key file of the settings/);
    assert.equal(readFileSync(join(w.folder, 'keys', 'executor.jwk'), 'utf8'), keyFile);

    // The commands need no private key. Settings whose "executor.keys" cannot be read, and --public-keys: each command works.
    const unreadable = settingsAt(w, 'unreadable-keys.json', w.address.port, (s) => ({ ...s, executor: { keys: 'keys/none.jwk' } }));
    for (const args of [['status'], ['seal', '--agent', 'alpha']]) {
      const r = await run([...args, '--config', unreadable, '--public-keys', publicAt], secret);
      assert.equal(r.code, 0, `${args.join(' ')}: ${r.stderr}`);
    }
    // No call waits to be acknowledged: it is the executor that says so, to the administrator.
    const nothing = await run(['acknowledge', '--agent', 'alpha', '--config', unreadable, '--public-keys', publicAt], secret);
    assert.equal(nothing.code, 1);
    assert.match(nothing.stderr, /nothing was acknowledged or set aside: This agent has no call without a receipt to acknowledge\./);
    assert.equal(sealsOf(await checked(w, 'alpha')).length, 1, 'the book was sealed by the running executor');
    // The same file as "executor.keys", in settings of the administrator's own: it had been refused with "Unsupported key usage for Ed25519 key".
    const publicOnly = settingsAt(w, 'public-only.json', w.address.port, (s) => ({ ...s, executor: { keys: publicAt } }));
    const ok = await run(['status', '--config', publicOnly], secret);
    assert.equal(ok.code, 0, ok.stderr);
    assert.deepEqual(Object.keys(JSON.parse(ok.stdout).agents), ['alpha']);

    // The check is as strong as it was: both signatures must check under the keys in the file. Another executor's public keys, or one of them, and the secret is not sent.
    const direct = settingsAt(w, 'direct.json', w.address.port);
    const other = await makeKeyFile(join(w.folder, 'keys', 'other.jwk'), 'agent');
    const wrongAt = join(w.folder, 'wrong-public.json');
    for (const keys of [other, [w.executorKeys[0], other[1]], [other[0], w.executorKeys[1]]]) {
      writeFileSync(wrongAt, JSON.stringify({ keys }));
      const r = await run(['status', '--config', direct, '--public-keys', wrongAt], secret);
      assert.equal(r.code, 2);
      assert.match(r.stderr, /its signatures do not check under the public keys in the file --public-keys names, .* The administrator's secret was not sent\./);
      assert.equal(r.stdout, '');
    }

    // A file with no usable keys: said in plain words, and nothing at all is sent.
    const atListener = settingsAt(w, 'at-listener.json', await listenOn(listener));
    const unusableAt = join(w.folder, 'unusable.json');
    const unusable = {
      'no keys': { keys: [] },
      'one key': { keys: [w.executorKeys[0]] },
      'three keys': { keys: [...w.executorKeys, w.executorKeys[0]] },
      'the two keys the other way round': { keys: [w.executorKeys[1], w.executorKeys[0]] },
      'a key cut short': { keys: [{ ...w.executorKeys[0], x: 'AAAA' }, w.executorKeys[1]] },
      'a key with no public part': { keys: [{ alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP' }, w.executorKeys[1]] },
      'what "keys" prints, which is not a key file': { alpha: { with: { keys: w.executorKeys } } },
      'not an object': null,
    };
    for (const [what, value] of Object.entries(unusable)) {
      writeFileSync(unusableAt, JSON.stringify(value));
      const r = await run(['status', '--config', atListener, '--public-keys', unusableAt], secret);
      assert.equal(r.code, 2, what);
      assert.match(r.stderr, /unusable\.json holds no usable keys of the executor\. It must hold the executor's two public keys, Ed25519 and then ML-DSA-87: .* The administrator's secret was not sent\./, what);
    }
    writeFileSync(unusableAt, 'not JSON');
    assert.match((await run(['status', '--config', atListener, '--public-keys', unusableAt], secret)).stderr, /unusable\.json could not be read \(it is not JSON\)\. .* The administrator's secret was not sent\./);
    const missing = await run(['status', '--config', atListener, '--public-keys', join(w.folder, 'none.json')], secret);
    assert.equal(missing.code, 2);
    assert.match(missing.stderr, /none\.json could not be read \(ENOENT\)\. .* The administrator's secret was not sent\./);
    // Where "executor.keys" is the file that cannot be read, the command says how to do without it.
    const hint = await run(['status', '--config', settingsAt(w, 'unreadable-at-listener.json', listener.address().port, (s) => ({ ...s, executor: { keys: 'keys/none.jwk' } }))], secret);
    assert.equal(hint.code, 2);
    assert.match(hint.stderr, /none\.jwk could not be read \(ENOENT\)\. .*"keys --public-keys <file>" writes the public keys alone to a file, and --public-keys <file> names it here\. The administrator's secret was not sent\./);
    assert.deepEqual(seen, [], 'the listener was sent nothing');

    // --public-keys is for asking a running executor: a command that works on the files refuses it, and does nothing.
    for (const args of [['status', '--offline'], ['seal', '--agent', 'alpha', '--offline'], ['acknowledge', '--agent', 'alpha', '--offline']]) {
      const r = await run([...args, '--config', w.configPath, '--public-keys', publicAt]);
      assert.equal(r.code, 2, args.join(' '));
      assert.match(r.stderr, /--public-keys names the file of public keys that a running HTTP executor is checked against\. This command asks no running executor/, args.join(' '));
    }
    // The executor itself signs, and cannot run on a file of public keys: "check" and a command on the files say so in plain words.
    const checkedSettings = await run(['check', '--config', publicOnly]);
    assert.equal(checkedSettings.code, 1);
    assert.ok(JSON.parse(checkedSettings.stdout).problems.some((p) => /^executor\.keys: The key file .*executor-public\.json holds public keys only\. The executor signs with private keys/.test(p)), checkedSettings.stdout);
    const onFiles = await run(['seal', '--agent', 'alpha', '--offline', '--config', publicOnly]);
    assert.equal(onFiles.code, 2);
    assert.match(onFiles.stderr, /executor-public\.json holds public keys only\. The executor signs with private keys/);
    const keysAgain = await run(['keys', '--config', publicOnly]);
    assert.equal(keysAgain.code, 2);
    assert.match(keysAgain.stderr, /executor-public\.json holds public keys only/);
    assert.ok(!/Unsupported key usage/.test(checkedSettings.stdout + onFiles.stderr + keysAgain.stderr));
  } finally {
    listener.close();
    listener.closeAllConnections();
    await w.close();
  }
});

test('a body sent to the executor\'s own addresses is read up to 64 KiB and no further, whatever bodyLimit is', async () => {
  // bodyLimit as it comes (10 MiB): a body that never ends is cut off once it passes 64 KiB, not read on.
  const w = await adminWorld({ agents: ['alpha'] });
  try {
    const req = http.request({ host: '127.0.0.1', port: w.address.port, path: '/provared/seal', method: 'POST', agent: false, headers: { authorization: `Bearer ${w.admin}`, 'content-type': 'application/json', 'transfer-encoding': 'chunked' } });
    const answered = new Promise((done) => {
      req.on('response', (res) => {
        res.resume();
        done(res.statusCode);
      });
      req.on('error', () => done('the connection failed'));
    });
    req.write('{"agent":"alpha","filler":"');
    req.write('x'.repeat(ADMIN_BODY_LIMIT + 1024));
    // The body is not ended.
    const status = await Promise.race([answered, pause(4000).then(() => 'no answer while the body goes on')]);
    req.destroy();
    assert.equal(status, 413);
    assert.ok(!bookText(w, 'alpha').includes('"seal"'));
  } finally {
    await w.close();
  }
  // A small bodyLimit is the agents' limit, not the administrator's: a body under 64 KiB is taken.
  const small = await adminWorld({ agents: ['alpha'], config: { bodyLimit: 1024 } });
  try {
    const r = await ask(small, 'POST', '/provared/seal', { body: { agent: 'alpha', filler: 'x'.repeat(4000) } });
    assert.equal(r.status, 200, r.body);
  } finally {
    await small.close();
  }
});

test('a timer over HTTP: one agent\'s long call does not hold back the seal of another agent\'s book', async () => {
  const w = await adminWorld({ recorder: { keys: 'keys/recorder.jwk', sealEvery: 1000 }, config: { timeout: 30000 } });
  try {
    await until(async () => sealsOf(await checked(w, 'alpha')).length === 1 && sealsOf(await checked(w, 'beta')).length === 1, { timeout: 20000 });
    // alpha keeps one call with the upstream for ten seconds.
    const long = call(w, 'alpha', 'slow', { ms: 10000 });
    await until(() => w.executor.agent('alpha').calls() === 1);
    await pause(300);
    await call(w, 'beta', 'echo', {});
    // beta's new entry is sealed at its next round, while alpha's call is still out.
    await until(async () => sealsOf(await checked(w, 'beta')).length === 2, { timeout: 6500 });
    assert.equal(w.executor.agent('alpha').calls(), 1, 'alpha\'s call is still with the upstream');
    assert.deepEqual((await checked(w, 'beta')).entries.map((e) => e.kind), ['slip', 'seal', 'stub', 'seal']);
    assert.ok((await long).json.result);
  } finally {
    await w.close();
  }
});

test('four books sealed at once do not hold up another agent\'s call: one SLH-DSA signature is made at a time', async () => {
  // Node.js's thread pool has four threads unless set. Were each seal's third signature made in it at once, it would be full.
  const sealing = ['alpha', 'beta', 'gamma', 'delta'];
  const w = await adminWorld({ agents: [...sealing, 'other'], config: { timeout: 30000 } });
  try {
    for (const name of [...sealing, 'other']) await call(w, name, 'echo', {});
    const began = Date.now();
    const done = {};
    const seals = sealing.map((name) => w.executor.seal(name).then((r) => {
      done[name] = Date.now() - began;
      return r;
    }));
    await pause(150);
    const asked = Date.now();
    const answer = await call(w, 'other', 'echo', {});
    const took = Date.now() - asked;
    assert.ok(answer.json.result);
    const sealed = await Promise.all(seals);
    const all = Date.now() - began;
    assert.equal(sealed.length, 4);
    for (const name of sealing) assert.equal(sealsOf(await checked(w, name)).length, 1, name);
    // The call was answered before the seals were all done, and in a small part of the time they took.
    assert.ok(took < all / 3, `the call took ${took} ms; the four seals ${all} ms (${JSON.stringify(done)})`);
    assert.ok(Math.min(...Object.values(done)) > 150 + took, `the call took ${took} ms; the first seal was done at ${Math.min(...Object.values(done))} ms`);
  } finally {
    await w.close();
  }
});

test('a start on the same files while the executor before it is ending waits for it, and then starts', async () => {
  const w = await adminWorld({ agents: ['alpha'] });
  let second = null;
  try {
    const opening = openHttpExecutor(w.settings, { root: w.folder, log: () => {} });
    await pause(1500);
    await w.closeExecutor();
    second = await opening;
    assert.deepEqual(second.agents, ['alpha']);
  } finally {
    if (second) await second.close();
    await w.upstream.close();
  }
});

test('a start that cannot listen seals nothing', async () => {
  const taken = net.createServer();
  const port = await listenOn(taken);
  const w = await adminWorld({ agents: ['alpha'], open: false, recorder: { keys: 'keys/recorder.jwk', sealEvery: 1000 } });
  const logs = [];
  const executor = await openHttpExecutor(w.settings, { root: w.folder, log: (e) => logs.push(e) });
  try {
    await assert.rejects(executor.listen({ port }), /EADDRINUSE/);
    await pause(3500);
    assert.deepEqual(logs.filter((e) => e.event === 'sealed' || e.event === 'not-sealed'), []);
    assert.equal(sealsOf(await checked(w, 'alpha')).length, 0);
  } finally {
    await executor.close();
    taken.close();
    await w.upstream.close();
  }
});

test('a second executor on the same files is refused before it reads them, and a call in flight gets its true receipt', async () => {
  const w = await adminWorld({ config: { timeout: 20000 } });
  try {
    await call(w, 'alpha', 'echo', {});
    const long = call(w, 'alpha', 'slow', { ms: 2500, tag: 'REAL-ANSWER' });
    await until(() => w.executor.agent('alpha').calls() === 1);
    await pause(300);
    const book = bookText(w, 'alpha');
    // A second start on the same settings, and the files opened as a command with --offline opens them: of either agent.
    // A start asks again for some seconds before it is refused; asked once here.
    for (const more of [{ lockWait: 0 }, { offline: true }]) {
      const logs = [];
      const asked = Date.now();
      await assert.rejects(openHttpExecutor(w.settings, { root: w.folder, log: (e) => logs.push(e), ...more }), (e) => e.code === 'LOCKED');
      assert.ok(Date.now() - asked < 2500, `asked once, it does not wait (${JSON.stringify(more)})`);
      assert.deepEqual(logs.filter((e) => e.event !== 'warning'), [], 'it wrote no receipt for the call in flight');
    }
    const sealed = await run(['seal', '--config', w.configPath, '--agent', 'beta', '--offline']);
    assert.equal(sealed.code, 2);
    assert.match(sealed.stderr, /An executor is running on the book/);
    assert.equal(bookText(w, 'alpha'), book);
    const answer = await long;
    assert.match(JSON.stringify(answer.json.result), /REAL-ANSWER/);
    const stub = stubsOf(await checked(w, 'alpha')).at(-1);
    assert.ok(docs(stub)[RESULT_DOCUMENT], 'the receipt names what came back');
    assert.equal(docs(stub)['provared.error'], undefined);
    assert.equal(w.executor.agent('alpha').stopped(), null);
  } finally {
    await w.close();
  }
  // Closed, the executor has given the files up. A command at work on them is not a start: it writes no late receipt for
  // a call the copy shows as sent, and does not seal that agent's book while one is due.
  const b = w.agents.beta;
  const key = loadCopyKey(b.copyKey);
  const copy = openCopy(b.copy, key, w.settings.name, readCopy(b.copy, key, w.settings.name).next);
  const details = [{ name: 'provared.arguments', sha256: await argumentsFingerprint({}) }, { name: TOOL_DOCUMENT, sha256: await identifierFingerprint('slow') }, { name: CALL_DOCUMENT, sha256: await identifierFingerprint('late-call') }];
  copy.note({ kind: 'sending', call: 'late-call', when: new Date().toISOString(), slip: w.executor.agent('beta').slip.fingerprint, tool: 'slow', action: 'slow.work', with: 'executor', details });
  await pause(5);
  const logs = [];
  const book = bookText(w, 'beta');
  const again = await openHttpExecutor(w.settings, { root: w.folder, log: (e) => logs.push(e), offline: true });
  assert.ok(!logs.some((e) => e.event === 'receipt-written-late'));
  assert.equal((await again.report()).agents.beta.receiptsAtNextStart, 1);
  await assert.rejects(again.seal('beta'), /next start will give one/);
  assert.equal(bookText(w, 'beta'), book);
  await again.close();
});

test('a held agent\'s book is not sealed by the timer, and the log says so once, not at every round', async () => {
  const w = await adminWorld({ agents: ['alpha'], recorder: { keys: 'keys/recorder.jwk', sealEvery: 1000 } });
  await until(() => w.logs.some((e) => e.event === 'sealed'), { timeout: 20000 });
  await call(w, 'alpha', 'echo', {});
  await until(async () => sealsOf(await checked(w, 'alpha')).length === 2, { timeout: 20000 });
  await leaveCallUnderOldSlip(w, 'alpha');
  await openHttpWorld(w);
  try {
    await pause(4500);
    const said = w.logs.filter((e) => e.event === 'not-sealed');
    assert.equal(said.length, 1, 'once, though four rounds have passed');
    assert.match(said[0].reason, /The agent is stopped/);
    assert.equal(sealsOf(await checked(w, 'alpha')).length, 2);
    // Acknowledged, the book is sealed again at the next round.
    assert.equal((await ask(w, 'POST', '/provared/acknowledge', { body: { agent: 'alpha' } })).status, 200);
    await until(async () => sealsOf(await checked(w, 'alpha')).length === 3, { timeout: 20000 });
  } finally {
    await w.close();
  }
});

test('the secret goes on the connection the executor proved itself on, and on no other', async () => {
  const w = await adminWorld({ agents: ['alpha'], open: false });
  await w.upstream.close();
  const { loadKeyFile } = await import('../files.mjs');
  const { identify } = await import('../identity.mjs');
  const { privateKeys } = await loadKeyFile(join(w.folder, 'keys', 'executor.jwk'), 'agent');
  const seen = [];
  // A stand-in that, for this test, holds the executor's keys: it proves itself, and closes the connection it did so on.
  const standIn = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      seen.push({ url: req.url, authorization: req.headers.authorization ?? null });
      if (req.url !== '/provared/hello') {
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end('{"agents":{}}');
      }
      const signatures = await identify(privateKeys, JSON.parse(Buffer.concat(chunks).toString('utf8')).challenge, req.socket.localAddress, req.socket.localPort);
      res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
      res.end(JSON.stringify({ signatures }));
    });
  });
  try {
    const r = await run(['status', '--config', settingsAt(w, 'at-stand-in.json', await listenOn(standIn))], { env: { [ENV]: w.admin } });
    assert.equal(r.code, 2, r.stdout + r.stderr);
    assert.match(r.stderr, /was closed before the administrator's secret could be sent on it\. The secret was not sent\./);
    assert.deepEqual(seen, [{ url: '/provared/hello', authorization: null }]);
  } finally {
    standIn.close();
    standIn.closeAllConnections();
  }
});
