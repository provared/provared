// Sealing, acknowledging and the status over HTTP: the executor's own
// addresses, for the administrator alone, and the commands that ask a
// running executor or work on the files of a stopped one.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook, identifierFingerprint, argumentsFingerprint, keySetFingerprint } = await import('provared');
const { httpWorld, openHttpWorld, call, rawRequest } = await import('./http-world.mjs');
const { signSlip, until, pause } = await import('./world.mjs');
const { CALL_DOCUMENT, TOOL_DOCUMENT, WRITTEN_LATE_DOCUMENT, WRITTEN_ON_ACKNOWLEDGEMENT } = await import('../executor.mjs');
const { ADMIN_BODY_LIMIT, newSecret, openHttpExecutor, readHttpSettings, secretHash, httpStatusFromFiles } = await import('../http.mjs');
const { readCopy, loadCopyKey, openCopy } = await import('../copy.mjs');
const { makeKeyFile } = await import('../files.mjs');

const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));
const ENV = 'PROVARED_MCP_EXECUTOR_ADMIN_SECRET';

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
    assert.equal(docs(stub)[WRITTEN_LATE_DOCUMENT], await identifierFingerprint(WRITTEN_ON_ACKNOWLEDGEMENT));
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
    await pause(2500);
    assert.equal(sealsOf(await checked(w, 'alpha')).length, 2, 'no seal over a seal');
    assert.equal(sealsOf(await checked(w, 'beta')).length, 1, 'nothing new in the other book');
    assert.equal((await checked(w, 'alpha')).summary.problemFound, false);
    assert.equal((await checked(w, 'alpha')).entries.at(-1).content.by.name, w.settings.name, 'named as the executor unless the settings say otherwise');
    assert.equal((await ask(w, 'GET', '/provared/status')).json.recorder.sealEvery, 1000);
  } finally {
    await w.close();
  }
  const text = bookText(w, 'alpha');
  await pause(1500);
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
    assert.match(nothing.stderr, /nothing was acknowledged: This agent has no call without a receipt/);
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
