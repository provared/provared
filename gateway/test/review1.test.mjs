// The faults the first independent review of the gateway found, each as a
// test that fails on the code it reviewed.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook, identifierFingerprint, thumbprint } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { world, json, call, upstream, tempFolder, signSlip, SECRET, OTHER_SECRET, ADMIN_SECRET, TOKEN } = await import('./world.mjs');
const { openGateway, checkConfig, secretHash, NOT_DELIVERED, OUTCOME_UNKNOWN } = await import('../gateway.mjs');
const { makeKeyFile } = await import('../files.mjs');

const JSONTYPE = { 'content-type': 'application/json' };
const stubsOf = async (w, name = 'patching') => (await w.gateway.writers().get(name).check()).entries.filter((e) => e.kind === 'stub');
const docs = (entry) => Object.fromEntries((entry.content.details ?? []).map((d) => [d.name, d.sha256]));

test('S1: a body whose names differ only in capitals, or in letters some readers fold together, gives no amount, and the call is not sent', async () => {
  const w = await world({ slip: { limits: [{ action: 'patch.apply', max: 5, unit: 'hosts' }] } });
  try {
    for (const body of [
      '{"hosts":[1],"HOSTS":[1,2,3,4,5,6,7,8,9,10]}',
      '{"hosts":[1],"hoſts":[1,2,3,4,5,6,7,8,9,10]}',
      '{"hosts":[1],"meta":{"kind":1,"Kind":2}}',
    ]) {
      const r = await w.call('POST', '/patch/v1/waves', { headers: JSONTYPE, body });
      assert.equal(r.status, 403, body);
      assert.equal(r.json.code, 'amount-not-found', body);
      assert.match(r.json.message, /differ only in capitals/);
    }
    assert.equal(w.patch.calls.length, 0);
  } finally {
    await w.close();
  }
});

test('M1: headers and parameters that change the method or the address are removed, with every address header', async () => {
  const w = await world();
  try {
    const sent = {
      'X-HTTP-Method-Override': 'DELETE',
      'X-HTTP-Method': 'DELETE',
      'X-Method-Override': 'DELETE',
      'X-Original-URL': '/api/now/table/sys_user/1',
      'X-Rewrite-URL': '/api/now/table/sys_user/1',
      'X-Forwarded-Prefix': '/admin',
      'X-Forwarded-Port': '1',
      'X-Forwarded-Server': 'x',
      'X-Forwarded-Anything': 'x',
      Forwarded: 'for=10.0.0.1',
      'X-Real-IP': '10.0.0.1',
      Via: '1.1 x',
      'True-Client-IP': '10.0.0.1',
      'X-Client-IP': '10.0.0.1',
      'X-Cluster-Client-IP': '10.0.0.1',
      'CF-Connecting-IP': '10.0.0.1',
      'X-Originating-IP': '10.0.0.1',
      Expect: '100-continue',
    };
    const r = await w.call('GET', '/tickets/api/now/table/incident?_method=DELETE&x=1', { headers: sent });
    assert.equal(r.status, 200);
    const got = w.tickets.calls[0];
    for (const h of Object.keys(sent)) assert.equal(got.headers[h.toLowerCase()], undefined, h);
    assert.equal(got.url, '/api/now/table/incident?x=1');
    const removed = w.logs.find((e) => e.event === 'credential-removed');
    assert.ok(removed.headers.includes('x-http-method-override') && removed.parameters.includes('_method'));
  } finally {
    await w.close();
  }
});

test('M2: a ";" in a path is refused, unless the upstream allows it; then the rules match each segment without what follows its ";"', async () => {
  const w = await world({
    rules: [
      { upstream: 'tickets', method: 'DELETE', path: '/admin/:id', action: 'provared.data.delete' },
      { upstream: 'tickets', method: 'DELETE', path: '/public/:rest*', action: 'ticket.update' },
      { upstream: 'patch', method: 'DELETE', path: '/admin/:id', action: 'provared.data.delete' },
      { upstream: 'patch', method: 'DELETE', path: '/public/:rest*', action: 'ticket.update' },
    ],
    slip: { actions: ['provared.data.delete', 'ticket.update'] },
    tickets: { semicolons: true },
  });
  try {
    for (const p of ['/patch/public/..;/admin/1', '/patch/public/a;x', '/patch/public/a%3Bx', '/patch/public/%2e%2e;/admin/1']) {
      const r = await w.call('DELETE', p);
      assert.equal(r.status, 400, p);
      assert.equal(r.json.code, 'address-refused', p);
    }
    assert.equal(w.patch.calls.length, 0);
    for (const p of ['/tickets/public/..;/admin/1', '/tickets/public/.;x/admin/1', '/tickets/public/;x/a']) assert.equal((await w.call('DELETE', p)).status, 400, p);
    assert.equal((await w.call('DELETE', '/tickets/admin;jsessionid=1/7')).status, 200);
    assert.equal((await w.call('DELETE', '/tickets/public/a;v=1')).status, 200);
    assert.deepEqual((await stubsOf(w)).map((s) => s.content.action), ['provared.data.delete', 'ticket.update']);
    assert.deepEqual(w.tickets.calls.map((c) => c.url), ['/admin;jsessionid=1/7', '/public/a;v=1']);
  } finally {
    await w.close();
  }
});

test('M3: an agent may have only so many calls waiting, holding only so many bytes of bodies', async () => {
  const release = [];
  const w = await world({ patchAnswer: (c, res) => release.push(() => json(res, 200, {})), config: { waitingCalls: 2, waitingBytes: 150 } });
  // Every wait is bounded, so that a gateway that does not answer fails the test rather than holding it.
  const soon = (p, what) => Promise.race([p, new Promise((_, no) => setTimeout(() => no(new Error(`${what}: no answer in 20 seconds`)), 20000).unref())]);
  const until = async (ready, what) => {
    const deadline = Date.now() + 20000;
    while (!(await ready())) {
      if (Date.now() > deadline) throw new Error(`${what}: not in 20 seconds`);
      await new Promise((d) => setTimeout(d, 10));
    }
  };
  try {
    const first = w.call('POST', '/patch/v1/hosts/a/reboot', { headers: JSONTYPE, body: { pad: 'x'.repeat(40) } });
    const second = w.call('POST', '/patch/v1/hosts/b/reboot', { headers: JSONTYPE, body: { pad: 'x'.repeat(40) } });
    const waiting = async () => (await soon(call(w.port, 'GET', '/provared/status', { secret: ADMIN_SECRET }), 'the status')).json.agents.patching.waiting;
    await until(async () => (await waiting()) >= 2 && release.length >= 1, 'two calls waiting');
    const asked = Date.now();
    const busy = (await soon(call(w.port, 'GET', '/provared/status', { secret: ADMIN_SECRET }), 'the status')).json.agents.patching;
    assert.ok(Date.now() - asked < 1000, 'at once, without waiting for the call');
    assert.equal(busy.checkedNow, false, 'the status answers while a call is with the upstream, from the last check');
    const third = await soon(w.call('POST', '/patch/v1/hosts/c/reboot', { headers: JSONTYPE, body: {} }), 'the third call');
    assert.equal(third.status, 503);
    assert.equal(third.json.code, 'too-many-waiting');
    for (const go of release.splice(0)) go();
    await soon(first, 'the first call');
    await until(() => release.length >= 1, 'a call at the upstream');
    for (const go of release.splice(0)) go();
    assert.equal((await soon(second, 'the second call')).status, 200);
    // Bytes: one call holds 100 bytes while it waits; a second of 100 would pass 150.
    const big = w.call('POST', '/patch/v1/hosts/d/reboot', { headers: JSONTYPE, body: { pad: 'x'.repeat(90) } });
    await until(() => release.length >= 1, 'a call at the upstream');
    const over = await soon(w.call('POST', '/patch/v1/hosts/e/reboot', { headers: JSONTYPE, body: { pad: 'x'.repeat(90) } }), 'the call over the bytes');
    assert.equal(over.status, 503);
    assert.equal(over.json.code, 'too-much-waiting');
    // Sent in pieces, with no length given: counted as it is read.
    const pieces = await soon(w.call('POST', '/patch/v1/hosts/f/reboot', { headers: { ...JSONTYPE, 'transfer-encoding': 'chunked' }, body: JSON.stringify({ pad: 'x'.repeat(90) }) }), 'the call sent in pieces');
    assert.equal(pieces.status, 503);
    for (const go of release.splice(0)) go();
    assert.equal((await soon(big, 'the big call')).status, 200);
    // Once answered, the bytes are free again.
    const later = w.call('POST', '/patch/v1/hosts/g/reboot', { headers: JSONTYPE, body: { pad: 'x'.repeat(90) } });
    await until(() => release.length >= 1, 'a call at the upstream');
    for (const go of release.splice(0)) go();
    assert.equal((await soon(later, 'the later call')).status, 200);
    assert.equal(await waiting(), 0);
  } finally {
    for (const go of release.splice(0)) go();
    await Promise.race([w.close(), new Promise((d) => setTimeout(d, 3000).unref())]);
    w.patch.server.closeAllConnections();
  }
});

function freePort() {
  return new Promise((done) => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => done(port));
    });
  });
}

test('M3: a call sent when the gateway stops has no receipt; the next start finds it, stops that agent, and the administrator acknowledges it', { timeout: 120000 }, async () => {
  const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));
  const folder = tempFolder();
  const passkey = await developmentPasskey();
  const keys = await makeKeyFile(join(folder, 'agent.jwk'), 'agent');
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(await signSlip({ passkey, agentKeys: keys })));
  let hold = true;
  const up = await upstream((c, res) => {
    if (!hold) json(res, 200, { ok: true });
  });
  const port = await freePort();
  const config = {
    listen: { host: '127.0.0.1', port },
    admin: { secretHash: await secretHash(ADMIN_SECRET) },
    upstreams: { tickets: { base: up.base, service: 'tickets', timeout: 60000 } },
    rules: [{ upstream: 'tickets', method: 'DELETE', path: '/x/:id', action: 'provared.data.delete' }],
    agents: { patching: { secretHash: await secretHash(SECRET), slip: 'slip.json', book: 'book.jsonl', keys: 'agent.jwk', issuerKeys: [await thumbprint(passkey.key)] } },
  };
  writeFileSync(join(folder, 'gateway.json'), JSON.stringify(config));
  const start = () =>
    new Promise((done, failed) => {
      const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', BIN, 'start', '--config', join(folder, 'gateway.json')], { env: process.env });
      let err = '';
      child.stderr.on('data', (d) => {
        err += d;
        if (err.includes('listening')) done({ child, log: () => err });
      });
      child.on('exit', () => failed(new Error(err)));
    });
  let g = await start();
  call(port, 'DELETE', '/tickets/x/1', { secret: SECRET }).catch(() => null);
  while (up.calls.length < 1) await new Promise((d) => setTimeout(d, 20));
  g.child.removeAllListeners('exit');
  g.child.kill('SIGKILL');
  await new Promise((d) => g.child.once('exit', d));
  const journal = readFileSync(join(folder, 'book.jsonl.journal'), 'utf8');
  assert.match(journal, /"sending"/);
  hold = false;
  g = await start();
  try {
    assert.match(g.log(), /receipt-missing/);
    const refused = await call(port, 'DELETE', '/tickets/x/2', { secret: SECRET });
    assert.equal(refused.status, 503);
    assert.match(refused.json.message, /no receipt in the book/);
    const status = await call(port, 'GET', '/provared/status', { secret: ADMIN_SECRET });
    assert.equal(status.json.agents.patching.receiptsMissing.length, 1);
    assert.equal(status.json.agents.patching.receiptsMissing[0].action, 'provared.data.delete');
    const ack = await call(port, 'POST', '/provared/acknowledge', { secret: ADMIN_SECRET, headers: JSONTYPE, body: { agent: 'patching' } });
    assert.equal(ack.status, 200, ack.text);
    assert.equal(ack.json.written.length, 1);
    assert.equal((await call(port, 'DELETE', '/tickets/x/3', { secret: SECRET })).status, 200);
    const again = await call(port, 'POST', '/provared/acknowledge', { secret: ADMIN_SECRET, headers: JSONTYPE, body: { agent: 'patching' } });
    assert.equal(again.status, 409);
  } finally {
    g.child.removeAllListeners('exit');
    g.child.kill();
    await new Promise((d) => g.child.once('exit', d));
  }
  const result = await checkBook(readFileSync(join(folder, 'book.jsonl'), 'utf8'), { issuerKeys: config.agents.patching.issuerKeys });
  assert.equal(result.summary.intact, true);
  const stubs = result.entries.filter((e) => e.kind === 'stub');
  assert.equal(stubs.length, 2, 'the acknowledged call and the next one; the call refused while stopped has none');
  assert.equal(docs(stubs[0])['provared.error'], await identifierFingerprint(OUTCOME_UNKNOWN));
  assert.ok(docs(stubs[0])['provared.http-request']);
  // A clean start empties the journal.
  g = await start();
  g.child.removeAllListeners('exit');
  g.child.kill();
  await new Promise((d) => g.child.once('exit', d));
  assert.equal(readFileSync(join(folder, 'book.jsonl.journal'), 'utf8'), '');
  await up.close();
});

test('L1: more credential headers are removed, and header names with "_" are refused unless the upstream allows them', async () => {
  const w = await world({ patch: { underscoreHeaders: true } });
  try {
    const r = await w.call('GET', '/tickets/api/now/table/x', { headers: { 'X-Goog-Api-Key': 'a', 'X-Vault-Token': 'a', 'X-Amz-Security-Token': 'a', 'X-Auth-Key': 'a' } });
    assert.equal(r.status, 200);
    for (const h of ['x-goog-api-key', 'x-vault-token', 'x-amz-security-token', 'x-auth-key']) assert.equal(w.tickets.calls[0].headers[h], undefined, h);
    const under = await w.call('GET', '/tickets/api/now/table/x', { headers: { X_Api_Key: 'own' } });
    assert.equal(under.status, 400);
    assert.equal(under.json.code, 'header-refused');
    assert.equal(w.tickets.calls.length, 1);
    assert.equal((await w.call('POST', '/patch/v1/hosts/a/reboot', { headers: { ...JSONTYPE, X_Trace: '1' }, body: {} })).status, 200, 'allowed where the upstream says so');
  } finally {
    await w.close();
  }
});

test('L2: a Connection header that names a header is refused; headers the upstream\'s Connection names are not handed on', async () => {
  const w = await world({
    ticketsAnswer: (c, res) => {
      res.writeHead(200, { 'content-type': 'application/json', connection: 'x-hop', 'x-hop': 'private', 'x-kept': 'yes', 'content-length': 2 });
      res.end('{}');
    },
  });
  try {
    const r = await w.call('POST', '/patch/v1/waves', { headers: { ...JSONTYPE, connection: 'content-type' }, body: { hosts: [1] } });
    assert.equal(r.status, 400);
    assert.equal(r.json.code, 'header-refused');
    assert.equal(w.patch.calls.length, 0);
    const a = await w.call('GET', '/tickets/api/now/table/x');
    assert.equal(a.status, 200);
    assert.equal(a.headers['x-hop'], undefined);
    assert.equal(a.headers['x-kept'], 'yes');
  } finally {
    await w.close();
  }
});

test('L5: a credential that cannot be sent as a header is refused at start', async () => {
  for (const value of ['token-with-a-euro-€-sign', 'tab\u0001x', 'café']) {
    const env = `PROVARED_GW_L5_${Math.random().toString(36).slice(2)}`;
    process.env[env] = value;
    const w = await world({ tickets: { credential: { header: 'Authorization', env, prefix: 'Bearer ' } } }).catch((e) => e);
    if (!(w instanceof Error)) await w.close();
    assert.ok(w instanceof Error && /cannot be sent in a header/.test(w.message), String(w?.message ?? 'started'));
  }
  const env = `PROVARED_GW_L5_${Math.random().toString(36).slice(2)}`;
  process.env[env] = 'x';
  const host = await world({ tickets: { credential: { header: 'Host', env } } }).catch((e) => e);
  if (!(host instanceof Error)) await host.close();
  assert.ok(host instanceof Error && /sets itself/.test(host.message));
});

test('L5: where no connection to the upstream was made, the stub says so by a label of its own', async () => {
  const w = await world({ ticketsAnswer: (c, res) => res.socket.destroy() });
  await w.patch.close();
  try {
    const refusedConnection = await w.call('POST', '/patch/v1/hosts/a/reboot', { headers: JSONTYPE, body: {} });
    assert.equal(refusedConnection.status, 502);
    const reset = await w.call('GET', '/tickets/api/now/table/x');
    assert.equal(reset.status, 502);
    const [first, second] = await stubsOf(w);
    assert.equal(docs(first)[NOT_DELIVERED], await identifierFingerprint(refusedConnection.json.error));
    assert.equal(docs(second)[NOT_DELIVERED], undefined, 'a connection was made, so the call may have reached the upstream');
  } finally {
    await w.gateway.close();
    await w.tickets.close();
  }
});

test('L6: two agents with one secret, or one book file, are refused at start and by check', async () => {
  const w = await world();
  await w.close();
  const second = (more) => ({ ...w.config, agents: { ...w.config.agents, other: { ...w.config.agents.patching, ...more } } });
  for (const [config, words] of [
    [second({ book: join(w.folder, 'other.jsonl') }), /the same secret/],
    [second({ secretHash: await secretHash(OTHER_SECRET) }), /share a file/],
    [second({ secretHash: await secretHash(OTHER_SECRET), book: join(w.folder, 'BOOKS', 'PATCHING.jsonl') }), process.platform === 'win32' ? /share a file/ : null],
  ]) {
    if (!words) continue;
    await assert.rejects(openGateway(config, { root: w.folder, log: () => {} }), words);
    const checked = await checkConfig(config, { root: w.folder });
    assert.ok(checked.problems.some((p) => words.test(p)), JSON.stringify(checked.problems));
  }
});

test('from the review\'s weakenings: a custom credential header is sent once, whatever its case; an upstream\'s own stripHeaders; HEAD keeps its Content-Length; one event identifier only', async () => {
  const w = await world({
    tickets: { credential: { header: 'X-Service-Token', env: (process.env.PROVARED_GW_CUSTOM = TOKEN, 'PROVARED_GW_CUSTOM') }, stripHeaders: ['X-Team-Secret'] },
    ticketsAnswer: (c, res) => {
      if (c.method === 'HEAD') {
        res.writeHead(200, { 'content-type': 'application/json', 'content-length': 1234 });
        return res.end();
      }
      res.writeHead(200, [['content-type', 'application/json'], ['x-request-id', 'one'], ['x-request-id', 'two'], ['content-length', '2']].flat());
      res.end('{}');
    },
    rules: [
      { upstream: 'tickets', method: 'GET', path: '/api/now/table/:table', action: 'provared.data.read' },
      { upstream: 'tickets', method: 'HEAD', path: '/api/now/table/:table', action: 'provared.data.read' },
    ],
  });
  try {
    const r = await w.call('GET', '/tickets/api/now/table/x', { headers: { 'x-service-token': 'agent-own', 'X-Team-Secret': 's' } });
    assert.equal(r.status, 200);
    const raw = w.tickets.calls[0].rawHeaders;
    const names = raw.filter((_, i) => i % 2 === 0).map((h) => h.toLowerCase());
    assert.equal(names.filter((h) => h === 'x-service-token').length, 1);
    assert.equal(w.tickets.calls[0].headers['x-service-token'], TOKEN);
    assert.equal(w.tickets.calls[0].headers['x-team-secret'], undefined);
    const [stub] = await stubsOf(w);
    assert.equal(docs(stub)['provared.event-id'], undefined, 'two identifiers: neither is named');
    const head = await w.call('HEAD', '/tickets/api/now/table/x');
    assert.equal(head.status, 200);
    assert.equal(head.headers['content-length'], '1234');
  } finally {
    await w.close();
  }
});
