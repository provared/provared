// The gateway: a call is forwarded once, with the upstream's credential and
// without the agent's, and its receipt is written; a call outside the slip
// is refused, not forwarded, and written as a denial; a call that was sent
// always gets its receipt, whatever the upstream does.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const { checkBook, httpRequestFingerprint, httpResponseFingerprint, identifierFingerprint, countersign, generateKeySet } = await import('provared');
const { world, json, call, OTHER_SECRET, ADMIN_SECRET, TOKEN, SECRET, signSlip } = await import('./world.mjs');
const { secretHash, UNLISTED_ACTION } = await import('../gateway.mjs');

const stubsOf = async (w) => (await w.gateway.writers().get('patching').check()).entries.filter((e) => e.kind === 'stub');
const denialsOf = async (w) => (await w.gateway.writers().get('patching').check()).entries.filter((e) => e.kind === 'denial');
const docs = (entry) => Object.fromEntries((entry.content.details ?? []).map((d) => [d.name, d.sha256]));

async function sameAsFile(w) {
  const text = readFileSync(w.bookPath, 'utf8');
  assert.equal(text, w.gateway.writers().get('patching').book(), 'the book file holds exactly the writer\'s book');
  assert.deepEqual(await w.gateway.writers().get('patching').check(), await checkBook(text, w.gateway.checkOptions('patching')));
}

test('an allowed call is forwarded once, with the credential added and the agent\'s own removed, and its stub binds the request and the answer', async () => {
  const w = await world({ ticketsAnswer: (c, res) => json(res, 200, { result: [1, 2] }, { 'x-request-id': 'evt-42', 'set-cookie': 'session=abc' }) });
  try {
    const r = await w.call('GET', '/tickets/api/now/table/incident?sysparm_limit=1&access_token=leak', {
      headers: { cookie: 'a=b', 'X-API-Key': 'agent-key', 'Proxy-Authorization': 'Basic xyz', 'x-forwarded-for': '10.0.0.1', traceparent: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' },
    });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json, { result: [1, 2] });
    assert.equal(r.headers['set-cookie'], undefined, 'the upstream\'s cookie is not handed to the agent');
    assert.match(r.headers['provared-stub'], /^[A-Za-z0-9_-]{43}$/);
    assert.equal(w.tickets.calls.length, 1, 'forwarded once');
    const sent = w.tickets.calls[0];
    assert.equal(sent.url, '/api/now/table/incident?sysparm_limit=1', 'the credential in the address is removed');
    assert.equal(sent.headers.authorization, `Bearer ${TOKEN}`, 'the upstream\'s credential is added');
    for (const h of ['cookie', 'x-api-key', 'proxy-authorization', 'x-forwarded-for']) assert.equal(sent.headers[h], undefined, `${h} is removed`);
    assert.ok(!sent.rawHeaders.join('\n').includes(SECRET), 'the agent\'s secret is never forwarded');
    assert.equal(sent.headers.traceparent, '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01');
    const [stub] = await stubsOf(w);
    assert.equal(stub.content.action, 'provared.data.read');
    assert.equal(stub.content.with, 'tickets');
    assert.equal(stub.fingerprint, r.headers['provared-stub']);
    const d = docs(stub);
    assert.equal(d['provared.http-request'], await httpRequestFingerprint({ method: 'GET', url: `${w.tickets.base}/api/now/table/incident?sysparm_limit=1` }));
    assert.equal(d['provared.http-response'], await httpResponseFingerprint({ status: 200, body: Buffer.from(JSON.stringify({ result: [1, 2] })) }));
    assert.equal(d['provared.event-id'], await identifierFingerprint('evt-42'));
    assert.equal(d['provared.trace-id'], await identifierFingerprint('0af7651916cd43dd8448eb211c80319c'));
    const removed = w.logs.find((e) => e.event === 'credential-removed');
    assert.deepEqual(removed.parameters, ['access_token']);
    assert.ok(removed.headers.includes('cookie') && removed.headers.includes('x-api-key'));
    assert.ok(!JSON.stringify(w.logs).includes('leak') && !JSON.stringify(w.logs).includes('agent-key'), 'no credential value is logged');
    await sameAsFile(w);
  } finally {
    await w.close();
  }
});

test('the agent\'s credentials are removed in any case, given many times, and the one sign-in header is never forwarded', async () => {
  const w = await world();
  try {
    const r = await w.call('GET', '/tickets/api/now/table/x', {
      rawHeaders: ['Authorization', `Bearer ${SECRET}`, 'COOKIE', 'a=1', 'cookie', 'b=2', 'X-Api-KEY', 'k1', 'x-api-key', 'k2', 'Private-Token', 'p', 'X-Auth-Token', 't', 'Api-Key', 'z'],
    });
    assert.equal(r.status, 200, r.text);
    const raw = w.tickets.calls[0].rawHeaders.map((h) => h.toLowerCase());
    for (const h of ['cookie', 'x-api-key', 'private-token', 'x-auth-token', 'api-key']) assert.ok(!raw.includes(h), h);
    assert.equal(raw.filter((h) => h === 'authorization').length, 1, 'only the upstream\'s credential');
    // Two sign-in headers: refused, as the gateway cannot tell which counts.
    const two = await call(w.port, 'GET', '/tickets/api/now/table/x', { rawHeaders: ['Authorization', `Bearer ${SECRET}`, 'Authorization', `Bearer ${SECRET}`] });
    assert.equal(two.status, 401);
    // A wrong secret, no secret, another scheme.
    assert.equal((await call(w.port, 'GET', '/tickets/api/now/table/x', { secret: 'wrong-secret-0123456789abcdefghijklmnop' })).status, 401);
    assert.equal((await call(w.port, 'GET', '/tickets/api/now/table/x')).status, 401);
    assert.equal((await call(w.port, 'GET', '/tickets/api/now/table/x', { headers: { authorization: `Basic ${SECRET}` } })).status, 401);
    // The administrator's secret is not an agent's.
    assert.equal((await call(w.port, 'GET', '/tickets/api/now/table/x', { secret: ADMIN_SECRET })).status, 401);
    assert.equal(w.tickets.calls.length, 1);
  } finally {
    await w.close();
  }
});

test('a credential read from a file loses its line ending, and goes into the header the upstream names', async () => {
  const w = await world();
  try {
    const r = await w.call('POST', '/patch/v1/hosts/h1/reboot', { headers: { 'content-type': 'application/json' }, body: {} });
    assert.equal(r.status, 200);
    const sent = w.patch.calls[0];
    assert.equal(sent.url, '/svc/v1/hosts/h1/reboot', 'the upstream\'s own path is kept in front');
    assert.equal(sent.headers['x-api-key'], `${TOKEN}-patch`);
    assert.equal(sent.headers.authorization, undefined);
    assert.match(sent.headers['x-gateway-call'], /^[A-Za-z0-9_-]{22}$/, 'the gateway sends an identifier of its own');
    const [stub] = await stubsOf(w);
    assert.deepEqual(stub.content.amount, { unit: 'hosts', value: 1 });
    assert.equal(docs(stub)['provared.request-id'], await identifierFingerprint(sent.headers['x-gateway-call']));
    assert.equal(docs(stub)['provared.http-request'], await httpRequestFingerprint({ method: 'POST', url: `${w.patch.base}/svc/v1/hosts/h1/reboot`, body: Buffer.from('{}') }));
  } finally {
    await w.close();
  }
});

test('refused: over a limit, a forbidden kind, after the slip ends, and a call no rule names. None is forwarded; each is written as a denial', async () => {
  const w = await world({ slip: { actions: ['provared.data.read', 'host.reboot'], limits: [{ action: 'host.reboot', count: 1 }], never: ['destroys'] } });
  try {
    assert.equal((await w.call('POST', '/patch/v1/hosts/a/reboot', { headers: { 'content-type': 'application/json' }, body: {} })).status, 200);
    const over = await w.call('POST', '/patch/v1/hosts/b/reboot', { headers: { 'content-type': 'application/json' }, body: {} });
    assert.equal(over.status, 403);
    assert.equal(over.json.code, 'not-allowed');
    assert.ok(over.json.breaches.some((b) => b.code === 'over-count-limit'), 'the checker\'s own words');
    assert.equal(over.json.denial.written, true);
    const forbidden = await w.call('DELETE', '/tickets/api/now/table/incident/1');
    assert.equal(forbidden.status, 403);
    assert.ok(forbidden.json.breaches.some((b) => b.code === 'prohibited'), JSON.stringify(forbidden.json));
    const unlisted = await w.call('PUT', '/tickets/api/now/table/incident/1', { headers: { 'content-type': 'application/json' }, body: { a: 1 } });
    assert.equal(unlisted.status, 403);
    assert.equal(unlisted.json.code, 'unlisted');
    assert.equal(unlisted.json.denial.written, true);
    const nowhere = await w.call('GET', '/elsewhere/x');
    assert.equal(nowhere.status, 403);
    assert.equal(w.patch.calls.length, 1);
    assert.equal(w.tickets.calls.length, 0);
    const denials = await denialsOf(w);
    assert.deepEqual(
      denials.map((d) => [d.content.action, d.content.source, d.content.codes ?? null]),
      [
        ['host.reboot', 'check', ['over-count-limit']],
        ['provared.data.delete', 'check', forbidden.json.breaches.map((b) => b.code)],
        [UNLISTED_ACTION, 'rule', null],
        [UNLISTED_ACTION, 'rule', null],
      ],
    );
    assert.ok(docs(denials[0])['provared.http-request'], 'a denial names the request as it would have been sent');
    assert.equal(docs(denials[0])['provared.request-id'], undefined, "and not the gateway's own identifier, which was never sent");
    assert.equal(docs(denials[2])['provared.http-request'], await httpRequestFingerprint({ method: 'PUT', url: `${w.tickets.base}/api/now/table/incident/1`, body: Buffer.from('{"a":1}') }));
    assert.equal(denials[3].content.with, undefined);
    await sameAsFile(w);
  } finally {
    await w.close();
  }
  // After the slip ends.
  const ended = await world({ slip: { from: Date.now() - 7200000, until: Date.now() + 1000 } });
  try {
    await new Promise((d) => setTimeout(d, 2100));
    const r = await ended.call('GET', '/tickets/api/now/table/x');
    assert.equal(r.status, 403);
    assert.ok(r.json.breaches.some((b) => b.code === 'outside-valid-time'), JSON.stringify(r.json));
    assert.equal(ended.tickets.calls.length, 0);
    assert.equal((await denialsOf(ended)).length, 1);
  } finally {
    await ended.close();
  }
});

test('"unlisted": "forward" forwards a call no rule names, with no receipt, and logs it', async () => {
  const w = await world({ unlisted: 'forward' });
  try {
    const r = await w.call('PUT', '/tickets/api/x');
    assert.equal(r.status, 200);
    assert.equal(r.headers['provared-stub'], undefined);
    assert.equal(w.tickets.calls.length, 1);
    assert.equal(w.tickets.calls[0].headers.authorization, `Bearer ${TOKEN}`);
    assert.equal((await stubsOf(w)).length, 0);
    assert.ok(w.logs.some((e) => e.event === 'forwarded-unlisted' && e.path === '/api/x'));
  } finally {
    await w.close();
  }
});

test('a call once sent always gets its stub: an error status, a connection closed half way, no answer, a stream, an answer too large', async () => {
  let mode = '500';
  const w = await world({
    tickets: { timeout: 400 },
    ticketsAnswer: (c, res) => {
      if (mode === '500') return json(res, 500, { error: 'broken' });
      if (mode === 'half') {
        res.writeHead(200, { 'content-type': 'application/json', 'content-length': 100 });
        res.write('{"partial":');
        return setTimeout(() => res.socket.destroy(), 20);
      }
      if (mode === 'reset') return res.socket.destroy();
      if (mode === 'stream') {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        return res.write('data: 1\n\n');
      }
      if (mode === 'large') {
        res.writeHead(200, { 'content-type': 'application/octet-stream' });
        return res.end(Buffer.alloc(3000));
      }
      // "none": never answers.
    },
    bodyLimit: 2048,
  });
  try {
    const expect = async (m, status, words) => {
      mode = m;
      // The gateway must answer of itself, in its own time: the test does not wait for ever.
      const late = new Promise((_, no) => setTimeout(() => no(new Error(`${m}: no answer from the gateway in 10 seconds`)), 10000).unref());
      const r = await Promise.race([w.call('GET', '/tickets/api/now/table/x'), late]);
      assert.equal(r.status, status, m);
      const stubs = await stubsOf(w);
      const stub = stubs.at(-1);
      assert.equal(stubs.length, w.tickets.calls.length, `${m}: one stub for each call sent`);
      assert.equal(r.headers['provared-stub'], stub.fingerprint, m);
      if (words) {
        assert.match(r.json.error, words, m);
        assert.equal(docs(stub)['provared.error'], await identifierFingerprint(r.json.error), `${m}: the error the agent was given is named`);
        assert.equal(docs(stub)['provared.http-response'], undefined);
      }
      return { r, stub };
    };
    const { stub } = await expect('500', 500);
    assert.equal(docs(stub)['provared.http-response'], await httpResponseFingerprint({ status: 500, body: Buffer.from('{"error":"broken"}') }));
    await expect('half', 502, /closed the connection before its answer was complete/);
    await expect('reset', 502, /failed before a whole answer came|closed the connection/);
    await expect('none', 504, /no whole answer within 400 milliseconds/);
    await expect('stream', 502, /stream of events/);
    await expect('large', 502, /larger than 2048 bytes/);
    await sameAsFile(w);
  } finally {
    // Bounded, so that a gateway still waiting on the upstream cannot hold the test run open.
    await Promise.race([w.close(), new Promise((d) => setTimeout(d, 3000).unref())]);
    w.tickets.server.closeAllConnections();
  }
});

test('the rule is matched on the query without its credentials, through the gateway', async () => {
  const w = await world({
    rules: [
      { upstream: 'tickets', method: 'DELETE', path: '/api/files/:id', search: 'mode=purge', action: 'provared.data.delete' },
      { upstream: 'tickets', method: 'DELETE', path: '/api/files/:id', action: 'ticket.update' },
    ],
    slip: { actions: ['provared.data.delete', 'ticket.update'] },
  });
  try {
    assert.equal((await w.call('DELETE', '/tickets/api/files/f1?token=x&mode=purge')).status, 200);
    assert.equal(w.tickets.calls[0].url, '/api/files/f1?mode=purge');
    assert.equal((await stubsOf(w))[0].content.action, 'provared.data.delete');
  } finally {
    await w.close();
  }
});

test('the book file is never appended to once someone else has changed it', async () => {
  const { bookFile } = await import('../files.mjs');
  const { tempFolder } = await import('./world.mjs');
  const { appendFileSync, writeFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const path = join(tempFolder(), 'book.jsonl');
  writeFileSync(path, 'a\n');
  const file = bookFile(path, 'a\n');
  file.save('a\nb\n');
  assert.equal(readFileSync(path, 'utf8'), 'a\nb\n');
  assert.equal(file.intact(), true);
  appendFileSync(path, 'x\n');
  assert.equal(file.intact(), false);
  assert.throws(() => file.save('a\nb\nc\n'), /not as the gateway left it/);
  assert.equal(readFileSync(path, 'utf8'), 'a\nb\nx\n');
  // The same size, other bytes at the end.
  const other = join(tempFolder(), 'book.jsonl');
  writeFileSync(other, 'a\nb\n');
  const f2 = bookFile(other, 'a\nb\n');
  writeFileSync(other, 'a\nc\n');
  assert.throws(() => f2.save('a\nb\nd\n'), /not as the gateway left it/);
  assert.throws(() => f2.save('a\n'), /shorter/);
});

test('an upstream that cannot be reached: the call was begun, so it gets its stub', async () => {
  const w = await world();
  await w.tickets.close();
  try {
    const r = await w.call('GET', '/tickets/api/now/table/x');
    assert.equal(r.status, 502);
    assert.match(r.json.error, /ECONNREFUSED/);
    const [stub] = await stubsOf(w);
    assert.equal(docs(stub)['provared.error'], await identifierFingerprint(r.json.error));
  } finally {
    await w.gateway.close();
    await w.patch.close();
  }
});

test('the upstream countersigns, where it says it can, and a bad countersignature leaves the stub one-sided', async () => {
  const service = await generateKeySet();
  let good = true;
  const w = await world({
    slip: { with: [{ id: 'tickets', name: 'The ticket system' }, { id: 'patch', name: 'The patch service', keys: service.keys }], requires: [{ need: 'countersignature', action: 'patch.apply' }] },
    patch: { countersign: '/countersign' },
    patchAnswer: async (c, res) => {
      if (c.url === '/countersign') {
        assert.equal(c.headers['content-type'], 'application/jose+json');
        assert.equal(c.headers['x-api-key'], `${TOKEN}-patch`);
        const stub = JSON.parse(c.body.toString());
        return json(res, 200, good ? await countersign(stub, service.privateKeys) : { payload: 'x', signatures: [] });
      }
      return json(res, 200, { wave: 7 });
    },
  });
  try {
    const r = await w.call('POST', '/patch/svc-not/v1/waves');
    assert.equal(r.status, 403, 'no rule');
    const ok = await w.call('POST', '/patch/v1/waves', { headers: { 'content-type': 'application/json' }, body: { hosts: ['a', 'b'] } });
    assert.equal(ok.status, 200);
    const writer = w.gateway.writers().get('patching');
    let [stub] = (await writer.check()).entries.filter((e) => e.kind === 'stub');
    assert.equal(stub.countersignature.state, 'valid');
    assert.deepEqual(stub.content.amount, { unit: 'hosts', value: 2 });
    good = false;
    const second = await w.call('POST', '/patch/v1/waves', { headers: { 'content-type': 'application/json' }, body: { hosts: ['c'] } });
    assert.equal(second.status, 200, 'the call was sent, so the agent gets its answer');
    stub = (await writer.check()).entries.filter((e) => e.kind === 'stub')[1];
    assert.equal(stub.countersignature.state, 'absent');
    assert.ok(w.logs.some((e) => e.event === 'countersignature-not-taken'));
    await sameAsFile(w);
  } finally {
    await w.close();
  }
  // Where the slip asks for a countersignature and the upstream names no address for it: refused.
  const v = await world({ slip: { requires: [{ need: 'countersignature', action: 'host.reboot' }] } });
  try {
    const r = await v.call('POST', '/patch/v1/hosts/a/reboot', { headers: { 'content-type': 'application/json' }, body: {} });
    assert.equal(r.status, 403);
    assert.ok(r.json.breaches.some((b) => b.code === 'countersignature-missing'));
    assert.equal(v.patch.calls.length, 0);
  } finally {
    await v.close();
  }
});

test('a body larger than the limit is refused before it is sent, and written as a denial', async () => {
  const w = await world({ bodyLimit: 100 });
  try {
    const r = await w.call('POST', '/patch/v1/waves', { headers: { 'content-type': 'application/json' }, body: { hosts: Array(50).fill('host') } });
    assert.equal(r.status, 413);
    assert.equal(r.json.denial.written, true);
    // Sent in pieces, with no length given.
    const chunked = await w.call('POST', '/patch/v1/waves', { headers: { 'content-type': 'application/json', 'transfer-encoding': 'chunked' }, body: JSON.stringify({ hosts: Array(50).fill('host') }) });
    assert.equal(chunked.status, 413);
    assert.equal(w.patch.calls.length, 0);
    const denials = await denialsOf(w);
    assert.deepEqual(denials.map((d) => [d.content.action, d.content.source]), [['patch.apply', 'rule'], ['patch.apply', 'rule']]);
  } finally {
    await w.close();
  }
});

test('websockets and tunnels are refused', async () => {
  const w = await world();
  try {
    const r = await w.call('GET', '/tickets/api/now/table/x', { headers: { connection: 'Upgrade', upgrade: 'websocket' } });
    assert.equal(r.status, 400);
    assert.equal(w.tickets.calls.length, 0);
    // Through handle() alone, as a program that embeds the gateway calls it.
    const res = fakeResponse();
    await w.gateway.handle(fakeRequest({ method: 'GET', url: '/tickets/api/now/table/x', headers: { authorization: `Bearer ${SECRET}`, upgrade: 'websocket', connection: 'upgrade' } }), res);
    assert.equal(res.statusCode, 400);
    assert.equal(JSON.parse(res.body).code, 'upgrade-refused');
    const tunnel = fakeResponse();
    await w.gateway.handle(fakeRequest({ method: 'CONNECT', url: 'tickets.example.invalid:443', headers: { authorization: `Bearer ${SECRET}` } }), tunnel);
    assert.equal(tunnel.statusCode, 400);
    assert.equal(w.tickets.calls.length, 0);
  } finally {
    await w.close();
  }
});

function fakeRequest({ method, url, headers }) {
  const { Readable } = process.getBuiltinModule('node:stream');
  const req = Readable.from([]);
  req.method = method;
  req.url = url;
  req.headers = headers;
  req.headersDistinct = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, [v]]));
  return req;
}
function fakeResponse() {
  return {
    headersSent: false,
    writeHead(status, headers) {
      this.statusCode = status;
      this.headers = headers;
      this.headersSent = true;
    },
    end(body) {
      this.body = body ? body.toString() : '';
    },
  };
}

test('two agents: each signs in with its own secret, and has its own slip, keys and book', async () => {
  const { developmentPasskey } = await import('provared/dev');
  const { thumbprint, signerFromKey } = await import('provared');
  const { tempFolder } = await import('./world.mjs');
  const { writeFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const folder = tempFolder();
  const passkey = await developmentPasskey();
  const keys = await generateKeySet();
  const slip = await signSlip({ passkey, agentKeys: keys.keys, actions: ['provared.data.read'] });
  writeFileSync(join(folder, 'second.json'), JSON.stringify(slip));
  const w = await world({
    agents: {
      second: {
        secretHash: await secretHash(OTHER_SECRET),
        slip: join(folder, 'second.json'),
        book: join(folder, 'second.jsonl'),
        privateKeys: [signerFromKey('Ed25519', keys.privateKeys[0], keys.keys[0]), signerFromKey('ML-DSA-87', keys.privateKeys[1], keys.keys[1])],
        issuerKeys: [await thumbprint(passkey.key)],
      },
    },
  });
  try {
    assert.equal((await call(w.port, 'GET', '/tickets/api/now/table/x', { secret: OTHER_SECRET })).status, 200);
    assert.equal((await call(w.port, 'POST', '/patch/v1/hosts/a/reboot', { secret: OTHER_SECRET, headers: { 'content-type': 'application/json' }, body: {} })).status, 403, 'its own slip allows reads only');
    assert.equal((await w.call('POST', '/patch/v1/hosts/a/reboot', { headers: { 'content-type': 'application/json' }, body: {} })).status, 200);
    const second = await w.gateway.writers().get('second').check();
    assert.equal(second.entries.filter((e) => e.kind === 'stub').length, 1);
    assert.equal((await stubsOf(w)).length, 1);
    const text = readFileSync(join(folder, 'second.jsonl'), 'utf8');
    assert.deepEqual(await checkBook(text, w.gateway.checkOptions('second')), second);
  } finally {
    await w.close();
  }
});

test('the administrator: status, and a seal on demand, with the recorder\'s keys', async () => {
  const w = await world();
  try {
    await w.call('GET', '/tickets/api/now/table/x');
    const asAgent = await call(w.port, 'GET', '/provared/status', { secret: SECRET });
    assert.equal(asAgent.status, 401);
    const s = await call(w.port, 'GET', '/provared/status', { secret: ADMIN_SECRET });
    assert.equal(s.status, 200);
    assert.equal(s.json.agents.patching.entries, 2);
    assert.equal(s.json.agents.patching.lastSeal, null);
    assert.equal(s.json.agents.patching.sound, true);
    const sealed = await call(w.port, 'POST', '/provared/seal', { secret: ADMIN_SECRET, headers: { 'content-type': 'application/json' }, body: { agent: 'patching' } });
    assert.equal(sealed.status, 200, sealed.text);
    assert.equal(sealed.json.entry, 2);
    const after = await call(w.port, 'GET', '/provared/status', { secret: ADMIN_SECRET });
    assert.deepEqual(after.json.agents.patching.lastSeal, { entry: 2, fingerprint: sealed.json.fingerprint });
    await w.call('GET', '/tickets/api/now/table/y');
    const again = await w.gateway.seal('patching');
    const result = await checkBook(readFileSync(w.bookPath, 'utf8'), w.gateway.checkOptions('patching'));
    assert.equal(result.summary.intact, true);
    assert.equal(result.summary.counts.seals, 2);
    assert.equal(result.entries[again.entry].fingerprint, again.fingerprint);
    assert.equal((await call(w.port, 'POST', '/provared/seal', { secret: ADMIN_SECRET, body: { agent: 'nobody' } })).status, 400);
  } finally {
    await w.close();
  }
});

test('the gateway starts again on the book it wrote, and carries it on', async () => {
  const w = await world();
  await w.call('GET', '/tickets/api/now/table/x');
  await w.gateway.close();
  const { openGateway } = await import('../gateway.mjs');
  const again = await openGateway(w.config, { root: w.folder, log: () => {} });
  const at = await again.listen({ host: '127.0.0.1', port: 0 });
  try {
    assert.equal((await call(at.port, 'GET', '/tickets/api/now/table/y', { secret: SECRET })).status, 200);
    const result = await checkBook(readFileSync(w.bookPath, 'utf8'), again.checkOptions('patching'));
    assert.equal(result.summary.intact, true);
    assert.equal(result.summary.counts.slips, 1);
    assert.equal(result.summary.counts.stubs, 2);
  } finally {
    await again.close();
    await w.tickets.close();
    await w.patch.close();
  }
});

test('a book file changed by someone else stops the agent: no further call is sent', async () => {
  const w = await world();
  try {
    await w.call('GET', '/tickets/api/now/table/x');
    const { appendFileSync } = await import('node:fs');
    appendFileSync(w.bookPath, '{"stub":"not one"}\n');
    const next = await w.call('GET', '/tickets/api/now/table/y');
    assert.equal(next.status, 503);
    assert.equal(next.json.code, 'agent-stopped');
    assert.equal((await w.call('GET', '/tickets/api/now/table/z')).status, 503);
    assert.equal(w.tickets.calls.length, 1);
  } finally {
    await w.close();
  }
});

test('an answer cannot pose as the gateway: a "Provared-Stub" header from the upstream is not handed on', async () => {
  const w = await world({ ticketsAnswer: (c, res) => json(res, 200, {}, { 'provared-stub': 'forged', 'Provared-Other': 'x' }) });
  try {
    const r = await w.call('GET', '/tickets/api/now/table/x');
    const [stub] = await stubsOf(w);
    assert.equal(r.headers['provared-stub'], stub.fingerprint);
    assert.equal(r.headers['provared-other'], undefined);
  } finally {
    await w.close();
  }
});

test('the log holds no body, no value from the query, no credential and no secret', async () => {
  const w = await world({ ticketsAnswer: (c, res) => json(res, 200, { answer: 'MARK-ANSWER' }), unlisted: 'refuse' });
  try {
    await w.call('PATCH', '/tickets/api/now/table/change_request/1?q=MARK-QUERY&token=MARK-TOKEN', { headers: { 'content-type': 'application/json', cookie: 'MARK-COOKIE' }, body: { b: 'MARK-BODY' } });
    await w.call('PUT', '/tickets/nothing?q=MARK-QUERY', { headers: { 'content-type': 'application/json' }, body: { b: 'MARK-BODY' } });
    await w.call('GET', '/tickets/api/now/table/x', { secret: 'MARK-WRONG-SECRET-0123456789abcdefghij' });
    const text = JSON.stringify(w.logs);
    for (const mark of ['MARK-ANSWER', 'MARK-QUERY', 'MARK-TOKEN', 'MARK-COOKIE', 'MARK-BODY', 'MARK-WRONG', SECRET, TOKEN]) assert.ok(!text.includes(mark), mark);
    assert.ok(w.logs.some((e) => e.event === 'taken') && w.logs.some((e) => e.event === 'refused') && w.logs.some((e) => e.event === 'not-signed-in'));
  } finally {
    await w.close();
  }
});

test('a seal asked for while calls are on their way covers the book as it stands, and every call keeps its stub', async () => {
  const slow = (c, res) => setTimeout(() => json(res, 200, {}), 10);
  const w = await world({ ticketsAnswer: slow });
  try {
    const calls = Array.from({ length: 8 }, (_, i) => w.call('GET', `/tickets/api/now/table/t${i}`));
    const sealed = w.gateway.seal('patching');
    const more = Array.from({ length: 4 }, (_, i) => w.call('GET', `/tickets/api/now/table/u${i}`));
    const results = await Promise.all([...calls, ...more]);
    const seal = await sealed;
    assert.ok(results.every((r) => r.status === 200));
    const result = await checkBook(readFileSync(w.bookPath, 'utf8'), w.gateway.checkOptions('patching'));
    assert.equal(result.summary.intact, true);
    assert.equal(result.summary.counts.stubs, 12);
    assert.equal(result.entries[seal.entry].kind, 'seal');
  } finally {
    await w.close();
  }
});

test('a body announced as larger than the limit is refused at once, without waiting for it', async () => {
  const w = await world({ bodyLimit: 1000 });
  try {
    const http = await import('node:http');
    const answer = await new Promise((done, failed) => {
      const req = http.request({ host: '127.0.0.1', port: w.port, method: 'POST', path: '/patch/v1/waves', headers: { authorization: `Bearer ${SECRET}`, 'content-type': 'application/json', 'content-length': 5000 } }, (res) => {
        res.resume();
        done(res.statusCode);
      });
      req.on('error', failed);
      req.write('{"hosts":['); // and nothing more: the gateway must not wait for the rest
      setTimeout(() => failed(new Error('the gateway waited for the body')), 3000).unref();
    });
    assert.equal(answer, 413);
  } finally {
    await w.close();
  }
});

test('a credential that holds a line break is refused at start', async () => {
  process.env.PROVARED_GW_TEST_BROKEN = 'abc\r\nX-Injected: 1';
  const w = await world({ tickets: { credential: { header: 'Authorization', env: 'PROVARED_GW_TEST_BROKEN' } } }).catch((e) => e);
  if (!(w instanceof Error)) await w.close();
  assert.ok(w instanceof Error && /line break/.test(w.message), String(w?.message ?? 'the gateway started'));
});
