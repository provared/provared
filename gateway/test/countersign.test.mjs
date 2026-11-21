// The gateway's own countersignature, and its own copy of each agent's
// calls. Where the slip names the gateway in "with" (an entry of its own,
// with the gateway's keys), every receipt of the agent names the gateway,
// the gateway countersigns each call it lets through, keeps a copy of the
// call apart from the book, and "compare" holds the copy against the book.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { appendFileSync, existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook, fingerprint, fromBase64url, generateKeySet, identifierFingerprint, keySetFingerprint, signerFromKey, thumbprint } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { world, json, call, upstream, tempFolder, signSlip, SECRET, ADMIN_SECRET } = await import('./world.mjs');
const { openGateway, checkConfig, secretHash } = await import('../gateway.mjs');
const { compareCopyWithBook } = await import('../compare.mjs');
const { loadCopyKey, readCopy, openCopy } = await import('../copy.mjs');
const { makeKeyFile } = await import('../files.mjs');

const JSONTYPE = { 'content-type': 'application/json' };
const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));
const stubsOf = async (w) => (await w.gateway.writers().get('patching').check()).entries.filter((e) => e.kind === 'stub');

/** The gateway's own key set, as signers in memory. */
async function gatewayKeys() {
  const set = await generateKeySet();
  return { keys: set.keys, privateKeys: [signerFromKey('Ed25519', set.privateKeys[0], set.keys[0]), signerFromKey('ML-DSA-87', set.privateKeys[1], set.keys[1])] };
}

/** A world whose gateway has its own keys, and whose slip names the gateway ("gateway", with those keys) and asks for its countersignature for one action. */
async function countersigningWorld(o = {}) {
  const own = o.own ?? (await gatewayKeys());
  const services = [{ id: 'gateway', name: 'The test gateway', keys: own.keys }, { id: 'tickets', name: 'The ticket system' }, { id: 'patch', name: 'The patch service' }];
  const w = await world({
    ...o,
    slip: { with: services, requires: o.requires ?? [{ need: 'countersignature', action: 'provared.data.read' }], ...(o.slip ?? {}) },
    config: { gateway: { name: 'The test gateway', keySet: own.keys, privateKeys: own.privateKeys }, ...(o.config ?? {}) },
  });
  return { ...w, own };
}

async function compareNow(w) {
  const at = w.gateway.copyOf('patching');
  return compareCopyWithBook({ copyPath: at.copy, copyKey: loadCopyKey(at.copyKey, { create: false }), name: 'patching', service: at.service, book: readFileSync(w.bookPath, 'utf8'), options: w.gateway.checkOptions('patching') });
}

const copyLines = (w) => readCopy(w.gateway.copyOf('patching').copy, loadCopyKey(w.gateway.copyOf('patching').copyKey), 'patching').lines.map((l) => l.entry);

test('the gateway countersigns, with its own keys, each call of an agent whose slip names the gateway; the stub names the gateway, and the countersignature checks', async () => {
  const w = await countersigningWorld({ ticketsAnswer: (c, res) => json(res, 200, { result: [1] }) });
  try {
    const r = await w.call('GET', '/tickets/api/now/table/incident');
    assert.equal(r.status, 200, r.text);
    assert.equal(w.tickets.calls.length, 1);
    const [stub] = await stubsOf(w);
    assert.equal(stub.content.with, 'gateway', "the stub names the gateway's own entry, not the upstream's");
    assert.equal(stub.countersignature.state, 'valid', 'the countersignature checks against the keys the slip gives the service');
    assert.ok(stub.content.details.some((d) => d.name === 'provared.http-response'), 'the stub countersigned names the answer');
    const checked = await checkBook(readFileSync(w.bookPath, 'utf8'), w.gateway.checkOptions('patching'));
    assert.equal(checked.summary.problemFound, false);
    assert.equal(checked.summary.withinSlips, true);
    assert.ok(w.logs.some((e) => e.event === 'taken' && e.countersigned === true));
    // The countersignature is the gateway's: signed by its key set, not the agent's.
    const line = JSON.parse(readFileSync(w.bookPath, 'utf8').trim().split('\n').at(-1));
    const content = JSON.parse(new TextDecoder().decode(fromBase64url(line.countersignature.payload)));
    assert.equal(content.type, 'provared.countersignature.v0');
    assert.equal(content.stub, stub.fingerprint);
    // A call to the other upstream is countersigned too, under the gateway's entry: every call of the agent names the gateway.
    const p = await w.call('POST', '/patch/v1/hosts/h1/reboot', { headers: JSONTYPE, body: {} });
    assert.equal(p.status, 200, p.text);
    assert.equal((await stubsOf(w)).at(-1).content.with, 'gateway');
    assert.equal((await stubsOf(w)).at(-1).countersignature.state, 'valid');
    const status = await w.gateway.status();
    assert.equal(status.agents.patching.countersigns, true);
    assert.equal(status.id, 'gateway');
    assert.equal(status.countersigner, await keySetFingerprint(w.own.keys));
  } finally {
    await w.close();
  }
});

test('without the gateway\'s own keys, a slip that asks for a countersignature from a service with no address for it refuses the call, as before', async () => {
  const own = await gatewayKeys();
  const w = await world({ slip: { with: [{ id: 'tickets', name: 'The ticket system', keys: own.keys }, { id: 'patch', name: 'The patch service' }], requires: [{ need: 'countersignature', action: 'provared.data.read' }] } });
  try {
    const r = await w.call('GET', '/tickets/api/now/table/incident');
    assert.equal(r.status, 403);
    assert.ok(r.json.breaches.some((b) => b.code === 'countersignature-missing'));
    assert.equal(w.tickets.calls.length, 0);
    assert.equal(w.gateway.copyOf('patching'), null, 'no copy is kept without the gateway\'s own keys');
  } finally {
    await w.close();
  }
});

test('the gateway\'s copy holds a line before each call and one after it, with the stub and the countersignature, and compare finds them matched', async () => {
  const w = await countersigningWorld();
  try {
    assert.equal((await w.call('GET', '/tickets/api/now/table/incident')).status, 200);
    const lines = copyLines(w);
    assert.deepEqual(lines.map((l) => [l.seq, l.kind]), [[0, 'sending'], [1, 'done']]);
    const [sending, done] = lines;
    assert.equal(sending.upstream, 'tickets');
    assert.equal(sending.with, 'gateway');
    assert.equal(sending.action, 'provared.data.read');
    const [stub] = await stubsOf(w);
    assert.equal(done.stub, stub.fingerprint);
    assert.equal(done.countersigned, true);
    const line = JSON.parse(readFileSync(w.bookPath, 'utf8').trim().split('\n').at(-1));
    assert.equal(done.countersignature, await fingerprint(fromBase64url(line.countersignature.payload)));
    assert.equal(stub.content.details.find((d) => d.name === 'gateway.call').sha256, await identifierFingerprint(sending.call));
    // Nothing of the call itself is in the copy: no address, no body, no credential.
    const text = readFileSync(w.gateway.copyOf('patching').copy, 'utf8');
    assert.ok(!text.includes('/api/now/table') && !text.includes('Bearer'));
    const result = await compareNow(w);
    assert.equal(result.summary.agree, true, JSON.stringify(result.summary));
    assert.equal(result.summary.matched, 1);
    assert.equal(result.matched[0].countersignature, 'valid');
  } finally {
    await w.close();
  }
});

test('a refused call is a "refused" line in the copy, with its denial, which compare finds in the book', async () => {
  const w = await countersigningWorld({ slip: { actions: ['provared.data.read', 'patch.apply', 'host.reboot'] } });
  try {
    // Not allowed by the slip: the check before acting refuses it.
    const r = await w.call('PATCH', '/tickets/api/now/table/change_request/1', { headers: JSONTYPE, body: {} });
    assert.equal(r.status, 403);
    // Named by no rule.
    const u = await w.call('GET', '/tickets/nothing/here');
    assert.equal(u.status, 403);
    const refused = copyLines(w).filter((l) => l.kind === 'refused');
    assert.deepEqual(refused.map((l) => l.reason), ['not-allowed', 'unlisted']);
    assert.ok(refused[0].codes.length > 0);
    assert.equal(refused[0].denial, r.json.denial.fingerprint);
    const result = await compareNow(w);
    assert.equal(result.refused.length, 2);
    assert.ok(result.refused.every((x) => x.denialInBook === true));
    assert.equal(result.summary.agree, true);
  } finally {
    await w.close();
  }
});

test('compare finds a receipt left out of the book, and one in the book that the copy does not know', async () => {
  const w = await countersigningWorld();
  let copyAt;
  try {
    assert.equal((await w.call('GET', '/tickets/api/now/table/a')).status, 200);
    assert.equal((await w.call('GET', '/tickets/api/now/table/b')).status, 200);
    copyAt = w.gateway.copyOf('patching');
  } finally {
    await w.close();
  }
  const book = readFileSync(w.bookPath, 'utf8');
  const lines = book.trim().split('\n');
  const key = loadCopyKey(copyAt.copyKey, { create: false });
  const options = w.gateway.checkOptions('patching');
  // The last stub taken out of the book: the gateway sent the call, and the book has no receipt for it.
  const cut = await compareCopyWithBook({ copyPath: copyAt.copy, copyKey: key, name: 'patching', service: copyAt.service, book: `${lines.slice(0, -1).join('\n')}\n`, options });
  assert.equal(cut.summary.missingFromBook, 1);
  assert.equal(cut.summary.agree, false);
  // An empty copy: both receipts are in the book, under the service the slip gives the gateway's keys for, and the copy does not know them.
  const empty = join(tempFolder(), 'empty.jsonl');
  writeFileSync(empty, '');
  const none = await compareCopyWithBook({ copyPath: empty, copyKey: key, name: 'patching', service: copyAt.service, book, options });
  assert.equal(none.summary.notInCopy, 2);
  assert.equal(none.summary.agree, false);
  // A line of the copy changed: it no longer checks.
  const text = readFileSync(copyAt.copy, 'utf8').replace('"provared.data.read"', '"provared.data.delete"');
  const changed = join(tempFolder(), 'changed.jsonl');
  writeFileSync(changed, text);
  const bad = await compareCopyWithBook({ copyPath: changed, copyKey: key, name: 'patching', service: copyAt.service, book, options });
  assert.ok(bad.copy.refused >= 1);
  assert.equal(bad.summary.agree, false);
});

test('the gateway does not start where its own keys are the agent\'s, or where its copy is not whole', async () => {
  const w = await countersigningWorld();
  let copyAt;
  try {
    assert.equal((await w.call('GET', '/tickets/api/now/table/a')).status, 200);
    copyAt = w.gateway.copyOf('patching');
  } finally {
    await w.close();
  }
  // The agent's keys given as the gateway's.
  const agentAsGateway = { ...w.config, gateway: { keySet: w.agentSet.keys, privateKeys: w.config.agents.patching.privateKeys } };
  await assert.rejects(openGateway(agentAsGateway, { root: w.folder, log: () => {} }), /names the gateway's own keys \("gateway"\) as the agent's keys/);
  // A line of the copy changed.
  const original = readFileSync(copyAt.copy, 'utf8');
  writeFileSync(copyAt.copy, original.replace('"provared.data.read"', '"provared.data.delete"'));
  await assert.rejects(openGateway(w.config, { root: w.folder, log: () => {} }), /its copy .* is not whole/);
  // A copy cut part-way through a line.
  writeFileSync(copyAt.copy, original.slice(0, -5));
  await assert.rejects(openGateway(w.config, { root: w.folder, log: () => {} }), /ends part-way through a line/);
  // A copy key that is not the one the copy was written with.
  writeFileSync(copyAt.copy, original);
  const keyText = readFileSync(copyAt.copyKey, 'utf8');
  writeFileSync(copyAt.copyKey, Buffer.alloc(32, 7).toString('base64url'));
  await assert.rejects(openGateway(w.config, { root: w.folder, log: () => {} }), /no line of its copy .* checks/);
  // A copy that holds lines, and no key: no new key is made for it.
  renameSync(copyAt.copyKey, `${copyAt.copyKey}.moved`);
  await assert.rejects(openGateway(w.config, { root: w.folder, log: () => {} }), /holds lines, and its copy key .* is missing/);
  assert.equal(existsSync(copyAt.copyKey), false);
  renameSync(`${copyAt.copyKey}.moved`, copyAt.copyKey);
  writeFileSync(copyAt.copyKey, keyText);
  const g = await openGateway(w.config, { root: w.folder, log: () => {} });
  await g.close();
});

test('a copy that something else wrote to stops the agent: the call is not sent, and the agent is answered 503', async () => {
  const w = await countersigningWorld();
  try {
    assert.equal((await w.call('GET', '/tickets/api/now/table/a')).status, 200);
    appendFileSync(w.gateway.copyOf('patching').copy, 'something else\n');
    const r = await w.call('GET', '/tickets/api/now/table/b');
    assert.equal(r.status, 503, r.text);
    assert.equal(r.json.code, 'agent-stopped');
    assert.match(r.json.message, /its copy could not be written/);
    assert.equal(w.tickets.calls.length, 1, 'the second call was not sent');
    assert.ok(w.logs.some((e) => e.event === 'copy-not-written'));
    assert.equal((await stubsOf(w)).length, 1, 'no stub for a call that was not sent');
  } finally {
    await w.close();
  }
});

test('check says that the gateway countersigns every call of an agent whose slip names it, and warns where the slip does not require it for every action', async () => {
  const w = await countersigningWorld();
  try {
    const { lines, problems, warnings } = await checkConfig(w.config, { root: w.folder });
    assert.deepEqual(problems, []);
    assert.ok(lines.some((l) => /agent "patching": the gateway countersigns, with its own keys, every call of this agent it lets through; each receipt names the gateway \("gateway"\)/.test(l)));
    assert.ok(warnings.some((x) => /does not require a countersignature for every action/.test(x)));
    assert.ok(w.logs.some((e) => e.event === 'warning' && /every action/.test(e.message)));
    const asAgent = await checkConfig({ ...w.config, gateway: { keySet: w.agentSet.keys, privateKeys: w.config.agents.patching.privateKeys } }, { root: w.folder });
    assert.ok(asAgent.problems.some((p) => /as the agent's keys/.test(p)));
  } finally {
    await w.close();
  }
});

function run(args, env = {}) {
  return new Promise((done) => {
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', BIN, ...args], { env: { ...process.env, ...env } });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('close', (code) => done({ code, out, err }));
  });
}

function freePort() {
  return new Promise((done) => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => done(port));
    });
  });
}

test('the commands: "keys --gateway" prints the slip\'s entries; a call cut off by a stop is countersigned when acknowledged; "compare" agrees', { timeout: 120000 }, async () => {
  const folder = tempFolder();
  const passkey = await developmentPasskey();
  const agentKeys = await makeKeyFile(join(folder, 'agent.jwk'), 'agent');
  let hold = false;
  const up = await upstream((c, res) => {
    if (!hold) json(res, 200, { ok: true });
  });
  const port = await freePort();
  const config = {
    listen: { host: '127.0.0.1', port },
    admin: { secretHash: await secretHash(ADMIN_SECRET) },
    gateway: { name: 'The test gateway', keys: 'gateway.jwk' },
    upstreams: { tickets: { base: up.base, service: 'tickets', timeout: 60000 } },
    rules: [{ upstream: 'tickets', method: 'DELETE', path: '/x/:id', action: 'provared.data.delete' }],
    agents: { patching: { secretHash: await secretHash(SECRET), slip: 'slip.json', book: 'book.jsonl', keys: 'agent.jwk', issuerKeys: [await thumbprint(passkey.key)] } },
  };
  const configPath = join(folder, 'gateway.json');
  writeFileSync(configPath, JSON.stringify(config));
  const keys = await run(['keys', '--config', configPath, '--gateway']);
  assert.equal(keys.code, 0, keys.err);
  const printed = JSON.parse(keys.out.slice(keys.out.indexOf('{')));
  assert.deepEqual(printed.requires, [{ need: 'countersignature' }]);
  assert.equal(printed.with.length, 1);
  assert.equal(printed.with[0].id, 'gateway', "the gateway's own entry, apart from the upstreams' services");
  assert.equal(printed.with[0].name, 'The test gateway');
  assert.equal(printed.with[0].keys.length, 2);
  assert.ok(!keys.out.includes('"d"') && !keys.out.includes('"priv"'), 'no private key is printed');
  const slip = await signSlip({ passkey, agentKeys, with: printed.with, requires: printed.requires });
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(slip));

  const start = () =>
    new Promise((done, failed) => {
      const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', BIN, 'start', '--config', configPath], { env: process.env });
      let err = '';
      child.stderr.on('data', (d) => {
        err += d;
        if (err.includes('listening')) done({ child, log: () => err });
      });
      child.on('exit', () => failed(new Error(err)));
    });
  const stop = async (g, how) => {
    g.child.removeAllListeners('exit');
    g.child.kill(how);
    await new Promise((d) => g.child.once('exit', d));
  };
  let g = await start();
  const first = await call(port, 'DELETE', '/tickets/x/0', { secret: SECRET });
  assert.equal(first.status, 200, first.text);
  // The next call is with the upstream when the gateway is stopped without warning.
  hold = true;
  call(port, 'DELETE', '/tickets/x/1', { secret: SECRET }).catch(() => null);
  while (up.calls.length < 2) await new Promise((d) => setTimeout(d, 20));
  await stop(g, 'SIGKILL');
  hold = false;
  g = await start();
  try {
    const ack = await call(port, 'POST', '/provared/acknowledge', { secret: ADMIN_SECRET, headers: JSONTYPE, body: { agent: 'patching' } });
    assert.equal(ack.status, 200, ack.text);
    assert.equal(ack.json.written.length, 1);
    assert.equal(ack.json.written[0].countersigned, true, 'the stub written on acknowledgement is countersigned by the gateway');
  } finally {
    await stop(g);
  }
  const checked = await checkBook(readFileSync(join(folder, 'book.jsonl'), 'utf8'), { issuerKeys: config.agents.patching.issuerKeys });
  assert.equal(checked.summary.problemFound, false);
  assert.equal(checked.summary.withinSlips, true, 'every stub carries the countersignature the slip asks for');
  const stubs = checked.entries.filter((e) => e.kind === 'stub');
  assert.equal(stubs.length, 2);
  assert.deepEqual(stubs.map((s) => s.countersignature.state), ['valid', 'valid']);
  assert.ok(stubs[1].content.details.some((d) => d.name === 'provared.error'));
  const compared = await run(['compare', '--config', configPath, '--agent', 'patching']);
  assert.equal(compared.code, 0, compared.out + compared.err);
  const result = JSON.parse(compared.out);
  assert.equal(result.summary.matched, 2);
  assert.equal(result.summary.agree, true);
  // The book with its last line taken out: compare says the receipt is missing, and ends with 1.
  const book = readFileSync(join(folder, 'book.jsonl'), 'utf8').trim().split('\n');
  const shorter = join(folder, 'shorter.jsonl');
  writeFileSync(shorter, `${book.slice(0, -1).join('\n')}\n`);
  const missing = await run(['compare', '--config', configPath, '--agent', 'patching', '--book', shorter]);
  assert.equal(missing.code, 1);
  assert.equal(JSON.parse(missing.out).summary.missingFromBook, 1);
  await up.close();
});
