// The command, as a person runs it: making a secret and the keys, checking
// the settings, starting the gateway, asking it for its status and a seal,
// and sealing a book while the gateway is stopped. Every server listens on
// 127.0.0.1.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook, keySetFingerprint, thumbprint } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { tempFolder, upstream, call, signSlip } = await import('./world.mjs');
const { secretHash, openGateway } = await import('../gateway.mjs');

const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));

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

test('the commands: secret, keys, check, start, status, seal, and seal --offline', { timeout: 120000 }, async () => {
  const folder = tempFolder();
  const tickets = await upstream();
  const port = await freePort();
  const made = await run(['secret']);
  assert.equal(made.code, 0);
  const [secret, hash] = made.out.split('\n').filter((l) => l.startsWith('  ')).map((l) => l.trim());
  assert.equal(await secretHash(secret), hash);
  const admin = (await run(['secret'])).out.split('\n').filter((l) => l.startsWith('  ')).map((l) => l.trim());
  const env = { PROVARED_GW_CLI_TOKEN: 'cli-token', PROVARED_GATEWAY_ADMIN_SECRET: admin[0] };
  const passkey = await developmentPasskey();
  const config = {
    listen: { host: '127.0.0.1', port },
    admin: { secretHash: admin[1] },
    recorder: { name: 'The gateway of the command test', keys: 'keys/recorder.jwk' },
    upstreams: { tickets: { base: tickets.base, service: 'tickets', credential: { header: 'Authorization', env: 'PROVARED_GW_CLI_TOKEN', prefix: 'Bearer ' } } },
    rules: [{ upstream: 'tickets', method: 'GET', path: '/api/now/table/:table', action: 'provared.data.read' }],
    agents: { patching: { secretHash: hash, slip: 'slip.json', book: 'books/patching.jsonl', keys: 'keys/patching.jwk', issuerKeys: [await thumbprint(passkey.key)] } },
  };
  const configPath = join(folder, 'gateway.json');
  writeFileSync(configPath, JSON.stringify(config, null, 2));

  const keys = await run(['keys', '--config', configPath, '--agent', 'patching']);
  assert.equal(keys.code, 0, keys.err);
  const agentKeys = JSON.parse(keys.out.slice(keys.out.indexOf('[')));
  assert.deepEqual(agentKeys.map((k) => k.alg), ['Ed25519', 'ML-DSA-87']);
  const again = await run(['keys', '--config', configPath, '--agent', 'patching']);
  assert.deepEqual(JSON.parse(again.out.slice(again.out.indexOf('['))), agentKeys, 'a key file that exists is kept');
  const rkeys = await run(['keys', '--config', configPath, '--recorder']);
  assert.equal(rkeys.code, 0, rkeys.err);
  const recorderKeys = JSON.parse(rkeys.out.slice(rkeys.out.indexOf('[')));
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(await signSlip({ passkey, agentKeys, actions: ['provared.data.read'], with: [{ id: 'tickets', name: 'The ticket system' }] })));

  const checked = await run(['check', '--config', configPath], env);
  assert.equal(checked.code, 0, checked.out + checked.err);
  assert.match(checked.out, /rule 1: GET \/tickets\/api\/now\/table\/:table -> provared\.data\.read \(reads\); no amount; service tickets/);
  assert.match(checked.out, /No problem found/);
  assert.ok(!checked.out.includes('cli-token'), 'no credential value is printed');

  const wrong = { ...config, rules: [...config.rules, { upstream: 'nowhere', method: 'GET', path: '/', action: 'host.reboot' }] };
  writeFileSync(join(folder, 'wrong.json'), JSON.stringify(wrong));
  const bad = await run(['check', '--config', join(folder, 'wrong.json')], env);
  assert.equal(bad.code, 2);
  assert.match(bad.out, /problem: rule 2: "upstream" must name one of the upstreams/);
  assert.match(bad.out, /warning: rule 1|warning: rule 2: the slip of agent "patching" does not allow "host.reboot"/);
  const noEnv = await run(['check', '--config', configPath], { PROVARED_GATEWAY_ADMIN_SECRET: admin[0], PROVARED_GW_CLI_TOKEN: '' });
  assert.equal(noEnv.code, 2, 'an empty credential is a problem, as the gateway refuses it at start');
  assert.match(noEnv.out, /PROVARED_GW_CLI_TOKEN is empty/);

  // Start it, and use it.
  const gateway = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', BIN, 'start', '--config', configPath], { env: { ...process.env, ...env } });
  let started = '';
  await new Promise((done, failed) => {
    gateway.stderr.on('data', (d) => {
      started += d;
      if (started.includes('listening')) done();
    });
    gateway.on('close', () => failed(new Error(`the gateway ended: ${started}`)));
  });
  try {
    const r = await call(port, 'GET', '/tickets/api/now/table/incident', { secret });
    assert.equal(r.status, 200);
    assert.equal(tickets.calls[0].headers.authorization, 'Bearer cli-token');
    const status = await run(['status', '--config', configPath], env);
    assert.equal(status.code, 0, status.err);
    assert.equal(JSON.parse(status.out).agents.patching.entries, 2);
    const sealed = await run(['seal', '--config', configPath, '--agent', 'patching'], env);
    assert.equal(sealed.code, 0, sealed.err);
    assert.match(sealed.out, /Sealed: entry 2 of patching's book is the seal [A-Za-z0-9_-]{43}\./);
    const wrongAdmin = await run(['seal', '--config', configPath, '--agent', 'patching'], { ...env, PROVARED_GATEWAY_ADMIN_SECRET: 'not-the-secret' });
    assert.equal(wrongAdmin.code, 1);
  } finally {
    gateway.kill();
    await new Promise((done) => (gateway.exitCode !== null ? done() : gateway.on('close', done)));
  }
  const stopped = await run(['seal', '--config', configPath, '--agent', 'patching'], env);
  assert.equal(stopped.code, 2);
  assert.match(stopped.err, /not running.*--offline/);
  const offline = await run(['seal', '--config', configPath, '--agent', 'patching', '--offline'], env);
  assert.equal(offline.code, 0, offline.err);
  assert.match(offline.out, /entry 3 of patching's book/);

  const text = readFileSync(join(folder, 'books', 'patching.jsonl'), 'utf8');
  const result = await checkBook(text, { issuerKeys: config.agents.patching.issuerKeys, sealKeys: [await keySetFingerprint(recorderKeys)] });
  assert.equal(result.summary.intact, true);
  assert.equal(result.summary.counts.seals, 2);
  assert.equal(result.summary.counts.stubs, 1);
  await tickets.close();
});

test('signers named by a module of the company\'s own', async () => {
  const folder = tempFolder();
  const tickets = await upstream();
  const passkey = await developmentPasskey();
  const { makeKeyFile } = await import('../files.mjs');
  const agentKeys = await makeKeyFile(join(folder, 'held-elsewhere.jwk'), 'agent');
  // A stand-in for a key service: the module reads keys this test made, and gives signers.
  writeFileSync(
    join(folder, 'signers.mjs'),
    `import { loadKeyFile } from ${JSON.stringify(new URL('../files.mjs', import.meta.url).href)};\nexport let asked = [];\nexport default async (who) => { asked.push(who); return (await loadKeyFile(${JSON.stringify(join(folder, 'held-elsewhere.jwk'))}, 'agent')).privateKeys; };\n`,
  );
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(await signSlip({ passkey, agentKeys, actions: ['provared.data.read'] })));
  const gateway = await openGateway(
    {
      upstreams: { tickets: { base: tickets.base, service: 'tickets' } },
      rules: [{ upstream: 'tickets', method: 'GET', path: '/x', action: 'provared.data.read' }],
      agents: { patching: { secretHash: await secretHash('a-secret-for-the-signers-test-0123456789'), slip: 'slip.json', book: 'book.jsonl', signers: 'signers.mjs', issuerKeys: [await thumbprint(passkey.key)] } },
    },
    { root: folder, log: () => {} },
  );
  const at = await gateway.listen({ host: '127.0.0.1', port: 0 });
  try {
    assert.equal((await call(at.port, 'GET', '/tickets/x', { secret: 'a-secret-for-the-signers-test-0123456789' })).status, 200);
    const module = await import(new URL(`file:///${join(folder, 'signers.mjs').replace(/\\/g, '/')}`).href);
    assert.deepEqual(module.asked, [{ agent: 'patching' }]);
    const result = await checkBook(readFileSync(join(folder, 'book.jsonl'), 'utf8'), gateway.checkOptions('patching'));
    assert.equal(result.summary.intact, true);
    assert.equal(result.summary.counts.stubs, 1);
  } finally {
    await gateway.close();
    await tickets.close();
  }
});

test('the gateway does not start where the settings, the slip, the keys or the book are not right', async () => {
  const folder = tempFolder();
  const passkey = await developmentPasskey();
  const { makeKeyFile } = await import('../files.mjs');
  const agentKeys = await makeKeyFile(join(folder, 'a.jwk'), 'agent');
  const otherKeys = await makeKeyFile(join(folder, 'b.jwk'), 'agent');
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(await signSlip({ passkey, agentKeys })));
  writeFileSync(join(folder, 'token'), '\n');
  const issuerKeys = [await thumbprint(passkey.key)];
  const base = (agent = {}, more = {}) => ({
    upstreams: { u: { base: 'http://127.0.0.1:9' } },
    rules: [],
    agents: { a: { secretHash: 'A'.repeat(43), slip: 'slip.json', book: 'book.jsonl', keys: 'a.jwk', issuerKeys, ...agent } },
    ...more,
  });
  const fails = async (config, words) => {
    await assert.rejects(openGateway(config, { root: folder, log: () => {} }), (e) => words.test(e.message) || assert.fail(e.message));
  };
  await fails(base({ keys: 'b.jwk' }), /bad-key|keys|signer/i);
  await fails(base({ issuerKeys: ['B'.repeat(43)] }), /passkey that "issuerKeys" does not name/);
  await fails(base({ secretHash: 'short' }), /secretHash/);
  await fails(base({ slip: 'nothing.json' }), /slip/);
  await fails(base({}, { upstreams: { u: { base: 'http://127.0.0.1:9', credential: { header: 'Authorization', file: 'token' } } } }), /credential is empty/);
  await fails(base({}, { upstreams: { u: { base: 'http://127.0.0.1:9', credential: { header: 'Authorization', env: 'PROVARED_GW_NOT_SET_ANYWHERE' } } } }), /environment holds no/);
  await fails(base({}, { admin: { secretHash: 'x' } }), /admin/);
  writeFileSync(join(folder, 'book.jsonl'), '{"not":"a book"}\n');
  await fails(base(), /the book file .* does not pass its check/);
  writeFileSync(join(folder, 'book2.jsonl'), 'half a line');
  await fails(base({ book: 'book2.jsonl' }), /whole line/);
  assert.ok(otherKeys);
});
