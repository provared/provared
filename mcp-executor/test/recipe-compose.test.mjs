// The Docker Compose recipe for claude.ai (recipes/claude-ai/compose): its
// first-start program, run here against this repository's executor, and
// what its files must hold (no published port of the guard's, images that
// follow their release lines by tag with the npm tree exact, plain folders
// and no Docker volume, the containers locked down). The recipe in Docker itself is checked by
// test/recipe-compose/docker-check.sh, outside "npm test".

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const RECIPE = fileURLToPath(new URL('../recipes/claude-ai/compose/', import.meta.url));
const START = join(RECIPE, 'start.mjs');
const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));
const SIGN = fileURLToPath(new URL('./recipe-compose/sign-test-permission.mjs', import.meta.url));
const read = (name) => readFileSync(join(RECIPE, name), 'utf8');
const { checkDomain, fillSettings, waiting, nextSteps, ownerState, watchPeer, guardRunning, markRunning, writes, CLIENT } = await import('../recipes/claude-ai/compose/start.mjs');
const POSIX = process.platform !== 'win32';

function folder() {
  const dir = mkdtempSync(join(tmpdir(), 'provared-recipe-'));
  return dir;
}

/** start.mjs as the container runs it, with this repository's executor and a data folder of the test's. */
function startProgram(data, env = {}, args = []) {
  const child = spawn(process.execPath, [START, ...args], {
    cwd: data,
    // No Caddy here: PROVARED_PEER empty, so the start does not look for one (watchPeer is tried on its own, below).
    env: { ...process.env, PROVARED_DATA: data, PROVARED_BIN: BIN, PROVARED_WAIT_MS: '200', PROVARED_PEER: '', ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  child.stdout.on('data', (d) => (out += d));
  child.stderr.on('data', (d) => (out += d));
  const ended = new Promise((done) => child.on('exit', (code) => done(code)));
  return {
    child,
    ended,
    out: () => out,
    async until(text, ms = 30_000) {
      const end = Date.now() + ms;
      while (!out.includes(text)) {
        if (Date.now() > end || child.exitCode !== null) throw new Error(`"${text}" did not come. Output:\n${out}`);
        await new Promise((r) => setTimeout(r, 50));
      }
    },
    stop() {
      // The guard is the start's child: on Windows, the whole tree goes.
      if (process.platform === 'win32') spawnSync('taskkill', ['/pid', String(child.pid), '/T', '/F']);
      else child.kill('SIGTERM');
      return ended;
    },
  };
}

function freePort() {
  return new Promise((done) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => done(port));
    });
  });
}

test('checkDomain: a DNS name only, lower-cased; no scheme, port, path, final dot or IP address', () => {
  assert.equal(checkDomain('Guard.Example.com'), 'guard.example.com');
  assert.equal(checkDomain(' guard.example.com\n'), 'guard.example.com');
  assert.equal(checkDomain('xn--bcher-kva.example'), 'xn--bcher-kva.example');
  assert.throws(() => checkDomain(''), /PROVARED_DOMAIN is not set/);
  assert.throws(() => checkDomain(undefined), /PROVARED_DOMAIN is not set/);
  for (const bad of ['https://guard.example.com', 'guard.example.com:443', 'guard.example.com/mcp', 'guard.example.com.', 'localhost', '192.0.2.1', '[2001:db8::1]', '-guard.example.com', 'guard_1.example.com', `${'a'.repeat(64)}.example.com`]) {
    assert.throws(() => checkDomain(bad), /not a domain name/, bad);
  }
});

test('fillSettings: the issuer and claude.ai\'s document are put in where written <like this>; another issuer is a problem, not changed', () => {
  const placeholders = { oauth: { issuer: '<public https address>', clients: ["<address of the client's metadata document>"], state: 'oauth-state.json' } };
  const filled = fillSettings(placeholders, 'guard.example.com');
  assert.equal(filled.problem, null);
  assert.equal(filled.changed, true);
  assert.equal(filled.settings.oauth.issuer, 'https://guard.example.com');
  assert.deepEqual(filled.settings.oauth.clients, [CLIENT]);
  assert.equal(placeholders.oauth.issuer, '<public https address>', 'the settings given are not changed in place');

  const again = fillSettings(filled.settings, 'guard.example.com');
  assert.equal(again.changed, false);
  assert.equal(again.problem, null);

  // A list of the business's own clients is kept.
  const own = fillSettings({ oauth: { issuer: 'https://guard.example.com', clients: ['https://client.example/meta.json'] } }, 'guard.example.com');
  assert.deepEqual(own.settings.oauth.clients, ['https://client.example/meta.json']);

  const moved = fillSettings(filled.settings, 'other.example.com');
  assert.match(moved.problem, /names https:\/\/guard\.example\.com as "oauth\.issuer".*other\.example\.com.*owner --reset/s);
  assert.equal(moved.settings.oauth.issuer, 'https://guard.example.com');

  assert.match(fillSettings({ agents: {} }, 'guard.example.com').problem, /names no "oauth"/);
});

test('waiting and nextSteps: what each OAuth agent lacks, and the exact steps for it', () => {
  const data = folder();
  try {
    const settings = {
      oauth: { issuer: 'https://guard.example.com' },
      agents: {
        'connection-1': { oauth: true, slip: 'slips/connection-1.json', issuerKeys: ["<thumbprint of the person's passkey>"] },
        'with-secret': { secretHash: 'x', slip: 'slips/with-secret.json', issuerKeys: [] },
      },
      tools: { echo: { action: 'demo.echo' }, add: { action: 'demo.add' } },
    };
    assert.deepEqual(waiting(settings, data), [{ name: 'connection-1', slip: 'slips/connection-1.json', lacks: ['slip', 'thumbprint'] }]);
    const steps = nextSteps(settings, waiting(settings, data));
    assert.match(steps, /waits for the permission/);
    assert.match(steps, /sudo cat guard-data\/permission-entries\.json/);
    assert.match(steps, /for the agent "connection-1" and the actions demo\.echo and demo\.add/);
    assert.match(steps, /sudo install -o 10001 -g 10001 -m 600 connection-1\.json guard-data\/slips\/connection-1\.json/);
    assert.match(steps, /agents\."connection-1"\.issuerKeys/);

    mkdirSync(join(data, 'slips'));
    writeFileSync(join(data, 'slips', 'connection-1.json'), '{}');
    assert.deepEqual(waiting(settings, data)[0].lacks, ['thumbprint']);
    settings.agents['connection-1'].issuerKeys = ['abc'];
    assert.deepEqual(waiting(settings, data), []);
  } finally {
    rmSync(data, { recursive: true, force: true });
  }
});

test('ownerState: no file, no owner; an owner; a setup and its end', () => {
  const data = folder();
  try {
    const path = join(data, 'oauth-state.json');
    assert.deepEqual(ownerState(path), { owner: false, setupEnds: null });
    writeFileSync(path, JSON.stringify({ owner: null, grants: [], setup: { hash: 'h', expires: 123 } }));
    assert.deepEqual(ownerState(path), { owner: false, setupEnds: 123 });
    writeFileSync(path, JSON.stringify({ owner: { key: {} }, grants: [] }));
    assert.deepEqual(ownerState(path), { owner: true, setupEnds: null });
  } finally {
    rmSync(data, { recursive: true, force: true });
  }
});

test('owner: the link goes to owner-link.txt, readable by its owner alone, and is not printed', async () => {
  const data = folder();
  try {
    const fake = join(data, 'fake-bin.mjs');
    writeFileSync(fake, "process.stdout.write('Start the executor, then open this link:\\n  https://guard.example.com/oauth/owner#SECRETCODE123\\nThen add the executor.\\n');\n");
    const run = startProgram(data, { PROVARED_BIN: fake }, ['owner']);
    assert.equal(await run.ended, 0, run.out());
    assert.doesNotMatch(run.out(), /SECRETCODE123/);
    assert.match(run.out(), /\[the link is in guard-data\/owner-link\.txt\]/);
    assert.equal(readFileSync(join(data, 'owner-link.txt'), 'utf8'), 'https://guard.example.com/oauth/owner#SECRETCODE123\n');
    if (POSIX) assert.equal(statSync(join(data, 'owner-link.txt')).mode & 0o777, 0o600);

    const extra = startProgram(data, { PROVARED_BIN: fake }, ['owner', '--now']);
    assert.equal(await extra.ended, 1);
    assert.match(extra.out(), /owner takes only --reset/);
  } finally {
    rmSync(data, { recursive: true, force: true });
  }
});

test('the start: an unset or wrong domain stops it, with what to do', async () => {
  const data = folder();
  try {
    const none = startProgram(data, { PROVARED_DOMAIN: '' });
    assert.equal(await none.ended, 1);
    assert.match(none.out(), /PROVARED_DOMAIN is not set\. Put the domain in the file \.env/);
    const url = startProgram(data, { PROVARED_DOMAIN: 'https://guard.example.com' });
    assert.equal(await url.ended, 1);
    assert.match(url.out(), /not a domain name/);
    assert.equal(existsSync(join(data, 'executor-http.json')), false, 'nothing is written before the domain is right');
  } finally {
    rmSync(data, { recursive: true, force: true });
  }
});

test('the start, from an empty folder to the guard answering: init, the issuer, the keys, the wait, the check, the owner\'s link, then "http"', { timeout: 120_000 }, async () => {
  const data = folder();
  let run;
  try {
    run = startProgram(data, { PROVARED_DOMAIN: 'guard.example.test' });
    await run.until('waits for the permission');
    const settings = JSON.parse(readFileSync(join(data, 'executor-http.json'), 'utf8'));
    assert.equal(settings.oauth.issuer, 'https://guard.example.test');
    assert.deepEqual(settings.oauth.clients, [CLIENT]);
    assert.deepEqual(settings.listen, { host: '127.0.0.1', port: 8796 }, 'the address the Caddyfile names');
    assert.ok(read('Caddyfile').includes(`reverse_proxy ${settings.listen.host}:${settings.listen.port}`));
    const entries = JSON.parse(readFileSync(join(data, 'permission-entries.json'), 'utf8'));
    assert.ok(entries['connection-1'].agent.keys, 'what the permission holds');
    assert.ok(existsSync(join(data, 'slips')));
    assert.match(run.out(), /for the agent "connection-1" and the actions demo\.echo and demo\.add/);
    assert.equal(existsSync(join(data, 'owner-link.txt')), false, 'no link before the permission');

    // Another port, so the test does not depend on 8796 being free; the start reads the settings again.
    const port = await freePort();
    writeFileSync(join(data, 'executor-http.json'), `${JSON.stringify({ ...settings, listen: { host: '127.0.0.1', port } }, null, 2)}\n`);
    const signed = spawnSync(process.execPath, [SIGN], { env: { ...process.env, PROVARED_DATA: data }, encoding: 'utf8' });
    assert.equal(signed.status, 0, signed.stderr);
    await run.until('Starting the guard', 60_000);
    assert.match(run.out(), /"check": no problem/);
    assert.match(readFileSync(join(data, 'owner-link.txt'), 'utf8'), /^https:\/\/guard\.example\.test\/oauth\/owner#\S+\n$/);
    assert.doesNotMatch(run.out(), /\/oauth\/owner#/, 'the link is not in the output');
    if (POSIX) {
      for (const f of ['executor-http.json', 'owner-link.txt', 'oauth-state.json', 'keys/executor.jwk']) assert.equal(statSync(join(data, f)).mode & 0o077, 0, `${f} is the owner's alone`);
    }

    // The guard itself answers: the 401 that names the metadata, at the issuer's address.
    let answer;
    for (let i = 0; i < 100; i++) {
      answer = await fetch(`http://127.0.0.1:${port}/mcp`, { method: 'POST' }).catch(() => null);
      if (answer) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    assert.equal(answer?.status, 401);
    assert.equal(answer.headers.get('www-authenticate'), 'Bearer resource_metadata="https://guard.example.test/.well-known/oauth-protected-resource/mcp"');
    await run.stop();

    // A second start keeps a link that still works, and says so.
    const again = startProgram(data, { PROVARED_DOMAIN: 'guard.example.test' });
    const link = readFileSync(join(data, 'owner-link.txt'), 'utf8');
    await again.until('Starting the guard', 60_000);
    assert.match(again.out(), /still works, until/);
    assert.equal(readFileSync(join(data, 'owner-link.txt'), 'utf8'), link);
    await again.stop();

    // The domain changed in .env: the start stops, and names the way to move.
    const moved = startProgram(data, { PROVARED_DOMAIN: 'other.example.test' });
    assert.equal(await moved.ended, 1);
    assert.match(moved.out(), /names https:\/\/guard\.example\.test as "oauth\.issuer"/);
  } finally {
    if (run && run.child.exitCode === null) await run.stop();
    rmSync(data, { recursive: true, force: true });
  }
});

test('an agent added after the first start gets its key file and its entries, the file of entries before kept beside (X351)', { timeout: 120_000 }, async () => {
  const data = folder();
  let run;
  try {
    run = startProgram(data, { PROVARED_DOMAIN: 'guard.example.test' });
    await run.until('waits for the permission');
    await run.stop();
    const before = readFileSync(join(data, 'permission-entries.json'), 'utf8');
    const key1 = readFileSync(join(data, 'keys', 'connection-1.jwk'), 'utf8');
    const settings = JSON.parse(readFileSync(join(data, 'executor-http.json'), 'utf8'));
    const two = 'connection-2';
    settings.agents[two] = { oauth: true, slip: `slips/${two}.json`, book: `books/${two}.jsonl`, keys: `keys/${two}.jwk`, issuerKeys: ["<thumbprint of the person's passkey>"] };
    writeFileSync(join(data, 'executor-http.json'), `${JSON.stringify(settings, null, 2)}\n`);
    run = startProgram(data, { PROVARED_DOMAIN: 'guard.example.test' });
    await run.until('waits for the permission');
    const entries = JSON.parse(readFileSync(join(data, 'permission-entries.json'), 'utf8'));
    assert.deepEqual(Object.keys(entries).sort(), ['connection-1', 'connection-2'], 'the file names the new agent');
    assert.ok(existsSync(join(data, 'keys', `${two}.jwk`)), 'its key file is made');
    assert.equal(readFileSync(join(data, 'keys', 'connection-1.jwk'), 'utf8'), key1, 'the first agent\'s keys are kept');
    assert.match(run.out(), /The agent "connection-2" had no entry in guard-data\/permission-entries\.json: .*the one before is guard-data\/permission-entries\.before-/);
    const kept = run.out().match(/the one before is guard-data\/(permission-entries\.before-[^ ]+\.json)/)[1];
    assert.equal(readFileSync(join(data, kept), 'utf8'), before);
    assert.match(run.out(), /holding the entries of "connection-2" in that file/);
    await run.stop();
    // Nothing missing: a third start writes nothing again.
    run = startProgram(data, { PROVARED_DOMAIN: 'guard.example.test' });
    await run.until('waits for the permission');
    assert.doesNotMatch(run.out(), /had no entry/);
  } finally {
    if (run && run.child.exitCode === null) await run.stop();
    rmSync(data, { recursive: true, force: true });
  }
});

test('a command that writes is refused while a start is at its first steps, before the guard runs (X364)', { timeout: 120_000 }, async () => {
  const data = folder();
  let run;
  try {
    run = startProgram(data, { PROVARED_DOMAIN: 'guard.example.test' });
    await run.until('waits for the permission');
    const reset = () => spawnSync(process.execPath, [START, 'owner', '--reset'], {
      cwd: data,
      env: { ...process.env, PROVARED_DATA: data, PROVARED_BIN: BIN, PROVARED_PEER: '' },
      encoding: 'utf8',
    });
    const r = reset();
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stderr, /The guard is running on these files/);
    await run.stop();
    // The start gone, the mark goes with it.
    assert.doesNotMatch(reset().stderr, /The guard is running on these files/);
  } finally {
    if (run && run.child.exitCode === null) await run.stop();
    rmSync(data, { recursive: true, force: true });
  }
});

test('a command run through the start writes its files for the guard\'s user alone, as the start does (X359)', { skip: POSIX ? false : 'file modes are POSIX', timeout: 120_000 }, async () => {
  const data = folder();
  let run;
  try {
    run = startProgram(data, { PROVARED_DOMAIN: 'guard.example.test' });
    await run.until('waits for the permission');
    await run.stop();
    const r = spawnSync(process.execPath, [START, 'keys', '--out', 'entries-again.json'], {
      cwd: data,
      env: { ...process.env, PROVARED_DATA: data, PROVARED_BIN: BIN, PROVARED_PEER: '' },
      encoding: 'utf8',
    });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(statSync(join(data, 'entries-again.json')).mode & 0o077, 0, 'entries-again.json is its owner\'s alone');
  } finally {
    if (run && run.child.exitCode === null) await run.stop();
    rmSync(data, { recursive: true, force: true });
  }
});

test('after "check" finds a problem, mending a file other than the settings and the permission starts the guard; the problems are said once (X358)', { timeout: 120_000 }, async () => {
  const data = folder();
  let run;
  try {
    run = startProgram(data, { PROVARED_DOMAIN: 'guard.example.test' });
    await run.until('waits for the permission');
    const settings = JSON.parse(readFileSync(join(data, 'executor-http.json'), 'utf8'));
    writeFileSync(join(data, 'executor-http.json'), `${JSON.stringify({ ...settings, listen: { host: '127.0.0.1', port: await freePort() } }, null, 2)}\n`);
    // The demonstration's credential file taken away: "check" finds that it cannot be read.
    renameSync(join(data, 'demo-token'), join(data, 'demo-token.away'));
    const signed = spawnSync(process.execPath, [SIGN], { env: { ...process.env, PROVARED_DATA: data }, encoding: 'utf8' });
    assert.equal(signed.status, 0, signed.stderr);
    await run.until('"check" found problems', 60_000);
    assert.match(run.out(), /DEMO_TOKEN/);
    const looked = Date.now();
    // Several looks (one every 200 ms here), each running "check" again.
    while (Date.now() - looked < 3000) await new Promise((r) => setTimeout(r, 100));
    assert.equal(run.out().split('"check" found problems').length - 1, 1, 'the same problems are said once');
    renameSync(join(data, 'demo-token.away'), join(data, 'demo-token'));
    await run.until('Starting the guard', 60_000);
    assert.match(run.out(), /"check": no problem/);
  } finally {
    if (run && run.child.exitCode === null) await run.stop();
    rmSync(data, { recursive: true, force: true });
  }
});

test('watchPeer: nothing while Caddy\'s port answers; once it has not answered so many times in a row, the guard is stopped', async () => {
  const server = net.createServer((s) => s.destroy());
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const peer = `127.0.0.1:${server.address().port}`;
  let lost = 0;
  const timer = watchPeer(() => lost++, { peer, every: 30, tries: 3 });
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(lost, 0, 'Caddy answers: the guard runs on');
  await new Promise((r) => server.close(r));
  const end = Date.now() + 5000;
  // eslint-disable-next-line no-unmodified-loop-condition -- lost is counted by watchPeer's callback, which runs while the loop waits.
  while (lost === 0 && Date.now() < end) await new Promise((r) => setTimeout(r, 30));
  assert.equal(lost, 1, 'Caddy gone from this network: the guard is stopped, once');
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(lost, 1);
  clearInterval(timer);
  assert.equal(watchPeer(() => lost++, { peer: '' }), null, 'an empty PROVARED_PEER: not looked for');
});

test('the start ends with code 1 once Caddy\'s port is gone from its network, so that Docker starts it again', { timeout: 120_000 }, async () => {
  const data = folder();
  let run;
  try {
    const port = await freePort();
    const closed = await freePort();
    run = startProgram(data, { PROVARED_DOMAIN: 'guard.example.test' });
    await run.until('waits for the permission');
    const settings = JSON.parse(readFileSync(join(data, 'executor-http.json'), 'utf8'));
    writeFileSync(join(data, 'executor-http.json'), `${JSON.stringify({ ...settings, listen: { host: '127.0.0.1', port } }, null, 2)}\n`);
    const signed = spawnSync(process.execPath, [SIGN], { env: { ...process.env, PROVARED_DATA: data }, encoding: 'utf8' });
    assert.equal(signed.status, 0, signed.stderr);
    await run.until('Starting the guard', 60_000);
    await run.stop();
    // Again, now looking for a port where nothing listens.
    run = startProgram(data, { PROVARED_DOMAIN: 'guard.example.test', PROVARED_PEER: `127.0.0.1:${closed}`, PROVARED_PEER_EVERY_MS: '100' });
    assert.equal(await run.ended, 1, run.out());
    assert.match(run.out(), /has not answered in this network 3 times in a row/);
  } finally {
    if (run && run.child.exitCode === null) await run.stop();
    rmSync(data, { recursive: true, force: true });
  }
});

test('a command that writes is refused while the start\'s mark answers, with no guard\'s lock to see (Caddy restarted alone); others are not; the mark gone, none is (X350)', async () => {
  const data = folder();
  const before = process.env.PROVARED_DATA;
  process.env.PROVARED_DATA = data;
  // Not spawnSync: the mark is served by this process, which must go on running while the command asks it.
  const command = (...args) =>
    new Promise((done) => {
      const child = spawn(process.execPath, [START, ...args], { cwd: data, env: { ...process.env, PROVARED_DATA: data, PROVARED_BIN: BIN }, stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => (stdout += d));
      child.stderr.on('data', (d) => (stderr += d));
      child.on('close', (status) => done({ status, stdout, stderr }));
    });
  let mark = null;
  try {
    assert.equal(writes('owner', []), true);
    assert.equal(writes('seal', ['--offline']), true);
    assert.equal(writes('acknowledge', ['--offline', '--all']), true);
    assert.equal(writes('http', []), true);
    assert.equal(writes('status', []), false);
    assert.equal(writes('keys', ['--out', 'x.json']), false);
    assert.equal(await guardRunning(), false, 'no mark: no guard');
    // The mark alone, as a guard left in Caddy's old network has it: no executor runs here, so no lock of the guard's is held.
    mark = await markRunning();
    assert.equal(await guardRunning(), true);
    for (const args of [['owner', '--reset'], ['owner'], ['seal', '--offline'], ['acknowledge', '--offline']]) {
      const r = await command(...args);
      assert.equal(r.status, 2, `${args.join(' ')}: ${r.stdout}${r.stderr}`);
      assert.match(r.stderr, /The guard is running on these files .*Stop the guard first \(docker compose stop guard\)/);
    }
    assert.doesNotMatch((await command('check')).stderr, /The guard is running on these files/, 'check writes nothing');
    await new Promise((r) => mark.close(r));
    mark = null;
    // The guard ended: a file left behind, at which nothing answers, refuses nothing.
    assert.equal(await guardRunning(), false);
    assert.doesNotMatch((await command('owner')).stderr, /The guard is running on these files/);
  } finally {
    if (mark) await new Promise((r) => mark.close(r));
    if (before === undefined) delete process.env.PROVARED_DATA;
    else process.env.PROVARED_DATA = before;
    rmSync(data, { recursive: true, force: true });
  }
});

test('a second start, with no command, is refused while the start\'s mark answers, and leaves that mark answering (X365)', async () => {
  const data = folder();
  const before = process.env.PROVARED_DATA;
  process.env.PROVARED_DATA = data;
  let mark = null;
  let child = null;
  try {
    mark = await markRunning();
    assert.equal(await guardRunning(), true);
    // A guard program that is not there: a start that went on past the mark would end at its first step.
    const r = await new Promise((done) => {
      child = spawn(process.execPath, [START], { cwd: data, env: { ...process.env, PROVARED_DATA: data, PROVARED_BIN: join(data, 'no-guard.mjs'), PROVARED_DOMAIN: 'guard.example.test', PROVARED_PEER: '' }, stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '';
      child.stdout.on('data', (d) => (out += d));
      child.stderr.on('data', (d) => (out += d));
      const timer = setTimeout(() => child.kill(), 20_000);
      child.on('close', (status) => {
        clearTimeout(timer);
        done({ status, out });
      });
    });
    assert.equal(r.status, 2, r.out);
    assert.match(r.out, /The guard is running on these files already .*this start does not begin/);
    assert.equal(await guardRunning(), true, 'the running start\'s mark still answers');
    assert.equal(existsSync(join(data, 'executor-http.json')), false, 'the second start wrote nothing');
  } finally {
    if (child && child.exitCode === null) child.kill();
    if (mark) await new Promise((r) => mark.close(r));
    if (before === undefined) delete process.env.PROVARED_DATA;
    else process.env.PROVARED_DATA = before;
    rmSync(data, { recursive: true, force: true });
  }
});

// --- what the recipe's files must hold ---

/** The lines of one service of compose.yaml, by its name. */
function service(compose, name) {
  const lines = compose.split('\n');
  const at = lines.indexOf(`  ${name}:`);
  assert.ok(at > 0, `compose.yaml has the service "${name}"`);
  const out = [];
  for (const line of lines.slice(at + 1)) {
    if (/^ {0,2}\S/.test(line)) break;
    out.push(line);
  }
  return out.filter((l) => !/^\s*#/.test(l)).join('\n');
}

test('compose.yaml: the guard publishes no port, shares Caddy\'s network, and only Caddy\'s 80 and 443 are published', () => {
  const compose = read('compose.yaml');
  const guard = service(compose, 'guard');
  const caddy = service(compose, 'caddy');
  const folders = service(compose, 'folders');
  assert.doesNotMatch(guard, /ports:|expose:/);
  assert.match(guard, /^ {4}network_mode: service:caddy$/m);
  assert.match(folders, /^ {4}network_mode: none$/m);
  assert.doesNotMatch(folders, /ports:/);
  // eslint-disable-next-line security/detect-unsafe-regex -- each repeated line ends in a line break the line cannot match, so matching takes time in proportion to the input.
  const published = /ports:\n((?: {6}- .*\n)+)/.exec(`${caddy}\n`);
  assert.deepEqual(published[1].trim().split('\n').map((l) => l.trim()), ['- "80:80"', '- "443:443"']);
  assert.equal(compose.match(/^\s+ports:/gm).length, 1, 'one list of ports in the file');
  assert.doesNotMatch(compose.replace(/#.*$/gm, ''), /8796/, 'the guard\'s port is named nowhere but in comments');
  const settings = compose.replace(/#.*$/gm, '');
  assert.doesNotMatch(settings, /network_mode: host|privileged:|pid:|ipc:|devices:|docker\.sock/);
  assert.doesNotMatch(settings, /deploy:|replicas|scale:/, 'one copy of the guard');
});

test('compose.yaml: plain folders beside it, bind-mounted; no Docker volume', () => {
  const compose = read('compose.yaml');
  assert.doesNotMatch(compose, /^volumes:/m, 'no named volume is declared');
  // eslint-disable-next-line security/detect-unsafe-regex -- each repeated line ends in a line break the line cannot match, so matching takes time in proportion to the input.
  const mounts = [...compose.matchAll(/^ {4}volumes:\n((?: {6}- .*\n)+)/gm)].flatMap((m) => m[1].trim().split('\n').map((l) => l.trim().slice(2)));
  assert.ok(mounts.length >= 6);
  for (const m of mounts) assert.match(m, /^\.\/(guard-data|caddy-data|caddy-config|Caddyfile):\//, m);
  assert.ok(mounts.includes('./guard-data:/data'));
  assert.ok(mounts.includes('./caddy-data:/data'));
  assert.ok(mounts.includes('./caddy-config:/config'));
  assert.ok(mounts.includes('./Caddyfile:/etc/caddy/Caddyfile:ro'));
  assert.doesNotMatch(compose, /tmpfs:\n\s+- \/data/);
});

test('compose.yaml: every container read-only, every capability dropped, no new privileges, a non-root user; Caddy gets none back', () => {
  const compose = read('compose.yaml');
  // eslint-disable-next-line security/detect-unsafe-regex -- each repeated line ends in a line break the line cannot match, so matching takes time in proportion to the input.
  const locked = /^x-locked: &locked\n((?: {2}.*\n)+)/m.exec(compose)[1];
  assert.match(locked, /read_only: true/);
  assert.match(locked, /cap_drop: \[ALL\]/);
  assert.match(locked, /security_opt: \["no-new-privileges:true"\]/);
  for (const name of ['folders', 'caddy', 'guard']) assert.match(service(compose, name), /^ {4}<<: \*locked$/m, name);
  assert.match(service(compose, 'guard'), /^ {4}user: "10001:10001"$/m);
  assert.match(service(compose, 'caddy'), /^ {4}user: "10002:10002"$/m);
  assert.doesNotMatch(service(compose, 'guard'), /cap_add/);
  assert.doesNotMatch(service(compose, 'caddy'), /cap_add/);
  assert.match(service(compose, 'folders'), /^ {4}cap_add: \[CHOWN, FOWNER\]$/m, 'the one root container gets back only what it needs');
  for (const name of ['caddy', 'guard']) {
    const s = service(compose, name);
    assert.match(s, /restart: unless-stopped/);
    assert.match(s, /mem_limit: \d+m/);
    assert.match(s, /pids_limit: \d+/);
    assert.match(s, /cpus: /);
  }
  // The folders' owners are the containers' users.
  assert.match(service(compose, 'folders'), /\/folders\/guard-data=10001:10001/);
  assert.match(service(compose, 'folders'), /\/folders\/caddy-data=10002:10002/);
  assert.match(service(compose, 'folders'), /\/folders\/caddy-config=10002:10002/);
  assert.match(read('start.mjs'), /GUARD_USER = '10001'/);
});

test('the images: Node.js and Caddy official, each following its release line by tag (no patch, no digest); the guard and its npm tree exact', () => {
  const compose = read('compose.yaml');
  const images = [...compose.matchAll(/^\s+image: (.*)$/gm)].map((m) => m[1]);
  assert.deepEqual(images.length, 1, 'one image pulled: Caddy\'s; the guard\'s is built');
  assert.equal(images[0], 'caddy:2.11-alpine', 'Caddy\'s 2.11 line');
  const dockerfile = read('Dockerfile');
  const from = [...dockerfile.matchAll(/^FROM (\S+)/gm)].map((m) => m[1]);
  assert.deepEqual(from[0], 'scratch');
  assert.equal(from[1], 'node:24-bookworm-slim', 'the Node.js 24 line');
  // Each file says which line it follows, and how to go back to one version.
  assert.match(dockerfile, /following the\n# release line of Node\.js 24/);
  assert.match(dockerfile, /To go back to one version, name it here/);
  assert.match(compose, /following Caddy's 2\.11\n\s+# release line/);
  assert.match(compose, /To go back to one version, name it here/);
  // The guard's packages: from the lockfile, with their hashes; a packed copy only where one is named.
  assert.match(dockerfile, /^ {6}npm ci --omit=dev --ignore-scripts --no-audit --no-fund; \\$/m);
  assert.match(dockerfile, /if \[ -n "\$EXECUTOR" \]; then/);
  assert.match(dockerfile, /^COPY --chmod=0644 package\.json package-lock\.json start\.mjs \.\/$/m);
  assert.match(dockerfile, /^USER 10001:10001$/m);
  const pkg = JSON.parse(read('package.json'));
  for (const [name, version] of Object.entries(pkg.dependencies)) assert.match(version, /^\d+\.\d+\.\d+$/, name);
  const executor = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.dependencies['provared-mcp-executor'], executor.version, 'the recipe builds this version of the executor');
  assert.equal(pkg.dependencies.provared, executor.dependencies.provared);
  // Only package.json, the lockfile and start.mjs reach the builder: never the data folders.
  assert.deepEqual(read('Dockerfile.dockerignore').split('\n').filter((l) => l && !l.startsWith('#')), ['*', '!package.json', '!package-lock.json', '!start.mjs']);
});

test('package-lock.json: version 3, the same dependencies as package.json, every package from npm at an exact version with a SHA-512 hash, and nothing else', () => {
  const pkg = JSON.parse(read('package.json'));
  const lock = JSON.parse(read('package-lock.json'));
  assert.equal(lock.lockfileVersion, 3);
  assert.equal(lock.name, pkg.name);
  assert.deepEqual(lock.packages[''].dependencies, pkg.dependencies);
  const entries = Object.entries(lock.packages).filter(([path]) => path !== '');
  assert.deepEqual(entries.map(([path]) => path).sort(), Object.keys(pkg.dependencies).map((n) => `node_modules/${n}`).sort(), 'the whole tree: the two packages, which need nothing else');
  for (const [path, e] of entries) {
    const name = path.slice('node_modules/'.length);
    assert.equal(e.version, pkg.dependencies[name], path);
    assert.equal(e.resolved, `https://registry.npmjs.org/${name}/-/${name}-${e.version}.tgz`, path);
    assert.match(e.integrity, /^sha512-[A-Za-z0-9+/]{86}==$/, path);
    assert.equal(e.dev, undefined, path);
    for (const [dep, range] of Object.entries(e.dependencies ?? {})) assert.equal(range, lock.packages[`node_modules/${dep}`]?.version, `${path} needs ${dep} at the exact version locked`);
  }
});

test('the Caddyfile: the domain from the environment, the guard\'s local address, nothing changed on the way, no log, no administration endpoint', () => {
  const caddyfile = read('Caddyfile').replace(/#.*$/gm, '');
  assert.match(caddyfile, /^\{\$PROVARED_DOMAIN\} \{$/m);
  assert.match(caddyfile, /^\treverse_proxy 127\.0\.0\.1:8796$/m);
  assert.match(caddyfile, /^\tadmin off$/m);
  assert.doesNotMatch(caddyfile, /header_up|header_down|rewrite|uri |strip_prefix|handle_path|\blog\b|email|tls /);
  assert.match(read('compose.yaml'), /PROVARED_DOMAIN: \$\{PROVARED_DOMAIN:\?/);
  assert.match(read('example.env'), /^PROVARED_DOMAIN=$/m);
});

test('package-lock.json: the executor\'s provisional entry is marked, and the release check stops on the mark until the lockfile is made from npm (X352)', () => {
  const CHECK = fileURLToPath(new URL('../../tools/release/check-recipe-lock.mjs', import.meta.url));
  const lock = JSON.parse(read('package-lock.json')).packages['node_modules/provared-mcp-executor'];
  const mark = JSON.parse(read('package-lock.provisional.json'));
  // The mark names the entry as it stands: an entry made again from npm with the mark left in place is caught here.
  assert.deepEqual([mark.package, mark.version, mark.integrity], ['provared-mcp-executor', lock.version, lock.integrity]);
  const run = (...args) => spawnSync(process.execPath, [CHECK, ...args], { encoding: 'utf8' });
  const shipped = run();
  assert.equal(shipped.status, 1, shipped.stdout + shipped.stderr);
  assert.match(shipped.stderr, /Stopped: the recipe's lockfile is provisional: its entry for provared-mcp-executor 0\.5\.0 was made from a pack/);
  // A copy with the mark taken away passes the check of the files; one whose versions differ does not.
  const copy = folder();
  try {
    for (const f of ['package.json', 'package-lock.json']) writeFileSync(join(copy, f), read(f));
    const unmarked = run('--recipe', copy);
    assert.equal(unmarked.status, 0, unmarked.stdout + unmarked.stderr);
    assert.match(unmarked.stdout, /from npm \(its hash not compared with npm: --registry does that\)/);
    const other = JSON.parse(read('package.json'));
    other.dependencies['provared-mcp-executor'] = '0.5.1';
    writeFileSync(join(copy, 'package.json'), JSON.stringify(other));
    const differs = run('--recipe', copy);
    assert.equal(differs.status, 1);
    assert.match(differs.stderr, /gives provared-mcp-executor 0\.5\.0, and package\.json 0\.5\.1/);
    assert.equal(run('--recipe', copy, '--wrong').status, 1);
    // A mistyped option is refused as one, with --recipe or without it, before any file is looked at (X367).
    for (const args of [['--registy'], ['--registy', '--recipe', copy], ['--recipe', copy, '--registy']]) {
      const wrong = run(...args);
      assert.equal(wrong.status, 1, args.join(' '));
      assert.match(wrong.stderr, /Stopped: "--registy" is not an option: give --registry, --recipe <folder>, or nothing\./, args.join(' '));
    }
    for (const args of [['--recipe'], ['--recipe', '--registry']]) {
      const bare = run(...args);
      assert.equal(bare.status, 1, args.join(' '));
      assert.match(bare.stderr, /Stopped: --recipe needs a folder after it\./, args.join(' '));
    }
  } finally {
    rmSync(copy, { recursive: true, force: true });
  }
});

test('the Caddyfile: the guard\'s administrator\'s addresses (/provared and under it) are Caddy\'s 404, not passed on (X349)', () => {
  const caddyfile = read('Caddyfile').replace(/#.*$/gm, '');
  assert.match(caddyfile, /^\t@own path \/provared \/provared\/\*$/m);
  assert.match(caddyfile, /^\trespond @own 404$/m);
  // The guard's own name for those addresses is still /provared.
  assert.match(readFileSync(new URL('../http.mjs', import.meta.url), 'utf8'), /export const ADMIN_PATH = '\/provared';/);
});

test('the README: what the boot unit does not cover, and Caddy away for longer (X366, X368)', () => {
  const readme = readFileSync(new URL('../recipes/claude-ai/README.md', import.meta.url), 'utf8').replace(/\s+/g, ' ');
  // The unit is a oneshot of the server's start: a restart of Docker alone does not run it again.
  assert.match(read('boot/provared-guard-boot.service'), /^Type=oneshot$/m);
  assert.ok(readme.includes('The unit runs once, at each start of the server, and not again until the next. Where Docker alone is restarted'));
  assert.ok(readme.includes('The unit also starts a guard that was stopped on purpose (`docker compose stop guard`)'));
  assert.ok(readme.includes('**Caddy away for longer.** Where Caddy is not running when Docker starts the guard again'));
  assert.ok(readme.includes('the guard stays stopped after Caddy is back'));
});

test('the README: the recipe from a signed release tag, checked with git tag -v against the repository\'s release signers; a patch not tried, and the way back', () => {
  const readme = readFileSync(new URL('../recipes/claude-ai/README.md', import.meta.url), 'utf8');
  assert.ok(readme.includes('git clone --depth 1 --branch <tag> https://github.com/provared/provared.git provared'));
  assert.ok(readme.includes('git -c gpg.ssh.allowedSignersFile=.github/release-signers tag -v <tag>'));
  const signers = readFileSync(new URL('../../.github/release-signers', import.meta.url), 'utf8');
  const fingerprint = /Fingerprint: (SHA256:\S+)/.exec(signers)[1];
  assert.ok(readme.includes(`Good "git" signature for sealwright with ED25519 key ${fingerprint}`), 'the README names the key the signers file names');
  assert.match(readme, /an update can bring a Node\.js or Caddy patch that\s+this recipe has not been tried with/);
  assert.ok(readme.includes('FROM node:24.22.3-bookworm-slim') && readme.includes('image: caddy:2.11.9-alpine'), 'how to go back to the versions tried');
});

test('the weekly timer: off until switched on, and it runs the README\'s update command', () => {
  const unit = read('weekly/provared-guard-update.service');
  const timer = read('weekly/provared-guard-update.timer');
  const steps = [...unit.matchAll(/^ExecStart=\/usr\/bin\/(.*)$/gm)].map((m) => m[1]);
  assert.deepEqual(steps, ['docker compose pull caddy', 'docker compose build --pull', 'docker compose up -d']);
  assert.match(timer, /^OnCalendar=Mon \*-\*-\* 04:00:00$/m);
  const readme = readFileSync(new URL('../recipes/claude-ai/README.md', import.meta.url), 'utf8');
  assert.ok(readme.includes(steps.join(' && ')), 'the README gives the same command');
});

test('a copy made under a strict umask: the image makes the guard\'s files readable, and the README says to make the Caddyfile so (X360)', () => {
  assert.match(read('Dockerfile'), /^COPY --chmod=0644 package\.json package-lock\.json start\.mjs \.\/$/m);
  const readme = readFileSync(new URL('../recipes/claude-ai/README.md', import.meta.url), 'utf8');
  assert.ok(readme.includes('`chmod 644 Caddyfile`'), 'the README gives the command for the Caddyfile');
  const check = readFileSync(new URL('./recipe-compose/docker-check.sh', import.meta.url), 'utf8');
  assert.ok(check.includes('chmod 600 "$WORK/package.json" "$WORK/package-lock.json" "$WORK/start.mjs"'), 'the Docker check builds from files of mode 600');
});

test('the boot unit: after a restart of the server, it starts whichever container is stopped, building and fetching nothing, once Docker has started (X357)', () => {
  const unit = read('boot/provared-guard-boot.service');
  const steps = [...unit.matchAll(/^ExecStart=(.*)$/gm)].map((m) => m[1]);
  assert.deepEqual(steps, ['/usr/bin/docker compose up -d --no-build --pull never']);
  assert.match(unit, /^Type=oneshot$/m);
  assert.match(unit, /^Requires=docker\.service$/m);
  assert.match(unit, /^After=docker\.service$/m);
  assert.match(unit, /^WantedBy=multi-user\.target$/m);
  assert.match(unit, /^WorkingDirectory=\/opt\/provared-guard$/m);
  const compose = read('compose.yaml');
  assert.match(compose, /network_mode: service:caddy/, 'the guard joins Caddy\'s network, which is why the order matters');
  const readme = readFileSync(new URL('../recipes/claude-ai/README.md', import.meta.url), 'utf8');
  assert.ok(readme.includes('### After a restart of the server') && readme.includes('sudo systemctl enable provared-guard-boot.service'), 'the README says how to switch it on');
  const check = readFileSync(new URL('./recipe-compose/docker-check.sh', import.meta.url), 'utf8');
  assert.ok(check.includes('boot/provared-guard-boot.service'), 'the Docker check runs the unit\'s own command');
});
