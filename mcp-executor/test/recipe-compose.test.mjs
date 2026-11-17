// The Docker Compose recipe for claude.ai (recipes/claude-ai/compose): its
// first-start program, run here against this repository's executor, and
// what its files must hold (no published port of the guard's, images pinned
// by version and digest, plain folders and no Docker volume, the containers
// locked down). The recipe in Docker itself is checked by
// test/recipe-compose/docker-check.sh, outside "npm test".

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
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
const { checkDomain, fillSettings, waiting, nextSteps, ownerState, watchPeer, CLIENT } = await import('../recipes/claude-ai/compose/start.mjs');
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
    assert.match(run.out(), /has not answered in this network 4 times in a row/);
  } finally {
    if (run && run.child.exitCode === null) await run.stop();
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

test('the images: Node.js and Caddy official, pinned by version and digest; the executor and library at exact versions', () => {
  const compose = read('compose.yaml');
  const images = [...compose.matchAll(/^\s+image: (.*)$/gm)].map((m) => m[1]);
  assert.deepEqual(images.length, 1, 'one image pulled: Caddy\'s; the guard\'s is built');
  assert.match(images[0], /^caddy:\d+\.\d+\.\d+-alpine@sha256:[0-9a-f]{64}$/);
  const dockerfile = read('Dockerfile');
  const from = [...dockerfile.matchAll(/^FROM (\S+)/gm)].map((m) => m[1]);
  assert.deepEqual(from[0], 'scratch');
  assert.match(from[1], /^node:\d+\.\d+\.\d+-bookworm-slim@sha256:[0-9a-f]{64}$/);
  assert.match(dockerfile, /npm install --omit=dev --ignore-scripts/);
  assert.match(dockerfile, /^USER 10001:10001$/m);
  const pkg = JSON.parse(read('package.json'));
  for (const [name, version] of Object.entries(pkg.dependencies)) assert.match(version, /^\d+\.\d+\.\d+$/, name);
  const executor = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.dependencies['provared-mcp-executor'], executor.version, 'the recipe builds this version of the executor');
  assert.equal(pkg.dependencies.provared, executor.dependencies.provared);
  // Only package.json and start.mjs reach the builder: never the data folders.
  assert.deepEqual(read('Dockerfile.dockerignore').split('\n').filter((l) => l && !l.startsWith('#')), ['*', '!package.json', '!start.mjs']);
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

test('the weekly timer: off until switched on, and it runs the README\'s update command', () => {
  const unit = read('weekly/provared-guard-update.service');
  const timer = read('weekly/provared-guard-update.timer');
  assert.match(unit, /^ExecStart=\/usr\/bin\/docker compose build --pull$/m);
  assert.match(unit, /^ExecStart=\/usr\/bin\/docker compose up -d$/m);
  assert.match(timer, /^OnCalendar=Mon \*-\*-\* 04:00:00$/m);
  const readme = readFileSync(new URL('../recipes/claude-ai/README.md', import.meta.url), 'utf8');
  assert.ok(readme.includes('docker compose build --pull && docker compose up -d'), 'the README gives the same command');
});
