// The demonstration's start: set up once, then run the executor in front of
// the made-up tool server (server.mjs), over the stdio transport.
//
// DEMONSTRATION ONLY. The permission is signed by the library's development
// stand-in for a passkey (provared/dev), not by a person: its issuer's name
// ends with "(development)", and its records prove nothing about anyone.
//
// On the first start, in the folder PROVARED_DEMO_DIR (by default
// ".provared-mcp-demo" in the home folder), it:
//   1. makes a development stand-in for a passkey, used for this set-up
//      only and then forgotten;
//   2. writes the executor's settings, naming that stand-in's thumbprint as
//      the passkey it trusts, and a made-up credential for the server;
//   3. makes the agent's and the executor's keys with the executor's own
//      "keys" command, which prints what goes into the permission;
//   4. signs a permission for the two tools, valid for 30 days, with the
//      stand-in;
//   5. checks the settings with the executor's own "check" command.
// On a later start it uses what is there, unless the permission ends within
// the hour; then the folder is renamed aside (nothing is thrown away) and
// the five steps run again.
//
// Then it starts "provared-mcp-executor stdio" with this process's own
// input and output. Everything this file says goes to its standard error:
// standard output carries MCP messages and nothing else.

import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assembleSlip, formatTime, prepareSlip, thumbprint } from 'provared';
import { developmentPasskey } from 'provared/dev';

const HERE = dirname(fileURLToPath(import.meta.url));
const BIN = join(dirname(fileURLToPath(import.meta.resolve('provared-mcp-executor/package.json'))), 'bin.mjs');
const STATE = resolve(process.env.PROVARED_DEMO_DIR || join(homedir(), '.provared-mcp-demo'));
const SETTINGS = join(STATE, 'executor.json');
const DAYS = 30;
const NODE_FLAGS = ['--disable-warning=ExperimentalWarning'];

const say = (text) => process.stderr.write(`provared demo: ${text}\n`);

function executor(args) {
  const run = spawnSync(process.execPath, [...NODE_FLAGS, BIN, ...args], { encoding: 'utf8' });
  if (run.error) throw run.error;
  return run;
}

// The permission's end, read from the slip as saved; null where it cannot be read.
function slipEnds() {
  try {
    const slip = JSON.parse(readFileSync(join(STATE, 'slip.json'), 'utf8'));
    const payload = JSON.parse(Buffer.from(slip.payload, 'base64url').toString('utf8'));
    const ends = Date.parse(payload.validUntil);
    return Number.isFinite(ends) ? ends : null;
  } catch {
    return null;
  }
}

async function setUp() {
  if (existsSync(STATE) && readdirSync(STATE).length) {
    const aside = `${STATE}.ended-${new Date().toISOString().replace(/[:.]/g, '-')}`;
    renameSync(STATE, aside);
    say(`the permission in ${STATE} has ended or cannot be read; that folder is now ${aside}.`);
  }
  mkdirSync(join(STATE, 'keys'), { recursive: true });
  const passkey = await developmentPasskey();
  writeFileSync(join(STATE, 'demo-token'), `${randomBytes(16).toString('hex')}\n`, { mode: 0o600 });
  const settings = {
    name: 'Provared MCP executor, demonstration',
    service: 'executor',
    server: {
      command: process.execPath,
      args: [join(HERE, 'server.mjs')],
      env: { DEMO_TOKEN: { file: 'demo-token' } },
    },
    agent: { slip: 'slip.json', book: 'book.jsonl', keys: 'keys/agent.jwk', issuerKeys: [await thumbprint(passkey.key)] },
    executor: { keys: 'keys/executor.jwk', copy: 'copy.jsonl' },
    tools: {
      echo: { action: 'demo.echo' },
      add: { action: 'demo.add' },
    },
    contentRules: join(HERE, 'content-rules.json'),
    unlisted: 'refuse',
  };
  writeFileSync(SETTINGS, `${JSON.stringify(settings, null, 2)}\n`);

  const keys = executor(['keys', '--config', SETTINGS]);
  if (keys.status !== 0) throw new Error(`"keys" failed: ${keys.stderr.trim()}`);
  const entries = JSON.parse(keys.stdout);

  const now = Date.now();
  const prepared = await prepareSlip({
    issuer: { name: 'Provared demonstration (development)', key: passkey.key, rpId: passkey.rpId, origin: passkey.origin },
    agent: { ...entries.agent, name: 'Any agent, through the demonstration executor' },
    actions: ['demo.echo', 'demo.add'],
    limits: [{ action: 'demo.add', count: 1000, per: 86400 }],
    requires: entries.requires,
    never: [],
    with: [entries.with],
    validFrom: formatTime(now - 60 * 1000),
    validUntil: formatTime(now + DAYS * 24 * 3600 * 1000),
    purpose: 'A demonstration of the Provared MCP executor in front of a made-up tool server. Signed by a development stand-in for a passkey, which no person signed: it proves nothing about anyone.',
  });
  const slip = assembleSlip(prepared, await passkey.sign(prepared.challenge));
  writeFileSync(join(STATE, 'slip.json'), `${JSON.stringify(slip)}\n`);

  const check = executor(['check', '--config', SETTINGS]);
  if (check.status !== 0) throw new Error(`"check" found problems: ${check.stdout.trim()} ${check.stderr.trim()}`);
  say(`set up in ${STATE}: a permission for "echo" and "add", signed by a development stand-in for a passkey, valid for ${DAYS} days.`);
}

async function main() {
  const ends = slipEnds();
  if (!existsSync(SETTINGS) || ends === null || ends < Date.now() + 3600 * 1000) await setUp();
  else say(`using the demonstration set up in ${STATE}.`);

  const child = spawn(process.execPath, [...NODE_FLAGS, BIN, 'stdio', '--config', SETTINGS], { stdio: 'inherit' });
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
  child.on('exit', (code, signal) => {
    process.exitCode = typeof code === 'number' ? code : signal ? 1 : 0;
  });
}

main().catch((e) => {
  say(e.message);
  process.exitCode = 2;
});
