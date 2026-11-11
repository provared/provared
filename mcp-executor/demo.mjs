// "provared-mcp-executor demo": the executor at work in a minute, with no
// passkey and no settings.
//
// DEMONSTRATION ONLY. The permission is signed by the library's development
// stand-in for a passkey (provared/dev), not by a person: its issuer's name
// ends with "(development)", the stand-in is made for this one run and then
// forgotten, and the records prove nothing about anyone.
//
// Everything is written in a new folder of its own in the system's
// temporary folder, which the run names at its start and leaves in place at
// its end, so that the book can be looked at. Nothing is written anywhere
// else. In that folder the run
//   1. writes the executor's settings, trusting the stand-in's thumbprint,
//      and a made-up credential for the made-up tool server
//      (demo/server.mjs, which reaches no network);
//   2. makes the agent's and the executor's keys with the executor's own
//      "keys" command;
//   3. has the stand-in sign a permission for the made-up server's two
//      tools, valid for one hour;
//   4. checks the settings with the executor's own "check" command;
//   5. starts the executor ("stdio") in front of the made-up server, as an
//      agent's MCP client would, and sends two tool calls: one the
//      permission allows, which is let through, and one that a rule on
//      content refuses, which is not sent on;
//   6. checks the book with the Provared checker.
// It says what happened at each step, and ends with exit code 0 only where
// each step went as it should.

import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { assembleSlip, checkBook, formatTime, prepareSlip, thumbprint } from 'provared';
import { DEVELOPMENT_MARK, developmentPasskey } from 'provared/dev';

const HERE = dirname(fileURLToPath(import.meta.url));
const BIN = join(HERE, 'bin.mjs');
const SERVER = join(HERE, 'demo', 'server.mjs');
const RULES = join(HERE, 'demo', 'content-rules.json');

export const DEMO_WARNING = `DEMONSTRATION ONLY. The permission below is signed by a development stand-in for a passkey, made for this run and then forgotten, not by a person. Its issuer's name ends with "${DEVELOPMENT_MARK}", and nothing this run writes proves anything about anyone.`;

function settingsFor(passkeyThumbprint) {
  return {
    name: 'Provared MCP executor, demonstration',
    service: 'executor',
    server: { command: process.execPath, args: [SERVER], env: { DEMO_TOKEN: { file: 'demo-token' } } },
    agent: { slip: 'slip.json', book: 'book.jsonl', keys: 'keys/agent.jwk', issuerKeys: [passkeyThumbprint] },
    executor: { keys: 'keys/executor.jwk', copy: 'copy.jsonl' },
    tools: { echo: { action: 'demo.echo' }, add: { action: 'demo.add' } },
    contentRules: RULES,
    unlisted: 'refuse',
  };
}

function command(args) {
  const run = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', windowsHide: true });
  if (run.error) throw run.error;
  return run;
}

/** Start the executor over stdio; ask() sends a request and awaits its answer; end() closes its input and awaits its exit. */
function startExecutor(settingsPath) {
  const child = spawn(process.execPath, [BIN, 'stdio', '--config', settingsPath], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  let said = '';
  child.stderr.setEncoding('utf8').on('data', (d) => {
    said += d;
  });
  const waiting = new Map();
  createInterface({ input: child.stdout }).on('line', (line) => {
    let m;
    try {
      m = JSON.parse(line);
    } catch {
      return;
    }
    waiting.get(m.id)?.(m);
    waiting.delete(m.id);
  });
  const exited = new Promise((done) => child.on('exit', (code) => done(code)));
  const killer = setTimeout(() => child.kill(), 60000);
  let next = 0;
  return {
    said: () => said,
    ask(method, params = {}) {
      const id = ++next;
      return new Promise((done, fail) => {
        waiting.set(id, done);
        exited.then(() => fail(new Error(`The executor ended before answering ${method}:\n${said.trim()}`)));
        child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
      });
    },
    async end() {
      child.stdin.end();
      const code = await exited;
      clearTimeout(killer);
      return code;
    },
  };
}

/**
 * Run the demonstration. "write" takes each line it says (by default, the
 * standard output). Gives {ok, folder, result}.
 */
export async function runDemo({ write = (line) => process.stdout.write(`${line}\n`) } = {}) {
  const say = write;
  let ok = true;
  const step = (good, text) => {
    if (!good) ok = false;
    say(`${good ? 'ok  ' : 'FAIL'}  ${text}`);
  };
  say(DEMO_WARNING);
  say('');
  const folder = mkdtempSync(join(tmpdir(), 'provared-mcp-demo-'));
  say(`Everything is written in a new temporary folder, and nowhere else: ${folder}`);

  // 1 to 4: the settings, the keys, the permission, the check.
  const passkey = await developmentPasskey();
  writeFileSync(join(folder, 'demo-token'), `${randomBytes(16).toString('hex')}\n`, { mode: 0o600 });
  const settingsPath = join(folder, 'executor.json');
  const trusted = await thumbprint(passkey.key);
  writeFileSync(settingsPath, `${JSON.stringify(settingsFor(trusted), null, 2)}\n`);
  const keys = command(['keys', '--config', settingsPath]);
  if (keys.status !== 0) throw new Error(`"keys" failed: ${keys.stderr.trim()}`);
  const entries = JSON.parse(keys.stdout);
  const now = Date.now();
  const prepared = await prepareSlip({
    issuer: { name: `Provared demonstration ${DEVELOPMENT_MARK}`, key: passkey.key, rpId: passkey.rpId, origin: passkey.origin },
    agent: { ...entries.agent, name: 'An agent, through the demonstration executor' },
    actions: ['demo.echo', 'demo.add'],
    limits: [{ action: 'demo.add', count: 100, per: 86400 }],
    requires: entries.requires,
    never: [],
    with: [entries.with],
    validFrom: formatTime(now - 60 * 1000),
    validUntil: formatTime(now + 3600 * 1000),
    purpose: 'A demonstration of the Provared MCP executor in front of a made-up tool server. Signed by a development stand-in for a passkey, which no person signed: it proves nothing about anyone.',
  });
  writeFileSync(join(folder, 'slip.json'), `${JSON.stringify(assembleSlip(prepared, await passkey.sign(prepared.challenge)))}\n`);
  step(true, '1. Set up: the settings, the agent\'s and the executor\'s keys (made by "keys"), and a permission for the tools "echo" and "add", signed by the stand-in.');
  const check = command(['check', '--config', settingsPath]);
  const report = (() => {
    try {
      return JSON.parse(check.stdout);
    } catch {
      return null;
    }
  })();
  step(check.status === 0, `2. "check": ${check.status === 0 ? 'no problems' : 'problems'} in the settings, the keys, the permission and the credential.`);
  if (check.status !== 0) {
    say(`        ${report?.problems?.join('\n        ') ?? check.stderr.trim()}`);
    return { ok: false, folder, result: null };
  }

  // 5: two calls through the executor.
  say('      3. The executor started in front of a made-up tool server, as an agent\'s MCP client starts it, and was sent two tool calls:');
  const executor = startExecutor(settingsPath);
  await executor.ask('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'provared-mcp-executor demo', version: '1' } });
  const allowed = await executor.ask('tools/call', { name: 'echo', arguments: { text: 'hello' } });
  step(allowed.result?.isError !== true && allowed.result?.content?.[0]?.text === 'hello', `   echo "hello": let through; the server answered ${JSON.stringify(allowed.result?.content?.[0]?.text ?? allowed.error?.message)}, and a receipt was written.`);
  const refused = await executor.ask('tools/call', { name: 'echo', arguments: { text: 'my password is swordfish' } });
  const why = refused.result?.content?.[0]?.text ?? refused.error?.message;
  step(refused.result?.isError === true && refused.result?._meta?.['red.prova/refused'] === 'content-rule', `   echo "my password is swordfish": refused and not sent on, since a rule on content forbids the word "password"; a denial was written. The agent was told: ${JSON.stringify(why)}`);
  const code = await executor.end();
  if (code !== 0) step(false, `The executor ended with code ${code}: ${executor.said().trim()}`);

  // 6: the book, checked.
  const bookPath = join(folder, 'book.jsonl');
  const result = await checkBook(readFileSync(bookPath, 'utf8'), { issuerKeys: [trusted] });
  const kinds = result.entries.map((e) => e.kind);
  const countersigned = result.entries.filter((e) => e.kind === 'stub').every((e) => e.countersignature?.state === 'valid');
  const clean = result.summary.intact && result.summary.fullyChecked && result.summary.withinSlips && !result.summary.problemFound;
  step(clean && countersigned && kinds.join(',') === 'slip,stub,denial', `4. The book, checked with the Provared checker: ${clean ? 'it checks clean' : 'it does NOT check clean'} (intact: ${result.summary.intact}, fully checked: ${result.summary.fullyChecked}, within the permission: ${result.summary.withinSlips}); it holds ${kinds.join(', ')}; the receipt is ${countersigned ? '' : 'NOT '}countersigned by the executor.`);
  say('');
  say(`The book is ${bookPath}. The folder is left in place for you to look at; nothing else was written.`);
  say('Again: the permission was signed by a development stand-in, not by a person. For real use, a person signs it with a passkey: start with "provared-mcp-executor init" (see the README).');
  return { ok, folder, result };
}
