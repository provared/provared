#!/usr/bin/env node
// provared-mcp-executor: the command.
//
//   provared-mcp-executor demo                             a demonstration with no passkey and no settings, in a
//                                                          new temporary folder: one call let through, one
//                                                          refused, and the book checked (demo.mjs)
//   provared-mcp-executor demo --stdio                     the same set-up, then the executor over stdio in
//                                                          front of the made-up server, as "stdio" runs, until
//                                                          its input closes: for an MCP client or inspector
//   provared-mcp-executor init    [--http]                 copy the example settings and rules into this folder,
//                                                          as executor.json (or executor-http.json) and
//                                                          content-rules.json; nothing is overwritten
//   provared-mcp-executor stdio   --config executor.json   run as the tool server the agent's client starts:
//                                                          start the real server, check and receipt each call
//   provared-mcp-executor http    --config executor-http.json
//                                                          run as a Streamable HTTP MCP server in front of an
//                                                          upstream HTTP MCP server, for several agents, each
//                                                          signing in with a secret of its own
//   provared-mcp-executor secret                           make a new secret for an agent, and print it with
//                                                          its hash (the hash goes into the settings)
//   provared-mcp-executor check   --config executor.json   say what each rule maps to, and what is wrong
//   provared-mcp-executor keys    --config executor.json [--out <file>]
//                                                          make the key files, if there are none, and print
//                                                          what goes into the permission: agent.keys, the
//                                                          executor's entry for "with", and the agent.software
//                                                          entry for the rules on content, where there are any
//                                                          (or write it to a new file, with --out). It needs no
//                                                          passkey's thumbprint and no secret hash yet, and
//                                                          writes nothing until all it needs has been read
//   provared-mcp-executor compare --config executor.json [--book <file>] [--agent <name>]
//                                                          hold the executor's copy against a book (over HTTP,
//                                                          the named agent's copy and book)
//   provared-mcp-executor seal    --config <settings> [--agent <name>] [--offline]
//                                                          seal a book now, with the recorder's three keys
//                                                          or, where the settings name one, by the central
//                                                          sealer that holds them
//   provared-mcp-executor acknowledge --config <settings> [--agent <name>] [--set-aside <call,…>] [--offline]
//                                                          acknowledge the calls sent under a permission no
//                                                          longer in force that have no receipt, and set
//                                                          aside those named
//   provared-mcp-executor status  --config <settings> [--offline]
//                                                          the last seal, whether each book passes its check,
//                                                          and the calls waiting to be acknowledged
//
// Over HTTP, "seal", "acknowledge" and "status" ask the running executor,
// with the administrator's secret from the environment
// (PROVARED_MCP_EXECUTOR_ADMIN_SECRET); with --offline they work on the
// files of an executor that is not running, and need no secret. Over stdio
// there is no address to ask: "seal" and "acknowledge" take --offline
// only, and "status" reads the files. A command with --offline takes the
// lock on the files (lock.mjs), so it is refused while an executor runs on
// them. Before the secret is sent, the executor must show that it is the
// executor (identity.mjs, askRunning).
//
// "check", "keys" and "compare" read either kind of settings: the stdio
// executor's (with "server" and "agent") or the HTTP executor's (with
// "upstream" and "agents"). "stdio" writes nothing to its standard output
// but MCP messages; what it has to say goes to its standard error, one JSON
// object to a line, as does "http". "demo --stdio" first says one plain
// line there: that it is a demonstration, when its permission ends, and
// where the book is.
//
// Node.js's notice that its ML-DSA-87 signing is experimental is set aside
// (quiet.mjs, imported first); every other warning is printed.

import './quiet.mjs';
import { randomBytes } from 'node:crypto';
import { constants, copyFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import nodeHttp from 'node:http';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { keySetFingerprint } from 'provared';
import { loadCopyKey } from './copy.mjs';
import { compareCopyWithBook } from './compare.mjs';
import { checkConfig, loadRules, openExecutor, readSettings, softwareEntry, statusFromFiles } from './executor.mjs';
import { loadKeyFile, makeKeyFile, readIfThere } from './files.mjs';
import { ADMIN_PATH, checkHttpConfig, httpStatusFromFiles, newSecret, openHttpExecutor, readHttpSettings, secretHash } from './http.mjs';
import { checkIdentity, plainAddress } from './identity.mjs';
import { makeRecorderKeyFile, readRecorderKeyFile } from './sealing.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(readFileSync(join(HERE, 'package.json'), 'utf8')).version;
/** The variable of the environment that holds the administrator's secret, for the commands that ask a running HTTP executor. */
const ADMIN_SECRET_ENV = 'PROVARED_MCP_EXECUTOR_ADMIN_SECRET';

const USAGE = `provared-mcp-executor ${VERSION}: an executor for MCP tool servers. It holds the server's credentials, checks each tool call against a permission a person signed, sends on the calls the permission allows, and writes a signed, countersigned receipt for each. Evidence, not a verdict.

  provared-mcp-executor demo    [--stdio]    try it with no passkey and no settings
  provared-mcp-executor init    [--http]     copy the example settings into this folder
  provared-mcp-executor stdio   --config executor.json
  provared-mcp-executor http    --config executor-http.json
  provared-mcp-executor secret
  provared-mcp-executor check   --config <settings>
  provared-mcp-executor keys    --config <settings> [--out <file>]
  provared-mcp-executor compare --config <settings> [--book <file>] [--agent <name>] [--sealer <fingerprint>]
  provared-mcp-executor seal    --config <settings> [--agent <name>] [--offline]
  provared-mcp-executor acknowledge --config <settings> [--agent <name>] [--set-aside <call,…>] [--offline]
  provared-mcp-executor status  --config <settings> [--offline]
  provared-mcp-executor --version

Over HTTP, "seal", "acknowledge" and "status" ask the running executor, with the administrator's secret in
${ADMIN_SECRET_ENV}; with --offline they work on the files of an executor that is not running, and need
no secret. Over stdio there is no address to ask: "seal" and "acknowledge" take --offline only, and "status"
reads the files. A command with --offline is refused while an executor runs on the same files. The secret is
sent only once the executor has shown, with its own keys, that it is the executor; the command reads
"executor.keys" to check.

Where the settings name a central sealer ("recorder.sealer"), a seal is asked of it; "status" asks it how
many lines of each book it holds; and a command that opens the files to write (--offline) needs its answer
first, as a start does.

Exit codes: 0 done, or all is well; 1 not done, or something to look at (status: a book that fails its check,
a call waiting, an agent stopped; compare: a disagreement; acknowledge: a call still waits); 2 the command
could not run; 3 (compare) the calls set aside are the only disagreement.`;

/** What the commands that work on the files say first, on the standard error. */
const OFFLINE_NOTICE = 'the files are opened here, for this command alone; it is refused if an executor is running on them.';

/** What to do with what "keys" prints, said in one line on the standard error. */
const KEYS_NEXT = 'What to do with this: it goes into the permission the person signs with a passkey: "agent" as the permission\'s agent (over HTTP, one for each agent), the "with" entry in its "with", and "requires" as it is. Then put the passkey\'s thumbprint in issuerKeys and run "check" (README, "Set it up").';

/** The example files "init" copies into the current folder: [file in the package, name in the folder]. */
const EXAMPLES = {
  stdio: [['executor.example.json', 'executor.json'], ['content-rules.example.json', 'content-rules.json']],
  http: [['executor-http.example.json', 'executor-http.json'], ['content-rules.example.json', 'content-rules.json']],
};

/** Whether a folder is there or can be made: the nearest part of its path that exists is a folder. */
function canMakeFolder(folder) {
  let at = folder;
  while (!existsSync(at)) {
    const up = dirname(at);
    if (up === at) return false;
    at = up;
  }
  try {
    return statSync(at).isDirectory();
  } catch {
    return false;
  }
}

/** Whether two paths name the same file (letter case aside on Windows). */
function samePath(a, b) {
  const [x, y] = [resolve(a), resolve(b)];
  return process.platform === 'win32' ? x.toLowerCase() === y.toLowerCase() : x === y;
}

/** Whether the settings are the HTTP executor's (several agents, one upstream) rather than the stdio executor's. */
const isHttp = (config) => config !== null && typeof config === 'object' && !Array.isArray(config) && Object.hasOwn(config, 'agents');

function option(args, name) {
  const at = args.indexOf(name);
  if (at === -1) return undefined;
  if (args.indexOf(name, at + 1) !== -1) throw new Error(`${name} is given twice.`);
  const value = args[at + 1];
  if (value === undefined || value.startsWith('--')) throw new Error(`${name} needs a value.`);
  return value;
}

function readConfig(args) {
  const path = option(args, '--config');
  if (!path) throw new Error('Name the settings file: --config executor.json');
  const full = isAbsolute(path) ? path : resolve(path);
  let config;
  try {
    config = JSON.parse(readFileSync(full, 'utf8').replace(/^﻿/, ''));
  } catch (e) {
    throw new Error(`The settings file ${full} could not be read as JSON (${e.code ?? e.message}).`);
  }
  return { config, root: dirname(full) };
}

/** The agent a command is for: over HTTP, the one --agent names; over stdio, the only one (null), and --agent is not taken. */
function agentOf(config, args, what) {
  const name = option(args, '--agent');
  if (!isHttp(config)) {
    if (name !== undefined) throw new Error('These settings are the stdio executor\'s, which has one agent: --agent is not taken.');
    return null;
  }
  const names = config.agents !== null && typeof config.agents === 'object' ? Object.keys(config.agents) : [];
  if (!name) throw new Error(`Name the agent ${what}: --agent <name> (one of ${names.join(', ')}).`);
  if (!names.includes(name)) throw new Error(`The settings name no agent "${name}" (they name ${names.join(', ')}).`);
  return name;
}

/** Refuse any option a command does not know, so that a mistyped option is not taken for none. "flags" take no value; "valued" take one. */
function onlyOptions(command, args, flags, valued) {
  for (let i = 1; i < args.length; i++) {
    if (valued.includes(args[i])) i += 1;
    else if (!flags.includes(args[i])) throw new Error(`${command} takes no "${args[i]}"; only ${[...valued.map((v) => `${v} <value>`), ...flags].join(', ')}. Nothing was done.`);
  }
}

/** The exit code of "status": 0 where every book shown passes its check (or is not there yet), no call waits to be acknowledged and no agent has stopped; 1 otherwise. */
function statusCode(value) {
  const agents = value?.agent ? [value.agent] : Object.values(value?.agents ?? {});
  return agents.every((a) => a && !a.problem && a.sound !== false && !a.stopped && (a.receiptsMissing ?? []).length === 0) ? 0 : 1;
}

/** Open the executor on its files, for a command run with --offline: no server is started, nothing listens, no credential is read. */
function openOffline(config, root) {
  return isHttp(config) ? openHttpExecutor(config, { root, offline: true }) : openExecutor(config, { root, offline: true });
}

/**
 * Ask the running HTTP executor at one of its own addresses, with the
 * administrator's secret from the environment. Gives {status, value}.
 *
 * The secret is sent only to the executor of these settings. Whatever
 * listens at the settings' address is first sent a fresh challenge, with no
 * secret (POST /provared/hello), and must answer with the executor's two
 * signatures over it and over the address and port this command connected
 * to, which are checked against the public keys in the executor's key file
 * (identity.mjs). The secret then goes on that same connection and no
 * other. The command must be able to read "executor.keys".
 *
 * The answer is waited for as long as a call may take ("timeout") and half
 * a minute more: a seal waits its turn behind a call in progress.
 */
async function askRunning(config, root, method, path, body, hint) {
  const secret = process.env[ADMIN_SECRET_ENV];
  if (!secret) throw new Error(`Put the administrator's secret in the environment: ${ADMIN_SECRET_ENV}.`);
  if (typeof config.executor?.keys !== 'string' || config.executor.keys === '') throw new Error('The settings name no key file of the executor ("executor.keys"), so the command cannot tell whether it is the executor that answers. The administrator\'s secret was not sent.');
  const { keys } = await loadKeyFile(isAbsolute(config.executor.keys) ? config.executor.keys : resolve(root, config.executor.keys), 'agent');
  const listen = config.listen ?? {};
  // An executor that listens on every address is asked at the local one.
  const host = listen.host === undefined || listen.host === '0.0.0.0' ? '127.0.0.1' : listen.host === '::' ? '::1' : listen.host;
  const port = listen.port ?? 8796;
  const wait = (Number.isInteger(config.timeout) ? config.timeout : 300000) + 30000;
  // One connection for both requests.
  const agent = new nodeHttp.Agent({ keepAlive: true, maxSockets: 1 });
  const send = (how, where, headers, value, provedOn) =>
    new Promise((done, failed) => {
      const data = value === undefined ? undefined : Buffer.from(JSON.stringify(value));
      const req = nodeHttp.request({ host, port, method: how, path: where, agent, headers: { ...headers, ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}) } }, (res) => {
        // The connection the answer came on, and where it leads: read now, before the answer's end hands the connection back.
        const socket = res.socket;
        const address = socket.remoteAddress;
        const remotePort = socket.remotePort;
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('error', failed);
        res.on('end', () => {
          let answer;
          try {
            answer = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          } catch {
            answer = undefined;
          }
          done({ status: res.statusCode, value: answer, socket, address, port: remotePort });
        });
      });
      req.setTimeout(wait, () => req.destroy(new Error(`What listens at ${host}:${port} gave no answer within ${wait} ms.`)));
      req.on('error', (e) => failed(e.code === 'ECONNREFUSED' ? new Error(`The executor is not running at ${host}:${port}. ${hint}`) : e));
      req.on('socket', (socket) => {
        // Nothing of the request, its headers included, is written before this: the secret goes only on the connection the executor proved itself on.
        if (provedOn && socket !== provedOn) return req.destroy(new Error(`The connection on which the executor at ${host}:${port} showed that it is the executor was closed before the administrator's secret could be sent on it. The secret was not sent. Try again.`));
        req.end(data);
      });
    });
  try {
    const challenge = randomBytes(32).toString('base64url');
    const hello = await send('POST', `${ADMIN_PATH}/hello`, {}, { challenge });
    const notProved = (why) => new Error(`What answers at ${host}:${port} did not show that it is the executor of these settings: ${why} The administrator's secret was not sent.`);
    if (hello.status === 404 && hello.value?.code === 'not-found' && /no administrator's secret/.test(hello.value.message ?? '')) throw notProved('it says that its settings name no administrator\'s secret ("admin"), so its own addresses answer nothing.');
    if (hello.status !== 200 || hello.value === undefined) throw notProved(`it answered ${hello.status} where the executor signs the challenge it is sent.`);
    if (!(await checkIdentity(keys, challenge, plainAddress(hello.address), hello.port, hello.value.signatures))) throw notProved('its signatures do not check under the public keys in the executor\'s key file ("executor.keys"), over this command\'s challenge and the address it connected to.');
    const answer = await send(method, path, { authorization: `Bearer ${secret}` }, body, hello.socket);
    if (answer.value === undefined) throw new Error('The executor gave an answer that is not JSON.');
    return { status: answer.status, value: answer.value };
  } finally {
    agent.destroy();
  }
}

/** "stdio" (and "demo --stdio"): run the executor over this process's standard input and output until the server ends. */
async function runStdio({ config, root }) {
  const executor = await openExecutor(config, { root });
  const ended = await executor.attach(process.stdin, process.stdout);
  // The server has ended and every receipt is written: the executor ends
  // too, whether or not the client still holds its input open (the
  // client restarts it, as the specification says).
  process.exit(typeof ended.code === 'number' ? ended.code : 1);
}

async function main(args) {
  const command = args[0];
  if (!command || command === '--help' || command === '-h') {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  if (command === '--version' || command === '-v') {
    process.stdout.write(`provared-mcp-executor ${VERSION}\n`);
    return 0;
  }
  if (command === 'demo') {
    const unknown = args.slice(1).filter((a) => a !== '--stdio');
    if (unknown.length) throw new Error(`demo takes no ${unknown.map((a) => `"${a}"`).join(', ')}; only --stdio.`);
    const { prepareStdioDemo, runDemo } = await import('./demo.mjs');
    if (!args.includes('--stdio')) return (await runDemo()).ok ? 0 : 1;
    // Nothing on the standard output but MCP messages.
    const { settingsPath, notice } = await prepareStdioDemo();
    process.stderr.write(`provared-mcp-executor: ${notice}\n`);
    return runStdio(readConfig(['--config', settingsPath]));
  }
  if (command === 'init') {
    const http = args.includes('--http');
    const unknown = args.slice(1).filter((a) => a !== '--http');
    if (unknown.length) throw new Error(`init takes no ${unknown.map((a) => `"${a}"`).join(', ')}; only --http.`);
    const files = EXAMPLES[http ? 'http' : 'stdio'].map(([from, to]) => [join(HERE, from), resolve(to)]);
    // Nothing is written unless every file can be: none is overwritten.
    const there = files.filter(([, to]) => existsSync(to)).map(([, to]) => to);
    if (there.length) throw new Error(`Nothing was written: ${there.join(' and ')} already ${there.length > 1 ? 'exist' : 'exists'}. Move ${there.length > 1 ? 'them' : 'it'}, or run init in another folder.`);
    for (const [from, to] of files) copyFileSync(from, to, constants.COPYFILE_EXCL);
    const settings = basename(files[0][1]);
    const steps = http
      ? [
          `In ${settings}, put in each value written <like this>: the upstream's credential file, and each agent's secret hash ("provared-mcp-executor secret" makes a secret and its hash); set "upstream.url" to your HTTP MCP server and "tools" to its tools; and change content-rules.json to rules of your own, or take "contentRules" out.`,
          `provared-mcp-executor keys --config ${settings}`,
          'The person signs a permission for each agent with a passkey, holding what "keys" printed; save each where its "slip" says (in the folder slips/, which you make), and put the passkey\'s thumbprint in its "issuerKeys".',
          `provared-mcp-executor check --config ${settings}   (it lists every problem left)`,
        ]
      : [
          `In ${settings}, put in each value written <like this>: your MCP tool server's program, the folder it runs in and the file that holds its credential; set "tools" to its tools; and change content-rules.json to rules of your own, or take "contentRules" out.`,
          `provared-mcp-executor keys --config ${settings}`,
          'The person signs the permission with a passkey, holding what "keys" printed; save it as slip.json, and put the passkey\'s thumbprint in "agent.issuerKeys".',
          `provared-mcp-executor check --config ${settings}   (it lists every problem left)`,
        ];
    process.stdout.write(`Wrote ${files.map(([, to]) => to).join(' and ')}, copied from the examples in ${HERE}.\nNext:\n${steps.map((s, i) => `  ${i + 1}. ${s}`).join('\n')}\n`);
    return 0;
  }
  if (command === 'stdio') return runStdio(readConfig(args));
  if (command === 'http') {
    const { config, root } = readConfig(args);
    const executor = await openHttpExecutor(config, { root });
    await executor.listen();
    const stop = async () => {
      await executor.close();
      process.exit(0);
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    return null;
  }
  if (command === 'secret') {
    const secret = newSecret();
    process.stdout.write(`The secret (give it to the agent, or, where it is the administrator's, keep it from every agent; it is not stored anywhere):\n  ${secret}\nIts hash (put it in the settings: as the agent's "secretHash", or as "admin.secretHash" for the administrator's):\n  ${secretHash(secret)}\n`);
    return 0;
  }
  if (command === 'check') {
    const { config, root } = readConfig(args);
    const report = isHttp(config) ? await checkHttpConfig(config, root) : await checkConfig(config, root);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return report.problems.length ? 1 : 0;
  }
  if (command === 'keys') {
    const { config, root } = readConfig(args);
    const http = isHttp(config);
    // The passkeys' thumbprints and the secret hashes are not needed yet: they come after.
    const { settings, problems } = http ? readHttpSettings(config, root, { keysOnly: true }) : readSettings(config, root, { keysOnly: true });
    if (problems.length) throw new Error(`The settings have problems:\n- ${problems.join('\n- ')}`);
    const out = option(args, '--out');
    const outAt = out ? (isAbsolute(out) ? out : resolve(out)) : null;
    // Everything "keys" needs is read and checked before anything is
    // written: the rules file, each key file already there, and that the
    // folder of each file it would write can be made (its nearest folder
    // that exists is a folder, not a file). A write can still fail after
    // that (a full disk, a folder it may not write in).
    const software = settings.contentRules ? [softwareEntry(settings.name, (await loadRules(settings.contentRules)).fingerprint)] : undefined;
    const agents = http ? [...settings.agents].map(([name, paths]) => [name, paths.keys]) : [[null, settings.agent.keys]];
    const keyPaths = [settings.executor.keys, ...agents.map(([, path]) => path)];
    for (const path of keyPaths) {
      if (existsSync(path)) await loadKeyFile(path, 'agent');
      else if (!canMakeFolder(dirname(path))) throw new Error(`Nothing was written: the key file ${path} cannot be made, since a file stands where its folder would be.`);
    }
    // The recorder's three keys for sealing, where the settings name a recorder: a file of its own.
    const recorderAt = settings.recorder?.keys ?? null;
    if (recorderAt) {
      if (keyPaths.some((path) => samePath(path, recorderAt))) throw new Error(`Nothing was written: recorder.keys (${recorderAt}) is also the key file of the executor or of an agent. The recorder has a key file of its own.`);
      if (existsSync(recorderAt)) await readRecorderKeyFile(recorderAt);
      else if (!canMakeFolder(dirname(recorderAt))) throw new Error(`Nothing was written: the key file ${recorderAt} cannot be made, since a file stands where its folder would be.`);
    }
    if (outAt) {
      if ([...keyPaths, ...(recorderAt ? [recorderAt] : [])].some((path) => samePath(path, outAt))) throw new Error(`Nothing was written: ${outAt} (--out) is a key file of the settings. Name another file.`);
      if (existsSync(outAt)) throw new Error(`Nothing was written: ${outAt} (--out) already exists. Name a new file.`);
      if (!canMakeFolder(dirname(outAt))) throw new Error(`Nothing was written: ${outAt} (--out) cannot be made, since a file stands where its folder would be.`);
    }
    const executor = await makeKeyFile(settings.executor.keys, 'agent');
    // The agent.software entry for the rules on content, where the settings name a rules file.
    const entry = (agent, who) => ({ agent: { name: who, keys: agent, ...(software ? { software } : {}) }, with: { id: settings.service, name: settings.name, keys: executor }, requires: [{ need: 'countersignature' }] });
    let result;
    if (http) {
      result = {};
      for (const [name, path] of agents) result[name] = entry(await makeKeyFile(path, 'agent'), `${name}, through ${settings.name}`);
    } else result = entry(await makeKeyFile(agents[0][1], 'agent'), `An agent, through ${settings.name}`);
    const text = `${JSON.stringify(result, null, 2)}\n`;
    if (outAt) {
      mkdirSync(dirname(outAt), { recursive: true });
      writeFileSync(outAt, text, { flag: 'wx' });
      process.stderr.write(`provared-mcp-executor: wrote ${outAt}. ${KEYS_NEXT}\n`);
    } else {
      process.stdout.write(text);
      process.stderr.write(`provared-mcp-executor: ${KEYS_NEXT}\n`);
    }
    if (config.recorder?.sealer !== undefined) {
      // A central sealer starts a recorder's books only from permissions for the agents it was named with, each by the fingerprint of its key set.
      const named = http ? Object.entries(result).map(([name, e]) => [`the agent "${name}"`, e.agent.keys]) : [['the agent', result.agent.keys]];
      for (const [who, keys] of named) process.stderr.write(`provared-mcp-executor: the fingerprint of the key set of ${who} is ${await keySetFingerprint(keys)}: the central sealer is told it when this recorder is added (provared-sealer add-recorder --agent).\n`);
    }
    if (recorderAt) {
      // The recorder's keys go into no permission: what a reader needs is the fingerprint of the key set.
      const fingerprint = await keySetFingerprint(await makeRecorderKeyFile(recorderAt));
      process.stderr.write(`provared-mcp-executor: the recorder's keys, with which the books are sealed, are in ${recorderAt}. The fingerprint of its key set is ${fingerprint}: whoever checks a book names it as the recorder they expect (the checker's --sealer).\n`);
    }
    return 0;
  }
  if (command === 'compare') {
    onlyOptions(command, args, [], ['--config', '--book', '--agent', '--sealer']);
    const { config, root } = readConfig(args);
    const { settings, problems } = isHttp(config) ? readHttpSettings(config, root) : readSettings(config, root);
    if (problems.length) throw new Error(`The settings have problems:\n- ${problems.join('\n- ')}`);
    let paths;
    if (isHttp(config)) {
      const name = option(args, '--agent');
      if (!name) throw new Error(`Name the agent whose copy and book to compare: --agent <name> (one of ${[...settings.agents.keys()].join(', ')}).`);
      paths = settings.agents.get(name);
      if (!paths) throw new Error(`The settings name no agent "${name}" (they name ${[...settings.agents.keys()].join(', ')}).`);
    } else paths = { ...settings.agent, copy: settings.executor.copy, copyKey: settings.executor.copyKey };
    const bookPath = option(args, '--book');
    const bookAt = bookPath ? (isAbsolute(bookPath) ? bookPath : resolve(bookPath)) : paths.book;
    if (!existsSync(bookAt)) throw new Error(`The book ${bookAt} does not exist.`);
    const copyKey = loadCopyKey(paths.copyKey, { create: false });
    if (!copyKey) throw new Error(`The copy key ${paths.copyKey} does not exist: the executor has not run yet, or the key was moved. Nothing to compare.`);
    // The recorder a seal in the book must be signed by: the one --sealer names by the fingerprint of its key set (as the
    // checker's --sealer; several with commas), or else the recorder of the settings, where its key file is here. The
    // answer says which was expected (book.sealersExpected), or null where a seal's keys were compared with nothing.
    const named = option(args, '--sealer');
    let sealKeys = null;
    if (named !== undefined) {
      sealKeys = named.split(',').map((s) => s.trim()).filter(Boolean);
      if (sealKeys.length === 0 || !sealKeys.every((f) => /^[A-Za-z0-9_-]{43}$/.test(f))) throw new Error('--sealer must be the fingerprint of a recorder\'s key set (43 characters of base64url), or several with commas between them.');
    } else if (settings.recorder?.sealer) sealKeys = [settings.recorder.sealer.keySet];
    else if (settings.recorder && existsSync(settings.recorder.keys)) sealKeys = [await keySetFingerprint(await readRecorderKeyFile(settings.recorder.keys))];
    const result = await compareCopyWithBook({ copyPath: paths.copy, copyKey, name: settings.name, service: settings.service, book: readIfThere(bookAt), options: { issuerKeys: paths.issuerKeys, ...(sealKeys ? { sealKeys } : {}) } });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    // 0: they agree. 3: they agree but for calls the administrator set aside, which is all that is known to be wrong. 1: anything else.
    return result.summary.agree ? 0 : result.summary.onlySetAside ? 3 : 1;
  }
  if (command === 'status') {
    onlyOptions(command, args, ['--offline'], ['--config']);
    const { config, root } = readConfig(args);
    let value;
    if (!isHttp(config)) value = await statusFromFiles(config, root);
    else if (args.includes('--offline')) value = await httpStatusFromFiles(config, root);
    else {
      const answer = await askRunning(config, root, 'GET', `${ADMIN_PATH}/status`, undefined, 'To read the files of an executor that is not running, add --offline.');
      process.stdout.write(`${JSON.stringify(answer.value, null, 2)}\n`);
      if (answer.status !== 200) return 1;
      value = answer.value;
      return statusCode(value);
    }
    process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
    return statusCode(value);
  }
  if (command === 'seal') {
    onlyOptions(command, args, ['--offline'], ['--config', '--agent']);
    const { config, root } = readConfig(args);
    const offline = args.includes('--offline');
    const name = agentOf(config, args, 'whose book to seal');
    const whose = name === null ? 'the book' : `${name}'s book`;
    if (offline) {
      process.stderr.write(`provared-mcp-executor: ${OFFLINE_NOTICE}\n`);
      const executor = await openOffline(config, root);
      try {
        const sealed = await (name === null ? executor.seal() : executor.seal(name));
        process.stdout.write(`Sealed: entry ${sealed.entry} of ${whose} is the seal ${sealed.fingerprint}.\n`);
      } finally {
        await executor.close();
      }
      return 0;
    }
    if (name === null) throw new Error(`Over stdio there is no running executor to ask. Seal the book while the executor is not running, with --offline; or set "recorder.sealEvery" in the settings, and the executor seals it on a timer while it runs.`);
    const answer = await askRunning(config, root, 'POST', `${ADMIN_PATH}/seal`, { agent: name }, 'To seal a book while it is stopped, add --offline.');
    if (answer.status !== 200) {
      process.stderr.write(`provared-mcp-executor: the book was not sealed: ${answer.value?.message ?? answer.status}\n`);
      return 1;
    }
    process.stdout.write(`Sealed: entry ${answer.value.entry} of ${whose} is the seal ${answer.value.fingerprint}.\n`);
    return 0;
  }
  if (command === 'acknowledge') {
    onlyOptions(command, args, ['--offline'], ['--config', '--agent', '--set-aside']);
    const { config, root } = readConfig(args);
    const offline = args.includes('--offline');
    const name = agentOf(config, args, 'whose calls to acknowledge');
    const aside = option(args, '--set-aside');
    const setAside = aside === undefined ? [] : aside.split(',').map((s) => s.trim()).filter(Boolean);
    let value;
    if (offline) {
      process.stderr.write(`provared-mcp-executor: ${OFFLINE_NOTICE}\n`);
      const executor = await openOffline(config, root);
      try {
        value = await (name === null ? executor.acknowledge({ setAside }) : executor.acknowledge(name, { setAside }));
      } finally {
        await executor.close();
      }
    } else {
      if (name === null) throw new Error('Over stdio there is no running executor to ask, and the executor does not start while a call waits to be acknowledged. Run the command with --offline.');
      const answer = await askRunning(config, root, 'POST', `${ADMIN_PATH}/acknowledge`, { agent: name, setAside }, 'To acknowledge while it is stopped, add --offline.');
      if (answer.status !== 200) {
        // The executor refused before it did anything.
        process.stderr.write(`provared-mcp-executor: nothing was acknowledged or set aside: ${answer.value?.message ?? answer.status}\n`);
        return 1;
      }
      value = answer.value;
    }
    const who = name ?? 'The executor';
    // What was done is said first, whatever else went wrong: a call set aside cannot be taken back.
    for (const l of value.setAside) process.stdout.write(`Set aside, with no receipt: ${l.call} (${l.problem ?? 'by the administrator'}).\n`);
    for (const w of value.written) process.stdout.write(w.found ? `Sent at ${w.when} (${w.tool}): the book already held its receipt, ${w.stub}; none was written.\n` : `Sent at ${w.when} (${w.tool}): its receipt, written under the permission it was sent under${w.formerKeys ? ' and countersigned with a key file the executor held before' : ''}, is ${w.stub}.\n`);
    for (const f of value.failed ?? []) process.stdout.write(`Not done: ${f.call} (sent at ${f.when}, ${f.tool}): ${f.problem}\n`);
    if (value.remaining.length) {
      for (const l of value.remaining) process.stdout.write(`Still waiting: ${l.call}: ${l.problem ?? 'can be acknowledged'}\n`);
      process.stdout.write(`${who} still takes no calls.\n`);
      return 1;
    }
    process.stdout.write(`${who} takes calls again${offline ? ', once it is started' : ''}.\n`);
    return 0;
  }
  throw new Error(`Unknown command "${command}".\n\n${USAGE}`);
}

main(process.argv.slice(2)).then(
  (code) => {
    // null: "http" keeps running until it is stopped.
    if (code !== null) process.exitCode = code;
  },
  (e) => {
    process.stderr.write(`provared-mcp-executor: ${e.message}\n`);
    process.exitCode = 2;
  },
);
