#!/usr/bin/env node
// provared-mcp-executor: the command.
//
//   provared-mcp-executor demo                             a demonstration with no passkey and no settings, in a
//                                                          new temporary folder: one call let through, one
//                                                          refused, and the book checked (demo.mjs)
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
//
// "check", "keys" and "compare" read either kind of settings: the stdio
// executor's (with "server" and "agent") or the HTTP executor's (with
// "upstream" and "agents"). "stdio" writes nothing to its standard output
// but MCP messages; what it has to say goes to its standard error, one JSON
// object to a line, as does "http".
//
// Node.js's notice that its ML-DSA-87 signing is experimental is set aside
// (quiet.mjs, imported first); every other warning is printed.

import './quiet.mjs';
import { constants, copyFileSync, existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadCopyKey } from './copy.mjs';
import { compareCopyWithBook } from './compare.mjs';
import { checkConfig, loadRules, openExecutor, readSettings, softwareEntry } from './executor.mjs';
import { loadKeyFile, makeKeyFile, readIfThere } from './files.mjs';
import { checkHttpConfig, newSecret, openHttpExecutor, readHttpSettings, secretHash } from './http.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(readFileSync(join(HERE, 'package.json'), 'utf8')).version;

const USAGE = `provared-mcp-executor ${VERSION}: an executor for MCP tool servers. It holds the server's credentials, checks each tool call against a permission a person signed, sends on the calls the permission allows, and writes a signed, countersigned receipt for each. Evidence, not a verdict.

  provared-mcp-executor demo                 try it with no passkey and no settings
  provared-mcp-executor init    [--http]     copy the example settings into this folder
  provared-mcp-executor stdio   --config executor.json
  provared-mcp-executor http    --config executor-http.json
  provared-mcp-executor secret
  provared-mcp-executor check   --config <settings>
  provared-mcp-executor keys    --config <settings> [--out <file>]
  provared-mcp-executor compare --config <settings> [--book <file>] [--agent <name>]
  provared-mcp-executor --version`;

/** What to do with what "keys" prints, said in one line on the standard error. */
const KEYS_NEXT = 'What to do with this: it goes into the permission the person signs with a passkey: "agent" as the permission\'s agent (over HTTP, one for each agent), the "with" entry in its "with", and "requires" as it is. Then put the passkey\'s thumbprint in issuerKeys and run "check" (README, "Set it up").';

/** The example files "init" copies into the current folder: [file in the package, name in the folder]. */
const EXAMPLES = {
  stdio: [['executor.example.json', 'executor.json'], ['content-rules.example.json', 'content-rules.json']],
  http: [['executor-http.example.json', 'executor-http.json'], ['content-rules.example.json', 'content-rules.json']],
};

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
    const { runDemo } = await import('./demo.mjs');
    return (await runDemo()).ok ? 0 : 1;
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
          'The person signs a permission for each agent with a passkey, holding what "keys" printed; save each where its "slip" says, and put the passkey\'s thumbprint in its "issuerKeys".',
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
  if (command === 'stdio') {
    const { config, root } = readConfig(args);
    const executor = await openExecutor(config, { root });
    const ended = await executor.attach(process.stdin, process.stdout);
    // The server has ended and every receipt is written: the executor ends
    // too, whether or not the client still holds its input open (the
    // client restarts it, as the specification says).
    process.exit(typeof ended.code === 'number' ? ended.code : 1);
  }
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
    process.stdout.write(`The secret (give it to the agent; it is not stored anywhere):\n  ${secret}\nIts hash (put it in the settings, as the agent's "secretHash"):\n  ${secretHash(secret)}\n`);
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
    // Everything "keys" needs is read before anything is written: the rules
    // file, each key file already there, and the folder for --out. A
    // problem with any of them leaves the disk as it was.
    const software = settings.contentRules ? [softwareEntry(settings.name, (await loadRules(settings.contentRules)).fingerprint)] : undefined;
    const agents = http ? [...settings.agents].map(([name, paths]) => [name, paths.keys]) : [[null, settings.agent.keys]];
    for (const path of [settings.executor.keys, ...agents.map(([, path]) => path)]) if (existsSync(path)) await loadKeyFile(path, 'agent');
    if (outAt) {
      if (existsSync(outAt)) throw new Error(`Nothing was written: ${outAt} (--out) already exists. Name a new file.`);
      let folder = false;
      try {
        folder = statSync(dirname(outAt)).isDirectory();
      } catch {
        folder = false;
      }
      if (!folder) throw new Error(`Nothing was written: the folder ${dirname(outAt)} (--out) does not exist.`);
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
      writeFileSync(outAt, text, { flag: 'wx' });
      process.stderr.write(`provared-mcp-executor: wrote ${outAt}. ${KEYS_NEXT}\n`);
    } else {
      process.stdout.write(text);
      process.stderr.write(`provared-mcp-executor: ${KEYS_NEXT}\n`);
    }
    return 0;
  }
  if (command === 'compare') {
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
    const result = await compareCopyWithBook({ copyPath: paths.copy, copyKey, name: settings.name, service: settings.service, book: readIfThere(bookAt), options: { issuerKeys: paths.issuerKeys } });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return result.summary.agree ? 0 : 1;
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
