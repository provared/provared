#!/usr/bin/env node
// provared-mcp-executor: the command.
//
//   provared-mcp-executor stdio   --config executor.json   run as the tool server the agent's client starts:
//                                                          start the real server, check and receipt each call
//   provared-mcp-executor http    --config executor-http.json
//                                                          run as a Streamable HTTP MCP server in front of an
//                                                          upstream HTTP MCP server, for several agents, each
//                                                          signing in with a secret of its own
//   provared-mcp-executor secret                           make a new secret for an agent, and print it with
//                                                          its hash (the hash goes into the settings)
//   provared-mcp-executor check   --config executor.json   say what each rule maps to, and what is wrong
//   provared-mcp-executor keys    --config executor.json   make the key files, if there are none, and print
//                                                          what goes into the permission: agent.keys, the
//                                                          executor's entry for "with", and the agent.software
//                                                          entry for the rules on content, where there are any
//   provared-mcp-executor compare --config executor.json [--book <file>] [--agent <name>]
//                                                          hold the executor's copy against a book (over HTTP,
//                                                          the named agent's copy and book)
//
// "check", "keys" and "compare" read either kind of settings: the stdio
// executor's (with "server" and "agent") or the HTTP executor's (with
// "upstream" and "agents"). "stdio" writes nothing to its standard output
// but MCP messages; what it has to say goes to its standard error, one JSON
// object to a line, as does "http".

import { existsSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { loadCopyKey } from './copy.mjs';
import { compareCopyWithBook } from './compare.mjs';
import { checkConfig, loadRules, openExecutor, readSettings, softwareEntry } from './executor.mjs';
import { makeKeyFile, readIfThere } from './files.mjs';
import { checkHttpConfig, newSecret, openHttpExecutor, readHttpSettings, secretHash } from './http.mjs';

const USAGE = `provared-mcp-executor: an executor for MCP tool servers. It holds the server's credentials, checks each tool call against a permission a person signed, sends on the calls the permission allows, and writes a signed, countersigned receipt for each. Evidence, not a verdict.

  provared-mcp-executor stdio   --config executor.json
  provared-mcp-executor http    --config executor-http.json
  provared-mcp-executor secret
  provared-mcp-executor check   --config <settings>
  provared-mcp-executor keys    --config <settings>
  provared-mcp-executor compare --config <settings> [--book <file>] [--agent <name>]`;

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
    const { settings, problems } = isHttp(config) ? readHttpSettings(config, root) : readSettings(config, root);
    if (problems.length) throw new Error(`The settings have problems:\n- ${problems.join('\n- ')}`);
    const executor = await makeKeyFile(settings.executor.keys, 'agent');
    // The agent.software entry for the rules on content, where the settings name a rules file.
    const software = settings.contentRules ? [softwareEntry(settings.name, (await loadRules(settings.contentRules)).fingerprint)] : undefined;
    const entry = (agent, who) => ({ agent: { name: who, keys: agent, ...(software ? { software } : {}) }, with: { id: settings.service, name: settings.name, keys: executor }, requires: [{ need: 'countersignature' }] });
    if (isHttp(config)) {
      const out = {};
      for (const [name, paths] of settings.agents) out[name] = entry(await makeKeyFile(paths.keys, 'agent'), `${name}, through ${settings.name}`);
      process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
      return 0;
    }
    process.stdout.write(`${JSON.stringify(entry(await makeKeyFile(settings.agent.keys, 'agent'), `An agent, through ${settings.name}`), null, 2)}\n`);
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
