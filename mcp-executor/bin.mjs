#!/usr/bin/env node
// provared-mcp-executor: the command.
//
//   provared-mcp-executor stdio   --config executor.json   run as the tool server the agent's client starts:
//                                                          start the real server, check and receipt each call
//   provared-mcp-executor check   --config executor.json   say what each rule maps to, and what is wrong
//   provared-mcp-executor keys    --config executor.json   make the key files, if there are none, and print
//                                                          what goes into the permission: agent.keys, the
//                                                          executor's entry for "with", and the agent.software
//                                                          entry for the rules on content, where there are any
//   provared-mcp-executor compare --config executor.json [--book <file>]
//                                                          hold the executor's copy against a book
//
// "stdio" writes nothing to its standard output but MCP messages; what it
// has to say goes to its standard error, one JSON object to a line.

import { existsSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { loadCopyKey } from './copy.mjs';
import { compareCopyWithBook } from './compare.mjs';
import { checkConfig, loadRules, openExecutor, readSettings, softwareEntry } from './executor.mjs';
import { makeKeyFile, readIfThere } from './files.mjs';

const USAGE = `provared-mcp-executor: an executor for MCP tool servers. It holds the server's credentials, checks each tool call against a permission a person signed, sends on the calls the permission allows, and writes a signed, countersigned receipt for each. Evidence, not a verdict.

  provared-mcp-executor stdio   --config executor.json
  provared-mcp-executor check   --config executor.json
  provared-mcp-executor keys    --config executor.json
  provared-mcp-executor compare --config executor.json [--book <file>]`;

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
  if (command === 'check') {
    const { config, root } = readConfig(args);
    const report = await checkConfig(config, root);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return report.problems.length ? 1 : 0;
  }
  if (command === 'keys') {
    const { config, root } = readConfig(args);
    const { settings, problems } = readSettings(config, root);
    if (problems.length) throw new Error(`The settings have problems:\n- ${problems.join('\n- ')}`);
    const agent = await makeKeyFile(settings.agent.keys, 'agent');
    const executor = await makeKeyFile(settings.executor.keys, 'agent');
    // The agent.software entry for the rules on content, where the settings name a rules file.
    const software = settings.contentRules ? [softwareEntry(settings.name, (await loadRules(settings.contentRules)).fingerprint)] : undefined;
    process.stdout.write(`${JSON.stringify({ agent: { name: `An agent, through ${settings.name}`, keys: agent, ...(software ? { software } : {}) }, with: { id: settings.service, name: settings.name, keys: executor }, requires: [{ need: 'countersignature' }] }, null, 2)}\n`);
    return 0;
  }
  if (command === 'compare') {
    const { config, root } = readConfig(args);
    const { settings, problems } = readSettings(config, root);
    if (problems.length) throw new Error(`The settings have problems:\n- ${problems.join('\n- ')}`);
    const bookPath = option(args, '--book');
    const bookAt = bookPath ? (isAbsolute(bookPath) ? bookPath : resolve(bookPath)) : settings.agent.book;
    if (!existsSync(bookAt)) throw new Error(`The book ${bookAt} does not exist.`);
    const copyKey = loadCopyKey(settings.executor.copyKey, { create: false });
    if (!copyKey) throw new Error(`The copy key ${settings.executor.copyKey} does not exist: the executor has not run yet, or the key was moved. Nothing to compare.`);
    const result = await compareCopyWithBook({ copyPath: settings.executor.copy, copyKey, name: settings.name, service: settings.service, book: readIfThere(bookAt), options: { issuerKeys: settings.agent.issuerKeys } });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return result.summary.agree ? 0 : 1;
  }
  throw new Error(`Unknown command "${command}".\n\n${USAGE}`);
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    process.stderr.write(`provared-mcp-executor: ${e.message}\n`);
    process.exitCode = 2;
  },
);
