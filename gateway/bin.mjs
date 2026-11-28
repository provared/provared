#!/usr/bin/env node
// provared-gateway: the command.
//
//   provared-gateway start  --config gateway.json     listen, and write a receipt for each call
//   provared-gateway check  --config gateway.json     say what each rule maps to, and what is wrong
//   provared-gateway seal   --config gateway.json --agent <name> [--offline]
//                                                     seal an agent's book now, with the recorder's keys
//   provared-gateway acknowledge --config gateway.json --agent <name> [--set-aside <call,…>] [--offline]
//                                                     take an agent's calls again, after a stop left calls
//                                                     with no receipt; a stub is written for each, and none
//                                                     for a journal line set aside
//   provared-gateway repair --config gateway.json --agent <name> [--cut <bytes> | --end-line]
//                                                     show, and with --cut take off, a last line of a book
//                                                     that a stop left part-written (the gateway stopped)
//   provared-gateway status --config gateway.json     what the running gateway says about each agent
//   provared-gateway keys   --config gateway.json (--agent <name> | --recorder | --gateway)
//                                                     make a key file, if there is none, and print its public keys
//                                                     (for --gateway, the slip's "with" entries that name them)
//   provared-gateway compare --config gateway.json --agent <name> [--book <file>] [--sealer <fingerprint>]
//                                                     hold the gateway's own copy of an agent's calls against its book
//   provared-gateway secret                           make a new secret, and print it with its hash
//
// "seal" and "status" ask the running gateway, with the administrator's
// secret from the environment (PROVARED_GATEWAY_ADMIN_SECRET). "seal
// --offline" opens the book itself, for a gateway that is not running.

import { randomBytes } from 'node:crypto';
import { appendFileSync, existsSync, readFileSync, truncateSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { dirname, isAbsolute, resolve } from 'node:path';
import { keySetFingerprint, toBase64url } from 'provared';
import { compareCopyWithBook } from './compare.mjs';
import { loadCopyKey } from './copy.mjs';
import { GATEWAY_ID, GATEWAY_NAME, checkConfig, copyPaths, journalKeyPath, loadJournalKey, openGateway, plainText, secretHash } from './gateway.mjs';
import { loadKeyFile, makeKeyFile } from './files.mjs';

const USAGE = `provared-gateway: a reverse proxy that writes a Provared receipt for each call an agent makes through it.

  provared-gateway start  --config gateway.json
  provared-gateway check  --config gateway.json
  provared-gateway seal   --config gateway.json --agent <name> [--offline]
  provared-gateway acknowledge --config gateway.json --agent <name> [--set-aside <call,…>] [--offline]
  provared-gateway repair --config gateway.json --agent <name> [--cut <bytes> | --end-line]
  provared-gateway status --config gateway.json
  provared-gateway keys   --config gateway.json (--agent <name> | --recorder | --gateway)
  provared-gateway compare --config gateway.json --agent <name> [--book <file>] [--sealer <fingerprint>]
  provared-gateway secret

"seal", "acknowledge" and "status" ask the running gateway, with the administrator's secret in
PROVARED_GATEWAY_ADMIN_SECRET; "seal --offline", "acknowledge --offline" and "repair" work on the files
of a stopped gateway, and need no secret. "compare" reads the files, and asks nobody: it ends with 0
where the copy and the book agree, 3 where the calls set aside are the only disagreement, and 1
otherwise.`;

/** What "Sealed: ..." adds where the seal carries a time-stamp, with the fingerprint of the certificate that signed it (X344). */
const stampWords = (sealed) => {
  if (sealed?.stamped !== true) return '';
  const by = typeof sealed.stampedBy === 'string' && /^[A-Za-z0-9_-]{43}$/.test(sealed.stampedBy) ? ` signed by the certificate ${sealed.stampedBy}` : '';
  return `, with a time-stamp${by}`;
};

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
  if (!path) throw new Error('Name the settings file: --config gateway.json');
  const full = isAbsolute(path) ? path : resolve(path);
  let config;
  try {
    config = JSON.parse(readFileSync(full, 'utf8').replace(/^﻿/, ''));
  } catch (e) {
    throw new Error(`The settings file ${full} could not be read as JSON (${e.code ?? e.message}).`);
  }
  return { config, root: dirname(full) };
}

function askRunning(config, method, path, body) {
  const secret = process.env.PROVARED_GATEWAY_ADMIN_SECRET;
  if (!secret) throw new Error('Put the administrator\'s secret in the environment: PROVARED_GATEWAY_ADMIN_SECRET.');
  const host = config.listen?.host ?? '127.0.0.1';
  const port = config.listen?.port ?? 8795;
  return new Promise((done, failed) => {
    const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = http.request({ host, port, method, path, headers: { authorization: `Bearer ${secret}`, ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}) } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try {
          done({ status: res.statusCode, value: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
        } catch {
          failed(new Error('The gateway gave an answer that is not JSON.'));
        }
      });
    });
    req.on('error', failed);
    req.end(data);
  });
}

async function main(args) {
  const [command, ...rest] = args;
  if (!command || command === '--help' || command === 'help') {
    console.log(USAGE);
    return 0;
  }
  if (command === 'secret') {
    const secret = toBase64url(randomBytes(32));
    console.log(`The secret (give it to the agent, or keep it for the administrator; it is not stored):\n  ${secret}`);
    console.log(`Its hash (put it in the settings, as "secretHash"):\n  ${await secretHash(secret)}`);
    return 0;
  }
  if (command === 'check') {
    const { config, root } = readConfig(rest);
    const { lines, problems, warnings } = await checkConfig(config, { root });
    for (const line of lines) console.log(line);
    for (const w of warnings) console.log(`warning: ${w}`);
    for (const p of problems) console.log(`problem: ${p}`);
    console.log(problems.length ? `${problems.length} problem(s): the gateway does not start with these settings.` : 'No problem found in the settings.');
    return problems.length ? 2 : 0;
  }
  if (command === 'keys' && rest.includes('--gateway')) {
    const { config, root } = readConfig(rest);
    if (option(rest, '--agent') !== undefined || rest.includes('--recorder')) throw new Error('Name one of --agent <name>, --recorder or --gateway.');
    const entry = config.gateway;
    if (!entry || typeof entry.keys !== 'string') throw new Error('The settings name no key file of the gateway\'s own ("gateway": {"keys": …}).');
    const path = isAbsolute(entry.keys) ? entry.keys : resolve(root, entry.keys);
    const others = [config.recorder?.keys, ...Object.values(config.agents ?? {}).map((a) => a?.keys)].filter((p) => typeof p === 'string').map((p) => (isAbsolute(p) ? p : resolve(root, p)));
    if (others.some((p) => p.toLowerCase() === path.toLowerCase())) throw new Error(`Nothing was written: gateway.keys (${path}) is also the key file of the recorder or of an agent. The gateway has a key file of its own.`);
    const id = entry.id ?? GATEWAY_ID;
    if (typeof id !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(id)) throw new Error('Nothing was written: gateway.id must be 1 to 64 lower-case letters, digits, full stops, hyphens or underscores, beginning with a letter or digit.');
    const keys = await makeKeyFile(path, 'gateway');
    const name = typeof entry.name === 'string' ? entry.name : GATEWAY_NAME;
    // The gateway's own "with" entry, with its keys: the slip gives it, and requires the countersignature.
    const out = { with: [{ id, name, keys }], requires: [{ need: 'countersignature' }] };
    console.log(`The gateway's own public keys are in ${path}. The slip's "with" names the gateway in an entry of its own, which every receipt of the agent then names, and "requires" asks for the countersignature:`);
    console.log(JSON.stringify(out, null, 2));
    return 0;
  }
  if (command === 'compare') {
    // Only these options: a mistyped one would otherwise compare the default book, say, without a word.
    for (let i = 0; i < rest.length; i += 2) if (!['--config', '--agent', '--book', '--sealer'].includes(rest[i])) throw new Error(`"compare" takes --config, --agent, --book and --sealer, each with a value; "${rest[i]}" is not one of them.`);
    const { config, root } = readConfig(rest);
    const agent = option(rest, '--agent');
    const entry = agent ? config.agents?.[agent] : undefined;
    if (!entry || typeof entry.book !== 'string') throw new Error(`Name the agent whose copy and book to compare: --agent <name> (one of ${Object.keys(config.agents ?? {}).join(', ')}).`);
    if (!config.gateway || typeof config.gateway !== 'object') throw new Error('The settings give the gateway no keys of its own ("gateway"), so the gateway keeps no copy to compare.');
    // The gateway's id in a slip's "with": no key file is read, since the book's own check holds each countersignature against the keys the slip gives.
    const service = config.gateway.id ?? GATEWAY_ID;
    const paths = copyPaths(entry, agent, root);
    const bookPath = option(rest, '--book');
    const bookAt = bookPath ? (isAbsolute(bookPath) ? bookPath : resolve(bookPath)) : isAbsolute(entry.book) ? entry.book : resolve(root, entry.book);
    if (!existsSync(bookAt)) throw new Error(`The book ${bookAt} does not exist.`);
    const copyKey = loadCopyKey(paths.copyKey, { create: false });
    if (!copyKey) throw new Error(`The copy key ${paths.copyKey} does not exist: the gateway has not run yet with its own keys, or the key was moved. Nothing to compare.`);
    // The recorder a seal in the book must be signed by: the one --sealer names (several with commas), or else the recorder of the settings, where its key file is here.
    const named = option(rest, '--sealer');
    let sealKeys = null;
    if (named !== undefined) {
      sealKeys = named.split(',').map((s) => s.trim()).filter(Boolean);
      if (sealKeys.length === 0 || !sealKeys.every((f) => /^[A-Za-z0-9_-]{43}$/.test(f))) throw new Error('--sealer must be the fingerprint of a recorder\'s key set (43 characters of base64url), or several with commas between them.');
    } else if (typeof config.recorder?.keys === 'string') {
      const at = isAbsolute(config.recorder.keys) ? config.recorder.keys : resolve(root, config.recorder.keys);
      if (existsSync(at)) sealKeys = [await keySetFingerprint((await loadKeyFile(at, 'recorder')).keys)];
    }
    const issuerKeys = Array.isArray(entry.issuerKeys) ? entry.issuerKeys : [];
    const result = await compareCopyWithBook({ copyPath: paths.copy, copyKey, name: agent, service, book: readFileSync(bookAt, 'utf8'), options: { issuerKeys, ...(sealKeys ? { sealKeys } : {}) } });
    console.log(JSON.stringify(result, null, 2));
    // 0: they agree. 3: they agree but for calls the administrator set aside, which is all that is known to be wrong. 1: anything else.
    return result.summary.agree ? 0 : result.summary.onlySetAside ? 3 : 1;
  }
  if (command === 'keys') {
    const { config, root } = readConfig(rest);
    const agent = option(rest, '--agent');
    const forRecorder = rest.includes('--recorder');
    if (!agent === !forRecorder) throw new Error('Name one of --agent <name>, --recorder or --gateway.');
    const entry = forRecorder ? config.recorder : config.agents?.[agent];
    if (!entry || typeof entry.keys !== 'string') throw new Error(`The settings name no key file ("keys") for ${forRecorder ? 'the recorder' : `agent "${agent}"`}.`);
    const path = isAbsolute(entry.keys) ? entry.keys : resolve(root, entry.keys);
    const keys = await makeKeyFile(path, forRecorder ? 'recorder' : 'agent');
    if (!forRecorder) {
      const book = typeof entry.book === 'string' ? (isAbsolute(entry.book) ? entry.book : resolve(root, entry.book)) : path;
      const journalKey = journalKeyPath(entry, root, book);
      loadJournalKey(journalKey);
      console.log(`The agent's journal key is in ${journalKey}. Keep it as the key file is kept.`);
    }
    console.log(forRecorder ? `The recorder's public keys (${path}):` : `The agent's public keys, for "agent.keys" in its slip (${path}):`);
    console.log(JSON.stringify(keys, null, 2));
    // The fingerprint of the agent's key set, in the guard's words: the signing window asks for it before the person
    // signs a permission for keys it has not seen. The recorder's keys go into no permission.
    if (!forRecorder) process.stderr.write(`provared-gateway: the fingerprint of the key set of the agent "${agent}" is ${await keySetFingerprint(keys)}: the signing window asks for it before the person signs a permission for these keys, the whole of it or at least its first 16 characters. Copy it from here only once the signing window has opened, and check that what the box then shows is the one printed here. If the window says it does not match, the keys it holds are not this agent's: do not sign.\n`);
    return 0;
  }
  if (command === 'status') {
    const { config } = readConfig(rest);
    const answer = await askRunning(config, 'GET', '/provared/status');
    console.log(JSON.stringify(answer.value, null, 2));
    return answer.status === 200 ? 0 : 1;
  }
  if (command === 'acknowledge') {
    const { config, root } = readConfig(rest);
    const agent = option(rest, '--agent');
    if (!agent) throw new Error('Name the agent whose calls to acknowledge: --agent <name>');
    const aside = option(rest, '--set-aside');
    const setAside = aside === undefined ? [] : aside.split(',').map((s) => s.trim()).filter(Boolean);
    let value;
    if (rest.includes('--offline')) {
      const gateway = await openGateway(config, { root });
      try {
        value = await gateway.acknowledge(agent, { setAside });
      } finally {
        await gateway.close();
      }
    } else {
      let answer;
      try {
        answer = await askRunning(config, 'POST', '/provared/acknowledge', { agent, setAside });
      } catch (e) {
        if (e.code === 'ECONNREFUSED') throw new Error('The gateway is not running. To acknowledge while it is stopped, add --offline.');
        throw e;
      }
      if (answer.status !== 200) {
        console.error(`Nothing was acknowledged: ${answer.value.message ?? answer.status}`);
        return 1;
      }
      value = answer.value;
    }
    for (const l of value.setAside) console.log(`Set aside, with no stub: ${l.call} (${l.problem ?? 'by the administrator'}).`);
    for (const w of value.written) console.log(`Sent at ${w.when} (${w.action}): its stub, saying the outcome is not known, is ${w.stub}.`);
    if (value.remaining.length) {
      for (const l of value.remaining) console.log(`Still waiting: ${l.call}: ${l.problem ?? 'can be acknowledged'}`);
      console.log(`${agent} still takes no calls.`);
      return 1;
    }
    console.log(`${agent} takes calls again.`);
    return 0;
  }
  if (command === 'repair') {
    const { config, root } = readConfig(rest);
    const agent = option(rest, '--agent');
    const entry = agent ? config.agents?.[agent] : undefined;
    if (!entry || typeof entry.book !== 'string') throw new Error('Name an agent of the settings: --agent <name>');
    const path = isAbsolute(entry.book) ? entry.book : resolve(root, entry.book);
    const bytes = readFileSync(path);
    const last = bytes.lastIndexOf(0x0a);
    const partial = bytes.subarray(last + 1);
    if (partial.length === 0) {
      console.log(`The book file ${path} ends with a whole line: there is nothing to repair.`);
      return 0;
    }
    const text = partial.toString('utf8');
    const shown = text.length > 200 ? `${text.slice(0, 120)} … ${text.slice(-60)}` : text;
    // The bytes may be a whole entry that lost only its line ending: then the line ending can be put back instead.
    let whole = false;
    try {
      const value = JSON.parse(text);
      whole = value !== null && typeof value === 'object' && !Array.isArray(value) && JSON.stringify(value) === text;
    } catch {
      whole = false;
    }
    const cut = option(rest, '--cut');
    if (rest.includes('--end-line')) {
      if (!whole) throw new Error('The bytes after the last whole line are not a whole entry, so a line ending cannot make them one; take them off with --cut.');
      appendFileSync(path, '\n');
      console.log(`Put back the line ending after the last ${partial.length} bytes of ${path}. Start the gateway: the book is checked as it starts.`);
      return 0;
    }
    if (cut === undefined) {
      console.log(`The book file ${path} ends with ${partial.length} bytes that are not a whole line, as a stop while a line was written leaves it:`);
      console.log(`  ${JSON.stringify(shown)}`);
      if (whole) {
        console.log('They are a whole entry, without its line ending. With the gateway stopped, put the line ending back with:');
        console.log(`  provared-gateway repair --config <settings> --agent ${agent} --end-line`);
        console.log('or take them off, as below.');
      }
      console.log(`With the gateway stopped, take them off (they are kept in a file of their own beside the book) with:\n  provared-gateway repair --config <settings> --agent ${agent} --cut ${partial.length}`);
      console.log('Then start the gateway: a call whose stub was in that line is listed for the administrator to acknowledge.');
      return 1;
    }
    if (!/^[0-9]+$/.test(cut) || Number(cut) !== partial.length) throw new Error(`--cut must be the number of bytes shown (${partial.length}), written in digits, so that nothing else is taken off.`);
    const kept = `${path}.cut-${new Date().toISOString().replace(/[:.]/g, '-')}`;
    writeFileSync(kept, partial, { flag: 'wx' });
    truncateSync(path, last + 1);
    console.log(`Took ${partial.length} bytes off the end of ${path}; they are kept in ${kept}.`);
    return 0;
  }
  if (command === 'seal') {
    const { config, root } = readConfig(rest);
    const agent = option(rest, '--agent');
    if (!agent) throw new Error('Name the agent whose book to seal: --agent <name>');
    if (rest.includes('--offline')) {
      const gateway = await openGateway(config, { root });
      const sealed = await gateway.seal(agent);
      await gateway.close();
      console.log(`Sealed (the book was opened here; no gateway may be running on it): entry ${sealed.entry} of ${agent}'s book is the seal ${sealed.fingerprint}${stampWords(sealed)}.`);
      if (sealed.stampProblem) console.error(`The seal has no time-stamp: ${plainText(sealed.stampProblem.message)} (${plainText(sealed.stampProblem.code)})`);
      return 0;
    }
    let answer;
    try {
      answer = await askRunning(config, 'POST', '/provared/seal', { agent });
    } catch (e) {
      if (e.code === 'ECONNREFUSED') throw new Error('The gateway is not running. To seal a book while it is stopped, add --offline.');
      throw e;
    }
    if (answer.status !== 200) {
      console.error(`The book was not sealed: ${answer.value.message ?? answer.status}`);
      return 1;
    }
    console.log(`Sealed: entry ${answer.value.entry} of ${agent}'s book is the seal ${answer.value.fingerprint}${stampWords(answer.value)}.`);
    if (answer.value.stampProblem) console.error(`The seal has no time-stamp: ${plainText(answer.value.stampProblem.message)} (${plainText(answer.value.stampProblem.code)})`);
    return 0;
  }
  if (command === 'start') {
    const { config, root } = readConfig(rest);
    const gateway = await openGateway(config, { root });
    const at = await gateway.listen();
    console.error(`provared-gateway is listening on ${at.address}:${at.port}.`);
    const stop = async () => {
      await gateway.close();
      process.exit(0);
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    return null;
  }
  throw new Error(`"${command}" is not a command of provared-gateway.\n\n${USAGE}`);
}

main(process.argv.slice(2)).then(
  (code) => {
    if (code !== null) process.exitCode = code;
  },
  (e) => {
    console.error(e.message);
    process.exitCode = 2;
  },
);
