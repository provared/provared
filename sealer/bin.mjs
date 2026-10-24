#!/usr/bin/env node
// provared-sealer: the command.
//
//   provared-sealer init  --folder <dir> --name <name>   write the settings and the key file, if there are none,
//                                                       and print the public keys and their fingerprint
//   provared-sealer add-recorder --folder <dir> --agent <fingerprint> [--agent ...] [--books <n>] <name>
//                                                       give a recorder a token, printed once; it starts books only
//                                                       with permissions for the agents named (the fingerprints of
//                                                       their key sets), and holds at most <n> books (100)
//   provared-sealer start --folder <dir> [--port <n>] [--fresh]
//                                                       listen on 127.0.0.1 and seal what the recorders send;
//                                                       --fresh begins again a state that is missing
//   provared-sealer release-unsealed --folder <dir> [<name>]
//                                                       while the sealer is stopped: take off the state the books
//                                                       that hold no seal (of one recorder, where a name is given)
//   provared-sealer keys  --folder <dir>                print the public keys and their fingerprint

import { existsSync, mkdirSync } from 'node:fs';
import { addRecorder, loadSigners, makeKeys, releaseUnsealed, sealerFiles, startSealer, writeDurably } from './sealer.mjs';

const USAGE = `provared-sealer: a central sealer, which seals books it is sent only the leaf fingerprints of.

  provared-sealer init  --folder <dir> --name <name>
  provared-sealer add-recorder --folder <dir> --agent <fingerprint> [--agent <fingerprint> ...] [--books <n>] <name>
  provared-sealer start --folder <dir> [--port <n>] [--fresh]
  provared-sealer release-unsealed --folder <dir> [<name>]
  provared-sealer keys  --folder <dir>`;

function options(args) {
  const o = { fresh: false, agents: [], rest: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--folder' || a === '--name' || a === '--port' || a === '--books') {
      if (i + 1 >= args.length) throw new Error(`${a} needs a value.`);
      const key = a.slice(2);
      if (o[key] !== undefined) throw new Error(`${a} is given twice.`);
      o[key] = args[++i];
    } else if (a === '--agent') {
      if (i + 1 >= args.length) throw new Error('--agent needs a value: the fingerprint of an agent\'s key set.');
      o.agents.push(args[++i]);
    } else if (a === '--fresh') {
      if (o.fresh) throw new Error('--fresh is given twice.');
      o.fresh = true;
    } else if (a.startsWith('--')) {
      throw new Error(`${a} is not an option of this command.`);
    } else {
      o.rest.push(a);
    }
  }
  if (!o.folder) throw new Error('--folder is needed: the folder the sealer keeps its settings, keys and state in.');
  return o;
}

async function printKeys(folder) {
  const { by, fingerprint } = await loadSigners(folder);
  console.log(`Name:            ${by.name}`);
  console.log(`Key set:         ${fingerprint}`);
  console.log('                 (give this to whoever checks the books: --sealer on the command-line checker)');
  console.log(JSON.stringify(by.keys));
}

async function main(argv) {
  const [command, ...args] = argv;
  if (!command || command === '--help' || command === 'help') {
    console.log(USAGE);
    return 0;
  }
  const o = options(args);
  const files = sealerFiles(o.folder);
  if (command !== 'add-recorder' && (o.agents.length > 0 || o.books !== undefined)) throw new Error('--agent and --books are options of add-recorder only.');
  if (command === 'init') {
    mkdirSync(files.root, { recursive: true });
    if (!existsSync(files.settings)) {
      if (!o.name) throw new Error('--name is needed the first time: the name the seals give (a label).');
      writeDurably(files.settings, JSON.stringify({ name: o.name, port: 8797, signers: {} }, null, 2) + '\n');
    } else if (o.name) {
      throw new Error(`There are settings already (${files.settings}); change the name there.`);
    }
    console.log((await makeKeys(o.folder)) ? `Made the key file ${files.keys} (for its owner alone).` : `The key file ${files.keys} is there already; it was not changed.`);
    await printKeys(o.folder);
    return 0;
  }
  if (command === 'keys') {
    await printKeys(o.folder);
    return 0;
  }
  if (command === 'add-recorder') {
    if (o.rest.length !== 1) throw new Error('add-recorder takes one recorder\'s name.');
    if (o.agents.length === 0) throw new Error('add-recorder needs at least one --agent: the fingerprint of the key set of an agent whose permissions this recorder starts books with.');
    let books;
    if (o.books !== undefined) {
      books = Number(o.books);
      if (!/^[0-9]{1,4}$/.test(o.books)) throw new Error('--books must be a whole number from 1 to 1,000.');
    }
    const token = await addRecorder(o.folder, o.rest[0], { agents: o.agents, books });
    console.log(`The recorder "${o.rest[0]}" is added. Its token, shown once (hand it to that recorder only):`);
    console.log(token);
    return 0;
  }
  if (command === 'release-unsealed') {
    if (o.rest.length > 1) throw new Error('release-unsealed takes at most one recorder\'s name.');
    const released = await releaseUnsealed(o.folder, o.rest[0]);
    console.log(`Released ${released.length} ${released.length === 1 ? 'book' : 'books'} with no seal${o.rest[0] ? ` of the recorder "${o.rest[0]}"` : ''}.`);
    for (const b of released) console.log(`  book ${b.number}, first line ${b.first}${b.recorder ? `, recorder ${b.recorder}` : ''}`);
    return 0;
  }
  if (command === 'start') {
    let port;
    if (o.port !== undefined) {
      port = Number(o.port);
      if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('--port must be a port number.');
    }
    const running = await startSealer({ folder: o.folder, port, fresh: o.fresh });
    console.log(`The central sealer listens at ${running.address}, with the key set ${running.fingerprint}.`);
    const stop = async () => {
      await running.close();
      process.exit(0);
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    return null;
  }
  throw new Error(`"${command}" is not a command.\n\n${USAGE}`);
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
