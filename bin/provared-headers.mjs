#!/usr/bin/env node
// provared-headers: fetch the chain of Bitcoin block headers from nodes you
// name, check every header on this device, and keep the chain in a file.
// The checker then reads that file (provared-check --headers <file>) to
// know, without asking anyone, which blocks are part of the chain.
//
//   provared-headers --node <host:port>... [--nodes-file <file>] [--chain <file>]
//
// Exit codes:
//   0  the chain is up to date, checked, and a second node on another
//      network handed back the latest blocks itself
//   2  it could not be done, or what you gave on the command line could
//      not be used. A chain file is never left half written, never made
//      shorter, and keeps only headers that were checked
//
// This command, and only this one, makes network requests: to the nodes
// you name, and to no one else.

import { readFileSync } from 'node:fs';
import { nodeAddress, updateChainFile } from '../net/headers.js';

// Node.js marks some of its methods as experimental and says so; this
// command does not repeat that warning. Any other warning is shown.
process.removeAllListeners('warning');
process.on('warning', (w) => {
  if (w.name !== 'ExperimentalWarning') console.error(`${w.name}: ${w.message}`);
});

const USAGE = `Usage: provared-headers --node <host:port>... [--nodes-file <file>] [--chain <file>]

Experimental: this command is new in version 0.1.0 and may change.

  --node        a Bitcoin node to fetch headers from: your own (127.0.0.1:8333), or any you choose; may be repeated
  --nodes-file  a file of nodes, one "host:port" to a line; anything after "#" on a line is set aside
  --chain       the file that holds the chain (default: block-headers.bin in this folder); it is checked
                in full when it is read, and only newer headers are fetched

Only the nodes you name are asked, in the order given. At least two are needed: a second node, on another
network, must hand back the latest blocks itself. Each node sees this device's address; a node named by
its name is looked up by this device's own name service. Every header is checked here,
by the rules every Bitcoin node applies, from the chain's first block; a node can refuse, but cannot have a
false header kept.

Evidence, not a verdict.`;

function parseArguments(argv) {
  const out = { nodes: [], chain: 'block-headers.bin', setAside: 0 };
  let chainGiven = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') return { help: true };
    if (a === '--node' || a === '--nodes-file' || a === '--chain') {
      if (i + 1 >= argv.length) return { error: `${a} needs a value.` };
      const value = argv[++i];
      if (a === '--node') {
        const node = nodeAddress(value);
        if (!node) return { error: `The value of --node is not the address of a node: host:port, [IPv6]:port, or a host alone.` };
        out.nodes.push(node);
      } else if (a === '--nodes-file') {
        let text;
        try {
          text = readFileSync(value, 'utf8');
        } catch {
          return { error: `The file of nodes could not be read: ${value}` };
        }
        for (const line of text.split('\n')) {
          if (line.split('#')[0].trim() === '') continue;
          const node = nodeAddress(line);
          if (node) out.nodes.push(node);
          else out.setAside++;
        }
      } else {
        if (chainGiven) return { error: '--chain may be given once.' };
        chainGiven = true;
        out.chain = value;
      }
    } else return { error: `Unknown option: ${a}` };
  }
  if (out.nodes.length < 2) return { error: 'Name at least two nodes: a second node, on another network, must hand back the latest blocks itself.' };
  return out;
}

const args = parseArguments(process.argv.slice(2));
if (args.help) {
  console.log(USAGE);
  process.exit(0);
}
if (args.error) {
  console.error(`${args.error}\n\n${USAGE}`);
  process.exit(2);
}
if (args.setAside) console.log(`${args.setAside} line${args.setAside === 1 ? '' : 's'} of the file of nodes ${args.setAside === 1 ? 'is' : 'are'} not the address of a node, and ${args.setAside === 1 ? 'was' : 'were'} set aside.`);

console.log('Experimental: provared-headers is new in version 0.1.0 and may change.');

let done;
try {
  done = await updateChainFile({ file: args.chain, nodes: args.nodes, log: (line) => console.log(line.startsWith('Checking') || line.startsWith('It holds') ? line : `  ${line}`) });
} catch (e) {
  console.error(e.message);
  process.exit(2);
}

const { chain, before } = done;
const tip = chain.height;
console.log(`\nThe chain in ${args.chain}: blocks 0 to ${tip}, every header checked on this device.`);
console.log(`The latest block, ${tip}: ${chain.fingerprintAt(tip)}, dated ${new Date(chain.timeAt(tip)).toISOString().slice(0, 19)}Z.`);
console.log(`${before >= 0 ? `${tip - before} new headers fetched. ` : ''}A second node, on another network, handed back the latest blocks itself.`);
console.log(`\nTo use it: provared-check <record> --headers ${args.chain} --issuer <thumbprint> ...`);
console.log('A block counts only if at least six blocks come after it in this chain.');
