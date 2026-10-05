// Fetching block headers from Bitcoin nodes: the only code in this package
// that makes a network request. The library (src/) never does. This is
// used by the command provared-headers alone, which the person runs.
//
// Only nodes the person names are asked. To each, this sends the network's
// own greeting (with no name of the software, a random number and this
// device's clock), its acknowledgement, answers to the node's "are you
// there" messages, and requests for headers: nothing else. The node sees
// this device's address. The connection is not encrypted; nothing secret
// is sent, and every header is checked here (src/headers.js), so a node can
// refuse or fall silent, but cannot have a false header kept.

import { closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, rmSync, writeSync } from 'node:fs';
import net from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { BITCOIN, MIN_BLOCKS_AFTER, readHeaderChain, startHeaderChain } from '../src/headers.js';

const MAGIC = Buffer.from('f9beb4d9', 'hex');
const PROTOCOL = 70016;
// A node sends at most this many headers in one answer.
const PAGE = 2000;
// No message this program waits for is longer: a full answer of headers is 162,003 bytes.
const MAX_MESSAGE = 1_000_000;
// Answers to "are you there" stop while this much waits to be sent to a node that does not read them.
const MAX_WAITING = 64 * 1024;
const sha256d = (b) => createHash('sha256').update(createHash('sha256').update(b).digest()).digest();

function message(command, payload = Buffer.alloc(0)) {
  const head = Buffer.alloc(24);
  MAGIC.copy(head, 0);
  head.write(command, 4, 'ascii');
  head.writeUInt32LE(payload.length, 16);
  sha256d(payload).copy(head, 20, 0, 4);
  return Buffer.concat([head, payload]);
}

function varint(n) {
  if (n < 0xfd) return Buffer.from([n]);
  const b = Buffer.alloc(3);
  b[0] = 0xfd;
  b.writeUInt16LE(n, 1);
  return b;
}

function readVarint(b, o) {
  if (o >= b.length) throw new Error('a message ends too early');
  const first = b[o];
  if (first < 0xfd) return [first, o + 1];
  if (first === 0xfd) return [b.readUInt16LE(o + 1), o + 3];
  if (first === 0xfe) return [b.readUInt32LE(o + 1), o + 5];
  return [Number(b.readBigUInt64LE(o + 1)), o + 9];
}

function versionPayload(now) {
  const b = Buffer.alloc(86);
  let o = 0;
  b.writeInt32LE(PROTOCOL, o); o += 4;
  o += 8; // services offered: none
  b.writeBigInt64LE(BigInt(Math.floor(now / 1000)), o); o += 8;
  o += 26; // the other node's address: left empty
  o += 26; // this device's address: left empty
  randomBytes(8).copy(b, o); o += 8;
  b[o] = 0; o += 1; // the name of the software: empty
  b.writeInt32LE(0, o); o += 4; // the latest block held: none said
  b[o] = 0; // send no transactions
  return b;
}

// Ask for headers after the latest blocks held: the last ten, then the
// first block. A node answers from the latest of them that it holds.
function getheadersPayload(chain) {
  const locator = [];
  for (let h = chain.height; h >= 0 && locator.length < 10; h--) locator.push(Buffer.from(chain.hashAt(h)));
  if (chain.height >= 10) locator.push(Buffer.from(chain.hashAt(0)));
  const head = Buffer.alloc(4);
  head.writeUInt32LE(PROTOCOL, 0);
  return Buffer.concat([head, varint(locator.length), ...locator, Buffer.alloc(32)]);
}

/**
 * Take headers from one node until it has no more, within the time each
 * node is given. Resolves with the number of headers taken from it; rejects
 * where it fails, falls silent, runs out of time, or gives a header that does
 * not check (what it gave before that is kept). Where the node's chain parts
 * from the one held within its last eleven blocks, its branch is tried on a
 * copy, and taken on only if it carries more work.
 */
function session(node, chain, { now, waits, progress = () => {} }) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: node.host, port: node.port });
    let inbox = Buffer.alloc(0);
    let given = 0;
    let asked = false;
    let ended = false;
    const shook = { version: false, verack: false };
    let quietTimer;
    // Waiting is measured from the last answer this program asked for, so
    // that a node cannot keep a session going with messages of its own.
    const quiet = (ms) => {
      clearTimeout(quietTimer);
      quietTimer = setTimeout(() => finish(new Error(`no answer for ${ms / 1000} seconds`)), ms);
    };
    const span = waits.session >= 60000 ? `${Math.round(waits.session / 60000)} minutes` : `${Math.round(waits.session / 1000)} seconds`;
    const deadline = setTimeout(() => finish(new Error(`more than ${span} with one node`)), waits.session);
    const finish = (error) => {
      if (ended) return;
      ended = true;
      clearTimeout(quietTimer);
      clearTimeout(deadline);
      socket.destroy();
      if (error) reject(Object.assign(error, { given }));
      else resolve(given);
    };
    const ask = () => {
      asked = true;
      socket.write(message('getheaders', getheadersPayload(chain)));
    };
    const take = async (payload) => {
      let [n, o] = readVarint(payload, 0);
      if (n > PAGE) throw new Error(`more than ${PAGE} headers in one answer`);
      if (o + n * 81 > payload.length) throw new Error('an answer of headers ends too early');
      const at = (i) => new Uint8Array(payload.subarray(o + i * 81, o + i * 81 + 80));
      if (n > 0 && chain.height >= 0) {
        const parent = payload.subarray(o + 4, o + 36);
        if (!parent.equals(Buffer.from(chain.hashAt(chain.height)))) {
          // The node's chain parts from the one held: find where they meet.
          let k = chain.height - 1;
          const lowest = Math.max(0, chain.height - 11);
          while (k >= lowest && !parent.equals(Buffer.from(chain.hashAt(k)))) k--;
          if (k < lowest) throw new Error('its headers do not join the chain held here');
          const branch = chain.copy();
          branch.keepTo(k);
          for (let i = 0; i < n; i++) await branch.add(at(i), now());
          if (branch.workAfter(k) <= chain.workAfter(k)) throw new Error('its branch carries no more work than the chain held here');
          chain.adopt(branch);
          given += n;
          return n;
        }
      }
      for (let i = 0; i < n; i++) {
        await chain.add(at(i), now());
        given++;
      }
      return n;
    };
    // One message at a time, in order, so that headers are checked in the order they came.
    let work = Promise.resolve();
    const handle = async (command, payload) => {
      if (command === 'version' && !shook.version) {
        shook.version = true;
        quiet(waits.between);
        socket.write(message('verack'));
      } else if (command === 'verack' && !shook.verack) {
        shook.verack = true;
        quiet(waits.between);
      } else if (command === 'ping') {
        // Answered only in the network's own form, and only while the node reads the answers.
        if (payload.length === 8 && socket.writableLength < MAX_WAITING) socket.write(message('pong', payload));
      } else if (command === 'headers' && asked) {
        asked = false;
        quiet(waits.between);
        const n = await take(payload);
        progress();
        if (n < PAGE) return finish();
        ask();
      }
      if (shook.version && shook.verack && given === 0 && !asked && command !== 'headers') ask();
    };
    quiet(waits.answer);
    socket.on('connect', () => {
      node.connected = socket.remoteAddress;
      socket.write(message('version', versionPayload(now())));
    });
    socket.on('error', (e) => finish(new Error(e.code || e.message)));
    socket.on('close', () => finish(new Error('the node closed the connection')));
    socket.on('data', (data) => {
      if (ended) return;
      inbox = Buffer.concat([inbox, data]);
      try {
        while (inbox.length >= 24) {
          if (!inbox.subarray(0, 4).equals(MAGIC)) throw new Error('not a Bitcoin message');
          const length = inbox.readUInt32LE(16);
          if (length > MAX_MESSAGE) throw new Error('a message too long');
          if (inbox.length < 24 + length) break;
          const command = inbox.toString('ascii', 4, 16).replace(/\0+$/, '');
          const payload = Buffer.from(inbox.subarray(24, 24 + length));
          if (!sha256d(payload).subarray(0, 4).equals(inbox.subarray(20, 24))) throw new Error('a damaged message');
          inbox = inbox.subarray(24 + length);
          work = work.then(() => (ended ? undefined : handle(command, payload))).catch((e) => finish(e));
        }
      } catch (e) {
        finish(e);
      }
    });
  });
}

// An IPv6 address written out in full: eight groups.
function ipv6Groups(text) {
  const [head, tail] = text.split('::');
  const part = (s) => (s ? s.split(':') : []);
  const groups = tail === undefined ? part(head) : [...part(head), ...Array(8 - part(head).length - part(tail).length).fill('0'), ...part(tail)];
  return groups.map((g) => parseInt(g || '0', 16).toString(16));
}

/**
 * The network a node is on, as Bitcoin nodes themselves group addresses:
 * the first two numbers of an IPv4 address (also when written as IPv6),
 * the first two groups of an IPv6 address, and otherwise the name.
 * @param {{host: string, connected?: string}} node
 */
export function networkOf(node) {
  let address = String(node.connected ?? node.host).toLowerCase().replace(/%.*$/, '').replace(/\.$/, '');
  address = address.replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/, '$1');
  if (/^\d+\.\d+\.\d+\.\d+$/.test(address)) return address.split('.').slice(0, 2).join('.');
  if (address.includes(':')) return ipv6Groups(address).slice(0, 2).join(':');
  return address;
}

/** Two nodes are apart if they are on different networks, judged by the address each was reached at. */
export function apart(a, b) {
  return networkOf(a) !== networkOf(b);
}

/**
 * Read a node's address: "host:port", "[IPv6]:port", or a host alone (port
 * 8333). Anything after "#" on a line is set aside, so that a list of
 * nodes with notes can be read as it is. Hidden-service names are not
 * taken: they cannot be reached directly.
 * @param {string} text
 * @returns {{host: string, port: number} | null}
 */
export function nodeAddress(text) {
  const line = String(text).split('#')[0].trim();
  const m = line.match(/^\[([0-9a-fA-F:.]+)\](?::(\d{1,5}))?$/) ?? line.match(/^([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)\.?(?::(\d{1,5}))?$/);
  if (!m) return null;
  const host = m[1].toLowerCase();
  const port = m[2] === undefined ? 8333 : Number(m[2]);
  if (port < 1 || port > 65535 || host.endsWith('.onion') || host === 'onion') return null;
  return { host, port };
}

/**
 * Bring a chain of headers up to date from the nodes named, one after
 * another, in the order given: a node that fails, falls silent or runs out
 * of time is left, and the next carries on from where the chain stands.
 * Then a second node, on a network apart from every node that gave headers
 * in this run, must hand back the latest blocks itself: it is asked for
 * them from six blocks before the latest, on a copy of the chain, and must
 * give the same latest block. Blocks it holds beyond that are not taken.
 *
 * @param {object} o
 * @param {ReturnType<import('../src/headers.js').startHeaderChain>} o.chain the chain so far, checked; it is added to
 * @param {{host: string, port: number}[]} o.nodes the nodes the person named
 * @param {(line: string) => void} [o.log]
 * @param {() => number} [o.now] the clock
 * @param {number} [o.stale] a latest block older than this, in milliseconds, means the node is behind
 * @param {{answer?: number, between?: number, broken?: number, session?: number}} [o.waits] how long to wait, in milliseconds
 * @returns {Promise<{from: number, to: number, by: object, agreed: object}>}
 */
export async function fetchHeaders({ chain, nodes, log = () => {}, now = Date.now, stale = 6 * 3600 * 1000, waits = {} }) {
  const w = { answer: 15000, between: 60000, broken: 60000, session: 15 * 60000, ...waits };
  // A chain starts with its first block, which every node knows.
  if (chain.height < 0) await chain.add(Uint8Array.from(Buffer.from(chain.rules.first, 'hex')), now());
  const from = chain.height;
  let next = 0;
  let by = null;
  let breaks = 0;
  // The nodes that gave headers in this run: the witness must be apart from each.
  const gave = [];
  const name = (node) => (node.host.includes(':') ? `[${node.host}]:${node.port}` : `${node.host}:${node.port}`);
  while (by === null) {
    if (next >= nodes.length) throw new Error('No node named gave the chain up to a recent block.');
    const node = { ...nodes[next++] };
    // A line every 100,000 blocks, so that a first fetch, which takes minutes, is seen to go on.
    let step = Math.floor(chain.height / 100000);
    const progress = () => {
      if (Math.floor(chain.height / 100000) > step) {
        step = Math.floor(chain.height / 100000);
        log(`${name(node)}: block ${chain.height} reached`);
      }
    };
    try {
      const given = await session(node, chain, { now, waits: w, progress });
      if (given > 0) gave.push(node);
      log(`${name(node)}: ${given} headers; the latest block held is ${chain.height}`);
    } catch (e) {
      if (e.given > 0) gave.push(node);
      log(`${name(node)}: ${e.message}; ${e.given ?? 0} headers taken from it`);
      // Where this device's own network is down, wait, then ask the same node again.
      if (/ENETUNREACH|ENETDOWN/.test(e.message)) {
        if (++breaks > 10) throw new Error('The network stayed unreachable from this device.');
        await new Promise((r) => setTimeout(r, w.broken));
        next--;
      }
      continue;
    }
    if (now() - chain.timeAt(chain.height) < stale) by = node;
    else log(`${name(node)}: its latest block is more than ${Math.round(stale / 3600000)} hours old; asking another node`);
  }
  const height = chain.height;
  const tip = chain.fingerprintAt(height);
  const start = Math.max(0, height - MIN_BLOCKS_AFTER);
  let agreed = null;
  while (agreed === null && next < nodes.length) {
    const node = { ...nodes[next++] };
    const check = chain.copy();
    check.keepTo(start);
    try {
      await session(node, check, { now, waits: w });
    } catch (e) {
      log(`${name(node)}: ${e.message}`);
      continue;
    }
    // Judged by the address reached: the same node under two names is one witness.
    if (![by, ...gave].every((other) => apart(node, other))) {
      log(`${name(node)}: on the same network as a node that gave headers; not counted as a second node`);
    } else if (check.height >= height && check.fingerprintAt(height) === tip) {
      agreed = node;
      log(`${name(node)}: handed back blocks ${start + 1} to ${height} itself, the same as held`);
    } else log(`${name(node)}: did not hand back the latest block ${height}`);
  }
  if (agreed === null) throw new Error('No second node, on another network, handed back the latest block.');
  return { from, to: chain.height, by, agreed };
}

// A file written beside the chain file, made sure to be on the disk, then
// put in its place, so that a chain file is never left half written.
function writeWhole(file, bytes) {
  const temporary = `${file}.part`;
  try {
    const fd = openSync(temporary, 'w');
    try {
      writeSync(fd, bytes);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(temporary, file);
  } catch (e) {
    try {
      rmSync(temporary, { force: true });
    } catch {
      // something else stands at that name; it is left as it is
    }
    throw new Error(`${file} could not be written (${e.code || e.message}). The chain file is as it was.`);
  }
}

/**
 * Read a chain file (checked in full), bring it up to date from the nodes
 * named, and write it back: only where it grew, or a branch with more work
 * replaced its end, and never shorter than it was read. A run that fails
 * keeps what it fetched and checked, where that is more than the file held.
 *
 * @param {object} o
 * @param {string} o.file
 * @param {{host: string, port: number}[]} o.nodes
 * @param {object} [o.rules] the chain's rules; Bitcoin's by default
 * @param {(line: string) => void} [o.log]
 * @param {() => number} [o.now]
 * @param {number} [o.stale]
 * @param {object} [o.waits]
 * @returns {Promise<{chain: object, before: number}>} the chain, and the latest block the file held before
 * @throws {Error} with a message that says what was done with the file
 */
export async function updateChainFile({ file, nodes, rules = BITCOIN, log = () => {}, now = Date.now, stale, waits }) {
  let chain;
  let before = -1;
  let beforeTip = null;
  if (existsSync(file)) {
    log(`Checking the chain already in ${file} …`);
    try {
      chain = await readHeaderChain(new Uint8Array(readFileSync(file)), { partial: true, rules, now: now() });
    } catch (e) {
      throw new Error(`The chain in ${file} could not be used: ${e.message} Move the file away, or name another with --chain.`);
    }
    before = chain.height;
    beforeTip = chain.fingerprintAt(before);
    log(`It holds blocks 0 to ${before}, and every header checks.`);
  } else chain = startHeaderChain(rules);

  let failure = null;
  try {
    await fetchHeaders({ chain, nodes, log, now, stale, waits });
    const last = rules.known.length ? rules.known.at(-1)[0] : -1;
    if (chain.height < last) failure = `The chain ends at block ${chain.height}, before block ${last}, which is known to be part of it.`;
  } catch (e) {
    failure = e.message;
  }
  const changed = chain.height > before || (before >= 0 && chain.height === before && chain.fingerprintAt(before) !== beforeTip);
  if (failure) {
    // Kept only where more is held than the file held, and more than the first block alone.
    if (chain.height > before && chain.height > 0) {
      writeWhole(file, chain.bytes());
      throw new Error(`${failure} The ${chain.height - Math.max(before, 0)} headers fetched and checked so far are kept in ${file}; run again to carry on.`);
    }
    throw new Error(`${failure} ${before >= 0 ? `The chain in ${file} is as it was.` : 'Nothing was written.'}`);
  }
  if (chain.height < before) throw new Error(`The nodes' chain ends at block ${chain.height}, before block ${before}, which the file already holds. The chain in ${file} is as it was.`);
  if (changed) writeWhole(file, chain.bytes());
  return { chain, before };
}
