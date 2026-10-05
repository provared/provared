// The chain of block headers: checked on this device (src/headers.js), and
// fetched from nodes the person names (net/headers.js). The chains here are
// made up, at the easiest difficulty, from a first block made up here; no
// real node is asked. The rules of the real chain are tested with real
// values: its first block, and two changes of difficulty.

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { apart, fetchHeaders, networkOf, nodeAddress, updateChainFile } from '../net/headers.js';
import { BITCOIN, MIN_BLOCKS_AFTER, answerFor, blocksInChain, checkHeaderChain, nextBits, readHeaderChain, startHeaderChain } from '../src/headers.js';
import { checkBook, toBase64url } from '../src/index.js';
import { makeBlockStamp } from './helpers/blockstamp.mjs';
import { START, makeWorld } from './helpers/world.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const sha256d = (b) => createHash('sha256').update(createHash('sha256').update(b).digest()).digest();
const written = (hash) => Buffer.from(hash).reverse().toString('hex');
const EASY = 0x207fffff; // the easiest target these made-up chains use: about one hash in two meets it

/** A header that meets its target: the nonce is tried until it does (or, with "fail", until it does not). */
function mine({ previous, time, bits = EASY, root = Buffer.alloc(32, 7), fail = false, version = 0x20000000 }) {
  const header = Buffer.alloc(80);
  header.writeInt32LE(version, 0);
  Buffer.from(previous).copy(header, 4);
  Buffer.from(root).copy(header, 36);
  header.writeUInt32LE(time, 68);
  header.writeUInt32LE(bits, 72);
  const exponent = bits >>> 24;
  const target = BigInt(bits & 0x7fffff) << BigInt(8 * (exponent - 3));
  for (let nonce = 0; ; nonce++) {
    header.writeUInt32LE(nonce, 76);
    const meets = BigInt('0x' + written(sha256d(header))) <= target;
    if (meets !== fail) return new Uint8Array(header);
  }
}

const FIRST = mine({ previous: Buffer.alloc(32), time: Math.floor(START / 1000) - 365 * 86400 });
/** The rules of a made-up chain: its own first block, the easiest target, and no change of difficulty. */
const RULES = { first: Buffer.from(FIRST).toString('hex'), limit: (1n << 255n) - 1n, interval: 2016, timespan: 1209600, retarget: false, known: [] };

/** A made-up chain of n headers after the first, ten minutes apart. "at" changes the header at one place. */
function chainOf(n, { from = FIRST, start = Math.floor(START / 1000) - 365 * 86400, at = {}, rootAt = {} } = {}) {
  const headers = [from];
  for (let h = 1; h <= n; h++) {
    const previous = sha256d(headers[h - 1]);
    const plain = { previous, time: start + h * 600, root: rootAt[h] ?? Buffer.alloc(32, h % 251) };
    headers.push(mine({ ...plain, ...(at[h] ? at[h]({ ...plain, headers }) : {}) }));
  }
  return headers;
}
const joined = (headers) => new Uint8Array(Buffer.concat(headers.map((h) => Buffer.from(h))));
const lastTime = (headers) => Buffer.from(headers.at(-1)).readUInt32LE(68) * 1000;
const read = (headers, o = {}) => readHeaderChain(joined(headers), { rules: RULES, now: lastTime(headers) + 3600 * 1000, ...o });

// --- the rules of the real chain, with real values ---

test('the real chain: its first block, and two changes of difficulty, as every node computes them', async () => {
  assert.equal(written(sha256d(Buffer.from(BITCOIN.first, 'hex'))), '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
  // The first change of difficulty, at block 32,256, and one at block 967,680.
  assert.equal(nextBits(0x1d00ffff, 1261130161, 1262152739), 0x1d00d86a);
  assert.equal(nextBits(0x1702355e, 1788640367, 1789801627), 0x17021ec5);
  // Never easier than the limit, and by at most four times either way.
  assert.equal(nextBits(0x1d00ffff, 0, 10 * 1209600), 0x1d00ffff);
  assert.equal(nextBits(0x1702355e, 0, 1), nextBits(0x1702355e, 0, 1209600 / 4));
  // The known blocks are in order, and each is a block's fingerprint.
  const heights = BITCOIN.known.map(([h]) => h);
  assert.deepEqual(heights, [...heights].sort((a, b) => a - b));
  for (const [, fingerprint] of BITCOIN.known) assert.match(fingerprint, /^0{8}[0-9a-f]{56}$/);
  // A chain file of the real chain that holds only its first block ends before the known blocks.
  await assert.rejects(checkHeaderChain(Uint8Array.from(Buffer.from(BITCOIN.first, 'hex'))), (e) => e.code === 'headers-invalid' && /before block 969696/.test(e.message));
});

// --- a made-up chain, checked ---

test('a sound chain is read, and a block is found with the number of blocks after it', async () => {
  const headers = chainOf(30);
  const chain = await read(headers);
  assert.equal(chain.height, 30);
  assert.equal(chain.fingerprintAt(30), written(sha256d(headers[30])));
  assert.equal(chain.heightOf(written(sha256d(headers[12]))), 12);
  assert.equal(chain.heightOf('0'.repeat(64)), -1);
  assert.equal(chain.heightOf('not a fingerprint'), -1);
  assert.deepEqual(chain.bytes(), joined(headers));
});

test('headers-invalid: each rule a node applies to headers is applied here', async () => {
  const cases = {
    'it does not name the block before it': chainOf(12, { at: { 5: () => ({ previous: Buffer.alloc(32, 1) }) } }),
    'does not carry the work it claims': chainOf(12, { at: { 5: () => ({ fail: true }) } }),
    'its difficulty does not follow the rule': chainOf(12, { at: { 5: () => ({ bits: 0x2007ffff }) } }),
    'not later than the middle of the eleven': chainOf(14, { at: { 13: ({ headers }) => ({ time: Buffer.from(headers[3]).readUInt32LE(68) }) } }),
  };
  for (const [words, headers] of Object.entries(cases)) {
    await assert.rejects(read(headers), (e) => e.code === 'headers-invalid' && e.message.includes(words), words);
  }
  // A time more than two hours ahead of this device's clock.
  const ahead = chainOf(5);
  await assert.rejects(read(ahead, { now: lastTime(ahead) - 3 * 3600 * 1000 }), (e) => /two hours ahead/.test(e.message));
  // Another first block; not whole headers; nothing at all.
  await assert.rejects(read(chainOf(3, { from: mine({ previous: Buffer.alloc(32, 9), time: 1 }) })), (e) => /Block 0/.test(e.message));
  await assert.rejects(readHeaderChain(joined(chainOf(3)).subarray(0, 250), { rules: RULES }), (e) => e.code === 'headers-invalid');
  await assert.rejects(readHeaderChain(new Uint8Array(0), { rules: RULES }), (e) => e.code === 'headers-invalid');
});

test('a chain must hold the known blocks at their places, and reach the last of them', async () => {
  const headers = chainOf(20);
  const right = written(sha256d(headers[10]));
  await read(headers, { rules: { ...RULES, known: [[10, right]] } });
  await assert.rejects(read(headers, { rules: { ...RULES, known: [[10, written(sha256d(headers[11]))]] } }), (e) => /Block 10: it is not the block known/.test(e.message));
  // One that ends before the last known block is refused, unless the command that fetches is carrying it on.
  const short = { ...RULES, known: [[25, '0'.repeat(64)]] };
  await assert.rejects(read(headers, { rules: short }), (e) => /ends at block 20, before block 25/.test(e.message));
  assert.equal((await read(headers, { rules: short, partial: true })).height, 20);
});

test('where the difficulty changes, the new one must be the one computed', async () => {
  const rules = { ...RULES, retarget: true, interval: 10, timespan: 1000 };
  // Blocks a minute apart: the run of ten took 540 seconds against 1,000, so the target shrinks.
  const build = (bitsAt10) => {
    const headers = [FIRST];
    const start = Buffer.from(FIRST).readUInt32LE(68);
    for (let h = 1; h <= 12; h++) {
      const bits = h < 10 ? EASY : h === 10 ? bitsAt10(headers) : Buffer.from(headers[10]).readUInt32LE(72);
      headers.push(mine({ previous: sha256d(headers[h - 1]), time: start + h * 60, bits }));
    }
    return headers;
  };
  const computed = (headers) => nextBits(EASY, Buffer.from(headers[0]).readUInt32LE(68), Buffer.from(headers[9]).readUInt32LE(68), rules);
  assert.notEqual(computed(build(() => EASY)), EASY);
  const good = build(computed);
  assert.equal((await read(good, { rules })).height, 12);
  await assert.rejects(read(build(() => EASY), { rules }), (e) => /Block 10: its difficulty does not follow the rule/.test(e.message));
});

// --- the blocks a record's block time-stamps lead to ---

test('a block time-stamp counts once its block is in a checked chain with six blocks after it', async () => {
  const w = await makeWorld();
  await w.add({ when: START + 3600 * 1000 });
  const sealed = await w.seal({ stamp: false });
  const stamp = await makeBlockStamp(sealed.fingerprintBytes, sealed.when + 3600 * 1000);
  // A made-up chain whose block 20 holds the proof's Merkle root, an hour after the seal.
  const sealTime = Math.floor((sealed.when + 3600 * 1000) / 1000);
  const headers = chainOf(30, { start: sealTime - 20 * 600, rootAt: { 20: Buffer.from(stamp.header.subarray(36, 68)) } });
  sealed.entry.stamps = [{ block: toBase64url(headers[20]), proof: toBase64url(stamp.proof) }];
  const book = w.book();
  const block = written(sha256d(headers[20]));

  const answer = async (upTo) => {
    const chain = await read(headers.slice(0, upTo + 1));
    const find = (fp) => {
      const h = chain.heightOf(fp);
      return h < 0 ? null : { height: h, after: chain.height - h };
    };
    return blocksInChain(await checkBook(book), { find });
  };
  const enough = await answer(20 + MIN_BLOCKS_AFTER);
  assert.deepEqual(enough.blocks, [block]);
  assert.deepEqual(enough.found, [{ block, stated: 912345, height: 20, after: MIN_BLOCKS_AFTER, counted: true }]);
  const counted = await checkBook(book, { blocks: enough.blocks });
  assert.equal(counted.entries.at(-1).stamps[0].state, 'valid');
  // With fewer blocks after it, or not in the chain at all, it is not counted.
  assert.deepEqual((await answer(20 + MIN_BLOCKS_AFTER - 1)).blocks, []);
  assert.deepEqual((await answer(19)).found[0].height, null);
});

// --- the chain check: what the review of the header tool found ---

test('a header version below what the upgrades ask is refused, and so is a target of zero', async () => {
  const rules = { ...RULES, versions: [[5, 4]] };
  await read(chainOf(8), { rules });
  await assert.rejects(read(chainOf(8, { at: { 6: () => ({ version: 3 }) } }), { rules }), (e) => /Block 6: its version is lower than every block from 5 on must have/.test(e.message));
  // A first block whose bits stand for a target of zero: no header after it can be counted.
  const zero = Buffer.from(FIRST);
  zero.writeUInt32LE(0x01000000, 72);
  const header = Buffer.from(mine({ previous: sha256d(zero), time: Buffer.from(FIRST).readUInt32LE(68) + 600 }));
  header.writeUInt32LE(0x01000000, 72);
  await assert.rejects(read([zero, header], { rules: { ...RULES, first: zero.toString('hex') } }), (e) => /Block 1: its hash does not meet its target/.test(e.message));
});

test('after the last known block, no target may be more than four times easier than its', async () => {
  // A made-up chain that starts well below the limit (a target of 2 to the
  // power 245), and whose difficulty changes every ten blocks.
  const hard = 0x1f200000;
  const t0 = Math.floor(START / 1000) - 365 * 86400;
  const first = mine({ previous: Buffer.alloc(32), time: t0, bits: hard });
  const rules = { ...RULES, first: Buffer.from(first).toString('hex'), retarget: true, interval: 10, timespan: 1000 };
  const headers = [first];
  const at = (h) => Buffer.from(headers[h]);
  for (let h = 1; h <= 30; h++) {
    const bits = h % 10 === 0 ? nextBits(at(h - 1).readUInt32LE(72), at(h - 10).readUInt32LE(68), at(h - 1).readUInt32LE(68), rules) : at(h - 1).readUInt32LE(72);
    // The first run is quick; the next two are dated so long that the target eases four times at each change.
    const time = h <= 10 ? t0 + h * 100 : t0 + 1000 + (h - 10) * 1000;
    headers.push(mine({ previous: sha256d(headers[h - 1]), time, bits }));
  }
  const now = at(30).readUInt32LE(68) * 1000 + 3600 * 1000;
  const known = { ...rules, known: [[10, written(sha256d(headers[10]))]] };
  // To block 29 the target is at most four times block 10's; at block 30 it is sixteen times.
  assert.equal((await readHeaderChain(joined(headers.slice(0, 30)), { rules: known, now })).height, 29);
  await assert.rejects(readHeaderChain(joined(headers), { rules: known, now }), (e) => /Block 30: its target is more than four times easier than that of block 10/.test(e.message));
  // Without a known block there is nothing to measure against, and the chain is read: the rule is what refuses it.
  assert.equal((await readHeaderChain(joined(headers), { rules, now })).height, 30);
});

test('the answer for a checked chain finds blocks; the Web Crypto path gives the same', async () => {
  const headers = chainOf(30);
  const chain = await read(headers);
  const answer = answerFor(chain);
  assert.equal(answer.height, 30);
  assert.equal(answer.tip, written(sha256d(headers[30])));
  assert.equal(answer.tipWhen, new Date(lastTime(headers)).toISOString().slice(0, 19) + 'Z');
  assert.deepEqual(answer.find(written(sha256d(headers[24]))), { height: 24, after: 6 });
  assert.equal(answer.find('f'.repeat(64)), null);
  const viaWeb = await read(headers, { webCrypto: true });
  assert.deepEqual(viaWeb.bytes(), chain.bytes());
  const changed = joined(headers);
  changed[15 * 80 + 40] ^= 1;
  await assert.rejects(readHeaderChain(changed, { rules: RULES, now: lastTime(headers) + 3600000, webCrypto: true }), (e) => e.code === 'headers-invalid');
});

// --- fetching from nodes ---

/**
 * A made-up node on this computer that answers as a Bitcoin node does:
 * the greeting, a "ping", and headers from the latest block it knows of
 * those asked about. It listens on IPv4 and IPv6 alike, so that one node
 * can be reached at 127.0.0.1 and at ::1, two networks. "behaviour"
 * changes what it does.
 */
async function fakeNode(headers, behaviour = {}) {
  const hashes = headers.map((h) => sha256d(h));
  const seen = { pongs: [], connections: 0 };
  const frame = (command, payload = Buffer.alloc(0), bad = {}) => {
    const head = Buffer.alloc(24);
    (bad.magic ?? Buffer.from('f9beb4d9', 'hex')).copy(head, 0);
    head.write(command, 4, 'ascii');
    head.writeUInt32LE(bad.length ?? payload.length, 16);
    sha256d(payload).copy(head, 20, 0, 4);
    if (bad.checksum) head[20] ^= 1;
    return Buffer.concat([head, payload]);
  };
  const server = net.createServer((socket) => {
    seen.connections++;
    let inbox = Buffer.alloc(0);
    let timer = null;
    socket.on('error', () => {});
    socket.on('close', () => clearInterval(timer));
    socket.on('data', (data) => {
      if (behaviour.silent) return;
      inbox = Buffer.concat([inbox, data]);
      while (inbox.length >= 24 && inbox.length >= 24 + inbox.readUInt32LE(16)) {
        const length = inbox.readUInt32LE(16);
        const command = inbox.toString('ascii', 4, 16).replace(/\0+$/, '');
        const payload = inbox.subarray(24, 24 + length);
        inbox = inbox.subarray(24 + length);
        if (command === 'version') {
          socket.write(Buffer.concat([frame('version', Buffer.alloc(86)), frame('verack'), frame('ping', Buffer.from('12345678'))]));
          if (behaviour.pings) timer = setInterval(() => socket.write(frame('ping', Buffer.from('87654321'))), behaviour.pings);
          if (behaviour.flood) for (let i = 0; i < behaviour.flood; i++) socket.write(frame('ping', Buffer.from('abcdefgh')));
          if (behaviour.oddPing) socket.write(frame('ping', Buffer.alloc(100)));
          if (behaviour.garbage) socket.write(frame('inv', Buffer.alloc(10), behaviour.garbage));
        } else if (command === 'pong') seen.pongs.push(payload.toString());
        else if (command === 'getheaders') {
          if (behaviour.neverHeaders) continue;
          const count = payload[4];
          let from = 0;
          for (let i = 0; i < count; i++) {
            const asked = payload.subarray(5 + i * 32, 5 + i * 32 + 32);
            const at = hashes.findIndex((h) => h.equals(asked));
            if (at >= 0) {
              from = at;
              break;
            }
          }
          const page = behaviour.empty ? [] : headers.slice(from + 1, from + 1 + 2000);
          const body = Buffer.concat([Buffer.from(page.length < 0xfd ? [page.length] : [0xfd, page.length & 0xff, page.length >> 8]), ...page.map((h) => Buffer.concat([Buffer.from(h), Buffer.from([0])]))]);
          const send = () => socket.write(frame('headers', body));
          if (behaviour.delay) setTimeout(send, behaviour.delay);
          else send();
        }
      }
    });
  });
  await new Promise((resolve) => server.listen({ port: 0, host: '::', ipv6Only: false }, resolve));
  return { port: server.address().port, seen, close: () => new Promise((resolve) => server.close(resolve)) };
}

const LONG = chainOf(4100);
const v4 = (node) => ({ host: '127.0.0.1', port: node.port });
const v6 = (node) => ({ host: '::1', port: node.port });
const WAITS = { answer: 2000, between: 1500, broken: 10, session: 20000 };
const fetchFrom = (nodes, o = {}) => {
  const chain = o.chain ?? startHeaderChain(RULES);
  return fetchHeaders({ chain, nodes, now: () => lastTime(LONG) + 600 * 1000, waits: WAITS, ...o }).then((r) => ({ ...r, chain }));
};
const closeAll = async (...nodes) => {
  for (const n of nodes) await n.close();
};

test('the chain is fetched page by page from one node, and a second node on another network must hand back the latest blocks', async () => {
  const one = await fakeNode(LONG);
  const two = await fakeNode(LONG);
  try {
    // The second node reached on the first one's network is passed over; the one on another network is the witness.
    const lines = [];
    const r = await fetchFrom([v4(one), v4(two), v6(two)], { log: (l) => lines.push(l) });
    assert.equal(r.chain.height, 4100);
    assert.deepEqual(r.chain.bytes(), joined(LONG));
    assert.equal(r.agreed.host, '::1');
    assert.match(lines.join('\n'), /on the same network as a node that gave headers/);
    assert.match(lines.join('\n'), /handed back blocks 4095 to 4100 itself/);
    assert.deepEqual(one.seen.pongs, ['12345678']);
  } finally {
    await closeAll(one, two);
  }
});

test('a node that gives a false header, falls silent, or is behind is left, and the next carries on', async () => {
  const liar = await fakeNode(chainOf(4100, { at: { 2500: () => ({ fail: true }) } }));
  const silent = await fakeNode(LONG, { silent: true });
  const behind = await fakeNode(LONG.slice(0, 3000));
  const good = await fakeNode(LONG);
  const lines = [];
  try {
    const r = await fetchFrom([v4(liar), v4(silent), v4(behind), v4(good), v6(good)], { log: (l) => lines.push(l) });
    assert.equal(r.chain.height, 4100);
    assert.deepEqual(r.chain.bytes(), joined(LONG));
    assert.match(lines.join('\n'), /Block 2500: its hash does not meet its target/);
    assert.match(lines.join('\n'), /no answer for 2 seconds/);
    assert.match(lines.join('\n'), /more than 6 hours old/);
  } finally {
    await closeAll(liar, silent, behind, good);
  }
});

test('an empty answer, a node behind, or the same node under another name is no second node', async () => {
  const one = await fakeNode(LONG);
  const empty = await fakeNode(LONG, { empty: true });
  const behind = await fakeNode(LONG.slice(0, 4099));
  const other = await fakeNode(chainOf(4100, { at: { 100: () => ({ time: Math.floor(lastTime(LONG.slice(0, 100)) / 1000) + 1 }) } }));
  try {
    for (const witness of [v6(empty), v6(behind), v6(other), v4(one), { host: '::ffff:127.0.0.1', port: one.port }]) {
      await assert.rejects(fetchFrom([v4(one), witness]), /No second node, on another network, handed back the latest block/, witness.host);
    }
  } finally {
    await closeAll(one, empty, behind, other);
  }
});

test('a branch near the end is taken on only if it carries more work', async () => {
  // Two branches from block 4095: one as long as the chain held, one a block longer.
  const twin = chainOf(4100, { at: { 4096: () => ({ root: Buffer.alloc(32, 99) }) } });
  const longer = chainOf(4101, { at: { 4096: () => ({ root: Buffer.alloc(32, 99) }) } });
  const same = await fakeNode(twin);
  const more = await fakeNode(longer);
  try {
    const held = await read(LONG);
    const lines = [];
    await assert.rejects(fetchFrom([v4(same), v6(same)], { chain: held, log: (l) => lines.push(l) }));
    assert.match(lines.join('\n'), /its branch carries no more work than the chain held here/);
    assert.deepEqual(held.bytes(), joined(LONG));
    const r = await fetchFrom([v4(more), v6(more)], { chain: held });
    assert.equal(r.chain.height, 4101);
    assert.deepEqual(r.chain.bytes(), joined(longer));
  } finally {
    await closeAll(same, more);
  }
});

test('a node cannot hold a session open with messages of its own, flood it, or send what is not a Bitcoin message', async () => {
  const pinger = await fakeNode(LONG, { pings: 200, neverHeaders: true });
  const flood = await fakeNode(LONG, { flood: 20000, neverHeaders: true });
  const odd = await fakeNode(LONG, { oddPing: true, neverHeaders: true });
  const bad = [
    await fakeNode(LONG, { garbage: { magic: Buffer.from('00000000', 'hex') } }),
    await fakeNode(LONG, { garbage: { checksum: true } }),
    await fakeNode(LONG, { garbage: { length: 5_000_000 } }),
  ];
  const slow = await fakeNode(LONG, { delay: 700 });
  try {
    const lines = [];
    const started = Date.now();
    await assert.rejects(fetchFrom([v4(pinger), v4(flood), v4(odd), ...bad.map(v4)], { log: (l) => lines.push(l) }));
    const said = lines.join('\n');
    assert.ok(Date.now() - started < 15000, `took ${Date.now() - started} ms`);
    assert.equal((said.match(/no answer for 1\.5 seconds/g) ?? []).length, 3, said);
    assert.deepEqual(odd.seen.pongs, ['12345678']);
    assert.match(said, /not a Bitcoin message/);
    assert.match(said, /a damaged message/);
    assert.match(said, /a message too long/);
    // A node slower than the time each node is given is left, and what it gave is kept.
    const slowLines = [];
    await assert.rejects(fetchFrom([v4(slow)], { waits: { ...WAITS, session: 1000 }, log: (l) => slowLines.push(l) }));
    assert.match(slowLines.join('\n'), /more than 1 seconds with one node; 2000 headers taken from it/);
  } finally {
    await closeAll(pinger, flood, odd, ...bad, slow);
  }
});

test('addresses of nodes are read strictly, and nodes are grouped by the network they are on', () => {
  assert.deepEqual(nodeAddress('203.0.113.5:8333 # a note'), { host: '203.0.113.5', port: 8333 });
  assert.deepEqual(nodeAddress('[2001:db8::1]:18333'), { host: '2001:db8::1', port: 18333 });
  assert.deepEqual(nodeAddress('Node.Example.'), { host: 'node.example', port: 8333 });
  for (const bad of ['', 'abc.onion:8333', 'abc.ONION', 'abc.onion.', 'host:0', 'host:70000', 'a b:1', 'http://node.example', 'a..b']) {
    assert.equal(nodeAddress(bad), null, bad);
  }
  assert.equal(apart({ host: '203.0.113.5' }, { host: '203.0.200.9' }), false);
  assert.equal(apart({ host: '203.0.113.5' }, { host: '198.51.100.7' }), true);
  assert.equal(apart({ host: 'x', connected: '::ffff:203.0.113.5' }, { host: 'y', connected: '203.0.9.9' }), false);
  assert.equal(apart({ host: '2001:db8::1' }, { host: '2001:db8:0:0::2' }), false);
  assert.equal(apart({ host: '2001:db8::1' }, { host: '2001:db9::1' }), true);
  assert.equal(networkOf({ host: 'Node.Example.' }), 'node.example');
});

// --- keeping the chain in a file ---

test('the chain file is written only where it grew, never shorter, and kept as it was when it cannot be used', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'provared-'));
  const file = join(dir, 'chain.bin');
  const good = await fakeNode(LONG);
  const partial = await fakeNode(chainOf(4100, { at: { 3000: () => ({ fail: true }) } }));
  const short = await fakeNode(LONG.slice(0, 4000));
  const update = (nodes, o = {}) => updateChainFile({ file, nodes, rules: RULES, now: () => lastTime(LONG) + 600 * 1000, waits: WAITS, ...o });
  try {
    // No node answers: nothing is written, not even the first block.
    await assert.rejects(update([{ host: '127.0.0.1', port: 9 }, { host: '::1', port: 9 }]), /Nothing was written/);
    assert.equal(existsSync(file), false);
    // A node that stops part of the way, with no other: what was checked is kept.
    await assert.rejects(update([v4(partial)]), /The 2999 headers fetched and checked so far are kept/);
    assert.equal(readFileSync(file).length, 3000 * 80);
    // Carried on to the end.
    const r = await update([v4(good), v6(good)]);
    assert.equal(r.before, 2999);
    assert.deepEqual(new Uint8Array(readFileSync(file)), joined(LONG));
    // Nodes whose chain is shorter leave the file as it was.
    await assert.rejects(update([v4(short), v6(short)]), /is as it was/);
    assert.deepEqual(new Uint8Array(readFileSync(file)), joined(LONG));
    // A file that cannot be written is said so, with nothing left half written.
    await assert.rejects(update([v4(good), v6(good)], { file: join(dir, 'no-such-folder', 'chain.bin') }), /could not be written/);
  } finally {
    await closeAll(good, partial, short);
  }
});

// --- the two commands ---

const run = (command, ...args) => {
  const r = spawnSync(process.execPath, [join(root, 'bin', command), ...args], { encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
};

test('provared-headers asks no one without two nodes named, and keeps a chain file it cannot use as it is', () => {
  assert.equal(run('provared-headers.mjs', '--help').code, 0);
  const none = run('provared-headers.mjs');
  assert.equal(none.code, 2);
  assert.match(none.err, /Name at least two nodes/);
  assert.equal(run('provared-headers.mjs', '--node', 'not an address').code, 2);
  const file = join(mkdtempSync(join(tmpdir(), 'provared-')), 'chain.bin');
  writeFileSync(file, 'not a chain');
  const r = run('provared-headers.mjs', '--chain', file, '--node', '127.0.0.1:9', '--node', 'localhost:9');
  assert.equal(r.code, 2);
  assert.match(r.err, /could not be used/);
  assert.equal(readFileSync(file, 'utf8'), 'not a chain');
});

test('provared-check --headers refuses a file that is not the real chain, before checking anything', () => {
  const dir = mkdtempSync(join(tmpdir(), 'provared-'));
  const sample = join(root, 'samples', 'office-supplies.jsonl');
  for (const [name, bytes, words] of [
    ['made-up.bin', joined(chainOf(5)), /Block 0: this is not the chain's first block/],
    ['first-only.bin', Buffer.from(BITCOIN.first, 'hex'), /before block 969696/],
  ]) {
    writeFileSync(join(dir, name), bytes);
    const r = run('provared-check.mjs', sample, '--headers', join(dir, name));
    assert.equal(r.code, 2, name);
    assert.match(r.err, words);
  }
  assert.equal(run('provared-check.mjs', sample, '--headers', join(dir, 'missing.bin')).code, 2);
});

// The two commands, built for a made-up chain: a whole copy of the code in
// which only the rules of the chain are those of the made-up one. So what
// they print, and how the command that fetches keeps its file, can be
// tried end to end with made-up nodes.
function madeUpBuild() {
  const dir = mkdtempSync(join(tmpdir(), 'provared-build-'));
  for (const part of ['src', 'bin', 'net', 'package.json']) cpSync(join(root, part), join(dir, part), { recursive: true });
  const file = join(dir, 'src', 'headers.js');
  const text = readFileSync(file, 'utf8');
  const start = text.indexOf('export const BITCOIN = Object.freeze({');
  const end = text.indexOf('\n});\n', start) + 5;
  assert.ok(start > 0 && end > start);
  const made = `export const BITCOIN = Object.freeze({ first: '${RULES.first}', limit: (1n << 255n) - 1n, interval: 2016, timespan: 1209600, retarget: false, versions: [], known: [] });\n`;
  writeFileSync(file, text.slice(0, start) + made + text.slice(end));
  const runs = (command, ...args) => {
    const r = spawnSync(process.execPath, [join(dir, 'bin', command), ...args], { encoding: 'utf8' });
    return { code: r.status, out: r.stdout, err: r.stderr };
  };
  // Run without blocking, so that made-up nodes in this process can answer.
  runs.later = (command, ...args) =>
    new Promise((resolve) => {
      const child = spawn(process.execPath, [join(dir, 'bin', command), ...args]);
      let out = '';
      let err = '';
      child.stdout.on('data', (d) => (out += d));
      child.stderr.on('data', (d) => (err += d));
      child.on('close', (code) => resolve({ code, out, err }));
    });
  return runs;
}

test('with a chain of headers, the checker says why a block counts, and --json says it too', async () => {
  const w = await makeWorld();
  await w.add({ when: START + 3600 * 1000 });
  const sealed = await w.seal({ stamp: false });
  const stamp = await makeBlockStamp(sealed.fingerprintBytes, sealed.when + 3600 * 1000);
  const sealTime = Math.floor((sealed.when + 3600 * 1000) / 1000);
  const recent = Math.floor(Date.now() / 1000) - 30 * 600;
  const headers = chainOf(30, { start: Math.min(sealTime - 20 * 600, recent), rootAt: { 20: Buffer.from(stamp.header.subarray(36, 68)) } });
  sealed.entry.stamps = [{ block: toBase64url(headers[20]), proof: toBase64url(stamp.proof) }];
  const dir = mkdtempSync(join(tmpdir(), 'provared-'));
  const book = join(dir, 'book.jsonl');
  const chainFile = join(dir, 'chain.bin');
  writeFileSync(book, w.book());
  writeFileSync(chainFile, joined(headers));
  const block = written(sha256d(headers[20]));
  const build = madeUpBuild();

  const r = build('provared-check.mjs', book, '--headers', chainFile);
  assert.match(r.out, new RegExp(`BLOCK TIME-STAMP: in block ${block} .*, which the chain of headers you checked holds, with 10 blocks after it\\.`));
  assert.match(r.out, new RegExp(`Block ${block}: number 20, with 10 blocks after it\\. Counted as part of the chain\\. The proof states the number 912345\\.`));
  assert.doesNotMatch(r.out, /which you named as trusted/);
  const json = JSON.parse(build('provared-check.mjs', book, '--headers', chainFile, '--json').out);
  assert.deepEqual(json.headers.found, [{ block, stated: 912345, height: 20, after: 10, counted: true }]);
  // Named with --block, and not in the chain: it counts because it was named, and the checker says so.
  writeFileSync(chainFile, joined(headers.slice(0, 20)));
  const named = build('provared-check.mjs', book, '--headers', chainFile, '--block', block);
  assert.match(named.out, /which you named as trusted/);
  assert.match(named.out, /NOT in this chain\. It counts all the same, because you named it with --block\./);
});

test('provared-headers, built for a made-up chain, fetches, keeps its file, and says what it set aside', async () => {
  const headers = chainOf(4100, { start: Math.floor(Date.now() / 1000) - 4100 * 600 - 600 });
  const node = await fakeNode(headers);
  try {
    const dir = mkdtempSync(join(tmpdir(), 'provared-'));
    const list = join(dir, 'nodes.txt');
    writeFileSync(list, `# made-up nodes\n127.0.0.1:${node.port} # one\nnot a node\n[::1]:${node.port}\n`);
    const chainFile = join(dir, 'chain.bin');
    const r = await madeUpBuild().later('provared-headers.mjs', '--nodes-file', list, '--chain', chainFile);
    assert.equal(r.code, 0, r.out + r.err);
    assert.match(r.out, /1 line of the file of nodes is not the address of a node, and was set aside/);
    assert.match(r.out, /handed back the latest blocks itself/);
    assert.deepEqual(new Uint8Array(readFileSync(chainFile)), joined(headers));
  } finally {
    await node.close();
  }
});
