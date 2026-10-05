// The block time-stamp: a proof that a fingerprint was written into a
// block of a public blockchain, used purely as a clock. Every block here
// is made up: no real chain is involved, and nothing is sent anywhere.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { BLOCK_TIME_ALLOWANCE_MS, blockFingerprint, blockStampItem, checkBlockStamp } from '../src/blockstamp.js';
import { concatBytes, sha256, utf8 } from '../src/encoding.js';
import { checkBook, checkShow, entryLine, formatTime, keySetFingerprint, makeShow, thumbprint } from '../src/index.js';
import { SHA256, blockStatement, header, joinAfter, joinBefore, makeBlockStamp, number, pendingStatement, start } from './helpers/blockstamp.mjs';
import { START, makeWorld } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const MINUTE = 60 * 1000;
const WHEN = Date.parse('2026-10-05T12:00:00Z');
const stamped = await sha256(utf8('what was stamped'));
const code = (expected) => (e) => e.code === expected;

function codes(result) {
  const out = result.problems.map((p) => p.code);
  for (const e of result.entries) out.push(...e.problems.map((p) => p.code), ...e.breaches.map((b) => b.code));
  return out;
}

// --- the proof itself ---

test('a proof that leads to a block the checker named is valid, and states the block\'s time', async () => {
  const s = await makeBlockStamp(stamped, WHEN, { height: 912345 });
  const r = await checkBlockStamp(s.proof, s.header, stamped, [s.fingerprint]);
  assert.deepEqual(r, {
    kind: 'block',
    state: 'valid',
    when: '2026-10-05T12:00:00Z',
    time: WHEN + BLOCK_TIME_ALLOWANCE_MS,
    earliest: WHEN - BLOCK_TIME_ALLOWANCE_MS,
    authority: s.fingerprint,
    height: 912345,
  });
  assert.equal(BLOCK_TIME_ALLOWANCE_MS, 2 * HOUR);
  assert.match(s.fingerprint, /^[0-9a-f]{64}$/);
  // The fingerprint may be given in capitals.
  assert.equal((await checkBlockStamp(s.proof, s.header, stamped, [s.fingerprint.toUpperCase()])).state, 'valid');
});

test('a sound proof that leads to a block the checker did not name is "untrusted", never valid', async () => {
  const s = await makeBlockStamp(stamped, WHEN);
  const other = await makeBlockStamp(stamped, WHEN);
  for (const trusted of [undefined, [], [other.fingerprint], 'everything', [null, 5]]) {
    assert.equal((await checkBlockStamp(s.proof, s.header, stamped, trusted)).state, 'untrusted');
  }
});

test('a proof made for something else, or that does not lead to the block that comes with it, is refused', async () => {
  const s = await makeBlockStamp(stamped, WHEN);
  await assert.rejects(checkBlockStamp(s.proof, s.header, await sha256(utf8('something else')), [s.fingerprint]), code('stamp-wrong-data'));
  const other = await makeBlockStamp(stamped, WHEN);
  await assert.rejects(checkBlockStamp(s.proof, other.header, stamped, [other.fingerprint]), code('stamp-invalid'));
  // A proof that is not yet complete names no block at all.
  const pending = concatBytes(start(stamped), joinAfter(new Uint8Array(8)), SHA256, pendingStatement('https://calendar.example'));
  await assert.rejects(checkBlockStamp(pending, s.header, stamped, [s.fingerprint]), code('stamp-invalid'));
  // A block's statement about a value that is not 32 bytes says nothing.
  const short = concatBytes(start(stamped), joinAfter(new Uint8Array(1)), blockStatement(1));
  const head = header(stamped, WHEN);
  await assert.rejects(checkBlockStamp(short, head, stamped, [await blockFingerprint(head)]), code('stamp-invalid'));
});

test('a proof may also hold statements of other kinds; they say nothing, and the proof still checks', async () => {
  const s = await makeBlockStamp(stamped, WHEN, { pending: true });
  assert.equal((await checkBlockStamp(s.proof, s.header, stamped, [s.fingerprint])).state, 'valid');
  // A statement of a kind this reader does not know, beside the block's.
  const unknown = concatBytes(new Uint8Array([0xff, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]), number(3), utf8('xyz'));
  const direct = concatBytes(start(stamped), unknown, blockStatement(7));
  const head = header(stamped, WHEN);
  assert.equal((await checkBlockStamp(direct, head, stamped, [await blockFingerprint(head)])).height, 7);
});

test('a proof that is not laid out as the format sets out is refused, never crashed on', async () => {
  const s = await makeBlockStamp(stamped, WHEN);
  const bad = code('stamp-bad-data');
  const check = (proof, head = s.header) => checkBlockStamp(proof, head, stamped, [s.fingerprint]);
  // Cut short at every length.
  for (let length = 0; length < s.proof.length; length++) await assert.rejects(check(s.proof.subarray(0, length)), bad, `cut at ${length}`);
  const change = (at, value) => {
    const copy = new Uint8Array(s.proof);
    copy[at] = value;
    return copy;
  };
  await assert.rejects(check(change(1, 0x58)), bad); // not the opening bytes
  await assert.rejects(check(change(31, 2)), bad); // another version
  await assert.rejects(check(change(32, 0x02)), bad); // the first fingerprint is not SHA-256
  await assert.rejects(check(concatBytes(s.proof, new Uint8Array([0]))), bad); // bytes after the end
  // Steps the format has and this reader does not accept, and a step it does not have.
  for (const step of [0x02, 0x03, 0x67, 0xf2, 0xf3, 0x55, 0xff]) {
    await assert.rejects(check(concatBytes(start(stamped), new Uint8Array([step]), blockStatement(1))), bad, `step ${step}`);
  }
  // A number not in its shortest form; a join of nothing; a value that grows too long; steps too deep.
  await assert.rejects(check(concatBytes(start(stamped), new Uint8Array([0xf0, 0x81, 0x00, 0x00]), blockStatement(1))), bad);
  await assert.rejects(check(concatBytes(start(stamped), new Uint8Array([0xf0, 0x00]), blockStatement(1))), bad);
  await assert.rejects(check(concatBytes(start(stamped), joinAfter(new Uint8Array(4090)), blockStatement(1))), bad);
  await assert.rejects(check(concatBytes(start(stamped), ...Array(256).fill(SHA256), blockStatement(1))), bad);
  // 255 steps in a row are allowed, as the format's own reader allows: the proof is then refused only for leading nowhere.
  await assert.rejects(check(concatBytes(start(stamped), ...Array(255).fill(SHA256), blockStatement(1))), code('stamp-invalid'));
  // The block's statement must hold the block's number and nothing more.
  await assert.rejects(check(concatBytes(start(stamped), new Uint8Array([0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01, 0x02, 0x01, 0x01]))), bad);
  // Too large, a header of the wrong length, and things that are not bytes.
  await assert.rejects(check(concatBytes(start(stamped), joinBefore(new Uint8Array(4000)), SHA256, joinBefore(new Uint8Array(4000)), SHA256, joinBefore(new Uint8Array(4000)), SHA256, joinBefore(new Uint8Array(400)), blockStatement(1))), bad);
  await assert.rejects(check(s.proof, s.header.subarray(0, 79)), bad);
  for (const wrong of [null, 'text', 5, [1, 2], {}]) {
    await assert.rejects(check(wrong), bad);
    await assert.rejects(check(s.proof, wrong), bad);
  }
  assert.throws(() => blockStampItem(s.proof, s.header.subarray(1)), bad);
  assert.deepEqual(blockStampItem(s.proof, s.header), s.item);
});

test('no byte of a proof can be changed and leave it valid for the same block, except the block\'s stated number', async () => {
  const s = await makeBlockStamp(stamped, WHEN);
  const sound = await checkBlockStamp(s.proof, s.header, stamped, [s.fingerprint]);
  for (let at = 0; at < s.proof.length; at++) {
    const copy = new Uint8Array(s.proof);
    copy[at] ^= 0x01;
    let result = null;
    try {
      result = await checkBlockStamp(copy, s.header, stamped, [s.fingerprint]);
    } catch (e) {
      assert.ok(['stamp-bad-data', 'stamp-wrong-data', 'stamp-invalid'].includes(e.code), `byte ${at}: ${e.code}`);
    }
    // The block's number is only what the proof says: nothing checks it, and it is shown as such.
    if (result) assert.deepEqual({ ...result, height: 0 }, { ...sound, height: 0 }, `byte ${at}`);
  }
  // And no byte of the header: its fingerprint is what the checker named.
  for (let at = 0; at < 80; at++) {
    const copy = new Uint8Array(s.header);
    copy[at] ^= 0x01;
    const r = await checkBlockStamp(s.proof, copy, stamped, [s.fingerprint]).catch((e) => e);
    assert.ok(r.code === 'stamp-invalid' || r.state === 'untrusted', `header byte ${at}`);
  }
});

// --- beside a seal ---

// One book, sealed twice: first with a block time-stamp only, then with a
// time-stamp from a service and a block time-stamp.
const w = await makeWorld();
await w.add({ when: START });
await w.add({ when: START + HOUR });
const first = await w.seal({ when: START + HOUR + 10 * MINUTE, stamp: false, blockTime: START + 3 * HOUR });
await w.add({ when: START + 2 * HOUR });
const second = await w.seal({ when: START + 2 * HOUR + 10 * MINUTE, blockTime: START + 5 * HOUR });
const blocks = [first.block.fingerprint, second.block.fingerprint];
const lines = w.book().split('\n').filter(Boolean);
const upTo = (n) => lines.slice(0, n).join('\n') + '\n';

test('a seal with only a block time-stamp covers the entries before it, for whoever names the block', async () => {
  const r = await checkBook(upTo(4), { blocks });
  assert.deepEqual(codes(r), []);
  assert.equal(r.summary.intact, true);
  const existedBy = formatTime(START + 3 * HOUR + BLOCK_TIME_ALLOWANCE_MS);
  assert.deepEqual(r.summary.sealed, { entries: 3, when: existedBy, seal: 3, by: 'block' });
  assert.deepEqual(r.entries.slice(0, 3).map((e) => e.existedBy), [existedBy, existedBy, existedBy]);
  assert.match(r.summary.limits.at(-1), /A block of a public blockchain, which you trust to be part of the chain, covers the first 3 entries/);
  assert.match(r.summary.limits.at(-1), /not on a signature/);
  assert.deepEqual(r.entries[3].stamps, [
    {
      kind: 'block',
      state: 'valid',
      when: formatTime(START + 3 * HOUR),
      time: START + 3 * HOUR + BLOCK_TIME_ALLOWANCE_MS,
      earliest: START + HOUR,
      authority: first.block.fingerprint,
      height: 912345,
    },
  ]);
});

test('a block the checker did not name counts for nothing, and the result says so', async () => {
  const r = await checkBook(upTo(4));
  assert.deepEqual(codes(r), []);
  assert.equal(r.summary.sealed, null);
  assert.equal(r.entries[0].existedBy, undefined);
  assert.ok(r.entries[3].notes.some((n) => n.includes('leads to a block you did not name as trusted') && n.includes(first.block.fingerprint)));
});

test('a block time-stamp and a time-stamp from a service sit side by side, and the earlier time counts', async () => {
  const both = await checkBook(w.book(), { blocks, stampServices: [w.stampService.fingerprint] });
  assert.deepEqual(codes(both), []);
  assert.equal(both.summary.intact, true);
  // The second seal: the service's time-stamp is the earlier, so it is the one that counts.
  assert.deepEqual(both.summary.sealed, { entries: 5, when: formatTime(START + 2 * HOUR + 11 * MINUTE), seal: 5, by: 'service' });
  assert.deepEqual(both.entries[5].stamps.map((s) => [s.kind, s.state]), [['service', 'valid'], ['block', 'valid']]);
  // The first seal's block states a time after the second seal's service time-stamp. That is no fault:
  // a block time-stamp is made hours after its seal.
  assert.equal(both.entries[4].existedBy, formatTime(START + 2 * HOUR + 11 * MINUTE));
  // Whoever names only the blocks still gets a time for everything.
  const blocksOnly = await checkBook(w.book(), { blocks });
  assert.deepEqual(codes(blocksOnly), []);
  assert.equal(blocksOnly.summary.sealed.by, 'block');
  assert.equal(blocksOnly.summary.sealed.when, formatTime(START + 5 * HOUR + BLOCK_TIME_ALLOWANCE_MS));
});

test('an entry, or a seal, dated well after the time a named block states is not as it says', async () => {
  // A stub dated six hours after the block that is said to cover it.
  const v = await makeWorld();
  await v.add({ when: START + 9 * HOUR + 10 * MINUTE });
  const sealed = await v.seal({ when: START, stamp: false, blockTime: START + HOUR });
  const r = await checkBook(v.book(), { blocks: [sealed.block.fingerprint] });
  assert.ok(codes(r).includes('dated-after-stamp'));
  // Within two hours of the block's time, and five minutes, it is allowed.
  const near = await makeWorld();
  await near.add({ when: START });
  const ok = await near.seal({ when: START + 2 * HOUR + 4 * MINUTE, stamp: false, blockTime: START });
  assert.deepEqual(codes(await checkBook(near.book(), { blocks: [ok.block.fingerprint] })), []);
});

test('block time-stamps beside a seal that are not as the format says are refused', async () => {
  const entry = JSON.parse(lines[3]);
  const [item] = entry.stamps;
  const withStamps = (stamps) => upTo(3) + entryLine({ seal: entry.seal, stamps }) + '\n';
  const check = async (stamps) => codes(await checkBook(withStamps(stamps), { blocks }));
  assert.ok((await check([{ ...item, extra: 'x' }])).includes('bad-field'));
  assert.ok((await check([{ proof: item.proof }])).includes('bad-field'));
  assert.ok((await check([item, item])).includes('bad-field'));
  assert.ok((await check([{ block: item.block, proof: '' }])).includes('bad-field'));
  assert.ok((await check([{ block: item.block.slice(4), proof: item.proof }])).includes('stamp-bad-data'));
  assert.ok((await check([{ block: item.block, proof: 'not base64url!' }])).includes('bad-base64url'));
  // A proof made for another seal.
  assert.ok((await check([JSON.parse(lines[5]).stamps[1]])).includes('stamp-wrong-data'));
});

test('the blocks a person names must be given as fingerprints, or the check stops', async () => {
  for (const wrong of ['text', [5], ['short'], [blocks[0].slice(1)], { a: 1 }, null]) {
    const r = await checkBook(upTo(4), { blocks: wrong });
    assert.deepEqual(r.problems.map((p) => p.code), ['bad-field']);
    assert.equal(r.summary.intact, false);
  }
});

test('a Show under a seal with a block time-stamp proves when its pages existed by', async () => {
  const show = await makeShow(upTo(4), [0, 1], { seal: 3 });
  const r = await checkShow(show, { blocks });
  assert.deepEqual(codes(r), []);
  assert.equal(r.summary.sealed.by, 'block');
  assert.equal(r.entries[0].existedBy, formatTime(START + 3 * HOUR + BLOCK_TIME_ALLOWANCE_MS));
});

test('a cancellation can carry a block time-stamp, and a stub must be shown to have existed before it', async () => {
  const v = await makeWorld();
  await v.add({ when: START });
  const sealed = await v.seal({ when: START + 10 * MINUTE });
  await v.add({ when: START + 20 * MINUTE });
  const cancel = await v.cancel({ when: START + HOUR });
  // The block states 12:00. A block's time is loose, so the cancellation counts from two hours before: 10:00.
  const proof = await makeBlockStamp(new Uint8Array(Buffer.from(cancel.fingerprint, 'base64url')), START + 3 * HOUR);
  cancel.entry.stamps = [proof.item];
  const r = await checkBook(v.book(), { blocks: [proof.fingerprint], stampServices: [v.stampService.fingerprint] });
  assert.deepEqual(r.entries.map((e) => e.breaches.map((b) => b.code)), [[], [], [], ['after-cancellation'], []]);
  assert.equal(r.entries[4].stampedAt, formatTime(START + HOUR));
  assert.equal(sealed.block, undefined);
});

test('the command-line checker takes --block, and says what a block time-stamp is', async () => {
  const file = join(mkdtempSync(join(tmpdir(), 'provared-')), 'book.jsonl');
  writeFileSync(file, upTo(4));
  const cli = join(fileURLToPath(new URL('..', import.meta.url)), 'bin', 'provared-check.mjs');
  const run = (...more) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', cli, file, ...more], { encoding: 'utf8' });
  const named = run('--block', blocks[0], '--issuer', await thumbprint(w.passkey.key), '--sealer', await keySetFingerprint(w.recorder.keys));
  assert.equal(named.status, 0);
  assert.match(named.stdout, new RegExp(`BLOCK TIME-STAMP: in block ${blocks[0]} \\(number 912345, as the proof states\\), which you named as trusted`));
  assert.match(named.stdout, /Time-stamped in a way you trust\?\s+yes: the first 3 entries existed by /);
  const unnamed = run();
  assert.match(unnamed.stdout, /Block time-stamp, NOT COUNTED/);
  assert.match(unnamed.stdout, /Time-stamped in a way you trust\?\s+no/);
  assert.equal(run('--block', 'not-a-fingerprint').status, 2);
});
