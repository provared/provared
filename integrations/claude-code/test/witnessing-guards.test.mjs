// The recorder's guards around its numbers and its witnesses, each held by
// a test (the independent review of step 7b found them untested): only seals
// on the disk shown to a witness; a seal kept apart placed only where it
// covers the book; the book before a new book found by passkey, agent and
// recorder keys, among the books kept before it; a kept book that cannot be
// read stops the seal; a witness's address checked; a book kept only once it
// is on the disk; one seal kept apart at a time; and no statement kept that
// the witness did not save. Every recorder and witness here works in a
// temporary folder and on a free port.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { checkBook, entryLine, fingerprint, fromBase64url, generateSealKeySet, keySetFingerprint, openRecorder, thumbprint, utf8, writeSeal } = await import('provared');
const { PENDING_SEAL, loadAgentKeys, loadRecorderKeys, makeAgentKeys, makeRecorderKeys, startService } = await import('../recorder.mjs');
const { initWitness, readToken, startWitness, witnessClient, witnessFiles } = await import('../witness.mjs');
const { WITNESSED_FOLDER, writeWitnessSettings } = await import('../witnessed.mjs');
const { freePort, runHook, signSlip, status, tempFolder, world } = await import('./world.mjs');

const read = (folder, name) => readFileSync(join(folder, name), 'utf8');
const lines = (text) => text.split('\n').filter(Boolean);
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const contentOf = (record) => JSON.parse(Buffer.from(record.payload, 'base64url').toString('utf8'));
async function sealsOf(text) {
  const out = [];
  for (const [place, line] of lines(text).entries()) {
    if (!line.startsWith('{"seal":')) continue;
    const value = JSON.parse(line);
    out.push({ place, record: value.seal, fingerprint: await fingerprint(fromBase64url(value.seal.payload)), content: contentOf(value.seal), witnesses: value.witnesses ?? [] });
  }
  return out;
}
async function witnessFor(folder, { faults } = {}) {
  const sealer = await keySetFingerprint((await makeRecorderKeys(folder)).keys);
  const wfolder = tempFolder('provared-w-');
  const made = await initWitness({ folder: wfolder, recorders: [sealer] });
  const w = await startWitness({ folder: wfolder, port: 0, ready: true, faults });
  return { w, wfolder, key: made.fingerprint, entry: { address: `http://127.0.0.1:${w.port}`, key: made.fingerprint, token: readToken(witnessFiles(wfolder).token) } };
}
/** What a witness holds, as its operator sees it. */
const heldBy = async (one) => (await witnessClient({ address: one.entry.address, token: readToken(witnessFiles(one.wfolder).operator), role: 'operator' }).ask('GET', '/status')).body.sequences;
async function until(check, what, ms = 20000) {
  const deadline = Date.now() + ms;
  for (;;) {
    const got = await check();
    if (got) return got;
    if (Date.now() > deadline) assert.fail(`not seen in time: ${what}`);
    await pause(100);
  }
}
/** Lines written with the library, under a slip, for a book made by hand. */
async function handBook(slip, agent, passkeyThumbprint, n) {
  const w = await openRecorder({ book: `${entryLine({ slip })}\n`, slip: await fingerprint(fromBase64url(slip.payload)), privateKeys: agent.privateKeys, issuerKeys: [passkeyThumbprint] });
  for (let i = 0; i < n; i++) await w.record({ action: 'provared.code.read', details: [{ name: 'Read', sha256: await fingerprint(utf8(`hand ${i} ${Math.random()}`)) }] });
  return w.book();
}

test('a witness that could not save its journal line gives the recorder nothing for that seal: no statement is kept beside the book, and status says why', async () => {
  const { folder } = await world([]);
  let failing = false;
  const one = await witnessFor(folder, { faults: (step) => { if (step === 'journal' && failing) throw new Error('the disk is full'); } });
  writeWitnessSettings(folder, [one.entry]);
  const service = await startService({ folder, port: 0, witnessRetryMs: 300 });
  try {
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    assert.equal((await service.seal()).witnessed.length, 1);
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'b' });
    failing = true;
    const second = await service.seal();
    assert.deepEqual(second.witnessed, []);
    failing = false;
    await until(async () => (await service.witnesses()).witnesses[0].problem?.code === 'witness-stopped', 'the witness reported as stopped');
    await pause(1200);
    assert.ok(!existsSync(join(folder, WITNESSED_FOLDER, `${second.fingerprint}.json`)), 'no statement for the seal the witness did not save');
    assert.equal((await service.witnesses()).witnesses[0].upToDate, false);
  } finally {
    await service.close();
    await one.w.close();
  }
});

test('a witness that does not sign now is asked only what it holds: it is shown no seal, and no proof is made for it', async () => {
  const { folder } = await world([]);
  const sealer = await keySetFingerprint((await makeRecorderKeys(folder)).keys);
  const wfolder = tempFolder('provared-w-');
  const made = await initWitness({ folder: wfolder, recorders: [sealer] });
  const w = await startWitness({ folder: wfolder, port: 0 });
  // A proxy in front of the witness that passes every byte on as it is, and counts what it is asked.
  const asked = [];
  const { createServer, request } = await import('node:http');
  const proxy = createServer((req, res) => {
    asked.push(`${req.method} ${new URL(req.url, 'http://x').pathname}`);
    const out = request({ host: '127.0.0.1', port: w.port, path: req.url, method: req.method, headers: req.headers }, (back) => {
      res.writeHead(back.statusCode, back.headers);
      back.pipe(res);
    });
    req.pipe(out);
  });
  await new Promise((done) => proxy.listen(0, '127.0.0.1', done));
  writeWitnessSettings(folder, [{ address: `http://127.0.0.1:${proxy.address().port}`, key: made.fingerprint, token: readToken(witnessFiles(wfolder).token) }]);
  const service = await startService({ folder, port: 0, witnessRetryMs: 200 });
  try {
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    assert.deepEqual((await service.seal()).witnessed, []);
    await until(async () => (await service.witnesses()).witnesses[0].problem?.code === 'witness-not-ready', 'the witness reported as not ready');
    await pause(1000);
    assert.ok(asked.length > 0);
    assert.ok(asked.every((a) => a === 'GET /hello' || a === 'GET /latest'), asked.join(', '));
  } finally {
    await service.close();
    await new Promise((done) => { proxy.closeAllConnections(); proxy.close(done); });
    await w.close();
  }
});

test('a seal whose line is not known to be on the disk is shown to no witness, until it is', async () => {
  const { folder } = await world([]);
  let failing = false;
  const service = await startService({ folder, port: 0, witnessRetryMs: 200, faults: (step) => { if (step === 'sync' && failing) throw new Error('not on the disk'); } });
  const one = await witnessFor(folder);
  try {
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    failing = true;
    const first = await service.seal();
    // A witness named now, after the seal: it is asked within the retry, and is shown nothing.
    writeWitnessSettings(folder, [one.entry]);
    await until(async () => (await service.witnesses()).witnesses.length === 1, 'the witness taken from the list');
    await pause(1500);
    assert.deepEqual(await heldBy(one), [], 'the witness holds nothing: the seal is not on the disk');
    failing = false;
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'b' });
    const second = await service.seal();
    await until(async () => (await heldBy(one)).length === 1, 'the witness signed once the seals were on the disk');
    assert.equal((await heldBy(one))[0].seal, second.fingerprint, 'at first contact, the latest');
    assert.notEqual(first.fingerprint, second.fingerprint);
  } finally {
    await service.close();
    await one.w.close();
  }
});

test('a seal kept apart that does not cover the entries the book holds is not written at the start, though the sizes agree', async () => {
  const { folder, passkey, slip } = await world([]);
  let service = await startService({ folder, port: 0 });
  await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
  await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'b' });
  await service.close();
  const book = read(folder, 'book.jsonl');
  // A seal of another book of three entries, by this recorder's own keys.
  const other = await handBook(slip, await loadAgentKeys(folder), await thumbprint(passkey.key), 2);
  const keys = await loadRecorderKeys(folder);
  const foreign = await writeSeal(other, { by: { keys: keys.keys, name: 'The recorder beside the coding agent' } }, keys.privateKeys);
  assert.equal(contentOf(foreign.record).size, lines(book).length);
  writeFileSync(join(folder, PENDING_SEAL), JSON.stringify({ about: 'x', book: 'book.jsonl', seal: foreign.record }));
  service = await startService({ folder, port: 0 });
  try {
    assert.match((await status(service.port)).pendingSealProblem, /does not cover the entries the book holds/);
    assert.equal(read(folder, 'book.jsonl'), book, 'the book is as it was');
  } finally {
    await service.close();
  }
});

test('a seal kept apart whose line is in a book kept since is let go at the start, with nothing written and nothing reported', async () => {
  const { folder } = await world([]);
  let service = await startService({ folder, port: 0 });
  await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
  await service.seal();
  await service.newBook();
  await service.close();
  const kept = await sealsOf(read(folder, 'book-1.jsonl'));
  writeFileSync(join(folder, PENDING_SEAL), JSON.stringify({ about: 'x', book: 'book.jsonl', seal: kept[0].record }));
  const before = read(folder, 'book.jsonl');
  service = await startService({ folder, port: 0 });
  try {
    assert.equal((await status(service.port)).pendingSealProblem, undefined);
    assert.ok(!existsSync(join(folder, PENDING_SEAL)));
    assert.equal(read(folder, 'book.jsonl'), before);
  } finally {
    await service.close();
  }
});

test('the book before a new book is the latest kept book of the same passkey, agent and recorder keys: not one sealed by other keys, nor one for another agent', async () => {
  const { folder, passkey } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    await service.newBook();
    const own = (await sealsOf(read(folder, 'book-1.jsonl'))).at(-1);
    const issuer = await thumbprint(passkey.key);
    // Kept by hand: a book of the same passkey and agent, sealed by other recorder keys.
    const agent = await loadAgentKeys(folder);
    const sameSlip = await signSlip({ agentKeys: agent.keys, passkey });
    const otherKeys = await generateSealKeySet();
    const a = await handBook(sameSlip, agent, issuer, 1);
    writeFileSync(join(folder, 'book-2.jsonl'), `${a}${entryLine({ seal: (await writeSeal(a, { by: { keys: otherKeys.keys, name: 'Another recorder' } }, otherKeys.privateKeys)).record })}\n`);
    // And one for another agent of the same passkey, sealed by this recorder's own keys.
    const agent2 = await makeAgentKeys(tempFolder());
    const otherAgentSlip = await signSlip({ agentKeys: agent2.keys, passkey });
    const b = await handBook(otherAgentSlip, agent2, issuer, 1);
    const ownKeys = await loadRecorderKeys(folder);
    writeFileSync(join(folder, 'book-3.jsonl'), `${b}${entryLine({ seal: (await writeSeal(b, { by: { keys: ownKeys.keys, name: 'The recorder beside the coding agent' } }, ownKeys.privateKeys)).record })}\n`);
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'b' });
    const sealed = await service.seal();
    assert.equal(sealed.book, 2);
    assert.equal((await sealsOf(read(folder, 'book.jsonl')))[0].content.previous, own.fingerprint, 'it follows book-1.jsonl');
  } finally {
    await service.close();
  }
});

test('a kept book sealed at the start follows only a book kept before it', async () => {
  const { folder, passkey } = await world([]);
  let service = await startService({ folder, port: 0 });
  const sealer = (await status(service.port)).sealer;
  for (const id of ['a', 'b', 'c']) {
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: id });
    await service.newBook();
  }
  await service.close();
  // Book 2 as if a stop had come before it was sealed: its seals taken off.
  writeFileSync(join(folder, 'book-2.jsonl'), `${lines(read(folder, 'book-2.jsonl')).filter((l) => !l.startsWith('{"seal":')).join('\n')}\n`);
  service = await startService({ folder, port: 0 });
  try {
    const [resealed] = await sealsOf(read(folder, 'book-2.jsonl'));
    const one = (await sealsOf(read(folder, 'book-1.jsonl'))).at(-1);
    assert.equal(resealed.content.book, 2);
    assert.equal(resealed.content.previous, one.fingerprint, 'it follows book-1.jsonl, not book-3.jsonl');
    const r = await checkBook(read(folder, 'book-2.jsonl'), { issuerKeys: [await thumbprint(passkey.key)], sealKeys: [sealer] });
    assert.equal(r.summary.intact, true);
  } finally {
    await service.close();
  }
});

test('a kept book that cannot be read when the book in force is first sealed stops that seal; tool calls go on; once it can be read, the seal is made as it should be', async () => {
  const { folder } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    await service.seal();
    await service.newBook();
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'b' });
    const kept = join(folder, 'book-1.jsonl');
    renameSync(kept, `${kept}.away`);
    mkdirSync(kept);
    await assert.rejects(service.seal(), /could not be read, so the number of the book in force/);
    assert.equal((await runHook(service.port, 'PreToolUse', 'Read', { file_path: 'c' })).out, '', 'a tool call is allowed');
    renameSync(kept, `${kept}.dir`);
    renameSync(`${kept}.away`, kept);
    const sealed = await service.seal();
    assert.equal(sealed.book, 2);
    assert.equal((await sealsOf(read(folder, 'book.jsonl')))[0].content.previous, (await sealsOf(read(folder, 'book-1.jsonl'))).at(-1).fingerprint);
  } finally {
    await service.close();
  }
});

test('a witness at an address that is not http://127.0.0.1:<port> is not asked, and status says why', async () => {
  const { folder } = await world([]);
  const away = await freePort();
  writeWitnessSettings(folder, [{ address: `http://localhost:${away}`, key: 'A'.repeat(43), token: 'A'.repeat(42) + 'A' }]);
  const service = await startService({ folder, port: 0 });
  try {
    const s = await status(service.port);
    assert.match(s.witnessesProblem, /address is not http:\/\/127\.0\.0\.1:<port>/);
    assert.deepEqual(s.witnesses, []);
  } finally {
    await service.close();
  }
});

test('a book is kept only once it is known to be on the disk', async () => {
  const { folder } = await world([]);
  let failing = false;
  const service = await startService({ folder, port: 0, faults: (step) => { if (step === 'sync' && failing) throw new Error('not on the disk'); } });
  try {
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    failing = true;
    await assert.rejects(service.newBook(), /could not be made sure to be on the disk, so it is not kept yet/);
    assert.deepEqual(readdirSync(folder).filter((n) => /^book-\d+\.jsonl$/.test(n)), []);
    failing = false;
    assert.equal((await service.newBook()).kept, 'book-1.jsonl');
  } finally {
    await service.close();
  }
});

test('one seal kept apart at a time: while the line of one is not known to be on the disk, the next seal is not held for the witnesses', async () => {
  const { folder } = await world([]);
  const one = await witnessFor(folder);
  writeWitnessSettings(folder, [one.entry]);
  let failing = false;
  const service = await startService({ folder, port: 0, faults: (step) => { if (step === 'sync' && failing) throw new Error('not on the disk'); } });
  try {
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    failing = true;
    const first = await service.seal();
    assert.equal(first.witnessed.length, 1, 'asked in time');
    const kept = read(folder, PENDING_SEAL);
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'b' });
    const second = await service.seal();
    assert.deepEqual(second.witnessed, [], 'not held for the witnesses');
    assert.equal(read(folder, PENDING_SEAL), kept, 'the seal kept apart is still the first');
    failing = false;
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'c' });
    await service.seal();
    assert.ok(!existsSync(join(folder, PENDING_SEAL)), 'let go once its line is on the disk');
  } finally {
    await service.close();
    await one.w.close();
  }
});
