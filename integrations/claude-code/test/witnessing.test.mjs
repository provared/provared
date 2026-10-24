// The recorder beside Claude Code numbers its books and chains each new
// book's first seal to the last seal of the book before (format
// description, section 21.6), and asks the witnesses named in its folder to
// sign for its seals (witnessed.mjs): beside the seal on its line where the
// statement comes in time, or kept beside the book where it comes later. A
// witness that is down or refuses never stops recording. Every recorder and
// witness here works in a temporary folder and on a free port.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { checkBook, fingerprint, fromBase64url, generateKeySet, keySetFingerprint, thumbprint, witnessProof, writeSeal, writeWitness } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { PENDING_SEAL, loadRecorderKeys, makeRecorderKeys, startService } = await import('../recorder.mjs');
const { initWitness, readToken, startWitness, witnessFiles } = await import('../witness.mjs');
const { WITNESSED_FOLDER, keepStatement, statementPasses, writeWitnessSettings } = await import('../witnessed.mjs');
const { freePort, runCommand, runHook, signSlip, status, tempFolder, world } = await import('./world.mjs');

const read = (folder, name) => readFileSync(join(folder, name), 'utf8');
const lines = (text) => text.split('\n').filter(Boolean);
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const contentOf = (record) => JSON.parse(Buffer.from(record.payload, 'base64url').toString('utf8'));

/** The seals on the lines of a book file, in order: each with its fingerprint, content, place, and the statements on its line. */
async function sealsOf(folder, name) {
  const out = [];
  for (const [place, line] of lines(read(folder, name)).entries()) {
    if (!line.startsWith('{"seal":')) continue;
    const value = JSON.parse(line);
    out.push({ place, fingerprint: await fingerprint(fromBase64url(value.seal.payload)), content: contentOf(value.seal), witnesses: value.witnesses ?? [] });
  }
  return out;
}

/** A book checked on its own, with the passkeys and the recorder named: intact and within its permissions. */
async function checked(folder, name, options) {
  const result = await checkBook(read(folder, name), options);
  assert.equal(result.summary.intact, true, `${name}: ${JSON.stringify([...result.problems, ...result.entries.flatMap((e) => e.problems)])}`);
  assert.equal(result.summary.withinSlips, true, name);
  return result;
}

/** A witness that serves this folder's recorder, started, and the entry that names it in witnesses.json. */
// A witness made here is told it may sign at its start (ready), unless the test says otherwise.
async function witnessFor(folder, { port = 0, faults, ready = true, start = true } = {}) {
  const sealer = await keySetFingerprint((await makeRecorderKeys(folder)).keys);
  const wfolder = tempFolder('provared-w-');
  const made = await initWitness({ folder: wfolder, recorders: [sealer] });
  const w = start ? await startWitness({ folder: wfolder, port, faults, ready }) : null;
  return { w, wfolder, key: made.fingerprint, entry: { address: `http://127.0.0.1:${w ? w.port : port}`, key: made.fingerprint, token: readToken(witnessFiles(wfolder).token) } };
}

/** Wait until every witness named holds the latest seal on the disk. */
async function upToDate(service, n, ms = 30000) {
  const deadline = Date.now() + ms;
  for (;;) {
    const s = await service.witnesses();
    if (s.witnesses.length === n && s.witnesses.every((w) => w.upToDate)) return s;
    if (Date.now() > deadline) assert.fail(`the witnesses are not up to date: ${JSON.stringify(s)}`);
    await pause(100);
  }
}
/** Wait until a witness has a problem with the code given. */
async function problemOf(service, code, ms = 20000) {
  const deadline = Date.now() + ms;
  for (;;) {
    const s = await service.witnesses();
    if (s.witnesses.some((w) => w.problem?.code === code)) return s;
    if (Date.now() > deadline) assert.fail(`no witness has the problem ${code}: ${JSON.stringify(s)}`);
    await pause(100);
  }
}

const keptStatements = (folder) => {
  const dir = join(folder, WITNESSED_FOLDER);
  return existsSync(dir) ? readdirSync(dir).map((n) => JSON.parse(read(dir, n))) : [];
};

// --- the books' numbers and the seals they name ---

test('books are numbered and chained: a new book\'s first seal gives its number and names the last seal of the book before, its later seals keep the number, and each book checks on its own', async () => {
  const { folder, passkey } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const trust = { issuerKeys: [await thumbprint(passkey.key)], sealKeys: [(await status(service.port)).sealer] };
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    assert.equal((await service.seal()).book, undefined, 'the first book gives no number');
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'b' });
    await service.newBook();
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'c' });
    assert.equal((await service.seal()).book, 2);
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'd' });
    assert.equal((await service.seal()).book, 2, 'a later seal of the book keeps its number');
    await service.newBook();
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'e' });
    assert.equal((await service.seal()).book, 3);

    const one = await sealsOf(folder, 'book-1.jsonl');
    const two = await sealsOf(folder, 'book-2.jsonl');
    const three = await sealsOf(folder, 'book.jsonl');
    assert.ok(one.every((s) => s.content.book === undefined), 'book 1 gives no number');
    assert.deepEqual(two.map((s) => s.content.book), [2, 2]);
    assert.equal(two[0].content.previous, one.at(-1).fingerprint, 'the first seal of book 2 names the last seal of book 1');
    assert.equal(two[1].content.previous, two[0].fingerprint);
    assert.equal(three[0].content.book, 3);
    assert.equal(three[0].content.previous, two.at(-1).fingerprint);
    for (const name of ['book-1.jsonl', 'book-2.jsonl', 'book.jsonl']) await checked(folder, name, trust);
    const shown = await checkBook(read(folder, 'book-2.jsonl'), trust);
    assert.match(shown.entries.find((e) => e.kind === 'seal').notes.join(' '), /first seal of book 2/);
  } finally {
    await service.close();
  }
});

test('the numbers hold across a restart, and a book whose seals give no number goes on giving none', async () => {
  const { folder, passkey } = await world([]);
  let service = await startService({ folder, port: 0 });
  const sealer = (await status(service.port)).sealer;
  const trust = { issuerKeys: [await thumbprint(passkey.key)], sealKeys: [sealer] };
  await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
  await service.newBook();
  await service.close();
  // Started again, with the new book unsealed: its first seal follows the kept book, read from its file.
  service = await startService({ folder, port: 0 });
  try {
    assert.equal((await service.seal()).book, 2);
    assert.equal((await sealsOf(folder, 'book.jsonl'))[0].content.previous, (await sealsOf(folder, 'book-1.jsonl')).at(-1).fingerprint);
    // As an earlier version left it: a book whose first seal gives no number and names none.
    await service.newBook();
    const keys = await loadRecorderKeys(folder);
    const unnumbered = await writeSeal(service.recorder.book(), { by: { keys: keys.keys, name: 'An earlier version' } }, keys.privateKeys);
    await service.recorder.add({ seal: unnumbered.record });
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'b' });
    assert.equal((await service.seal()).book, undefined, 'it goes on as its first seal says');
    await service.newBook();
    assert.equal((await service.seal()).book, 2, 'and the book after it is book 2, one more than that book\'s own number');
    assert.equal((await sealsOf(folder, 'book.jsonl'))[0].content.previous, (await sealsOf(folder, 'book-3.jsonl')).at(-1).fingerprint);
    for (const name of ['book-1.jsonl', 'book-2.jsonl', 'book-3.jsonl', 'book.jsonl']) await checked(folder, name, trust);
  } finally {
    await service.close();
  }
});

test('a book whose first line is a permission from another passkey begins a sequence of its own, and a book from the first passkey again follows the last book of that passkey', async () => {
  const { folder, passkey, agent } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const sealer = (await status(service.port)).sealer;
    const second = await developmentPasskey();
    const trust = { issuerKeys: [await thumbprint(passkey.key), await thumbprint(second.key)], sealKeys: [sealer] };
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    await service.renew(await signSlip({ agentKeys: agent.keys, passkey: second, purpose: 'with a new passkey' }), { newPasskey: true });
    await service.newBook();
    assert.deepEqual(await service.seal().then((s) => [s.book]), [undefined], 'the first book of the second passkey');
    assert.equal((await sealsOf(folder, 'book.jsonl'))[0].content.previous, undefined, 'naming no seal');
    await service.newBook();
    assert.equal((await service.seal()).book, 2, 'the second book of the second passkey');
    assert.equal((await sealsOf(folder, 'book.jsonl'))[0].content.previous, (await sealsOf(folder, 'book-2.jsonl')).at(-1).fingerprint);
    // Back to the first passkey: the new book follows book-1.jsonl, the last book that began with it.
    await service.renew(await signSlip({ agentKeys: agent.keys, passkey, purpose: 'the first passkey again' }));
    await service.newBook();
    assert.equal((await service.seal()).book, 2);
    assert.equal((await sealsOf(folder, 'book.jsonl'))[0].content.previous, (await sealsOf(folder, 'book-1.jsonl')).at(-1).fingerprint);
    for (const name of ['book-1.jsonl', 'book-2.jsonl', 'book-3.jsonl', 'book.jsonl']) await checked(folder, name, trust);
  } finally {
    await service.close();
  }
});

test('before the book in force is first sealed, a kept book that a call may still come back to is closed and sealed, and the call goes into the book in force', async () => {
  const { folder, passkey } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const trust = { issuerKeys: [await thumbprint(passkey.key)], sealKeys: [(await status(service.port)).sealer] };
    for (const id of ['x', 'y']) assert.equal((await runHook(service.port, 'PreToolUse', 'Read', { file_path: id }, { more: { tool_use_id: id } })).out, '');
    await service.newBook();
    // "x" comes back: into the kept book, which stays open while "y" may still come back.
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'x' }, { more: { tool_use_id: 'x' } });
    assert.equal(Object.keys(JSON.parse(lines(read(folder, 'book-1.jsonl')).at(-1)))[0], 'stub');
    const sealed = await service.seal();
    assert.equal(sealed.book, 2);
    const kept = await sealsOf(folder, 'book-1.jsonl');
    assert.equal(kept.at(-1).place, lines(read(folder, 'book-1.jsonl')).length - 1, 'the kept book was sealed after the late stub');
    assert.equal((await sealsOf(folder, 'book.jsonl'))[0].content.previous, kept.at(-1).fingerprint, 'and the new book names that last seal');
    const before = read(folder, 'book-1.jsonl');
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'y' }, { more: { tool_use_id: 'y' } });
    assert.equal(read(folder, 'book-1.jsonl'), before, 'the kept book is closed: nothing follows its last seal');
    assert.equal(Object.keys(JSON.parse(lines(read(folder, 'book.jsonl')).at(-1)))[0], 'stub', '"y" is in the book in force');
    await checked(folder, 'book-1.jsonl', trust);
    await checked(folder, 'book.jsonl', trust);
  } finally {
    await service.close();
  }
});

// --- witnesses ---

test('one witness: the seal "seal" makes is witnessed beside it on its line, and the book checks as witnessed, with the library and with "check"', async () => {
  const { folder, passkey } = await world([]);
  const one = await witnessFor(folder);
  writeWitnessSettings(folder, [one.entry]);
  const service = await startService({ folder, port: 0 });
  try {
    const issuer = await thumbprint(passkey.key);
    const trust = { issuerKeys: [issuer], sealKeys: [(await status(service.port)).sealer], witnesses: [one.key] };
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    const sealed = await service.seal();
    assert.deepEqual(sealed.witnessed, [one.key]);
    const [s] = await sealsOf(folder, 'book.jsonl');
    assert.equal(s.witnesses.length, 1, 'the statement is on the seal\'s line');
    const result = await checked(folder, 'book.jsonl', trust);
    assert.deepEqual(result.summary.witnessed, { seal: s.place, entries: s.place, by: [one.key], seals: [s.place] });
    assert.deepEqual(keptStatements(folder), [], 'nothing is kept beside the book');
    assert.ok(!existsSync(join(folder, PENDING_SEAL)), 'the seal is no longer kept apart');
    const run = await runCommand(['check', '--issuer', issuer], { folder, port: service.port });
    assert.equal(run.code, 0, run.out + run.err);
    assert.match(run.out, /Witnessed by a witness you trust\?\s+yes/);
    assert.match(run.err, /named from this recorder's own list/);
    const s2 = await status(service.port);
    assert.equal(s2.witnesses[0].upToDate, true);
    assert.equal(s2.witnesses[0].holds.entries, s.place);
  } finally {
    await service.close();
    await one.w.close();
  }
});

test('two witnesses across a new book: the old book\'s last seal is witnessed beside the book, the new book\'s first seal on its line, chained, and each book checks as witnessed', async () => {
  const { folder, passkey } = await world([]);
  const one = await witnessFor(folder);
  const two = await witnessFor(folder);
  writeWitnessSettings(folder, [one.entry, two.entry]);
  const service = await startService({ folder, port: 0 });
  try {
    const issuer = await thumbprint(passkey.key);
    const keys = [one.key, two.key].sort();
    const trust = { issuerKeys: [issuer], sealKeys: [(await status(service.port)).sealer], witnesses: keys };
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    assert.equal((await service.seal()).witnessed.length, 2);
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'b' });
    await service.newBook();
    await upToDate(service, 2);
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'c' });
    const second = await service.seal();
    assert.equal(second.book, 2);
    assert.equal(second.witnessed.length, 2, `the first seal of book 2 is witnessed on its line: each witness held the last seal of book 1 (${JSON.stringify(await service.witnesses())})`);

    const kept = await sealsOf(folder, 'book-1.jsonl');
    assert.equal(kept.at(-1).witnesses.length, 0, 'book 1\'s last seal was made at the new book: its statements are beside the book');
    const held = keptStatements(folder);
    assert.equal(held.length, 1);
    assert.equal(held[0].witnesses.length, 2);
    assert.equal(await fingerprint(fromBase64url(held[0].seal.payload)), kept.at(-1).fingerprint);
    const heldFile = join(folder, WITNESSED_FOLDER, `${kept.at(-1).fingerprint}.json`);
    const r1 = await checked(folder, 'book-1.jsonl', { ...trust, seals: [held[0]] });
    assert.equal(r1.summary.witnessed.seal, kept.at(-1).place, 'book 1 is witnessed to its last seal');
    assert.deepEqual(r1.summary.witnessed.by, keys);
    const r2 = await checked(folder, 'book.jsonl', trust);
    assert.equal(r2.summary.witnessed.seal, (await sealsOf(folder, 'book.jsonl'))[0].place);
    // "check" hands the statements kept beside a book over with it.
    const run = await runCommand(['check', 'book-1.jsonl', '--issuer', issuer], { folder, port: service.port });
    assert.equal(run.code, 0, run.out + run.err);
    assert.match(run.err, /One seal of this book is handed over beside it \(--seal\) only to bring the statements/);
    assert.match(run.err, /"held elsewhere": it is not, and cannot show the book cut short/, 'said plainly, before and after the checker\'s answer');
    assert.match(run.err, /\nNote: One seal of this book/);
    // The checker's own words: the seal kept beside the book was compared, and is the latest witnessed.
    assert.match(run.out, /Seals held elsewhere compared\?\s+yes/);
    assert.match(run.out, new RegExp(`Witnessed by a witness you trust\\?\\s+yes: the seal at entry ${kept.at(-1).place}\\b`));
    assert.ok(existsSync(heldFile));
    // The book in force is handed none of book 1's seals: a seal of another book handed over gives no pass.
    const inForce = await runCommand(['check', '--issuer', issuer], { folder, port: service.port });
    assert.equal(inForce.code, 0, inForce.out + inForce.err);
    assert.doesNotMatch(inForce.err, /handed over beside it/);
  } finally {
    await service.close();
    await one.w.close();
    await two.w.close();
  }
});

test('a witness that is down never stops recording: status says why, and once it answers it is brought up to date and its statement kept beside the book', async () => {
  const { folder, passkey } = await world([]);
  const port = await freePort();
  const later = await witnessFor(folder, { port, start: false });
  writeWitnessSettings(folder, [later.entry]);
  const service = await startService({ folder, port: 0, witnessRetryMs: 300 });
  let w = null;
  try {
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    const t0 = Date.now();
    const sealed = await service.seal();
    assert.deepEqual(sealed.witnessed, []);
    assert.ok(Date.now() - t0 < 5000, 'a witness that does not answer is not waited for');
    const asked = await runHook(service.port, 'PreToolUse', 'Read', { file_path: 'b' });
    assert.equal(asked.out, '', 'tool calls go on');
    const s = await problemOf(service, 'unreachable');
    assert.equal(s.witnesses[0].upToDate, false);
    // The witness comes up: within the retry it is asked about the latest seal, and its statement kept beside the book.
    w = await startWitness({ folder: later.wfolder, port, ready: true });
    await upToDate(service, 1);
    const held = keptStatements(folder);
    assert.equal(held.length, 1);
    assert.equal(await fingerprint(fromBase64url(held[0].seal.payload)), sealed.fingerprint);
    // Up to date, the next seal is witnessed on its line.
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'c' });
    assert.deepEqual((await service.seal()).witnessed, [later.key]);
    await checked(folder, 'book.jsonl', { issuerKeys: [await thumbprint(passkey.key)], sealKeys: [(await status(service.port)).sealer], witnesses: [later.key], seals: held });
  } finally {
    await service.close();
    await w?.close();
  }
});

test('a witness that refuses never stops recording, and status gives its reason: one not ready, one that does not serve this recorder', async () => {
  const { folder } = await world([]);
  const one = await witnessFor(folder);
  await one.w.close();
  // A new witness (its journal empty) is ready at once: it signs once here, and is then started again from what it kept.
  let w = await startWitness({ folder: one.wfolder, port: 0, ready: true });
  writeWitnessSettings(folder, [{ ...one.entry, address: `http://127.0.0.1:${w.port}` }]);
  const service = await startService({ folder, port: 0, witnessRetryMs: 300 });
  try {
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    assert.equal((await service.seal()).witnessed.length, 1);
    await w.close();
    w = await startWitness({ folder: one.wfolder, port: 0 });
    writeWitnessSettings(folder, [{ ...one.entry, address: `http://127.0.0.1:${w.port}` }]);
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'b' });
    assert.deepEqual((await service.seal()).witnessed, []);
    await problemOf(service, 'witness-not-ready');
    assert.equal((await runHook(service.port, 'PreToolUse', 'Read', { file_path: 'c' })).out, '', 'tool calls go on');
    // Its operator says it is up to date: it is brought up to the latest seal.
    const { witnessClient } = await import('../witness.mjs');
    await witnessClient({ address: `http://127.0.0.1:${w.port}`, token: readToken(witnessFiles(one.wfolder).operator), role: 'operator' }).ask('POST', '/ready', {});
    await upToDate(service, 1);
  } finally {
    await service.close();
    await w.close();
  }
  // A witness that serves another recorder.
  const other = await world([]);
  const foreign = await witnessFor(tempFolder('provared-cc-'));
  writeWitnessSettings(other.folder, [foreign.entry]);
  const elsewhere = await startService({ folder: other.folder, port: 0 });
  try {
    await runHook(elsewhere.port, 'PostToolUse', 'Read', { file_path: 'a' });
    assert.deepEqual((await elsewhere.seal()).witnessed, []);
    await problemOf(elsewhere, 'recorder-not-served');
  } finally {
    await elsewhere.close();
    await foreign.w.close();
  }
});

test('no tool call waits for a witness: a call asked while "seal" waits is answered at once, the seal\'s line is written without the statement, and the statement is kept beside the book when it comes', async () => {
  const { folder } = await world([]);
  let slow = 0;
  const one = await witnessFor(folder, { faults: async (step) => { if (step === 'signing' && slow) await pause(slow); } });
  writeWitnessSettings(folder, [one.entry]);
  const service = await startService({ folder, port: 0, witnessWaitMs: 30000 });
  try {
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    slow = 8000;
    const t0 = Date.now();
    const sealing = service.seal();
    const asked = await runHook(service.port, 'PreToolUse', 'Read', { file_path: 'b' });
    const answered = Date.now() - t0;
    assert.equal(asked.out, '', 'the call is allowed');
    assert.ok(answered < 6000, `the call was answered after ${answered} ms, while the witness takes 8,000`);
    const sealed = await sealing;
    assert.deepEqual(sealed.witnessed, [], 'the line was written without the statement');
    assert.ok(Date.now() - t0 < 6000, 'and the seal did not wait for it');
    slow = 0;
    await upToDate(service, 1);
    assert.equal(keptStatements(folder).length, 1, 'the statement that came later is kept beside the book');
    // With no other request, "seal" waits, up to the time set, and the statement is on the line.
    slow = 1000;
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'c' });
    assert.deepEqual((await service.seal()).witnessed, [one.key]);
  } finally {
    await service.close();
    await one.w.close();
  }
});

for (const step of ['pending', 'statements']) {
  test(`a stop after "${step}", before the seal's line is written: the next start writes the seal at its place, and the witness goes on`, async () => {
    const { folder, passkey } = await world([]);
    const one = await witnessFor(folder);
    writeWitnessSettings(folder, [one.entry]);
    const crash = new Error(`stopped after ${step}`);
    let service = await startService({ folder, port: 0, faults: (at) => { if (at === step) throw crash; } });
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    await assert.rejects(service.seal(), (e) => e === crash);
    await service.close();
    assert.ok(existsSync(join(folder, PENDING_SEAL)), 'the seal is kept apart');
    const kept = JSON.parse(read(folder, PENDING_SEAL)).seal;
    assert.equal((await sealsOf(folder, 'book.jsonl')).length, 0, 'its line is not in the book');
    service = await startService({ folder, port: 0 });
    try {
      const [s] = await sealsOf(folder, 'book.jsonl');
      assert.equal(s.fingerprint, await fingerprint(fromBase64url(kept.payload)), 'written at its place at the start');
      assert.equal(s.place, contentOf(kept).size);
      assert.ok(!existsSync(join(folder, PENDING_SEAL)), 'and no longer kept apart');
      await upToDate(service, 1);
      assert.equal(keptStatements(folder).length, 1, 'the witness\'s statement for it is kept beside the book');
      await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'b' });
      assert.deepEqual((await service.seal()).witnessed, [one.key], 'and the witness signs for the next seal');
      await checked(folder, 'book.jsonl', { issuerKeys: [await thumbprint(passkey.key)], sealKeys: [(await status(service.port)).sealer], witnesses: [one.key], seals: keptStatements(folder) });
    } finally {
      await service.close();
      await one.w.close();
    }
  });
}

test('a seal kept apart that cannot be written at its place (the book changed since) is set aside, and status says so', async () => {
  const { folder } = await world([]);
  const one = await witnessFor(folder);
  writeWitnessSettings(folder, [one.entry]);
  try {
    let service = await startService({ folder, port: 0, faults: (at) => { if (at === 'statements') throw new Error('stopped'); } });
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'b' });
    await assert.rejects(service.seal());
    await service.close();
    // The book cut back by hand while the recorder was stopped: it no longer ends where the seal begins.
    const book = lines(read(folder, 'book.jsonl'));
    writeFileSync(join(folder, 'book.jsonl'), `${book.slice(0, -1).join('\n')}\n`);
    service = await startService({ folder, port: 0 });
    try {
      const s = await status(service.port);
      assert.match(s.pendingSealProblem, /could not be written into it: it covers 3 entries, and the book holds 2/);
      assert.ok(!existsSync(join(folder, PENDING_SEAL)));
      assert.ok(readdirSync(folder).some((n) => n.startsWith('pending-seal-not-placed-')), 'kept under another name');
      assert.equal((await sealsOf(folder, 'book.jsonl')).length, 0, 'and nothing was written into the book');
    } finally {
      await service.close();
    }
  } finally {
    await one.w.close();
  }
});

test('a statement that does not pass is never written: one signed with other keys than the ones named, and one changed after it was signed', async () => {
  const { folder, passkey } = await world([]);
  const one = await witnessFor(folder);
  const other = await witnessFor(tempFolder('provared-cc-'));
  // The address and token of one witness, under another witness's fingerprint.
  writeWitnessSettings(folder, [{ ...one.entry, key: other.key }]);
  const service = await startService({ folder, port: 0 });
  try {
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    assert.deepEqual((await service.seal()).witnessed, []);
    await problemOf(service, 'witness-invalid');
    assert.equal((await sealsOf(folder, 'book.jsonl'))[0].witnesses.length, 0, 'not on the line');
    assert.deepEqual(keptStatements(folder), [], 'not kept beside the book');
    // The check itself, on a statement changed by one byte in its signature.
    writeWitnessSettings(folder, [one.entry]);
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'b' });
    await service.seal();
    const text = read(folder, 'book.jsonl');
    const [first, second] = await sealsOf(folder, 'book.jsonl');
    const statement = keptStatements(folder).find((h) => h.seal)?.witnesses[0] ?? JSON.parse(lines(text)[second.place]).witnesses[0];
    const record = JSON.parse(lines(text)[second.place]).seal;
    const before = lines(text).slice(0, second.place).join('\n') + '\n';
    const path = await witnessProof(before, second.place, null);
    const seal = { record, fingerprint: second.fingerprint, content: second.content };
    assert.equal(await statementPasses(seal, lines(text)[0], path, statement, one.key), true, 'as handed back, it passes');
    const changed = structuredClone(statement);
    const bytes = Buffer.from(changed.signatures[0].signature, 'base64url');
    bytes[5] ^= 1;
    changed.signatures[0].signature = bytes.toString('base64url');
    assert.equal(await statementPasses(seal, lines(text)[0], path, changed, one.key), false, 'changed, it does not');
    assert.equal(await statementPasses(seal, lines(text)[0], path, statement, other.key), false, 'nor under another witness\'s name');
    assert.equal(first.witnesses.length, 0);
    await checked(folder, 'book.jsonl', { issuerKeys: [await thumbprint(passkey.key)], sealKeys: [(await status(service.port)).sealer], witnesses: [one.key], seals: keptStatements(folder) });
  } finally {
    await service.close();
    await one.w.close();
    await other.w.close();
  }
});

test('a witness that holds a seal of the same recorder, person and agent that is in none of this recorder\'s books is reported: a second history, or a book moved or cut short', async () => {
  // Two folders with the same keys and the same permission: two histories of one sequence.
  const { folder } = await world([]);
  await makeRecorderKeys(folder);
  const twin = tempFolder();
  for (const name of ['agent-keys.jwk', 'recorder-keys.jwk', 'slip.json']) writeFileSync(join(twin, name), read(folder, name));
  const one = await witnessFor(folder);
  writeWitnessSettings(folder, [one.entry]);
  writeWitnessSettings(twin, [one.entry]);
  const a = await startService({ folder, port: 0 });
  try {
    await runHook(a.port, 'PostToolUse', 'Read', { file_path: 'the first history' });
    assert.deepEqual((await a.seal()).witnessed, [one.key]);
  } finally {
    await a.close();
  }
  const b = await startService({ folder: twin, port: 0 });
  try {
    await runHook(b.port, 'PostToolUse', 'Read', { file_path: 'the second history' });
    assert.deepEqual((await b.seal()).witnessed, [], 'the witness signs for no other history');
    const s = await problemOf(b, 'witness-holds-another');
    assert.match(s.witnesses[0].problem.message, /in none of the recorder's books/);
    assert.equal((await runHook(b.port, 'PreToolUse', 'Read', { file_path: 'x' })).out, '', 'recording goes on');
  } finally {
    await b.close();
    await one.w.close();
  }
});

test('two statements kept beside the book for one seal at the same moment are both kept, one from each witness, four at most', async () => {
  const { folder } = await world([]);
  const service = await startService({ folder, port: 0 });
  let sealed;
  try {
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    sealed = await service.seal();
  } finally {
    await service.close();
  }
  const [s] = await sealsOf(folder, 'book.jsonl');
  const record = JSON.parse(lines(read(folder, 'book.jsonl'))[s.place]).seal;
  const statementBy = async (keySet) => (await writeWitness({ seal: s.fingerprint, size: s.content.size, root: s.content.root, by: { keys: keySet.keys, name: 'A witness (test)' } }, keySet.privateKeys)).record;
  const sets = await Promise.all([1, 2, 3, 4, 5].map(() => generateKeySet()));
  const statements = await Promise.all(sets.map(statementBy));
  const added = await Promise.all(statements.slice(0, 2).map((st) => keepStatement(folder, sealed.fingerprint, record, st)));
  assert.deepEqual(added, [true, true]);
  assert.equal(keptStatements(folder)[0].witnesses.length, 2, 'both are kept');
  assert.equal(await keepStatement(folder, sealed.fingerprint, record, statements[0]), false, 'one from each witness');
  await Promise.all(statements.slice(2).map((st) => keepStatement(folder, sealed.fingerprint, record, st)));
  assert.equal(keptStatements(folder)[0].witnesses.length, 4, 'four at most');
});

test('add-witness checks the witness before it names it, and remove-witness names it no more; status shows each witness', async () => {
  const { folder } = await world([]);
  const one = await witnessFor(folder);
  const tokenFile = witnessFiles(one.wfolder).token;
  const port = await freePort();
  const add = (...args) => runCommand(['add-witness', ...args], { folder, port });
  assert.equal((await add('http://localhost:8796', one.key, tokenFile)).code, 2, 'only http://127.0.0.1:<port>');
  assert.equal((await add(one.entry.address, 'not a fingerprint', tokenFile)).code, 2);
  assert.equal((await add(one.entry.address, one.key, join(folder, 'slip.json'))).code, 2, 'a file that holds no token');
  const wrong = await add(one.entry.address, 'A'.repeat(43), tokenFile);
  assert.equal(wrong.code, 1, 'a witness that signs with other keys is not named');
  assert.match(wrong.err, /signs with the key set .* not A{43}/);
  const added = await add(one.entry.address, one.key, tokenFile);
  assert.equal(added.code, 0, added.err);
  assert.match(added.out, /answers, proves that it holds the token/);
  assert.deepEqual(JSON.parse(read(folder, 'witnesses.json')).witnesses, [one.entry]);
  // One that does not answer now is named all the same, and said so.
  const away = await freePort();
  const later = await add(`http://127.0.0.1:${away}`, 'B'.repeat(42) + 'A', tokenFile);
  assert.equal(later.code, 0, later.err);
  assert.match(later.out, /nothing answers/);
  const service = await startService({ folder, port });
  try {
    const shown = JSON.parse((await runCommand(['status'], { folder, port })).out);
    assert.deepEqual(shown.witnesses.map((w) => w.key), [one.key, 'B'.repeat(42) + 'A']);
  } finally {
    await service.close();
  }
  assert.equal((await runCommand(['remove-witness', 'B'.repeat(42) + 'A'], { folder, port })).code, 0);
  assert.equal((await runCommand(['remove-witness', 'B'.repeat(42) + 'A'], { folder, port })).code, 1);
  assert.deepEqual(JSON.parse(read(folder, 'witnesses.json')).witnesses.map((w) => w.key), [one.key]);
  await one.w.close();
});
